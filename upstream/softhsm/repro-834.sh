#!/usr/bin/env bash
# SoftHSMv2 #834 (and #857, #780) reproduction: OpenSSL through pkcs11-provider over SoftHSM,
#   upstream/softhsm/repro-834.sh path/to/libsofthsm2.so path/to/ossl-modules
# Needs softhsm2-util, OpenSC's pkcs11-tool and openssl 3 on PATH (checks.softhsm-pkcs11-provider
# arranges them). pkcs11-provider is activated before `default`, the order that deadlocks
# SoftHSM 2.7.0 in C_Login (#834). Then a streaming signature, which 2.7.0 refuses with
# CKR_OPERATION_NOT_INITIALIZED (#857), verified; every openssl run must exit 0, which 2.7.0's
# crash at exit (#780) does not. Exits 1 on the first failure.
set -euo pipefail

module=$1
provider_dir=$2
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
export SOFTHSM2_CONF=$dir/softhsm2.conf
mkdir "$dir/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$dir/tokens" >"$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label t834 --pin 1234 --so-pin 5678 >/dev/null
pkcs11-tool --module "$module" --token-label t834 --login --pin 1234 \
  --keypairgen --key-type EC:prime256v1 --id 01 --label k >/dev/null

export PKCS11_PROVIDER_MODULE=$module
key='pkcs11:token=t834;object=k;type=private?pin-value=1234'
via=(-provider-path "$provider_dir" -provider pkcs11 -provider default)
echo "signed through pkcs11-provider" >"$dir/data"
run() {
  local rc=0
  timeout 60 openssl "$@" || rc=$?
  if [ "$rc" = 124 ]; then
    echo "FAIL: openssl $1 did not finish in 60s (deadlock in C_Login, #834)"
    exit 1
  elif [ "$rc" != 0 ]; then
    echo "FAIL: openssl $1 exited $rc"
    exit 1
  fi
}
run pkey "${via[@]}" -in "$key" -pubout -out "$dir/pub.pem"
run dgst -sha256 "${via[@]}" -sign "$key" -out "$dir/sig" "$dir/data"
run dgst -sha256 -verify "$dir/pub.pem" -signature "$dir/sig" "$dir/data"
echo "ok: login, public key, streaming ECDSA-SHA256 signature verified, clean exits"
