#!/usr/bin/env bash
# Sourced by each example's run.sh: a working directory, throwaway tokens and a step runner
# that requires each step's exit code, so an example that drifts from cakeys fails
# (checks.examples). Every token here takes user PIN 1234 and SO PIN 5678.
#
# Environment, as the token kinds need: SOFTHSM_MODULE, KRYOPTIC_MODULE, TPM2_PKCS11_MODULE;
# TPM2_TEST_ENV (default: the repository's nix/tpm2-test-env.sh) and TPM_PORT (default 24321);
# KEEP=1 leaves the working directory.

set -euo pipefail

examples=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tpm_env=${TPM2_TEST_ENV:-$examples/../nix/tpm2-test-env.sh}
work=$(mktemp -d "${TMPDIR:-/tmp}/cakeys-example.XXXXXX")
tpm_up=0
cleanup() {
  [ "$tpm_up" = 1 ] && bash "$tpm_env" down "$work/tpm" || true
  if [ "${KEEP:-0}" = 1 ]; then echo "kept: $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT
cd "$work"
echo 1234 >"$work/pin"

# Run a command, show it and the start of its output (stderr, then stdout), and require the
# exit code `want`; `limit` lines at most (default 12). What it printed on stdout is in $work/stdout.
expect() {
  local want=$1 code=0 out
  shift
  printf '$ %s\n' "$*"
  out=$("$@" 2>&1 >"$work/stdout") || code=$?
  local printed
  if [ "$(LC_ALL=C tr -d '[:print:][:space:]' <"$work/stdout" | wc -c)" != 0 ]; then
    printed="($(wc -c <"$work/stdout") bytes of binary output)"
  else
    printed=$(<"$work/stdout")
  fi
  # tpm2-pkcs11 warns of its FAPI backend on every load, though the store is esysdb: cut.
  out=$(printf '%s\n%s' "$out" "$printed" | sed '/^$/d; /FAPI/d')
  [ -n "$out" ] && awk -v max="${limit:-12}" '
    NR <= max { print "  " $0 }
    END { if (NR > max) printf "  … (%d more lines)\n", NR - max }' <<<"$out"
  if [ "$code" != "$want" ]; then
    echo "  → exit $code, expected $want: the example no longer matches cakeys"
    exit 1
  fi
  echo "  → exit $code"
}

# The software tokens as every harness sets them up.
# shellcheck source=nix/token-env.sh
. "${CAKEYS_TOKEN_ENV_SH:-$examples/../nix/token-env.sh}"

# A SoftHSM token labelled $1.
softhsm_token() {
  softhsm_conf "$work"
  softhsm_init "$1"
}

# A kryoptic token labelled $1 (one per run).
kryoptic_token() {
  kryoptic_conf "$work"
  kryoptic_init "$KRYOPTIC_MODULE" "$1"
}

# A tpm2-pkcs11 token labelled $1, on a software TPM this run starts (nix/tpm2-test-env.sh).
tpm_token() {
  if [ "$tpm_up" = 0 ]; then
    tpm_up=1
    bash "$tpm_env" up "$work/tpm" "${TPM_PORT:-24321}"
    # shellcheck source=/dev/null
    . "$work/tpm/env"
  fi
  tpm2_ptool addtoken --pid=1 --label="$1" --sopin=5678 --userpin=1234 --path "$work/tpm/store" >/dev/null
}

# OpenSSL with pkcs11-provider over module $1: `default` activated first, as pkcs11-provider's
# own examples list it (SoftHSM 2.7.0 deadlocks in C_Login otherwise: docs/OPEN.md).
openssl_pkcs11() {
  export PKCS11_PROVIDER_MODULE=$1
  export OPENSSL_CONF=$work/openssl-pkcs11.cnf
  cat >"$OPENSSL_CONF" <<EOF
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
pkcs11 = pkcs11_sect

[default_sect]
activate = 1

[pkcs11_sect]
module = ${PKCS11_PROVIDER_DIR:?}/pkcs11.so
activate = 1
EOF
}
