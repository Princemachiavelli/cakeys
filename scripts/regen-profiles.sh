#!/usr/bin/env bash
# Regenerate the committed module profiles the reference suites check (docs/PROVIDERS.md phase
# 3): softhsm/2.7, kryoptic/1.5 and tpm2-pkcs11/1.10+swtpm, each probed with --write on a fresh
# token set up the way the Nix check phase sets it up (nix/package.nix), and written over its
# committed file — [migration] and [manual] kept. Afterwards `git diff profiles/` is the drift;
# the build's conformance tests then pass.
#
#   scripts/regen-profiles.sh <cakeys> <dir>
#
# <cakeys> must carry the patched cryptoki (the probe refuses to write through an unpatched
# one): the Nix-built package — while the committed profiles drift its check phase fails, so
# build it without the check phase:
#   nix build --impure -o /tmp/cakeys --expr \
#     "(builtins.getFlake \"git+file://$PWD\").packages.x86_64-linux.cakeys.overrideAttrs { doCheck = false; }"
# The tools come from the flake's own nixpkgs, so the probed versions are the build's:
#   nix shell --inputs-from . nixpkgs#{softhsm,opensc,swtpm,dbus,tpm2-abrmd,tpm2-tools,tpm2-pkcs11} -c \
#     env KRYOPTIC_MODULE=... TPM2_PKCS11_MODULE=... scripts/regen-profiles.sh /tmp/cakeys/bin/cakeys <dir>
set -euo pipefail

bin=$(realpath "$1") dir=$(realpath -m "$2")
repo=$(realpath "$(dirname "$(realpath "$0")")/..")
: "${KRYOPTIC_MODULE:?the path to libkryoptic_pkcs11.so}" "${TPM2_PKCS11_MODULE:?the path to libtpm2_pkcs11.so}"
softhsm=$(dirname "$(dirname "$(readlink -f "$(command -v softhsm2-util)")")")/lib/softhsm/libsofthsm2.so
mkdir -p "$dir"
echo 1234 >"$dir/pin"

export SOFTHSM2_CONF=$dir/softhsm2.conf
mkdir -p "$dir/softhsm-tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
  "$dir/softhsm-tokens" >"$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label kmtest --pin 1234 --so-pin 5678 >/dev/null

export KRYOPTIC_CONF=$dir/kryoptic.conf
printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "%s"\n' "$dir/kryoptic.sql" >"$KRYOPTIC_CONF"
pkcs11-tool --module "$KRYOPTIC_MODULE" --init-token --slot 1 --so-pin 5678 --label kmtest >/dev/null
pkcs11-tool --module "$KRYOPTIC_MODULE" --token-label kmtest --login --login-type so \
  --so-pin 5678 --init-pin --pin 1234 >/dev/null

export HOME=$dir
# Its own port: the harness default (23211) may be another run's.
bash "$repo/nix/tpm2-test-env.sh" up "$dir/tpm" "${TPM_PORT:-23311}"
trap 'bash "$repo/nix/tpm2-test-env.sh" down "$dir/tpm"' EXIT
# shellcheck source=/dev/null
. "$dir/tpm/env"

token() {
  printf '[tokens.%s]\nmodule = "%s"\ntokenLabel = "kmtest"\npinFile = "%s"\nscratch = true\n\n' \
    "$1" "$2" "$dir/pin"
}
{
  token softhsm "$softhsm"
  token kryoptic "$KRYOPTIC_MODULE"
  token tpm "$TPM2_PKCS11_MODULE"
} >"$dir/keys.toml"

status=0
for t in softhsm:softhsm/2.7:softhsm/2.7.toml kryoptic:kryoptic/1.5:kryoptic/1.5.toml \
  tpm:tpm2-pkcs11/1.10+swtpm:tpm2-pkcs11/1.10+swtpm.toml; do
  IFS=: read -r token name file <<<"$t"
  echo "== $name"
  # 15 is drift, the rows named: the file is written anyway, the diff is for review.
  rc=0
  "$bin" --config "$dir/keys.toml" probe --profiles "$repo/profiles" --token "$token" --write \
    --diff "$name" --out "$repo/profiles/modules/$file" || rc=$?
  [ "$rc" = 0 ] || [ "$rc" = 15 ] || status=$rc
done
exit "$status"
