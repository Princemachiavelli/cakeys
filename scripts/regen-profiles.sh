#!/usr/bin/env bash
# Regenerate the committed module profiles the reference suites check (docs/CAPROBE.md phase
# 3): softhsm/2.7, kryoptic/1.5 and tpm2-pkcs11/1.10+swtpm, each probed with --write-probes on a fresh
# token set up the way the Nix check phase sets it up (nix/package-common.nix), and written over
# its committed file — [migration] and [manual] kept. Afterwards `git diff profiles/` is the
# drift; the build's conformance tests then pass.
#
#   scripts/regen-profiles.sh <caprobe> <dir>
#
# <caprobe> must carry the patched cryptoki (the probe refuses to write through an unpatched
# one): the Nix-built package — while the committed profiles drift its check phase fails, so
# build it without the check phase:
#   nix build --impure -o /tmp/cakeys --expr \
#     "((builtins.getFlake \"git+file://$PWD\").packages.x86_64-linux.cakeys.overrideAttrs { doCheck = false; }).caprobe"
# The tools come from the flake's own nixpkgs, so the probed versions are the build's:
#   nix shell --inputs-from . nixpkgs#{opensc,swtpm,dbus,tpm2-abrmd,tpm2-tools,tpm2-pkcs11} -c \
#     env KRYOPTIC_MODULE=... TPM2_PKCS11_MODULE=... scripts/regen-profiles.sh /tmp/cakeys-caprobe/bin/caprobe <dir>
# SoftHSM is the flake's own patched build (.#softhsm-unwrap-value-len), which this script
# builds: the one the conformance test re-probes, and pkcs11-check-compare's (apps.nix).
# SOFTHSM_PACKAGE names that build's store path instead, where nix cannot run (inside a
# derivation on the Linux builder).
set -euo pipefail

[ $# -eq 2 ] || {
  echo "usage: $0 <caprobe> <dir>" >&2
  exit 2
}
bin=$(realpath "$1") dir=$(realpath -m "$2")
repo=$(realpath "$(dirname "$(realpath "$0")")/..")
: "${KRYOPTIC_MODULE:?the path to libkryoptic_pkcs11.so}" "${TPM2_PKCS11_MODULE:?the path to libtpm2_pkcs11.so}"
softhsm_pkg=${SOFTHSM_PACKAGE:-$(nix build --no-link --print-out-paths "$repo#softhsm-unwrap-value-len")}
softhsm=$softhsm_pkg/lib/softhsm/libsofthsm2.so
# Its softhsm2-util initialises the token (nix/token-env.sh), so module and tool are one build.
export PATH=$softhsm_pkg/bin:$PATH
mkdir -p "$dir"
echo 1234 >"$dir/pin"

# The tokens as the check phase sets them up (nix/token-env.sh).
# shellcheck source=nix/token-env.sh
. "$repo/nix/token-env.sh"
softhsm_conf "$dir"
softhsm_init kmtest
kryoptic_conf "$dir"
kryoptic_init "$KRYOPTIC_MODULE" kmtest

export HOME=$dir
# Its own port: the harness default (23211) may be another run's.
# The trap first: `down` takes whatever PID files there are, so it covers an `up` cut short.
trap 'bash "$repo/nix/tpm2-test-env.sh" down "$dir/tpm"' EXIT
bash "$repo/nix/tpm2-test-env.sh" up "$dir/tpm" "${TPM_PORT:-23311}"
# shellcheck source=/dev/null
. "$dir/tpm/env"

# A TOML basic string: backslash and quote escaped, so any path reads back as itself.
toml_string() {
  local s=${1//\\/\\\\}
  printf '"%s"' "${s//\"/\\\"}"
}
token() {
  printf '[tokens.%s]\nmodule = %s\ntokenLabel = "kmtest"\npinFile = %s\nprobe = { scratch = true }\n\n' \
    "$1" "$(toml_string "$2")" "$(toml_string "$dir/pin")"
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
  "$bin" --config "$dir/keys.toml" probe --profiles "$repo/profiles" --token "$token" --write-probes --rsa-max-bits 4096 \
    --diff "$name" --out "$repo/profiles/modules/$file" || rc=$?
  [ "$rc" = 0 ] || [ "$rc" = 15 ] || status=$rc
done
exit "$status"
