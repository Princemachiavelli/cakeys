#!/usr/bin/env bash
# pkcs11-check against a reference module on throwaway tokens, set beside the module's caprobe
# profile (docs/PLAN.md A6): `nix run .#pkcs11-check-compare -- <module> [pass] [--out DIR]
# [-- pkcs11-check test arguments]`. A report, never a check: pkcs11-check's counts move with
# its releases, and which finding contradicts a profile is for a person to decide.
#
#   module  softhsm (the flake's patched 2.7.0, as the profile was probed on), kryoptic, or
#           tpm2-pkcs11 (over swtpm, started here)
#   pass    main         the suite without slow tests (on tpm2-pkcs11, the files that bear on
#                        cakeys' profile rows: the whole suite is hours on swtpm)
#           destructive  the SO-login and CKA_TRUSTED files, with --destructive
#           vectors      the Wycheproof and ACVP suites, their vectors fetched once into
#                        ${XDG_CACHE_HOME:-~/.cache}/cakeys/pkcs11-check-data (network)
#
# Writes pkcs11-check's own artifacts (results.json, report.jsonl, coverage.json, run.log) and
# summary.md (scripts/pkcs11-check-compare.py) to DIR, default ./pkcs11-check-<module>-<pass>.
# Exits 0 once summary.md is written, whatever the tests found; nonzero when the run produced
# no results.
#
# Environment (set by the app, apps.nix): SOFTHSM_MODULE, KRYOPTIC_MODULE, TPM2_PKCS11_MODULE,
# CAKEYS_TOKEN_ENV_SH (nix/token-env.sh), TPM2_TEST_ENV, PROFILES (profiles/modules), TESTCASES (pkcs11-check's testcases directory),
# COMPARE (pkcs11-check-compare.py); on PATH pkcs11-check, softhsm2-util, pkcs11-tool, python3
# and the TPM stack. TPM_PORT picks swtpm's port (default 24331).
set -euo pipefail

usage() {
  sed -n '2,/^set -euo/{/^#/s/^# \{0,1\}//p}' "$0" >&2
  exit 2
}
[ $# -ge 1 ] || usage
module=$1
shift
pass=main
case ${1:-} in main | destructive | vectors) pass=$1 && shift ;; esac
out=$PWD/pkcs11-check-$module-$pass
extra=()
while [ $# -gt 0 ]; do
  case $1 in
  --out)
    [ $# -ge 2 ] || usage
    out=$(realpath -m "$2") && shift 2
    ;;
  --) shift && extra=("$@") && break ;;
  *) usage ;;
  esac
done

case $module in
softhsm) lib=$SOFTHSM_MODULE profile=$PROFILES/softhsm/2.7.toml ;;
kryoptic) lib=$KRYOPTIC_MODULE profile=$PROFILES/kryoptic/1.5.toml ;;
tpm2-pkcs11) lib=$TPM2_PKCS11_MODULE profile=$PROFILES/tpm2-pkcs11/1.10+swtpm.toml ;;
*) usage ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/cakeys-pkcs11-check.XXXXXX")
tpm_up=0
cleanup() {
  [ "$tpm_up" = 1 ] && bash "$TPM2_TEST_ENV" down "$work/tpm" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
mkdir -p "$out"
# What a run writes, removed first: a run that writes nothing must not leave the last run's
# results for the guard below and the summary to read as this one's.
rm -f "$out/results.json" "$out/report.jsonl" "$out/coverage.json" "$out/run.log" "$out/summary.md"

# A token labelled kmtest, user PIN 1234, SO PIN 5678, as scripts/regen-profiles.sh sets one up
# (nix/token-env.sh).
# shellcheck source=nix/token-env.sh
. "$CAKEYS_TOKEN_ENV_SH"
case $module in
softhsm)
  softhsm_conf "$work"
  softhsm_init kmtest
  ;;
kryoptic)
  kryoptic_conf "$work"
  kryoptic_init "$lib" kmtest
  ;;
tpm2-pkcs11)
  tpm_up=1
  export HOME=$work/home
  mkdir -p "$HOME"
  bash "$TPM2_TEST_ENV" up "$work/tpm" "${TPM_PORT:-24331}"
  # shellcheck source=/dev/null
  . "$work/tpm/env"
  ;;
esac
export P11TEST_PIN=1234 P11TEST_SO_PIN=5678

args=(test -m "$lib" --pin 1234 --rv-trace-compact 10 -o json --output-file "$out/results.json")
files=()
case $pass in
main)
  args+=(--skip-slow)
  [ "$module" = tpm2-pkcs11 ] && files=(
    test_rsa_oaep.py test_oaep_parameter_fidelity.py test_rsa_key_wrapping.py test_mech_wrap.py
    security/test_unwrap_reimport.py test_ecdh_extended.py test_ecdh_known_answer.py
    test_mech_derive.py test_ro_session.py test_ro_session_restrictions.py test_ec_curves.py
    test_key_sizes.py test_mech_keygen.py test_ec_import_export.py test_rsa_key_import.py
    test_private_key_import_policy.py test_always_authenticate.py test_attribute_defaults.py
    test_key_usage_policy.py test_sensitivity.py test_eddsa.py test_access_levels.py
    test_trust_objects.py test_set_attribute.py test_setattr_restricted.py
    test_attribute_enforcement.py test_mech_sign.py test_keypair_consistency.py test_data_objects.py
  )
  ;;
destructive)
  # Slow tests included (test_key_sizes' large RSA); the files that can re-PIN or re-initialise
  # the token last.
  args+=(--destructive)
  files=(
    test_trust_objects.py x509/test_attributes.py security/test_unwrap_reimport.py
    security/test_cve_regression.py test_attribute_enforcement.py test_always_authenticate.py
    test_key_sizes.py test_access_levels.py test_pin.py test_so_pin.py
  )
  ;;
vectors)
  args+=(--skip-slow)
  export PKCS11_CHECK_DATA_DIR=${XDG_CACHE_HOME:-$HOME/.cache}/cakeys/pkcs11-check-data
  for source in wycheproof acvp; do
    [ -d "$PKCS11_CHECK_DATA_DIR/$source" ] || pkcs11-check fetch-data "$source" --data-dir "$PKCS11_CHECK_DATA_DIR"
  done
  files=(
    acvp/test_keygen_key_size_conformance.py acvp/test_acvp_rsa_keygen.py acvp/test_acvp_rsa.py
    acvp/test_acvp_ecdh.py acvp/test_acvp_ecdsa.py acvp/test_acvp_eddsa.py
    wycheproof/test_wycheproof_rsa_oaep.py wycheproof/test_wycheproof_rsa_decrypt.py
    wycheproof/test_wycheproof_rsa.py wycheproof/test_wycheproof_rsa_pss.py
    wycheproof/test_wycheproof_ecdh.py wycheproof/test_wycheproof_ecdsa.py
    wycheproof/test_wycheproof_ed25519.py wycheproof/test_wycheproof_x25519.py
    wycheproof/test_wycheproof_aes.py wycheproof/test_wycheproof.py
  )
  ;;
esac
for f in "${files[@]}"; do args+=("$TESTCASES/$f"); done

# pkcs11-check keeps its state files in the working directory.
mkdir "$work/run"
cd "$work/run"
echo "pkcs11-check ${args[*]} ${extra[*]}" | tee "$out/run.log"
SECONDS=0
code=0
pkcs11-check "${args[@]}" "${extra[@]}" 2>&1 | tee -a "$out/run.log" || code=$?
echo "exit $code after ${SECONDS}s" | tee -a "$out/run.log"
# pkcs11-check writes report.jsonl and coverage.json beside the output file.
[ -f "$out/results.json" ] || {
  echo "pkcs11-check-compare: no results.json in $out: the run did not complete" >&2
  exit 1
}
python3 "$COMPARE" "$out" "$profile" >"$out/summary.md"
echo "summary: $out/summary.md"
