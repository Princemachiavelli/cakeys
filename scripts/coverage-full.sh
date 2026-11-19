#!/usr/bin/env bash
# Coverage of the whole test run with the suites the Nix build cannot run: `nix build .#coverage`
# measures what runs in the sandbox (the software tokens); this adds the opt-in hardware suites,
# on the host, into one report. `nix run .#coverage-full` from the repository root, which
# brings cargo-llvm-cov and the llvm tools of this rustc.
#
#   nix run .#coverage-full [-- cargo-nextest arguments for the software pass]
#
# The software pass is scripts/local-tests.sh (a token set per test, the patched cryptoki),
# instrumented. A hardware suite runs after it when its variables are set, one test at a time,
# stopping at its first failure:
#
#   CAKEYS_TEST_YUBIKEY_PIN, CAKEYS_TEST_YUBIKEY_MGM   files holding the PIV PIN and the admin
#       credential (never read here: the paths go to the tests): the YubiKey suites, which write
#       only to retired slots 90-95. CAKEYS_YUBIKEY_WIPE=1 empties those slots
#       (scripts/yubikey-empty-slots.py: the management key alone, never the PIN; slots 82-84
#       compared before and after): slot 95 before camigrate's import, which needs it empty,
#       and slots 90-95 again before cakeys' suite, which then generates every key rather than
#       adopting an earlier run's (review yubikey.rs F2), and attests what it generated. Without
#       it the import is left out and cakeys' suite adopts what the slots hold.
#   CAKEYS_FTPM_PROFILE   the committed pair profile of this host's TPM (e.g.
#       tpm2-pkcs11/1.10+amd-ftpm): the real-TPM suites, through nix/ftpm-test-env.sh.
#       CAKEYS_FTPM_ATTEST=1 adds the attestation test (the store under the platform's storage
#       root key, only read; cakeys' Attestation Key at 0x81000016). The persistent handles are
#       listed before and after and must be the same (0x81000016 aside), and the lockout
#       counter must still be 0.
#
# The report is target/coverage-full/: summary.txt, missing.txt, lcov.info, html/index.html.
# It exits 1 when a test failed; the report is written either way and says what ran.
set -euo pipefail

if [ "${CAKEYS_COVERAGE_STAGE:-}" != run ]; then
  repo=$(cd "$(dirname "$0")/.." && pwd)
  command -v cargo-llvm-cov >/dev/null && [ -n "${LLVM_COV:-}" ] && [ -n "${LLVM_PROFDATA:-}" ] || {
    echo "coverage-full: cargo-llvm-cov, LLVM_COV or LLVM_PROFDATA is missing: run it as 'nix run .#coverage-full'" >&2
    exit 1
  }
  export CAKEYS_COVERAGE_STAGE=run CAKEYS_COVERAGE_REPO=$repo CAKEYS_LOCAL_TESTS_THEN=$repo/scripts/coverage-full.sh
  exec "$repo/scripts/local-tests.sh" "$@"
fi

# From here: inside scripts/local-tests.sh's environment (the tree copy, the token templates,
# the reference modules), in place of its `cargo nextest run`.
features=$1
shift
out=$CAKEYS_COVERAGE_REPO/target/coverage-full

# The hardware suites' variables are theirs alone: the software pass must not see them.
yk_pin=${CAKEYS_TEST_YUBIKEY_PIN:-} yk_mgm=${CAKEYS_TEST_YUBIKEY_MGM:-}
yk_module=${CAKEYS_TEST_YUBIKEY_MODULE:-${CAKEYS_YKCS11_MODULE:-}}
ftpm_profile=${CAKEYS_FTPM_PROFILE:-} ftpm_attest=${CAKEYS_FTPM_ATTEST:-}
ftpm_module=${CAKEYS_FTPM_MODULE:-$CAKEYS_TPM_MODULE}
unset CAKEYS_TEST_YUBIKEY_PIN CAKEYS_TEST_YUBIKEY_MGM CAKEYS_TEST_YUBIKEY_MODULE CAKEYS_YUBIKEY_REQUIRE \
  CAKEYS_FTPM_PROFILE CAKEYS_FTPM_ATTEST CAKEYS_FTPM_MODULE CAKEYS_FTPM_REQUIRE

ran=() failed=()
# One instrumented nextest run, its profile data added to what the runs before it left.
pass() {
  local name=$1
  shift
  ran+=("$name")
  cargo llvm-cov nextest --no-report --workspace --features "$features" "$@" || failed+=("$name")
}
hardware() {
  local name=$1
  shift
  pass "$name" --test-threads 1 --fail-fast "$@"
}

cargo llvm-cov clean --workspace
pass "software tokens" --no-fail-fast "$@"

if [ -n "$yk_pin" ] && [ -n "$yk_mgm" ]; then
  [ -r "$yk_pin" ] && [ -r "$yk_mgm" ] && [ -f "$yk_module" ] || {
    echo "coverage-full: the YubiKey suites need readable CAKEYS_TEST_YUBIKEY_PIN and _MGM files and libykcs11.so ($yk_module)" >&2
    exit 1
  }
  # CAKEYS_YUBIKEY_REQUIRE: this run means the suites, so one that finds its opt-in unset fails
  # rather than passing having run nothing (crates/cli/tests/common, review D9).
  export CAKEYS_TEST_YUBIKEY_MODULE=$yk_module CAKEYS_TEST_YUBIKEY_PIN=$yk_pin CAKEYS_TEST_YUBIKEY_MGM=$yk_mgm \
    CAKEYS_YUBIKEY_REQUIRE=1
  # The key and the certificate of each test slot named: ykcs11 shows a certificate left alone
  # as a certificate and a public key under the slot's CKA_ID, which cakeys then refuses to
  # create beside. The management key alone authenticates, so a failure costs no PIN try.
  wipe() { "$CAKEYS_YUBIKIT_PYTHON" -I "$CAKEYS_COVERAGE_REPO/scripts/yubikey-empty-slots.py" "$yk_mgm" "$@"; }
  # camigrate's import needs slot 95 empty, and cakeys' suite then generates into it.
  if [ "${CAKEYS_YUBIKEY_WIPE:-}" = 1 ]; then
    wipe 95
    hardware "YubiKey: camigrate's import into slot 95" -E 'package(camigrate) & binary(yubikey)'
  else
    echo "coverage-full: camigrate's YubiKey import is left out: it needs slot 95 empty (CAKEYS_YUBIKEY_WIPE=1)" >&2
  fi
  # cakeys' suite generates into slots 90-95 and attests what it finds there: an imported key
  # (the one the import above left) has no attestation, and an earlier run's would be adopted
  # rather than generated, so every test slot is emptied.
  [ "${CAKEYS_YUBIKEY_WIPE:-}" != 1 ] || wipe 90 91 92 93 94 95
  # A login that failed is not tried again: the PIN has three tries.
  if [ ${#failed[@]} -eq 0 ] || [ "${failed[-1]#YubiKey}" = "${failed[-1]}" ]; then
    hardware "YubiKey: cakeys and caprobe" -E 'binary(yubikey) & not package(camigrate)'
  fi
  unset CAKEYS_TEST_YUBIKEY_MODULE CAKEYS_TEST_YUBIKEY_PIN CAKEYS_TEST_YUBIKEY_MGM CAKEYS_YUBIKEY_REQUIRE
else
  echo "coverage-full: no YubiKey suites: CAKEYS_TEST_YUBIKEY_PIN and CAKEYS_TEST_YUBIKEY_MGM are not set" >&2
fi

if [ -n "$ftpm_profile" ]; then
  F=$(mktemp -d "$TMPDIR/ftpm.XXXXXX")
  # The parent of the store: the platform's storage root key for the attestation, else transient.
  printf '%s\n' "${ran[@]}" >"$F/ran"
  printf '%s\n' "${failed[@]}" >"$F/failed"
  # The private tpm2-abrmd on the host's TPM goes however this ends: a failed `up` stops what it
  # started itself, and this covers an exit anywhere below.
  trap 'bash nix/ftpm-test-env.sh down "$F"' EXIT
  bash nix/ftpm-test-env.sh up "$F" ${ftpm_attest:+persistent}
  # The `||` after this subshell turns errexit off inside it: each step that must hold says so.
  (
    # shellcheck source=/dev/null
    . "$F/env" || exit 1
    # The persistent handles but cakeys' Attestation Key. A failing tpm2_getcap fails it,
    # rather than reading as an empty list that compares equal to another.
    handles() {
      local all
      all=$(tpm2_getcap handles-persistent) || return 1
      grep -v 0x81000016 <<<"$all" || true
    }
    before=$(handles) || exit 1
    # As for the YubiKey: required, so a suite that finds no opt-in fails.
    export CAKEYS_FTPM_MODULE=$ftpm_module CAKEYS_FTPM_PROFILE=$ftpm_profile CAKEYS_FTPM_REQUIRE=1
    [ -z "$ftpm_attest" ] || export CAKEYS_FTPM_ATTEST=$ftpm_attest
    # caprobe first: its probe wants the fresh store.
    hardware "real TPM: caprobe" -E 'package(caprobe) & binary(ftpm)'
    [ ${#failed[@]} -gt 0 ] && [ "${failed[-1]}" = "real TPM: caprobe" ] ||
      hardware "real TPM: cakeys" -E 'package(cakeys) & binary(ftpm)'
    printf '%s\n' "${ran[@]}" >"$F/ran"
    printf '%s\n' "${failed[@]}" >"$F/failed"
    if ! after=$(handles); then
      echo "coverage-full: THE TPM'S PERSISTENT HANDLES COULD NOT BE READ AFTER THE RUN" >&2
      echo "real TPM: persistent handles unreadable after the run" >>"$F/failed"
    elif [ "$before" != "$after" ]; then
      printf 'coverage-full: THE TPM'"'"'S PERSISTENT HANDLES CHANGED\nbefore:\n%s\nafter:\n%s\n' "$before" "$after" >&2
      echo "real TPM: persistent handles changed" >>"$F/failed"
    fi
    lockout=$(tpm2_getcap properties-variable | sed -n 's/^TPM2_PT_LOCKOUT_COUNTER: *//p')
    [ "$lockout" = 0x0 ] || {
      echo "coverage-full: THE TPM'S LOCKOUT COUNTER IS $lockout, NOT 0" >&2
      echo "real TPM: lockout counter $lockout" >>"$F/failed"
    }
  ) || echo "real TPM: the run stopped" >>"$F/failed"
  bash nix/ftpm-test-env.sh down "$F"
  trap - EXIT
  mapfile -t ran < <(grep . "$F/ran" || true)
  mapfile -t failed < <(grep . "$F/failed" || true)
else
  echo "coverage-full: no real-TPM suites: CAKEYS_FTPM_PROFILE is not set" >&2
fi

rm -rf "$out"
mkdir -p "$out"
cargo llvm-cov report --lcov --output-path "$out/lcov.info"
cargo llvm-cov report --summary-only >"$out/summary.txt"
cargo llvm-cov report --show-missing-lines >"$out/missing.txt"
cargo llvm-cov report --html --output-dir "$out"
{
  printf 'ran: %s\n' "${ran[@]}"
  [ ${#failed[@]} -eq 0 ] || printf 'FAILED: %s\n' "${failed[@]}"
} | tee "$out/suites.txt"
tail -n 1 "$out/summary.txt"
echo "coverage-full: the report is in $out"
[ ${#failed[@]} -eq 0 ]
