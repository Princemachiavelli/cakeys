#!/usr/bin/env bash
# A token set of its own for one test process (docs/DEVELOPMENT.md, "Testing"). The crane
# check phase runs every test binary through this script (cargo's target runner) under
# cargo-nextest, which starts one process per test: so each test gets a fresh SoftHSM token
# directory and kryoptic database copied from the templates the check phase initialised, and —
# for the suites that use them — its own `p11-kit server` and its own swtpm. Tests then run in
# parallel, and none sees what another left on a token.
#
#   test-tokens.sh <test binary> [args...]
#
# Needs $CAKEYS_TOKEN_TEMPLATE (softhsm-tokens/ and kryoptic.sql, nix/package-common.nix);
# without it, and to list a binary's tests, the binary runs as it is. The token setup, the
# p11-kit and the TPM environments are the scripts $CAKEYS_TOKEN_ENV_SH, $CAKEYS_P11KIT_ENV_SH
# and $CAKEYS_TPM_ENV_SH name. A suite that uses p11-kit or the TPM is named in the lists below:
# there is no shared server or TPM to fall back on, so one left out fails.
set -euo pipefail

# The tools take their keys.toml and lock from these when no flag names them: a developer's own
# would have the suites write their real lock (review common/mod.rs F1). Every test, any binary.
unset CAKEYS_CONFIG CAKEYS_LOCK

case " $* " in *" --list "*) exec "$@" ;; esac
[ -n "${CAKEYS_TOKEN_TEMPLATE:-}" ] || exec "$@"

# Short: a socket path has to fit in sun_path.
D=$(mktemp -d "${TMPDIR:-/tmp}/tok.XXXXXX")
cleanup() {
  [ ! -d "$D/p11" ] || bash "$CAKEYS_P11KIT_ENV_SH" down "$D/p11" || true
  [ ! -d "$D/tpm" ] || bash "$CAKEYS_TPM_ENV_SH" down "$D/tpm" || true
  rm -rf "$D"
}
trap cleanup EXIT

# shellcheck source=nix/token-env.sh
. "${CAKEYS_TOKEN_ENV_SH:?the token setup, nix/token-env.sh}"
cp -r "$CAKEYS_TOKEN_TEMPLATE/softhsm-tokens" "$D/softhsm-tokens"
softhsm_conf "$D"
cp "$CAKEYS_TOKEN_TEMPLATE/kryoptic.sql" "$D/kryoptic.sql"
kryoptic_conf "$D"

# The test binary's name without cargo's hash: which suite this is.
suite=$(basename "$1")
suite=${suite%-*}

# Coverage (docs/PLAN.md A1): with $CAKEYS_TRACE_DIR, every module this test can load goes
# through a copy of p11-fault with a tag of its own (libp11_fault-<tag>.so reads only
# P11_FAULT_*_<TAG>), a pure forwarder that logs each call to <dir>/<suite>/<test>.jsonl. The
# copies are made once per run, and are copies: the loader takes two links to one file for one
# library, whose settings both would share. The tests that put their own p11-fault in front of a
# module run untraced: that shim's hooks call the module too, inside the tool's process, and the
# trace would count those calls as the tool's. This case is the one list of them; cakeys'
# `every_test_with_its_own_fault_shim_runs_untraced` fails on one it does not name. The kryoptic
# probe is the other: it calls C_EncapsulateKey, a Cryptoki 3.2 function the shim's 2.40 function
# list does not forward, so traced it could not observe the row the profile has.
test=unnamed prev=
for a in "$@"; do
  [ "$prev" != --exact ] || test=$a
  prev=$a
done
case $suite/$test in
fault/* | reference/kryoptic_committed_profile_is_what_the_probe_observes | tpm2/tpm2_attestation_says_what_it_lacks | tpm2/tpm2_identity_failure_after_create_leaves_nothing | dry_run/a_failed_reopen_after_ptool_says_what_is_in_the_tpm) untraced=1 ;;
*) untraced= ;;
esac
if [ -n "${CAKEYS_TRACE_DIR:-}" ] && [ -z "$untraced" ]; then
  trace=$CAKEYS_TRACE_DIR/$suite/${test//::/.}.jsonl
  shim=$(dirname "$1")/libp11_fault.so
  [ -e "$shim" ] || {
    echo "test-tokens.sh: CAKEYS_TRACE_DIR, but no $shim" >&2
    exit 1
  }
  mkdir -p "$CAKEYS_TRACE_DIR/$suite" "$CAKEYS_TRACE_DIR/shims"
  for pair in softhsm:CAKEYS_TEST_MODULE kryoptic:CAKEYS_KRYOPTIC_MODULE tpm:CAKEYS_TPM_MODULE \
    p11kit:CAKEYS_P11KIT_CLIENT; do
    tag=${pair%%:*} var=${pair#*:}
    [ -n "${!var:-}" ] || continue
    copy=$CAKEYS_TRACE_DIR/shims/libp11_fault-$tag.so
    [ -e "$copy" ] || { cp "$shim" "$copy.$$" && mv -f "$copy.$$" "$copy"; }
    export "P11_FAULT_MODULE_${tag^^}=${!var}" "P11_FAULT_TRACE_${tag^^}=$trace" "$var=$copy"
  done
fi
# tests/fault.rs runs the reference suite again, through p11-fault in front of this test's own
# SoftHSM token. CAKEYS_FAULT_REQUIRE is test_env's, not this arm's: a fault suite this name
# match misses fails rather than skipping (review 2026-11-24 C-11).
if [ "$suite" = fault ]; then
  export P11_FAULT_MODULE=$CAKEYS_TEST_MODULE
fi
case $suite in
p11kit | reference | references | dry_run)
  SOFTHSM_MODULE=$CAKEYS_TEST_MODULE bash "$CAKEYS_P11KIT_ENV_SH" up "$D/p11"
  # shellcheck source=/dev/null
  . "$D/p11/env"
  ;;
esac
case $suite in
tpm2 | references | dry_run)
  if [ -n "${CAKEYS_TPM_MODULE:-}" ]; then
    # A port pair of its own: nextest numbers the tests running at once, so its slot is free.
    # Without nextest nothing numbers them: a random slot, and another one if that pair turns out
    # taken (a failed `up` stops what it started). CAKEYS_TPM_PORT_BASE moves the range, for two
    # runs on one machine (scripts/local-tests.sh).
    if [ -n "${NEXTEST_TEST_GLOBAL_SLOT:-}" ]; then
      slots=$NEXTEST_TEST_GLOBAL_SLOT
    else
      slots="$((RANDOM % 4000)) $((RANDOM % 4000)) $((RANDOM % 4000)) $((RANDOM % 4000))"
    fi
    up=
    for slot in $slots; do
      rm -rf "$D/tpm"
      if bash "$CAKEYS_TPM_ENV_SH" up "$D/tpm" $((${CAKEYS_TPM_PORT_BASE:-24000} + 2 * slot)); then
        up=1
        break
      fi
    done
    [ -n "$up" ] || {
      tail -n 20 "$D"/tpm/*.log >&2
      exit 1
    }
    # shellcheck source=/dev/null
    . "$D/tpm/env"
  fi
  ;;
esac

"$@"
