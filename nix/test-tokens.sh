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
# without it, and to list a binary's tests, the binary runs as it is. The p11-kit and TPM
# environments are the scripts $CAKEYS_P11KIT_ENV_SH and $CAKEYS_TPM_ENV_SH name.
set -euo pipefail

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

cp -r "$CAKEYS_TOKEN_TEMPLATE/softhsm-tokens" "$D/softhsm-tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\nlog.level = ERROR\n' \
  "$D/softhsm-tokens" >"$D/softhsm2.conf"
export SOFTHSM2_CONF=$D/softhsm2.conf

# The slot table ends the file: the suite appends a mechanism deny list to it.
cp "$CAKEYS_TOKEN_TEMPLATE/kryoptic.sql" "$D/kryoptic.sql"
printf '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "%s"\n' "$D/kryoptic.sql" >"$D/kryoptic.conf"
export KRYOPTIC_CONF=$D/kryoptic.conf

# The test binary's name without cargo's hash: which suite this is.
suite=$(basename "$1")
suite=${suite%-*}
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
    # A port pair of its own: nextest numbers the tests running at once; else by process ID.
    slot=${NEXTEST_TEST_GLOBAL_SLOT:-$(($$ % 4000))}
    bash "$CAKEYS_TPM_ENV_SH" up "$D/tpm" $((24000 + 2 * slot)) || {
      tail -n 20 "$D"/tpm/*.log >&2
      exit 1
    }
    # shellcheck source=/dev/null
    . "$D/tpm/env"
  fi
  ;;
esac

"$@"
