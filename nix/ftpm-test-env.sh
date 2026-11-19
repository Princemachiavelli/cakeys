#!/usr/bin/env bash
# The host's real TPM for the opt-in tests (crates/cli/tests/ftpm.rs): a private tpm2-abrmd over
# the kernel resource manager, and a fresh tpm2-pkcs11 store with token `kmtest` (user PIN 1234).
#
#   ftpm-test-env.sh up <dir> [persistent]
#                                 start a private D-Bus + tpm2-abrmd; new store; write <dir>/env.
#                                 With `persistent`, the store's parent is the platform's storage
#                                 root key 0x81000001 (only read, never changed), which the
#                                 tpm-certify attestation needs; else a transient primary.
#   ftpm-test-env.sh down <dir>   stop them (by PID file); the store stays until <dir> is removed
#
# Safe on a TPM the platform depends on (measured boot, disk unlock):
# - The store's primary is transient (`--transient-parent`): nothing is made persistent and
#   nothing is written to NV. The platform's persistent handles are never touched.
# - tpm2-abrmd runs over /dev/tpmrm0 (needs only rw on it, e.g. the `tss` group), never
#   /dev/tpm0. The kernel resource manager alone allows 3 loaded objects per connection, which
#   tpm2-pkcs11 exhausts (profiles/modules/tpm2-pkcs11/1.10+amd-ftpm.toml, [manual]); abrmd
#   swaps them.
# - The tests log in with the right PIN only: a wrong one would count against the TPM's
#   dictionary-attack lockout, which every other user of the TPM shares.
# A fresh store per run: tpm2-pkcs11 leaves objects behind that it cannot destroy, and they
# change what the next probe can do.
#
# The D-Bus, tpm2-abrmd and environment setup, the cleanup of a failed `up` and the waiting
# `down` are nix/tpm2-test-env.sh's (`device-up`), shared with the software TPM. This script is
# the one way to reach the real TPM (docs/DEVELOPMENT.md, "Hardware rules"), and runs from a
# checkout only.
#
# Needs dbus-daemon, tpm2-abrmd, tpm2_ptool and tpm2-tools on PATH.
set -euo pipefail

usage() {
  echo "usage: $0 up <absolute dir> [persistent] | down <absolute dir>" >&2
  exit 2
}
cmd=${1:-} D=${2:-}
# `up` removes <dir>/store: never on an empty or relative <dir> (`up ""` would name /store).
case $D in
/?*) ;;
*) usage ;;
esac
env_sh=$(dirname "$(realpath "$0")")/tpm2-test-env.sh
case $cmd in
up)
  case ${3:-} in "" | persistent) ;; *) usage ;; esac
  exec bash "$env_sh" device-up "$D" ${3:+"$3"}
  ;;
down) exec bash "$env_sh" down "$D" ;;
*) usage ;;
esac
