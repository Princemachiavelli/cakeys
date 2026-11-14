#!/usr/bin/env bash
# The host's real TPM for the opt-in tests (crates/cli/tests/ftpm.rs): a private tpm2-abrmd over
# the kernel resource manager, and a fresh tpm2-pkcs11 store with token `kmtest` (user PIN 1234).
#
#   ftpm-test-env.sh up <dir>     start a private D-Bus + tpm2-abrmd; new store; write <dir>/env
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
# Needs dbus-daemon, tpm2-abrmd, tpm2_ptool and tpm2-tools on PATH.
set -euo pipefail

cmd=$1 D=$2
case $cmd in
up)
  rm -rf "$D/store"
  mkdir -p "$D/store"
  conf="$(dirname "$(dirname "$(readlink -f "$(command -v dbus-daemon)")")")/share/dbus-1/session.conf"
  dbus-daemon --config-file="$conf" --address="unix:abstract=cakeys-ftpm-$$" \
    --fork --print-address=3 --print-pid=4 \
    3>"$D/dbus.addr" 4>"$D/dbus.pid" </dev/null >/dev/null 2>"$D/dbus.log"
  DBUS_SESSION_BUS_ADDRESS=$(head -1 "$D/dbus.addr")
  export DBUS_SESSION_BUS_ADDRESS
  tpm2-abrmd --session --tcti=device:/dev/tpmrm0 </dev/null >"$D/abrmd.log" 2>&1 &
  echo $! >"$D/abrmd.pid"
  tcti="$(dirname "$(dirname "$(command -v tpm2-abrmd)")")/lib/libtss2-tcti-tabrmd.so.0:bus_type=session"
  cat >"$D/env" <<E
export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'
export TPM2TOOLS_TCTI='$tcti' TPM2_PKCS11_TCTI='$tcti' TPM2_PKCS11_STORE='$D/store'
export TPM2_PKCS11_BACKEND=esysdb TSS2_LOG=all+NONE
E
  # shellcheck source=/dev/null
  . "$D/env"
  for _ in $(seq 50); do
    timeout 2 tpm2_getcap properties-fixed >/dev/null 2>&1 && break
    sleep 0.1
  done
  timeout 5 tpm2_getcap properties-fixed >/dev/null
  tpm2_ptool init --transient-parent tpm2-tools-ecc-default --path "$D/store" >/dev/null
  tpm2_ptool addtoken --pid=1 --label=kmtest --sopin=5678 --userpin=1234 --path "$D/store" >/dev/null
  ;;
down)
  for p in abrmd dbus; do
    [ -f "$D/$p.pid" ] && kill "$(cat "$D/$p.pid")" 2>/dev/null || true
  done
  ;;
*)
  echo "usage: $0 up|down <dir>" >&2
  exit 2
  ;;
esac
