#!/usr/bin/env bash
# Start a software TPM for the tpm2-pkcs11 tests and create token `kmtest` (user PIN 1234).
#
#   tpm2-test-env.sh up <dir> [port]   start swtpm + private D-Bus + tpm2-abrmd; write <dir>/env
#   tpm2-test-env.sh down <dir>        stop them (by PID file)
#
# Needs swtpm, dbus-daemon, tpm2-abrmd, tpm2_ptool and tpm2-tools on PATH. A resource manager is
# required: without one, tpm2_ptool runs out of TPM object slots. Daemons get /dev/null as stdin
# and log files as output, so callers using $(...) don't hang on their pipes.
set -euo pipefail

cmd=$1 D=$2 PORT=${3:-23211}
case $cmd in
up)
  mkdir -p "$D/state" "$D/store"
  swtpm socket --tpmstate dir="$D/state" --tpm2 \
    --server type=tcp,port="$PORT" --ctrl type=tcp,port=$((PORT + 1)) \
    --flags not-need-init,startup-clear --daemon --pid file="$D/swtpm.pid" --log file="$D/swtpm.log"
  # A private bus from dbus's own session.conf (the Nix sandbox has no /etc/dbus-1), on an
  # abstract socket so long directory names don't hit the 108-byte socket path limit.
  conf="$(dirname "$(dirname "$(readlink -f "$(command -v dbus-daemon)")")")/share/dbus-1/session.conf"
  dbus-daemon --config-file="$conf" --address="unix:abstract=cakeys-tpm-$$-$PORT" \
    --fork --print-address=3 --print-pid=4 \
    3>"$D/dbus.addr" 4>"$D/dbus.pid" </dev/null >/dev/null 2>"$D/dbus.log"
  DBUS_SESSION_BUS_ADDRESS=$(head -1 "$D/dbus.addr")
  export DBUS_SESSION_BUS_ADDRESS
  tpm2-abrmd --session --tcti=swtpm:port="$PORT" --flush-all </dev/null >"$D/abrmd.log" 2>&1 &
  echo $! >"$D/abrmd.pid"
  tcti="$(dirname "$(dirname "$(command -v tpm2-abrmd)")")/lib/libtss2-tcti-tabrmd.so.0:bus_type=session"
  cat >"$D/env" <<E
export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'
export TPM2TOOLS_TCTI='$tcti' TPM2_PKCS11_TCTI='$tcti' TPM2_PKCS11_STORE='$D/store'
export TPM2_PKCS11_BACKEND=esysdb TSS2_LOG=all+NONE
E
  # shellcheck source=/dev/null
  . "$D/env"
  # Wait for the resource manager; each probe is bounded (a missing abrmd would block forever).
  for _ in $(seq 50); do timeout 2 tpm2_getcap properties-fixed >/dev/null 2>&1 && break; sleep 0.1; done
  timeout 5 tpm2_getcap properties-fixed >/dev/null
  tpm2_ptool init --path "$D/store" >/dev/null
  tpm2_ptool addtoken --pid=1 --label=kmtest --sopin=5678 --userpin=1234 --path "$D/store" >/dev/null
  ;;
down)
  for p in abrmd dbus swtpm; do
    [ -f "$D/$p.pid" ] && kill "$(cat "$D/$p.pid")" 2>/dev/null || true
  done
  ;;
*)
  echo "usage: $0 up|down <dir> [port]" >&2
  exit 2
  ;;
esac
