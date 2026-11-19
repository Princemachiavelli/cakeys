#!/usr/bin/env bash
# Serve SoftHSM token `kmp11` (user PIN 1234) through `p11-kit server` for the forwarding tests.
#
#   p11kit-test-env.sh up <dir>     init the token (in $SOFTHSM2_CONF), start the server, write <dir>/env
#   p11kit-test-env.sh down <dir>   stop the server, and wait until it is gone
#
# Needs softhsm2-util and p11-kit on PATH, and the SoftHSM module path in $SOFTHSM_MODULE. <dir>
# must be short: the socket path has to fit in sun_path (about 107 bytes).
set -euo pipefail

cmd=${1:-} D=${2:-}
[ -n "$D" ] || {
  echo "usage: $0 up|down <dir>" >&2
  exit 2
}

# Whether process $1 still runs: a zombie (exited, not yet reaped by whoever inherited it) does
# not. /proc is Linux's; elsewhere `kill -0` alone answers.
alive() {
  kill -0 "$1" 2>/dev/null || return 1
  local stat
  stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 0
  case ${stat##*) } in
  Z*) return 1 ;;
  esac
}

case $cmd in
up)
  mkdir -p "$D"
  softhsm2-util --init-token --free --label kmp11 --pin 1234 --so-pin 5678 >/dev/null
  p11-kit server -f -n "$D/p11.sock" --provider "$SOFTHSM_MODULE" 'pkcs11:token=kmp11' \
    </dev/null >"$D/server.log" 2>&1 &
  pid=$!
  echo "$pid" >"$D/server.pid"
  # Ready once the socket is there and the server still runs: one that died (after making the
  # socket or before) is reported now, with its log, not as a later connection error.
  for _ in $(seq 50); do
    alive "$pid" || break
    [ -S "$D/p11.sock" ] && break
    sleep 0.1
  done
  if ! [ -S "$D/p11.sock" ] || ! alive "$pid"; then
    echo "p11kit-test-env: p11-kit server did not come up:" >&2
    cat "$D/server.log" >&2
    exit 1
  fi
  echo "export P11_KIT_SERVER_ADDRESS='unix:path=$D/p11.sock'" >"$D/env"
  ;;
down)
  # Gone before returning: the caller (nix/test-tokens.sh) removes <dir> next, with the
  # server's socket and SoftHSM's files in it. SIGKILL for one still there after 5 s.
  [ -f "$D/server.pid" ] || exit 0
  pid=$(cat "$D/server.pid")
  kill "$pid" 2>/dev/null || exit 0
  for _ in $(seq 50); do
    alive "$pid" || exit 0
    sleep 0.1
  done
  echo "p11kit-test-env: p11-kit server ($pid) ignored SIGTERM for 5 s: SIGKILL" >&2
  kill -KILL "$pid" 2>/dev/null || true
  for _ in $(seq 20); do
    alive "$pid" || exit 0
    sleep 0.1
  done
  ;;
*)
  echo "usage: $0 up|down <dir>" >&2
  exit 2
  ;;
esac
