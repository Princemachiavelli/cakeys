#!/usr/bin/env bash
# Serve SoftHSM token `kmp11` (user PIN 1234) through `p11-kit server` for the forwarding tests.
#
#   p11kit-test-env.sh up <dir>     init the token (in $SOFTHSM2_CONF), start the server, write <dir>/env
#   p11kit-test-env.sh down <dir>   stop the server
#
# Needs softhsm2-util and p11-kit on PATH, and the SoftHSM module path in $SOFTHSM_MODULE. <dir>
# must be short: the socket path has to fit in sun_path (about 107 bytes).
set -euo pipefail

cmd=$1 D=$2
case $cmd in
up)
  mkdir -p "$D"
  softhsm2-util --init-token --free --label kmp11 --pin 1234 --so-pin 5678 >/dev/null
  p11-kit server -f -n "$D/p11.sock" --provider "$SOFTHSM_MODULE" 'pkcs11:token=kmp11' \
    </dev/null >"$D/server.log" 2>&1 &
  echo $! >"$D/server.pid"
  for _ in $(seq 50); do [ -S "$D/p11.sock" ] && break; sleep 0.1; done
  [ -S "$D/p11.sock" ] || { cat "$D/server.log" >&2; exit 1; }
  echo "export P11_KIT_SERVER_ADDRESS='unix:path=$D/p11.sock'" >"$D/env"
  ;;
down)
  [ -f "$D/server.pid" ] && kill "$(cat "$D/server.pid")" 2>/dev/null || true
  ;;
*)
  echo "usage: $0 up|down <dir>" >&2
  exit 2
  ;;
esac
