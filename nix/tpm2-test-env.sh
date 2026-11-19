#!/usr/bin/env bash
# Start a software TPM for the tpm2-pkcs11 tests and create token `kmtest` (user PIN 1234).
#
#   tpm2-test-env.sh up <dir> [port]   start swtpm + private D-Bus + tpm2-abrmd; write <dir>/env
#   tpm2-test-env.sh down <dir>        stop them (by PID file)
#   tpm2-test-env.sh device-up <dir> [persistent]
#                                      the host's real TPM instead: nix/ftpm-test-env.sh's `up`,
#                                      which says what it is safe for. Never call it directly.
#
# Needs swtpm, dbus-daemon, tpm2-abrmd, tpm2_ptool and tpm2-tools on PATH. A resource manager is
# required: without one, tpm2_ptool runs out of TPM object slots. Daemons get /dev/null as stdin
# and log files as output, so callers using $(...) don't hang on their pipes. An `up` that fails
# stops what it started before it exits, so a caller needs no `down` for it.
set -euo pipefail

cmd=${1:-} D=${2:-}

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

# Stop the daemons <dir>'s PID files name, each gone before the next: swtpm writes its state on
# the way out, and the caller (nix/test-tokens.sh) removes the directory next ("Directory not
# empty" otherwise). SIGTERM, and SIGKILL for one still there after 5 s.
stop() {
  local p pid
  for p in abrmd dbus swtpm; do
    [ -f "$1/$p.pid" ] || continue
    pid=$(cat "$1/$p.pid")
    kill "$pid" 2>/dev/null || continue
    for _ in $(seq 50); do
      alive "$pid" || continue 2
      sleep 0.1
    done
    echo "tpm2-test-env: $p ($pid) ignored SIGTERM for 5 s: SIGKILL" >&2
    kill -KILL "$pid" 2>/dev/null || true
    for _ in $(seq 20); do
      alive "$pid" || continue 2
      sleep 0.1
    done
  done
}

# A private D-Bus and tpm2-abrmd on it over TCTI $2, with abrmd's further flags after $4; writes
# <dir>/env (with $4 appended to its last export line), sources it, and waits for the resource
# manager. Shared by the software and the device TPM, so the two cannot drift apart.
abrmd_up() {
  local dir=$1 tpm_tcti=$2 bus=$3 marker=$4 conf tcti
  shift 4
  # A private bus from dbus's own session.conf (the Nix sandbox has no /etc/dbus-1), on an
  # abstract socket so long directory names don't hit the 108-byte socket path limit.
  conf="$(dirname "$(dirname "$(readlink -f "$(command -v dbus-daemon)")")")/share/dbus-1/session.conf"
  dbus-daemon --config-file="$conf" --address="unix:abstract=$bus" \
    --fork --print-address=3 --print-pid=4 \
    3>"$dir/dbus.addr" 4>"$dir/dbus.pid" </dev/null >/dev/null 2>"$dir/dbus.log"
  DBUS_SESSION_BUS_ADDRESS=$(head -1 "$dir/dbus.addr")
  export DBUS_SESSION_BUS_ADDRESS
  tpm2-abrmd --session --tcti="$tpm_tcti" "$@" </dev/null >"$dir/abrmd.log" 2>&1 &
  echo $! >"$dir/abrmd.pid"
  tcti="$(dirname "$(dirname "$(command -v tpm2-abrmd)")")/lib/libtss2-tcti-tabrmd.so.0:bus_type=session"
  cat >"$dir/env" <<E
export DBUS_SESSION_BUS_ADDRESS='$DBUS_SESSION_BUS_ADDRESS'
export TPM2TOOLS_TCTI='$tcti' TPM2_PKCS11_TCTI='$tcti' TPM2_PKCS11_STORE='$dir/store'
export TPM2_PKCS11_BACKEND=esysdb TSS2_LOG=all+NONE$marker
E
  # shellcheck source=/dev/null
  . "$dir/env"
  # Wait for the resource manager; each probe is bounded (a missing abrmd would block forever).
  for _ in $(seq 50); do
    timeout 2 tpm2_getcap properties-fixed >/dev/null 2>&1 && break
    sleep 0.1
  done
  timeout 5 tpm2_getcap properties-fixed >/dev/null
}

case $cmd in
up)
  [ -n "$D" ] || {
    echo "usage: $0 up <dir> [port]" >&2
    exit 2
  }
  PORT=${3:-23211}
  mkdir -p "$D/state" "$D/store"
  trap 'stop "$D"' EXIT
  # The TPM profile is pinned, not left to swtpm's default: it sets what the TPM generates
  # (default-v1 caps RSA at 3072, default-v2 allows 4096), and profiles/hardware/swtpm.toml and
  # the tpm2-pkcs11/1.10+swtpm pair were measured on default-v1.
  swtpm socket --tpmstate dir="$D/state" --tpm2 --profile name=default-v1 \
    --server type=tcp,port="$PORT" --ctrl type=tcp,port=$((PORT + 1)) \
    --flags not-need-init,startup-clear --daemon --pid file="$D/swtpm.pid" --log file="$D/swtpm.log"
  # CAKEYS_TPM_SWTPM: this is the software TPM, where the tests may change TPM state (tpm2.rs
  # `on_swtpm`, which also asks the TPM).
  abrmd_up "$D" swtpm:port="$PORT" "cakeys-tpm-$$-$PORT" " CAKEYS_TPM_SWTPM=1" --flush-all
  tpm2_ptool init --path "$D/store" >/dev/null
  tpm2_ptool addtoken --pid=1 --label=kmtest --sopin=5678 --userpin=1234 --path "$D/store" >/dev/null
  trap - EXIT
  ;;
device-up)
  # The store is removed and remade: refuse anything but an absolute directory of its own.
  case $D in
  /?*) ;;
  *)
    echo "usage: $0 device-up <absolute dir> [persistent]" >&2
    exit 2
    ;;
  esac
  case ${3:-} in
  "" | persistent) ;;
  *)
    echo "usage: $0 device-up <absolute dir> [persistent]" >&2
    exit 2
    ;;
  esac
  rm -rf "$D/store"
  mkdir -p "$D/store"
  trap 'stop "$D"' EXIT
  # The kernel resource manager, never /dev/tpm0; no --flush-all (other users' sessions), and no
  # CAKEYS_TPM_SWTPM: this TPM is not the tests' to change.
  abrmd_up "$D" device:/dev/tpmrm0 "cakeys-ftpm-$$" ""
  if [ "${3:-}" = persistent ]; then
    tpm2_ptool init --primary-handle=0x81000001 --path "$D/store" >/dev/null
  else
    tpm2_ptool init --transient-parent tpm2-tools-ecc-default --path "$D/store" >/dev/null
  fi
  tpm2_ptool addtoken --pid=1 --label=kmtest --sopin=5678 --userpin=1234 --path "$D/store" >/dev/null
  trap - EXIT
  ;;
down)
  [ -n "$D" ] || {
    echo "usage: $0 down <dir>" >&2
    exit 2
  }
  stop "$D"
  ;;
*)
  echo "usage: $0 up|down <dir> [port]" >&2
  exit 2
  ;;
esac
