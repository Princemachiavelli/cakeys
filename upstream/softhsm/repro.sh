#!/usr/bin/env bash
# SoftHSMv2 #628 reproduction against a libsofthsm2.so (default: nixpkgs' SoftHSM):
#   upstream/softhsm/repro.sh [path/to/libsofthsm2.so]
# Needs softhsm2-util and python-pkcs11 on PATH/PYTHONPATH (checks.softhsm-unwrap-value-len
# arranges both). Exits 1 while the module leaves CKA_VALUE_LEN at 0 on an unwrapped key.
set -euo pipefail

module=${1:-$(dirname "$(dirname "$(readlink -f "$(command -v softhsm2-util)")")")/lib/softhsm/libsofthsm2.so}
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
export SOFTHSM2_CONF=$dir/softhsm2.conf
mkdir "$dir/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$dir/tokens" >"$SOFTHSM2_CONF"
softhsm2-util --init-token --free --label repro --pin 1234 --so-pin 5678 >/dev/null

python3 "$(dirname "$0")/repro.py" "$module" repro 1234
