#!/usr/bin/env bash
# Cross-version check (docs/REFACTOR-2026-11-12.md, R0): a lock recorded by one cakeys build must
# verify, compare and re-record byte-identically with another. The integration tests write their
# locks with the code under test, so they cannot see format drift; this can.
#
#   scripts/xversion.sh record <old-cakeys> <dir>   # fresh SoftHSM token, objects of every class, lock
#   scripts/xversion.sh check  <new-cakeys> <dir>   # verify, compare-only realise, re-record, diff
#
# The lock layout changed once, in place (WORKPLAN.md stage 1: the [observations] table): a lock
# recorded by an older build has `provenance.module` per realisation and does not load here. So
# <old-cakeys> must be built at or after that change; `check` refuses an older base lock by name.
#
# Needs softhsm2-util and pkcs11-tool on PATH (the dev shell has both).
set -euo pipefail

mode=$1 bin=$(realpath "$2") dir=$3
module=${XV_MODULE:-$(dirname "$(dirname "$(command -v softhsm2-util)")")/lib/softhsm/libsofthsm2.so}
fixtures=$(dirname "$(realpath "$0")")/../crates/cli/tests/fixtures
specs=(ec ecpub rsa ed aes hmac wrapped cert data)
export SOFTHSM2_CONF=$dir/softhsm2.conf

km() { "$bin" --config "$dir/keys.toml" "$@"; }

record() {
  rm -rf "$dir" && mkdir -p "$dir/tokens"
  printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$dir/tokens" >"$SOFTHSM2_CONF"
  softhsm2-util --init-token --free --label xv --pin 1234 --so-pin 5678 >/dev/null
  printf 1234 >"$dir/pin"
  local p11=(pkcs11-tool --module "$module" --token-label xv --login --pin 1234)
  "${p11[@]}" --write-object "$fixtures/adopt-cert.der" --type cert --label cert >/dev/null
  printf 'xversion data' >"$dir/data.bin"
  "${p11[@]}" --write-object "$dir/data.bin" --type data --label data >/dev/null
  cat >"$dir/keys.toml" <<EOF
[tokens.soft]
module = "$module"
tokenLabel = "xv"
pinFile = "$dir/pin"

[objects.ec]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "P-256"
[objects.ecpub]
class = "CKO_PUBLIC_KEY"
keyType = "CKK_EC"
curve = "secp256r1"
[objects.rsa]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
modulusBits = 2048
[objects.ed]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC_EDWARDS"
curve = "edwards25519"
[objects.aes]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32
[objects.hmac]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32
[objects.wrapped]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 16
[objects.cert]
class = "CKO_CERTIFICATE"
certificateType = "CKC_X_509"
[objects.data]
class = "CKO_DATA"

[specs.ec]
object = "ec"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
publicAttributes = { CKA_VERIFY = true }
tokens.soft = { locator = { CKA_LABEL = "ec", CKA_ID = "0e" }, autoCreate = true }
[specs.ecpub]
object = "ecpub"
tokens.soft = { locator = { CKA_LABEL = "ec" } }
[specs.rsa]
object = "rsa"
attributes = { CKA_DECRYPT = true }
tokens.soft = { locator = { CKA_LABEL = "rsa" }, autoCreate = true, binding = "pop-decrypt" }
[specs.ed]
object = "ed"
attributes = { CKA_SIGN = true }
tokens.soft = { locator = { CKA_LABEL = "ed" }, autoCreate = true }
[specs.aes]
object = "aes"
attributes = { CKA_SIGN = true, CKA_ENCRYPT = true, CKA_EXTRACTABLE = false, CKA_ALLOWED_MECHANISMS = ["CKM_AES_ECB", "CKM_AES_CMAC"] }
tokens.soft = { locator = { CKA_LABEL = "aes" }, autoCreate = true }
[specs.hmac]
object = "hmac"
attributes = { CKA_SIGN = true }
tokens.soft = { locator = { CKA_LABEL = "hmac" }, autoCreate = true }
[specs.wrapped]
object = "wrapped"
attributes = { CKA_EXTRACTABLE = true }
tokens.soft = { locator = { CKA_LABEL = "wrapped" }, autoCreate = true }
[specs.cert]
object = "cert"
tokens.soft = { locator = { CKA_LABEL = "cert" } }
[specs.data]
object = "data"
tokens.soft = { locator = { CKA_LABEL = "data" } }
EOF
  for s in "${specs[@]}"; do
    km realise "$s" --token soft >"$dir/resolve.$s.json"
  done
  cp "$dir/keys.lock" "$dir/base.lock"
  echo "recorded ${#specs[@]} specs with $bin into $dir/base.lock"
}

check() {
  # The pre-observation-table layout (per-realisation provenance.module): not readable by a build
  # that has the table, so the comparison would only report that.
  if [[ $(<"$dir/base.lock") == *".provenance.module]"* ]]; then
    echo "$dir/base.lock has the lock layout before the observation table; record it with a newer build" >&2
    exit 1
  fi
  cp "$dir/base.lock" "$dir/keys.lock"
  for s in "${specs[@]}"; do
    km verify "$s" --token soft >/dev/null
    km realise "$s" --token soft --no-update-lock >/dev/null
    km resolve "$s" --token soft | diff -u "$dir/resolve.$s.json" - || {
      echo "resolve output of $s changed" >&2
      exit 1
    }
    km realise "$s" --token soft >/dev/null 2>&1
  done
  diff -u "$dir/base.lock" "$dir/keys.lock" || {
    echo "re-recording changed the lock" >&2
    exit 1
  }
  echo "ok: ${#specs[@]} specs verify, compare and re-record byte-identically with $bin"
}

"$mode"
