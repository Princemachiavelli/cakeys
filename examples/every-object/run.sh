#!/usr/bin/env bash
# examples/every-object/keys.toml played on throwaway tokens: SoftHSM, kryoptic, and
# tpm2-pkcs11 over swtpm. Every key is born on soft, every file-born object arrives there
# first, and everything then moves to kryo (sealed) and to tpm (through the host). Each step
# states the exit code it expects (examples/lib.sh): checks.examples runs it.
#
# Needs SOFTHSM_MODULE, KRYOPTIC_MODULE, TPM2_PKCS11_MODULE, and on PATH cakeys, camigrate,
# softhsm2-util, pkcs11-tool, openssl, jq and the TPM stack nix/tpm2-test-env.sh starts.
# shellcheck source=examples/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

softhsm_token every-object
kryoptic_token every-object
tpm_token every-object
export EXAMPLE_PIN_FILE=$work/pin

# The objects born in files.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout cert-key.pem \
  -subj /CN=every-object -days 1 -out cert.pem 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 2>/dev/null | openssl pkey -pubout -out pubkey.pem
echo "every object, pinned by its hash" >note.txt
openssl rand -out hmac.key 32
export EXAMPLE_CERT=$work/cert.pem EXAMPLE_PUBKEY=$work/pubkey.pem EXAMPLE_NOTE=$work/note.txt EXAMPLE_HMAC=$work/hmac.key

# keys.lock is written beside keys.toml: a copy here, so the example directory stays as it is.
install -m 644 "$examples/every-object/keys.toml" keys.toml
export CAKEYS_CONFIG=$work/keys.toml

# ── Born ──────────────────────────────────────────────────────────────────────────────────

# Every pair checked against its token's profiles, no token opened: the YubiKey's too. So no
# PIN file is read, and the variable naming it need not be set.
expect 0 env -u EXAMPLE_PIN_FILE cakeys --new-lock validate
expect 0 cakeys --new-lock validate
# Every key whose pair on soft says origin = "create", made and recorded; then kryo's
# transport key, whose public half the lock records for sealing to it.
expect 22 cakeys --new-lock create --token soft
expect 22 cakeys create --token kryo
# The objects born in files, onto soft (the HMAC key's file is plaintext: hence the flag), and
# the HMAC key onto kryo from the same file.
expect 22 camigrate import --to soft --allow-host-plaintext
expect 22 camigrate import hmac-sha256 --to kryo --allow-host-plaintext

# ── Moved ─────────────────────────────────────────────────────────────────────────────────

# The plan first, for everything soft holds: per object the method and what it exposes, or why
# it stays. Some stay (the DES3 key is not extractable, the HMAC key reached kryo from its
# file), so the plan as a whole is 15; then each object that can go, by name.
limit=60 expect 15 camigrate migrate --from soft --to kryo --dry-run
# The objects a plan says can go (its JSON's ready ones), sorted: what the loops below move. They
# must be the ones written here, so an object added to keys.toml, or one a plan stops moving,
# fails the example instead of going unmigrated without a word.
movable() {
  local plan code=0
  plan=$(camigrate migrate --from soft --to "$1" --dry-run --json "${@:2}") || code=$?
  [ "$code" = 15 ] || {
    echo "  → the plan for $1 exited $code, expected 15" >&2
    exit 1
  }
  jq -r '.plans[] | select(.ready) | .object' <<<"$plan" | sort | paste -sd' ' -
}
want_movable() {
  [ "$2" = "$3" ] || {
    echo "  → the plan for $1 moves: $2; the example expects: $3" >&2
    exit 1
  }
}
moves=$(movable kryo)
want_movable kryo "$moves" "aes256 cert ed25519 ed448 generic note p256 p384 p521 pubkey rsa2048 rsa4096"
for o in $moves; do
  expect 22 camigrate migrate "$o" --from soft --to kryo
done
# tpm2-pkcs11 imports only plaintext, so its keys pass through camigrate's memory: said, and
# allowed per run. A TPM takes fewer types; the plan says which and why.
limit=60 expect 15 camigrate migrate --from soft --to tpm --dry-run --allow-host-plaintext
moves=$(movable tpm --allow-host-plaintext)
want_movable tpm "$moves" "cert p256 p384 rsa2048"
for o in $moves; do
  expect 22 camigrate migrate "$o" --from soft --to tpm --allow-host-plaintext
done

# ── Checked ───────────────────────────────────────────────────────────────────────────────

# Every pair on each token, against the lock: identity, policy and possession.
for t in soft kryo tpm; do
  expect 0 cakeys check --token "$t"
done
echo "One identity per object, wherever it is (the first scheme of each):"
awk '/^\[objects\.[a-z0-9-]+\.ids\]$/ {
  name = $0; sub(/^\[objects\./, "", name); sub(/\.ids\]$/, "", name)
  getline; printf "  %-15s %s\n", name, $0 }' keys.lock
