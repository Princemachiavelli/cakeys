#!/usr/bin/env bash
# examples/every-object/keys.toml played on throwaway tokens: SoftHSM, kryoptic, and
# tpm2-pkcs11 over swtpm. Every key is born on soft, every file-born object arrives there
# first, and everything then moves to kryo (sealed) and to tpm (through the host). Each step
# states the exit code it expects (examples/lib.sh): checks.examples runs it.
#
# Needs SOFTHSM_MODULE, KRYOPTIC_MODULE, TPM2_PKCS11_MODULE, and on PATH cakeys, camigrate,
# softhsm2-util, pkcs11-tool, openssl and the TPM stack nix/tpm2-test-env.sh starts.
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

# Every pair checked against its token's profiles, no token opened: the YubiKey's too.
expect 0 cakeys validate
# Every key whose pair on soft says origin = "create", made and recorded; then kryo's
# transport key, whose public half the lock records for sealing to it.
expect 0 cakeys create --token soft
expect 0 cakeys create --token kryo
# The objects born in files, onto soft (the HMAC key's file is plaintext: hence the flag), and
# the HMAC key onto kryo from the same file.
expect 0 camigrate import --token soft --allow-host-plaintext
expect 0 camigrate import hmac-sha256 --token kryo --allow-host-plaintext

# ── Moved ─────────────────────────────────────────────────────────────────────────────────

# The plan first, for everything soft holds: per object the method and what it exposes, or why
# it stays. Some stay (the DES3 key is not extractable, the HMAC key reached kryo from its
# file), so the plan as a whole is 15; then each object that can go, by name.
limit=60 expect 15 camigrate migrate --from soft --to kryo --dry-run
for o in p256 p384 p521 ed25519 ed448 rsa2048 rsa4096 aes256 generic cert pubkey note; do
  expect 0 camigrate migrate "$o" --from soft --to kryo
done
# tpm2-pkcs11 imports only plaintext, so its keys pass through camigrate's memory: said, and
# allowed per run. A TPM takes fewer types; the plan says which and why.
limit=60 expect 15 camigrate migrate --from soft --to tpm --dry-run --allow-host-plaintext
for o in p256 p384 rsa2048 cert; do
  expect 0 camigrate migrate "$o" --from soft --to tpm --allow-host-plaintext
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
