#!/usr/bin/env bash
# examples/programs on SoftHSM: a key made and pinned, then signed with from Python (sign.py)
# through the URI `cakeys check` hands back, the signature verified with the public key alone;
# and with the key swapped, the program refuses before it signs. Each step states the exit code
# it expects (examples/lib.sh): checks.examples runs it.
#
# Needs SOFTHSM_MODULE, and on PATH cakeys, softhsm2-util, pkcs11-tool, openssl and a python3
# with python-pkcs11.
# shellcheck source=examples/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

softhsm_token programs
export PROGRAMS_PIN_FILE=$work/pin
install -m 644 "$examples/programs/keys.toml" keys.toml
export CAKEYS_CONFIG=$work/keys.toml

expect 22 cakeys --new-lock create signing
echo "signed from Python" >message
expect 0 python3 "$examples/programs/sign.py" signing <message
cp stdout message.sig
# The public half, as anyone verifying would hold it.
soft=(--module "$SOFTHSM_MODULE" --token-label programs)
pkcs11-tool "${soft[@]}" --read-object --type pubkey --id 01 2>/dev/null | openssl pkey -pubin -inform DER -out signing.pub
expect 0 openssl dgst -sha256 -verify signing.pub -signature message.sig message

# The same program on a token whose PIN is an environment variable (`pinEnv`): the URI then
# names it, `pin-source=env:PROGRAMS_PIN`, and the program reads it there.
sed -i 's/^pinFile = .*/pinEnv = "PROGRAMS_PIN"/' keys.toml
export PROGRAMS_PIN=1234
expect 0 cakeys check signing --uri-module --uri-pin source
[[ $(<stdout) == *pin-source=env:PROGRAMS_PIN* ]] || {
  echo "  → the URI names no pin-source=env:PROGRAMS_PIN"
  exit 1
}
expect 0 python3 "$examples/programs/sign.py" signing <message
cp stdout message-env.sig
expect 0 openssl dgst -sha256 -verify signing.pub -signature message-env.sig message

# Another key under the same label and ID: the check fails (10), and so does the program, before
# it touches the key.
pkcs11-tool "${soft[@]}" --login --pin 1234 --delete-object --type privkey --id 01 >/dev/null 2>&1
pkcs11-tool "${soft[@]}" --login --pin 1234 --delete-object --type pubkey --id 01 >/dev/null 2>&1
pkcs11-tool "${soft[@]}" --login --pin 1234 --keypairgen --key-type EC:prime256v1 --label signing --id 01 \
  --usage-sign >/dev/null 2>&1
expect 10 python3 "$examples/programs/sign.py" signing <message
