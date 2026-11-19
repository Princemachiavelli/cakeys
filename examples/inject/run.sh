#!/usr/bin/env bash
# examples/inject on a software TPM: openssl signs a CSR from a key *file* that is never written.
# unotify-inject answers its open of the file with what `cakeys check` prints at that moment
# (a seccomp user notification, a memfd injected as the descriptor), so the key it uses is one
# cakeys has just verified, and a failed check fails the open. Then the URI as the file's content,
# the count of opens, several paths from a rules file, and the key swapped behind cakeys' back.
# Each step states the exit code it expects (examples/lib.sh): checks.examples runs it.
#
# Needs TPM2_PKCS11_MODULE, PKCS11_PROVIDER_DIR (pkcs11-provider's ossl-modules), and on PATH
# cakeys, pkcs11-tool, openssl, python3 and the TPM stack nix/tpm2-test-env.sh starts.
# shellcheck source=examples/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

inject=(python3 "$examples/inject/unotify-inject") # by interpreter: the build sandbox has no /usr/bin/env
tpm_token inject
export INJECT_PIN_FILE=$work/pin
install -m 644 "$examples/inject/keys.toml" keys.toml
export CAKEYS_CONFIG=$work/keys.toml
module=(--module "tpm=$TPM2_PKCS11_MODULE")
# What the program is given, as the commands print it: pkcs11-provider's key file, and the bare
# URI. Each runs at every open of the path (`sh -c`, here, not in the program).
check_pem="cakeys --module tpm=$TPM2_PKCS11_MODULE check signing --format pkcs11-provider-pem --uri-pin source"
check_uri="cakeys --module tpm=$TPM2_PKCS11_MODULE check signing --uri-pin source"

expect 0 cakeys "${module[@]}" create signing
openssl_pkcs11 "$TPM2_PKCS11_MODULE"

# The path must exist, as openssl stats it before it opens it; what is in it is never read.
: >signing.pem
expect 1 openssl req -new -key signing.pem -subj /CN=injected -out empty.csr

# The same command, its one open of the file answered by the check: the CSR is signed by the key
# in the TPM, and its signature verifies against the public key the CSR carries.
expect 0 "${inject[@]}" "$work/signing.pem" "$check_pem" 1 -- openssl req -new -key signing.pem -subj /CN=injected -out signing.csr
expect 0 openssl req -in signing.csr -verify -noout
[ ! -s signing.pem ] # still the placeholder: nothing was written where the program read from

# What a program that reads a URI is given: the string, from a file that is not there.
expect 0 "${inject[@]}" "$work/signing.uri" "$check_uri" 1 -- cat signing.uri
[[ $(<stdout) == pkcs11:* ]] || {
  echo "  → not a URI"
  exit 1
}

# Opens are counted. A program that opened the file once, where two were due, and one that opens
# it again, where it was due once, both fail the run (125), and the second open is refused.
expect 125 "${inject[@]}" "$work/signing.uri" "$check_uri" 2 -- cat signing.uri
expect 125 "${inject[@]}" "$work/signing.uri" "$check_uri" 1 -- sh -c 'cat signing.uri; cat signing.uri'

# Several paths, each with its own command and count, from a rules file: the key file once and
# the URI twice, in one program. (TOML literal strings: the commands hold quotes of their own.)
cat >rules.toml <<EOF
[[inject]]
path = "$work/signing.pem"
command = '$check_pem'
reads = 1

[[inject]]
path = "$work/signing.uri"
command = '$check_uri'
reads = 2
EOF
two='openssl req -new -key signing.pem -subj /CN=both -out both.csr && cat signing.uri signing.uri'
expect 0 "${inject[@]}" --rules rules.toml -- sh -c "$two"
expect 0 openssl req -in both.csr -verify -noout
# One rule's count is not another's: the URI read once, where the rules file wants it twice.
expect 125 "${inject[@]}" --rules rules.toml -- sh -c 'openssl req -new -key signing.pem -subj /CN=one -out one.csr && cat signing.uri'

# Another key under the same label and ID, as a wiped or tampered TPM store would have it. The
# check says so (10) when the program opens the file; the open fails, the program never holds a
# key, and the run ends with the check's code.
tpm=(--module "$TPM2_PKCS11_MODULE" --token-label inject --login --pin 1234)
pkcs11-tool "${tpm[@]}" --delete-object --type privkey --label signing >/dev/null 2>&1
pkcs11-tool "${tpm[@]}" --delete-object --type pubkey --label signing >/dev/null 2>&1
pkcs11-tool "${tpm[@]}" --keypairgen --key-type EC:prime256v1 --label signing --id 01 --usage-sign >/dev/null 2>&1
expect 10 "${inject[@]}" "$work/signing.pem" "$check_pem" 1 -- openssl req -new -key signing.pem -subj /CN=swapped -out swapped.csr
[ ! -e swapped.csr ]
