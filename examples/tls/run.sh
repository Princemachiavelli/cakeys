#!/usr/bin/env bash
# examples/tls on a software TPM: the key is born in the TPM, a CSR is made from it, and a TLS
# server holding nothing but the key file `cakeys check` wrote completes a handshake. Then the
# key is swapped behind cakeys' back, and the check that gates the server fails. Each step
# states the exit code it expects (examples/lib.sh): checks.examples runs it.
#
# Needs TPM2_PKCS11_MODULE, PKCS11_PROVIDER_DIR (pkcs11-provider's ossl-modules), and on PATH
# cakeys, pkcs11-tool, openssl and the TPM stack nix/tpm2-test-env.sh starts.
# shellcheck source=examples/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

tpm_token web
export WEB_TPM_PIN_FILE=$work/pin
install -m 644 "$examples/tls/keys.toml" keys.toml
export CAKEYS_CONFIG=$work/keys.toml
module=(--module "tpm=$TPM2_PKCS11_MODULE")

# Born in the TPM, recorded in keys.lock: commit the lock beside keys.toml.
expect 0 cakeys "${module[@]}" create web-tls
# What the server is given: pkcs11-provider's key file, the URI the check verified with the PIN
# by reference. On NixOS the check unit writes it (configuration.nix).
expect 0 cakeys "${module[@]}" check web-tls --format pkcs11-provider-pem --uri-pin source
cp stdout web-tls.pem

# A CSR signed by the TPM key, for the CA. Here a throwaway CA stands in for ACME.
openssl_pkcs11 "$TPM2_PKCS11_MODULE"
expect 0 openssl req -new -key web-tls.pem -subj /CN=localhost -out web.csr
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -subj "/CN=example CA" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -days 1 -out ca.pem 2>/dev/null
printf 'subjectAltName = DNS:localhost\n' >san.cnf
expect 0 openssl x509 -req -in web.csr -CA ca.pem -CAkey ca.key -days 1 -extfile san.cnf -out web.pem

# The server: its certificate from a file, its key in the TPM. One connection, then it exits.
port=${TLS_PORT:-24443}
openssl s_server -accept "127.0.0.1:$port" -cert web.pem -key web-tls.pem -naccept 1 -quiet >server.log 2>&1 &
server=$!
for _ in $(seq 100); do
  [[ $(<server.log) == *ACCEPT* ]] && break
  kill -0 "$server" 2>/dev/null || break
  sleep 0.1
done
expect 0 openssl s_client -connect "127.0.0.1:$port" -CAfile ca.pem -verify_hostname localhost \
  -verify_return_error -brief </dev/null
wait "$server" || true

# Swap the key behind cakeys' back, as a wiped or tampered TPM store would: another key under
# the same label and ID. The check that gates the server says so (10), so it never starts.
tpm=(--module "$TPM2_PKCS11_MODULE" --token-label web --login --pin 1234)
pkcs11-tool "${tpm[@]}" --delete-object --type privkey --label web-tls >/dev/null 2>&1
pkcs11-tool "${tpm[@]}" --delete-object --type pubkey --label web-tls >/dev/null 2>&1
pkcs11-tool "${tpm[@]}" --keypairgen --key-type EC:prime256v1 --label web-tls --id 01 --usage-sign >/dev/null 2>&1
expect 10 cakeys "${module[@]}" check web-tls --format pkcs11-provider-pem --uri-pin source
