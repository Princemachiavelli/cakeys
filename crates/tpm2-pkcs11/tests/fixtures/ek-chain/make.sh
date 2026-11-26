#!/usr/bin/env bash
# This script writes the certificates for the test an_ek_chain_longer_than_max_links_is_refused
# in crates/tpm2-pkcs11/src/attest/ek.rs (review 2026-11-24 L5). It creates a self-signed root,
# a chain of three CAs under it (root -> ca-1 -> ca-2 -> ca-3), and two EK certificates whose
# extendedKeyUsage is tcg-kp-EKCertificate (2.23.133.8.1). The certificate ek-3 is signed by ca-2,
# so its chain to the root has three signatures, which is MAX_LINKS. The certificate ek-4 is signed
# by ca-3, so its chain has four signatures, one more than MAX_LINKS. All certificates are valid,
# so the two chains differ only in their length.
#
# The output is reproducible. Each P-256 key is derived from its name (the SHA-256 hash of
# "cakeys ek-chain <name>"), each signature is deterministic ECDSA (RFC 6979, which needs OpenSSL
# 3.2 or later, as in the dev shell), and the dates and serial numbers are fixed. The keys are
# test keys and the script does not keep them. Run it from the repository root in the dev shell:
# `crates/tpm2-pkcs11/tests/fixtures/ek-chain/make.sh crates/tpm2-pkcs11/tests/fixtures/ek-chain`.
set -euo pipefail
mkdir -p "$1"
out=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

cat >ext.cnf <<'CNF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = placeholder
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign
[ek]
basicConstraints = CA:FALSE
keyUsage = critical, keyEncipherment
extendedKeyUsage = 2.23.133.8.1
CNF

dates=(-not_before 20260101000000Z -not_after 20460101000000Z)
serial=0

# key NAME CN: derives the P-256 key NAME.key from NAME and writes the request config NAME.cnf
# with the subject CN.
key() {
  local scalar
  scalar=$(printf 'cakeys ek-chain %s' "$1" | openssl dgst -sha256 -r | cut -d' ' -f1)
  printf 'asn1=SEQUENCE:k\n[k]\nversion=INTEGER:1\nkey=FORMAT:HEX,OCTETSTRING:%s\ncurve=EXPLICIT:0,OID:prime256v1\n' \
    "$scalar" >"$1.asn1"
  openssl asn1parse -genconf "$1.asn1" -noout -out "$1.der"
  openssl ec -inform DER -in "$1.der" -out "$1.key" 2>/dev/null
  sed "s/^CN = placeholder$/CN = $2/" ext.cnf >"$1.cnf"
}

# root NAME CN: writes the self-signed CA certificate NAME.pem with the subject CN.
root() {
  key "$1" "$2"
  serial=$((serial + 1))
  openssl req -new -x509 -key "$1.key" -config "$1.cnf" -extensions ca -sha256 -sigopt nonce-type:1 \
    -set_serial "$serial" "${dates[@]}" -out "$1.pem"
}

# issued NAME CN ISSUER SECTION: writes the certificate NAME.pem with the subject CN, signed by
# ISSUER, with the extensions of the config section SECTION (ca or ek).
issued() {
  key "$1" "$2"
  serial=$((serial + 1))
  openssl req -new -key "$1.key" -config "$1.cnf" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA "$3.pem" -CAkey "$3.key" -sha256 -sigopt nonce-type:1 \
    -set_serial "$serial" "${dates[@]}" -extfile ext.cnf -extensions "$4" -out "$1.pem" 2>/dev/null
}

root root 'cakeys ek-chain root'
issued ca-1 'cakeys ek-chain CA 1' root ca
issued ca-2 'cakeys ek-chain CA 2' ca-1 ca
issued ca-3 'cakeys ek-chain CA 3' ca-2 ca
issued ek-3 'cakeys ek-chain EK 3' ca-2 ek
issued ek-4 'cakeys ek-chain EK 4' ca-3 ek

for f in root ca-1 ca-2 ca-3 ek-3 ek-4; do
  cp "$f.pem" "$out/$f.pem"
done
