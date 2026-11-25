#!/usr/bin/env bash
# Test chains for the walk's certificate rules (crates/core/src/chain.rs, review 2026-11-23 A-3):
# each differs from the valid `ok` chain in the one rule its test names. No secret: the keys are
# thrown away. From the repository root:
# `crates/core/tests/fixtures/chain-rules/make.sh crates/core/tests/fixtures/chain-rules`.
set -euo pipefail
mkdir -p "$1"
out=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

cat >ext.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = placeholder
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign
[ca_no_certsign]
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature
[ca_name_constraints]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign
nameConstraints = critical, permitted;DNS:example.com
[leaf]
basicConstraints = CA:FALSE
keyUsage = critical, keyEncipherment
[leaf_ek]
basicConstraints = CA:FALSE
keyUsage = critical, keyEncipherment
extendedKeyUsage = 2.23.133.8.1
[leaf_server]
basicConstraints = CA:FALSE
keyUsage = critical, keyEncipherment
extendedKeyUsage = serverAuth
EOF

# The key of `name`, and its own request config naming it (LibreSSL takes the config's
# distinguished name over -subj).
key() {
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out "$1.key"
  sed "s/^CN = placeholder$/CN = cakeys chain-rules $1/" ext.cnf >"$1.cnf"
}

# A self-signed root `name` with the extensions of section `ext`.
root() {
  key "$1"
  openssl req -new -x509 -days 36500 -sha256 -key "$1.key" -config "$1.cnf" -extensions "$2" -out "$1.pem"
}

# A leaf `name` signed by root `issuer`, with the extensions of section `ext`.
leaf() {
  key "$1"
  openssl req -new -sha256 -key "$1.key" -config "$1.cnf" -out "$1.csr"
  openssl x509 -req -days 36500 -sha256 -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -set_serial 0x$RANDOM \
    -extfile ext.cnf -extensions "$3" -out "$1.pem"
}

root ok-root ca
leaf ok-leaf ok-root leaf
root no-certsign-root ca_no_certsign
leaf no-certsign-leaf no-certsign-root leaf
root constrained-root ca_name_constraints
leaf constrained-leaf constrained-root leaf
leaf ek-leaf ok-root leaf_ek
leaf server-leaf ok-root leaf_server

for f in ok-root ok-leaf no-certsign-root no-certsign-leaf constrained-root constrained-leaf ek-leaf server-leaf; do
  cp "$f.pem" "$out/$f.pem"
done
