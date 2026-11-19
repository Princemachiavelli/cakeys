#!/usr/bin/env bash
# The fixed test keys caprobe's import probes ask a module to take (docs/CAPROBE_MIGRATION.md
# M2): test keys, no secret, embedded so a profile regenerates byte for byte. A rerun replaces
# every key, and with them every committed profile's import rows: run it only to change the set,
# from the repository root: `crates/caprobe/fixtures/import/make.sh crates/caprobe/fixtures/import`.
set -euo pipefail
out=$1
mkdir -p "$out"
cd "$out"
openssl version >openssl-version.txt

# A private key as PKCS#8 DER: `genpkey -outform DER` writes an EC key as SEC1.
pkcs8() {
  openssl pkcs8 -topk8 -nocrypt -outform DER -out "$1"
}

# One per curve the host reads (cakeys_core::plaintext): Weierstrass, then Ed25519.
for curve in secp256r1:P-256 secp384r1:P-384 secp521r1:P-521 secp256k1:secp256k1 \
  brainpoolP256r1:brainpoolP256r1 brainpoolP384r1:brainpoolP384r1; do
  openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:${curve#*:}" -pkeyopt ec_param_enc:named_curve |
    pkcs8 "ec-${curve%%:*}.der"
done
openssl genpkey -algorithm ED25519 | pkcs8 ec-edwards25519.der

# One per size the generation probes try (caprobe RSA_SIZES) that the host reads: the rsa
# crate refuses a public key under 1024 bits or over 8192, so cakeys identifies none there.
for bits in 1024 1536 2048 3072 4096 6144 8192; do
  openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" | pkcs8 "rsa-$bits.der"
done

# AES values, by length in bytes.
for len in 16 24 32; do
  openssl rand -out "aes-$len.key" "$len"
done

# A certificate for create.CKO_CERTIFICATE: self-signed, under the P-256 key.
openssl req -x509 -new -key ec-secp256r1.der -keyform DER -subj /CN=cakeys-probe -days 36500 \
  -outform DER -out certificate.der
