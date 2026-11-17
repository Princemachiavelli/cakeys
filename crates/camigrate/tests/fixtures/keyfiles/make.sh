#!/usr/bin/env bash
# Key files as OpenSSL writes them, for camigrate's keyfile tests (docs/FILE.md).
set -euo pipefail
out=$1
mkdir -p "$out"
cd "$out"
pass='pass:pass phrase'
openssl version >openssl-version.txt

# P-256: one key in every format a deployment holds.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out p256.pkcs8.pem
# (`openssl pkey -outform DER` writes an EC key as SEC1, not PKCS#8.)
openssl pkcs8 -topk8 -nocrypt -in p256.pkcs8.pem -outform DER -out p256.pkcs8.der
openssl ec -in p256.pkcs8.pem -out p256.sec1.pem
openssl ec -in p256.pkcs8.pem -outform DER -out p256.sec1.der
openssl pkcs8 -topk8 -v2 aes-256-cbc -in p256.pkcs8.pem -passout "$pass" -out p256.enc.pem
openssl ec -in p256.pkcs8.pem -aes256 -passout "$pass" -out p256.legacy-enc.pem
openssl pkey -in p256.pkcs8.pem -pubout -out p256.pub.pem
openssl pkey -in p256.pkcs8.pem -pubout -outform DER -out p256.pub.der
openssl req -x509 -new -key p256.pkcs8.pem -subj /CN=keyfile-p256 -days 36500 -out p256.crt.pem
openssl x509 -in p256.crt.pem -outform DER -out p256.crt.der

# A CA beside it, for bundles and chains.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.pkcs8.pem
openssl req -x509 -new -key ca.pkcs8.pem -subj /CN=keyfile-ca -days 36500 -out ca.crt.pem

# A server bundle: curve parameters, the key, its certificate and the CA's, in one file.
openssl ecparam -name prime256v1 >p256.bundle.pem
cat p256.sec1.pem p256.crt.pem ca.crt.pem >>p256.bundle.pem
# Two certificates and no key: which one is meant cannot be told.
cat p256.crt.pem ca.crt.pem >two-certs.pem

# PKCS#12: OpenSSL 3's default (its certificates in a PBES2-encrypted container) and -legacy.
openssl pkcs12 -export -inkey p256.pkcs8.pem -in p256.crt.pem -certfile ca.crt.pem -passout "$pass" -out p256.p12
openssl pkcs12 -export -legacy -inkey p256.pkcs8.pem -in p256.crt.pem -passout "$pass" -out p256.legacy.p12

# RSA 2048: PKCS#1 as `openssl genrsa -traditional` writes it, and PKCS#8.
openssl genrsa -traditional -out rsa2048.pkcs1.pem 2048
openssl rsa -in rsa2048.pkcs1.pem -traditional -outform DER -out rsa2048.pkcs1.der
openssl pkey -in rsa2048.pkcs1.pem -out rsa2048.pkcs8.pem

# Ed25519, which only PKCS#8 holds.
openssl genpkey -algorithm ED25519 -out ed25519.pkcs8.pem

# A secret key and a data object: their bytes; the same key as hex digits and as base64.
openssl rand -out aes256.key 32
od -An -tx1 -v aes256.key | tr -d ' \n' >aes256.hex
openssl base64 -in aes256.key -out aes256.b64
printf 'release 2026-11-16\n' >note.bin
