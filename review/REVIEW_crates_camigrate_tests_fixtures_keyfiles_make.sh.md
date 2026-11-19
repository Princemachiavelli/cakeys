# Review: crates/camigrate/tests/fixtures/keyfiles/make.sh (49 lines)

Reviewed 2026-11-18 [read]. Summary: generates key files as OpenSSL writes them for camigrate's
key-file tests: P-256 in PKCS#8/SEC1 PEM and DER, encrypted PKCS#8 and legacy PEM, public keys,
certificates, a bundle, PKCS#12 (default and legacy), RSA PKCS#1/PKCS#8, Ed25519, raw/hex/base64
secrets. Nothing to report: the passphrase is a fixture value by design.

## Findings

None.

## Design

None.

## Checked, no issue

- `set -euo pipefail`; the OpenSSL version is recorded beside the files.
