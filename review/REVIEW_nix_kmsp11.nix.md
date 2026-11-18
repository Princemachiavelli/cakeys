# Review: nix/kmsp11.nix (61 lines)

Reviewed 2026-11-18 [read]. Summary: Google's prebuilt Cloud KMS PKCS#11 library (and its FIPS
build), pinned by hash, with the release signature verified against a checked-in release key
whose own SHA-256 is pinned at evaluation. Exemplary supply-chain handling.

## Findings

None.

## Design

None.

## Checked, no issue

- `openssl dgst -sha384 -verify` fails the install on a bad signature (non-zero exit under the
  phase's `set -e`).
- `throwIfNot` on the key file's hash stops a silently replaced key at evaluation.
