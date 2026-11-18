# Review: fuzz/fuzz_targets/certificate.rs (11 lines)

Reviewed 2026-11-18 [read]. Summary: any bytes as an X.509 certificate; its subject key, if
read, must be a fixed point of `spki_canonical`. `id::cert_spki` already returns
`spki_canonical(spki)` (`crates/core/src/id.rs:688-697`), so the assertion is the same
idempotence `public_key` checks; what this target adds is coverage of the `x509-cert` parse of
token-held certificates. No findings.

## Findings

None.

## Design

None.

## Checked, no issue

- Seeded from the fixture certificates (`nix/fuzz.nix:50`).
