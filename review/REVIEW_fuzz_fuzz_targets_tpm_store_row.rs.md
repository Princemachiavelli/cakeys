# Review: fuzz/fuzz_targets/tpm_store_row.rs (9 lines)

Reviewed 2026-11-18 [read]. Summary: text as a tpm2-pkcs11 `tobjects.attrs` row and a
`pobjects.config` row. Property: "never a panic" only, which fits: these are read-only parsers
of another program's store, with no writer in cakeys to round-trip against. Seeded from the
fixtures (`nix/fuzz.nix:56`). No findings.

## Findings

None.

## Design

None.

## Checked, no issue

- Both parsers run on every input (`object.and(parent)` after both were called), so neither
  shadows the other (`crates/tpm2-pkcs11/src/attest/mod.rs:19-23`).
