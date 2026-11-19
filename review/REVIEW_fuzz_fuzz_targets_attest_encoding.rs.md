# Review: fuzz/fuzz_targets/attest_encoding.rs (10 lines)

Reviewed 2026-11-18 [read]. Summary: calls `cakeys_core::fuzzing::attest_encoding_reads_back`
on three arbitrary byte fields. A real property: the framing used for `tpm-certify` and
`piv-attestation` hashes reads back to the same three fields, i.e. the encoding is injective.
Can find real bugs (a length prefix that loses information). No findings.

## Findings

None.

## Design

None.

## Checked, no issue

- The property lives in `crates/core/src/fuzzing.rs:42` (reviewed elsewhere) and is shared
  with proptest/Kani, per the "properties as plain functions" design.
