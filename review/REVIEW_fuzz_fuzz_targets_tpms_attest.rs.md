# Review: fuzz/fuzz_targets/tpms_attest.rs (9 lines)

Reviewed 2026-11-18 [read]. Summary: the same bytes as a marshalled `TPMS_ATTEST` (tss-esapi
`Attest::unmarshall`), as a public blob for `recompute_name`, and for
`unmarshal_public`/`material_of`. Property: "never a panic" only. No findings.

## Findings

None.

## Design

- `Attest::unmarshall` and `PublicBuffer::unmarshall` call the C `Tss2_MU_*` unmarshallers
  through FFI. Without a sanitizer (ISSUES.md "Unsafe code and other tools": `checks.fuzz` runs
  without ASan) a memory error in that C code is found only if it crashes; the Rust under test
  is tss-esapi's conversion from the C structs and cakeys' own `recompute_name`
  (`crates/tpm2-pkcs11/src/attest/esys.rs:445`), which slices with `get`. A stronger property
  is available: for a blob `unmarshal_public` accepts, `recompute_name` should equal the Name
  tss-esapi computes for the same `Public`.

## Checked, no issue

- The certify branch only reads lengths; nothing is asserted that could false-positive.
