# Review: fuzz/fuzz_targets/p521_point.rs (7 lines)

Reviewed 2026-11-18 [read]. Summary: `cakeys_tpm2_pkcs11::fuzzing::ec_point_fix` on any bytes.
A real property: `fix_ec_point` repairs exactly the malformed short-length P-521 point, the
repair is DER of the same point, untouched input is returned as-is, and a repaired value is
stable. Since commit 69ee620 Kani proves the same function for every input up to 258 bytes, so
this target mostly adds longer inputs. No findings.

## Findings

None.

## Design

None.

## Checked, no issue

- The oracle (`crates/tpm2-pkcs11/src/lib.rs:116-133`) is written independently of
  `fix_ec_point`'s code (a pattern match on the shape), so it is a real cross-check, not a
  restatement.
