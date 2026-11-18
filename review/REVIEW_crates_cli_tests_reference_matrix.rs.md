# Review: crates/cli/tests/reference/matrix.rs (24 lines)

Reviewed 2026-11-18 [read]. Summary: runs the object matrix (`tests/object_matrix/`) on the
reference token with up to 8 workers, except through the fault shim, where it would repeat
SoftHSM's table. Trivial.

## Findings

### F1. Through the fault shim the test returns early and is reported as passed — nit

`reference/matrix.rs:12-14`. This is deliberate and commented, but it prints nothing, unlike every
other skip in the suite. Add an `eprintln!` so the fault binary's log shows the skip. [read]

## Design

None.

## Checked, no issue

- The worker count is capped at 8 and the batch is unbounded (one session) for software tokens;
  tpm2.rs uses 8/4 for tpm2-pkcs11's limits.
