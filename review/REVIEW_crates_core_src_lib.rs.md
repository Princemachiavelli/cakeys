# Review: crates/core/src/lib.rs (18 lines)

Reviewed 2026-11-18 [read]. Summary: module list and the `KmError`/`Msg`/`Result` re-exports.
No findings beyond the placement of `fuzzing` (REVIEW fuzzing.rs F1).

## Findings

None.

## Design

- Every module is `pub`, so `cakeys-core`'s whole surface is API for six crates. Several items
  are crate-internal in spirit (`id::attest_encoding` is already `pub(crate)`;
  `LockRealisation`'s `pub(crate)` fields show the intent), which is consistent.

## Checked, no issue

- The crate doc ("Touches no token") holds: no cryptoki dependency in
  `crates/core/Cargo.toml`.
