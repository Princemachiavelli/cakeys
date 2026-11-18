# Review: crates/p11-fault/Cargo.toml (25 lines)

Reviewed 2026-11-18 [read]. Summary: `cdylib` + `rlib`, workspace lints, dependencies on
`cryptoki-sys`, `libloading`, `libc`, `p11-names`, `serde`, `serde_json`, `toml`. No cakeys
crate, as docs/FAULT_SHIM.md requires. No findings.

## Findings

None.

## Design

- The root `Cargo.toml` builds this crate at `opt-level = 2`, `strip = "symbols"` in dev
  (`Cargo.toml:133-136`), so a panic in the shim during a debug test run has no symbols in its
  backtrace; acceptable given `guard` turns panics into `CKR_GENERAL_ERROR`, but it makes the
  silent `Err(_)` arm of `guard` (`lib.rs:200`) harder to diagnose.

## Checked, no issue

- Every dependency is used (`libc` for `dladdr`, `serde_json` for the trace, `toml`/`serde`
  for the plan).
- The crate-level `#![expect(unsafe_code)]` is in `lib.rs:11`, matching the workspace lint.
