# Review: crates/profile/Cargo.toml (16 lines)

Reviewed 2026-11-18 [read]. Summary: workspace-inherited metadata and lints; depends on `serde`
and `toml` only, which keeps the crate independent of core as docs/ARCHITECTURE.md says. No
findings.

## Findings

None.

## Design

None.

## Checked, no issue

- No dependency on `cakeys-core` (independence stated in `lib.rs:7`).
- `[lints] workspace = true`.
