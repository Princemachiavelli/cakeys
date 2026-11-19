# Review: crates/aws-cloudhsm/Cargo.toml (18 lines)

Reviewed 2026-11-18 [read]. Summary: workspace metadata; dependencies core, pkcs11, cryptoki and
cryptoki-sys.

## Findings

None beyond REVIEW_crates_aws-cloudhsm_src_lib.rs.md F1 (`cryptoki-sys` used for one null check).

## Design

None.

## Checked, no issue

- Every dependency is used; no build script, no features, `publish = false` via the workspace.
