# Review: crates/kmsp11/Cargo.toml (19 lines)

Reviewed 2026-11-18 [read]. Summary: workspace metadata; dependencies core, pkcs11, profile,
cryptoki, serde_json.

## Findings

None.

## Design

`serde_json` is pulled in only to parse the crate's own embedded table at run time; a Rust
`const` table (or a build-script-generated one) would drop the dependency and turn a malformed
row into a compile error (see REVIEW_crates_kmsp11_src_lib.rs.md, Design).

## Checked, no issue

- Every dependency is used: `cakeys-profile` for `KeyKind`/`On`, `cryptoki` for mechanism and
  attribute types, `serde_json` for `keys.json`.
