# Review: crates/ykcs11/build.rs (27 lines)

Reviewed 2026-11-18 [read]. Summary: pins each embedded trust-anchor file by SHA-256 and fails
the build when one differs, with `rerun-if-changed` per file. Correct and minimal.

## Findings

None.

## Design

The digests pin the files as Yubico published them; `the_yubico_roots_are_pinned` additionally
pins each root's SPKI digest and the pool's size. The two pins are redundant on purpose (a
deliberate two-place diff to update), which roots/README.md documents.

## Checked, no issue

- Paths are relative to the crate directory, which cargo sets as the build script's cwd.
- `rerun-if-changed` is printed before the read, so a missing file still registers the path.
- No network, no environment input; a mismatch message names both digests and the README.
