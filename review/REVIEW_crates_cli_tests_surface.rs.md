# Review: crates/cli/tests/surface.rs (13 lines)

Reviewed 2026-11-18 [read]. Summary: runs the shared surface floor for `cakeys` over `tests/`,
with an empty `UNTESTED` list. One of only two `cakeys` test binaries that need no token, so it
runs everywhere.

## Findings

### F1. The other packages' `#[path]` spelling inside cli itself — nit

`surface.rs:3`: `#[path = "../../cli/tests/common/mod.rs"]` resolves to `tests/common/mod.rs`, so a
plain `mod common;` would do, as every other cakeys test binary has it. [read]

## Design

None.

## Checked, no issue

- `UNTESTED` is empty, and a stale entry would fail. How weak the floor is is in the review of
  common/surface.rs (F1).

## Resolutions (2026-11-18)

- F1 **Fixed (2026-11-18):** plain `mod common;`.
