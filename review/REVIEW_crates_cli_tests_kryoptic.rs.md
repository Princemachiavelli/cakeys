# Review: crates/cli/tests/kryoptic.rs (11 lines)

Reviewed 2026-11-18 [read]. Summary: the reference suite's kryoptic binary: `mod reference` with
`REF = KRYOPTIC`. The header is accurate.

## Findings

None in this file. Note that one test included from `reference/identity.rs:349` reads SoftHSM's
require variable, not `CAKEYS_KRYOPTIC_REQUIRE` (see that review's F1).

## Design

None.

## Checked, no issue

- `CAKEYS_KRYOPTIC_REQUIRE` matches `common::KRYOPTIC.require_var` and the Nix check.
