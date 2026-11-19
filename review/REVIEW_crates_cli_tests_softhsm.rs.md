# Review: crates/cli/tests/softhsm.rs (10 lines)

Reviewed 2026-11-18 [read]. Summary: the reference suite's SoftHSM binary: `mod reference` with
`REF = SOFTHSM`. The header documents the module variable, the token and the require variable
correctly.

## Findings

None.

## Design

None.

## Checked, no issue

- `CAKEYS_TEST_REQUIRE` is the require variable `common::SOFTHSM` names and the one the Nix check
  sets.
