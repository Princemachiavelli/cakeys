# Review: fuzz/fuzz_targets/hex.rs (13 lines)

Reviewed 2026-11-18 [read]. Summary: `hex_round_trips` on any bytes and `only_hex_decodes` on
any UTF-8 text. Real properties (round trip in either case; decode accepts exactly hex of whole
bytes). Low bug-finding yield on a 29-line module that Kani already proves for short inputs, but
cheap. No findings.

## Findings

None.

## Design

None.

## Checked, no issue

- Both properties are `core::fuzzing` functions also run by proptest and Kani.
