# Review: crates/core/src/fuzzing.rs (131 lines)

Reviewed 2026-11-18 [read]. Summary: the hex and attestation-encoding properties as plain
panicking functions, run by proptest here, by the fuzz targets, and (hex) by Kani. Matches the
"properties as plain fns" decision; one placement question.

## Findings

### F1. Test-only panicking helpers are a public module of the library — nit

`crates/core/src/lib.rs:8`, `crates/core/src/fuzzing.rs:157,169,185`. `pub mod fuzzing` ships
three `pub fn`s that `assert!` in every build of `cakeys-core`, so they appear in its API and
docs beside the real modules. They must be reachable from the fuzz crate, which rules out
`#[cfg(test)]`; `#[doc(hidden)]` on the module, or a `fuzzing` cargo feature the fuzz crate
enables, would keep them out of the normal API. [read]

**Fixed (2026-11-18):** `pub mod fuzzing` is compiled only under `cfg(test)`, `kani` or the `fuzzing` feature, which only fuzz/Cargo.toml enables. No test.

## Design

None.

## Checked, no issue

- `only_hex_decodes` states the rule independently of `decode` (even length, ASCII hex
  digits) and checks both directions.
- `unframe` reads `attest_encoding`'s framing with checked splits; no panic on any input.
- The Kani harnesses use fixed arrays with a symbolic length, as the memory note on symbolic
  heap lengths requires; the doc explains why `attest_encoding_reads_back` has no proof.
