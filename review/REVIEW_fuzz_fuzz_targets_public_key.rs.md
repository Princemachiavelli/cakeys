# Review: fuzz/fuzz_targets/public_key.rs (31 lines)

Reviewed 2026-11-18 [read]. Summary: any bytes as an SPKI, as an RSA modulus/exponent pair
(last four bytes the exponent), and as a point on each curve; every SPKI produced must be a
fixed point of `spki_canonical`. A real property (canonical form is idempotent), on the parsers
that read token output.

## Findings

### F1. The curve list is spelled out instead of `Curve::ALL` — nit

`fuzz/fuzz_targets/public_key.rs:19-28`. The eight curves equal `Curve::ALL`
(`crates/core/src/id.rs:417`) today; a curve added to core is silently not fuzzed. Iterate
`Curve::ALL`.
[read]

**Fixed (2026-11-18):** the target iterates `Curve::ALL`. No test: the fuzz crate builds (`cargo check --manifest-path fuzz/Cargo.toml`).

## Design

- The property is idempotence only; it does not check that the SPKI from
  `spki_from_point(p)` (or `rsa_spki(n, e)`) carries `p` (or `n`, `e`). A re-encode that drops
  or alters the key would pass. Extracting the point or modulus back out of the produced SPKI
  and comparing with the input would let the target find more.

## Checked, no issue

- `split_at(len.saturating_sub(4))` never panics on short input.
- ISSUES.md Q20 (Done 2026-11-17): the fixed point is unchanged by the `KeyAlg` dispatch.
