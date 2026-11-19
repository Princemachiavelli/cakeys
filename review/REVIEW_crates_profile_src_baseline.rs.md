# Review: crates/profile/src/baseline.rs (177 lines)

Reviewed 2026-11-18 [read]. Summary: the generated PKCS#11 3.2 baseline as data (name-to-ID
tables, functions, curves, classes) plus `table`/`table_mut` by TOML name. Straightforward
data; no logic to get wrong beyond the table macro, which matches `TABLES` one for one.

## Findings

### F1. `Baseline` and `ClassMembers` accept unknown keys — nit

`crates/profile/src/baseline.rs:32` and `:43`. Unlike every profile section (B12), these lack
`#[serde(deny_unknown_fields)]`, so a misspelt `parameter_sets` in a `[class.*]` loads as an
empty list. The embedded baseline is generated and pinned by caprobe's test, but caprobe's
`--profiles` directory loads baselines too (`lib.rs:99`). Add the attribute.
[read]

**Fixed (2026-11-18):** `Baseline` and `ClassMembers` are `#[serde(deny_unknown_fields)]`. Test: `a_misspelt_baseline_key_is_refused`.

## Design

- `CURVES` is a third curve list (core's `id::Curve::ALL`, the probe's); ISSUES.md Q18 accepted
  this, with `the_profiles_name_every_curve_cakeys_has` (pkcs11 `gate.rs:230`) holding core's
  list inside it. Note that the test is one-directional: a curve here that core lacks is not
  caught (the Montgomery ones are intentional).

## Checked, no issue

- `tables!` arms equal `TABLES` (18 names, same spellings).
- Optional constant families default to empty, as the comment says; the required ones
  (mechanisms, key types, …) do not.
