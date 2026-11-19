# Review: crates/core/tests/properties.rs (359 lines)

Reviewed 2026-11-18 [read]. Summary: proptests of the lock rules (record/compare idempotence,
what a second realisation may change, material linking through shared schemes), the
injectivity of the attestation and commitment-label encodings, `sri`/`is_sri`, and no-panic
properties of the key parsers and the two loaders. The lock-rule properties are well built and
assert exit codes. The parser properties are weaker than they look: their generators produce
almost only invalid input, so the "fixed point" assertions are close to unreachable.

## Findings

### F1. `key_parsers_never_panic`: the fixed-point assertions are almost never reached — risk

**Verification:** confirmed (downgraded to practice). `properties.rs:306-318` draws 0-160 uniform bytes, so the `spki_canonical` and Weierstrass `spki_from_point` `Ok` branches are essentially unreachable; but the fixed point is asserted on real curves at `crates/core/tests/refusals.rs:255` and by `fuzz/fuzz_targets/public_key.rs:9-10`, run by `checks.fuzz` from the fixtures (docs/DEVELOPMENT.md:105), so no property goes unchecked: the proptest's assertion is just mostly dead weight. [read]
`crates/core/tests/properties.rs:305-319`. The input is 0-160 uniformly random bytes. A random
byte string essentially never parses as DER SPKI or a certificate, and never as an uncompressed
Weierstrass point on P-256/P-384/P-521/secp256k1 (on-curve and of exact length), so the
`if let Ok(spki)` branches for `spki_canonical` and the four Weierstrass `spki_from_point`
calls do not execute in 256 cases; only `rsa_spki` and the Edwards curves (where many 32/57-byte
strings decode) reach `prop_assert_eq!`. What remains is "does not panic", which the doc comment
does not overstate, but the "a canonical SPKI is a fixed point" half is untested here for EC
keys. `refusals.rs:255` checks the fixed point on five real curves, and the `public_key` fuzz
target is seeded from fixtures, so the property is covered elsewhere. Fix: generate from valid
material and mutate (e.g. `prop_oneof![valid_spki_from_fixture().prop_map(flip_bytes), any
bytes]`), as `fuzzing::tests::text()` does for hex. [read]

**Fixed (2026-11-18):** `key_parsers_never_panic` draws from valid material (the fixture certificates and their SPKIs, a point of every curve raw and DER-wrapped, Ed448), as it is or with bytes changed, or any bytes; material taken as it is must parse. Test: `the_parser_seeds_reach_every_fixed_point`, `key_parsers_never_panic`.

### F2. The compare half of the downgrade property checks `is_ok` only — practice

`crates/core/tests/properties.rs:182-215`. The doc comment says another material is 10 and a
weaker binding or replaced object 14 "in both modes", but for `LockWrite::Compare` the test
asserts only `compared.is_ok() == !refused && !drift` (`:204`); the exit code is checked for
the write alone (`:207-211`). A compare that answered 14 for a pure material mismatch, or 10 for
a downgrade, passes. The expected compare code is computable from the same booleans (14 when
`downgrade || replaced || drift`, else 10 when `mismatch`). lock_mbt.rs does compare compare-mode
codes, so the gap is covered there. Fix: assert `exit(&compared)` like the write branch, or
correct the comment. [read]

**Fixed (2026-11-18):** the compare half asserts the exit: 14 for a downgrade, a replaced object or drift, else 10 for other material, else 0 (mutation: swapping the 10/14 order fails it). Test: `a_write_fills_gaps_and_never_overrides`.

### F3. Generators stay inside the valid space the lock model also covers — nit

`crates/core/tests/properties.rs:81-103`, `:150-155`. `variant()` has policy as `[bool; 2]`
(always reported; never "recorded, now absent"), mode always `Direct`, no attestation, bindings
limited to `PopSign`/`PopEcdh`/`TokenAsserted`, material two values. These are reasonable for
the properties stated, and lock_mbt.rs reaches Unset policy, attestation and the 14 rules; noted
so nobody reads this file as the coverage of those transitions. [read]

**Decided (2026-11-18):** MOOT in verification: the lock model covers the space outside the generators..

### F4. `commitment_labels_are_injective` holds by construction for the generated alphabet — nit

`crates/core/tests/properties.rs:268-292`; `crates/core/src/id.rs:367-375`. The label is
`{label}/{scheme}/{keyType}/{bits}`; since scheme, key type name and bit count contain no `/`, the
format is injective for any label read from the right, so "whatever `/` the label holds" is
trivially true. The interesting collisions are elsewhere: `value_len: None` and `Some(0)` both
give `0` bits, and `key_type: None` gives `""`; the strategy always sets both (`:285-289`). If
those cases cannot reach a commitment (loader refuses them), say so in the comment; otherwise
add them to the strategy. [read]

**Fixed (2026-11-18):** lengths are `option::of(1..=u32::MAX)`: an absent `valueLen` writes 0, which no loaded length is, and the doc says why the empty key type never reaches a label. Test: `commitment_labels_are_injective`.

### F5. Fixture code duplicated with lock_mbt.rs — complexity

`crates/core/tests/properties.rs:17-75` vs `crates/core/tests/lock_mbt.rs:23-61`, `:255-278`.
See lock_mbt.rs F4: `facts()`, `empty_lock()` are identical and the keys.toml constants
overlap. [read]

**Fixed (2026-11-18):** `facts` and `empty_lock` live in tests/common/mod.rs, shared with lock_mbt.rs. Test: `recorded_then_compared_and_idempotent`.

### F6. Out-of-range `valueLen` tested twice, once pinning prose — nit

`crates/core/tests/properties.rs:353-359` vs `crates/core/tests/refusals.rs:619-626`. Both test
the same bound (2^61 here, `u32::MAX + 1` there); this one also pins the message text
`"valueLen 2305843009213693952 bytes is out of range"`. The refusals.rs test (both edges of
the bound) is the better one; this one can go, or keep only the exit code. [read]

**Fixed (2026-11-18):** `an_out_of_range_value_len_is_refused` removed; refusals.rs's bound test asserts 17 and carries the overflow rationale. Test: `the_value_length_bound_is_inclusive`.

## Design

- The project rule is "properties as plain functions shared by proptest, cargo-fuzz and Kani"
  (`crates/core/src/fuzzing.rs`). This file's parser properties (`key_parsers_never_panic`,
  `loaders_refuse_damaged_files_without_panicking`) and the fuzz targets that cover the same
  parsers (`fuzz/fuzz_targets/public_key.rs` etc.) each state the property separately; moving
  them into `cakeys_core::fuzzing` would let the fuzz targets' fixture seeds and this file's
  generator check one definition (and would fix F1 by reusing the seeds).

## Checked, no issue

- `material_links_only_through_a_shared_scheme` checks both modes' exit codes, the
  "first realisation on t2 compares 14" special case, and that no locked ID is overwritten.
- `recorded_then_compared_and_idempotent` compares the TOML snapshot byte for byte.
- `attestation_ids_are_injective`: `prop_assume!(i != j)` rejects only when both indices
  coincide (empty input), well under proptest's reject limit; domain separation checked.
- `loaders_refuse_damaged_files_without_panicking` starts from fixtures that `fixtures_load`
  proves valid; the accepted codes (0/17, 0/15/17) match the loaders' contract.
- `properties.proptest-regressions`: both seeds (the PopSign→TokenAsserted downgrade shrink and
  the `'#'` edit) are inputs of tests that still exist with the same signature.
