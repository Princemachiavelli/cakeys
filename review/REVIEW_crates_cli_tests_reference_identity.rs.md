# Review: crates/cli/tests/reference/identity.rs (750 lines)

Reviewed 2026-11-18 [read]. Summary: every identity scheme against an independent host oracle.
HMAC commitments, AES `cmac`/`kcv-ecb`/`kcv-ecb-dec`/`kw` at every size, DES3 check values, the EC,
Edwards and RSA SPKI through a hand-written DER oracle, `valuehash` for data objects. Also: disjoint
schemes never link material, and lock-upgrade notes. This is the suite's backbone and is well built.
One skip reads the wrong require variable.

## Findings

### F1. The HMAC-types test reads SoftHSM's require variable in every binary — risk

**Verification:** confirmed (downgraded to nit). reference/identity.rs:349 hard-codes `CAKEYS_TEST_REQUIRE`, but both supported runners set it alongside `CAKEYS_KRYOPTIC_REQUIRE` (nix/package-common.nix:179, :189; scripts/local-tests.sh:107, :110) and both link the patched cryptoki, so the skip is reachable only in a hand-rolled kryoptic-only `cargo test` with stock cryptoki. Same item as REVIEW_crates_cli_tests_common_mod.rs.md F7. [read]
`reference/identity.rs:349`: `cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TEST_REQUIRE").is_ok())`.
The file runs in three binaries (`softhsm`, `kryoptic`, `fault`). The kryoptic binary's require
variable is `REF.require_var` = `CAKEYS_KRYOPTIC_REQUIRE` (`common/mod.rs:234`). With only that set,
for example a kryoptic-only run, an unpatched cryptoki makes `hmac_key_types_commit_with_their_own_hash`
skip and pass. Kryoptic is the reference that exercises `hmac_key_gen` (`:412-416`). The Nix check
sets both variables, so CI is unaffected today. Fix: `cryptoki_hmac_types_fixed(std::env::var(REF.require_var).is_ok())`,
as `caprobe/tests/reference.rs:18` does. [read]

**Fixed (2026-11-18):** the test asks `hmac_types_fixed(REF.require_var)`, the running binary's own require variable. Test: `no_opted_in_suite_skips_an_unpatched_build`.

### F2. Five copies of the HMAC oracle — nit

`reference/identity.rs:381-407` repeats the same three lines per hash. A generic
`fn hmac<D: ..>(key, label)`, or one macro arm per type, would leave one line each. [read]

**Fixed (2026-11-18):** one `mac!` macro, one line per hash. Test: `hmac_key_types_commit_with_their_own_hash`.

## Design

None.

## Checked, no issue

- `curves_and_rsa_sizes_match_an_independent_der_oracle`: each curve's `rfc7093m4` equals
  `sri(oracle_spki(..))`, built from raw attributes by the test's own DER writer. Eight fresh
  verifications per key catch encoding quirks. Missing curves assert 15 *and* nothing left behind.
- `aes_commitments_match_host_oracles` asserts the lock never contains the raw CMAC output
  (`:195-201`), only its hash.
- `disjoint_schemes_never_link_material`: 14, and neither the `kw` ID nor the realisation is
  written.
- `des3_check_values_match_host_oracles`: the kryoptic branch (`:511-519`) asserts 15 plus nothing
  created, so it is not a silent skip.
