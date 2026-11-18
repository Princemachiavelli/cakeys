# Review: crates/p11-names/src/lib.rs (861 lines)

Reviewed 2026-11-18 [read]. Summary: compiler-checked name/value tables (`RV`, `ATTRIBUTE`,
`FLAG`, `MECHANISM`) built by macros from `cryptoki-sys` constants, with linear lookups by name
and `rv_name` by value. Each entry is an identifier, so a misspelt name fails to compile and the
value can never drift from cryptoki-sys. Compared against the committed 3.2 baseline
(`profiles/baselines/pkcs11-3.2.toml`) [run: `comm` of the two name sets]: every `CKR_*`,
`CKA_*` and `CKM_*` there is in the tables, apart from the OASIS header's own typo spellings
`CKM_PBE_SHA1_DES{2,3}_EDGE_CBC` (the table has the correct `…_EDE_CBC`).

## Findings

### F1. `FLAG` mixes slot and token flags whose bits collide — practice

`crates/p11-names/src/lib.rs:293-323`. The doc says "the slot flags … and token flags", in one
table: `CKF_TOKEN_PRESENT`/`CKF_RNG` (1), `CKF_REMOVABLE_DEVICE`/`CKF_WRITE_PROTECTED` (2),
`CKF_HW_SLOT`/`CKF_LOGIN_REQUIRED` (4) share values, so `flag()` cannot tell a plan which
structure a name belongs to. This is what lets REVIEW p11-fault plan.rs F1 happen. Two tables
(`SLOT_FLAG`, `TOKEN_FLAG`) would let the plan refuse the wrong kind.
[read]

## Design

- Aliases are in the name tables (`CKA_SUB_PRIME_BITS`, `CKA_ECDSA_PARAMS`,
  `CKM_ECDSA_KEY_PAIR_GEN`), which is right for name lookup; only `rv_name` reverses a table,
  and `RV` has no duplicate values, so "the first name" is unambiguous. If a reverse lookup is
  ever added for attributes or mechanisms, the alias order will matter.

## Checked, no issue

- No cakeys dependency (`Cargo.toml`: `cryptoki-sys` only), as p11-fault requires.
- ISSUES.md Q4 (Done 2026-11-17): the table is its own crate; `rv_name` is what
  `cakeys_pkcs11::token::rv_name` names return values with.
- `rv_name(CKR_VENDOR_DEFINED + n)` is `None` for `n > 0`, so vendor codes print as hex.
