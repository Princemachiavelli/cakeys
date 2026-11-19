# Review: crates/cli/tests/reference/validate.rs (222 lines)

Reviewed 2026-11-18 [read]. Summary: what is refused before a token is asked. Adoption rules,
attributes per class, the `CKA_ALWAYS_AUTHENTICATE`/`pop-sign-pin`/`CKA_TRUSTED` rules,
brainpoolP512r1 (15), provider options checked by the provider, and the one address grammar for
every verb. Clear tests. The address test misses the documented ambiguity case, and one loop pins
exit codes only.

## Findings

### F1. Address ambiguity (12) is never tested — practice

`reference/validate.rs:182-222`. docs/CAKEYS.md: "`--spec` and `--token` narrow it where keys.toml
realises the object more than once (else 12)". `every_verb_names_the_object_first` declares one
pair only, so `check signer`, `lock signer` and `delete signer` never meet a second pair. No other
cakeys test asserts 12 for an address (the 12s in `reference/drift.rs`, `reference/tokens.rs`,
`fault.rs` and `references.rs` are about objects or tokens). Add a second spec or token for
`signer` and assert 12 without narrowing, and 0 with `--spec` or `--token`. [read]

### F2. Five invalid attribute sets are asserted as "17" alone — practice

`reference/validate.rs:36-61`. The five cases share one skeleton with no positive control of that
exact skeleton before them, and the reason is never checked. Any refusal unrelated to the attribute
under test (a label, origin or locator rule) satisfies them. The second half (`:63-108`) does pin
reasons. Do the same here. [read]

**Fixed (2026-11-18):** each case pins its reason with 17. Two had passed for the wrong reason:
`CKA_TRUSTED = true` and a mechanism list on `CKA_SIGN`, on a private key without
`CKA_SIGN = true`, were refused by the proof-of-possession rule, never their own. The private-key
cases now declare `CKA_SIGN = true` and the list sits on `CKA_DERIVE`.

### F3. The final `delete` is not shown to remove anything — nit

`reference/validate.rs:221`: `delete signer` → 0 is also what an absent object gives. Assert
`check signer` → 11 afterwards, or count the objects. [read]

## Design

None.

## Checked, no issue

- `adoption_rules_are_validated`: each case asserts both `validate` and `create` (17), and that
  nothing labelled `x` exists afterwards.
- `provider_options_are_checked_by_the_provider`: refused at open (resolve) and, with the provider
  named, statically by `validate`.
