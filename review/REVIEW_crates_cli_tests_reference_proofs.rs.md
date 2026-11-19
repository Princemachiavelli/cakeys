# Review: crates/cli/tests/reference/proofs.rs (487 lines)

Reviewed 2026-11-18 [read]. Summary: proof of possession. `CKA_ALWAYS_AUTHENTICATE` keys proving
under a per-use PIN (with a negative check that the module really enforces it); a refused binding
downgrade; `pop-ecdh`/`pop-decrypt`/`pop-unwrap` with swapped-key conflicts; proofs the token or
the key cannot give (15/16); fallbacks to raw ECDSA, extractable ECDH and PKCS#1 v1.5; keys bound
to one RSA signature; and ykcs11's PIV attestation lookups on planted fixtures. Good coverage, with
negative controls in the right places.

## Findings

### F1. Six invalid configurations are asserted as "17" without the reason — practice

`reference/proofs.rs:101-112` (and `:114-115`). Each case is refused only by its exit code. The
cases share one skeleton (`tokens.ref = { locator = { CKA_LABEL = "x" }, origin = "adopt", .. }`).
A change that makes the skeleton itself invalid (for example a schema rename of `binding` or
`origin`) turns all six into passes for the wrong reason. The positive cases that follow
(`:118-140`) use a different token entry (`origin = "create"`), so they are not a control for this
skeleton. Fix: pin a word of each refusal (the binding and the missing bit), as
`attributes_are_validated_per_class` does for its last cases. [read]

**Fixed (2026-11-18):** each case and the default-proof one pin their reason with 17.

### F2. Stale comment about a shared token — nit

`reference/proofs.rs:89-93` ("The token is shared between runs ..."): see common/mod.rs F6. [read]

**Fixed (2026-11-18):** the comment is gone (common/mod.rs F6's resolution). No test.

## Design

- `piv_attestations_are_found_by_slot_and_chain_to_yubico` (`:386-487`) already plants a full
  ykcs11 attestation chain on SoftHSM. It is the cheapest place to test `check --at` and
  `--ignore-validity` against a real chain (see reference/check.rs F1).

## Checked, no issue

- `always_authenticate_keys_prove_possession_with_a_per_use_pin`: `:36` shows that signing without
  the context login fails, so the passing proof did log in. The undeclared case is decided from the
  attribute the token reports.
- `proofs_fall_back_to_what_the_token_has`: each fallback runs with its first choice hidden (the
  observation mechanism), and the extractable ECDH path still catches a swapped key.
- `proofs_the_key_will_not_give_are_refused`: the kryoptic/SoftHSM difference in creating an
  always-authenticate public key is asserted (`:318`), not skipped.
