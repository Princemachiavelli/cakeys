# Review: crates/pkcs11/src/token/policy.rs (362 lines)

Reviewed 2026-11-18 [read]. Summary: the type and policy check of a found object against its
spec (`check`, `check_policy`, `check_public_half`), the observed policy vector and immutables,
the provider's flag repair, mechanism naming and the boolean attribute table. Readable and
consistent with `core::attrs`, except that a certificate's declared policy is never checked.

## Findings

### F1. A certificate's declared policy attributes are never checked — bug

**Verification:** confirmed. The certificate branch returns after the type test (policy.rs:19-24) while the data and key branches end in `check_policy` (:32, :97); `check_policy` has no other caller, and `resolve_with` makes no other declared-attribute comparison (ops.rs:355-385, `policy` at :382 is only observed). Certificates may declare `CKA_TRUSTED` plus the COMMON booleans (attrs.rs:20-26,70; plan.rs:220-232). [read]
`crates/pkcs11/src/token/policy.rs:19-24`. For `CKO_CERTIFICATE`, `check` returns after the
`CKA_CERTIFICATE_TYPE` test without calling `check_policy`. A certificate spec may declare
`CKA_TRUSTED`, `CKA_PRIVATE`, `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE`
(`crates/core/src/attrs.rs:20-26`, `:70`; `plan::check_declared` accepts them), and the data
object branch right below does call `check_policy`. No other step of `ops::resolve_with`
(`crates/pkcs11/src/ops.rs:355-385`) compares declared attributes to the token. Failure
scenario: a Secure Boot spec declares `attributes = { CKA_TRUSTED = true }` for its CA
certificate; the token's certificate is not trusted (or is modifiable when the spec says
`CKA_MODIFIABLE = false`); `cakeys check`/`lock` succeed with exit 0 and record the observed
policy, so the declaration is decorative. Fix: return `self.check_policy(h, spec)` after the
type test, as the data branch does. [read]

**Fixed (2026-11-18):** an X.509 certificate goes on to `check_policy`, as data objects and keys do. Test: `a_certificates_declared_attributes_are_checked` (cli reference/adoption.rs).

### F2. `check_public_half` skips the "same key" test when either SPKI is unreadable — nit

`crates/pkcs11/src/token/policy.rs:246-250`. `if let (Some(a), Some(b))` treats an unreadable
public object as matching and then checks `publicAttributes` on it. Not exploitable on the
resolve path, because `check_public_objects` (`token/identity.rs:175`) runs later and refuses a
public object without readable material, but `check_public_half` reads as if it were the guard.
Fix: refuse (as `check_public_objects` does) or say in a comment which later check covers it.
[read]

**Fixed (2026-11-18):** an unreadable public key object is a conflict (13), never a match;
the private key's own material is compared where it has any (`same_public_key`). Test:
`an_unreadable_public_half_is_no_match`.

### F3. `mechanism_name` scans the baseline linearly per call, and `policy_template` calls it per mechanism per name — nit

`crates/pkcs11/src/token/policy.rs:263-271`, `:277-287`. For each declared mechanism name,
every usable mechanism is named, and each name cryptoki lacks scans the whole baseline map by
value. Tens of mechanisms times a few hundred baseline entries per spec: negligible for the
verbs, but it runs again in every `check_templates`. Fix: build the name map once per token.
[read]

**Fixed (2026-11-18):** `mechanism_namer` indexes the baseline by value once, on first need;
`policy_template` names the token's mechanisms once per template. Test:
`mechanisms_are_named_by_their_constants`.

## Design

- The RSA size check (`:60-73`) counts whole bytes after the leading zeros, so a modulus whose
  top byte is below 0x80 is reported as a multiple of 8 above its bit length. Modules generate
  exact sizes, and B17 only meant to drop zero padding, so this is acceptable; a bit-exact size
  would need the top byte's leading zero bits subtracted.

## Checked, no issue

- B17 (fixed in `2120ec1`): leading zero bytes are ignored in the RSA size check.
- Data objects: a private value is identified only when the spec declares `CKA_PRIVATE = true`;
  a spec saying true for a public object fails `check_policy`.
- `flag` routes every boolean through `Provider::repair` (`policy_flag`), so ykcs11's
  `CKA_DERIVE` repair reaches both the check and the observed vector.
- `allowed_mechanisms` maps cryptoki's `NotSupported` (an unnamed mechanism without the patch)
  to an `Unsupported` that names the patch.
- `immutables` drops `CK_UNAVAILABLE_INFORMATION` for `CKA_KEY_GEN_MECHANISM`.
- The `bool_attrs!` table round-trips every name `core::attrs` observes (unit test).
