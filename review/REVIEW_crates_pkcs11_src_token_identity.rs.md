# Review: crates/pkcs11/src/token/identity.rs (416 lines)

Reviewed 2026-11-18 [read]. Summary: material identities (`ids`): the canonical SPKI of a key
from its own material, a public key object, `CKA_PUBLIC_KEY_INFO` or a certificate, with
cross-checks; the type/curve check of a stand-in; the public-objects rule; secret-key
commitments directly or through wrap-and-rebind. The identity logic holds up (as ISSUES.md
"What held up" says): `CKA_PUBLIC_KEY_INFO` is never trusted alone, stand-ins are type-checked,
session objects are destroyed on every path. Findings are about error mapping and repeated work.

## Findings

### F1. `held_spki` turns a failed read into "no key material", which callers report as a conflict — practice

`crates/pkcs11/src/token/identity.rs:209-215`. `Err(_) => None` swallows every error of
`material_spki`, including `Unavailable` from a failed `C_GetAttributeValue` (a dropped
connection to a network HSM, a session error). Callers then decide on `None`:
`check_public_objects` (`:192-201`) returns `Conflict` (13) "exposes no key material, so it
cannot be told apart"; `destroy_identified` (`token/generate.rs:207-211`) counts the object as
"left" (holding another key); `Token::trusted` and `Token::occupied` (`token/mod.rs:637`,
`:698`) count it as another object / a collision. Failure scenario: a transient module error
while `check` reads a public key object exits 13 (a wrong-material verdict) instead of
`Unavailable`. Fix: return `Result<Option<Vec<u8>>>` and let `Unavailable` propagate; keep
`None` for "readable but no material in a form cakeys reads" (`Unsupported`). [read]

### F2. The same SPKI is computed up to four times per resolve — complexity

`crates/pkcs11/src/token/identity.rs:49`, `:176`, and `crates/pkcs11/src/ops.rs:384`, `:425`.
`resolve_with` computes `spki(h, loc)` in `ids`, again in `check_public_objects`, again in
`attest` and again for `public_key` (transport keys); `delete` adds a fifth in
`destroy_identified`. Each is two to four `C_GetAttributeValue` calls and up to two
`C_FindObjects`, plus the cross-checks. On Cloud KMS and CloudHSM each is a network round
trip. Fix: compute it once in `compute_ids` and pass it on (it is the identity being checked,
so it should be one value). [read]

**Fixed (2026-11-18):** as suggested, `delete` included (`a_resolve_reads_the_public_key_once`).

## Design

- `material_spki` and `check_kind` read the raw `CKA_KEY_TYPE` (not `Token::key_type`, the
  provider-repaired one). It works for the one repair in tree (aws-cloudhsm's Ed25519 is
  reported `CKK_EC` with the Ed25519 OID, which `Curve::from_params` maps right), but a future
  key-type repair that `from_params` cannot infer would diverge between `check` (repaired) and
  the identity (raw). Using `self.key_type(h)` in both would keep one view.

## Checked, no issue

- `spki`: material first; a single public key object (cross-checked); `CKA_PUBLIC_KEY_INFO`;
  a single certificate; several of either is `Ambiguous`; the result is cross-checked against
  the object's own `CKA_PUBLIC_KEY_INFO` and its type/curve (`check_kind`).
- `commit` (`kw`): the fixed input key is a `SessionObject`, destroyed whatever `wrap_key`
  returns.
- `wrap_rebind`: both templates asked of the provider before anything is made; KEK and copy are
  `SessionObject`s, destroyed on every path, the copy before the KEK.
- `commit_mechanism` agrees with core's mechanism names (unit test).
- B4 (`wrap_rebind` adds a usage only if absent) is in `templates::rebind_copy`.
