# Review: crates/pkcs11/src/templates.rs (293 lines)

Reviewed 2026-11-18 [read]. Summary: every template cakeys builds (generation halves, imports,
public halves, public objects, session keys, wrap-rebind's copy), shared by the run and by
plans without a token (`known_policy`). A clean single source of truth (Q18, §4(c)); the one
real issue is how it decides whether "the spec declares" a public-key default.

## Findings

### F1. A private key's declared `CKA_PRIVATE` removes the public half's `CKA_PRIVATE = false` — risk

**Verification:** confirmed, with the scenario corrected. `declared` reads `spec.attributes` too (templates.rs:76,80), and so do `generate`'s `private_declared` (generate.rs:130-131) and camigrate's `create_public_half` (sealed.rs:585); `CKA_PRIVATE` is declarable on a private key (core attrs.rs:22,113). But SoftHSM's `C_GenerateKeyPair` defaults the public half to `CKA_PRIVATE = false` (SoftHSM.cpp:7196, store source), so generation there is unaffected; its `C_CreateObject` defaults to private (SoftHSM.cpp:14674), so the import path (`public_half` via camigrate) shows the failure, and other modules' generation defaults are token-specific. [read]
`crates/pkcs11/src/templates.rs:75-83` (`public_defaults`), used by `generation_public`
(`:135`) and `public_half` (`:172`). `declared(n)` is true when `spec.attributes` *or*
`spec.publicAttributes` names the attribute. The public template only ever carries
`publicAttributes` (plus the defaults), so the stated reason, "a template may not carry a type
twice", applies only to `publicAttributes`. A spec that declares `CKA_PRIVATE = true` on its
private key (declarable on every class, `core::attrs` COMMON; a natural thing to write) makes
the generated or imported public key object carry no `CKA_PRIVATE` at all, so it takes the
module's default, which on SoftHSM is private (the comment at `:179` says SoftHSM makes data
objects private by default [run]). Failure scenario: `attributes = { CKA_SIGN = true,
CKA_PRIVATE = true }` on SoftHSM -> the public key is invisible without login, so consumers that
list public keys in a public session (`ssh-keygen -D`, `p11tool --list-all` without login) do
not find it, and nothing reports it (the public half's `CKA_PRIVATE` is checked only if
`publicAttributes` declares it). `CKA_VERIFY` has the same test but is not declarable on private
keys, so only `CKA_PRIVATE` is affected. Fix: decide the public defaults from
`spec.public_attributes` alone (and the same in `token::generate`'s `private_declared` and
camigrate's `sealed.rs:589` `declared("CKA_PRIVATE")`). [read]

### F2. `known_policy` uses `KmError::NotFound("")` as an in-band sentinel — nit

`crates/pkcs11/src/templates.rs:55-62`. The mapper returns an empty `NotFound` for an unknown
mechanism name, and any `NotFound` out of `policy` is read as "unknown name". Today `policy`
produces no other `NotFound`, so it holds; a future error of that kind would be silently turned
into "the plan cannot decide". Fix: have the mapper return `Option` and thread it, or use a
private marker type. [read]

## Design

- The plan's templates (`known_policy`) and the run's (`Token::policy_template`) map mechanism
  names differently by design (baseline dictionary vs the token's usable list). A name the
  baseline knows but the token's profiles subtract passes the plan and is refused at the run
  (`Unsupported`), still before anything is created, so this is acceptable; worth stating in
  the module doc beside "a refusal comes before anything is made".

## Checked, no issue

- `generation_key`: DES3 gets no `CKA_VALUE_LEN` (fixed by key type); other secret keys require
  `valueLen`.
- `generation_public`: RSA public exponent 65537; EC params by OID unless `ec_params` (the
  by-name retry) is given.
- `object`: a data object no spec declares private is made public explicitly.
- `session`: the proof secret is sealed (sensitive, not extractable, sign-only) or readable as
  asked; the export KEK is sensitive but extractable (it leaves only wrapped), the import KEK
  not extractable; `rebind_copy` adds each usage once.
- Secret material never enters these templates; the callers add it after the provider hook
  (`token/host.rs`).
