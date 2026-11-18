# Review: crates/pkcs11/src/token/possession.rs (870 lines)

Reviewed 2026-11-18 [read]. Summary: proof of possession on the token for each binding
(`pop-sign`/`pop-sign-pin`, `pop-ecdh` sealed then extractable, `pop-decrypt`, `pop-unwrap`),
the shared refusal check (`proof_refusal`, also used by camigrate's plan), RSA signature choice
under `CKA_ALLOWED_MECHANISMS`, OAEP parameter tables, and `derive_any`. Careful code: every
derived or unwrapped secret is a `SessionObject` destroyed in the session it lives in (the
read-write extra session included), comparisons are constant-time, and the busy-session hazard
of OAEP retries is handled. Findings are minor.

## Findings

### F1. The extractable ECDH fallback drops the return value it reports — practice

`crates/pkcs11/src/token/possession.rs:189-195`. `extractable_after` rebuilds an
`Unavailable`/`Unsupported` from `format!("{m} (sealed: {why})")`, a new `Msg` without the
`CK_RV` `m` carried (Q3). A `pop-ecdh` proof that falls back and then fails reports no value,
unlike every other proof failure. Fix: keep the value, e.g. `.with_rv(m.rv())` on the rebuilt
error. [read]

### F2. The ECDH secret read back from the token is not wiped — nit

`crates/pkcs11/src/token/possession.rs:244-260`. `prove_ecdh_extractable` reads the derived
secret's `CKA_VALUE` into a plain `Vec<u8>` (and the `Attribute::Value` it came in), never
zeroized. B16 wipes the host's copy of the same shared secret (`core/src/pop.rs`). The comment
argues the value reveals nothing (an ephemeral host key), which is true, so this is only an
inconsistency with B16; wrap it in `Zeroizing` or drop the B16 claim for this secret. [read]

### F3. A doc comment belongs to the wrong function — nit

`crates/pkcs11/src/token/possession.rs:490-499`. The doc of `proof_secret` ("The session secret
a proof makes on the token ...") is fused onto `ecdh_seals`, whose own doc follows it, and
`proof_secret` (`:501`) has none. Fix: move the first four lines above `proof_secret`. [read]

### F4. `CKA_ALLOWED_MECHANISMS` is read twice for an RSA `pop-sign` — nit

`crates/pkcs11/src/token/possession.rs:71`, `:99`. `proof_permits(h)` reads it, then the RSA
branch reads it again for `rsa_signature`. One `C_GetAttributeValue` more per proof. Fix: read it
once and pass the list to both. [read]

## Design

- `recorded_binding` refuses `pop-ecdh`/`pop-decrypt`/`pop-unwrap` on a
  `CKA_ALWAYS_AUTHENTICATE` key with `Unavailable` (`:30-39`), a code that reads as transient,
  though the cause is a permanent property of the key (only the sign path does the per-use
  login). `Unsupported` (15) would match how `proof_refusal` reports the other "this token
  cannot prove it" cases.

## Checked, no issue

- `sign_with_pin`: `C_SignInit`, then one `CKU_CONTEXT_SPECIFIC` login, never retried; on login
  failure `C_SignFinal` ends the operation so the session stays usable.
- `prove_ecdh`: the sealed attempt falls back only on a refused derivation or a refused
  `C_SignInit`; a `Conflict` from the derivation is the proof's answer; the derived secret is
  destroyed before the fallback runs.
- `derive_for_proof`/`prove_unwrap`: on `CKR_SESSION_READ_ONLY` a read-write session is opened
  once (the `rw.is_none()` guard ends the loop), and the session object is destroyed in that
  session before it closes.
- `oaep_hash_refused`: only a parameter refusal at the init call (or the single
  `C_UnwrapKey`) moves to the next hash; unit-tested.
- `rsa_signature`/`rsa_sign`: raw mechanisms sign the host digest (in `DigestInfo` for v1.5), PSS
  salt equals the hash length; `digest_info` prefixes match RFC 8017; unit-tested.
- `proof_refusal` is the one check for the proof, `create`'s capability check and camigrate's
  plan.
- `derive_any`: retries only on template refusals, reports the first refusal when nothing takes.
