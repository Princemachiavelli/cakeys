# Review: crates/camigrate/src/sealed.rs (681 lines)

Reviewed 2026-11-18 [read]. Summary: the `sealed`/`enforced` moves. `export` wraps keys on the
source under a fresh AES KEK and the transport key (session objects, destroyed on drop), or by
`CKM_RSA_AES_KEY_WRAP`. `import` checks a bundle entry against the lock, unwraps it on the target,
creates the public half, records the key through `ops::lock_import`, and rolls back by handle on
failure. Handle-based rollback, session-object lifetimes and the template checks before any
creation are well done. The authenticity argument for bundles is weaker than the docs claim.

## Findings

### F1. A forged bundle with a swapped private key passes under `binding = "token-asserted"` — risk

**Verification:** confirmed. `check_against_lock` (sealed.rs:443-488) compares only bundle metadata copied from the public lock; `create` makes the public half from `e.public_spki()` (:523-527) before unwrapping; `Token::spki` (identity.rs:86-110) falls back to that public key object when the private key has no material and no `CKA_PUBLIC_KEY_INFO`, and `check_kind` checks only the curve. `no_downgrade` (reconcile.rs:252) compares a realisation only with its own earlier record, so a new `token-asserted` pair passes; RSA keys (modulus on the private key) are not affected. D5 (docs/CAMIGRATE.md:130-132) overclaims. [read]
`crates/camigrate/src/sealed.rs:443-488` (`check_against_lock`), `:523-527` (the public half is
created from the bundle's `publicKey`), `crates/pkcs11/src/token/identity.rs:86-110` (`spki` uses
the private key's own material, else the public key object under the locator). D5 and the
bundle.rs header say "RFC 5649 authenticates the key bytes … so a tampered or swapped blob fails
either way". It does not authenticate the origin. The transport public key is public (the lock's
`publicKey`, the transport file), so anyone can OAEP-wrap a fresh KEK to it and RFC 5649-wrap
their own key under that KEK.

The attack: keep the entry's `publicKey`, `ids` and `type` (all from the public lock) and
replace `wrapped` and `kek` with an attacker-chosen EC key. On a target whose unwrapped EC
private key exposes no point and no `CKA_PUBLIC_KEY_INFO` (SoftHSM, by bundle.rs:60-62's own
account), `Token::spki` takes the public half the import just created from the bundle. The
identity then matches the lock.

What catches it: a `pop-*` binding catches it (the proof fails), as does a target that
cross-checks `CKA_PUBLIC_KEY_INFO` (kryoptic). Under `token-asserted`, which plan.rs:167-211 tells
users to opt into for keys with no usable proof, the swapped key is recorded as the locked object.

Fix: refuse `token-asserted` on pairs a sealed import lands on, or after the unwrap check the key
against the public half by a host-verified signature even when the binding does not require it.
Correct D5's claim either way. [read]

**Fixed (2026-11-18):** `check_carried` refuses (14) an EC or Edwards key under `token-asserted`
from a bundle file, before the target is touched; `migrate`'s in-memory bundle is not checked. D5
is corrected. Test: `a_bundle_files_unproven_ec_key_is_refused`.

### F2. Every unwrap failure is reported as tampering, exit 13 — practice

`crates/camigrate/src/sealed.rs:506-511`. Any `C_UnwrapKey` error becomes `Conflict` with "the
bundle was tampered with, or wrapped to another key". That includes a template the module refuses
(`CKR_TEMPLATE_INCONSISTENT`, `CKR_ATTRIBUTE_VALUE_INVALID`), a mechanism refused at run time,
and a session or login problem. Those are 15 or 16 conditions with a misleading diagnosis. Map
by the return value (`token::rv_of`): data or encrypted-data and wrapped-key errors to 13,
template and mechanism errors to `to.unsupported(…)`. [read]

**Fixed (2026-11-18):** `unwrap_failure` classifies a failed `C_UnwrapKey` by its `CK_RV`: only
`CKR_ENCRYPTED_DATA_INVALID`/`_LEN_RANGE` and `CKR_WRAPPED_KEY_INVALID`/`_LEN_RANGE` are 13
("tampered with"); a refused mechanism, parameter, unwrapping key or template (and a mechanism
this build cannot name) is `Token::unsupported` (15); anything else (device, session, login) is
16. Each carries its return value. CAMIGRATE.md's exit codes say so. Test:
`an_unwrap_failure_is_tampering_only_when_the_data_is_bad`.

**Fixed (2026-11-18), kept and finished:** the rule stays. A module that fails and says no more
(`CKR_DEVICE_ERROR`, `CKR_GENERAL_ERROR`, `CKR_FUNCTION_FAILED`: `UnwrapFailure::Opaque`) is 16
said as what may be a damaged or altered bundle, since kryoptic reports a tampered RFC 5649 blob
that way [run]. A PIN or session error does not say so. The dry-run twin (`xref::Env::run`)
accepts that 16 after a dry run that passed, and the token tests expect it per module: 16 on
kryoptic, 13 where the module says the data is bad. Tests:
`an_unwrap_failure_is_tampering_only_when_the_data_is_bad` (the hint on exactly the opaque
values), `bundles_are_checked_against_the_lock` (`tampered_unwrap`), and
`a_move_the_module_fails_is_refused_and_undone` (`unwrap-key` 16, `unwrap-bad` 13) [run].

### F3. A bundle's `source.token` goes into the lock unchecked — nit

`crates/camigrate/src/sealed.rs:379-381`, `:370`. The provenance `from` is whatever string the
(untrusted, D5) bundle names. It can be a token keys.toml does not have, or `"file"`, which then
reads like a file import in the lock. Provenance is "never a verdict", but checking the name
against keys.toml, or saying in the record that the source is claimed, keeps the lock honest. [read]

**Fixed (2026-11-18):** `import` refuses (17) a bundle whose `source.token` keys.toml does not
name (`Bundle::check_source`), before anything is opened, so `file` or a made-up name never
reaches `Origin::from`. Test: `the_source_must_be_a_token_keys_toml_names`.

### F4. `rfc5649`'s doc comment sits on `unwrap_declared` — nit

`crates/camigrate/src/sealed.rs:605-609`. The paragraph "The RFC 5649 key wrap a token offers …"
runs straight into `unwrap_declared`'s own, so `unwrap_declared` carries two doc paragraphs, the
first about another function, and `rfc5649` (`:627`) has none. [read]

**Fixed (2026-11-18):** the paragraph is `rfc5649`'s doc comment again.

### F5. Two ways to ask a token for a mechanism — nit

`crates/camigrate/src/sealed.rs:539`. The fallback looks for `"CKM_RSA_AES_KEY_WRAP"` in
`to.mechanism_names()`, while `rfc5649` (`:627-636`) asks `to.has(MechanismType::…)`. Both read
the usable set, but one idiom would keep the two in step. [read]

**Fixed (2026-11-18):** `rsa_aes_key_wrap(to)` asks `to.has(MechanismType::RSA_AES_KEY_WRAP)` as
`rfc5649` asks (false without `kwp`, where the build cannot name it, which the message says).

## Design

- The bundle's integrity rests on the target's identity check (`lock_import`) and the proof of
  possession, not on the wrap. Only a `pop-*` binding ties the unwrapped private key to the
  locked public key (F1). That should be said in D5, and `token-asserted` and `sealed` import
  should be treated as incompatible.
- `export` and the planner decide "shared KEK or `CKM_RSA_AES_KEY_WRAP`" through one predicate
  (`shares_kek`), but the token side reads `rfc5649(from)` (live) and the plan reads
  `side_rfc5649` (profile side). They agree only while `Side.mechanisms` is the token's usable
  list, which tokens.rs `side` keeps true.

## Checked, no issue

- Session objects (transport public key, shared KEK, import KEK) are `SessionObject`s, destroyed
  on every exit path (ISSUES Q5).
- `import`: `check_against_lock` (type, IDs, commitment label, transport key by object and
  `rfc7093m4`) and `ops::check_import` run before anything is created. `roll_back` removes only
  the handles `made`.
- Shared KEK hash: taken from the first item that shares it (`:116-120`). The planner gives every
  object of one source and target pair the same hash, and `Bundle::parse` refuses mixed hashes,
  so this cannot diverge.
- `CKM_RSA_AES_KEY_WRAP` output is split at the transport modulus length, and a blob no longer
  than the modulus is refused. The target joins the two blobs again when it lacks RFC 5649.
- An enforced key wraps only under the trusted copy. A missing copy is 14 with the command that
  makes one, and other `CKA_TRUSTED` objects are warned about.
- `check_transport_size` is applied to every transport key that reaches `export` (`Transport::key`,
  `locked_transport`, `Transport::new`).
