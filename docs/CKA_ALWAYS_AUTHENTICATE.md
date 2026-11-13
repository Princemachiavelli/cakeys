# `CKA_ALWAYS_AUTHENTICATE` and PIN-gated proof of possession

> **Status: implemented (sign path); touch policy deferred.** This documents the decision to prove
> possession of `CKA_ALWAYS_AUTHENTICATE` keys under their own per-use PIN policy, and the PIN-retry
> safety rule that comes with it. Authoritative for current behaviour: [`DESIGN.md`](DESIGN.md)
> §3.6, `crates/core/src/plan.rs::check_binding` and `crates/pkcs11/src/token/possession.rs`.

## Problem

`CKA_ALWAYS_AUTHENTICATE` (private keys, PKCS#11 3.2 §4.10) is a per-use authorization gate:
after every `C_SignInit`/`C_DecryptInit` the user must re-authenticate with
`C_Login(CKU_CONTEXT_SPECIFIC)` before the operation runs. On a YubiKey PIV this is the
"PIN always" policy.

It does **not** forbid signing. The proof of possession is exactly the normal one — the token
signs a fresh host challenge, the host verifies against the locked SPKI — with one extra step:
a context-specific login before each signature. The PIN unlocks the key; the signature is still
the proof. `cakeys` used to refuse the combination outright (`plan.rs::check_binding`, exit 17;
`possession.rs::prove_binding`, exit 16), pointing at `publicOnly` / `token-asserted`.

That refusal was cost-based, not capability-based, and it over-drew the line twice:

- A normal private key needs at most one `C_Login(CKU_USER)` at session open, then signs freely.
  An always-authenticate key re-authenticates before *every* use — but the PIN is the same one
  that already opened the session, so the marginal cost is a redundant successful login, not a new
  secret or a new risk.
- An always-authenticate key is `CKA_PRIVATE`, so it is **invisible without a user login**. Proving
  it at all already presupposes a PIN. A configured `pinFile`/`pinEnv` is therefore already the
  operator's consent to PIN-driven operation; a separate opt-in adds ceremony, not protection.

## Decision

`pop-sign` on a `CKA_ALWAYS_AUTHENTICATE` key is **not refused**; it is *performed* under the
key's per-use PIN policy, and the lock records that fact distinctly. No manual opt-in: the only
real precondition is the one the key already imposes — a PIN source.

### Name

The recorded value is **`pop-sign-pin`**: the same `pop-sign` proof, PIN-gated per use. It is
**derived**, never handwritten (`binding = "pop-sign-pin"` in keys.toml is invalid, 17): the
proof resolves the planned `pop-sign` to `pop-sign-pin` when the token **reports**
`CKA_ALWAYS_AUTHENTICATE = true` on the private key, declared in the spec or not
(`Token::recorded_binding`). Deriving it from the observed attribute keeps the lock in step with
what ran: a PIV slot whose module sets the attribute without the spec declaring it (ykcs11's 9c)
still records `pop-sign-pin`. The working title "commitmentWithPin" was rejected on two counts:

- **"commitment" is the wrong noun.** In `cakeys`, *commitments* are the MAC-based identity for
  *secret* keys (`declared_commits`, the `Commitment` identity mode). *Private* keys use
  **binding** / proof of possession (`pop-*`), per `DESIGN.md` §3.6.
- **Case format.** Binding values are kebab-case (`pop-sign`, `pop-ecdh`, `pop-decrypt`,
  `token-asserted`).

### Semantics of `pop-sign-pin`

- The proof is byte-for-byte the `pop-sign` proof of §3.6: the host builds
  `"cakeys/pop/v1" ‖ SHA-256(SPKI) ‖ nonce`, the token signs it, the host verifies with RustCrypto
  against the same canonical SPKI it hashes into `rfc7093m4`. Nothing derived from the proof is
  ever stored.
- The only difference from `pop-sign` is the required step before the signature: a
  `C_Login(CKU_CONTEXT_SPECIFIC)` with the user PIN. The PIN is the one already used to open the
  session (an always-authenticate object is unreachable without it); the token keeps it in memory
  (zeroized on drop) whenever one was read.
- It requires `CKA_SIGN = true` in the spec, exactly as `pop-sign` does.
- It is stronger than `publicOnly` / `token-asserted`: the private half *does* prove possession.

### Signing in parts (cryptoki limitation)

PKCS#11 accepts the context-specific login only *between* `C_SignInit` and the signature. cryptoki
0.12's single-part `Session::sign` issues `C_SignInit` and `C_Sign` in one call, and its public
`sign_init` pairs only with the multi-part `sign_update`/`sign_final`. The proof therefore runs
`C_SignInit → C_Login(CKU_CONTEXT_SPECIFIC) → C_SignUpdate → C_SignFinal`, which constrains the
mechanisms:

| Key / module | Mechanism | Result |
|---|---|---|
| RSA (all modules) | `CKM_SHA256_RSA_PKCS` | proven |
| EC on ykcs11, kryoptic | `CKM_ECDSA_SHA*` | proven |
| EC on SoftHSM | `CKM_ECDSA_SHA*` (single-part only in SoftHSM) | Unsupported (15) |
| EC on a token without hashed ECDSA | raw `CKM_ECDSA` (single-part only) | Unsupported (15) |
| Ed25519 | `CKM_EDDSA` (single-part only) | invalid (17) when declared, else Unsupported (15) |

`token-asserted` stays the opt-out for these. **Follow-up:** patch cryptoki with a public
single-part `C_Sign` after `sign_init` (alongside the patches in `nix/patches/`, PR draft under
`upstream/rust-cryptoki/`) and upstream it; the proof then signs single-part and every row above
is proven. The spot is marked `TODO(cryptoki)` in `possession.rs::sign_with_pin`.

### Rank and downgrade rule

`pop-sign-pin` proves the **identical fact** as `pop-sign` — possession of the named public key —
so it shares rank 0 with `pop-sign` / `pop-ecdh` / `pop-decrypt` (`Binding::rank`, `config.rs`).
Moving `pop-sign` ↔ `pop-sign-pin` is **not** a downgrade; the "costs a PIN per use" fact is
also recorded by the observed `CKA_ALWAYS_AUTHENTICATE` bit in the policy vector, whose drift is a
change to review. Moving to `token-asserted` remains a downgrade (exit 14).

### Rules

- `CKA_ALWAYS_AUTHENTICATE = true` (observed) + `pop-sign` (the default) → the proof does the
  context-specific login and the lock records `pop-sign-pin`. No refusal. A token without a usable
  PIN never reaches the private object anyway (a public session cannot see `CKA_PRIVATE` objects,
  §4.4/§5.7.7), so a missing PIN is a `not found`/`Unavailable`, not a separate rule.
- `CKA_ALWAYS_AUTHENTICATE = false` → plain `pop-sign`, as before, with no context-specific login.
- `pop-ecdh` / `pop-decrypt` on an always-authenticate key are refused (16): only the sign path
  logs in per use.
- `publicOnly` / `binding = "token-asserted"` remain the explicit opt-outs for keys that cannot or
  should not be proven (non-signing, Ed448, the single-part rows above, tpm2-pkcs11 P-521, or a key
  the operator wants to adopt without a PIN).

## PIN-retry safety on PIV

The invariant: **`cakeys` spends at most one failed PIN attempt per run, and never the last one.**

- **The open-time login is the real check — the existing M2 guard (`Pin::guard`).** It refuses to
  attempt a login when the counters report `CKF_USER_PIN_LOCKED` or `CKF_USER_PIN_FINAL_TRY`. This
  is not about retrying within a run: a *persistently wrong* `pinFile`/`pinEnv` across repeated
  runs (CI, cron, deploy) burns one retry per run, and without this guard run 3 locks the token.
  The guard stops *before* the attempt once the counter says it is the last.
- **The context-specific login needs no pre-check.** It reuses the same in-memory, already-verified
  PIN, so it cannot be wrong: a wrong PIN would have failed at session open and the proof would
  never be reached. A *successful* login resets the PIV counter, so the context login spends no
  retry. It can only fail if another actor locks the token in the window; whatever the token
  returns (`CKR_PIN_LOCKED`, `CKR_PIN_INCORRECT`, `CKR_USER_NOT_LOGGED_IN`) is `Unavailable` (16),
  and the active sign operation is ended (`C_SignFinal`) so the session stays usable.
- **Exactly one context-specific login per proof, no retry loop.** Together with the open-time
  guard, a single wrong PIN costs at most one retry and never the last one.
- **`CKF_USER_PIN_COUNT_LOW` is informational** — a failure has already occurred but retries
  remain; every verb that opens the token prints a warning (`Token::pin_warning`), none refuses.
- **`CKF_USER_PIN_TO_BE_CHANGED` / `CKF_USER_PIN_LOCKED`** surface the same as before (M2); a
  locked/final-try token is `Unavailable` (16), never tried.

## Touch policy (deferred)

A PIV slot can carry a *touch* policy alongside the PIN policy. Touch is invisible in PKCS#11
(§4.10) and observable only through the PIV attestation's `1.3.6.1.4.1.41482.3.8` extension (§3.7);
a proof on a slot that requires touch blocks on a human.

The planned `tokens.<t>.touchPolicy = "refuse" | "allow"` knob is **deferred**, because as
specified it could not act in time:

- The proof runs before the attestation (`ops.rs`: `tok.ids` then `attest`), and attestation runs
  only for specs with `attestation = true`. The lock stores only the attestation digest, not the
  `.3.8` bytes. So "refuse what the attestation path has already observed" would only fire after
  a touch had already blocked.
- Touch is independent of `CKA_ALWAYS_AUTHENTICATE`: a PIN-once, touch-always slot blocks plain
  `pop-sign` today. A posture for it belongs to every proof, not to this change.

A working version needs: fetch the attestation and parse `.3.8` (touch byte: always or cached) before
the proof when the spec opts into attestation, then refuse (16) or warn for every `pop-*` proof on
such a slot. Until then an unobservable touch policy is the operator's responsibility; the
yubikey suite bounds every run in time so a touch fails the test instead of hanging it.

## Scope and non-goals

- **A configured PIN is the opt-in.** Nothing here adds a gate on top of what the key's own policy
  already demands; the only new behaviour is that `pop-sign` on an always-authenticate key works
  instead of being refused, spending the redundant successful login and recording `pop-sign-pin`.
- **Only the sign path.** `pop-ecdh` / `pop-decrypt` variants for derive-only / decrypt-only
  `CKA_ALWAYS_AUTHENTICATE` keys are not added here; those keys keep `token-asserted` / the
  refusal. The same PIN gate would apply analogously if they are ever added.

## Implementation

- `crates/core/src/config.rs`: `Binding::PopSignPin` (`"pop-sign-pin"`), rank 0.
- `crates/core/src/plan.rs::check_binding`: the unconditional `CKA_ALWAYS_AUTHENTICATE` refusal is
  gone; a handwritten `pop-sign-pin` and a declared always-authenticate Edwards key are invalid (17).
- `crates/pkcs11/src/token/possession.rs`: `recorded_binding` derives `pop-sign-pin` from the
  observed attribute (and refuses `pop-ecdh`/`pop-decrypt` on such keys); `sign_with_pin` does the
  multi-part sign with the context-specific login.
- `crates/pkcs11/src/ops.rs`: `resolve` and `delete` prove and record the derived binding.
- `crates/pkcs11/src/token/mod.rs`: the user PIN is kept whenever read; `Pin` reads
  `CKF_*_PIN_COUNT_LOW` for `Token::pin_warning`. `Pin::guard` (M2) is unchanged.
- Tests: `always_authenticate_keys_prove_possession_with_a_per_use_pin` (SoftHSM and kryoptic —
  also asserting a bare sign *fails*, so the module really enforces the login) and
  `attributes_are_validated_per_class`.
