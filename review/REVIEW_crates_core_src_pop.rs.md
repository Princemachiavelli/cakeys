# Review: crates/core/src/pop.rs (398 lines)

Reviewed 2026-11-18 [read]. Summary: the host side of proof of possession — the
domain-separated challenge, signature verification by the key's own algorithm, the ECDH,
OAEP-decrypt and OAEP-unwrap challenges, RSA encryption for the probe, and a constant-time
compare. The protocol is sound (fresh 32-byte nonce, SPKI hash in the message, host-side
verification, `subtle` comparison). One secret is not wiped, contrary to ISSUES.md B16.

## Findings

### F1. The `pop-unwrap` secret is not zeroized (B16 "Done" only in part) — practice

**Verification:** confirmed (practice kept). `unwrap_challenge_with` uses a plain `let mut secret = [0u8; 32]` that is encrypted, used as the HMAC key and dropped unwiped (pop.rs:204-208); the only `Zeroizing` in pop.rs is the ECDH `secret` (:118,144), so ISSUES.md:76's "the unwrap secret [is] wiped" is not true. [read]
`crates/core/src/pop.rs:204-208`. `unwrap_challenge_with` fills a plain `[u8; 32]`, encrypts it
and keys the HMAC with it, then lets it drop unwiped. ISSUES.md B16 (fixed in `2120ec1`) says
"the ECDH shared secret and the unwrap secret are wiped (`core/src/plaintext.rs`,
`core/src/pop.rs`)"; that commit's pop.rs diff changes only `EcdhChallenge::secret`. The value
is the session key the token unwraps; while it lives it lets anyone reading host memory forge
the token's MAC for this one challenge. Low impact (one use), but it is exactly the class of
secret B16 set out to wipe. Fix: `let mut secret = zeroize::Zeroizing::new([0u8; 32]);`. [read]

**Fixed (dc3f102):** `let mut secret = zeroize::Zeroizing::new([0u8; 32]);`.

### F2. `verify_with` loses the reason when an RSA or Ed25519 key's parser refuses it — practice

`crates/core/src/pop.rs:94-105`, with `sig::rsa_pkcs1v15`/`rsa_pss`/`ed25519` returning `None`
on a parse failure (`crates/core/src/sig.rs:99,113,128`). After Q20 the algorithm is already
known, so `None` no longer means "another kind": for an RSA key rsa refuses (e.g. under 1024
bits, see REVIEW id.rs F1) the user sees "proof of possession for the public key …: its
algorithm's own parser does not read it", without the crate's reason. ECDSA keys get
`Some(Err("the public key: …"))` and then `Conflict` (13) "the private key did not sign" —
a malformed *public* key reported as a failed proof. Not reachable from `resolve` today (the
SPKI there was already canonicalized), so practice, not bug. Fix: have the `sig` helpers take
an already-parsed key, or return the parse error as its own variant. [read]

**Fixed (2026-11-18):** the `sig` helpers answer `Refused::Key(why)` when a key's own parser refuses it, and `verify_with` reports it as unsupported (15) with the parser's reason (an RSA size outside 1024-8192 by its size, with the opt-in), never as a failed proof (13). Test: `a_refused_public_key_is_no_failed_proof`.

### F3. The HMAC keyed with a proof secret may not be zeroized — nit

`crates/core/src/pop.rs:264-268`. `Hmac::<Sha256>::new_from_slice(key)` keeps key-derived
ipad/opad state, keyed with the ECDH shared secret (`:143`) and the unwrap secret (`:208`).
hmac 0.13 has no zeroize code of its own: its `zeroize` feature only forwards to
`digest/zeroize`, under which digest's buffer macros make the type `ZeroizeOnDrop`
(`digest-0.11.3/src/buffer_macros/fixed.rs:463-485`). The workspace declares
`hmac = "0.13"` with no features (`Cargo.toml:81`). Unverified whether another crate in the
graph turns `digest/zeroize` on, and whether the sha2 core then wipes its state. Fix: enable
`hmac/zeroize` and assert `Hmac<Sha256>: ZeroizeOnDrop` at compile time, or note the gap
beside B16. [read]

**Fixed (2026-11-18):** core's Cargo.toml enables sha2's `zeroize` feature (the workspace's `hmac` enables its own, which wipes only the block buffer), so the two SHA-256 cores of the HMAC state wipe on drop; a compile-time assertion (pop.rs:290) requires `sha2::block_api::Sha256VarCore` to be `ZeroizeOnDrop`. The comment there names what stays unwiped (stack copies in upstream code). No test: the build checks it.

## Design

- `OaepHash` (transport names) and `RsaPadding::OaepSha512` (proof/probe only) live here, in the
  proof module, while `migrate::Method` imports `OaepHash` from it: the frozen transport
  vocabulary depends on the proof module. Q15 accepted the split; moving `OaepHash` to
  `migrate.rs` (or a small `rsa` module) would make the dependency point the right way.

## Checked, no issue

- B16, ECDH half (Done): `EcdhChallenge::secret` is `Zeroizing`; `EphemeralSecret` and
  `SharedSecret` zeroize on drop.
- Q20 (Done): `verify_with` and `ecdh_challenge` dispatch on `KeyAlg::of_spki`.
- Challenge layout pinned (`DOMAIN ‖ SHA-256(spki) ‖ nonce`), nonce from `getrandom`, errors
  mapped to `Unavailable`; `ct_eq` uses `subtle` (only the length is observable).
- Ed448 refused with an explicit `token-asserted` hint, matching `plan::check_binding`.
- ECDSA accepts high-s (normalized) — fine for a proof: malleability does not matter here.
