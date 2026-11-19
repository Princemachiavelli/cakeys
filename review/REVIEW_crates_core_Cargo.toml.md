# Review: crates/core/Cargo.toml (47 lines)

Reviewed 2026-11-18 [read]. Summary: workspace-inherited package metadata and lints, 27
dependencies (all workspace-pinned), three dev-dependencies. Every dependency is used in
`src/` (checked one by one with `rg`); dev-dependencies are used by `tests/`.

## Findings

### F1. `pkcs8`/`der`/`spki` are reached through `p256`'s re-exports, and `spki` also through `x509-cert` — nit

`crates/core/Cargo.toml:21`, used at `crates/core/src/id.rs:10-11,524-526,536,547`,
`sig.rs:10`, `pop.rs:17`, and `id.rs:666` (`x509_cert::spki`). Generic SPKI and PKCS#8
parsing goes through `p256::pkcs8::…`, so dropping or feature-trimming `p256` would break RSA
and Ed25519 code paths that have nothing to do with P-256, and the same `spki` types arrive
by two paths. Fix: depend on `pkcs8` (and `der`) directly at the workspace version and import
them by name. [read]

**Fixed (2026-11-18):** cakeys-core depends on `pkcs8` and `der` directly at the workspace
version (one each in Cargo.lock), and id.rs, sig.rs, pop.rs and plaintext.rs import SPKI and
PKCS#8 types from `pkcs8::` and `der::` by name; no `p256::pkcs8` or `x509_cert::spki` path is
left outside two curve-OID test asserts. A compile-only change: the existing id/sig/pop tests
cover the paths.

### F2. `hmac` without its `zeroize` feature — nit

`crates/core/Cargo.toml:20` (`hmac.workspace = true`; workspace `Cargo.toml:81`,
`hmac = "0.13"`). The proofs key HMAC with the ECDH shared secret and the unwrap secret (see
REVIEW pop.rs F3). hmac's feature only forwards to `digest/zeroize`, which makes the HMAC
type `ZeroizeOnDrop` through digest's buffer macros; enabling it is cheap, but whether it
wipes the sha2 core state too is unverified, as is whether another crate already enables
it. [read]

**Fixed (2026-11-18):** the workspace `hmac` line enables `zeroize`, and cakeys-core enables
sha2's own `zeroize`. Checked in the sources: hmac 0.13 forwards to `digest/zeroize`, which
wipes the block buffers on drop; sha2's feature gives `Sha256VarCore` a wiping `Drop`. digest's
MAC wrapper does not implement `ZeroizeOnDrop` itself, so the guarantee is pinned on the core
state: pop.rs asserts at compile time that `Sha256VarCore: ZeroizeOnDrop`. Two temporaries stay
unwiped upstream (hmac's padded key block in `new_from_slice`, the inner hash in
`finalize_fixed_core`); see REVIEW pop.rs F3.

## Design

None.

## Checked, no issue

- No unused dependency (each of the 27 appears in `crates/core/src`); B7's removals elsewhere
  do not apply here.
- `tempfile` is a normal dependency on purpose (`write_whole`), `rustix` for `access(2)`.
- `quint-connect` and `anyhow` only as dev-dependencies (`tests/lock_mbt.rs`).
