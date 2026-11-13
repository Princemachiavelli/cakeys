# Next: Rust and crypto-library best practices (2026-11-12) — done

All five items from the plan at deb0365 are implemented (uncommitted; CHECKPOINT.md has the
entry). The plan, and what became of it:

1. **Dependency advisories (`cargo-deny`).** `deny.toml` + the `advisory-db` flake input +
   `checks.deny` (`nix/deny.nix`): the database is pinned and the crate graph vendored from
   `Cargo.lock`, so the check runs offline in the sandbox (licenses, bans and sources too).
   The expected RUSTSEC-2023-0071 ignore turned out not to be needed: the current database
   marks the rsa 0.10 series patched (`patched = [">= 0.10.0"]`), which is what the workspace
   pins — verified against the pinned database with a scratch rsa 0.9.0 project, where the
   advisory does fire. Yanked stays allowed offline (yanked-ness is registry metadata, not an
   advisory, and the sandbox has no network); `nix run .#deny-online` runs the same check on
   the host with the live index and `--deny yanked` — verified to fire on a hand-locked
   yanked version (cargo refuses to resolve one, so what it guards is a yank after locking).
2. **Clippy in `nix flake check`.** `checks.clippy`: `cargo clippy --workspace --all-targets
   -- -D warnings` over the same build environment as the package.
3. **`[workspace.lints]`.** `unsafe_code = "deny"` (the two exemptions are `#[allow]`ed:
   `crates/tpm2-pkcs11/src/attest/esys.rs`, `crates/core/src/config.rs`) plus `clippy::pedantic`
   with one blanket allow (`must_use_candidate`: plain lookups in an internal workspace) —
   the ~230 warnings pedantic reported are fixed, and every other exemption is a per-site
   `#[allow]` with its reason, so a new occurrence anywhere warns.
4. **`// SAFETY:` comments.** On both `Tss2_MU_*` blocks in `esys.rs`; `config.rs`'s already
   had one.
5. **Constant-time comparison from a crate.** `pop::ct_eq` is now `subtle::ConstantTimeEq`
   (also a direct dependency of cakeys-core), covering both proof comparisons (`pop-ecdh`
   and `pop-decrypt`).

The "already done right" list below is unchanged.

## Already done right

- The PIN and the admin credential are held in `Zeroizing` and wiped after use.
- Randomness comes from the OS RNG (`getrandom`, `sys_rng`).
- The RustCrypto crates are built with `default-features = false` and only the features needed.
- Public keys are re-encoded canonically before hashing, so module encoding quirks never change
  an identity.
- The ECDSA hash comes from the signature algorithm (prehash), not from the curve.
- `Cargo.lock` is committed, and every dependency is on its latest release (DESIGN §6.4).
