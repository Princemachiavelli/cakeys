# Publishing to crates.io: review

Written 2026-11-15. Nothing is published: `publish = false` stays in `[workspace.package]` until
the blockers below are fixed. The tools ship through the flake meanwhile (README.md, "Nix").

## Names

Every name was free on crates.io on 2026-11-15 (checked against the API, with `serde` as the
control), as were the similar names `cakey`, `ca-keys`, `p11fault` and `pkcs11-fault`:

| Crate | Source lines | Role |
|---|---|---|
| `cakeys-core` | 5,473 | config, lock, content-addressed identity (no token access) |
| `cakeys-pkcs11` | 4,776 | the PKCS#11 backend and the `Provider` trait |
| `camigrate` | 4,492 | moves keys between tokens |
| `caprobe` | 2,756 | measures modules into capability profiles |
| `p11-fault` | 2,092 | a fault-injecting PKCS#11 module (below) |
| `cakeys-tpm2-pkcs11` | 1,721 | tpm2-pkcs11 provider (tss-esapi, sqlite) |
| `cakeys-profile` | 1,354 | capability profiles |
| `cakeys-ykcs11` | 652 | YubiKey PIV provider |
| `cakeys-kmsp11` | 529 | Google Cloud KMS provider |
| `cakeys` | 411 | the pinning and verifying tool |
| `cakeys-cli-common` | 135 | what the three tools share |
| `cakeys-aws-cloudhsm` | 134 | AWS CloudHSM provider |

They follow the conventions: kebab-case, no `-rs` suffix, one `cakeys-` prefix for the family
(as `tokio-*`). `caprobe` and `camigrate` sit outside the prefix, which suits installable tools.

**Ownership.** A crates.io name belongs to its owners (users or a GitHub team), not to a
repository. Splitting the repository changes only the `repository` field of the next release.

**Nothing is reserved until published.** The crates.io usage policy removes a crate that
"exists only to reserve a name for a prolonged period of time ... without having any genuine
functionality, purpose, or significant development activity". A real 0.1 is fine; an empty
placeholder risks deletion.

## Blockers

`cargo package --workspace` on a copy with `publish = true` stops at `cakeys-profile`. With the
profiles copied under `crates/profile/` and its `include_str!` paths pointed there, all twelve
crates package and verify (default features, against the unpatched cryptoki of the registry).
Run it with the plain `cargo`, not the dev shell's `auditable-cargo` wrapper, which asks
crates.io for the workspace's own unpublished crates and fails at the first binary.

1. **`cakeys-profile` embeds 13 files from `profiles/`**, outside its crate directory
   (`crates/profile/src/embedded.rs`). The package does not contain them and does not build.
   Every tool depends on it. Fix: move the profiles under `crates/profile/`. This is the only
   thing that stops `cargo package`.
2. **No crate ships `LICENSE`.** BSD-3-Clause requires the notice to travel with redistributed
   source, and a crate tarball is that. Fix: a copy (or symlink, which cargo follows) per crate.

The cryptoki dependency does block packaging as it stands: the workspace depends on
`cryptoki` and `cryptoki-sys` as git sources at a pinned rev of rust-cryptoki's main (it has
`sign_single` and the vendor mechanisms in the list, which 0.12.1 lacks), and crates.io refuses a
crate with a git dependency without a version beside it. Publishing waits for a cryptoki release
that has both (the dependency goes back to the version), or the dependency becomes
`version = "0.12", git = ...` (cargo publishes the version) with the code needing `sign_single`
and the vendor arm behind features. The patches are not a block: no default feature needs them.
A registry build does less (see "Patches"): `kwp` does not compile if enabled, and without the
HMAC key-type fix SHA-224/384/512 HMAC keys are refused.

## Smaller gaps

- **Tests do not build from the tarballs:** about 25 integration-test includes of
  `crates/cli/tests/common`, and unit tests that include fixtures from other crates
  (`camigrate/src/file.rs`, and caprobe's `#[cfg(test)]` `baseline.rs`). Publishing does not
  build tests, but distribution packagers run them. Self-contained tests or `exclude`.
- **No README, `keywords` or `categories`** in any crate.
- **`pkcs12 = "0.2.0-rc.0"`** accepts every later release candidate: pin it (`=`) or wait for 0.2.
- **docs.rs:** set `[package.metadata.docs.rs]` without `all-features` (the patch features do
  not compile there). tss-esapi-sys skips linking under `DOCS_RS`, and rusqlite is bundled, so
  the default features should document.

Already in place: edition 2024 and `rust-version` (checked by `checks.msrv`), `missing_docs`,
the rustdoc check, `unsafe_code = "deny"`, cargo-deny, `repository` on every crate, a `version`
on every path dependency, and small packages (the largest 103 KiB compressed).

## Patches

A published crate cannot ask for a patched dependency. The ways out:

1. **Upstream** (preferred). rust-cryptoki [#373](https://github.com/parallaxsecond/rust-cryptoki/pull/373)
   (HMAC key types), [#376](https://github.com/parallaxsecond/rust-cryptoki/pull/376)
   (`CKM_AES_KEY_WRAP_KWP`) and [#377](https://github.com/parallaxsecond/rust-cryptoki/pull/377)
   (`CKM_RSA_AES_KEY_WRAP`, draft) are open; `Session::sign_single` and the vendor arm are on
   main already and cakeys uses them (upstream/rust-cryptoki/).
2. **A renamed fork** depended on with `cryptoki = { package = "..." }`. Its types would not
   interoperate with any other crate using `cryptoki`; avoid.
3. **The current design**, which suits a registry once cryptoki has a release with main's
   changes: `kwp` is off by default, so a stock build compiles and does less. Document on the
   feature that it needs the patched cryptoki. The HMAC fix cannot be a feature, so stock builds
   refuse those key types until #373 is released.

## How many crates

Twelve crates in one workspace is ordinary on crates.io (tokio, clap, cargo and wasmtime each
publish many internal crates). What matters is that every dependency of a published crate must
be published too: `cargo install cakeys` needs eight of these. Each one is a public API to
version and keep compatible.

- **The provider crates stay separate, by design.** `cakeys-ykcs11`, `cakeys-tpm2-pkcs11`,
  `cakeys-kmsp11` and `cakeys-aws-cloudhsm` are built exactly as an outside provider would be:
  against the `Provider` trait and the few items `cakeys-pkcs11` makes public for it. They are
  the demonstration, and the proof that the public surface a provider needs stays small and
  compatible; a provider that reached into internals would not compile. Their size (134 to
  1,721 lines) shows the interface is small, not that the crates are too many. The TPM one also
  keeps tss-esapi and sqlite away from whoever does not need a TPM.
- **`cakeys-cli-common` (135 lines)** is the one crate that is internal glue rather than an
  interface: published, it becomes a public crate to keep stable. Fold it into `cakeys-pkcs11`
  behind a `cli` feature, or keep it and say in its docs that it is internal and released in
  lockstep with the tools.

The published set would then be eleven: everything but `cakeys-cli-common`, or all twelve with
it marked internal.

## p11-fault

Probably the most broadly useful crate here: one built `libp11_fault.so` serves every fault.
It is configured from the environment at the first `C_GetFunctionList`, so any PKCS#11 client
(pkcs11-tool, OpenSSL's pkcs11-provider, NSS, p11-kit, cakeys) can load it unchanged:

- `P11_FAULT_MODULE`: the real module it forwards to.
- `P11_FAULT_PLAN`: a TOML plan (unset, it is a pure forwarder). Rules name PKCS#11 things only:
  a function and optionally its n-th call or one object by `CKA_LABEL`, then a return value
  before or after forwarding, a flag, a dropped or swapped attribute (docs/FAULT_SHIM.md).
- `P11_FAULT_TRACE`: one JSON line per call.

The plan is read once per process, so another fault is another plan file and another process,
never another build.

It is the one crate that packages and verifies on its own today (10 files, 22 KiB compressed):
it depends only on `cryptoki-sys`, `libloading`, `serde`, `serde_json` and `toml`, none of them
patched. Open before publishing:

- **How users get the `.so`.** `cargo install` installs binaries only, never a cdylib. Options:
  prebuilt `.so` files as GitHub release assets, the flake's `packages.p11-fault` (already
  there), and the crates.io source for `cargo build`. A small Rust API for test harnesses
  (write a plan, return the environment to set) would make the crate itself useful as a
  dev-dependency; how a dependent crate finds a dependency's cdylib needs checking first.
- **The 3.x interface:** v1 exports only the 2.40 entry point, so a client that needs a
  3.x-only function gets `CKR_FUNCTION_NOT_SUPPORTED`. Worth stating in its README.
- Its own README with a plan example, and `keywords` (`pkcs11`, `testing`, `fault-injection`).

## Badges

The README carries the CI, license, MSRV, coverage and mutation badges (the last two read from
the `badges` branch, which `.github/workflows/reports.yml` and `mutants.yml` write). At the first release add crates.io
(`img.shields.io/crates/v/<name>`), docs.rs (`docs.rs/<name>/badge.svg`) and dependency health
in its per-crate form (`deps.rs/crate/<name>/<version>/status.svg`). Not the repository form:
deps.rs does not resolve `dep.workspace = true` and reports "dependencies: none" for this repo.
