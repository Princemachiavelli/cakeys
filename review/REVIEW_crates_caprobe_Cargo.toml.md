# Review: crates/caprobe/Cargo.toml (70 lines)

Reviewed 2026-11-18 [read]. Summary: library plus binary, `tpm2`/`ykcs11` forwarded to
cli-common, `kwp` for the patched-cryptoki key wraps, the hardware test targets gated on their
features.

## Findings

### F1. The probe's correctness depends on `cakeys-pkcs11/rv-value`, which this manifest does not express — risk

**Verification:** confirmed. `kwp = []` forwards nothing (Cargo.toml:27); `rv-value` is enabled only in nix/package-common.nix:76-82 (and scripts/local-tests.sh, which reads that list), while the crane `minimal` package (nix/package-crane.nix:72-76, built as a check, checks.nix:33) applies the same cryptoki patches but omits `cakeys-pkcs11/rv-value`, so `binding::patched()` (pkcs11/src/binding.rs:30) is true there and `rv_value` returns `None` (pkcs11/src/token/mod.rs:267-275). Nothing in-tree runs `probe` from `minimal`, so the damage is latent. [read]
`crates/caprobe/Cargo.toml:21-27`; `nix/package-crane.nix:75`.
The write probes decide "busy session, undetermined" by `CK_RV` (probe.rs F2), which exists only
with `cakeys-pkcs11/rv-value`. caprobe has no feature that turns it on (`kwp = []` forwards
nothing), so the right combination lives only in `nix/package-common.nix`'s list; the crane
`minimal` package's own list leaves `rv-value` out. Fix: give caprobe a feature (e.g. make
`kwp`, or a new `patched` feature, enable `cakeys-pkcs11/rv-value`) so the build lists cannot
diverge, and check it at run time before writing a profile. [read]

**Fixed (2026-11-18):** each tool has one `patched-cryptoki` feature implying `kwp`, `rv-value`
and `sign-after-init`, which the Nix builds (package-common.nix `features`, the crane `minimal`
build) name instead of the parts. `caprobe probe` refuses to write or diff a profile unless the
binding is patched and both `rv-value` and `kwp` are on (`build_lacks`), and the tests of
`cakeys-pkcs11` and caprobe fail when the patched binding is linked without them. Tests:
`a_kept_profile_needs_every_patch_and_feature`, `the_patched_binding_comes_with_its_features`.

### F2. Normal dependencies repeated under dev-dependencies — nit

`crates/caprobe/Cargo.toml:36-41`, `:50`, `:54`, `:56`.
`aes`, `cryptoki` and `sha2` are both dependencies and dev-dependencies; the dev entries add
nothing. [read]

**Fixed (2026-11-18):** the three dev-dependency entries are gone.

## Design

None.

## Checked, no issue

- `cakeys-cli-common` comes from the workspace with `default-features = false`, so
  `--no-default-features` really drops tpm2/ykcs11; the `tpm2`, `ftpm` and `yubikey` test targets
  are gated on the matching features.
