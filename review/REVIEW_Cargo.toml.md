# Review: Cargo.toml (136 lines)

Reviewed 2026-11-18 [read]. Summary: the workspace manifest: 13 members, the tools as default
members, shared dependency versions, workspace lints (unsafe denied, pedantic clippy, missing
docs) and three dev-profile overrides. Tidy; each pin and override says why.

## Findings

### F1. The patched-cryptoki features live on a library, so every build names them by hand — complexity

`Cargo.toml:30-41` (with `crates/pkcs11/Cargo.toml:28-36`). `rv-value` and `sign-after-init` are
features of `cakeys-pkcs11`; the tools forward their own `tpm2`/`ykcs11` but not these, so each
builder spells `cakeys-pkcs11/...` itself: nix/package-common.nix:77-82, nix/package-crane.nix:75
(which has already drifted: no `rv-value`), nix/package-crane.nix:117-131 (mutants' filter),
scripts/local-tests.sh:60 (sed-parses the Nix list). One umbrella feature per tool (for example
`patched-cryptoki = ["kwp", "cakeys-pkcs11/sign-after-init", "cakeys-pkcs11/rv-value"]`) would
make the set one name and keep the lists from diverging. [read]

### F2. A caret requirement on a release candidate — nit

`Cargo.toml:91`. `pkcs12 = "0.2.0-rc.0"` matches every later `0.2.0-rc.N` and `0.2.x`; RCs carry
no compatibility promise, so a `cargo update` may take a breaking RC. Cargo.lock pins it today;
`=0.2.0-rc.0` would make the update deliberate (as `quint-connect` is pinned, line 71). [read]

## Design

- `default-members` includes p11-fault, so a plain `cargo build` builds the fault shim; the Nix
  outputs move it to its own output. Fine.

## Checked, no issue

- `unsafe_code = "deny"` with the two exemptions the comment names.
- `[profile.dev.package.*]` overrides only affect debug builds (local-tests), as stated.
