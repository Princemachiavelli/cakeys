# Review: pkgs.nix (82 lines)

Reviewed 2026-11-18 [read]. Summary: the flake's own derivation set: both cakeys builds, the
tools around them (caprobe/camigrate outputs, p11-fault, pcsc-probe, mezura, pkcs11-check,
cloud tools, kmsp11, CloudHSM, cargo-deny, Kani, fuzz, patched SoftHSM, demo). Small and
straightforward.

## Findings

None.

## Design

- `msrvToolchain` (lines 15-19) reads `rust-version` from Cargo.toml at evaluation, so the MSRV
  check follows the manifest.
- `deny` vendors Cargo.lock through `importCargoLock` (lines 56-59): a git dependency would need
  `outputHashes`; none today.

## Checked, no issue

- `kani` is passed to `cakeys-crane` only on x86_64-linux (line 27), matching `meta.platforms` in
  nix/kani.nix, so `checks.kani` exists only there.
- `kmsp11`/`cloudhsm` are defined for every system but exported only on x86_64-linux
  (flake.nix:147-155); lazily evaluated.
