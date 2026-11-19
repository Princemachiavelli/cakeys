# Review: nix/kani.nix (134 lines)

Reviewed 2026-11-18 [read]. Summary: Kani 0.68.0 built from source with crane on the nightly its
rust-toolchain.toml names: driver and compiler, the three sysroots, wrappers putting the nightly,
CBMC, Kissat and gcc on PATH. The library Cargo.lock is checked in to avoid IFD and compared with
the toolchain's at build time. Careful and self-checking (ldd, `kani --version`).

## Findings

### F1. The nightly date is written twice — nit

`nix/kani.nix:37-38`. `nightly = "nightly-2026-08-21"` and `rustBin.nightly."2026-08-21"`; a bump
that changes one leaves the rpath directory name and the toolchain disagreeing. Derive one from
the other. [read]

**Fixed (2026-11-18):** the nightly read from kani-src's rust-toolchain.toml; derivation unchanged (same drv path).

## Design

- Memory: the proofs this tool runs need up to 5.7 GB (nix/package-crane.nix); the package itself
  does not bound it, see REVIEW_nix_package-crane.nix.md F2.

## Checked, no issue

- `CARGO_NET_OFFLINE=true`: a missing vendored crate fails the build instead of fetching.
- The `cmp` of library-Cargo.lock against the toolchain's fails with an actionable message.
- `dontStrip` keeps the rlib metadata.
