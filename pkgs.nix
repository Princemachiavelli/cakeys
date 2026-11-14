# The flake's own derivations (flake.nix): cakeys and the tools around it. The packages,
# apps, checks and devShell outputs all draw from this one set.
{
  pkgs,
  advisory-db,
  craneLib,
}:
rec {
  cakeys = pkgs.callPackage ./nix/package.nix { };
  # The same build with crane (nix/package-crane.nix): its dependencies built once per
  # Cargo.lock, so the checks (and their clippy and minimal builds) rebuild only cakeys' crates.
  cakeys-crane = pkgs.callPackage ./nix/package-crane.nix { inherit craneLib; };
  # The module measurer and the key mover (README.md, "Three tools"): outputs of the same
  # build.
  inherit (cakeys) caprobe camigrate;
  pcsc-probe = pkgs.callPackage ./nix/pcsc-probe.nix { };
  mezura = pkgs.callPackage ./nix/mezura.nix { };
  # cargo-deny: the sandboxed checks.deny (advisories against the pinned
  # RustSec database, licenses, bans, sources) and the online apps.deny-online (yanked —
  # registry metadata the sandbox has no network for). Configuration: deny.toml.
  deny = pkgs.callPackage ./nix/deny.nix {
    inherit advisory-db;
    cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = ./Cargo.lock; };
  };
  # cargo-fuzz (fuzz/): a fixed-seed smoke run in checks.fuzz, and apps.fuzz for long runs.
  fuzz = pkgs.callPackage ./nix/fuzz.nix { };
  # SoftHSM with the upstream/softhsm/ patch (CKA_VALUE_LEN on unwrapped keys, SoftHSMv2 #628),
  # and the same with SoftHSM's own test suite run: checks.softhsm-unwrap-value-len.
  softhsm-unwrap-value-len = pkgs.callPackage ./nix/softhsm-unwrap-value-len.nix { };
  softhsm-unwrap-value-len-tested = pkgs.callPackage ./nix/softhsm-unwrap-value-len.nix {
    withTests = true;
  };
  # The walkthrough of cakeys' main ideas on SoftHSM and kryoptic: apps.demo, checks.demo.
  demo = pkgs.callPackage ./nix/demo.nix { inherit cakeys; };
  # The demo the checks run, on the crane build.
  demo-crane = pkgs.callPackage ./nix/demo.nix { cakeys = cakeys-crane; };
}
