# The flake's own derivations (flake.nix): cakeys and the tools around it. The packages,
# apps, checks and devShell outputs all draw from this one set.
{ pkgs, advisory-db }:
rec {
  cakeys = pkgs.callPackage ./nix/package.nix { };
  # The module measurer (docs/SCOPE.md, "Three tools"): an output of the same build.
  inherit (cakeys) caprobe;
  pcsc-probe = pkgs.callPackage ./nix/pcsc-probe.nix { };
  mezura = pkgs.callPackage ./nix/mezura.nix { };
  # cargo-deny (NEXT.md §1): the sandboxed checks.deny (advisories against the pinned
  # RustSec database, licenses, bans, sources) and the online apps.deny-online (yanked —
  # registry metadata the sandbox has no network for). Configuration: deny.toml.
  deny = pkgs.callPackage ./nix/deny.nix {
    inherit advisory-db;
    inherit (cakeys) cargoDeps;
  };
  # cargo-fuzz (fuzz/): a fixed-seed smoke run in checks.fuzz, and apps.fuzz for long runs.
  fuzz = pkgs.callPackage ./nix/fuzz.nix { };
  # The walkthrough of cakeys' main ideas on SoftHSM and kryoptic: apps.demo, checks.demo.
  demo = pkgs.callPackage ./nix/demo.nix { inherit cakeys; };
}
