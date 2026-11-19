# Review: flake.nix (272 lines)

Reviewed 2026-11-18 [read]. Summary: the flake's outputs (packages, apps, checks, devShell,
NixOS module, formatter) over one per-system evaluation (`perSystem`), with the derivations in
pkgs.nix and the checks in checks.nix. Clean and well commented; inputs are locked by flake.lock
(nixpkgs as a channel tarball with a narHash, the others by rev). No evaluation-time impurity
(`builtins.currentSystem`, IFD, unpinned fetch) was found.

## Findings

### F1. Three systems declared, one ever built — risk

**Verification:** confirmed. flake.nix:51-55 declares three systems; flake-check.yml:44 runs plain `nix flake check -L` on `ubuntu-latest` (x86_64), which builds only the current system's checks, and REVIEW_nix_examples.nix.md F1 (verified) is a live aarch64-linux failure it misses. [read]
`flake.nix:51-55`, `.github/workflows/flake-check.yml:44`. The flake serves x86_64-linux,
aarch64-linux and aarch64-darwin, but CI runs `nix flake check` / `nix build .#checks-no-vm` on
an x86_64 runner, which builds only that system's checks. A Linux-generic check that is in fact
x86-specific goes unnoticed: `checks.aarch64-linux.examples` fails today (nix/examples.nix
hard-codes `linuxx64.efi.stub`, see REVIEW_nix_examples.nix.md F1). Add an aarch64-linux job
(GitHub has arm64 runners), or at least `nix flake check --no-build --all-systems` so the other
systems' evaluation errors surface. [read]

**Decided (2026-11-18):** the user decided CI builds x86_64 only.

## Design

- `nixosModules.default` defaults `services.cakeys.package` to `packages.cakeys`, the regular
  `buildRustPackage` build, while every check runs `cakeys-crane`. They share
  nix/package-common.nix, so the risk is small, but the build a deployment gets is not the one
  the VM/module tests exercised.
- `checks-crane-only` and `checks-no-vm` are defined by subtraction (`removeAttrs`), so a new
  heavy check lands in the light CI gate by default; the safer default.

## Checked, no issue

- `pkgsCloudhsm`: unfree allowed by name prefix only, evaluated only when used.
- `legacyPackages.pcscSandboxProbe` takes a nonce, documented as uncached on purpose.
- devShell: `inputsFrom = [ local.cakeys ]` plus the token tools; the patched SoftHSM the tests
  need is fetched by scripts/local-tests.sh itself.
