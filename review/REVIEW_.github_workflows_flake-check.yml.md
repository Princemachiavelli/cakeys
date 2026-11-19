# Review: .github/workflows/flake-check.yml (44 lines)

Reviewed 2026-11-18 [read]. Summary: the full CI gate: `nix flake check -L` (VM tests, fuzz smoke,
Kani included) after checking that /dev/kvm is writable. Pinned actions, read-only permissions.

## Findings

### F1. Everything heavy shares one 16 GB runner — risk

**Verification:** confirmed (risk, unquantified). flake-check.yml:44 is one `nix flake check -L` job; the kani derivation (nix/package-crane.nix:256-272) sets no memory bound, has `cargoArtifacts = null` so nothing orders it after the crane build, and docs/OPEN.md:297 records 5.7 GB for fix_ec_point. The VM figure is overstated: only module-test sets 2048 MB (nix/module-test.nix:150); vm and tpm (two nodes) use the 1 GB default. Same root as REVIEW_nix_package-crane.nix.md F2; no ISSUES.md entry. [read]
`.github/workflows/flake-check.yml:44`. `nix flake check` builds Kani's proofs (up to 5.7 GB,
nix/package-crane.nix:251-254) concurrently with three NixOS VMs (2 GB each for the module test)
and the crane build. An OOM kill fails the job with an unhelpful log. Uncertain: depends on
max-jobs and timing. Splitting Kani (and perhaps fuzz) into its own job would make the failure
modes separate and the runs shorter. [read]

**Fixed (2026-11-18):** one workflow, checks.yml, with three jobs that split the checks
between them (flake.nix `vmChecks`): `light` (`checks-no-vm`, after `nix flake check
--no-build`), `vm` (`checks-vm`: the VM tests and the fuzz run) and `kani`, on a runner of its
own. flake-check.yml is gone; `checks.ci-jobs` fails when the workflow stops building a part, or
when a second workflow builds them again.

## Design

- `nix flake check` builds only the runner's system (x86_64-linux); aarch64-linux and
  aarch64-darwin outputs are never built or even evaluated in CI (REVIEW_flake.nix.md F1).
- Overlaps with checks.yml on every trigger (REVIEW_.github_workflows_checks.yml.md F1).

## Checked, no issue

- The KVM guard turns a slow emulated VM run into an immediate failure.
- Same pinning and permission hygiene as checks.yml.
