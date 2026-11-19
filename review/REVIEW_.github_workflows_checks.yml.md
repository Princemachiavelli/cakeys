# Review: .github/workflows/checks.yml (40 lines)

Reviewed 2026-11-18 [read]. Summary: the light CI gate: `nix build .#checks-no-vm` on pushes to
main, pull requests and manual runs, with Determinate Nix and magic-nix-cache. Actions pinned by
commit, `contents: read`, checkout without persisted credentials, telemetry off. Read in full by
the previous review; re-read.

## Findings

### F1. The light and full gates run side by side on every push — practice

`.github/workflows/checks.yml:6-10` vs `.github/workflows/flake-check.yml:6-10`. Both trigger on
the same events, and `checks-no-vm` is a subset of `nix flake check`, so each push builds and
tests the crane build twice in parallel (magic-nix-cache only helps once one of them has pushed).
If the light gate is meant as fast feedback, have flake-check `needs:` it (one workflow, two
jobs), or run flake-check only on main and on a label. [read]

**Fixed (2026-11-18):** one workflow, checks.yml, with three jobs that split the checks
between them (flake.nix `vmChecks`): `light` (`checks-no-vm`, after `nix flake check
--no-build`), `vm` (`checks-vm`: the VM tests and the fuzz run) and `kani`, on a runner of its
own. flake-check.yml is gone; `checks.ci-jobs` fails when the workflow stops building a part, or
when a second workflow builds them again.

### F2. The header's list of what runs is incomplete — nit

`.github/workflows/checks.yml:1-3`. `checks-no-vm` also includes `examples`, `quint`, `profiles`,
`lib` and `minimal` (flake.nix:137-145 subtracts only fuzz, kani and the VMs). [read]

**Fixed (2026-11-18):** the header names the three jobs and says the list is an example.

## Design

- x86_64-linux only; see REVIEW_flake.nix.md F1.
- `runs-on: ubuntu-latest` floats with GitHub's image updates; the Nix build is insulated from it,
  the "Free disk space" paths are not.

## Checked, no issue

- Actions pinned by full SHA with the version as a comment; `permissions: contents: read`;
  `persist-credentials: false`; concurrency cancels superseded runs per ref.
- Fork pull requests get a read-only token and no secrets; their magic-nix-cache entries are
  scoped to the PR ref.
