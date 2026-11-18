# Review: nix/deny.nix (124 lines)

Reviewed 2026-11-18 [read]. Summary: cargo-deny twice: `check`, offline in the sandbox against the
vendored crates and the flake's pinned advisory-db, and `online`, an app that fetches the live
index for yanked flags and reruns the check with `--deny yanked`. The database-path derivation
(XxHash64 of the URL) is documented and fails loudly if the scheme changes.

## Findings

### F1. No path ever checks against current advisories, and the staleness guard is disabled — risk

**Verification:** confirmed. `install-db` copies the pinned `advisory-db` input and touches FETCH_HEAD (nix/deny.nix:36-42); both `check` (:85) and `online` (:115-121) use it with `--offline`, and no workflow updates flake.lock or the advisory-db input (.github has only checks/flake-check/reports.yml, no dependabot). The header (:11-12) states the pinned database for `online` deliberately, so this is a design gap, not a slip. [read]
`nix/deny.nix:36-42` (`install-db`), `:91-123` (`online`). `install-db` copies the pinned
advisory-db input and `touch`es `FETCH_HEAD`, so cargo-deny's own "database older than 90 days"
error can never fire. That is reasonable for the reproducible sandbox check, but `apps.deny-online`,
the one run with network, installs the same pinned database too and runs `--offline`: it refreshes
yanked flags, not advisories. A RustSec advisory published after the last `nix flake update
advisory-db` is seen by neither, and nothing in .github/workflows updates flake.lock. Let the
online app fetch the database (`cargo deny fetch db` with no `install-db`, then check without
`--offline`), and/or give `FETCH_HEAD` the input's `lastModified` time so the sandbox check fails
once the pin is 90 days old. [read]

## Design

- The check's coverage claim ("duplicate crates and sources") is not backed by deny.toml; see
  REVIEW_deny.toml.md F1.

## Checked, no issue

- `check` builds a writable copy of the workspace and points cargo at the vendored sources, all
  offline; reproducible with the flake.lock.
- `online` uses a throwaway `CARGO_HOME` removed by a trap, and `cargo fetch --locked` leaves
  Cargo.lock untouched.
