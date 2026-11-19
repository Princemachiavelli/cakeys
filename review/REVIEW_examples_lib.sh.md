# Review: examples/lib.sh (101 lines)

Reviewed 2026-11-18 [read]. Summary: sourced by each example's run.sh: a temporary working
directory, SoftHSM/kryoptic/swtpm token helpers, an OpenSSL config for pkcs11-provider, and
`expect`, which runs a step, shows its output and requires its exit code. Tidy.

## Findings

### F1. Fixed swtpm port — nit

`examples/lib.sh:72`. `TPM_PORT` defaults to 24321 for every example; two example runs on one
host at once (two worktrees) collide, and swtpm's bind error surfaces as a failed `up`. In the
sandbox there is no problem. Randomise as scripts/local-tests.sh does. [read]

**Fixed (2026-11-18):** random TPM port, retried up to four times.

## Design

- The token helpers are another copy of the check phase's setup
  (REVIEW_nix_package-common.nix.md F2).

## Checked, no issue

- Cleanup trap set before any token is made; the TPM is torn down only if it was started.
- `expect` captures stderr and the exit code separately and detects binary stdout before printing.
