# Review: nix/test-tokens.sh (103 lines)

Reviewed 2026-11-18 [read]. Summary: cargo's target runner for the token suites: copies the
SoftHSM and kryoptic templates into a per-test directory, starts a per-test p11-kit server and
swtpm for the suites that need them, optionally routes every module through a tracing p11-fault
copy, runs the test, and cleans up on exit. Read by the previous review; re-read.

## Findings

### F1. Which suite gets a p11-kit server or a TPM is a hard-coded name list — complexity

`nix/test-tokens.sh:80-101`. `p11kit | reference | references | dry_run` and `tpm2 | references |
dry_run` must name every test binary that uses those environments; a new suite left out silently
falls back to the check phase's shared global stack in Nix (REVIEW_nix_package-common.nix.md F1)
and fails under scripts/local-tests.sh. Starting both lazily for every suite that has
`CAKEYS_P11KIT_CLIENT`/`CAKEYS_TPM_MODULE` set costs a few hundred ms per test; alternatively keep
the list but make the global fallback fail. [read]

**Fixed (2026-11-18), the fallback half:** the list stays, and the check phase's shared
p11-kit server and swtpm are gone, so a suite left out of it fails in both places.

### F2. Port fallback outside nextest can collide — nit

`nix/test-tokens.sh:92`. Without `NEXTEST_TEST_GLOBAL_SLOT`, `$$ % 4000` can give two concurrent
processes the same port pair; swtpm then fails to bind and the test fails with a log tail. Only
reachable when the runner is used without nextest. [read]

**Fixed (2026-11-18):** without nextest, up to four random slots, retrying when `up` fails (a failed up cleans itself).

## Design

None.

## Checked, no issue

- `"$@"` runs as a child, not `exec`, so the EXIT trap tears down the per-test daemons; `--list`
  is `exec`ed untouched.
- The shim copy is made atomically (`cp` to `$copy.$$`, then `mv -f`).
- `suite=${suite%-*}` strips cargo's hash from binary names; test names with `::` are mapped to
  file names.
