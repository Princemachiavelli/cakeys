# Review: nix/demo.sh (341 lines)

Reviewed 2026-11-18 [read]. Summary: the five-act walkthrough on SoftHSM and kryoptic: first use
(18), recording, the Nix view, a lost and a planted key (11, 14, 10), one identity across two
modules, and a planned sealed migration. Every step states its exit code and the demo stops on
any other, so checks.demo tracks cakeys' behaviour. Well structured.

## Findings

### F1. With `jqf`, a jq failure replaces the command's exit code — nit

`nix/demo.sh:57-68`. The comment says "the exit code stays the command's", but under `pipefail` the
status of `"$@" | jq -c "$jqf"` is the last failing command's: when cakeys exits non-zero and prints
nothing parseable on stdout (an error before its JSON), jq fails too and `code` is jq's (2 or 5), so
the demo reports "exit 5, expected 10" for what was a different cakeys failure. Capture the
command's status separately (`PIPESTATUS[0]`). [read]

**Fixed (2026-11-18):** the command's status when it failed, else jq's (PIPESTATUS).

### F2. `--keep` cleanup references variables set later — nit

`nix/demo.sh:22-29`. Under `set -u`, a failure before line 108 makes the trap's `$SOFTHSM2_CONF`
unbound and the trap itself errors. Use `${SOFTHSM2_CONF-}`. [read]

**Fixed (2026-11-18):** `${VAR-}` in the trap.

## Design

- The token setup duplicates the check phase's (REVIEW_nix_package-common.nix.md F2).

## Checked, no issue

- ISSUES.md "To test: create and exit 19" and the 2026-11-17 `create` change: act 1 creates once
  (18), act 3 `create` on a pinned, lost key expects 14, act 5 `create --token soft` expects 10
  for the planted `signing` while creating the unpinned keys; these match the "Done" behaviour in
  ISSUES.md (a pinned pair verified as `check` does, lost is 14) [read; checks.demo runs it].
- `work` comes from `mktemp -d` and is removed unless `--keep`.
