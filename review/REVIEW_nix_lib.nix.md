# Review: nix/lib.nix (194 lines)

Reviewed 2026-11-18 [read]. Summary: `mkKeys`, the builtins-only view of keys.toml and keys.lock:
per object a function that resolves the (spec, token) pair and returns the type, the pinned IDs,
the token's system feature and the `check` command line, every word shell-escaped. Read in full by
the previous review; re-read for this batch. Sound and well tested by checks.lib.

## Findings

### F1. A lock path that does not exist is silently "no lock" — nit

`nix/lib.nix:65`. `hasLock = lock != null && builtins.pathExists lock`. In a git flake, a
keys.lock that is committed locally but not `git add`ed (or mistyped) is invisible, so `id` is
empty and `check` runs without `--lock`. It fails closed (cakeys reports first use, 18, with
`got:`), but the message then points at recording an ID that is already recorded. Throwing when
`lock` is a path that does not exist, and accepting `null` for "not yet", would separate the two
cases; nix/examples.nix and examples/secure-boot/sign.nix currently rely on the silent form. [read]

**Fixed (2026-11-18):** a non-null lock path that does not exist throws (id and check); null is not yet recorded. Test: `checks.lib` assertions.

## Design

None.

## Checked, no issue

- ISSUES.md N2 "Done": `type` is the lock's canonical one once it pins the object, keys.toml's
  without `migrate` before (line 149); asserted by checks.nix:221-245.
- Lock `version` other than 1 throws; ambiguous or missing pairs throw at the call, not lazily
  (`builtins.seq pick`).
- `escapeShellArg` matches nixpkgs' rule; hostile names are tested in checks.lib.
