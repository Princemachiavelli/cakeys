# Review: nix/sandbox-hook.sh (47 lines)

Reviewed 2026-11-18 [read]. Summary: the nix-daemon pre-build-hook: reads the derivation's
`requiredSystemFeatures` (plain, structured attrs, `__json`), looks them up in the module's
feature-to-paths map, and prints the existing paths in the hook protocol; always exits 0. Read
by the previous review; re-read. No issues.

## Findings

None.

## Design

- Features are self-declared by derivations, so any user allowed to build can ask for a token's
  paths; the module documents that `allowed-users` is the access control (module.nix:236-241).

## Checked, no issue

- Only `/*.drv` arguments are looked at; anything else grants nothing.
- jq's `index($k)` on an array of strings returns null when absent (falsy) and 0 when first
  (truthy), so the first feature in the list is not missed.
- Paths come only from the map; the module's `strMatching` forbids newlines and a second `=`, so a
  path cannot inject protocol lines. Only existing sources are granted.
- Output ends with a blank line, terminating the `extra-sandbox-paths` block.
