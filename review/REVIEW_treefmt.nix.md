# Review: treefmt.nix (91 lines)

Reviewed 2026-11-18 [read]. Summary: formatters and linters for `nix fmt` and
`checks.formatting`: deadnix, statix, nixfmt, keep-sorted, rumdl, rustfmt, shellcheck, shfmt,
taplo, typos; patches, key material and lock files excluded. Fine.

## Findings

None.

## Design

- shellcheck sees `.sh` files only. Shell embedded in Nix strings (nix/package-common.nix
  `preCheck`/`postCheck`, the `runCommand` bodies in checks.nix and nix/examples.nix) is never
  linted; only `writeShellApplication` bodies are shellchecked, at build. Much of the shell the
  checks depend on is in the unlinted category.

## Checked, no issue

- Fixers run before nixfmt (priorities 1-3).
- `*.lock` excluded, so taplo never reflows a generated keys.lock.
