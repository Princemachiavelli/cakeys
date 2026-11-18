# Review: nix/pkcs11-check.nix (83 lines)

Reviewed 2026-11-18 [read]. Summary: packages the third-party pkcs11-check suite (and its missing
dependency pytest-reportlog) from a tagged release, hash-pinned, with its site directories added to
`PYTHONPATH` for the suite's subprocesses. Used ad hoc, never as a check (as intended).

## Findings

None.

## Design

None.

## Checked, no issue

- `fetchFromGitHub` by tag with a hash; `fetchPypi` with a hash.
- `pythonImportsCheck` proves the module loads, which is all the package promises.
