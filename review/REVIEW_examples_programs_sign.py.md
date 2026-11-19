# Review: examples/programs/sign.py (55 lines)

Reviewed 2026-11-18 [read]. Summary: an example program that names a cakeys object, runs `cakeys
check --uri-module --uri-pin source`, parses the URI (RFC 7512) and signs stdin with
python-pkcs11, exiting with cakeys' code when the check fails. A good pattern to show.

## Findings

### F1. `pin-source=env:` is not handled, and the docstring says cakeys never writes it — practice

`examples/programs/sign.py:39-42`. "a file (`file:` or a bare path); cakeys writes no other", but
docs/CAKEYS.md:83 says `--uri-pin source` writes `pin-source=file:` or `env:` (`pinFile`/`pinEnv`).
Copied into a deployment whose token uses `pinEnv`, the program opens a file named `env:NAME` and
dies with `FileNotFoundError` after the check passed. Handle `env:` (`os.environ[...]`) or state
the restriction correctly. [read]

**Fixed (2026-11-18):** `env:NAME` read from the environment. Test: examples/programs/run.sh signs with `pinEnv` (old: FileNotFoundError, mutation-checked).

### F2. A signal-killed `cakeys` gives a negative exit status — nit

`examples/programs/sign.py:25-27`. `sys.exit(run.returncode)` with `-15` exits 241. Map negative
codes to 128+N or 1. [read]

**Fixed (2026-11-18):** negative return codes exit 128+N.

## Design

None.

## Checked, no issue

- Path attributes are unquoted to bytes (`id` is binary), query attributes to text.
- The key is looked up by `CKA_ID` from the verified URI; only the private key class is accepted.
