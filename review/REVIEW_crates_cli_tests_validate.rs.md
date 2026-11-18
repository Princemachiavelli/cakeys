# Review: crates/cli/tests/validate.rs (130 lines)

Reviewed 2026-11-18 [read]. Summary: the static gate. `validate` against fixture configurations
and the committed profiles, with no token or module: a profile's "no" refuses (15) and names the
profile, the lock's observation chooses profiles when keys.toml names no provider, and the
generation note appears once. It runs everywhere, including plain `cargo test`.

## Findings

### F1. A third way to run the binary, without the environment scrub — complexity

`validate.rs:10-15` copies `common::BIN` and runs `Command::new(BIN)` without removing
`NIX_BUILD_TOP`, `IN_NIX_SHELL` or `CAKEYS_LOCK`. `validate` passes `--config` but no `--lock`, so a
developer's `CAKEYS_LOCK` decides which lock supplies the observations (`:36-69`), and the result
depends on the caller's environment. See common/mod.rs F1 and F5. [read]

### F2. The profile verdict is pinned with its exact prose — nit

`validate.rs:26, 30`: `"no — kryoptic/1.5"` and `"CKM_AES_KEY_WRAP: no — p11-kit/0.26"`, em dash
included. The exit (15) is the contract. The profile name is a reasonable pin, but the punctuation
is not. [read]

## Design

None.

## Checked, no issue

- The branch on `cakeys_pkcs11::binding::patched()` asserts both outcomes, so neither is skipped.
- The fixtures are read in place from the source tree. `validate` never writes, so this is safe.
- `:33` asserts that what the profiles allow is not reported (a negative control).
