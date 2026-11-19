# Review: nix/ftpm-test-env.sh (69 lines)

Reviewed 2026-11-18 [read]. Summary: the opt-in real-TPM environment: a private D-Bus and
tpm2-abrmd over /dev/tpmrm0, a fresh tpm2-pkcs11 store with a transient primary (or, with
`persistent`, the platform SRK read-only). The safety notes are thorough and the code matches
them: nothing is made persistent, no NV write, right PIN only.

## Findings

### F1. `rm -rf "$D/store"` on an unchecked argument — nit

`nix/ftpm-test-env.sh:30`. `set -u` catches a missing `$2` but not an empty one: `up ""` removes
`/store`. Refuse an empty or relative `D` before the `rm`. [read]

**Fixed (2026-11-18):** an empty or relative <dir> is refused (both scripts) before any rm.

### F2. `down` does not wait for abrmd to exit — nit

`nix/ftpm-test-env.sh:60-64`. Unlike nix/tpm2-test-env.sh, it returns at once; a caller that
starts a second `up` immediately (scripts/coverage-full.sh runs one up/down per run, so not today)
could meet the old abrmd still holding the TPM connection. [read]

**Fixed (2026-11-18):** `down` is tpm2-test-env.sh's waiting stop.

## Design

- Duplication with nix/tpm2-test-env.sh: see that review's F3.

## Checked, no issue

- Uses `/dev/tpmrm0`, never `/dev/tpm0`; `tpm2_getcap` probes are bounded by `timeout`.
- With `persistent`, the store is parented under 0x81000001 without creating or evicting it.
