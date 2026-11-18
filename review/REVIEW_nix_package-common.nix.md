# Review: nix/package-common.nix (232 lines)

Reviewed 2026-11-18 [read]. Summary: what the regular and the crane build share: source set,
outputs, inputs, the six cryptoki patches, the features that use them, the test scope, and the
check-phase token environment (SoftHSM and kryoptic templates, a p11-kit server, a swtpm stack).
Well documented; the cryptoki patch list and feature list are the single source the other
builders and scripts/local-tests.sh read.

## Findings

### F1. The global p11-kit server and swtpm are a silent fallback for any suite test-tokens.sh does not list — risk

**Verification:** confirmed (latent). preCheck exports the global p11-kit and TPM stacks (nix/package-common.nix:198-202, :209-214) and nix/test-tokens.sh:91-110 replaces them only for the listed suites. Closest case: camigrate's `from_files` (unlisted) calls `xref::env` (crates/cli/tests/common/xref.rs:45-60), which picks up the global `CAKEYS_P11KIT_CLIENT`/`CAKEYS_TPM_MODULE` and writes those tokens into keys.toml, but its specs use only softhsm/kryoptic (crates/camigrate/tests/from_files.rs:63-69), and camigrate's `fault` builds its own Env (fault.rs:29); so no suite touches the shared stack today. [read]
`nix/package-common.nix:198-202`, `:209-214`; `nix/test-tokens.sh:80-101`. preCheck starts one
p11-kit server and one swtpm/abrmd stack and exports their addresses (`P11_KIT_SERVER_ADDRESS`,
`TPM2_PKCS11_*`, `DBUS_SESSION_BUS_ADDRESS`) to every test process. test-tokens.sh gives a suite
its own server/TPM only if its binary name is in a hard-coded list (`p11kit | reference |
references | dry_run`, `tpm2 | references | dry_run`). A new suite that uses p11-kit or the TPM
but is missing from those lists therefore passes in Nix on a stack shared by every parallel test
(the cross-test interference the per-test design exists to prevent), while scripts/local-tests.sh,
which starts no global stack, fails it. Today every user is listed (checked with `rg` over
`crates/*/tests`), so this is latent. Fix: do not export the global stack's variables (or do not
start it: with `CAKEYS_TOKEN_TEMPLATE` set, test-tokens.sh always provides its own), so an
unlisted suite fails loudly in both places. [read]

### F2. The token setup is copied into about ten scripts — complexity

`nix/package-common.nix:173-189`. The same `softhsm2.conf` printf + `--init-token` and the
kryoptic slot table + two `pkcs11-tool` init calls appear in nix/test-tokens.sh:75-83,
scripts/local-tests.sh:103-113, scripts/regen-profiles.sh:157-167, scripts/pkcs11-check.sh:196-208,
nix/demo.sh:108-117, examples/lib.sh:50-66, nix/test.nix:123-130, nix/module-test.nix:202-207,
scripts/xversion.sh:24-26, upstream/softhsm/repro*.sh and scripts/cloud/aws.sh:389-394.
local-tests.sh is an explicit hand copy of this preCheck. A change (a kryoptic option, a SoftHSM
setting) must be made in each, and the regen script and the check phase can drift apart, which
matters because the probe's profiles must match what the check phase re-probes. One
`nix/token-env.sh init-softhsm|init-kryoptic <dir> <label>` sourced by all would remove it. [read]

## Design

- ISSUES.md Q4 "Done" spot-check: `../upstream/rust-cryptoki/0003-...patch` is in the patch list
  (line 69) and `cakeys-pkcs11/rv-value` in `features` (line 81). The regular and crane main
  builds both take this list; only the crane `minimal` build deviates (REVIEW_nix_package-crane.nix.md F1).
- `canCheck` keeps cross builds from depending on every token package; good.

## Checked, no issue

- `withTpm2 = false` turns on `ykcs11` explicitly and `--no-default-features`, and excludes the
  TPM crate from `--workspace`; consistent with the crates' feature tables.
- The token templates are copied before the global p11-kit `up` adds `kmp11`, so per-test sets
  start clean.
- `postCheck` stops both global stacks.
