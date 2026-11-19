# Review: nix/module-test.nix (236 lines)

Reviewed 2026-11-18 [read]. Summary: VM test of the NixOS module: nix.conf settings, pcscd from
the sandbox with auto UIDs (plain and structured-attrs derivations), the hook's per-feature
grants, uid-range builds, and the check unit gating an OpenSSL signer through a key file. The
assertions are specific (exact return codes, file mode and group, signature verified).

## Findings

### F1. The gate is only tested from a stopped state — risk

**Verification:** confirmed. nix/module-test.nix:229-231 deletes the key, then `systemctl stop signer.service cakeys-check-signing.service` before the failing start, so the restart-while-check-active path (REVIEW_nix_module.nix.md F1, module.nix:334-335) is never exercised. A test gap that hides that finding, not an independent defect. [read]
`nix/module-test.nix:228-234`. After deleting the key the test runs `systemctl stop
signer.service cakeys-check-signing.service` before starting the signer again; without stopping
the check unit the signer would start on the earlier pass (REVIEW_nix_module.nix.md F1). Add the
case that matters in production: key deleted, `systemctl restart signer.service`, expect failure.
It fails today, which is the point. [read]

**Fixed (2026-11-18):** the check unit has `RemainAfterExit = false`, so each start of a
unit in `requiredBy` runs it again, and it is ordered after `time-sync.target` without pulling it
in (systemd.special(7)); the option and docs/CAKEYS.md say a synchronized clock needs
`systemd-time-wait-sync`. Test: `checks.module` restarts the signer after deleting the key, with
no hand stop of the check unit, and expects the restart to fail with the check unit's
`Result=exit-code` (the signer fails without the key either way); it asserts the passed check
is inactive with `Result=success`, and `time-sync.target` in `After` but not `Wants`/`Requires`.

### F2. Setup duplicated with nix/test.nix — complexity

`nix/module-test.nix:18-33` (keys.toml), `:202-207` (softhsm2.conf and token init),
`:158-162` (guest build helper) repeat nix/test.nix:17-43, :123-130, :103-109, and the build helper
is in nix/tpm-test.nix:71-77 a third time. A small shared `nix/vm-common.nix` (keys.toml writer,
SoftHSM init commands, guest build helper) would keep the three in step. [read]

### F3. The module's assertions are not exercised — nit

`nix/module.nix:321-324`, `:311-314`. Neither "`--uri-pin value` needs `outputFile`" nor "pcscd
token needs `sandbox.pcscd.enable`" is tested; an evaluation-only check (like checks.lib) with
`builtins.tryEval` over a failing configuration would cover both cheaply. [read]

## Design

None beyond F1.

## Checked, no issue

- Structured-attrs probe reads `$out` from `NIX_ATTRS_SH_FILE`.
- ISSUES.md "To test: create and exit 19": the test calls `create` once, then `lock`; no second
  create of a pinned key, so the B2 change does not affect it.
- The test uses the patched SoftHSM because pkcs11-provider over stock 2.7.0 fails (documented).
