# Review: nix/module.nix (364 lines)

Reviewed 2026-11-18 [read]. Summary: the NixOS module: per-token system features with a
pre-build-hook granting sandbox paths, pcscd/polkit and TPM ACL support for build users,
uid-range builds, and `checks.<n>`, oneshot units that run `cakeys check` before the units that
use a key, optionally writing what it prints to a file. Options are typed with sensible
defaults; the output-file helper is careful (umask, temp file, rename on success). The weak
points are the check unit's lifecycle and its lack of hardening.

## Findings

### F1. A passed check stays "active" for the rest of the boot: a restarted service is not re-checked — risk

**Verification:** confirmed. nix/module.nix:334-335 sets `Type = "oneshot"; RemainAfterExit = true;` with only `requiredBy`/`before` (:328-330), so a later start of the dependent finds the check unit already active and runs nothing; nix/module-test.nix:230 has to stop the check unit by hand to get a re-check, and no doc states the gate is boot-scoped (module.nix:249-251 says it "blocks" the units). [read]
`nix/module.nix:333-335` (`Type = "oneshot"; RemainAfterExit = true;`). Once the check has passed,
the unit stays active; `systemctl restart signer` (or a crash restart) finds its `Requires=` already
satisfied and starts without running `cakeys check` again. A token wiped or swapped after boot is
then used unchecked until the next reboot, contrary to the option's description ("blocks the units
in requiredBy unless the token holds the locked identity", lines 249-251). nix/module-test.nix:230
has to `systemctl stop ... cakeys-check-signing.service` by hand to get a fresh check, which is
this behaviour. With `RemainAfterExit = false`, `Requires=` + `Before=` re-runs the oneshot on
every start of a dependent (a finished oneshot is not "explicitly stopped", so the dependent is
not stopped); uncertain only in that the module-test sequence should be re-run to confirm. Keep
`outputFile` cleanup as is. [read]

### F2. No ordering after time synchronisation, though `check` now judges certificate dates by the clock — risk

**Verification:** confirmed (low likelihood). The unit orders only after `pcscd.socket` (nix/module.nix:331-332) and docs/CAKEYS.md:40 says `check` judges PIV attestation dates by the system clock (exit 13). Only a `notBefore` later than the boot clock matters; the pinned nixpkgs systemd sets its floor to its release timestamp (pkgs/os-specific/linux/systemd/default.nix:402) and timesyncd restores its saved clock, so it bites mainly a YubiKey manufactured after the systemd release on a host without RTC or saved clock. [read]
`nix/module.nix:329-332`. Since ISSUES.md B8 "Done" (docs/CAKEYS.md:40) `check` holds a PIV
attestation chain to its validity periods by the system clock and fails with 13 outside them. The
unit has `after = [ "pcscd.socket" ]` only. On a host without a battery-backed RTC, early boot runs
with systemd's release-date floor until NTP syncs; a certificate whose `notBefore` is later than
that floor makes the check fail, and a oneshot is not retried, so the gated service stays down for
the boot. How often a Yubico slot or f9 certificate's `notBefore` exceeds the floor is unknown
(probably rarely), hence risk. Add `after = [ "time-sync.target" ]` (with `wants`) for checks, and
note in the docs that `systemd-time-wait-sync` must be enabled for that target to mean anything,
or pass `--at`/`--ignore-validity` through `args` deliberately. [read]

### F3. The check unit runs as root with no sandboxing — practice

`nix/module.nix:333-358`. `cakeys check` loads whatever PKCS#11 module keys.toml or `modules`
names, as root, with full filesystem and network access. No `NoNewPrivileges`, `ProtectSystem`,
`ProtectHome`, `PrivateTmp`, `RestrictAddressFamilies` or `User=`. The check only reads tokens
and writes `outputFile`; `ProtectSystem = "strict"` with `ReadWritePaths` for the output directory
and the token stores (tpm2-pkcs11's sqlite store, SoftHSM's directory), plus the cheap flags,
would contain a misbehaving vendor module. [read]

### F4. Secrets can only reach the check through `environment`, which is world-readable in the store — practice

`nix/module.nix:125-131`, `:329`. `environment` becomes `Environment=` lines in a unit file under
/nix/store. A token configured with `pinEnv` (docs/CAKEYS.md:83) gets its PIN there. There is no
`environmentFile` or `LoadCredential` option, and the option has no warning. Add
`environmentFile` (mapped to `EnvironmentFile=`) or systemd credentials, and say in the
description that `environment` is public. [read]

### F5. A check with no `requiredBy` never runs — nit

`nix/module.nix:132-136`. The default is `[ ]` and the unit has no `wantedBy`, so such a check is
defined but never started, silently. Assert `requiredBy != [ ]`, or add `wantedBy =
[ "multi-user.target" ]` so it at least runs and logs. [read]

### F6. Options without descriptions — nit

`nix/module.nix:111-131`: `token`, `spec`, `environment`. [read]

## Design

- The check unit is the pre-use gate for services, but it is a boot-time gate (F1), and it
  depends on clock and pcscd ordering that the module only partly states (F2). The module test
  covers the happy path and one failure, not a restart after a token change.
- Feature names here and keys.toml's tokens meet only through a string (documented, lines 238-241).

## Checked, no issue

- `writeOutput` (lines 176-195): removes the old file, creates the temp file under umask 077 with
  `mktemp`, renames only on success, trap removes the temp on failure. The parent directory is
  made before the umask (0755), which is fine for a file that is 0600/0640.
- `valuePin` covers `--uri-pin value` and `--uri-pin=value`; with empty `args` the `range` is
  empty. The assertion forbids a value PIN without `outputFile`.
- TPM ACL: the `id-count` multiple-of-65536 assertion matches the slot arithmetic; pcscd
  `PrivateUsers=false` only with auto UIDs.
- `pre-build-hook` is a plain definition, so a second hook conflicts instead of overriding.
