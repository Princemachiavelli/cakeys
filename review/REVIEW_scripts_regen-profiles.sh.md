# Review: scripts/regen-profiles.sh (67 lines)

Reviewed 2026-11-18 [read]. Summary: regenerates the three committed reference profiles
(SoftHSM, kryoptic, tpm2-pkcs11 over swtpm) with a write probe on fresh tokens, diffing each
against the committed one and treating exit 15 (drift) as "written for review". Short and
clear; the probe must be the Nix-built caprobe, and the header says how to build it.

## Findings

### F1. It probes stock SoftHSM; the conformance test re-probes the patched one — practice

`scripts/regen-profiles.sh:16`, `:23`. The instructions put `nixpkgs#softhsm` (stock 2.7.0) on
PATH and the script takes the module from `softhsm2-util`'s location. The build's conformance
test, which re-probes and compares against the committed profile, runs on
`softhsm-unwrap-value-len` (nix/package-common.nix:44, :178), and apps.nix:103-104 states the
profiles were probed on that build. The four patches change unwrap (#628), multi-part ECDSA
(#857) and OpenSSL context handling (#834); the probe's current rows appear insensitive to them
(caprobe/src/probe.rs:1647-1679 asks only whether a `CKA_VALUE_LEN` template is refused, and the
profile's [manual] notes say the probe never reads the unwrapped length), so the regenerated file
probably matches today. But the regeneration and the check compare two different modules, and
the memory rule "regenerate, don't drift" assumes they are the same. Build
`.#softhsm-unwrap-value-len` in the script (as scripts/local-tests.sh:26 does) and drop
`softhsm` from the instructions. [read]

**Fixed (2026-11-18):** builds and uses `.#softhsm-unwrap-value-len` (module and softhsm2-util); `softhsm` dropped from the instructions.

### F2. The TPM stack is started before the cleanup trap is set — nit

`scripts/regen-profiles.sh:41-42`. If `tpm2-test-env.sh up` fails after starting swtpm (for
example on a port in use, the case the comment at line 40 anticipates), the script exits with
swtpm, dbus-daemon and tpm2-abrmd left running on the host. Set the trap first; `down` tolerates
missing PID files. [read]

**Fixed (2026-11-18):** trap set before `up`.

### F3. Stale reference in the header — nit

`scripts/regen-profiles.sh:4`. "set up the way the Nix check phase sets it up (nix/package.nix)":
that setup is in nix/package-common.nix. [read]

**Fixed (2026-11-18):** header names nix/package-common.nix.

### F4. Paths written into TOML unescaped — nit

`scripts/regen-profiles.sh:46-49`. A `<dir>` or module path containing `"` or `\` yields an
invalid keys.toml. Unlikely for the documented use. [read]

**Fixed (2026-11-18):** paths written as escaped TOML strings (`toml_string`).

## Design

- The token setup duplicates the check phase's (REVIEW_nix_package-common.nix.md F2); since the
  profiles must regenerate byte for byte against what the check phase probes, this is the copy
  where drift costs most.

## Checked, no issue

- `--diff` and exit 15 handling: drift does not abort the loop; any other code is returned.
- Uses its own swtpm port (`TPM_PORT`, default 23311) so it can run beside the check phase.
