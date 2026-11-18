# Review: scripts/coverage-full.sh (159 lines)

Reviewed 2026-11-18 [read]. Summary: one coverage report over the software suites (inside
local-tests' environment) plus the opt-in YubiKey and real-TPM suites, run one test at a time,
with the real TPM's persistent handles and lockout counter compared before and after. The
hardware precautions (PIN files never read, a failed YubiKey login not retried, slot 95 wiped
only on request) are careful.

## Findings

### F1. No cleanup if the real-TPM environment fails to come up — practice

`scripts/coverage-full.sh:115`. `bash nix/ftpm-test-env.sh up "$F"` runs under `set -e` with no
trap; if it fails after starting dbus-daemon and tpm2-abrmd (e.g. `tpm2_getcap` timing out on a
busy TPM), the script exits and leaves a private tpm2-abrmd attached to the host's
/dev/tpmrm0. Set `trap 'bash nix/ftpm-test-env.sh down "$F"' EXIT` before `up`. [read]

### F2. `errexit` is off inside the TPM subshell, so its fallback line is dead — nit

`scripts/coverage-full.sh:116-139`. Bash ignores `set -e` inside a command whose status is tested
by `||`, so `( ... ) || echo "real TPM: the run stopped"` never fires for a failing `. "$F/env"`
or `tpm2_getcap`: the subshell carries on and ends with the status of its last test. The
outcomes are still conservative (an empty `after` or `lockout` is reported as a change), but the
"run stopped" line suggests a guard that is not there. Check the critical steps explicitly
(`. "$F/env" || exit 1`) inside the subshell. [read]

## Design

None.

## Checked, no issue

- The hardware variables are captured and unset before the software pass, so it cannot touch the
  YubiKey or the real TPM.
- The report is written whether or not a suite failed, and the exit status says whether one did.
- The persistent-handle comparison excludes cakeys' own 0x81000016, as documented.
