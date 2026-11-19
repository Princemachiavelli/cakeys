# Review: nix/tpm2-test-env.sh (66 lines)

Reviewed 2026-11-18 [read]. Summary: starts swtpm (pinned `default-v1` profile), a private D-Bus
and tpm2-abrmd, waits for the TPM with bounded probes, initialises a tpm2-pkcs11 store with token
`kmtest`; `down` stops them by PID file and waits for each to exit. Solid: no unbounded sleeps,
daemons detached from the caller's pipes.

## Findings

### F1. A failed `up` leaves the daemons running — practice

`nix/tpm2-test-env.sh:19-47`. With `set -e`, a failure after swtpm or dbus started (port in use,
`tpm2_getcap` timeout, `tpm2_ptool` error) exits with swtpm, dbus-daemon and abrmd still
running; the PID files exist, so `down` can stop them, but only if the caller calls it. Callers
that set their trap before `up` are fine (nix/test-tokens.sh, examples/lib.sh,
scripts/pkcs11-check.sh); scripts/regen-profiles.sh:41-42 does not (see its review). A trap inside
`up` that runs `down` on error would make every caller safe. [read]

**Fixed (2026-11-18):** `up` sets an EXIT trap running the stop of what it started, cleared on success. Test: local-tests run with tpm2 suite; no failing-up test committed (see report).

### F2. `down` never escalates — nit

`nix/tpm2-test-env.sh:52-60`. After 5 s it gives up silently; a wedged swtpm then breaks the
caller's `rm -rf` with the error this wait exists to avoid. Send SIGKILL after the wait. [read]

**Fixed (2026-11-18):** SIGKILL after 5 s, then a 2 s wait; zombies count as gone.

### F3. The D-Bus/abrmd/env block is duplicated in nix/ftpm-test-env.sh — complexity

`nix/tpm2-test-env.sh:24-45` vs nix/ftpm-test-env.sh:32-52: identical apart from the TCTI and the
abstract socket name. One shared function (or `ftpm` as a mode of this script) would keep the two
from drifting. [read]

**Fixed (2026-11-18):** the D-Bus/abrmd/env block is one function; nix/ftpm-test-env.sh is a wrapper calling `device-up`, keeping its differences (no --flush-all, no CAKEYS_TPM_SWTPM, device TCTI, its init).

## Design

None.

## Checked, no issue

- The abstract socket name includes PID and port, so concurrent instances do not collide.
- The PINs on `tpm2_ptool`'s command line are the fixed test PINs (ISSUES.md accepts the same for
  the product path).
