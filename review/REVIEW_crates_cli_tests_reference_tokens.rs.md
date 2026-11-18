# Review: crates/cli/tests/reference/tokens.rs (195 lines)

Reviewed 2026-11-18 [read]. Summary: opening tokens. Provider detected or named; an unset
`pinEnv` (16); two tokens with one label (12) and `tokenSerial`; `pinFile = "$NAME"`; the SO
credential read only by SO steps; PIN counters stopping cakeys before it spends a try. Sound. The
PIN-reset guard has a panic-in-drop hazard and a stale rationale.

## Findings

### F1. `ResetPin::drop` unwraps, so a second failure aborts and hides the first — practice

`reference/tokens.rs:144-149`. The guard runs during unwinding when the test has already failed. If
its `open_rw_session`, SO login or `init_pin` then fails, for example because the token is the one
the failing assertion left in an odd state, the panic inside `Drop` during a panic aborts the
process. The original assertion message is lost. Fix: log the error and return from `drop` instead
of unwrapping. [read]

### F2. The guard's rationale is out of date — nit

`reference/tokens.rs:139-141` says "the regular build runs every test on one token". Both builds
now run a token set per test (nix/test-tokens.sh). The guard is still harmless; the comment should
say why it stays, or the guard can go. [read]

### F3. The SoftHSM path of the PIN-counter test ends after the first case — nit

`reference/tokens.rs:183-185`. This is deliberate (SoftHSM reports only `CKF_USER_PIN_COUNT_LOW`),
but it returns silently. kryoptic covers the 16s. [read]

## Design

None.

## Checked, no issue

- `tokens_that_cannot_be_opened_as_named_are_refused`: `assert_eq!(free.is_some(), provider ==
  "softhsm")` makes kryoptic's missing free slot an assertion, not a skip. Both serials are named
  in the 12.
- `admin_credential_is_read_only_by_security_officer_steps`: a credential file that does not exist
  is never read on SoftHSM's user-session create, and a missing user PIN is 17 at load.
- `pin_counters_stop_cakeys_before_it_spends_a_try` asserts after the run that the last try was not
  spent (`:190`).
