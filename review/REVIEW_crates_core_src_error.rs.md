# Review: crates/core/src/error.rs (223 lines)

Reviewed 2026-11-18 [read]. Summary: `KmError` with stable exit codes and `Msg`, a message
that may carry the `CK_RV` of the module call that failed (Q3). Correct and small; the
variant-to-message match is written out three times, and one display prefix is misleading.

## Findings

### F1. The same ten-arm match three times — complexity

`crates/core/src/error.rs:163-177`, `:181-195`, `:208-222`. `msg_mut`, `rv` and `into_msg` each
list all ten `Msg`-carrying variants; a new variant must be added to all three (and to
`exit_code`). Fix: a `fn msg(&self) -> Option<&Msg>` beside `msg_mut`, with `rv` as
`self.msg().and_then(Msg::rv)`; `into_msg` stays as the by-value form. [read]

### F2. `Validation` displays as "invalid spec:" for lock, config and option errors — nit

`crates/core/src/error.rs:124-126`. Exit 17 covers an invalid keys.toml, an invalid keys.lock
(`config.rs:855`, every lock invariant), token options and CLI addresses, but every one prints
`invalid spec: keys.lock: object 'a' …`. A user reading "invalid spec" for a broken lock looks
in the wrong file. Fix: `#[error("invalid: {0}")]`, or let the message carry its own subject
(it already starts with the file name). Changing it touches tests that match on the prefix. [read]

## Design

None.

## Checked, no issue

- Exit codes are distinct and match docs/CAKEYS.md's list (10–20, 1 for I/O).
- Q3 (Done): `Msg` displays its text only; `with_rv` sets the value on every message variant
  and is a no-op on `HashMismatch`/`FirstUse`, which no module call produces.
- `Msg: Deref<Target = str>` keeps the many `m.contains(...)` matches in tests working.
