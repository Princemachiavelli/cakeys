# Review: crates/p11-fault/src/lib.rs (248 lines)

Reviewed 2026-11-18 [read]. Summary: the shim's loader (own path and tag via `dladdr`, settings
from the environment, `dlopen` of the real module, its function list), the per-call driver
(`Shim::call`) and `guard`, which stops panics at the C boundary. Thread safety holds: the shim
is one `OnceLock`, rules are immutable, counters atomic, the trace behind a `Mutex`. Findings are
about diagnostics, not soundness.

## Findings

### F1. Only the first `Fatal` of the process is ever printed, and a hook's `Fatal` leaves no trace line — practice

`crates/p11-fault/src/lib.rs:34-37` and `:181`. `Fatal::report` prints through one static
`Once` for every message, so after any fatal (or the load failure) a later, different one —
`from_label: no object labelled …`, `resolving a label: C_OpenSession returned …` — is
silent. And `Shim::call` returns at `forward(&call)?` before `trace.line`, so the failed call
is missing from the trace, although its counter was incremented. A test then sees
`CKR_GENERAL_ERROR` with no explanation in either place. Keep the `Once` for the load failure
only, print hook fatals each time (or once per message), and trace the call with its `rv`.
[read]

### F2. A panic while loading leaves `LOADING` set and later reports a recursion that did not happen — nit

`crates/p11-fault/src/lib.rs:64-68`. If `Shim::load` unwinds, `LOADING.set(false)` is skipped,
the `OnceLock` stays empty, and `guard` returns `CKR_GENERAL_ERROR` silently (`:200`); the next
call on that thread fails with "P11_FAULT_MODULE leads back to this shim". Nothing in `load`
is expected to panic, so this is about clarity; a drop guard resets it.
[read]

## Design

- The plan's call counters are process-wide and survive `C_Finalize`/`C_Initialize` cycles
  (`plan.rs:197`), as documented; a client that re-initialises sees `call = n` count across
  cycles.

## Checked, no issue

- Unsafe: `dladdr` on a zeroed `Dl_info`, `dli_fname` null-checked before `CStr::from_ptr`
  (`:76-91`); `C_GetFunctionList` result checked for `CKR_OK` and non-null before `&*list`
  (`:153-163`); the library is kept for the process, so `&'static` holds; `*out` written only
  when non-null (`:224-230`).
- Re-entrance: a module whose load calls back into this shim on the same thread is refused,
  not deadlocked on the `OnceLock` (`:61-63`); a shim pointed at itself is refused (`:133`).
- `guard` covers every exported entry point (`C_GetFunctionList` and every forwarder, see
  `forward.rs:80`); the workspace sets no `panic = "abort"`, so `catch_unwind` is effective.
- Tagged copies read only their tagged variables (`variable`), so stacked shims do not share
  settings.
