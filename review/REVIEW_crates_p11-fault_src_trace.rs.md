# Review: crates/p11-fault/src/trace.rs (313 lines)

Reviewed 2026-11-18 [read]. Summary: the JSON-lines call log and the readers (`Detail`) that pull
the mechanism, its parameters, user type, flags and template types/classes out of a call's
arguments after it returns. The unsafe readers are careful: mechanism parameters are read only
when `ulParameterLen` equals the structure's size, unaligned; template values only when 8 bytes
long. One-write-per-line keeps concurrent processes' lines whole.

## Findings

### F1. Output readers trust the caller's memory when no real call filled it — nit

`crates/p11-fault/src/trace.rs:155-183` and `:192-212`, with `lib.rs:186`. `ok` is the `rv`
the caller saw, after the plan: a `when = "before"` rule returning `CKR_OK` on
`C_GetTokenInfo`/`C_GetSlotInfo`/`C_GetMechanismInfo` skips the real call, yet the trace reads
`flags` out of the caller's unfilled struct and logs whatever was there. `template` does not
look at `ok` at all, so a failed `C_GetAttributeValue` logs classes and key types from buffers
the module may not have written. The values are only logged (no UB beyond reading the caller's
own bytes), but a test reading them gets garbage. Read outputs only when the real call ran and
succeeded.
[read]

**Fixed (2026-11-18):** `Detail::ok` is set from the real call's own `rv` (false when a rule
answered before it), and `C_GetAttributeValue` reads its template through `filled_template`,
which takes the types always and the values only when `ok`. Tests:
`outputs_are_read_only_where_the_module_filled_them`, `a_filled_template_gives_values_only_when_filled`.

## Design

None.

## Checked, no issue

- `mechanism`: null-checked; `fits` requires `pParameter` non-null and the exact size before
  each `read_unaligned`; `CKM_RSA_AES_KEY_WRAP`'s nested OAEP pointer null-checked.
- `initialize`: reads `CK_C_INITIALIZE_ARGS.flags` only when non-null.
- `template`: count converted with `try_from`, null or empty template skipped.
- `line`: a poisoned mutex or failed write is dropped, never changes the caller's result; the
  `expect` is on a literal JSON object and cannot fail (and is inside `guard`).
- `rv` names come from `p11_names::rv_name`, hex otherwise.
