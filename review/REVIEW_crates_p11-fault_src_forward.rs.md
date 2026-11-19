# Review: crates/p11-fault/src/forward.rs (179 lines)

Reviewed 2026-11-18 [read]. Summary: one macro that generates the `Fn` enum, an `extern "C"`
forwarder per 2.40 slot (each inside `guard`), and the shim's `CK_FUNCTION_LIST`. The table
literal names every slot, so a missing one does not compile; signatures come from
`cryptoki-sys`. Compact and correct; one ABI risk in the table's version.

## Findings

### F1. The shim's 2.40-sized table carries the real module's version — risk

**Verification:** confirmed (downgraded to nit). forward.rs:101-104 does copy `real.version` into a 2.40-sized `CK_FUNCTION_LIST`, but cryptoki 0.12.1 picks a 3.x layout only from `C_GetInterface`'s list (`context/mod.rs:113-127`), which the shim does not export, and otherwise takes `C_GetFunctionList`'s table as `FunctionList::V2` unconditionally (:151-162); no in-tree client or reference module was found that makes the overread reachable. [read]
`crates/p11-fault/src/forward.rs:101-104`. `table()` copies `real.version`. If the real module
reports a 3.x version in the table `C_GetFunctionList` returns, a client that picks the table
layout from that version (treating it as a `CK_FUNCTION_LIST_3_0`, as some 3.0-aware clients
do when `C_GetInterface` is absent) reads the 24 extra slots past the end of the shim's
`CK_FUNCTION_LIST` (into the rest of the `Shim` static) and calls whatever it finds. Whether any
reference module reports 3.x there, and whether cakeys' other clients (OpenSSL's provider, NSS)
switch on it, was not checked; cryptoki and p11-kit use `C_GetInterface` or treat the list as
2.x. docs/FAULT_SHIM.md `:62` documents the copy. Cap the version at 2.40 until the 3.x
interface exists.
[read]

**Fixed (2026-11-18):** `table()` passes the real version on only up to 2.40 and says 2.40 above
it; docs/FAULT_SHIM.md "Loading" says so. Test: `the_table_says_no_more_than_2_40`.

## Design

- The hook dispatch (`=> hook`) is by convention: a hooked function must forward on its own,
  and `substitute_key` relies on the key being the third argument (`plan::KEY_FUNCTIONS`). The
  macro arms pin the argument shapes, so a mismatch fails to compile; good.

## Checked, no issue

- Every forwarder runs inside `guard` and resolves the real slot with `ok_or_else(Fatal)`,
  never `unwrap` (`:24`, `:80-95`).
- A slot the real module leaves `NULL` stays `NULL` in the shim's table (`:105`).
- `C_GetFunctionList` in the shim's table points at the shim's unexported `get_function_list`,
  not the real module's.
- `Fn as usize` indexes `plan.counts`, sized from `Fn::ALL` in the same order (`plan.rs:165`).
- Trace readers run after the call returns, with the same pointers the caller passed.
