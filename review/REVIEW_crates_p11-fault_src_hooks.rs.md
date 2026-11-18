# Review: crates/p11-fault/src/hooks.rs (445 lines)

Reviewed 2026-11-18 [read]. Summary: the hooks that change arguments or outputs (flags, find
results, mechanism list, attribute values, key substitution, output corruption) and the
label-to-handle resolver on a session of the shim's own. Unsafe use is careful: every pointer is
null-checked, caller buffers are bounded by caller-given lengths, and the ISSUES.md "p11-fault
counts" fix is in place. Three findings weaken the "a rule that fired changed something"
guarantee docs/FAULT_SHIM.md relies on, or the bound-everything standard the counts fix set.

## Findings

### F1. `use_label` reports its rule fired when the label resolves to nothing — risk

**Verification:** confirmed. hooks.rs:199 returns `(…first().copied().unwrap_or(key), Some(i))`, so with no object under the label the caller's own key is used and the trace records rule `i` as fired, while `from_label` (:266-268) raises `Fatal` in the same situation. [read]
`crates/p11-fault/src/hooks.rs:199`. `named(...).first().copied().unwrap_or(key)` keeps the
caller's key when no object carries the label, yet returns `Some(i)`, so the trace line says
`"rule": i`. docs/FAULT_SHIM.md (`:228`, `:320`) makes "the trace says the rule fired" each
fault test's guard against "a plan that matches nothing makes a test pass for the wrong
reason". A `use_label = "decoy"` typo (or a decoy the test forgot to create) then runs the real
key and the test's fired-assertion still passes. `from_label` (`:270`) fails loudly in the same
situation. Return `None` (or a `Fatal`) when nothing is substituted.
[read]

### F2. `corrupt_output` trusts the length the module wrote back — risk

**Verification:** confirmed (downgraded to nit). hooks.rs:168-179 flips `out[*len - 1]` from the post-call `*len` with no record of the caller's room (forward.rs:40-51 captures none), but it runs only on `CKR_OK`, and a module returning `CKR_OK` with `*len` larger than the buffer has already broken the contract (it wrote past the buffer or lied about it). Worth the same one-line cap as the counts fix, but not reachable with a conformant module. [read]
`crates/p11-fault/src/hooks.rs:168-179`, called from `forward.rs:40-51` after the real call.
It flips `out[*len - 1]` using the module's post-call `*len`, never the caller's buffer size
before the call. A module that reports more bytes than the caller's buffer (the very case the
"p11-fault counts" fix stopped believing in `find_objects`/`mechanism_list`) makes the shim
write past the caller's buffer. Capture `*len` before forwarding (as `mechanism_list` does at
`:128`) and corrupt only when `0 < n <= room`.
[read]

### F3. `add_label` can return the same handle in several batches — risk

**Verification:** confirmed (downgraded to nit). The dedupe is per call (hooks.rs:96-103, `found.contains(&h)` on this batch only), so a module that returns matches over several short batches gets the decoy appended to each. cryptoki 0.12.1's iterator stops after the first short batch (`object_management.rs:157-163`), and an empty batch adds nothing (`!found.is_empty()`), so no client the tests use sees a duplicate; it is a docs/FAULT_SHIM.md:284 wording gap. [read]
`crates/p11-fault/src/hooks.rs:96-103`. The "already found" check is per call
(`found.contains(&h)`), so a real search that returns its matches over several partial
batches (allowed by PKCS#11) gets the decoy appended to each, and the client sees one object
twice. docs/FAULT_SHIM.md `:284` says "`add_label` skips a handle already found". cryptoki
0.12's iterator stops at the first short batch (`session/object_management.rs:157` in the
registry copy), and a full batch leaves no room to add, so cakeys' tests are unaffected today;
a client that reads until a call returns zero (pkcs11-tool-style) sees the duplicate. Track the handles
added per caller session until `C_FindObjectsFinal`, or add only once per search.
[read]

### F4. A failed `C_FindObjectsInit` is reported as `C_FindObjects` — nit

`crates/p11-fault/src/hooks.rs:399-413`. `rv` from `C_FindObjectsInit` falls through to
`failed("C_FindObjects", rv)`.
[read]

## Design

- A `Fatal` from a hook (label resolution failing) is raised after the real call may have
  consumed state (e.g. a batch of the caller's search in `find_objects`, `:75` then `:89`); the
  caller gets `CKR_GENERAL_ERROR` and the batch is lost. Acceptable for a test tool, but worth a
  sentence in the doc.

## Checked, no issue

- ISSUES.md "p11-fault counts" (Fixed since): `find_objects` clamps `*count` to `max`
  (`:79-83`); `mechanism_list` reads the caller's room before the call and clamps (`:128`,
  `:137`); both write back at most what fits.
- `attribute_value`: the caller's template is sliced only when non-null and `count > 0`; the
  unruled entries go to the real module in a copy whose `pValue`s are the caller's buffers;
  lengths are copied back; `serve` writes only when `ulValueLen >= len`.
- `value_of`: refuses `CK_UNAVAILABLE_INFORMATION`, sizes the buffer from the first call,
  truncates to the second call's length.
- `named`: its own session, always closed; `C_FindObjectsFinal` on every opened search.
- `class_of`: `try_into` an 8-byte array, so a short value is `None`, not a panic.
- `token_info`/`slot_info`: touch `flags` only after `CKR_OK` and a non-null pointer.
