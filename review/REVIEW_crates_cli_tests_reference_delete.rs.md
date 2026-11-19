# Review: crates/cli/tests/reference/delete.rs (221 lines)

Reviewed 2026-11-18 [read]. Summary: the EC lifecycle (11 → create 18 → lock → verify/check → wrong
If-Match 14 → delete → absent 0 → D1 refusal), `gc` printing and applying exactly what is stale,
and a foreign public key under a private key's locator (13 for every resolving verb, 16 without
login, only identified objects deleted). Strong tests. Two documented behaviours have no test.

## Findings

### F1. A correct `--if-match` is never tested — practice

`reference/delete.rs:52-53` is the only `--if-match` in the cakeys tests, and it is the wrong value
(14). The success path (`--if-match <locked id>` deletes, docs/CAKEYS.md) and an If-Match without a
lock are untested. A regression that makes `--if-match` always refuse, or that ignores it in favour
of the lock, would pass. [read]

### F2. docs/CAKEYS.md cites a test that does not exist — nit

docs/CAKEYS.md (the `delete` row) names `delete_removes_only_what_it_identified`. The test is
`a_foreign_public_key_conflicts_and_is_never_deleted` (`reference/delete.rs:153`). [read]

**Fixed (2026-11-18):** docs/CAKEYS.md names `a_foreign_public_key_conflicts_and_is_never_deleted`. Test: `a_foreign_public_key_conflicts_and_is_never_deleted`.

### F3. `ec_lifecycle` does not check the token after `delete` — nit

`reference/delete.rs:55-57` infers removal from `verify` → 11. It does not check that the public
half went too, which `delete` promises when the half holds the same key. The foreign-key test does
check object counts (`:208-220`). [read]

### F4. `gc --apply` holding the sidecar lock is untested — nit

docs/CAKEYS.md says `gc --apply` "holds the update lock". `reference/lockfile.rs:206-247` tests
the sidecar only for `lock`. [read]

## Design

None.

## Checked, no issue

- `gc_prints_then_removes_stale_entries`: the printed lines equal what `--apply` removes. Object
  `ids` survive a spec's removal, the orphaned observation is collected with its realisation, and
  the object itself goes only when keys.toml drops it.
- A present object with no expected identity is never deleted (14), and absent is success even
  without a lock.

## Resolutions (2026-11-18)

- F1 **Fixed (2026-11-18):** `--if-match <locked id>` deletes, and `--if-match` with no lock deletes. Test: `ec_lifecycle`.
- F3 **Fixed (2026-11-18):** no object labelled `ec-lifecycle` is left after the delete. Test: `ec_lifecycle`.
- F4 **Fixed (2026-11-18):** `gc --apply` waits for a held `<lock>.lck`. Test: `update_lock_waits_for_the_sidecar_lock` (helper `waits_for_the_sidecar`).
