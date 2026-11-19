# Review: crates/camigrate/src/host.rs (213 lines)

Reviewed 2026-11-18 [read]. Summary: the `host` path. The key is extracted from the source under
a host-drawn session KEK (`Token::extract`), held in `Zeroizing` memory, checked against the
locked `rfc7093m4` on the host before any write, then created by `C_CreateObject` or
`tpm2_ptool`, recorded by `ops::lock_import`, and removed by handle on failure. Plaintext handling
is tight. Its weak spots are the `tpm2_ptool` reopen and checks repeated between `import` and
`create_and_record`.

## Findings

### F1. A failed reopen after `tpm2_ptool import` leaves the key in the TPM unrecorded and unmentioned — risk

**Verification:** confirmed. host.rs:172-174 imports, then `reopen(target, notes)?` returns early; the closure (lib.rs:568-572) sets the target to `None` before reopening, so nothing can even try to remove it, and only the `lock_import` branch (:177-187) notes or destroys the stray object. The next run's `free_locator` (:161) refuses the locator with 13. [read]
`crates/camigrate/src/host.rs:172-174`. After `to.import_plaintext(…)` succeeds,
`reopen(target, notes)?` returns early if the second `C_Initialize`/login fails (a busy TPM, a
transient resource-manager error). The key is in tpm2-pkcs11's store, nothing records it, and
the error says only why the reopen failed. The next run's `free_locator` refuses that locator
with 13 ("the lock records no realisation there"), and no message names the stray object. On
reopen failure, add a note naming what was imported and how to remove it
(`tpm2_ptool rmobject`), as the `lock_import` failure branch (`:179-186`) already does. [read]

**Fixed (2026-11-18):** a failed reopen says the key is in the TPM, unrecorded, with the
`cakeys lock` and `tpm2_ptool rmobject` steps. Test: `a_failed_reopen_after_ptool_says_what_is_in_the_tpm`.

### F2. `import` repeats the checks `create_and_record` makes again — complexity

`crates/camigrate/src/host.rs:39-45` against `:84-105`. `already_there`, `ops::check_import` and
`free_locator` run once in `import` (before extraction, on purpose: "nothing is in plaintext yet
when it refuses") and again in `create_and_record`. The second pass costs a few more
`C_FindObjects`, and the order of checks now has two copies to keep in step. Give
`create_and_record` a `prechecked` variant, or split out an `ensure_landing(dst, to, spki)` that
both call once. [read]

**Fixed (2026-11-18):** the checks are `landing` (`ops::check_import`, then `free_locator`) and
`check_identity`, each asked once: `import` runs `landing` before the key is in memory and
`check_identity` after, then `create_landed`; `create_and_record` (key files) runs
`check_identity`, `landing`, `create_landed`; `import_ptool` uses `landing` too. A refactor
with no change in what is refused; the token suites' refusal tests (dry_run.rs "would collide
with") cover it.

### F3. `free_locator` duplicates `public::preflight` — nit

`crates/camigrate/src/host.rs:122-135` and `crates/camigrate/src/public.rs:170-184`. Both run
the same `Token::occupied` call with the same `colliding > 0` refusal, worded slightly
differently, and return different halves of `Occupied`. One function returning `Occupied` would
do. [read]

**Fixed (2026-11-18):** `public::free_locator` is the one occupancy check (one message); host,
sealed and the key-file verbs call it, and `public::preflight` is it for a public object.

## Design

- `create_and_record` is the one funnel every plaintext key passes through before an
  irreversible write (from a token, `--in`, or an object's own file). It is the right place for
  every "never write this here" rule: the host identity check is already here, and the
  PIV-attestation refusal (lib.rs F1/F2) should be too.

## Checked, no issue

- The host-side identity check (`:89-101`) runs before `free_locator` and before any write.
  With nothing pinned it is 10 with "a locked rfc7093m4" expected. `from_its_file` puts the host
  IDs into the lock first, so first use passes.
- Plaintext lifetime: `hand_over` returns `Zeroizing`, `import_ptool` drops it right after the
  tool runs, and `create_and_record` only borrows it. `private_from_pkcs8` parts are wiped
  (ISSUES B16).
- ykcs11 gets no public key object (`accepts_public_key_objects`).
- `import_ptool`'s rollback `destroy` removes every private and public key under the locator.
  That is only the import, since `free_locator` and the `public_half` refusal (`:161-170`)
  established the locator held neither class before.
