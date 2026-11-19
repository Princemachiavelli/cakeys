# Review: crates/camigrate/src/lib.rs (1525 lines)

Reviewed 2026-11-18 [read]. Summary: the camigrate CLI (clap types, `dispatch`) and every verb's
driver: `export` (bundle or key file), `import` (bundle, `--in` key file, objects' own files),
`migrate`, `transport`/`--trusted`, plus the plan glue (`Run::plan`, `landing_checks`) and the
landing-pair rules (`import_target`, `specs_select`). The per-object error collection and the
lock save before reporting a failure are careful, and plaintext stays in `Zeroizing` buffers. The
weak points are guards that live only in the planner (and so are skipped by paths that do not
plan, or plan without `--spec`), and a file that mixes CLI parsing with three verbs' logic.

## Findings

### F1. The landing checks ignore `--spec`, so a dry run and `migrate` skip them for an object with several import specs — bug

**Verification:** confirmed. `landing_checks` (lib.rs:788) calls `import_target(…, None, MOVE)`, which errs "several specs; pass --spec" (:979-981), and returns silently; `no_import_pair` passes when any spec is `import`, and `migrate` runs `specs_select` only after `ready()` (:541-543). `host::import`'s `check_import` re-asks proof and templates (ops.rs:298-318) but nothing re-asks the PIV attestation rule, and ykcs11's `destroy` refuses keys (ykcs11/src/lib.rs:122-128), so the rollback leaves the key in the slot. [read]
`crates/camigrate/src/lib.rs:788` (`landing_checks`: `import_target(cfg, &p.object, to, None, MOVE)`,
`let Ok(dst) = … else { return }`), `:642` (`Run::plan` takes no `specs`), `:541-543` (`migrate`
plans, then `specs_select`). When an object has two `origin = "import"` specs on the target (the
case `--spec` exists for), `import_target(…, None, …)` returns "several specs" and
`landing_checks` returns silently. It then skips `unprovable`, `template_refusal`, and the
PIV-import attestation refusal (`:806`). The plan says `ready`, and `migrate --spec s` goes ahead.
Example: a YubiKey target spec with `attestation = true`. `host::import` writes the key into the
PIV slot, `lock_import` then fails the attestation (ykcs11's `attestation_cert`, "imported keys
have none"), and `roll_back` cannot erase it (ykcs11 refuses deletes). The key is left in the
slot with nothing in the lock. Fix: pass `specs` into `Run::plan` and use `spec_for`. When
`import_target` fails, block the plan with that error instead of returning. [read]

### F2. Key-file imports bypass the PIV attestation guard, the only one there is — bug

**Verification:** confirmed. The only `attestation`-on-import check is lib.rs:806; `import_file` (:1131-1166) goes `import_target` → `import_checks` (dry run) / `host::create_and_record` with no attestation test, and `check_import` → `check_attestation` (ops.rs:278-296) passes since ykcs11 attests `PrivateKey` as a class. No load rule exists: `.attestation` is read only at core/src/plan.rs:272 (non-key objects), ops.rs:22/282/1048, despite docs/FILE.md:93 saying load refuses it. [read]
`crates/camigrate/src/lib.rs:806-809` (the only check), `:1098-1199` (`import_file`), `:1361-1454`
(`from_its_file`); `docs/FILE.md` "Load rules". The refusal of `attestation = true` for an imported
PIV key exists only in `landing_checks`, which only `export`/`migrate` plans run.
`import --in key.p12 --passphrase-file … --allow-host-plaintext --token yubikey` (it lands on
`import` pairs, `KEY_FILE`) and `import --token yubikey` for a `file` pair both go straight to
`host::create_and_record`. `ops::check_import` passes there, since ykcs11 attests private keys
as a class. The key is created in the slot, and only then does the attestation fail and the
rollback fail to erase it. FILE.md says load refuses `attestation = true` on a `file` pair when
the provider cannot attest an imported key. No such rule exists in `crates/core/src/config.rs`,
`crates/core/src/plan.rs`, `crates/pkcs11/src/gate.rs` or `ops.rs`: searching `attestation` and
`key_origin()` there finds only the lock's record checks and `create`'s pass-over messages. F1 and
F2 are two routes to one gap: the only guard is in `landing_checks`. Fix: move the check into
`host::create_and_record` (every plaintext path passes there before the irreversible write),
keyed on the provider or `PlaintextImport::PivImport` rather than the method. [read]

### F3. A transport file is read twice, and only the first read is checked against the lock — risk

**Verification:** confirmed. `plan` reads and parses the file (lib.rs:654-658) and `plan_moves` checks only that copy with `pinned` (tokens.rs:614); `export` re-reads it at :429-432 and seals to `Transport::parse(..)?.key()?` with no `pinned` call (`pinned` has no other caller, and `sealed::export` does not check it). Exploiting it needs write access to the file during the run, so risk is right. [read]
`crates/camigrate/src/lib.rs:654-658` (`plan` reads and parses `--transport`), `:429-432`
(`export` reads and parses it again and seals to it); `crates/camigrate/src/tokens.rs:614` (the
`pinned` check, on the plan's copy only). D3 says a transport file is used only when the source's
lock pins its key. `export` never calls `tokens::pinned` on the copy it seals to. If the file
changes between the two reads, the bundle is sealed to whatever key the second copy holds. The
window spans the plan's token opens and logins, which take seconds on a YubiKey or a TPM. The
second copy only has to be self-consistent (`Transport::parse` checks only that `rfc7093m4` hashes
`spki`). The target's import would refuse it, but whoever holds that key can unwrap the bundle.
Fix: parse the file once in `dispatch` and pass the `Transport` to both, or call `tokens::pinned`
in `export` before `key()`. [read]

**Fixed (2026-11-18):** `Destination::transport` reads and parses the file once; the export checks
that parse against the lock (`tokens::pinned`) before it wraps. Test: `the_transport_file_is_read_once`.

### F4. The lock is saved once per run, after every token write — risk

**Verification:** confirmed. `migrate`'s loop mutates only the in-memory `self.lock` and calls `self.save` once after it (lib.rs:574-617), as `import` does (:521); a kill mid-loop leaves imported objects that `free_locator` (host.rs:122-133) then refuses with 13, and ykcs11 cannot delete keys (ykcs11/src/lib.rs:122). Not in ISSUES.md (B9 covers only the reported-error path). [read]
`crates/camigrate/src/lib.rs:521` (`import`), `:617` (`migrate`), `:1270` (`import_files`). Each
verb writes objects to the target one by one and saves the lock at the end. A run killed between
a successful object and the save (SIGINT, OOM, a crash in a later object's module call) leaves
objects on the token that no realisation records. Every later run then refuses that locator with
13 (`host::free_locator`, `public::preflight`: "the lock records no realisation there"). On ykcs11
the object cannot be removed by cakeys at all. `save_lock` is already atomic (`write_whole`:
temporary file, fsync, rename), so saving after each `Moved::Imported` costs one fsync per
object and closes the window to one object. B9 fixed the reported-error case only. [read]

**Fixed (2026-11-18):** `Run::record` saves the lock after each imported object in `import`,
`migrate`, `import --in` (key file) and `import_files`. Test (p11-fault `abort`):
`an_import_killed_part_way_has_recorded_what_it_made`.

### F5. A run opens the source token up to three times and swallows the trust lookup's errors — practice

`crates/camigrate/src/lib.rs:687-689` (`trusted_transport`: `open(from)…is_ok_and(…)`), `:652`/`tokens.rs:572`
(`plan_moves` opens it again), `:413`/`:566` (`export`/`migrate` open it a third time, Scratch).
Also `:589-590`: `migrate` calls `tokens::transport` once per object, which runs `ops::verify`
(and with it the `pop-unwrap` proof) on the same transport key again for every object. Each open
logs in. On tokens with slow logins (YubiKey, TPM) this triples the cost. A
`C_FindObjects(CKA_TRUSTED)` failure is read as "no trusted copy", so an enforced key is blocked
with the misleading hint to run `transport --trusted`. Open each side once per run and pass the
`Token` to the plan; resolve the transport key once before the loop; propagate the error. [read]

### F6. The passphrase readers duplicate the PIN reader and differ from it — practice

`crates/camigrate/src/lib.rs:1318-1353` (`read_passphrase`, `file_passphrase`) against
`crates/pkcs11/src/token/mod.rs:985` (`read_secret`). Both read the env var first, then the file,
but:

- a file gives its first line here and the whole file less trailing newlines there;
- an empty value is refused only when it comes from a file (`passphraseEnv` set to "" passes);
- an unset variable is 17 here and 16 (`Unavailable`) for a PIN.

One shared `read_secret` with a "first line, non-empty" option would keep credential handling in
one place (cf. ISSUES.md Q14's direction). [read]

### F7. Three verbs share one per-object loop, written out three times, in a 1,500-line CLI file — complexity

`crates/camigrate/src/lib.rs:472-522`, `:574-618`, `:1245-1271`. Each loop keeps its own
`(changed, failed)` bookkeeping and prints its own `Imported`/`AlreadyThere`/`Err` lines. They
already differ: `migrate` stops at the first failure (`:611-614`); `import` and `import_files`
go on. `dispatch` (`:206-298`, 92 lines) mixes the Nix-sandbox refusal, login and lock
preconditions, and argument routing. The key-file code (`import_file`, `import_files`,
`from_its_file`, `file_passphrase`, `read_passphrase`, about 330 lines) has nothing to do with
the CLI. Suggest: one `for_each_object(… ) -> (changed, first_failure)` helper, and a `files`
module for the key-file verbs, leaving lib.rs as parsing plus routing. [read]

**Fixed (2026-11-18), the loop:** `Tally` is the one bookkeeping of `import`, `migrate`, `import`
from files and one file's certificate; `migrate` now goes on past a failure as the others do
(`a_failed_move_leaves_the_others_moving`). The key-file verbs are `file_verbs.rs` (beside
`file.rs`, the formats written, and `keyfile.rs`, the files read); `dispatch` is left as it is.

### F8. The help text's exit-code list leaves out codes camigrate returns — nit

`crates/camigrate/src/lib.rs:40-41`. It lists 0, 11, 14, 15, 16, 17 and 1. The verbs also return
10 (`HashMismatch`, e.g. `host::create_and_record`), 12 (`Ambiguous`, `transport_named`) and 13
(`Conflict`, an occupied locator), all of which docs/CAMIGRATE.md documents. [read]

### F9. A PKCS#12 export can carry an empty `localKeyId` — nit

`crates/camigrate/src/lib.rs:1050-1057`. `unwrap_or_default()` writes an empty `localKeyId` when
the lock has no `rfc7093m4`. `ops::verify` just passed, so this is unreachable today, but a
missing ID should be an error rather than an empty attribute that importers pair on. [read]

### F10. `locked_spki` swallows a base64 error — nit

`crates/camigrate/src/lib.rs:1313`. `.ok()` turns a malformed `publicKey` into "the lock records
no public key" (`trust`, `:1281`). Lock load validates the field, so this is only a wrong message
should that ever change. [read]

## Design

- Plan-only guards are a pattern. D9 says the dry run *is* the planner, but `import` (bundle),
  `import --in` and `import` without `--in` never call `tokens::plan`. They re-ask a subset
  (`import_checks`), so any rule added only to `plan`/`landing_checks` is silently missing on
  those paths (F1, F2). Rules that guard an irreversible write belong at the write
  (`host::create_and_record`, `sealed::import`), with the planner calling the same predicate.
- Lock durability (F4) is a cross-tool question: `cakeys create` over several pairs has the same
  save-at-end shape (cli-common `save_changed`). Saving per object is cheap with the existing
  atomic write.
- Q14 spot-check: `Opener`, `read_lock` and `save_changed` are used, and `Run` is
  `{ opener, lock, lock_path }`. What is left to share is credential reading (F6) and the
  per-object loop (F7).

## Checked, no issue

- ISSUES.md B9 (Done): `import_file` saves the lock before returning the certificate's failure
  (`:1176-1198`). The key's own failure happens before anything is written (`create_and_record`
  rolls back).
- Q14 (Done): `needs_login` runs before `read_lock`, as ISSUES.md says.
- `from_its_file` restores the lock (`before`) when a first use fails after the host IDs were
  put in, and checks the file against pinned IDs (10) before any write.
- D8: real `export`, key-file reads (including `--dry-run`) and `transport --trusted` are refused
  in a Nix build. Lock-writing verbs are refused by `read_lock`.
- `export_file`: the PKCS#8 is `Zeroizing` and dropped before the write, and the file is
  written 0600 through `write_whole`'s temporary file and rename.
- `import_target`/`specs_select`/`specs_import`: an unknown or non-selecting `--spec` is 17; a
  `create`/`adopt` pair is never a landing.
- `noExport`: blocked first and left out of the bundle quietly.
- Panics on external input: none. The `unreachable!` sites (`:247`, `:402`, `:434`, `:665`),
  `bundle.keys[0]` (`:594`, a bundle `sealed::export` just made from one item) and
  `cfg.objects[*o]` (`:1241`, names drawn from `cfg.objects`) are internal invariants.
