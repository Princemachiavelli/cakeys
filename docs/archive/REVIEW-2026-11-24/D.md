# Area D: camigrate — review 2026-11-24

Reviewer D. Scope: `crates/camigrate` at `bc94263`. Read-only; no builds or tests run.

## Root causes in this area (fill at the end: 3-8 causes, each with the finding IDs that evidence it)

1. **Fixes are scoped to the reported line, and their regression test mutates only the reported
   field.** C-1's test swaps the object and keeps the token. C-13 moved the check into the function the
   finding named. B-3 reached the gate and `check_import` but not the plan. C-21 fixed the message, not
   the control flow. fce5432 ("Not built or tested here") shipped C-1/C-2/B-3 unbuilt (P-UNRUN).
   Evidence: D-1, D-2, D-5, D-9, D-10.
2. **The plan is a hand-written mirror of the write-time checks, not the same code.** `landing_checks`
   copies two of `check_import`'s three static parts. The move plan never calls `free_locator`, which
   the import plans do. A transport file gets no landing rules because `Dest::token()` is `None`. Empty
   plans end differently. Plan item 3 of 2026-11-23 ("dry run and real run share one entry") was done
   as a file split, not as one entry. Evidence: D-2, D-3, D-4, D-6.
3. **The D9 guard (the dry-run twin) has a permissive oracle.** `dry 0 → real ∈ {0,22,10,13}` for every
   verb since e746511, so a knowable 13 passes. Verdict divergences outside the twin (`km_alone`) are
   not compared at all. Evidence: D-3, D-6.
4. **Names read from untrusted files are taken as authority.** The transport file's `token` picks
   which key is acceptable. The bundle's `transport.object` picks the unwrapping key. The transport-key
   rule is re-asked per path, not carried by a type. Evidence: D-1, D-8, D-10.
5. **The hostile-module case is not modelled, so identity checks have no failing test and are dropped
   from new paths.** p11-fault cannot make a source hand over another key (C-13 "No test"), and no
   reference token hides a flag. The safety nets that exist only for lying modules are exactly the ones
   that drift. Evidence: D-5, D-7; unguarded `host.rs:108,133`.
6. **"Unknown" is representable as "permitted".** `Option<bool>` flags are read `== Some(true)` for
   restrictions, and `Side::pkcs11` defaults to capable. Evidence: D-7 (D-TYPES).
7. **Docs state universal guarantees that nothing checks**, and fixes are judged against them: "the
   one way" (host.rs), "every host path" (D6), "for the file's token" (D3). Evidence: D-1, D-5.

Counts:

- By severity: 1 high (D-1), 4 medium (D-2, D-3, D-5, D-7) and 5 low (D-4, D-6, D-8, D-9, D-10).
  9 are verified and 1 plausible (D-7). There are also 14 unguarded decisions.
- By escape code: D-MULTIPATH 6, T-ABSENT 6, T-INSTANCE 3, D-DOCS 2, T-FRIENDLY 2, T-ORACLE 1, T-GATED 1,
  D-PARALLEL 1, D-TYPES 1, P-UNRUN 1.

## Test gap map (fill at the end: per crate, what behaviour has no failing test, and why: gated, absent, oracle)

camigrate. All token suites skip under plain `cargo test` and run only in the Nix check (nextest).

- **Gated:**
  - `tests/yubikey.rs`: opt-in hardware, never in Nix or CI. It is the only move into ykcs11 and covers
    placement, the occupied slot and `piv-import`.
  - `tests/fault.rs`: Linux only (p11-fault).
  - tpm2-ptool paths: swtpm on Linux only.
- **Absent:**
  - A source handing over another key: the identity checks in `host.rs:108,133`, and `export_file` has
    no check at all (D-5).
  - Another target's genuine transport file (D-1).
  - Placement or a ykcs11 stand-in in the move plan (D-2). The pattern exists in `from_files.rs`.
  - An empty export without names under the twin (D-6).
  - An unknown `CKA_PRIVATE` / `CKA_WRAP_WITH_TRUSTED` (D-7).
  - `save_lock` failing mid-run, or `migrate` killed mid-run (D-9).
  - A bundle naming a non-transport object (D-8).
  - The refusals for: a key file without `--allow-host-plaintext` (15), `--passphrase-file` with a
    bundle (17), a real `export --json` (17), `needs_login` on import, and several observations (13).
- **Oracle:**
  - The twin admits 10/13 after a dry 0 (D-3).
  - `surface.rs` counts flag mentions.
  - Otherwise the move tests are strong. They assert the lock's `origin.method`/`from` and run
    `cakeys check` (24 call sites). A refused move leaves the lock and the target unchanged. AES
    commitments are compared with host-computed values. Most refusals assert both code and message.

## Findings (appended per file)

First batch read, with their tests: `src/lib.rs`, `src/landing.rs`, `src/tokens.rs`, `src/transport.rs`,
`src/sealed.rs`, `src/host.rs`, `src/public.rs`, `src/plan.rs`, `src/bundle.rs`; `tests/dry_run.rs`
(the parts that target them), `tests/fault.rs`, `tests/yubikey.rs`, `crates/cli/tests/common/xref.rs`
(the dry-run twin).

### D-1. C-1's fix binds a transport file to the token the file itself names: swapping in another target's genuine transport file still seals to that target's key, and the real export never says which target it sealed for — high — verified

`crates/camigrate/src/lib.rs:908-911`, `:665-670`, `:161-163`; `crates/camigrate/src/tokens.rs:805-821`; `docs/CAMIGRATE.md:98-101`
What: `pinned(lock, t, transport_choice(cfg, &t.token, how))` takes `t.token` from the file. C-1's own
  scenario is one lock pinning `tk-prod` (prod HSM) and `tk-dev` (a dev SoftHSM). The attacker who can
  swap the file now replaces it whole with dev's genuine `camigrate transport --token dev` output
  (`token = "dev"`, `object = "tk-dev"`, real `rfc7093m4`/`spki`), not only its `object` line.
  `transport_spec(lock, "dev", dev's transportWith)` passes, `realised == t.object` passes and the ID
  matches. `export k --from src --to-transport-file prod.toml --out b.toml` exits 0 and seals `k` to
  `tk-dev` (only an explicit `--transport-spec tk-prod` would refuse it: that spec is not realised on
  `dev`). `--to-transport-file` takes no target name (`lib.rs:161-163`), so nothing on the command
  line names prod. The real export prints only "wrote b.toml (k by …)" (`lib.rs:681-682`), and the bundle
  records no target token, only `transport.object`. Only the `--dry-run` table shows `src -> dev`. The
  bundle fails at prod's import (14), but by then it already exists and has been handed over. That is
  exactly C-1's stated consequence.
Why missed: T-INSTANCE, D-DOCS, P-UNRUN. The regression test `a_transport_file_of_another_pinned_key_is_refused`
  (`tests/dry_run.rs:1311-1340`) rewrites `object`/`rfc7093m4`/`spki` and keeps `token = "kryoptic"`, so it
  covers only the reported line. The fix commit fce5432 says "Not built or tested here". The original
  finding framed the bug as "the object is not the token's transport key", so the fix checked exactly
  that, against a token name the attacker also controls. CAMIGRATE.md D3 says the file is held to "the
  transport key … names for the file's token", which writes the gap into the spec. No document or test
  asks where the target's name comes from.
Class: fields of an untrusted file used as trusted names. Here (1) `Transport.token` chooses which
  target's transport key is acceptable; (2) the bundle's `transport.object` chooses the unwrapping key on
  import (D-8); (3) the bundle's `exposure` (`sealed`/`enforced`) and (4) its `source.token` go into the
  lock's provenance. `check_source` only requires a keys.toml token, not one the lock realises the object
  on. That is 4 instances, and only (1) is high.
Instance fix: `--to-transport-file` requires `--to <token>` (or a positional target), and `pinned`
  refuses `t.token != to`. Name the target token in the real export's "wrote" line and in the bundle
  (a `target` field that `import` checks against `--to`).
Class fix: a rule that every name read from a file the docs call "may cross untrusted channels" is
  either bound to an operator-given name or derived from the lock, never taken as given. A test
  generator that, for each such file field, swaps in another *valid* value the same lock pins
  (another token, another object, another exposure), not a garbage one.

### D-2. B-3's PIV placement rule is asked before every import's write but not by the move plan: `migrate --dry-run` says ready (0) and the run refuses (17) — medium — verified

`crates/camigrate/src/landing.rs:110-136`; `crates/camigrate/src/tokens.rs:187-200`; `crates/pkcs11/src/ops/capabilities.rs:158-166`; `crates/ykcs11/src/lib.rs:67-86,125-127`
What: for a ykcs11 target whose import pair is located by `CKA_LABEL`, by no `CKA_ID`, or by `CKA_ID = "19"`
  (f9), `landing_checks` asks `unprovable`, the providers' templates (`Provider::adjusted`) and
  `check_imported_attestation`. ykcs11 has no `template` hook; its rule is `placement`, and nothing in
  the plan calls it. Nothing at keys.toml load checks it either (only `cakeys validate`'s gate,
  `gate.rs:146-153`). So `migrate k --to yubikey --allow-host-plaintext --dry-run` plans `piv-import`
  ready, and the run then stops in `host::landing → ops::check_import → placement` with 17. D9 says the
  run "exits as the dry run did". `import --dry-run` (bundle, key file, files) does call `check_import`
  and agrees with its run.
Why missed: T-INSTANCE, T-GATED, D-MULTIPATH, D-PARALLEL. The B-3 status lists "Tests: ykcs11 unit,
  validate"; no camigrate test was added. The only camigrate test with a ykcs11 target is the opt-in
  hardware `tests/yubikey.rs`, which never runs in Nix or CI and uses a valid slot. The CI-safe stand-in
  (SoftHSM bound to `provider = "ykcs11"`) exists in
  `from_files.rs::an_import_the_provider_cannot_attest_is_refused_before_the_write`, but only for the
  attestation rule on the from-files path. `landing_checks` hand-copies two of `check_import`'s three
  static parts (template, attestation) and missed the third, which arrived later (fce5432).
Class: write-time rules that the plan re-implements by hand: `check_import`'s placement, the locator
  (D-3) and the landing rules for a transport file (D-4). That is 3 in camigrate, plus B-3/C-2 before.
Instance fix: `landing_checks` asks `provider.placement(&dst.on_token.locator)` for a key, and a
  `migrate --dry-run` and a real run against the ykcs11 stand-in with `CKA_LABEL` and `CKA_ID = "19"`
  both expect 17.
Class fix: split `ops::check_import` into a static part (placement, attestation, templates, proof
  needs), which the plan, the gate and every import call, and a token part. The plan then cannot
  drift from the write.

### D-3. `migrate --dry-run` never checks the target locator (If-None-Match), though `import --dry-run` does; the dry-run twin explicitly allows "ready, then 13", so the D9 property cannot see it — medium — verified

`crates/camigrate/src/landing.rs:20-76`; `crates/camigrate/src/lib.rs:729-740`; `crates/cli/tests/common/xref.rs:136-150`; `crates/camigrate/tests/dry_run.rs:2129-2143`
What: the migrate plan opens the target (`Access::Read`, logged in: `needs_login`) but never calls
  `public::free_locator`. A target locator holding another key makes `migrate --dry-run` exit 0, and the
  run exits 13 ("would collide with"). `import --dry-run` runs `sealed::preflight → free_locator` and
  says 13 itself. CAMIGRATE.md lists "an occupied locator or PIV slot" under 13, the target refused, and
  D9 says the dry-run verdict is the outcome. On a YubiKey the occupied-slot case is the one
  `yubikey.rs` shows (13, real run only).
Why missed: T-ORACLE, D-MULTIPATH. The twin's oracle (`xref.rs:143-149`; since e746511, 2026-11-14)
  is `dry == 0 → real ∈ {0, 22, 10, 13}`. 13 was admitted for "a blob that does not unwrap", which is
  unknowable before an import, but the allowance covers every verb, and in `migrate` 13 is also the
  locator collision, which is knowable. `host_moves_refuse_what_they_cannot_check` (`dry_run.rs:2138`)
  runs exactly this case through the twin, which passes with dry 0 and real 13. The test that should
  catch the gap is built to tolerate it.
Class: oracle relaxations in the twin. 10 is likewise allowed after a ready dry run, which is right for
  a lying source on `migrate` but hides any knowable 10 on `import` from files, where the host computes
  IDs before planning.
Instance fix: in the migrate plan, ask `free_locator(dst, target, spki)` when the target opened.
Class fix: allow 13 only where the run's stderr names the unwrap ("tampered"), as is already done for
  16 ("damaged or altered bundle"), and 10 only on paths whose identity check needs the plaintext.

### D-4. `export --to-transport-file` is planned without any landing rule that `export --to <token>` applies — low — verified

`crates/camigrate/src/tokens.rs:497-502`; `crates/camigrate/src/landing.rs:34-58,62-70`
What: `Dest::token()` is `None` for `Dest::Transport`, although `t.token` names a keys.toml token whose
  specs camigrate has. `block` therefore skips, for an offline export, everything it does for
  `Dest::Bundle`: the landing pair's `unprovable`, the target's provider templates, the imported
  attestation, and "the transport key's spec is gone". The plan says ready, the bundle is written, and
  the target's `import` refuses it (15/17). Two export paths to the same target plan differently.
Why missed: D-MULTIPATH, T-ABSENT. No test plans the same object both ways against a target that
  refuses it.
Class: as D-2. Instance fix: `Dest::token()` returns `Some(&t.token)` for a transport file (with
  `bundle()` true), so `landing_checks` runs on the file's `Side`. Class fix: as D-2.

### D-5. Plaintext leaves a token with no identity check on `export --to-key-file`: C-13's fix covers `hand_over` only, and secret keys are unchecked on every host path, while the code says "the one way" and CAMIGRATE.md D6 says "every host path" — medium — verified

`crates/camigrate/src/file_verbs.rs:32-50`; `crates/camigrate/src/host.rs:70-73,96-110`; `docs/CAMIGRATE.md:164-166`
What: `export_file` verifies the source realisation, then calls `source.extract(h, &kwp)` itself and
  writes the PKCS#8 (or a PKCS#12 that pairs it with the lock's certificate under the lock's `rfc7093m4`
  as `localKeyId`) with no `check_identity`. A source module that hands over another key's bytes (the
  case C-13 was about) produces a key file whose key is not the locked one, with the right certificate
  beside it. Java, Windows and cloud vaults import that file without re-checking. `hand_over`'s comment
  calls itself "the one way a move from a token holds the plaintext, so none writes an unchecked key";
  `export_file` is a second way. Separately, `check_identity` returns `Ok` for every non-private key, so
  `host-raw` and `tpm2-ptool` HMAC write a secret key before any identity check. FILE.md lists host-side
  secret commitments as not built, but CAMIGRATE.md D6 still claims every host path.
Why missed: T-INSTANCE, T-FRIENDLY, D-DOCS. The fix (fcaa6aa) moved the check into the function named
  in the finding. C-13's status says "No test: p11-fault cannot make a source hand over another key", so
  deleting either call fails no test. The prior review saw `export_file` (C-14 is in it) but read it for
  passphrases.
Class: plaintext extraction sites (`host::hand_over`, `file_verbs::export_file`; caprobe's
  `probe/moves.rs:415` is a probe). 1 of 2 camigrate sites is checked, and secret keys on neither.
Instance fix: `export_file` goes through one `extract_checked(from, h, dst_or_src, lock)`.
Class fix: make `Token::extract` return a type that can only be consumed after an identity check
  against a `Target` (a `Checked<Zeroizing<Vec<u8>>>`). Teach p11-fault to substitute a `C_WrapKey`
  output so the check is testable.

### D-6. An export without names whose every object is kept home dry-runs 0 and runs 15 — low — verified

`crates/camigrate/src/lib.rs:598-605`, `:643-645`; `crates/camigrate/src/landing.rs:25-27`; `crates/camigrate/src/tokens.rs:571-576`
What: without names, `block` drops every `noExport` object and the token's transport key
  (`retain`). If nothing else is realised on `--from` (a target token holding only its transport key,
  or a source of `noExport` keys), `moves.plans` is empty. The dry run's `Moves::ready()` is `Ok` on an
  empty list, so it exits 0, and the real export fails "nothing on '…' can go into a bundle" (15).
Why missed: T-ABSENT, D-MULTIPATH. `a_transport_key_never_leaves` uses `km_alone` (no twin), and its
  source has other objects. Class: emptiness handled differently by plan and run. Instance fix:
  `plan_moves` with `partial` and no plan returns the run's 15. Class fix: the dry run and the run end in
  one verdict function over `Moves`.

### D-7. Fail-open policy defaults: a data object whose `CKA_PRIVATE` the lock did not record is planned public, so its value travels in clear in a bundle; an unrecorded `CKA_WRAP_WITH_TRUSTED` plans a host path — medium — plausible

`crates/camigrate/src/plan.rs:121`, `:137`, `:143`; `crates/pkcs11/src/token/policy.rs:117-123`
What: the observed policy omits a flag the module will not show (`flag_if_readable` → `None`). The
  planner reads `CKA_EXTRACTABLE` fail-closed (`!= Some(true)`), but reads `CKA_PRIVATE` on a data object
  (`== Some(true)`) and `CKA_WRAP_WITH_TRUSTED` (`== Some(true)`) fail-open. A private data object on a
  module that does not report `CKA_PRIVATE` therefore moves by `public`, and `export --to` writes its
  value in base64 into a bundle that "may cross untrusted channels". An unreported wrap-with-trusted key
  is planned `host`/`sealed`; the token refuses the wrap later, so this second case is only a wrong plan.
Why missed: T-ABSENT, T-FRIENDLY, D-TYPES. `public_objects_move_as_they_are` asserts `Some(true)` and
  `Some(false)` only. Flipping `== Some(true)` to `!= Some(false)` fails no test, and no reference
  token hides the flag. Class: `Option<bool>` restrictions read as "absent = permitted": these 2 in
  `plan.rs`, against 1 fail-closed sibling. `Side::pkcs11` likewise defaults `trusted_wrap`,
  `secret_unwraps` and both OAEP hashes to yes for a module with no profile. Instance fix: the data rule
  is `!= Some(false)`, said as "not known to be public". Class fix: a tri-state `Known<bool>` in
  `Material` whose restriction accessors take the restrictive side, with a unit test per flag for the
  unknown case.

### D-8. A bundle's import unwraps with whichever object the bundle names, realised on the target; it is not held to the token's transport key as every sealing path is — low — verified

`crates/camigrate/src/lib.rs:706-709`; `crates/camigrate/src/landing.rs:394-412`; `crates/camigrate/src/sealed.rs:517-525`
What: `realised_target(cfg, lock, &t.object, token, …)` accepts any object realised on `--to`. Its
  `transport_fault` rule (RSA, `CKA_UNWRAP`, non-extractable) and `transportWith`/`--transport-spec` are
  never asked. `check_against_lock` compares the bundle's `rfc7093m4` with the lock's for that same
  object, which is tautological for the object name. Material identity is still checked after the
  unwrap, so this is not a key-substitution hole. But the target's `C_UnwrapKey` runs under a key the
  file chose, and the export and import sides enforce different rules for "the transport key".
Why missed: D-MULTIPATH, T-ABSENT. The rule was written for the sealing side (D3) only. Class: D-1's
  class (instance 2). Instance fix: `import` resolves the transport key as `transport_target(cfg, lock,
  token, transport_choice(…))` and refuses a bundle naming another one. Class fix: as D-1.

### D-9. The run's per-object JSON and its first failure are lost on the 21 path and on every key-file refusal, and the 21 path ("key moved, lock not written") has no test — low — verified

`crates/camigrate/src/lib.rs:749-751`, `:848-850`; `crates/camigrate/src/file_verbs.rs:134-146`, `:165-169`, `:186`, `:257`
What: `tally.moved(…)` and then `self.record(…)?` return before `Tally::finish`. When the save fails,
  stdout carries no array (the help promises "Prints each object's outcome, as a JSON array"), and an
  earlier object's failure code is replaced by 21. `import --in <key file>` returns every refusal (real
  and dry) with `?`, before any tally, whereas a bundle's import reports the same refusals as JSON.
  Mid-migration recovery itself holds: the object is saved before the next one starts, and a later run's
  13 names `cakeys lock --spec … --token …`. But only an import killed mid-run (`fault.rs:233`), a failed
  tpm2 reopen and a refused destroy are tested. No test makes `save_lock` fail mid-run, and none kills a
  `migrate`.
Why missed: T-ABSENT. C-21 fixed the hint text, and its test asserts the hint on the collision path
  (`dry_run.rs:2143`) only. Class: output contracts that each verb loop keeps by hand (C-7). Instance
  fix: `record` failures go through `tally.fail` and then `finish`, which returns 21 only if no earlier
  failure. Class fix: one loop driver for import/migrate/files/key-file (prior "review D8" merged three
  of four) that owns record, tally and exit.

### D-10. `transport --trusted` makes a CKA_TRUSTED copy of whatever public key the lock records, without the transport key's size rule that `transport --out`, a transport file's read and every seal apply — low — verified

`crates/camigrate/src/lib.rs:999-1018`; `crates/camigrate/src/landing.rs:361-371`; `crates/core/src/config/check.rs:135`
What: `trust` takes `locked_spki` and calls `create_trusted_copy` with no `check_transport_size`.
  keys.toml refuses a transport key below 2048 bits only if `modulusBits` is declared, so a lock
  realisation holding a 1024-bit key (spec with no `modulusBits`) is made trusted on the source.
  Sealing to it is still refused, so the harm is a trusted object that widens `enforced`'s set (the
  code itself warns that "`enforced` is only as narrow as that set").
Why missed: D-MULTIPATH, T-ABSENT. C-20/"transport.rs F1" added the size check to `new`, `parse` and
  `key`, the three file-shaped paths, but not to the lock-shaped one. Class: D-1/D-8 (the transport-key
  rule asked per path). Instance fix: `check_transport_size` in `trust`. Class fix: one
  `TransportKey::from_lock`/`from_file` constructor that every path goes through, holding the
  RSA/size/`CKA_UNWRAP`/non-extractable rule.

Read since: `src/file_verbs.rs` (D-5, D-9), `src/file.rs`, `src/keyfile.rs`, `src/side.rs`,
`src/main.rs`, `Cargo.toml`, `tests/from_files.rs`, `tests/surface.rs`, fixtures. `file.rs` and
`keyfile.rs` are clean: crafted-input refusals with unit and fuzz tests, and fixtures made by OpenSSL
3.5.9 (`make.sh`), not by the code under test, so not T-TAUTO.

### Rule x path parity (D-MULTIPATH)

Y = enforced before the write, N = skipped (finding), n/a = no such step, `post` = only after the
token made it. "files" is `import` without `--in`.

| rule | migrate | migrate --dry-run | export --to | export --to-transport-file | export --to-key-file | import bundle (real/dry) | import key file (real/dry) | import files (real/dry) | transport --trusted |
|---|---|---|---|---|---|---|---|---|---|
| private key identity on host | Y (`hand_over`) | n/a | n/a | n/a | **N** (D-5) | `post` (PoP after unwrap) | Y / Y | Y / Y | n/a |
| secret key identity on host | **N**, `post` only (D-5) | n/a | n/a | n/a | n/a | `post` | `post` | `post` (FILE.md: not built) | n/a |
| transport key bound to the target | lock | lock | lock | **file's own token** (D-1) | n/a | **any realised object** (D-8) | n/a | n/a | lock, **no size** (D-10) |
| extractability / wrap policy | plan | plan | plan | plan | plan | n/a | n/a | n/a | n/a |
| unknown flag = restrictive | **N** (D-7) | **N** | **N** | **N** | **N** | n/a | n/a | n/a | n/a |
| PIV placement (B-3) | Y (`check_import`) | **N** (D-2) | n/a | n/a | n/a | Y / Y | Y / Y | Y / Y | n/a |
| locator free (13) | Y | **N** (D-3) | n/a | n/a | n/a | Y / Y | Y / Y | Y / Y | n/a |
| imported attestation | Y | Y | Y | **N** (D-4) | n/a | Y / Y | Y / Y | Y / Y | n/a |
| provider templates, unprovable | Y | Y | Y | **N** (D-4) | n/a | Y / Y | Y / Y | Y / Y | n/a |
| empty plan is 15 | Y | Y | Y | Y | Y (one key) | Y | Y | Y | n/a |
| export without names | n/a | n/a | 15 real, **0 dry** (D-6) | same | n/a | n/a | n/a | n/a | n/a |
| login before reading the target | Y | Y | n/a | n/a | n/a | Y / Y (unguarded) | Y / Y | Y / Y | SO |

Exit codes per path, where dry and real differ for a cause the dry run could know: migrate 0 then 13
(D-3) or 17 (D-2); an export without names 0 then 15 (D-6); `export --to-transport-file` 0 then the
target's import 15/17 (D-4). By design: a dry run is 0 where the run's 10/13/16 comes from the material
(unwrap, PoP, commitment), and a real `export --json` is 17 where its dry run prints the plan (0).

## Unguarded decisions (appended per file, from mutation testing)

- `src/lib.rs:324-326`: `needs_login` for `Cmd::Import`. Only `migrate` is tested ("without login",
  `dry_run.rs:2178-2181`). Without it, an import's `free_locator` runs unlogged, cannot see private
  objects under the locator, and could create a second key there.
- `src/lib.rs:340-350`: a key file without `--allow-host-plaintext` is 15. No test asserts the message
  or code.
- `src/lib.rs:354-358`: a bundle with `--passphrase-file` is 17. No test.
- `src/lib.rs:431-436`: a real `export --json` is 17. No test.
- `src/lib.rs:665-670`: `pinned` re-checked at seal time. The plan already blocked; deleting it fails
  nothing (redundant by design, so unguarded).
- `src/lib.rs:821-844`: migrate's dispatch catch-all `_ => public::import` runs for any method that
  `landing::built` lets through. Two hand-kept lists (D-PARALLEL). A method added to `built` without an
  arm would be "imported" as a public object, and no test can see that.
- `src/landing.rs:159-184`: `built`/`limit_token_plans` (C-2's second half). No planner path makes a
  ready, unbuilt method for a token, so it is unreachable and deleting it fails nothing.
- `src/landing.rs:130-135`: the plan's `check_imported_attestation`. Only the from-files path and its
  run are tested; no migrate plan to an attesting provider.
- `src/host.rs:108` and `:133`: `check_identity`. No test can make a source hand over another key
  (C-13 status). It is the "only safety net" on a YubiKey (CAMIGRATE.md D6).
- `src/host.rs:185-194`: `import_ptool` refuses a public half already under the locator. Only reachable
  on swtpm (Linux), and no test asserts it.
- `src/sealed.rs:273-277`: a `CKM_RSA_AES_KEY_WRAP` output no longer than the modulus is 15. A lying
  module only; no test.
- `src/plan.rs:121` and `:143`: the unknown (`None`) case of `CKA_PRIVATE` and `CKA_WRAP_WITH_TRUSTED`
  (D-7).
- `src/tokens.rs:688-694`: several observations of a target turn into the open's error. No test.
- `src/file.rs:274-276`: `kdf_refused` in `encrypted_octets`, the KDF bound for a PKCS#12's encrypted
  certificate container. The unit test refuses by container count first, so deleting this check fails
  nothing.

## Prior fixes re-checked (prior ID — holds / instance only / wrong / regressed)

- C-1: **instance only** (D-1). The test swaps the object and keeps the file's token; fce5432 was unbuilt.
- C-2: holds for `--spec`. The `built` half (`limit_token_plans`) is now unreachable and unguarded.
- C-13: **instance only** (D-5). `export_file` extracts with no check; secret keys are unchecked; no test.
- C-14: holds (`dry_run.rs:1149-1153`, `an_empty_passphrase_is_refused_by_its_source`).
- C-20: holds (`transport.rs:146-158`, `a_modulus_counts_its_bits`).
- C-21: **partial** (D-9). The hint is added and tested on the collision. Remaining objects dropped,
  the first failure lost and the JSON array missing on 21 are all untouched, and none is tested.
- C-22: holds (`p256.nokeypbe.p12`, made by OpenSSL).
- C-23 / plan item 3 ("dry run and real run then share one entry"): **partial**. `landing.rs` exists,
  but the real run's write-time checks (`check_import`, `free_locator`) are still separate from the
  plan (D-2, D-3), and lib.rs is still 1073 lines.
- B-3: **instance only** for camigrate (D-2). Placement is in the gate and in `check_import`, but not
  in the move plan.
- 2026-11-18 `transport.rs` F1 (a small key in a file): holds. Its lock-side sibling is D-10.
- 2026-11-18 `from_files.rs` F1/F2: hold (`assert_aes_ids_are_the_files` compares with host-computed
  commitments; `env` no longer needs two references).

## Cross-area notes (one line each)

- C (harness): `crates/cli/tests/common/xref.rs:143-149` admits real 10/13 after a dry 0 for every verb; this hides D-3.
- C (harness): `crates/camigrate/tests/surface.rs` proves each flag is *mentioned* in a test, not asserted (a real `export --json` → 17 has no assertion).
- B (pkcs11): `Provider::placement` and `Provider::template` are two hooks for one kind of rule; only `check_import` and the gate ask both (D-2, D-SEAM).
- B (pkcs11): `attrs::observed` / `flag_if_readable` drop unreadable flags; every consumer picks its own fail direction (D-7).
- A (core): `config/check.rs:135` checks a transport key's size only when `modulusBits` is declared; the lock's `publicKey` size is never checked (D-10).
- B/caprobe: `caprobe/src/probe/moves.rs:415` is the other `Token::extract` caller (a probe's session key; not a finding).
- Docs: CAMIGRATE.md D3 ("for the file's token") and D6 ("every host path") state the gaps of D-1 and D-5 as guarantees.

## Files reviewed (every file in scope: clean | finding IDs | unguarded count)

| file | result | unguarded |
|---|---|---|
| `Cargo.toml` | clean | 0 |
| `src/main.rs` | clean | 0 |
| `src/lib.rs` | D-1, D-3, D-6, D-8, D-9, D-10 | 6 |
| `src/landing.rs` | D-2, D-4, D-8, D-10 | 2 |
| `src/tokens.rs` | D-1, D-4, D-6 | 1 |
| `src/transport.rs` | clean (its binding is D-1, in `tokens::pinned`) | 0 |
| `src/sealed.rs` | D-8 (its `check_against_lock` object compare is tautological) | 1 |
| `src/host.rs` | D-5 | 2 |
| `src/public.rs` | clean (`free_locator` is right; D-3 is that the plan skips it) | 0 |
| `src/plan.rs` | D-7 | 1 |
| `src/bundle.rs` | clean (exposure is "the source's word", documented) | 0 |
| `src/file_verbs.rs` | D-5, D-9 | 0 |
| `src/file.rs` | clean | 1 |
| `src/keyfile.rs` | clean | 0 |
| `src/side.rs` | clean (optimistic `Side::pkcs11` defaults, see D-7 class) | 0 |
| `tests/dry_run.rs` | evidence for D-1 (the C-1 test keeps `token`), D-3 (`:2138` passes dry 0 / real 13) | n/a |
| `tests/fault.rs` | clean; Linux-only (p11-fault) | n/a |
| `tests/from_files.rs` | clean; its ykcs11 stand-in is the pattern D-2 lacks | n/a |
| `tests/yubikey.rs` | T-GATED: opt-in hardware, never in Nix or CI; the only ykcs11 move test | n/a |
| `tests/surface.rs` | T-ORACLE (mentions, not behaviour) | n/a |
| `tests/fixtures/keyfiles/*` (27 files, `make.sh` and `openssl-version.txt` among them) | clean; made by OpenSSL 3.5.9 | n/a |
| `tests/fixtures/sample.bundle.toml` | clean (unit test and fuzz seed) | n/a |
