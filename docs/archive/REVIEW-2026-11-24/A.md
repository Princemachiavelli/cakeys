# Area A: core, profile, p11-names, fuzz — review 2026-11-24

## Root causes in this area (fill at the end: 3-8 causes, each with the finding IDs that evidence it)

1. **Changes land without the full check suite having run (P-UNRUN).** The "verbatim" config split
   8aaba2e deleted core's keys.toml unit tests and left docs citing them, which `checks.doc-references`
   would refuse — so main was merged without `nix flake check` passing; the same commit had to repair
   test drift from the unrun 2026-11-23 branch; the A-2 fix (fce5432) was written unrun and over-refuses.
   Evidence: A-1, A-5, A-6.
2. **Fixes are scoped to the reported instance; nobody looks for siblings (T-INSTANCE).** Each prior fix
   added a test for exactly the reported shape (EC key, same locator; yes-from-absence; the walk but not
   the slot link; a target without an oracle). Evidence: A-3, A-5(b), A-7, A-9, A-10; rechecks of
   2026-11-23 A-2, A-3, A-8, A-9, A-16, A-18.
3. **Identity and validity are approximated by text or call-site discipline instead of types (D-TYPES).**
   "Same token object" is locator equality; `Config` is `Deserialize` with pub fields, so plan/reconcile
   unit tests build configs that never passed load; `Object::new` is fallible at ~12 call sites; "every
   value" lists are hand-written beside exhaustive matches (4); a rule is private while the primitive that
   skips it is public. Evidence: A-4, A-5, A-7, A-8 (2026-11-23) recheck.
4. **Parallel tables across crate boundaries the dependency graph forbids sharing (D-PARALLEL).** The
   profile crate is independent of core by design, so commitment kinds/mechanisms, proof names, curves and
   per-curve hashes are restated; three verdict ladders in `effective.rs` restate one rule. Each fix
   edits the table the report named. Evidence: A-8, A-9, A-4 class, 2026-11-23 A-9 recheck.
5. **Verification artefacts outgrow their fixed coverage while docs keep the stronger claim (D-DOCS +
   T-ABSENT).** The Quint model's keys.toml cannot express the two rules added since it was written;
   DEVELOPMENT.md still says a rule change fails `lock_mbt`; `answers.txt` asks `commit` only where
   interpolation never runs; a fuzz header promises an oracle the body discards; the "known rows" test
   covers 9 of 20 variants. Evidence: A-6, A-9, A-10.
6. **Load and lock rules are exercised mainly by token-gated, exit-code-only suites (T-GATED +
   T-ORACLE).** After A-1, 13 of `check.rs`'s ~27 decisions have no failing test; `Lock::check`'s
   invariants are reached by `cli/tests/reference/lockfile.rs` (gated) asserting 17 only, which every lock
   rule returns. Evidence: A-1, batch 1 and 2 unguarded lists (8 gated-only decisions).
7. **Doc checks cover Markdown only.** `checks.doc-references` reads backticked names of 4+ words in
   Markdown; Rust doc comments and test names that cite deleted functions rot unseen. Evidence: A-2
   (2 instances), A-1 (the Markdown half would be caught, had the check run).

## Test gap map (fill at the end: per crate, what behaviour has no failing test, and why: gated, absent, oracle)

**crates/core**

- `config/check.rs` — names grammar, DES3 length, Nix-store secret files, `migrate.*` rules, origins,
  malformed `$NAME`: **absent** (tests deleted in 8aaba2e, A-1). SO-credential-needs-PIN, unset `$NAME`
  16: **gated** only. Transport key `CKA_UNWRAP`: absent (only the `CKA_EXTRACTABLE` half). Scratch slot by
  label: absent (A-3).
- `config/lock.rs` — SRI form, binding-iff-private: **gated + oracle** (exit 17 only); alias refused,
  schemes ⊆ object IDs: **absent**.
- `reconcile.rs` — cross-spec downgrade: **instance** (EC, identical locator); secret-key usage subsets,
  other locator spellings, `publicOnly` second spec: **absent** (A-5); locator change as spec change:
  absent; `publicOnly` flip: gated; lost schemes: lock_mbt only, message shared with the attestation rule
  (**oracle**); file-origin exemption, transport `publicKey`: gated (camigrate).
- `spec/lock.qnt` + `lock_mbt.rs` — shared objects, RSA `modulusBits`, `publicOnly`, imports,
  retargeting: **outside the model** (A-6).
- `sig.rs`/`pop.rs` — own hash for secp256k1/brainpool: absent (A-8); padding overhead bounds other than
  OAEP-SHA-256: absent.
- `chain.rs` — `valid_at` boundaries: gated/ykcs11 only; `certificatePolicies` understood: absent in core;
  PIV slot link rules: absent (A-7).
- `id.rs`, `plaintext.rs`, `secret.rs`, `migrate.rs`, `types.rs`, `attrs.rs`, `plan.rs`, `fuzzing.rs` —
  well covered (KATs, properties, pinned tables).

**crates/profile**

- `effective.rs` — `commit` at untried lengths: **oracle** (`answers.txt` asks probed lengths only) and the
  all-refused → No rule **absent** (A-9).
- `capability.rs` — the profile's `commit_mechanism` table: pinned to nothing; known-rows test covers 9/20
  variants (absent for the rest).
- `profile.rs` — `min > max` in `Reported`/`Restrict`: absent (unvalidated).

**crates/p11-names** — completeness against cryptoki-sys: unchecked (hand list).

**fuzz/** — `cert_bundle`, `piv_chain`, `tpm_store_row`, `tpms_attest`: panic-only oracles; `cert_bundle`'s
stated oracle unchecked (A-10); fuzz/Cargo.lock vs Cargo.lock versions: no check.

Answers to the area questions: (1) core logic reached only through the gated CLI suite: 8 of 33 unguarded
decisions, plus every `Lock::check` invariant at exit-code granularity. (2) validity by call-site
discipline: root cause 3. (3) unchecked doc claims: DEVELOPMENT.md:198 (A-6), CONFIG.md shared objects
(A-5), `every_variant` (A-4), DESIGN/FILE test citations (A-1), `token.rs` and `id.rs` docs (A-2),
`load_config` doc on unset `$NAME`, `cert_bundle` header (A-10). (4) the profile layer no longer says yes
from absence (2026-11-23 A-1 holds); it now says no from absence for commitments (A-9); `generate` trusts
the module's reported range by design. (5) fuzz oracles: 9 of 14 meaningful, 4 panic-only, 1 overclaimed.

## Findings (appended per file)

Written per batch under "Per-file notes" below. Index:

- A-1 medium — the "verbatim" config split deleted core's keys.toml unit tests; docs cite them (batch 1)
- A-2 low — Rust docs cite deleted functions and the pre-D-1 guard (2 instances) (batches 1, 3)
- A-3 low — scratch-slot load guard checks `CKA_ID` locators only (batch 1)
- A-4 low — `every_variant` and 3 other hand "ALL" lists are not compiler-forced (batches 1, 6)
- A-5 medium — the 2026-11-23 A-2 fix: bypassed by locator spelling; over-refuses narrower secret-key specs with an impossible remedy (batch 2)
- A-6 medium — `lock.qnt` no longer models the lock rules; DEVELOPMENT.md's guarantee false (batch 2)
- A-7 low — chain rules (2026-11-23 A-3) skipped on the PIV slot link (batch 4)
- A-8 low — ECDSA hash per curve in two tables (batch 5)
- A-9 medium — `Effective::commit` says no for untried lengths (mirror of 2026-11-23 A-1) (batch 7)
- A-10 low — `cert_bundle` fuzz target overclaims its oracle (batch 8)

## Unguarded decisions (appended per file, from mutation testing)

Listed per batch below (33 in all: 15 in config, 9 in reconcile/plan, 4 in id/chain, 2 in sig/pop, 3 in profile, 1 in fuzz).

## Prior fixes re-checked (prior ID — holds / instance only / wrong / regressed)

Summary (details per batch): **holds** — 2026-11-23 A-3 (walk), A-4, A-5, A-10, A-11, A-12, A-13, A-15, A-17, B-7 (core half);
**instance only / partial** — A-1 (yes- but not no-from-absence, A-9), A-3 (PIV slot link, A-7), A-8 (`Object` still made fallibly at ~12 sites), A-9 (profile's own table remains), A-14 (code holds, core test deleted), A-16 (`answers.txt` at probed lengths only; `every_variant` gap), A-18 (panic-only target, A-10), A-7 (done, tests lost: A-1);
**wrong / regressed** — A-2 (bypassable by locator spelling; over-refuses documented shared secret keys: A-5).

## Cross-area notes (one line each)

See per batch; the main ones: caprobe `probe.rs:121-123` stale pre-D-1 doc (A-2 class); `cli/tests/tpm2.rs` asserts `lock --dry-run` exits 22; transport-key rule in two homes (`camigrate/src/tokens.rs:742-755`, `core/src/config/check.rs:118-145`); `ykcs11/src/attest.rs:63-71` (A-7); `pkcs11/src/token/possession.rs:685-692` (A-8); `pkcs11/src/gate.rs:259-281` turns A-9 into a 15; an empty PIN file reaches `C_Login` (pkcs11 `login.rs:205`: does it burn a PIV retry?).

## Files reviewed (every file in scope: clean | finding IDs | unguarded count)

| File | Result |
|---|---|
| crates/core/Cargo.toml | clean |
| crates/core/spec/lock.qnt | A-6 |
| crates/core/src/attrs.rs | clean |
| crates/core/src/chain.rs | A-7; 2 unguarded |
| crates/core/src/config/address.rs | clean |
| crates/core/src/config/check.rs | A-1, A-3; 13 unguarded |
| crates/core/src/config/io.rs | clean; 1 unguarded (root-only) |
| crates/core/src/config/lock.rs | 4 unguarded |
| crates/core/src/config/mod.rs | A-1 (doc at :179) |
| crates/core/src/config/object.rs | 2026-11-23 A-8 instance only |
| crates/core/src/config/observe.rs | clean |
| crates/core/src/config/spec.rs | clean (A-5 premise: locator equality) |
| crates/core/src/config/token.rs | A-2 |
| crates/core/src/error.rs | A-4 |
| crates/core/src/fuzzing.rs | clean |
| crates/core/src/hex.rs | clean |
| crates/core/src/id.rs | A-2 (class instance); 1 unguarded |
| crates/core/src/lib.rs | clean |
| crates/core/src/migrate.rs | A-4 class (`BUILTIN`) |
| crates/core/src/plaintext.rs | clean |
| crates/core/src/plan.rs | clean; 1 unguarded |
| crates/core/src/pop.rs | clean; 1 unguarded |
| crates/core/src/reconcile.rs | A-5; 8 unguarded |
| crates/core/src/secret.rs | clean (empty-PIN note, cross-area) |
| crates/core/src/sig.rs | A-8; 1 unguarded |
| crates/core/src/types.rs | clean (model fix for A-4's class) |
| crates/core/tests/common/mod.rs | clean |
| crates/core/tests/config_doc.rs | clean |
| crates/core/tests/exit_codes.rs | A-4 |
| crates/core/tests/fixtures/attest95.pem | clean |
| crates/core/tests/fixtures/chain-rules/constrained-leaf.pem | clean |
| crates/core/tests/fixtures/chain-rules/constrained-root.pem | clean |
| crates/core/tests/fixtures/chain-rules/ek-leaf.pem | clean |
| crates/core/tests/fixtures/chain-rules/make.sh | clean |
| crates/core/tests/fixtures/chain-rules/no-certsign-leaf.pem | clean |
| crates/core/tests/fixtures/chain-rules/no-certsign-root.pem | clean |
| crates/core/tests/fixtures/chain-rules/ok-leaf.pem | clean |
| crates/core/tests/fixtures/chain-rules/ok-root.pem | clean |
| crates/core/tests/fixtures/chain-rules/server-leaf.pem | clean |
| crates/core/tests/fixtures/f9.pem | clean |
| crates/core/tests/fixtures/root.pem | clean |
| crates/core/tests/fixtures/slot.pem | clean |
| crates/core/tests/fuzzing_surface.rs | clean (scans manifests only, noted) |
| crates/core/tests/lock_mbt.rs | A-6 |
| crates/core/tests/properties.proptest-regressions | clean |
| crates/core/tests/properties.rs | clean |
| crates/core/tests/refusals.rs | clean as tests; its keys.toml siblings lost (A-1); `for_curve` pinned for 3 of 6 Weierstrass curves (A-8) |
| crates/p11-names/Cargo.toml | clean |
| crates/p11-names/src/lib.rs | clean |
| crates/profile/Cargo.toml | clean |
| crates/profile/src/baseline.rs | clean |
| crates/profile/src/capability.rs | 2026-11-23 A-9 partial; 1 unguarded |
| crates/profile/src/effective.rs | A-9; 1 unguarded |
| crates/profile/src/embedded.rs | clean |
| crates/profile/src/lib.rs | clean; 1 unguarded (known-rows coverage) |
| crates/profile/src/names.rs | clean (dead `PopSignPin` nit) |
| crates/profile/src/profile.rs | clean (`min > max` nit) |
| crates/profile/tests/answers.rs | A-9 (commit asked at probed lengths only) |
| crates/profile/tests/answers.txt | clean (snapshot) |
| fuzz/Cargo.lock | clean; 1 unguarded (drift vs root lock) |
| fuzz/Cargo.toml | clean |
| fuzz/fuzz_targets/attest_encoding.rs | clean |
| fuzz/fuzz_targets/bundle.rs | clean |
| fuzz/fuzz_targets/cert_bundle.rs | A-10 |
| fuzz/fuzz_targets/certificate.rs | clean |
| fuzz/fuzz_targets/config.rs | clean (exit-code oracle) |
| fuzz/fuzz_targets/hex.rs | clean |
| fuzz/fuzz_targets/key_file.rs | clean |
| fuzz/fuzz_targets/lock.rs | clean |
| fuzz/fuzz_targets/p521_point.rs | clean |
| fuzz/fuzz_targets/piv_chain.rs | clean (panic-only) |
| fuzz/fuzz_targets/profile.rs | clean |
| fuzz/fuzz_targets/public_key.rs | clean |
| fuzz/fuzz_targets/tpm_store_row.rs | clean (panic-only) |
| fuzz/fuzz_targets/tpms_attest.rs | clean (panic-only) |

Totals: 10 findings (4 medium: A-1, A-5, A-6, A-9; 6 low: A-2, A-3, A-4, A-7, A-8, A-10), 33 unguarded
decisions. Escape codes across findings: T-ABSENT 4, T-INSTANCE 4, D-DOCS 5, T-ORACLE 2, D-PARALLEL 2,
P-UNRUN 2, T-TAUTO 1, D-MULTIPATH 1, P-REVIEW 1.

## Per-file notes (appended as each file is finished)

### Batch 1: crates/core Cargo.toml, lib.rs, hex.rs, error.rs, config/{mod,object,spec,token,check,address,observe,io,lock}.rs, tests/{exit_codes,config_doc,common/mod}.rs

#### Findings

### A-1. The "verbatim" config split deleted core's whole keys.toml unit-test module; docs still cite three of the deleted tests — medium (process: the top finding of this area) — verified

`crates/core/src/config/mod.rs` (test module gone in 8aaba2e), `crates/core/src/config/check.rs:12-289`, `docs/DESIGN.md:469,493,498`, `docs/FILE.md:347`
What: 8aaba2e ("Split … core config; … Both moves are verbatim", 2026-11-24, the last commit before the
merge bc94263) moved config/mod.rs's code into object/spec/token.rs and dropped its `#[cfg(test)] mod tests`
(lines 994-1356 of 8aaba2e^): `names_are_letters_digits_dashes_and_underscores`,
`origins_say_how_an_object_comes_to_be_on_a_token`, `objects_born_in_files_read_their_migrate_file`,
`no_secret_file_is_in_the_nix_store`, `paths_resolve_before_they_compare`,
`env_references_and_object_refs_are_checked_at_load`, `unknown_classes_and_key_types_are_invalid_at_load`,
`des3_value_len_is_the_key_types`. Diffing the non-test lines shows the code itself moved verbatim (one
`pub(super)`), so only the tests were lost (671 added, 1017 deleted). Nothing else in the workspace tests what
they tested: rg for each rule's message finds no test for the name grammar (`check_names`), the load-time
Nix-store guard on `pinFile`/`soCredentialFile`/`migrate.passphraseFile`/secret `migrate.file`
(`check_secret_files`), `resolves_under`'s component-wise comparison, a malformed `$NAME` (17), a private/secret
key without `origin`, `origin = "file"` without `migrate.file`, `create` on an object born in a file,
`passphraseFile`/`encoding` without `file`, `encoding` on a non-secret, a secret file without
`valueLen`/`encoding`, and DES3's fixed 24 bytes. 13 of check.rs's ~27 decisions are now unguarded (list
below); `secret::read`'s own test still covers the store guard at read time.
Why missed: T-ABSENT (now) + P-UNRUN + P-REVIEW. The commit message asserted "verbatim"; the diff stat
(-346 net) says otherwise and nobody compared. `checks.doc-references` must fail on main: DESIGN.md:469,
:493, :498 and FILE.md:347 name three of the deleted fns (`env_references_…`, `origins_say_…`,
`objects_born_in_files_…`), names the script checks (≥4 words) — so main was merged without
`nix flake check` passing. The same commit also had to repair the token suites the 2026-11-23 fix branch
broke ("fix review test drift": exit 22, unset $NAME 16), i.e. that branch's fixes were never run either.
Class: a refactor commit that drops tests with a "verbatim" claim; tests living in the module they test,
so a module split silently takes them. Instances: 1 found (8 tests). The test-name diff 4304989→bc94263 over
core/profile/fuzz shows 11 removed names; 3 moved (camigrate::side ×2, exit-code test replaced), 8 lost.
Instance fix: restore the 8 tests from `8aaba2e^:crates/core/src/config/mod.rs` into `config/check.rs`
(and `io.rs` for `paths_resolve_before_they_compare`).
Class fix: (1) a CI guard that the set of `#[test]` names never shrinks without the commit listing each
removed one (a `tests.lock`-style list checked by a script, like `surface.rs`); (2) actually gate merges on
`nix flake check` (doc-references already catches this); (3) put load-rule tests in `tests/refusals.rs`
(an integration file a split cannot touch), not in the split module.

### A-2. `ProbeCfg.scratch_id`'s doc still states the guard the critical D-1 replaced, and cites a deleted function — low — verified

`crates/core/src/config/token.rs:78-84`
What: "The probe still refuses a slot holding anything but its provider's own placeholder
(`Provider::scratch_occupant`)". 2026-11-23 D-1 (critical) was exactly that this placeholder test let the
probe overwrite real PIV keys; fce5432 removed `scratch_occupant` and made the guard accept only the probe's
own certificate or an empty slot (`caprobe/src/probe.rs:256-270`). A reader of `TokenCfg` learns the unsafe
rule. caprobe's own `probe()` doc (`caprobe/src/probe.rs:121-123`, cross-area) says the same.
Why missed: D-DOCS + T-ABSENT. `checks.doc-references` checks backticked names only in Markdown and only
of ≥4 words; rustdoc checks only `[links]`; nothing checks a backticked `Type::fn` in a doc comment. The D-1
fix commit changed the guard but not this text (the text moved verbatim into token.rs in 8aaba2e).
Class: stale names in Rust doc comments. A scan of the scope (every backticked `Type::fn` / snake name in
`//` comments against all `fn` names) finds 1 dangling here, plus `id.rs:1147` (`spki_curve`, A-13 deleted
it — see id.rs batch) — 2.
Instance fix: "The probe refuses a slot holding anything but its own certificate (`CN=cakeys-probe`) or
nothing." Class fix: extend doc-references.py to Rust `//` comments and to `Type::fn` forms of any length.

### A-3. The scratch-slot load guard (D-1) checks `CKA_ID` locators only; a label-only locator on that slot loads — low — verified

`crates/core/src/config/check.rs:67-86`
What: `check_scratch_slots` refuses a `probe.scratchId` equal to a spec locator's `CKA_ID` on the same token
name. A spec that names the slot by label (`{ CKA_LABEL = "Private key for Retired Key 4" }`; CONFIG.md's
own ykcs11 example uses a label-only locator) or reaches the same YubiKey through a second `[tokens]` entry
passes load. The probe's runtime guard (only an empty slot or the probe's mark) still stops the overwrite,
so this is the second line of defence only; but OPEN/Status describe D-1's load rule as "a scratchId a
locator uses is invalid at load".
Why missed: T-INSTANCE — `refusals.rs:224-229` tests the `CKA_ID` case (and `0A`/`0a`) only.
Class: a rule keyed on one locator form while locators have two (label, ID). Instance fix: for a ykcs11
token, map PIV labels to slot IDs (ykcs11 already knows the table) or refuse a label-only locator beside a
`scratchId`; say "by CKA_ID" in the docs otherwise. Class fix: one `Locator::names_id(&[u8])` the provider
answers, used by every rule that compares a locator to a slot.

### A-4. `KmError::every_variant` promises compile-time completeness it does not give — low — verified

`crates/core/src/error.rs:159-199`
What: the doc says "a new variant does not compile until it is listed here too". The exhaustive `match`
forces a new arm, not a new entry in the `all` vec; a variant added to the match only is invisible to
`documented_exit_codes_are_the_ones_returned` and `the_exit_code_table_lists_every_code`, so its code can
be missing from `EXIT_CODES` and CAKEYS.md. (Prior A-16's fix replaced source scraping with this.)
Why missed: D-PARALLEL (two lists in one function) + D-DOCS; the fix (61b7000) has no test that a vec of
length N matches the enum's N variants. Class: hand-synced enum lists (also `said!`, `exit_code`). Instance
fix: build `all` inside the match (`match e { KmError::X(..) => "X", … }` over a vec whose length is
asserted against a `const VARIANTS: usize` updated in the same match), or derive `strum::EnumIter`.

#### Unguarded decisions (no failing test if flipped or deleted)

- `config/check.rs:19-25` — DES3 `valueLen` must be 24 — test deleted in 8aaba2e (A-1).
- `config/check.rs:58-63` — SO credential needs a user PIN — only `cli/tests/reference/tokens.rs:144` (T-GATED).
- `config/check.rs:98-114` — name grammar — test deleted (A-1); a dotted name breaks `check o.id.s` parsing and the Nix shell quoting.
- `config/check.rs:138` — transport key must declare `CKA_UNWRAP = true` — only the `CKA_EXTRACTABLE` half is tested (`refusals.rs:240-243`), the EC case fails earlier at the RSA check.
- `config/check.rs:153-170` — load-time Nix-store guard for secret files — test deleted (A-1).
- `config/check.rs:180-182, 184-186, 188-193, 197-205` — migrate.passphrase*/encoding/secret-file-length rules — tests deleted (A-1).
- `config/check.rs:215-223` — a private/secret key must state its origin — test deleted (A-1).
- `config/check.rs:229-234, 241-247` — `origin = "file"` needs `migrate.file`; never `create` beside a file — tests deleted (A-1).
- `config/check.rs:279-283` — malformed `$NAME` is 17 — test deleted (A-1).
- `config/check.rs:286-288` — unset `$NAME` is 16 (A-14) — only `cli/tests/reference/lockfile.rs` (T-GATED).
- `config/lock.rs:97-101` — input alias (`pubkeyhash`) refused in a lock — no test.
- `config/lock.rs:105, 150` — object IDs / specDigest must be SRI — only `cli/tests/reference/lockfile.rs:163-164`, exit code 17 only (T-GATED + T-ORACLE: every lock rule is 17).
- `config/lock.rs:156-158` — a realisation's schemes are among its object's IDs — no test asserts this message (lock_mbt projects onto a model that has the invariant, but never feeds a lock that breaks it).
- `config/lock.rs:160-165` — binding present exactly for private keys — only `lockfile.rs` (gated, exit code only).
- `config/io.rs:95-106` owner/group half of A-4 (mode is tested) — root-only, accepted.

#### Prior fixes re-checked

- 2026-11-23 A-4 (lock keeps mode) — holds; tested (`a_saved_lock_keeps_its_mode_and_a_read_only_sidecar_guards`).
- A-12 (read-only sidecar) — holds; tested.
- A-17 (invalid lock on save is 21) — holds; tested in `gc_and_save_leave_a_lock_that_loads`. `toml` encode failure is still `Io` (1) after a token write (`io.rs:58-59`), unreachable in practice.
- A-14 (unset `$NAME` is 16) — holds in code; its core unit test was deleted with A-1; only the gated lockfile suite pins it.
- A-16 (every_variant) — instance of the intent only: see A-4.
- A-7 (split mod.rs) — done, but the second split (8aaba2e) lost the tests: see A-1.
- A-8 (parse object types once) — instance only: `Config.objects` is still `BTreeMap<String, ObjectCfg>`; the parsed `Object` is rebuilt fallibly (`Object::new(..)?`) at ~12 production sites outside core (caprobe ×7, kmsp11, pkcs11), and the curve string is still read at `camigrate/src/side.rs:44`, `camigrate/src/plan.rs:266`, `camigrate/src/keyfile.rs:73` (`object.curve().ok()`: a re-parse with its error swallowed) and `pkcs11/src/gate.rs:242`. The proposed class fix (store the parsed kind in `Config`) was not made.
- A-15 (CONFIG example loads) — holds; `the_annotated_config_example_loads`.

#### Cross-area notes

- `caprobe/src/probe.rs:121-123`: `probe()`'s `# Errors` still says the slot may hold "nothing but the provider's own placeholder" (pre-D-1 rule; see A-2).
- `cli/tests/tpm2.rs` (8aaba2e): `lock --dry-run` is asserted to exit 22 ("the lock was written") — a dry run that writes nothing reporting LOCK_WRITTEN looks wrong; worth a check by area C.
- `camigrate/src/tokens.rs:742-755` `transport_fault` and `core/src/config/check.rs:118-145` are two versions of the transport-key rule (the lock-side one accepts an absent `CKA_EXTRACTABLE` and checks no size; `check_transport_size` does that separately): one rule, two homes.

#### Per-file

- Cargo.toml, lib.rs, hex.rs — clean.
- error.rs — A-4.
- config/mod.rs — A-1 (tests lost); `load_config`'s doc (`:179`) says an unset `$NAME` is invalid at load, true only for `profileDirs`.
- config/object.rs, spec.rs — A-8 recheck (instance only).
- config/token.rs — A-2.
- config/check.rs — A-1, A-3; 13 unguarded.
- config/address.rs, observe.rs — clean.
- config/io.rs — clean (A-4/A-12/A-17 hold).
- config/lock.rs — 4 unguarded invariants.
- tests/exit_codes.rs — A-4. tests/config_doc.rs, tests/common/mod.rs — clean.

### Batch 2: crates/core plan.rs, reconcile.rs, spec/lock.qnt, tests/{properties,lock_mbt}.rs, properties.proptest-regressions

#### Findings

### A-5. The A-2 fix decides "the same token object" by locator spelling: a differently written locator bypasses it, and a narrower secret-key spec on the same locator can never be locked — medium — verified (by trace)

`crates/core/src/reconcile.rs:303-327` (`same_object_no_weaker`), `:382-387`; `crates/pkcs11/src/ops/mod.rs:33-41`; `docs/DESIGN.md:382-384`
What: (a) Bypass. The guard compares other specs' realisations only when
`prev.locator == t.on_token.locator` (structural equality of `{CKA_LABEL, CKA_ID}`). Spec `s` locked on
token `t` with `{ CKA_LABEL = "k" }`, `attestation = true`, `pop-sign`; spec `s2` for the same object with
`{ CKA_LABEL = "k", CKA_ID = "01" }` (or `{ CKA_ID = "01" }`) finds the very same PKCS#11 object, but the
guard skips `s`, so `lock --spec s2` records it `token-asserted`, unattested, silently — the exact scenario
of 2026-11-23 A-2, plus one locator key. The code comment ("Another locator is another object of the
same material") is the wrong premise: two locators can name one object.
(b) Over-refusal (regression). For a secret key the schemes follow the declared usage
(`ops::wanted_commits` → `declared_commits`). `s1` = AES with `{ CKA_SIGN, CKA_WRAP }` locks `{cmac, kw}`;
`s2` = the same object and locator with `{ CKA_SIGN }` computes `{cmac}`; `same_object_no_weaker` runs
`no_downgrade` against `s1`'s realisation and `lost = ["kw"]` → 14 "identity downgrade … a weaker
realisation needs a new object name", also under `lock`. Locked the other way round it passes. CONFIG.md
names this use ("the same key used sign-only by one service and sign-and-decrypt by another"). The advised
remedy is impossible: `record` (`:576-591`) and the lock's load invariant refuse the same material under a
second object name of the same class, so DESIGN §3.7's "a realisation that should stop attesting needs a
new object name" can only be done by deleting the old object and `gc` first.
Why missed: T-INSTANCE + T-TAUTO + D-DOCS. `a_second_spec_of_the_same_object_cannot_record_it_weaker`
(`reconcile.rs:920-955`) tests one EC key whose `Resolved.ids` is the fixed `resolved()` fixture (not what
the spec would compute), with an identical locator and one "copy" with a different label — never a
second spelling of the same object nor a secret key with a narrower usage. The fix (fce5432) changed a
lock rule without touching `spec/lock.qnt` (unchanged since 2026-11-18): the model's keys.toml has no
two specs on one object and token, so `lock_mbt` cannot notice (A-6). The token-gated `shared-*`
reference test uses two different labels, so it never meets the guard. Written without a run (P-UNRUN:
the branch's status says so).
Class: identity of a token object approximated by configuration text (the locator) rather than by what
the token returned; and "downgrade" defined as "fewer schemes" across specs whose schemes are
legitimately different by declaration. Instances: this rule; `spec_diff`'s locator comparison is the same
approximation, but there a false positive only asks for a review.
Instance fix: decide sameness by the object found — compare the found object's `CKA_ID`/`CKA_LABEL`
(both read anyway) against the other realisation's locator, or record a stable object fingerprint
(label+id as read) in `observed`; compare across specs only mode, binding, attestation and immutables,
not the scheme set (each spec's schemes are its own declaration). Make the 14's advice say "remove the
other spec's realisation (`delete`/`gc`) or attest this one too", or let `record` accept a second name
only after the first is gone. Class fix: model two specs sharing an object in `lock.qnt` (A-6) and add a
property over every (spec1, spec2) usage pair on one object.

### A-6. The lock model no longer describes the lock rules, and the documented "a rule change without a model change fails `lock_mbt`" does not hold — medium — verified

`crates/core/spec/lock.qnt:1-21`, `crates/core/tests/lock_mbt.rs:27-66, 182-196`; `docs/DEVELOPMENT.md:198-199`
What: two lock rules changed on 2026-11-23 (fce5432 A-2 `same_object_no_weaker`; fcaa6aa A-5
`same_type` and the `modulusBits` gap in `record_object`); `lock.qnt` was last changed 2026-11-18
(git log). The model's fixed keys.toml has one spec per (object, token) and no RSA key, so neither rule
can fire in a replayed trace, and the model header's "left out" list names neither. DEVELOPMENT.md:198
claims "A change to the lock rules changes the model in the same commit, or `lock_mbt.rs` fails" — false
for any rule keyed on configuration the model fixes (shared objects, locators, `publicOnly`, RSA, imports,
`origin = "file"`, transport `publicKey`). The `rule_of` marker table would even pass the new A-2
message as "attestation-lost"/"binding" because it only adds a suffix.
Why missed: D-DOCS + T-ABSENT. The guarantee is enforced only for rules whose triggering input the model
already generates; nothing checks that the Rust's refusal set equals the model's (the witness check runs
in the other direction: model rules must be reached, not Rust rules modelled).
Class: a verification artefact whose coverage boundary is fixed in a header and silently outgrown. Same
shape: `fuzzing_surface.rs`'s hard-coded count (see fuzz batch), DEVELOPMENT.md's "Mutation-checked"
claims for properties.rs.
Instance fix: extend the model's keys.toml with a second spec on `k`/t1 (other usage), an RSA object with
and without `modulusBits`, and model `same_object_no_weaker`; list in the header what stays out.
Class fix: a test that enumerates every `KmError::PreconditionFailed` construction in reconcile.rs (or every
`rule_of` marker) and requires each to be either a model rule or named in a `LEFT_OUT` list; correct
DEVELOPMENT.md to the weaker claim it can keep.

#### Unguarded decisions

- `reconcile.rs:282-284` — a changed locator is a spec change (14 on `check`) — no test anywhere asserts it (lock_mbt fixes locators; unit tests never change one).
- `reconcile.rs:285-287` — `publicOnly` flipped is a spec change — only `cli/tests/reference/drift.rs:473` (T-GATED).
- `reconcile.rs:310` — `prev.public_only == r.public_only` in the A-2 filter — no test with a `publicOnly` second spec.
- `reconcile.rs:382-387` — lost schemes on the same realisation — only lock_mbt (the `schemes-lost` witness); no unit/property test, and the message shares "which it no longer computes" with the attestation rule (`:368`), so `attestation_changes_are_never_rerecorded`'s `contains("no longer computes")` cannot tell them apart (T-ORACLE).
- `reconcile.rs:176-178` — the `origin = "file"` exemption from "an import needs locked IDs" — only camigrate's gated `from_files.rs`.
- `reconcile.rs:541-546` — deprecated schemes not recorded — unreachable today (no scheme is deprecated); no test (fine, but the decision is unguarded when one is added).
- `reconcile.rs:554-560` — a transport key's `publicKey` recorded as a gap only — no core test; gated camigrate suites only.
- `reconcile.rs:688-710` — provider / cakeys version / profile change notes — untested (notes only).
- `plan.rs:50` — `transport` flag (decides whether `publicKey` is recorded) — no core test.

#### Prior fixes re-checked

- 2026-11-23 A-2 — wrong/instance: see A-5 (bypassable by locator spelling; over-refuses narrower secret-key specs; advice impossible).
- A-5 (`modulusBits` not a new type) — holds; `a_declared_modulus_size_is_not_a_new_type` (note its configs are built by `toml::from_str`, not load, so `canonicalize` never ran on them).
- A-10 (proof forbidden by allowed list is 17 at load) — holds; `a_proof_the_allowed_mechanisms_forbid_is_refused_at_load`; core's table held to pkcs11's by `the_proofs_mechanisms_are_the_ones_load_checks`, over 5 of 9 key kinds (secp256k1, brainpool ×2 and Ed448 not sampled).
- 2026-11-23 "reconcile.rs design: `record` relies on `compare` having run" — still no comment or type enforcing it (`record` is private and only `reconcile` calls it, so it holds by construction).

#### Cross-area notes

- `pkcs11/src/ops/mod.rs:33-41`: commitment-mode schemes are the declared ones; any cross-spec comparison of scheme sets (A-5) must account for that.

#### Per-file

- plan.rs — clean (well tested; 1 unguarded).
- reconcile.rs — A-5; 8 unguarded.
- spec/lock.qnt — A-6.
- tests/lock_mbt.rs — A-6.
- tests/properties.rs — clean; its oracles are hand-written (not from the code), good. It never varies mode, attestation or scheme loss on one realisation, nor two specs per token object.
- tests/properties.proptest-regressions — clean (data).

### Batch 3: crates/core/src/id.rs

- id.rs — clean apart from one more instance of A-2's class: `id.rs:1144-1147`'s doc ("each is refused alike by `spki_curve` and by `spki_canonical`") and the two test names `spki_curve_names_the_key_kind` / `spki_curve_reads_what_canonical_spkis_hold` name `spki_curve`, deleted in 61b7000 (2026-11-23 A-13). A-2's class count: 2 (token.rs:78-84, id.rs:1144-1147).
- Checked and holding: RSA identity of any size (`rsa_key` refusals all tested); wrapped/raw `CKA_EC_POINT` cannot both parse to two different points for any supported curve (OCTET STRING length byte vs SEC1 lengths: 63/95/130 inner bytes are never 33/65, 49/97, 67/133); one SPKI dispatcher by OID (D6); commitment label injective (property) and pinned (KATs); spec digest pinned; curve aliases canonical (`refusals.rs:615`).
- Note: an AES/generic secret without `valueLen` loads and commits with `…/0` bits; declaring `valueLen` later is a type change (14) — correct (the label changes), unlike `modulusBits` (2026-11-23 A-5), but the asymmetry is undocumented in CONFIG.md's `valueLen` text.

#### Unguarded decisions

- `id.rs:356-359` — `Commit::profile_kind` — no test pins it against the profile crate's `capability.rs:318-326` kind→mechanism table (a second table of the same names; see profile batch, 2026-11-23 A-9 recheck).

#### Prior fixes re-checked

- 2026-11-23 A-13 (`spki_curve` folded into `KeyAlg`) — holds in code; doc/test names left dangling (A-2 class).
- 2026-11-23 A-9 (one commitment table) — `Commit::profile_kind` is the one table in core; see profile batch for the profile's own copy.

### Batch 4: crates/core/src/chain.rs, tests/fixtures/{attest95,f9,root,slot}.pem, tests/fixtures/chain-rules/*

### A-7. The 2026-11-23 A-3 chain rules hold inside `chain_to_anchor` only; the PIV slot link is verified with the bare `verify_signed_by` — low — verified

`crates/core/src/chain.rs:195-251` (`may_issue`, `no_unknown_critical`: private), `crates/ykcs11/src/attest.rs:63-71`
What: `chain_to_anchor` now refuses an issuer without CA / `keyCertSign` and any certificate with an
unprocessed critical extension. The PIV path walks the *device* (f9) certificate to the root, then checks
the *slot* certificate with the public `verify_signed_by(&slot, &device)` alone: the device's CA flag and
`keyUsage` are never asked about the certificate it signs, and the slot certificate's critical extensions
are never inspected. A device certificate with `keyUsage = digitalSignature` only, or a slot certificate
with a critical `nameConstraints`/vendor extension, verifies. Defence in depth (the f9 key is the device's),
hence low.
Why missed: T-INSTANCE + D-MULTIPATH. The A-3 fix (fce5432 region; tests
`issuers_sign_certificates_and_critical_extensions_are_understood`) put the rules in the walk's `link`
closure and kept them private, while the one caller that verifies a link outside the walk uses the
public primitive. No ykcs11 test hands `verify_piv` a device certificate lacking `keyCertSign`.
Class: a rule placed in one composite operation while a lower-level primitive that skips it stays public.
Instances: 1 (`verify_signed_by` has one production caller outside chain.rs: ykcs11 attest.rs:67).
Instance fix: let `chain_to_anchor` take the slot certificate as the start (`Start::EndEntity`) with the
device in the pool, or expose `Cert::link_to(issuer, below)` running all four checks and use it there.
Class fix: make `verify_signed_by` `pub(crate)` and export only link-checking entry points.

- chain.rs — A-7; otherwise clean. Checked: tbs sliced from the original DER; outer/inner algorithm equality; every name-matching issuer tried; walk depth bounded (`max_links` 3 at both callers, so pool^3 signature checks at worst); pathLen counting by caller's `Start`.
- fixtures (attest95, f9, root, slot, chain-rules/*.pem, make.sh) — clean; make.sh documents each fixture's one differing rule; openssl confirms f9 is `CA:TRUE` (so A-7's fix would not break the real chain shape).

#### Unguarded decisions

- `chain.rs:126` — `valid_at` inclusive at both ends — no test at the boundary seconds; only gated `cli/tests/reference/proofs.rs` and ykcs11's unit test reach `valid_at` at all.
- `chain.rs:37-43` — `certificatePolicies` (2.5.29.32) in `UNDERSTOOD` — no core test fails if it is dropped (only a chain walk over Yubico's intermediates would; core's `issuers_must_be_cas_within_their_path_length` calls `may_issue` only).

#### Prior fixes re-checked

- 2026-11-23 A-3 — holds in the walk; instance only for the PIV slot link (A-7).

### Batch 5: crates/core/src/pop.rs, sig.rs

### A-8. The ECDSA hash per curve is two tables: the token signs with `HashAlg::for_curve`, the host verifies with `ecdsa_over`'s own per-curve literal — low — verified

`crates/core/src/sig.rs:67-74` (`for_curve`) vs `:139-145` (`curve!(…, HashAlg::ShaNNN, …)`); signer side `crates/pkcs11/src/token/possession.rs:685-692`
What: `pop::verify` verifies an EC proof with `sig::ecdsa(.., None)`, i.e. the hash hard-coded in each
`curve!` arm; the token is asked to sign with `ecdsa_hash` = `HashAlg::for_curve`. Today they agree. A
change to one (a new curve, a corrected brainpool hash) makes every proof on that curve fail 13 ("did not
sign for the public key") — loud, never a false pass, hence low.
Why missed: D-PARALLEL + T-ABSENT. `types_name_their_hash_and_curve` (`refusals.rs:677-687`) pins
`for_curve` for P-256/384/521 only (not secp256k1 or the brainpools); `ecdsa_encodings_and_kinds` pins
the macro's own hash for P-256 only. Nothing ties the two tables; the token-side counterpart runs only in
gated suites.
Class: hand-synced per-curve tables. Siblings: `Curve::params`/`from_cfg`/`name`/`display` (pinned by
`curve_params_roundtrip_and_match_the_crates`, fine); `proof_mechanisms` vs pkcs11's proof mechanisms
(pinned over 5 of 9 key kinds, see batch 2). 2 unpinned of 4.
Instance fix: `ecdsa_over` takes its own hash from `HashAlg::for_curve(c)` (one table). Class fix: a test
iterating `Curve::ALL` for every per-curve table.

- pop.rs — clean. Checked: challenge = domain ‖ H(spki) ‖ 32-byte OS nonce (pinned); verifier picked by OIDs; a refused key is 15, never a failed proof (13); ECDH/unwrap MACs compared in constant time; proof secrets zeroized (compile-time check on sha2's `ZeroizeOnDrop`).
- sig.rs — A-8; otherwise clean (`None` means "another kind" only; high-`s` normalized; strict Ed25519).

#### Unguarded decisions

- `sig.rs:141-145` — the own hash for secp256k1 / brainpoolP256r1 / brainpoolP384r1 — no test (A-8).
- `pop.rs:224-229` — the overheads `11`, `2·20+2`, `2·64+2` (PKCS#1 v1.5, OAEP-SHA-1, OAEP-SHA-512) — only OAEP-SHA-256's limit is tested at the boundary (62 bytes); an off-by-one in the others turns a 15 into a 16.

#### Prior fixes re-checked

- 2026-11-23 A-11 (RSA "message too long" is 16) — holds; `a_message_too_long_for_the_modulus_is_unsupported`.
- 2026-11-23 A-13 (test-only pop wrappers) — holds: `verify`, `unwrap_challenge` are the former `_with` forms; `oaep_challenge` gone.
- 2026-11-23 B-7 (32-byte proof secret fits RSA-1024) — holds in core (`secret()`; tested at 1024 bits).

### Batch 6: crates/core secret.rs, hex.rs, lib.rs, plaintext.rs, migrate.rs, types.rs, attrs.rs, fuzzing.rs, Cargo.toml, tests/{common/mod.rs, config_doc.rs, fuzzing_surface.rs}

- secret.rs — clean (one reader; Nix-store refusal at read time, link resolved; multi-line refused; non-UTF-8 env is 17 not 16). Note: an empty PIN file or empty `pinEnv` is a PIN of `""` by design (`a_secret_is_one_line_of_its_file` pins `("", "")`), so a secret deployed empty (an undecrypted sops/agenix target) reaches `C_Login` — whether that burns a PIV retry is pkcs11's (cross-area note).
- hex.rs, lib.rs — clean.
- plaintext.rs — clean (parser chosen by declared type and curve, 2026-11-23 A-8; secret parts zeroized, never echoed; multi-prime RSA is 15).
- migrate.rs — clean; `Method::BUILTIN` is a hand list beside the exhaustive `builtin_name` match: a new built-in method missing from it has a name that never parses back (`from_name` → `None`). Sibling of A-4 (below).
- types.rs — clean, and the in-repo model fix for A-4's class: `pkcs11_names!` generates `ALL`, `name`, `FromStr` from one list.
- attrs.rs — clean; the observed vector is pinned (it changes locks).
- fuzzing.rs — clean; `lock_round_trips` compares `Debug` of both reads, a real oracle (not "no panic").
- Cargo.toml — clean (`fuzzing` feature off by default; sha2 `zeroize` required by pop.rs's compile-time check).
- tests/common/mod.rs — clean.
- tests/config_doc.rs — holds 2026-11-23 A-15 for the one annotated block; CONFIG.md's other prose claims (shared objects, A-5) are not exercised.
- tests/fuzzing_surface.rs — clean; it scans Cargo.toml manifests only, so a Nix `cargoExtraArgs`/`--features …/fuzzing` would escape it. Today nix/package-common.nix's `features` list has none (checked), so this is a boundary note, not a finding.

A-4 class count (hand-written "every value" lists beside an exhaustive match, nothing forcing the list): `KmError::every_variant` (A-4), `Scheme::ALL` (`id.rs:89-100`; a scheme missing there is "unknown to this cakeys" — its locked IDs only warned about, `reconcile.rs:500-511`, and `is_attestation` load checks skip it), `Curve::ALL` (`id.rs:435-444`), `Method::BUILTIN` (`migrate.rs:142-159`): 4. `types.rs`'s macro shows the fix.

#### Unguarded decisions

- `secret.rs:33-36` — trailing `\r`/`\n` stripped, then any inner one refused — tested; clean.
- `migrate.rs:131-139` — vendor method parts must be names — tested; clean.
- (none new beyond the A-4 class.)

### Batch 7: crates/profile (Cargo.toml, lib.rs, embedded.rs, names.rs, baseline.rs, capability.rs, profile.rs, effective.rs, tests/answers.rs, tests/answers.txt)

### A-9. `Effective::commit` answers *no* for a length never tried whenever every tried length was refused — the mirror of 2026-11-23 A-1, left in place — medium — verified (by trace; latent in committed data)

`crates/profile/src/effective.rs:248-250`; consumer `crates/pkcs11/src/gate.rs:259-281`
What: `commit(kind, kt, Some(n))` with `n` untried and every tried row `no` returns `Verdict::No`
(`if rows.iter().all(|(_, yes)| !yes)`), for free-length key types too. `generate_secret` and `generate`,
given the same shape, answer Unknown ("probed … only"). A module profile whose HMAC rows are
`16: no, 32: no` (SoftHSM's SHA-384/512 HMAC refuse short keys; its profile happens to also try 64) and
a keys.toml generic secret of `valueLen = 64` would be refused up front by `gate::commitments` ("computes
none of its commitments", 15), although 64 is above every refused length and the module computes it.
D5 ("unknown, never a guess") and the function's own doc ("any other length is unknown") say otherwise.
Today's committed profiles reach it for CloudHSM `kw` only, where all three AES lengths were tried, so it
is latent.
Why missed: T-INSTANCE + T-ORACLE. The 2026-11-23 A-1 fix (`between_working`) closed *yes* from
absence; its test `secret_lengths_interpolate_only_between_two_that_worked` has no all-refused key type.
The 2026-11-23 A-16 fix pins `commit` verdicts in `answers.txt`, but `answers.rs:166-172` asks them only
at the lengths the rows name (where interpolation and this rule never run) — unlike generation, asked at
the ten `BYTES` lengths. Deleting the line changes no test. Introduced fcd2779 (2026-11-19, caprobe
commitments), untouched by the A-1 fix.
Class: three verdict functions (`generate`, `generate_secret`, `commit`) re-implement the same
"decided / interpolated / unknown" ladder by hand; each fix lands in the one(s) the report named. 1
remaining divergence found (this); `generate` additionally trusts the reported range (by design, tested).
Instance fix: answer Unknown when `n` is untried and every row is no (keep No only for `bytes = None`, as
`generate_secret` does). Class fix: one `decide_size(rows, n, free)` used by all three, and `answers.rs`
asking `commit` at the `BYTES` lengths like generation.

- Cargo.toml, embedded.rs — clean.
- lib.rs — clean, well tested (runtime `profileDirs` only add observed module profiles; symlink loops end; one baseline). Provider code wins over a data family (`pkcs11/src/registry.rs:89`), so a runtime profile cannot stand in for a coded provider.
- names.rs — clean; `Proof::PopSignPin` ("pop-sign-pin") is dead: `Binding::proof_name` maps PopSignPin to "pop-sign" and no profile has such a row (nit).
- baseline.rs — clean; `CURVES` pinned against core by `pkcs11/src/gate.rs:294-300`.
- capability.rs — clean parser (one key per row, enforced); see unguarded and the A-9 (2026-11-23) recheck.
- profile.rs — clean; `Reported`/`Restrict`/`MechanismInfo` accept `min > max` unchecked (a hand-written layer with `min-bits = 4096, max-bits = 2048` refuses every size; nit).
- effective.rs — A-9.
- tests/answers.rs, answers.txt — snapshot oracle generated by the code under test (T-TAUTO by construction; the reviewer of the diff is the oracle); see A-9 for what it does not ask.

#### Unguarded decisions

- `effective.rs:248-250` — all-refused → No at any length — no failing test (A-9).
- `capability.rs:316-328` — the profile's own `commit_mechanism(kind, key_type)` table — pinned against nothing in core (`Commit::mechanism`/`profile_kind`); it decides `Capability::mechanisms`, i.e. `untested_problems` and the probe's "tried" set.
- `lib.rs` `the_committed_profiles_name_only_known_rows` (`lib.rs:411-436`) — checks 9 of 20 `Capability` variants; a misspelt `commit.<kind>` or a `crypt/sign/kdf/attr` row's `CKK_` name loads and answers nothing.
- `effective.rs:316-318` — `reported` range decides `no` outside `[min, max]` before probed rows — tested (`key_types_and_size_bounds_decide_exactly`); clean.

#### Prior fixes re-checked

- 2026-11-23 A-1 (`between_working`) — holds for yes-from-absence in all three functions; instance only: no-from-absence remains in `commit` (A-9).
- 2026-11-23 A-9 (four commitment tables) — partial: the names now agree (profiles regenerated with `kcv-ecb-dec`, checked), `profile_kind` lives in core, pkcs11's `commit_mechanism` is pinned to core's names (`identity.rs:434`); the profile crate's `commit_mechanism` remains a fourth table pinned to nothing.
- 2026-11-23 A-13 (one baseline; `Restrict.operation` a plain string) — holds.
- 2026-11-23 A-16 (pin `commit` verdicts) — instance only: pinned at probed lengths, not the interpolated ones (A-9).

#### Cross-area notes

- `pkcs11/src/gate.rs:259-281` turns A-9's false No into a 15 at `validate`/`create`.

### Batch 8: crates/p11-names (Cargo.toml, src/lib.rs), fuzz/ (Cargo.toml, Cargo.lock, fuzz_targets/*.rs)

### A-10. The `cert_bundle` fuzz target (the 2026-11-23 A-18 fix) states an oracle it does not check; 4 of 14 targets assert only "no panic" — low — verified

`fuzz/fuzz_targets/cert_bundle.rs:1-15`; also `piv_chain.rs`, `tpm_store_row.rs`, `tpms_attest.rs` (`let _ = …`), `config.rs` (exit code only)
What: `cert_bundle`'s header says "every certificate it yields walks to an anchor among the file's own,
or is refused" — `chain_to_anchor` returns `Ok` or `Err` by type, and the result is discarded, so the only
property checked is absence of panics. A PEM splitter that dropped or merged a block, or a walk that
accepted a bad signature, passes. A-18 asked for "`chain_to_anchor` against the fixture roots"; the
target anchors each file on itself instead, where every self-signed certificate is trivially an anchor.
Why missed: D-DOCS + T-ORACLE; the fix commit (61b7000 region) added the target and its seed corpus, and
the smoke check (`nix/fuzz.nix`) can only fail on a panic.
Class: fuzz targets whose doc promises a property the body does not assert. 1 of 14 (the other
panic-only targets say "never a panic" and mean it). The meaningful ones — `lock`, `bundle`, `profile`
(round trips), `certificate`, `public_key` (canonical fixed point), `hex`, `attest_encoding`
(reads back), `p521_point` — are good oracles.
Instance fix: assert `pem_certs` round-trips (each yielded DER re-encoded to PEM reads back to the same
DER) and that an `Ok` anchor's signature verifies over the last link (`verify_signed_by`), or reword the
header. Class fix: none needed beyond a rule that a target's header names only what it asserts.

- p11-names — clean; every name is bound to its `cryptoki_sys` constant by the compiler; slot/token flag tables kept apart (tested). Completeness ("every CKR_* cryptoki-sys defines") is a hand list, not checked (nit).
- fuzz/Cargo.toml — clean; `fuzzing` features turned on only here (held by `fuzzing_surface.rs`). `nix/fuzz.nix` refuses a target file with no `[[bin]]` entry (good class fix).
- fuzz/Cargo.lock — clean today: of 187 crates shared with the root `Cargo.lock`, every version the fuzz build uses is one the product uses (checked by script). Nothing keeps them so: a `cargo update` of the root leaves the fuzzed parsers (der, x509-cert, rsa, p256…) at the old versions silently (unguarded, below).
- fuzz_targets — A-10; the rest clean.

#### Unguarded decisions

- `fuzz/Cargo.lock` vs `Cargo.lock` — no check compares the versions of the crates both build; the fuzzed parsers can drift from the shipped ones.

#### Prior fixes re-checked

- 2026-11-23 A-18 — instance only/weak: target added, oracle panic-only, anchors not the fixture roots (A-10).
- 2026-11-23 A-16 — holds: `a_lock_that_cannot_be_saved_is_its_own_code` now has a root-proof case (`io.rs:290-294`); `exit_codes.rs` scraping replaced by `every_variant` (A-4 notes its own gap); lock_mbt retargeting documented as left out in `lock.qnt`'s header (decision, not a fix).
