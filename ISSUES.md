# Code review findings

Review of `origin/main` at `5c2a0bd`, 2026-11-16. The easy items were fixed in `2120ec1`
("Fixed in this pass"), and a few more after it ("Fixed since"); everything else under "Bugs and
behaviour" and "Poor practices" is still open. Evidence tags as in [docs/CAPROBE.md](docs/CAPROBE.md): **[run]**
reproduced or measured in this review, **[read]** from the code, not run. Every item is [read]
unless it says otherwise.

Checks at the start of the review: `cargo clippy --workspace --all-targets -- -D warnings` and
`cargo test --workspace --no-fail-fast` both pass [run]. The token suites skip under plain
`cargo test`, and no Nix check was run.

## Coverage of the review

| Read in full | Skimmed or searched | Not read |
|---|---|---|
| Every `src/` file of `core`, `pkcs11`, `profile`, `camigrate`, `cli`, `cli-common`, `ykcs11`, `tpm2-pkcs11`, `kmsp11`, `aws-cloudhsm`; `caprobe/{probe,lib,diff,emit,coverage,supports}.rs`; `p11-fault/{lib,hooks,forward,trace,plan}.rs`; `nix/lib.nix`, `nix/sandbox-hook.sh`, `nix/test-tokens.sh`; `.github/workflows/checks.yml` | The unit tests inside those files; `nix/module.nix` (options only); the other two workflows (permissions and pins); three of the seven fuzz targets; the integration tests (searched for sleeps, ignores and the surface lists) | `caprobe/baseline.rs` (the header parser); `p11-fault/names.rs` (name tables); the integration test bodies (`crates/*/tests/`, about 13k lines); the rest of `nix/`; `scripts/`; the Terraform under `scripts/cloud/` |

## Issues flagged in docs: are they fixed?

| Source | Item | Status |
|---|---|---|
| REVIEW-2026-11-15 | V1: `check` creates and provisions | Fixed: read-only session, never provisions |
| | V2: `realise` does three things, `autoCreate` | Fixed: `lock` verb, `origin` per pair; `autoCreate` and `createOn` are unknown fields |
| | V3: exit 10 means two things | Fixed: `FirstUse` is 18 |
| | V4: two address grammars | Fixed: one `Address`; `verify` is an alias of `check` |
| | V5, C6: object types validated per target | Fixed: `ObjectKind` parsed at load |
| | C1: two specs create one object | Fixed: at most one `create` pair per object |
| | C2, N3: no name grammar, unescaped shell | Fixed: `check_names`, `escapeShellArg` |
| | C3, C4, C5: tool settings in the core schema, `provider` overloaded, label-only selection | Fixed: `probe`/`migrate`/`nix` tables, `moduleProfile`, `tokenSerial`, `soCredential*` |
| | N1: the view exposes the unverified URI | Fixed: `uri` removed |
| | N2: the library re-implements rules | Fixed: view shrunk, lock version asserted, and since 2026-11-17 `type` comes from the lock, canonical, once it pins the object (keys.toml's as written before), with no alias table in Nix; `checks.lib` asserts both |
| | P1: a missing profile is fatal at open | Fixed: nearest profile with a note |
| | P2: a profile row picks the ECDH protocol | Fixed: sealed is tried, extractable is the fallback |
| | §4 (a): collapse the `Provider` trait | Done: two repairs, four operations |
| | §4 (b): kmsp11 and aws-cloudhsm touch nothing outside their crates | Holds, checked 2026-11-17 [read]. Both import only `Provider` and core types and implement only its hooks: aws-cloudhsm `repair` and `stand_in`, kmsp11 `hint`, `generation` and `bound_keys`. Outside them, a search finds only their registration (`cli-common`), their embedded profiles and tests. kmsp11's `pop-unwrap` and `pop-ecdh` refusals (`crates/kmsp11/src/lib.rs:290`) are a backstop: `check_reported` refuses the `CKA_UNWRAP = true` or `CKA_DERIVE = true` those bindings need first, since Cloud KMS reports both false. kmsp11 leaves `Provider::template` at its default and replaces the generation template whole, as that hook's documentation allows; what it cannot import is profile data. B11's proofs are still unrun on Cloud KMS ("To test") |
| | §4 (c): the probe calls the verbs' operations | Partly: proofs and EC/RSA generation go through `Token::prove_binding` and `Token::create`. `bound_keys`, `scratch_occupant`, `stand_ins` remain, and Montgomery, secret-key and wrap probes keep their own templates (about 24 template sites, two `Provider::template` calls, on 2026-11-17). Scheduled 2026-11-17: all of them onto `Provider::template`, then the profiles regenerated |
| | §4 (d): one capability row type | Done (`Capability`, `Row`). The emitter is still hand-written (Q27) |
| | §4 (e): per-deployment answers in the lock | Done (`observations.*.capabilities`) |
| | E1: two tests red under plain `cargo test` | Fixed [run] |
| PLAN.md A2 | `uri.rs` leaves `/` unescaped | Fixed in this pass (B3) |
| PUBLISH_REVIEW | Profiles embedded from outside the crate; no `LICENSE` per crate | Not fixed (`publish = false` still). Deferred 2026-11-17 to one pass when a release is planned |
| | READMEs, `keywords`, docs.rs metadata, `pkcs12` rc pin | Not fixed. Deferred with the rest |
| OPEN.md, Engineering | Split the reference suite | Done 2026-11-17 (it had grown to 3,709 lines): a verb's own tests in its file (`check`, `create`, `delete` with `gc`, `validate`), what `lock` and `check` share by concern (`identity`, `proofs`, `adoption`, `drift`, `lockfile`, `tokens`), the harness and shared fixtures in `mod.rs`. A strict verb split would have left 49 of the 66 tests in `lock` |
| | Token suites crash under a parallel `cargo test` | Crash fixed 2026-11-17: the test helpers share one reference-counted context per module (`tests/common`'s `Module`; the last holder finalizes, so a later session still initializes afresh), and a second session takes the login the first made. The SoftHSM suite now runs to its end in one process [run]. It still does not pass there: its tests share one token set (60 of 66 pass with the two token-altering tests skipped). Plain `cargo test` with tokens stays unsupported; nextest (a token set per test) is unchanged, 524/524 [run] |
| | No unit test in `core` for the lock's load-time invariants or the transport-key rules | Fixed: the review's search missed `crates/core/tests/refusals.rs`, whose `lock_objects_keep_their_invariants` reaches every branch of `check_pairs` and `check_one_object_per_material`, and whose transport-key cases now reach every branch of `check_transport_keys` |
| | Fuzz the remaining parsers (PIV chain, P-521 fix-up, profile emit and parse) | Done 2026-11-17: `piv_chain` (slot and device certificates to Yubico's roots and the fixture's, dates included), `p521_point` (what `fix_ec_point` repairs is DER of the same point, and stays repaired) and `profile` (parse, emit, parse is a fixed point), seeded from the fixture chain, the malformed point and the committed profiles; each ran its 100 000 smoke inputs clean [run]. The fuzz crate's lock, stale since p11-names, is current again |
| | `tpm2_ptool` takes the PIN on its command line | Not fixed (accepted for now) |

The lock design review's S-items (`reports/`) were not re-verified one by one; the ones crossed
on the way (S3, S4, S7, S8, S9, S10, S12) are fixed.

## Fixed in this pass

Committed as `2120ec1`, on top of `5c2a0bd`. Checked with clippy, `cargo test --workspace` and
`scripts/local-tests.sh` (492 tests, all passing, after the last change) [run]; no Nix check
was run. B1, B5, B9, B14
and B17 have no test of their own: no reference token is write-protected or pads a modulus,
and the others need a second step that fails or a second spelling of a module path.

| Item | Fix |
|---|---|
| B1 | `cakeys lock` opens with `Access::Scratch`, so a write-protected token can be pinned (`crates/cli/src/lib.rs`); `docs/FAULT_SHIM.md` says `create` |
| B3 | `/` is escaped in URI path attributes and kept in query attributes, as RFC 7512 §2.3 has it [run: the RFC's ABNF], with a unit test (`crates/pkcs11/src/token/uri.rs`) |
| B4 | `wrap_rebind` adds a usage attribute only if the template lacks it (`token/identity.rs`) |
| B6 | An empty PIN is not "redacted" out of `tpm2_ptool`'s message (`tpm2-pkcs11/src/ptool.rs`) |
| B7 | `aes` and `sha2` dropped from `cakeys-pkcs11`, `serde` from `cakeys` |
| B9 | A key-file import saves the lock before it reports a failed certificate import (`camigrate/src/lib.rs`) |
| B12 | `MatchInfo`, `Subtract`, `Restrict` and `AcceptRow` refuse unknown keys, with a unit test (`profile/src/profile.rs`, `lib.rs`) |
| B14 | `caprobe probe --out` overwrites only a file that is absent or readable (`caprobe/src/lib.rs`) |
| B15 | `caprobe supports --token` takes `moduleProfile` before `provider` (`caprobe/src/supports.rs`) |
| B2 | `create` never finds a key: one already under its locator is `Exists`, exit 19, before any capability is asked of the token (`pkcs11/src/ops.rs`, `core/src/error.rs`); three reference tests and `docs/CAKEYS.md` follow. `lock_as` lost its `create` flag (Q11, in part) |
| B5 | The library cache is keyed by the canonical path of a module named by path (`pkcs11/src/token/mod.rs`) |
| B10 | The PKCS#12 MAC key takes 600,000 iterations, as the encryption does (`camigrate/src/file.rs`) |
| B11 | kmsp11 no longer refuses `pop-decrypt` or `pop-sign` on PSS and SHA-512 keys; `pop-unwrap` and `pop-ecdh` stay refused. **Not run against Cloud KMS** (see "To test") |
| B16 | EC and Edwards scalars, the ECDH shared secret and the unwrap secret are wiped (`core/src/plaintext.rs`, `core/src/pop.rs`). The `--userpin=` argument is left: it is on `tpm2_ptool`'s command line either way |
| B17 | The RSA size check ignores leading zero bytes (`pkcs11/src/token/policy.rs`) |
| B19 | A key file's scrypt parameters are bounded (N × r up to 2²³, p up to 16), with a unit test. Verified first: this build's `pkcs5` does decrypt scrypt |
| Q1 | The dead `CKK_EC`/`CKK_EC_EDWARDS` branches are gone from `probe_curves`; `operate`'s fallthrough message no longer says ECDH |
| Q9, in part | `Token::runnable` compares mechanism types, not formatted names |
| Q15, in part | `read_mgm` is `read_so_credential`, and its error says "SO credential" |
| Q18, in part | caprobe's `ckr` calls `token::rv_name` |
| Q30, in part | "unsupported policy attribute" names its target, as the errors beside it do |
| Q5, Q6 | `SessionObject` destroys a session object when dropped; `sealed::export`, `wrap_rebind`, the proofs and `Token::extract` use it, and `export` works on `Found` and `Wrapped` structs in a plain loop. Two destroys stay explicit in the probe, which records their failure |
| Q7, Q8 | `prove_ecdh` has one fallback closure and one sealed-secret template; the OAEP loops count hashes instead of ending in `unreachable!` |
| Q9, in part | One `sorted_names` for the three places that list mechanisms by name |
| Q10 | `delete` picks its scheme and expected ID in one step |
| Q11 | `Provision` and `Verb` enums in `ops.rs`; `prove_sign` takes the binding |
| Q12 | `parse_config_with` calls `check_value_len` and `check_token` |
| Q14, in part | `ops::split_reference` parses `<object>.id.<scheme>` for the CLI and the verb |
| Q18, in part | One table each for OAEP parameters (`token::oaep_params`, `oaep_of`), the `DigestInfo` prefix, hex encoding (`core::hex::encode`), the proof name (`Binding::proof_name`), capability keys (`gate::proof_capability`, `generate_capability`), the Nix-sandbox check, whole-file writes (`config::write_whole`, now synced), the binding layer's name and `Scheme::Rfc7093m4.name()` |
| Q21 | `Profile::new` and `TokenCfg::labelled` replace the 14-field literals |
| Q22 | kmsp11 parses `keys.json` once, behind a `LazyLock` |
| Q25 | `host.rs` shares `source_key` and `hand_over`; `public::origin` builds the provenance record; camigrate has `Run::save` |
| Q26, in part | The probe's `Oaep` and `Refused` wrappers are plain options |
| Q29 | ykcs11 reads a certificate's value in one helper |
| Q30 | `Mode::rank` and `name`, `Binding::name`; `keeps_destroyed_keys` returns a `String`; the lone serde alias is gone |
| Q31 | The planner collects `Candidate`s in a `Ways`; the CLI's enum is `Destination`; the capability source is the `Known` enum, not a string |
| Q15, in part | `target_target` is `import_target` |
| Stale comments | `profile/src/lib.rs`, `core/src/migrate.rs`, `camigrate/src/tokens.rs` (the removed `migration` hook), `Cargo.toml` (two `unsafe` exemptions) |

Withdrawn: `profile/src/effective.rs` saying no and unknown exit 15 and 16 is correct
(`caprobe supports` does).

## Fixed since

| Item | Fix |
|---|---|
| B13 | `probe_unbound` writes no row for a key type the module generated without a binding, and says so in the probe's undetermined list (`crates/caprobe/src/probe.rs`). No committed profile changes; no test, since no reference module is purpose-bound |
| p11-fault counts | `find_objects` and `mechanism_list` believe the real module's count only up to the caller's room (`crates/p11-fault/src/hooks.rs`) |
| Transport keys | The one untested branch of `check_transport_keys`, a token naming a spec not realised on it, has a case in `crates/core/tests/refusals.rs` |

## To test

- **Key-file timing.** With the PKCS#12 MAC at 600,000 iterations, a debug build takes
  seconds per file (the three `file::tests` take 15 s together, with the KDF crate built
  optimised); a release build was not timed.
- **B11 on Cloud KMS.** `create` of a PSS key, a SHA-512 key and an OAEP decrypt key with their
  `pop-sign` and `pop-decrypt` bindings. The opt-in test (`crates/cli/tests/cloud.rs`) still
  creates its decrypt key `token-asserted`; `scripts/cloud/gcp/cakeys.toml` says which pair to
  switch. Its "refused before creating" case is now a `pop-unwrap` key, so no label is spent.
- **`create` and exit 19 in the Nix tests.** `nix/test.nix`, `nix/module-test.nix` and
  `nix/demo.sh` call `create` once per key, so they should be unaffected; not run.

## Bugs and behaviour

Still open.

- **B8. The PIV attestation chain is verified without a validity-period check.**
  `chain_to_anchor` (`crates/ykcs11/src/attest.rs:210`) checks signatures, the name links and
  `basicConstraints` with path length, never `notBefore`/`notAfter`. **Done 2026-11-17:**
  `check` holds every link (slot, device f9, pooled intermediates, pinned root) to its
  validity period against the system clock, never `SOURCE_DATE_EPOCH` (stdenv sets it to 1980);
  `--at <YYYY-MM-DDTHH:MM:SSZ>` judges the chain as of that time, and `--ignore-validity` skips
  the dates with a note (`cakeys_pkcs11::ChainTime`, set on the token `check` opens and passed
  to the provider in `AttestCtx`). `lock`, `create` and camigrate stay clock-free. The pinned
  roots and Yubico's intermediates run to 2052 and 9999, so real chains should rarely trip it.
  Tested on the fixture chain (`check_holds_the_chain_to_its_dates`) and through the CLI on a
  key without attestation; not run on the YubiKey.
- **`create` flags** (from B2). `create` now stops with 19 at the first key that exists. A flag
  such as `--only-new`, to skip those and create the rest, is parked in docs/OPEN.md.
  **Done 2026-11-17:** no flag. Every pair whose object the lock pins, named or not, is
  verified as `check` verifies it (`ops::verify`) instead of skipped unseen: one that matches
  is left alone with a note, one that does not fails with `check`'s code, one its token lost is
  14. A key the lock does not pin still stops the run with 19, naming `lock`. Exit 0 when
  nothing failed; stdout lists what was created, and `--dry-run` says `verify` for the pinned
  pairs. A run over every pair now opens each token that holds a pinned pair, logins included.
- **B18. The by-name curve fallback retries after any failure**
  (`crates/pkcs11/src/token/generate.rs:141`), not only a refusal of the parameters. Left:
  narrowing it needs the return value ykcs11 gives an Edwards OID, which the profile records as
  "by-name" without the code, and the hardware rules keep that from being measured here.
  **Done 2026-11-17:** profile-driven (`Token::retries_by_name`). Retry by name only when the
  token's module profile (the lock's recorded answers included) says `via = "by-name"` for the
  curve, or has no row for it; any other refusal is reported at once, with its own return
  value. `a_refused_curve_is_tried_by_name_only_where_the_profile_says_so` (fault shim,
  SoftHSM's edwards25519) sees one generation, where the old retry made two.

## Poor practices and hard-to-read code

Still open. Each says why it was not done with the rest.

### Need a decision

- **Q3. Control flow read out of error text**, in the probe: `contains("CKR_OPERATION_ACTIVE")`
  (`crates/caprobe/src/probe.rs`, twice), `contains("C_Login (SO)")`, `refused` and `evidence`
  cutting `CKR_*` and cryptoki's prose out of a formatted `KmError`, and the `create` note
  scanned for `CKA_PRIVATE = false`. Fixing it means `KmError` carries the return value and
  `Token::create` returns a typed note: a change to the public error type and to the
  `Provider::create` signature. **Done 2026-11-17:** `KmError` keeps its variants; their
  message is a `cakeys_core::Msg`, the same text plus an optional `CK_RV`
  (`KmError::rv`), which the token layer sets where a module call failed (`token::rv_of`: the
  shared `ck`, the proofs' `proof_failed`, generation, imports, commitments). The probe
  matches `CKR_OPERATION_ACTIVE` and names a refusal by that value, its operation outcomes
  carrying it too; `Token::create` returns a typed `CreateNote` (`public_made_private`,
  `by_name`) whose text is what it said before. Two fault cases pin the busy session by value
  (mutation-checked: each fails without its value). The SO-login check still reads cakeys'
  own message, now through one constant (`token::SO_LOGIN`): which login failed is no return
  value.
- **Q4. `rv_name` derives `CKR_*` names from cryptoki's `Debug` output**, which committed
  profiles pin. cryptoki 0.12 has no conversion from `RvError` back to its number, so the
  alternative is a hand-kept table of about ninety variants. **Done 2026-11-17:** p11-fault's
  compiler-checked `cryptoki-sys` table is its own crate, `crates/p11-names` (no cakeys
  dependency; p11-fault re-exports it as `names`). `token::rv_value` finds an `RvError`'s
  `CK_RV` by running the table's values through cryptoki's `Rv::from`, and `rv_name` names it
  from the table; every named value converts back and keeps the name the variant gave
  (`every_named_value_converts_back`), so no profile changes. The upstream PR (`RvError` to
  `CK_RV`, and `RvError::name`) is drafted, not filed: `upstream/rust-cryptoki/PR-RV-VALUE.md`.
- **Q24. The profile set is process-global and order-dependent** (`Set::activate` after
  `Set::active` fails; `Registry::named` hides a set that does not parse). **Done
  2026-11-17:** the `OnceLock` stays; `Set::active` errors when nothing activated it, never
  building the embedded set behind the caller's back; every tool activates through
  `cli-common::activate_profiles`, profile directories or not; `Set::activate_embedded` is the
  repeatable activation for tests (14 in-process tests now call it); `Registry::named` and
  `knows` return a `Result`, so a missing set is reported, never taken for "no such provider".
  `the_set_is_activated_before_it_is_asked_for` pins the order.
- **Q27. The profile emitter re-implements taplo's layout** (`crates/caprobe/src/emit.rs`), so
  generated profiles survive `nix fmt` byte for byte. **Accepted 2026-11-17:** the layout test
  and treefmt's check catch drift.
- **Q28. String-typed fields kept for forward compatibility**: `Capability`'s `binding` and
  `key_type`, `Answered::answer`, `Restrict::operation`, `BoundKey::kind`/`on`. **Done
  2026-11-17:** `cakeys_profile::names` has `KeyKind` (Montgomery included, which
  `core::KeyType` must not take), `Proof` and `Operation`, each with an `Other(String)` kept as
  read and compared, hashed and ordered by its name, so rows keep their order; `Capability`'s
  key types and proof, `Restrict`'s operation and key type and `BoundKey`'s kind use them, and
  `BoundKey::on` is an `On`. The lock's `Answered::answer` is core's `Said` (yes, no, or a word
  kept as read that answers nothing), written as the word. The profile crate stays independent
  of core: `the_profiles_know_every_key_type_and_proof_cakeys_has` (in pkcs11) holds the names
  together. `every_committed_profile_is_what_the_emitter_writes` now pins every committed
  module profile byte for byte, the hardware ones no test re-probes included.
- **Q20. Key type dispatch by trial parsing** (`spki_canonical`, `spki_of_pkcs8`,
  `ecdh_challenge`, `verify_with`). Dispatching on the OID changes which parser sees a
  malformed key, and with it some error texts and the `public_key` fuzz target's fixed point.
  **Done 2026-11-17:** `id::KeyAlg` (`of_spki`, `of_pkcs8`) reads the algorithm and curve OIDs
  (an Edwards key's algorithm OID is its curve's), and `spki_canonical`, `spki_of_pkcs8`,
  `ecdh_challenge`, `verify_with` and `sig::ecdsa`, the fifth of the kind, match on it. A
  malformed key is refused by its own type's parser, by name (`SPKI of a P-256 key: …`); an
  algorithm cakeys does not read is named by its OID; junk is "not a
  SubjectPublicKeyInfo". The `public_key` fuzz target's fixed point holds unchanged: only the
  error texts moved.

### Refactors left for a pass of their own

**Scheduled 2026-11-17, all seven:** Q18's rest (the public half's defaults in one place, the
probe's curves from `core::id`), Q15 (one hash type for ECDSA and RSA, such as `HashAlg`; fold
`OaepSha512` into `Oaep` only if the frozen transport names allow it), Q9 (one mechanism list,
the other views methods over it), Q13 (`resolve` in named steps), Q2 (a probe key-kind enum,
built with Q28's enums), Q26 (`Made` split, no `Deref` on `Draft`, `rsa_ops` sized to the key)
and Q14 (one opener for cakeys and camigrate).

- **Q2. Key types as strings in the probe** (31 `"CKK_*"` literals). Montgomery has no
  `KeyType`, so this needs a probe-local kind enum threaded through `operate`, `prove` and the
  generation rows; the conformance tests would catch a slip, but it is a rewrite of the
  probe's spine. **Done 2026-11-17**, with Q28's `cakeys_profile::KeyKind` rather than a
  probe-local enum: `operate`, `prove`, `prove_key`, `create_curves`, the generation rows
  (`Draft::generate`), the unbound probe and the import and export tables take it; the curve
  fixtures name core's `KeyType`, from which their kind follows. No `"CKK_*"` literal is left
  in the probe's code.
- **Q26. The probe's `Made`** (12 fields) and `Draft`'s `Deref` to `Profile`; `rsa_ops` signs a
  fixed 256-byte block whatever the key's size. **Done 2026-11-17:** the scratch objects are
  `Scratch` (target, handles, labels, the label counter; `label`, `track`, `destroy_all`,
  `leftovers`, `clear_stale`), and one `track` replaces eight hand-written handle-and-label
  pushes; `Made` keeps nine fields. The same handles reach the one `destroy_all`, in the same
  order. `Draft` has no `Deref`: the probes write through `Draft::set` and `Draft::note`, and
  name `profile.out` for the rest. The raw `CKM_RSA_X_509` block is the key's modulus size
  (`pop::rsa_modulus_len`): unchanged on the 2048-bit generated key, right on an existing
  larger one (Cloud KMS's). The SoftHSM, kryoptic and swtpm re-probes still give their
  committed profiles byte for byte [run].
- **Q13. `resolution::resolve` is 127 lines.** **Done 2026-11-17:** it is the steps by name —
  the binding layer, `add_forwarders`, `add_configured`, `hidden_module`, `module_profile` —
  and the module profile's notes are one method each (`nearest_version`, `hardware_unknown`,
  `weak_match`, `other_hardware`), each dropping the hardware rows where it says so. The
  notes' texts are unchanged.
- **Q14. CLI setup is still duplicated** between `cakeys` and `camigrate`: the `Run` struct, the
  load-and-guard prologue, `(cfg, modules, registry)` at each `open_token`. A shared opener
  collides with the `&mut self.lock` both hold across those calls. **Done 2026-11-17:**
  `cli_common::Opener` holds keys.toml, the `--module` overrides and the providers, loads
  them (`Opener::load`: overrides, config, profile activation) and opens tokens (`open`,
  `open_quiet`); `cli_common::read_lock` refuses an unwritable lock for a writing verb, takes
  the update guard and loads the lock, and `save_changed` saves it. Each `Run` is `{ opener,
  lock, lock_path }`: a verb borrows `&self.opener` beside `&mut self.lock`, disjoint fields,
  so the nine `(cfg, modules, registry)` destructurings are gone. caprobe, whose config is
  optional, keeps the free `open_token` the opener calls. camigrate now asks for the target's
  login before refusing an unwritable lock; both are refusals before any token is touched.
- **Q9. `Token` still keeps four views of the mechanism list.** **Done 2026-11-17:** it keeps
  two, what `C_GetMechanismList` listed and what the profiles leave usable, which differ by
  design; the sorted names of each are methods (`mechanism_names()`, `advertised()`), and
  `lists(m)` asks the listed one by type, as the probe now does instead of comparing names.
- **Q18, the rest.** The public half's defaults are written in `generate.rs` and `sealed.rs`;
  curve lists live in `core::id`, `profile::baseline` (independent by design) and the probe.
  **Done 2026-11-17:** the library writes the public half's defaults once
  (`templates::public_defaults`; generation and the sealed import share
  `with_public_default_dropped`); the probe's own templates still spell them, which §4(c)
  moves onto `Provider::template`. The probe generates on `Curve::ALL`, core's list, not the
  baseline's names filtered through `Curve::from_cfg`; the baseline keeps its own spellings,
  and `the_profiles_name_every_curve_cakeys_has` holds them to core's.
- **Q15. Naming**: `EcdsaHash` is also the RSA hash type (about forty uses);
  `RsaPadding::OaepSha512` sits beside `Oaep(OaepHash)` because `OaepHash` names frozen
  transport methods. **Done 2026-11-17, in part:** `EcdsaHash` is `HashAlg`. `OaepSha512`
  stays: folding it into `OaepHash` would give camigrate's transport-method parser
  (`tokens::oaep_hash`, the bundle's frozen `rsa-oaep-sha1`/`-sha256` names) and the probe's
  wrap loop a hash no transport uses, each to be refused by hand.

## Unsafe code and other tools

Every unsafe site is in `p11-fault` (four files, about 80 sites) plus `loaded_path` in
`crates/pkcs11/src/token/mod.rs` [run]. All four p11-fault files with unsafe code were read;
nothing a client can trigger was found. Each pointer read is guarded by a null check and a
length check against the structure's size, and panics stop at `guard`. The one soundness gap,
`find_objects` and `mechanism_list` trusting the count the real module writes back, is closed
("Fixed since").

RAPx would cover only that crate and needs a pinned nightly: not run. An ASan build of the fuzz
targets (`checks.fuzz` runs without a sanitizer today) covers the same ground more cheaply.
cargo-machete found the unused dependencies (B7).

## What held up

Worth saying, since the list above is long: the identity core (`reconcile.rs`, `identity.rs`,
`possession.rs`), the TPM attestation path and the PIV chain verifier check what they claim to,
with host-side verification throughout and no stored proof. Errors carry stable exit codes,
`unsafe` is confined, CI pins every action by commit with read-only permissions, and no
production `unwrap` on external input was found outside kmsp11's embedded table (Q22).
