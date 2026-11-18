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
| | §4 (c): the probe calls the verbs' operations | Partly: proofs and EC/RSA generation go through `Token::prove_binding` and `Token::create`. `bound_keys`, `scratch_occupant`, `stand_ins` remain, and Montgomery, secret-key and wrap probes keep their own templates (about 24 template sites, two `Provider::template` calls, on 2026-11-17). Scheduled 2026-11-17: all of them onto `Provider::template`, then the profiles regenerated. **Done 2026-11-17** for every template made from cakeys' own: the scratch AES and generic secret keys and the AES-wrap KEK ask it as `Template::Generate` (`secret_template`), beside the generations, imports, public objects and composed moves that already did; `tests/template_hook.rs` runs the probe in-process (`caprobe::main_from`) with a provider that refuses secret-key templates, and fails when the probe bypasses the hook [run]. Left raw on purpose: Montgomery pairs (core has no Montgomery key type to declare them by; they follow when it does), the `unwrap.refuse` measurement (the hook's `Import` filter is that measurement's output), `bound_keys` (the provider's own templates) and the unbound probe (bare by design). No shipped provider overrides the hook and the attributes sent are unchanged, so the profiles regenerate unchanged: the SoftHSM, kryoptic and swtpm re-probes give their committed profiles byte for byte [run]; ykcs11 and the AMD fTPM were not re-probed, as nothing they are sent changed |
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
| B16 | EC and Edwards scalars and the ECDH shared secret are wiped (`core/src/plaintext.rs`, `core/src/pop.rs`). The `--userpin=` argument is left: it is on `tpm2_ptool`'s command line either way. **Corrected:** this row also claimed the unwrap secret, which stayed a plain array, and missed the RSA CRT coefficient's owned copy; both are wiped since (see "Fixed since") |
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

From the file-by-file review (`review/`, 2026-11-18). Each fix has a test that fails without it
(checked by putting the old code back), except where the row says otherwise.

| Item | Fix |
|---|---|
| `tpm2_ptool --id` | `tpm2_ptool` stores the `--id` text as the ID's bytes; cakeys passed its hex, so a key meant for `CKA_ID` `0a` landed under `30 61` and nothing found it. The locator's ID is now passed as the text its bytes spell, and an ID that is not UTF-8 text (or holds a NUL) is refused (17) before the tool runs (`tpm2-pkcs11/src/ptool.rs`). Tests: `the_id_is_passed_as_the_text_its_bytes_spell`, camigrate `tpm2_ptool_imports_under_the_locator_id`. Left: camigrate's dry run does not refuse such an ID; the real run does |
| Attestation of an import | An import asking for an attestation the provider gives only for keys the device generated (PIV) is refused (15) before the write, by `ops::check_import` on every camigrate import path, and by the plan through the same predicate (`AttestationCap::imported`). Tests: camigrate `an_import_the_provider_cannot_attest_is_refused_before_the_write` |
| Landing checks per spec | camigrate's plan made its landing checks on the pair `--spec` picks: an object with two import pairs on the target skipped them all (`camigrate/src/lib.rs`). Test: `landing_checks_follow_the_spec_named` |
| Retargeted spec | A spec pointed at another object is judged as that object: `compare` no longer applies the old object's no-downgrade rule, nor `record` its object diff (`core/src/reconcile.rs`). Test: `a_retargeted_spec_is_judged_as_its_new_object`; the Quint model's "left out" list says so |
| `gc --apply` | Drops the realisations whose recorded object it drops (an object renamed in keys.toml), so the lock it writes loads; `save_lock` refuses (17) a lock that would not load and keeps the old file (`core/src/config.rs`). Test: `gc_and_save_leave_a_lock_that_loads` |
| Module hashes | `check_observations` checks every observation's module hash, not the first one found (`core/src/config.rs`). Test: a two-observation case in `locks_that_contradict_themselves_are_invalid` |
| Certificate policy | A certificate's declared attributes (`CKA_TRUSTED`, `CKA_PRIVATE`, …) are checked against the token, as a key's are (`pkcs11/src/token/policy.rs`). Test: `a_certificates_declared_attributes_are_checked` |
| `create` without login | On a private or secret key, a session without login is `Unavailable` (16, "configure pinFile or pinEnv") before D1, which said the pinned key was gone (14) (`pkcs11/src/ops.rs`). Test: `create_without_login_asks_for_a_pin` |
| Profile verdicts | A key type asked about without a curve or size is no when every row of it says no (`caprobe supports CKK_EC_EDWARDS --profile tpm2-pkcs11/1.10+swtpm` said yes), and a size between two that generated is unknown when a refused size lies between them (`profile/src/effective.rs`). Tests: `refused_rows_never_add_up_to_yes`, cases in `supports_answers_from_the_embedded_profiles`. `crates/profile/tests/answers.txt`, regenerated, had pinned the wrong answer: `CKK_EC_EDWARDS` and `CKK_EC_MONTGOMERY` yes on every profile whose rows all say no (swtpm, AMD fTPM, Cloud KMS HSM, CloudHSM FIPS; Montgomery on SoftHSM and ykcs11 too) |
| caprobe's profile set | `supports` and `probe --diff` read keys.toml's `profileDirs`, and `supports --token` stacks the token's configured `profiles` layers, as token resolution does (`caprobe/src/lib.rs`, `supports.rs`); `docs/CAPROBE.md` says so. Test: cases in `supports_asks_by_token_and_refuses_what_it_cannot_ask`; `probe --diff` shares the set, untested. Left: `supports --token` still does not consult the lock's recorded module and answers (caprobe never reads keys.lock; `gate::stack`, which `cakeys validate` uses, does), nor does it detect layers from `C_GetInfo` as an opened token does |
| kmsp11 `HMAC_SHA256` | Its table row lists `CKM_SHA256_HMAC`, so a spec declaring it finds the algorithm (`kmsp11/src/keys.json`). Test: `every_mac_row_serves_its_hmac` |
| B16, rest | The unwrap proof's secret and the RSA CRT coefficient's owned copy are wiped (`core/src/pop.rs`, `plaintext.rs`). No test: a wipe is not observable from a test |
| EFI stub | `checks.examples` takes systemd's stub for the host's EFI architecture, not `linuxx64` alone (`nix/examples.nix`). Not run on aarch64 |
| TPM attestation material | The SPKI, `CKA_LOCAL` and `CKA_EXTRACTABLE` a `TPM2_Certify` attests are read from the store blob whose Name the TPM signed, no longer from `TPM2_ReadPublic`'s public area, which nothing authenticates (password sessions, no response HMAC); a ReadPublic answer that is not that blob's public area is refused (13). An interposer on the TCTI could otherwise pass the attestation of one key for another's material (`tpm2-pkcs11/src/attest/esys.rs`, split into `verify_certified`). Test: `the_material_is_the_attested_blobs_not_read_publics`, a host-signed `TPMS_ATTEST` with a swapped ReadPublic. Left: the transport is still unauthenticated (an HMAC or salted session, with the EK → AK work) |
| Bundle files under `token-asserted` | `import --in` refuses (14), before the target is touched, an EC or Edwards private key whose target binding is `token-asserted`: the transport key is public, so anyone can seal a key of their own beside the lock's IDs and `publicKey`, and on a target that keeps no point with an unwrapped EC key (SoftHSM) the identity came from the public half the import made from that same `publicKey` (`camigrate/src/sealed.rs` `check_carried`). RSA keys carry their modulus; `migrate`, whose bundle never leaves the process, still moves such a key. docs/CAMIGRATE.md D5 and the bundle.rs header no longer claim the wrap authenticates the origin. Test: `a_bundle_files_unproven_ec_key_is_refused` (an honest bundle: the old code imported it; a forged one would need SoftHSM as the target) |
| Transport file read once | `--transport <file>` is read and parsed once (`Destination::transport`): the plan checks against the lock the very key the export seals to, and the export checks it again (`tokens::pinned`) before it wraps. A file changed between the plan's read and the export's was sealed to unchecked (camigrate lib.rs F3). Test: `the_transport_file_is_read_once`, a FIFO whose second read names another object |
| PEM gate | `holds_private_key` reads the same scan the reader decodes by (`pem_blocks`, `der_kind`): a `-----BEGIN PRIVATE KEY-----` after text on its line was decoded without `--allow-host-plaintext` (keyfile.rs F1). A PEM file the scan cannot split is taken to hold a key. Test: `the_gate_sees_every_key_the_reader_decodes`, every fixture mangled five ways (text before BEGIN, indented, CRLF, behind a certificate, unterminated): whatever the reader decodes a key from, the gate sees |
| Reopen after `tpm2_ptool` | A failed reopen after `tpm2_ptool import` says the key is in the TPM, unrecorded, and how to record (`cakeys lock`) or remove it (camigrate host.rs F1). Test: `a_failed_reopen_after_ptool_says_what_is_in_the_tpm`, tpm2-pkcs11 behind p11-fault answering the reopen's `C_Login` (the TPM sees nothing); `cakeys lock` then records it |
| Late creation errors | `create` removes what is under the (empty before) locator when `Token::create` fails, not only when the identity fails: a module erring after it made the key left it unrecorded (ops.rs F2). Test: `a_creation_that_fails_after_the_write_is_undone` (`C_GenerateKeyPair` `when = "after"`) |
| `as_so` | The step's result comes first: a step done with a failed SO logout or user re-login is an error saying it was done; a failed step keeps its own error (token/mod.rs F2). Tests: `the_so_step_is_reported_before_the_session_trouble` (`so_outcome`), camigrate `an_so_step_that_was_done_is_said_to_be_done` (the SO's `C_Logout` failed after `transport --trusted`) |
| caprobe lost pair | A pair the module reported made but not under its locator is no `cannot` row: a note, and its label is tracked for the cleanup (caprobe probe.rs F3, `Created::Lost`). Test: `a_pair_made_but_not_found_is_no_refusal` (`hide_label` on the first probe pair) |
| Public half's defaults | A key pair's public half takes `CKA_PRIVATE = false` and `CKA_VERIFY = true` unless its own `publicAttributes` declare them (`templates::public_declares`, used by the templates, `generate` and camigrate's `create_public_half`): a private key declared `CKA_PRIVATE = true` made its public half the module's default, private on SoftHSM's `C_CreateObject` (templates.rs F1). Test: `the_public_half_takes_its_defaults_from_its_own_declarations` |
| RSA identity of any size | An RSA key's identity no longer needs a key the `rsa` crate computes with (1024–8192 bits, e ≤ 2^33−1): `id::rsa_of_spki` and `rsa_spki` refuse only what is no RSA key (even modulus, even or < 3 exponent, e ≥ n); a legacy RSA-768 key was a conflict (13) (core id.rs F1). The public half's material and keyfile's type check read it the same way. A proof of possession, which verifies, refuses such a key on policy (15), naming its size. Tests: `rsa_keys_of_any_size_have_an_identity` (sizes 512–16384, e = 2^35+1; the same bytes as before where `rsa` takes the key), `a_legacy_rsa_key_has_an_identity` (SoftHSM: adopt, lock both ways, verify) |
| ykcs11 match | ykcs11 matches `C_GetInfo`'s description ("PKCS#11 PIV Library") beside the manufacturer: `yubihsm_pkcs11` reports the same "Yubico (<https://www.yubico.com>)" \[run, both libraries' strings\] and was auto-detected as a PIV token (ykcs11 lib.rs F1). Test: `only_the_piv_module_is_ykcs11` |
| One library per file | The library cache keys a module by the file the loader mapped, after loading: a bare name and a path to the same file shared no context, and the second `C_Initialize` was refused (token/mod.rs F3). Test: `a_bare_name_and_a_path_share_one_library` (re-runs itself with `LD_LIBRARY_PATH`) |
| Profile emitter | `[subtract]` with only a note, and a `public-accepts` row's `min-bits`/`max-bits`, are emitted (caprobe emit.rs F1). Test: `every_optional_field_alone_round_trips`, each optional field the parser reads set alone through the fuzz target's round trip |
| p11-fault plan mistakes | `use_label` naming nothing fails the call (`CKR_GENERAL_ERROR`, "p11-fault: use_label: …") instead of running the caller's key under a rule traced as fired (hooks.rs F1); slot and token flags are two tables, each function taking its own (plan.rs F1: `CKF_HW_SLOT` on `C_GetTokenInfo` set `CKF_LOGIN_REQUIRED`). Tests: `a_substitution_of_nothing_is_the_plans_mistake`, `slot_and_token_flags_are_apart`, the plan refusals |
| Test runs scrubbed | No test run sees the developer's keys.toml or lock: nix/test-tokens.sh unsets `CAKEYS_CONFIG`/`CAKEYS_LOCK`, and every tool run goes through `common::tool`, which removes them (common/mod.rs F1). Test: `no_test_run_sees_a_real_keys_toml_or_lock` |
| swtpm guard | `on_swtpm()` needs the harness's `CAKEYS_TPM_SWTPM=1` and swtpm's vendor strings; the attestation test and its persistent handles run only there, and a marker on another TPM fails (tpm2.rs F1, F3) |
| Dry-run twin | compares the token of a shared reference (`kryoptic-der`) too (xref.rs F1). Test: `the_dry_run_twin_compares_every_token_a_move_names` |
| `YubiKey` PIN tries | one `YubiKey` test at a time across processes, and a `CKR_PIN_*` latches every later one off (yubikey.rs F1); login failures name their `CKR_*` so the latch can read them. Tests: `a_failing_module_call_is_unavailable`, `a_failed_yubikey_login_stops_every_later_one` |
| Lock-wait test | an updater says it waits for `<lock>.lck` before blocking; the test waits for that line, not 500 ms (lockfile.rs F1) |
| B8 through the CLI | `check --at` and `--ignore-validity` tested on ykcs11's fixture chain (check.rs F1), in `piv_attestations_are_found_by_slot_and_chain_to_yubico` |
| Opted-in suites | an opted-in hardware suite on an unpatched build fails instead of passing with nothing compared: ftpm and caprobe's `YubiKey` probes (ftpm.rs F1). Test: `no_opted_in_suite_skips_an_unpatched_build` |
| Host-move matrix | every row runs: the dry run's exit is its plan's, blocked rows are 15 with nothing changed, and `host-pkcs8` has a floor (dry_run.rs F1) |
| What loads is usable | keys.toml's load refuses a locator with neither field or a non-hex `CKA_ID`, an AES `valueLen` other than 16/24/32, a secret key's 0, and a spec on an undefined token, and plans every (spec, token) pair; `CKA_ID` is stored lower case in keys.toml and the lock (review D1, config.rs F3). Every shipped keys.toml still loads. Test: `what_loads_is_usable` |
| Symlinked lock | the `.lck` guard, the write and the writability check go to the file the lock path resolves to: a symlinked lock is written through, never replaced by a copy, and its two names share one guard (review D2, config.rs F7). Tests: `a_symlinked_lock_is_written_through`, `update_lock_waits_for_the_sidecar_lock` |
| Documented exit codes | `read_lock`'s doc said 18 for the 14 it returns (cli-common lib.rs F1); every `` `Variant` (NN) `` in the sources is now held to `KmError::exit_code`. Test: `documented_exit_codes_are_the_ones_returned`. An unwritable lock's 14 is listed in CAKEYS.md; whether it gets a code of its own is open |
| Lock saved per object | `cakeys create` (`ops::create_selected`'s `persist`) and every camigrate import loop (`import`, `migrate`, `import --in` for a key file or files) save the lock as each object lands, so a run killed, or failing to save, part-way never leaves an object on a token the lock does not record. `create` prints what it created whatever ended the run (cli lib.rs F1). p11-fault gained `abort = true` (the process dies at a call) to test it. Tests: cakeys `a_create_killed_part_way_has_recorded_what_it_made`, camigrate `an_import_killed_part_way_has_recorded_what_it_made`, p11-fault `abort_ends_the_process_at_its_call`. Left: a key killed between its creation and its own record is still unrecorded (one object, not the run); a failed save after `create` has no test (nothing makes the save fail after `read_lock`'s check) |

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
  token's module profile says `via = "by-name"` for the curve, or has no row for it; any other
  refusal is reported at once, with its own return value.
  `a_refused_curve_is_tried_by_name_only_where_the_profile_says_so` (fault shim, SoftHSM's
  edwards25519) sees one generation, where the old retry made two. **Corrected 2026-11-18:**
  this said "the lock's recorded answers included"; they are not. `Token::open` never applies
  them (`Resolved::with_answers` serves the static gate and camigrate's plan), and it should
  not as things stand: a by-name generation is recorded as a plain `yes`, without the `via`,
  so a recorded answer over the profile's `via = "by-name"` row would stop the retry, and a
  YubiKey's second Ed25519 key would fail. Left: `ops::answers` should record `via = "by-name"` from
  the `CreateNote`, the precondition for ever applying recorded answers at open.

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
  **Since 2026-11-17** the build applies that draft itself (`nix/package-common.nix`), and
  `rv_value`/`rv_name` use it behind `cakeys-pkcs11/rv-value`; the table is p11-fault's alone,
  and `names_agree` holds cryptoki's names to the ones derived without the patch.
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
