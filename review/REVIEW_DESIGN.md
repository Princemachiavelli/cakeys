# Design review: cross-cutting findings

Collected from the per-file reviews (the `## Design` sections) and from the reviewing agents'
reports, then grouped by theme. Each item names the per-file review that holds the evidence;
those files carry the `file:line` refs and the verification verdicts. Ordered by how much each
theme affects correctness.

Weight: an item that rests on a bug or risk finding (`F<n>` in a linked file) carries a
verification verdict. The rest are observations from the reviewers' design notes, not re-read
by a second pass: among them the `.lck` guard keyed on the typed path, `held_spki` swallowing
read errors, the SPKI computed up to four times, `create` skipping chain dates, Q28's partial
forward compatibility, and the overloaded exit 14.

## D1. Rules that guard irreversible writes live in planners, not at the write site

The clearest pattern in this review. A safety check sits in a planner or a dry-run step, and
some path that writes to a token never runs it.

- camigrate refuses `attestation = true` for an imported key only in the dry-run planner
  (`landing_checks`). The planner ignores `--spec` and returns early, and the key-file imports
  (`import_file`, `from_its_file`) never plan at all. On a YubiKey the key is written, the
  attestation fails, and ykcs11 cannot delete it. ([camigrate lib.rs](REVIEW_crates_camigrate_src_lib.rs.md))
- docs/FILE.md promises a load-time rule for this. No such rule exists in `core::config`,
  `core::plan`, `gate.rs` or `ops.rs`.
- Validation is split three ways: `core::config` (load), `core::plan` (static, exit 17) and the
  token layer. Several things load cleanly and are then refused at every use: an empty or
  non-hex locator `CKA_ID` (whose case is also not normalised), an invalid AES `valueLen`, the
  `plan_mode` checks, a spec naming an undefined token. ([core config.rs](REVIEW_crates_core_src_config.rs.md))
- `Token::check` returns early for certificates before `check_policy`, so a certificate's
  declared policy attributes are validated statically and never compared with the token.
  ([pkcs11 policy.rs](REVIEW_crates_pkcs11_src_token_policy.rs.md))

**Recommendation.** Put each rule that protects an irreversible write in the function that
performs the write (`host::create_and_record` for imports, `ops::create_absent` for
generation), and have the planner call that same predicate for its dry run. Move every rule that
needs only keys.toml into `core::config`'s load, so "loads" means "usable".

**Fixed (2026-11-18):** the attestation refusal sits before the write for every import, and a
certificate's declared policy is compared (dc3f102). Load now checks locators, AES lengths and
undefined tokens, and plans every (spec, token) pair (`plan_mode`), so a spec that loads is one
every verb can use. Tests: `what_loads_is_usable` and the ISSUES.md "Fixed since" rows.

## D2. The lock: durability, validation on save, and what "previous" means

- `save_lock` never validates; only `load_lock` does. `gc --apply` can drop an object a kept
  realisation still names, and the saved lock then fails to load for every verb, including the
  `lock` run that would repair it. Validating before the atomic rename would turn this bug, and
  any future one like it, into a refused write that keeps the old lock.
  ([core config.rs](REVIEW_crates_core_src_config.rs.md))
- `reconcile::compare` and `reconcile::record` disagree about the previous realisation:
  `record` means "this object", `compare` means "this (spec, token) slot". After a spec is
  pointed at a new object, `lock` refuses it with downgrade or replacement errors that tell the
  user to rename what they already renamed. DESIGN.md should state which one downgrades are
  judged against, and both functions should follow it.
  ([core reconcile.rs](REVIEW_crates_core_src_reconcile.rs.md))
- The lock is saved once, at the end of a run, in both `cakeys create` and camigrate. A crash
  or a failed later step after a token write leaves objects the lock does not record. On a
  YubiKey those objects cannot be removed. The write is already atomic, so saving after each
  object is cheap. ([camigrate lib.rs](REVIEW_crates_camigrate_src_lib.rs.md),
  [cli lib.rs](REVIEW_crates_cli_src_lib.rs.md)) **Fixed (2026-11-18):** both save after each
  object; tested by killing the run part-way (p11-fault `abort`).
- The update guard (`.lck`) is held across every token operation of a long `create`, and it is
  keyed on the path as typed, so a symlinked lock gets a second guard.
- Exit 14 is overloaded for an unwritable lock, and `cli_common::read_lock`'s doc says 18.
  ([cli-common lib.rs](REVIEW_crates_cli-common_src_lib.rs.md))

**Fixed (2026-11-18):** `save_lock` validates before the rename, and `reconcile` judges a
retargeted spec against its new object (dc3f102). The guard, the write and the writability
check go to the file a lock path resolves to, so a symlinked lock is one guarded file, written
through. A run that waits for the guard says so first. `read_lock`'s doc says 14, and a test
holds every documented exit code to `KmError::exit_code`. The guard still spans a whole
`create`: that span is what keeps the run's read-modify-write whole. **Decided
(2026-11-18):** an unwritable lock is `LockUnwritable` (21), both refused up front and a save
that fails part-way (it was `Io`, 1, though the token may then hold what the lock does not
record). `the_exit_code_table_lists_every_code` holds CAKEYS.md's table to every code.

## D3. Build features change run-time behaviour, unchecked

The `CK_RV` value now drives control flow (the probe's busy-session handling, `rv_is`), not only
messages. It exists only with `cakeys-pkcs11/rv-value`, a feature of the patched cryptoki.
Without it `rv_value` returns `None` for every standard error, the busy-session branches go
dead, and a probe would write busy failures into a profile as definitive "no" rows. The probe
checks `binding::patched()` at run time but not `rv-value` or `kwp`, and every Nix builder names
the features by hand. The crane `minimal` build already leaves `rv-value` out; today that build
only compiles, so no wrong output reaches a profile.
([pkcs11 token/mod.rs](REVIEW_crates_pkcs11_src_token_mod.rs.md),
[caprobe probe.rs](REVIEW_crates_caprobe_src_probe.rs.md),
[nix package-crane.nix](REVIEW_nix_package-crane.nix.md))

**Recommendation.** One umbrella feature per tool (`patched-cryptoki`) that implies all three.
Have `caprobe probe` refuse to write a profile unless all of them are on, or make the code
that branches on `CK_RV` require the feature at compile time.

**Fixed (2026-11-18):** each tool has one `patched-cryptoki` feature implying `kwp`, `rv-value`
and `sign-after-init`, which the Nix builds (package-common.nix `features`, the crane `minimal`
build) name instead of the parts. `caprobe probe` refuses to write or diff a profile unless the
binding is patched and both `rv-value` and `kwp` are on (`build_lacks`), and the tests of
`cakeys-pkcs11` and caprobe fail when the patched binding is linked without them. Tests:
`a_kept_profile_needs_every_patch_and_feature`, `the_patched_binding_comes_with_its_features`.

## D4. "Unknown, never a guess" (DESIGN D5) has two holes in the profile algebra

`profile::effective` answers yes from missing data in two places. A key type whose every probed
row says no still answers yes when no curve or size is asked; for example, `supports
CKK_EC_EDWARDS` on the swtpm profile says yes. RSA sizes interpolated between two that worked
ignore a size refused between them (2560 bits on swtpm, where 1536 was refused). Both were
reproduced with `caprobe supports` against the committed swtpm profile [run].
([profile effective.rs](REVIEW_crates_profile_src_effective.rs.md))

Q28's forward compatibility is partial. `prove.*` rows, OAEP hashes and unwrap-template keys
accept only known names, so a profile from a newer cakeys fails to load as a whole, and
`Proof::Other` can never come from profile data. ([profile lib.rs](REVIEW_crates_profile_src_lib.rs.md))

caprobe keeps two profile sets per run and a reduced copy of token resolution, instead of the
one active set and `gate::stack` the verbs use. As a result, `supports` and `probe --diff`
ignore keys.toml's `profileDirs`, and `supports --token` ignores the token's configured layers.
Both can disagree with `cakeys validate`. ([caprobe lib.rs](REVIEW_crates_caprobe_src_lib.rs.md),
[caprobe supports.rs](REVIEW_crates_caprobe_src_supports.rs.md))

**Fixed (2026-11-18):** the two verdict holes and caprobe's `profileDirs` and layers in dc3f102
(profile verdicts; `supports_answers_from_the_embedded_profiles`,
`supports_asks_by_token_and_refuses_what_it_cannot_ask`). Q28: a newer cakeys's proof, OAEP hash
or template attribute loads as read and answers nothing (`a_newer_cakeys_names_load_and_answer_nothing`,
the round trip over `Proof::NAMES`). caprobe activates the one profile set (`--profiles` loaded over it) and
`supports --token` resolves through `gate::stack`: its own composition took a hardware profile
whole where `validate` drops the hardware's rows (`supports_asks_by_token_and_refuses_what_it_cannot_ask`).

## D5. Attestation trust boundaries

- **TPM.** The attestation's integrity rests on the TPM connection itself: there is no
  authenticated session, and the Attestation Key is trusted on first use. The SPKI and the
  `CKA_LOCAL`/`CKA_EXTRACTABLE` checks read the public area from `TPM2_ReadPublic`. The Name the
  host recomputes and compares against the signed `TPMS_ATTEST` comes from the store blob, so
  the material checked and the material attested can differ. Taking the material from the
  store's public blob, whose Name is checked, closes that. A session salted to the AK would
  close the transport. (Corrected 2026-11-18: it cannot be the AK. `TPM2_StartAuthSession`
  encrypts the salt to a decrypt key, and the AK is a restricted signing key; see below.)
  ([tpm2 attest/esys.rs](REVIEW_crates_tpm2-pkcs11_src_attest_esys.rs.md))
- **PIV.** The chain checks held up (pathLen, CA flags, slot-to-device signature, SPKI
  cross-check, dates). The dates are only checked where the caller sets `Token::chain_time`;
  the default is unchecked, and `create`'s "verify as `check` does" skips them.
  ([pkcs11 token/mod.rs](REVIEW_crates_pkcs11_src_token_mod.rs.md))
- **Clock.** Checking dates against the system clock meets a NixOS check unit that is not
  ordered after `time-sync.target` and, with `RemainAfterExit`, is never re-run on a service
  restart. ([nix module.nix](REVIEW_nix_module.nix.md))
- **Bundles.** A bundle's integrity rests on the target's proof of possession, not on the wrap.
  Under `token-asserted`, on a target that exposes no public point for an unwrapped EC key, a
  swapped private key goes undetected. CAMIGRATE.md D5 ("a tampered or swapped blob fails
  either way") overstates this. Sealed import and `token-asserted` should be refused together.
  ([camigrate sealed.rs](REVIEW_crates_camigrate_src_sealed.rs.md))

**Fixed (2026-11-18):**

- TPM: in dc3f102, the material is read from the store blob whose Name the signed `TPMS_ATTEST`
  carries (`verify_certified`). Left, corrected 2026-11-18: the AK is trusted on first use. Once
  the lock pins it, a forged `TPM2_Certify` fails its signature, and the material is read from
  signed data, so what remains is first use itself and the unsealed token key crossing the
  transport in the clear. A salted session needs a decrypt key (the EK or the SRK, not the AK),
  and its key read over the same transport is only as trusted as first use. What closes first
  use is EK→AK credential activation with the EK certificate checked to the manufacturer. swtpm
  issues EK certificates, so the tests need no hardware. This machine's fTPM already holds
  cakeys' AK (0x81000016). Running the flow there needs the endorsement auth known to be empty,
  or it would send a wrong auth, which the hardware rules forbid. That is the user's call.
- PIV: `Token::open` takes the `ChainTime` and it has no default, so every open names whether
  the dates are checked; the verbs that record pass `Unchecked`, as B8 decided (a lock recorded
  today verifies tomorrow). Decided (2026-11-18): the verbs that record judge
  the dates by the clock too and warn (`ChainTime::Warn`); `check` enforces
  (`a_chain_out_of_its_dates_warns_where_check_refuses`).
- Clock: the check unit is ordered after `time-sync.target` and runs again on every start of a
  unit it gates (`checks.module`, restart without a hand stop).
- Bundles: in dc3f102, `import --in` refuses an EC or Edwards key under `token-asserted`
  (`dry_run.rs`, sealed.rs F1), and CAMIGRATE.md D5 says what the bundle proves. RSA and secret
  keys take their identity from the target's own material (modulus, check value), so a swapped
  one fails against the lock.

## D6. Identity computation carries usage policy

Identity is a hash of public bytes, but it is computed through RustCrypto parsers that also
enforce usage policy. `rsa` refuses moduli under 1024 or over 8192 bits and large exponents,
so a legacy RSA-768 key gets no identity and is reported as a conflict (13, which reads as
tampering). Point validity belongs in identity; size policy belongs in the gate, with its own
code. `id::spki_curve` is also a second OID dispatcher beside `KeyAlg::of` (Q20 missed it) and
accepts encodings the other refuses. ([core id.rs](REVIEW_crates_core_src_id.rs.md))

**Fixed (2026-11-18):** the size half was F1 (dc3f102). `spki_curve` is now `KeyAlg::of_spki`
mapped: every caller passes a canonical SPKI (`spki_canonical`'s output, a canonicalized key
file), which never holds the forms only the second dispatcher read, and `spki_canonical`
refuses them already. `spki_curve_reads_what_canonical_spkis_hold` pins each disputed encoding
as refused by both.

## D7. Secrets and cleanup: owners, not end-of-run passes

- `SessionObject` (Q5, Q6) gives the verbs drop-based cleanup. The probe's `Scratch` is still
  one `destroy_all` at the end, which any `?` in `write_probes` or in `moves.rs` skips (the
  next run's `clear_stale` sweeps them, so this is practice), and `Made::create` loses track
  of a key pair it made when one half is missing (risk). **Fixed (2026-11-18):** `Made::create`
  tracks the label once `create` succeeds (dc3f102); `write_probes` destroys what the run made
  on either arm, after an error by handle and then by label (`destroy_after_failure`) —
  `a_probe_an_error_ends_destroys_what_it_made`. A crash is still the next run's.
- The same "error after a write loses the write" shape appears in four places: `as_so`
  (below), `create_absent`'s `tok.create(..)?` skipping cleanup (`ops.rs:610`), camigrate's
  `reopen(..)?` after `tpm2_ptool import` (`host.rs:172`), and the probe's `Made::create`.
  Each needs the write recorded or undone before the later error returns. **Fixed
  (2026-11-18):** `create_absent` undoes a failed creation (`undo_created`), camigrate says what
  `tpm2_ptool` left and how to record or remove it, `as_so` reports a done step as done
  (`so_outcome`), and the probe as above.
- Zeroization (B16) is incomplete: the `pop-unwrap` secret is a plain `[u8; 32]`, and the RSA
  CRT coefficient is dropped unwiped. ([core pop.rs](REVIEW_crates_core_src_pop.rs.md),
  [core plaintext.rs](REVIEW_crates_core_src_plaintext.rs.md)) **Fixed (dc3f102):** both are
  `Zeroizing`.
- `as_so` drops a step's successful result when the SO logout or user re-login fails. If the
  step generated a key, it is neither cleaned up nor recorded.
  ([pkcs11 token/mod.rs](REVIEW_crates_pkcs11_src_token_mod.rs.md)) **Fixed:** F2 there.
- `held_spki` swallows read errors, so a transient module failure is reported as a conflict.
  **Fixed (2026-11-18), wider than found:** every optional attribute read (`held_spki`,
  `policy()`, `immutables()`, `CKA_PUBLIC_KEY_INFO`, `CKA_ALLOWED_MECHANISMS`, the key type a
  provider repairs a flag by) goes through `if_readable`: a refusal of the attribute is still
  "absent", but a failed device, token or session is 16. Failing each `C_GetAttributeValue` of
  `verify`, `check` and `lock` in turn found 13s (a public key object read as "no key material")
  and 14s (a policy flag left out, read as "changed since it was realised", and recorded so by
  `lock`) — `a_failed_attribute_read_is_never_an_answer`.

## D8. Module and crate boundaries

- `core/src/config.rs` (2,615 lines) holds five concerns: keys.toml rules, lock invariants,
  the observation model, file I/O and locking, and `gc`/address selection. `pkcs11/src/ops.rs`
  mixes the verbs, the capability and template checks, and the create planner. **Fixed
  (2026-11-18), pure moves:** `config/` (`mod.rs` keys.toml and its rules, `lock.rs`, `observe.rs`,
  `io.rs`), `ops/` (`mod.rs` the verbs, `capabilities.rs`, `planner.rs`), and camigrate's
  `file_verbs.rs`; every public path is re-exported where it was. `checks.doc-references` now
  holds Rust source paths the docs cite, which a split leaves behind.
- The provider crates' public surface is wider than the `Provider` trait (`pub mod attest`,
  `esys`, `store`, `fuzzing`; `pub` helpers on `Ykcs11`). Fuzzing entry points, and in ykcs11 a
  test root, are built into production; put them behind a feature. **Fixed (2026-11-18):**
  every `mod fuzzing` is `#[cfg(any(test, feature = "fuzzing", kani))]`, only fuzz/ turns the
  feature on (`fuzzing_surface.rs` holds both), tpm2-pkcs11's `attest` is private (its fuzzing
  entry points re-exported from the crate's own `fuzzing`), and `Ykcs11`'s helpers are private.
  The linker had dropped the fixture root from the binary already; the API is what changed.
- `provider.rs` still lists `aws-cloudhsm` as a data provider. **Fixed (2026-11-18).**
- Q14's remaining duplication: the transport-key rule is written three times (camigrate
  `tokens.rs` twice, core config) (**fixed 2026-11-18** for camigrate's two readers of the lock:
  `transport_fault`; keys.toml's check holds declarations, a rule of its own), the passphrase readers duplicate `read_secret` with
  different semantics (**fixed 2026-11-18:** `cakeys_core::secret::read` for both; a decision:
  the file's one line, a second refused (17), unset or unreadable 16, where a passphrase was the
  first line and exited 1 or 17), and the per-object loop is copied across three verbs (**fixed
  2026-11-18:** `Tally`; `migrate` goes on past a failure, as `import` does). camigrate's
  `keyfile` has two PEM scanners that can disagree, so a certificate import can decode a
  private key without `--allow-host-plaintext`.
- `tpm2_ptool` and the attestation parse the `tcti` option separately. **Fixed (2026-11-18):**
  `Tpm2Options::of` parses it at open (17 there, as its doc already claimed), and the
  attestation's connection takes that parse; `tpm2_ptool` is handed the string as written, which
  its TCTI loader reads in every form.
- One resolve computes the same SPKI up to four times, a network round trip each on Cloud KMS
  and CloudHSM. **Fixed (2026-11-18):** `compute_ids` reads it once and hands it to the
  identity, the check of the public objects, the attestation, a transport key's `publicKey` and
  `delete`'s `destroy_identified`. `a_resolve_reads_the_public_key_once` counts the trace's
  point reads: 8 before, 5 now (one SPKI, and the comparison with the one public object).

## D9. Test architecture

- With no environment set, 243 of the 247 tests in the `cakeys` test binaries pass without
  running anything. The Nix check and `scripts/local-tests.sh` set every `*_REQUIRE`, which
  turns the skips into failures for the software tokens, so this is practice rather than risk;
  the hardware suites (ftpm, yubikey, cloud) and a few skips inside tests stay outside it, and
  nothing counts skips. ([cli tests common/mod.rs](REVIEW_crates_cli_tests_common_mod.rs.md))
  **Fixed (2026-11-18):** each skip inside a test fails under its suite's `*_REQUIRE` or is a
  fact of one reference (`rsa_legacy` on kryoptic), and the hardware suites opt in all or none.
  Skips are not counted: the check phase skips the hardware and cloud suites by design.
- `on_swtpm()` is a substring match on the D-Bus address. If `nix/tpm2-test-env.sh` renamed
  it, the object matrix and the attestation-key cases would skip without failing CI, even
  under `CAKEYS_TPM_REQUIRE`. The same test file makes persistent TPM handles (one through
  `cakeys create`, one through a raw `tpm2_evictcontrol`) outside any swtpm guard.
  ([cli tests tpm2.rs](REVIEW_crates_cli_tests_tpm2.rs.md)) (**Fixed** before this pass:
  `on_swtpm` reads the script's marker and the TPM's vendor strings, and fails under
  `CAKEYS_TPM_REQUIRE` off swtpm.)
- The skip gate, the `Env` wrapper and the binary runner are copied four to eight times; the
  copies clear different environment variables, and none passes `--lock` or clears
  `CAKEYS_LOCK`. A developer with `CAKEYS_LOCK` exported has test realisations written into
  their real lock. (**Fixed** before this pass, the lock half: `tool()` removes `SCRUBBED`,
  `no_test_run_sees_a_real_keys_toml_or_lock`; the copies themselves remain.) **Fixed
  (2026-11-18), the copies:** one `Suite` (the suites' `Env`s), `suite_var`/`required_var` the
  only skip gates, one `Run` builder for every tool run (bounded runs read the pipes as the child
  writes), one `ptool`/`tpm2_store`, one `swap_private_key` for the five swap setups, and the
  curve constants; the hardware opt-ins gained `CAKEYS_FTPM_REQUIRE` and
  `CAKEYS_YUBIKEY_REQUIRE`. `the_harness_helpers_are_written_once` fails on a second copy.
- The fault suite relies on the trace to show that a rule fired. Two confirmed gaps weaken
  that signal: `use_label` reports a hit when its label matches nothing, and slot and token
  flag names share bit values, so a rule can set a different flag from the one it names.
  ([p11-fault hooks.rs](REVIEW_crates_p11-fault_src_hooks.rs.md),
  [p11-fault plan.rs](REVIEW_crates_p11-fault_src_plan.rs.md)) (**Fixed** before this pass:
  `use_label` naming nothing fails the call as the plan's mistake, and slot and token flags are
  two tables, each function taking its own; ISSUES.md "p11-fault plan mistakes".)
- Half the fuzz targets check only "no panic". `lock` and `bundle` are files cakeys writes and
  reads back, yet neither target checks the round trip. camigrate's key-file reader (PKCS#12,
  encrypted PKCS#8, the B19 bounds) takes operator-supplied files and has no target. **Fixed
  (2026-11-18):** `lock_round_trips` and `bundle_round_trips` (what is read back from the
  writing is what was read, every field), and a `key_file` target whose property ties the
  reader to `holds_private_key`; each run on the repository's fixtures by `cargo test`.
- Hardware opt-in skips are written by hand in each file. A half-set opt-in, or a build
  without the patched cryptoki, passes silently (caprobe `ftpm.rs` calls its only check with
  `require = false`; both `yubikey.rs` suites), and `pkcs11/tests/templates.rs` ignores
  `CAKEYS_TEST_REQUIRE`. One shared all-or-none helper would cover every suite. **Fixed
  (2026-11-18):** `opted_in` (common/mod.rs), a pure `opt_in` of the environment: every
  variable set runs the suite, none skips it, a half-set one fails naming what is missing. The
  ftpm suites opt in by module and profile, the `YubiKey` suites that log in by the PIN and
  management-key files (the module alone stays the read-only probe's). templates.rs honours
  `CAKEYS_TEST_REQUIRE`. `every_hardware_suite_opts_in_through_the_harness` keeps a suite from
  reading an opt-in variable itself. The unpatched-build half was fixed before
  (`no_opted_in_suite_skips_an_unpatched_build`).
  ([caprobe tests ftpm.rs](REVIEW_crates_caprobe_tests_ftpm.rs.md))
- The lock's model-based test compares exit codes only (as docs/DEVELOPMENT.md says), so the
  order among the twelve rules that exit 14 is untested. The projection type `Written` drops
  lock fields it does not name, where DEVELOPMENT.md says it refuses them. A `quint run` of
  500 traces reached all 18 rules, so there is no coverage hole today, only no assertion
  guarding it. ([core tests lock_mbt.rs](REVIEW_crates_core_tests_lock_mbt.rs.md)) **Fixed
  (2026-11-18):** the rule is compared with the exit code, the projection names every lock
  field, and the replay fails on a rule it never reached.
- About 60 refusal cases in `core/tests/refusals.rs`, and several table tests in the CLI
  suite, assert a message substring or exit 17 alone, not the documented code and reason
  together. **Fixed (2026-11-18):** each asserts both. Pinning the reasons found two CLI
  cases refused for another rule than the one they named (a private key without `CKA_SIGN`);
  their skeleton is fixed.
- The surface check counts flag literals across the whole shared harness, so a flag can count
  as tested because another tool's helper spells it. **Fixed (2026-11-18):** a tool's own
  tests count, without comment lines; caprobe's `--module` had been counted by cakeys' helper,
  and its new test found a malformed override exiting 1, now 17.
- The SoftHSM/kryoptic token setup is copied into about ten places (`scripts/local-tests.sh`
  is a hand copy of `preCheck`); `test-tokens.sh` picks its isolated suites from a hard-coded
  list. **Fixed (2026-11-18):** one `nix/token-env.sh`, sourced by the check phase, the runner,
  local-tests.sh and the profile, demo and example scripts, held there by `checks.token-setup`;
  and no shared p11-kit server or swtpm in the check phase, so a suite the list leaves out fails
  instead of sharing one.

## D10. Build and CI

- CI builds only x86_64-linux, though the flake declares more systems, and
  `checks.examples` hard-codes the x86_64 EFI stub.
- The deny check uses the pinned advisory-db with a faked `FETCH_HEAD`, the online app too, so
  advisories newer than the pin are never seen. `deny.toml` has no `[bans]` or `[sources]`.
- The two gate workflows duplicate work; Kani shares a 16 GB runner with the VM tests.

**Fixed (2026-11-18), the deny half:** `nix run .#deny-online` checks against the current
advisory database (cargo-deny fetches it; the pin stays in the sandbox's `checks.deny`) as
well as yanked releases, and deny.toml denies wildcard requirements and any source but
crates.io, and warns on duplicate versions. **Fixed (2026-11-18), the CI half:** one workflow
whose three jobs build each check once (`light`, `vm`, `kani`), Kani on a runner of its own;
`checks.ci-jobs` holds the workflow to flake.nix's split. CI stays x86_64 Linux, by decision.

## Documentation drift found on the way

- docs/CAMIGRATE.md:234: the PKCS#12 MAC takes 600,000 iterations, not 10,000.
- docs/CAKEYS.md names a test, `delete_removes_only_what_it_identified`, that does not exist.
- `crates/cli/tests/cloud.rs:25` cites docs/CLI.md, which does not exist.
- ISSUES.md B18 says the by-name retry reads "the lock's recorded answers included"; the code
  never applies `with_answers` at `Token::open`.
- ISSUES.md B16 is marked fixed; the `pop-unwrap` secret is still not wiped. (It is: dc3f102,
  before this list was written down.)

**Fixed (2026-11-18):** the iteration count, the test name (now
`a_foreign_public_key_conflicts_and_is_never_deleted`) and the CLI.md citation; B18 was
corrected earlier the same day; B16 goes with D7's zeroization. `checks.doc-references` holds
the docs to the tests, functions and docs files they cite; it found one more (ISSUES.md's
`every_named_value_converts_back`, now `token::tests::names_agree`). A number such as an
iteration count is outside it.
