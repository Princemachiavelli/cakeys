# Area D: caprobe, profiles data, integration test harness

## Summary

caprobe is careful code: every write probe records an observation or says why not, cleanup on
error paths is in (`destroy_after_failure`, the next run's `clear_stale`), the emit → parse → emit
round trip is pinned by a fuzz property, the committed-profile byte test and the conformance
probes, and the diff is set-based and deterministic. All 2026-11-18 findings in this area are
fixed or decided. The biggest risk is the scratch-slot guard: on a YubiKey it cannot tell a probe
leftover from any key ykcs11 generated (every key `cakeys create` makes there), so one wrong hex
digit in `probe.scratchId` overwrites a real key (D-1). Probe trust has gaps where a call that
merely returns bytes counts as "works": 9 of 11 RSA and 2 of 6 ECDSA signing variants are never
verified though host verifiers exist, and those feed `add` rows (D-2); wrap round trips never
compare the key that comes back (D-3); non-module refusals become generation "no" rows (D-4).
Biggest simplification wins: archive the three plan/log docs whose "today" sections contradict
the code (~1,050 live doc lines), make the spec-coverage trace an opt-in report (two of its
statuses decide 0 of 1,097 rows; it costs a second full traced test pass per crane check),
split `probe.rs` and delete the Montgomery-only template machinery and the dead `CKM_DES3_CMAC`
probe. The test harness is now well factored (one `Run`, `Suite`, `suite_var`, `OptIn`); what is
left is test placement and a few weak assertions.

## Findings

### D-1. The scratch-slot guard accepts any key ykcs11 generated, so a mistyped `scratchId` overwrites a real key — critical — 1, 2 — verified
`crates/caprobe/src/probe.rs:236-270`, `crates/ykcs11/src/lib.rs:153-178`, `crates/core/src/config/mod.rs:1006-1010`, `crates/caprobe/src/probe.rs:163-165`
`check_slot` passes a slot whose only certificates are ykcs11's own placeholder (serial 0,
self-issued, `CN=YubiKey PIV Slot <n>`) plus the attestation. ykcs11 writes that same placeholder
for every key it generates (the provider's own doc, `token_generate_key` [src]), so a key made by
`cakeys create` (ykcs11 generation as SO, no certificate written) or by any ykcs11 client is
indistinguishable from a probe leftover. The repo's own fixture `placeholder95.pem` is the
placeholder of the P-256 key cakeys' YubiKey suite generates in slot 95. Trigger: keys.toml with a
cakeys-created key at `CKA_ID = "18"` and `probe = { scratchId = "18" }` (one digit off "17"), then
`caprobe probe --token yubikey --write`: the guard passes and every generation and import replaces
that key; PIV cannot restore it. Nothing else stops it: config validation only checks hex, the
probe never compares `scratchId` with the locators keys.toml declares on the same token (it has
the config loaded), and nothing restricts it to the retired slots 82–95 that DEVELOPMENT.md's
hardware rules name. The function's own doc says "a typo must never overwrite a real key". The
user's current device is protected only because slots 82–84 hold real certificates. Fix: (a)
refuse a `scratchId` equal to any `locator.CKA_ID` of an object on that token in keys.toml
(cheap, in `target()`); (b) let the probe mark its slot: after the last generation write its own
fixture certificate (`CN=cakeys-probe`, already in `fixtures/import/certificate.der`) or a
probe-specific placeholder, and accept only "empty" or "that marker"; (c) have the ykcs11
provider refuse non-retired slots (01–04) for `scratchId`.

### D-2. Most signing mechanisms count as working without a verified signature, and `add` rows rest on that — medium — 1 — verified
`crates/caprobe/src/probe.rs:1777-1811`, `:1583-1596`, `:477-480`, `crates/core/src/sig.rs:144-171`
`rsa_ops` verifies only `CKM_RSA_PKCS` and `CKM_SHA256_RSA_PKCS`; the other nine (SHA-1/224/384/512
PKCS#1, all five PSS, raw X.509) pass `none`, so any returned bytes are "worked". `ec_ops` gives
`CKM_ECDSA_SHA1` and `_SHA224` no verifier. An unlisted mechanism that "worked" becomes an `add`
row (`Ops::finish`), which makes the gate answer yes: CAPROBE.md cites SoftHSM's and kryoptic's
`CKM_ECDSA_SHA224` and `CKM_SHA224_RSA_PKCS` adds, both unverified. A module that ignores the hash
parameter (signs SHA-384 as SHA-256) or returns garbage is recorded as offering the mechanism.
The verifiers exist: `sig::rsa_pkcs1v15::<D>` and `sig::rsa_pss::<D>` are generic over the
digest. Fix: replace the `verified: bool` column with a verifier per row (`rsa_pkcs1v15::<Sha384>`,
`rsa_pss::<Sha256>`, …; SHA-224 through `sha2::Sha224`), add SHA-1/224 prehash ECDSA or leave
those rows note-only, and write `add` only for a verified signature.

### D-3. Wrap round trips count an unwrap that succeeded, not one that gave the key back — medium — 1 — plausible
`crates/caprobe/src/probe.rs:1946-1976`, `:2085-2106`, `crates/caprobe/src/probe/moves.rs:649-661`
`probe_wrapping` writes `wrap.rsa-oaep.<hash> = yes` when `C_UnwrapKey` returns a handle;
`probe_key_wraps` likewise keeps a mechanism out of `subtract`. Neither compares the unwrapped key
with the original (`same_aes` exists in moves.rs and is used for the export rows), and neither
checks that the module honoured the OAEP hash: a module that wraps and unwraps with SHA-1 whatever
is asked records SHA-256 yes. camigrate then plans a sealed move by OAEP SHA-256 between this token
and an honest one, and the unwrap fails late (sealed.rs maps `CKR_ENCRYPTED_DATA_INVALID` to 13, a
conflict). CAPROBE.md says "counted only when the key unwraps back". Fix: check the unwrapped key
with `same_aes` against an imported AES fixture of known value, and unwrap a host-made OAEP blob
(`pop::rsa_encrypt` with the hash) so the token's decode of that hash is tested; with the imported
`rsa-2048` fixture as transport key the host can also decrypt the token's blob and check the wrap
side.

### D-4. Asymmetric generation records any non-SO error as the module's "no" — medium — 1 — verified
`crates/caprobe/src/probe.rs:750-777`, `:1286-1290`, `:1349-1353`; compare `:784-806`, `:1895-1904`
`Made::create` maps every `Token::create` error except an SO-login failure to `Created::Refused`,
which `create_curves` and `probe_rsa` write as `generate.<kt>.<on> = no`. Errors that carry no
`CK_RV` are cakeys' or the provider's (a `Provider::template` refusal, a host encoding error), and
`create_secret`/`probe_secrets` already treat those as undetermined ("says nothing of the
module"). Trigger: a provider whose `template` hook refuses a key-pair generation (the
`template_hook.rs` test provider does this for secret keys only): the pair rows become module
refusals with prose evidence, and a regeneration commits them. Fix: in `Made::create`, return
`Refused` only when `e.rv().is_some()`; otherwise push an undetermined line, as `probe_secrets`
does.

### D-5. Two attribute rows are decided without a control — medium — 1 — verified (code), plausible (which modules)
`crates/caprobe/src/probe/extras.rs:87-92`, `:138-149`, `:172-175`
`aes_key`'s doc says "extractable false" but the template sets no `CKA_EXTRACTABLE`, so the key
takes the module's default; `attr.read.CKA_NEVER_EXTRACTABLE` then answers yes whenever the key is
extractable (`extractable || NeverExtractable(true)`), whatever the module reports. On a module
defaulting to extractable the row cannot be "no". `attr.set.CKA_ALLOWED_MECHANISMS` records
`via = "enforced"` when an AES-CBC encryption outside the list fails for any reason, including a
module with no CBC, a busy session or a missing `CKA_ENCRYPT`, with no check that ECB (inside the
list) works. All four committed profiles with the rows say yes. Fix: add
`Attribute::Extractable(false)` to `aes_key`'s template; for "enforced", require ECB to succeed and
CBC to fail with `CKR_MECHANISM_INVALID`/`CKR_KEY_FUNCTION_NOT_PERMITTED`, else "listed-only" with
a note.

### D-6. The regeneration instructions omit `--rsa-max-bits 4096`, and following them breaks the conformance test — medium — 6 — verified
`crates/caprobe/src/emit.rs:150-158`, `crates/cli/tests/common/mod.rs:562-566`, `crates/caprobe/src/lib.rs:191-195`
Every committed profile starts with "regenerate with `caprobe probe --token <t> --write --diff
<profile> --out <this file>`", and `assert_profile_conforms`' failure message says the same. The
default `--rsa-max-bits` is 16384; the reference and hardware profiles (softhsm, kryoptic, swtpm,
fTPM, ykcs11) stop at 4096 and their conformance tests pass 4096. Following the instruction adds
6144–16384 rows (over a minute per size on a software token), and the next conformance run sees
them "only claimed" and fails (15). `scripts/regen-profiles.sh` passes 4096. Fix: put
`--rsa-max-bits 4096` in both messages for the profiles the tests regenerate, or record the
probed maximum in the profile (`[reported]` already exists) and have `--diff` default
`--rsa-max-bits` to it.

### D-7. `supports --layer` help names a layer that does not exist — medium — 6 — verified
`crates/caprobe/src/lib.rs:151`, `crates/caprobe/src/supports.rs:111-117`, `profiles/layers/cryptoki.toml:8`
The help says "repeatable: p11-kit/0.26, cryptoki/0.12-unpatched, swtpm". No profile is named
`cryptoki/0.12-unpatched` anywhere in the repo: `--layer cryptoki/0.12-unpatched` exits 17 (unknown
profile), and `--layer cryptoki/0.12` is silently dropped (`p.profile != binding::NAME`). A user on a
patched binary cannot ask "what would an unpatched binding say" the way the help suggests;
`checks.profiles` does it by writing its own layer file through `--profiles`. Fix: name the real
values in the help (`p11-kit/0.26`, `swtpm`, a file under `--profiles`), and either ship the
unpatched subtraction as an addressable layer or say in the help that the binding layer is
decided by the build.

### D-8. spec-coverage: two statuses decide nothing, and the file costs a second full traced test pass per crane check — medium — 4, 8 — verified
`crates/caprobe/src/coverage.rs:265-314`, `:345-358`, `spec-coverage/cakeys.toml` (`[summary]`), `nix/package-crane.nix:205-215`
The committed summary is `used = 250, out-of-scope = 797, gap = 50`: the `profile` status
(`profile_names`, `recorded_names`, `ck_names`, `PROSE` and their test, ~70 lines) and `refused`
(no rule uses it) classify 0 of 1,097 rows, because manual rules are matched before profiles and
108 wildcard rules cover the rest. CAPROBE.md documents both as live statuses. The only consumer
of the file is the test that regenerates it; to keep it current, every crane build runs the whole
token test suite a second time under the tracing shim. Fix: delete `profile` and `refused`; make
the traced regeneration an opt-in report (as `packages.coverage` is: "a report, never a check")
and keep only the cheap trace-free consistency check in the normal build.

### D-9. Two plan documents describe a state the code no longer has — medium — 5 — verified
`docs/CAPROBE_PROFILE_COVERAGE.md:3-4`, `:20-38`, `:478-519`; `docs/CAPROBE_MIGRATION.md:15-24`
CAPROBE_PROFILE_COVERAGE.md opens "Nothing here is built yet" and its "Where things stand" table
says import rows exist for AES only and `advertise` has no status per entry; its own "Built"
section at the end says Parts 0–8 are implemented (generic/HMAC/DES3 import rows exist,
`moves.rs:752-760`; `[untested]` exists). CAPROBE_MIGRATION.md's "Where things stand" says "The
probe imports nothing" and cites `probe.rs:655`, `:1497`, `:1583`, which now point elsewhere; its
"Built" section contradicts it. A reader landing on either top section is misled. Fix: archive
both (and the dated COVERAGE_PLAN.md log) under `docs/archive/`, moving the still-true "Built" and
"Not done" bullets into CAPROBE.md and OPEN.md (proposal 1).

### D-10. The `CKM_DES3_CMAC` probe can never run, and the doc gives the wrong reason — low — 4, 5 — verified
`crates/caprobe/src/probe/secrets.rs:105-129`, `docs/CAPROBE_PROFILE_COVERAGE.md:493-494`, `docs/OPEN.md:58-60`, `nix/patches/cryptoki-allowed-mechanisms-unnamed.patch:29`
`MechanismType::try_from(0x138)` fails for an unnamed standard value (OPEN.md; the patch itself
falls back to `from_raw` only for `CKA_ALLOWED_MECHANISMS`), so the function returns at its first
line; and `Token::lists` reads cryptoki's `C_GetMechanismList`, which drops the same value. The
doc says "no reference module lists it yet", while OPEN.md records that SoftHSM 2.7 lists it
[run]. Fix: delete the 25 lines and the `VendorDefined` import until the cryptoki patch for
`CKM_DES3_CMAC` lands; correct the doc sentence.

### D-11. Montgomery generation: the "bare" fallback is stricter than the usage template, and refusals miss the row's evidence — low — 1, 5 — verified
`crates/caprobe/src/probe.rs:1183-1196`, `:1215-1218`
The usage try sends public `[CKA_EC_PARAMS]`; the fallback ("bare") sends public
`[CKA_EC_PARAMS, CKA_VERIFY = true, CKA_PRIVATE = false]`. A Montgomery key cannot verify, so a
module that refused the usage template for another reason is likely to refuse the fallback too,
and the curve is recorded `cannot`. The refusal goes to `[notes]` under the bare curve name
(`"curve25519" = "generation refused: …"`), where `probe_unbound` also writes, instead of the row's
evidence (`generation_evidence`), unlike every other generation; the committed rows
`generate.CKK_EC_MONTGOMERY.* = no` therefore carry no evidence. Fix: make the fallback
`[CKA_EC_PARAMS]` with a bare private template, and record through `generation_evidence`
(proposal 4 removes the surrounding machinery).

### D-12. A sealed ECDH derivation counts as working without checking the secret when the module lists no HMAC — low — 1 — verified
`crates/caprobe/src/probe.rs:1676-1690`, `:1625-1637`
With no `CKM_SHA256_HMAC`, `try_sealed` returns `Derives` when the secret merely reports
sensitive and non-extractable, so `derive.ecdh.sealed = yes` and `CKM_ECDH1_DERIVE` is "worked"
without the derived value being compared with the host's. The proofs require HMAC for the sealed
path (`ops::ecdh_seals`), so no proof is misled, but the extractable path is then never tried and
the mechanism's row is unverified. Fix: without HMAC, fall back to the extractable comparison
(it is what `pop-ecdh` will do) and record sealed only as a note.

### D-13. Commitment rows turn a busy session or a failed second call into "no" — low — 1 — verified
`crates/caprobe/src/probe/secrets.rs:123-127`, `:149-153`
`probe_des3_cmac` maps any `C_Sign` error to no, including `CKR_OPERATION_ACTIVE`, which
`refusal_row`/`crypt_row` treat as undetermined. `commit_row` takes the second commitment with
`.ok()`, so an error on it is written as "the same key does not give the same commitment twice".
Fix: route both through `refusal_row`.

### D-14. A probe that made objects but counts none writes no `delete` rows and says nothing — low — 1 — verified
`crates/caprobe/src/probe.rs:925-965`, `docs/CAPROBE_MIGRATION.md:257-259`
When the before-count is empty although `scratch.labels` is not (the fTPM run: "the leftover count
found nothing to count … the probe should say so rather than write nothing"), `delete_rows`
returns `Ok(vec![])` and neither a row nor an undetermined line appears. Fix: when labels were
tracked and the before-count is empty, push "no delete rows: nothing found under the probe's
labels".

### D-15. The catch-all coverage rule's reason is false for return values the tools match by name — low — 5 — verified
`spec-coverage/manual.toml:848-851`, `spec-coverage/cakeys.toml:927`, `crates/caprobe/src/probe.rs:468`, `crates/caprobe/src/probe/secrets.rs:281`, `crates/camigrate/src/sealed.rs:626-646`
`CKR_*` → out-of-scope, "met by no test and matched by no name". `CKR_OPERATION_ACTIVE` (six
matches in caprobe), `CKR_MECHANISM_PARAM_INVALID` (`crypt_row`, sealed.rs) and
`CKR_ENCRYPTED_DATA_INVALID` (sealed.rs) are matched by name, so they belong to the "gap" rules
above it ("matched by name, met by no test"). The fault suites inject them but run untraced. Fix:
add them to the gap rules (or, with D-8, retire the file).

### D-16. caprobe-local CLI nits — low — 6 — verified
`crates/caprobe/src/lib.rs:120-123`, `:124`, `:143-162`, `:171-172`, `:191-195`, `:288-292`; `docs/CAPROBE.md:14-19`, `:158`
`caps --token` and `probe --token` have no help text. `supports`' help says "what a vendor SO
version supports": SO means shared object here and Security Officer two lines later in `probe`'s
help. `--rsa-max-bits` is accepted and ignored without `--write` (`requires = "write"` would say
so). `supports CKM_X --class pq` silently drops `CKM_X`, and `--bits` is ignored for any name but
`CKK_RSA`. `--profiles` is per subcommand (supports, probe) but CAPROBE.md writes it as a global
`caprobe --profiles`, and `caps` lacks it. CAPROBE.md's synopsis omits `--rsa-max-bits` and
`--module`.

### D-17. Small inconsistencies in probe.rs — low — 5, 7 — verified
`crates/caprobe/src/probe.rs:2159-2191`, `:760`, `:793`, `crates/caprobe/src/probe/moves.rs:187-190`, `crates/kmsp11/src/lib.rs:26`
`generate`'s doc comment (`The probe verb …`, `# Errors`) is attached to `build_lacks`, whose own
doc follows it, and `generate` has none. An SO-login failure is recognised by the substring
`"C_Login (SO)"` in a message, in three copies (moves.rs has a `so_login` helper probe.rs does
not use). The purpose-bound keys use the label prefix `caprobe-`, every other probe object
`cakeys-probe-`.

### D-18. Profile evidence embeds the verbs' prose and provider hints — low — 4, 5 — verified
`crates/caprobe/src/probe.rs:1514-1559`, `profiles/modules/kmsp11/1.9+hsm.toml` (`prove.pop-decrypt.CKK_RSA.RSA_SIGN_*`)
`evidence()` strips cryptoki's prose but keeps cakeys' own message, including `hint for kmsp11:
Cloud KMS: a key libkmsp11 creates keeps its versions 30 days …`, repeated in eight rows. Any
rewording of an error message in cakeys-pkcs11 or a provider changes committed profile bytes: the
reference profiles fail their byte test until regenerated, and the cloud and hardware ones go
silently stale (the diff ignores evidence). Fix: evidence = the `C_*` function and `CKR_*` name
(plus cakeys' refusal class), never the hint; keep prose in `[notes]` if wanted.

### D-19. No test holds the probe to leaving non-probe objects alone, or the slot guard to a placeholder-only real key — low — 7 — verified
`crates/caprobe/tests/fault.rs:16-29`, `crates/caprobe/tests/reference.rs:180-215`
`scratch()` plants a `decoy` pair "no probe made" and uses it only as a substitution target; no
case asserts it survives the write probes, `clear_stale` and `destroy_after_failure`. The guard
test covers a foreign certificate and an empty slot, but not a slot holding a key with no
certificate, nor a ykcs11-generated key with only its placeholder (D-1). Fix: assert
`labelled("decoy").len() == 2` after `probe_cases`; add the two slot cases.

### D-20. The emitter's "every optional field alone" list has drifted — low — 7 — verified
`crates/caprobe/src/emit.rs:410-461`
Its doc says "A field added to the parser belongs here", but `[untested]`, `[mechanism-info]` and
`[claims]` (added with the coverage plan) are missing. They round-trip today only because the
committed profiles carry them. Fix: add the three bodies, or derive the list from a fixture
profile that sets every field.

### D-21. The cakeys `validate` test binary is mostly harness self-tests; two fault tests accept any failure — low — 7 — verified
`crates/cli/tests/validate.rs:44-236`, `crates/cli/tests/fault.rs:322`, `:479`
Eight of its twelve tests test the harness (YubiKey latch, env scrub, opt-in, bounded run, and
four lints that grep test sources), beside four static-gate tests the file header describes. The
latch test also removes the latch before asserting it was written (`:62`), so a regression fails
with a `NotFound` unwrap, not the assertion. `fault.rs` asserts `assert_ne!(code, 0)` where the
documented outcome is a specific code (16 for a failing call). Fix: move the self-tests to
`tests/harness.rs`; assert exact exit codes.

### D-22. After an interrupted slot probe the guard refuses with "may hold a real key" for the probe's own certificate — low — 6 — verified
`crates/caprobe/src/probe/moves.rs:122-136`, `crates/caprobe/src/probe.rs:256-269`
In a scratch slot the move probes write the fixture certificate (`CN=cakeys-probe`) and only the
final P-256 generation puts ykcs11's placeholder back. A run stopped in between (Ctrl-C, an SO
login failure, or that generation refused, which is only an undetermined line) leaves the probe's
certificate, and every later run is refused (17) as if a real key were there, until the user
clears the slot by hand. Fix: accept the probe's own fixture certificate as an occupant (it is
also the marker D-1 proposes).

### D-23. The surface test merges flags across subcommands — low — 7 — verified
`crates/cli/tests/common/surface.rs:14-25`, `:59-66`
`surface()` collects every long flag into one set, so a flag shared by two verbs counts as tested
when either uses it: `probe --profiles` (the regeneration flag the scripts use) is run by no test,
only `supports --profiles`, and caprobe's surface test passes. The file says it is "a floor", but
not that it is per tool rather than per verb. Fix: record `verb --flag` pairs and match them
within one argument list, or say so in the doc.

### D-24. Smaller doc drift — low — 5 — verified
`docs/CAPROBE.md:278-279`, `:299-300`, `crates/caprobe/src/baseline.rs:255-265`, `crates/caprobe/tests/template_hook.rs:12-15`, `crates/caprobe/src/lib.rs:211-215`
CAPROBE.md says the baseline "regenerates byte for byte"; the test compares parsed baselines. Its
diff paragraph omits `[untested]`, which `diff` compares. template_hook.rs' header says a second
in-process `main_from` is refused; `main_from` now reuses the set for the same directories, so the
subprocess control is no longer forced.

## Complexity reduction proposals (ranked, with estimated lines saved)

1. **Archive the plan and log documents** (D-9): `docs/CAPROBE_PROFILE_COVERAGE.md` (519),
   `docs/CAPROBE_MIGRATION.md` (259) and `docs/COVERAGE_PLAN.md` (325) to `docs/archive/`, after
   moving their still-true "Built"/"Not done" bullets (~40 lines) into CAPROBE.md and OPEN.md.
   About −1,060 lines of live documentation, and the contradictions go with them.
2. **spec-coverage as an opt-in report** (D-8): drop the `profile` and `refused` statuses
   (coverage.rs −~80 lines with their test), move the traced regeneration out of every crane
   check into an app or package beside `packages.coverage`, keep the trace-free consistency test.
   Saves one full traced pass of the token suites per CI build.
3. **Split `probe.rs`** (2,475 lines) by job, no behaviour change: `probe/scratch.rs` (Target,
   Scratch, `target`, `check_slot`, `clear_stale`, `destroy_all`, `delete_rows`, `count_by_class`,
   ~300), `probe/asym.rs` (curves, RSA, `operate`, `prove`, `ec_ops`, `rsa_ops`, ECDH derive
   family, ~800), `probe/wraps.rs` (`probe_wrapping`, `probe_key_wraps`, `KeyWrap`, ~240),
   `probe/bound.rs` (`probe_bound`, `probe_unbound`, ~140), `probe_secrets` and the size tables into
   `secrets.rs`; probe.rs keeps Draft, Ops, Made, `generate`, `keep_claims` (~650). With it, the
   dedups: `Made::create` re-implements `moves.rs`' `locator()` (probe.rs:751-757); the AES unwrap
   template literal is written four times (probe.rs:1957, 1994, 2028, 2093); SO-login detection
   three times; `on: &str` carries "RSA-2048" and is parsed back in `prove` (probe.rs:1482-1496):
   pass `On`. About −60 lines.
4. **Delete the Montgomery-only template machinery** (D-11): `Made::pair`, `pair_for_use`,
   `note_dropped`, the policy-default drop loop and `template_notes`' second writer serve only the
   Montgomery generation (probe.rs:682-744, 819-829), whose templates are the probe's own. A
   ~20-line generation beside `extras::montgomery_ecdh` replaces ~95 lines: about −75.
5. **Delete `probe_des3_cmac`** (D-10): −25 lines and the `VendorDefined` import, back when cryptoki
   names `CKM_DES3_CMAC`.
6. **Verify by table in `rsa_ops`** (D-2): replace the `(Mechanism, data, bool)` table and the
   `pkcs1`/`none` closures with `(Mechanism, data, verifier)`; roughly line-neutral, removes the
   unverified class of rows.
7. **Use the `hmac` crate already in the workspace** for `secrets::hmac_sha256` and share one AES
   block helper between `secrets::aes256_cbc` and `moves::host_kcv`: about −20.
8. **Fold `checks.profiles`' `supports` block into `caprobe/tests/supports.rs`**: 9 of its 11
   cases repeat the test's; the two that depend on the patched binding can run there behind
   `cakeys_pkcs11::binding::patched()`. About −20 lines of Nix.
9. **Move the harness self-tests** out of `cli/tests/validate.rs` into `tests/harness.rs` (D-21):
   no saving, but the static-gate file then holds what its header says.

## Still open from the 2026-11-18 review (one line each)

- None open: every finding on the files in scope is fixed or decided. Decided, and still valid:
  caprobe `tests/fault.rs` F3, caprobe `tests/reference.rs` F3, `common/xref.rs` F2,
  `object_matrix/mod.rs` F1.
- Decided, now partly obsolete: caprobe `tests/template_hook.rs` F2 — `main_from` reuses a set
  for the same directories, so the header's "one call per process" rationale is stale (D-24).

## Cross-area notes (issues seen in another agent's files; one line each, no deep dive)

- `crates/ykcs11/src/lib.rs:153-178` `scratch_occupant` is where D-1's fix belongs (slot range, probe marker).
- `crates/core/src/config/mod.rs:1006-1010`: `scratchId` is validated as hex only; a check against the token's declared locators belongs in `check_token` or the probe.
- `crates/cli/tests/common/surface.rs` (D-23) gives cakeys and camigrate the same per-tool, not per-verb, guarantee.
- `checks.nix:172-216` duplicates `caprobe/tests/supports.rs` (proposal 8); `nix/package-crane.nix:205-215` runs the second traced pass (D-8).
- `crates/kmsp11/src/lib.rs:26` labels bound keys `caprobe-`, the probe uses `cakeys-probe-` (D-17).
- Provider hints in `KmError` messages end up in committed profile evidence (D-18): cakeys-pkcs11 and provider crates.
- `crates/core/src/sig.rs`: `HashAlg` has no SHA-1/SHA-224, which is why ECDSA SHA-1/224 go unverified in the probe (D-2).

## Files reviewed (every file in scope, with one line each: "clean" or finding IDs)

caprobe source and tests:
- `crates/caprobe/src/probe.rs` — D-1, D-2, D-3, D-4, D-11, D-12, D-14, D-17, D-18; proposals 3, 4, 6
- `crates/caprobe/src/probe/moves.rs` — D-3, D-17, D-22; proposal 3
- `crates/caprobe/src/probe/secrets.rs` — D-10, D-13; proposals 5, 7
- `crates/caprobe/src/probe/extras.rs` — D-5, D-11
- `crates/caprobe/src/emit.rs` — D-6, D-20
- `crates/caprobe/src/diff.rs` — clean (set-based, sorted output; emit → parse → diff is empty by the round-trip property)
- `crates/caprobe/src/coverage.rs` — D-8, D-15
- `crates/caprobe/src/baseline.rs` — D-24 (doc says byte-for-byte; test compares parsed)
- `crates/caprobe/src/supports.rs` — D-7, D-16
- `crates/caprobe/src/lib.rs` — D-6, D-7, D-16, D-24
- `crates/caprobe/src/main.rs` — clean
- `crates/caprobe/Cargo.toml` — clean
- `crates/caprobe/fixtures/import/*` (make.sh, keys, certificate, openssl-version.txt) — clean (certificate usable as D-1/D-22 marker)
- `crates/caprobe/tests/fault.rs` — D-19
- `crates/caprobe/tests/reference.rs` — D-19
- `crates/caprobe/tests/supports.rs` — proposal 8
- `crates/caprobe/tests/template_hook.rs` — D-24
- `crates/caprobe/tests/surface.rs` — D-23
- `crates/caprobe/tests/tpm2.rs`, `ftpm.rs`, `yubikey.rs` — clean

Integration-test harness (`crates/cli/tests`):
- `common/mod.rs` — D-6 (message at :562-566); otherwise clean (prior F3–F8 fixes hold)
- `common/surface.rs` — D-23
- `common/xref.rs` — clean
- `object_matrix/mod.rs` — clean
- `validate.rs` — D-21
- `fault.rs` — D-21
- `reference/mod.rs`, `adoption.rs`, `check.rs`, `create.rs`, `delete.rs`, `drift.rs`, `identity.rs`, `lockfile.rs`, `matrix.rs`, `proofs.rs`, `tokens.rs`, `validate.rs` — clean (no new findings; the lock-sidecar test waits on the tool's note, not a timer)
- `references.rs`, `tpm2.rs`, `p11kit.rs`, `cloud.rs`, `ftpm.rs`, `yubikey.rs`, `offline.rs`, `softhsm.rs`, `kryoptic.rs`, `surface.rs` — clean
- `fixtures/*` — clean (the five files no Rust test reads are read by checks.nix and nix/examples.nix)

Profiles and coverage data:
- `profiles/modules/softhsm/2.7.toml`, `kryoptic/1.5.toml`, `tpm2-pkcs11/1.10+swtpm.toml`, `tpm2-pkcs11/1.10+amd-ftpm.toml`, `ykcs11/2.7.toml` — D-6 (RSA rows stop at 4096), D-11 (Montgomery rows without evidence)
- `profiles/modules/kmsp11/1.9+hsm.toml`, `1.9+hsm-fips.toml`, `aws-cloudhsm/5.18+hsm2m-fips.toml`, `5.18+hsm2m-non-fips.toml` — D-18
- `profiles/layers/cryptoki.toml` — D-7
- `profiles/layers/p11-kit.toml`, `profiles/hardware/swtpm.toml` — clean
- `profiles/baselines/pkcs11-3.2.toml` — clean (generated, pinned); vendored headers skipped as instructed
- `spec-coverage/cakeys.toml`, `spec-coverage/manual.toml` — D-8, D-15
- `spec-coverage/objects/softhsm.toml`, `kryoptic.toml`, `tpm2-pkcs11+swtpm.toml` — clean (generated and pinned by the object-matrix test; consumed only by it)

Documentation:
- `docs/CAPROBE.md` — D-7, D-8, D-16, D-24
- `docs/CAPROBE_PROFILE_COVERAGE.md` — D-9, D-10; proposal 1
- `docs/CAPROBE_MIGRATION.md` — D-9, D-14; proposal 1
- `docs/COVERAGE_PLAN.md` — proposal 1 (a dated 2026-11-14 log, not current)
- `docs/DEVELOPMENT.md` — D-1 (its hardware rules for slots are not enforced in code); otherwise clean
