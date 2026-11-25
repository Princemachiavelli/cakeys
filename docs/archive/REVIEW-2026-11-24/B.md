# Area B: PKCS#11 core and providers (pkcs11, ykcs11, tpm2-pkcs11, kmsp11, aws-cloudhsm, p11-fault) — review 2026-11-24

## Root causes in this area (fill at the end: 3-8 causes, each with the finding IDs that evidence it)

1. **A rule lives at one call site, not at the operation.** Each entry path (run, dry-run, gate, plan,
   import, delete) asks its own subset of provider facts, so a rule added to one path is missing from the
   others. B-1 (placement: 2 of 4 paths), B-2 (placement only inside a `create` override), B-4 (the
   private-object guard re-derived at 4 sites), B-13 (delete's "really gone" knowledge sits in ykcs11's
   code and a profile row, not in `ops::delete`).
2. **One decision, two hand-synced sources of truth.** Code and data (or two functions) each answer the
   same question and drift. B-10 (code `matches` vs profile `[match]`), B-9 (a `matches!` list over a
   growing enum), B-5 (two `bit_len`s), B-4 (4 private-object rules), B-13 (`delete.*` row vs ykcs11 code).
3. **Provider seams default to "nothing", and what an override does or returns is never checked.** Safety
   lives in "remember to call X" prose. B-2, B-3 (template output unchecked), B-7 (a name silently
   resolves to a hook-less data provider), B-8 (session-template security attributes unpinned).
4. **Verifiers are tested against one adversary, or none.** Each attestation/proof check is exercised
   by an honest fixture and at most one kind of liar; the p11-fault shim can model more liars than any
   test uses. B-11 (PIV: coherent chain only), B-12 (tpm-certify: lying store yes; lying module and
   interposer no), B-13 (destroy that lies), UD-12..15 (identity/possession guards).
5. **Fixes close the reported instance; the regression test pins that instance; the class re-forms.**
   B-1 and B-2 (prior B-3), B-5 (prior C-20), B-6 (prior B-8), B-10 (prior ykcs11 F1, recorded fixed in
   ISSUES.md:143), B-12 (prior B-1's vendor path), and B-2 itself re-introduced prior B-27's "paired
   hooks" class in fce5432 one day before 61b7000 fixed B-27's two named pairs.
6. **Tests assert that something happened, not the property it exists for.** B-4 (asserts 11 for a
   wrong "absent"), B-8 (asserts which templates were asked), UD-1 (`patched()` is its own oracle),
   prior B-11's test asserting prose.
7. **The real-device paths run only by hand.** ykcs11 live create/destroy/derive (UD-21, UD-22), kmsp11's
   B11 proofs (never run, `kmsp11/src/lib.rs:323-327`), fTPM EK roots, CloudHSM stand-ins: T-GATED, and
   P-UNRUN for kmsp11.

## Test gap map (fill at the end: per crate, what behaviour has no failing test, and why: gated, absent, oracle)

T-GATED table, provider code path → test → runner and condition:

| Path | Test | Runner / condition |
|---|---|---|
| pkcs11 gate, templates, registry, resolution, provider defaults, policy, rv | inline unit | plain `cargo test`, every platform, Nix check |
| pkcs11 token layer on a real module | `crates/pkcs11/tests/{logins,library,templates}.rs`, `cli/tests/reference/*` | `CAKEYS_TEST_MODULE` (SoftHSM) + kryoptic, p11-kit; Nix check / `scripts/local-tests.sh` (nextest); plain cargo test skips |
| PoP and identity under a lying module | `cli/tests/fault.rs`, `caprobe/tests/fault.rs`, `camigrate/tests/{fault,dry_run}.rs` | p11-fault, Linux only: Linux Nix check |
| ykcs11 placement, slot table, scratch companion, PIV chain | `ykcs11/src/{lib,attest}.rs` unit + fixtures | plain `cargo test` |
| ykcs11 live create, destroy refusal, CKA_DERIVE repair, attestation | `cli/tests/yubikey.rs`, `caprobe/tests/yubikey.rs` | `CAKEYS_TEST_YUBIKEY_*`, by hand; never Nix or CI |
| tpm2 store reader, `verify_certified`, EK chain, vendor output parse, ptool refusals | `tpm2-pkcs11/src/**` unit | `cargo test` on Linux; the crate is out of scope on darwin |
| tpm2 store-path attest, hostile store, B-1 copy, salted session | `cli/tests/tpm2.rs` | swtpm + nixpkgs module, `CAKEYS_TPM_REQUIRE` in the Linux Nix check |
| tpm2 vendor route (`CKM_TPM2_CERTIFY`, `akLabel`) | `cli/tests/tpm2.rs:1116-1213` | patched module, `CAKEYS_TPM_VENDOR_REQUIRE`, Linux Nix check |
| tpm2 EK to a manufacturer root | ek.rs unit (AMD fixtures); live fTPM | unit everywhere Linux; live `CAKEYS_FTPM_ATTEST` by hand |
| kmsp11 algorithm choice, refusals | unit | plain `cargo test` |
| kmsp11 / CloudHSM live | `cli/tests/cloud.rs` | `CAKEYS_TEST_GCP=1`, `CAKEYS_TEST_AWS`, by hand; B11 never run |

Per crate, what has no failing test:

- **pkcs11** — absent: placement on the plan path and unnamed-provider gate (B-1), placement without a `create`
  override (B-2), a template hook's output (B-3), session-template attributes (B-8), all-commitments-No (UD-2),
  `!cap.imported` (UD-4), scheme mismatch 13 (UD-6), SO PIN flags (UD-8), `device_failed` beyond DEVICE_ERROR
  (UD-10), `check_kind` and the public-object cross-check (UD-12/13), `proof_failure` 15-vs-13 (UD-14), destroy
  that lies (B-13). Oracle: private non-key "absent" asserted as 11 (B-4); templates asserted by kind (B-8);
  prose (prior B-11). Tauto: `patched()` (UD-1). Gated: attest downgrade 14 only under swtpm (UD-7).
- **ykcs11** — absent: slot signed by the device (B-11), chain length (UD-19), f9 suffix rule (UD-20), detection
  through the profile (B-10). Gated: every live path (UD-21, UD-22).
- **tpm2-pkcs11** — absent: lying vendor module and TPM interposer (B-12: 7 checks), vendor refusal of a secret
  key and of `ekCertificate` (UD-23, UD-24), unparsable NV EK (UD-26). Gated: Linux only; fTPM by hand.
- **kmsp11, aws-cloudhsm** — unit-tested choices; every live path gated (by hand), B11 P-UNRUN.
- **p11-fault** — itself unit-tested; under-used: 8 plausible behaviours never injected (per-file log).

## Findings (appended per file)

13 findings, all in the per-file log below: B-1..B-13. Severity: critical 0, high 0, medium 10, low 3.
Escape codes (findings carrying each): T-ABSENT 8, T-INSTANCE 5, D-PARALLEL 4, T-FRIENDLY 3, D-SEAM 3,
P-REVIEW 3, T-ORACLE 2, D-MULTIPATH 1, T-TAUTO 0 (UD-1), T-GATED 0 (UD-7, UD-21, UD-22), P-UNRUN 0
(kmsp11 B11, known open).

## Unguarded decisions (appended per file, from mutation testing)

UD-1..UD-29 in the per-file log; 26 unguarded (UD-17, UD-28, UD-29 guarded; UD-23..25 are B-12's).

## Prior fixes re-checked (prior ID — holds / instance only / wrong / regressed)

- 11-23 B-1 (secret key bound by TPM2_HMAC) — holds on the store path, tested (`tpm2.rs:1036`); the vendor
  path's refusal is untested — instance only (B-12).
- B-2 (akLabel caveat) — holds, tested (`tpm2.rs:1173`).
- B-3 (PIV slot rule) — instance only: B-1 (plan path, unnamed provider), B-2 (live path needs a `create` override).
- B-4 (template hook) — kept by decision; its risk is B-3 here.
- B-5 (registry is no provider) — holds; but the data fallback is B-7/B-10.
- B-6, B-11 (test asserts prose), B-12, B-14 (`limit()` has no unit test), B-26 — hold.
- B-7 (32-byte PoP secret), B-8 (ECDH fallback only on template refusal) — hold; B-8's sibling is B-6.
- B-9 (hint by topic) — holds, tested (`providers.rs:59`, `kmsp11/src/lib.rs`).
- B-10 (`read_attribute` duplicated) — holds (`cakeys_pkcs11::token::read_attribute`).
- B-13 (two store tokens of one label) — holds, unit-tested (`store.rs:528-530`).
- B-16, B-17, B-18 (p11-fault) — hold, unit-tested / derived from the `forward!` table.
- B-22 (one `repair` hook) — holds: typed `ec_point`/`key_type`/`policy_flag`/`stand_in`.
- B-24 (two build.rs) — holds (`crates/pin-roots.rs`).
- B-25 (trusted copy left on the token) — holds (`tests/templates.rs:220-231`).
- B-27 (paired hooks) — holds for its two pairs; the class came back as `placement` + `create` (B-2), from fce5432.
- B-15, B-19..B-21, B-23 — not re-checked (docs and dead code outside these files).
- Older: ykcs11 lib.rs F1 — instance only (B-10); C-20 — instance only (B-5); 11-23 D-1 — holds.

## Cross-area notes (one line each)

- camigrate `landing.rs:110-135` `landing_checks` never asks `placement` (B-1) — Area D.
- core `config/mod.rs:336` `secret_material` and camigrate `file_verbs.rs:345` re-derive the private-object rule (B-4).
- caprobe `probe/asymmetric.rs:402` counts RSA bits as `n.len() * 8` (B-5).
- caprobe `probe/scratch.rs:30-34` ignores `C_DestroyObject`'s rv, so `delete.*` rows cannot say whether the module lied (B-13).
- `nix/package-crane.nix:79-83` ships `cakeys-minimal` without the ykcs11/tpm2 providers, whose names then resolve to data providers (B-7) — Area C.
- `profiles/modules/ykcs11/2.7.toml` `[match]` claims every "Yubico (<https://www.yubico.com>)" module, the YubiHSM too (B-10); ISSUES.md:143 says fixed.
- `cli/tests/reference/identity.rs:732-733` asserts 11 for a private data object read without login (B-4, T-ORACLE).

## Files reviewed (every file in scope: clean | finding IDs | unguarded count)

| File | Result | UD |
|---|---|---|
| crates/pkcs11/Cargo.toml, src/lib.rs, src/chain_time.rs | clean | 0 |
| crates/pkcs11/src/binding.rs | clean | 1 (UD-1) |
| crates/pkcs11/src/gate.rs | B-1 | 2 |
| crates/pkcs11/src/ops/capabilities.rs | B-2 | 2 |
| crates/pkcs11/src/ops/planner.rs | B-1 | 0 |
| crates/pkcs11/src/provider.rs | B-2, B-3, B-7 | 0 |
| crates/pkcs11/src/ops/mod.rs | B-4, B-13 | 3 |
| crates/pkcs11/src/token/mod.rs, types.rs, measure.rs, library.rs, host.rs, public.rs, uri.rs | clean | 0 |
| crates/pkcs11/src/token/generate.rs | B-6, B-13 | 0 |
| crates/pkcs11/src/token/login.rs | clean | 1 |
| crates/pkcs11/src/token/rv.rs | clean | 1 |
| crates/pkcs11/src/token/policy.rs | B-5 | 1 |
| crates/pkcs11/src/token/identity.rs | clean | 2 |
| crates/pkcs11/src/token/possession.rs | clean | 2 |
| crates/pkcs11/src/templates.rs | B-3, B-8 | 1 |
| crates/pkcs11/src/registry.rs | B-7, B-10 | 0 |
| crates/pkcs11/src/providers.rs | clean | 0 |
| crates/pkcs11/src/resolution.rs | B-9 | 0 |
| crates/pkcs11/tests/patched_cryptoki.rs, logins.rs, library.rs | clean (logins.rs: prior B-11 prose oracle) | 0 |
| crates/pkcs11/tests/templates.rs | B-8 | 0 |
| crates/ykcs11/Cargo.toml, build.rs, roots/*, tests/fixtures/* | clean | 0 |
| crates/ykcs11/src/lib.rs | B-10 | 3 |
| crates/ykcs11/src/attest.rs | B-11 | 2 |
| crates/tpm2-pkcs11/Cargo.toml, build.rs, roots/*, tests/fixtures/*, src/lib.rs, src/ptool.rs, src/attest/store.rs, src/attest/credential.rs | clean | 0 |
| crates/tpm2-pkcs11/src/attest/mod.rs | B-12 | 2 |
| crates/tpm2-pkcs11/src/attest/vendor.rs | B-12 | 1 |
| crates/tpm2-pkcs11/src/attest/esys.rs | B-12 | 2 |
| crates/tpm2-pkcs11/src/attest/ek.rs | clean | 1 |
| crates/kmsp11/Cargo.toml, src/lib.rs, src/keys.json | clean | 0 |
| crates/aws-cloudhsm/Cargo.toml, src/lib.rs | clean | 0 |
| crates/p11-fault/Cargo.toml, src/{lib,forward,hooks,plan,trace}.rs | clean | 0 |
| crates/pin-roots.rs | clean | 0 |

## Per-file log (appended as each file is finished)

### crates/pkcs11: Cargo.toml, src/lib.rs, src/binding.rs, src/chain_time.rs, tests/patched_cryptoki.rs

- Cargo.toml, lib.rs: clean. chain_time.rs: clean (Warn falls back to undated only after a dated
  failure; both branches and NoClock unit-tested).
- binding.rs: unguarded (UD-1 below).

### crates/pkcs11/src/gate.rs, src/ops/capabilities.rs, src/ops/planner.rs, src/provider.rs

#### B-1. Prior B-3 fixed on two paths only: `camigrate migrate --dry-run` never asks `Provider::placement`, and `validate`/`create --dry-run` skip it whenever the provider is not named — medium — verified

`crates/camigrate/src/landing.rs:110-135` (`landing_checks`), `crates/pkcs11/src/gate.rs:29-58,147-154`, `crates/pkcs11/src/ops/planner.rs:160-174`
What: `landing_checks` (the plan every `migrate`/`--dry-run` prints) asks the target provider
`check_imported_attestation` statically via `registry.named`, but not `placement`. A ykcs11 target
pair with a `CKA_LABEL` locator, or `CKA_ID = "19"` (f9), plans "ready" (0); the real run refuses at
`ops::check_import` (17). Separately, `gate::stack` returns `Err(..)` when keys.toml names no
`provider` and the lock has no realisation yet (the normal first run), so `gate::check` — and with it
placement — never runs; `create --dry-run` and `validate` report the pair `create` with only a
generic "not checked before opening the token" note. No key is written (the live paths refuse), so
this is the C-2 class (dry run ≠ run), not data loss.
Why missed: T-INSTANCE, D-MULTIPATH, P-REVIEW. fce5432 (the B-3 fix) added `placement` to `gate::check`
and `check_import` and tested exactly the reported instance: `validate.rs:148` with
`provider = "ykcs11"` named. No test plans a move to a ykcs11 pair, and no test runs `validate` on a
ykcs11 token without `provider`. The prior review listed three entry paths (gate, dry-run, imports);
the fix enumerated call sites rather than making one function every path calls.
Class: one static rule re-asked at each entry path by hand. Instances: `placement` (gate, check_import,
ykcs11 `create`; missing in `landing_checks`), `check_imported_attestation` (asked separately in
`check_import` and `landing_checks`), `check_attestation` (gate + `check_capabilities`). 3 rules × 3-4 paths.
Instance fix: `landing_checks` asks `provider.placement(&dst.on_token.locator)`. Class fix: one
`ops::static_checks(t, provider) -> Vec<Refusal>` (placement, attestation cover, import attestation,
own generation) that gate, `check_capabilities`, `check_import` and camigrate's plan all call; a test
iterates every planner entry (validate, create --dry-run, migrate --dry-run, import --dry-run) over one
table of refusals.

#### B-2. `Provider::placement` is enforced on the live `create` path only if the provider also overrides `create` — medium — verified

`crates/pkcs11/src/provider.rs:226-251`, `crates/pkcs11/src/token/generate.rs:26-51`, `crates/pkcs11/src/ops/capabilities.rs:260-283`
What: the default `create` (`Token::create_declared`) and the live capability check
(`check_capabilities`) never call `placement`. Its doc says it is asked "by a `Self::create` override".
A provider (in-tree or the `custom-provider` example's kind) that overrides `placement` alone gets it
enforced by the gate (only when the stack resolves statically, B-1) and by imports, never by `cakeys
create`. Only ykcs11 implements it today and it also overrides `create`, so this is latent.
Why missed: D-SEAM, T-ABSENT. The contract ("an override must remember to call X") lives in prose; no
test provider overrides `placement` without `create`.
Class: hooks whose enforcement depends on another hook's override calling them. Instances: `placement`
(needs `create`), `manages_as_so` (honoured only through `managing`, which `create_declared`/
`destroy_plain` call; an override that skips it creates in a user session). 2.
Instance fix: `Token::create` asks `self.provider.placement(loc)?` before `provider.create`. Class fix:
the core calls every static fact itself before dispatching to an operation override; overrides receive
an already-checked request.

#### B-3. `Provider::template` may rewrite security attributes of every template, and nothing checks what comes back — medium — plausible

`crates/pkcs11/src/provider.rs:172-201,316-325,409-438`; callers `token/generate.rs:104-127`, `token/mod.rs:364,496`, `token/identity.rs:367`, camigrate `sealed.rs:113,553,698`, `host.rs:232`, `public.rs:217`
What: `Attributes::set/remove` accept any attribute. A provider can set `CKA_EXTRACTABLE = true` or
`CKA_SENSITIVE = false` on `SessionKey::ExportKek`/`HostKek`/`ImportKek`/`ProofSecret{sealed:true}`,
`CKA_TOKEN = true` on a session key, or change `CKA_ID`/`CKA_LABEL` (the locator) of a generation.
The generated object is later read back against its spec (`Token::check`), but session keys and
camigrate's KEKs are never read back, so a weakened sealed export would go unnoticed. The hook is kept
by decision (prior B-4) for the user to implement, so its first implementor meets no guard.
Why missed: D-SEAM, T-ABSENT. The only tests (`provider.rs:651`, `pkcs11/tests/templates.rs`,
`caprobe/tests/template_hook.rs`) check that the hook is *asked* and that a refusal propagates, never
what an adjustment may not change.
Class: repair/adjust hooks whose output is trusted ("must return exactly what a spec-compliant module
would", provider.rs:2-3) with no post-condition check. Instances: `template`, `ec_point`, `key_type`,
`policy_flag` (a repair can report `CKA_SIGN` true for a key the module says false; policy checks see
the repaired value). 4.
Instance fix: `adjusted` refuses (17) an adjustment that adds/changes `CKA_ID`, `CKA_LABEL`,
`CKA_TOKEN`, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_PRIVATE` (key classes) or any policy attribute the
spec declares. Class fix: give each repair/adjust hook an allow-list of attributes it may touch,
checked in the `impl dyn Provider` wrapper, plus a property test over a hostile provider.

#### Unguarded decisions (gate.rs, capabilities.rs, planner.rs, provider.rs, binding.rs)

- UD-1 `crates/pkcs11/src/binding.rs:36-40` — `patched()` (which layer subtracts HMAC key types; caprobe's
  write refusal; camigrate's kwp assertion) — its only test (`binding.rs:63`) and `validate.rs:171` take
  `patched()` itself as the oracle: hard-coding it to `true` or `false` passes both builds (T-TAUTO). A test
  `assert_eq!(patched(), cfg!(feature = "patched-cryptoki"))` in a crate that has the feature would anchor it.
- UD-2 `gate.rs:274-276` — every declared commitment measured "no" → refusal (15) — no test asserts it;
  `validate.rs:113-115` covers only the "unknown" note.
- UD-3 `gate.rs:135-144` — unknown provider name → note only, all provider checks skipped — a misspelt
  `provider = "ykcs1l"` silently disables placement/attestation checks in `validate`; only the note is tested.
- UD-4 `capabilities.rs:181` — `!cap.imported` refusal — tested only through camigrate's ykcs11 plan
  (static); no test drives `check_import` itself to refuse it (YubiKey suites are T-GATED).
- UD-5 `capabilities.rs:39` `ecdh_seals` (`derive_sealed == Some(false)` → never sealed) — no unit test;
  flipping it changes which session template is pre-asked, only caught if a provider refuses one (none does).

### crates/pkcs11/src/ops/mod.rs, src/token/mod.rs, src/token/generate.rs, src/token/login.rs, src/token/library.rs, src/token/rv.rs, src/token/types.rs, src/token/measure.rs, src/token/policy.rs, tests/logins.rs, tests/library.rs

#### B-4. A private data object (or any CKA_PRIVATE non-key) is "absent" without a login: `delete` drops its realisation from the lock and succeeds; `check` says 11 — medium — verified

`crates/pkcs11/src/ops/mod.rs:413,587-635` (guard at :618); `crates/cli/tests/reference/identity.rs:732-733`
What: `delete` and `create_absent` decide "a session without login cannot see it" by class
(`PrivateKey | SecretKey`). A `CKO_DATA` object whose spec declares `CKA_PRIVATE = true` (DESIGN §3.1
`valuehash`), or a public key/certificate a module keeps private (AWS CloudHSM makes every public key
private, generate.rs:270), is invisible to `C_FindObjects` without a login. On a token with no
`pinFile`, `cakeys delete <obj>` gets `find_key → None`, reports `absent`, removes the realisation
(`lock.realisations[spec].remove(token)`, :629-634) and writes the lock, while the object stays.
`check` reports 11 "not under its locator" instead of 16 "configure a PIN".
Why missed: T-ORACLE, D-PARALLEL. The one test of this path, `private_data_objects_are_identified_when_declared`,
asserts the misleading answer: `check ... --token ref-anon` == 11 with the comment "absent". The
login guard (e0aee60) and the private-data identity (later) arrived separately; nothing ties them.
Class: "is this object's material visible only under login" decided in three places by three rules:
`ops/mod.rs:413` and `:618` (class only), `core::Config::secret_material` (class + declared
`CKA_PRIVATE`, `config/mod.rs:336`), camigrate `file_verbs.rs:345` (`private_data`, re-derived). 4 sites.
Instance fix: guard on `cfg.secret_material(object)` (or the spec's `CKA_PRIVATE` flag) and refuse 16 in
`delete`, `resolve`/`check`. Class fix: one `Target::needs_login()` in core, used by every verb; change the
identity.rs oracle to expect 16.

#### B-5. Prior C-20 fixed in camigrate only: `Token::check` still counts the RSA modulus in whole bytes — low — verified

`crates/pkcs11/src/token/policy.rs:60-72`; sibling `crates/caprobe/src/probe/asymmetric.rs:402`
What: `size = nonzero_bytes * 8`, so a 2041–2047-bit RSA key passes a spec with `modulusBits = 2048`
(the live type check of every verb), and caprobe records a probed key's size the same way.
Why missed: T-INSTANCE, P-REVIEW. C-20's fix added a private `bit_len` to `camigrate/src/sealed.rs:785`
with its own test (`a_modulus_counts_its_bits`); nobody searched for the same computation. The
drift.rs test uses a modulus of a different byte length, so the off-by-bits case is untested.
Class: duplicated size arithmetic. 3 sites (sealed.rs fixed; policy.rs:62, asymmetric.rs:402 not).
Instance fix: compute bits as `bit_len` does. Class fix: one `cakeys_core::id::modulus_bits(&[u8])`, used
everywhere; a clippy `disallowed-methods`-style grep check for `len() * 8` on moduli.

#### B-6. Retry-on-any-failure survives prior B-8 in the by-name curve retry, and the by-name refusal ignores the 16/15 split 8aaba2e introduced — low — verified

`crates/pkcs11/src/token/generate.rs:158-167`
What: when no profile row answers (`ByName::Unprofiled`), any OID-form `C_GenerateKeyPair` failure —
`CKR_DEVICE_ERROR`, `CKR_PIN_EXPIRED`, `CKR_TEMPLATE_INCONSISTENT` from a policy attribute — triggers a
second generation by name. When both fail, `by_name_refused` returns 15 (`unsupported_for`) even for a
device failure, while every other generation failure is now 16 (`refused_generation`, 8aaba2e).
Why missed: T-INSTANCE. Prior B-8 restricted the ECDH fallback to template refusals; the sibling retry
here was not searched. 8aaba2e changed `generate_own` and the plain path but not the retry, and added
no test for the retry's code (the fault test `a_refused_curve_is_tried_by_name...` uses a profiled curve).
Class: fallbacks keyed on "any error". Instances in this area: by-name retry (here); the correct form
exists three times (B-8's ECDH fix, `with_public_default_dropped` on `AttributeValueInvalid` only, caprobe's
CTR retry on `CKR_MECHANISM_PARAM_INVALID` only), each with its own predicate.
Instance fix: retry only on `CKR_DOMAIN_PARAMS_INVALID`/`CKR_CURVE_NOT_SUPPORTED`/`CKR_ATTRIBUTE_VALUE_INVALID`;
route both failures through `refused_generation`. Class fix: one `template_refusal(rv)` predicate (exists in
possession.rs) required by every fallback.

#### Unguarded decisions (ops/mod.rs, token/*.rs above)

- UD-6 `ops/mod.rs:248-252` — attested scheme ≠ advertised scheme → 13 — no test (no test provider returns another scheme).
- UD-7 `ops/mod.rs:236-244` — attestation unavailable under a locked attestation → 14 — tested only in `cli/tests/tpm2.rs` (swtpm; Linux Nix check only; T-GATED on darwin).
- UD-8 `login.rs:74` — `pins.so.guard` (SO PIN locked / final try → refuse) — no test sets `CKF_SO_PIN_*`;
  `cli/tests/fault.rs:224-226` covers only the user flags. Deleting the line fails nothing.
- UD-9 `policy.rs:85-94` — key with no `CKA_VALUE_LEN` → 15 — no test.
- UD-10 `rv.rs:101-119` `device_failed` list — which errors are "the device" vs "the key" now decides 16
  vs 15 for generations and "absent" vs error for attribute reads; only `CKR_DEVICE_ERROR` is exercised
  (fault.rs:480). `CKR_USER_NOT_LOGGED_IN` / `CKR_FUNCTION_FAILED` on a read become "attribute absent".
- UD-11 `ops/mod.rs:428-443` — create refuses when objects of another class sit under the locator — tested by exit 13 only (create.rs:24), shared with other 13s.

#### Prior fixes checked here

- prior B-11 (SO credential not retried): holds; test `logins.rs:46` asserts prose, not call count — T-ORACLE but adequate.
- prior B-12 (already-logged-in PIN): holds (`login.rs:182-194`, `logins.rs:34`).
- prior B-6 (rv values from p11-names): holds (`rv.rs:34-39`, `every_variant_has_its_value`).
- prior B-14 (`Limit` spelled): holds; `measure.rs:112` has no unit test (low).
- prior B-26 (one `unpadded`): holds (`library.rs:107`).

### crates/pkcs11/src/token/identity.rs, possession.rs, host.rs, public.rs, uri.rs; src/templates.rs; src/registry.rs; src/providers.rs; src/resolution.rs; tests/templates.rs

identity.rs, possession.rs: all five proofs host-verified against a fresh challenge; prior B-7 (32-byte
`pop::secret`, possession.rs:290-293) and prior B-8 (`template_refusal` only, :183-187) hold. host.rs:
plaintext only in `Secret`/`Zeroizing`; clean. public.rs, uri.rs: clean.

#### B-7. A code provider's name resolves to a hook-less data provider when its crate is not linked — medium — verified

`crates/pkcs11/src/registry.rs:52-61`, `crates/cli-common/src/lib.rs:23-29`, `profiles/modules/ykcs11/2.7.toml` (`[match] manufacturer`)
What: `named_in` falls back to `Data(family)` for any profile family. `ykcs11` and `tpm2-pkcs11` are both
code providers (cargo features) and profile families. In a build without the feature (the shipped `cakeys-minimal`
package, `nix/package-crane.nix:79-83`, `--no-default-features`; every darwin build lacks `tpm2`,
`nix/package-common.nix:28`; or a downstream `Registry::new()`), `provider = "ykcs11"` is
not "unknown provider" (17) but `Data("ykcs11")`, and an unnamed YubiKey auto-detects to it by
manufacturer. Every static safety fact silently takes its default: no `placement` (prior B-3's f9 rule),
`manages_as_so() == false` (so caprobe's scratch-slot guard at `caprobe/src/probe.rs:199` does not run),
no destroy refusal, no attestation; the lock records `provider = "ykcs11"` as if it were the real one.
Today the device's own SO requirement makes the writes fail rather than land; the guard is the
device, not cakeys. (A lock that records an attestation still gets 14 on `check`: ops/mod.rs:236-244.)
Why missed: D-SEAM, T-ABSENT. `registry.rs:159` tests that a family is "selectable by name" — the
intended behaviour — but nothing asserts that a family which *also* has a code provider is refused when
the code is absent. Every test and CI build uses the default features.
Class: safety rules attached to a provider *implementation*, selected by a *name* two registries share.
Instances: ykcs11 (placement, SO, destroy, attestation, scratch companion), tpm2-pkcs11 (attestation,
`tpm2_ptool` import, EC point repair), aws-cloudhsm (repairs; but always linked). 2 live.
Instance fix: `named_in`/`select_in` refuse (17) a family whose name is a known code provider's
(`cakeys_pkcs11::KNOWN_CODE_PROVIDERS`) when the registry lacks it. Class fix: a profile declares
`requires-code = true`; resolution refuses a Data provider for such a family.

#### B-8. No test pins the security attributes of cakeys' session templates — medium — verified

`crates/pkcs11/src/templates.rs:226-282` (`session`)
What: `HostKek` (`CKA_EXTRACTABLE = false`), `ImportKek`, `RebindKek`/`RebindCopy` (sensitive, not
extractable), `ExportKek` (`CKA_SENSITIVE = true`), `ProofSecret{sealed}` decide whether the host's KEK,
a commitment copy or a sealed export key can be read off the token. Flipping any of them passes every
test: `tests/templates.rs` checks only *which* templates the provider was asked (`kind(req)` strings),
and the runs succeed either way.
Why missed: T-ORACLE, T-ABSENT. Tests assert the operation worked, not the property the attribute exists
for. Combined with B-3 (a provider may rewrite them), nothing holds these attributes at all.
Class: security properties expressed as template literals with no property test. Instances: 8 session
templates; `generation_key`/`import_key` carry no sensitivity defaults at all (by design: the spec's).
Instance fix: a unit test asserting, per `SessionKey`, `CKA_TOKEN = false` and the expected
`CKA_SENSITIVE`/`CKA_EXTRACTABLE`; a token-suite test reading them back from the created session object.
Class fix: a typed `SessionTemplate { sensitive, extractable, ... }` whose constructor is the only way to
build one, plus the post-adjustment check of B-3.

#### B-9. `clear_hardware_rows` keeps 12 of 20 capability kinds from another hardware's profile — low — verified

`crates/pkcs11/src/resolution.rs:409-427`
What: on other or unknown hardware the profile's `Prove`, `Commit`, `Crypt`, `DeriveSealed`,
`DeriveReadOnly`, `Move` and `Delete` rows plus `Kdf`, `DeriveEcdh`, `Sign`, `Encapsulate`, `Attr` still answer (12 kept, 8 cleared). The gate refuses on a carried `prove.*` or
`commit.*` "no" (gate.rs:178-185, 274-276) for hardware that was never measured, and a carried
`derive.ecdh.sealed = no` changes the proof path. Wrong refusals, not wrong acceptances.
Why missed: D-PARALLEL, T-ABSENT. A hand-written `matches!` list over a 20-variant enum; `clear_hardware_rows` dates from 3ce84ce
(11-13), `Prove` arrived in eda0c66 (11-15), `Commit`/`Crypt` in fcd2779 (11-19): later variants were never classified. No test of `clear_hardware_rows` names the kinds it keeps.
Class: non-exhaustive classification of an enum that grows. Instance/class fix: an exhaustive `match`
returning `hardware_dependent: bool` per variant, so a new variant does not compile until classified.

#### Unguarded decisions (identity, possession, templates, registry)

- UD-12 `identity.rs:117-146` `check_kind` (a stand-in public key of another type/curve) — no test names it;
  under `token-asserted` it is the only guard against another key's public object.
- UD-13 `identity.rs:99` cross-check of a public-key-object stand-in — tested only via the private key's
  own `CKA_PUBLIC_KEY_INFO` (`drift.rs`, `references.rs`); removing :99 alone fails nothing found.
- UD-14 `possession.rs:446-478` `proof_failure` mapping (which `CK_RV` is 13 "wrong key" vs 15 vs 16) — only
  the swapped-key 13 is tested (`fault.rs` `use_label`); `KeyFunctionNotPermitted` → 15 untested for decrypt/unwrap.
- UD-15 `possession.rs:23-41` `recorded_binding` (`CKA_ALWAYS_AUTHENTICATE` → pop-sign-pin, others refused 16) —
  only on SoftHSM objects created with the flag; the refusal branch for pop-ecdh/decrypt/unwrap has no test.
- UD-16 `templates.rs:226-282` — see B-8.
- UD-17 `registry.rs:88-90` code-before-data detection order — tested (`registry.rs:175`). Guarded.

### crates/ykcs11: Cargo.toml, build.rs, src/lib.rs, src/attest.rs, roots/*, tests/fixtures/*

Prior B-3 (placement): the provider rule holds and is unit-tested (`lib.rs:311-321`); its reach is B-1/B-2.
Prior D-1 (placeholder is no scratch companion): holds, fixture-tested (`lib.rs:335-348`). build.rs pins
the roots by SHA-256: clean.

#### B-10. Prior "ykcs11 lib.rs F1" fixed in code only: a YubiHSM 2 still auto-detects as `ykcs11`, through the profile family — medium — verified

`crates/pkcs11/src/registry.rs:88-94`, `profiles/modules/ykcs11/2.7.toml:46-47`, `crates/profile/src/lib.rs:226-236`
What: ab58460 (11-18) made `Ykcs11::matches` require the description "PKCS#11 PIV Library" because
`yubihsm_pkcs11` reports the same manufacturer. But `select_in` then falls through to
`set.module_families(manufacturer)`, which matches the ykcs11 *profile's* `[match] manufacturer =
"Yubico (www.yubico.com)"` alone, so a YubiHSM 2 gets `Data("ykcs11")` and the `ykcs11/2.7` module
profile (a single candidate is chosen whatever its version, `resolution.rs:366`). Its `move.export = no`,
`move.unwrap = no`, `prove.*`, `commit.*` and subtract rows (not hardware-cleared, B-9) decide the gate and
camigrate's plan for a different device; the lock records `provider = "ykcs11"`. Only a "matched by
manufacturer alone" note says so. ISSUES.md:143 records the issue as fixed.
Why missed: D-PARALLEL, T-INSTANCE, P-REVIEW. Two detectors (code `matches`, profile `[match]`) for one
decision; the regression test `only_the_piv_module_is_ykcs11` asserts the code detector only, and no
`registry.rs` test passes a Yubico manufacturer. The data fallback (9837f57, 11-14) predates the fix, so
the fix's author had both paths in front of them.
Class: provider detection by profile manufacturer, where one manufacturer string covers several modules.
Instances: ykcs11 (live); kmsp11's "Google" and CloudHSM's "CloudHSM" are single-product today. 1 live.
Instance fix: when a registered code provider *of that family* declined the module, `select_in` must not
fall back to the family's data provider. Class fix: profile `[match]` gains `description`, and detection is
one function shared by code and data (a code provider's `matches` defaults to its profile's `[match]`).

#### B-11. The piv-attestation check that the slot certificate was signed by the device key has no test — medium — verified

`crates/ykcs11/src/attest.rs:67-71`
What: `verify_signed_by(&slot, &device)` is what ties the slot's attestation to a genuine device. Without
it, any public f9 certificate that chains to Yubico (they are not secret) plus a self-signed slot
certificate naming the attacker's key attests that key. Deleting the call fails no test: the only fixture
chain is coherent, and the negative tests are "other material" and "no anchor" (`attest.rs:211-229`).
`core/src/chain.rs:570-580` tests `verify_signed_by` itself, not this call site.
Why missed: T-FRIENDLY, T-ABSENT. Fixtures are one well-formed chain; no forged chain (slot signed by
another key, a non-PIV device CA, a 4-link chain) is modeled. Hardware tests are gated and positive.
Class: attestation verifiers tested only on coherent chains. Instances: this; tpm2 (see B-13).
Instance fix: a fixture `slot-other.pem` signed by a second key, asserting `Conflict` "not signed by the
device". Class fix: a shared forged-chain test kit (`cakeys_core::chain::test_forgeries`) every scheme
must run: wrong signer, wrong subject key, extra link, non-CA issuer, out-of-date.

#### Unguarded decisions (ykcs11)

- UD-18 `attest.rs:67` — slot signed by device — see B-11.
- UD-19 `attest.rs:63` — chain length 3 — no fixture longer than 2 links.
- UD-20 `lib.rs:223` — the non-empty slot suffix that keeps the f9 cert from being taken as the slot's —
  no test (needs a session; hardware only).
- UD-21 `lib.rs:137-142` — keys are never claimed deleted — only `cli/tests/yubikey.rs:203` (hardware, env-gated, never Nix).
- UD-22 `lib.rs:149-153` — `CKA_DERIVE` repair for EC/Montgomery — only hardware tests.

### crates/tpm2-pkcs11: Cargo.toml, build.rs, src/lib.rs, src/ptool.rs, src/attest/{mod,vendor,esys,store,ek,credential}.rs, roots/*, tests/fixtures/*

Where it is tested (no `tests/` dir): inline unit tests (plain `cargo test`, Linux only: on darwin the crate
is excluded from the workspace scope, `nix/package-common.nix:95-100`); `crates/cli/tests/tpm2.rs` and
`crates/caprobe/tests/tpm2.rs` on swtpm with nixpkgs' module and the vendor-patched one
(`CAKEYS_TPM_MODULE`/`CAKEYS_TPM_VENDOR_MODULE`, required in the Linux Nix check, `nix/token-env.sh:63-66`);
AMD fTPM only opt-in (`CAKEYS_FTPM_ATTEST`).

lib.rs (`fix_ec_point`: proptest + Kani + fuzz), ptool.rs (memfd, PIN redacted, ID-as-text refused before
the tool), store.rs, ek.rs, credential.rs: clean. The hostile *store* is modeled well (`tpm2.rs:893-983`:
extractable lie, swapped blobs, symmetric swap; `:984-1044` the B-1 copy).

Prior B-1 (secret key bound by TPM2_HMAC with the certified object): holds on the store path
(`esys.rs:596-610`, test `tpm2.rs:1036-1038`). Prior B-2 (akLabel caveat): holds (`mod.rs:310-315`, test
`tpm2.rs:1173`). Prior B-13 (two tokens of one label): holds (`store.rs:141-152`, test `store.rs:528-530`).
Prior B-22: see Prior fixes section.

#### B-12. tpm-certify's checks against a lying module or a TPM interposer have no test; only the lying store is modeled — medium — verified

`crates/tpm2-pkcs11/src/attest/vendor.rs:178-197`, `esys.rs:389-391`, `esys.rs:759-768`, `attest/mod.rs:318-328`, `attest/mod.rs:133-145`
What: on the vendor route the module returns the statement, the object's public area (`CKA_TPM2_PUB_BLOB`)
and runs the certify; the host's defenses are the nonce check, the Name-vs-reported-blob check, the
qualified-signer check and the material cross-check. On the store path, with password sessions (no EK),
the TPM responses are unauthenticated; the defenses are the nonce, the attested Names vs the loaded object,
and the qualified signer. None of these seven `Conflict`s is asserted by any test (rg of each message:
source only). Also untested: the module route's refusal of a secret key (`mod.rs:318-328`, the second
path of prior B-1: without it the vendor route would certify a secret key bound to nothing), and
`refuse_ek_for_module` (`mod.rs:133-145`: without it an `ekCertificate` would be silently dropped to trust on
first use). Deleting any one fails nothing.
Why missed: T-FRIENDLY, T-ABSENT. The vendor suite runs the honest patched module; p11-fault can model a
lying one (`Corrupt` on `C_Sign`'s output, `attribute = "CKA_TPM2_PUB_BLOB"` with `value`/`from_label`), but
`tpm2.rs` uses the shim only to truncate `CKA_EC_POINT` and drop attributes (`tpm2.rs:188,1363`). Prior B-1's
fix (6900764) tested the store path alone: T-INSTANCE.
Class: attestation verifiers whose negative paths are modeled for one adversary (the store file) and not
the others (module, transport). With B-11: 10 unguarded verifier checks across 2 schemes.
Instance fix: vendor-suite tests through the fault shim: `C_Sign` corrupted (signature), `CKA_TPM2_PUB_BLOB`
from another key (Name), the vendor route with `class = CKO_SECRET_KEY` (15), `ekCertificate` with the
vendor module (15). Unit tests of `verify_certified` with a statement for other Names and another signer
(the `certify_statement` helper at `esys.rs:1170` already builds them). Class fix: per scheme, a table of
adversaries (store, module, transport, chain) × checks, each row a test, kept beside the verifier.

#### Unguarded decisions (tpm2-pkcs11)

- UD-23 `mod.rs:318-328` — vendor route refuses a secret key — see B-12.
- UD-24 `mod.rs:133-145` — `ekCertificate`/`ekRoots` refused on the module route — see B-12.
- UD-25 `vendor.rs:185-197`, `esys.rs:389,759,766` — nonce, Names, signer — see B-12.
- UD-26 `ek.rs:72-77` `from_nv` — an NV EK certificate that does not parse is silently first use
  (`.and_then(|der| Cert::from_der(der).ok())`, `ek.rs:62`): no test; a lock pinned to the EK root still
  gets 13 on `check`, so it is a first-lock weakness only.
- UD-27 `esys.rs:820` `extractable = !(fixedTPM || fixedParent)` — mirrors the module's derivation; tested
  only via the store-lie test (`tpm2.rs:914-922`), which flips the module side, not this formula.

### crates/kmsp11: Cargo.toml, src/lib.rs, src/keys.json; crates/aws-cloudhsm: Cargo.toml, src/lib.rs

kmsp11: clean. `algorithm_for` + core `plan.rs:187-217` (binding needs its usage flag) + the sign-and-decrypt
refusal keep every binding on a key that can prove it; `check_reported` refuses what libkmsp11 would not
show, before a CryptoKey ID is used up. Detection (`"Google"`) agrees with the profile's `[match]` (B-10's
class: consistent here). Known open (not a finding): ISSUES.md B11, the PSS/SHA-512/OAEP proofs never run
on Cloud KMS (`lib.rs:323-327` says so) — P-UNRUN evidence, recorded.
aws-cloudhsm: clean. `ec_point`/`key_type`/`stand_in` unit-tested (`lib.rs:111-141`); the stand-ins are
relied on only where a measured profile `add` row says so. Its live paths are `cli/tests/cloud.rs`, opt-in
(`CAKEYS_TEST_AWS`, `CAKEYS_TEST_GCP`), never in Nix or CI.
Unguarded: none beyond the hooks' unit tests; the `generation` hook's template replacing the spec's
policy entirely (`kmsp11/src/lib.rs:385-388`) is the documented contract (prior ISSUES §4 (b)).

### crates/p11-fault: Cargo.toml, src/lib.rs, src/forward.rs, src/hooks.rs, src/plan.rs, src/trace.rs

Clean (darwin injection out of scope). Prior B-16 (`named()` count past the batch): holds, `hooks.rs:487-494`,
test `a_count_past_the_batch_is_named`. Prior B-17 (RO session beside SO): holds, `hooks.rs:466-470`, test
`a_label_resolves_beside_an_so_session`. Prior B-18 (hand-synced function lists): holds, `plan.rs:247-249`
derives them from the `forward!` table. The trace reads only `CK_ULONG` values: no PIN or key bytes.

What tests inject (rg of plan text in `crates/*/tests`, `nix/*.nix`): `rv` (~43 rules; 16 distinct CKRs,
`CKR_DEVICE_ERROR` 32 of them), `use_label` on `C_SignInit`/`C_DeriveKey`/`C_DecryptInit`/`C_UnwrapKey`,
`corrupt` on `C_Sign` and `C_Decrypt` (`cli/tests/fault.rs:269-270`), attribute `value`/`from_label`/`truncate`/
`drop`/`length`, `add_label`/`hide_label`, `set_flags` (user PIN flags only), `hide_mechanisms`, `abort`.
PoP forgery coverage is good: a swapped key for 4 of 5 proofs → 13, corrupted signature/plaintext → 13,
another key's `CKA_PUBLIC_KEY_INFO` → 13 (`cli/tests/fault.rs:236-283`).

Plausible hostile behaviours never modeled (T-FRIENDLY), modelable today unless noted:

1. `C_DestroyObject` answering `CKR_OK` and keeping the object (`rv = "CKR_OK"`, before) — see B-13.
2. A lying vendor certify (`corrupt` on `C_Sign` with `CKM_TPM2_CERTIFY`, `CKA_TPM2_PUB_BLOB` from another key) — B-12.
3. `C_Login` answering `CKR_OK` without logging in (`rv = "CKR_OK"`, before): private objects then read as absent (B-4, UD-10).
4. An attribute that changes between two reads of one run (attribute rule with `call = n`): never used; every attribute rule fires on every call.
5. Session or device loss mid-run: `CKR_SESSION_HANDLE_INVALID`, `CKR_DEVICE_REMOVED`, `CKR_TOKEN_NOT_PRESENT`, `CKR_USER_NOT_LOGGED_IN`, `CKR_FUNCTION_FAILED`, `CKR_OBJECT_HANDLE_INVALID` are never injected (UD-10's list; `generate.rs:255` tolerates `OBJECT_HANDLE_INVALID` after the first handle, untested).
6. pop-unwrap's host MAC check: the swapped key fails inside SoftHSM (16, `fault.rs:253`), and no `corrupt` targets the unwrap proof's `C_Sign`, so the host comparison for pop-unwrap is never reached with a wrong value; pop-sign-pin's key swap is never tried.
7. Not modelable: a two-call length that grows between the size query and the fetch, `C_GetMechanismInfo` lies (sizes, flags), a module that hangs.
8. SO PIN flags (`CKF_SO_PIN_*`) never set (UD-8).

#### B-13. `delete` trusts `CKR_OK` from `C_DestroyObject`; the measured `delete.<class>` answer is never read — medium — plausible

`crates/pkcs11/src/token/generate.rs:244-260`, `crates/pkcs11/src/ops/mod.rs:611-634`, `crates/caprobe/src/probe/scratch.rs:185-192`, `profiles/modules/tpm2-pkcs11/1.10+swtpm.toml:119,201`
What: `destroy_plain` counts every handle it was given as destroyed when the module answers `CKR_OK`; `ops::delete`
then says "destroyed N object(s)" and removes the realisation from the lock. Nothing re-finds the locator. The probe
measures exactly this (`delete.<class>`: "C_DestroyObject really removing an object"), and the committed tpm2-pkcs11
profile records `delete.CKO_PRIVATE_KEY = no` ("C_DestroyObject leaves 4 of 6 behind"), yet no consumer reads a
`Delete` row (rg: only `capability.rs` and the probe). Tpm2Pkcs11 has no `destroy` override. If the module answers
`CKR_OK` (the probe ignores the rv, so which it is is not recorded: plausible), `cakeys delete` on a tpm2 private key
reports success, the lock forgets the key, and the key stays on the token. ykcs11's same behaviour is caught only
because its provider hard-codes a refusal (`ykcs11/src/lib.rs:136-142`), which B-7's minimal build drops.
Why missed: T-FRIENDLY, T-ABSENT, D-PARALLEL. `delete` is tested on SoftHSM (`cli/tests/reference/delete.rs`),
whose destroy works; no tpm2 suite test deletes; the fault shim can answer `CKR_OK` without the call but no test does.
The knowledge exists twice (ykcs11's code, the profile row) and is consumed once (the code).
Class: measured profile facts that no decision reads; module behaviour the provider code re-states by hand.
Instances: `delete.*` (write-only); ykcs11's hand refusal vs its own unrecorded delete rows. 1 class, 2 instances.
Instance fix: after `destroy_identified`, re-find the locator; any object still there is `Unavailable` (16) and the
lock is kept. Refuse (15) up front when the resolved profile answers `delete.<class> = no`. Class fix: every
`Capability` kind has a named consumer or is marked `informational` in the enum, checked by a test that walks the enum.

#### Unguarded decisions (p11-fault)

- UD-28 `plan.rs:279-281` "when goes with rv" and the other plan refusals — unit-tested (`plan.rs` tests). Guarded.
- UD-29 `hooks.rs:240-243` corrupt only within the caller's room — tested (`corruption_stays_inside_the_callers_buffer`). Guarded.
