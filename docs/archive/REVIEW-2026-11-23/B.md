# Area B: Token layer, providers, PKCS#11 plumbing

## Summary

The token layer is careful where it matters most: proof of possession is host-verified against a fresh nonce for every binding, `CKA_PUBLIC_KEY_INFO` and every stand-in public key are cross-checked, reads that fail on the device are never taken for "absent", secrets sit in `Zeroizing`, SO steps report the step before any session trouble, and p11-fault's unsafe code is sound: lengths are clamped, panics are caught, and there is no aliasing.

All 60 findings from 2026-11-18 for files in this area are marked Fixed. I spot-checked 12 of the fixes and none has regressed.

The biggest risks are in attestation trust:
- **High:** `tpm-certify` of a secret key is not bound to the key's material (B-1).
- **Medium:** on the `akLabel` vendor route, the signer's public key is whatever the module reports (B-2).
- **Medium:** ykcs11's PIV slot rule is enforced only inside a run-time `create` override. The static gate and camigrate imports never apply it (B-3).

The biggest simplification wins:
- Delete the unused `Provider::template` seam and its "ask before creating" machinery (about 650 lines across four crates).
- Turn ykcs11's two operation overrides into static facts. The `create`/`destroy` hooks then go, which also fixes B-3.
- Get `CK_RV` values from p11-names, which removes the behaviour-changing `rv-value` feature.
- Split `token/mod.rs` (6 concerns) and `provider.rs` (ChainTime and Registry are not provider concerns).

## Findings

### B-1. A secret key's `tpm-certify` attests whichever TPM object the module points at, not the key's material — high — 2 — verified
`crates/tpm2-pkcs11/src/attest/esys.rs:685-705` (`cross_check`: `(None, None) => Ok`), `attest/mod.rs:351-367`, `attest/vendor.rs:161,207-208`, `attest/mod.rs:229-231`

**What happens.** For `CKO_SECRET_KEY`, `ctx.spki` is `None`. Which TPM object gets certified is decided only by data the module supplies:
- Store route: the `CKA_ID` and label the module reports for `ctx.key` select the store row (`store.find`).
- Vendor route: the module reports the object's `CKA_TPM2_PUB_BLOB` and runs the certify itself.

`cross_check` then passes any symmetric TPM object. The only link is that `CKA_LOCAL`/`CKA_EXTRACTABLE` must be equal (`mod.rs:324-334`).

**Trigger.** A lying module, a tampered or duplicated store row, or a `tpm2Store` that names another store. The module reports another HMAC key's `CKA_ID`, or that key's public blob, for the key under commitment. The commitment (computed through PKCS#11) passes for key K. The attestation certifies the Name of K', another TPM-resident keyed-hash object, and `lock` pins that ID.

**Consequence.** `tpm-certify` on a secret key does not prove that K is resident. DESIGN §8.1 says "the attested key must be the material the object's portable scheme names", and `mod.rs:229-231` says the "Name and SPKI checks bind the row to the live object". Neither holds without an SPKI.

**Fix.** On the store route, after `TPM2_Load`, compute the commitment with the loaded object (`TPM2_HMAC` for KeyedHash, `TPM2_EncryptDecrypt` for SymCipher where its mode allows) and compare it with the commitment ID this run computed through PKCS#11. On the vendor route, refuse `tpm-certify` for secret keys until the module can prove the same. At minimum, correct DESIGN §3.7/§8.1 and the comment at `mod.rs:229-231`.

### B-2. On the `akLabel` route the AK's public area is module-asserted, so the module can forge every statement — medium — 2,3 — verified
`crates/tpm2-pkcs11/src/attest/vendor.rs:1-10,224-311`

**What happens.** With `options.akLabel`, the signer's key and its "restricted, fixedTPM" attributes come from the module's `CKA_TPM2_PUB_BLOB` of the AK object (`token_ak`, then `check_ak`). Nothing from the TPM authenticates them, and `qualified_signer` is not checked.

**Trigger.** A module with no TPM behind it can make its own P-256 key and report a blob with `restricted|fixedTPM` set. It can then sign any `TPMS_ATTEST` naming any Name, including signed attributes that make `CKA_LOCAL` true for an imported key. `lock` pins the forged AK as `root`.

**Consequence.** The module header says "The module is no more trusted than on the store path". That is false here: `check_ak` guards against a mis-labelled key, not against the module. With `akHandle`, the AK is read through ESYS from the TPM.

**Fix.** State in `vendor.rs` and DESIGN §8.2 that on the `akLabel` route the AK and its attributes are TOFU-asserted by the module, not by the TPM. Alternatively, read the AK's public area through ESYS whenever a TCTI is configured, or require the EK activation (`CKM_TPM2_ACTIVATE_CREDENTIAL`) before `akLabel` is accepted.

### B-3. ykcs11's PIV-slot locator rule is enforced only in its `create` override: the static gate and imports skip it — medium — 3,1 — verified (gate path); plausible (f9 overwrite)
`crates/ykcs11/src/lib.rs:65-84,122-125`; `crates/pkcs11/src/gate.rs:146-153`; `crates/pkcs11/src/ops/capabilities.rs:157-160`

**What happens.**
- The rule (`CKA_ID` alone, 01–18; no label; never 19 = f9) runs only from `Provider::create` at run time.
- `gate::check` and `check_capabilities` ask only `Provider::generation`, which ykcs11 does not override. So `cakeys validate` and `create --dry-run` pass a ykcs11 spec with a label locator or `CKA_ID = "19"`, and the error comes only after the token is opened.
- camigrate's `piv-import` (`host.rs` `landing` → `ops::check_import` → `Token::create_private`) never goes through `Provider::create`, so imports apply no slot rule at all.
- If ykcs11 takes a `C_CreateObject` private key at `CKA_ID` 0x19 and does not list an f9 private-key object for `Token::occupied` to collide with, an import would overwrite the device attestation key. Yubico: that key cannot be restored.

**Fix.** Make the rule a static provider fact that every creation path asks: the gate, the generation and the import check. One way is to extend `generation` into a `plan_create(object, spec, loc, binding) -> Result<Option<Generation>>` that ykcs11 implements for the locator check, and to call it from `check_import` too. Then delete the `create` override (see proposal 2).

### B-4. `Provider::template` has no implementor, yet every template in four crates is pre-asked through it — medium — 4 — verified
`crates/pkcs11/src/provider.rs:141-168,356-478`; `ops/capabilities.rs:42-148`; `gate.rs:180-196,345-385`; `token/mod.rs:615-622`; `generate.rs:84-113`; `identity.rs:360-368`; `tests/templates.rs` (225 lines)

**What happens.** ARCHITECTURE says "No in-tree provider overrides it yet", and `rg 'fn template'` confirms that only test providers do. Supporting it takes:
- 6 `Template` variants, 8 `SessionKey` variants, `Declared`/`Half`/`Via`/`Attributes`;
- `session_templates`, `check_templates` and `plan_templates`;
- the gate's asks, camigrate's `tokens::template_refusal`/`source_refusal`/`target_refusal` (about 120 lines), and the caprobe asks;
- two test files: `pkcs11/tests/templates.rs` and `caprobe/tests/template_hook.rs`.

**Cost.** About 650 lines that exist for a hook whose only candidate user, the CloudHSM Ed25519 import in OPEN.md, is "untried".

**Fix.** Delete the hook and the asking machinery, and keep the `templates.rs` builders. Re-add the hook with its first real user.

### B-5. `token/mod.rs` and `provider.rs` each mix several concerns; `Token` carries probe-only API — medium — 3,4 — verified
`crates/pkcs11/src/token/mod.rs:160-247` (library registry), `288-407` (`CK_RV` naming and error mapping), `65-109,946-1021,1131-1191` (PIN guard, login, SO), `673-725,129-131,537-549,656-667` (probe-only: `mechanism_info(s)`, `token_claims`, `rsa_bits`, `unprofiled`, `advertised`), `1193-1286` (core↔cryptoki type mapping); `provider.rs:572-657` (`ChainTime`), `722-826` (`Registry`)

**What happens.** `token/mod.rs` is 1,398 lines covering six unrelated concerns. Several public `Token` methods exist only for caprobe. `ChainTime` (certificate-date policy) and `Registry` sit in `provider.rs` but are not about providers.

**Fix.** See complexity proposal 4.

### B-6. The `rv-value` feature (and its patch coupling) is avoidable: p11-names already maps names to values — medium — 4 — plausible
`crates/pkcs11/src/token/mod.rs:300-325`, `binding.rs:42-44,82-93`, `Cargo.toml:30-34`, `tests/patched_cryptoki.rs:10`

**What happens.** Without the feature, `rv_value` returns `None` for every standard error, which is why caprobe must refuse to write profiles in a plain cargo build (prior Cargo F1). But `derived_name(rv)` already equals cryptoki's patched name for every variant (`names_agree`), and `p11_names::rv(name)` gives the `CK_RV`. That combination works in every build, so `rv_is` and `KmError::rv()` would work unpatched.

**Fix.** Implement `rv_value(rv) = p11_names::rv(&derived_name(rv))`, plus the vendor and unknown arms. Then drop the feature, the `RV_VALUE` const, the cfg arms, the rv-value part of the patched-binding test and caprobe's `build_lacks` rv-value branch.

It is plausible rather than verified because it depends on p11-names `RV` covering every `CKR_*` cryptoki has a variant for. Its doc claims it does; a test can assert it.

### B-7. `pop-decrypt` on an RSA-1024 key cannot fall back past SHA-1 OAEP — low — 1 — verified
`crates/pkcs11/src/token/possession.rs:293-303`; `crates/core/src/pop.rs:25-28`

**What happens.** The challenge is 78 bytes (14 + 32 + 32). OAEP-SHA256 on a 128-byte modulus carries at most 62. When a token refuses SHA-1 OAEP parameters at `C_DecryptInit`, the loop moves to SHA-256, and `pop::rsa_encrypt(...)?` fails with "message too long" (16). That error is neither the next try nor the token's refusal. DESIGN supports RSA from 1024 bits.

**Fix.** Encrypt a 32-byte random secret and compare it, as `pop-unwrap` does. The binding to the SPKI comes from encrypting to it.

### B-8. `prove_ecdh` retries the extractable form after any derive failure — low — 1,5 — verified
`crates/pkcs11/src/token/possession.rs:174-185`

**What happens.** `Err(refusal) => return extractable_after(...)` catches every non-`Conflict` error from `derive_for_proof`, including `CKR_KEY_FUNCTION_NOT_PERMITTED` (no `CKA_DERIVE`) and device errors. Each of those runs a second `C_DeriveKey`.

**Conflict with the docs.** The comment ("Only that refusal") and DESIGN §3.6 ("a derivation that ran and failed is never retried") say this should not happen. `derive_any` has already tried the template variants.

**Fix.** Fall back only on `template_refusal`-class return values.

### B-9. A provider's hint is appended to every `Unsupported` error of its token — low — 6 — verified
`crates/pkcs11/src/token/mod.rs:553-561`

**What happens.** `Token::unsupported` always adds `hint()`. Examples:
- On tpm2-pkcs11, a missing `CKM_ECDSA_SHA512` for a proof reads "... (hint for tpm2-pkcs11: secret keys cannot be generated through tpm2-pkcs11 ...)".
- On kmsp11, every refusal carries the 30-day destruction note.

**Fix.** Make hints per cause, for example `hint(&self, about: HintTopic)`, or attach a hint only at the sites it describes (generation for tpm2, creation for kmsp11).

### B-10. `read_attribute` is duplicated verbatim in two provider crates, tests included — low — 4 — verified
`crates/ykcs11/src/lib.rs:270-280,334-345`; `crates/tpm2-pkcs11/src/attest/mod.rs:392-402,513-524`

**Fix.** Add one `pub fn` in `cakeys_pkcs11::token`, next to `if_readable`, or a method `AttestCtx::attribute(t)`.

### B-11. SO PIN counters are read once at open, so a second `as_so` retries a credential that just failed — low — 1,2 — plausible
`crates/pkcs11/src/token/mod.rs:963`

**What happens.** `self.pins.so.guard` uses the flags from open. After a failed `C_Login(SO)`, a later `as_so` on the same `Token` tries the same credential again, possibly on the final try. No current caller continues after the first SO failure (`create_selected` breaks; caprobe stops), so this is latent.

**Fix.** Mark the SO credential as failed in the `Token` (a `Cell`) or re-read `C_GetTokenInfo` before each SO login.

### B-12. `CKR_USER_ALREADY_LOGGED_IN` at open keeps an unvalidated PIN — low — 2 — plausible
`crates/pkcs11/src/token/mod.rs:1159-1160,988-991`; `possession.rs:142`

**What happens.** When another `Token` of the same slot in the process already logged in, a wrong `pinFile` is accepted and stored. It is later used for `CKU_CONTEXT_SPECIFIC`, which can spend a PIV retry, and for the TPM unseal. DESIGN §3.6 says the context login "cannot be wrong".

**Fix.** Treat "already logged in" as validated only when this process logged in with the same PIN, or log in context-specifically only after a successful user login of this `Token`.

### B-13. The tpm2 store reader picks the first `tokens` row by label and ignores `tokenSerial` — low — 1 — plausible
`crates/tpm2-pkcs11/src/attest/store.rs:122-134`

**What happens.** `query_row` silently takes the first match. With two store tokens of one label (which PKCS#11 resolves by `tokenSerial`), the seal and rows can come from the other token. For a secret key that compounds B-1.

**Fix.** Refuse more than one row (12), or match the serial.

### B-14. `token_claims` writes cryptoki's `Debug` of `Limit` into committed profiles — low — 7 — verified
`crates/pkcs11/src/token/mod.rs:721-722`; e.g. `profiles/modules/kmsp11/1.9+hsm.toml:166-167` (`"Infinite"`)

**What happens.** The profile format depends on a dependency's `Debug` output, so a cryptoki update can drift committed profiles.

**Fix.** Format explicitly, for example `infinite`, `unavailable` and the number.

### B-15. p11-names is a crate for one user, and its doc claims a user it does not have — low — 4,5 — verified
`crates/p11-names/src/lib.rs:1-4`; `docs/FAULT_SHIM.md:51`

**What happens.** Both places say `cakeys_pkcs11`'s `rv_name` uses it. It does not: `cakeys-pkcs11` does not depend on it, and only p11-fault does (4 call sites). Its 482-line `MECHANISM` table only serves `hide_mechanisms`.

**Fix.** Fold it into p11-fault as `names.rs`, or give it the user B-6 proposes, and fix both docs.

### B-16. p11-fault `named()` slices the module's batch by an unchecked count — low — 1,7 — verified
`crates/p11-fault/src/hooks.rs:478-482`

**What happens.** `&batch[..n]` panics when a module reports `n > 16`. `guard` turns the panic into `CKR_GENERAL_ERROR`, with no message and no trace line. This is the same class as the fixed hooks F2.

**Fix.** Use `.min(batch.len())`, or return a `Fatal` that names the module's count.

### B-17. p11-fault resolves labels in a read-only session, which fails while the client holds an SO R/W session — low — 1 — plausible
`crates/p11-fault/src/hooks.rs:466`

**What happens.** PKCS#11 refuses a read-only `C_OpenSession` while an SO R/W session exists (`CKR_SESSION_READ_WRITE_SO_EXISTS`). Any label rule (`use_label`, `of_label`, `add_label`, `from_label`) on a call made during an SO step (ykcs11 generation, a trusted copy) becomes a `Fatal`.

**Fix.** Retry with `CKF_RW_SESSION`.

### B-18. p11-fault's `KEY_FUNCTIONS` and `OUTPUT_FUNCTIONS` are hand-synced with the `forward!` annotations — low — 4 — verified
`crates/p11-fault/src/plan.rs:245-256` vs `forward.rs:141-174`

**What happens.** A function added to the list without the hook gives a rule that parses and never fires, the "test of nothing" the plan parser exists to refuse.

**Fix.** Generate both lists from `=> substitute_key` and `=> corrupt_output` in the macro.

### B-19. ARCHITECTURE "Providers" drifts from the code — low — 5 — verified
`docs/ARCHITECTURE.md:193,49,158-175`
- The kmsp11 row says `generation` refuses `pop-decrypt` and "PSS with `pop-sign`". The code proves both (`crates/kmsp11/src/lib.rs:321-336`; tests at 529-530 and 566).
- The crate diagram lists only ykcs11 and tpm2 as providers. kmsp11 and aws-cloudhsm are unconditional dependencies of cli-common.
- The hook list omits `plaintext_import`.

### B-20. FAULT_SHIM.md drifts from the shim — low — 5 — verified
`docs/FAULT_SHIM.md:56,104,125,215`
- It says "About 1–1.5k lines"; the shim is 2.1k lines plus 0.9k for p11-names.
- The macro sketch uses a `key => key` form; the code's form is `=> substitute_key`.
- The trace example shows `"mechanism":"CKM_ECDSA_SHA256"`, but the trace writes numbers (`trace.rs:7`).

### B-21. CLOUD_HSM.md drifts from the code and from itself — low — 5 — verified
`docs/CLOUD_HSM.md:95,106,161,172-173,327`
- Profile names are written `libkmsp11/1.9+hsm`; the real ones are `kmsp11/1.9+hsm` (used correctly at line 101).
- glibc "2.29 or later [doc]" contradicts "glibc 2.17 only" (line 87).
- The destroy-duration `[todo]` (172-173) was settled at 97-98.
- "behind `Provider::bound_keys`" omits `generation`.

### B-22. One `repair` hook over a `Report` enum allows a "wrong variant" state that typed hooks would not — low — 3,4 — verified
`crates/pkcs11/src/provider.rs:126-128,281-340`

**What happens.** The three wrappers (`ec_point`, `key_type`, `policy_flag`) fall back silently when a provider returns another variant. `PolicyFlag` carries a `&dyn Fn` and `EcPoint` needs a `Cow` dance (`tpm2-pkcs11/src/lib.rs:43-49`).

**Fix.** Use three default methods: `repair_ec_point(&[u8]) -> Cow`, `repair_key_type(kt, params) -> KeyType` and `repair_flag(attr, reported, ...) -> bool`.

### B-23. Small dead code and pass-through wrappers — low — 4 — verified
- `Registry::knows` (`provider.rs:752-759`) is used only by its own test.
- `curve_of` (`token/mod.rs:1216-1218`) just calls `object.curve()`.
- `store_hex` (`attest/mod.rs:68-70`) and `store_dir` (`attest/mod.rs:192-194`) are one-line forwards.
- Two Name computations: `credential::name_of` (`credential.rs:40-51`, TPMT, SHA-256) and `esys::recompute_name` (`esys.rs:503-518`, TPM2B, three hashes).

### B-24. The two `build.rs` root-pinning scripts are identical, and the roots are pinned twice — low — 4,8 — verified
`crates/ykcs11/build.rs`, `crates/tpm2-pkcs11/build.rs` (same 27 lines apart from `PINNED`). Unit tests also pin each root's SPKI (`attest.rs:162-172`, `ek.rs:151-161`).

**Fix.** Share one script via `include!`, or keep only the SPKI pins in tests (they fail just as loudly in `nix flake check`).

### B-25. `tests/templates.rs` leaves a `CKA_TRUSTED` object on the shared token — low — 7 — verified
`crates/pkcs11/tests/templates.rs:215-218`

**What happens.** The trusted copy "tmpl-trusted" is never destroyed. On a persistent token every run adds one, and `Token::trusted()`'s "others" count (camigrate's `enforced` narrowness) grows.

**Fix.** Destroy it at the end of the test, as SO.

### B-26. Manufacturer matching trims inconsistently — low — 5 — verified
- `module_info` already trims (`token/mod.rs:1038`).
- `Kmsp11`, `AwsCloudHsm` and `Registry::select_in` trim `[' ', '\0']` again (`kmsp11/lib.rs:348`, `aws-cloudhsm/lib.rs:50`, `provider.rs:812`).
- `Tpm2Pkcs11` and `P11Kit` compare exactly; ykcs11 uses `starts_with`.

**Fix.** Pick one rule and drop the redundant trims.

### B-27. Paired hooks that must agree but are declared separately — low — 3 — verified
- `plaintext_import()` (a fact) and `import_plaintext()` (the operation) are two hooks for one choice (`provider.rs:226-235`; tpm2 overrides both).
- `attestation()` and `attest()` are another such pair: `attest`'s default is "unreachable in practice" (`provider.rs:241-260`).

**Risk.** A provider overriding one hook and not the other compiles and misbehaves.

**Fix.** Give each pair one hook: an enum carrying the tool, and `Option<&dyn Attester>`.

## Complexity reduction proposals (ranked, with estimated lines saved)

1. **Delete `Provider::template` and the pre-asking machinery (B-4).** It takes the `Template`/`SessionKey`/`Declared`/`Half`/`Via`/`Attributes` types, `adjusted`, `session_templates`, `check_templates`, `plan_templates`, the gate's asks and its `Asked` test, camigrate's `template_refusal`/`source_refusal`/`target_refusal`/`ask`, the caprobe asks, `pkcs11/tests/templates.rs` and `caprobe/tests/template_hook.rs`. Keep `templates.rs` as the builders. Saves about 650 lines (≈300 in cakeys-pkcs11 src, ≈120 camigrate, ≈60 caprobe, ≈325 tests).
2. **Replace ykcs11's two operation overrides with static facts (B-3).** Add a `plan_create`/locator refusal that the gate, generation and import all ask, and an `erases_keys() -> bool` fact. Then delete `Provider::create`, `Provider::destroy`, `Create`, `Destroy` and the `create_declared`/`destroy_plain` indirection. Saves about 90 lines and fixes B-3. The trait goes from 17 methods to 15.
3. **Derive `CK_RV` from p11-names (B-6).** Drop the `rv-value` feature, `RV_VALUE`, the cfg arms, part of `patched_cryptoki.rs` and caprobe's `build_lacks` rv-value branch. Saves about 60 lines, removes a feature whose absence changed behaviour (prior Cargo F1), and makes p11-names earn its crate.
4. **Split the two large files (B-5).** No lines saved, but no file stays over about 500 lines.
   - `token/mod.rs` becomes `library.rs` (Library registry, `loaded_path`, `module_info`, ≈180 lines), `rv.rs` (≈130), `login.rs` (`Pin`, `session`, `as_so`, `so_outcome`, PIN/SO reads, ≈220) and `types.rs` (`class_of`…`hmac_key_type`, ≈100).
   - Probe-only queries (`mechanism_info(s)`, `token_claims`, `rsa_bits`, `advertised`) move to caprobe over a `Token::context()/slot()` accessor: about 80 lines out of cakeys-pkcs11.
   - `provider.rs` loses `ChainTime` (about 90 lines, to `chain_time.rs`) and `Registry` (about 100, to `registry.rs`). With proposals 1–2 it ends near 450 lines.
5. **Typed repair hooks instead of the `Report` enum (B-22).** Saves about 40 lines and removes the wrong-variant state.
6. **Merge the paired hooks (B-27).** Saves about 25 lines.
7. **Small deduplications (B-10, B-23, B-24).** One `read_attribute` and one Name function, a shared `build.rs`, and no `Registry::knows`, `curve_of`, `store_hex` or `store_dir`. Saves about 100 lines.
8. **Fold p11-names into p11-fault**, if proposal 3 is not taken (B-15). Saves one crate, one manifest and one workspace entry (about 20 lines).
9. **Generate `KEY_FUNCTIONS`/`OUTPUT_FUNCTIONS` from `forward!` (B-18).** Saves about 12 lines and removes a hand-synced table.

## Still open from the 2026-11-18 review (one line each)

- None. All 60 findings for this area's files are marked Fixed.
- Spot-checked fixes still hold: token/mod.rs F2, F3, F5; ops F2 (now `ops/mod.rs:420-436`); esys F1; store F1, F2; hooks F2, F3; gate F1; templates F1; uri F1.
- The prior pkcs11 Cargo F1 (`rv-value`) is fixed by a build refusal; B-6 proposes removing its cause instead.

## Cross-area notes (issues seen in another agent's files; one line each, no deep dive)

- camigrate `src/tokens.rs:171-260` (`template_refusal`, `source_refusal`, `target_refusal`, `ask`) and caprobe's template asks (`probe.rs`, `probe/moves.rs`) go with proposal 1.
- camigrate `src/host.rs:60-63` (`landing` → `ops::check_import`) applies no ykcs11 slot rule to `piv-import` (B-3).
- core `pop.rs:25-28`: the 78-byte challenge does not fit OAEP-SHA256 on RSA-1024 (B-7).
- cli-common registers kmsp11 and aws-cloudhsm unconditionally while ARCHITECTURE draws only feature-gated providers (B-19).
- `ISSUES.md:190` (B11: Cloud KMS `pop-decrypt`/PSS never run) is still open, while ARCHITECTURE:193 already describes the old refusal.

## Files reviewed (every file in scope, with one line each: "clean" or finding IDs)

**crates/pkcs11**
- `crates/pkcs11/Cargo.toml` — B-6
- `crates/pkcs11/src/lib.rs` — clean
- `crates/pkcs11/src/binding.rs` — B-6
- `crates/pkcs11/src/gate.rs` — B-3, B-4
- `crates/pkcs11/src/ops/mod.rs` — clean (`create_absent`/`undo_created` rollback and `delete` If-Match traced)
- `crates/pkcs11/src/ops/capabilities.rs` — B-3, B-4
- `crates/pkcs11/src/ops/planner.rs` — clean
- `crates/pkcs11/src/provider.rs` — B-4, B-5, B-22, B-23, B-26, B-27
- `crates/pkcs11/src/providers.rs` — B-26
- `crates/pkcs11/src/resolution.rs` — clean
- `crates/pkcs11/src/templates.rs` — B-4
- `crates/pkcs11/src/token/mod.rs` — B-5, B-6, B-9, B-11, B-12, B-14, B-23, B-26
- `crates/pkcs11/src/token/generate.rs` — B-4 (`by_name` retry and public-default fallback traced: clean)
- `crates/pkcs11/src/token/host.rs` — clean (plaintext zeroized; KEK destroyed on every path)
- `crates/pkcs11/src/token/identity.rs` — B-4 (SPKI sources, cross-check and `check_kind` traced: clean)
- `crates/pkcs11/src/token/policy.rs` — clean
- `crates/pkcs11/src/token/possession.rs` — B-7, B-8 (all five proofs host-verified with a fresh nonce: sound)
- `crates/pkcs11/src/token/public.rs` — clean
- `crates/pkcs11/src/token/uri.rs` — clean
- `crates/pkcs11/tests/library.rs` — clean
- `crates/pkcs11/tests/patched_cryptoki.rs` — B-6
- `crates/pkcs11/tests/templates.rs` — B-4, B-25

**crates/ykcs11**
- `crates/ykcs11/Cargo.toml` — clean
- `crates/ykcs11/build.rs` — B-24
- `crates/ykcs11/src/lib.rs` — B-3, B-10, B-26
- `crates/ykcs11/src/attest.rs` — clean (no liveness: known, DESIGN §8.2)
- `crates/ykcs11/roots/README.md` (and `roots/*.pem`) — clean
- `crates/ykcs11/tests/fixtures/*.pem` — clean (data)

**crates/tpm2-pkcs11**
- `crates/tpm2-pkcs11/Cargo.toml` — clean
- `crates/tpm2-pkcs11/build.rs` — B-24
- `crates/tpm2-pkcs11/src/lib.rs` — B-22
- `crates/tpm2-pkcs11/src/ptool.rs` — clean (PIN on argv: known, OPEN.md)
- `crates/tpm2-pkcs11/src/attest/mod.rs` — B-1, B-10, B-23
- `crates/tpm2-pkcs11/src/attest/esys.rs` — B-1, B-23 (EK salt, credential binding to the host-held AK area, signature and Name checks traced: sound)
- `crates/tpm2-pkcs11/src/attest/store.rs` — B-13
- `crates/tpm2-pkcs11/src/attest/vendor.rs` — B-1, B-2
- `crates/tpm2-pkcs11/src/attest/credential.rs` — B-23 (KDFa, KDFe, CFB and blob layout checked against TPM 2.0 Part 1 §24: correct)
- `crates/tpm2-pkcs11/src/attest/ek.rs` — clean
- `crates/tpm2-pkcs11/roots/README.md` (and `roots/*.pem`) — clean
- `crates/tpm2-pkcs11/tests/fixtures/*` — clean (data)

**crates/kmsp11**
- `crates/kmsp11/Cargo.toml` — clean
- `crates/kmsp11/src/lib.rs` — B-9, B-26
- `crates/kmsp11/src/keys.json` — clean (28 rows, 21 probe)

**crates/aws-cloudhsm**
- `crates/aws-cloudhsm/Cargo.toml` — clean
- `crates/aws-cloudhsm/src/lib.rs` — B-26

**crates/p11-names**
- `crates/p11-names/Cargo.toml` — B-15
- `crates/p11-names/src/lib.rs` — B-15

**crates/p11-fault**
- `crates/p11-fault/Cargo.toml` — clean
- `crates/p11-fault/src/lib.rs` — clean (`guard` catches panics; tagged copies; load-recursion guard)
- `crates/p11-fault/src/forward.rs` — B-18
- `crates/p11-fault/src/hooks.rs` — B-16, B-17
- `crates/p11-fault/src/plan.rs` — B-18
- `crates/p11-fault/src/trace.rs` — clean (no secret values traced)

**docs**
- `docs/ARCHITECTURE.md` (Providers) — B-19
- `docs/FAULT_SHIM.md` — B-15, B-20
- `docs/CLOUD_HSM.md` — B-21
