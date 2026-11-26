# Area E: caprobe, profiles, spec coverage — review 2026-11-24

## Root causes in this area (fill at the end: 3-8 causes, each with the finding IDs that evidence it)

1. **Fixes are scoped to the reported call site, and no shared type makes the siblings fail.**
   - D-4 fixed 2 of about 20 "error → no" sites (E-2).
   - D-3 host-checked `wrap.rsa-oaep` but not the `export.sealed`/`unwrap` rows camigrate uses
     (E-3).
   - D-2 fixed `add` rows but not listed unchecked mechanisms (E-4).
   - D-6 fixed the header but not the scripts or the default (E-8).
   - D-20 left a hand list (E-1 batch).
2. **The probe is both the measurement and the oracle.** Profiles are probe output. The
   conformance tests compare a fresh probe with the file the same probe wrote, and the
   regeneration scripts overwrite before they diff. A probe bug is regenerated, committed and
   then "conforms". Only the host-side checks inside the probe are independent. (E-7, E-5, E-1,
   E-3)
3. **A row cannot say whose answer it is or how it was checked (D-TYPES).**
   - `Row {answer, evidence, via}` has no place for "module refused" vs "cakeys refused" vs
     "device failed", nor for "host-verified" vs "self-consistent" vs "unverified".
   - So every site decides ad hoc, and an unverifiable check reads `yes`.

   (E-2, E-4, E-3, E-5)
4. **The hardware and cloud truth is gated and maintained by hand.**
   - 6 of 9 module profiles are re-derived by no automated run.
   - Review fixes hand-edit them under a "Never edit, re-probed on every build" banner.
   - Hardware-specific guards are tested only on software tokens posing as the hardware.

   (E-7, E-6, E-5, E-2's ykcs11 rows)
5. **The failure model in the tests is friendly.**
   - The fault suite injects one failure family per probe.
   - One case asserts that a `CKR_DEVICE_ERROR` is the module's "no".
   - The guard suite models 5 slot occupants but not "our mark beside a foreign key".
   - Nothing corrupts a blob the module still accepts.

   (E-2, E-3, E-6)
6. **Docs and generated headers claim guarantees nothing checks**:
   - CAPROBE.md:135 "unknown, never yes" (E-4)
   - CAPROBE.md:204 "never touches PIV data objects" (E-6)
   - `bound.rs:7-9` "cannot rows are observations" (E-5)
   - the emitter header (E-7, E-8)

## Test gap map (fill at the end: per crate, what behaviour has no failing test, and why: gated, absent, oracle)

- **caprobe src**:
  - Error classification at every "no" site except `Made::create`/`probe_secrets` generation and
    `export_sealed`: absent, plus one T-ORACLE fault case (E-2).
  - Unverified-yes paths (SHA-1/raw signatures, `host_blob` Untold, `same_key` None, allowed
    mechanisms "not told"): absent (E-4).
  - `keep_claims` refusals (unpatched build, unparsable file): absent.
  - `refused_as_such` key-wrap subtraction, `probe_unbound` projection, the bound-label
    precedence: cloud only (T-GATED).
  - `clear_stale` against a real object with a bound label: absent.
  - `commit_row:144` error-as-distinct: absent.
  - `[untested]` exclusion: checked only on committed data (T-TAUTO).
  - `diff.rs` `[untested]` comparison: absent (batch 1).
- **caprobe tests**:
  - Conformance (`reference.rs`, `tpm2.rs`, `ftpm.rs`, `yubikey.rs`): T-TAUTO by design.
  - Hardware suites: opt-in, never in Nix.
  - swtpm: Linux Nix only.
  - Fault suite: needs the shim.
  - The slot guard on real ykcs11: opt-in only.
  - No marker-plus-foreign-key occupant (E-6).
- **profiles**:
  - softhsm and kryoptic are re-probed per build, swtpm on Linux only.
  - ykcs11, amd-ftpm, aws×2 and kmsp11×2: no automated check beyond the emitter's format round
    trip (T-ORACLE, E-7).
  - `layers/p11-kit.toml`: advertise list checked.
  - `layers/cryptoki.toml` and `hardware/swtpm.toml`: hand facts, checked only through
    `supports` exit codes.
- **spec-coverage**:
  - `used` means reached, not asserted (T-ORACLE, E-1).
  - The manual-rule checks: absent.
  - Without a trace, `used` comes from the committed file (T-TAUTO).
  - `objects/*`: golden files from the code under test, hand-edited (area C).

### Summary counts

- By severity: high 1 (E-2); medium 4 (E-3, E-4, E-5, E-7); low 3 (E-1, E-6, E-8).
- By escape code (finding count):
  - T-INSTANCE 4
  - T-ORACLE 3
  - T-GATED 3
  - D-DOCS 3
  - T-TAUTO 2
  - T-FRIENDLY 2
  - P-UNRUN 2
  - D-TYPES 1
  - D-PARALLEL 1
  - D-MULTIPATH 1
  - P-REVIEW 1
- Unguarded decisions: 6 (batch 1), 11 (batch 2), 2 (batch 3).
- Prior fixes:
  - Instance only: D-2, D-3, D-4, D-6, D-17, D-20.
  - Hold: D-1 (weakened, E-6), D-5 (partial), D-8, D-11 (hardware hand-edited), D-12, D-13,
    D-14, D-15, D-19, D-22, D-24.

## Findings (appended per file)

## Unguarded decisions (appended per file, from mutation testing)

## Prior fixes re-checked (prior ID — holds / instance only / wrong / regressed)

## Cross-area notes (one line each)

## Files reviewed (every file in scope: clean | finding IDs | unguarded count)

<!-- ===== batch 1: Cargo.toml, fixtures/import, src/baseline.rs, src/coverage.rs, src/diff.rs, src/emit.rs, scripts/coverage-*.sh ===== -->

### Findings: baseline.rs, coverage.rs, diff.rs, emit.rs

### E-1. spec-coverage counts a row "used" when a tool's call named it, whatever the module answered — low — verified

`crates/caprobe/src/coverage.rs:196-262`, `docs/CAPROBE.md:209-236`
What: `observe` adds the mechanism, attribute, key type, class and flag rows of every traced call
of cakeys/caprobe/camigrate with no look at `rv`. caprobe's sweep tries every signing, ECDH,
decryption and key-wrap mechanism it knows on every reference token, listed or not, so a
mechanism whose only traced call returned `CKR_MECHANISM_INVALID` is `used` (90 mechanism rows are
`used`). "used = 250" therefore measures what was *asked*, not what any test *checked*: the
row says nothing about whether a test asserted the result.
Why missed: T-ORACLE. The coverage file's oracle is "a call reached it". The prior D-8 work
removed two dead statuses but kept this definition. The definition is accurate to the letter
("reached"), so no review flagged it. But the file is cited as coverage (PLAN.md A1) and reads as
"tested".
Class: coverage is measured as reach, not as an assertion. The other instance is the surface test
(`crates/cli/tests/common/surface.rs`), which counts a flag as covered when any test passes it,
whatever that test asserts (D.md, Test gap map). 2 instances.
Instance fix: record `used` only for rows reached by a call that returned `CKR_OK`, or split
`used-ok` / `used-refused`. Tag rows reached only by `caprobe` (its sweep is not a test of the
tools). Class fix: count coverage at the assertion. A row is covered when a test compares that
call's *result* with an expected value from outside the code under test.

### Unguarded decisions (batch 1)

- `crates/caprobe/src/coverage.rs:202`: only the three tools' calls count. No test feeds a
  non-tool `exe` line (`traced_names_outside_the_baseline_are_unnamed` uses `cakeys` only).
  Dropping the filter would count pkcs11-tool's and the harness's calls, and no test would fail.
- `crates/caprobe/src/coverage.rs:272-284`: four manual-rule checks: a status not in `MANUAL`, an
  empty reason, a rule matching no row, a plain name of a used row. None has a unit test. Only
  today's data exercises them, and it conforms, so deleting any one fails nothing.
- `crates/caprobe/src/coverage.rs:383`: without a trace, `used` comes from the committed file
  itself (T-TAUTO, decided in D-8). The last traced regeneration was b0dc980 (2026-11-19).
  Since then fce5432, fcaa6aa, 61b7000 and 8aaba2e changed which calls the tools make. Nothing
  fails if `used` rows are stale.
- `crates/caprobe/src/diff.rs:23-33`: the `[untested]` comparison has no test anywhere (rg
  `untested.` in tests: none). If it is deleted or inverted, every conformance probe still
  passes. A module that starts refusing an `[untested]` mechanism, or a probe that stops
  measuring one, then goes unnoticed.
- `crates/caprobe/src/baseline.rs:102`: `curves` comes from `cakeys_profile::baseline::CURVES`
  on both sides of `committed_baseline_is_generated_from_the_vendored_headers` (T-TAUTO). Only
  two curve names are pinned (`names_and_ids_are_pinned`, `:351`).
- `crates/caprobe/src/emit.rs:411-468`: the "every optional field alone" list is still hand-kept.
  `Row.via` and `Row.evidence` alone are not in it. See D-20 below.

### Prior fixes re-checked (batch 1)

- D-8 (coverage statuses, traced pass): holds. `refused` and `profile` are gone, and the traced
  regeneration is `packages.spec-coverage`. Consequence: the per-build check is now tautological
  for `used` (above).
- D-15 (three CKR_* to gap rules): holds (`manual.toml:849-861`).
- D-20 (emitter's optional-field list): instance only. The three bodies were added
  (`emit.rs:450-455`), but the list is still hand-kept, so the class (parser fields with no
  round-trip case) can recur. The class fix proposed in D-20 was not taken: derive the list from
  a fixture that sets every field.
- D-24 (baseline "byte for byte"): holds. CAPROBE.md now says "pinned by a test".

### Files reviewed (batch 1)

- `crates/caprobe/Cargo.toml`: clean
- `crates/caprobe/fixtures/import/*` (make.sh, keys, certificate, openssl-version.txt): clean.
  Note: `certificate.der` is also the YubiKey slot mark (see probe/scratch.rs).
- `crates/caprobe/src/baseline.rs`: clean | 1 unguarded
- `crates/caprobe/src/coverage.rs`: E-1 | 3 unguarded
- `crates/caprobe/src/diff.rs`: clean | 1 unguarded
- `crates/caprobe/src/emit.rs`: see E-header finding under profiles | 1 unguarded
- `scripts/coverage-file.sh`, `scripts/coverage-full.sh`: clean (the fault suites are untraced by design)

<!-- ===== batch 2: src/lib.rs, src/main.rs, src/probe.rs, src/probe/{asymmetric,bound,extras,moves,scratch,secrets,wraps}.rs, src/supports.rs, tests/* ===== -->

### E-2. The D-4 fix covered two generation call sites. About twenty others still turn "an error" into the module's `no`. A fault test asserts that behaviour, and committed profiles carry the rows — high — verified (code, rows, test); plausible (that ykcs11 can import RSA)

`crates/caprobe/src/probe/moves.rs:287-292`, `:347-362`, `:413-421`, `:748-752`, `:834-839`; `probe/asymmetric.rs:99-105`, `:411-417`; `probe/bound.rs:34-44`, `:106-124`; `probe/extras.rs:113-131`, `:175`, `:230-233`, `:443-449`, `:474-475`; `probe/secrets.rs:76-77`, `:263`, `:506`; `probe.rs:729-730`, `:928`; `tests/fault.rs:211-220`
What: the probe decides "the module says no" at about 20 sites, under three different rules:

- No exclusion at all: moves.rs import/public-half/export/secret-import/create, bound.rs, the
  Montgomery and PQ generations, extras' attribute read and allowed-mechanisms generation.
- Busy session excluded (`CKR_OPERATION_ACTIVE`): `prove`, `crypt_row`, `Ops::record`.
- Busy and "no `CK_RV`" both excluded: `refusal_row`, `run_derivations`, `montgomery_ecdh`,
  plus `Made::create` and `probe_secrets`, which exclude only "no `CK_RV`" (the D-4 fix).

No site uses `cakeys_pkcs11::token::rv::device_failed`. The token crate uses it to class
`CKR_DEVICE_ERROR`, `CKR_GENERAL_ERROR`, `CKR_HOST_MEMORY`, `CKR_SESSION_*` and
`CKR_TOKEN_NOT_PRESENT` as the device's failure, not the key's (`token/generate.rs:74-81`).

Rows this has put in committed profiles:

- `ykcs11/2.7.toml:91-102`: ten `import.* = no, evidence = "CKR_DEVICE_ERROR"` rows, RSA-2048
  to 4096 and Ed25519 among them. They decide before the hand-written `[migration]
  plaintext-accepts` (RSA 1024-4096, Ed25519) in the same file (CAPROBE.md:131-135). Commit
  7da60ad says so: "These rows now decide over the hand-written plaintext-accepts". So
  camigrate's planner refuses an RSA import into a YubiKey on the strength of a device error.
  A YubiKey 5 imports RSA-2048 as PIV; plausible, not run here.
- `softhsm/2.7.toml:134`: `prove.pop-sign.CKK_EC_EDWARDS.edwards448 = no`, evidence "no Ed448
  signature verifier". That is cakeys' own limitation, written as SoftHSM's answer.
- `tpm2-pkcs11/1.10+swtpm.toml:109`: `prove.pop-sign.CKK_EC.secp521r1 = no` (`CKR_HOST_MEMORY`).
- `amd-ftpm.toml:84,91,107`: three `no` rows from `CKR_GENERAL_ERROR`.
- `kryoptic/1.5.toml:123-125`: three `generate` `no` rows from `CKR_GENERAL_ERROR`.

Why missed: T-ORACLE, T-INSTANCE, D-MULTIPATH, P-UNRUN, P-REVIEW.

- `tests/fault.rs:211-220` injects `CKR_DEVICE_ERROR` on every `C_UnwrapKey` and asserts that the
  profile holds `wrap.rsa-oaep.SHA-1 = no` and `SHA-256 = no`. The test pins the bug as the
  expected behaviour (T-ORACLE).
- D-4's regression test (`tests/template_hook.rs:87-89`) has the provider refuse only
  `Template::Generate`. It records that `Import`, `PublicHalf` and `Object` templates were
  asked (`:94-96`) but never refuses them, so the moves.rs sites stay untested (T-INSTANCE).
- fce5432 (the D-4 fix, "written without a build", P-UNRUN) edited moves.rs (+47 lines) and left
  `import_private`'s `Err(e) => Answer::No` (ad0919e, 2026-11-16) in place, as well as
  `import_secret`, `public_half` and `create_public`.
- `export_sealed` (`moves.rs:570-578`) already applies the rule "the provider refusing the
  template is not the module's answer". The four sibling sites in the same file do not.
- The 2026-11-23 review (D-4) named only `Made::create` (P-REVIEW: one instance was reported,
  and the fix was scoped to it).
Class: "error → no" without one shared classifier. About 20 instances under 3 policies.
Siblings outside caprobe are for B/C, for example `same_aes`, which maps any ECB failure to
`Unavailable`.
Instance fix: in each site, route the error through `refusal_row`, extended with
`device_failed` and the session/login family.
Class fix: one typed verdict, `enum Refusal { Module(rv), Busy, Device, Host(msg) }`, built
once from a `KmError`. `Profile::set(.., Answer::No, ..)` should accept only
`Refusal::Module`, so the compiler names every site that writes a `no`. Then fault cases that
inject a device error and a provider refusal at each probe family, asserting *no* row.

### E-3. `export.sealed.*` and `unwrap.*`, the rows camigrate plans by, are a round trip on one module, and the host never decodes the blob. The D-3 fix reached only `wrap.rsa-oaep` — medium — verified

`crates/caprobe/src/probe/moves.rs:479-552`, `:560-610`; `probe/wraps.rs:52-61`, `:181-191`
What: `trip` wraps on the token and unwraps with the same token's transport key, and `same`
checks that the key came back. Nothing checks that the blob is the standard encoding another
token would accept. The transport key is the token's own generated RSA pair, so the host
cannot decrypt the blob. A module with a proprietary `CKM_RSA_AES_KEY_WRAP` or composed
encoding records `export.sealed.* = yes via <camigrate method>`, and camigrate then plans a
cross-token move that fails at the destination. For `Sealed::RsaAes` neither side is ever
host-checked. That is the method the CloudHSM profiles say camigrate moves by. The D-3 fix
(fce5432) added `host_blob` to `wrap.rsa-oaep` only. Even there, `HostBlob::Untold` (no
`CKM_AES_ECB`, a template refusal) keeps the row `yes` with only a stderr line (`:55-60`).
`same_key == None` counts as the same key (`:48`, `:184-190`).
Why missed: T-INSTANCE (D-3 named `probe_wrapping` and `probe_key_wraps`; the fix covered those
and not the export rows that camigrate consumes), T-FRIENDLY (no fault case corrupts a
`C_WrapKey` blob in a way the same module still unwraps). The prior review's suggested class
fix, an imported `rsa-2048` fixture as the transport key so the host can decrypt the module's
blob, was not taken.
Class: a module checked against itself. Other instances:

- `crypt.*` (`secrets.rs:154-161`): encrypt then decrypt on the token.
- `commit.*` on generated keys (`secrets.rs:106-151`): stable and distinct, never compared with a
  host value.
- Montgomery ECDH (`extras.rs:251-320`): both sides on the token.
- PQ `sign.*` (`extras.rs:474-481`): signed and verified by the module.
- `encapsulate.*` (`extras.rs:505-531`).
That is 6 row families. Only `sign` for EC/RSA/Ed25519, `decrypt.*`, `derive.CKM_*`,
`derive.ecdh` and the imports are host-checked.
Instance fix: wrap toward the imported `rsa-2048` fixture's public key and decrypt the blob on
the host (`aes-kw` is already a dev-dependency). Record `export.sealed` only when the host
recovers the key.
Class fix: give `Row` a `checked: host|module` field (or a `via` suffix) so a self-consistency
`yes` is distinguishable in the profile and the gate can treat it as unknown for cross-token
plans.

### E-4. A check that cannot run leaves the row `yes`, and the profile cannot show it — medium — verified

`crates/caprobe/src/probe/asymmetric.rs:433-436`, `:674-716`; `probe.rs:399-408`; `probe/wraps.rs:48`, `:55-60`, `:184-190`; `probe/extras.rs:186-197`
What: CAPROBE.md:135-136 says an advertised mechanism "no row measures ... reads *unknown*,
never *yes*". But `Draft::finish` leaves out of `[untested]` every mechanism the probe *tried*
(`tried.contains(m)`), including those whose result the host could not check. Those are
`CKM_ECDSA_SHA1`, `CKM_SHA1_RSA_PKCS`, `CKM_SHA1_RSA_PKCS_PSS` and `CKM_RSA_X_509`: `sign`
returns `Ok(false)`, which counts as `worked`. So a listed mechanism that returns garbage reads
`yes`. The D-2 fix stopped such mechanisms becoming `add` rows (unlisted) but not this listed
case. The same "could not check, so yes" pattern appears in:

- `host_blob` Untold → `wrap.rsa-oaep yes`;
- `same_key` None → round trip;
- `attr.set.CKA_ALLOWED_MECHANISMS = yes` with no `via` when enforcement is not told.

Each says so only in the run's stderr (`undetermined`), never in the committed file.
Why missed: D-TYPES (`Row` has `answer`, `evidence` and `via`, with nowhere to say
"unverified"), T-INSTANCE (D-2's test `only_a_verified_signature_adds_a_mechanism` covers
`add` only).
Class: verification strength not carried in the data. 5 instances above.
Instance fix: put tried-but-unchecked listed mechanisms in `[untested]` with
`why = "unverified"`.
Class fix: as in E-3, a `checked` field on rows, and the gate treats `checked = module` as
unknown.

### E-5. For a purpose-bound module (Cloud KMS), cakeys' own algorithm table decides the rows. A refusal of a template that names no curve is written as `no` for every curve — medium — verified (code); plausible (Cloud KMS secp256k1 and OAEP-SHA-1)

`crates/caprobe/src/probe/bound.rs:7-9`, `:71-80`, `:102-146`; `crates/kmsp11/src/keys.json`; `profiles/modules/kmsp11/1.9+hsm.toml:53-58`, `:73`, `:185-186`
What: `probe_bound` probes only the algorithms in `kmsp11/src/keys.json`: P-256, P-384, RSA, AES,
HMAC-SHA256. `probe_unbound` sends a bare template naming *no curve*, gets
`CKR_TEMPLATE_INCOMPLETE`, and writes `generate.CKK_EC.<curve> = no` for every curve the table
lacks (`:118-125`), with no row evidence. `decrypt.rsa-oaep.SHA-1 = no` comes from keys.json
having no `RSA_DECRYPT_OAEP_*_SHA1` key. Cloud KMS documents `EC_SIGN_SECP256K1_SHA256` (HSM)
and `RSA_DECRYPT_OAEP_*_SHA1`, so these `no` rows are plausibly wrong. Either way they measure
cakeys' table, not the module, and the gate refuses on them (15). The function's own doc
(`bound.rs:7-9`) says "their `cannot` rows are observations too".
Why missed: T-TAUTO (the table under test bounds the "observation"), T-GATED (cloud-only; no
test re-probes it), D-DOCS.
Class: a hand table standing in for a probe (D-PARALLEL with the vendor's algorithm list).
Another instance: `RSA_KEYS`/`CURVE_KEYS` in moves.rs bound the import rows (documented in
`undetermined`, which is the right pattern).
Instance fix: write "unknown" (no row, an `undetermined` line) for what no binding covers.
Class fix: rows from a refusal must name the input refused. A refusal of input X may not
answer for Y.

### E-6. The slot mark identifies a certificate, not the key beside it — low — plausible

`crates/caprobe/src/probe.rs:258-289`, `probe/moves.rs:63-66`, `:148-177`; `docs/CAPROBE.md:204-205`
What: `check_slot` passes a slot whose certificates are the fixed `SLOT_MARKER` (a committed
fixture) plus an attestation companion, whatever key is there. In PIV the certificate and the
key are separate objects. A key put into a probed slot without a new certificate, for example
`ykman piv keys generate`/`import` (which write no certificate), keeps the mark, and the next
`probe --write-probes` overwrites it. The mark's public key (the P-256 fixture) is never compared
with the slot's key (the probe's last generated P-256). CAPROBE.md:204 says the probe "never
touches PIV data objects", yet it writes the slot's certificate twice (`create.CKO_CERTIFICATE`,
`mark_slot`).
Why missed: T-FRIENDLY, T-GATED. The guard suite (`tests/reference.rs:141-251`) models ykcs11
on SoftHSM/kryoptic with five occupants: empty, real cert, key-only, placeholder, marker. None
is "marker plus a foreign key". The real ykcs11 path runs only in the opt-in YubiKey suite.
Class: a mark that names an object other than the one it vouches for (compare C-1/D-1's "guard
recognises the wrong thing").
Instance fix: issue the mark over the slot's last key (a self-signed certificate of the
generated P-256 key), and in the guard require that the mark's SPKI equal the slot's public key.

### Unguarded decisions (batch 2)

- `crates/caprobe/src/probe.rs:1016-1024`: a kept profile from an unpatched build is refused
  (17). Only `build_lacks` is unit-tested; no test reaches the refusal (the Nix build is
  always patched).
- `crates/caprobe/src/probe.rs:1077-1078`: an `--out` file that does not parse is refused. No test.
- `crates/caprobe/src/probe.rs:133`: `module-version` omitted when the module reports `0.0`.
  Only the kryoptic conformance run (Nix, Linux) reaches it.
- `crates/caprobe/src/probe.rs:403`: what counts as measured for `[untested]`. Only
  `untested_entries_are_consistent_...` checks it, on the committed profiles (T-TAUTO).
- `crates/caprobe/src/probe/wraps.rs:203-209`: only `CKR_MECHANISM_INVALID`/`FUNCTION_NOT_SUPPORTED`
  subtract a key wrap. No unit or fault test; the only evidence is the CloudHSM run.
- `crates/caprobe/src/probe/wraps.rs:295-305`: template errors vs blob refusals in `host_blob`.
  The fault test injects a key swap (`use_label`), never a template refusal.
- `crates/caprobe/src/probe/bound.rs:82-83`: "generated under one binding" beats "refused under
  another". Cloud only.
- `crates/caprobe/src/probe/asymmetric.rs:388`: RSA sizes the host cannot compute with get no
  proof rows. No test.
- `crates/caprobe/src/probe/scratch.rs:81`: `clear_stale` destroys any object whose label starts
  `cakeys-probe-` or equals a bound label. The test (`fault.rs:384`) plants a stale probe
  object; none plants a real object with a bound-key label on a scratch Cloud KMS token.
- `crates/caprobe/src/probe/secrets.rs:144`: an error computing the second key's commitment
  counts as "distinct". No test.
- `crates/caprobe/src/probe/extras.rs:123`: a failed attribute read becomes four `no` rows (E-2).

### Prior fixes re-checked (batch 2)

- D-1 (slot guard → probe's own mark): holds for the reported case (a placeholder-only slot is
  refused, `reference.rs:209-211`). Weakened by E-6 (the mark vouches for a certificate, not
  the key).
- D-2 (every signature verified per row): instance only. 4 mechanisms are still unchecked (SHA-1
  ×3, raw X.509). The fix applies to `add` rows only; listed unchecked mechanisms read yes (E-4).
- D-3 (wrap round trips compare the key): instance only. `wrap.rsa-oaep` is host-checked, but the
  check degrades to yes on `Untold`. `export.sealed`/`unwrap` rows, which camigrate consumes,
  are still self round trips (E-3).
- D-4 (cakeys' refusals vs the module's "no"): instance only. 2 of about 20 sites, and a fault
  test pins a device error as "no" (E-2).
- D-5 (control cases): holds. `aes_key` sets `CKA_EXTRACTABLE = false`, and "enforced" needs ECB
  to work and CBC to be listed. Residual: the CBC failure's reason is not checked
  (`extras.rs:184`), so a device error outside the list reads "enforced".
- D-6 (header names `--rsa-max-bits 4096`): holds for the header. The `--rsa-max-bits` default
  is still 16384, so the class (instructions drift from the test's arguments) remains.
- D-11 (Montgomery fallback template): holds (`a_montgomery_fallback_is_never_stricter_than_the_first_try`).
  But the hardware profiles' Montgomery evidence was hand-edited, not re-probed (E-7).
- D-12, D-13, D-14: hold (`asymmetric.rs:565`, `secrets.rs:124-129`, `scratch.rs:220-222`).
- D-17 (labels): instance only. Bound keys still use `caprobe-` (`kmsp11/src/lib.rs:25`, test
  `:472`) and probe objects `cakeys-probe-`. The doc comment now says so on purpose.
- D-19 (decoy pairs counted): holds (`fault.rs:117`).
- D-22 (interrupted run vs own cert): holds by construction (the cert is the mark).

### Cross-area notes (batch 2)

- B: `token::rv::device_failed` is `pub(super)`. caprobe cannot use the token crate's own
  device-vs-key classification (E-2).
- B: `ykcs11` `scratch_companion` decides what may sit beside the mark. It is tested only in
  ykcs11's unit tests.
- D (camigrate): the planner trusts `export.sealed`/`unwrap` rows that are self round trips (E-3)
  and `import.*` `no` rows from device errors (E-2).

### Files reviewed (batch 2)

- `crates/caprobe/src/lib.rs`: clean | 0 unguarded (the read-only `--out` refusal is tested
  by exit code in `assert_profile_conforms:570`)
- `crates/caprobe/src/main.rs`: clean
- `crates/caprobe/src/probe.rs`: E-2, E-4, E-6 | 4 unguarded
- `crates/caprobe/src/probe/asymmetric.rs`: E-2, E-4 | 1
- `crates/caprobe/src/probe/bound.rs`: E-2, E-5 | 1
- `crates/caprobe/src/probe/extras.rs`: E-2, E-3, E-4 | 1
- `crates/caprobe/src/probe/moves.rs`: E-2, E-3, E-6 | 0
- `crates/caprobe/src/probe/scratch.rs`: clean | 1
- `crates/caprobe/src/probe/secrets.rs`: E-2, E-3 | 1
- `crates/caprobe/src/probe/wraps.rs`: E-3, E-4 | 2
- `crates/caprobe/src/supports.rs`: clean
- `crates/caprobe/tests/fault.rs`: E-2 (asserts the bug at `:211-220`); Linux-only (T-GATED)
- `crates/caprobe/tests/reference.rs`: E-6 (no marker-plus-foreign-key case); conformance is T-TAUTO (E-7)
- `crates/caprobe/tests/template_hook.rs`: E-2 (refuses `Generate` only)
- `crates/caprobe/tests/supports.rs`, `surface.rs`: clean
- `crates/caprobe/tests/tpm2.rs`, `ftpm.rs`, `yubikey.rs`: E-7 (opt-in; conformance oracle is the committed file)

<!-- ===== batch 3: profiles/ (sampled), scripts/regen-profiles.sh, scripts/cloud/{aws,gcp}.sh, spec-coverage/ ===== -->

### E-7. Six of the nine module profiles are checked by no automated run, and review fixes hand-edit them. Every one of them carries the header "Never edit ... the conformance test re-probes and compares on every build" — medium — verified

`crates/caprobe/src/emit.rs:150-158`, `:278-300`; `profiles/modules/{ykcs11/2.7,tpm2-pkcs11/1.10+amd-ftpm,aws-cloudhsm/5.18+hsm2m-fips,aws-cloudhsm/5.18+hsm2m-non-fips,kmsp11/1.9+hsm,kmsp11/1.9+hsm-fips}.toml`; `crates/cli/tests/common/mod.rs:550-572`
What: when the probe logic changes, nothing re-derives the hardware and cloud rows.

- The last probe of ykcs11 was 798f58f, amd-ftpm 8aeaa8d, and aws and kmsp11 7785424, all on
  2026-11-19.
- The D-2/D-3/D-5/D-11 logic changed afterwards (fce5432, 61b7000; 2026-11-23/24).
- fcaa6aa, 6d4beab and 61b7000 then edited all six by hand. Examples: the Montgomery evidence
  moved from `[notes]` into rows, `"Max(16)"` became `"16"`, `"Infinite"` became `"infinite"`,
  and provider hints were dropped from 22+ kmsp11 rows. The commit message says so: "the other
  profiles that came from the same path follow by hand".

So rows that the pre-fix logic wrote stand unchecked by the post-fix logic:

- `add` rows: ykcs11 `CKM_ECDSA_SHA224`, amd-ftpm `CKM_SHA384/512_RSA_PKCS`, aws
  `CKM_SHA224_RSA_PKCS`. These are D-2's row type.
- aws `wrap.rsa-oaep.SHA-1/SHA-256 = yes`, D-3's row type, written before the host-blob check.
- the E-2 `no` rows (`ykcs11` import with `CKR_DEVICE_ERROR`).

They may still be right. Nothing will tell. The emitter writes the same header into every file
(`emit.rs:150-158`), so the claims "Never edit", "re-probes ... on every build" and the
`--rsa-max-bits 4096` command are false for these six (see E-8).

Why missed:

- T-GATED: `tests/yubikey.rs` and `tests/ftpm.rs` are opt-in and never run in Nix. aws and
  kmsp11 have no test at all, only `scripts/cloud/*.sh`, run by hand against billing accounts.
- T-ORACLE: `every_committed_profile_is_what_the_emitter_writes` (`emit.rs:278`) is the only
  check that touches them. It compares format only (parse → emit → parse), so any hand edit that
  stays well-formed passes.
- T-TAUTO: where a conformance test does run (`assert_profile_conforms`), its expected value is
  the file the same probe wrote. `scripts/regen-profiles.sh`, `gcp.sh` and `aws.sh` write
  `--out` over the committed file and keep going on drift (exit 15: "the file is written
  anyway"). A probe bug is therefore regenerated, committed and then "conforms". The only
  independent oracles are the host-side checks inside the probe and the hand `[migration]` /
  `[manual]` rows.
- P-UNRUN: fce5432 was "written without a build" (REVIEW-2026-11-23 Status).
- D-DOCS: the header.

Class: a generated artifact that the generator's tests cannot reach, maintained by hand under a
"generated" banner. Instances:

- 6 module profiles.
- `profiles/modules/tpm2-pkcs11/1.10+swtpm.toml`, hand-edited in 61b7000 "to be re-probed on
  Linux". It is checked only by the Linux Nix build (`withTpm2 ? isLinux`), never on the darwin
  dev host.
- `spec-coverage/objects/*.toml`, the object-matrix golden files. fcaa6aa rewrote 244 lines
  (`exit 15` became `exit 17`) under a "Never edit: CAKEYS_UPDATE_OBJECTS rewrites it" header
  (area C).

That is 8 files.

Instance fix: give each gated profile a `[provenance]` table (caprobe commit, date, device or
firmware), written by the emitter. Write the header per provenance: a profile no build re-probes
says so and names its script.

Class fix: the emitter refuses to emit over a file whose `[provenance]` commit differs from the
running probe unless the token is probed. A CI check, `git log` over `crates/caprobe/src` newer
than a profile's provenance, lists stale gated profiles in the PR. Hand edits then show up as a
provenance mismatch instead of passing as "generated".

### E-8. The regeneration command differs by path: the header, the test helper and `regen-profiles.sh` use `--rsa-max-bits 4096`; the cloud scripts use the default 16384 — low — verified

`crates/caprobe/src/emit.rs:151-153`, `crates/caprobe/src/lib.rs` (`--rsa-max-bits` default 16384), `scripts/cloud/gcp.sh:173-181`, `scripts/cloud/aws.sh:350-358`, `scripts/regen-profiles.sh:73`, `crates/cli/tests/common/mod.rs:561`
What: the aws and kmsp11 profiles have 10 `generate.CKK_RSA.*` rows (up to 16384), and the
others have 6. A cloud profile regenerated by the command in its own header would drop 4 rows
and drift, and the cloud scripts do not run the command the header names. Harmless today:
those sizes are refused. But a provider that accepts RSA-8192 gets the row on one path and
"unknown" on the other.
Why missed: T-INSTANCE (D-6 fixed the header text to match the tests' 4096, not the scripts or
the default), D-PARALLEL (four hand-copied command lines), D-DOCS.
Class: hand-copied invocations of one command. 4 copies: emitter header, `assert_profile_conforms`,
`regen-profiles.sh`, `scripts/cloud/*.sh` (×2).
Instance fix: make 4096 the `--rsa-max-bits` default, or pass it in both cloud scripts.
Class fix: one `caprobe regenerate <profile>` verb that holds the flags, called by every script
and by the test helper. The header names that verb.

### Area questions (E)

- **Trust of probe results** (which host check proves each row type):
  - Host-checked:
    - `sign.*`/`prove.pop-sign` for EC/RSA/Ed25519: a host verifier against the SPKI the module
      reported, except 4 SHA-1/raw mechanisms (E-4).
    - `decrypt.*`: host-encrypted.
    - `derive.ecdh` (sealed/extractable): host challenge.
    - `derive.CKM_*` KDFs: host-computed.
    - `wrap.rsa-oaep`: host blob, but `Untold` counts as yes.
    - `import.*`: fixtures with known values.
  - Module say-so (T-FRIENDLY/T-ORACLE):
    - `export.sealed`/`unwrap`, `crypt.*`, `commit.*` on generated keys, Montgomery ECDH, PQ
      `sign`/`encapsulate` (E-3).
    - every `no` row, whose classification is not checked (E-2).
    - `attr.set.*` when enforcement is not told (E-4).
    - kmsp11 `cannot` rows from cakeys' table (E-5).
- **T-TAUTO**: yes. Every conformance test compares a fresh probe with the file the probe wrote.
  The regeneration scripts overwrite before they diff. Same for `spec-coverage/cakeys.toml` (the
  `used` rows come from the committed file without a trace) and `spec-coverage/objects/*` (E-7).
- **T-GATED**:
  - YubiKey (`tests/yubikey.rs`) and AMD fTPM (`tests/ftpm.rs`): opt-in.
  - swtpm (`tests/tpm2.rs`): Linux Nix only.
  - Cloud KMS and CloudHSM: no test, scripts only.
  - The fault suite needs the shim (`P11_FAULT_MODULE`).
  - So 3 of the 9 module profiles are checked per build, and 2 of those on darwin.
- **Destructive-write guards**:
  - The slot guard (`check_slot`): tested with 5 occupants on SoftHSM/kryoptic posing as ykcs11
    (`reference.rs:141-251`). Missing: marker plus a foreign key (E-6). Real ykcs11 only in
    opt-in.
  - `scratch = true` token guard: refusal tested (`reference.rs:30-32`).
  - `clear_stale`: tested with a stale probe object and a decoy pair (`fault.rs:384`, `:117`).
    Not tested with a real object under a bound-key label (unguarded).
  - Cleanup after failure: tested (`fault.rs:402`).
  - Cloud KMS key creation (30-day label burn): guarded by `gcp.sh preflight` only.
- **D-PARALLEL tables**:
  - `kmsp11/src/keys.json` vs Cloud KMS algorithms (E-5).
  - `RSA_KEYS`/`CURVE_KEYS` vs the import rows (documented).
  - `CURVES` on both sides of the baseline check (batch 1, unguarded).
  - The emitter optional-field list (D-20).
  - The regeneration command ×4 (E-8).
  - `FORWARDING_DROPS` vs `layers/p11-kit.toml`: checked by a test, fine.

### D.md root-cause patterns, checked against this area

- "Fixes scoped to the reported instance": **confirmed**.
  - D-2: E-4, 4 mechanisms and the listed case left.
  - D-3: E-3, export rows untouched.
  - D-4: E-2, 2 of ~20 sites.
  - D-6: E-8.
  - D-20: batch 1.
- "Dry-run paths as hand-written copies": no dry run in caprobe. The analog holds:
  - regeneration commands copied 4× (E-8);
  - `export_sealed`'s "provider refusal is not the module's" rule re-implemented in one of five
    sibling sites (E-2).

### Unguarded decisions (batch 3)

- `profiles/hardware/swtpm.toml` (hand-maintained `max-bits = 3072`): no build checks it against
  a probe. Only `tests/supports.rs:39-41` reads it (exit 15 at 4096), and that test reads the
  layer.
- `profiles/layers/cryptoki.toml`: hand-maintained subtract list. Its agreement with
  `binding.rs` belongs to area B.

### Cross-area notes (batch 3)

- C: `spec-coverage/objects/*.toml` are golden snapshots generated by the code under test, and
  fcaa6aa hand-edited 244 lines (T-TAUTO, E-7 class).
- D (camigrate): `[migration]` rows lose to probed `import.* = no` rows (CAPROBE.md:131-135),
  so the E-2 device-error rows override the hand claim.

### Files reviewed (batch 3)

- `profiles/modules/softhsm/2.7.toml`: E-2 (Ed448 row)
- `profiles/modules/kryoptic/1.5.toml`: E-2 (GENERAL_ERROR rows)
- `profiles/modules/tpm2-pkcs11/1.10+swtpm.toml`: E-2, E-7 (hand-edited, Linux-checked)
- `profiles/modules/tpm2-pkcs11/1.10+amd-ftpm.toml`: E-2, E-7
- `profiles/modules/ykcs11/2.7.toml`: E-2, E-7
- `profiles/modules/aws-cloudhsm/5.18+hsm2m-{fips,non-fips}.toml`: E-3 (`RsaAes`), E-7, E-8
- `profiles/modules/kmsp11/1.9+hsm{,-fips}.toml`: E-5, E-7, E-8
- `profiles/layers/p11-kit.toml`: clean (checked by `the_forwarder_subtracts_exactly_its_layer`)
- `profiles/layers/cryptoki.toml`: clean | 1 unguarded (area B)
- `profiles/hardware/swtpm.toml`: clean | 1 unguarded
- `profiles/baselines/pkcs11-3.2.toml`, `profiles/baselines/headers/pkcs11-3.2/*`: clean (D-24 holds)
- `scripts/regen-profiles.sh`: E-7 (writes over before diff), E-8
- `scripts/cloud/gcp.sh`, `scripts/cloud/aws.sh` (+ `main.tf`, `cakeys.toml`): E-7, E-8
- `spec-coverage/cakeys.toml`: E-1
- `spec-coverage/manual.toml`: clean (D-15 holds)
- `spec-coverage/objects/{softhsm,kryoptic,tpm2-pkcs11+swtpm}.toml`: E-7 class (area C)
- `docs/archive/CAPROBE_PROFILE_COVERAGE.md`, `docs/archive/COVERAGE_PLAN.md`: archive, not reviewed for findings
