# Area A: Core model and design

Repo `~/srcs/cakeys` @ 4304989. Read-only review; nothing built or run. Prior per-file reviews
(2026-11-18) read for every file; every prior finding in scope is marked Fixed or Decided, and the
fixes spot-checked here hold (gc/save validation, retargeted-spec downgrade gate, recorded label
never overwritten, RSA of any size, `spki_curve` on `KeyAlg`, `Verdict` meaning, size interpolation
in `generate`, etc.).

## Summary

The core is in good shape: the lock rules in `reconcile.rs` are pure, ordered and well tested
(unit, proptest, Quint replay); IDs are never overwritten, mode/binding/attestation/immutable
downgrades are refused per realisation, and proof-of-possession is sound (fresh 32-byte nonce,
domain-separated, host-verified against the same canonical SPKI, constant-time compares, secrets
zeroized). No critical or high findings. Biggest risks: (1) the profile algebra still infers *yes*
from absence in `Effective::commit` (reachable with the committed SoftHSM profile, so `validate`
and `create`'s gate pass a spec the module refuses), the same hole prior F1/F2 closed for
`generate`; (2) downgrade protection is per (spec, token), not per object as DESIGN.md says, so a
second spec realises the same key on the same token weaker with no note; (3) the new X.509 chain
walker (`chain.rs`, not previously reviewed) ignores critical extensions, keyUsage and EKU;
(4) `save_lock` silently resets the lock's file mode/owner. Biggest simplification wins: move
camigrate's capability model (`Side`, `Accept`, …) out of core, parse object types once instead of
re-parsing `curve` strings in ~10 places, collapse the four hand-synced commitment/name tables,
and split the 2,084-line `config/mod.rs` (≈320 lines of its tests belong to `lock.rs`/`io.rs`).

## Findings

### A-1. `Effective::commit` (and `generate_secret`) answer *yes* from absence for free-length key types — medium — 1, 4 — verified

`crates/profile/src/effective.rs:267-273`, `:206-211`; doc at `:233-237`
`commit` returns `Yes` for *any* length of a free-length type once *any* row says yes
(`if free && rows.iter().any(yes)`), although its own doc says "any length that did stands for one
between two that did, and any other length is unknown". With the committed
`profiles/modules/softhsm/2.7.toml` rows `commit.hmac-sha256.CKK_GENERIC_SECRET.{16: no
(CKR_KEY_SIZE_RANGE), 32: yes, 64: yes}`, a keys.toml generic secret with `valueLen = 8` and
`CKA_SIGN = true` gets `commit(..., Some(8)) = Yes` (8 is *below* a refused size), so
`gate::commitments_refused` (`crates/pkcs11/src/gate.rs:240-256`) never refuses: `validate` passes and
`create` generates the key (SoftHSM generates generic secrets at 1..1024), and only the commitment
at `lock` fails, after creation (rollback). This breaks DESIGN §4.1 "create checks the profiles
before it makes anything" and D5 "unknown, never a guess". `generate_secret`'s free-length
interpolation has the hole prior F2 closed in `generate`: it takes the nearest *generated* sizes on
either side and ignores a refused size between them (latent: no committed profile has yes/no/yes
for a free type yet). `tests/answers.txt` pins no `commit` verdict, so neither is caught. Fix: one
helper `between_tried(can, cannot, n)` (nearest *tried* size below and above, both yes) used by
`generate` (bits), `generate_secret` and `commit` (bytes); pin `commit` verdicts in `answers.rs`.

### A-2. Downgrade protection is per (spec, token), not per object: a second spec on the same token records a weaker realisation silently — medium — 2, 3 — verified

`crates/core/src/reconcile.rs:198-211`, `:541-552`; `docs/DESIGN.md:320-322`, `:369-371`
`compare` judges mode, binding, attestation, lost schemes and replaced immutables only against
`lock.realisation(t.spec_name, t.token_name)`. Object `a` locked on token `t` by spec `s` with
`attestation = true`, `pop-sign` and `CKA_LOCAL = true`: add spec `s2` (same object, same token,
`binding = "token-asserted"`, no attestation) and run `lock`. There is no previous realisation of
`(s2, t)`, the material IDs match, so `record` adds a realisation with no attestation, no proof and
whatever immutables the (possibly re-imported) object now has, and prints nothing (notes are emitted
only when a previous realisation exists). `check a --spec s2` then passes. DESIGN says "a
realisation that should stop attesting needs a new object name" — a new spec name is enough. Fix:
in `compare`, also hold the run to the strongest existing realisation of the same object on the same
token (any spec) for binding/attestation/immutables, or at least `notes.warn` that another spec
records it stronger; correct DESIGN §3.6/§3.7 wording either way.

### A-3. The attestation chain walker ignores critical extensions, keyUsage and EKU — medium — 2 — verified

`crates/core/src/chain.rs:145-166` (`may_issue`: basicConstraints only), `:265-306`, `:318-358`
No code in the workspace reads `Extension::critical`, `keyUsage` or `extendedKeyUsage`
(`rg critical|KeyUsage|NameConstraints crates` hits only a test's openssl config). RFC 5280 §4.2
requires rejecting a certificate with an unrecognised critical extension, and §4.2.1.3 requires
`keyCertSign` on an issuer whose keyUsage is present. So a path through an issuer whose keyUsage
forbids certificate signing, or one carrying a critical `nameConstraints`/`policyConstraints` (an
`options.ekRoots` anchor a user supplies, or any intermediate under the pinned Yubico/AMD roots),
verifies. For the EK leaf, any end-entity certificate under an anchor is taken as an EK certificate
(no `tcg-kp-EKCertificate` 2.23.133.8.1 check; activation still needs the TPM to hold the key, so
this is defence in depth). Fix: in `issuer_chain`'s `link`, require `keyCertSign` when keyUsage is
present; reject any critical extension outside an allowlist (basicConstraints, keyUsage,
subjectAltName — TCG EK leaves mark SAN critical — extendedKeyUsage, certificatePolicies); let
`tpm2-pkcs11/attest/ek.rs` require the EK EKU where present.

### A-4. `save_lock` replaces the lock with a new 0666&umask file: mode, owner and group are lost — medium — 2, 1 — verified

`crates/core/src/config/io.rs:57`, `:70-89`
`write_whole` creates a fresh temp file with `0o666` under the umask and renames it over the lock.
A deployment that keeps `keys.lock` at 0600 (DESIGN §8.2: commitment IDs and private `valuehash`
let anyone with the lock test guesses of a low-entropy secret offline) gets a 0644 file after the
first `lock`; a group-shared 0660 lock becomes 0644 owned by the writer, and the next group member's
writing run is refused (21). Nothing says so. Fix: when the target exists, create the temp with the
target's permission bits (and best-effort `fchown` to its uid/gid), falling back to 0666&umask only
for a new lock.

### A-5. Adding a descriptive `modulusBits` to a locked RSA object is refused forever as "different material" — medium — 3, 6 — verified

`crates/core/src/reconcile.rs:186-197`, `crates/core/src/config/mod.rs:321-342` (derived `PartialEq`),
`crates/core/src/migrate.rs:198-201`, `crates/camigrate/src/tokens.rs:352`
The type check compares the whole `ObjectCfg`, so `modulusBits` (which the SPKI already fixes and
`pkcs11/src/token/policy.rs:60` verifies on the token) counts as identity. camigrate's probed rows
become `Accept { modulus_bits: Some((b, b)) }`, which `covers` only objects that declare it, so a user
moving an adopted RSA key is pushed to add `modulusBits`; every `verify`/`check`/`lock` then fails
14 "the type … changed …; different material needs a new object name", and only a hand edit of
`objects.<o>.type` recovers. (Prior config.rs design note, not a finding ID.) Fix: compare only the
identity-bearing fields (`class`, `keyType`, `curve`, `valueLen`, `certificateType`); treat a newly
declared `modulusBits` as a gap `record_object` fills, since the token check verifies it.

### A-6. camigrate's capability model lives in core with a single user — medium — 3, 4 — verified

`crates/core/src/migrate.rs:163-352` (+ tests `:411-462`)
`Side`, `Accept`, `Probed`, `ProbedWays`, `PlaintextImport` and `VendorMethod` are used only by
`crates/camigrate/src/{plan,tokens,lib,sealed}.rs` (rg). Core's own need is `Method`/`Exposure`
(frozen names; `lock.rs:175` validates `provenance.origin.method`). The profile crate already models
the same `[migration]` data a second way (`profile::{Migration, AcceptRow, PlaintextKind}`) that
camigrate converts into these types (`tokens.rs:352-395`). Fix: move the six types and their tests
into `camigrate::tokens`, keep `Method`/`Exposure` in core, and move `OaepHash` from `pop` to
`migrate` (prior pop.rs design note: the frozen names currently import from the proof module).

### A-7. `config/mod.rs` (2,084 lines) still mixes five concerns; a third of its tests test other modules — medium — 4 — verified

`crates/core/src/config/mod.rs`
Prior F5 split the sources but left: `ModuleInfo`/`TokenInfo` (`:1346-1389`, observation types,
belong in `observe.rs`); verb addressing `select`/`address` (`:1280-1343`, used by
`pkcs11::ops` and camigrate only); ~300 lines of load rules (`check_value_len`, `check_token`,
`check_names`, `check_transport_keys`, `check_secret_files`, `check_origins`, `env_ref`,
`:965-1221`); `Mode`/`Binding` (`:749-856`, lock/plan vocabulary). The tests from `:1397-1566` and
`:1945-2084` (~320 lines: `fixture_lock_parses`, `unknown_observation_keys…`, `observations_are…`,
`gc_and_save…`, `a_lock_that_cannot_be_saved…`, `a_symlinked_lock…`, `attestation_is_per_realisation…`,
`a_lock_saves_and_loads_back`, `an_unwritable_lock_says_why`) exercise `lock.rs`/`io.rs`. Fix:
`config/check.rs` for the load rules, move tests beside the code they test, `ModuleInfo`/`TokenInfo`
to `observe.rs`, `select`/`address` to `cli-common` or `pkcs11::ops::planner`. mod.rs ≈ 900 lines.

### A-8. Object types are modelled three times and re-parsed after load — medium — 3, 4 — verified

`crates/core/src/config/mod.rs:57-88` (`ObjectEntry`), `:320-474` (`ObjectCfg`, `kind`, `curve`,
`checked_key_type`), `:476-529` (`ObjectKind`)
Load parses every object into `ObjectKind` (`:901`) and throws it away; consumers then re-parse the
stringly `ObjectCfg` with fallible calls that cannot fail after load: `plan.rs:252`,
`pkcs11/src/token/mod.rs:1227` and `kmsp11/src/lib.rs:243` (`checked_key_type`), `token/mod.rs`
and `camigrate/keyfile.rs` (`.curve()`), `plaintext.rs:57`, `camigrate/host.rs:230`,
`caprobe/probe/moves.rs:204`, `camigrate/plan.rs:270`, `pkcs11/gate.rs:217`,
`token/possession.rs:678` (`curve.as_deref()` strings, with `"?"` fallbacks). Fix: keep `ObjectCfg`
as the serialized/digest form, store the parsed `ObjectKind` beside it in `Config` (e.g.
`objects: BTreeMap<String, Object { cfg, kind }>`), and pass `Curve`/`ObjectKind` to
`private_from_pkcs8` (prior plaintext.rs design note). Removes the fallible re-parses and their
unreachable error arms.

### A-9. Four hand-synced commitment tables, with names that disagree — low — 4, 5 — verified

`crates/core/src/id.rs:326-363` (`Commit::scheme`, `Commit::mechanism`),
`crates/pkcs11/src/token/identity.rs:374-400` (`commit_kind`, `commit_mechanism`),
`crates/profile/src/capability.rs:315-329` (`commit_mechanism(kind)`)
The same computation is `kcv-ecb-dec` in the lock, `kcv-ecb-decrypt` in a profile row, and
`kcv-des3-ecb`/`kcv-des3-ecb-decrypt` for DES3 where the lock uses one scheme for both ciphers. A new
commitment needs four edits plus the pinning tests. Fix: put `Commit::profile_kind()` next to
`Commit::mechanism()` in core (pkcs11 then derives `MechanismType` from the name it already has), and
rename the profile kinds to the scheme names (profiles are regenerated).

### A-10. A proof the declared `CKA_ALLOWED_MECHANISMS` forbids is refused only at token time (15), unlike commitments (17 at load) — low — 3, 5 — verified

`crates/core/src/plan.rs:154-217` vs `:281-311`, `:320-324`
`plan_mode` refuses a secret key whose declared allowed list permits none of its commitments
(17, at load), but `check_binding` never consults the list: an EC key with
`attributes = { CKA_SIGN = true, CKA_ALLOWED_MECHANISMS = ["CKM_ECDH1_DERIVE"] }` and the default
`pop-sign` loads, then every verb refuses it at the proof (15, `possession.rs` `none_allowed`) —
"what loads is usable" (review D1) does not hold. Fix: in `check_binding`, refuse (17) when the
declared list contains none of the binding's mechanisms (the table `possession.rs:700-710` already
lists them per binding; move it to core).

### A-11. Host-side RSA encryption failures are "unavailable" (16) — low — 1, 5 — verified

`crates/core/src/pop.rs:245-262`; caller `crates/pkcs11/src/token/possession.rs:295`, `OAEP` at `:632`
`rsa_encrypt` maps every `rsa` error to `Unavailable`. The pop challenge is 78 bytes
(14 + 32 + 32); OAEP-SHA-256 on RSA-1024 carries at most 62. A 1024-bit decrypt-only key on a token
that refuses SHA-1 OAEP params ends with `16 unavailable: RSA encryption: message too long` ("the
token cannot be used now") instead of 15 naming the size. Fix: map the size/`MessageTooLong` case to
`Unsupported` naming key size and hash, keep `Unavailable` for the RNG.

### A-12. The `.lck` sidecar is opened for writing and not covered by the writability pre-check — low — 1, 6 — verified

`crates/core/src/config/io.rs:122-131`, `:226-244`
`lock_for_update` opens `<lock>.lck` with `write(true).create(true)`; a sidecar left by another
user (0644 under umask 022) makes every writing run of a shared lock fail with exit 1 "opening
keys.lock.lck: Permission denied", while `lock_unwritable` (which promises the up-front 21 with
`--no-update-lock` named) checks only the lock and its directory. `flock` works on a read-only
descriptor. Fix: open read-only when the sidecar exists, or include it in `unwritable`.

### A-13. Test-only and dead API in library code — low — 4, 7 — verified

`crates/core/src/pop.rs:52-62` (`verify`), `:175-185` (`oaep_challenge`), `:196-208`
(`unwrap_challenge`): no caller outside core's tests (production uses `verify_with`, `rsa_encrypt`,
`unwrap_challenge_with`); `crates/core/src/config/lock.rs:72-75` (`validate` wraps `check`);
`crates/core/src/id.rs:695-708` (`spki_curve`, a three-line wrapper over `KeyAlg::of_spki`);
`crates/profile/src/lib.rs:41-44,115` (`baselines: Vec<(String, Baseline)>`: the path is never read
and only one baseline is ever allowed); `crates/profile/src/names.rs:146-151` (`Operation`, one
variant). Fix: delete the three pop wrappers (rename the `_with` forms), inline `validate`, store
one `Baseline`, make `Restrict.operation` a plain `"generate"` check. ~60 lines.

### A-14. An unset environment variable for the PIN is 16 or 17 depending on how it is named — low — 5, 6 — verified

`crates/core/src/secret.rs:45-46` (`pinEnv` unset → `Unavailable` 16) vs
`crates/core/src/config/mod.rs:1218-1220` via `TokenCfg::pin_path` (`pinFile = "$VAR"` unset →
`Validation` 17). Both mean "this host's environment does not provide the PIN"; scripts must
handle two codes. CONFIG.md documents both (`:65`, `:86`). Fix: one code (16) for an unset variable
at use, 17 only for a malformed reference at load.

### A-15. Doc-vs-code drift in the core's documents — low — 5 — verified

- `docs/CONFIG.md:283-284` "a `$NAME` path reference must name a set variable" at load: since
  34969c4 only the form is checked at load (`config/mod.rs:904-928`); the same file says so at
  `:85-87`. `:37` "valid … with `TPM_PIN_FILE` set" is stale, and no test loads this example.
- `docs/DESIGN.md:277-280` "asked SHA-256, then SHA-512, each with a fresh challenge": the same
  challenge (nonce) is re-encrypted per hash (`possession.rs:57`, `:295`, `:347`); harmless, wording.
- `docs/DESIGN.md:741-744` §10's frozen lock field list omits `mode`, `version`, `type`,
  `commitmentLabel`, `publicKey`, `attestation`/`kind`/`root`/`id`, `session`, `capabilities`.
- `docs/LOCK.md:274` "`lock` and `delete` write the lock by default" omits `create` (README,
  DESIGN §3.5 include it); `:113-115` lists the bindings without `pop-unwrap`.
- `crates/core/src/config/observe.rs:85-86` cites "`caprobe probe --record`", which does not exist
  (no `record` flag in `crates/caprobe`).
Fix: correct the text; add a test that loads CONFIG.md's annotated example.

### A-16. Test-quality gaps in core tests — low — 7 — verified

- `crates/core/tests/exit_codes.rs:84-106` lists `KmError` variants by scraping `src/error.rs`'s
  text for match arms and keeps a hand list in `code_of` (`:8-27`); a `#[cfg(test)]` exhaustive
  `match` in error.rs gives the same guarantee at compile time.
- `crates/core/src/config/mod.rs:1544-1547`: `a_lock_that_cannot_be_saved_is_its_own_code` returns
  (passes) when run as root.
- `crates/core/tests/lock_mbt.rs:28-66`: the model's keys.toml never retargets a spec, so the rule
  review reconcile F1 fixed (`reconcile.rs:204`) is outside the replay; OPEN.md's "left for the
  model" list does not name it.
- `crates/profile/tests/answers.rs:87-146` pins `generate`, `generate_secret`, `curve`, `oaep` but
  no `commit` verdict (A-1 went unseen).

### A-17. A lock that fails validation on save after a token write exits 17, not 21 — low — 1 — verified (latent)

`crates/core/src/config/io.rs:53`, `crates/core/src/error.rs:128-132`
`save_lock` maps only I/O errors to `LockUnwritable` (21, "the token may hold what the lock does not
record"); a `check` failure stays `Validation` (17) even after `create` made a key. Reachable only
through a `record` bug, which is what the save-time check exists to catch. Fix: map it to 21 with
the validation reason.

### A-18. No fuzz target for the PEM/DER certificate reader of user-named files — low — 7 — plausible

`crates/core/src/chain.rs:177-210`; `fuzz/fuzz_targets/`
`certs_of`/`pem_certs` hand-split PEM blocks of `options.ekCertificate`/`ekRoots` files (new with
912a06d); the `piv_chain` target feeds DER only and `certificate` only `id::cert_spki`. The slicing
is on ASCII delimiters and looks safe; a target is cheap insurance. Fix: `fuzz_targets/cert_bundle.rs`
calling `chain::certs_of` (and `chain_to_anchor` against the fixture roots).

## Complexity reduction proposals (ranked, with estimated lines saved)

Repo-wide (architecture) first:

1. **One home per model: move camigrate's capability model out of core (A-6)** and convert the
   profile crate's `Migration`/`AcceptRow`/`PlaintextKind` straight into it inside camigrate.
   Core keeps the frozen `Method`/`Exposure` (+ `OaepHash`). Core −290 lines; net −60 to −100
   once one of the two `Accept`/`AcceptRow` models goes. Evidence: rg shows no non-camigrate user.
2. **One vocabulary for the names core, profile, pkcs11 and camigrate share.** Today: commitment
   kinds/mechanisms in four tables (A-9); `profile::KeyKind` vs `core::types::KeyType`;
   `profile::Proof` vs `config::Binding`; `baseline::CURVES` vs `id::Curve::ALL`; profile OAEP hash
   strings mapped by hand to `pop::OaepHash` (`camigrate/src/tokens.rs:398-404`); three pinning
   tests (`the_profiles_name_every_curve_cakeys_has`, `…know_every_key_type_and_proof…`,
   `commit_mechanisms_are_pinned`). The profile crate's stated independence from core serves no
   consumer (pkcs11, caprobe and camigrate all depend on both). Let profile depend on core's types
   (or a tiny names crate) with an open wrapper `KeyKind::Known(KeyType) | Other(..)`. ~120-180
   lines and three sync tests.
3. **Parse object types once (A-8).** ~80-120 lines of fallible re-parsing and unreachable
   error arms across core, pkcs11, kmsp11, camigrate, caprobe.
4. **Verification stack proportional to the code.** `hex` (two one-line `base16ct` wrappers) has a
   proptest, a fuzz target and two Kani proofs; `attest_encoding` (a length-prefixed concat) a
   proptest and a fuzz target; Kani is built from source (`nix/kani.nix`) and `checks.kani` costs
   ~3 min and up to 5.7 GB for three proofs (OPEN.md:353-377). Keep the proptests; drop the `hex`
   and `attest_encoding` fuzz targets and the hex Kani proofs; keep Kani only if the
   `fix_ec_point` proof is judged worth the package. −70 Rust (`fuzzing.rs:9-32,135-167`, two
   targets, 12 Cargo lines), and possibly `nix/kani.nix` + `checks.kani`.
5. **Trim the profile algebra to what verbs ask (A-1 context).** `Effective::query`, `class`, `curve`,
   `oaep`, CKP parameter-set routing and `baseline.class` serve only `caprobe supports`; 12 of the
   baseline's 18 tables (`return-values`, `flags`, … `validation-types`) are parsed at every tool
   start and read by nothing at run time (planned by PLAN.md A1). Merge `generate`/`generate_secret`/
   `commit`'s three interpolation rules into one helper (fixes A-1). ~120 Rust lines; ~600 lines of
   baseline TOML not parsed at start if A1 is dropped.

Local:

6. **Split `config/mod.rs` (A-7)**: no net change, mod.rs 2,084 → ~900; ~320 test lines move to
   lock.rs/io.rs.
7. **Delete test-only/dead API (A-13)**: ~60 lines.
8. **`exit_codes.rs` source scraping → exhaustive match (A-16)**: ~25 lines, and the test stops
   depending on rustfmt's layout of `exit_code`.

## Still open from the 2026-11-18 review (one line each)

Every numbered prior finding in scope is Fixed or Decided (properties.rs F3: Decided, moot). Open
design notes (no ID):

- plan.rs design: `Target::schemes` and `plan_mode` still derive "which commitments" by two paths (`plan.rs:57-69` vs `:281-311`).
- plaintext.rs design: `private_from_pkcs8` still takes `curve: Option<&str>` (folded into A-8).
- pop.rs/migrate.rs design: `migrate::Method` still imports `OaepHash` from `pop` (`migrate.rs:8`) (folded into A-6).
- config.rs design: whole-`ObjectCfg` type equality (now A-5).
- profile.rs design: `Restrict`/`Reported` `min-bits <= max-bits` still unchecked at load.
- effective.rs design: no table-driven "never yes from absence" test over committed profiles (A-1 is the hole it would catch).
- reconcile.rs design: `record` still has no comment that it relies on `compare` having run.
- fuzz design notes: `config` target's `env` always answers; `piv_chain` reaches chain rules only unmodified; `tpms_attest` without a sanitizer; `public_key` checks idempotence only.

## Cross-area notes (issues seen in another agent's files; one line each, no deep dive)

- `crates/pkcs11/src/gate.rs:240-256`: `commitments_refused` refuses only when every verdict is No, so A-1's wrong Yes passes the gate.
- `crates/pkcs11/src/token/possession.rs:57,295,347`: one challenge reused across OAEP hash retries (fine; DESIGN wording, A-15).
- `crates/tpm2-pkcs11/src/attest/ek.rs:81-85`: no `tcg-kp-EKCertificate` EKU or keyUsage check on the EK leaf (A-3).
- `crates/ykcs11/src/attest.rs:63-67`: the slot certificate's issuer name is never compared with the device subject (signature is checked; low).
- `crates/cli-common/src/lib.rs:248-269`: `read_lock` takes the `.lck` guard the pre-check does not cover (A-12).
- `crates/camigrate/src/{keyfile.rs:241,host.rs:75,file_verbs.rs:106}`, `caprobe/src/probe/moves.rs:203`: every `plaintext::spki_of_pkcs8` call is wrapped in `id::spki_canonical`; return the canonical SPKI once.
- `crates/p11-names` (from cryptoki-sys, used only by p11-fault) and the profile baseline (from the OASIS headers) are two PKCS#11 name registries.
- `crates/camigrate/src/tokens.rs:398-404`: OAEP hash names mapped by hand from profile strings to `pop::OaepHash`.

## Files reviewed (every file in scope, with one line each: "clean" or finding IDs)

- `crates/core/Cargo.toml` — clean
- `crates/core/src/lib.rs` — clean
- `crates/core/src/attrs.rs` — clean
- `crates/core/src/chain.rs` — A-3, A-18
- `crates/core/src/config/mod.rs` — A-5, A-7, A-8, A-14, A-16
- `crates/core/src/config/lock.rs` — A-13
- `crates/core/src/config/io.rs` — A-4, A-12, A-17
- `crates/core/src/config/observe.rs` — A-15
- `crates/core/src/error.rs` — A-16, A-17
- `crates/core/src/fuzzing.rs` — proposal 4
- `crates/core/src/hex.rs` — clean (proposal 4)
- `crates/core/src/id.rs` — A-9, A-13
- `crates/core/src/migrate.rs` — A-5, A-6
- `crates/core/src/plaintext.rs` — A-8
- `crates/core/src/plan.rs` — A-10
- `crates/core/src/pop.rs` — A-11, A-13
- `crates/core/src/reconcile.rs` — A-2, A-5
- `crates/core/src/secret.rs` — A-14
- `crates/core/src/sig.rs` — clean
- `crates/core/src/types.rs` — clean
- `crates/core/tests/common/mod.rs` — clean
- `crates/core/tests/exit_codes.rs` — A-16
- `crates/core/tests/fuzzing_surface.rs` — clean (source-scanning meta test, hard-coded count of 6 is intended)
- `crates/core/tests/lock_mbt.rs` — A-16
- `crates/core/tests/properties.rs` — clean
- `crates/core/tests/refusals.rs` — clean
- `crates/core/tests/fixtures/*.pem`, `properties.proptest-regressions` — clean (data)
- `crates/profile/Cargo.toml` — clean
- `crates/profile/src/lib.rs` — A-13
- `crates/profile/src/baseline.rs` — proposal 5
- `crates/profile/src/capability.rs` — A-9
- `crates/profile/src/effective.rs` — A-1
- `crates/profile/src/embedded.rs` — clean
- `crates/profile/src/names.rs` — A-13, proposal 2
- `crates/profile/src/profile.rs` — clean (open design note: min/max unchecked)
- `crates/profile/tests/answers.rs` — A-16
- `crates/profile/tests/answers.txt` — skimmed, clean (does not cover `commit`)
- `fuzz/Cargo.toml` — proposal 4
- `fuzz/fuzz_targets/attest_encoding.rs` — proposal 4
- `fuzz/fuzz_targets/bundle.rs` — clean
- `fuzz/fuzz_targets/certificate.rs` — clean
- `fuzz/fuzz_targets/config.rs` — clean (open design note)
- `fuzz/fuzz_targets/hex.rs` — proposal 4
- `fuzz/fuzz_targets/key_file.rs` — clean
- `fuzz/fuzz_targets/lock.rs` — clean
- `fuzz/fuzz_targets/p521_point.rs` — clean
- `fuzz/fuzz_targets/piv_chain.rs` — A-18
- `fuzz/fuzz_targets/profile.rs` — clean
- `fuzz/fuzz_targets/public_key.rs` — clean
- `fuzz/fuzz_targets/tpm_store_row.rs` — clean
- `fuzz/fuzz_targets/tpms_attest.rs` — clean (open design note)
- `docs/DESIGN.md` — A-2, A-15
- `docs/LOCK.md` — A-15
- `docs/CONFIG.md` — A-14, A-15
