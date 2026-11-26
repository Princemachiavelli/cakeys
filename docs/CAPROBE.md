# caprobe: capability profiles and the probe

What a PKCS#11 module can really do — which mechanisms work, which curves it generates, which
OAEP hashes it implements, its unwrap-template rules — is data, not provider code: a
*capability profile* per module on its hardware, and one per layer between cakeys and the token.
`caprobe` measures modules and writes those profiles; `cakeys` and `camigrate` read them. It is
the only tool that creates and destroys scratch objects.

Evidence tags: **[run]** verified in this repo, **[spec]** the OASIS PKCS #11 and TCG TPM2
standards, **[src]** read in a module's source, **[todo]** still to verify.

## Command line

```console
$ caprobe supports [<CKM_*|CKK_*|CKP_*|curve>] (--profile <p> | --token <t>) [--layer <l> ...] \
    [--bits <n>] [--class pq|hmac|key-wrap|oaep] [--oaep] [--profiles <dir>]
$ caprobe caps --token <t>
$ caprobe probe --token <t> [--write-probes] [--out <file> [--accept]] [--diff <profile>] [--name <profile>] [--profiles <dir>]
```

- `supports` asks the profiles alone; no token is touched, and `--profile` needs no keys.toml.
  Answers cite the deciding profile ("no: cryptoki (unpatched build) subtracts it"). Exit 0 yes,
  15 no, 16 unknown. `--token` resolves the token's stack as `cakeys validate` and `create`'s
  gate do (`gate::stack`): its provider (or `moduleProfile`), its configured `profiles` layers,
  from the one profile set every tool activates (embedded, `profileDirs`, then `--profiles`). It
  never reads keys.lock, so it answers as `validate` does for a token the lock records nothing
  of: with no module recorded, the rows the hardware decides are unknown. A key type asked without a curve or size is yes when some row of it generated or the
  module reports it, no when every row says no.
- `caps` prints a token's provider, its resolved stack of profiles and its usable mechanisms as
  JSON.
- `probe` generates a token's profile (below). With `--diff`, any difference in the observable
  rows is printed and the exit is 15.

Other exit codes are the shared ones ([CAKEYS.md](CAKEYS.md#exit-codes)); 17 includes a write
probe on a token not marked scratch.

Regenerating the committed profiles: `profiles/LEDGER.toml` names the command for each
(["The ledger"](#the-ledger)). `scripts/regen-profiles.sh` sets up the three reference tokens as the check phase does and
regenerates their files; the others take the device or the cloud. Only the Nix-built binary
carries the patched cryptoki the probe needs.

## Why data, and what stays code

| Fact | Example | Medium |
|---|---|---|
| What a module shows through PKCS#11 | usable mechanisms; OAEP hashes actually implemented (SoftHSM: SHA-1 only [run]); generatable curves (kryoptic: no secp256k1 [run]); unwrap-template rules; SO-login needs; delete semantics | profile data |
| Behaviour outside PKCS#11, or that must be rewritten | tpm2's P-521 point repair; PIV attestation and its pinned roots; `TPM2_Certify`; `tpm2_ptool` | provider code |

The `Provider` hooks that rewrite behaviour or reach outside the module (`ec_point`, `key_type`, `policy_flag`, `stand_in`, `template`, `create`, `destroy`, `attestation`,
`check_options`, `plaintext_import`, `bound_keys`, `generation`) stay code. A
vendor whose module needs no fix-ups needs no Rust. When no code provider claims a module, the
module profile whose `[match] manufacturer` it reports names its provider by family
(`provider::Data`). `softhsm` and `kryoptic` are such data providers, and
`provider = "<family>"` selects one by name. Two families claiming one manufacturer are refused
(17) until `provider` names one. A family whose provider is code (`CODE_FAMILIES`) is never a
data provider: without its code it is refused (17).

## The format: deltas over a spec baseline

**The baseline** (`profiles/baselines/pkcs11-3.2.toml`) is generated from the OASIS 3.2 headers,
vendored unmodified at `profiles/baselines/headers/pkcs11-3.2/`, and pinned by a test
(`CAKEYS_UPDATE_BASELINE=1` regenerates it, beside it until `CAKEYS_ACCEPT=1`). It is the vocabulary of one spec revision: every
mechanism, key type, attribute (the array attributes included), object class, curve, function
and parameter set, and the other constant families (return values, flags, user types, session
states, certificate and hardware-feature types, MGFs and IV generators, KDFs, sources,
notifications, trust and validation types), name → ID, grouped into classes (`pq`, `hmac`,
`key-wrap`, `oaep`). It validates names and powers by-class queries; it never claims what a
vendor supports.

**A module profile** (`mode = "observed"`, `profiles/modules/<family>/<version>[+<hardware>].toml`)
records what a probe measured, as deltas against the module's own advertisement:

```toml
profile = "softhsm/2.7"
mode = "observed"
advertise = ["CKM_AES_CBC", "..."]         # what C_GetMechanismList returns
# subtract = { mechanisms = [...] }        # listed but unusable; `add` for usable but unlisted
[match]
manufacturer = "SoftHSM"
module-version = "2.7"
model = "SoftHSM v2"
firmware = "2.7"
[capabilities]                             # one row type: what cakeys' operations do here
"generate.CKK_EC.secp256r1" = { answer = "yes", by = "host" }
"generate.CKK_EC_EDWARDS.edwards25519" = { answer = "yes", by = "host", via = "by-name" }
"generate.CKK_RSA.2048" = { answer = "yes", by = "host" }
"wrap.rsa-oaep.SHA-256" = { answer = "no", by = "module", evidence = "CKR_ARGUMENTS_BAD" }
"decrypt.rsa-oaep.SHA-1" = { answer = "yes", by = "host" }
"unwrap.template.CKA_VALUE_LEN" = { answer = "no", by = "module" }   # refused in an unwrap template
"derive.ecdh.sealed" = { answer = "yes", by = "host" }   # also derive.ecdh.read-only
"move.secret-unwrap" = { answer = "no" }              # move.*: hand-written claims
[reported."CKK_RSA"]                       # the sizes C_GetMechanismInfo reports
min-bits = 512
max-bits = 16384
[migration]                                # hand-written: what the import paths take
plaintext-import = "create-object"
[notes]                                    # what the probe saw, as CKR_* names
[manual."secret-unwraps"]                  # findings a person made: `finding` and `evidence`
```

A capability row is `"<capability>" = { answer, by, evidence, via }`: `answer` is `yes` or `no`,
`by` who showed it, `evidence` what shows it, `via` how it succeeded where there is more than one
way. The
capabilities name cakeys' operations (`crates/profile/src/capability.rs`): a generation per key
type and curve or size, a wrap and a decryption per OAEP hash, an unwrap template attribute,
ECDH into a sealed secret and in a read-only session, the moves, a proof of possession per
binding and key (`prove.pop-ecdh.CKK_EC.secp256r1`), and per key type and curve or size how a
key gets in and out: imported from plaintext (`import.CKK_AES.32`, `via` the path), a public
object created from its value (`create.CKO_CERTIFICATE`), handed to the host or wrapped toward
another token (`export.host.*`, `export.sealed.*`, `via` camigrate's method), unwrapped
(`unwrap.*`), and deleted per class (`delete.CKO_PRIVATE_KEY`)
([What the probe measures](#what-the-probe-measures)). A size is in the key type's own unit: RSA in
bits, a `valueLen` type in bytes. The probe measures the proofs with the
verbs' own code (`Token::prove_binding`) on a token opened with no module profile
(`Token::unprofiled`), so what it records is what the module does, not what the committed
profile already says; it generates the key types cakeys manages the same way (`Token::create`,
the provider's create operation), each refusal the row's evidence. A new one is a variant
there and the operation that tests it; the emitter, the diff and the stack algebra do not
change. *An absent row is unknown*: never probed, never claimed — a spec-compliant default.
A row naming a key type, proof (`pop-*`), OAEP hash or template attribute (`CKA_*`) this
cakeys does not know loads as read and answers nothing, so a profile from a newer cakeys loads;
only a row's shape is refused. A probe from this cakeys never writes such a row, so `--diff`
reports it and a regeneration drops it.

**Provenance** (review 2026-11-24 E-2 to E-5). `by` is `host` where the host checked the
outcome (a signature verified, a key read back or compared, a commitment recomputed, or the
module's answer found wrong), `module` for the module's own refusal, and `unverified` for a yes
only the module vouches for (a commitment or a cipher mode the host does not recompute, a secret
import checked only by the module's own commitment, an unwrap of the module's own blob alone).
A sealed export wraps toward the imported `rsa-2048` test key and is `host` only when the host
decodes the blob to the key (RFC 8017 OAEP, then RFC 5649 under the KEK); a blob it cannot decode
is a `host` no, since another token reads only that encoding (review 2026-11-24 E-3). camigrate
takes an `unverified` yes and defers rule `capability` to the run. A `yes` is never `module`, a
`no` never `unverified`, and a `module` no citing a
device failure is refused at load (`Row::problem`). A step that failed with a device, token or
session return value (`DEVICE_FAILED_RV`: `CKR_DEVICE_ERROR`, `CKR_GENERAL_ERROR`,
`CKR_HOST_MEMORY`, ...) is no answer of the module's: the probe writes no row but an `[untested]`
entry under the capability, `why = "device"`; one cakeys refused before the module was asked (a
provider's template, no host verifier for Ed448, a key no binding names) is `why = "cakeys"`.
Both read *unknown* and are refused like a no (15), naming the re-probe (T2 in
`profiles/LEDGER.toml`): never planned as yes. A mechanism that signs but whose signatures the
host cannot verify (SHA-1, raw RSA) is `[untested]` `why = "unverified"`. A row without `by` is
legacy, probed before provenance (the hardware and cloud profiles, until probed again) or written
by hand (`move.*`), and decides as before, except a legacy `no` whose evidence names a device
failure: unknown, refused (15) with the same note. The committed ones are tpm2-pkcs11's 4 on
amd-ftpm and ykcs11's 10 import rows (`the_committed_device_failures_are_these`). A profile with
`by` does not load in a cakeys from before it (17: an unknown field), so a `profileDirs` profile
regenerated by this caprobe needs this cakeys.

A shipped profile describes a kind of token; the lock records what each deployment's own token
answered (docs/LOCK.md, an observation's `capabilities`: the proofs `lock` gave, the
generations `create` made), and those answers decide before the profile's in `validate`,
`create`'s gate and camigrate's planner. A profile's *no* — or the token's — refuses; *unknown*
means try, except for what cannot be undone.

`[migration]`, the `move.*` rows and `[manual]` are written by hand; the probe preserves them
and the diff never compares them, so a reader always knows which rows were observed. `--out`
keeps them only from a file of the profile just probed: one of another family is refused (17),
and one of another name of the family unless `--name` says which it is. A file there that the
profile differs from is replaced only with `--accept`; otherwise the profile goes beside it, as
`<file>.new`, for review ([DEVELOPMENT.md](DEVELOPMENT.md), "Golden files"). Where a
probed `import.*`, `create.*`, `export.*` or `unwrap.*` row covers an object's type it decides
before `[migration]` and `move.*`, which answer for the rest until every committed profile
carries the probed rows ([archive/CAPROBE_MIGRATION.md](archive/CAPROBE_MIGRATION.md) M4). A mechanism the
module advertises that no row measures is listed in `[untested]` with a reason (`cryptoki`,
`vendor`, `hardware`, `cloud`, `scope`, `unprobed`) and reads *unknown*, never *yes*; the
commitments cakeys computes (`commit.*`), the symmetric modes (`crypt.*`), key derivations
(`derive.CKM_*`), attributes (`attr.*`) and post-quantum rows are probed beside the rest, and
`[mechanism-info]` and `[claims]` record what the module reports of itself, never compared. What
was built and what is open: [What the probe measures](#what-the-probe-measures).

**Layers** (`mode = "delta"`, `profiles/layers/`, `profiles/hardware/`) forward everything except
what they subtract:

- `p11-kit/0.26`: its RPC drops AES key wrap, `CKM_RSA_AES_KEY_WRAP`, Edwards generation and
  `CKM_EDDSA`, among others [run]. It is marked `requires-provider = true`: it hides the module
  behind it, so nothing about that module applies until keys.toml names its `provider`, and
  plans warn until it does.
- `cryptoki/0.12`, the binding layer, injected into every stack. What it subtracts is decided at
  run time: a binding with the HMAC key-type fix (the Nix patches, or upstream once released)
  subtracts nothing, so the layer heals itself.
- `swtpm`: libtpms's default-v1 profile refuses RSA-4096 [run]. Hardware layers are hand-made
  factorings of an observed module-on-hardware pair, never probe output.

`supports(x)` is the intersection over the stack: any layer's subtraction kills it; otherwise the
module profile decides. The binary embeds the profiles this repo ships.

- **`caprobe --profiles <dir>`** adds or replaces entries; regeneration needs to replace.
- **keys.toml's `profileDirs`** add module profiles at run time for all three tools: a new
  vendor, and its provider, without a rebuild. They only add, and may not replace an embedded
  profile, a layer or the baseline: those are this repository's, each measured as
  `profiles/LEDGER.toml` records. The run says which profiles came from there.

## What the probe measures

What the profile-coverage and probed-move plans built (their history:
[archive/CAPROBE_PROFILE_COVERAGE.md](archive/CAPROBE_PROFILE_COVERAGE.md),
[archive/CAPROBE_MIGRATION.md](archive/CAPROBE_MIGRATION.md)); what is still open is in OPEN.md
("More probes").

- **`[untested]`**: a mechanism the module advertises that no row measures, with why (`cryptoki`,
  `vendor`, `hardware`, `cloud`, `scope`, `unprobed`, `unverified`), computed from what the probe
  tried; and a capability the probe could not decide, `device` or `cakeys` (Provenance, above).
  It reads *unknown*, never *yes*, except `scope` (digests the tools hash on the host).
  `Profile::untested_problems` and an emitter test keep it consistent. cryptoki's own limits
  (`CKM_AES_CFB128`, `CKM_XEDDSA`, `CKM_AES_KEY_WRAP_KWP`) are notes and subtractions in
  `profiles/layers/cryptoki.toml`, and the patched-binding layer in `binding.rs`.
- **Secret keys**: `commit.<kind>.<key type>.<bytes>`, computed with the verbs' own
  `Token::commit`, twice and on a second key for distinctness; the gate refuses only when every
  commitment a spec declares is measured *no*. Import, export and unwrap rows for generic secret,
  the five HMAC types and Triple DES, checked by commitment (AES by its host check value).
- **Reported, never compared**: `[mechanism-info]` (`C_GetMechanismInfo`) and `[claims]` (token
  flags, session limits, PIN length, interface version, hardware-feature, profile and validation
  object counts); a generation outside the reported range is a note. `attr.read.*` and
  `attr.set.CKA_ALLOWED_MECHANISMS` (`via = "enforced"`).
- **Operations**: `crypt.*` (AES CBC, CBC-PAD, CTR, GCM; Triple DES CBC and CBC-PAD, a round trip
  on the token); `derive.CKM_*` (HKDF, the three concatenations, XOR, extract-key-from-key,
  AES-CBC-encrypt-data, each against the host); Montgomery ECDH; `CKK_DES2` and `CKK_HKDF`
  generation; ML-DSA, ML-KEM and SLH-DSA per parameter set (every listed pure and hashed
  signing variant, verified on the token, and encapsulate/decapsulate).
- **Moves** (`crates/caprobe/src/probe/moves.rs`, after the wrap probes): `import.*`,
  `create.*`, `export.*`, `unwrap.*` and `delete.*` (`Capability::{Import, Create, Export,
  Unwrap, Delete}`), from the fixed keys in `crates/caprobe/fixtures/import`. camigrate's planner
  reads them through `Side::probed`, as do `Profile::unwraps` and
  `Profile::creates_public_keys`. Where they depart from a plain measurement:
  - RSA import runs from 1024 to 8192 bits: the rsa crate takes no public key outside that range.
  - `move.secret-unwrap` stays a claim: the reference suites run SoftHSM with the upstream
    `CKA_VALUE_LEN` fix, deployments stock 2.7, so `unwrap.*` checks the material alone.
  - `tpm2_ptool` imports are not probed (the token would have to be reopened): tpm2-pkcs11
    profiles have no `import.*` rows, and their hand-written `plaintext-accepts` decide.
  - The sealed exports name camigrate's methods, tried in camigrate's order with
    `CKM_RSA_AES_KEY_WRAP` last.
  - Only the planner, the proof check and `accepts_public_key_objects` read the move rows;
    `validate` and `create`'s gate do not yet. `delete.*` is read by the delete's rule
    (`deletion`): a row that answers no refuses the delete before anything is destroyed
    (`k6_a_profile_no_refuses_the_delete_before_any_destroy`).
  - On a YubiKey the probe imports as SO into the scratch slot only, and writes there the key
    it probes and its own mark certificate (`CN=cakeys-probe`), leaving the placeholder
    certificate ykcs11 generates (`only_the_slots_attestation_sits_beside_the_probes_certificate`).

## Coverage

`spec-coverage/cakeys.toml` gives every row of the baseline one status (PLAN.md A1). It is
generated, never edited, and pinned like the baseline:

| Status | Meaning |
|---|---|
| `used` | a call of cakeys, caprobe or camigrate reached it in the traced test run |
| `out-of-scope`, `gap` | `spec-coverage/manual.toml`: a hand-kept rule, with its reason (a gap names its OPEN.md item) |

- **The trace** is the test suites run with every module behind a tracing p11-fault
  (`nix/test-tokens.sh` with `CAKEYS_TRACE_DIR`): each call's function, return value,
  mechanism (with its OAEP or PSS hash and MGF, OAEP source or ECDH KDF), template attribute
  types, object classes, key and certificate types, user type, and the flags it passed or read
  back. Only the tools' own calls count: not a test harness, pkcs11-tool, `p11-kit remote` or
  OpenSSL. The tests that run their own p11-fault are not traced, nix/test-tokens.sh naming them (their hooks' calls would count
  as the tool's).
- **The check**: every build's test run holds the committed file to the baseline and
  `manual.toml` from its own `used` rows (`crates/caprobe/src/coverage.rs`): a row without a
  status, a manual rule that matches nothing or names a used row (by name, or a pattern whose
  every row is used), or a file that differs fails it. Whether the `used` rows are still what a
  traced run reaches is the report's to say, not the check's (it cost a second full traced pass
  per build).
- **Regenerate**, a report and never a check: `nix build .#spec-coverage` (then copy
  `result/cakeys.toml` over the committed file), or `scripts/coverage-file.sh` outside Nix. Both
  write `coverage-report.txt` too: the tests behind each used row, and what the trace reached
  that the baseline does not name (vendor mechanisms, return values, functions).
- **What it cannot see**: `C_GetInterface` (p11-fault exports the 2.40 entry point only, so the
  traced run uses the 2.40 table); calls only a hardware suite makes (the YubiKey and the real
  TPM are never traced).

## Decisions

- **D1.** Baselines are generated from the PKCS #11 OASIS headers, one file per spec revision,
  committed and pinned. PQ parameter sets are first-class rows.
- **D2.** Module profiles record deltas against the module's advertisement, not against the
  whole spec: small files, and `C_GetMechanismList` stays the drift baseline.
- **D3.** Two modes: `observed` (module on hardware) and `delta` (layers). Effective support is
  the intersection over the stack. The cryptoki binding is a layer too.
- **D4.** Claims and observations are kept apart: a token's `CKO_PROFILE` (`CKP_*`) claims are
  to be recorded and verified, never trusted. Not built yet.
- **D5.** Probes write profiles; the committed TOML is what everything queries. Write probes are
  the offline compiler, scratch-guarded. `cakeys` runs no live-token profile check (decided
  2026-11-13): the operator runs `caprobe probe --diff`.
- **D6.** Behaviour hooks and vendor tools stay code. A profile with no hooks needs no crate.
- **D7.** Say *capability profile*, to keep clear of the spec's `CKP_*` conformance profiles.
- **D8.** The lock records the resolved profile name in the observation (`observations.<key>.profile`), so
  drift warnings and `caps` name it.
- **D9.** A profile matches on four keys: manufacturer, module version (`C_GetInfo`; omitted when
  the module hides it as 0.0), token model and firmware (`C_GetTokenInfo`). Resolution prefers
  the profile matching the most, with a note when the evidence is weak. Never a module digest: a
  rebuild of the same module is another hash with no behavioural difference.
- **D10.** A probe measures a module and its hardware together, and nothing in PKCS#11 says whose
  refusal is whose. So an observed profile is a pair, named module first
  (`tpm2-pkcs11/1.10+swtpm`; software tokens keep plain names). A token whose hardware has no
  pair yet resolves the nearest one for what the module advertises only: generation and wrapping
  answer unknown. Pairs rank by a hardware layer the config names, then model and firmware.
  A module version no pair of its family records (a client library update) is no error either:
  the nearest recorded version stands in the same way, module rows only, with a note naming
  `caprobe probe`. No profile is ever required to open a token.
- **D11.** TOML, like keys.toml and the lock, so Nix reads profiles directly. p11-kit's `.module`
  files cannot carry mechanism lists or evidence.
- **D12.** A token's *mode* (FIPS-approved or not) is a match axis like its firmware, entered as
  data in `[match.fields]`: standard fields from PKCS#11 3.2 (`CKO_VALIDATION` objects,
  `C_GetSessionValidationFlags`, `CKF_ERROR_STATE`), vendor fields through an observing provider
  hook (`"ykcs11.fips-mode"`, a TPM's `TPM_PT_MODES`). One generic match rule for every field.
  Requiring a mode is policy, checked against the live token at open
  (`tokens.<t>.require = { fips = "approved" }`, 14 when unmet). Not built (OPEN.md).

## The probe

- **Read-only probes**, safe on any token: `C_GetInfo`, `C_GetTokenInfo` (never the serial, so a
  profile regenerates identically), `C_GetMechanismList`, and `C_GetMechanismInfo` for RSA sizes.
- **Write probes**, only with `--write-probes` on a token keys.toml marks `probe.scratch = true`, logged in
  (refused with 17 otherwise): key pairs per baseline curve, and per RSA size from 512 to 16384
  bits (512, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384), whatever the module
  reports — what it reports is a claim, `[reported."CKK_RSA"]`, and cryptoki the only limit;
  `--rsa-max-bits` stops earlier. Every regeneration passes 4096 (`[regen]` in
  `profiles/LEDGER.toml`, which `checks.ledger` holds each script to): 16384 bits take a
  software token over a minute, so the committed profiles stop there, and the gate answers
  unknown above. The cloud profiles keep rows to 16384 from before that rule (review 2026-11-24
  E-8) until their next probe. A curve family whose generation mechanism the module does not list is tried
  all the same, an `add` row where it generates. Each key that generates with its usage proves
  possession by every binding of its kind, a `prove.*` row each. Every secret key type cakeys
  manages (AES, generic secret, Triple DES, the five hash-bound HMAC types) the module lists a
  generation mechanism for, made as the verbs make it (`Token::create`) at a sweep of lengths in
  bytes, `generate.<key type>.<bytes>`, yes or no: AES at 8, 16, 24, 32, 48 and 64 (the three it
  defines, and lengths a module should refuse), a generic secret and an HMAC key at 1 to 1024,
  Triple DES at the 24 its type fixes. The gate answers for a length it tried, and for a length
  between two that generated only where the length is free (never AES). A mechanism that
  generates no length is a `subtract` row; RSA-OAEP SHA-1 and SHA-256, counted only when the key unwraps
  back; each advertised key wrap (`CKM_AES_KEY_WRAP`, `_PAD`, `_KWP`, and `CKM_RSA_AES_KEY_WRAP`
  under the RSA key) round-tripped, a `subtract` row only when refused as a mechanism
  (`CKR_MECHANISM_INVALID`, `CKR_FUNCTION_NOT_SUPPORTED`) and a note otherwise — `C_GetMechanismInfo`
  flags are no evidence (AWS CloudHSM [run]); the `CKA_VALUE_LEN` unwrap rule;
  fixed test keys (`crates/caprobe/fixtures/import`) imported, then handed to the host and
  wrapped toward the RSA key and back, each checked on the host, and a certificate and a data
  object created; delete-really-deletes, a `delete.<class>` row per class the probes made. On
  the first key of each kind, every signing, ECDH and decryption
  mechanism the probe knows, listed or not (on a key bound to some, Cloud KMS, only those),
  checked on the host where cakeys can verify. An advertised mechanism that fails on every key
  is a `subtract` row, a partial failure a note; one the module does not list but runs is an
  `add` row (SoftHSM and kryoptic sign with `CKM_ECDSA_SHA224` and `CKM_SHA224_RSA_PKCS`, which
  neither lists [run]). A failure because an earlier operation left the session busy
  (`CKR_OPERATION_ACTIVE`: tpm2-pkcs11 leaves a failed one active [run]) is undetermined, never
  a row.
  A standard mechanism the module does not list but the provider runs its own way (what
  `Provider::stand_in` answers: AWS CloudHSM's Ed25519 generation and EdDSA) is probed through
  the stand-in, and an `add` row when it works (the host verifies the signature); the token then
  counts it as offered, and nothing else does.
  Every run destroys what it made. Notes carry `CKR_*` names, stable across binding releases.
- **SO-only modules** (ykcs11): `tokens.<t>.probe.scratchId` names the one slot write probes may
  generate into. The slot must be empty or hold the probe's own certificate (`CN=cakeys-probe`),
  which every slot run writes there last, one issued over each key the slot holds (signed by the
  P-256 test key, the same bytes for the same key), beside those keys (or the probe's own test
  keys) and at most the device's attestation of the slot; anything else is refused (17) before a
  write, a marked slot whose key is another too (one `ykman piv keys generate` put there).
  ykcs11's placeholder certificate is no mark: it writes one for every key it generates, a real
  key's too. A run stopped before its last step leaves the slot unmarked, refused until it is
  emptied (`scripts/yubikey-empty-slots.py`). A `scratchId` that is the `CKA_ID` of a locator
  keys.toml has on that token is invalid at load.
  No delete or wrap probes there: PIV cannot erase a key.
- **RSA sizes**: an observed size decides; outside the reported range is no; between two that
  generated, with no size tried between them refused, is yes; otherwise unknown (a TPM
  generates only its discrete sizes: swtpm's 1024 yes, 1536 no leaves 1280 unknown).
- **The diff** compares the match keys, `advertise`, `reported`, `subtract`, `add`, `restrict`,
  `[untested]` (each mechanism's reason) and every probed capability row (answer and `via`); without `--write-probes`, only what a read-only probe sees.
- **Only the Nix-built binary may write or diff a profile**: an unpatched binding hides
  mechanisms it cannot name (kryoptic's `CKM_AES_KEY_WRAP_KWP` [run]).

## What the probes found

| Profile | Findings |
|---|---|
| `softhsm/2.7` | OAEP SHA-1 only, for wrapping and decryption (SHA-256 is `CKR_ARGUMENTS_BAD`); every baseline curve generates; RSA 512–16384 reported. AES generates at 16, 24 and 32 bytes, refuses 8, 48 and 64 (`CKR_ATTRIBUTE_VALUE_INVALID`); a generic secret at 1 to 1024; Triple DES at 24; no `CKM_SHA*_KEY_GEN`, so no hash-bound HMAC key. An unwrapped secret key's `CKA_VALUE_LEN` reads 0 (`move.secret-unwrap` no, an upstream issue to file). Offers `CKM_RSA_AES_KEY_WRAP`; the SO can create a trusted RSA public key |
| `kryoptic/1.5` | Reports module version 0.0, matched by firmware (its real version). OAEP SHA-1 and SHA-256; secp256k1 and brainpool refused; advertises the 3.2 PQ mechanisms (not yet probed). Generates every secret key type it lists, the five hash-bound HMAC types included, at 1 to 1024 bytes, and AES at 8, 16, 24, 32, 48 and 64 bytes alike (no length check; softhsm refuses the three AES does not define); no Triple DES. Cannot make an RSA public key trusted (`move.trusted-wrap` no) |
| `tpm2-pkcs11/1.10+swtpm` | Reports Cryptoki 2.40. `CKM_AES_KEY_GEN` advertised but `CKR_FUNCTION_NOT_SUPPORTED`; no Edwards; RSA 1024–3072. Derived secrets cannot sign (no `CKA_ALLOWED_MECHANISMS`), leak a reference and stay as store rows, so `pop-ecdh` takes the extractable path (`derive.sealed = false`) in a read-write session (`derive.read-only = false`). Never wraps or unwraps |
| `tpm2-pkcs11/1.10+amd-ftpm` | P-256, P-384, RSA up to 2048; SHA-1 and SHA-256 only, so SHA-384/512 ECDSA and RSA-PSS are `subtract` rows, and such a failed `C_Sign` or `C_Decrypt` leaves its operation active on the session (the next `C_SignInit` is `CKR_OPERATION_ACTIVE` [run]: the probe proves possession before its mechanism probes). `pop-sign`, `pop-decrypt` and `pop-ecdh` prove; `pop-unwrap` is `CKR_FUNCTION_NOT_SUPPORTED`. Needs tpm2-abrmd: the kernel resource manager's 3 slots run out on undestroyable objects (`[manual.resource-manager]`) |
| `ykcs11/2.7` (YubiKey 5C NFC FIPS, 5.7.4) | Reports version 2.73, manufacturer `Yubico (www.yubico.com)`. P-256, P-384, Ed25519 (by name only), RSA 2048–4096; refuses RSA-1024, P-521, secp256k1, brainpool, Ed448, X25519 (its template wants a malformed `PrintableString` [src]). ECDH only into an extractable secret, no HMAC; every key reports `CKA_DERIVE = false` (repaired by its provider's `repair`). OAEP decrypts with SHA-1, SHA-256 and SHA-512. Nothing unwraps: `pop-sign`, `pop-decrypt` and `pop-ecdh` prove, `pop-unwrap` cannot. FIPS mode is a `[manual]` finding until D12 |
| `aws-cloudhsm/5.18+hsm2m-fips` (AWS CloudHSM, us-west-1, 2026-11-15) | Reports manufacturer `CloudHSM`, model `LS2`, firmware 10.23, Cryptoki 2.40. Refuses a public key with `CKA_PRIVATE = false`: generated without it, the public key reads `CKA_PRIVATE = true` (the probe retries and notes it). P-256, P-384, P-521, secp256k1, RSA 2048–4096; refuses RSA-1024, brainpool, every Edwards and Montgomery curve. OAEP SHA-1 and SHA-256 wrap; SHA-1, SHA-256 and SHA-512 decrypt. `CKM_ECDSA_SHA1` fails: FIPS refuses an 80-bit digest on a 128-bit key (the client's `enable_ecdsa_with_weak_hash`). Raw ECDH needs the client option `ecdh_without_kdf` (`aws.sh activate` sets it); the derived secret refuses `CKA_EXTRACTABLE = false` (dropped, `CKA_VALUE_LEN` added: `derive.template`), reads sensitive and extractable, and MACs (`derive.sealed`); derivation needs a read-write session. `CKM_AES_KEY_WRAP` and `_PAD` are listed with `CKF_WRAP \| CKF_UNWRAP` and refused (`subtract`) [run]; the client option `--aes-key-wrap-mapping` maps the first to a vendor padding [doc], untried; `CKM_RSA_AES_KEY_WRAP` round-trips, and camigrate moves by it. Even a session object needs a read-write session (camigrate's `Access::Scratch`). Vendor mechanisms (EdDSA `0x80001057`, ML-DSA, AES-GCM, `0x8000216F` = RFC 5649, `0x8000210A` = RFC 3394 over PKCS#5 padding) are listed but cryptoki drops vendor IDs from the list [run]. RSA PKCS#1 v1.5 decryption fails. An unwrap template may not carry `CKA_VALUE_LEN`. Regenerated by `scripts/cloud/aws.sh probe` |
| `aws-cloudhsm/5.18+hsm2m-non-fips` (same, a NON_FIPS cluster) | As the FIPS profile, except that `CKM_ECDSA_SHA1` and RSA PKCS#1 v1.5 decryption work. Ed25519 through the aws-cloudhsm provider's stand-ins, which the probe measures and records in `add` (`CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKM_EDDSA`): the module lists neither, generates Ed25519 as `CKM_EC_KEY_PAIR_GEN` with the Ed25519 OID, reports `CKK_EC` with the whole SPKI as `CKA_EC_POINT`, and signs pure Ed25519 with the vendor `0x80001057` (no parameters) [run]. It never imports one (`[migration] refuses`: a `CKK_EC_EDWARDS` public half is `CKR_ATTRIBUTE_VALUE_INVALID` [run]); it exports one. The FIPS cluster refuses the stand-in generation (`CKR_ATTRIBUTE_VALUE_INVALID`, "Ed25519 key generation not available"), so its profile adds nothing and cakeys refuses an Ed25519 key there before creating. Its match keys equal the FIPS profile's, since PKCS#11 reports no mode (D12): a tie resolves to the FIPS profile, embedded first, the stricter, and the run says so in a note naming both (`caprobe caps` lists it). A NON_FIPS cluster pins this one with `moduleProfile` (`aws.sh cakeys` and `camigrate` do). `CAKEYS_AWS_MODE=NON_FIPS scripts/cloud/aws.sh probe` |
| `kmsp11/1.9+hsm`, `kmsp11/1.9+hsm-fips` (Google Cloud KMS, HSM protection level, us-west1, 2026-11-15) | Probed through the provider's bound keys: one key per Cloud KMS algorithm, each with its own mechanisms. The FIPS build of the library measures the same, with the same `C_GetInfo` (`Google`, 1.9, `Cloud KMS Token`, firmware 0.0), so it is embedded first and the two tie. P-256 and P-384 (signing only), RSA 2048–4096. RSA-1024, P-521, secp256k1 and brainpool have no algorithm (`CKR_TEMPLATE_INCOMPLETE` without one); Edwards and Montgomery are `CKR_MECHANISM_INVALID`. OAEP decrypts with SHA-256 or SHA-512, each key only with its algorithm's hash (`CKR_MECHANISM_PARAM_INVALID` for the others); there is no wrap, unwrap or derive. `C_GetMechanismList` repeats `CKM_RSA_PKCS_KEY_PAIR_GEN` 24 times. `C_DestroyObject` takes a version out of view. Regenerated by `scripts/cloud/gcp.sh probe --write` |
| `p11-kit/0.26` (layer) | Hides eight of SoftHSM's mechanisms, plus `CKM_RSA_AES_KEY_WRAP`; reports version 1.1 (detected by manufacturer) |

## The ledger

`profiles/LEDGER.toml` records what was measured on hardware or a cloud and no build repeats:
the hardware and cloud profiles, the device certificates the tests read, and the example
YubiKey lock. It also lists the profiles a build re-probes (`verified-by`), so every module
profile has an entry, and each entry names its regeneration command (`regen`). The profile
header points there rather than claim either (review 2026-11-24 E-7, E-8).

For a file no build re-derives, the entry holds its run (`[artifact.probed]`: the commit, the
date, the file as written, the hash of the code on its path then), every hand edit since
(`[[artifact.hand-edits]]`) and the file now (`hash`). `code` lists the globs whose change can
change the file: for a profile, the probe, the token operations it drives, the host-side checks
and the provider crate (`[groups] probe`), and for a cloud its script and module build. Not the
emitter: every build holds the committed text to it.

`code` also names the lock entries that pin what a run went through, not whole lockfiles, so a
bump marks stale only what it can change:

- `Cargo.lock#cryptoki` and `Cargo.lock#cryptoki-sys`, the binding, for every profile and the
  lock (`[groups] probe` and `lock`, beside its patches);
- `flake.lock#nixpkgs`, the nixpkgs that builds ykcs11 and the host TPM's tpm2-pkcs11 stack
  (`[groups] nixpkgs`). SoftHSM, kryoptic and tpm2-pkcs11 on swtpm come from it too, but every
  build re-probes them;
- the cloud modules, vendor builds pinned by version and hash in `nix/kmsp11.nix` and
  `nix/cloudhsm.nix`, are watched as those whole files.

`checks.ledger` (`nix/ledger.py`, in CI's light job; locally `nix develop -c python3 -I
nix/ledger.py .`) hashes the tree, not git. In the code's hash, a Rust file counts as its
tokens: a comment, a doc comment or rustfmt's spacing changes nothing, while a literal or any
other token does, an import reorder included. Any other file counts byte for byte, and a lock
entry as its parsed value. The check fails when:

- a file changed and its entry did not;
- a file is not its run's output and no hand-edit row says so;
- the code on its path changed since the run and no `[artifact.acknowledged]` names that code's
  hash, with who, why and what still needs a run on the hardware (`reprobe`);
- a module profile has no entry, a glob names no file, or a regeneration passes another
  `--rsa-max-bits` than `[regen]`.

Acknowledging is the reviewable act: the diff carries the new code hash and the reason, and the
check reports the file `STALE` until the next run. After a run on the hardware: set
`[artifact.probed]` `by` and `date`, drop the hand edits and the acknowledgement, and take the
file's hash (`hash`, `probed.hash`) and the code's (`probed.code-hash`) from what the check then
prints. On 2026-11-25 every hardware and cloud profile and the lock are stale, acknowledged.

The files a build regenerates and compares with are golden: the `verified-by` profiles, the
object matrix's tables, `spec-coverage/cakeys.toml` and the baseline. The code under test writes
them, so a regeneration in the commit that changed the code moves the expectation with it
(review 2026-11-24 C-8). Each has a `[golden."<path>"]` entry: its `generator` (globs, as `code`)
and a record per change, `[[golden."<path>".regenerated]]` or `[[golden."<path>".hand-edits]]`,
naming the file it made (`hash`), who, and each row that moved with what it `was` and `why` the
new value is right. `checks.ledger` fails a golden file that no record names as it is, a `why`
left empty or `"TODO"`, and a listed row that did not move; in CI, `nix/golden-rows.py` checks
that the listed rows are exactly the ones the pull request moved ([DEVELOPMENT.md](DEVELOPMENT.md),
"Golden files").

## Tests

- **Algebra and the baseline**: modes, intersection, by-class queries; the baseline the vendored
  headers generate equals the committed one, compared parsed (`CAKEYS_UPDATE_BASELINE=1`
  regenerates it); frozen spellings are pinned. `checks.profiles` runs the pinned `supports` cases
  against the built binary, including an unpatched binding modelled through `--profiles`.
- **Conformance**, in every Nix build's check phase: a fresh probe of SoftHSM, kryoptic and
  tpm2-pkcs11-on-swtpm conforms to its committed profile and regenerates it byte for byte; the
  scratch guard refuses; through p11-kit SoftHSM advertises its profile minus the layer. The
  YubiKey and fTPM checks are opt-in, and the cloud profiles have none: `checks.ledger` says
  when the code on their path changed since their last run.
- **Drift**: one edited row makes the diff non-empty and names the row.
- **The static gate** (`cakeys validate`, and `cakeys create` before it opens a token): kryoptic
  generating secp256k1 for a pair with `origin = "create"`, or a `kw` commitment through p11-kit,
  is refused naming the deciding profile, with no token present. An adopted or imported key is
  never asked about generation.
