# Provider profiles (plan, 2026-11-12)

What a vendor module can do — which mechanisms are usable, which curves it generates, which OAEP
hashes it actually implements, its unwrap-template rules — moves out of provider code
(crates/pkcs11/src/provider.rs) into data: a capability profile per vendor SO version, and one
per layer between cakeys and the token. Profiles are queried statically (a config file and a
vendor SO version, no token attached), produced and re-verified by probing, and consumed by
`validate`, migrate planning and the Nix integration. docs/PROVIDER_PROFILE.md is the analysis;
this is the plan.

Evidence tags: **[run]** verified in this repo (spikes, tests, the provider crates), **[spec]**
the OASIS PKCS #11 and TCG TPM2 standards, **[todo]** still to verify.

## Why data, and what stays code

| Fact | Example | Medium |
|---|---|---|
| Capabilities a module shows through PKCS#11 | usable mechanisms; OAEP hashes actually implemented (SoftHSM: SHA-1 only [run]); generatable curves (kryoptic: no secp256k1 [run]); unwrap-template rules (SoftHSM refuses CKA_VALUE_LEN [run]); SO-login needs; delete semantics | profile data |
| Behaviour outside PKCS#11, or that must be rewritten | tpm2's P-521 point repair; PIV attestation and its pinned roots; TPM2_Certify; tpm2_ptool | provider code |

Stays code: the `Provider` hooks that rewrite behaviour or reach outside the module (`ec_point`,
`attest`, `check_create`, `check_options`). Everything else becomes profile rows, and the registry
ties a profile name to its hooks when it has any. A vendor whose module needs no fix-ups needs no
Rust at all: `provider = "<profile>"`.

## The format: deltas over a spec baseline

Three artifacts, one small algebra.

**1. The baseline** (`profiles/baselines/pkcs11-3.2.toml`, generated from the OASIS 3.2
headers [spec], committed, pinned by a test): the universe and taxonomy of one spec revision —
every mechanism, key type, attribute, named curve and function, name → numeric ID, grouped
(`mechanisms.pq`, `mechanisms.hmac`, …). PQ parameter sets (ML-DSA-44/65/87, ML-KEM-512/768/1024,
SLH-DSA's twelve) are first-class rows [spec: 3.2 §6.67–6.69]. Baselines validate names, power
by-class queries ("which PQ mechanisms are supported?"), and pin the target spec revision. They
never claim what a vendor supports.

**2. The module profile** (per vendor SO version): probe-recorded deltas against the module's
*own advertisement*, `mode = "observed"`:

```toml
# profiles/modules/softhsm/2.7.toml
profile = "softhsm"
mode = "observed"
match = { manufacturer = "SoftHSM", module-version = "2.7" }
advertise = ["CKM_RSA_PKCS", "..."]        # what C_GetMechanismList returns
subtract = { mechanisms = [] }             # listed but unusable
add = { mechanisms = [] }                  # usable but unlisted
wrap = { oaep = ["SHA-1"] }                # parameters actually implemented
generate = { ec = { curves = ["secp256r1", "secp384r1", "secp521r1"] } }
unwrap = { refuse = ["CKA_VALUE_LEN"] }     # MIGRATE's template rules, as data
```

Deltas against the advertisement, not against the whole spec: the files stay small, and
C_GetMechanismList remains the drift baseline. What a module *cannot* do is discovered by diffing
against the baseline only when a by-class query asks.

**3. The layers**, `mode = "delta"`: open-world, they forward everything except what they
subtract. Known today:

- p11-kit's client drops `CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_PAD`,
  `CKM_EC_EDWARDS_KEY_PAIR_GEN` and `CKM_EDDSA` from the RPC [run].
- the cryptoki binding build: SHA-224/384/512 HMAC key types and `CKM_AES_KEY_WRAP_KWP` without
  the Nix patches [run] — the one layer whose subtraction answers differ per cakeys build.
- the token hardware under the module: swtpm refuses RSA-4096 [run]; YubiKey firmware versions
  differ under the same ykcs11. Matched on `C_GetTokenInfo`'s model and hardware/firmware
  versions (D10).

`supports(x) = ⋀ layers`: any layer's subtraction kills it; else the observed module set decides.

The binary embeds the profiles this repo ships; a directory override (`--profiles`, or an env var)
adds or replaces entries, so vendors and users maintain profiles this repo does not. The TOML is
the interchange format, not a database we own.

## What the spec gives, and what it cannot

The spec's own conveyance is recorded, not trusted. Since 3.0 a token carries findable
`CKO_PROFILE` objects naming the conformance subsets it claims (Base §4.13, `CKP_*` [spec]);
3.2 adds `C_GetInterfaceList` and the FIPS validation objects. The probe reads these as *claims*,
and the profile keeps claims and observations in separate sections.

What no spec API can say, and only profiles express:

| Gap | Example |
|---|---|
| Advertised but broken | tpm2 lists `CKM_AES_KEY_GEN`; `C_GenerateKey` fails [run] |
| Parameter sets | which OAEP hash; ML-DSA-44 vs -87 — 3.2's answer is `CKR_PARAMETER_SET_NOT_SUPPORTED`: find out by trying [spec] |
| Behavioural rules | unwrap templates; attribute defaults on created keys |
| Hardware under the module | the SO speaks for what is beneath it (swtpm vs a real TPM [run]) |

## Queries

`cakeys supports --token <t> CKM_SHA512_HMAC`, or `--module <so> --version <v>` with nothing
attached — pure algebra over profiles. Answers cite the deciding layer ("no: cryptoki (unpatched
build) subtracts it"). `--pq`, `--curves` list by baseline class; `--diff` compares two vendor
versions. Wiring: `validate` gains a static gate (each spec's demands vs its token's effective
profile, no token needed), and the Nix build a pure check (profiles are TOML, like keys.toml and
the lock).

## The probe

`cakeys probe --token <t> [--write] [--out <file>] [--diff <profile>] [--name <profile>]` — the
profile compiler:

- Read-only probes, safe on production tokens: mechanism list and per-mechanism info, token and
  module info, `CKO_PROFILE` claims, how existing objects are encoded.
- Write probes — generating each type and curve, wrapping and unwrapping with each mechanism and
  OAEP hash, unwrap templates, attribute defaults, delete-really-deletes — only with `--write`
  on a token keys.toml marks `scratch = true`, refused (17) otherwise.
- Output: a generated profile plus a diff against what a shipped profile claims.

That gives conformance (the shipped SoftHSM and kryoptic profiles must equal a fresh probe —
hand-maintained provider data becomes a re-verifiable artifact), drift detection (probe a new
module build, diff), and vendor onboarding without writing a crate. What phase 3 built of this
list, and what it left, is in its results below.

## Prior art

- `CKO_PROFILE` conformance profiles [spec]: the spec's named-subset claims — a source to
  record and verify, not a replacement for observation.
- TPM2's `TPM2_GetCapability` [spec]: the structured in-band query PKCS#11 lacks; tpm2-pkcs11
  swallows it, so TPM facts land in the hardware layer anyway.
- Vulkan Profiles: a JSON schema per API revision, named profiles with status and history, and
  an official merge script with intersection and union — our layer algebra as a shipped tool.
  Borrow the schema versioning, the status field, and merge-as-command.
- `vulkaninfo --json` and the GPU capability databases: the probe emits the committed artifact;
  per-(device, driver) databases are the drift baseline.
- Kernel quirk tables (`unusual_devs.h`, udev hwdb): "advertised but actually broken" corrections
  keyed by vendor and version, with evidence notes.
- In-repo: `Accept` and `Side` (crates/core/src/migrate.rs) already are the capability
  expression; the profile TOML is their serialization, not a second language.

## Decisions

- **D1.** Baselines are generated from the PKCS #11 3.2 OASIS headers, one file per spec
  revision, committed and pinned. PQ parameter sets are first-class rows.
- **D2.** Module profiles record deltas against the module's advertisement
  (`advertise` ± `subtract`/`add`), not against the whole spec: small files, and
  `C_GetMechanismList` stays the drift baseline. Baselines carry taxonomy and name validation.
- **D3.** Two profile modes: `observed` (module, hardware) and `delta` (layers). Effective
  support is the intersection over all layers.
- **D4.** Claims and observations are separate sections; the token's `CKP_*` claims are probed,
  recorded and verified, never trusted.
- **D5.** Probes write profiles; the committed TOML is what everything queries; a read-only probe
  at token open asserts the live token still matches. Write probes are the offline compiler,
  scratch-guarded.
- **D6.** Behaviour hooks (`ec_point`, `attest`, `check_create`, `check_options`) and vendor tools
  stay code. A profile with no hooks needs no crate.
- **D7.** Say *capability profile* in docs and messages, to keep clear of `CKP_*` conformance
  profiles; the claimed `CKP_*` IDs are recorded inside each capability profile.
- **D8.** The lock records the resolved profile name beside the provider in the realisation's
  provenance, so drift warnings and `caps` name it. Lock v1 is still a draft, so this changes it
  in place, like MIGRATE D7's `origin`.
- **D9.** Profiles match on the manufacturer and the expressed module version (`C_GetInfo`), with
  the tokenInfo versions as secondary evidence — never a module digest: a rebuild of the same SO
  is a different hash with no behavioural difference. A module that hides its version (kryoptic
  reports 0.0 [run]) matches on manufacturer alone, flagged low-evidence. *Revised in phase 3:*
  a profile records all four keys — manufacturer, module version (omitted when hidden as 0.0),
  token model and firmware — and resolution prefers the one matching the most; a hidden
  version is matched by the firmware (kryoptic's token firmware is its real version, 1.5),
  always with a note.
- **D10.** Hardware layers match on what `C_GetTokenInfo` gives (model, hardwareVersion,
  firmwareVersion); the userspace (module) version is the module profile's key, so the effective
  profile is the pair (module profile, hardware layer). Phase 3 probes the YubiKey present here at
  its current firmware — no wider matrix. *Revised in phase 3:* a probe measures a module and the
  hardware under it together, and nothing in PKCS#11 tells whose refusal is whose (tpm2-pkcs11
  refuses secp256k1 in its own NID table, while its RSA cap is the TPM's [src]). So an observed
  profile is a module-on-hardware pair, named module first (`tpm2-pkcs11/1.10+swtpm`; software
  tokens keep plain names, the module being the hardware), and hardware layers are hand-made
  factorings of such a pair (profiles/hardware/swtpm.toml), never probe output. A token whose
  hardware has no pair yet resolves the nearest one for what the module advertises only:
  generation, wrapping and unwrapping answer unknown.
- **D11.** TOML, like keys.toml and the lock, so Nix reads profiles directly. p11-kit's `.module`
  files are flat key/value (`module`, `priority`, `enable-in`, `x-*`) and cannot carry mechanism
  lists, modes or evidence, so they are not the interchange; one of their `x-` keys may later
  point at a cakeys profile.
- **D12.** A token's *mode* is a match axis like its model and firmware: the same module on the
  same hardware behaves differently in FIPS-approved mode (no SHA-1 OAEP, no small RSA, no
  non-approved curves), so it is a different observed profile. Modes enter as **match fields** —
  data, never logic:
  - *Who reports them*: generic code reads the standard ones from PKCS#11 3.2 — the
    `CKO_VALIDATION` objects (`CKA_VALIDATION_TYPE`, `_LEVEL`, `_CERTIFICATE_IDENTIFIER`, …),
    `C_GetSessionValidationFlags` (`CKS_LAST_VALIDATION_OK`) and the token's `CKF_ERROR_STATE`
    [spec]. A vendor crate adds its own through a provider hook that only *observes* (D6), for
    what lives outside PKCS#11: a YubiKey FIPS's approved mode (its management interface, not
    ykcs11), a TPM's `TPM_PT_MODES` (`TPM2_GetCapability`).
  - *Where they live*: in the one profile schema, `[match.fields]` beside the four fixed keys;
    vendor fields are prefixed with the provider name (`"ykcs11.fips-mode" = "approved"`),
    standard ones are not. The probe records every field reported; the diff compares them like
    the other match keys, so conformance covers them.
  - *How they match*: one generic rule for every field — absent from the profile matches
    anything, recorded must equal the token's value; the profile matching the most fields wins;
    a mismatch resolves the advertise and subtract rows only (D10's fallback). No vendor code
    runs in resolution: what a profile matches is readable from the profile.
  - *Requiring a mode is policy, not capability*: keys.toml says it per token
    (`tokens.<t>.require = { fips = "approved" }`), and cakeys checks it against the **live**
    token's fields when the token opens, before any key is used — never against a profile. A
    token not in the required mode, or in `CKF_ERROR_STATE`, is refused with 14 (precondition
    failed, DESIGN §5). docs/USE_CASE.md, problem 7.

## Phases

| Phase | Scope | Estimate |
|---|---|---|
| 0 | **Done 2026-11-12.** Baseline generator (OASIS 3.2 headers → TOML), pinned by a test | ≈300 lines, 2–3 days |
| 1 | **Done 2026-11-12.** The model, modes, intersection, queries, and the `supports` query | ≈500, 4–5 days |
| 2 | **Done 2026-11-12.** Resolution (match keys, layers), wiring `mechanisms()`, migrate `Side` and the binding layer into profiles | ≈400, 3–4 days |
| 3 | **Done 2026-11-13.** `probe`: the scratch guard, profile + diff, generated profiles; the conformance check in the reference suites; the opt-in YubiKey probe (not yet all ~25 probes: see its results) | ≈700, 5–7 days |
| 4 | The static `validate` gate, the wider Nix check (the query part moved here from phase 4 into phases 1's `supports`) | ≈300, 2–3 days |
| 5 | D12: `[match.fields]` and their generic matching; the standard 3.2 fields (validation objects, session validation flags, `CKF_ERROR_STATE`); the observing provider hook, first for ykcs11's FIPS mode (the YubiKey 5C NFC FIPS here) and the TPM's `TPM_PT_MODES`; `tokens.<t>.require` checked at token open (14). Independent of phase 4 | ≈400, 3–4 days |

### Phase 0 and 1 results (2026-11-12)

`cakeys-profile` (crates/profile), a standalone crate — pure data and algebra over TOML, no
dependency on the rest of cakeys, so the existing provider code is untouched:

- **The baseline** (profiles/baselines/pkcs11-3.2.toml): generated by
  `Baseline::from_headers` from the OASIS TC's official v3.2 headers, vendored unmodified at
  profiles/baselines/headers/pkcs11-3.2/ (commit a110ba8a). Mechanisms, key types,
  attributes, objects, functions, parameter sets, conformance profiles, curves, and the
  curated classes (pq, hmac, key-wrap, oaep) — 739 ID rows, including 3.2's PQ mechanisms and
  XMSS/HSS, and `CKP_*` parameter sets split from the conformance profiles. The pinned test
  (tests/baseline.rs) regenerates and compares on every run
  (`CAKEYS_UPDATE_BASELINE=1` rewrites); a second test pins frozen spellings and IDs.
- **The profiles** (profiles/{modules,layers,hardware}/): committed from this repo's [run]
  evidence — SoftHSM's OAEP SHA-1-only and `CKA_VALUE_LEN` rule, kryoptic's ungeneratable
  curves, tpm2's advertised-but-broken key generation, ykcs11's slots and SO login; the
  p11-kit, cryptoki-unpatched and swtpm layers. All module profiles are `partial`: no
  `advertise` list until the probe, so unknown answers unknown (D5).
- **The algebra** (`Effective`): `supports(x) = ⋀ layers`, verdicts citing the deciding
  profile, yes/no/unknown with exit 0/15/16.
- **The query**: `cakeys supports` (CLI, additive): `--profile` (or `--token` through its
  `provider`), repeatable `--layer`, `--bits`, `--class`, `--oaep`, `--profiles <dir>` (D11).
  `checks.profiles` runs the nine pinned query cases against the built binary.

Kept out on purpose (the transparency rule): the provider trait and its behaviour hooks, the
lock and the fixture configs were unchanged — `supports` read keys.toml but touched no token,
and every command still required `--config`. The structural steps phase 2 then took, and the
ones it still defers, are with its results below.

### Phase 2 results (2026-11-12)

The token layer resolves each open token's capability stack, and the profiles decide what the
planner and the mechanism list see:

- **The binding layer is automatic and self-healing** (D3): renamed to `cryptoki/0.12` and
  injected into every stack — `Token::open`, `supports`, and the lock- and transport-file
  planners alike. What it subtracts is decided at run time
  (crates/pkcs11/src/binding.rs): a cryptoki with the HMAC key-type fix — the Nix patches, or
  the upstream PRs released — subtracts nothing, so the patch fixes the bug *and* the layer
  records it, and the answer heals itself when upstream ships. `checks.profiles` models an
  unpatched binding through `--profiles` to keep that path tested from a patched build.
- **Resolution** (crates/pkcs11/src/resolution.rs): the binding layer first; a forwarder
  recognised from the module itself (`p11-kit/0.26` when `C_GetInfo` names "PKCS#11 Kit",
  the hidden module still reachable through `provider = "..."`); `tokens.<t>.profiles = [...]`
  for the rest (swtpm; a config schema addition, CONFIG.md); the module profile by provider
  family, its version matched against what `C_GetInfo` expresses — the one committed version of
  a family matching by manufacturer alone, flagged low-evidence in the resolution notes
  (kryoptic reports 0.0 [run]).
- **`mechanisms()` is data**: the advertisement filtered by the resolved stack's subtractions;
  `Tpm2Pkcs11`'s override is deleted, its rows in profiles/modules/tpm2-pkcs11/1.10.toml. A
  token with no resolved profile keeps the provider's own filter.
- **`Side` is data**: the migration capability rows (`[migration]`: exports/unwraps,
  `plaintext-import` and its `accepts`, `public-accepts`; `wrap.oaep` for the hashes) are built
  from the module profile wherever one resolves — `SoftHsm::migration`, `Ykcs11::migration`
  and `Tpm2Pkcs11::migration` are deleted. The layer subtractions apply to the plan too: an
  unpatched binding drops the KWP method and the SHA-2 HMAC accept rows.
- **`caps` prints the stack** it decided by; `unwrap_refusals` exposes the template rules for
  MIGRATE phase 3 to consume.

Not done here, flagged:

- **D8 (the lock records the profile name) is deferred** to MIGRATE's lock change: `Provenance`
  has `deny_unknown_fields`, so adding a field breaks `xversion.sh`'s byte-identical re-record
  of existing locks — the break must happen once, with MIGRATE D7's `origin`, not now.
- The unwrap-template rules (`unwrap.refuse`) are defined and exposed but unconsumed: MIGRATE
  phase 3, where the wrapping code exists, is their consumer.
- **Phase 3's scratch guard** still adds a `scratch` key to `[tokens.<t>]` in keys.toml, and
  the probe still fills the `advertise` lists that today make mechanism queries answer unknown.

≈2.2k lines, 2–3 weeks, in line with docs/PROVIDER_PROFILE.md's estimate.

### Phase 3 results (2026-11-13)

The probe (crates/pkcs11/src/probe.rs, `cakeys probe`) generates the committed module profiles,
and the reference suites check on every build that they are exactly what it observes:

- **Read-only probes**: `C_GetInfo` (manufacturer, version), `C_GetTokenInfo` (model,
  firmware; never the serial, so a profile regenerates identically), `C_GetMechanismList` (the
  `advertise` list, D2) and `C_GetMechanismInfo` for RSA key-pair generation (the reported
  `min-bits`/`max-bits`).
- **Write probes**, only with `--write` on a token marked `scratch = true` and logged in;
  refused (17) otherwise, and always for a provider that creates as SO (ykcs11): key pairs per
  baseline curve (`can`/`cannot`) and per RSA size 1024–4096 (`can-bits`/`cannot-bits`); the
  advertised secret-key generation (a refusal is a `subtract` row); RSA-OAEP with SHA-1 and
  SHA-256 (MGF1 of the same hash), counted only when the key unwraps back (`wrap.oaep`); the
  `CKA_VALUE_LEN` unwrap-template rule (`unwrap.refuse`); delete-really-deletes (a note when
  objects stay). Every run destroys what it made. Notes carry `CKR_*` names, not the binding's
  prose, so they are stable across cryptoki releases.
- **Absent is not empty**: `wrap.oaep` and `unwrap.refuse` are absent when never probed (a
  spec-compliant default) and `[]` when probed with nothing working (no OAEP method planned).
- **RSA sizes**: an observed size decides; outside the reported range is no; a size between two
  that generated is yes; any other untried size is unknown. Observed: SoftHSM reports
  512–16384, kryoptic 1024–16384, tpm2-pkcs11 on swtpm 1024–3072 (it asks the TPM).
- **The diff** (`cakeys_profile::diff`) compares the observable rows — the match keys,
  `advertise`, the generate rows, `subtract.mechanisms`, `wrap.oaep`, `unwrap.refuse`,
  `restrict` — never names, notes or `[migration]`; without `--write`, only what a read-only
  probe sees. Drift is exit 15 with each row named.
- **The binding is a layer for the probe too** (D3): cryptoki drops from
  `C_GetMechanismList` every mechanism it cannot name, so through an unpatched binding
  kryoptic's `CKM_AES_KEY_WRAP_KWP` vanishes from the advertisement [run]. Profiles are
  probed with the Nix-built cakeys (the patched binding); any other build may print a probe
  but refuses (17) to write or diff one, and the conformance tests skip there.
- **Maintenance**: `probe --token <t> --write --diff <profile> --out <file>` regenerates a
  committed file: the claimed name kept, its `[migration]` claims (the one section the probe
  does not observe) preserved. `--out` refuses a file that does not parse, and any existing
  file from a read-only probe. `--name` names a new pair.
- **Conformance** (tests/reference/, tests/tpm2.rs): on the reference tokens of every Nix
  build, a fresh probe of SoftHSM, kryoptic and tpm2-pkcs11-on-swtpm conforms, regenerating
  each committed file changes no byte, and the scratch guard refuses. tests/p11kit.rs checks
  that through p11-kit SoftHSM advertises exactly its profile minus the p11-kit layer.
  tests/yubikey.rs (opt-in, real hardware, no credentials) checks ykcs11/2.7's read-only rows.

What the probe found against the repo's earlier evidence:

- kryoptic: OAEP with SHA-1 and SHA-256 both round-trip and `CKA_VALUE_LEN` is accepted in
  unwrap templates (MIGRATE.md's spike agrees); secp256k1 and brainpool are refused
  (`CKR_GENERAL_ERROR`); it advertises the PKCS#11 3.2 PQ mechanisms.
- SoftHSM: OAEP SHA-1 only (SHA-256 is `CKR_ARGUMENTS_BAD` even with MGF1-SHA256); every
  baseline curve generates.
- tpm2-pkcs11 1.10: reports Cryptoki 2.40; `CKM_AES_KEY_GEN` advertised but
  `CKR_FUNCTION_NOT_SUPPORTED` (the old `CKM_GENERIC_SECRET_KEY_GEN` claim is gone: it is not
  advertised); no edwards generation.
- p11-kit's client filters `C_GetMechanismList`: it hides eight of SoftHSM's mechanisms, three
  of them (`CKM_CONCATENATE_*`) missing from the layer until now. Its `C_GetInfo` reports
  version 1.1, not the 0.26 the layer's match records (detection uses the manufacturer).
- ykcs11 (yubico-piv-tool 2.7.3) reports version 2.73 and manufacturer
  `Yubico (www.yubico.com)`: the hand profile's "2.7"/"Yubico" never matched, so every ykcs11
  token resolved low-evidence. ykcs11/2.7 stays hand-maintained, its read-only rows now copied
  from a probe of the YubiKey 5 (firmware 5.74 as `C_GetTokenInfo` encodes 5.7.4).

Not done here, flagged:

- **D4's claims**: no `CKO_PROFILE` read and no claims section yet.
- **More probes**: PQ parameter sets (kryoptic advertises ML-DSA/ML-KEM/SLH-DSA key-pair
  generation; `supports CKP_ML_DSA_65` stays unknown), AES-KW/KWP round-trips, the HMAC key
  types, `C_GetMechanismInfo` beyond RSA, attribute defaults, existing-object encodings.
- **D5's token-open assertion** (a read-only probe against the resolved profile at every open):
  possible now that the read-only diff conforms; unscheduled.
- A killed probe run leaves `cakeys-probe-NN` objects, which the next run's leftover check
  would report as a delete failure.

Order against MIGRATE.md: phases 0–2 land **before MIGRATE phase 3**, so the wrapping code
consumes the template rules as data (that plan's risk #1); the probe runs alongside MIGRATE
phases 3–4.

## Tests

- **Algebra**: modes, intersection, by-class queries; an unknown module resolves to a
  conservative profile that says so loudly.
- **Conformance**: a fresh probe of each reference token equals its shipped profile, and
  regenerates it byte for byte (done: the reference suites in the package's check phase, which
  every Nix build of `cakeys` runs, rather than a separate `checks` entry).
- **Drift**: a profile with one edited row makes the probe's diff non-empty and names the row.
- **Static gate**: keys.toml asking kryoptic for secp256k1, or a `kw` commitment through p11-kit,
  fails `validate` citing the profile — no token present.
- **Frozen names**: mechanism, curve and parameter-set spellings are pinned, like scheme names.
