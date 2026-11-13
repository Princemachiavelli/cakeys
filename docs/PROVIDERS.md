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

`cakeys probe --token <t> [--scratch] [--out <file>] [--diff <profile>]` — the profile compiler:

- Read-only probes, safe on production tokens: mechanism list and per-mechanism info, token and
  module info, `CKO_PROFILE` claims, how existing objects are encoded.
- Write probes — generating each type and curve, wrapping and unwrapping with each mechanism and
  OAEP hash, unwrap templates, attribute defaults, delete-really-deletes — only with
  `[tokens.<t>.scratch]` in keys.toml, refused otherwise.
- Output: a generated profile plus a diff against what a shipped profile claims.

That gives conformance (the shipped SoftHSM and kryoptic profiles must equal a fresh probe —
hand-maintained provider data becomes a re-verifiable artifact), drift detection (probe a new
module build, diff), and vendor onboarding without writing a crate.

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
  reports 0.0 [run]) matches on manufacturer alone, flagged low-evidence.
- **D10.** Hardware layers match on what `C_GetTokenInfo` gives (model, hardwareVersion,
  firmwareVersion); the userspace (module) version is the module profile's key, so the effective
  profile is the pair (module profile, hardware layer). Phase 3 probes the YubiKey present here at
  its current firmware — no wider matrix.
- **D11.** TOML, like keys.toml and the lock, so Nix reads profiles directly. p11-kit's `.module`
  files are flat key/value (`module`, `priority`, `enable-in`, `x-*`) and cannot carry mechanism
  lists, modes or evidence, so they are not the interchange; one of their `x-` keys may later
  point at a cakeys profile.

## Phases

| Phase | Scope | Estimate |
|---|---|---|
| 0 | **Done 2026-11-12.** Baseline generator (OASIS 3.2 headers → TOML), pinned by a test | ≈300 lines, 2–3 days |
| 1 | **Done 2026-11-12.** The model, modes, intersection, queries, and the `supports` query | ≈500, 4–5 days |
| 2 | Resolution (match keys, layers), the profile-backed `Provider`, wiring `mechanisms()`, migrate `Side` and unwrap templates to profiles | ≈400, 3–4 days |
| 3 | `probe`: the ~25 probes, the scratch guard, profile + diff; the conformance check in checks; the opt-in YubiKey probe | ≈700, 5–7 days |
| 4 | The static `validate` gate, the wider Nix check (the query part moved here from phase 4 into phases 1's `supports`) | ≈300, 2–3 days |

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

Kept out on purpose (the transparency rule): the provider trait, the token layer, the lock and
the fixture configs are unchanged — `supports` reads keys.toml but touches no token, and every
command still requires `--config`. The structural steps that remain, each flagged:

- **Phase 2 is where existing code changes.** Wiring `Provider::mechanisms`/`migration` and
  the unwrap templates to read profiles replaces bodies in crates/pkcs11; the lock gains the
  profile name in provenance (D8, a lock-v1 in-place change); profile auto-detection at token
  open (D9's match keys) lands there too.
- **Phase 3's scratch guard** adds a `scratch` key to `[tokens.<t>]` in keys.toml (a config
  schema addition), and the probe fills the `advertise` lists that today make mechanism
  queries answer unknown.
- The cryptoki layer ships as `cryptoki/0.12-unpatched`, applied explicitly: a patched
  (nix-built) cakeys names no layer. A build-time selection between the two would be a build
  change; it is deliberately not attempted.

≈2.2k lines, 2–3 weeks, in line with docs/PROVIDER_PROFILE.md's estimate.

Order against MIGRATE.md: phases 0–2 land **before MIGRATE phase 3**, so the wrapping code
consumes the template rules as data (that plan's risk #1); the probe runs alongside MIGRATE
phases 3–4.

## Tests

- **Algebra**: modes, intersection, by-class queries; an unknown module resolves to a
  conservative profile that says so loudly.
- **Conformance**: a fresh probe of each reference token equals its shipped profile (a
  `checks` entry, like `checks.formatting`).
- **Drift**: a profile with one edited row makes the probe's diff non-empty and names the row.
- **Static gate**: keys.toml asking kryoptic for secp256k1, or a `kw` commitment through p11-kit,
  fails `validate` citing the profile — no token present.
- **Frozen names**: mechanism, curve and parameter-set spellings are pinned, like scheme names.
