# Profile coverage: everything the tools use, and everything a module advertises

Planned 2026-11-19, against branch `worktree-probe-secrets` at `211e709`, after the secret-key
sweep ([CAPROBE.md](CAPROBE.md), "The probe"). Nothing here is built yet.

**Goal.** Every operation cakeys and camigrate perform on a token, and every mechanism a module
advertises, ends in one of two places in that module's profile:

1. a **measured row**: the probe did it on a scratch object and wrote the answer; or
2. an **`[untested]` entry**: the module advertises it, the probe could not try it, and the
   profile says why.

Nothing is left as a bare name in `advertise`. A committed check enforces that (Part 0), so a
new mechanism in a module's list, or a new operation in the verbs, cannot go unrecorded.

Evidence tags, as in [CAPROBE.md](CAPROBE.md): **[run]** verified in this repo, **[spec]** the
OASIS PKCS #11 standard, **[src]** read in this repo's source or a dependency's, **[todo]** not
verified yet; each part says which of its claims still are.

## Where things stand

### What a profile records today

The `Capability` row families (`crates/profile/src/capability.rs`), and what writes each
[src]:

| Row family | Written by the probe | Notes |
|---|---|---|
| `generate.<CKK>.<size or curve>` | yes: RSA 10 sizes, EC 6 curves, Edwards 2, Montgomery, and (since `213b5c9`) AES, generic and the five HMAC types in bytes, DES3 at 24 | `Token::create`, the verbs' own call |
| `prove.<binding>.<CKK>.<on>` | yes, asymmetric keys only | `prove`, `rsa_ops`, `ec_ops` |
| `wrap.rsa-oaep.<hash>`, `decrypt.rsa-oaep.<hash>` | yes | `probe_wrapping` |
| `unwrap.template.<CKA>` | yes | |
| `derive.ecdh.sealed`, `derive.ecdh.read-only` | yes | ECDH only |
| `import.*`, `export.*`, `unwrap.<CKK>.*` | yes: RSA, EC, Edwards, AES at 16, 24 and 32 bytes | `probe_moves` (`crates/caprobe/src/probe/moves.rs`) |
| `create.CKO_*`, `delete.CKO_*` | yes | |
| `move.*` | **no, claims** (`Capability::probed()` is false) | hand-kept, never diffed |
| `[migration]` | **no, claims** | hand-kept, never diffed |
| `advertise` | yes, but only a list of names | no status per entry |

### What cakeys and camigrate call

The mechanisms named in `crates/pkcs11/src` and `crates/camigrate/src` (40 [src]), grouped by
whether a profile row measures them:

| Use | Mechanisms | Measured today |
|---|---|---|
| Key generation | `CKM_*_KEY_PAIR_GEN`, `CKM_AES_KEY_GEN`, `CKM_DES3_KEY_GEN`, `CKM_GENERIC_SECRET_KEY_GEN`, `CKM_SHA*_KEY_GEN` | yes |
| Asymmetric signing and decryption | `CKM_RSA_PKCS`, `CKM_RSA_PKCS_PSS` and the `SHA*_RSA_PKCS(_PSS)` hashes, `CKM_RSA_PKCS_OAEP`, `CKM_ECDSA*`, `CKM_EDDSA`, `CKM_ECDH1_DERIVE` | yes, as `prove.*` and `decrypt.rsa-oaep.*` (exact hash coverage per curve: **[todo]**, read `rsa_ops` and `ec_ops`) |
| Key wrap | `CKM_AES_KEY_WRAP`, `_PAD`, `_KWP`, `CKM_RSA_AES_KEY_WRAP`, RSA-OAEP | yes, for one AES key only |
| **Secret-key commitments** (`Commit::Hmac`, `Cmac`, `KcvEcb`, `KcvEcbDecrypt`, `Kw` in `crates/pkcs11/src/templates.rs`) | `CKM_SHA_1_HMAC`, `CKM_SHA224_HMAC`, `CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`, `CKM_SHA512_HMAC`, `CKM_AES_CMAC`, `CKM_DES3_ECB`, `CKM_AES_ECB` | **no.** `CKM_SHA256_HMAC` is signed once, over an ECDH-derived secret (`ec_ops`, `crates/caprobe/src/probe.rs:1574`); `CKM_AES_ECB` is encrypted once inside the import check (`moves.rs:644`); the other six are never run [src] |

"Traced by a test" (a `used` row in `spec-coverage/cakeys.toml`) is not "measured": `reference/identity.rs`
runs all five HMAC commitments, and so `CKM_SHA_1_HMAC` is `used`, but no profile row says a
module can do it.

### What the verbs set and read, with no row saying the module honors it

Templates and checks (`crates/pkcs11/src/templates.rs`, `token/policy.rs`, `token/possession.rs`,
`token/identity.rs` [src]):

- set at creation: `CKA_ALLOWED_MECHANISMS`, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`,
  `CKA_WRAP`, `CKA_UNWRAP`, `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_SIGN`, `CKA_VERIFY`,
  `CKA_DERIVE`, `CKA_PRIVATE`, `CKA_TOKEN`, `CKA_WRAP_WITH_TRUSTED`, `CKA_VALUE_LEN`;
- read back as provenance or policy: `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`,
  `CKA_NEVER_EXTRACTABLE`, `CKA_KEY_GEN_MECHANISM`, `CKA_ALWAYS_AUTHENTICATE`, `CKA_TRUSTED`,
  `CKA_PUBLIC_KEY_INFO`, `CKA_EC_POINT`, `CKA_MODULUS`;
- not set or read by anything: `CKA_COPYABLE`, `CKA_DESTROYABLE`, `CKA_MODIFIABLE`,
  `CKA_SIGN_RECOVER`, `CKA_VERIFY_RECOVER` appear in no template. They are `out-of-scope`, and
  stay so.

The probe exercises some of these as a side effect (`move.trusted-wrap` is `CKA_WRAP_WITH_TRUSTED`;
`unwrap.template.CKA_VALUE_LEN`), but no row says "this module returns `CKA_LOCAL` truthfully" or
"accepts `CKA_ALLOWED_MECHANISMS`". Which attributes are covered by an existing probe: **[todo]**,
Part 3 starts by tabulating it.

### What a module advertises that nothing tries

From the committed profiles, once the generation mechanisms (probed through `Token::create`) are
set aside [run]: AES CBC, CBC-PAD, CBC-encrypt-data, CFB128, CTR and GCM; HKDF
(`DERIVE`, `DATA`, `KEY_GEN`); SP800-108 counter, feedback, double-pipeline; `CKM_CONCATENATE_*`,
`CKM_EXTRACT_KEY_FROM_KEY`, `CKM_XOR_BASE_AND_DATA`; ML-DSA, ML-KEM and SLH-DSA with their 18
`CKM_HASH_*` variants; `CKM_DES3_CMAC`; `CKM_XEDDSA`; and vendor IDs (kryoptic reports
`0x8007678c`, CloudHSM a list). The coverage file marks the first group `profile` or `gap`
[run].

## Part 0. The `[untested]` marker, and where cryptoki's limits go

This part comes first: every other part ends by moving entries from "advertised" to "measured",
and what is left must have a home.

**The marker.** A module profile gains a table keyed by what the module advertises:

```toml
[untested]
CKM_DES3_CMAC = { why = "cryptoki", note = "…" }
"unknown 8007678c" = { why = "vendor", note = "vendor mechanism; the baseline gives it no name, parameters or semantics" }
```

`why` is one of:

| `why` | Means | Example |
|---|---|---|
| `cryptoki` | the binding has no constant or parameter type for it, and caprobe cannot build the call by hand (below) | `CKM_AES_CFB128`, if hand-built parameters fail |
| `vendor` | a mechanism ID the baseline does not name: no known parameters, so no meaningful call | kryoptic `0x8007678c` |
| `hardware` | testing needs state or a risk the probe's rules forbid | the real fTPM (docs/DEVELOPMENT.md, "Hardware rules"), YubiKey slots 82–84 |
| `cloud` | needs a service that was not run for this profile | CloudHSM, KMS |
| `scope` | `spec-coverage/manual.toml` decided cakeys will not use it (the reason is that rule's) | multi-part and message-based operations |

**What it does.**

- `supports` answers *unknown* for an entry, citing the reason, never *yes*: advertised is not
  measured. Today's answer for an advertised-only name: **[todo]**, read `crates/profile/src/effective.rs`
  before writing the rule down.
- `caprobe probe --diff` compares the set of entries. An entry whose cause is gone (the probe now
  measures it) is drift, and so is a new advertised name with neither a row nor an entry.
- Regeneration writes the table; it is probe output, not a claim, and is not preserved by hand.
- **The closing check.** A test in `crates/caprobe` walks every committed module profile and
  fails when an `advertise` entry has neither a measured row family that covers it nor an
  `[untested]` entry. The mapping from a mechanism to the rows that measure it is one table in
  one place, a new function beside the probes in `crates/caprobe/src/probe.rs`. Adding a probe means
  adding its lines to that table; a mechanism a probe tries but the table omits fails the same
  check.

**Cryptoki's limits get their own note, in the cryptoki layer.** A mechanism the binding cannot
express is a fact about the binding, so it goes in `profiles/layers/cryptoki.toml`: the
mechanism in `[subtract]`, a line in `[notes]`, as `CKM_AES_KEY_WRAP_KWP` already is. It does
not go in the spec baseline (`profiles/baselines/pkcs11-3.2.toml`): that file is generated from
the OASIS headers and pinned (CAPROBE.md D1), and must say what the specification defines
whatever the binding does. Two rows result, and they say different things:

- the **cryptoki layer** subtracts it, so `supports` answers no, "cryptoki subtracts it": cakeys
  cannot ask for it with this build;
- the **module profile** keeps it in `advertise` and `[untested]` with `why = "cryptoki"`: the
  module may well support it, and the profile does not claim to know.

The layer heals itself at run time today (`binding::patched`, `crates/pkcs11/src/binding.rs`).
That works for the HMAC key types because one constant differs. For a name the binding lacks
there is nothing to compare at run time, so each such entry needs a recorded way to notice the
fix: **[todo]** decide between a `binding.rs` list that a dependency bump updates, guarded by a
test that fails when `cryptoki-sys`'s constant becomes reachable through the binding's typed
API, and dropping the subtraction when a patch under `nix/patches` lands.

**"Cryptoki cannot name it" is not "cannot test it".** The pinned cryptoki (`2e4ff5d`) has
`Mechanism::VendorDefined`, which carries a raw mechanism type and raw parameter bytes [src].
So before a mechanism is marked `why = "cryptoki"`, the probe tries it by hand where the
parameters are known from the spec: `CKM_DES3_CMAC` takes none, `CKM_DES3_CMAC_GENERAL` one
`CK_MAC_GENERAL_PARAMS`. The pinned binding names, among the advertised mechanisms, AES CBC and
GCM, HKDF, SP800-108 (`kbkdf`), concatenate, extract, XOR, ML-DSA, ML-KEM and SLH-DSA; it does
not name `CKM_DES3_CMAC`, `CKM_XEDDSA` or `CKM_AES_CFB128` [src, a text search of its
`mechanism/mod.rs`]. A mechanism the binding names but whose parameter type is missing is also
a `VendorDefined` case. Only a mechanism whose parameters are unknown or cannot be encoded in
bytes ends in `why = "cryptoki"`.

**Vendor mechanisms.** The assumption holds: a vendor ID that the baseline does not name stays
`why = "vendor"`, listed in `advertise` as it is today (`unknown 8007678c`) and in
`[untested]`. A mechanism the baseline does name but whose number a vendor reuses (CloudHSM's
EdDSA `0x80001057` standing in for `CKM_EDDSA`) is a vendor *alias*: **[todo]** decide whether
the profile records the alias's semantics as a hand claim; OPEN.md ("Vendor mechanisms are
invisible to the probe") predates the pinned binding listing them and needs updating when this
lands.

**Tests.** A profile-crate test for the table's round trip and for `supports`; a caprobe test
for the closing check, run against a fixture profile with one unmeasured name; the `--diff`
cases (entry appears, entry goes).

**Regenerate.** The schema change alone regenerates nothing; every profile then needs its
`[untested]` table, which Part 9 fills.

## Part 1. Secret-key commitments

The largest gap: every secret-key identity in a `keys.lock` rests on an operation no profile row
measures, so `validate` and the gate can only believe the advertised list.

**New rows.** `commit.<kind>.<CKK>.<bytes>`, one per commitment kind and key type and length the
module generates (the lengths the secret-key sweep already records):

| `<kind>` | Mechanism | Key types |
|---|---|---|
| `hmac-sha1`, `hmac-sha224`, `hmac-sha256`, `hmac-sha384`, `hmac-sha512` | `CKM_SHA*_HMAC` | generic secret, and the matching `CKK_SHA*_HMAC` |
| `cmac` | `CKM_AES_CMAC` | AES |
| `kcv-ecb` | `CKM_AES_ECB` (encrypt) | AES |
| `kcv-ecb-decrypt` | `CKM_AES_ECB` (decrypt) | AES |
| `kcv-des3-ecb` | `CKM_DES3_ECB` | Triple DES |
| `kw` | `CKM_AES_KEY_WRAP` (and `_PAD`, `_KWP`) of a fixed value | AES |

**How the probe measures.** It builds the key through the verbs' own template for that
commitment (`templates::rebind_copy` already maps each `Commit` to the use it needs: `CKA_SIGN`
for HMAC and CMAC, `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_WRAP`), runs the operation over the fixed value the
verbs use, and records:

- *yes* when the token returns and the same call twice gives the same bytes, and a second key
  of the same type gives different bytes (a module returning a constant is the failure this
  catches);
- *yes, host-checked* when the key was **imported** (Part 2): the host computes the same
  value with its own crate and compares. Which crate: **[todo]**, whatever `cakeys` already uses
  to verify host-side;
- *no*, with the `CKR_*` the module returned.

`prove.*` has no secret-key counterpart and should not get one: a secret key proves nothing
without being shared, and the commitment is its identity. This corrects the earlier reading of
"no `prove` rows for secret keys" as a gap.

**Needs.** `Needs` in `crates/pkcs11/src/ops/capabilities.rs` reads the new rows (`commit`)
next to its mechanism group, so `create` of a secret key refuses a type whose commitment the
profile says the module cannot do, with the row cited, as the generation row already does.

**Tests.** Profile: a new `Effective` query for the commitment rows. Probe: the new probes against softhsm and kryoptic in
the object matrix, which already holds aes, des3, generic and hmac-sha256 (`spec-coverage/objects`
[src]); extend it to the other four HMAC types. Gate: a CLI test that a secret key whose
commitment the profile says "no" is refused.

**Regenerate.** All modules the sweep touched. Expected new `no` rows: tpm2-pkcs11 (no AES, so
no AES commitments); softhsm's `CKM_DES3_ECB` is the one to watch.

## Part 2. Secret-key moves

camigrate moves AES, generic secret, Triple DES and HMAC keys ([CAMIGRATE.md](CAMIGRATE.md)). The
profile measures AES at 16, 24 and 32 bytes only.

**New rows.** `import.CKK_<type>.<bytes>`, `export.host.*`, `export.sealed.*` and
`unwrap.CKK_<type>.<bytes>` for generic secret, Triple DES and the five HMAC types, at the
lengths the sweep found the module generates, plus the AES lengths the module accepts beyond
what keys.toml allows (kryoptic's 8 and 64 bytes), recorded for completeness and never read by
the gate (`check_value_len` rejects them at load).

**How.** Extend `probe_moves`: it already wraps and unwraps one AES key; each type gets its own
wrap through `CKM_AES_KEY_WRAP_PAD` (host) and RSA-OAEP / `CKM_RSA_AES_KEY_WRAP` (sealed), and
the import path reuses `Token::create` with a plaintext `CKA_VALUE`, then reads the key back
the way the verbs' identity check does. A hash-bound HMAC key is created with its own key type
and the right `CKM_SHA*_KEY_GEN`-compatible template.

**Replace the claims.** With these rows present, `move.secret-unwrap` (SoftHSM's `CKA_VALUE_LEN`
of 0) is measured by the unwrap rows, and `[migration]` is derived from them. That is
[CAPROBE_MIGRATION.md](CAPROBE_MIGRATION.md)'s remaining work; this part does the secret-key
share of it and leaves the asymmetric rows as they are.

**Also in this part, already known to be missing** [src]: Ed448 import (no host test key) and
RSA-512 import. Generate a key with `openssl` at test time, as `CAPROBE_MIGRATION.md` says the
other import keys are.

**Regenerate.** softhsm, kryoptic, swtpm. tpm2-pkcs11 has no import rows at all because the
probe does not run `tpm2_ptool`; this part does not change that (Part 9 lists it).

## Part 3. Mechanism information and attributes

### `C_GetMechanismInfo`

Recorded today for RSA only; the profile docs already call the flags no evidence. New table
`[mechanism-info."CKM_X"]` with `min`, `max` and `flags` **as reported**, for every mechanism the
probe has a row for, plus a probe comparison: where the probe sweeps sizes (RSA, AES, HMAC,
generic) it checks that the reported minimum and maximum bracket what generated, and writes a
`finding` when the module reports a size it then refuses (SoftHSM's AES 8 and 48, kryoptic's
unreported 8 and 64 are the two we already know of [run]). The flags stay claims; this is the
cross-check the 2.7 SoftHSM profile never had.

### Attributes

Start by tabulating which of the attributes in "What the verbs set and read" an existing probe
already exercises (**[todo]**). For the rest, two row families:

- `attr.set.<CKA>.<CKK or class>`: the module accepts the attribute in a creation template and
  a read-back shows it set. For `CKA_ALLOWED_MECHANISMS`, also that the module *enforces* it:
  a call with a mechanism outside the list is refused (`CKR_KEY_FUNCTION_NOT_PERMITTED`, which
  is one of the six unprobed return codes). tpm2-pkcs11 lacking it is the known case
  ([CAPROBE.md](CAPROBE.md), the swtpm row).
- `attr.read.<CKA>.<CKK or class>`: the module returns it, and truthfully: `CKA_LOCAL` true on a
  generated key and false on an imported one; `CKA_ALWAYS_SENSITIVE` and
  `CKA_NEVER_EXTRACTABLE` consistent with how the key was made; `CKA_KEY_GEN_MECHANISM` equal to
  the generation mechanism; `CKA_PUBLIC_KEY_INFO` equal to the host-built SPKI; and
  `CKA_ALWAYS_AUTHENTICATE` after a key is made with it.

These are what `LOCK.md`'s provenance claims stand on, so a "no" here should surface in
`validate` as a weaker identity mode.

**Regenerate.** All modules; the ones likeliest to show `no`: tpm2-pkcs11 (`CKA_ALLOWED_MECHANISMS`,
`CKA_LOCAL`), ykcs11 (the PIV objects carry few attributes), CloudHSM.

## Part 4. Symmetric modes

Mechanisms: `CKM_AES_CBC`, `CKM_AES_CBC_PAD`, `CKM_AES_CTR`, `CKM_AES_GCM`, `CKM_AES_CFB128`,
`CKM_AES_CBC_ENCRYPT_DATA`, `CKM_DES3_ECB` (also a commitment, Part 1), and `CKM_DES3_CBC*` where
a module lists them.

**Row.** `crypt.<CKM>.<CKK>.<bytes>`. One round trip per mechanism and key type: encrypt a fixed
plaintext, decrypt it, compare. The key is the one the probe's secret sweep already holds (32
bytes AES, 24 Triple DES) and that is enough: a mode that works at one length works at the
sizes the key itself accepts. Parameters come from the cryptoki types (`AesCtrParams`, the GCM
parameters). A mechanism with a size rule gets a second row: CBC without padding refuses a
length that is not a multiple of 16 (`CKR_DATA_LEN_RANGE`), which is the behaviour the
`CKR_ENCRYPTED_DATA_LEN_RANGE` gap names.

`CKM_AES_CBC_ENCRYPT_DATA` is a derive mechanism (it derives a key from data encrypted under a
base key), so it belongs to Part 5's derive probe with its own parameter structure.

`CKM_AES_CFB128`: the pinned binding has no name for it [src]; try `VendorDefined` with the IV
parameter, else `[untested]` `why = "cryptoki"` (Part 0).

**Host check.** When the module is softhsm or kryoptic and the key is an extractable imported
key, the host recomputes the ciphertext with the `aes` crate family and compares; otherwise the
round trip stands.

**Regenerate.** softhsm, kryoptic, swtpm. swtpm cannot generate an AES key, so the probe has no
key to run the modes on: those rows are `[untested]`, not *no*, and Part 9 gives the rule that
tells the two apart.

## Part 5. Key derivation

Mechanisms: `CKM_HKDF_DERIVE`, `CKM_HKDF_DATA`, `CKM_HKDF_KEY_GEN` (with `CKK_HKDF`),
`CKM_SP800_108_COUNTER_KDF`, `_FEEDBACK_KDF`, `_DOUBLE_PIPELINE_KDF`, `CKM_CONCATENATE_BASE_AND_DATA`,
`CKM_CONCATENATE_BASE_AND_KEY`, `CKM_CONCATENATE_DATA_AND_BASE`, `CKM_EXTRACT_KEY_FROM_KEY`,
`CKM_XOR_BASE_AND_DATA`, `CKM_AES_CBC_ENCRYPT_DATA`, and `CKM_ECDH1_DERIVE` for Montgomery keys
(Part 6).

**Row.** `derive.<CKM>.<CKK of base>`. The probe imports an extractable base key of known bytes
(Part 2's import), derives an extractable key with fixed parameters, reads `CKA_VALUE`, and
compares it with the host's computation:

| Mechanism | Host check |
|---|---|
| HKDF | the `hkdf` crate (RFC 5869) |
| SP800-108 | HMAC-based counter, feedback and double-pipeline, hand-written from SP 800-108 (about forty lines each) |
| Concatenate, XOR, extract | trivial |
| AES-CBC-encrypt-data | the host's CBC |

When the module refuses an *extractable* derived key (SoftHSM does not for these, tpm2-pkcs11
does), the probe falls back to deriving a sealed key and signing a fixed message with it
(HMAC or CMAC, Part 1) against the same host computation on the base. The row records which
check decided it (`via = "host-value"` or `via = "sealed-mac"`), as `Import.via` records its
path.

`CKM_HKDF_KEY_GEN` writes `generate.CKK_HKDF.<bytes>` through `Token::create`'s generation
path; the secret sweep's length list applies.

**Regenerate.** softhsm, kryoptic; swtpm shows `no` for most (no `CKA_ALLOWED_MECHANISMS`,
derived secrets as store rows).

## Part 6. Asymmetric gaps

Items the profile treats as listed or `note: probe: not probed yet`:

- **ECDH with Montgomery keys** (`CKK_EC_MONTGOMERY`: curve25519 and curve448): `derive.ecdh.CKK_EC_MONTGOMERY.<curve>`, with the host side computed by `x25519-dalek` or the
  `openssl` the tests already use. `CKM_XEDDSA` is signing with a Montgomery key: the pinned
  binding has no name for it [src], so the plan is `VendorDefined` with no parameters (spec
  XEdDSA takes none) or `[untested]`.
- **Ed448 and RSA-512 import** (Part 2).
- **SHA-224 RSA-PSS** and any other hash the asymmetric probes skip: the exact set is **[todo]**
  until `rsa_ops` and `ec_ops` are read; the rule is that every hash a verb can request has a row.
- **`CKK_DES2`** and **`CKM_DES2_KEY_GEN`**: `generate.CKK_DES2.16`. cakeys does not support the
  key type; the profile records it for modules that do.
- **Scratch-slot modules (ykcs11)**: secret keys, wrap, export and delete probes do not run in
  a PIV slot, and slots 82–84 are never touched (docs/DEVELOPMENT.md, "Hardware rules"). Whatever
  the module advertises that a scratch slot cannot host is `[untested]`, `why = "hardware"`,
  with a note naming the rule.
- **Delete in a scratch slot** and **kryoptic's `CKA_VALUE_LEN` read-back**: the latter is the
  small hardening the secret sweep left (read `CKA_VALUE_LEN` back before recording a *yes*).

## Part 7. Post-quantum

Kryoptic advertises ML-DSA, ML-KEM and SLH-DSA with their parameter sets. cakeys does not accept
them as key types (OPEN.md, "Post-quantum key types"); this part records what modules do, so
that item can be decided from data.

**Rows.**

- `generate.CKK_ML_DSA.<CKP_ML_DSA_44|65|87>`, `generate.CKK_ML_KEM.<CKP_ML_KEM_512|768|1024>`,
  `generate.CKK_SLH_DSA.<the twelve CKP_SLH_DSA_* sets>`; the `On::Item` rows `GenerateRow`
  already holds. `CKA_PARAMETER_SET` goes in the template.
- `sign.ML_DSA.<set>`, `sign.SLH_DSA.<set>` and a row per `CKM_HASH_ML_DSA_*` and
  `CKM_HASH_SLH_DSA_*` variant: sign a fixed message, verify **on the token**, and compare
  nothing else. A host library for ML-DSA is a dependency the project does not carry yet; the
  token-side verify is enough for a capability row.
- `encapsulate.ML_KEM.<set>`: `C_EncapsulateKey` then `C_DecapsulateKey`, the two shared secrets
  compared on the token by signing the same message with each (HMAC), since neither is
  extractable by default. The pinned binding has the encapsulation session methods
  (`session/encapsulation.rs` [src]).
- The 18 hash variants are 18 calls; cost is the run time, not the code.

Not recorded as cakeys behaviour: `CKA_ENCAPSULATE`, `CKA_DECAPSULATE` and their templates stay
`gap` in `manual.toml` until OPEN.md decides the key types.

**Regenerate.** kryoptic only for now; the others record `no` for the generation rows (so the
row families exist everywhere) or, for CloudHSM's vendor ML-DSA, `[untested]` (`vendor`).

## Part 8. What nothing records at all

Not used by cakeys or camigrate; named in the earlier answer as supported-but-unrecorded. These
are recorded as **reported claims**, never probed, so they cost one table each and no scratch
objects.

| Table | From | Notes |
|---|---|---|
| `[interface]` | `C_GetInterfaceList`, `C_GetInterface` | versions the module offers; the traced run cannot see them (p11-fault exports 2.40 only), so this comes from caprobe's own load. Whether the pinned cryptoki exposes the list: **[todo]**; if not, `[untested]`, `why = "cryptoki"` |
| `[token-flags]` | `CK_TOKEN_INFO.flags` | `CKF_WRITE_PROTECTED`, `CKF_SO_PIN_COUNT_LOW`, `CKF_SO_PIN_FINAL_TRY`, and the rest the baseline names |
| `[hardware-features]` | `CKO_HW_FEATURE` objects | clock, monotonic counter, user interface |
| `[claims]` | `CKO_PROFILE` objects | the CAPROBE.md D4 claims, recorded and verified against the measured rows, never trusted |
| `[validation]` | `CKO_VALIDATION` | the module's FIPS or similar claim |
| session limits | `ulMaxSessionCount`, `ulMaxRwSessionCount` | reported; a measured open-until-refused probe is **hardware** on anything real, and `[untested]` there |
| object classes | `CKO_OTP_KEY`, `CKO_DOMAIN_PARAMETERS`, `CKO_TRUST` | a `create.CKO_*` try on scratch-safe modules, else `[untested]` |
| return values | the six `gap` `CKR_*` codes | not rows: each is a `finding` that the relevant probe cites when it sees one. `CKR_KEY_FUNCTION_NOT_PERMITTED` is Part 3's |

## Part 9. What ends up untested, and who regenerates what

The expected `[untested]` entries, by module, once Parts 1–8 are built (the sweep decides the
final list; this is the plan's forecast):

| Module | `[untested]` | `why` |
|---|---|---|
| kryoptic | `0x8007678c` and any other unnamed ID | `vendor` |
| kryoptic | `CKM_DES3_CMAC`, `CKM_XEDDSA`, `CKM_AES_CFB128` (the ones it advertises) | `cryptoki`, if hand-built `VendorDefined` calls fail |
| softhsm | whichever of the above it lists | `cryptoki` |
| swtpm / fTPM | every operation needing AES, and `tpm2_ptool` import | the AES ones are measured *no* (`CKR_FUNCTION_NOT_SUPPORTED`), not untested; import is `hardware` for the real fTPM and `cloud`-style *not run* for swtpm |
| ykcs11 | secret-key, wrap, export, delete, most of Parts 1–5 | `hardware` (scratch-slot rules) |
| CloudHSM, kmsp11 | all new rows | `cloud` until a run |

The rule that tells a measured *no* from an untested entry: **if the probe made the call and the
module refused it, that is a `no` row with the `CKR_*`; if the probe never made the call, it is
`[untested]` with the reason.** A module that refuses an advertised mechanism is a finding
(already the case for swtpm's `CKM_AES_KEY_GEN`).

**Hardware rules for the real-hardware regenerations** (docs/DEVELOPMENT.md, "Hardware rules"):

- `tpm2-pkcs11/1.10+amd-ftpm` is the AMD fTPM that unlocks the disk. It is regenerated by the
  user with `CAKEYS_FTPM_PROFILE=tpm2-pkcs11/1.10+amd-ftpm nix run .#coverage-full`, only through
  `nix/ftpm-test-env.sh`, with the persistent handles untouched. No background job runs it. The
  secret-key sweep already leaves it stale (OPEN.md, "Profiles still to regenerate for the
  secret-key sweep"); this plan adds to that debt, and one regeneration pays all of it.
- ykcs11: scratch slots 90–95 only; slot 95 is always safe to wipe; slots 82–84 are never
  touched; credential files are never printed or copied.
- CloudHSM and kmsp11: the scripts under `scripts/cloud/` (an AWS or GCP account, a running HSM);
  cost and time are the user's to decide.

## Order, gates and cost

| Order | Part | Why this order |
|---|---|---|
| 1 | 0, the marker and the closing check | everything else needs a place to put what it cannot measure, and the check keeps the rest honest |
| 2 | 1, commitments | the biggest used-but-unmeasured surface |
| 3 | 2, secret moves | Parts 1 and 5 want imported keys of known bytes |
| 4 | 3, attributes and mechanism info | uses Part 2's imports for `CKA_LOCAL` |
| 5 | 4 and 5, modes and derivation | independent; both need Part 2 |
| 6 | 6 and 7 | independent |
| 7 | 8 | reported claims, trivial |

Each part is its own commit with its regenerated profiles (softhsm, kryoptic, swtpm; the
hardware and cloud ones listed above are the user's), `docs/CAPROBE.md` updated, and
`spec-coverage/cakeys.toml` regenerated with `scripts/coverage-file.sh` (the trace gains the new
calls). Per [DEVELOPMENT.md](DEVELOPMENT.md), the gate after a part is `nix build .#checks-crane-only`;
the full `nix flake check` once at the end. A probe run is minutes on softhsm and kryoptic; the
PQ part is the longest (18 hash variants times a parameter set).

**Constraints that hold throughout.**

- The probe builds what it tests through the verbs' own operations (`Token::create` and the
  templates), so a row measures what cakeys would do, not a lookalike. A probe that needs a
  call the verbs do not make (derive with HKDF) is the exception, marked as such in its row's
  evidence.
- Regenerate profiles, never hand-edit, and never keep a mismatch to spare a re-probe.
- A probe never decides which keys cakeys supports: kryoptic's 8-byte AES generates, and the row
  says so; keys.toml still refuses it.
- Every new row family gets its `Capability` variant, `probed()` returning true, its `supports`
  vocabulary and its coverage-file status.

## Open questions

1. **Layer or baseline for cryptoki's limits.** This plan puts them in
   `profiles/layers/cryptoki.toml` (Part 0), because the baseline is the spec's, not the
   binding's. If a note on the spec row is wanted as well, it is a comment in the baseline
   generator, not a row.
2. **A host-side ML-DSA library** for host verification, or token-side only (Part 7 chooses
   token-side).
3. **How the cryptoki layer notices a fix** for names the binding lacks (Part 0).
4. **Vendor aliases** (CloudHSM's EdDSA at a vendor number): record their semantics as a hand
   claim or leave them `vendor`.
5. **Whether `commit.*` rows replace the advertised-list check in `Needs`**, or sit beside it as
   a second opinion. This plan has them replace it where a row exists and fall back to the list
   where it does not.

## Built

Parts 0 to 8 are implemented in one pass, for the well-known surface; the profiles for softhsm,
kryoptic, swtpm and ykcs11 (scratch slot 94 only) are regenerated with it.

- **Part 0.** `[untested]` (`Why`: cryptoki, vendor, hardware, cloud, scope, unprobed) is computed
  by the probe from what `Ops` tried, emitted, compared by `diff`, and read by `Effective`: an
  untested mechanism is *unknown*, never *yes*, except `scope` (digests the tools hash on the
  host). `Profile::untested_problems` and an emitter test keep it consistent. cryptoki's limits
  (`CKM_AES_CFB128`, `CKM_XEDDSA`, `CKM_AES_KEY_WRAP_KWP`) are notes and subtractions in
  `profiles/layers/cryptoki.toml`, and the patched-binding layer in `binding.rs`.
- **Part 1.** `commit.<kind>.<key type>.<bytes>` rows, computed with the verbs' own
  `Token::commit`, twice, and on a second key for distinctness; `Effective::commit` and the gate
  (refused only when every commitment the spec declares is measured *no*). `CKM_DES3_CMAC` is
  called through `VendorDefined`; no reference module lists it yet, so it has no row.
- **Part 2.** Import, export and unwrap rows for generic secret, the five HMAC types and Triple
  DES, checked by commitment (AES by its host check value).
- **Parts 3 and 8.** `[mechanism-info]` (`C_GetMechanismInfo`) and `[claims]` (token flags,
  session limits, PIN length, interface version, hardware-feature, profile and validation object
  counts) as reported claims, never compared; a generation outside the reported range is a note.
  `attr.read.*` (`CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`,
  `CKA_KEY_GEN_MECHANISM`) and `attr.set.CKA_ALLOWED_MECHANISMS` (with `via = "enforced"`).
- **Part 4.** `crypt.*`: AES CBC, CBC-PAD, CTR and GCM, Triple DES CBC and CBC-PAD, a round trip
  on the token.
- **Part 5.** `derive.CKM_*`: HKDF, the three concatenations, XOR, extract-key-from-key and
  AES-CBC-encrypt-data, each compared with what the host computes.
- **Part 6.** Montgomery ECDH (two pairs on the token, equal secrets), `CKK_DES2` and `CKK_HKDF`
  generation.
- **Part 7.** ML-DSA, ML-KEM and SLH-DSA generation per parameter set, signing with every listed
  pure and hashed variant (verified on the token) on the first pair, and encapsulate/decapsulate.

**Not done, and where it stands** (also OPEN.md): the SP 800-108 KBKDFs and `CKM_HKDF_DATA`
(`[untested]`, `unprobed`); `CKM_XEDDSA` and `CKM_AES_CFB128` (`cryptoki`); Ed448 and RSA-512
import; SHA-224 RSA-PSS; the tpm2-pkcs11 import (needs `tpm2_ptool`); delete rows; a measured
session limit; `CKO_OTP_KEY`, `CKO_DOMAIN_PARAMETERS` and `CKO_TRUST`; the host-side check of the
hashed PQ variants. The amd-ftpm, aws-cloudhsm and kmsp11 profiles are not regenerated: the
fTPM is the user's, by the rules above, and the two cloud ones need an AWS or GCP account.
