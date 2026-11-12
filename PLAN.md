# Key management plan

> **Current design and state: [`docs/DESIGN.md`](docs/DESIGN.md)** (authoritative). Review findings: [`docs/REVIEW-2026-11-11.md`](docs/REVIEW-2026-11-11.md). Visual overviews: [`docs/diagrams.md`](docs/diagrams.md). This file is the roadmap and the history of decisions; where it disagrees with DESIGN.md, DESIGN.md wins. The project was renamed from `key-mgmnt` to **`cakeys`** on 2026-11-11; the history below uses the old name.

## TODO (deferred, from the 2026-11-11 reviews)

Parked deliberately; the lock stays `version = 1`, a draft, until the reviews pass.

- **Attestation (P2-11, lock review):** record an `attestation` per realisation — YubiKey PIV
  attestation verified to the pinned Yubico root (not the device's own slot f9 self-cert), or
  `TPM2_Certify` with an EK-chained AK. A new binding level `attested` would sit above the
  `pop-*`s and replace them only by explicit opt-in. Note the shipped YubiKey keys are imported,
  and Yubico attests only keys generated on-device.
- **Native TPM backend:** `tss-esapi` beside tpm2-pkcs11 — PCR/policy-bound keys need the native
  path; `pubkeyhash` must agree across both paths (swtpm + the real `/dev/tpmrm0`).
- **Post-quantum:** no token here has PQ hardware (YubiKey PIV, TPM 2.0); map the PKCS#11 v3
  PQ key types (`CKK_*ML*`, `CKA_PARAMETER_SET`) and the kryptic module when they matter.
- **Lock merge rule (S16 remainder):** M3 serializes updaters and D3 collects stale entries, but
  two hand-edited lock fragments still need a manual merge.
- **M1/M2 (open, code review):** read-only sessions for read-only verbs; read the PIV PIN
  counters (`CKF_USER_PIN_FINAL_TRY` …) before login.

Uniquely create, store, export/import and manage PKCS11 and TPM keys, objects, certificatse and any other type relevent.
The core premise here is we use some content-addressed identification intead of the raw PKCS11 URI or other volatile identifier.
This content-addressed Id can be a digest (hash) or other "one-way" mathmatical function or equivilent value (public key) already provided.

Multiple contant-addressed IDs can describe the same real object; in the case that different HSM provides expose different object attributes or differ
in exact crypto/digest functions available. This is important for interopibility between HSM/TPM/etc.

A content-addressed ID that can be generated on the HSM (either direct digest or key wrapping) is preferred, otherwise using key-wrapping to export the private
material in order to take the digest is OK (we should track the providence of how the digest/CA-ID was computed).

The content-addressed ID should be mapped to the originanal (PKCS11 URI, attributes, etc.) "inputs" that were used to create it.

For each object, a HAL should provide consistent PKCS11-like operations accross different PKCS11 provider backends. This is necessary
since HSMs can vary in supported operations/features.

We should use a declarative TOML input schema. Creating a key "populates" the CA identifier(s) in the input schema. (see below)

Not actually sure on the usage semantics but some ideas:
1. this can "provide" the hash for a Nix FOD (so PKCS11 objects become FODS). (myobject.digest)
2. beside the FOD, expose the described pkcs11-URI or TPM identfier for this object  (myobject.uri.hsm-named-bob and myojbect.uri.hsm-named-sue)
3. report the possible cryptographic operations this object can do for the given token: (myojbect.functions.hsm.hsm-named-bob.canSHA256 == true ) (and without canSha256 just prints list of supported vs non-supported in JSON)
4. Let's explore more ideas here. Interopability with Nix (nixpkgs) is a very important feature.

# Misc goils
* Mantain transparent schema on top of existing PKCS11 and TPM primatives.
Don't invent opinionated interfaces.
Don't re-invent interfaces that can already be re-purposed from somwhere else.
Maintain correct abstraction.
Prefer minimal code. Use existing libraries and tools.

---

# Terminology

This mirrors Nix's own split between input-addressed derivations, content-addressed outputs and the "realisations" that map one to the other.

## Three levels: object (material) ← spec (policy) ← realisation (token)
**The key material is the root, not the spec.** The same material can be held under **several specs with different attributes**, e.g. extractable on SoftHSM and non-extractable on the TPM, or sign-only in one place and decrypt-only in another. The **object type must be identical** across them.

| Term | Nix analogue | Meaning |
|---|---|---|
| **Object** | CA output | The real material. It has a **type**, the *intrinsic* part, which must be identical across all its specs: `CKA_CLASS`, `CKA_KEY_TYPE`, and the size or curve. It is identified by **material CA-IDs**: `pubkeyhash`, `certhash`, `valuehash`, `commitment`. These depend *only* on the material and its type, never on attributes. |
| **Spec** | derivation | The *policy* part: usage bits, `CKA_SENSITIVE`/`EXTRACTABLE`/`MODIFIABLE`/`PRIVATE`, `CKA_ALLOWED_MECHANISMS`, TPM `objectAttributes`/`authPolicy`, and so on. It references exactly one object. **Many specs can share one object.** |
| **Spec digest** | input-addressed `.drv` hash | The hash of the canonicalized spec (policy + the object's type). It is known before any key exists. |
| **Instance CA-ID** | — | An ID that binds material **and** attributes. The **TPM Name** is one: it hashes `objectAttributes` and `authPolicy`. It identifies a (spec, material) pair, **not** the object, so two specs over the same material have different Names. |
| **Locator** | store path / substituter | A volatile address on one token: a PKCS#11 URI (RFC 7512), a TPM persistent handle, a context/blob file. A *cached hint*, never an identity. |
| **Realisation** | `realisations` / lock | One (spec, token) pair: locator, identity mode, provenance, observed capabilities, plus any instance CA-ID. |

Cardinalities: **object 1 ← N spec**, and **spec 1 ← N realisation** (one per token).

**Names vs identity.** Object and spec names (`signing`, `signing-tpm`) are **local, human-readable handles** scoped to one config, like Nix attribute or flake-input names.
- They bind spec, lock and Nix attributes together, including *before* a generated key has a CA-ID.
- They are not identity. Two configs may name the same material differently; they agree on the CA-ID.
- They are never written to a token unless the user reuses one in a locator (e.g. `CKA_LABEL`).
- **Renaming is safe.** When the tool sees a locked CA-ID under a new name, it treats it as a rename and moves the lock entry. It must not treat it as a new object.

Ways objects and specs can relate:
- **Replicated, same policy:** one object, one spec, N realisations.
- **Replicated, different policy:** one object, N specs (one per token or group of tokens), each with its own realisations. The attribute differences are explicit and reviewable as separate specs.
- **Same token, two specs:** PKCS#11 allows the same key bytes in two objects with different attributes on one token (e.g. one sign-only, one decrypt-only). This is allowed. The two are told apart by their locators.
- **Generated per token:** the same *policy* generated independently on N tokens creates **N different objects**, since the material differs. TPM primary keys work like this: the template plus a per-TPM seed gives a different key on each TPM. In the spec this is written once, as a policy template, and it expands into N objects in the lock.

**Rules:**
- **Validation rejects a spec whose type differs from its object's type.** For symmetric keys, the type is also mixed into the commitment's domain label (e.g. `"key-management/v1/CKK_AES/256"`). Otherwise the same bytes held as `CKK_AES` and as `CKK_GENERIC_SECRET` would share an ID. This holds even though wrap-rebind computes on a temporary copy of a different type.
- **Resolve by locator, then verify by material CA-ID.** Since several specs on one token can share material, `resolve` by material CA-ID alone can legitimately match more than one object. That is only an error if the spec's own locator is ambiguous.
- **How a replica was made constrains its attributes.** Unwrapping honours the wrapping key's `CKA_UNWRAP_TEMPLATE`. A non-extractable source cannot be replicated at all, unless the key was imported from the host onto each token. The validator checks that each spec is reachable from the object's provenance.
- **The identity mode is per realisation** (see "Per-token identity modes"), so differing attributes can legitimately give different modes for the same object.

## Input and lock shape (sketch)
```toml
# keys.toml (input)
[objects.signing]                       # intrinsic type only
class = "CKO_PRIVATE_KEY"
key_type = "CKK_EC"
curve = "secp256r1"

[specs.signing-soft]                    # policy, references an object
object = "signing"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = true }
tokens.softhsm = { locator = { CKA_LABEL = "signing" }, autoCreate = true }

[specs.signing-tpm]
object = "signing"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }   # different policy, same material
tokens.tpm = { locator = { handle = "0x81000010" }, identity.allow = [] }
```
```toml
# keys.lock (input and updated in place)
[objects.signing]
ids.pubkeyhash = "sha256-…"

[realisations."signing-tpm".tpm]
spec_digest = "sha256-…"
mode = "direct"
tpm_name = "000b…"
locator = "0x81000010"
```

# Prior art / landscape

## Systems that address keys by a digest across storage backends

### GnuPG keygrip (`gpg-agent`, `scdaemon`)
- **What it does:** The keygrip is a hash of only the public-key parameters, independent of protocol (OpenPGP/X.509/SSH) and of storage. `private-keys-v1.d/<keygrip>.key` holds either the key itself or a *stub* that points at a smartcard. The same key on two cards has the same keygrip. This is the closest existing match to "CA-ID + locator".
- **What's missing:**
  - Asymmetric keys only.
  - SHA-1 based.
  - Smartcard via scdaemon only; there is no general PKCS#11 or TPM backend. A TPM can only be used to protect soft keys (`keyboxd`/`tpm2d`).
  - No declarative spec, no capability reporting, and no Nix story.

### Sequoia `sequoia-keystore` (Rust, LGPL-2.0-or-later)
- **What it does:**
  - A keystore *service*. Clients talk to it over IPC, and it multiplexes backends through a trait in `sequoia-keystore-backend`.
  - Backends: `softkeys` and `gpg-agent` (on by default), plus `openpgp-card` and `tpm` (opt-in). Backends are compiled in.
  - Keys are addressed by **OpenPGP fingerprint** in every backend.
  - The TPM backend (`sequoia-keystore-tpm`, built on `sequoia-tpm`) creates keys from **YAML templates** (for example `tpm/examples/rsa2k-dec.yml`). That is a precedent for declarative TPM key specs. However, those keys are *named by TPM handle*, which is the same locator-as-identity problem this project is trying to solve.
- **What's missing:**
  - **PKCS#11.** There is no merged PKCS#11 backend. There is a feature request (issue #28, which prioritises PKCS#11 3.2) and a *draft* MR (!2) for YubiKey via `ykcs11`, built on `openpgp-pkcs11-sequoia`. That draft notes, as a possible future addition, having the keystore query the backend for public key material, which is exactly the CA-ID problem.
  - **The identity is OpenPGP-specific.** A v4/v6 fingerprint hashes an OpenPGP key packet, which includes a *creation time*. So a raw PKCS#11 or TPM key has no canonical fingerprint until someone invents a creation time. The same material imported with two different timestamps gets two fingerprints. A protocol-neutral CA-ID such as an SPKI digest (or a keygrip-style hash) is needed underneath.
  - **Symmetric keys and data objects are out of scope.** OpenPGP has no notion of HSM-resident AES or HMAC keys.
  - **No declarative spec digest.** The YAML is an input to a tool, not a hashed, canonical identity, and nothing maps a spec to its realisations.
  - **No model of N locators per key** with provenance for how the ID was computed.
  - **No capability or mechanism reporting** for each token, and no attribute verification against a spec.
  - **No Nix integration.**
- **Worth reusing as reference:** the backend trait shape (device → key → operations), the TPM YAML template format, and `openpgp-pkcs11-sequoia` for the PKCS#11 ↔ OpenPGP glue. LGPL is fine to *depend on*, but keep that in mind before copying code.

### Parsec (CNCF Sandbox, Rust)
- **What it does:**
  - A platform abstraction *service* (a daemon plus `parsec-client`) over PKCS#11, TPM 2.0, Mbed Crypto, Trusted Services and CryptoAuthLib. It is the origin of the `cryptoki` and `tss-esapi` crates.
  - Its API is the **PSA Crypto API**, an Arm standard rather than Parsec's own invention. A key's attributes are `{type, bits, policy: {usage_flags, permitted_algorithms}}`.
  - It reports capabilities through `CanDoCrypto` and `ListOpcodes`.
  - Key identity is held in a *Key Info Manager* (KIM, on disk or sqlite) that maps an `(application, key name)` identity to a provider-specific `id` and attributes. The KIM plays the same role as this project's lock, but it is keyed by name rather than by content.
- **Current status** (as of 2026-11, from the [coverage table](https://parallaxsecond.github.io/parsec-book/parsec_client/operations/service_api_coverage.html)):
  - **PKCS#11 and TPM providers, both:** generate, import, destroy, export-public, sign/verify hash, and asymmetric encrypt/decrypt.
  - **TPM provider only:** `AttestKey` and `PrepareKeyAttestation`.
  - **Neither provider:** any symmetric key (AES, HMAC, raw data, derive), cipher/MAC/AEAD/hash operations, key agreement, or `PsaExportKey`.
  - **Curves:** SECP-R1 only on both providers.
  - The repo is not archived, but how active it is was not checked.
- **What's missing for this project:**
  - **No secret keys at all.** The on-token HMAC CA-ID cannot be computed through Parsec.
  - **No content-addressed identity.** The KIM is keyed by name.
  - **It does not appear to adopt keys it did not create**; the KIM must already own the mapping. (The docs don't say; verify.)
  - **PSA attributes are a third vocabulary.** They lose TPM `authPolicy`/`objectAttributes` and PKCS#11 `CKA_EXTRACTABLE`/vendor nuances, which conflicts with "transparent schema over PKCS#11/TPM primitives".
- **How it could be used:**
  1. **PSA key attributes as the cross-backend *capability and policy vocabulary*** in the HAL. Keep native PKCS#11 and TPM attributes as the canonical spec, and derive the PSA view from them.
  2. **A custom KIM keyed by CA-ID,** which would make Parsec a resolver/consumer of our realisations.
  3. **Run the daemon and contribute upstream** whatever is missing (symmetric keys, more curves, adopting existing keys).

  **Decision (2026-11-11):** use Parsec's useful shared Rust crates (`cryptoki`, `tss-esapi`, and `psa-crypto` types where they fit) and borrow its terminology (usage flags, permitted algorithms, "can do crypto"). Do **not** run the daemon or force the design through Parsec's API.

### SSH (`ssh-agent`, `ssh-keygen -D`, `ssh-tpm-agent`), `age-plugin-tpm`, `age-plugin-yubikey`
- **What they do:** Keys are referenced by their public key or a `SHA256:` fingerprint, wherever they live. This is an everyday precedent that the public key *is* the identity.
- **What's missing:** Each covers only its own protocol, has no spec, and handles symmetric keys only implicitly or not at all.

## Native identity mechanisms in the underlying standards

### TPM 2.0
- **Name.** An object's Name is `nameAlg || H(TPMT_PUBLIC)`. It binds the public key, `objectAttributes` (`fixedTPM`, `sensitiveDataOrigin`, `sign`, `decrypt`, …) and `authPolicy`. That makes it a native spec-plus-key digest, and it is **attestable**: `TPM2_Certify` signs the Name, and `TPM2_ReadPublic` returns it. This is the best CA-ID available on any backend.
- **Primary keys are deterministic.** The template plus the hierarchy seed gives the same key every time. On one TPM the spec *is* the identity; across TPMs it is not.
- **Locators are volatile.** Persistent handles (`0x81…`) and context/blob files can change, so they are locators only.
- **Related tools:** `tpm2-tools`, the `tss-esapi` crate, and `tpm2-pkcs11`, which exposes TPM keys as PKCS#11 and keeps its own metadata in a sqlite store. A TPM object might therefore be reached both natively and through PKCS#11; the CA-ID must be the same on both paths.

### PKCS#11
- **`CKA_ID`.** Free-form. By convention OpenSC, NSS and p11-kit set it to SHA-1(public key), the SKI. That makes it *sometimes* stable across tokens, but only by convention and it is mutable.
- **`CKA_UNIQUE_ID`** (3.0). Assigned by the token and read-only, but **not** stable across tokens.
- **`CKA_PUBLIC_KEY_INFO`** (2.40+). A DER SubjectPublicKeyInfo stored *on the private key object*. When the token supports it, an SPKI digest can be computed without the matching public object.
- **`CKA_CHECK_VALUE`.** A 3-byte KCV for secret keys and certificates. It is too short to identify anything; at most it can be a weak alias or sanity check.
- **`CKA_ALLOWED_MECHANISMS`** together with `C_GetMechanismList`/`C_GetMechanismInfo` is the raw material for capability reporting.
- **RFC 7512 PKCS#11 URIs** are the locator format. p11-kit has URI parsing and module configuration.

### KMIP
- **What it does:** There is a `Digest` attribute (a hash of the key block, computed by the server) and a `Unique Identifier`.
- **What's missing:** The UID is assigned by the server, and the digest is server-local and depends on the format. The protocol and server model are heavy.

### SPIFFE/SPIRE
- **What it does:** Workload identity built on attestation plugins, including TPM.
- **What's missing:** Keys are ephemeral, and the identity belongs to the *workload*, not the key. It is relevant only as an attestation model.

## Canonical key-thumbprint formats to reuse rather than invent
- **SPKI SHA-256** (RFC 7469 pinning): a hash of the DER SubjectPublicKeyInfo. It covers any X.509-expressible public key and is the default asymmetric CA-ID.
- **RFC 5280 SKI method 1:** SHA-1 of the subjectPublicKey BIT STRING. Useful as a legacy alias because it matches the `CKA_ID` convention.
- **RFC 7638 JWK Thumbprint**, plus **RFC 9278** for its URI form (`urn:ietf:params:oauth:jwk-thumbprint:sha-256:…`).
- **RFC 9679 COSE Key Thumbprint.**
- **multihash / multicodec** (as used by `did:key`): a self-describing `<alg><len><digest>`. This fits the requirement for several CA-IDs over different algorithms, with provenance; the `multihash` crate exists.
- **Certificates and data objects:** SHA-256 of the DER `CKA_VALUE`.

## Libraries and tools to build on (Rust / Nix)
- `cryptoki` (PKCS#11) and `tss-esapi` (TPM ESAPI): from Parsec, both maintained.
- RustCrypto `spki`, `der`, `x509-cert`, `sha2`: canonical SPKI encoding and hashing.
- `toml`/`serde`: the spec and lock format. Nix reads TOML natively with `builtins.fromTOML`.
- Test backends, all packaged in nixpkgs, which allows hermetic `nix flake check` tests:
  - **SoftHSMv2** and **Kryoptic** (a Rust PKCS#11 soft token) as PKCS#11 tokens.
  - **swtpm** as a TPM.
  - `tpm2-pkcs11` to exercise the "same TPM key reached via two paths" case.
- Consumers to generate configuration for:
  - p11-kit (`pkcs11.conf.d`).
  - OpenSSL `pkcs11-provider` and `tpm2-openssl`.
  - `ssh-agent`.
  - systemd (`systemd-cryptenroll`, `LoadCredentialEncrypted`).

# What is missing (the gap this project fills)

No existing project combines all of the following:
1. **A protocol-neutral CA-ID across PKCS#11 *and* TPM.**
   - Sequoia comes closest, but its identity is OpenPGP-specific and timestamp-dependent, and it has no PKCS#11 backend.
   - GnuPG's keygrip is neutral, but it is SHA-1 and limited to smartcards.
2. **CA-IDs for secret (symmetric) keys and data objects**, not just public keys.
3. **Multiple CA-IDs per object, each with provenance:** which scheme, which algorithm, and whether it was computed on the token or on the host, and by which mechanism.
4. **A canonical, hashable declarative spec** (the spec digest), and verification that a realised object's *live* attributes still satisfy that spec.
5. **N locators per identity** (replicated keys), and N identities per spec (per-token generation).
6. **Per-token capability reporting:** the intersection of the key's attributes, `CKA_ALLOWED_MECHANISMS` and the token's mechanism list.
7. **Nix integration:** pure evaluation over a lock or realisation file, plus generated consumer configuration.

# CA-ID schemes per object type

Every CA-ID is stored together with its provenance: `{scheme, hash_alg, computed_by = "token" | "host", mechanism?, token?}`.

| Object | Primary CA-ID | Aliases / notes |
|---|---|---|
| Asymmetric key (PKCS#11) | SHA-256(DER SPKI). Source the SPKI from `CKA_PUBLIC_KEY_INFO`, the public object, or `CKA_MODULUS`/`CKA_EC_POINT`. It is hashed on the host, which is fine because the input is public. | SKI (SHA-1) to match `CKA_ID`; JWK thumbprint |
| Asymmetric key (TPM) | SHA-256(DER SPKI), so the CA-ID is the same as on PKCS#11 | TPM Name. It is TPM-specific, but it is attestable and also binds attributes and policy. |
| Certificate | SHA-256(DER cert) | the SPKI CA-ID of the subject key, as a link |
| Data object | SHA-256(`CKA_VALUE`) | (value must be readable) |
| Secret key | A PRF commitment computed *on the token*, using the key itself: HMAC (`CKM_SHA256_HMAC`) or CMAC over a fixed domain-separation label, e.g. `"key-management/ca-id/v1"`. | `CKA_CHECK_VALUE` (a weak alias only) |

Caveats for secret keys:
- **The PRF commitment needs a usage bit** (`CKA_SIGN`) that the spec might otherwise forbid. Make it an explicit spec option, and record when no token-side CA-ID was possible.
- **Wrap-then-digest:**
  - A digest of the *wrapped blob* depends on the wrapping key and the mode. AES-KW/KWP (RFC 3394/5649) is deterministic, but GCM and RSA-OAEP are not. Such a digest is valid only as `CA-ID = f(key, wrapping key)`, and the wrapping key's CA-ID must be recorded with it.
  - Unwrapping on the host in order to hash the *plaintext* takes the key outside the HSM boundary. It must be an explicit opt-in recorded in provenance, and it should still use the domain-separated HMAC rather than a raw hash.
- **The same secret has the same CA-ID on every token only if every token supports the chosen PRF mechanism.** This is the case the original "multiple CA-IDs per object" requirement anticipated.

# Spec canonicalization

- **Inside the spec digest:** security-relevant, immutable attributes only.
  - The referenced object's type (class, key type, size or curve). This part is shared by every spec of the object.
  - `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_MODIFIABLE`, `CKA_TOKEN`, `CKA_PRIVATE`.
  - Usage bits: `CKA_SIGN`, `CKA_DECRYPT`, `CKA_WRAP`, `CKA_DERIVE`, …
  - `CKA_ALLOWED_MECHANISMS`.
  - TPM `objectAttributes`, `authPolicy`, `nameAlg` and the parent/hierarchy.
- **Outside the spec digest:**
  - `CKA_LABEL` and `CKA_ID`, which are mutable and belong to the locator.
  - `CKA_LOCAL` and `CKA_KEY_GEN_MECHANISM`, which describe how the key was realised.
  - Vendor-defined attributes. These can be carried as per-token *extensions* that are not hashed.
- **Encoding:** a deterministic encoding such as sorted-key canonical JSON or deterministic CBOR, so that the same TOML always hashes the same way. Attribute names follow the PKCS#11 / TPM spec names verbatim, with no invented vocabulary.


# Decisions (2026-11-11, from RESPONSE.md)

| Topic | Decision |
|---|---|
| Identity | **Portable CA-IDs by default; token-specific CA-IDs allowed but flagged** (see below). |
| Nix mechanism | A **"pseudo-FOD" pre-use check** run by our tool inside the consuming derivation, not true Nix FODs. A never-cached Nix derivation is preferred only if Nix can do it cleanly; it can't today (see below). |
| Parsec | Use its shared crates and terminology only. |
| Locator attributes | `CKA_LABEL`/`CKA_ID` are **arbitrary user values** declared in the spec for each token. The HAL **fails if they don't resolve to exactly one object**. |
| Token order | SoftHSMv2 (reference), then **YubiKey PIV** (via `ykcs11`, the PKCS#11 hardware on this host), then the **TPM** (`/dev/tpmrm0`), then Nitrokey (model TBD). CloudHSM and other HSMs later. **Wide HSM support is a core feature.** |
| Key creation | **Follow the schema** (`autoCreate`, etc.). Users supply PINs, PIV management keys and any HSM-specific settings. Provider-specific warnings and checks come later. |
| Lock | A **separate lock file** that is both an input and updated in place (like `flake.lock`). |
| Weak identity modes | `commit-at-creation`, `host-at-import` and `token-specific` need an **explicit opt-in per (object, token)**, recorded in the lock. A weaker mode than the one locked is an error (see "Per-token identity modes"). |
| Key classes in v1 | **Asymmetric and symmetric.** |
| TPM access | **Both** native (`tss-esapi`) and `tpm2-pkcs11`. Native is required for TPM-only features such as PCR policies. |
| Concurrency | **One writer** per token. |
| "Last copy" delete guard | **Dropped.** The tool only knows the tokens listed in the config, so it cannot know whether a copy is the last one anywhere. |
| ID string format | SRI `sha256-…` is the default rendering, but nothing depends on it. IDs are `(scheme, algorithm, bytes)` internally. |

# Identity: portable vs token-specific CA-IDs

Each object exposes **several** CA-IDs. The default, used in about 99% of cases, is one that is true on *every* token:

| CA-ID | Portable across tokens? | Notes |
|---|---|---|
| `pubkeyhash`: SHA-256(DER SPKI) | **yes** | Any asymmetric key, on PKCS#11 or TPM, either path. |
| `certhash`: SHA-256(DER cert) | **yes** | |
| `valuehash`: SHA-256(`CKA_VALUE`) | **yes** | Readable data objects. |
| `hmac-commitment`: HMAC/CMAC(key, label) | **yes, conditionally** | Portable only if every token holding the key supports the *same* mechanism (`CKM_SHA256_HMAC` or `CKM_AES_CMAC`). Otherwise it degrades to token-specific. |
| `tpm-name`: TPM Name | no (TPM-only) | Still attestable, and it binds attributes and policy. |
| `wrapped-digest`: digest of a wrapped blob | no | Depends on the wrapping key and mode. |
| `kcv`: `CKA_CHECK_VALUE` | no | Too short to identify anything. |

Rules:
- **Portable access:** `myobject.id.pubkeyhash` (or `certhash`, …).
- **Token-specific access:** `myobject.id.<token>` gives the ID specific to that token. Using it **emits a Nix warning** (`lib.warn`), or an **error** when `strictIdentity = true`, because identity between tokens can no longer be guaranteed.
- **Secret keys with no common mechanism:** if a secret key's tokens share no PRF mechanism, there is no portable ID, and the spec must explicitly opt in to token-specific IDs.

(The attribute name `fod` from RESPONSE.md is renamed `id` here, since these are no longer true FODs. Purely cosmetic.)

## Secret-key identity (commitments)
The problem: a non-extractable secret key (`CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`) can never be read, so it can't be hashed. The only way to fingerprint it is to have the token **run a deterministic function with the key on a fixed input, and hash the output**. That output is a *commitment*. Because it comes from a PRF or block cipher, it is safe to publish.

**Commitment methods**, in order of preference. Each needs a usage bit on the key and a mechanism on the token:

| Method (scheme) | Key usage needed | Typical mechanism | Applies to |
|---|---|---|---|
| HMAC-SHA256(key, label) (`commitment`) | `CKA_SIGN` | `CKM_SHA256_HMAC`, TPM `TPM2_HMAC` | generic secret / HMAC keys |
| AES-CMAC(key, label) (`cmac`) | `CKA_SIGN` | `CKM_AES_CMAC` | AES keys |
| AES-ECB(key, fixed block) (`kcv-ecb`) | `CKA_ENCRYPT` | `CKM_AES_ECB`, TPM `EncryptDecrypt` | AES keys. This is the full-length form of the classic KCV |
| AES-KW(key, fixed dummy key) (`kw`) | `CKA_WRAP` | `CKM_AES_KEY_WRAP` (RFC 3394, deterministic) | wrap-only KEKs |
| Host-computed at import | none | none | imported or replicated keys only. The plaintext is on the host before import anyway |

- **Portability is about the mathematical function, not the API.** HMAC-SHA256 gives identical bytes whether SoftHSM's `CKM_SHA256_HMAC` or the TPM's `TPM2_HMAC` computes it. A commitment is portable when *every* token holding the key can compute the *same* function.
- **The tool chooses at spec-validation time.** It intersects the key's allowed usages (and `CKA_ALLOWED_MECHANISMS`) with each declared token's quirks profile and picks the first common method. This happens **before** any key is created, so a failure surfaces early.

### Wrap-and-rebind: commit through a temporary copy
For keys whose own usages allow no commitment, make a short-lived copy *on the same token* that has the needed usage:
1. **Generate** (do not import) a temporary wrapping key on the token: a **session object** (`CKA_TOKEN=false`) with `CKA_WRAP`/`CKA_UNWRAP`.
   - Generating it on the token keeps the wrapped blob opaque to the host, even though the blob passes through host memory.
   - Importing a host-known key would let the host unwrap the blob, which is equivalent to exporting the plaintext.
2. `C_WrapKey` the target with the temporary key. **Any wrap mechanism works** (AES-KW/KWP, `CKM_AES_CBC_PAD`, …). Determinism doesn't matter, because the blob is unwrapped on the same token and never hashed.
3. `C_UnwrapKey` it into a **session-object copy** whose template allows the commitment: `CKA_SIGN=true`, and **any key type the token has a function for**. The same bytes can be unwrapped as `CKK_GENERIC_SECRET` to use HMAC, or as `CKK_AES` to use CMAC/ECB.
4. Compute the commitment on the copy. Destroy the copy and the temporary key.
   - Because both are session objects, the token also discards them automatically if the tool crashes or the session closes. There are no orphans to clean up.
5. Record provenance: `method = "wrap-rebind"`, the wrap mechanism, the commitment function, and the token.

**Rerunning it is safe**, so `verify` can use the same steps later; this is not a one-time host computation.

**Limits:**
- **The target must have `CKA_EXTRACTABLE=true`.** `C_WrapKey` on a non-extractable key fails (`CKR_KEY_UNEXTRACTABLE`), and PKCS#11 only lets `CKA_EXTRACTABLE` go true → false, never back.
- **No new exposure.** PKCS#11 already treats an extractable key's usage attributes as unenforceable, since anyone with wrap access can re-import it with other attributes. The trick therefore weakens nothing that `CKA_EXTRACTABLE=true` hadn't already given up. The spec validator should still state this explicitly.
- **`CKA_WRAP_WITH_TRUSTED=true` on the target** requires a wrapping key with `CKA_TRUSTED=true`, which only the SO can set. In that case wrap-and-rebind needs SO login; the schema supplies it, consistent with "follow the schema".
- **Token quirks:** the token must permit unwrap with a changed key type or added usage bits. This goes in the quirks profile.
- **TPM analogue:** `TPM2_Duplicate` followed by `TPM2_Import` as a `keyedHash`/`sign` object. This is possible only for objects with `fixedTPM=0` and `fixedParent=0` whose policy allows duplication. A `fixedTPM` object is the TPM's version of non-extractable.

### Commit-at-creation (keys we create, not extractable)
1. Generate the key with the commitment usage enabled, and compute the commitment.
2. Drop the usage with `C_SetAttributeValue` (e.g. `CKA_SIGN=false`).

Limits:
- Requires `CKA_MODIFIABLE=true` and a token that allows turning usage bits off.
- Like host-at-import, it **cannot be re-verified later** without turning the usage back on, so `verify` falls back to checking the locator and attributes, and says so.

### Per-token identity modes (explicit opt-in, decided 2026-11-11)
The same key material can be fully verifiable on one token and not on another. Causes: a different model or mechanism set, or **different attributes on each replica**, e.g. extractable on SoftHSM but unwrapped as non-extractable on another token. The identity mode is therefore tracked **per (object, token)**, never per object.

**Modes, strongest first:**

| Mode | How the ID is obtained | Re-verifiable on this token? | Opt-in? |
|---|---|---|---|
| `direct` | hash of readable public data (SPKI, cert, data object) | yes | no |
| `commitment` | the key's own usage computes the commitment | yes | no |
| `wrap-rebind` | temporary session copy with commitment usage | yes | no. It is implied by `CKA_EXTRACTABLE=true`, but the lock still records it |
| `commit-at-creation` | computed once at generation, then the usage is dropped | **no**, attributes only | **yes, per token** |
| `host-at-import` | computed on the host from plaintext before import | **no**, attributes only (unless a mode above also works) | **yes, per token** |
| `token-specific` | per-token commitment or TPM Name; does not match the portable ID | yes, but **not across tokens** | **yes, per token** |

**Rules:**
- **Spec.** Each token entry declares which weak modes it allows, e.g. `[objects.foo.tokens.yubikey] identity.allow = ["host-at-import"]`. The validator computes the best achievable mode for each token from its attributes and the token's quirks profile. If that mode is below `wrap-rebind` and not listed in `identity.allow` for *that* token, it is a **validation error**, raised before any key is created or imported.
- **Lock.** It records, per (object, token): the mode actually used, its provenance (mechanism, commitment function, wrap mechanism) and the ID. **The mode is part of the lock**, so a weaker mode shows up in review just like a hash change.
- **Downgrades.** `verify` recomputes the achievable mode every time. If it is *weaker* than the locked mode (a firmware change, a mechanism removed, attributes changed), that is an **error**, not a silent fallback. Accepting it needs a new opt-in and a lock update.
- **Portable ID claims.** `myobject.id.<scheme>` is portable only across tokens whose mode yields that same ID. A token in `token-specific` mode is excluded, and accessing its ID gives the identity warning.
- **Consumers choose a minimum.** The pre-use check takes a required strength, e.g. `key-mgmnt cfg myobject.id.commitment --token bob --require reverifiable`. Nix exposes `myobject.mode.<token>`, so a consumer can assert on it at eval time.

### When there is no digest at all
1. **Non-extractable key whose usages allow nothing deterministic and observable**, created elsewhere, or with `CKA_MODIFIABLE=false`. Examples: derive-only, unwrap-only, or `CKA_ALLOWED_MECHANISMS` restricted to random-IV modes. Wrap-and-rebind is impossible, so this is truly un-identifiable unless the spec loosens the policy or the key was imported (host-at-import). Treat it as a validation error unless the spec opts in to the fallbacks below.
2. **Tokens share no common function.** For **extractable** keys this is solved by wrap-and-rebind's choice of key type at unwrap: each token can apply *any* function it has to the raw bytes, so the tool only needs one function that every token implements for *some* key type. HMAC-SHA256 is near-universal, including on the TPM. For non-extractable keys it stays token-specific.
3. **The token cannot hold the key type at all** (e.g. YubiKey PIV and symmetric keys). The object cannot exist there, so `Unsupported` is the whole story.

**Fallbacks** (explicit opt-in only):
- **Token-specific ID:**
  - a per-token commitment, or
  - for TPM symmetric/keyedHash objects, the **TPM Name**. Its public `unique` field is `H(seedValue ‖ sensitive)`, a commitment the TPM computes without using the key, but the random `seedValue` differs per object.
  
  Either way it carries the identity warning.
- **Host-computed at import:** stable and portable, but tokens can only *verify* it if they also support a commitment method. Otherwise `verify` can only check the locator and attributes, and must say so.

Public keys, certificates and readable data objects never hit this problem: they can always be read and hashed.

# Nix integration

## Why not a "never cached" derivation?
- **`__impure = true`** (experimental feature `impure-derivations`) is the only Nix mechanism that is never cached or substituted. The catch, according to the Nix manual, is that **only other impure derivations (or FODs) may depend on an impure derivation.**
  - Using it would make every consumer of a key, and everything downstream of that consumer, impure and therefore never cached.
  - It is still experimental. It is **not** enabled on this machine; the test in this session failed because the daemon lacks the feature.
- **`allowSubstitutes = false`** only skips binary caches. An output already in the local store is still reused.
- **True FODs** are substituted once their output exists, so they never touch the HSM again.

**Conclusion: use the pseudo-FOD pre-use check.** Revisit `__impure` if it stabilises *and* the infectious-impurity rule is relaxed.

## Pseudo-FOD pre-use check
The consuming derivation calls the tool itself, immediately before using the key:

```sh
URI=$(key-mgmnt ${configFile} myobject.id.pubkeyhash)   # or: --token hsm-bob
```

1. **Input tracking.** `configFile`, which includes the expected CA-ID, is a store-path input of the consumer. Recording or changing a hash therefore changes the consumer's derivation hash, so it rebuilds. This is the same *tracking* property a FOD gives.
2. **What the tool does:**
   1. `resolve` the locator declared for the token.
   2. Enforce **exactly one** match.
   3. Recompute the CA-ID and check the live attributes against the spec.
   4. Compare with the expected CA-ID.
   5. Print the locator (a PKCS#11 URI or TPM handle) on stdout.
3. **First use** (`autoCreate = true` on the template, and no recorded hash):
   1. `realise` creates the key under its declared locator.
   2. It prints `got: sha256-…`.
   3. It **exits non-zero**, so the build fails, just like a FOD with `lib.fakeHash`.
   
   Retrying never creates a duplicate, because the declared locator is set at creation time. On a retry the object is found and the run turns into `HashMismatch` again, or succeeds once the hash is recorded.
4. **Scheduling.** The consumer gets **`requiredSystemFeatures = myobject.rsf.<token>`** (e.g. `[ "token-hsm-bob" ]`). Builders that own the token advertise that feature in `system-features`.
5. **Caching semantics are now correct.** A cached consumer output proves the key existed and matched *when that output was produced*, which is exactly when it was used. For **runtime** use (services), the same command runs as `ExecStartPre=` or as a NixOS activation check.

## Sandbox access (host setup: `nixosModules.default`)
**What real builds may reach (decided 2026-11-11).** Only two things:
- **A p11-kit forwarding socket.** `p11-kit server` runs outside the sandbox with the real module loaded; the build talks PKCS#11 over the socket.
- **A real TPM** (`/dev/tpmrm0`).

**Token databases are never exposed raw.** A SoftHSM token directory holds the keys encrypted under a PIN-derived key: reading it allows offline PIN guessing and then key extraction, and writing it allows tampering. SoftHSM is only the test reference; the VM tests' SoftHSM sandbox path exists for testing only.
- **tpm2-pkcs11's SQLite store is not SoftHSM.** It holds TPM-wrapped blobs that only that TPM can load, and its PIN checks are enforced by the TPM, including dictionary-attack lockout. Even so, real builds should use it through `p11-kit server` (a socket), not as a file.
- **Direct `/dev/tpmrm0` is for the native TPM backend.** There, keys are persistent handles or context blobs, with no extra database.

**Per-build access through a pre-build-hook (2026-11-11).** Global `extra-sandbox-paths` reach every build on the host. Instead, the module installs `nix.settings.pre-build-hook` (`nix/sandbox-hook.sh`, bash + jq over `nix derivation show`). The hook grants a token's paths only to builds whose `requiredSystemFeatures` name that token's `systemFeature`.
- **Protocol (Nix 2.35.3 source).** nix-daemon runs the hook as root for every sandboxed build, with the `.drv` path and the sandbox directory. Stdout is `extra-sandbox-paths`, then `/path` or `/target=/source` lines, then a blank line. There is no optional `?` form, so the hook only emits paths that exist.
- **Feature sources.** The hook reads features from the env string (plain derivations), from `structuredAttrs` (JSON v4, Nix 2.33+), and from `env.__json` (older JSON).
- **Paths come only from the module's map** (`tokens.<n>.sandboxPaths`, plus `/run/pcscd` when `tokens.<n>.pcscd`). The derivation merely selects entries.
- **Contract.** The hook always exits 0, writes nothing but the protocol to stdout, and grants nothing on any error. A failing hook would fail every build. Recovery for trusted users: `--option pre-build-hook ""`.
- **One hook only.** `pre-build-hook` is set with a plain definition, so a second hook elsewhere in the configuration is a merge conflict rather than a silent override.
- **Features are self-declared.** Any user allowed to build can require `token-x`. The hook keeps tokens out of unrelated builds; it does not authenticate the requester. The gate on who may build at all is `nix.settings.allowed-users`.
- **One source for feature names.** Consumers take the feature from `lib.mkKeys` (`rsf`, from keys.toml's `systemFeature`, default `token-<name>`). The module's `tokens.<n>.systemFeature` has the same default. Keep the token names equal.
- **Tests (`checks.module`).** The positive and negative builds cover pcscd (plain and structured attrs) and the SoftHSM directory. Neither is in `nix.conf`'s `extra-sandbox-paths`. `checks.vm`'s in-guest pseudo-FOD consumer gets its token through the hook.

**Build identities (Nix 2.35.3 source, confirmed on this host).** Device permissions are checked against the build's host IDs:
- **With build users:** `nixbldN`, with the `nixbld` GID.
- **With `auto-allocate-uids`:**
  - The Linux sandbox always uses a user namespace, and the build's host GID equals its UID. That UID is the first ID of a 65 536-ID slot: `start-id + i·65536`, so 128 slots with the default `id-count`.
  - Supplementary groups are dropped.
  - Probe: `uid_map 1000 872480768 1`, `gid_map 100 872480768 1`, no groups.
- **For ACLs, that means** a device such as `/dev/tpmrm0` can be opened to every possible build with one ACL holding `g:nixbld` and the 128 slot GIDs. A 128-entry ACL is accepted on tmpfs.
- **Implemented and tested.** `services.key-management.sandbox.tpm2.enable` adds a udev rule that sets this ACL on `/dev/tpmrm*`. `checks.tpm` is a VM with a QEMU vTPM and two nodes, one with auto-allocated UIDs and one with nixbld users:
  - The ACL lists the 128 slot GIDs, or GID 30000 on the nixbld node.
  - A build requiring `token-tpm` runs `tpm2_getrandom` through `device:/dev/tpmrm0`. This works with auto-allocated UIDs (UID = GID = slot 0), in a `uid-range` build (root in the sandbox maps to the slot's first ID), and with nixbld users.
  - A build without the feature does not see the device.
  - After `setfacl -b`, the same build gets `Permission denied`; a udev change event (`udevadm trigger`) restores access.
  - So ACLs on devtmpfs work through the build's user namespace. On a live host the rule applies at the next add/change event.
- **It depends on Nix internals** (slot size, always a user namespace), so the module computes the slot GIDs from `start-id`/`id-count` and asserts `id-count % 65536 == 0`.

**tpm2-pkcs11 store (superseded: real builds reach tpm2-pkcs11 through `p11-kit server`, see above).**
- **Using a key does not need write access.** The store holds TPM-wrapped key blobs and the PIN-wrapped auth; signing reads it.
- **Write access is below the PIN.** Through PKCS#11 a PIN guards operations, but anyone who can write the SQLite file can delete or corrupt tokens and keys without one. The store is the only copy of each wrapped key, so that loss is permanent. On a YubiKey, destructive operations need the PIN or management key.
- **Write access only buys `autoCreate` inside a build,** and on tpm2-pkcs11 only for EC/RSA, since secret keys cannot be generated there at all. It also covers SQLite housekeeping.
- **The hook changes the calculation:** only builds requiring the TPM feature see the store, so a per-token writable opt-in is reasonable. It stays off by default.
- **Unverified:** that tpm2-pkcs11 never needs to write on open, e.g. for a schema upgrade or recovery of a leftover journal.

**Credentials:** PINs never enter the store. A build that uses private objects needs the PIN, through a PIN file granted by the hook and readable by build users. `p11-kit server` cannot hold a login for its clients: login is per client connection (tested). `publicOnly` checks need no PIN.

## Exposed attributes
- `myobject.id.pubkeyhash` and the other portable IDs (see the identity section).
- `myobject.id.<token>`: token-specific, with a warning or error.
- `myobject.uri.<token>`: the declared locator (PKCS#11 URI, TPM handle or context path). For pure evaluation only; consumers should prefer the tool's verified output.
- `myobject.rsf.<token>`: `requiredSystemFeatures`.
- `myobject.functions.<token>.<mechanism>` plus a JSON dump. This is **recorded** by `realise`, since evaluation cannot query a token.
- `myobject.public`: the public artifact (SPKI/PEM/cert). This one can be a **true FOD**, or simply a file written from the lock, because it is pure data.
- `lib.checkKey myobject token`: a shell snippet or `nativeBuildInputs` hook that wraps the pre-use check.
- Generated consumer configuration: p11-kit, `pkcs11-provider`/`tpm2-openssl`, `authorized_keys`, systemd units with `ExecStartPre` checks.
- `nix flake check` against SoftHSMv2, Kryoptic and swtpm.

# Token verbs: idempotent and safe, with HTTP-style semantics

Every verb is either **safe to repeat** (idempotent) or **explicitly unsafe**. There is no "usually fine" middle ground. The CA-ID plays the role of an HTTP **ETag**, and verbs take **preconditions** (`If-Match`, `If-None-Match`).

| Verb | HTTP analogue | Safe? | Idempotent? | Semantics |
|---|---|---|---|---|
| `resolve` | GET/HEAD | yes | yes | Find by the declared locator, or by CA-ID. **Exactly one match, otherwise `Ambiguous`.** Recompute the CA-ID and return locator + attributes + capabilities. Never writes. |
| `verify` | GET + `If-Match` | yes | yes | `resolve`, then check the CA-ID equals the expected value and the live attributes satisfy the spec. This is what the pseudo-FOD check runs. |
| `realise` | PUT | no | **yes** | Locator absent: create (only when `autoCreate`). Present and matching the spec: no-op. Present but different: `Conflict`. Then compare the CA-ID with the expected value: `HashMismatch { got }` if none is recorded or it differs. |
| `import` / `replicate` | PUT with known body | no | yes | The CA-ID is known before writing, so it is verified on write. |
| `delete` | DELETE + `If-Match` | no | **yes** | Delete by locator *and* expected CA-ID. Already absent: **success**. Locator holds a different CA-ID: `PreconditionFailed`, and nothing is touched. |
| `generate-new` | POST | no | **no** | Not exposed. |

**Error classes:** `NotFound`, `Ambiguous` (locator not unique), `Conflict`, `PreconditionFailed`, `HashMismatch { got }`, `Unsupported` (missing capability or mechanism), `Unavailable` (token absent or locked).

## Locator rules (formerly "slot")
- The spec declares the locator attributes for each token: `CKA_LABEL`, `CKA_ID`, a TPM persistent handle, a blob path. They are arbitrary user values, **outside** the spec digest.
- **`realise` sets them at creation.** That makes creation idempotent and recoverable after a crash, because an orphan is found again by its locator.
- **Uniqueness is enforced by the HAL.** It is not enforced by PKCS#11 itself.
- **Some providers fix the locator values themselves.** The HAL owns these quirks; see the next section.

# HAL: provider-specific behaviour

Wide HSM support is a core feature. Each provider gets a small **quirks profile**: the locator model, supported mechanisms, whether keys can be generated on the device, which attributes are readable, and whether creation is destructive.

| Provider | Path | Known quirks to encode (verify on hardware) |
|---|---|---|
| **SoftHSMv2** | PKCS#11 | The reference. Arbitrary labels and IDs, HMAC/CMAC/AES-KW available. Its token directory needs to be in `sandbox-paths`. |
| **YubiKey 5** (present: `1050:0407`, CCID) | PIV through `ykcs11` (or OpenSC) | **Fixed slots.** `CKA_ID`/labels are fixed per PIV slot, so the locator is the *slot*. **Generating into an occupied slot overwrites it**, so `realise` must use `If-None-Match` semantics. No symmetric keys (`Unsupported`). Access goes through pcscd. |
| **Nitrokey** | HSM 2 through OpenSC `sc-hsm`, or Nitrokey 3 PIV/OpenPGP | Model TBD. |
| **TPM 2.0** (present: `/dev/tpmrm0`) | native `tss-esapi` *and* `tpm2-pkcs11` | **PCR/policy-bound keys need the native path**: as far as I know `tpm2-pkcs11` cannot express arbitrary policies (verify). Test: `pubkeyhash` must agree between the two paths. |
| **tpm2-pkcs11** 1.10.1 (secondary reference, swtpm) | PKCS#11, `key-mgmnt-tpm2-pkcs11` | See "tpm2-pkcs11 findings" below. |
| CloudHSM, others | vendor PKCS#11 | Later. |

## Crate layout (2026-11-11)
The project is a Cargo workspace, so that a PKCS#11 module's quirks live in its own crate:

| Crate | Contents |
|---|---|
| `key-mgmnt-core` (`crates/core`) | `keys.toml`/`keys.lock`, error kinds and exit codes, CA-ID computation. No token access and no `cryptoki`. |
| `key-mgmnt-pkcs11` (`crates/pkcs11`) | The token layer over `cryptoki`, the idempotent verbs (`ops`), the `Provider` trait and the `Registry`. |
| `key-mgmnt-softhsm`, `key-mgmnt-ykcs11`, `key-mgmnt-tpm2-pkcs11`, `key-mgmnt-p11-kit` | One provider per module. |
| `key-mgmnt` (`crates/cli`) | The CLI as a library: `key_mgmnt::main(registry)`, plus a thin `main.rs`. The integration tests and fixtures live here. |

**Writing a provider:**
- **Hooks.** A provider implements `name` and `matches(&ModuleInfo)` (auto-detection from `C_GetInfo`). It overrides only the hooks its module needs: `mechanisms` (drop advertised but unusable ones), `ec_point` (repair an encoding) and `hint` (advice on errors).
- **The fix-up rule.** A hook must return exactly what a spec-compliant module would return, so identities stay portable across modules and versions. This is also why the provider's name is not recorded in the lock.
- **Selection.** An explicit `provider = "<name>"` on a token wins. An unknown name is a validation error. Otherwise the first registered provider whose `matches` accepts the module is used, then `generic`.
- **Registration.** The CLI registers the built-in providers through the same public API a downstream binary uses: `key_mgmnt::main(key_mgmnt::default_registry().with(MyProvider))` (see `crates/cli/examples/custom-provider.rs`). Rust has no stable plugin ABI, so providers are linked in, not loaded.
- **The backend-neutral trait is deferred.** The verbs still speak PKCS#11. A trait above `Token` gets extracted when the native TPM backend starts, once there is a second implementation to shape it.

# Effort estimate

Rough sizes of the **new code**. Dependencies are `cryptoki`, `tss-esapi`, RustCrypto `spki`/`der`/`x509-cert`, `serde`/`toml`, and possibly `psa-crypto`.

| Component | New code (approx.) | Notes |
|---|---|---|
| Spec schema, canonicalization, spec digest | 0.4–0.7k LOC Rust | |
| CA-ID computation, provenance, portable vs token-specific | 0.6–1.0k | |
| HAL: PKCS#11 + TPM adapters + quirks profiles | 1.5–2.5k | Grows with each provider; this is the "wide HSM support" cost |
| Verbs, errors, lock I/O, pseudo-FOD CLI | 0.8–1.2k | |
| Nix library + NixOS module (sandbox paths, permissions, `ExecStartPre`) | 0.5–1.0k Nix | |
| Tests (SoftHSMv2, Kryoptic, swtpm in `flake check`; hardware tests run manually) | 0.8–1.5k | |
| **Total** | **≈ 4.5–8k LOC** | |

**How much is prior art?**
- **By code executed:** more than 95% prior art.
- **By engineering effort:** about **70–80%**. The identity model, verbs, the pseudo-FOD check, the provider quirks and the Nix glue are green-field.

# Open questions

- **Which Nitrokey model?** HSM 2 or Nitrokey 3.
- **pcscd:** is it built with polkit on this host? If so, a rule for build users is needed, or the `p11-kit server` approach.

# Next steps

## TODO: opt-in keystores with an `idPrefix` (2026-11-11)
- **Today cakeys imposes nothing on token objects.** Locators (`CKA_LABEL`/`CKA_ID`) and attributes are the user's. The commitment label `key-management/v1` is only an input to the ID computation and never reaches a token (DESIGN §3.3).
- **Proposal:** an explicit, non-default (but recommended) grouping in `keys.toml`, a *keystore*: a set of objects and specs with shared settings. Its optional `idPrefix` would be prepended to `CKA_LABEL` and/or `CKA_ID`, so it is obvious on the token which objects cakeys manages.
- **Uses:**
  - telling managed objects apart from foreign ones;
  - a future `gc`/inventory verb;
  - safer If-None-Match, since prefixed locators cannot collide with foreign objects.
- **Open questions:**
  - How the prefix composes with fixed PIV slot IDs (prefix labels only?).
  - Whether the prefix enters the spec digest. Probably not, since locators are not identity.
  - Migrating existing objects.

## kryoptic as a reference token, and post-quantum (planned 2026-11-11)
**kryoptic** (nixpkgs 1.5.3, Rust, OpenSSL 3.5 backend) becomes the third reference token after SoftHSM and tpm2-pkcs11. It is the one that implements PKCS#11 **3.2**. Its `pkcs11-tool -M` lists `ML-KEM` (key pair generation, key sizes 800–1568), `ML-DSA` with `HASH-ML-DSA-*` (1312–2592), and `SLH-DSA` with `HASH-SLH-DSA-*` (32–64). SoftHSM 2.7 has none of these.

Steps:
1. **Provider and harness.**
   - A `cakeys-kryoptic` provider crate.
   - A test harness like SoftHSM's: `KRYOPTIC_CONF` with a sqlite slot, and a token created with `C_InitToken`.
   - Run the existing classical suites against it too, as a second software reference.
2. **cryptoki ≥ 0.11 for the PKCS#11 3.2 API.** Done: cakeys is on 0.12.1. That gives `CKK_ML_DSA`/`CKK_ML_KEM`/`CKK_SLH_DSA`, `CKA_PARAMETER_SET` (`CKP_ML_DSA_44/65/87`, …) and `C_EncapsulateKey`/`C_DecapsulateKey`.
3. **Identity: `pubkeyhash`, unchanged.**
   - Build the SPKI from the public key and parameter set; confirm exactly how kryoptic exposes the public key (`CKA_VALUE` and `CKA_PARAMETER_SET`).
   - Canonicalize with `ml-dsa` 0.1.2 and `ml-kem` 0.3.4. Both are stable and use `pkcs8` 0.11, the same generation as our stack.
   - `slh-dsa` 0.1.0 has no SPKI support (0.2 is a release candidate), so either wait for it or check length only, as for Ed448.
   - ML-KEM private keys are identified by their encapsulation key. Shared secrets are ordinary secret keys (existing schemes).
4. **Config:** `keyType = "CKK_ML_DSA"` plus a new `parameterSet = "ML-DSA-65"`. It is omitted from the spec digest when unset, so existing digests are unchanged.
5. **Oracles:** OpenSSL 3.5.9 (nixpkgs) generates ML-DSA/ML-KEM/SLH-DSA keys and certificates; hash their SPKI on the host.
6. **p11-kit gate.** Test whether p11-kit forwards PKCS#11 3.2 (`C_EncapsulateKey`, ML-DSA parameters such as `CK_SIGN_ADDITIONAL_CONTEXT`). Its RPC already drops EdDSA, and real builds go through p11-kit, so do this first.
7. **Hardware:** none of our tokens has PQ (YubiKey PIV, TPM 2.0 hardware). Composite (hybrid) keys come later.

- **More reference implementations** (from NEXT.md): an **OP-TEE PKCS#11 TA in QEMU** (an Arm TrustZone token). QEMU's emulated TPM is already one (`checks.tpm`, and swtpm in the package tests).

1. Write the spec schema (TOML), with declared locators per token and `autoCreate`, plus canonicalization and the spec digest. Test with golden vectors.
2. Build the HAL over `cryptoki` against SoftHSMv2: `resolve` with uniqueness, `pubkeyhash` (`CKA_PUBLIC_KEY_INFO`, falling back to the public object), and `hmac-commitment`.
3. Implement the verbs and the pseudo-FOD CLI (`key-mgmnt <config> <obj>.id.<scheme>`) with the `HashMismatch { got }` exit.
4. Add the Nix library: `id`, `uri`, `rsf`, `functions` and `lib.checkKey`, plus a `flake check` that runs a consumer derivation against SoftHSM inside the sandbox.
5. Add the TPM backends: native `tss-esapi` (including PCR policy) and `tpm2-pkcs11`, with a cross-path `pubkeyhash` test against swtpm, then the real `/dev/tpmrm0`.
6. Add the YubiKey PIV quirks profile (`ykcs11`), then Nitrokey.
7. Add a NixOS module: sandbox paths, device and pcscd permissions, and `ExecStartPre` checks.

# POC status (2026-11-11)

> History of what was built, in order. The current state is described in `docs/DESIGN.md`.

**Implemented** (Rust + `cryptoki`, built with `rustPlatform.buildRustPackage`):
- **`key-mgmnt` CLI** with `validate`, `resolve`, `verify`, `realise [--update-lock]`, `delete [--if-match] [--update-lock]`, `check <object>.id.<scheme>` (the pseudo-FOD pre-use check) and `caps`.
- **Exit codes:** 10 hash mismatch (`got:` on stderr), 11 not found, 12 ambiguous, 13 conflict, 14 precondition failed, 15 unsupported, 16 unavailable, 17 invalid spec.
- **Object types:** EC P-256 (`pubkeyhash` = SHA-256 of DER SPKI, from `CKA_PUBLIC_KEY_INFO` or the public object's `CKA_EC_POINT`), plus generic-secret and AES keys.
- **Identity modes:** `direct`, `commitment` (on-token HMAC-SHA256 over a type-bound label) and `wrap-rebind` (session KEK → wrap → unwrap a session generic-secret copy → HMAC → destroy).
- **Weak modes:** they need a per-token opt-in and are rejected *before* any key is created. They are not implemented in the POC.
- **Model:** object ← spec ← realisation; several specs may share one object. Locators must match exactly one object, the type and policy of the live object are checked against the spec, and identity downgrades are errors.
- **Nix library** (`lib.mkKeys`, builtins only): `id`, `uri`, `mode`, `specDigest`, `functions`, `rsf`, `specs.<spec>.*` and `check { token; }`.

**Adoption of existing keys (2026-11-11):**
- **New object types:** RSA keys (`keyType = "CKK_RSA"`, `modulusBits`) and certificates (`class = "CKO_CERTIFICATE"`, `certificateType = "CKC_X_509"`). A certificate has `certhash` (SHA-256 of DER) plus the `pubkeyhash` of its subject key, which links it to its key object.
- **`publicOnly = true` (per token):** verifies a private key's identity through its public key object, with no login (no PIV PIN retries spent). It is recorded in the lock. It is incompatible with `autoCreate` and with policy attributes, `delete` refuses it, and the URI handed to consumers still names the private key.
- **If-None-Match on create:** `realise` never creates under a locator that already holds any object. This protects occupied PIV slots.
- **ykcs11 quirk:** it reports `CKA_PUBLIC_KEY_INFO` with length 0, then rejects the fetch with `CKR_ARGUMENTS_BAD`. The HAL treats that as absent and falls back to modulus/exponent.
- **`examples/yubikey-secureboot.{toml,lock}`:** the Whonix PK/KEK/db keys and certificates in YubiKey PIV retired slots 1–3, adopted read-only.
  - Every `pubkeyhash` and `certhash` matches `openssl` run over `pkcs11-tool` exports.
  - Each key's `pubkeyhash` (from the modulus/exponent) equals its certificate's (from X.509 parsing).
  - A derivation built in the host sandbox ran `check` for the PK key and certificate through `lib.mkKeys` successfully.

**Module and token provenance (2026-11-11):**
- **URIs are pure locators.** The lock's URIs no longer carry `module-path`. A store path in the lock has no string context, so it is never a Nix dependency (the module used comes from `modules.<token>` / `--module`), and it churned on every rebuild.
- **Each realisation records** `module = { path, description, manufacturer, version, cryptoki }` (C_GetInfo plus the loaded file) and `token = { model, serial, firmware }`. Versions are raw `CK_VERSION` major.minor, so ykcs11 2.7.3 shows as `2.73`.
- **A difference is never an error.** Identity is enforced by the CA-IDs. On `verify`/`check`/`realise`, a different module build identity or token is a *warning*, and a different module file with the same build identity is a *note*. Build flags such as FIPS can change behaviour at the same version, so the path is kept for provenance.
- **`realise --update-lock` re-binds** both, as a reviewable lock diff.
- **The Nix lib exposes them** as `module.<token>` and `tokenInfo.<token>`.

**Type coverage on SoftHSM (2026-11-11):**
- **Crates do the crypto.** Public keys are decoded and re-encoded by `p256`/`p384`/`p521`, `ed25519-dalek`, `ed448` and `rsa` (the RustCrypto pkcs8 0.11 generation). Our code only picks one by curve or OID. `ed448` has no stable point-arithmetic crate yet, so Ed448 points are checked for length only.
- **Private keys:** `CKK_EC` with `curve = secp256r1 | secp384r1 | secp521r1`, `CKK_EC_EDWARDS` with `curve = edwards25519 | edwards448`, and `CKK_RSA` of any `modulusBits`. The curve is read back from `CKA_EC_PARAMS`; for Edwards curves, the OID and PKCS#11 3.0 PrintableString forms are both accepted.
- **Certificates** with EC or Edwards subject keys link to their key objects just like RSA certificates.
- **AES commitments, selected by the spec's declared usage bits** (never by token defaults): `CKA_SIGN` gives `cmac`, `CKA_ENCRYPT` gives `kcv-ecb` (one domain-separated block; never CTR/GCM with a fixed nonce), and `CKA_WRAP` gives `kw` (wrap of a fixed, label-derived session key).
  - Each scheme is a separate ID under `objects.<name>.ids`, so tokens with different usage bits never report false mismatches.
  - A spec with several bits computes all of them. That links specs of the same material.
  - Wrap-rebind on an AES key unwraps an AES copy and computes all three.
  - Only the token mechanisms present are used. If none is available, the result is *unsupported*.
  - **Material is linked only through a shared scheme.** If the object already has locked IDs and none of the computed schemes is among them, `realise` refuses (*precondition failed*) instead of attaching new IDs. So a SIGN-only copy on one token and a WRAP-only copy on another cannot be bound to one object. Nothing could prove they are the same. Realise a spec that computes both schemes first.
  - `check <object>.id.<scheme>` rejects a scheme the spec can never compute *before* opening the token, and one this token cannot compute (a missing mechanism) right after opening it, before `realise`. Either way, nothing is created.
- **The lock stores SHA-256 of each commitment output, never the output.** The output is a valid MAC or ciphertext under the key. A published `kw` blob in particular would let anyone feed the token a "wrapped" key of known value.
- **`check <object>` without a scheme** verifies every ID the spec computes. `check <object>.id.<scheme>` also requires that scheme. The Nix lib's `check {}` no longer guesses a primary scheme.
- **Tests use independent oracles:**
  - Public keys: a hand-written DER encoder over the raw PKCS#11 attributes (P-256/384/521, Ed25519/Ed448, RSA 3072/4096), checked through both the private-key and `publicOnly` paths.
  - Certificates: openssl-computed hashes of the P-384 and Ed25519 fixtures.
  - AES: the `cmac`, `aes` and `aes-kw` crates over a known key value planted sensitive and non-extractable.
- **Not covered:** DES/3DES, DSA, DH, GOST (legacy), `CKO_DATA`, and AES keys that may only `CKA_UNWRAP` or `CKA_DECRYPT`. An unwrap-only KEK has no deterministic commitment on SoftHSM: unwrapping a fixed blob fails the RFC 3394 integrity check.

**More types (2026-11-11):**
- **HMAC key types** `CKK_SHA_1_HMAC`, `CKK_SHA224_HMAC`, `CKK_SHA256_HMAC`, `CKK_SHA384_HMAC` and `CKK_SHA512_HMAC`.
  - **Identity:** the `commitment` scheme, using HMAC with the key type's own hash. The key type is in the label, so types never share an ID. Generic secrets keep HMAC-SHA256.
  - **No `autoCreate`:** PKCS#11 has no key generation for the hash-bound types (`CKM_GENERIC_SECRET_KEY_GEN` makes `CKK_GENERIC_SECRET`), so it is refused up front.
  - **Oracles:** SoftHSM keys with known values (each at least as long as its hash output, which SoftHSM requires) and a tpm2-pkcs11 `hmac:sha384` import match host HMACs.
  - **cryptoki 0.10.1 bug:** cryptoki (≤ 0.12.1 and main) gives `KeyType::SHA224/384/512_HMAC` the value 0x2b. The Nix build applies `nix/patches/cryptoki-hmac-key-types.patch` to the vendored crate sources (`postPatch`, `$cargoDepsCopy`). Without the patch, key-mgmnt refuses those three types and the tests skip them. Upstream fix drafted in `upstream/rust-cryptoki/`.
- **AES-128/192:** all four schemes match the host oracle, which now handles 128, 192 and 256 bits.
- **Decrypt-only AES (`kcv-ecb-dec`):** single-block ECB *decryption* of the domain-separated block, enabled by `CKA_DECRYPT`. Wrap-rebind computes it too, after `cmac` and `kcv-ecb` and before `kw` in order of preference. A decrypt-only key no longer needs an opt-in mode. Unwrap-only keys remain impossible.
- **Stand-alone public keys (`CKO_PUBLIC_KEY`):** adopted only, identified by `pubkeyhash`, URI `type=public`, with policy attributes such as `CKA_VERIFY` checked.
- **Data objects (`CKO_DATA`):**
  - **Identity:** `valuehash`, the SHA-256 of `CKA_VALUE`. That is the same SRI hash as a flat (not NAR) Nix fixed-output hash of the content.
  - **Adopted only,** URI `type=data`.
  - **Private data objects are refused.** A hash of a low-entropy private value (password, PIN) in the lock would be an offline guessing oracle.
- **Curves:** secp256k1, brainpoolP256r1 and brainpoolP384r1 (`k256`/`bp256`/`bp384`), checked against the DER oracle on SoftHSM. brainpoolP512r1 has no RustCrypto crate and is refused with that reason.
- **Upgrade rule:** a newly computed scheme that the lock does not record is only a note once another scheme matched; with nothing to compare it is still first use (exit 10). An explicitly requested `check <obj>.id.<scheme>` needs that scheme locked.
- **Spec digests are pinned** by a unit test (certificate and RSA digests from the YubiKey lock). `keyType` became optional for data objects without changing any digest.

**tpm2-pkcs11 as the secondary reference (2026-11-11):**
- **Works:**
  - P-256, P-384 and P-521 (with the fix-up below) and RSA 2048/3072, both generated and adopted through `publicOnly`.
  - EC and RSA keys imported with `tpm2_ptool import`; their `pubkeyhash` matches openssl over the PEM.
  - HMAC keys: `CKK_SHA256_HMAC` is a standard key type and is now accepted. Imported with a known value, the HMAC `commitment` matches a host-computed HMAC. The key type is part of the label, so the same bytes held as `CKK_GENERIC_SECRET` have a different ID.
  - AES keys made with `tpm2_ptool addkey`, through `kcv-ecb`.
- **Not available** (no mechanism; refused before anything is created): CMAC, AES key wrap (so neither `kw` nor wrap-rebind), Edwards curves. RSA 4096 is refused by swtpm.
- **Quirks, handled by the `key-mgmnt-tpm2-pkcs11` provider:**
  - **`C_GenerateKey` returns `CKR_FUNCTION_NOT_SUPPORTED`** although `CKM_AES_KEY_GEN` is advertised. The provider drops `CKM_AES_KEY_GEN` and `CKM_GENERIC_SECRET_KEY_GEN` from the usable mechanisms, so `autoCreate` of a secret key is refused up front, with a hint to use `tpm2_ptool addkey`/`import` and adopt.
  - **P-521 `CKA_EC_POINT` has a malformed DER length:** `04 85 …` instead of `04 81 85 …`. The length is always written as one byte, in both `src/lib/tpm.c` and `tools/tpm2_pkcs11/utils.py`; P-256/P-384 points are short enough to escape it. The provider re-encodes exactly that form; anything else still meets the strict parser. This is an upstream bug worth reporting.
- **Quirks that need no code:**
  - `tpm2_ptool import` does not support P-521 at all, so trimmed-coordinate imports cannot arise.
  - Imported keys are `CKA_EXTRACTABLE = true`.
  - `CKA_ID` is empty for generated keys and random hex for `tpm2_ptool` keys.
  - The token serial is all zeros on swtpm.
  - A session does not see objects created by another process after it opened. key-mgmnt opens a fresh session per run.
- **A refused `realise` leaves nothing behind (generic).** If the identity of a just-created object cannot be established, `realise` destroys what it created. If-None-Match guaranteed the locator was empty. Seen with the P-521 bug when the provider is disabled (`provider = "generic"`).
- **Test harness (`nix/tpm2-test-env.sh`):** swtpm, a private D-Bus from dbus's packaged `session.conf` on an abstract socket, tpm2-abrmd, and token `kmtest`. `tpm2_ptool` needs the resource manager; without one it runs out of TPM object slots. It runs in the package's `preCheck`, so `checks.key-mgmnt` exercises tpm2-pkcs11 in the Nix sandbox.
- **Oracles:**
  - Generated public keys: the hand-written DER oracle. For P-521 it applies the same length repair; the independence lies in building the SPKI, and the p521 crate checks the point is on the curve.
  - Imported keys: openssl over the fixture PEMs (test-only keys).
  - HMAC: computed on the host.
  - AES: a consistency check only, because tpm2-pkcs11 cannot import AES keys. The independent AES oracle runs on SoftHSM.

**p11-kit forwarding (2026-11-11), the path for real builds.** `p11-kit server` serves a token on a socket, and builds load `p11-kit-client.so`. Provider crate: `key-mgmnt-p11-kit`. Test suite: `tests/p11kit.rs`, which puts a SoftHSM token behind the server in the package build and compares it with direct access. Observed with p11-kit 0.26.5:
- **The module behind the proxy is hidden.** `C_GetInfo` describes p11-kit ("PKCS#11 Kit Proxy Module" 1.1, Cryptoki 3.2), so provider auto-detection yields `p11-kit` and the lock records p11-kit as the module. `C_GetTokenInfo` is forwarded unchanged. To apply the real module's fix-ups, e.g. tpm2-pkcs11's P-521 repair, name its provider explicitly (`provider = "tpm2-pkcs11"`).
- **The RPC drops mechanisms it cannot marshal:** `CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_PAD`, `CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKM_EDDSA` and `CKM_AES_CBC_ENCRYPT_DATA`. Through p11-kit there is therefore no `kw` commitment, no wrap-rebind and no Edwards key generation. These are refused before anything is created, with a p11-kit hint.
  - AES specs that declare several usage bits still link with direct access, through `cmac`/`kcv-ecb`.
  - A WRAP-only AES key cannot be identified through p11-kit at all.
- **Login is per client.** While one client holds a logged-in session, another client without a PIN still cannot see private objects; `publicOnly` works.
- **The server exports only the tokens in its URI** (`pkcs11:token=kmp11`): another token of the same SoftHSM is not present.
- **The socket path must fit `sun_path`.** A long path makes the server abort on an assertion (`strlen (address) < sizeof (sa.sun_path) - 1`).
- **Socket access.** By default the socket is owner-only (`srwx--x--x`). `p11-kit server -u/-g` give it to one user or group; auto-allocated build UIDs need the same per-slot ACL as `/dev/tpmrm0`.
- **What agrees:**
  - P-256/P-521/RSA-3072 generated through p11-kit give the same `pubkeyhash` when opened directly and through `publicOnly`, and match the DER oracle.
  - AES `cmac`/`kcv-ecb` and the HMAC `commitment` match the host oracles.
  - The SoftHSM suite passes unchanged on the same SoftHSM.
- **Still to do (module and VM test):**
  - A `p11-kit server` service per token, running as a dedicated user with the token's storage.
  - The socket ACL'd for the build GIDs and granted by the pre-build-hook.
  - A consumer in the sandbox that sees only the socket, never the database.

**NixOS module (`nixosModules.default`, nix/module.nix):**
- **`services.key-management.sandbox.pcscd.enable`:** pcscd, `/run/pcscd` in the sandbox, a polkit rule for `nixbld` *and* the auto-allocated UID range, and `PrivateUsers = false` on pcscd when UIDs are auto-allocated.
- **`sandbox.uidRange.enable`:** `auto-allocate-uids` plus the `uid-range` feature.
- **`tokens.<name>.{systemFeature, sandboxPaths}`:** these extend, rather than replace, the NixOS default `system-features`.
- **`checks.<name>`:** a oneshot `key-management-check-<name>` unit running `key-mgmnt check`, `requiredBy` the units that use the key.
- **`checks.module`:** a VM test of all of the above, including a sandboxed pcscd connection with auto-allocated UIDs and a `uid-range` build.
- **Status:** not yet applied to infinitejest, which still carries its hand-written equivalents.

**Tests:**
- **`checks.key-mgmnt`:** unit tests, plus SoftHSM integration tests that run inside the Nix build sandbox:
  - the TOFU flow, with no duplicate on retry;
  - DELETE + If-Match (deleting an absent object succeeds even with no lock; a present object with no expected ID is never deleted);
  - a host-side HMAC oracle for both secret modes;
  - two specs sharing one material giving the same ID;
  - the opt-in rule, conflict/ambiguous/type mismatch, and downgrade.
- **`checks.lib`:** pure evaluation of the Nix library against fixtures.
- **`checks.vm`:** a NixOS VM.
  - The pseudo-FOD first-use runs inside the *guest's* Nix sandbox (key created, build fails with `got:`; a retry doesn't duplicate). Recording the hash out of band then lets the consumer build.
  - An independent oracle (`pkcs11-tool` + `openssl`) matches `pubkeyhash`.
  - Also covered: wrap-rebind, DELETE semantics, and the caching caveat (a cached consumer succeeds after the key is gone; `--check` fails).
- **`packages.test-nspawn`:** the same flow in systemd-nspawn, minus the in-guest Nix build. Passes on infinitejest (2026-11-11) with `auto-allocate-uids = true` and `uid-range`. It stays out of `checks` because hosts without `uid-range` cannot build it. The test mounts a tmpfs over `/var` first, because host `extra-sandbox-paths` under `/var` make the sandbox's `/var` unwritable to the build's root.

**pcscd on this host (resolved 2026-11-11):**
- **Host and sandboxed builds both reach the YubiKey** (`nix run .#pcsc-probe`, `nix run .#pcsc-sandbox-probe`). ykcs11 lists `YubiKey PIV #39189318` (YK5, firmware 5.7.4).
- **Host config needed for this** (in nixos_flake `hosts/infinitejest.nix`): `auto-allocate-uids` + `uid-range`, a polkit rule admitting the auto-allocated UID range, and `PrivateUsers = false` on pcscd. Upstream's `PrivateUsers=identity` maps only UIDs 0–65535, so pcscd would otherwise see build UIDs as 65534.
- **PIV quirks observed:** labels and `CKA_ID`s are fixed per slot (e.g. "X.509 Certificate for Retired Key 1" = ID 0x05; attestation = 0x19). Retired slots 1–3 already hold certificates on this key, presumably the Secure Boot signing keys. The PIV profile must never generate into an occupied slot.