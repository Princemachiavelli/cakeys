# TPM 2.0 object model: identity, state, and how a cakeys config + lock could describe TPM objects

Scope note: all spec citations are to the **TPM 2.0 Library Specification, Version 185** (cover date 12 March 2026), the current published revision as of November 2026, unless a different revision is named. Section and table numbers move between revisions; they were checked against the text extracted from the v185 PDFs:

- Part 1 (Architecture): <https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf>, abbreviated **P1**
- Part 2 (Structures): <https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf>, abbreviated **P2**
- Part 3 (Commands): <https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf>, abbreviated **P3**

cakeys context comes from `docs/DESIGN.md`, `crates/core/src/config.rs`, `PLAN.md` and `docs/REVIEW-2026-11-11.md` in the repo (local files, read 2026-11-11).

## Q1. TPM 2.0 object structure and the Name as a built-in content address (spec revisions, TPMT_PUBLIC, TPMT_SENSITIVE, TPM2B_PRIVATE, Name, Qualified Name, parent and hierarchy)

### Takeaway

A TPM object is a public area (`TPMT_PUBLIC`) plus a sensitive area (`TPMT_SENSITIVE`). The sensitive area leaves the TPM only as an encrypted, parent-specific `TPM2B_PRIVATE` blob. The object's **Name** is `nameAlg ‖ H_nameAlg(TPMT_PUBLIC)`. It is a native content address over type, attributes, authPolicy, parameters and the public key (or, for symmetric objects, a salted hash of the secret). It excludes the parent, hierarchy, handle, blob and authValue. Those are captured by the **Qualified Name**, `QN_B = H(QN_parent ‖ Name_B)`, which chains the Names of all ancestors.

### Cited Findings

**Spec revisions**

- The TCG lists these TPM 2.0 Library revisions — [TCG library page](https://trustedcomputinggroup.org/resource/tpm-library-specification/):

  | Revision | Date | Parts |
  |---|---|---|
  | 01.16 | Oct 2014 | 1–4 |
  | 01.38 | Sep 2016 | 1–4 |
  | 01.59 | Nov 2019 | 1–4 |
  | 01.83 | Mar 2024 | 1–4, with Part 3/4 code |
  | 184 | Mar 2025 | 0–3 |
  | 185 | Mar 2026 | 0–3, plus errata |

  The ISO/IEC 11889:2015 listing is the older ISO edition. From 184 on, revision numbers drop the "01." prefix, and Part 4 (code) is no longer listed.
- v185 adds:
  - ML-KEM, including Endorsement Keys;
  - ML-DSA, including Attestation Keys;
  - Curve25519/Curve448;
  - the sign/verify sequence commands (`SignVerifySequenceStart`, `SignSequenceComplete`, `VerifySequenceComplete`).

  — [TCG announcement, 22 Mar 2026](https://trustedcomputinggroup.org/new-computing-specification-implements-pqc-measures-to-protect-users-from-quantum-attacks/)
- v185 adds `TPM_ALG_MLDSA`/`TPM_ALG_HASH_MLDSA` and `TPM_ALG_MLKEM` members to `TPMU_PUBLIC_ID`; the `unique` of an ML-DSA or ML-KEM object is its public key — P2 §12.2.3.2 Table 226; P1 §24.5.3.6–24.5.3.7 ([P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf), [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf))
- Deprecations relevant to a validator:
  - `TPM2_CreateLoaded()` and derived objects were deprecated in version 184 — P1 §25.1.
  - Keys with both `sign` and `decrypt` SET were deprecated in version 185 — P2 §8.3.2 Table 37, bits 17–18.
  - RSA scheme `TPM_ALG_NULL` was deprecated in version 185, except for storage keys and raw RSAEP/RSADP — P2 §12.2.3.4.

  — [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf), [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)

**TPMT_PUBLIC (P2 §12.2.4, Table 235)**

- Fields: `type` (TPMI_ALG_PUBLIC), `nameAlg` (+TPMI_ALG_HASH, may be NULL), `objectAttributes` (TPMA_OBJECT), `authPolicy` (TPM2B_DIGEST, computed with nameAlg; the Empty Policy when absent), `[type]parameters` (TPMU_PUBLIC_PARMS), `[type]unique` (TPMU_PUBLIC_ID).
- The spec defines the Name directly: "The Name of the object is nameAlg concatenated with the digest of this structure using nameAlg."
- P1 §23.2 Table 34 groups the attributes into five classes:

  | Class | Attributes |
  |---|---|
  | usage | sign, encrypt, restricted |
  | authorization | userWithAuth, adminWithPolicy, noDA |
  | duplication | fixedParent, fixedTPM, encryptedDuplication |
  | creation | sensitiveDataOrigin |
  | persistence | stClear |

  An object meant to be duplicated "must have an authPolicy enabling the duplication."

  — [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf), [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

**TPMA_OBJECT bit layout (P2 §8.3.2 Table 37, v185)**

| Bit | Attribute |
|---|---|
| 0 | reserved |
| 1 | fixedTPM |
| 2 | stClear |
| 3 | reserved |
| 4 | fixedParent |
| 5 | sensitiveDataOrigin |
| 6 | userWithAuth |
| 7 | adminWithPolicy |
| 8 | **firmwareLimited** |
| 9 | **svnLimited** |
| 10 | noDA |
| 11 | encryptedDuplication |
| 12–15 | reserved |
| 16 | restricted |
| 17 | decrypt |
| 18 | sign / encrypt (for a symcipher this bit means *encrypt*) |
| 19 | x509sign |
| 20–31 | reserved |

- "The state of the attributes is determined when the object is created and they are never changed by the TPM" — P2 §8.3.1. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- Table 37 says verbatim: "fixedTPM does not indicate that key material resides on a single TPM (see sensitiveDataOrigin)." — P2 §8.3.2. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- sensitiveDataOrigin: "If the fixedTPM attribute is SET, then this attribute is authoritative and accurately reflects the source of the sensitive area data. If the fixedTPM attribute is CLEAR, then validation of this attribute requires evaluation of the properties of the ancestor keys." — P2 §8.3.3.5. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- Asymmetric keys:
  - When the TPM creates an asymmetric key, sensitiveDataOrigin must be SET; the caller cannot supply an asymmetric private key to Create.
  - An imported asymmetric key cannot have fixedTPM SET.
  - The attribute is only checked at creation and may have any value on load or import.

  — P1 §22.2.3. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- Functional combinations of sign/decrypt/restricted — P1 §22.1.5 Table 33. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

  | sign | decrypt | restricted | Meaning |
  |---|---|---|---|
  | 0 | 0 | 0 | sealed data blob (keyedHash only; read with `TPM2_Unseal`) |
  | 0 | 1 | 1 | Storage Parent; a keyedHash with these bits is a Derivation Parent |
  | 1 | 0 | 1 | restricted signing key, i.e. an "Attestation Key"; signs only TPM-produced digests |
  | 1 | 0 | 0 | general signing key; for keyedHash, an HMAC key |
  | 0 | 0 | 1 | not allowed |
  | 1 | 1 | 1 | not supported |

**unique, and the binding between public and sensitive areas**

- The `unique` field holds a different value for each object type — P1 §24.5.3.2–24.5.3.7, Equation 48. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

  | Object type | `unique` |
  |---|---|
  | RSA | the modulus |
  | ECC | the public point |
  | ML-DSA, ML-KEM | the public key |
  | KEYEDHASH (HMAC key or sealed data) | `H_nameAlg(obfuscate ‖ key)`, where obfuscate is `seedValue.buffer` and key is `sensitive.bits.buffer` |
  | SYMCIPHER | the same formula as KEYEDHASH |

- Rationale for the obfuscation:
  - It prevents an offline guess of low-entropy secrets from `unique`.
  - It prevents identity theft: an attacker cannot pair an arbitrary sensitive area with a known public area, which would subvert `TPM2_PolicySecret`.

  "For symmetric objects ... the key (or data) is hashed with a TPM-generated obfuscation value." — P1 §24.5.3.1, §23.3. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- For Create and CreatePrimary, the TPM validates `type, nameAlg, objectAttributes, authPolicy, parameters` and copies them from the template unchanged; `unique` is then produced by the TPM — P1 §24.5.2–24.5.3. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- RSA `exponent = 0` in `TPMS_RSA_PARMS` means the default 2^16+1. Support for other exponents is optional, and "use of other exponents in duplicated keys is not recommended" — P2 §12.2.3.4. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)

**TPMT_SENSITIVE, the private area and TPM2B_PRIVATE**

- `TPMT_SENSITIVE` holds `sensitiveType`, `authValue` (TPM2B_AUTH, no longer than the nameAlg digest), `seedValue` and `[sensitiveType]sensitive` — P2 §12.3.2.4 Table 240. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
  - `seedValue` is the size of the nameAlg digest.
  - For a parent it is the optional protection seed; for other objects it is the obfuscation value.
- The private area is the marshaled sensitive area, encrypted with a key derived from the **Storage Parent's** seedValue. Its HMAC includes the Name of the object — P1 §23.4, §23.6–23.7. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
  - "Similar protections are used when an object is context saved or duplicated."
  - All symmetric encryption of the sensitive area uses CFB.
- `TPM2B_PRIVATE` is a size plus an encrypted `_PRIVATE`, which holds integrityOuter, integrityInner and sensitive. For Duplicate/Import the layers may differ; integrity may be absent. "When the TPM returns a TPM2B_PRIVATE Structure, the TPM pads the TPM2B_AUTH to its maximum size." — P2 §12.3.6–12.3.7 Tables 242–243. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- `TPM2_ObjectChangeAuth` changes an object's authValue by returning a **new private area**, which must be loaded before it applies. It cannot be used on NV indexes or Primary Objects; a primary with a new auth must be recreated — P3 §12.8. [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)

**Names of all entity types (P1 §13, Table 9)**

| Entity | Name |
|---|---|
| PCR, sessions, permanent handles | the handle value |
| NV Index | `nameAlg ‖ H_nameAlg(nvPublicArea)` |
| Transient (0x80) and persistent (0x81) objects | `nameAlg ‖ H_nameAlg(publicArea)` |
| sequence object | an Empty Buffer |

- "The handle associated with an object may change due to context management ..., but the Name of an object remains constant."
- "The Name of a public area template is computed in the same way as the Name of a Transient Object."

— [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

**Qualified Name (P1 §23.5)**

- `QN_B := H_B(QN_A ‖ NAME_B)` when A is B's Storage Parent. The Name and QN of a Primary Seed are its handle, so a primary's QN is `H_nameAlg(hierarchy handle ‖ Primary Object Name)`. For `TPM_RH_NULL` both are `TPM_RH_NULL`.
- "The QN of an object is included in its certification to indicate that the key is being used in a different environment (ancestry) than the one in which it was created."
- Creation data includes the parent's Name and QN.

— [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

- fixedTPM SET: "The hierarchy of the object, as indicated by its Qualified Name, may not change." — P2 Table 37, bit 1. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- tpm2-tools documentation likewise says the qualified name "serves as proof of the objects parents" — [tpm2_readpublic(1)](https://man.archlinux.org/man/extra/tpm2-tools/tpm2_readpublic.1.en)
- tpm2-pytss `get_name()` computes the Name on the host from a `TPM2B_PUBLIC` without asking the TPM — [tpm2-pytss docs](https://tpm2-pytss.readthedocs.io/en/1.0.0/types.html)

**Saved contexts**

- `TPMS_CONTEXT` metadata (sequence, savedHandle, hierarchy) is normative. The enclosed `TPMS_CONTEXT_DATA` is vendor-specific and encrypted, with fresh protection values on every save — P1 §27.2. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- stClear objects' saved contexts are invalidated by Startup(CLEAR) — P2 Table 37, bit 2. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)

### Inferences

- **The Name is a "spec + material" digest, which PLAN calls an instance CA-ID.**
  - It changes when any attribute, the authPolicy, nameAlg, a scheme or a parameter changes, even for the same key.
  - It does **not** change with the parent, the hierarchy, the handle, the authValue (`ObjectChangeAuth`) or the blob bytes.
  - So "same key material re-imported under another parent" gives the **same Name**, a **different QN** and a **different `TPM2B_PRIVATE`**. This holds when the public area is unchanged, which Duplicate/Import preserves except that Import forbids fixedTPM/fixedParent (P3 §13.3).
- **The blob is never identity.**
  - It is parent-specific: encrypted under the parent's seed.
  - It is re-randomised by ObjectChangeAuth.
  - Context blobs are vendor-specific and re-randomised on every save.
  - A blob digest is at most a cache key or locator.
- **Name portability depends on how the object was made.**
  - Two TPMs holding duplicates of the same object share the Name.
  - Two independently created objects with an identical template never do: different keys, or a different random `seedValue` for symmetric objects.
- **The Name is not an SRI hash.** It is `TPM_ALG_ID (2 bytes) ‖ digest`, and nameAlg may be SHA-384, SHA-512, SM3 or SHA3. A cakeys scheme for it needs its own immutable name (e.g. `tpm2-name`) and an encoding that carries nameAlg, e.g. `sha384-<b64>` SRI with the alg mapped from `TPM_ALG_ID`. DESIGN §10 freezes the SRI form as `sha256-<base64>`, so that rule needs extending for other algorithms.
- **Compute the Name on the host.** The verifier should hash the `TPMT_PUBLIC` returned by `TPM2_ReadPublic` itself and compare. Trusting the TPM-reported name field alone is not enough. tpm2-pytss's `get_name()` is an example of the host-side computation; whether systemd computes the Name on the host was not checked.

### Gaps

- The revision in which `x509sign`, `firmwareLimited` and `svnLimited` (TPMA_OBJECT bits 19, 8, 9) were introduced was not verified (likely 1.59 and 1.83 respectively, but unconfirmed).
- Part 0 (the v185 deprecation list) was not read.
- The exact ECC `unique` encoding was not checked. Are `x`/`y` always left-padded to field size by real TPMs, or can leading zeros be stripped? This matters for SPKI canonicalisation; cf. the existing tpm2-pkcs11 P-521 `CKA_EC_POINT` repair in DESIGN §6.2.

## Q2. Hierarchies, seeds, primary-key determinism, persistence, contexts, duplication, NV indexes, PCRs and policy digests

### Takeaway

Primary objects are a **derivation**: `TPM2_CreatePrimary(hierarchy, template)` deterministically regenerates the same key from the hierarchy's Primary Seed and *all bits* of the template. The determinism holds only on one TPM, under one seed epoch and one implementation.

- The algorithm is a vendor choice.
- It changed from KDFa to DRBG at 1.38.
- It is reset by `TPM2_Clear` (storage seed) or `ChangeEPS`.
- It is cut off by firmware-limited hierarchies.

Ordinary objects are random and must be persisted:

- as a blob under a parent, or
- in NV via `TPM2_EvictControl`, at handles 0x81000000–0x817FFFFF for the owner and 0x81800000–0x81FFFFFF for the platform.

Policies are content-addressed by construction. The `authPolicy` is a hash chain over policy assertions. `PolicyAuthorize` and `PolicyAuthorizeNV` let a stable digest delegate to a signed or NV-stored policy. systemd-pcrlock uses `PolicyAuthorizeNV` for exactly this reason, and its `pcrlock.json` is effectively a lock file.

### Cited Findings

**Seeds**

- Primary Seeds never leave the TPM — P1 §11.1, §11.4. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

  | Seed | Hierarchy and what it generates | Changed by | Effect of a change |
  |---|---|---|---|
  | EPS | endorsement; EKs | `TPM2_ChangeEPS` (platformAuth) | invalidates all Endorsement-hierarchy objects and EK certs |
  | PPS | platform firmware | `TPM2_ChangePPS` | — |
  | SPS | owner; SRKs | `TPM2_Clear` | invalidates the Storage hierarchy irrecoverably, and the Endorsement hierarchy except recreatable primaries |
  | Null seed | random on every TPM Reset | TPM Reset | objects cannot be made persistent |

- **Determinism.** "As long as the seed value does not change, the same key parameters generate the same EKs" — P1 §11.2. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
  - "All of the bits of the template are used in the creation of the Primary Key."
  - With the same seed and template, "the TPM shall produce the same Primary Object."
  - "An Empty Buffer is a legal unique field value." The template's `unique` is therefore an input that callers may use to diversify primaries.

  — P3 §24.1.1. [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)
- **Entropy for each object kind** — P1 §24.6 Table 37, §24.6.3. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
  - Primary objects use a DRBG instantiated with the hierarchy seed, the hash of the input template and a use string.
  - Ordinary objects use the TPM's default DRBG.
  - Derived objects use a KDF over the Derivation Parent's key with caller label and context.
  - "Choice of the entropy generation for Primary Objects is a vendor option"; the reference code uses SP 800-90A.
- **Field-upgrade caveat.** "A field upgrade can cause TPM2_CreatePrimary() to generate a different key for the same input template. For example, versions prior to version 1.38 used KDFa, while version 1.38 and after use DRBG." — P1 §11.4.1. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
  - The TPM shall keep regenerating the *manufacturer-certified EKs*.
  - It "should" keep regenerating other primaries when the strength and algorithm are unchanged.
  - "This requirement shall not be in effect for other keys derived from the EPS or for keys derived from the SPS or PPS."
- **Injected EPS or EK.** Manufacturers may inject the EPS or precomputed EKs compatible with specific templates — P1 §11.3. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- **Sensitive area of a primary.** It is never returned. A primary "will need to be regenerated each time it is needed, or it can be made persistent" — P1 §20.7. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- **Implied parent attributes.** For a primary, the parent is treated as having fixedParent, fixedTPM, decrypt and restricted SET, plus firmwareLimited/svnLimited when the hierarchy is a firmware- or SVN-limited one — P3 §24.1.1. [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)

**Firmware-limited and SVN-limited objects (P1 §41)**

- A firmwareLimited object is "cryptographically limited to the current firmware of the TPM":
  - `fwSecret := KDFa(hashAlg, bootloaderSecret, "FW_SECRET", H(tpmFw.image), ...)`.
  - svnLimited objects are reachable by firmware with SVN ≥ the object's.
  - Objects in such hierarchies become unusable after a firmware change or downgrade.

  — [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

**Persistence and handles**

- `TPM2_EvictControl` moves a loaded object to a persistent handle, or removes one — P1 §34.3; P3 §28.5. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
  - It is not allowed for NULL-hierarchy or stClear objects, or their descendants.
  - Owner handles are 0x81000000–0x817FFFFF; platform handles are 0x81800000–0x81FFFFFF.
  - A handle already in use cannot be reassigned.
- **New in v185:** "Support for persisting public-only objects was added in version 185." — P1 §34.3. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- The FAPI profile puts the SRK at a fixed persistent handle (`"srk_template": "system,restricted,decrypt,0x81000001"`) — [tpm2-tss fapi-profile.md](https://github.com/tpm2-software/tpm2-tss/blob/master/doc/fapi-profile.md)
- systemd-cryptenroll's default seal-key handle is the SRK at 0x81000001. systemd creates it if absent and writes it to `/run/systemd/tpm2-srk-public-key.tpm2b_public` at boot — [systemd-cryptenroll.xml](https://github.com/systemd/systemd/blob/main/man/systemd-cryptenroll.xml)
- systemd derives the SRK template from the "TCG TPM v2.0 Provisioning Guidance" §7.5.1 and the EK Credential Profile — [systemd tpm2-util.c](https://github.com/systemd/systemd/blob/main/src/shared/tpm2-util.c)

**Duplication**

- Duplication makes an object a child of an additional parent, on the same or another TPM — P1 §20.3. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
  - It requires a policy session whose policy sets `commandCode = TPM_CC_Duplicate`.
  - The outer wrapper uses the new parent's KEM; the inner wrapper is a symmetric key.
  - With encryptedDuplication SET, an inner wrapper and a non-NULL new parent are mandatory.
  - With encryptedDuplication CLEAR, `newParent = TPM_RH_NULL` and no inner wrapper exports the sensitive area in the clear (P1 §22.2.7).
- Hierarchy attribute combinations — P1 §20.6 Table 31. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

  | fixedParent | fixedTPM | Meaning |
  |---|---|---|
  | 0 | 0 | duplication root |
  | 0 | 1 | not allowed |
  | 1 | 0 | bound to its parent; moves only when an ancestor is duplicated |
  | 1 | 1 | created on this TPM; no duplicate possible |

- `TPM2_Import` rejects `objectPublic` with fixedTPM or fixedParent SET. It checks public/sensitive binding once at import when the new parent is fixedTPM, and otherwise on every load — P3 §13.3. [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)

**NV indexes**

- NV Name = `nameAlg ‖ H(TPMS_NV_PUBLIC)`. For the non-legacy NV handle types (MSO 0x11/0x12), it is `H(TPMU_NV_PUBLIC_2)`; the revision that introduced them was not established — P1 §13. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
  - `TPMS_NV_PUBLIC` holds nvIndex, nameAlg, attributes (TPMA_NV), authPolicy and the data size — P2 §13.6 Table 251.
  - **The Name changes** when `TPMA_NV_WRITTEN` becomes SET and when the index is write- or read-locked.
  - Callers should therefore compute the Name from their own copy of the public area.
- `TPMT_NV_PUBLIC_2` (P2 §13.10) and `TPMS_NV_PUBLIC_EXP_ATTR` (P2 §13.8) are new tagged forms. The Name hashes the bare union content, which starts with the `TPM_HT` byte of the handle, so legacy Names are unchanged — P1 §13. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf), [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- NV index types (P1 §34.2.6.2–34.2.6.6): ordinary, counter, bit field, extend and PIN (PIN Pass/Fail). The PIN types can limit how often an object is used — P1 §34.2.8.1. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

**Policy digests (the content-addressed policy identity)**

- `TPM2_PolicyPCR`: `policyDigest_new := H_policyAlg(policyDigest_old ‖ TPM_CC_PolicyPCR ‖ pcrs ‖ digestTPM)` — P3 §23.7. [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)
- `TPM2_PolicyAuthorize`: checks a signature by `keySign` over `approvedPolicy ‖ policyRef`, then resets the digest and applies `PolicyUpdate(TPM_CC_PolicyAuthorize, keySign, policyRef)`. The resulting authPolicy depends only on the **signer's Name** and policyRef — P3 §23.16. [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)
- `TPM2_PolicyAuthorizeNV`: compares the session digest with the NV contents, resets, then sets `policyDigest_new := H(policyDigest_old ‖ TPM_CC_PolicyAuthorizeNV ‖ nvIndex→Name)` — P3 §23.22, Eq. 9. [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)
- Policy authorization of objects:
  - `authPolicy` uses the object's nameAlg (P2 Table 235).
  - userWithAuth CLEAR forces USER-role actions through the policy.
  - adminWithPolicy SET forces ADMIN-role actions through the policy (P1 §22.2.4–22.2.5).
  - Trial sessions, or a host-side computation, produce the digest (P1 §16.7.10, §16.7.13–16.7.14).

  — [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

**systemd-pcrlock**

- What it does — [systemd-pcrlock(8)](https://www.freedesktop.org/software/systemd/man/latest/systemd-pcrlock.html):
  - It predicts PCR values from the firmware and userspace event logs plus `*.pcrlock` component files.
  - It builds a policy of `PolicyPCR` and `PolicyOR`, written to an **NV index** (allocated on first run).
  - Secrets are bound to it with `PolicyAuthorizeNV`, which needs TPM 1.38+.
  - The default PCRs are 0–5, 7, 11 and 13–15.
  - Metadata lives in `/var/lib/systemd/pcrlock.json`: the prediction, TPM and NV info, and an encrypted recovery PIN that can regain write access to the NV index.
  - Introduced in v255; credential copy in v256, `is-supported` in v258, `--strict` in v262.
- `*.pcrlock` files are JSON arrays in a subset of TCG CEL-JSON. Variants live in `*.pcrlock.d/` directories. More than 8 alternatives become a nested `PolicyOR` tree, up to 8^5 = 32768 values per PCR — [systemd.pcrlock(5) source](https://github.com/systemd/systemd/blob/main/man/systemd.pcrlock.xml)
- The policy JSON fields systemd parses (all mandatory): `pcrBank`, `pcrValues`, `nvIndex`, `nvHandle`, `nvPublic`, `srkHandle`, `pinPublic` and `pinPrivate` — [systemd tpm2-util.c, `tpm2_pcrlock_policy_from_json`](https://github.com/systemd/systemd/blob/main/src/shared/tpm2-util.c)

**Creation data and creation PCRs**

- Create and CreatePrimary return `TPMS_CREATION_DATA` with these fields — P1 §24.4, §24.8; P2 §15.1 Table 261:
  - `pcrSelect`, `pcrDigest` (selected PCRs at creation);
  - `locality`;
  - `parentNameAlg`, `parentName`, `parentQualifiedName`;
  - `outsideInfo`;

  plus a ticket so that `TPM2_CertifyCreation` can later prove the TPM created the object. "The creation data will act as a form of certification of the object that is most useful when fixedTPM is CLEAR." — [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf), [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)

### Inferences

- **A primary key is a pure derivation, the closest TPM analogue to a Nix input-addressed derivation.** Its output key is a function of (TPM implementation, seed epoch, hierarchy, template). The template, i.e. the spec, is fully known in advance, but the output differs per TPM and after `TPM2_Clear`. This matches PLAN's "generated per token" case. The lock must record the resulting Name/SPKI **per realisation** and treat a changed output on the same TPM as "the seed or firmware changed", a distinct diagnostic.
- **The hierarchy's identity can be fingerprinted.** The Name of a standard-template primary, such as the TCG SRK template under the owner seed or the EK under the EPS, acts as a "seed epoch ID". The TPM exposes no seed identifier, so this is the only observable stand-in. systemd's `tpm2_srk` field (a serialized ESYS_TR of the SRK) is precedent for pinning the parent in metadata.
- **An NV index's identity is state-dependent.** The Name shifts with WRITTEN, WRITELOCKED and READLOCKED. A lock entry must pin the NV public area in its *expected steady state*, e.g. WRITTEN=1. The `PolicyAuthorizeNV` digest commits to that exact Name.
- **Which policy primitive fits a lock.**
  - Raw `PolicyPCR` digests break on every firmware or kernel update. That gives a "lock churn" pattern, where every boot-chain change rewrites the lock.
  - `PolicyAuthorize` (signer Name + policyRef) or `PolicyAuthorizeNV` (NV Name) give a **stable authPolicy, and therefore a stable object Name**. The mutable PCR prediction moves into a signed blob or an NV index.
  - So the object lock should record the stable digest, and the PCR prediction should be its own lock entry. That is what pcrlock does, with pcrlock.json as the "lock" for the NV policy.
- **v185 public-only persistence is the TPM version of REVIEW finding H1.**
  - The problem: a persistent handle can now hold a public area with the expected Name and no private part, and `TPM2_ReadPublic` would still return the right Name.
  - Verification must include proof of possession:
    - sign a fresh challenge, for sign keys;
    - decrypt or ECDH with an ephemeral key, for decrypt keys;
    - HMAC a challenge, for keyedHash sign keys.
  - Or it must certify the object with `TPM2_Certify` under a trusted AK.
  - The same concern applies to `TPM2_LoadExternal` public-only objects in the NULL hierarchy.

### Gaps

- Whether `TPM2_Certify` can certify a public-only persistent object was not checked. It needs the object's ADMIN authorization, and a v185 public-only object may or may not satisfy it.
- Whether the input `authValue`, `inSensitive` or `outsideInfo` affects primary derivation was not confirmed. P1 §24.6.3 names only seed, template hash and a use string. `outsideInfo` and `creationPCR` presumably only affect creation data, and caller-supplied symmetric primary data presumably replaces the derived sensitive part. Neither was verified in P3 §24.1 detail.
- Vendor behaviour in practice was not checked: whether a given TPM model still uses KDFa, or reproduces the same SRK after a firmware update.

## Q3. Attestation: proving an object is TPM-resident with given attributes

### Takeaway

`TPM2_Certify` signs `TPMS_ATTEST{magic=TPM_GENERATED, type, qualifiedSigner, extraData(nonce), clockInfo, firmwareVersion, attested={name, qualifiedName}}` with an Attestation Key. The verifier needs the object's `TPMT_PUBLIC`: it recomputes the Name, matches it, and reads `fixedTPM` and `sensitiveDataOrigin` from the attested public area. Given a trusted AK chain (AK → EK via MakeCredential/ActivateCredential → EK certificate from the manufacturer), this proves:

- the key was generated inside a genuine TPM;
- it can never leave that TPM;
- it carries exactly the declared policy.

No standard PKCS#11 mechanism can prove that property. Vendor attestation exists outside the standard, e.g. YubiKey PIV attestation certificates. These signed structures can be stored in a lock and **verified offline** without the TPM.

### Cited Findings

- **Attestation commands and keys.**
  - Commands: `TPM2_Quote` (PCRs), `TPM2_GetTime`, the audit digests and `TPM2_Certify` (objects).
  - "The highest confidence is provided by a fixedTPM, restricted signing key that is created on a TPM with a certificate from the TPM manufacturer."
  - A restricted signing key signs only TPM-produced digests and refuses external data starting with `TPM_GENERATED_VALUE`.

  — P1 §28.1, §22.1.3. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- **Attestation structures.**
  - `TPMS_ATTEST`: magic, type, qualifiedSigner (the QN of the signing key), extraData, clockInfo, firmwareVersion, attested — P2 §10.11.12 Table 154.
  - `TPMS_CERTIFY_INFO` = {name, qualifiedName} of the certified object — P2 §10.11.3 Table 145.
  - `TPMS_QUOTE_INFO` = {pcrSelect, pcrDigest} — P2 §10.11.4 Table 146.
  - `TPMS_NV_CERTIFY_INFO` = {indexName, offset, nvContents} — P2 §10.11.8 Table 150.
  - `TPMS_NV_DIGEST_CERTIFY_INFO`, a hashed-contents variant, was added in 1.59 — P2 §10.11.9.

  — [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- **Obfuscation of counters.** When the signer is in the Storage hierarchy, `resetCount`, `restartCount` and `firmwareVersion` are obfuscated with a per-key value; deltas between attestations by the same key remain visible — P2 §10.11.12; P1 §28.3. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf), [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- **sensitiveDataOrigin is authoritative only under fixedTPM.** With fixedTPM SET it accurately reflects the source of the sensitive data; otherwise the ancestors must be evaluated. fixedTPM alone "does not indicate that key material resides on a single TPM" — P2 §8.3.2, §8.3.3.5. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- **Other attestation commands** — P3 §18.2–18.4, §31.16. [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)
  - `TPM2_CertifyCreation` attests the creation data: creation PCRs, locality, parent Name and QN.
  - `TPM2_NV_Certify` attests an NV index's Name and contents.
- **The EK Credential Profile (v2.6 r23, July 2024)** — [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6-Revision-23_16July24.pdf)
  - **Templates.** It defines default templates L-1 and L-2 (Low Range: RSA 2048 and ECC NIST P-256) and H-1 to H-25 (High Range).
  - **Storage.** EK certificates (DER X.509, possibly with trailing bytes) and optional non-default EK Templates (a marshaled `TPMT_PUBLIC`) live in NV indices. The Low Range is 0x01C00002–0x01C0000C, the High Range 0x01C00012–0x01C07FFF. The Low Range also permits an "EK Nonce" that modifies the template's `unique`.
  - **The `unique` field differs between the two ranges.**
    - Low Range L-1/L-2: "The buffer reserved for the public key of the EK is set to all zeros."
    - High Range: `unique` is an Empty Buffer for RSA and an Empty Point for ECC.
    - For NV-stored templates, "the unique field buffer size(s) SHOULD be zero".
    - The profile notes that the `unique` field "is only necessary to generate multiple different EKs if the rest of the TPMT_PUBLIC is the same". It also notes that a changed authPolicy yields a different EK.
    - It strongly recommends a different template, with `unique` used for diversity, for non-EK endorsement primaries.
  - **Policies.**
    - L-1/L-2 use PolicyA = `TPM2_PolicySecret(TPM_RH_ENDORSEMENT)`; authorization goes only through authPolicy.
    - High-Range templates use PolicyB = PolicyOR(PolicyA, PolicyC). PolicyC is `TPM2_PolicyAuthorizeNV` on a per-hash-algorithm Policy Index: I-1 is 0x01C07F01 for SHA-256 (H-1/H-2), I-2 is 0x01C07F02 for SHA-384, and so on.
- **The EK template matters.** Because the EK is a primary derived from the EPS and template, the EK certificate holds for whoever re-creates the EK with the *same template*. A changed EPS gives a different EK — P1 §11.2, §11.3.2. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- **Keylime** — [keylime design overview](https://keylime-docs.readthedocs.io/en/latest/design/overview.html)
  - The registrar collects EKpub, the EK certificate and AKpub.
  - It verifies "that the AK belongs to the EK (using MakeCredential and ActivateCredential)".
  - The tenant uses the EK certificate to judge the TPM.
  - The verifier checks quotes against UEFI and IMA event logs.
- **v185 Firmware-Limited Attestation Keys** exist so that relying parties can attest the TPM's own firmware — P1 §41.1, §41.9. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)

### Inferences

- **What attestation proves for a cakeys lock.** A `TPM2_Certify` over the realised object, nonce'd with something lock-bound such as the spec digest, combined with the stored `TPMT_PUBLIC`, gives an offline-verifiable proof of three things:
  1. The Name matches, so the public key, attributes and authPolicy are exactly as locked.
  2. `fixedTPM ∧ fixedParent ∧ sensitiveDataOrigin` holds, i.e. TPM-generated and non-duplicable: the TPM equivalent of PKCS#11 `CKA_LOCAL ∧ CKA_NEVER_EXTRACTABLE`, but *signed*.
  3. The QN places it in a specific hierarchy, under the AK's TPM.

  This is stronger than `pubkeyhash` alone, which only proves "some holder of this key".
- **A natural new identity mode, e.g. `attested`.** It would sit above `direct` for TPM realisations. The lock stores:
  - the certify blob and signature;
  - the AK public area;
  - and either the EK certificate digest or the AK→EK credential-activation transcript, as provenance.
- **Freshness.** A certify nonce'd with the spec digest binds the evidence to the spec but does **not** prove freshness. A live `verify` that wants a freshness claim must certify again with a fresh nonce; the stored blob is historical provenance only.
- **Where `firmwareVersion` comes from.** It is obfuscated for Storage-hierarchy AKs. Use an Endorsement-hierarchy AK, or `TPM2_GetCapability(TPM_PT_FIRMWARE_VERSION_1/2)` directly, for lock provenance; compare it like the PKCS#11 token firmware is compared today (warn, don't fail).

### Gaps

- TCG "TPM 2.0 Keys for Device Identity and Attestation" (IAK/IDevID) was not read. It defines manufacturer-certified AKs that would shortcut the EK→AK activation step.
- The verification rules for chaining a duplicated key (fixedTPM=0) back to an origin were not researched.

## Q4. Typical usage and tooling (tpm2-tools, ESAPI/FAPI, tss-esapi, tpm2-pkcs11, systemd, ssh-tpm-agent, age-plugin-tpm, keylime, Nix)

### Takeaway

Real-world TPM usage converges on four patterns:

1. A **well-known SRK at 0x81000001**, with ordinary child keys stored as **blobs** outside the TPM. The blobs are TSS2 key files, sqlite rows or LUKS2 token JSON.
2. **Sealed keyedHash secrets** bound to PCR or pcrlock policies (systemd-cryptenroll and systemd-creds).
3. **EK/AK attestation** (keylime).
4. **PKCS#11 facades** (tpm2-pkcs11).

Each tool's metadata already records parts of what a lock needs: policy hash, PCR mask and bank, primary algorithm, and a parent pin (systemd's `tpm2_srk`). None records the *object's own* Name as an identity that is checked before use.

### Cited Findings

**FAPI (tpm2-tss)** — [fapi-profile.md](https://github.com/tpm2-software/tpm2-tss/blob/master/doc/fapi-profile.md), [fapi-config.md](https://github.com/tpm2-software/tpm2-tss/blob/master/doc/fapi-config.md)

- The JSON **profile** fixes, for all keys:
  - nameAlg;
  - the asymmetric type, scheme, curve or keyBits and exponent;
  - symmetric parameters;
  - the PCR selection;
  - the SRK template (`"system,restricted,decrypt,0x81000001"`) and EK template;
  - JSON policies for the EK, SRK and hierarchies;
  - the DA lockout parameters.
- The **config** file names the profile, `user_dir`/`system_dir` keystores, the TCTI, `system_pcrs`, `ek_cert_less` and `ek_fingerprint`.

**tpm2-pkcs11**

- All objects live under a **persistent primary in the owner hierarchy**. Its handle is stored as a serialized ESYS_TR in the store. — [tpm2-pkcs11 ARCHITECTURE.md](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/ARCHITECTURE.md)
  - Per token, two sealed objects (SO and USER) are unsealed with the salted PIN, yielding an AES-256 wrapping key.
  - That key GCM-wraps every object's authValue.
  - Policy support is listed as future work.
- **Store.** The sqlite store sits under `TPM2_PKCS11_STORE`, `/etc/tpm2_pkcs11` or `$HOME/.tpm2_pkcs11`. Transient primaries are created from a template and need owner hierarchy auth. — [tpm2-pkcs11 INITIALIZING.md](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/INITIALIZING.md)
- **Schema.** Tables `pobjects(hierarchy, config, objauth)`, `tokens(pid, label, config)`, `sealobjects(userpub, userpriv, sopub, sopriv, salts)` and `tobjects(tokid, attrs)`. The pobjects config is YAML: `persistent: true` plus `esys-tr: <hex>`, or a transient template name. — [tpm2-pkcs11 src/lib/db.c](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/src/lib/db.c)
- **Vendor attributes.** Inside `tobjects.attrs` it keeps `CKA_TPM2_OBJAUTH_ENC`, `CKA_TPM2_PUB_BLOB`, `CKA_TPM2_PRIV_BLOB`, `CKA_TPM2_ENC_BLOB` and `CKA_TPM2_SERIALIZED_TR` — [tpm2-pkcs11 src/lib/attrs.h](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/src/lib/attrs.h), [src/lib/object.c](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/src/lib/object.c)

**systemd-cryptenroll (LUKS2 token `systemd-tpm2`)** — [systemd tpm2-util.c, `tpm2_make_luks2_json`](https://github.com/systemd/systemd/blob/main/src/shared/tpm2-util.c)

- The token JSON records:
  - `tpm2-blob` (the sealed object's pub and priv);
  - `tpm2-pcrs`, `tpm2-pcr-bank`, `tpm2-primary-alg`, `tpm2-policy-hash`, `tpm2-pin`;
  - `tpm2_pcrlock` and `tpm2_pcrlock_nv`;
  - `tpm2_pubkey`, `tpm2_pubkey_pcrs`, `tpm2_pubkey_ref` (signed-PCR-policy key and reference);
  - `tpm2_salt`;
  - `tpm2_srk` (serialized SRK handle);
  - the Argon2id parameters.
- A code comment says future fields use `_` rather than `-`.
- The SRK handle and offline sealing against a public key file (`/run/systemd/tpm2-srk-public-key.tpm2b_public`, or `systemd-analyze srk`) are documented in [systemd-cryptenroll.xml](https://github.com/systemd/systemd/blob/main/man/systemd-cryptenroll.xml).
- The legacy path, used for older sealed data, created a **transient** primary from a fixed template, flushed it, and relied on re-deriving "the exact same template" — [systemd tpm2-util.c](https://github.com/systemd/systemd/blob/main/src/shared/tpm2-util.c)

**TSS2 key files (`-----BEGIN TSS2 PRIVATE KEY-----`)**

- The ASN.1 is `TPMKey ::= SEQUENCE { type OID, emptyAuth [0], policy [1], secret [2], authPolicy [3], description [4], rsaParent [5], parent INTEGER, pubkey OCTET STRING, privkey OCTET STRING }`.
- `type` is one of three OIDs:

  | OID | Kind | Used with |
  |---|---|---|
  | 2.23.133.10.1.3 | loadable | `TPM2_Load` |
  | 2.23.133.10.1.4 | importable | `TPM2_Import` |
  | 2.23.133.10.1.5 | sealed | `TPM2_Unseal` |

- The parent "SHOULD be either a persistent handle (MSO 0x81) or a permanent handle (MSO 0x40)", never a volatile one.
- The version found, hosted at hansenpartnership.com, is `draft-bottomley-tpm-keys-00`, dated July 2024 and expired January 2025. Whether a newer IETF version exists was not established; a datatracker lookup returned nothing usable.

— [TPM 2 Key Format draft](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html)

**ssh-tpm-agent and age-plugin-tpm** — [ssh-tpm-agent README](https://github.com/Foxboron/ssh-tpm-agent), [age-plugin-tpm README](https://github.com/Foxboron/age-plugin-tpm)

- ssh-tpm-agent stores TPM-sealed SSH keys in `.tpm` files using that TSS2 key format.
- It supports:
  - import of existing keys;
  - remote wrapping to a target SRK exported with `tpm2_createprimary ... -a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda' -f pem`;
  - the owner hierarchy with an SRK.
- age-plugin-tpm creates age identities whose keys are created on the TPM and sealed outside it, with an optional PIN.

**tss-esapi (Rust)** — [crates.io tss-esapi](https://crates.io/crates/tss-esapi)

- The latest stable release is **7.7.0** (2026-04-24).
- The 8.0 line is in alpha: 8.0.0-alpha.4, 2026-10-09.

**Keylime**

- Agent, registrar and verifier; EK/AK enrollment via MakeCredential/ActivateCredential; quotes plus UEFI/IMA logs — [keylime design overview](https://keylime-docs.readthedocs.io/en/latest/design/overview.html)

**cakeys today**

- TPM is reached through tpm2-pkcs11, which lacks `C_GenerateKey` for AES and generic secrets and needs a P-521 `CKA_EC_POINT` repair.
- `sandbox.tpm2.enable` sets an ACL on `/dev/tpmrm*` for build users.
- PLAN says a native backend is needed for PCR and policy keys.

— `docs/DESIGN.md` §6.2, §7.3; `PLAN.md` "Target tokens" (local repo)

### Inferences

- **Pattern 1 (SRK + blob) maps cleanly onto cakeys' realisation and locator model.**
  - The locator is either a persistent handle or a blob reference: a TSS2 key file path, or a tpm2-pkcs11 row through PKCS#11.
  - The **parent pin** (the SRK Name) belongs in the lock. systemd's `tpm2_srk` is a serialized ESYS_TR, a format that carries the object's Name, which makes it an existing precedent for pinning the parent. Exactly how systemd checks it on unseal was not traced.
  - The TSS2 `TPMKey` format is a good *on-disk blob* format for a native backend. It is interoperable with openssl tpm2-provider, ssh-tpm-agent and the kernel, and already holds parent, pubkey (whose hash gives the Name), privkey and policy.
- **pcrlock.json and the LUKS2 token JSON are existing "lock files".** They record policy hash, PCR mask and bank, NV public area and SRK. cakeys could *read* them, e.g. adopting a LUKS2 TPM keyslot, but should not duplicate pcrlock's prediction engine.
- **FAPI profiles are a declarative precedent for spec-level defaults** (nameAlg, schemes, SRK template). FAPI's keystore paths, however, are locators, not identities: the same locator-as-identity problem PLAN raises for sequoia's TPM backend.

### Gaps

- **NixOS** `security.tpm2.*` options (enable, pkcs11, abrmd, tctiEnvironment) and nixpkgs versions of tpm2-tss, tpm2-tools and tpm2-pkcs11 were not verified in this pass.
- **systemd-creds** (`--with-key=tpm2`, host+tpm2) was not read.
- **FAPI keystore path semantics** (`/HS/SRK/...`, `/P_<profile>/...`) and the FAPI JSON policy language were not read in detail.
- The **tss-esapi 8.0 API** changes were not reviewed.
- **openssl tpm2-provider and kernel trusted keys** consumption of TSS2 key files was not checked.

## Q5. Mapping proposal for cakeys config + lock (intrinsic type / identity / location / provenance), and tpm2-pkcs11 versus a native backend

### Takeaway

Map the TPM onto cakeys' three levels as follows:

| cakeys level | TPM content | Where the IDs live |
|---|---|---|
| **object** | the material: `type` and size or curve, the same as today's `ObjectCfg` | material CA-IDs (`pubkeyhash` from `unique`, or the existing commitment schemes for symmetric keys) stay in `objects.<n>.ids` and stay portable across PKCS#11 and TPM |
| **spec** | a complete `TPMT_PUBLIC` *template* minus `unique`: nameAlg, every TPMA_OBJECT bit, scheme and parameters, authPolicy (by reference to a policy definition), and, for primaries, the template `unique` input | spec digest |
| **realisation** | the instance identity, location and provenance | see below |

The realisation records:

- **instance identity:** the Name, plus the stored `TPM2B_PUBLIC` so it can be recomputed offline;
- **location:** hierarchy, parent Name/QN, persistent handle or blob reference;
- **provenance:** manufacturer, firmware and spec revision, an EK certificate hash or seed fingerprint, and an optional `TPM2_Certify` attestation.

tpm2-pkcs11 collapses all TPM policy into `CKA_EXTRACTABLE ↔ !(fixedTPM|fixedParent)` and `CKA_LOCAL ↔ sensitiveDataOrigin`. It loses authPolicy, PCR binding, nameAlg, userWithAuth/adminWithPolicy, noDA, restricted, the Name and QN, and attestation. A native backend is required for any of these to be declared or verified.

### Cited Findings

**How tpm2-pkcs11 maps attributes** — [tpm2-pkcs11 src/lib/tpm.c](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/src/lib/tpm.c)

- On read:
  - `CKA_EXTRACTABLE = !(objattrs & (FIXEDTPM|FIXEDPARENT))`;
  - `CKA_ALWAYS_SENSITIVE = !extractable`;
  - `CKA_NEVER_EXTRACTABLE = !extractable`;
  - `CKA_LOCAL = SENSITIVEDATAORIGIN`.
- On create: `CKA_EXTRACTABLE=true` clears fixedTPM|fixedParent; false sets both.
- Its key templates hard-code `FIXEDTPM | FIXEDPARENT | SENSITIVEDATAORIGIN` combinations.
- Object authValues are random, GCM-wrapped by the token key.
- The primary is persistent in the owner hierarchy.
- Policy is "future" work.

— [ARCHITECTURE.md](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/ARCHITECTURE.md)

**Spec facts the mapping depends on**

- Name = nameAlg ‖ H(TPMT_PUBLIC) — P2 §12.2.4. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- QN chains the parents — P1 §23.5. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- The authValue is in the sensitive area, not the Name; changing it gives a new private blob — P2 Table 240; P3 §12.8. [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)
- The symmetric `unique` is `H(seedValue ‖ key)`, with a TPM-generated obfuscation value on creation — P1 §24.5.3. [P1](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)
- Import checks the public/sensitive binding (P3 §13.3), and the duplicated sensitive area includes seedValue (P2 Table 240). [P3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)
- RSA exponent 0 means 65537 — P2 §12.2.3.4. [P2](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)
- PLAN already names the TPM Name an "instance CA-ID" (spec + material, not object). It requires `pubkeyhash` to agree between the native and tpm2-pkcs11 paths, and it lists a TPM Name fallback for symmetric keys under `token-specific` — `PLAN.md` (local repo)

### Inferences

**Field classification (TPM → cakeys)**

| TPM field | Class | cakeys home |
|---|---|---|
| `type`, keyBits, curveID, symmetric keyBits, keyedHash vs symcipher | intrinsic type | `[objects.<n>]` (existing `class/keyType/curve/modulusBits/valueLen`); add a TPM `type` mapping (`TPM_ALG_ECC` ↔ `CKK_EC`, `SYMCIPHER/AES` ↔ `CKK_AES`, `KEYEDHASH`+sign ↔ `CKK_SHA256_HMAC`, `KEYEDHASH` sealed ↔ a private `CKO_DATA`-like class) |
| `nameAlg`, all TPMA_OBJECT bits, schemes (ECDSA/ECDAA/RSASSA/PSS/OAEP + hash), the `symmetric` of storage parents, KDF of keyedHash, `authPolicy` | policy | `[specs.<n>]` → spec digest. The marshaled `TPMT_PUBLIC` template with empty `unique` is itself a canonical, spec-defined digest input: the "template Name" (P1 §13) |
| `unique` (public key) | material identity | `objects.<n>.ids.pubkeyhash` (SPKI built from `unique`, exponent 0→65537, ECC point padded). Portable to PKCS#11 |
| Name | instance identity | `realisations.<spec>.<token>.ids.tpm2-name` (new immutable scheme). Must equal `nameAlg ‖ H(lock.publicArea)` |
| `TPM2B_PUBLIC` bytes | public evidence | lock (base64). Public, lets anyone recompute Name and SPKI offline |
| hierarchy, parent Name, parent QN, own QN | location (ancestry) | realisation `location` |
| persistent handle / TSS2 key file / tpm2-pkcs11 locator | locator | `keys.toml` locator; also recorded in the lock, as today's URI is |
| `TPM2B_PRIVATE` | locator payload (opaque, per parent, re-randomised by ChangeAuth) | **not identity.** Optionally `blobDigest` as a cache hint; never compared as identity |
| authValue | secret | never in lock; `pinFile`/`pinEnv`-like source |
| creation data + ticket, `TPM2_Certify` output, EK cert digest, AK public | attestation and provenance | realisation `attestation` and `provenance` |
| `TPM_PT_MANUFACTURER`, vendor strings, firmware version 1/2, spec revision (`TPM_PT_REVISION`), SVN | provenance | realisation `tpm` table (like today's `token` C_GetTokenInfo table) |

**Re-import under another parent.** For the same material and the same public area:

- the Name is equal, so the instance ID matches;
- the QN differs, the parent differs and the blob differs.

The lock should treat equal `tpm2-name` + `pubkeyhash` with a changed parent as a **move**, a location change reported as a note. It should not be treated as new material.

**The spec digest is frozen (DESIGN §10).** The current digest is canonical JSON `{"v":1,"type":…,"attributes":<boolean CKA_*>}`, so adding `tpm.*` policy fields changes its shape. There are two options; this note does not pick one.

- **(a)** A new digest version (`"v":2`) with TPM fields in canonical JSON.
- **(b)** For TPM specs, use the Name of the marshaled template `TPMT_PUBLIC` (with empty `unique`, or the primary's `unique` input) as the digest input. That encoding is canonical by the TPM spec (P1 §13: "The Name of a public area template is computed in the same way as the Name of a Transient Object"), which avoids canonical-JSON pitfalls. It does not cover non-TPMT fields such as the parent or locator, which are not identity anyway.

**Two specs over the same material** (e.g. sign-only versus decrypt-only, or with/without a PCR policy) give two Names and one `pubkeyhash`. This matches PLAN's object ← N specs.

**Symmetric and keyedHash objects**

- **TPM2_Create** with a TPM-generated or caller-supplied key: the Name is random per object (random `seedValue`), so it is a token-specific ID. It must be paired with a portable commitment computed by the TPM:
  - `TPM2_HMAC` for keyedHash sign objects → the existing `commitment` scheme;
  - `TPM2_EncryptDecrypt` for symcipher with the encrypt bit (bit 18) → `kcv-ecb`, or decrypt → `kcv-ecb-dec`;
  - CMAC needs a symcipher with sign=1 (SMAC; P1 §22.1.3).
- **TPM2_Import of host material:** the caller supplies `seedValue` in the duplicated sensitive area. A deterministic `seedValue`, e.g. derived from the commitment label, would therefore make `unique` and the Name **host-predictable and identical across TPMs** for the same key and template.
  - This is an *inference, not verified on hardware*.
  - It would make the TPM Name itself a portable commitment for imported symmetric keys, `H(label-derived salt ‖ key)`, with no key use required.
  - It does not help keys generated inside a TPM.
  - **Caveat:** the obfuscation value exists precisely to stop offline guessing of low-entropy secrets from `unique` (P1 §24.5.3.1). A public, label-derived salt removes that protection. It is only acceptable for full-entropy keys, e.g. random 256-bit AES/HMAC keys, and must never be used for sealed data, passwords or other low-entropy keyedHash content.
- **Sealed data** (keyedHash, sign=decrypt=0): the Name is a salted commitment over the data. A `valuehash` is possible only by unsealing, which needs auth or policy satisfaction.

**PCR and policy recording**

- Record the **authPolicy digest** as part of the spec, and the **policy definition** as its own declared entity, so cakeys can recompute the digest on the host. The definition is an ordered list of assertions (PolicyPCR with selection + expected digest, PolicyAuthorize with signer Name + policyRef, PolicyAuthorizeNV with NV public area, PolicySecret, PolicyCommandCode, PolicyOR branches).
- Prefer indirection (`PolicyAuthorize`/`PolicyAuthorizeNV`) for anything PCR-based. The key's Name then stays stable while the PCR prediction lives in an NV index (pcrlock) or in signed policies. Each of those is its own lockable entity: an NV index with a Name, and a signer with a `pubkeyhash`.
- Record the PCR bank and selection explicitly, never as a default.

**Primary keys ("derived per token")**

- The spec holds the template, including the `unique` input (e.g. empty, or a diversifier), plus the hierarchy.
- The lock holds one realisation per TPM with:
  - the resulting Name and `pubkeyhash`;
  - a `seedFingerprint` (the Name of the standard SRK or EK template under the same hierarchy).
- `verify` re-runs `CreatePrimary`, or reads the persistent handle, and compares. When the output differs and the `seedFingerprint` changed too, report "hierarchy seed changed (TPM2_Clear/ChangeEPS) or firmware changed primary derivation" (P1 §11.4.1) instead of a bare hash mismatch.

**Config sketch (`keys.toml`, illustrative)**

```toml
[tokens.tpm]
backend = "tpm2"                       # native (tss-esapi); PKCS#11 tokens keep module=
tcti = "device:/dev/tpmrm0"

[objects.signing]                      # unchanged: intrinsic type
class = "CKO_PRIVATE_KEY"; keyType = "CKK_EC"; curve = "secp256r1"

[policies.boot]                        # host-recomputable policy, digest goes to the lock
nameAlg = "sha256"
assertions = [ { PolicyAuthorizeNV = { nv = "pcrlock-nv" } } ]

[nv.pcrlock-nv]                        # an NV index is its own declared object
nvIndex = "0x01d10000"; nameAlg = "sha256"
attributes = ["TPMA_NV_OWNERWRITE","TPMA_NV_AUTHREAD","TPMA_NV_WRITTEN", "..."]  # expected steady state
dataSize = 34

[specs.signing-tpm]
object = "signing"
tpm.nameAlg = "sha256"
tpm.objectAttributes = ["fixedTPM","fixedParent","sensitiveDataOrigin","userWithAuth","noDA","sign"]
tpm.scheme = { ecdsa = "sha256" }
tpm.authPolicy = "boot"                # or an explicit digest, or empty
tpm.parent = { primary = "srk-ecc" }   # another spec (a primary template)
tokens.tpm = { locator = { persistentHandle = "0x81000010" }, autoCreate = true }
# alternative locator: { keyFile = "/var/lib/cakeys/signing.tss2" }  (TSS2 PRIVATE KEY)

[specs.srk-ecc]                        # a primary: the template is the whole spec
tpm.hierarchy = "owner"
tpm.template = "tcg-srk-ecc-p256"      # or an explicit TPMT_PUBLIC; unique input = empty
tokens.tpm = { locator = { persistentHandle = "0x81000001" } }

[objects.hmac]
class = "CKO_SECRET_KEY"; keyType = "CKK_SHA256_HMAC"; valueLen = 32
[specs.hmac-tpm]
object = "hmac"
tpm.nameAlg = "sha256"
tpm.objectAttributes = ["fixedTPM","fixedParent","userWithAuth","sign"]  # keyedHash HMAC
tpm.parent = { primary = "srk-ecc" }
tokens.tpm = { locator = { keyFile = "hmac.tss2" }, identity.allow = [] }
```

**Lock sketch (`keys.lock`, illustrative)**

```toml
[objects.signing.ids]
pubkeyhash = "sha256-…"                # same value as via tpm2-pkcs11 / SoftHSM

[objects.hmac]
commitmentLabel = "key-management/v1"
[objects.hmac.ids]
commitment = "sha256-…"                # TPM2_HMAC over the label; portable

[realisations.signing-tpm.tpm]
specDigest = "sha256-…"
mode = "direct"                        # or "attested" when certify evidence is present
ids."tpm2-name" = "sha256-…"           # nameAlg-tagged; recomputed from publicArea
publicArea = "base64 TPM2B_PUBLIC"
authPolicy = "sha256-…"                # = policies.boot digest at realisation time
[realisations.signing-tpm.tpm.location]
hierarchy = "owner"
parentName = "sha256-…"                # SRK Name (cf. systemd tpm2_srk)
qualifiedName = "sha256-…"
persistentHandle = "0x81000010"
[realisations.signing-tpm.tpm.tpm]     # provenance, warn-not-fail like module/token today
manufacturer = "…"; vendor = "…"; firmware = "…"; specRevision = 185
seedFingerprint = "sha256-…"           # Name of the TCG SRK template under owner seed
ekCertHash = "sha256-…"                # optional
[realisations.signing-tpm.tpm.attestation]   # optional, offline-verifiable
certifyInfo = "base64 TPMS_ATTEST"; signature = "base64"; akPublic = "base64 TPM2B_PUBLIC"
nonce = "specDigest"

[realisations.srk-ecc.tpm]             # primary: per-TPM derived output
specDigest = "sha256-…"; mode = "direct"
ids."tpm2-name" = "sha256-…"; ids.pubkeyhash = "sha256-…"
publicArea = "base64"

[realisations.hmac-tpm.tpm]
mode = "commitment"
ids."tpm2-name" = "sha256-…"           # token-specific (random seedValue unless imported)
[realisations.hmac-tpm.tpm.location]
parentName = "sha256-…"; keyFile = "hmac.tss2"; blobDigest = "sha256-…"  # hint only

[nv.pcrlock-nv.tpm]
name = "sha256-…"                      # Name of NV public in expected (WRITTEN) state
nvPublic = "base64 TPMS_NV_PUBLIC"
```

**Verification (verify/check) for a native TPM realisation**

1. Resolve the locator: the persistent handle, or load the key file under the parent.
2. **Bind the parent cryptographically, not only through `ReadPublic`.** Under v185 public-only persistence, a public-only SRK would pass a Name comparison.
   - **Salted session.** Start a session salted to the *locked* parent public area (`tpmKey` = parent; P1 §16.6.11 Eq. 23). Only a TPM holding the parent's private key can decrypt the salt.
   - **Key files.** A successful `TPM2_Load` of a key file already proves the parent's seed, because the private blob is integrity-protected under it (P1 §23.4, §23.7).
   - **cpHash.** The command cpHash covers the Names of the handles (P1 §15.7 Eq. 15), so authorized commands are bound to the expected Names.
3. `ReadPublic`, then recompute the Name on the host. Compare it with the lock, and the SPKI hash with `objects.ids.pubkeyhash`.
4. Check every TPMA bit, scheme and authPolicy against the spec. Exit 13 on conflict, as today.
5. **Proof of possession**, to close the H1 analogue (e.g. v185 public-only persistence). The method depends on the key type:

   | Key type | Proof of possession |
   |---|---|
   | unrestricted sign | sign a fresh challenge |
   | keyedHash sign | HMAC a fresh challenge |
   | unrestricted decrypt | ECDH or decrypt with an ephemeral host key |
   | restricted decrypt (SRK, storage primaries) | cannot decrypt arbitrary data, so use the salted-session method of step 2 |
   | restricted sign (AK) | `TPM2_Hash` → ticket → `TPM2_Sign`, or self-`Certify` |

6. Optionally `TPM2_Certify` with a pinned AK, for `attested` mode.

The lock never stores secrets or blobs as identity, only public areas and hashes, which is consistent with DESIGN §8.1.

**tpm2-pkcs11 versus native**

- Through PKCS#11, cakeys can verify `pubkeyhash`, the commitment schemes, `CKA_EXTRACTABLE` (= fixedTPM|fixedParent) and `CKA_LOCAL` (= sensitiveDataOrigin).
- It cannot verify: authPolicy/PCR binding, nameAlg, userWithAuth/adminWithPolicy, noDA, restricted, encryptedDuplication, stClear, the parent or QN, or attestation.
- Its derivation of `CKA_ALWAYS_SENSITIVE`/`CKA_NEVER_EXTRACTABLE` from fixedTPM|fixedParent is lossy: it is not tracked over the object's history.
- Realisations through the two paths should share `objects.ids` (`pubkeyhash`/commitments). Only the native realisation carries `tpm2-name`, unless tpm2-pkcs11's vendor `CKA_TPM2_PUB_BLOB` turns out to be readable (see Gaps).

### Gaps

- Not verified whether `CKA_TPM2_PUB_BLOB` is returned by `C_GetAttributeValue` to PKCS#11 clients. If it is, the Name is computable on the tpm2-pkcs11 path as well and the two paths could cross-check `tpm2-name`. An easy test in the existing `tests/tpm2.rs` harness.
- Not verified on hardware or swtpm that `TPM2_Import` with a caller-chosen `seedValue` yields a deterministic, cross-TPM Name for symmetric keys. The inference rests on P1 §24.5.3 and P3 §13.3 binding checks.
- Not verified whether tpm2-pkcs11 reports `CKA_PUBLIC_EXPONENT` as 65537 for TPM keys with exponent 0. If it reports 0, cross-path `pubkeyhash` agreement needs a provider fix-up.
- **Commitment mechanisms on real TPM hardware.** `TPM2_EncryptDecrypt` in ECB mode and `TPM2_MAC` (CMAC) are optional in TPM profiles. The `kcv-ecb`/`cmac` commitment path for TPM symmetric keys has been shown on swtpm (via tpm2-pkcs11, DESIGN §3.1) but not on hardware TPMs. Check the [PC Client Platform TPM Profile](https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Specific-Platform-TPM-Profile-for-TPM-2p0-v1p07_rc1_12Dec2025.pdf) for which modes and commands are mandatory. `TPM2_HMAC` (keyedHash) is the safer portable choice.
- Not researched:
  - SPKI encodings for ML-DSA/ML-KEM TPM keys (needed for a portable `pubkeyhash` of PQC TPM keys);
  - whether the v185 Curve25519/448 additions use `TPMS_ECC_POINT` with new curve IDs.
- No source found that proposes a TPM-Name-based lock file or a declarative TPM object manifest beyond FAPI profiles, the TSS2 key format, sequoia's YAML templates (cited in PLAN) and systemd's pcrlock/LUKS2 metadata. The proposal above is original synthesis.
