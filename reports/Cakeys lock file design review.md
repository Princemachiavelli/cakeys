# Cakeys locks pin material, not state

Today a `keys.toml` + `keys.lock` pair proves **which material** an object is (cryptographically for public keys, certificates and data objects; by token assertion for secret keys), but it does **not** completely describe the object's state, and at commit `8889898` the lock schema is still underdefined in specific, fixable ways. The identity core is sound and stricter than the closest prior art: frozen scheme names, an SRI digest on every ID, a recorded type and commitment label, and failure whenever any computed scheme disagrees. The user's stronger requirement, that config plus lock be enough to prove that something else in a change caused a hash break, fails on two fronts. There are **seven false-pass paths**, where verify succeeds when it should not; the most consequential are H1 (an EC/Edwards private key's identity taken from an unbound public object, the only one reproduced by a test), its widening H1b (a settable, unchecked `CKA_PUBLIC_KEY_INFO` on SoftHSM and kryoptic that cakeys reads first, so RSA is affected too), and S3 (a spec/token pair the lock has never recorded verifies on object IDs alone, skipping the spec-digest and downgrade checks). There are also **two misattribution paths**, where an object retarget or a locator change surfaces as an unexplained exit 10 instead of "keys.toml changed", and a `version = 1` that names at least three different schemas. The fixes fall into three tiers: first stop the false passes (a fresh proof of possession for every private key recorded as a `binding` level, a required realisation record, and comparison of `object`, locator and `publicOnly`); then close the schema (a required frozen version, separate compared/observed/provenance tables, and a pinned full policy vector); then extend the model (typed policy, attestation, a native TPM mapping built on the TPM Name, and post-quantum key types). Some facts stay unprovable through PKCS#11 or a TPM no matter what: that no copy exists, what happened to the key in the past, and whether a lying module really holds the secret key it commits to. The lock should say so by recording an evidence class for every fact it asserts.

## The identity core already matches the strongest prior art

`pubkeyhash` is exactly **RFC 7093 method 4**, SHA-256 over the whole DER SubjectPublicKeyInfo, untruncated ([RFC 7093](https://www.rfc-editor.org/rfc/rfc7093.html)), canonicalized by decoding and re-encoding through RustCrypto ([DESIGN.md §3.2](../docs/DESIGN.md)). That is the "fundamental parameters, not encodings" rule TUF's TAP 12 adopted after **GHSA-3633-5h82-39pq**, where one key listed under SHA-256 and SHA-512 keyids counted twice toward a signature threshold in go-tuf ([GHSA](https://github.com/advisories/GHSA-3633-5h82-39pq), [TAP 12](https://github.com/theupdateframework/taps/blob/master/tap12.md)). The common alternatives are weaker for this purpose:

| Identity | Weakness |
|---|---|
| OpenPGP fingerprints | Hash the creation time, so the same material yields different fingerprints ([RFC 9580 §5.5.4](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4)) |
| JWK and COSE thumbprints | Identify a key only under a single unambiguous encoding ([RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679.html)) |
| Sequoia's new PKCS#11 backend | Recovers OpenPGP fingerprints by storing the creation time inside the *mutable* `CKA_ID` ([sequoia-keystore cryptoki README](https://gitlab.com/sequoia-pgp/sequoia-keystore/-/blob/main/cryptoki/README.md)), the locator-as-identity mistake cakeys avoids |

Algorithm agility follows the right pattern: a changed computation gets a new scheme name, never an edit ([DESIGN.md §10](../docs/DESIGN.md)), mirroring go.sum's `h1` with `h2` reserved ([Go modules reference](https://go.dev/ref/mod#go-sum-files)) and Nix's declared `outputHashMode` next to the SRI hash ([Nix manual](https://nix.dev/manual/nix/latest/language/advanced-attributes)). On a mismatch, cakeys is deliberately stricter than its peers. in-toto accepts a match if "ANY acceptable field matches" ([in-toto DigestSet](https://github.com/in-toto/attestation/blob/main/spec/v1/digest_set.md)), and Terraform's dependency lock accepts a package matching "at least one" recorded checksum ([Terraform](https://developer.hashicorp.com/terraform/language/files/dependency-lock)), whereas cakeys fails if any computed, locked scheme disagrees ([ops.rs `reconcile`](../crates/pkcs11/src/ops.rs)). For cakeys that strictness is required, not merely safer: Terraform's checksums all hash the same package bytes, while cakeys' commitment schemes hash different token outputs of one secret.

Secret-key commitments are the industry's key check value (KCV) idea, upgraded to identity strength:

| Scheme | Construction | Output |
|---|---|---|
| PKCS#11 `CKA_CHECK_VALUE` | ECB of a zero block for AES; SHA-1 of the key value for generic secrets | **3 bytes**; "Two different keys can have the same" value ([PKCS#11 3.2 §4.11](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)) |
| X9.24-1-2017 | CMAC over a zero block | at most 40 bits ([summary](https://en.wikipedia.org/wiki/Key_checksum_value)) |
| cakeys | MAC or encryption over a domain-separated label `<label>/<scheme>/<keyType>/<bits>` | only SHA-256 of the full output is stored |

Because cakeys never computes `E_K(0)`, the Iwata–Wang attacks that exploit a public zero-block KCV do not apply ([ePrint 2014/183](https://eprint.iacr.org/2014/183)). The relevant strength is the cost of finding a *different* key that reproduces a given, locked commitment: about 2^128 work for AES-based outputs and about 2^256 for HMAC-SHA-256. Birthday collisions among 128-bit outputs would appear around 2^64 keys, but they do not matter here, because an attacker must match a fixed locked value rather than any pair.

The closest commercial analogue is **AWS KMS `KeyMaterialId`**, a 256-bit identifier derived from the key ID and the material, recomputed on re-import, with a mismatch failing as `IncorrectKeyMaterialException` ([AWS KMS](https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html)). The nearest pre-use check is **age-plugin-yubikey**, which refuses a PIV slot unless a **4-byte** SHA-256 tag of the public key matches ([key.rs](https://github.com/str4d/age-plugin-yubikey/blob/main/src/key.rs)), enough against accidents but not against an adversary.

| System | Identity of material | Secret keys | Verified before use | Lock |
|---|---|---|---|---|
| cakeys | SHA-256 of SPKI (RFC 7093 m4), cert or data value | on-token MAC/ECB/KW over a label, hashed | every use, also in the Nix sandbox | IDs, type, label, spec digest, provenance |
| Vault Ent. / OpenBao | `key_label`/`key_id` locator only ([Vault](https://developer.hashicorp.com/vault/api-docs/system/managed-keys)) | locator | test-sign proves usability only | none |
| KMIP 2.1 | server-assigned UID plus an unkeyed digest ([KMIP](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html)) | unkeyed hash of the secret | not specified | server DB |
| Terraform state | provider attributes, secrets in plaintext ([Terraform](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)) | plaintext | refresh / drift | `tfstate` |
| age-plugin-yubikey | serial + slot + 4-byte tag | — | yes, at connect | identity stub |
| AWS KMS | — | `KeyMaterialId` | on re-import | service-side |

No surveyed system combines protocol-neutral identities for asymmetric keys, secret keys and data objects with a declarative spec, a canonical digest and mandatory recomputation before use, so the design is novel where it matters. Two lessons from this prior art bear directly on the lock. First, TUF requires that "only one unique key has that KEYID" ([TUF spec](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)), but a naive cakeys version of that rule ("one ID, one object name") would reject the shipped YubiKey lock, where `whonix-db` and `whonix-db-cert` legitimately share a `pubkeyhash` ([yubikey-secureboot.lock](../examples/yubikey-secureboot.lock)); the invariant must be per scheme *and class*, with an explicit `pairs` relation between a key and its certificate. Second, the first-use `got:` flow is trust on first use in RFC 4251's sense ([RFC 4251 §4.1](https://www.rfc-editor.org/rfc/rfc4251.html#section-4.1)): the lock commit is the trust decision, and attestation, where a token offers it, is the only way to base that decision on more than faith.

## A four-way field test makes "complete" checkable

No source gives a formal definition of a complete lock, but four agree on a usable one. SLSA Build L3 requires external parameters to be "complete" and tells verifiers to "reject unrecognized or unexpected fields" ([SLSA v1.0](https://slsa.dev/spec/v1.0/provenance)); Bazel's `error` mode fails "if any information consulted during resolution is missing or out-of-date" ([Bazel lockfile](https://bazel.build/external/lockfile)); PEP 751 requires tool data to be disposable, so that it "MUST NOT affect installation" ([PEP 751](https://peps.python.org/pep-0751/)); and Nix fixed-output derivations declare the digest *method* next to the hash. Together they give this test: a lock is **not underdefined** when every value an ID or a verify verdict depends on falls into exactly one class.

| Class | Meaning |
|---|---|
| **(a) compared** | Recorded in the lock and compared on verify |
| **(b) frozen** | Fixed by an immutable definition that the lock names |
| **(c) provenance** | Never decides success; at most warns |
| **(d) out of scope** | Declared out of scope, with a reason |

Under that test, "something else in the change caused the hash break" becomes provable: if every (a) field is unchanged and every (b) name is known, a mismatch can only come from the token's material. Applied to every field at `8889898`:

| Field (where) | Class today | Verdict |
|---|---|---|
| `version` | compared, exact match | **Underdefined.** It names at least three schemas: `90d5353` added `commitmentLabel` and `8889898` added `type`, provenance and spec-digest comparison, all without a bump. A missing value defaults to *current* ([config.rs](../crates/core/src/config.rs)). |
| `objects.*.type` | (a), exit 14 even under `--update-lock` | OK, but a certificate's type is written back as `keyType = "CKC_X_509"`, because `certificateType` is only an input alias of `keyType` |
| `objects.*.commitmentLabel` | (a), feeds the commitment input | OK |
| `objects.*.ids.<known scheme>` | (a), exit 10 | OK |
| `objects.*.ids.<unknown scheme>` | (c), warning, never counts as proof | OK; matches SRI and in-toto's "ignore unknown" |
| Scheme computations | (b), pinned by `scheme_definitions_are_pinned` and `commitment_mechanisms_are_pinned` | OK |
| RustCrypto re-encoding; the provider fix-up rule | (b) in practice | **Unlisted premises**; §10 should freeze them by name |
| `realisations.*.specDigest` | (a), but only when a realisation record exists | **Leaks** (S3) |
| `realisations.*.mode` | (a), downgrade is exit 14, also only with a record | **Leaks** (S3) |
| `realisations.*.publicOnly` | diffed only under `--update-lock` | **Unclassified** (S4) |
| `realisations.*.uri` (locator) | diffed only under `--update-lock` | **Unclassified** (S9) |
| `realisations.*.mechanisms` | never compared, yet feeds `functions.<token>` in Nix eval ([lib.nix](../nix/lib.nix)) | **Unclassified** (S11) |
| `provider`; `module` build identity; `token` | (c), warning | OK, but mixed in with (a) fields |
| `module.path`; `cakeysVersion` | (c), note | OK, but churns on every nixpkgs or cakeys bump |
| `specs.<s>.object` (config only) | not recorded per realisation | **Unclassified** (S8) |
| Undeclared policy attributes | never read | **Unclassified** (S5) |
| `autoCreate`, `identity.allow` | gate creation and modes | `autoCreate` should be declared (d); `identity.allow` is enforced through `mode` |

The ID computation passes the test. The realisation layer fails it, with two leaking compared fields (`specDigest` and `mode`), five unclassified fields and two unlisted premises. That is the precise sense in which the schema is underdefined today.

## What config plus lock prove today, by evidence class

The facts a lock asserts differ in strength, and four evidence classes describe them: **[crypto]** facts the host checks with its own cryptography, **[attested]** facts a vendor or the TPM signs and the host verifies to a root, **[token-asserted]** facts the module merely reports, and **[unobservable]** facts no query reveals.

| Facet | Today | Best achievable | Never provable via PKCS#11/TPM |
|---|---|---|---|
| Public material (SPKI, cert, data) | **[crypto]**, hash of the public value | same | — |
| Private ↔ public binding | **[token-asserted]**, and for H1 **unbound** | [crypto] by fresh PoP; [attested] by YubiKey attestation or `TPM2_Certify` | — |
| Secret-key identity | **[token-asserted]** commitment; a dishonest module can replay it | same, unless the host shares the key at import | liveness against a lying module |
| Type and parameters | [crypto] for public keys; [token-asserted] `CKA_VALUE_LEN` for secrets | same | — |
| Declared policy bits | [token-asserted], re-checked on every verify | full vector, re-checked; frozen by `CKA_MODIFIABLE=false` on honest tokens | — |
| Undeclared policy | **not observed** | [token-asserted], pinned in the lock | — |
| Origin (generated on token, never extractable) | not recorded | [attested] (YubiKey; TPM `sensitiveDataOrigin` + `fixedTPM`) | — |
| Location (token, slot, locator) | [token-asserted]; p11-kit hides the module (D4) | [attested] via attestation serial or EK chain | relaying to a key held elsewhere, absent nonce-bound attestation |
| Exclusivity and history | — | bounded by `NEVER_EXTRACTABLE ∧ ¬COPYABLE` or `fixedTPM` | **[unobservable]**: copies, past exports |

The shipped YubiKey lock shows where these limits bite ([yubikey-secureboot.lock](../examples/yubikey-secureboot.lock)). Its certificates are proven by `certhash` [crypto]. Its three private keys are imported Secure Boot keys realised `publicOnly`, and Yubico produces attestation only for keys "generated on device" ([Yubico](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html)), so none is attestable. Their `pubkeyhash` is therefore token-asserted: ykcs11 serves a slot's public key from attestation, then from `GET METADATA`, then from the slot's certificate ([ykcs11.c](https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-2.7.3/ykcs11/ykcs11.c)), and the recorded firmware `5.74` (5.7.4) implies the metadata path by code reading. A proof of possession there would cost a PIN entry, and a touch for keys with a touch policy, on every verify, which is exactly why `publicOnly` exists. The honest fix is to record `binding = "token-asserted"` for these realisations rather than pretend they are bound.

Once the P0 and P1 changes below are in, the lock can state its guarantee in one sentence each way. If `verify` exits 0, the token exposes, through this module, material whose IDs equal the locked IDs under frozen schemes; the private half proved possession now, at the recorded binding level; its observed policy vector and spec-immutable attributes equal the recorded ones; and the spec, object, locator and `publicOnly` are unchanged. If it exits 10 while every compared field is unchanged, the material changed. Today S3–S5 break the first statement and S8–S9 break the second.

## Eighteen gaps, seven of them false passes

The register uses the severity scale of REVIEW-2026-11-11.md (**H**: identity can be wrong; **M**: wrong or unsafe behaviour in realistic use; **L**: robustness and clarity), with new IDs starting at S2 so they slot into the existing tracker. Cakeys-side facts were checked against the code at `8889898`; module behaviour comes from the cited upstream sources.

| ID | Sev | Kind | Finding | Evidence |
|---|---|---|---|---|
| H1 | H | false pass | An EC/Edwards private key on SoftHSM takes its `pubkeyhash` from the single public object under the locator, which nothing binds to the private key. | **reproduced**: `known_gap_ec_private_identity_comes_from_an_unbound_public_object` ([softhsm.rs](../crates/cli/tests/softhsm.rs)) |
| H1b | H | false pass | `public_spki()` reads `CKA_PUBLIC_KEY_INFO` *first* ([token/identity.rs](../crates/pkcs11/src/token/identity.rs)). SoftHSM 2.7.0 marks it modifiable (`ck8`) and never checks correspondence ("TODO … we do not calculate it"), though the spec says the token "MUST verify" ([P11Objects.cpp](https://github.com/softhsm/SoftHSMv2/blob/2.7.0/src/lib/P11Objects.cpp), [3.2 §4.10](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)); kryoptic's `C_SetAttributeValue` path is unchecked too ([kryoptic](https://github.com/latchset/kryoptic)). A swapped **RSA** key with a forged SPKI therefore also passes, contradicting REVIEW's "RSA carries the modulus". | code reading |
| S2 | H | false pass | OpenSC serves a private key's RSA modulus from a "friend" public key or certificate ([framework-pkcs15.c](https://github.com/OpenSC/OpenSC/blob/master/src/pkcs11/framework-pkcs15.c)); on firmware without metadata, ykcs11 builds key objects from the slot certificate alone. Both are unbound. | code reading |
| S3 | M | false pass | The spec-digest and mode-downgrade checks sit inside `if let Some(prev)`, so a (spec, token) pair the lock has never recorded verifies on object IDs alone and its policy is never pinned. | code reading, `ops.rs` 287–303 |
| S4 | M | false pass | `publicOnly` is compared only under `--update-lock`; a false→true flip on a spec with no attributes silently drops the check that the private half is present (with attributes, the spec digest catches it). | code reading, `ops.rs` 381–391 |
| S5 | M | false pass | Policy is open-world: only declared booleans are read, and undeclared attributes take token-specific defaults (footnote 9; CloudHSM defaults AES `CKA_SIGN=true` ([AWS](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-attributes-interpreting.html))). Clulow's wrap/decrypt attack makes undeclared WRAP or DECRYPT bits security-relevant ([CHES 2003](https://iacr.org/workshops/ches/ches2003/presentations/CHES%20-%20On%20the%20Security%20of%20PKCS11.pdf)). | code reading + spec |
| S6 | M | false pass | Never checked: the public half of a generated pair (`VERIFY`, `ENCRYPT`, `WRAP`, `TRUSTED`, templates) and certificate policy (`CKA_TRUSTED`, `CKA_CERTIFICATE_CATEGORY`, `CKA_PRIVATE`, refused at validation); non-boolean policy (`CKA_ALLOWED_MECHANISMS`, wrap/unwrap/derive templates) cannot be expressed. | code reading |
| S7 | M | consumer divergence | The URI carries the token *label* but not its `serial`; without a PIN, the uniqueness check runs in a public session that cannot see `CKA_PRIVATE` objects ([3.2 §5.7.7](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)); and OpenSSH picks the first private key with a matching `CKA_ID` ([ssh-pkcs11.c](https://github.com/openssh/openssh-portable/blob/master/ssh-pkcs11.c)), so a consumer may sign with a different key. | code reading |
| S8 | M | misattribution | A realisation does not record its object, and the spec digest hashes only `{v, type, attributes}` ([id.rs](../crates/core/src/id.rs)); retargeting `specs.<s>.object` to another object of the same type gives exit 10, or "first use", instead of exit 14. | code reading |
| S9 | M | misattribution | A locator moved onto different material gives an unexplained exit 10 (moved onto the same material, it correctly passes). | code reading |
| S10 | M | underdefined | `version = 1` names several schemas, and a missing version reads as current, so once v2 exists an unmarked v1 lock would be parsed as v2. | code reading + `git log` |
| S11 | M | underdefined | The compared/provenance split lives in code, not schema; `mechanisms` drives Nix evaluation but is never verified; `module.path` (a `/nix/store` path) and `cakeysVersion` rewrite every touched realisation after a bump. | code reading |
| S12 | L | underdefined | ID, `specDigest` and label strings are not syntax-checked, so a malformed lock fails as exit 10 rather than exit 17. | code reading |
| S13 | L | underdefined | No record of which realisation established which scheme, so the "linked only through a shared scheme" rule (§3.5) cannot be audited from the lock. | code reading |
| S14 | L | underdefined | The certificate type is stored under `keyType`, and a key and its certificate share `pubkeyhash` under two object names with no declared relation or check tying them. | **visible in the shipped lock** |
| S15 | L | underdefined | No scheme-strength or deprecation table, so a future `kcv-ecb` weakness could not be expressed as "insufficient alone". | design |
| S16 | M | operations | Concurrent `--update-lock` runs can lose updates (M3); no GC (D3); no per-section merge rule. | code reading |
| S17 | L | underdefined | Spec-immutable instance attributes (`CKA_LOCAL`, `NEVER_EXTRACTABLE`, `KEY_GEN_MECHANISM`, `UNIQUE_ID`) are not recorded, so replacing an object with the same material (which resets its policy) is invisible. | spec + code reading |

Only H1 is reproduced, and S14 is visible in a committed file; everything else is code reading and needs its own reproduction before it can be called fixed. The cheapest tests to add to `tests/softhsm.rs`, ahead of the fixes as the H1 test was, are a `C_SetAttributeValue(CKA_PUBLIC_KEY_INFO)` on a swapped SoftHSM RSA key followed by verify (H1b), a verify on a second token with no realisation record (S3), a `publicOnly` flip on an attribute-less spec (S4) and a retarget of a spec to another object of the same type (S8). Four further items are not gaps but permanent limits that DESIGN §8 should name as such: secret-key commitments can be replayed by a lying module, exclusivity and export history are unobservable through PKCS#11, p11-kit hides the module behind it (D4), and every first use is trust on first use.

## PKCS#11 3.0–3.2 fits the three levels, with three leaks

The specification has moved under cakeys. Version 3.0 introduced `CKA_UNIQUE_ID`, `CKA_PUBLIC_KEY_INFO`, `CKA_COPYABLE`, `CKA_DESTROYABLE` and `CKO_PROFILE` ([3.0 base](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html)); 3.1 already carries HSS/LMS ([3.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html)); and 3.2, an OASIS Standard since **3 June 2026**, adds `CKO_TRUST`, `CKO_VALIDATION`, `CKA_OBJECT_VALIDATION_FLAGS`, `CKA_PUBLIC_CRC64_VALUE`, the ML-DSA, ML-KEM and SLH-DSA key types with `CKA_PARAMETER_SET`/`CKA_SEED`, and `C_EncapsulateKey`/`C_DecapsulateKey` with matching `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` usage bits ([3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)). The spec's attribute footnotes sort every attribute into a role (1,4,6 without 8 for intrinsic values; 8 for modifiable; 11 and 12 for one-way; 2,4,6 for token-assigned), and each role has a natural home in cakeys' three levels:

| Role | Attributes | cakeys home today | Where it belongs |
|---|---|---|---|
| Intrinsic / material | `CLASS`, `KEY_TYPE`, `CERTIFICATE_TYPE`, `EC_PARAMS`, `MODULUS`, `PUBLIC_EXPONENT`, `VALUE_LEN`, `PARAMETER_SET`, `VALUE` | `objects.<n>.type` + IDs (no `parameterSet`) | same, plus `parameterSet` |
| Mutable policy (fn. 8) | usage bits incl. `SIGN_RECOVER`, `ENCAPSULATE`/`DECAPSULATE` | declared subset of 11 booleans → spec digest | spec (partial allowed) + observed vector in the realisation |
| Set-once policy | `ALLOWED_MECHANISMS`, wrap/unwrap/derive templates, `ALWAYS_AUTHENTICATE`, `TOKEN`, `PRIVATE`/`MODIFIABLE`/`DESTROYABLE` (change only via copy) | mostly inexpressible | typed spec values + observed vector |
| One-way lifecycle | `SENSITIVE`↑, `WRAP_WITH_TRUSTED`↑, `EXTRACTABLE`↓, `COPYABLE`↓, `TRUSTED` (SO only) | `SENSITIVE`/`EXTRACTABLE` only | full set, with the downgrade direction checked |
| Token-assigned instance facts | `LOCAL`, `KEY_GEN_MECHANISM`, `ALWAYS_SENSITIVE`, `NEVER_EXTRACTABLE`, `UNIQUE_ID`, `PUBLIC_CRC64_VALUE`, validation flags | not read | realisation `immutables`, compared, attributed to the module |
| Locator / informational | `LABEL`, `ID`, dates, `SUBJECT`, cert `ISSUER`/`SERIAL_NUMBER` | locator → `uri` | locator compared per realisation |

**Leak 1: the spec gives private keys no public material.** Weierstrass EC, Edwards, ML-DSA, ML-KEM and SLH-DSA private keys carry only `CKA_EC_PARAMS` or `CKA_PARAMETER_SET` and a sensitive `CKA_VALUE`; **there is no `CKA_EC_POINT` on an EC private key in the spec** ([3.2 §6.3.4](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)). The only route is the optional, modifiable `CKA_PUBLIC_KEY_INFO`, whose binding depends on the module honouring its duty to "verify correspondence", which SoftHSM does not; AWS CloudHSM exposes neither attribute on EC private keys ([AWS](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-attributes-interpreting.html)). H1 is therefore a property of the specification, not a SoftHSM quirk, and only a host-verified proof of possession closes it uniformly. ykcs11 illustrates both the second-best source, a public key backed by the device's attestation or metadata, and the worst, a public key synthesized from a certificate that anyone holding the PIV management key can overwrite ([objects.c](https://github.com/Yubico/yubico-piv-tool/blob/yubico-piv-tool-2.7.3/ykcs11/objects.c)).

**Leak 2: policy is open-world, and history attributes are only as honest as the module.** Defaults are "token-specific" (footnote 9) and an undeclared attribute is never read. Reported history is unreliable in practice: ykcs11 hard-codes `ALWAYS_SENSITIVE` and `NEVER_EXTRACTABLE` to TRUE even for imported keys, and tpm2-pkcs11 keeps every PKCS#11 attribute in a host-side SQLite `attrs` column ([db.c](https://github.com/tpm2-software/tpm2-pkcs11/blob/1.10.1/src/lib/db.c)). These attributes must be locked as *observed instance facts attributed to a module*, never as proof of origin.

**Leak 3: locators are conventions that consumers resolve differently.** "Cryptoki does not enforce" that a key pair and its certificate share `CKA_ID` ([3.2 §4.8.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)); RFC 7512 treats missing URI attributes as wildcards, and `token=` is a user-set label ([RFC 7512](https://datatracker.ietf.org/doc/html/rfc7512)); OpenSSH resolves by `CKA_ID` and takes the first match; and a public session hides private duplicates. The emitted URI should therefore carry `serial=` and always `type=`, the lock should record which session kind performed the uniqueness check, and a logged-in check should refuse a second private key under the consumer-visible `CKA_ID`.

`CKA_UNIQUE_ID` will not rescue identity. It is token-generated and may be reused after `C_InitToken` ([3.2 §4.4.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)); among the modules read, **only kryoptic populates it**, with a random UUIDv4 ([kryoptic object/mod.rs](https://github.com/latchset/kryoptic/blob/v1.5.3/src/object/mod.rs)); and Securosys Primus does not support it ([Securosys](https://docs.securosys.com/pkcs/Concepts/identifiers)). Its only use is as a per-realisation tripwire for replace-in-place. Likewise, `CKA_CHECK_VALUE` could serve D5's unwrap-only AES keys as an opt-in `kcv3` mode, but it is 24 bits and token-asserted, and because `SHA-256(KCV)` can be reversed with about 2^24 guesses, such a mode breaks DESIGN §8.1's "never token outputs" invariant in substance and must say so.

## TPM 2.0 already ships a content address, and it is an instance ID

A TPM object's **Name** is `nameAlg ‖ H_nameAlg(TPMT_PUBLIC)`, which hashes `type`, `nameAlg`, every `TPMA_OBJECT` bit, `authPolicy`, the parameters and `unique` ([Part 2 §12.2.4](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_2_Structures_Version_185_pub_c0a962a931.pdf)). The `unique` field is the modulus for RSA, the public point for ECC, the public key for ML-DSA and ML-KEM, and a salted hash `H(seedValue ‖ key)` for symmetric and keyedHash objects ([Part 1 §24.5.3](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_1_Architecture_Version_185_pub_2a3392dc49.pdf)). The Name excludes the parent, hierarchy, handle, authValue and private blob; ancestry lives in the **Qualified Name**, `QN_B = H(QN_parent ‖ Name_B)`; and "the state of the attributes is determined when the object is created and they are never changed by the TPM". The Name is therefore exactly what PLAN calls an *instance* CA-ID, spec plus material, not an object ID: the same key under two policies has two Names and one `pubkeyhash`, and a duplicate imported under another parent keeps its Name while its QN and blob change.

Library revision **185** (March 2026) adds ML-KEM and ML-DSA ([TCG](https://trustedcomputinggroup.org/new-computing-specification-implements-pqc-measures-to-protect-users-from-quantum-attacks/)) and support for persisting **public-only** objects (Part 1 §34.3). The latter is the TPM form of H1: a persistent handle can return the right Name from `TPM2_ReadPublic` with no private key behind it. The TPM offers stronger countermeasures than PKCS#11. A private blob cannot load with a foreign public area, because its integrity HMAC covers the Name ([TCG reference Load.c](https://android.googlesource.com/platform/external/tpm2/+/5c18d72/Load.c)); a session salted to the locked parent's public area proves the parent's private key is present; and `TPM2_Certify` with a host nonce and an Attestation Key chained to the Endorsement Key attests the full public area, residence and freshness ([tpm2_certify](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_certify.1/)).

Primary keys are derivations. `TPM2_CreatePrimary` regenerates the same key from the hierarchy seed and "all of the bits of the template", but only within one seed epoch, which `TPM2_Clear` or `ChangeEPS` ends, and only while the derivation is unchanged, which a field upgrade can break, as the KDFa-to-DRBG switch at 1.38 did (Part 1 §11.4.1). A lock entry for a primary must therefore be per TPM, and when the output and a standard-template "seed fingerprint" change together, verify should report "seed or firmware changed" rather than a bare mismatch. Policies are content-addressed by construction: raw `PolicyPCR` digests churn on every boot-chain update, while `PolicyAuthorize` (signer Name plus policyRef) and `PolicyAuthorizeNV` (the NV index Name) keep `authPolicy`, and hence the object's Name, stable ([Part 3 §23.16, §23.22](https://medias.cdn.trustedcomputinggroup.org/production/Trusted_Platform_Module_2_0_Library_Part_3_Commands_Version_185_pub_87a5c10230.pdf)). That is why systemd-pcrlock writes its prediction to an NV index, and its `pcrlock.json` is in effect a lock file for the policy ([systemd-pcrlock](https://www.freedesktop.org/software/systemd/man/latest/systemd-pcrlock.html)).

Typical TPM usage already contains the pieces a cakeys realisation needs, but none of it checks the object's own Name before use. The dominant pattern is a well-known storage root key at persistent handle **0x81000001**, fixed by the FAPI profile ([fapi-profile.md](https://github.com/tpm2-software/tpm2-tss/blob/master/doc/fapi-profile.md)) and used by systemd-cryptenroll, with ordinary child keys kept outside the TPM as blobs. The TSS2 `TPMKey` file (loadable, importable or sealed, whose parent "SHOULD be" a persistent or permanent handle) is the interoperable on-disk form used by ssh-tpm-agent ([TPM 2 key format draft](https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html)). systemd's LUKS2 token JSON records `tpm2-blob`, `tpm2-pcrs`, `tpm2-pcr-bank`, `tpm2-policy-hash`, the pcrlock NV index and `tpm2_srk`, a serialized handle that pins the parent ([tpm2-util.c](https://github.com/systemd/systemd/blob/main/src/shared/tpm2-util.c)). In cakeys terms, the persistent handle or key-file path is the locator, the storage root key's Name belongs in the realisation's `location`, and the recorded policy hash is the spec's `authPolicy`. A native backend can therefore adopt keys created by these tools without inventing a new on-disk format.

**tpm2-pkcs11 is lossy.** It maps only `CKA_EXTRACTABLE ↔ !(fixedTPM|fixedParent)` and `CKA_LOCAL ↔ sensitiveDataOrigin`, and lists policy as future work ([tpm.c](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/src/lib/tpm.c), [ARCHITECTURE.md](https://github.com/tpm2-software/tpm2-pkcs11/blob/master/docs/ARCHITECTURE.md)), losing `authPolicy`, `nameAlg`, `userWithAuth`/`adminWithPolicy`, `noDA`, `restricted`, the Name and QN, and attestation. Declaring or verifying any of those needs a native backend, mapped as follows:

| TPM field | Class | cakeys home |
|---|---|---|
| `type`, keyBits/curve, symmetric size | intrinsic | `objects.<n>.type`, with a frozen `TPM_ALG_*` ↔ `CKK_*` table |
| `unique` | material identity | `objects.<n>.ids.pubkeyhash` (SPKI built from `unique`, exponent 0 → 65537), portable to PKCS#11 |
| `nameAlg`, every TPMA bit, scheme, `authPolicy` | policy | spec; digest input is the marshaled template with empty `unique`, canonical per Part 1 §13 |
| Name | instance identity | `realisations.*.ids."tpm2-name"`, recomputed on the host from the stored `TPM2B_PUBLIC` |
| hierarchy, parent Name, QN, handle or TSS2 key file | location | realisation `location`, compared; a parent change with an equal Name is a *move* (note) |
| `TPM2B_PRIVATE` | opaque locator payload | never identity; at most a cache-hint digest |
| authValue | secret | never in the lock |
| creation ticket, `TPM2_Certify`, EK cert, AK public | attestation | realisation `attestation` |
| manufacturer, firmware, `TPM_PT_REVISION` | provenance | realisation provenance, warn only |
| policy definition | its own entity | `[policies.<n>]` with a host-recomputed digest; NV indexes as `[nv.<n>]`, pinned in their WRITTEN steady state |

Two decisions follow from this mapping. The spec digest for TPM specs should take the TPM's own canonical template marshaling, wrapped in the v2 JSON envelope, which reuses an encoding the TPM spec already makes canonical instead of re-encoding TPM fields as JSON. And because `nameAlg` may be SHA-384, SHA-512, SM3 or SHA3 while DESIGN §10 freezes IDs as `sha256-<base64>`, the SRI rule must be relaxed for `tpm2-name` to `sha256`, `sha384` or `sha512` with a frozen `TPM_ALG_ID` mapping, refusing algorithms SRI cannot name. For symmetric objects created inside a TPM the Name is random per object, so portable identity must keep using the existing commitments, preferably `TPM2_HMAC`, because ECB-mode `TPM2_EncryptDecrypt` and `TPM2_MAC` are optional in TPM profiles.

## Fourteen changes, ordered by what they stop

The changes bundle every change to the spec-digest shape, including L2's curve-alias canonicalization, into **one v2 bump**.

| Pri | Change | Closes | Schema delta |
|---|---|---|---|
| P0-1 | **Fresh PoP for every private key** on `realise`, `adopt` and `verify`, recorded as `binding` and folded into the mode order so a downgrade is exit 14 | H1, H1b, S2 | `binding` per realisation |
| P0-2 | **SPKI source order:** RSA `MODULUS`/`PUBLIC_EXPONENT` or the public object's `EC_POINT` first; `CKA_PUBLIC_KEY_INFO` only as a cross-check that must agree. This also covers standalone public keys, which PoP cannot. | H1b | none |
| P0-3 | **Require a realisation record** for verify/check: exit 14 "not realised on this token" when the object has IDs but the pair has none; objects without IDs keep the first-use exit 10 | S3 | none |
| P0-4 | **Compare `object`, `locator` and `publicOnly`** per realisation; a change is exit 14 "keys.toml changed", re-recorded with `--update-lock` | S4, S8, S9 | `object`, `locator` |
| P1-5 | **Freeze the version:** `version` required with no default; the current shape declared v1 and frozen; readers refuse an unknown major; writers keep the version they found and upgrade only on request | S10 | `version` required |
| P1-6 | **Split tables:** compared fields at the top level, `observed` (cached `mechanisms`, feeds Nix eval, never compared) and `provenance` (disposable: deleting it changes no verdict); drop `module.path`; provenance-only differences never trigger a rewrite | S11 | three sub-tables |
| P1-7 | **Observed policy vector and spec-immutables:** every applicable boolean the module answers, plus `LOCAL`/`NEVER_EXTRACTABLE`/`ALWAYS_SENSITIVE`/`KEY_GEN_MECHANISM`; drift is exit 14, with module attribution | S5, S17 | `policy`, `immutables` |
| P1-8 | **Validation and audit:** SRI and label syntax at load (exit 17); per-realisation `schemes`; a per-(scheme, class) uniqueness invariant; a checked `pairs` relation; a `certificateType` field | S12, S13, S14 | several fields |
| P1-9 | **URI and session:** emit `serial=` and always `type=`; record `session = "public"\|"user"`; when logged in, refuse a second private key under the same `CKA_ID` | S7 | `session` |
| P2-10 | **Typed policy:** `ALLOWED_MECHANISMS`, templates, the missing booleans, certificate and public-half policy; spec digest v2 | S6, L2 | spec digest v2 |
| P2-11 | **Attestation records:** YubiKey PIV verified to the pinned Yubico root (not slot f9), `TPM2_Certify` with an EK-chained AK, vendor blobs; `binding = "attested"` replaces PoP only by opt-in | origin facet | `attestation` |
| P2-12 | **Native TPM:** the mapping above, `tpm2-name` with nameAlg-tagged SRI, `[policies]`, `[nv]`, `seedFingerprint` | TPM policy | new tables |
| P2-13 | **PQ readiness:** `parameterSet` in `type`; `pop-kem` via `C_DecapsulateKey`; a PQ `pubkeyhash` frozen only after the SPKI OIDs are pinned | PQ | `parameterSet` |
| P3-14 | **Operations:** `flock` around read-modify-write, a `gc` verb (print, then `--apply`), per-section merge rules, a frozen scheme-strength table, standard KCVs only as non-identity hints | S15, S16 | none |

### Proof of possession must be fresh, domain-separated and never stored

The challenge must be **fresh on every verify**. A stored proof such as a CSR-style self-signature proves possession only once, and a module can replay it ([RFC 2986 §4.2](https://www.rfc-editor.org/rfc/rfc2986#section-4.2)), so the lock records only the *required binding level*, never a signature. Signing keys sign `"cakeys/pop/v1" ‖ objectName ‖ SHA-256(SPKI) ‖ 32-byte nonce` with hashing mechanisms only (`CKM_ECDSA_SHA256/384/512`, `CKM_SHA256_RSA_PKCS_PSS`, pure `CKM_EDDSA`), never raw `CKM_ECDSA` or `CKM_RSA_X_509`, following RFC 4211's warning never to "sign a completely random value" ([RFC 4211 §4.2.3](https://www.rfc-editor.org/rfc/rfc4211#section-4.2.3)); the host verifies with RustCrypto, which needs the `ecdsa` feature on `k256`/`bp256`/`bp384`, while Ed448 needs a verifier crate or an opt-in. Derive-only EC keys use RFC 6955-style static-ephemeral ECDH ([RFC 6955](https://www.rfc-editor.org/rfc/rfc6955)): the host computes `e·Q_locked`, the token derives `d·(e·G)`, and the two are compared through an extractable session secret or an HMAC under the derived key. RSA decrypt-only keys decrypt an OAEP challenge, and ML-KEM keys decapsulate, as in RFC 9810's direct KEM proof of possession ([RFC 9810 §4.3.4](https://www.rfc-editor.org/rfc/rfc9810#section-4.3.4)). The method is chosen from the spec's *declared* usage bits and the token's mechanisms, mirroring §3.1, and the resulting binding levels rank as follows:

| Rank | Binding | Requires |
|---|---|---|
| 1 | `pop-*` + nonce-bound attestation | — |
| 2 | `pop-*` | — |
| 3 | `attested` | opt-in to replace PoP |
| 4 | `self` (module derives the public key from private data) | — |
| 5 | `token-asserted` | explicit per-token opt-in, recorded |
| 6 | `none` | explicit per-token opt-in, recorded |

The YubiKey example's `publicOnly` keys belong at rank 5.

### Versioning, per-realisation records and the policy world

Prior art is unanimous that a lock should **version the schema, not the tool** ([Nesbitt](https://nesbitt.io/2026/01/17/lockfile-format-design-and-tradeoffs.html)), and PEP 751 makes the major/minor split decide between refusal and warning, with an unknown major that "MUST raise an error". For cakeys that translates into one rule per section: unknown content in compared sections is refused, unknown schemes in `ids` are warned about and never count as proof (as today), and unknown keys in `provenance` are preserved and warned about, as TUF requires for re-serialization ([TUF](https://theupdateframework.github.io/specification/latest/)).

For policy, the recommendation is a closed-world *lock* over a partial *spec*. The spec may stay partial, so existing specs keep working, and the lock pins the full observed vector, so drift in an undeclared attribute becomes "lock out of date" (exit 14) instead of a silent token default. The alternative, requiring every applicable attribute in `keys.toml`, is more declarative but forces users to restate token defaults and breaks every existing spec; it fits better as an optional `validate --strict`.

Instance facts belong per realisation, because the same AES key is `LOCAL=true` on the token that generated it and `LOCAL=false` after unwrapping elsewhere. A v2 sketch, using the shipped YubiKey example:

```toml
version = 2                                    # required; no default

[objects.whonix-db]
type  = { class = "CKO_PRIVATE_KEY", keyType = "CKK_RSA", modulusBits = 2048 }
ids   = { pubkeyhash = "sha256-…" }
pairs = ["whonix-db-cert"]                     # equal pubkeyhash required, checked

[objects.whonix-db-cert]
type = { class = "CKO_CERTIFICATE", certificateType = "CKC_X_509" }
ids  = { certhash = "sha256-…", pubkeyhash = "sha256-…" }

[realisations.whonix-db-piv.yubikey]           # compared: any difference is exit 14 unless --update-lock
object      = "whonix-db"
specDigest  = "sha256-…"                       # v2 digest
locator     = { CKA_ID = "07" }
publicOnly  = true
mode        = "direct"
binding     = "token-asserted"                 # opt-in; PoP would need PIN and touch
schemes     = ["pubkeyhash"]
session     = "public"
policy      = { CKA_VERIFY = true, CKA_MODIFIABLE = false }   # publicOnly: full vector of the public object; the private half is unobserved
# immutables = { CKA_LOCAL = …, CKA_NEVER_EXTRACTABLE = … }   # only with a user session; module-attributed
uri         = "pkcs11:token=…;serial=39189318;id=%07;type=private"

[realisations.whonix-db-piv.yubikey.observed]  # cached observation: feeds Nix eval, never compared
mechanisms = ["CKM_RSA_PKCS", "…"]

[realisations.whonix-db-piv.yubikey.provenance]  # disposable: deleting it changes no verdict
provider = "ykcs11"; cakeysVersion = "0.2.0"
module = { description = "PKCS#11 PIV Library (SP-800-73)", manufacturer = "Yubico (www.yubico.com)", version = "2.73", cryptoki = "3.0" }
token  = { model = "YubiKey YK5", serial = "39189318", firmware = "5.74" }
# attestation = { kind = "yubico-piv", sha256 = "sha256-…", root = "sha256-…", origin = "generated", pinPolicy = "…", touchPolicy = "…" }
```

### Post-quantum keys need a parameter set and a pinned SPKI wrapping

A PKCS#11 3.2 ML-DSA public key is a raw FIPS 204 `CKA_VALUE`, not an SPKI, and its parameter set is a separate attribute ([3.2 §6.67](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)); vendors already deviate, with CloudHSM using its own `CKA_CLOUDHSM_PARAMETER_SET` and not supporting ML-DSA import ([AWS](https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-attributes-interpreting.html)). A PQ `pubkeyhash` should wrap the raw value into an SPKI, so that a key's ID equals its certificate's as the `pairs` relation requires, frozen by a known-answer test only after the algorithm OIDs are pinned from the final IETF documents, which this research did not verify. Until then PQ keys should be refused clearly, as brainpoolP512r1 is today. The outer SRI hash stays frozen; any future agility comes from new scheme names, not from redefining existing ones. On the TPM side, revision 185 already puts the ML-DSA or ML-KEM public key in `unique`, so the same wrapping makes PQ `pubkeyhash` portable between PKCS#11 and a native TPM backend.

## Conclusion

The central result is a reframing. A cakeys lock is already an excellent **fixed-output declaration for material**, but not yet a **lock for state**, because "complete" is not one property but a ladder of evidence classes, and the token-asserted rungs (policy, origin flags, secret-key commitments) can only be pinned and re-observed, never proven. That changes what the user's requirement can mean: proving that "something else in the change caused the hash break" is achievable, but only for the fields the schema assigns to the compared class. The most valuable change is therefore not a new cryptographic scheme but a schema in which every field declares its class, the version means exactly one thing, and an absent record fails instead of passing.

Two non-obvious consequences follow. H1 is not a SoftHSM bug to special-case: it follows from a PKCS#11 object model that gives EC, Edwards and PQ private keys no public material, and it recurs in TPM revision 185 as public-only persistence, so a fresh, host-verified proof of possession belongs in the identity definition, not in a test. And the TPM Name and PKCS#11 `CKA_UNIQUE_ID` together show that the lock needs **two identity tiers**, portable material IDs in `objects` and instance IDs in `realisations`; with only one tier, a replaced object or a policy reset hides behind an unchanged hash.
