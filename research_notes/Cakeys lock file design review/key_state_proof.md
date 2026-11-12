# Proving the state of a PKCS#11 / TPM key: binding, possession, attestation, immutability

Scope: what a host such as cakeys can prove about a key or object held in a PKCS#11 token or TPM, and how. The goal is to decide whether a `keys.toml` + `keys.lock` pair can be shown to describe that key's state completely, and how to close H1.

Status as of 2026-11-11. Code citations come from sources read locally:
- SoftHSM 2.7.0, OpenSC 0.27.1, yubico-piv-tool 2.7.3 and kryoptic 1.5.x: the current nixpkgs `src`.
- tpm2-pkcs11: the local checkout `~/srcs/tpm2-pkcs11` on branch `jhoffer_fix_p521_point`, head `4c3c5b1`. It carries an unmerged P-521 DER patch, so its behaviour may differ from upstream.

Evidence tags used below:
- **[crypto]**: the host checks it with its own cryptography.
- **[attested]**: a vendor or TPM signs it, and the host verifies the signature chain.
- **[token-asserted]**: the PKCS#11 module reports it, and the host must trust the module.
- **[unobservable]**: nothing the host can query reveals it.

## Proof of possession and binding the public key to the private key

### Takeaway
H1 is broader than "SoftHSM EC private keys". Reading the public key from a private-key handle is token-asserted. By code reading (not yet reproduced), it can be decoupled from the private material in four of the five open-source modules read:
- **OpenSC** serves RSA `CKA_MODULUS` on a private key from a "friend" public key or certificate.
- **ykcs11** serves a private key's `CKA_EC_POINT` and modulus from the slot's attestation, metadata or certificate.
- **SoftHSM** and **kryoptic** let a user with an R/W session *set* `CKA_PUBLIC_KEY_INFO` on a private key. They accept it unchecked on any object with `CKA_MODIFIABLE=TRUE`, which is the default. cakeys reads that attribute first.

The only token-independent binding is a fresh proof of possession (PoP), checked on the host against the locked SPKI:
- **Signing keys:** sign a challenge.
- **Derive-only EC keys:** ECDH with an ephemeral host key.
- **RSA decrypt-only keys:** decrypt a challenge.
- **ML-KEM keys:** decapsulate.

### Cited Findings
**What the PKCS#11 specification requires**
- `CKA_PUBLIC_KEY_INFO` on a private key is "DER-encoding of the SubjectPublicKeyInfo for the associated public key (MAY be empty; DEFAULT derived from the underlying private key data; MAY be manually set for specific key types; if set; MUST be consistent with the underlying private key data)". It carries footnote 8, so it is modifiable via `C_SetAttributeValue`/`C_CopyObject`. — [PKCS#11 v3.2 §4.10, Table "Private key object attributes"](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- If `CKA_PUBLIC_KEY_INFO` is supplied to `C_CreateObject`, `C_CopyObject` or `C_SetAttributeValue` for a private key:
  - "the token MUST verify correspondence between the private key data and the public key data … either by deriving a public key from the private key and comparing the values, or by doing a sign and verify operation. If there is a mismatch, the command SHALL return CKR_ATTRIBUTE_VALUE_INVALID."
  - A token "MAY choose not to support" the attribute on creation, and then returns `CKR_ATTRIBUTE_TYPE_INVALID`.
  - "private keys of any type SHOULD store sufficient information to retrieve the public key information."
  - [PKCS#11 v3.2 §4.10](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- Private keys are not tied to their certificate or public key by the spec: "It is intended in the interests of interoperability that the subject name and key identifier for a private key will be the same as those for the corresponding certificate and public key. However, this is not enforced by Cryptoki". The spec also does not enforce that a certificate's `CKA_PUBLIC_KEY_INFO` matches the certificate. — [PKCS#11 v3.2 §4.6.2, §4.10](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)

**SoftHSM 2.7.0**
- The private-key object declares `CKA_PUBLIC_KEY_INFO` with check flag `ck8` (modifiable after creation) and the comment "TODO: CKA_PUBLIC_KEY_INFO is accepted, but we do not calculate it". Its default is the empty string, and no correspondence check exists. This is a spec violation, found by code reading and not yet reproduced. — [SoftHSMv2 `src/lib/P11Objects.cpp`:1069–1070, `P11Attributes.cpp` `P11AttrPublicKeyInfo::setDefault`](https://github.com/softhsm/SoftHSMv2/blob/develop/src/lib/P11Objects.cpp)

**kryoptic 1.5.x**
- Computes `CKA_PUBLIC_KEY_INFO` for private EC keys on import, from the private value (`extract_public_key`).
- If the template supplies a different value, `Object::ensure_bytes` returns `CKR_ATTRIBUTE_VALUE_INVALID`.
- On generation, the public key's SPKI is copied to the private key.
- Tests assert that the public and private `CKA_PUBLIC_KEY_INFO` are equal for RSA, ML-KEM, ML-DSA and SLH-DSA.
- Caveat in its own code: on OpenSSL older than 4.0 an unextractable key may leave the value unset (`CKR_KEY_UNEXTRACTABLE` is tolerated).
- **But the set path is unchecked.**
  - On private (and public) keys, `CKA_PUBLIC_KEY_INFO` is declared with `OAFlags::empty()`: not `NeverSettable`, not `Unchangeable`.
  - The generic `set_object_attributes` only checks `is_modifiable()` and those flags, then calls `obj.set_attr(...)`. No factory overrides it.
  - So `C_SetAttributeValue(CKA_PUBLIC_KEY_INFO)` on a modifiable private key is accepted without the correspondence check the spec requires. This is from code reading.
- [kryoptic `src/ec/ecdsa.rs`:42–72, 265–312, 448–452; `src/object/mod.rs`:379–393; `src/object/key.rs`:253, 318; `src/object/factory.rs`:483–537; `src/tests/{rsa,mlkem,mldsa,slhdsa}.rs`](https://github.com/latchset/kryoptic)

**OpenSC 0.27.1**
- `pkcs15_prkey_get_attribute` answers `CKA_MODULUS`, `CKA_PUBLIC_EXPONENT` and `CKA_EC_PARAMS` on a private key from `prkey->pub_data`. Otherwise it searches for a "friend certificate's public key" or a "friend public key" with the same PKCS#15 ID.
- Its comment says CKA_MODULUS for private keys "is not generally available from a smart card".
- No `CKA_EC_POINT` is served on private EC keys.
- [OpenSC `src/pkcs11/framework-pkcs15.c` `pkcs15_prkey_get_attribute` (line 4076ff)](https://github.com/OpenSC/OpenSC/blob/master/src/pkcs11/framework-pkcs15.c)

**ykcs11 (yubico-piv-tool 2.7.3)**
- A private key's `CKA_EC_POINT` and `CKA_MODULUS` come from `s->pkeys[sub_id]` (`get_proa`, objects.c:710–719).
- At session init that slot is filled from three sources, in order:
  1. The public key in a freshly created attestation certificate, but only for keys generated on the device.
  2. Else from `GET METADATA` (`md.pubkey`), on firmware that supports it.
  3. Else from the certificate stored in the slot (`store_cert(...)`, "Will only overwrite key if not set from attestation or metadata").
- [yubico-piv-tool `ykcs11/ykcs11.c`:980–1063, `ykcs11/objects.c`:546–843](https://github.com/Yubico/yubico-piv-tool)

**tpm2-pkcs11**
- Computes `CKA_EC_POINT` from the TPM public area at create/import (`tpm.c`:3595–3630). Private EC objects are required to carry it (`attrs.c`:914).
- At run time, however, object attributes are parsed from the sqlite `attrs` column (`db.c`:149–172), not re-derived from the TPM public blob.
- [tpm2-pkcs11 `src/lib/{tpm.c,attrs.c,db.c}`](https://github.com/tpm2-software/tpm2-pkcs11), local checkout.

**PoP in the PKI standards**
- RFC 4211 (CRMF) on why PoP exists: without it, "one cannot truly know if the binding of the public key and the identity in the certificate is actually correct". It notes "there can be hardware limitations on what POP methods may be usable, e.g., if the private key is maintained in a hardware token". — [RFC 4211 §4](https://www.rfc-editor.org/rfc/rfc4211#section-4)
- RFC 4211 defines PoP per key type:
  - signature (`POPOSigningKey`);
  - key encipherment and key agreement (`POPOPrivKey`: `subsequentMessage`, `agreeMAC`, `encryptedKey`).
  - `thisMessage` and `dhMAC` are deprecated.
  - [RFC 4211 §4.1–4.2](https://www.rfc-editor.org/rfc/rfc4211#section-4.1)
- RFC 4211 §4.2.3 guidance for challenge-response PoP:
  - the response "MUST NOT be just the hash of the encrypted value, as one should never 'sign' a completely random value";
  - include identity information in the hash;
  - require transaction identifiers and nonces.
  - [RFC 4211 §4.2.3](https://www.rfc-editor.org/rfc/rfc4211#section-4.2.3)
- RFC 6955 defines PoP for Diffie-Hellman and EC key-agreement keys: "two methods for producing an integrity check value from a Diffie-Hellman key pair and one method for producing an integrity check value from an Elliptic Curve key pair … designed to provide a Proof-of-Possession of the private key and not to be a general purpose signing algorithm". The MAC key comes from static-static DH with a recipient key. — [RFC 6955](https://www.rfc-editor.org/rfc/rfc6955)
- RFC 9810 (CMP v3, obsoletes RFC 4210) adds KEM-key PoP (§4.3.4):
  - **Direct:** the CA issues a random challenge to decrypt.
  - **Indirect:** the certificate is encrypted under a secret derived from a KEM encapsulation to the public key, and the end entity returns a hash of the decrypted certificate. The RFC encourages the indirect method.
  - [RFC 9810 §4.3.4](https://www.rfc-editor.org/rfc/rfc9810#section-4.3.4)
- **CSR self-signature (RFC 2986).** "The value of the certificationRequestInfo component is DER encoded … The result of step 1 is signed with the certification request subject's private key". The signature covers only the request content: subject, SPKI and attributes. It has no verifier nonce, so it proves possession *at signing time* and can be replayed indefinitely. — [RFC 2986 §4.2](https://www.rfc-editor.org/rfc/rfc2986#section-4.2)
- PKCS#11 3.2 adds `C_EncapsulateKey`/`C_DecapsulateKey` (§5.18.8–9), the `CKF_ENCAPSULATE`/`CKF_DECAPSULATE` mechanism flags and `CKA_ENCAPSULATE`/`CKA_DECAPSULATE` key attributes. These make a token-side decapsulation PoP expressible in the API. — [PKCS#11 v3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)

**cakeys today**
- `spki()` tries the object's own `CKA_PUBLIC_KEY_INFO` first, then the RSA modulus/exponent or EC params/point, then "the single public-key object under the same locator". — `crates/pkcs11/src/token.rs`:380–425 (local); `docs/DESIGN.md` §3.2
- Certificates and standalone public keys take different paths:
  - **Certificates:** `pubkeyhash` is derived from the parsed `CKA_VALUE` (`id::cert_spki`). It is not taken from the certificate's `CKA_PUBLIC_KEY_INFO`, so it is safe.
  - **Standalone public-key objects:** these go through `spki()` → `public_spki()`, so `CKA_PUBLIC_KEY_INFO` wins over `CKA_EC_POINT`/modulus.
  - — `crates/pkcs11/src/token.rs`:340–357 (local)
- SoftHSM accepts `CKA_PUBLIC_KEY_INFO` on public-key and certificate objects at creation with check flags `0`, uncalculated. — [SoftHSMv2 `src/lib/P11Objects.cpp`:422–423, 699–700](https://github.com/softhsm/SoftHSMv2/blob/develop/src/lib/P11Objects.cpp)
  - This means it can be supplied on `C_CreateObject` but is not modifiable afterwards.
  - It also means a public-key object can be created whose `CKA_PUBLIC_KEY_INFO` names key B while its `CKA_EC_POINT` (which the token uses for `C_Verify`) is key A.
- The crypto crates in the workspace:
  - `p256`/`p384`/`p521` are enabled with the `ecdsa` feature;
  - `k256`, `bp256` and `bp384` only with `arithmetic`;
  - `ed25519-dalek` 3, `ed448` 0.5 and `rsa` 0.10 are also present.
  - `Cargo.toml`:22–31 (local)

### Inferences
**H1 is wider than SoftHSM EC**
- **SoftHSM and kryoptic, any key type.** An attacker with an R/W user session can swap the material, then `C_SetAttributeValue(CKA_PUBLIC_KEY_INFO = <old SPKI>)` on the new private key, which is `CKA_MODIFIABLE=TRUE` by default. cakeys takes step 1 and accepts it, so this works for RSA too. This is from code reading only; reproduce it before claiming it.
- **Standalone public-key objects.** Their `pubkeyhash` can disagree with the key the token actually verifies with, if `CKA_PUBLIC_KEY_INFO` and `CKA_EC_POINT`/modulus differ (SoftHSM, at creation).
  - PoP does not cover this: there is no private half.
  - Fix: when an object exposes both, decode both and fail on disagreement. Otherwise prefer the type-specific attribute, `CKA_EC_POINT` or modulus, over `CKA_PUBLIC_KEY_INFO`.
  - Apply the same cross-check to private objects that expose both.
- **Certificates are not affected.** cakeys already derives their SPKI from the DER.
- **OpenSC cards.** The RSA private modulus is reproduced from a friend public object or certificate. EC private keys fall through to cakeys' step 3. Both are unbound.
- **ykcs11.**
  - Generated keys: bound by the device, via attestation or metadata.
  - Imported keys: bound on firmware with metadata. Otherwise bound only to whatever certificate sits in the slot.
- **tpm2-pkcs11.** Bound at creation. But anyone who can write the sqlite store can pair a different TPM key blob with the old `attrs`, and the TPM will load any blob that is valid under the parent.

**Consequences for the identity scheme**
- "Public key read from the private handle" is token-asserted. It is a crypto binding only for modules that derive it from the private material on each read, as kryoptic does on import and as RSA keys do where the modulus is intrinsic.
- The only uniform fix is a host-verified PoP for every private-key object, run against the SPKI the lock pins. Run it whatever step produced the SPKI.

**PoP recipe: signing keys**
- Sign `DST ‖ object-name ‖ SHA-256(SPKI) ‖ 32-byte host nonce`, with:
  - `DST` a fixed domain-separation tag, such as `"cakeys/pop/v1"`;
  - a hashing mechanism: `CKM_ECDSA_SHA256/384/512` (choose by curve), `CKM_SHA256_RSA_PKCS_PSS` or `CKM_SHA256_RSA_PKCS`, or `CKM_EDDSA` (pure).
- Avoid raw `CKM_ECDSA` and `CKM_RSA_X_509` over host-chosen bytes. This follows RFC 4211 §4.2.3's "never sign a completely random value".
- Verify the signature on the host with RustCrypto. To do so, enable `ecdsa` on `bp256`, `bp384` and `k256`.
- Ed448 has no verifier in the current stack, so it needs another crate or an opt-in.

**PoP recipe: derive-only EC (RFC 6955-style static-ephemeral)**
1. The host makes an ephemeral `e` and computes `Z_h = e·Q_locked`.
2. The token runs `C_DeriveKey(CKM_ECDH1_DERIVE, pub = e·G)` and gets `Z_t = d·(e·G)`.
3. `Q_locked` must be a valid point on the curve. RustCrypto's SEC1/SPKI decoding already ensures this. `e·G` is the host's own point and needs no validation.
4. Compare `Z_h` with `Z_t`, either:
   - by deriving `Z_t` as an extractable, non-sensitive session generic secret and reading it; or
   - if the token forbids that, by deriving it as a session HMAC key and comparing `HMAC(Z_t, nonce)` with the host's `HMAC(Z_h, nonce)`.
5. The session key is destroyed afterwards. Equality proves `d·G = Q_locked`, because `e` is fresh and random.

**PoP recipe: RSA decrypt-only**
- The host encrypts a random 32-byte value under the locked public key, with OAEP-SHA256 (preferred) or PKCS#1 v1.5.
- The token decrypts, and the host compares.
- Prefer OAEP so the check is not a padding oracle.

**PoP recipe: ML-KEM**
- The host encapsulates to the locked public key, and the token `C_DecapsulateKey` → session secret.
- Compare as in the ECDH recipe (extractable session secret, or HMAC with it). This is RFC 9810's "direct" KEM PoP, done locally.

**Why the nonce matters**
- A stored proof, such as a CSR-style signature recorded in the lock, would only prove possession once (RFC 2986 semantics) and could be replayed by a module.
- So the PoP challenge must be generated fresh at each `verify`, and is never stored as evidence.
- The lock records only that a PoP of a given kind is *required* (the binding level).

**Keys that allow none of these**
- Examples: a wrap-only RSA key, or an EC key with every usage bit false.
- These cannot be bound through PKCS#11. Treat them as `publicOnly`-style trust (an explicit opt-in, recorded), or as attested (next section).

**Operational cost**
- PIV keys with PIN policy "always" (`CKA_ALWAYS_AUTHENTICATE`) need a context-specific login per PoP.
- Keys with touch policy "always" need a physical touch on every `verify`.
- For generated PIV keys, a verified attestation chain is a touch-free alternative (next section).
- PoP is still the only fresh evidence.

### Gaps
- The SoftHSM and kryoptic `C_SetAttributeValue(CKA_PUBLIC_KEY_INFO)` swap is from code reading only. It is not reproduced in cakeys' test VM.
- I did not check whether `C_CreateObject` with a mismatching `CKA_PUBLIC_KEY_INFO` is also accepted. The code suggests yes.
- Not read: Thales Luna, nShield, AWS CloudHSM or Google PKCS#11 behaviour for `CKA_PUBLIC_KEY_INFO` / `CKA_EC_POINT` on private objects.
- I did not verify whether `bp256`/`bp384` 0.14 offer an `ecdsa` feature (likely, by RustCrypto convention, but unconfirmed).
- Whether kryoptic, SoftHSM and tpm2-pkcs11 permit an extractable ECDH-derived session key, or HMAC-with-derived-key, in practice was not tested.

## Attestation of key generation and attributes

### Takeaway
Attestation proves *provenance*: generated inside a specific device, under a given policy. It is checkable offline against a vendor or TPM root. But most schemes carry no verifier nonce, so they prove nothing about *current* residence or liveness. TPM2_Certify with `qualifyingData` is the exception: it attests a full public area, attributes included, and is freshness-bound.

Coverage across cakeys' token types:
- **YubiKey PIV (ykcs11), YubiKey OpenPGP, native TPM:** usable attestation.
- **Network HSMs (Luna, nShield, Google Cloud HSM):** vendor attestation exists, outside PKCS#11.
- **tpm2-pkcs11:** no attestation exposed through its PKCS#11 interface, but the underlying TPM can attest.
- **SoftHSM, kryoptic:** none. They are software.

### Cited Findings
**YubiKey PIV**
- What it asserts:
  - Attestation shows "that a certain asymmetric key has been generated on device and not imported". A certificate is produced only for keys generated on the device.
  - The factory attestation key and certificate in slot f9 are signed by a Yubico PIV CA.
  - Overwriting f9 is irreversible, and a reset does not clear it.
- Extensions:

  | OID | Meaning |
  |---|---|
  | `1.3.6.1.4.1.41482.3.3` | firmware version |
  | `.3.7` | serial number |
  | `.3.8` | PIN policy and touch policy |
  | `.3.9` | form factor |
  | `.3.10` | FIPS certified (factory f9 certificate only) |
  | `.3.11` | CSPN certified (factory f9 certificate only) |

- History:
  - Introduced in YubiKey 4.3/5.
  - The root was updated 2018-09-24.
  - Firmware 5.7.4+ chains to a new 2025 Yubico root.
- [Yubico PIV attestation](https://developers.yubico.com/PIV/Introduction/PIV_attestation.html)

**ykcs11**
- Calls `ykpiv_attest` per slot when it opens a session. On success it:
  - sets origin = generated;
  - parses the PIN and touch policy from the certificate;
  - exposes the attestation certificate as a PKCS#11 object (`PIV_*_OBJ_ATTESTATION`);
  - takes the slot's public key from it.
- Its comment: "No attestation can be created for imported objects".
- [yubico-piv-tool `ykcs11/ykcs11.c`:980–1063, 1538, 1658](https://github.com/Yubico/yubico-piv-tool)

**YubiKey OpenPGP**
- Attestation since firmware 5.2 (sources differ: 5.2 vs 5.2.3).
- The certificate carries a "generated on device" integer (0 = imported, 1 = generated) and the key fingerprint.
- It is signed by a factory attestation key under the Yubico OPGP CA.
- [Yubico OpenPGP Attestation](https://developers.yubico.com/PGP/Attestation.html); [OID arc](https://docs.yubico.com/hardware/oid/oid-pgp-arc.html); [5.2.3 notes](https://developers.yubico.com/PGP/YubiKey_5.2.3_Enhancements_to_OpenPGP_3.4.html)

**TPM 2.0**
- `TPM2_Certify` "Proves that an object with a specific NAME is loaded in the TPM. By certifying that the object is loaded, the TPM warrants that a public area with a given NAME is self-consistent and associated with a valid sensitive area."
- "If a relying party has a public area that has the same NAME as a NAME certified with this command, then the values in that public area are correct."
- An object with only its public area loaded cannot be certified.
- The attestation is signed by a separate signing key (`-C`).
- [tpm2_certify(1)](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_certify.1/), quoting TCG Part 3.
- The result is a `TPMS_ATTEST` of type `TPM_ST_ATTEST_CERTIFY` (0x8017), carrying the name and qualified name. — [python-fido2 TPM attestation source](https://developers.yubico.com/python-fido2/API_Documentation/_modules/fido2/attestation/tpm.html)
- In the TCG reference `TPM2_Load`, the Name is computed from the input public area and passed to `PrivateToSensitive`. That routine returns `TPM_RC_INTEGRITY` if the private blob's HMAC does not validate, so a private blob cannot be loaded with a foreign public area. — [TCG reference implementation, `Load.c` (Android mirror)](https://android.googlesource.com/platform/external/tpm2/+/5c18d72/Load.c)
- tpm2-pkcs11 maps TPM object attributes to PKCS#11:
  - `CKA_LOCAL` = `sensitiveDataOrigin`;
  - `CKA_EXTRACTABLE` = !(`fixedTPM`|`fixedParent`);
  - `CKA_ALWAYS_SENSITIVE` and `CKA_NEVER_EXTRACTABLE` = !extractable.
  - [tpm2-pkcs11 `src/lib/tpm.c`:3810–3830](https://github.com/tpm2-software/tpm2-pkcs11)

**Network HSMs**
- **Thales Luna.**
  - "Public Key Confirmation" (PKC) is issued only for private keys created inside a Luna module that cannot leave it.
  - Chain: Thales root → Manufacturing Integrity → Hardware Origin (per HSM) → Device Authentication → PKC.
  - Output is PKCS#7 DER via `cmu getpkc`. It requires non-extractable keys.
  - It is automatic for RSA. ECC uses a separate MIC, and PQC needs firmware 7.9.1+ / client 10.9.1+.
  - [Thales Luna 7 docs](https://thalesdocs.com/gphsm/luna/7/docs/network/Content/admin_partition/confirm/confirm_hsm.htm); [PKI Consortium validation notes](https://pkic.org/remote-key-attestation/validation/thales-luna7)
- **Google Cloud HSM.**
  - An HSM-signed attestation per key version, with certificate chains to Google and the manufacturer.
  - Field `0x0163` (= `CKA_LOCAL`) is `\x01` for keys created in the HSM and `\x00` for imported keys.
  - [Google Cloud KMS: verify attestations](https://docs.cloud.google.com/kms/docs/attest-key)
- **Entrust nShield.** Offers a "Key Attestation Verifier" to prove a signing key was generated and protected by an nShield HSM, aimed at CA/B Forum §6.2.7.2. — [Entrust datasheet](https://lac.entrustdatacard.com/sites/default/files/2024-03/nshield-key-attestation-verifier-ds.pdf)
- **AWS CloudHSM.** No native per-key attestation found. A CA guide says AWS CloudHSM "does not currently provide any means … to automate attestation of keys generated on the HSM", which may be dated. The hsm2m.medium instance type is FIPS 140-3 L3 (#4703). — [SSL.com](https://www.ssl.com/?p=25033); [AWS announcement](https://aws.amazon.com/about-aws/whats-new/2024/08/aws-cloudhsm-hsm2m-medium-instance-type)

**Android Key Attestation (analogy)**
- `KeyDescription` carries an `attestationChallenge` ("The challenge provided at key generation time"), `attestationSecurityLevel` (Software / TrustedEnvironment / StrongBox) and authorization lists split into `hardwareEnforced` and `softwareEnforced`.
- Those lists include `origin` (tag 702), `purpose` and `rollbackResistance`.
- [AOSP key attestation](https://source.android.com/docs/security/features/keystore/attestation)

**PKCS#11 3.2 validation objects**
- `CKO_VALIDATION` objects are read-only and "describe which third party validations the module conforms to". They name the authority (NIST CMVP, Common Criteria), level, certificate identifier and profile.
- `CKA_OBJECT_VALIDATION_FLAGS` marks keys "created consistent with" a validation. It is a runtime indicator, not a signed attestation.
- [PKCS#11 v3.2 §4.15](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)

### Inferences
**What attestation covers per token**
- **YubiKey PIV and OpenPGP.** Attestation binds the public key to "generated on this serial, with this PIN/touch policy, on this firmware", signed under a Yubico root.
  - It is generated per call, so it reflects the slot's *current* key.
  - But there is no verifier nonce, so a malicious module or proxy can replay an old one.
  - Through ykcs11 it is reachable as a certificate object.
  - Verify to the Yubico root, not to f9 alone, because f9 is user-overwritable.
  - For PIV, the attestation is also what makes ykcs11's private `CKA_EC_POINT` trustworthy.
- **Native TPM.** `TPM2_Certify(object, AK, qualifyingData = host nonce)`, with the AK chained to the EK certificate, gives four things:
  - **[attested]** the full public area, including `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `userWithAuth`/`adminWithPolicy`, `authPolicy` and the key's public point;
  - freshness;
  - residence in *that* TPM;
  - binding, because the Name covers the public point and the TPM certifies a matching sensitive area.

  The catch is AK/EK provisioning: an EK certificate chain to the TPM vendor, plus TPM2_MakeCredential/ActivateCredential to tie the AK to the EK.
- **tpm2-pkcs11.** It does not expose this. cakeys could reach the TPM directly by reading the object's TPM public/private blobs from the tpm2-pkcs11 store and certifying them via tss-esapi. That bypasses the PKCS#11 abstraction.
- **Network HSMs.** Vendor attestations prove generation in a validated HSM and some attributes:
  - Google exposes a PKCS#11-like attribute dump, including `CKA_LOCAL`.
  - Luna proves non-extractable residence of the key.

  They are vendor-specific formats, fetched out of band, not via standard PKCS#11 calls. cakeys could accept them as an optional "attestation blob" input per object.

**Lock design**
- An attestation is evidence of *provenance* (where the key was generated). It belongs in the lock as an `attestation` record per realisation: format, root fingerprint, the asserted properties and the SPKI hash.
- Re-verify it on `verify` against the locked SPKI.
- It does not replace PoP for liveness, except for TPM2_Certify with a nonce.

### Gaps
- Not read:
  - TCG Part 1/2 text for the exact `TPMA_OBJECT` bit semantics and the integrity HMAC input layout;
  - FIDO/WebAuthn attestation specs;
  - Apple Secure Enclave attestation (App Attest, or Managed Device Attestation);
  - KeyMint `Tag::ORIGIN` values;
  - Nitrokey (OpenPGP 3.4) attestation;
  - nShield internals (key generation certificates, ACL hashes);
  - AWS CloudHSM current docs.
- The YubiKey PIV attestation page does not describe whether the attestation includes a nonce. The inference "no nonce" rests on the absence of any challenge input in `ykpiv_attest(state, slot, data, &len)` (ykcs11.c:999). Confirm it in the Yubico spec.
- Whether YubiKey `GET METADATA` (fw 5.3+) public keys are device-derived for imported keys was inferred from ykcs11's use of `md.pubkey`, not from Yubico documentation.

## PKCS#11 attribute evidence and mutability after the lock is written

### Takeaway
The history attributes `CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE` and `CKA_KEY_GEN_MECHANISM` are token-asserted only. Two of the modules read *fabricate* them:
- ykcs11 hardcodes ALWAYS_SENSITIVE and NEVER_EXTRACTABLE to TRUE.
- OpenSC copies personalisation-time PKCS#15 flags.

Only tpm2-pkcs11's `CKA_LOCAL` derives from a TPM-certifiable bit.

The spec fixes the following as one-way:
- `CKA_SENSITIVE` and `CKA_WRAP_WITH_TRUSTED` (once TRUE);
- `CKA_EXTRACTABLE` and `CKA_COPYABLE` (once FALSE).

Everything with footnote 8 stays changeable after the lock is written unless `CKA_MODIFIABLE=FALSE`. That covers usage bits, `CKA_LABEL`, `CKA_ID`, `CKA_PUBLIC_KEY_INFO` and dates. So these must be re-verified on every `verify`.

### Cited Findings
**What the spec says**
- Footnote 8: "May be modified after object is created with a C_SetAttributeValue call, or in the process of copying object with a C_CopyObject call".
- Footnote 11: "Attribute cannot be changed once set to CK_TRUE. It becomes a read only attribute."
- Footnote 12: "… once set to CK_FALSE".
- Footnote 10: "Can only be set to CK_TRUE by the SO user".
- On private and secret keys:
  - `CKA_SENSITIVE`: footnotes 8 and 11;
  - `CKA_EXTRACTABLE`: footnotes 8 and 12;
  - `CKA_WRAP_WITH_TRUSTED`: footnote 11;
  - `CKA_TRUSTED`: footnote 10;
  - `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`, `CKA_LOCAL`, `CKA_KEY_GEN_MECHANISM`: footnotes 2, 4 and 6, meaning not specifiable on create, generate or unwrap.
- [PKCS#11 v3.2 §4.2 Table 13; §4.7, §4.10, §4.11 tables](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- `CKA_LOCAL` is TRUE "only if key was either generated locally (i.e., on the token) with a C_GenerateKey or C_GenerateKeyPair call [or] created with a C_CopyObject call as a copy of a key which had its CKA_LOCAL attribute set to CK_TRUE". — [PKCS#11 v3.2 §4.7](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- Common object attributes:
  - `CKA_MODIFIABLE` default TRUE;
  - `CKA_COPYABLE` default TRUE, "Can't be set to TRUE once it is set to FALSE";
  - `CKA_DESTROYABLE` default TRUE.
  - Scoped to the common *storage-object* attributes table only, not to key attributes, which follow their own footnotes (footnote 8 etc.): "Only the CKA_LABEL attribute can be modified after the object is created. (The CKA_TOKEN, CKA_PRIVATE, and CKA_MODIFIABLE attributes can be changed in the process of copying an object, however.)"
  - [PKCS#11 v3.2 §4.4](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- `C_CopyObject` may change "the Cryptoki attributes which are described as being modifiable, plus the four special attributes CKA_TOKEN, CKA_PRIVATE, CKA_MODIFIABLE and CKA_DESTROYABLE". `CKA_SENSITIVE` may go FALSE→TRUE "but not the other way around". Modifiability is token-dependent ("A particular token might not actually support modification"). — [PKCS#11 v3.2 §4.1.2–4.1.3](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- `CKA_UNIQUE_ID` (3.0+): "Any time a new object is created, a value for CKA_UNIQUE_ID MUST be generated by the token". It cannot be modified or specified. Re-initialising the token "MAY cause reuse of CKA_UNIQUE_ID values". — [PKCS#11 v3.2 §4.4.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)

**What the modules actually report**
- **ykcs11** private-key objects:
  - `CKA_ALWAYS_SENSITIVE` is "Always true";
  - `CKA_NEVER_EXTRACTABLE` is "Always true";
  - `CKA_EXTRACTABLE` and `CKA_COPYABLE` are always false;
  - `CKA_DESTROYABLE` is always true;
  - `CKA_LOCAL` = origin == GENERATED, from attestation or metadata.
  - [yubico-piv-tool `ykcs11/objects.c`:298–300, 605–645](https://github.com/Yubico/yubico-piv-tool)
- **OpenSC** sets `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE` and `CKA_LOCAL` from PKCS#15 `prv_info->access_flags` (`SC_PKCS15_PRKEY_ACCESS_{ALWAYSSENSITIVE,NEVEREXTRACTABLE,LOCAL}`). — [OpenSC `framework-pkcs15.c` `pkcs15_prkey_get_attribute`](https://github.com/OpenSC/OpenSC/blob/master/src/pkcs11/framework-pkcs15.c)
- **tpm2-pkcs11** rejects `CKA_LOCAL=TRUE` in templates ("CKA_LOCAL cannot be true"), sets `CKA_KEY_GEN_MECHANISM` to `CK_UNAVAILABLE_INFORMATION` for imported objects, and derives `CKA_LOCAL` from `sensitiveDataOrigin`. — [tpm2-pkcs11 `src/lib/object.c`:958–1006, 1157–1171; `tpm.c`:3810–3830](https://github.com/tpm2-software/tpm2-pkcs11)

**Academic attack literature**
- Clulow, "On the Security of PKCS #11", CHES 2003 (historical, LNCS 2779, pp. 411–425).
  - Key-separation attacks. The canonical one is wrap/decrypt: wrap a sensitive key under a key with both WRAP and DECRYPT, then decrypt the wrapped blob to obtain the key in the clear.
  - He also showed attacks via ECB wrapping of double-length 3DES keys.
  - [IACR CHES slides](https://iacr.org/workshops/ches/ches2003/presentations/CHES%20-%20On%20the%20Security%20of%20PKCS11.pdf); [Steel, SecAppDev 2013 handouts](https://handouts.secappdev.org/handouts/2013/Graham%20Steel/STEEL-crytpo-apis-handouts.pdf)
- Bortolozzo, Centenaro, Focardi, Steel, "Attacking and fixing PKCS#11 security tokens", CCS 2010, pp. 260–269 (historical).
  - Tookan reverse-engineers a token's API, model-checks it, and runs the attacks found.
  - Of 18 commercial tokens, 10 were vulnerable and 8 severely restricted.
  - The authors give a secure configuration without new mechanisms.
  - [researchr](https://researchr.org/publication/BortolozzoCFS10); [IMDEA talk abstract](https://software.imdea.org/events/invited-talks/2011/02-22/)
- Proposed countermeasures in this line of work (Delaune–Kremer–Steel formal analyses, then Tookan) include "sticky" attributes that cannot be unset once set, and conflict rules that forbid e.g. WRAP+DECRYPT on one key. — [Steel handouts](https://handouts.secappdev.org/handouts/2013/Graham%20Steel/STEEL-crytpo-apis-handouts.pdf); [Delaune, Kremer, Steel (LSV)](https://lsv.ens-paris-saclay.fr/Publis/PAPERS/PDF/DKS-tfit08.pdf)

### Inferences
**Evidence ladder for "this key was generated on the token and never left"**
1. **[token-asserted]** `CKA_LOCAL`/`NEVER_EXTRACTABLE`/`ALWAYS_SENSITIVE`. These are worthless on ykcs11 for the latter two, and personalisation-asserted on OpenSC.
2. **[attested]** A vendor-signed dump: Google `0x0163`, Luna PKC, Yubico attestation.
3. **[attested + fresh]** TPM2_Certify over a Name whose public area has `sensitiveDataOrigin` + `fixedTPM`.

cakeys should record which level it has. It should never print `CKA_LOCAL=TRUE` as "generated on token" without the level.

**Re-check on every `verify` (state that can change after the lock)**
- Usage bits: SIGN, DECRYPT, WRAP, UNWRAP, DERIVE, ENCRYPT, VERIFY.
- `CKA_ALLOWED_MECHANISMS`, the `CKA_WRAP_TEMPLATE`/`UNWRAP_TEMPLATE`/`DERIVE_TEMPLATE` templates, `CKA_LABEL`/`CKA_ID` (the locator!), `CKA_PUBLIC_KEY_INFO`, `CKA_START_DATE`/`CKA_END_DATE`.
- `CKA_SENSITIVE` FALSE→TRUE only, and `CKA_EXTRACTABLE` TRUE→FALSE only.
- `CKA_TRUSTED` (SO only).
- Whether the object still exists. `CKA_DESTROYABLE` may be TRUE.

**Clulow's attack makes usage bits security-relevant**
- A key locked as "SIGN only" could later gain WRAP or DECRYPT and become an attack tool. So cakeys' existing "policy of the live object must match the spec" check is the right control.
- On a conforming token, `CKA_MODIFIABLE=FALSE` + `CKA_COPYABLE=FALSE` + `CKA_DESTROYABLE=FALSE` freezes the policy. This is token-asserted, but declarable in `keys.toml` and checkable.

**What cannot be detected after the lock**
- **Copies.** `C_CopyObject` (if COPYABLE), or wrap and re-import (if EXTRACTABLE), can create copies elsewhere: under another label, on another token, or off-token.
- "No other copy of this material exists" is **[unobservable]** via PKCS#11.
- It is bounded only by `CKA_NEVER_EXTRACTABLE ∧ ¬CKA_COPYABLE`, which is token-asserted, or by `fixedTPM`, which is TPM-attested.

**`CKA_UNIQUE_ID` as a swap detector**
- It is a cheap observed-layer complement to PoP: delete and recreate yields a new ID. It catches the H1 swap on honest 3.0+ modules.
- It is not a fix. It is token-asserted, IDs can be reused after `C_InitToken`, and SoftHSM/ykcs11 support is unverified.
- It also changes on legitimate re-creation, so it belongs in the realisation record, not the identity.

### Gaps
- Not checked: which of SoftHSM, kryoptic, ykcs11 and tpm2-pkcs11 implement `CKA_UNIQUE_ID`.
- Not checked: whether each honours `CKA_MODIFIABLE=FALSE` against `C_SetAttributeValue` on usage bits.
- The full Tookan paper text was not retrieved; the secgroup page returned 404. Its exact attack list (re-import, unwrap-with-attribute-change) and the secure-configuration specifics are not quoted here.
- The full Clulow paper and the DKS papers were not read in full text.

## KCV and commitment security

### Takeaway
Publishing `SHA-256(token_output)` for a fixed, domain-separated message is a sound identity for 128-bit-or-stronger keys:
- It reveals no block-cipher pair or MAC tag.
- It is collision-resistant to about 2^128 for AES-block outputs and about 2^256 for HMAC.

Its real risks:
1. It is an offline key-guess oracle, which matters only for low-entropy keys.
2. It is replayable: a malicious module can return the locked value without holding the key. Secret-key *liveness* is therefore unprovable via PKCS#11.
3. It is a deliberate cross-token linker, which is intended.

The classic 3-byte KCV is a 24-bit *check*, not an identity.

### Cited Findings
**PKCS#11 `CKA_CHECK_VALUE`**
- It is 3 bytes and "operates like a fingerprint, or checksum of the key".
- Properties: it "should not be usable to obtain any part of the key value"; "Two different keys can have the same CKA_CHECK_VALUE".
- If supported, it "SHALL be supplied even if the encryption operation for the key is forbidden (i.e. when CKA_ENCRYPT is set to CK_FALSE)".
- A template value "MUST match what the library calculates it to be or the library returns a CKR_ATTRIBUTE_VALUE_INVALID".
- Per key type:
  - AES, DES2 and DES3: the first 3 bytes of ECB encryption of a zero block;
  - generic secret, ChaCha20 and Salsa20: the first 3 bytes of SHA-1(`CKA_VALUE`);
  - certificates: the first 3 bytes of SHA-1 of the DER.
- [PKCS#11 v3.2 §4.11, §6.8.2, §6.10.2, §6.18, §6.58–6.59, §4.6.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)

**Payments-industry KCVs**
- ANSI X9.24-1-2017 Annex A (secondary source) has two KCV methods:
  - the legacy one, encryption of a zero block;
  - CMAC over a zero block, truncated to at most 40 bits.
- AES keys must use the CMAC method. — [Wikipedia: Key checksum value](https://en.wikipedia.org/wiki/Key_checksum_value), summarising X9.24-1-2017; standard not read
- AWS Payment Cryptography uses an AES KCV of CMAC over 16 zero bytes, keeping 3 bytes. — [AWS SDK docs](https://docs.aws.amazon.com/sdk-for-kotlin/api/latest/paymentcryptography/aws.sdk.kotlin.services.paymentcryptography.model/-key/key-check-value-algorithm.html)

**Iwata–Wang**
- Iwata and Wang, "Impact of ANSI X9.24-1:2009 Key Check Value on ISO/IEC 9797-1:2011 MACs" (FSE 2014 / ePrint 2014/183).
- They treat the KCV (encryption of the zero block) as public, and "show attacks against five MACs by taking advantage of the knowledge of the key check value". For the other four, the birthday bound holds.
- [ePrint 2014/183](https://eprint.iacr.org/2014/183)

**cakeys' own design**
- Commitments are computed over `<label>/<scheme>/<keyType>/<bits>`. The lock stores only SHA-256 of the token output. A test asserts the raw CMAC is absent.
- `kcv-ecb` encrypts the first 16 bytes of SHA-256(label), not a zero block.
- `kw` wraps a fixed public key derived from the label.
- `docs/DESIGN.md` §3.1, §3.3 (local)

### Inferences
**Why the Iwata–Wang family of attacks does not apply**
- The CMAC subkey derivation uses `L = E_K(0^128)`. That is exactly the raw zero-block KCV, which is why X9.24 moved AES KCVs to CMAC.
- cakeys never computes `E_K(0)`. It never stores any raw `E_K(m)` or MAC tag either, only SHA-256 of it.
- Even a leaked raw `kcv-ecb` value would be a single known plaintext/ciphertext pair at a non-zero, label-derived point. That is harmless for AES under standard PRP assumptions.

**Collision and binding strength**
- AES-ECB/CMAC/KW commitments: 128-bit outputs (KW: 192+ bits).
- For AES-256 about 2^128 keys share each output, so the commitment is not *unique*. But finding a second key matching a given commitment is a generic search of about 2^128 work, even for someone who knows K.
- HMAC-SHA-256: about 2^256.
- The hash wrapper does not reduce this.
- Domain separation by the label prefix and key type stops a protocol message from coinciding with the commitment input.
- Recording the label per object (fix P1) keeps it stable.

**Offline key-guess oracle**
- The commitment lets anyone holding the lock test a guessed key.
- That is irrelevant for generated 128/256-bit keys, but real for password-derived or human-entered secrets (generic secrets / HMAC from passphrases).
- Recommendation: document it, or allow a per-object salt in the label, without changing the scheme.

**Replay, and why liveness is unprovable**
- The host cannot check a fresh MAC or encryption without knowing the key, so every secret-key commitment is a fixed value a dishonest module can memorise.
- So secret-key identity is **[token-asserted]**, robust against operator mistakes and honest-token swaps, but not against a lying module.
- Exception: if the host shares the key (import-time `host-at-import` mode), it can challenge with fresh nonces.
- By contrast, asymmetric PoP is fresh.

**`CKA_CHECK_VALUE` fills a gap**
- The spec says it is supplied even when ENCRYPT is false, so it is a usable fallback for "non-extractable secret keys without usable usage bits", which currently have no identity.
- It is only a 24-bit **[token-asserted]** check. Use it as a weak, explicitly opted-in mode (`kcv3`), never as the identity link: about 1 in 16M random collisions, and ~2^24 work to forge.
- For AES it equals `E_K(0)[0..3]`. Publishing 3 bytes of the CMAC L value is what the standard already does, and the Iwata–Wang attacks target MAC forgery, not key recovery. Still, record it raw only under an explicit opt-in.
- **Recording a KCV breaks a lock invariant.** Storing any KCV-derived value breaks DESIGN §8.1's rule that "the lock never holds token outputs, only their hashes" *in substance*. Hashing a 24-bit value is reversible with 2^24 guesses, so `SHA-256(KCV)` is effectively the raw KCV. An opt-in `kcv3` mode must say so, rather than hide behind the hash.

### Gaps
- The X9.24-1-2017 text itself was not read; the 40-bit/CMAC claims are from a secondary summary.
- I found no literature specifically analysing "hash of a MAC over a fixed label" as a public key identifier. The reasoning above is standard PRF/hash argument, not a cited proof.
- Which modules implement `CKA_CHECK_VALUE` for AES and generic secrets (SoftHSM, kryoptic, tpm2-pkcs11) was not checked.

## What "config+lock completely describes key/object state" can mean

### Takeaway
"Complete description" is achievable only as a layered claim. Each locked fact should carry the strongest evidence class available for that token, and the lock should record that class so downgrades fail.

Classes and examples:
- **[crypto]:** the public key, plus binding of private to public via fresh PoP.
- **[attested]:** generated-on-device and policy, via YubiKey, TPM2_Certify or vendor HSM.
- **[token-asserted]:** usage and policy attributes, history attributes, secret-key commitments, `CKA_UNIQUE_ID`.
- **[unobservable]:** that no other copy exists, past exports, and that the module is not a relay.

H1 should be closed by mandatory PoP for every private-key object (with a recorded `binding` level), not by special-casing SoftHSM EC.

### Cited Findings
- Every finding above. In particular, all three of these come only from the module and are not bound:
  - the private-key public material in OpenSC, ykcs11 and SoftHSM (§1);
  - the history attributes in ykcs11 and OpenSC (§3);
  - secret-key commitments (§4).
- cakeys' current security model:
  - recomputes the content-addressed ID (CA-ID) from the token;
  - checks the live object's type and policy against the spec;
  - records identity mode per realisation, with "a downgrade fails (exit 14)".
  - `docs/DESIGN.md` §3.4, §8.1 (local)
- REVIEW H1 recommends PoP (sign, ECDH, or publicOnly opt-in). Its note that "RSA private objects carry the modulus" holds for SoftHSM, but not for OpenSC, where the modulus is served from a friend object (§1). — `docs/REVIEW-2026-11-11.md` (local)

### Inferences
**Facets of object state and what can establish each**

| Facet | What it is | Best evidence | Notes |
|---|---|---|---|
| Identity (which material) | SPKI hash, cert/data hash, secret commitment | public: [crypto] (hash of public value); secret: [token-asserted] (commitment) | Public identity alone does not prove the private key matches. |
| Binding (private ↔ public) | the private key on the token corresponds to the locked SPKI | [crypto] via PoP; [attested] via YubiKey / TPM2_Certify | Today cakeys has this only implicitly, and only where the module derives the public part honestly. |
| Liveness / residence | still present and usable now, on *this* token | PoP proves access now ([crypto]); TPM2_Certify + nonce + EK-chained AK proves residence ([attested]); otherwise [token-asserted] | A module could relay operations to a key held elsewhere. Only device-bound, nonce-bound attestation excludes that. |
| Type / parameters | class, key type, curve, bits | [crypto] for public keys (from the SPKI); [token-asserted] for secrets (`CKA_VALUE_LEN`) | — |
| Policy (mutable) | usage bits, `ALLOWED_MECHANISMS`, templates, label/ID, dates | [token-asserted]; re-check every `verify` | Frozen only if `MODIFIABLE=FALSE` (still token-asserted). TPM: `authPolicy`/`userWithAuth` are [attested] via the Name. |
| Policy (one-way) | `SENSITIVE`↑, `EXTRACTABLE`↓, `COPYABLE`↓, `WRAP_WITH_TRUSTED`↑ | [token-asserted]; monotone, so once seen in the safe state it cannot regress on an honest token | Still re-check, because the module may be replaced. |
| Provenance | generated on token; never extractable | [token-asserted] `CKA_LOCAL` etc. (fabricated on ykcs11/OpenSC); [attested] YubiKey / Google / Luna / TPM `sensitiveDataOrigin` | Record the level, not just the boolean. |
| Location | module, token serial, locator | [token-asserted] (`C_GetTokenInfo` serial, label/ID); [attested] if the attestation carries a serial (YubiKey `.3.7`) or the TPM EK | p11-kit hides the module (D4). |
| Exclusivity | no other copies exist | [unobservable]; bounded by `NEVER_EXTRACTABLE ∧ ¬COPYABLE` [token-asserted] or `fixedTPM` [attested] | — |
| History | past exports, attribute changes, wrapping events | [unobservable] via PKCS#11 (no audit log in the API) | Vendor HSM audit logs are out of band. |

**Evidence per token type**

| Token | Private → public source | Binding without PoP | PoP possible | Provenance attestation | History attributes |
|---|---|---|---|---|---|
| SoftHSM 2.7.0 | `CKA_PUBLIC_KEY_INFO` (settable, unchecked); RSA: modulus; EC/Ed: none → public object | **none** (all types, via a settable `CKA_PUBLIC_KEY_INFO`) | yes (sign / ECDH / decrypt) | none (software) | token-asserted |
| kryoptic 1.5.x | `CKA_PUBLIC_KEY_INFO` computed from private data and checked on `C_CreateObject`, but settable unchecked via `C_SetAttributeValue` | **none** after a set (code reading); otherwise [token-asserted, derived] | yes, plus `C_DecapsulateKey` for ML-KEM | none | token-asserted |
| tpm2-pkcs11 | `CKA_EC_POINT`/modulus computed at creation from the TPM public area, served from sqlite | [token-asserted]; can be broken by tampering with the sqlite store | yes | not via PKCS#11; possible via direct TPM2_Certify on the stored blob | `CKA_LOCAL` from `sensitiveDataOrigin` (TPM-certifiable) |
| YubiKey PIV (ykcs11) | attestation → metadata → slot certificate | generated keys: [attested]; imported keys on firmware without metadata: **none** | yes (sign, ECDH for derive); touch/PIN policy may block unattended use | Yubico PIV attestation (no nonce) | `ALWAYS_SENSITIVE`/`NEVER_EXTRACTABLE` hardcoded TRUE; `LOCAL` from attestation or metadata |
| OpenSC cards | RSA: friend public key or certificate; EC: none → public object | **none** | yes (card-dependent mechanisms) | card-specific; PIV cards via the Yubico path; OpenPGP 3.4 cards via the OpenPGP attestation slot | from PKCS#15 personalisation flags |
| Network HSMs (Luna, nShield, Google) | vendor-derived (not read) | [token-asserted] | yes | vendor attestation, out of band (Luna PKC, Google `0x0163`, nShield verifier) | token-asserted, vendor-attested in Google's dump |
| Native TPM | TPM public area (Name) | [crypto + attested]: TPM2_Load integrity binds private to public; TPM2_Certify proves it | yes (sign / ECDH / RSA decrypt) | TPM2_Certify with nonce, AK→EK chain | `TPMA_OBJECT` bits, [attested] |

**Recommendation to close H1**

1. **Prove possession of every private-key object on `realise`, `adopt` and `verify`.**
   - Do this whatever path produced the SPKI. Order of methods:
     1. `pop-sign`: a hashing mechanism over a domain-separated, nonce-bearing message.
     2. `pop-ecdh`: ECDH with an ephemeral host key; compare the extractable session secret, or HMAC under the derived key.
     3. `pop-decrypt`: RSA-OAEP.
     4. `pop-kem`: ML-KEM decapsulation via `C_DecapsulateKey` when the token offers it.
   - Use the first one the key's *declared* usage bits and the token's mechanism list allow. This mirrors the commitment-scheme rule in DESIGN §3.1.
   - A wrong PoP is a hash-mismatch-class failure.
2. **Record a per-realisation `binding` level**, ordered strongest first:

   ```
   pop-* + attested (nonce-bound)
   > pop-* + attested
   > pop-*
   > attested
   > token-derived
   > none
   ```

   - Fold it into the existing §3.4 strength order, so the downgrade rule (exit 14) already covers it.
   - `none` is allowed only with an explicit per-object or per-token opt-in, alongside `publicOnly`. Examples: an EC key with no SIGN/DERIVE, or a wrap-only RSA key.
3. **Accept attestation as optional extra evidence**, and make it a *substitute* for PoP only on opt-in. The touch-free case for generated PIV keys is the motivating example.
   - **YubiKey PIV:** verify the chain to the pinned Yubico root (not just f9), then compare the attested SPKI with the locked `pubkeyhash`. Record serial, firmware and PIN/touch policy.
   - **TPM:** TPM2_Certify with a nonce and an EK-chained AK. Record the Name and the TPMA bits.
   - **Vendor HSMs:** an opaque blob plus the verifier tool's result, locked by hash.
4. **Stop trusting the history attributes as provenance.**
   - Report `CKA_LOCAL`/`NEVER_EXTRACTABLE` as token-asserted.
   - Mark them "unreliable" for ykcs11 and OpenSC.
   - Lock them only as *policy expectations* ("the token must say TRUE"), never as provenance proof.
5. **Re-check all mutable policy on every `verify`**, which cakeys already does for the declared spec:
   - include `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE`, `CKA_ALLOWED_MECHANISMS` and the templates, so that a key gaining WRAP/DECRYPT (Clulow) fails;
   - optionally record `CKA_UNIQUE_ID` per realisation as a cheap swap detector (a note, not an error, on legitimate re-creation).
6. **For non-extractable secret keys without usage bits**, offer opt-in `kcv3` (`CKA_CHECK_VALUE`): a weak, token-asserted, 24-bit link. Otherwise keep "no identity".
   - It is an explicit exception to the "no token outputs in the lock" invariant. Hashing does not hide 24 bits.
7. **Cross-check public-key attributes.** When an object exposes both `CKA_PUBLIC_KEY_INFO` and `CKA_EC_POINT`/modulus, decode both and fail on disagreement.
   - This covers standalone public-key objects, which PoP cannot cover.
   - Certificates keep deriving their SPKI from the DER, as now.
8. **State the limits explicitly in DESIGN §8.** A config+lock pair proves:
   - **[crypto]:** which public material, and that the token can use the matching private key *now*;
   - **[attested]:** where it was generated, when an attestation exists;
   - **[token-asserted]:** everything about secrets and policy.

   It cannot prove that no copies exist, past exports, or that a malicious module holds the secret key it commits to.

### Gaps
- No formal model (for example Tamarin or ProVerif) of the proposed PoP-plus-lock protocol was found or built.
- I found no academic work that defines "complete state description" for HSM objects as such. The facet taxonomy above is my synthesis, not a cited framework.
- Not verified:
  - network HSM behaviour for public-key attributes on private objects;
  - support for `CKA_UNIQUE_ID` and `C_DecapsulateKey` across the listed tokens;
  - whether tpm2-pkcs11 exposes an `ESYS` handle path that lets cakeys run TPM2_Certify without parsing the sqlite store.
