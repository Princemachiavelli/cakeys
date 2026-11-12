# Prior art for content-addressed and declarative key/credential management, compared with cakeys (state: 2026-11-11)

Scope note. The cakeys baseline used for every comparison below is `docs/DESIGN.md` (2026-11-11) and `README.md` in `/home/jhoffer/srcs/key-management`. Its key facts:
- **Identity schemes:** `pubkeyhash` is SHA-256 of canonical DER SPKI, re-encoded through RustCrypto. `certhash` and `valuehash` are SHA-256 of the DER or value. For secret keys, the token computes `commitment` / `cmac` / `kcv-ecb` / `kcv-ecb-dec` / `kw` over the label `<commitmentLabel>/<scheme>/<keyType>/<bits>`, and only SHA-256 of the token's output is stored.
- **The lock:** records type, commitment label, spec digest and per-realisation provenance. Scheme definitions are frozen.
- **Behaviour:** first use is a "got:" mismatch, as with a Nix FOD. Locators are `CKA_LABEL`/`CKA_ID`.

PLAN.md's earlier "Prior art / landscape" survey was re-checked here. Corrections are flagged **[PLAN.md correction]**.

---

## Q1. Content-addressed key identity: which schemes define canonicalization precisely, and which had ambiguity bugs?

### Takeaway
- **Byte-exact definitions:** OpenPGP v4/v6 fingerprints, the SSH fingerprint, RFC 7638 JWK and RFC 9679 COSE thumbprints, RFC 7093 method 4 SKI (SHA-256 over the whole DER SPKI, the same input as cakeys' `pubkeyhash`) and TUF keyids (SHA-256 over canonical JSON of the key) all define their input exactly. GnuPG's keygrip is defined only by libgcrypt code.
- **Definitions that leave room for ambiguity:**
  - JWK and COSE thumbprints say outright that they identify a key only if a single unambiguous representation is used.
  - RFC 5280 SKI is only a SHOULD, with "other methods … acceptable".
  - TUF/go-tuf had a real threshold-bypass advisory because one key carried several keyids.
  - OpenPGP fingerprints include the creation time, so the same material yields different fingerprints.
  - PKCS#11's `CKA_UNIQUE_ID` and KMIP's Unique Identifier are assigned by the token or server, not derived from content.

### Cited Findings

**OpenPGP (RFC 9580, July 2024)**
- **v4 fingerprint:** SHA-1 over `0x99 ‖ 2-octet length ‖ entire Public Key packet` starting at the version field. The Key ID is the low 64 bits. — [RFC 9580 §5.5.4.2](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4.2)
- **v6 fingerprint:** SHA-256 over `0x9B ‖ 4-octet length ‖ Public Key packet`, with an explicit 4-octet length for the key material. The Key ID is the *high* 64 bits. — [RFC 9580 §5.5.4.3](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4.3)
- **Creation time is hashed:** both v4 and v6 hash a 4-octet "timestamp of key creation". The same RSA material as a v3, v4 or v6 key "will have different Key IDs as well as different fingerprints". — [RFC 9580 §5.5.4](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4)
- **Collisions:** "it is possible for there to be collisions of Key IDs", and there is a "much smaller, but still non-zero" probability of fingerprint collisions. "Implementations SHOULD NOT assume that Key IDs are unique." — [RFC 9580 §5.5.4, §3.3](https://www.rfc-editor.org/rfc/rfc9580.html#section-3.3)
- **Historical:** the v3 fingerprint was MD5 over the RSA MPIs, and its Key ID was the low 64 bits of the modulus. "both version 3 keys and MD5 are deprecated." — [RFC 9580 §5.5.4.1](https://www.rfc-editor.org/rfc/rfc9580.html#section-5.5.4.1)
- **Historical attack (Evil32):** colliding 32-bit short key IDs were generated for every key in the Web of Trust strong set, at "4 seconds to generate a colliding 32bit key id on a GPU". Key servers accepted keys with colliding IDs, and GPG imported both. — [Evil 32](https://evil32.com/)

**GnuPG keygrip (libgcrypt)**
- **Definition:** the keygrip is "the SHA-1 hash of the public key parameters expressed in a way depending on the algorithm". It accepts public, private, protected or shadowed (stub) key S-expressions, so a card stub and the soft key share a grip. — [libgcrypt cipher/pubkey.c `_gcry_pk_get_keygrip`](https://github.com/gpg/libgcrypt/blob/master/cipher/pubkey.c)
- **RSA:** the keygrip hashes only the raw bytes of the modulus `n`. — [libgcrypt cipher/rsa.c `compute_keygrip`](https://github.com/gpg/libgcrypt/blob/master/cipher/rsa.c)
- **ECC:** the keygrip hashes the curve domain parameters `p, a, b, g, n` plus `q`, filled in from the curve name.
  - Compressed Weierstrass points are uncompressed first.
  - Ed25519 is hashed in *compressed* form.
  - For Curve25519 (`djb-tweak`), a 0x40 prefix is stripped.
  - Where no curve name is given, the code itself says the fallback is "a crude hacks. We need to fix that."

  So the canonical form is defined by implementation special cases, not by a specification. — [libgcrypt cipher/ecc.c `compute_keygrip`](https://github.com/gpg/libgcrypt/blob/master/cipher/ecc.c)

**SSH**
- **Historical:** RFC 4716 defines the SSH fingerprint as MD5 of the RFC 4253 public-key blob, shown as colon-separated hex. — [RFC 4716 §4](https://www.rfc-editor.org/rfc/rfc4716.html#section-4)
- **Current:** OpenSSH `ssh-keygen -E` accepts `md5` or `sha256`; "The default is 'sha256'". — [ssh-keygen(1)](https://man.openbsd.org/ssh-keygen.1)

**X.509 SubjectKeyIdentifier**
- **RFC 5280 methods:** (1) SHA-1 of the subjectPublicKey BIT STRING value, or (2) a 0100 type field plus the low 60 bits of that SHA-1. "Other methods of generating unique numbers are also acceptable." "Applications are not required to verify that key identifiers match." — [RFC 5280 §4.2.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2)
- **RFC 7093 methods 1–3** (Informational): SHA-256, SHA-384 or SHA-512 of the BIT STRING, truncated to the leftmost 160 bits.
- **RFC 7093 method 4:** the hash of the DER-encoded *whole* SubjectPublicKeyInfo. Its example is an untruncated SHA-256.
- **RFC 7093 on hash strength:** collision resistance "[is] not needed for key identifiers". — [RFC 7093 §2](https://www.rfc-editor.org/rfc/rfc7093.html)

**JWK thumbprint (RFC 7638) and thumbprint URI (RFC 9278)**
- **Procedure:**
  - Use only the required members: EC `crv,kty,x,y`; RSA `e,kty,n`; oct `k,kty`.
  - Sort them lexicographically by code point.
  - Use no whitespace and no escaping, and integers without fraction or exponent.
  - Hash the UTF-8 bytes.
- **Ambiguity (Security Considerations):** a thumbprint identifies a key only if "a single unambiguous JWK representation" is used. For example, RSA `e` encoded as "AAEAAQ" instead of "AQAB" gives a different thumbprint for the same key. Platform sort functions may disagree on non-ASCII member names. — [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html)
- **URI form:** RFC 9278 defines `urn:ietf:params:oauth:jwk-thumbprint:<hash-alg>:<value>`, which makes the hash algorithm explicit. — [RFC 9278 §3](https://www.rfc-editor.org/rfc/rfc9278.html#section-3)

**COSE Key Thumbprint (RFC 9679, Dec 2024, Standards Track)**
- **Procedure:**
  - Use only the required parameters, `kid` excluded.
  - EC2 points must be uncompressed.
  - `kty` must be the integer from the IANA registry.
  - Encode with RFC 8949 §4.2.1 deterministic CBOR, then hash. SHA-256 is mandatory.
- **URI:** `urn:ietf:params:oauth:ckt:sha-256:<b64url>`.
- **Security Considerations:**
  - Comparing thumbprints "cannot reliably block keys", because a transformed key such as modulus 3·N still partially works but has a different thumbprint.
  - **Symmetric-key thumbprints must not be computed from low-entropy secrets** (precomputation attacks). If entropy cannot be verified, do not thumbprint symmetric keys at all.

  — [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679.html)

**TUF keyids, and the advisory caused by multiple keyids per key**
- **Current TUF spec** (v1.0.37, dated 2026-10-08):
  - KEYID is "a hexdigest of the SHA-256 hash of the canonical form of the key".
  - Root keyids "MUST be correct for the specified KEY. Clients MUST calculate each KEYID to verify this is correct".
  - Clients must ensure "only one unique key has that KEYID".
  - When counting the threshold, "each KEY MUST only contribute one SIGNATURE".

  — [TUF specification source, tuf-spec.md](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
- **The 1.x spec does not yet adopt TAP 12:** it lists TAPs 6, 9, 10 and 11 as adhered to. — [TUF specification source](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
- **TAP 12** ("Improving keyid flexibility", Status: Accepted, TUF-Version 1.1.0):
  - It proposes letting metadata owners compute keyids "using any method" so long as they are unique within a metadata file.
  - It lists keyid collision as a privilege-escalation risk. If root lists the same keyid for a snapshot key and a root key, the snapshot key can sign root.
  - It accepts that the same key may have different keyids in different files. — [TAP 12](https://github.com/theupdateframework/taps/blob/master/tap12.md)
- **GHSA-3633-5h82-39pq** (go-tuf < 0.3.2, published 2022-09-16, no CVE):
  - The same public key listed under two keyids, SHA-256(K_B) and SHA-512(K_B), let one signature count twice toward a threshold.
  - The advisory blames the non-standard `keyid_hash_algorithms` field.
  - It points to TAP 12's idea of deduplicating keys "on the basis of the fundamental parameters … rather than specific encodings (e.g., PEM)".

  — [GitHub Advisory GHSA-3633-5h82-39pq](https://github.com/advisories/GHSA-3633-5h82-39pq)
- **A separate, later go-tuf issue (CVE-2026-23992):** improper validation of the delegation threshold, so a threshold of 0 could disable integrity checks. Affects v2.3.0 and earlier, fixed in 2.3.1. — reported via [GitLab advisory DB](https://advisories.gitlab.com/pkg/golang/github.com/theupdateframework/go-tuf/v2/CVE-2026-23992/) (seen in search results only; primary advisory not fetched)

**DSSE (the envelope Sigstore and in-toto use)**
- `KEYID` is an "Optional, unauthenticated hint … It **MUST NOT** be used for security decisions; it may only be used to narrow the selection of possible keys to try." — [DSSE protocol.md](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)

**PKCS#11** (v3.2, OASIS Standard, 03 June 2026)
- **`CKA_UNIQUE_ID`** is generated by the token. It "MUST be unique across all objects visible to any particular session, and SHOULD be unique across all objects created by the token". "Reinitializing the token … MAY cause reuse". It is read-only. — [PKCS#11 v3.2 §4.4.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- **`CKA_CHECK_VALUE` (KCV):**
  - It is 3 bytes and "operates like a fingerprint, or checksum of the key". It is meant to "cross-check symmetric keys against other systems where the same key is shared".
  - "Two different keys can have the same CKA_CHECK_VALUE."
  - If a value is supplied in a creation template, it must match or the call returns `CKR_ATTRIBUTE_VALUE_INVALID`.
  - An application can suppress it with a zero-length template entry.

  — [PKCS#11 v3.2 §4.11](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- **KCV derivation by object type:**
  - Default for secret keys: the first 3 bytes of ECB encryption of one block of 0x00 (for example AES and DES3).
  - Generic secret and ChaCha20/Salsa20 keys: the first 3 bytes of **SHA-1 of `CKA_VALUE`**, an unkeyed hash of the secret.
  - Certificates: the first 3 bytes of SHA-1 of the certificate's `CKA_VALUE`.

  — [PKCS#11 v3.2 §4.6.3, §6.8, §6.10, §6.58](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)

**KMIP 2.1**
- **Unique Identifier:** "generated by the key management system". It is required to be unique only "within the identifier space managed by a single key management system", SHOULD be globally unique, and is immutable until destroyed.
- **Digest attribute:**
  - It is a digest of the Key Material. If that material is a structure, the digest is taken over its TTLV encoding.
  - The digest records which Key Format Type it was computed on, and a SHA-256 digest over the default format is mandatory if the attribute exists.
  - Additional digests for other formats or algorithms are allowed.
  - It is set by the *server* at creation or registration.
  - For symmetric keys this is an unkeyed hash of the secret material.

  — [KMIP 2.1 §4.21 "Digest" and "Unique Identifier"](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html)

**AWS KMS imported key material: a cloud identity for secret material derived from content**
- **Derivation and re-import check:** AWS KMS "assigns a unique identifier to the key material based on the KMS key ID and the imported key material". On re-import with a specified `KeyMaterialId`, KMS "Computes the identifier … Matches the computed identifier against the specified key material ID".
- **Format:** `KeyMaterialId` is 64 lowercase hex characters (256 bits).
- **Mismatch:** a mismatch fails with `IncorrectKeyMaterialException` ("not the same key material that was previously imported").
- **Multi-region:** replica Regions must import "the same key material".

  — [AWS KMS API: ImportKeyMaterial](https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html)

**Sequoia keystore: PKCS#11 backend now merged** **[PLAN.md correction]**
- **Status:**
  - Issue #28 ("Add support for signing/decrypting messages using PKCS#11 tokens") is *closed* (2025-12-15).
  - MR !126 "cryptoki: New backend." was merged 2025-12-19, and MR !133 was merged 2026-07-05.
  - The repo tree now has a `cryptoki/` backend crate, `sequoia-keystore-cryptoki` 0.1.1, LGPL-2.0-or-later.

  — [sequoia-keystore issue #28](https://gitlab.com/sequoia-pgp/sequoia-keystore/-/work_items/28); [MR !126](https://gitlab.com/sequoia-pgp/sequoia-keystore/-/merge_requests/126); [MR !133](https://gitlab.com/sequoia-pgp/sequoia-keystore/-/merge_requests/133)
- **How it works:**
  - The backend is off by default (`sequoia-keystore/cryptoki` feature) and currently needs the `pqc` branches of `sequoia-keystore` and `sq`.
  - Keys are generated and imported through a separate tool, `sq-cryptoki`.
  - Configuration is a TOML list of module paths.
  - Keys are addressed by OpenPGP fingerprint. The example shows `CKA_PUBLIC_KEY_INFO` populated on the public object.

  — [sequoia-keystore cryptoki/README.md](https://gitlab.com/sequoia-pgp/sequoia-keystore/-/blob/main/cryptoki/README.md)
- **How it handles the creation-time problem:** `sq-cryptoki` writes the fingerprint inputs into **`CKA_ID`**, for example `pgp:v4:eddsa:20251219T093551Z:oil-yard-given` (version, algorithm, creation timestamp and a label). — [sequoia-keystore cryptoki/README.md](https://gitlab.com/sequoia-pgp/sequoia-keystore/-/blob/main/cryptoki/README.md)

**Parsec KIM**
- The Key Info Manager stores "an `id`, which is the reference to a key in the specific provider" plus "attributes". It maps "key identities" (application and key *name*) to provider metadata in SQLite (recommended) or on disk (to be deprecated). — [Parsec book: Key Info Managers](https://github.com/parallaxsecond/parsec-book/blob/main/src/parsec_service/key_info_managers.md)

### Inferences
- **cakeys `pubkeyhash` is exactly RFC 7093 method 4 with an untruncated SHA-256.** cakeys can cite it as such: "SHA-256 SPKI digest, RFC 7093 §2 method 4". It is *not* the RFC 5280 SKI, nor the OpenSC/NSS `CKA_ID` convention, which hash only the BIT STRING with SHA-1.
- **Canonicalization ranking:**
  - **Precise:** RFC 9580 fingerprints, RFC 7638 and RFC 9679 thumbprints (both rely on a stated canonical encoding), RFC 7093 method 4 (DER is canonical) and TUF's canonical-JSON keyid.
  - **By implementation:** the GnuPG keygrip, which carries libgcrypt special cases for ECC.
  - **Weak or allocated:** the RFC 5280 SKI (a SHOULD, any method), `CKA_UNIQUE_ID`, the KMIP UID and the Parsec KIM (all name or assignment based).
- **Documented ambiguity failures:**
  - TUF/go-tuf (GHSA-3633-5h82-39pq) gave one key several IDs.
  - JWK/COSE warn about non-canonical encodings and about transformed keys such as 3·N.
  - OpenPGP's creation time makes the identity a property of the *packet*, not the key.
  - Short Key IDs were brute-forced (Evil32).
- **cakeys already defends against encoding ambiguity** by decoding and re-encoding SPKI through RustCrypto. This is the "fundamental parameters, not encodings" deduplication that TAP 12 and the GHSA recommend.
- **Sequoia's CKA_ID workaround** confirms PLAN.md's critique: an OpenPGP fingerprint cannot be derived from token material alone. Sequoia stores the missing creation time in a *mutable* locator attribute (CKA_ID). If that CKA_ID is rewritten, the fingerprint changes while the key does not.

### Gaps
- **Sigstore:** I did not fetch Sigstore docs on how `cosign`/Fulcio/Rekor compute key IDs. Only the DSSE "unauthenticated hint" rule was verified.
- **securesystemslib:** not checked for whether its keyid still hashes the `keyid_hash_algorithms` field.
- **go-tuf issue #368** (removing `keyid_hash_algorithms`): resolution not checked.
- **CVE-2026-23992:** seen only in search snippets.
- **TPM 2.0 Name** (nameAlg ‖ H(TPMT_PUBLIC)): taken from PLAN.md and not re-verified against TCG Part 1 this round.
- **Cloud KMS version IDs:** I did not verify how GCP Cloud KMS `cryptoKeyVersions` and Azure Key Vault versioned `kid`s are assigned. They are presumably server-assigned names, but that is unconfirmed.
- **RFC 7469 SPKI pinning:** not re-fetched.
- **AWS KMS:** the exact function behind `KeyMaterialId` is not published.

---

## Q2. Declarative and stateful key management: how do existing systems declare keys and record state?

### Takeaway
- **Locators, not identities.** Mainstream declarative and secret-management tools reference HSM keys by locator: Vault Enterprise managed keys and the OpenBao PKCS#11 seal use `key_label`/`key_id` plus `slot`/`token_label`.
- **Recipient public keys in Nix tools.** agenix, sops-nix and age plugins name recipients by public key or OpenPGP fingerprint.
- **Plaintext state.** Terraform's state file is a plaintext store that may contain secrets.
- **Few check identity before use.** None of the systems checked stores a content hash of a secret key, and few verify identity before use. The best is age-plugin-yubikey, which checks a 4-byte public-key tag before using a PIV slot.

### Cited Findings
- **HashiCorp Vault managed keys** (Enterprise only for PKCS#11):
  - The PKCS#11 backend identifies a key by `key_label` or `key_id` ("ID of the key as assigned by the HSM"), plus `slot` or `token_label`, `mechanism`, `pin` and a `library` stanza.
  - No parameter checks a key fingerprint.
  - `POST /sys/managed-keys/:type/:name/test/sign` signs and verifies random data. It may *generate* a key if none exists and generation is allowed.

  — [Vault API: managed keys](https://developer.hashicorp.com/vault/api-docs/system/managed-keys)
- **OpenBao PKCS#11 auto-unseal:** `key_label` (`CKA_LABEL`, required) and optional `key_id` (`CKA_ID`), one of `slot`/`serial`/`token_label`, and `mechanism` with "best available" as the default. The docs generate the key with `pkcs11-tool --keypairgen … --label`. — [OpenBao docs: seal/pkcs11.mdx](https://github.com/openbao/openbao/blob/main/website/content/docs/configuration/seal/pkcs11.mdx)
- **Terraform:**
  - "Terraform stores your state in a plaintext file, which includes any secret values you defined in your configuration."
  - Since 1.10, `ephemeral` variables, outputs and blocks are omitted from state.
  - Since 1.11, managed resources may have *write-only* arguments, which are never persisted.

  — [Terraform: Manage sensitive data](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)
- **No generic PKCS#11 Terraform provider found.** The registry has cloud-HSM key resources (e.g. Azure `azurerm_key_vault_managed_hardware_security_module_key`, IBM `ibm_hpcsmanagedkey`) and an HSM *integration* resource (`pingaccess_hsm_provider`). — [search results incl. pingaccess provider docs](https://iwarapter.github.io/terraform-provider-pingaccess/resources/pingaccess_hsm_provider); [Pulumi/IBM hpcsmanagedkey](https://www.pulumi.com/registry/packages/ibm/api-docs/hpcsmanagedkey/)
- **Terraform dependency lock file (`.terraform.lock.hcl`):**
  - **What it records:** it "tracks only provider dependencies" (not modules). For each provider it records `version`, `constraints` and a `hashes` list containing several checksum schemes (`h1:…` and `zh:…`).
  - **How it verifies:** on install, Terraform verifies "that each package it installs matches at least one of the checksums it previously recorded … returning an error if none of the checksums match".
  - **TOFU:** the docs describe the model as "trust on first use". With registry-signed checksums, Terraform treats all signed checksums as valid if one matches, and prints the signing key ID so the user can confirm it before committing the lock.
  - **Mirrors:** with mirror installs, only the local platform's checksum can be recorded.

  — [Terraform: Dependency Lock File](https://developer.hashicorp.com/terraform/language/files/dependency-lock)
- **SPIRE key managers:** the plugin docs list agent `disk` and `memory` key managers, and server `disk`, `memory`, `aws_kms`, `azure_key_vault`, `gcp_kms`, `hashicorp_vault` and `kmip` key managers. TPM appears only as the `tpm_devid` *node attestor* (agent and server), plus a TPM deployment walkthrough. **No TPM key manager exists.** — [spiffe/spire doc/ directory](https://github.com/spiffe/spire/tree/main/doc)
- **agenix:** encrypts secrets to SSH public keys listed in a rules file (the current README names it `agenix-rules.nix`). The NixOS module decrypts them at activation. — [agenix README](https://github.com/ryantm/agenix)
- **sops-nix:** recipients in `.sops.yaml` `creation_rules` are age public keys or GPG fingerprints. `ssh-to-age` converts SSH Ed25519 host keys, for example from `ssh-keyscan`, into age recipients. — [sops-nix README](https://github.com/Mic92/sops-nix/blob/master/README.md)
- **age-plugin-yubikey:**
  - An identity is a stub that encodes the YubiKey **serial**, PIV **slot** and a **tag** (`serial.to_le_bytes() ‖ slot ‖ tag`).
  - On connect, the plugin opens the key by serial and refuses with "stub mismatch" unless `recipient.static_tag() == self.tag`.
  - `TAG_BYTES = 4`, and `static_tag(pk) = SHA-256(pk)[0..4]`.

  — [age-plugin-yubikey src/key.rs](https://github.com/str4d/age-plugin-yubikey/blob/main/src/key.rs); [src/recipient.rs](https://github.com/str4d/age-plugin-yubikey/blob/main/src/recipient.rs); [src/native.rs](https://github.com/str4d/age-plugin-yubikey/blob/main/src/native.rs); [README](https://github.com/str4d/age-plugin-yubikey)
- **age-plugin-tpm:** encrypts to "age identities sealed by the TPM". Keys are created on the TPM and sealed outside it, with an optional PIN. — [age-plugin-tpm README](https://github.com/Foxboron/age-plugin-tpm)
- **systemd-creds:**
  - `--with-key=` is one of `host`, `tpm2`, `host+tpm2`, `null`, `auto`, `auto-initrd`. The default binds to both the TPM2 and `/var/lib/systemd/` host key.
  - `null` gives "no confidentiality nor authenticity", and is refused on SecureBoot+TPM2 systems.
  - Credentials can be bound to PCRs (`--tpm2-pcrs=`) or to signed PCR policies.

  — [systemd-creds(1) source](https://github.com/systemd/systemd/blob/main/man/systemd-creds.xml)
- **cert-manager:** a declarative `Certificate` resource. `rotationPolicy` defaults to `Always` from v1.18.0 (formerly `Never`), so the private key Secret is regenerated on reissue. — [cert-manager docs: Certificate](https://github.com/cert-manager/website/blob/master/content/docs/usage/certificate.md)
- **SPIRE:** the agent `KeyManager "disk"` "generates a key pair for the agent's identity, storing the private key on disk". The configuration is a directory, with no key identity pinning. — [SPIRE plugin_agent_keymanager_disk.md](https://github.com/spiffe/spire/blob/main/doc/plugin_agent_keymanager_disk.md)
- **p11-glue shared trust model:** a declarative system trust store. Attached certificate extensions "are associated with the subject public key info", and blacklisting covers keys or certificates. — [p11-glue: Storing Trust Model](https://p11-glue.github.io/p11-glue/doc/storing-trust-policy/storing-trust-model.html)
- **Sequoia cryptoki backend:** its only declarative input is `[[modules]] path = …`. Key creation is imperative (`sq-cryptoki key generate`). — [sequoia-keystore cryptoki/README.md](https://gitlab.com/sequoia-pgp/sequoia-keystore/-/blob/main/cryptoki/README.md)

### Inferences
- **Terraform vs cakeys.** Terraform's state file is the nearest "lock" analogue in IaC. It is a *cache of provider-reported attributes* (secrets included), not a set of identities recomputed before every use. cakeys' rule that "the lock never holds token outputs, only their hashes" matches the direction Terraform has taken with ephemeral and write-only values.
- **The Terraform dependency lock is the closest IaC precedent for DESIGN §10's "like a dependency lock" framing.** It also stores several hash schemes per artefact and accepts a match on *any one* of them, and it names its first install as TOFU.
  - cakeys is stricter in two ways. Every locked scheme that can be computed is checked, and disjoint schemes never link.
  - Terraform's "any one matches" rule is safe only because every scheme hashes the same package bytes. cakeys' commitment schemes hash different *outputs* of one secret, so a mismatch in any of them should still fail. It does today.
- **Vault/OpenBao:** "test/sign" checks only that the key works. It cannot detect that a label now points to *different* material, which is exactly the label-reuse risk cakeys removes.
- **age-plugin-yubikey is the closest small-scale precedent** for cakeys' pre-use check: a locator (serial, slot) plus a content tag checked before use. Its tag is only 32 bits of SHA-256, enough against accidents but not against an adversary. cakeys uses 256-bit SPKI hashes.
- **Nix secret managers address recipients by public key.** None treats an HSM-resident key as an input with a fixed hash. cakeys fills that gap: a pseudo-FOD over token-resident material.
- **Usage policy as part of identity?**
  - systemd-creds and TPM-sealed age identities bind *usage* to PCR state.
  - cakeys binds usage through the spec digest and live attribute checks.
  - cakeys could treat a TPM-backed realisation's `authPolicy` (PCR policy) as part of its spec digest, as the TPM Name does natively. This is unverified this round.

### Gaps
- **Not researched (budget):** Keyfactor/EJBCA crypto-token configuration as code, Thales CipherTrust and Entrust KeyControl Terraform providers, AWS CloudHSM configuration-as-code, Ansible/Salt HSM modules, OpenSSL `pkcs11-provider` URI handling, and the internals of SPIRE's `tpm_devid` node attestor and `kmip` key manager. Only their existence was confirmed.
- **sops metadata:** not confirmed from a primary source (the `getsops.io/docs` page fetched without that content). This covers per-recipient entries, the `mac` field and `lastmodified`.
- **Nix FOD-for-secrets patterns** (e.g. impure derivations, `requiredSystemFeatures` gating): no published projects found or checked.

---

## Q3. Does any system commit to secret-key identity with an on-device MAC/KCV like cakeys' commitments? What are the exact KCV definitions?

### Takeaway
- **KCVs are the industry's on-device commitment for secret keys.** They are short, at most 3 bytes for the legacy zero-block method and at most 5 bytes for the CMAC method, computed over a fixed all-zero (or all-0x01) input, and published raw.
- **Where cakeys differs:** it uses domain-separated labels, stores only SHA-256 of the full output, and has several schemes. It is stronger as an identity but not interoperable with vendor KCVs.
- **Unkeyed hashes elsewhere.** PKCS#11 generic-secret KCVs and KMIP Digests hash the secret itself, which RFC 9679 warns against for low-entropy keys.
- **Closest cloud analogue:** AWS KMS `KeyMaterialId`, a 256-bit identifier derived from the key ID and the key material, verified on re-import.

### Cited Findings
- **ANSI X9.24-1-2017 Annex A and PCI PIN Security Req. 15-1** (as quoted by Wikipedia; primary is paywalled):
  - **Two methods.** "TDEA may use either method. AES must only use the CMAC method."
  - **Method 1:** encrypt "an all binary zeros block … using the leftmost n-bits of the result; where n is at most 24 bits (6 hex digits/3 bytes)".
  - **Method 2:** CMAC (ISO 9797-1 / NIST SP 800-38B) over "an all binary zeros block", leftmost n bits, "where n is at most 40 bits (10 hexadecimal digits)", using the key's own block cipher.

  — [Wikipedia: Key checksum value](https://en.wikipedia.org/wiki/Key_checksum_value) (secondary, quoting X9.24-1-2017 Annex A and PCI PIN v3.1 Req 15-1)
- **GlobalPlatform / GSMA KCV:**
  - DES: encrypt 8 bytes of 0x00 and keep 3 bytes.
  - AES: encrypt 16 bytes of **0x01** and keep 3 bytes, unlike the zero block of X9.24.

  — [Wikipedia: Key checksum value](https://en.wikipedia.org/wiki/Key_checksum_value) (quoting GlobalPlatform Card Spec 2.3.1 §B5, GSMA SGP.02 Annex F)
- **AWS Payment Cryptography:**
  - TDES KCV: encrypt 8 zero bytes and keep the 3 high-order bytes.
  - AES KCV: "computed using a CMAC algorithm where the input data is 16 bytes of zero and retaining the 3 highest order bytes".
  - HMAC KCV: "the hash selected at key creation on a zero-length message, taking the leftmost 3 bytes".
  - It notes that KCV's integrity role "is now included as part of key block formats such as TR-31".
  - `ImportKey` takes `KeyCheckValueAlgorithm`.

  — [AWS Payment Cryptography terminology](https://docs.aws.amazon.com/payment-cryptography/latest/userguide/terminology.html); [ImportKey API](https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_ImportKey.html)
- **TR-31 optional blocks:** an optional block `KC` "contains a key check value of the key that is in the key block", and `KP` contains the KCV of the KBPK (key-block protection key, the wrapping KEK). IBM notes KC is "not valid for single-length DES keys or HMAC keys". A PCI presentation describes KC/KP as *CMAC* KCVs. — [IBM CCA docs (search snippet)](https://www.ibm.com/docs/en/linuxonibm/lxcc/wskc_r_l0wskc303.html); [PCI SSC presentation on X9.143 key blocks](https://www.pcisecuritystandards.org/day-2_track-2_8_x9-143-and-pci-pin-compliant-key-blocks_richard-kisley_approved_8-19-22_v2dm/)
- **Older vs CMAC KCV:** an FSE 2014 talk notes that ANSI X9.24-1:2009 defined the check value as the leftmost six hex digits of encrypting a zero block, and that the CMAC-based value is a different construction. — [FSE 2014 slides](https://www.iacr.org/workshops/fse2014/slides-05_4.pdf) (search snippet)
- **PKCS#11 3.2 (cited in Q1):** the 3-byte `CKA_CHECK_VALUE`. For AES/DES3 it is ECB(0x00 block), and for generic secrets and ChaCha20 it is SHA-1(`CKA_VALUE`). It must be supplied "even if the encryption operation for the key is forbidden (i.e. when CKA_ENCRYPT is set to CK_FALSE)". — [PKCS#11 v3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- **KMIP Digest:** a server-set SHA-256 over the key material (or its TTLV), recording the key format type. — [KMIP 2.1 §4.21](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html)
- **AWS KMS `KeyMaterialId`:** 64 hex characters, "based on the KMS key ID and the imported key material". It is recomputed and compared on re-import, and a mismatch raises `IncorrectKeyMaterialException`. — [AWS KMS ImportKeyMaterial](https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html)
- **RFC 9679** on thumbprinting symmetric keys: only random keys of at least 128 bits, never low-entropy secrets. — [RFC 9679 Security Considerations](https://www.rfc-editor.org/rfc/rfc9679.html)

### Inferences
- **Yes, on-device commitments to secret keys are standard practice.** That is the KCV, but it is designed as a checksum (3–5 bytes, collisions expected), not an identity.
- **cakeys schemes vs standard KCVs:**
  - cakeys `cmac` is CMAC over a label, not the zero block.
  - cakeys `kcv-ecb` is ECB over the first 16 bytes of SHA-256(label), not 0x00 or 0x01 blocks.
  - So none of cakeys' AES schemes reproduce an X9.24, PKCS#11 or GlobalPlatform KCV.
  - The design choice is defensible. A fixed public input such as the zero block makes E_K(0) or CMAC_K(0) a value that any other protocol or vendor KCV might also expose, whereas a domain-separated label avoids that collision.
- **Possible addition:** record standard KCVs as *non-identity aliases* (call them hints, in DSSE's sense). Candidates are `x9.24-cmac-kcv` (5 bytes), `p11-check-value` (`CKA_CHECK_VALUE` as read) and `kcv-zero-ecb` (3 bytes). They would cross-check against key ceremony paperwork, TR-31 KC blocks and AWS Payment Cryptography output. They must never satisfy `verify`, and never link material. This also gives a cheap cross-check that a token's own `CKA_CHECK_VALUE` matches cakeys' independently computed ECB(0) on AES keys. A mismatch would expose a buggy or lying token.
- **Notable:** PKCS#11 says `CKA_CHECK_VALUE` is supplied even when `CKA_ENCRYPT=false`. Where a token implements it, it is a usage-bit-free on-device signal for AES. cakeys' commitment schemes need `CKA_SIGN`/`ENCRYPT`/`WRAP`, which forces the "wrap-rebind" or "weak mode" paths. Reading `CKA_CHECK_VALUE` could cover the "no usable usage bit" case as a **weak, opt-in** mode, much as `token-specific` is planned.
  - **Caveat:** 24 bits is far too short against an adversary.
  - **Caveat:** the value is computed by the token (trusted), not challenged.
- **Avoid unkeyed hashes of secrets.** For generic secrets, PKCS#11 KCVs and KMIP Digests hash the secret directly. cakeys' HMAC commitment with a label is the RFC 9679-consistent choice. Keep refusing to hash private data objects' values (DESIGN.md already does).
- **AWS KMS `KeyMaterialId` validates cakeys' approach:**
  - The identifier is derived from content but scoped. It is "based on" key ID plus material, comparable to cakeys' label `<label>/<scheme>/<keyType>/<bits>`.
  - Re-import compares a computed value with an expected one, which is If-Match semantics.

### Gaps
- **Exact normative text is paywalled** for X9.24-1-2017 Annex A, X9.143-2022 and TR-31:2018 (the KC/KP optional block format, including the algorithm-indicator byte that distinguishes legacy from CMAC KCVs). Only secondary and vendor sources were available. IBM's page renders by JS and was seen only via search snippet.
- **Undocumented:** how AWS derives `KeyMaterialId` (hash function, inputs) is not disclosed.
- **Not checked:** whether any HSM vendor exposes a *labelled* MAC-based key identity (as opposed to a KCV) as a first-class attribute.

---

## Q4. Documented failure modes and attacks: key substitution, fingerprint collisions, TOFU, stale state

### Takeaway
- **Most common failure: multiple non-canonical identifiers for one key,** which breaks counting and deduplication (go-tuf).
- **Truncated or short identifiers** can be brute-forced (OpenPGP short IDs, Evil32) or are expected to collide (KCVs).
- **Identity that depends on metadata outside the key:** the creation time in OpenPGP fingerprints, a sort order or exponent padding in JWK.
- **Unauthenticated key-ID hints** (DSSE).
- **TOFU first-use acceptance** (SSH, RFC 4251).
- **Plaintext state** (Terraform).
- **Locators trusted as identity** (Vault/OpenBao labels).

### Cited Findings
- **Duplicate keyids defeat threshold counting:** the same key under SHA-256 and SHA-512 keyids counted twice in go-tuf < 0.3.2. — [GHSA-3633-5h82-39pq](https://github.com/advisories/GHSA-3633-5h82-39pq)
- **Keyid collisions across roles escalate privilege:** a snapshot key can be used to sign root if both share a keyid. — [TAP 12 Rationale](https://github.com/theupdateframework/taps/blob/master/tap12.md)
- **Short key IDs can be forged:** 32-bit OpenPGP key ID collisions in 4 s on a GPU, and key servers accepted the duplicates (historical; GnuPG since patched). — [Evil 32](https://evil32.com/)
- **Key IDs collide by spec:** RFC 9580 says Key IDs can collide and should not be assumed unique. — [RFC 9580 §3.3, §5.5.4](https://www.rfc-editor.org/rfc/rfc9580.html#section-3.3)
- **KCVs collide by design:** "Two different keys can have the same CKA_CHECK_VALUE." — [PKCS#11 v3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- **Encoding ambiguity changes thumbprints:** RSA `e` "AAEAAQ" vs "AQAB". — [RFC 7638 Security Considerations](https://www.rfc-editor.org/rfc/rfc7638.html)
- **Transformed keys evade thumbprint blocklists** (modulus 3·N). — [RFC 9679](https://www.rfc-editor.org/rfc/rfc9679.html)
- **Key-ID hints must not drive security decisions.** — [DSSE protocol.md](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md)
- **TOFU:** RFC 4251 describes accepting "a host key without checking the first time a host is connected, save the key in a local database, and compare against that key on all future connections". It notes that unchecked first connections expose users to man-in-the-middle attacks. — [RFC 4251 §4.1](https://www.rfc-editor.org/rfc/rfc4251.html#section-4.1)
- **Secrets in state:** Terraform state is plaintext and contains secrets, and `terraform output -json/-raw` shows sensitive values in plaintext. — [Terraform: Manage sensitive data](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)
- **Recycled unique IDs:** PKCS#11 `CKA_UNIQUE_ID` values MAY be reused after `C_InitToken`. — [PKCS#11 v3.2 §4.4.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/os/pkcs11-spec-v3.2-os.html)
- **Unverified SKI linkage:** RFC 5280 "Applications are not required to verify that key identifiers match". — [RFC 5280 §4.2.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2)
- **Silent behaviour change on upgrade:** cert-manager changed the default `rotationPolicy` to `Always` in v1.18.0, so a declarative config with no edits regenerates keys after an upgrade. — [cert-manager docs](https://github.com/cert-manager/website/blob/master/content/docs/usage/certificate.md)
- **Unauthenticated fallback key:** the systemd-creds `null` key provides no confidentiality or authenticity, and is refused only on SecureBoot+TPM2 systems. — [systemd-creds(1)](https://github.com/systemd/systemd/blob/main/man/systemd-creds.xml)

### Inferences
- **Lessons for cakeys' multi-scheme lock (from TUF):**
  1. Never treat two IDs of different schemes as two objects. cakeys already links only through a shared scheme.
  2. If cakeys ever gets anything count-like (k-of-n tokens, "the key exists on ≥2 tokens", lock GC, dedupe), count *objects* by verified material, not IDs.
  3. Add a lock-level invariant: two different `objects.<name>` with an equal ID under the same scheme should be an error or warning ("same material declared twice"). It is the analogue of TUF's "only one unique key has that KEYID".
- **cakeys' first-use `got:` flow is TOFU.** The lock commit is the trust decision. Possible mitigations:
  - Require the first-use output to be reviewed. It already needs `--update-lock`.
  - For TPM, attach `TPM2_Certify` / EK-chain evidence to provenance.
  - For PKCS#11 HSMs with attestation (e.g. YubiKey PIV attestation, vendor key attestation), record the attestation certificate's hash as provenance.
- **Known gap H1 is a binding gap that allows key substitution** (my inference, not taken from a cited source). SoftHSM EC private keys take their identity from a public object that is *asserted* to match the private key under the same locator, not *proven* to match it.
  - **Fix:** proof of possession. Sign a fixed, domain-separated message with the private key and verify it against the locked SPKI. That is a sign-based commitment for asymmetric keys, analogous to cakeys' MAC commitments.
  - **Limit:** it needs `CKA_SIGN` on the private key, so decrypt-only and derive-only private keys stay uncovered. Those would need a decrypt or ECDH-based challenge instead.
- **cakeys' frozen scheme names avoid the cert-manager problem.** A newer cakeys can add a scheme, which is only a note, but cannot change what an existing lock means. cert-manager's v1.18 default flip shows the failure mode that this rule prevents.
- **Stale state:**
  - Terraform drift is resolved by refresh.
  - cakeys resolves it by recomputing before every use, and by spec-digest comparison (exit 14).
  - **Remaining staleness risk:** Nix caching. A cached consumer is not rebuilt, so the token is not re-checked (README). Pair runtime `cakeys-check-*` units with any long-lived cached artefact.

### Gaps
- **Not searched for:** documented real-world incidents of HSM label reuse or substitution (e.g. CVEs in PKCS#11 consumers that pick the wrong object by label).
- **Not checked:** PKCS#11 attacks on KCV leakage (e.g. Clulow/Bortolozzo-style attribute attacks).

---

## Q5. Is anything doing essentially what cakeys does? Comparison matrix, plus lessons to adopt or avoid

### Takeaway
- **No surveyed system combines all of cakeys' features.** These are a protocol-neutral content hash for asymmetric keys, *secret* keys and data objects; a declarative spec with a canonical digest; a lock of identities plus provenance; and mandatory recomputation before use, including inside the Nix sandbox.
- **Partial overlaps:**
  - Sequoia keystore, which now has PKCS#11; identity is the OpenPGP fingerprint, and it is imperative.
  - AWS KMS `KeyMaterialId` (cloud only, secret material, If-Match on re-import).
  - age-plugin-yubikey (serial+slot locator plus a 4-byte pubkey tag checked before use).
  - TUF (keyids recomputed by clients, canonical form).
  - GnuPG keygrip (protocol-neutral, SHA-1, asymmetric only).

### Cited Findings
- **Sequoia keystore cryptoki:**
  - OpenPGP fingerprint identity, with a module-path TOML config.
  - Imperative `sq-cryptoki key generate`.
  - Fingerprint inputs stored in `CKA_ID`.
  - Gated by a feature flag and the `pqc` branches.

  — [sequoia-keystore cryptoki/README.md](https://gitlab.com/sequoia-pgp/sequoia-keystore/-/blob/main/cryptoki/README.md)
- **GnuPG keygrip:** SHA-1 of algorithm-dependent public parameters, computed for public, private and shadowed (card-stub) keys alike. — [libgcrypt pubkey.c](https://github.com/gpg/libgcrypt/blob/master/cipher/pubkey.c)
- **AWS KMS:** a content-derived, 256-bit-hex `KeyMaterialId`, compared on re-import. — [AWS KMS ImportKeyMaterial](https://docs.aws.amazon.com/kms/latest/APIReference/API_ImportKeyMaterial.html)
- **age-plugin-yubikey:** serial, slot and 4-byte SHA-256 tag, checked on connect. — [age-plugin-yubikey src/key.rs](https://github.com/str4d/age-plugin-yubikey/blob/main/src/key.rs)
- **TUF:** clients MUST recompute keyids, and keyids are SHA-256 of the canonical key form. — [TUF spec](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)
- **Parsec KIM:** maps names to provider IDs. — [Parsec book KIM](https://github.com/parallaxsecond/parsec-book/blob/main/src/parsec_service/key_info_managers.md)
- **Vault/OpenBao:** label- and ID-located PKCS#11 keys with no fingerprint parameter. — [Vault managed keys](https://developer.hashicorp.com/vault/api-docs/system/managed-keys); [OpenBao pkcs11 seal](https://github.com/openbao/openbao/blob/main/website/content/docs/configuration/seal/pkcs11.mdx)
- **KMIP:** server-assigned UID plus a server-computed Digest. — [KMIP 2.1](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html)
- **Search for exact matches:** an extended search for "declarative HSM key provisioning lock file content-addressed PKCS#11" found no project matching the combination. The nearest results were HSM provisioning scripts (e.g. swedenconnect `hsm-support-scripts`) and patents on HSM fleets. — [swedenconnect credentials-support key-generation README](https://github.com/swedenconnect/credentials-support/blob/main/hsm-support-scripts/key-generation/README.md)

### Inferences

**Comparison matrix.** Derived from the findings above. "?" means not verified this round, "—" means not applicable or absent.

| System | Identity scheme (asymmetric) | Secret-key identity | Declarative spec | Lock / state file | Verify before use | Multi-backend HAL | Provenance recorded | Reproducible / same ID across tokens & time |
|---|---|---|---|---|---|---|---|---|
| **cakeys** | SHA-256(canonical DER SPKI) = RFC 7093 m4; plus certhash, valuehash | On-token HMAC/CMAC/ECB/KW over a domain-separated label; SHA-256 of the output stored | `keys.toml` objects + specs; canonical spec digest | `keys.lock`: IDs, type, label, spec digest, per-token provenance | Yes, every use; also in the Nix sandbox (pseudo-FOD) | PKCS#11 now (SoftHSM, tpm2-pkcs11, p11-kit, ykcs11); TPM native planned | module, token, provider, mode, mechanisms, version | Yes by design (frozen schemes); same secret gives the same ID on any token supporting the scheme |
| GnuPG keygrip | SHA-1 of algorithm-specific params (libgcrypt) | — | — | `private-keys-v1.d/<grip>.key` (key or card stub) | Implicit (agent) | scdaemon cards + soft keys | — | Yes for the same params (no timestamp); SHA-1 |
| OpenPGP v4/v6 fpr | SHA-1 / SHA-256 of key packet incl. creation time | — | — | keyring | Signature verification | — | creation time in packet | Only if the creation time is preserved |
| Sequoia keystore (+cryptoki, 2025–26) | OpenPGP fingerprint | — | Module-list TOML only; TPM YAML templates (per PLAN.md) | Cert store; fingerprint inputs in `CKA_ID` | Implicit (key lookup by fpr) | softkeys, gpg-agent, openpgp-card, TPM, PKCS#11 | ? | Depends on `CKA_ID`-stored timestamp |
| SSH fingerprints | SHA-256 (MD5 historical) of key blob | — | — | known_hosts (TOFU) | Yes (host key compare) | agent | — | Yes |
| X.509 SKI | SHA-1 of BIT STRING or "any method" | — | — | — | Not required | — | — | Not guaranteed |
| JWK / COSE thumbprint | SHA-256 of canonical JSON / deterministic CBOR | Defined for `oct`/`kty 4`, but must be high-entropy (exposes an unkeyed hash) | — | — | App-defined | — | — | Yes if canonical |
| TUF keyid | SHA-256 of canonical key JSON | — | Root metadata (signed) | Signed metadata | Clients MUST recompute | — | — | Yes; broken by multiple keyids (GHSA) |
| DSSE / Sigstore keyid | Unauthenticated hint | — | — | — | Must not be relied on | — | — | — |
| PKCS#11 attrs | `CKA_ID` (convention: SHA-1 SKI); `CKA_UNIQUE_ID` (token-assigned) | `CKA_CHECK_VALUE`, 3 bytes | — | — | — | — | — | UNIQUE_ID not portable; KCV collides |
| KMIP 2.1 | Server UID; Digest SHA-256 of key material (format-dependent) | Digest = unkeyed hash of secret | Templates/attributes | Server DB | ? | Server-defined | Key Format Type in Digest | Digest depends on format |
| Payment KCV / TR-31 | — | ECB(0) ≤3 B or CMAC(0) ≤5 B; KC/KP blocks | Key block headers | — | Manual compare at ceremony/import | — | — | Yes, but checksum-grade |
| AWS KMS KeyMaterialId | — | 64-hex ID from (key ID, material) | API/IaC | Service-side | On re-import (If-Match-like) | AWS only | ? | Yes within the key ID |
| Parsec | KIM: name → provider id | — (no symmetric support per PLAN.md) | PSA attributes | KIM sqlite | No | PKCS#11, TPM, … | — | No (name-based) |
| Vault Ent. / OpenBao seal | `key_label`/`key_id` locator | Locator only | HCL config | Vault storage | test/sign (usability only) | PKCS#11, cloud KMS | — | No |
| Terraform | Provider attributes | Provider attributes (may be plaintext in state) | HCL | `terraform.tfstate` (plaintext); `.terraform.lock.hcl` pins provider version + multi-scheme hashes (`h1:`, `zh:`) | Provider packages: must match ≥1 locked checksum (TOFU); resources: refresh/plan drift | Many providers | Provider version, constraints, signing key ID shown at init | Providers: yes (hash-pinned); resources: no |
| agenix / sops-nix | Recipient pubkey / GPG fpr | — | Nix rules / `.sops.yaml` | Encrypted files | Decrypt succeeds or fails | age, GPG, KMS (sops) | — | Yes (pubkey) |
| age-plugin-yubikey | Locator (serial, slot) + 4-byte SHA-256 tag | — | — | Identity stub file | Yes, tag checked on connect | YubiKey PIV only | serial | Yes |
| systemd-creds | — | Bound to TPM2/host key/PCR policy | Unit `LoadCredentialEncrypted` | Credential blob | Decrypt/auth on load | TPM2, host key | — | Bound to the machine |
| cert-manager / SPIRE | Keys regenerated (ephemeral identity) | — | CRDs / HCL | k8s Secret / disk | — | SPIRE: disk, memory, AWS/GCP/Azure KMS, Vault, KMIP key managers; TPM only for node attestation | — | No, by design |

**Ideas worth adopting:**
1. **Name the `pubkeyhash` construction by standard**, "RFC 7093 §2 method 4, SHA-256, untruncated". Optionally add new schemes `jwk-thumbprint` (RFC 7638) and `cose-thumbprint` (RFC 9679), exportable in RFC 9278 / RFC 9679 URI form (`urn:ietf:params:oauth:jwk-thumbprint:sha-256:…`, `urn:ietf:params:oauth:ckt:sha-256:…`) for JOSE/COSE/OAuth DPoP consumers.
   - Their inputs are canonical JWK JSON and deterministic COSE CBOR, *not* DER SPKI, so they must be computed separately.
   - `pubkeyhash` cannot be relabelled as a JWK/COSE thumbprint.
   - Under DESIGN.md §10, a different computation means a new scheme name.
2. **Record standard KCVs as non-identity hints** (DSSE's "unauthenticated hint" model): X9.24 CMAC KCV, ECB-zero KCV, and the token's own `CKA_CHECK_VALUE`. Use them for key-ceremony and TR-31 cross-checks, and as a consistency test on tokens. Never use them to link or verify.
3. **Add a lock invariant that one CA-ID (per scheme) maps to one object name**, the TUF "only one unique key has that KEYID" rule. Count by object, not by ID, wherever cakeys counts.
4. **Proof-of-possession for asymmetric keys.** Sign a fixed label with `CKM_ECDSA`/`EdDSA`/RSA-PSS and verify against the locked SPKI, which closes H1. It parallels the secret-key commitments. Randomized signatures are fine, since verification is all that matters, but store nothing derived from the signature.
5. **Make first-use (TOFU) explicit:** attach attestation evidence where the backend offers it (`TPM2_Certify` over the Name; vendor HSM or YubiKey attestation certificates) as provenance, and print it at `--update-lock` time. This mirrors SSH's advice to verify fingerprints out-of-band.
6. **Borrow AWS KMS's If-Match semantics for import.** Importing known material onto another token with `--if-match <CA-ID>` should create, compute, compare and destroy on mismatch. cakeys already does create-then-destroy on identity failure.

**Things to avoid:**
- **No identity inputs outside the key material and the frozen label.** Creation time (OpenPGP), mutable `CKA_ID` metadata (Sequoia's `pgp:v4:…:timestamp` workaround), and server- or token-assigned IDs (KMIP UID, `CKA_UNIQUE_ID`, Parsec KIM) are all out.
- **No unkeyed hashes of secret material** (PKCS#11 generic-secret KCV, KMIP Digest, JWK `oct` thumbprints). Keep using MACs over a label.
- **No per-object choice of hash algorithm** that yields several "equal" IDs for one key (go-tuf `keyid_hash_algorithms`). cakeys' fixed per-scheme definition, where a new computation means a new scheme name, is the right model. TAP 12's "any method" flexibility should *not* be copied for the identity itself.
- **Do not truncate identifiers below collision-resistant length** (32-bit OpenPGP short IDs, 3-byte KCVs, the 4-byte age tag). They are acceptable only as UI hints.
- **Never let secret values or token outputs into the lock,** unlike Terraform state. DESIGN.md already enforces this.

**Corrections to PLAN.md's survey:**
- **Sequoia:** now has a merged PKCS#11 ("cryptoki") backend (Dec 2025 and Jul 2026). Issue #28 is closed. The backend stores OpenPGP fingerprint inputs in `CKA_ID`.
- **PKCS#11 `CKA_CHECK_VALUE`:** described as "for secret keys and certificates". Correct, but note the generic-secret/ChaCha20 variant is an unkeyed SHA-1 of the value, and the certificate variant is SHA-1 of the DER.
- **PKCS#11 3.2 is now an OASIS Standard** (03 June 2026). PLAN mentions only 3.0 and 2.40 features.

### Gaps
- **Not verified this round:** the matrix cells for the Sequoia TPM YAML templates and Parsec's symmetric support. Those come from PLAN.md or remain "?".
- **No exhaustive registry or GitHub search** was done for niche projects, e.g. "hsm-as-code" or "pkcs11 terraform provider" community repos. A small unknown project with a similar design cannot be ruled out.
- **Not researched:** Keyfactor/EJBCA, Thales/Entrust/CloudHSM config-as-code and OpenSSL pkcs11-provider, due to the tool-call budget.
