# Open and parked items

This file lists everything that is not built or not decided, in one place. Each item names the
place where its context lives. "archive" means `docs/archive/`, and git history holds the
earlier plans (PLAN.md, NEXT.md, MIGRATE.md, docs/PROVIDERS.md, WORKPLAN.md).

## Identity coverage: what objects cakeys can take

- **A matrix of what can be created, and at what assurance** (2026-11-14). The plan is to
  generate PKCS#11 objects over every sane combination of class, key type and attributes (usage
  bits, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`, `CKA_ALLOWED_MECHANISMS`, …), by property test or by
  fuzzing, on every reference token. The matrix then records which identity mode, schemes,
  binding and assurance each object gets, or the reason that it gets none. The goal is that
  keys.toml can declare any sane object, even one with low assurance, and that the matrix states
  what that assurance is. Clean fixtures that cakeys made itself are no evidence of what
  deployments need. **Built for SoftHSM and kryoptic** (2026-11-15, PLAN.md A4):
  `spec-coverage/objects/<token>.toml` holds 1544 objects for each token, and the test adopts
  each object the way a legacy key arrives (crates/cli/tests/object_matrix/). The objects are
  generated keys, imported secret keys, imported private keys (grouped by where their public
  half is), certificates and data objects. The matrix also runs on tpm2-pkcs11 over swtpm
  (`tpm2-pkcs11+swtpm.toml`), where most rows record that the module refuses to hold the object.
  That module generates EC keys only with `CKA_SIGN` and RSA keys only with both `CKA_SIGN` and
  `CKA_DECRYPT`, and it generates no secret key at all. It takes no private key through
  `C_CreateObject`. It stores an imported secret key as a software blob without
  `CKA_VALUE_LEN`, which cakeys now refuses as unverifiable (15) instead of reporting a conflict.
  It holds data objects only as private objects and certificates only as public objects. The
  findings of the matrix are fixed:
  - A proof chooses its mechanism within the key's `CKA_ALLOWED_MECHANISMS` (raw `CKM_ECDSA`,
    raw `CKM_RSA_PKCS` over a `DigestInfo`, PKCS #1 v1.5 decryption). Every binding names the
    mechanism that the list lacks (15) instead of failing inside the token. A declared list
    narrows the commitments that cakeys computes (DESIGN §3.4, §3.6).
  - A list that holds a mechanism without a name can be read (patch
    `cryptoki-allowed-mechanisms-unnamed`).
  - An HMAC-typed key is generated with `CKM_SHA*_KEY_GEN` (on kryoptic; SoftHSM 2.7 refuses
    that generation at validation).
  - An imported EC or Edwards private key whose importer wrote only the certificate beside it
    takes its public half from the certificate (DESIGN §3.2). Any stand-in must be a key of the
    private key's own type and curve (13 otherwise).
- **An imported EC private key with nothing beside it has no identity** (11, object matrix:
  `public=none`). `pkcs11-tool --write-object --type privkey` writes exactly that for an EC key,
  and a PKCS#11 EC private key carries no `CKA_EC_POINT` (kryoptic computes the point for an
  Edwards key; SoftHSM does not). Today, the fix is to write the public key object or the
  certificate beside the private key. For a non-sensitive key, the host could compute the point
  from `CKA_VALUE`, but that reads the private key out of the token. This is not done.
- **Upstream cryptoki: keep an unnamed `CKA_ALLOWED_MECHANISMS` entry.** In 0.12.1,
  `MechanismType::try_from` refuses every value that it has no name for. These values include
  vendor mechanisms (CloudHSM's EdDSA is `0x80001057`, CLOUD_HSM.md) and some 385 standard ones
  (`CKM_DES3_CBC_PAD`), so the read of the whole attribute fails. Upstream main (6cc2278 and
  later), which cakeys builds against, accepts vendor values but not unnamed standard values.
  Our patch keeps the raw value. The patch is a candidate for an upstream PR, and it is not
  filed.
- **Weaker identity modes for keys cakeys did not create** (DESIGN §3.4). Non-extractable keys
  with no usage bit that a commitment can use (keys that may only derive, keys that may only
  unwrap, and keys whose allowed mechanisms all take a random IV) are common, especially among
  existing and legacy keys, and cakeys refuses them today (17). The candidate modes are
  `commit-at-creation`, `host-at-import` and `token-specific` (for example, a TPM Name). Each
  mode must rank below `wrap-rebind` and must report that cakeys does not check the token again.
  The matrix above shows which cases need these modes.
- **X25519 / Montgomery keys**: `id.rs` has no key type for them (the work is an SPKI identity
  and X25519 on the host). ykcs11 cannot generate them anyway.
- **More Triple DES** (2026-11-15). cakeys identifies `CKK_DES3` keys by the two check values
  (`kcv-ecb`, `kcv-ecb-dec`, `CKM_DES3_ECB`). It refuses the other Triple DES keys that payment
  and banking HSMs also hold:
  - *Sign-only DES3 keys* (MAC keys: ISO 9797-1 retail MAC, CMAC) that are non-extractable get
    17, because no commitment applies to them. SoftHSM 2.7 offers `CKM_DES3_CMAC`
    (`pkcs11-tool -M` [run]), but cryptoki has no `MechanismType` constant or `Mechanism` for it
    (0.12, and main at the pinned revision), so the mechanism is also missing from SoftHSM's
    profile. The work is a cryptoki patch beside the KWP patch (and its upstream PR), a `cmac`
    commitment over DES3, and a regenerated profile. kryoptic 1.5 and tpm2-pkcs11 have no DES at
    all (15).
  - *Two-key Triple DES* (`CKK_DES2`, 16 bytes: the "double-length" keys of payment schemes,
    which many HSMs store this way) is an unknown key type (17). It would use the same
    mechanisms (`CKM_DES3_ECB`) and its own key type in the label, with `des::TdesEde2` as the
    oracle.
  - *Single DES* (`CKK_DES`) is not planned.
- **Moving private data objects** (2026-11-15). `cakeys` identifies a private data object
  (`valuehash`) when its spec declares `CKA_PRIVATE = true`. camigrate moves no such object (15,
  `private_data_objects_never_move`), because the `public` method would put the value in a
  bundle and recreate the object under the target's default `CKA_PRIVATE`. Moving them would
  serve application secrets and tpm2-pkcs11's data objects, which are all private. PKCS#11 wraps
  keys, not data objects, so the candidate is the `host` path behind `--allow-host-plaintext`,
  with `CKA_PRIVATE = true` in the target's template and the value zeroized afterward. A bundle
  is never a candidate.
- **brainpoolP512r1** (2026-11-15): cakeys refuses this curve (15, `CURVES_WITHOUT_CRATE`).
  Support would serve keys under BSI TR-03111 (German government and eID PKI) and HSMs that offer
  the curve beside P256r1 and P384r1. RustCrypto has no `bp512` release. "Add Brainpool P-512"
  (RustCrypto/elliptic-curves#1914) is open and has stayed unmerged since 2026-08-18, and an
  earlier draft (#1186) was closed. The one crate on crates.io, `bp512-nestler` 0.2.1, has the
  license PolyForm-Noncommercial-1.0.0, which is outside `deny.toml`'s allowlist and cannot be
  used in a BSD-3-Clause workspace. It also builds on a fork of `primeorder`
  (`nestler-primeorder`, a release candidate). Take the curve up when RustCrypto releases a
  `bp512` on the elliptic-curve 0.14 line: the work is the SPKI re-encoding, ECDSA with SHA-512,
  and ECDH, as for the other Brainpool curves. Do not implement the curve here, because this
  repository does not write curve arithmetic.
- **Post-quantum key types** (ML-DSA, ML-KEM, SLH-DSA through kryoptic): the work is
  `rfc7093m4` over the SPKI, a `parameterSet` in keys.toml (left out of the spec digest when it
  is unset), OpenSSL 3.5 as the oracle, and, first, a test of whether p11-kit forwards PKCS#11
  3.2. No token here has post-quantum hardware.
- **`pop-ecdh`, `pop-decrypt` and `pop-unwrap` for `CKA_ALWAYS_AUTHENTICATE` keys**: only the
  sign path logs in for each use, so cakeys refuses an always-authenticate key that may only
  derive, decrypt or unwrap (17 when the spec declares the attribute, 16 when the token reports
  it).
- **`binding = "attested"`** as an opt-in replacement for `pop-*` on PIV keys (a proof that
  needs no touch).
- **PIV touch policy**: PKCS#11 does not show the touch policy, and only the attestation's
  `1.3.6.1.4.1.41482.3.8` extension holds it. A working version would fetch the attestation
  before the proof, and it would refuse (16) or warn for every `pop-*` on a slot that requires a
  touch.

## To decide

- **The contract with programs** (CAKEYS.md): whether the CLI alone is the binding, or whether a
  C-ABI library is added when a consumer asks for one; a versioned JSON form of `check` (the
  URI, the IDs, the time of the verification); how notes and warnings reach a binding; and
  whether closing the gap between the check and the use is worth tying programs to the
  library's session.
- **Asserting how keys relate**: "A and B are the same key" or "A and B must differ", across
  locks. The options are declarative assertions in keys.toml that `validate` and `check` test,
  or a documented Nix pattern over `lib.mkKeys` results
  (`assert a.id.rfc7093m4 != b.id.rfc7093m4`, which works today but compares only what the locks
  pin).
- **Changing an existing object's policy**: a verb that applies the spec's attribute changes with
  `C_SetAttributeValue` when the material still matches, and then records the object again.
  PKCS#11 allows only one-way changes, and only on modifiable objects. It is still to decide
  whether such a verb fits cakeys at all, and whether a loosened key counts as a downgrade.
- **Signing the lock**: every lock write would sign the canonical lock into `keys.lock.sig`, and
  `check` would refuse a lock whose signature does not verify. The hard part is an anchor that
  the lock's editor cannot change. Until then, keys.toml and keys.lock live in signed, reviewed
  version control. The signature should reuse an existing format (SSH signatures, minisign,
  DSSE) instead of a new one.
- **A merge rule for lock fragments** (review S16): updates are serialized, and `gc` collects
  stale entries, but two fragments edited by hand still need a manual merge.
- **A published JSON Schema** for keys.toml and keys.lock (`schemars`), for readers in other
  languages and for validation in editors (taplo). The invariants that span several fields stay
  in code.
- **Remote keystores beyond p11-kit forwarding** (KMIP, cloud KMS), as a backend crate, if ever.
- **`--no-update-lock`** stays on `create` alone (review 2026-11-23 C-4: `lock` and `delete`
  take `--dry-run`), because it is how a user sees a first use before cakeys records it.
- **Keystores with an `idPrefix`**: an opt-in grouping whose prefix marks the managed objects on
  the token (on PIV, perhaps in the labels only), probably outside the spec digest.
- **One token through two modules** (from the user's TODO.md, which is not in the repository):
  objects are created through a vendor's SO module and then used through p11-kit (as in the Nix
  sandbox). The questions are whether the planner and the profiles can express "created through
  A, used through B", and whether `--module` should also switch the token's profile.

## Moving keys (CAMIGRATE.md)

- **Phase 6, `tpm-duplicate`**: a duplication blob built on the host for the public key of the
  target's parent, and `TPM2_Import` through tss-esapi.
- **Phase 7, vendor methods** (D10) for Luna, CloudHSM and nShield, which need the hardware.
- **`CKA_UNWRAP_TEMPLATE` on transport keys**: warn when a `migrate.transportWith` key has no
  unwrap template. A template that forces `CKA_SENSITIVE` and non-extractable keys stops even the
  holder of the target's PIN from reading the KEK. This needs a cryptoki patch first (0.12 can
  neither read nor set array attributes), and a strict template breaks the direct-OAEP path.
- **Delete and replace a key in a PIV slot** (PIV DELETE KEY and MOVE KEY, firmware 5.7 and
  later): ykcs11 cannot erase a key, so `cakeys delete` refuses, and an import refuses a slot
  that is occupied.
- **`tpm2_ptool` takes the user PIN on its command line** (allowed for now): other local users
  can read the PIN while the import runs.
- **A secret key into tpm2-pkcs11 is refused only after it is written** (2026-11-17,
  `examples/every-object` [run]): `camigrate import <hmac key> --to tpm` from its file runs
  `tpm2_ptool import`, then finds no `CKA_VALUE_LEN` on the result, removes the result and exits
  15 (the module's defect under "Upstream"). The plan could refuse the import first, from a
  profile row that says that the module drops the length of what it imports, as
  `move.secret-unwrap` does for SoftHSM.

## Capability profiles (CAPROBE.md)

- **D12, FIPS mode as a match field**: the work is `[match.fields]`, the standard 3.2 fields,
  the provider hook that observes the mode (ykcs11's FIPS mode, a TPM's `TPM_PT_MODES`), and
  `tokens.<t>.require` (14). ykcs11/2.7 was probed in approved mode, so its profile may refuse,
  for a device that is not in FIPS mode, an operation that the device can do.
- **D4, `CKO_PROFILE` claims**: read and record them, but never trust them. For example,
  native-pkcs11 serves a `CKP_BASELINE_PROVIDER` profile object while it accepts any PIN and
  reports a constant key policy (PLAN.md A0b).
- **native-pkcs11 as a Darwin reference token** (PLAN.md A0b), parked. It is the only module
  here over a platform keystore (macOS Keychain, Secure Enclave keys), and it holds keys that
  cakeys did not create, which the object matrix still lacks (the matrix makes its keys on
  software tokens). The reasons against it: it is read-only, so caprobe's write probes and
  `create` have nothing to do; it reports policy as constants (DESIGN §8.2); its EC private key
  has no `CKA_EC_POINT` or `CKA_PUBLIC_KEY_INFO`, so the key's identity needs a stored public key
  item under the same locator, which Secure Enclave keys usually lack [todo]; and it runs on
  macOS only, it is not in nixpkgs, and the Nix sandbox cannot reach the keychain [todo].
  `pop-sign` should work through the raw `CKM_ECDSA` fallback [src]. Take it up if cakeys is to
  pin keychain keys.
- **The rest of making the probe test everything it can** (2026-11-15). These are done
  (CAPROBE.md, write probes): RSA sizes from 512 to 16384 bits, curve families and operation
  mechanisms that the module does not list, and proofs at every size and curve. Every secret key
  type's generation at a sweep of lengths is done too (2026-11-19, `probe_secrets`: AES, generic
  secret, Triple DES, and the five hash-bound HMAC types). The probe still tries only the key
  wraps that the module advertises (`probe_key_wraps`). Cryptoki is the limit: it drops from
  `C_GetMechanismList` the standard mechanisms that it cannot name, and the probe cannot ask for
  a mechanism that cryptoki has no type for.
- **Secret keys in the probe** (2026-11-19). When this item was written, only AES keys had
  import, export and unwrap rows (`moves.rs`), at 16, 24 and 32 bytes. The probe decided the
  commitments' operations (`CKM_AES_CMAC`, `CKM_DES3_ECB`, and HMAC over the label with each
  hash) from the advertised list alone, and no `prove` row existed for a secret key. The coverage
  plan ([archive/CAPROBE_PROFILE_COVERAGE.md](archive/CAPROBE_PROFILE_COVERAGE.md), Parts 1 and
  2) has since added both kinds of row. A `commit.<kind>.<key type>.<bytes>` row computes each
  listed commitment on a probe key with the verbs' own `Token::commit`, in place of the `prove`
  rows that an asymmetric key has. Import, export and unwrap rows now exist for a generic secret,
  the five HMAC types and Triple DES, checked by commitment. What remains: the object matrix
  (`spec-coverage/objects`) makes one HMAC type (SHA-256) beside AES, Triple DES and a generic
  secret. The commitments of the five HMAC types are checked on the host by
  `reference/identity.rs`, which generates only the SHA-384 type on a token. kryoptic generates
  AES keys at 8, 48 and 64 bytes (SoftHSM refuses them with `CKR_ATTRIBUTE_VALUE_INVALID`). This
  is a module quirk, which is harmless while keys.toml takes only the three AES lengths, and the
  profile records it.
- **tpm2-pkcs11 over swtpm: P-521 signing fails with `CKR_HOST_MEMORY`** (2026-11-15, the proofs
  at every curve): `pop-sign` on secp521r1 fails at `C_SignInit` on every run, while `pop-ecdh`
  on the same key proves possession. The cause is a module defect or a P-521 limit of swtpm's
  TPM, and the profile records the "no". The next step is to read tpm2-pkcs11's sign path and to
  report the defect upstream.
- **Every profile is regenerated for the coverage plan** (2026-11-19,
  [archive/CAPROBE_PROFILE_COVERAGE.md](archive/CAPROBE_PROFILE_COVERAGE.md)): softhsm, kryoptic,
  swtpm, the AMD fTPM (through `nix/ftpm-test-env.sh`, with the handles and the lockout counter
  unchanged), ykcs11 (scratch slot 94 only), `aws-cloudhsm/5.18+hsm2m-*` (both clusters) and
  `kmsp11/1.9+hsm*`. kmsp11's keys are purpose-bound, so the probe goes beyond generation only
  for the AES keys of its CBC and CTR bindings (`probe: true` for `AES_256_CBC` and
  `AES_256_CTR` in `keys.json`, which costs two more key versions per run). Its other secret-key
  probes (import, wrap, derive, commitments, attributes) cannot run on kmsp11, and a note in the
  profile says so.
- **Parameter variants: a refusal may be about the call, not the mechanism.** The probe fixes
  one parameter choice for each mechanism, so it can record `CKR_MECHANISM_PARAM_INVALID` as a
  "no" that the module would not give with other parameters. This was found and fixed for AES
  CTR: the probe tries a 32-bit counter and then a counter of the whole block, which is what
  Cloud KMS takes, and the row notes the width that worked. These mechanisms still use one fixed
  choice: **AES GCM** (a 12-byte IV that the caller supplies, and a 128-bit tag; both AWS
  profiles record a "no" with `CKR_MECHANISM_PARAM_INVALID`, probably because CloudHSM generates
  the IV itself, which is not verified), **RSA-PSS** (the MGF matching the hash, and a salt as
  long as the digest), **HKDF** (hash, salt, info), **ECDH1_DERIVE** (no KDF and no shared
  data), **RSA_AES_KEY_WRAP** (a 256-bit AES key) and **OAEP** (the MGF matching the hash, and
  an empty label; a refused hash is its own row, not a "no" for the mechanism). `crypt_row` in
  `crates/caprobe/src/probe/secrets.rs` takes a list of variants and moves on to the next
  variant only for that one return value, so the other mechanisms can use it.
- **Cloud tests**: `aws.sh` creates the lock's directory on the runner (the AWS test passes it a
  local path). Before that change, the AWS end-to-end test could not create a key.
- **More probes**: the SP 800-108 KBKDFs and `CKM_HKDF_DATA`, AES-KW and AES-KWP round trips,
  attribute defaults, the encodings of existing objects, SHA-224 RSA-PSS (no binding has that
  variant), delete in a scratch slot, Ed448 and RSA-512 import, a measured session limit,
  `CKO_OTP_KEY`, `CKO_DOMAIN_PARAMETERS` and `CKO_TRUST`.
- **TODO: probe the tpm2-pkcs11 import.** The module creates keys from values only through
  `tpm2_ptool import`, which writes the module's store directly, not through PKCS#11. A
  `C_CreateObject` probe would therefore measure only a refusal, and the probe records no
  `import.*` rows on swtpm or the fTPM. Nothing prevents the probe from using the tool:
  `crates/tpm2-pkcs11/src/ptool.rs` already imports EC, RSA and HMAC keys, and camigrate's
  `import_ptool` reopens the token as the module needs (the module loads its objects at
  initialization). The probe would import each fixture, reopen the token, check the key by its
  commitment, and record `import.*` rows with `via = "tpm2-ptool"`. On the fTPM, it would run
  only through `nix/ftpm-test-env.sh`.
- **haskoki as a reference token** (PLAN.md A0b), parked: it implements everything that cakeys
  uses, but beside kryoptic it is one more software token backed by OpenSSL, and it is packaged
  for Docker, not for nixpkgs (it is written in Haskell and pins OpenSSL 4). Take it up with the
  post-quantum key types, where a second implementation beside kryoptic is worth having.
- **caprobe profiles as pkcs11-check's run scoping**: pkcs11-check's roadmap asks for a way to
  state which curves, key sizes and mechanisms a module implements, so that its vector suites
  skip what the module never offered. A caprobe profile is that statement. This item is a
  conversation with upstream, not code.
- **Ed25519 into AWS CloudHSM**: the module holds an Ed25519 key as `CKK_EC` and refuses a
  `CKK_EC_EDWARDS` public half (`C_CreateObject`, `CKR_ATTRIBUTE_VALUE_INVALID` [run]), so the
  non-FIPS profile's `migration.refuses` blocks a move into the module. A move out of the module
  works. A provider hook that writes the module's key type into import templates (the reverse
  of `key_type`), with the point in the `CKA_EC_POINT` form that the module takes, would let the
  key in. This is untried.
- **Vendor mechanisms in the probe**: when this item was written, cryptoki 0.12 dropped every ID
  that it could not name from `C_GetMechanismList`, so CloudHSM's vendor list (EdDSA
  `0x80001057`, ML-DSA, AES-GCM, its RFC 3394 and RFC 5649 wraps) was in no profile. cakeys now
  builds against cryptoki main, which keeps the values from `CKM_VENDOR_DEFINED` up. Both AWS
  profiles list them (for example, `unknown 80001057`) under `[untested]` with
  `why = "vendor"`, because the probe knows no parameters or semantics to call them with. A
  provider reaches a vendor mechanism only through its own code: as a stand-in for a standard
  mechanism (CloudHSM's EdDSA), or in its attestation (tpm2-pkcs11's `CKM_TPM2_CERTIFY`).
- **CloudHSM's `--aes-key-wrap-mapping`** (`configure-pkcs11`) maps `CKM_AES_KEY_WRAP` to a
  vendor padding [doc]. It is untried, so the profiles describe only the default client
  configuration.
- **Cloud KMS AES keys** support GCM (Google's vendor mechanism), CBC and CTR only. cakeys
  commits to an AES key by CMAC, by an ECB check value or by key wrap, so it refuses these keys.
  A commitment by AES-CBC encryption of the label would cover them.
- **Probing bound keys more narrowly**: a binding lists `CKM_RSA_PKCS` for signing, and
  `rsa_ops` also tries that mechanism for decryption on that key. The SHA-512 keys receive the
  probe's SHA-256 inputs. Both cases end as notes, not rows (each mechanism works on some key),
  but the notes carry no information. A list of operations (sign, decrypt) and a digest for each
  binding would remove them.
- **Forwarding modules do not identify themselves**: pkcs11-proxy and pkcs11-proxy-ng report the
  backend's `C_GetInfo`, so keys.toml must name their layer (`profiles = [...]`). This is worth
  stating in CAKEYS.md once A6 settles whether pkcs11-proxy-ng needs a layer at all.

## TPM and attestation

- **`tpm-certify` of AES and Triple DES keys, and of secret keys through the vendor mechanism.**
  A secret key's certification is bound to the key because the loaded object computes the key's
  HMAC commitment again (DESIGN §3.7, review 2026-11-23 B-1), so only HMAC and generic secret
  keys on the store path are attested. An AES key could be bound in the same way by its
  `kcv-ecb` (`TPM2_EncryptDecrypt2` in ECB mode, where the object's mode allows it). The vendor
  mechanism would need the module to compute the commitment with the object that it certifies.
- **Chain the Attestation Key to the EK certificate** (MakeCredential/ActivateCredential), so
  that `tpm-certify` proves "a genuine TPM", not only "the same TPM as at first use".
- **`tpm-certify` reads tpm2-pkcs11's private sqlite store**, which is why it has a version guard
  that accepts only 1.10.x. This dependency is unusual and fragile. A better design is that
  tpm2-pkcs11 exposes what attestation needs as vendor-defined attributes or a vendor mechanism,
  so that cakeys never opens the database. This is drafted. The upstream patch
  `upstream/tpm2-pkcs11/0002-…CKM_TPM2_CERTIFY.patch` (the PR text is in `PR-CERTIFY.md`, not
  filed) adds `CKM_TPM2_CERTIFY`, a `TPM2_Certify` through `C_SignInit`/`C_Sign` that a
  persistent key named by the caller signs. It also fixes `CKA_TPM2_PUB_BLOB`, which
  `C_GetAttributeValue` already returns (verified on 1.10.1 with swtpm). The provider has the
  mechanism path (`attest/vendor.rs`). It asks `C_GetMechanismInfo` for `CKM_TPM2_CERTIFY`, uses
  the mechanism with no store read, and keeps the store reader (with its 1.10.x guard) for
  modules without the mechanism. Both paths produce the same `tpm_certify_id` and root, and
  `tpm2_vendor_module_attests_as_the_store_path_does` checks that against a module built with
  the patches (`nix/tpm2-pkcs11-vendor.nix`, master a5156c5, because the patches do not apply to
  the 1.10.1 tag). The profiles do not change, because they are probed on nixpkgs' tpm2-pkcs11,
  which has none of these vendor mechanisms. Not done yet: the EK chain
  (`CKM_TPM2_ACTIVATE_CREDENTIAL`) on the cakeys side, and the run on a real TPM. The second
  upstream PR is drafted too (`0003-…attestation-key….patch`, `PR-AK.md`).
  `CKM_TPM2_AK_PAIR_GEN` makes the Attestation Key an object of the token, and
  `CKM_TPM2_CERTIFY_OBJECT` signs with it, so cakeys needs no TCTI on this path
  (`options.akLabel`, `tpm2_vendor_token_attestation_key_needs_no_tpm_handle_or_store`). This
  path changes the pinned `attestation.root` (a re-lock), and it drops the qualified-signer
  check on that path (a client cannot compute the qualified name, and the pinned key identifies
  the signer). The third PR is drafted as well (`0004-…ACTIVATE_CREDENTIAL….patch`,
  `PR-ACT.md`). It adds `CKA_TPM2_EK_PUB_BLOB` on the attestation key (the EK public area and
  certificate, readable only after the login) and `CKM_TPM2_ACTIVATE_CREDENTIAL` (`C_Decrypt`)
  for the EK chain. The client makes the credential with MakeCredential, which needs no TPM, and
  checks the certificate chain itself (docs/VENDOR.md, "What the client verifies"). All four
  were tested on swtpm only. The series is on the branches `upstream-pr/1-certify`,
  `upstream-pr/2-attestation-key` and `upstream-pr/3-activate-credential` of
  Princemachiavelli/tpm2-pkcs11 (one commit each, stacked, not filed). A real TPM's endorsement
  authorization and EK are untested.
- **A native TPM backend** beside tpm2-pkcs11, for keys bound to PCRs and policies.
- **Vendor HSM attestation formats** (Luna PKC, Google Cloud HSM, nShield): each format needs a
  scheme of its own, and none is researched.
- **Maybe, a challenge bank**: challenges that the host holds and uses once would narrow the
  replay of secret-key fingerprints after `lock`. A bank needs mutable state on the host, which
  the sandboxed `check` lacks.

## Upstream

- **SoftHSM, to reproduce**: the probe's process died in SoftHSM's `C_Sign` after the shim
  (FAULT_SHIM.md) gave every `C_SignInit` a P-256 private key, whatever the mechanism was. One
  of those initializations accepted a key of a type other than its mechanism's, and the
  signature crashed. This was seen once (2026-11-14), through `use_label` without `call`, and
  the mechanism that caused it is not isolated yet. A direct reproduction (`C_SignInit` with
  `CKM_EDDSA` or an RSA mechanism and an EC key) would make it an upstream report.
- **SoftHSM**: `C_UnwrapKey` stores an unwrapped secret key's `CKA_VALUE` but never its
  `CKA_VALUE_LEN` (which reads 0), and it refuses `CKA_VALUE_LEN` in the template
  (`CKR_ATTRIBUTE_READ_ONLY`; SoftHSMv2 #628). This is filed as SoftHSMv2 #925 with tests
  (`upstream/softhsm/PR.md`; the older #650 has the same core change), and
  `checks.softhsm-unwrap-value-len` tests it on a patched SoftHSM. A fixed release will get its
  own profile without the `move.secret-unwrap` "no".
- **SoftHSM under pkcs11-provider** (which reads `check --format pkcs11-provider-pem`): SoftHSM
  2.7.0 does its own cryptography in the application's default OpenSSL library context. So when
  pkcs11-provider is activated before `default`, SoftHSM's `C_Login` calls into SoftHSM again
  and deadlocks on the token mutex (SoftHSMv2 #834, open; pkcs11-provider #723 calls it
  SoftHSM's defect). A fix is drafted in `upstream/softhsm/` (0004, `PR-834.md`). It is not
  filed: first ask on #834 whether the maintainers want the minimal change or every call in the
  default context converted. 2.7.0 also refuses multi-part `CKM_ECDSA_SHA*` (`C_SignUpdate`, so
  `openssl dgst -sign` fails) and crashes at exit under OpenSSL's cleanup (#780). Main fixed
  both after 2.7.0 (#857, #897), and cakeys backports the fixes as 0002 and 0003. The check
  phase and `scripts/local-tests.sh` test on SoftHSM with all four patches, and
  `checks.softhsm-pkcs11-provider` runs the reproduction. A deployment on stock 2.7.0 must list
  `default` before `pkcs11`, and it cannot sign a stream through the provider.
- **rust-cryptoki**: the PRs for the HMAC key-type fix (#373), `CKM_AES_KEY_WRAP_KWP` (#376),
  `CKM_RSA_AES_KEY_WRAP` (draft #377) and an `RvError` back to its `CK_RV` (draft #380) are
  filed (`upstream/rust-cryptoki/`). The single-part sign after `C_SignInit` needs no PR,
  because upstream main has `Session::sign_single` (d1b283e). Later: array attributes and
  `CKM_DES3_CMAC` (a DES3 `cmac`, above).
- **rust-cryptoki, untouched attributes read as zero** [src]: `get_attributes` (in 0.12, and in
  main at the pinned revision) gives each fixed-size attribute a zeroed buffer of its size. A
  module that answers `CKR_ATTRIBUTE_TYPE_INVALID` without setting that entry's length to
  `CK_UNAVAILABLE_INFORMATION` leaves the zeros, and cryptoki returns them as a value.
  native-pkcs11 does this for every type it does not know, and for the entries after that type.
  Through cakeys, this records `CKA_MODIFIABLE`, `CKA_COPYABLE`, `CKA_DESTROYABLE` and
  `CKA_WRAP_WITH_TRUSTED` as false in the observed policy, and `CKA_KEY_GEN_MECHANISM` as
  `CKM_RSA_PKCS_KEY_PAIR_GEN` (0) in the immutables, on an EC key too. A first pass that asks
  only for the length of every attribute would make the untouched entry a zero-length value,
  which fails to convert, instead of a false value. Reproduce it under the shim first
  (FAULT_SHIM.md, "untouched"), and then report it.
- **tpm2-pkcs11**: the P-521 `CKA_EC_POINT` fix (`upstream/tpm2-pkcs11/`). Another defect is not
  filed yet: a secret key made by `C_CreateObject` is stored without `CKA_VALUE_LEN`, which
  PKCS#11 requires of AES and generic secret keys (the object matrix shows it; it is the same
  class of defect as SoftHSM's unwrap above), so cakeys cannot check the key's length (15).

## Engineering

- **The token suites under a plain parallel `cargo test`** no longer crash. Since 2026-11-17, the
  test helpers share one reference-counted context per module (`tests/common`'s `Module`), so no
  test finalizes the module while another test uses it. But the suites do not pass there. All
  tests of a binary share one token set, so the tests that change the token (a second `kmtest`
  token, PIN tries used up) break the others, and some tests do not find an object that a CLI
  run just made, for a cause that is not established. This way of running is unsupported.
  `scripts/local-tests.sh` (nextest, with a token set for each test) is the local runner, as the
  crane check phase and the coverage report are. The mutation report runs on one thread against
  shared tokens.
- **Closing the gaps that the reports show** (`packages.coverage`, `packages.mutants`,
  DEVELOPMENT.md): `crates/core/tests/refusals.rs`, which a plain `cargo test` runs, pins the
  lock's load-time invariants and the transport-key rules. The sealed path with OAEP SHA-256 and
  the host path's occupied-locator and rollback branches run in no test. The YubiKey provider
  and the probe's scratch-slot guard run only in the opt-in hardware tests.
- **Unit tests in `cakeys-pkcs11`**: the crate is tested almost only through the reference suite
  (`crates/cli/tests/reference/`, which every reference binary includes whole). On 2026-11-15,
  the crate had 4.5k lines and 16 unit tests. On 2026-11-26, it had about 10,100 lines and 66
  unit tests.
- **Design models** (DEVELOPMENT.md, "Verification beyond tests"): a Quint model of the lock
  rules is begun (2026-11-18: `crates/core/spec/lock.qnt`, `checks.quint`,
  `crates/core/tests/lock_mbt.rs`). These are left for the model: imports and provenance;
  certificates and public-key objects (pairs, and the certificate exception of the second-name
  rule); transport keys (`publicKey`); locators and `publicOnly`; recorded commitment labels;
  deprecated schemes; and a spec in keys.toml retargeted to another object (the reconcile rule
  that the review finding "reconcile F1" fixed, in `reconcile.rs`; the model's keys.toml never
  retargets a spec; review 2026-11-23 A-16). An inductive invariant is also left, so that
  Apalache proves the properties for every reachable lock, not only within two steps. After the
  Quint model come Alloy for the lock's structure and S16, and Tamarin for proof of possession
  and attestation.
- **Kani and fuzzing**: a property is written once, as a function that panics when the property
  fails (`cakeys_core::fuzzing`, `cakeys_tpm2_pkcs11::fuzzing`, `camigrate::fuzzing`). A
  proptest then checks it on random inputs, a cargo-fuzz target checks it under libFuzzer, and,
  where a proof fits, a Kani proof checks it for every input up to a bound. A proof fits only
  code without FFI or deep parser stacks. The properties (2026-11-18, DEVELOPMENT.md "Testing")
  are these: hex round-trips, and `decode` accepts exactly hex (fuzz target `hex`); the
  length-prefixed encoding of the attestation IDs reads back to its fields (`attest_encoding`);
  `tpm2_pkcs11::fix_ec_point` repairs exactly the malformed short form (`p521_point`); the lock
  and the bundle read back from their own output (`lock`, `bundle`); and a key file yields a
  private key only where the shape scan sees one (`key_file`). Kani is packaged (`nix/kani.nix`,
  0.68.0 built from source), and `checks.kani` (in `nix flake check`, not in
  `checks-crane-only`) proves three properties: the hex round trip for every input of up to two
  bytes (52 s, 2.5 GB), `decode` for every text of up to four bytes (13 s, 0.5 GB), and
  `fix_ec_point` for every input of up to 258 bytes, which covers every shape that it repairs or
  leaves alone (1m42s, 5.7 GB). Under Kani, a heap value of symbolic length becomes array
  constraints. So a proof takes a fixed array and a length, never a `Vec` or a `String`, and the
  cost comes from code that copies symbolic lengths onto the heap. `fix_ec_point`'s one copy
  takes most of its 5.7 GB. `attest_encoding`, which copies every field, has no proof: even with
  fields of up to one byte, the proof ran out of 8 GB, both for the two encodings together and
  for `tpm-certify`'s two fields alone. All three engines first ran through bolero (one harness,
  `--engine kani`), and bolero was dropped on 2026-11-18 for three reasons. Its `Vec` and
  `String` generators produce such heap values (there is no fix as of 2026-11; bolero #231
  fixed only its byte-slice input). Its engine took the hex round trip past 8 GB, where the
  plain proof takes 2.5 GB, and `fix_ec_point` past 8 GB, where the plain proof takes 5.7 GB.
  And its libFuzzer side was never wired, while cargo-fuzz is. The injectivity of
  `Commit::label` stays a proptest: Kani handles `format!` badly, and a proof would need a label
  parser written only for the proof. The other fuzz targets stay with cargo-fuzz, because
  tss-esapi's unmarshalling is C, and the DER, X.509 and TOML parsers are too deep for a bounded
  proof. Kani's use is minimal so far (review 2026-11-23): there are three proofs, each of a
  property that a proptest already samples, so for these three alone the proptests would be
  enough. The check stays for the proofs to come. Until then, it adds only exhaustive coverage
  up to each bound.
- **More reference tokens**: an OP-TEE PKCS#11 TA in QEMU; a Nitrokey.
- **Examples on hardware and in the cloud** (2026-11-17): `examples/` runs on software tokens and
  swtpm only. The YubiKey pairs (`every-object`'s imports, and `secure-boot`'s attested PK and
  KEK) are validated against the ykcs11 profile but never run. Cloud KMS and CloudHSM have no
  example. `examples/tls/configuration.nix` and `examples/secure-boot/sign.nix` are evaluated but
  not deployed: no VM test boots the TLS unit pair or builds the signing derivation on a TPM
  host.
