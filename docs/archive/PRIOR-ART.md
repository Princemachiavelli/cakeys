# Prior art, early identity design and Nix reasoning (excerpts from PLAN.md, 2026-11-11)

Archived from PLAN.md when it was folded into the current documents (2026-11-14): the prior-art
survey, the reasoning behind the identity modes DESIGN §3.4 keeps and the weaker ones it parks
(docs/OPEN.md), and the reasoning behind the Nix integration (the sandbox, build identities).
The project was then called `key-mgmnt`.

## Prior art / landscape

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

## What is missing (the gap this project fills)

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

## Identity: portable vs token-specific CA-IDs

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

## Nix integration

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
