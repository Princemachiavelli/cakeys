# cakeys design: identity and the lock

How cakeys identifies objects and what its lock promises. The tools have their own documents:
[CAKEYS.md](CAKEYS.md) (the verbs, exit codes and Nix integration),
[CAPROBE.md](CAPROBE.md) (capability profiles) and [CAMIGRATE.md](CAMIGRATE.md) (moving keys).
The annotated file references are [CONFIG.md](CONFIG.md) and [LOCK.md](LOCK.md); the crate map is
[ARCHITECTURE.md](ARCHITECTURE.md), and the pictures are in [diagrams.md](diagrams.md). Section
numbers are stable, since code cites them; moved sections leave a pointer.

## 1. Purpose

Declare PKCS#11 (and later TPM) objects in a file, and address them by a **content-addressed
identity (CA-ID)**: a hash of the object's material, not a name. Names (labels, IDs, URIs, slot
numbers) are only *locators*: arbitrary, mutable, and not identity. A lock file records each
object's CA-IDs. A check before each use proves that the token still holds that material: the
guarantee is *verified at check time*, like a file checked and then opened (§8.2 names the
window). In Nix this check runs inside the build sandbox as a pseudo fixed-output check.

## 2. Model

| Level | What it is | Identified by |
|---|---|---|
| **Object** (`[objects.<name>]`) | The material and its intrinsic type: class, key type, curve/size. | CA-IDs in `keys.lock` (`objects.<name>.ids`) |
| **Spec** (`[specs.<name>]`) | Policy for one use of an object: boolean `CKA_*` attributes. Several specs may share one object. | Spec digest: SHA-256 of canonical JSON of type plus attributes |
| **Realisation** (per spec × token) | The object on one token, found through a locator. | Locator (`CKA_LABEL` and/or `CKA_ID`), recorded with mode, URI and provenance |

- **The object name is an internal handle.** It is never written to the token.
- **Locators** are user-chosen `CKA_LABEL` and/or hex `CKA_ID`, and must match exactly one object.
  - Several matches → *ambiguous* (exit 12) — `conflicts_and_ambiguity`.
  - The live object's class, key type, curve/size and every policy attribute must match the spec, or *conflict* (exit 13) — `conflicts_and_ambiguity`, `curves_and_rsa_sizes_match_an_independent_der_oracle`.

## 3. Identity

### 3.1 Schemes

Each scheme is one CA-ID kind, stored as `sha256-<base64>` (SRI). The lock may hold several per
object.

| Scheme | Objects | Input | Requires | Tests |
|---|---|---|---|---|
| `rfc7093m4` (input alias `pubkeyhash`) | private/public keys, certificates | RFC 7093 §2 method 4: the hash (here SHA-256, named by the SRI prefix) of the DER SubjectPublicKeyInfo, applied to the *canonical* SPKI (re-encoded, EC points uncompressed; §3.2) | readable public key | `curves_and_rsa_sizes_…`, `adopt_*`, `standalone_public_key_objects`, VM oracle (pkcs11-tool + openssl) |
| `certhash` | X.509 certificates | SHA-256 of the certificate DER | readable `CKA_VALUE` | `adopt_certificate_…`, `adopt_ec_and_edwards_certificates` |
| `valuehash` | public data objects | SHA-256 of `CKA_VALUE` (equals Nix's flat fixed-output hash) | `CKA_PRIVATE=false` | `data_objects_are_identified_by_their_public_value` |
| `commitment` | generic secrets, `CKK_SHA*_HMAC` | HMAC over the label (§3.3), using the key type's hash | `CKA_SIGN` | `secret_commitments_match_host_hmac`, `hmac_key_types_commit_with_their_own_hash`, `tpm2_imported_keys_…` |
| `cmac` | AES | AES-CMAC over the label | `CKA_SIGN` | `aes_commitments_match_host_oracles` |
| `kcv-ecb` | AES | AES-ECB encryption of one block (first 16 bytes of SHA-256(label)) | `CKA_ENCRYPT` | same, `tpm2_aes_key_is_identified_by_its_kcv` |
| `kcv-ecb-dec` | AES | AES-ECB *decryption* of such a block | `CKA_DECRYPT` | `aes_128_192_and_decrypt_only_match_host_oracles` |
| `kw` | AES | RFC 3394 key wrap of a fixed key (SHA-256(label)) | `CKA_WRAP` | `aes_commitments_match_host_oracles` |
| `piv-attestation` | private/public keys (YubiKey PIV) | Canonical digest of what the slot's attestation certificate asserts (§3.7), verified to the pinned Yubico root; per realisation | opt-in `attestation = true` (no login needed to read the certificates) | `fixture_chain_verifies_and_pins`, `the_yubico_roots_are_pinned`, `issuers_must_be_cas_within_their_path_length` |
| `tpm-certify` | private and secret keys on tpm2-pkcs11 tokens | Canonical digest of the Name and qualified Name a native `TPM2_Certify` attests (§3.7), host-verified against a provisioned AK; per realisation | opt-in `attestation = true`, the module's TCTI + store, the PIN | `tpm2_keys_attest_their_tpm_residence`, `tpm2_each_token_pins_its_own_attestation`, `tpm2_attested_material_travels_to_a_second_hsm` |

- **Commitment schemes never reveal what the token computed.** The lock stores only SHA-256 of the
  token's output, never a MAC or ciphertext under the key — `aes_commitments_…` asserts the raw
  CMAC is absent from the lock.
- **Which commitment schemes are computed** follows the spec's *declared* usage bits, never token
  defaults. The preference order (the first computed is the primary scheme) is
  `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`.
- **Only mechanisms the token offers are used.** If none fits, the result is *unsupported* (exit 15).
- **Attestation schemes are computed only by explicit opt-in** (`attestation = true` on the spec's
  token entry, §3.7): they promise TPM- or vendor-signed provenance from then on, and a run that
  cannot attest would otherwise turn every previously-attested realisation into a downgrade.

**Scheme strength and deprecation** (finding S15). Per class, the schemes in the order cakeys
prefers them — the first computed is the primary identity, and a weaker scheme is only computed
when the spec's declared usage bits allow nothing stronger:

| Class | Schemes, strongest first | Why the order |
|---|---|---|
| private/public keys | `rfc7093m4` | the host verifies it against the material it hashes, and the private half proves possession (§3.6) |
| certificates | `certhash`, then `rfc7093m4` | `certhash` pins the exact bytes; `rfc7093m4` only names the subject key, which renewed certificates share |
| data objects | `valuehash` | SHA-256 of the content, equal to Nix's flat fixed-output hash |
| generic secret / `CKK_SHA*_HMAC` | `commitment` | HMAC over the domain-separated label (§3.3), with the key type's hash |
| AES | `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw` | CMAC is a PRF over the whole label; each KCV exposes one fixed-block ECB relation; `kw` needs the fixed-key wrap |

Deprecation:

- **A changed or weakened computation gets a new scheme name, never an edit** (§10) — like go.sum's
  `h1`/`h2`. The old name keeps meaning what it meant.
- **A deprecated scheme still verifies identities already locked under it** — with a warning — but
  `realise` never records a *new* identity under it: migrate by realising a spec that
  computes the replacement. (`gc` will not drop the old entry: the identity is still true.)
- **No scheme is deprecated today.** The register is `Scheme::DEPRECATED` in
  `crates/core/src/id.rs`, pinned empty by `the_deprecation_register_is_pinned`; the AES order
  above is pinned by `aes_commit_strength_order_is_pinned`.

### 3.2 Public keys

Public keys are decoded and re-encoded by RustCrypto crates, so provider encoding quirks never
change a hash:

- `p256`, `p384`, `p521`, `k256`, `bp256`, `bp384`;
- `ed25519-dalek`, `ed448` (length check only: there is no stable Ed448 arithmetic crate);
- `rsa` (1024–8192 bits).

Where the public key comes from, in order (key material first, never what the module merely asserts):

1. The object's own material: RSA modulus and exponent, or `CKA_EC_PARAMS`/`CKA_EC_POINT`. The point
   may be a DER OCTET STRING or raw.
2. Otherwise, the material of the single public-key object under the same locator (SoftHSM EC and
   Edwards private keys carry no point). The private key is bound to it by proof of possession
   (§3.6).
3. Otherwise, `CKA_PUBLIC_KEY_INFO`. Errors are treated as absent: ykcs11 reports length 0, then
   fails.

Wherever `CKA_PUBLIC_KEY_INFO` is present it must agree with the material, or the result is a
conflict (exit 13): modules may let it be set without checking —
`h1b_a_forged_public_key_info_is_a_conflict`.

Supported curves:

- `CKK_EC`: secp256r1 (alias prime256v1, P-256), secp384r1, secp521r1, secp256k1, brainpoolP256r1,
  brainpoolP384r1.
- `CKK_EC_EDWARDS`: edwards25519, edwards448.
- brainpoolP512r1 is refused, because no RustCrypto crate supports it — `brainpool_p512_is_refused_clearly`.

### 3.3 Commitment label

The token computes on `<commitment label>/<scheme>/<keyType>/<bits>`, built in
`crates/core/src/id.rs`.

- **The lock records the commitment label per object** (`objects.<name>.commitmentLabel`), and
  verification always uses the recorded value. The code only supplies the default
  (`DEFAULT_COMMITMENT_LABEL = "key-management/v1"`) for objects the lock does not know yet. A
  future default, or a configurable label such as the planned keystore `idPrefix`, never breaks an
  existing lock. Lock objects are self-contained, so lock files can be joined or split per object.
  Tests: `commitment_label_comes_from_the_lock`, which proves a non-default label in the lock is
  used, and that commitment IDs without a label are refused (exit 17).
- **The label is never written to a token.** It is only the fixed message the token MACs or
  encrypts to compute a secret key's ID; labels, `CKA_ID`s, attributes and URIs stay the user's.
  A distinctive string keeps the operation from coinciding with another protocol's use of the key.
- **The key type is part of the label,** so the same bytes held as two types never share an ID.
- **`bits`** is `8 × valueLen`. It is 0 when `valueLen` is unset (finding L11).

### 3.4 Identity modes

Strongest first. The mode is recorded per realisation; a downgrade fails (exit 14) — `downgrade_is_an_error`.

| Mode | Used for |
|---|---|
| `direct` | public keys, certificates, data objects (hash of public material) |
| `commitment` | secret keys whose declared usage bits allow a commitment scheme |
| `wrap-rebind` | extractable secret keys without such bits. The key is wrapped under a session KEK, unwrapped as a session copy that allows every scheme of its type, committed, then both are destroyed. Computes every scheme (AES: all four). |

A secret key that fits none of these — non-extractable, with no usage bit a commitment scheme can
use (derive-only, unwrap-only, `CKA_ALLOWED_MECHANISMS` limited to random-IV modes) — is refused
at validation (17), naming the spec change that would identify it —
`a_secret_key_without_a_reverifiable_identity_is_refused`.

**Weaker modes may have to come back** (review A6 removed them unbuilt). Such keys are common in
real deployments, especially existing and legacy keys that cakeys did not create and cannot
re-declare, so tests built from clean keys must not decide what cakeys can adopt. Each candidate
gives up re-verification: `commit-at-creation` (compute once, then drop the usage bit),
`host-at-import` (hash the plaintext before an import), `token-specific` (an identity one token
alone can compute, such as a TPM Name). If they return, they get their own names, rank below
`wrap-rebind`, and a reported assurance that says the token is not re-checked ([OPEN.md](OPEN.md)).

### 3.5 Linking and upgrades

- **Identities are only linked through a shared scheme.** If an object already has locked IDs and
  none of the computed schemes is among them, `realise` fails (exit 14) instead of attaching new
  IDs — `disjoint_schemes_never_link_material`.
- **`realise` and `delete` write the lock by default, and a write only fills gaps.** Like
  `nix build` with `flake.lock`: what the lock lacks is recorded (first use included), but a
  locked ID, anchor, binding, type or immutable is never overwritten — those changes fail even
  when the lock is written. `--no-update-lock` compares only (`--update-lock` names the
  default). First use is trust on first use, so the review is the `keys.lock` diff.
- **A write that replaces a realisation says what it accepted,** one line each (`re-recorded
  …`): what keys.toml changed (locator, object, `publicOnly`, spec digest) and policy
  attributes the lock did not record are notes; a policy attribute or immutable that changed
  on the token, which nobody edited, is a warning — `a_write_says_what_it_rerecorded`.
- **Where the lock cannot be written, a writing run is refused (14) before any token is
  touched** — never a key created and then not recorded — naming `--no-update-lock`: inside a
  Nix build sandbox (`NIX_BUILD_TOP` set without `IN_NIX_SHELL`, which `nix develop` also
  sets), where a write would be lost with the build, or when the lock file or its directory is
  not writable (`access(2)`). `check`, `verify` and `resolve` never write and are unaffected —
  `lock_is_written_by_default_and_refused_where_it_cannot_be`.
- **A computed scheme missing from an otherwise matching lock is a note.** This happens, for
  example, when a newer version computes more schemes.
  - With nothing to compare, it is first use: `realise` records it; `--no-update-lock`,
    `verify` and `check` fail with a hash mismatch (exit 10), printing `got:`.
  - An explicitly requested `check <obj>.id.<scheme>` needs that scheme locked.
  - Test: `a_new_scheme_missing_from_the_lock_is_a_note_unless_requested`.

### 3.6 Proof of possession (`binding`)

A private key's identity hashes a public key, which may come from a separate object (§3.2). Each
time it resolves a private key (`resolve`, `verify`, `realise`, `check`, `delete`), cakeys binds the
key to its identity:

1. The host builds a challenge: `"cakeys/pop/v1\0" ‖ SHA-256(SPKI) ‖ 32-byte nonce` from the OS
   RNG (`crates/core/src/pop.rs`).
2. The token proves, with the private-key object found under the locator, that it holds the
   private half of that SPKI — by whichever capability the key has (the spec's `binding`):
   - `pop-sign` (default): the token signs the challenge:
     - ECDSA with the curve's hash (P-256, secp256k1, brainpoolP256r1: SHA-256; P-384,
       brainpoolP384r1: SHA-384; P-521: SHA-512): `CKM_ECDSA_SHA*` if offered, else `CKM_ECDSA`
       over the host's digest;
     - Ed25519: `CKM_EDDSA` (pure);
     - RSA: `CKM_SHA256_RSA_PKCS`.

     On a key the token reports `CKA_ALWAYS_AUTHENTICATE` (declared or not), the same proof runs
     under the key's per-use policy and is recorded as **`pop-sign-pin`**:
     `C_SignInit → C_Login(CKU_CONTEXT_SPECIFIC) → C_SignUpdate → C_SignFinal`, once, with the
     PIN that opened the session, never retried. It is multi-part because
     cryptoki 0.12 has no other point for the login, so the single-part-only mechanisms
     (`CKM_EDDSA`, raw `CKM_ECDSA`) and a module that refuses to sign in parts (SoftHSM's
     `CKM_ECDSA_SHA*`) are refused (15); a declared always-authenticate Edwards key is invalid
     (17). A cryptoki patch for a single-part sign after `C_SignInit` would lift both.
   - `pop-ecdh` (EC keys that only derive): the host generates an ephemeral key on the same curve
     and MACs the challenge with HMAC-SHA256 under the ECDH shared secret; the token derives the
     same secret with `CKM_ECDH1_DERIVE` into a non-extractable session key and MACs the same
     challenge. The MACs agree only for the matching private key.
     - **Extractable variant.** Some tokens have no HMAC. Others derive only into an
       extractable secret, or cannot MAC with a sealed one; their module profile says
       `derive.sealed = false` (ykcs11, tpm2-pkcs11 1.10 [run]). On those, the token derives
       into an extractable session secret, and the host reads its `CKA_VALUE` and compares it
       in constant time with the shared secret it computed. The secret belongs to a single-use
       ephemeral key the host generated, so reading it reveals nothing the host did not already
       hold. The binding is still `pop-ecdh`.
     - **Read-write session (an exception to M1).** tpm2-pkcs11 keeps derived secrets as
       store rows, so it refuses `C_DeriveKey` in a read-only session (`derive.read-only =
       false`). A read-only verb's (`verify`, `check`) proof then derives in a read-write
       session opened for it, and destroys the row again. That is the one write a read-only
       verb makes. Where the store itself is read-only (a sandbox mounting it so), `pop-ecdh`
       stays unavailable (16) on such a token.
     - **Misreported attribute.** ykcs11 reports `CKA_DERIVE = false` on every key from a
       fixed table while its keys derive. The provider repairs the reported value
       (`Provider::policy_flag`), so `CKA_DERIVE = true` checks and is recorded. A lock
       recorded before that repair fails `verify` once (14, "CKA_DERIVE false -> true"), and
       `realise` re-records it.
   - `pop-decrypt` (RSA keys that only decrypt): the host encrypts the challenge to the public key
     with RSA-OAEP (SHA-1, MGF1-SHA1 — the PKCS#11 baseline; SoftHSM implements no other OAEP);
     the token decrypts with `CKM_RSA_PKCS_OAEP`. The plaintext matches only for the matching
     private key.
   - `pop-unwrap` (RSA keys that only unwrap: transport keys, CAMIGRATE.md D3): the host wraps a
     fresh 32-byte secret to the public key with the same OAEP; the token unwraps it with
     `CKM_RSA_PKCS_OAEP` into a sensitive, non-extractable session `CKK_GENERIC_SECRET` and
     HMAC-SHA256s the challenge with it, which the host checks against its own MAC. No plaintext
     leaves the token, so the key needs no `CKA_DECRYPT`.
3. The host checks the proof with RustCrypto against the same canonical SPKI it hashes into
   `rfc7093m4` (signature verification, MAC comparison, plaintext comparison — all constant
   time where it matters). No proof value is ever stored.

Outcomes:

- **A proof that does not verify is a conflict (exit 13):** the private key under the locator
  is not the one the identity names. This also applies to `delete`, so If-Match cannot pass on a
  public object beside an unrelated key.
- **A token that refuses** (no `CKA_SIGN`/`CKA_DERIVE`/`CKA_DECRYPT`/`CKA_UNWRAP`, missing
  mechanism) is exit 15. A token error is 16, as is a failed context-specific login. `pop-ecdh`,
  `pop-decrypt` and `pop-unwrap` have no per-use login: a `CKA_ALWAYS_AUTHENTICATE` key that only
  derives, decrypts or unwraps is refused (16).
- **The spec must declare the capability the proof uses** — `CKA_SIGN = true` for `pop-sign`,
  `CKA_DERIVE = true` for `pop-ecdh` (Weierstrass EC keys only), `CKA_DECRYPT = true` for
  `pop-decrypt` and `CKA_UNWRAP = true` for `pop-unwrap` (RSA only) — or opt out per token with `binding = "token-asserted"`; otherwise it
  is invalid (exit 17). The rule uses declared attributes only, like `declared_commits`.
- **Opting out is needed** for keys with no provable capability, Ed448 (no RustCrypto verifier
  or ECDH yet), and tpm2-pkcs11 1.10.1 P-521 keys: its `C_SignInit` parses its own malformed
  `CKA_EC_POINT` and fails (`upstream/tpm2-pkcs11` fixes both).
- **`publicOnly` implies `token-asserted`.**
- **PIN retries.** A run spends at most one failed PIN attempt, and never the last: the login at
  token open refuses (16) once the token reports `CKF_USER_PIN_LOCKED` or
  `CKF_USER_PIN_FINAL_TRY`, and the context-specific login reuses the PIN that already logged in,
  so it cannot be wrong (a successful login resets PIV's counter). `CKF_USER_PIN_COUNT_LOW` is a
  warning. A slot's PIV *touch* policy is invisible in PKCS#11 and not handled (OPEN.md).
- **`pop-sign-pin` is recorded, never configured:** `binding = "pop-sign-pin"` in keys.toml is
  invalid (17); `pop-sign` (the default) becomes it on an always-authenticate key.

The lock records the binding per realisation (`pop-sign`, `pop-sign-pin`, `pop-ecdh`,
`pop-decrypt`, `pop-unwrap` or `token-asserted`). The `pop-*` methods share the top rank — each proves possession of the same
key — so a realisation never weakens unless it drops to `token-asserted`, which is refused
(exit 14), also when the lock is written — `binding_downgrade_is_refused`.

### 3.7 Attestation commitments (`piv-attestation`, `tpm-certify`)

Attestation is *signed provenance*: a vendor or the TPM signs what a key is and where it was
made, and the host verifies the signature to a pinned anchor. Two schemes turn it into a
content-addressed identity — one per token type that can produce it:

| Scheme | Token | Evidence | Anchor pinned in the lock |
|---|---|---|---|
| `piv-attestation` | YubiKey PIV (ykcs11) | the slot's on-demand attestation certificate, signed by the device attestation key in slot f9, verified to a pinned Yubico root (never to f9 alone — a holder of the management key can overwrite it) through Yubico's *PIV* intermediates only (the pool's FIDO, OpenPGP, SD and YubiHSM CAs are excluded), every issuer a CA within its `pathLen`. Yubico attests only keys generated on device; ykcs11 mints the certificate when it lists the slot, with no login | the Yubico root's SPKI |
| `tpm-certify` | tpm2-pkcs11 tokens | a native `TPM2_Certify` (tss-esapi) over the object's Name with a fresh random nonce, host-verified; the object's TPM blobs are read (read-only) from the module's own store — `options.tpm2Store`, else found as the module finds it — and loaded under the token's primary over the module's TCTI (`options.tcti`, else `$TPM2_PKCS11_TCTI`, `$TPM2TOOLS_TCTI`, `$TCTI`): `TPM2_Load` revalidates their integrity, the certify signs their Name, and the nonce makes the response fresh. Every transient object is flushed again, so TCTIs without a resource manager do not fill the TPM | the Attestation Key's SPKI |

- **The commitment hashes asserted content, never signed bytes.** A PIV certificate is minted
  per session with a random serial and a randomized ECDSA signature; a `TPMS_ATTEST` carries a
  per-run nonce and clock. `piv-attestation` hashes the certificate's stable claims (issuer
  SPKI, subject SPKI, firmware, serial, PIN/touch policy, form factor extensions), and
  `tpm-certify` the attested Name and qualified Name (`cakeys/tpm-certify/v1`, `id.rs`; the
  definitions are pinned by `attestation_definitions_are_pinned`). The Name is
  `nameAlg ‖ H(TPMT_PUBLIC)`, so it covers the key, every `objectAttributes` bit and the
  `authPolicy`.
- **An attestation includes the key identity by construction.** The PIV certificate's subject
  SPKI *is* the attested key; the TPM Name covers the public area. Both schemes cross-check it
  at compute time against the SPKI the object's `rfc7093m4` hashes — an attestation of other
  material is a conflict (13), never a second opinion; an asymmetric key is never attested
  without that SPKI. For symmetric keys (which PIV cannot attest; the TPM can), there is no
  SPKI: the portable identity is the commitment scheme, and the cross-check is that the
  module's `CKA_LOCAL`/`CKA_EXTRACTABLE` match the signed `objectAttributes`.
- **An attestation ID is per device, so it lives on the realisation.** The same material on two
  tokens either cannot attest on the second (PIV attests only keys generated on the device) or
  attests to a *different* ID: `TPM2_Certify` certifies imported objects too, and a TPM's
  qualified Name names its own hierarchy — an imported HMAC's Name even differs per import (a
  fresh `seedValue`). So the attestation ID is recorded with the realisation that computed it
  (`attestation.id`), never in `objects.<name>.ids`, where a second TPM's ID would collide with
  the first's — `tpm2_each_token_pins_its_own_attestation`. `tpm-certify` proves *residence* in
  that TPM, not generation there: `sensitiveDataOrigin` (`CKA_LOCAL`) is part of the Name, so
  an imported key's ID says so.
- **Attestation never replaces portable identity — and never stands alone.** A realisation with
  an attestation must also match a portable scheme (`rfc7093m4` for keys, a commitment for
  secret keys), and an object's `ids` never hold an attestation scheme — both enforced on load
  (exit 17). The realisations of one material on several tokens join through that shared
  portable scheme; each keeps its own attestation, and a token that cannot attest (SoftHSM)
  verifies through the portable scheme alone — material still links only through shared
  schemes (§3.5).
- **Opt-in per spec-token** (`tokens.<t>.attestation = true` in the spec's token entry): once a
  realisation's attestation is locked, a run that cannot attest — the TPM unreachable, no PIN,
  no Attestation Key, no attestation certificate — fails (14) as a scheme downgrade, while
  evidence that is *wrong* keeps its own code (13). That strictness is chosen, not sprung, and
  it is one-way: opting out again (`attestation = false`) is a downgrade too, also when
  the lock is written; a realisation that should stop attesting needs a new object name. A provider
  that attests nothing (SoftHSM, kryoptic, p11-kit) refuses the opt-in up front (15, before
  anything is created), as does a class it cannot attest (PIV: asymmetric keys only; TPM:
  private and secret keys — a public-key object is stored without a private blob, and
  `TPM2_Certify` cannot attest a public-only area).
- **The lock pins the attestation** per realisation: `attestation = { kind = "yubico-piv" |
  "tpm-certify", root = <SRI of the anchor's SPKI>, id = <the attestation ID> }`. A changed
  anchor — a re-provisioned TPM, another device signing the same claims — fails (14), and a
  changed ID under the same anchor (the attested object was replaced, or its attributes or
  policy changed) fails (10), both even when the lock is written, like immutables: the material
  needs a new object name.
- **The TPM Attestation Key** is a restricted signing key (P-256, ECDSA-SHA256, empty auth,
  owner hierarchy) that cakeys provisions at a persistent handle and never uses for anything
  but certify: a restricted key signs only TPM-generated structures. Only `realise` provisions
  it; `resolve`, `verify` and `check` never change the TPM, and fail (16, or 14 once locked)
  when it is missing. A key already at the handle is used only if its public area is exactly
  cakeys' template (restricted sign-only P-256, fixedTPM, empty policy) — anything else is a
  conflict (13), since an unrestricted key there could sign a forged attestation. The handle
  defaults to `0x81000016` (cakeys-tpm2-pkcs11 `DEFAULT_AK_HANDLE`), configurable per token
  (`options.akHandle`, `0x`-prefixed, owner persistent range). Trust in it is TOFU through the pinned
  `root`; **chaining it to the Endorsement Key certificate (EK → AK via
  MakeCredential/ActivateCredential) is not implemented yet** — until it is, the AK proves
  "this TPM", not "this genuine TPM".
- **What each scheme proves, and what it does not.** `tpm-certify` is freshness-bound by the
  nonce: the object was loaded in that TPM *at verify time*, with the certified attributes.
  `piv-attestation` has no verifier nonce (Yubico's certificate carries none), so it proves
  the claims but not liveness — a malicious module could replay an old certificate; it is
  [attested] provenance, not [crypto] proof of presence. Neither scheme can say anything about
  other tokens: exclusivity stays [unobservable] (§8.2).
- **Vendor HSM attestations** (Luna PKC, Google Cloud HSM, nShield) are out-of-band formats,
  not researched (see the review's gap): reserved for a future scheme each, never guessed.

## 4. Files

### 4.1 `keys.toml`

Annotated, with the reasons behind each table: [`CONFIG.md`](CONFIG.md).

What may be created and adopted:

- **References are checked at load** (exit 17): a spec's `object` must name an `[objects.<name>]`
  table — also when nothing uses the spec — and a `$NAME`/`${NAME}` path reference (in `pinFile`
  or `module`) must name a set environment variable; one shared `keys.toml` can then carry
  machine-specific paths. `pinEnv = "VAR"` remains the way to pass the *PIN itself* through the
  environment — `env_references_and_object_refs_are_checked_at_load`,
  `pin_file_path_can_come_from_the_environment`.
- **The admin credential (`mgmKeyFile`/`mgmKeyEnv`) is read only by a step that needs the SO.** A
  provider declares that its module creates and destroys objects only in an SO session
  (ykcs11 does); elsewhere the user creates and deletes, and the credential (the SO PIN) is read
  only by `camigrate transport --trusted` (CAMIGRATE.md D2) —
  `admin_credential_is_read_only_by_security_officer_steps`.
  Login state is per token, so the step logs the user out, logs in as SO, generates (or
  destroys), logs out and logs the user back in; the SO credential is read just before and
  zeroized after. `resolve`, `verify` and `check` never read it.
- **`autoCreate`** is allowed for private and secret keys only. Certificates, public keys and data
  objects are adopted — `adoption_rules_are_validated`, `standalone_public_key_objects`,
  `data_objects_…`. When the lock already pins the object's material (ids recorded, from this or
  another token), `autoCreate` is refused (14) before anything is created: generated material
  could never match (D1) — `autocreate_never_fights_a_locked_identity`. Put the same material
  under the locator instead, or give the token's key its own object name.
- **`createOn`** names the token an object is born on: `create` and `autoCreate` generate it only
  there, `create` on another token is refused (17) and its skip note names the import
  (`camigrate migrate`). `autoCreate` on another token, or on several without `createOn`, is
  invalid at load (17) — `create_on_names_where_an_object_is_born`,
  `create_happens_on_the_create_on_token_only`. It is kept apart from the object's type: the lock
  and the spec digest never see it.
- **`CKK_SHA*_HMAC` keys** cannot be generated (PKCS#11 has no mechanism for them) —
  `hmac_key_types_commit_with_their_own_hash`.
- **`publicOnly`** verifies a private key through its public-key object, without login (it spares
  PIV PIN retries). It forbids `autoCreate` and policy attributes, and `delete` refuses it —
  `adopt_certificate_and_public_only_key`.
- **`binding = "token-asserted"`** skips the proof of possession for a private key (§3.6).
- **Declared attribute names must fit the class** (PKCS#11 3.2 §4): every class may carry the
  common `CKA_PRIVATE`, `CKA_MODIFIABLE`, `CKA_COPYABLE` and `CKA_DESTROYABLE`; private keys add
  `CKA_SIGN`, `CKA_SIGN_RECOVER`, `CKA_DECRYPT`, `CKA_UNWRAP`, `CKA_DERIVE`, `CKA_SENSITIVE`,
  `CKA_EXTRACTABLE`, `CKA_ALWAYS_AUTHENTICATE` and `CKA_WRAP_WITH_TRUSTED`; public keys `CKA_VERIFY`,
  `CKA_VERIFY_RECOVER`, `CKA_ENCRYPT`, `CKA_WRAP`, `CKA_DERIVE` and `CKA_TRUSTED`; secret keys all of
  the key booleans; certificates `CKA_TRUSTED`; `CKA_ALLOWED_MECHANISMS` only on key objects.
  Anything else is invalid (exit 17) — `attributes_are_validated_per_class`. Certificates therefore
  take policy attributes: declare what the object shows (`CKA_TRUSTED = true` must match an object
  the token's security officer already trusted; users cannot set it).
- **`CKA_ALWAYS_AUTHENTICATE = true` proves possession with a PIN per use** (`pop-sign-pin`, §3.6):
  a successful context-specific login with the session's PIN spends no retry. An Edwards key that
  declares it is invalid (exit 17) until cryptoki can sign single-part after the login —
  `always_authenticate_keys_prove_possession_with_a_per_use_pin`.
- **`CKA_TRUSTED = true` refuses `autoCreate`** (exit 17): generation cannot set it.
- **Not expressible:** `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, `CKA_DERIVE_TEMPLATE` and
  `CKA_CERTIFICATE_CATEGORY` — cryptoki 0.12 maps none of them.

### 4.2 `keys.lock` (input, updated in place)

Annotated, with the reasons behind each table: [`LOCK.md`](LOCK.md).

- **Every realisation field has one class:** compared, observed or provenance. Removing
  `observed`, `observation`, `provenance` and the `observations` table changes no verdict, and a
  lock without `version` or a compared field is invalid (exit 17) —
  `observed_and_provenance_never_change_a_verdict`. An observed mechanism the token no longer
  offers is a warning.
- **The observation table only deduplicates.** A realisation still says exactly what it was
  recorded with; two recorded through different module builds name two entries. An entry's
  key is not recomputed on load, and an entry is the one lock table that keeps keys this cakeys
  does not know. A realisation naming a missing entry is invalid (17); a write and `gc` drop the
  entries nothing names. A token's observation (`Lock::token_observation`, for the static gate
  and `export` from the lock) is known only when all its realisations name one entry; otherwise
  the caller says so and names `realise`.
- **The policy vector is closed-world.** The spec declares the attributes it requires; the lock
  records every attribute the object shows for its class, declared or not — the booleans
  (SoftHSM EC private keys, for example, default to `CKA_DECRYPT`, `CKA_UNWRAP` and
  `CKA_SIGN_RECOVER`) and, on key objects, `CKA_ALLOWED_MECHANISMS` when the token reports a
  non-empty list. A recorded attribute that changes or becomes unreadable fails `verify` (exit 14)
  until `realise`; a newly readable one is a note. With `publicOnly`, this is the
  public object's vector.
- **Immutables** (`CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`,
  `CKA_KEY_GEN_MECHANISM`) are compared the same way. A flag that was `true` and is not any more
  means the object was replaced (for example, the same material re-imported). That is refused
  even when the lock is written, like a downgrade — `policy_drift_and_replaced_objects_are_refused`.
- **Loading checks the lock's own invariants** (exit 17, never a hash mismatch) —
  `lock_invariants_are_checked`:
  - every ID and `specDigest` is a `sha256-` SRI digest of 32 bytes; a `commitmentLabel` is
    non-empty printable ASCII;
  - a realisation's `object` is in the lock, and its `schemes` are among that object's IDs;
  - **one object per material:** no two objects of one class share an ID under one scheme
    (a certificate's `rfc7093m4` is exempt: it names the subject key, which renewed
    certificates share). `realise` refuses to record a second name (exit 14);
  - **`pairs`** makes the key ↔ certificate relation explicit: objects that share an
    `rfc7093m4`. A listed partner present in the file must share it and list back; one that is
    absent may live in another fragment, so locks still split and join per object. Partners
    present but unlisted are a note, and `realise` records them;
  - a private-key realisation records its `binding`, and no other class has one.
- **`schemes`** records which schemes a realisation computed and matched, so the lock shows which
  realisation established which ID. A realisation that later computes fewer is refused like a
  mode downgrade (exit 14).
- **Writes are atomic** (temporary file, then rename), and a run that may update the lock holds an
  advisory exclusive lock on `<lock>.lck` across its read-modify-write (finding M3), so concurrent
  updaters on different tokens queue instead of losing each other's realisations. Readers never
  take it: the rename makes each read a consistent snapshot. A leftover `.lck` is harmless
  (advisory, released when its holder exits) — `update_lock_waits_for_the_sidecar_lock`.
- **`gc`** collects entries the config no longer names (finding D3): every
  `[realisations.<spec>.<token>]` whose spec dropped the token and every `[objects.<name>]` gone
  from `keys.toml`. It prints the stale table names and removes exactly those with `--apply`; live
  objects keep their `ids`, since the same material may live on other tokens or come back.
- **URIs are pure locators** (RFC 7512), with no `module-path`. They carry the token `serial`
  (tokens may share a label) and always the object `type`.
- **One private key per `CKA_ID`.** Consumers such as OpenSSH pick the first private key whose
  `CKA_ID` matches. With a login, another private key under the same `CKA_ID` as a private key,
  public key or certificate being resolved is ambiguous (exit 12). A public session cannot see
  private keys, so `observed.session` records which view the check had; going from `user` to
  `public` warns — `a_second_private_key_under_the_same_id_is_ambiguous`.
- **Versions** are raw `CK_VERSION` major.minor (ykcs11 2.7.3 → `2.73`).
- **Observations:** a different module build identity or token is a *warning*, and so is a
  different module file `hash` at the same `path` (the file replaced in place, which a path
  outside the Nix store cannot show); only a different module file `path` is a *note*. None
  fails — `module_and_token_provenance_warn_but_do_not_fail`. The `path` is the file the dynamic
  loader mapped, symlinks resolved, whatever named it (`$NAME`, `--module`, a bare name found
  by the library search).
- **The spec digest** is the SHA-256 of the RFC 8785 (JCS) form of `{"v":1,"type":<object, camelCase>,
  "attributes":<…>}`: keys sorted at every level, no whitespace (`serde_jcs`; the pinned digests
  features). Attribute values are typed: booleans, and `CKA_ALLOWED_MECHANISMS` as a sorted,
  duplicate-free list; `certificateType` and `publicAttributes` take part only when set, under
  their own key. Curves are canonical (`secp256r1`, never an alias), so a curve alias is the same
  type and the same digest. Pinned by `spec_digests_are_pinned`.
- **A realisation record is required.** `verify`/`check` of a (spec, token) pair the lock does not
  record fails (exit 14) even when the material matches the locked IDs: the lock describes where
  objects live, not only what they are — `s3_an_unrecorded_token_is_a_precondition_failure`.
  First use, with no locked IDs to compare, is still exit 10 with `got:`.
- **The record is compared** with keys.toml: a different `object`, `locator`, `publicOnly` or spec
  digest fails `verify`/`check` (exit 14, naming each change) until `realise`
  re-records it, like a lockfile that is out of date — `s4_a_public_only_flip_is_a_spec_change`,
  `s8_a_retargeted_spec_is_a_spec_change`. A changed locator or object is never reported as an
  unexplained hash mismatch.
- **A changed object type** in `keys.toml` is refused with exit 14, naming the change, also when
  the lock is written: different material needs a new object name. Curve aliases are canonicalized on
  load (in `keys.toml` and in the lock's recorded types), so they are the same type and need
  nothing — `the_lock_pins_type_spec_provenance_and_schemes`.
- **Provenance:** a different `provider` is a warning; a different `cakeysVersion` is a note.
- **Locked schemes that are not checked** are reported: unknown to this cakeys → warning, naming
  the scheme; known but not computable for this spec on this token → note.

## 5. Verbs and exit codes

Moved to [CAKEYS.md](CAKEYS.md#verbs).

## 6. Architecture

Moved to [ARCHITECTURE.md](ARCHITECTURE.md): crates, providers, the cryptoki patches and
dependencies.

## 7. Nix integration

Moved to [CAKEYS.md](CAKEYS.md#nix-integration): the library, the pseudo-FOD check, the NixOS
module and what real builds may reach.

## 8. Security model

### 8.1 Enforced (with tests)

- **Identity is the CA-ID.** Every check recomputes it from the token and compares it with the lock.
- **Locators never create over occupied slots** (If-None-Match), and never match more than one
  object.
- **Type and policy of the live object** must match the spec.
- **Private keys prove possession** of the key their identity names, unless opted out per token;
  the binding is recorded and cannot weaken (§3.6).
- **Attestation commitments are verified evidence, never a standalone identity** (§3.7): the
  chain or signature is checked on the host against the pinned anchor, the attested key must be
  the material the object's portable scheme names, and the attestation is pinned per
  realisation beside a portable scheme — so the same material on another token verifies there
  through the portable scheme, attested by that token or not.
- **Identity modes never weaken.** A downgrade fails (§3.4).
- **Material is linked only through a shared scheme.**
- **The lock never holds token outputs, only their hashes.** Private data objects are not hashed.
- **Lock updates are serialized** by the advisory `<lock>.lck` sidecar; readers get consistent
  snapshots through the atomic rename — `update_lock_waits_for_the_sidecar_lock`.
- **Refused operations leave nothing behind:** checks before creating, and cleanup after a failed
  identity — except a key on a module that cannot delete keys (ykcs11), which stays and is
  reported.
- **Token paths reach only builds that require the token's feature.**

### 8.2 Not enforced / known gaps

The reviews these come from are archived: `docs/archive/REVIEW-2026-11-11.md` (code) and
`docs/archive/REVIEW-2026-11-13.md` (the threat model).

- **The check is not the use.** A consumer opens the key by its URI after `check` returns; a
  key swapped in between is not seen until the next check. This is the contract of a file or
  an HTTP resource — checked, then used — and is accepted as such ([CAKEYS.md](CAKEYS.md#the-contract-with-programs-that-use-keys)).
- **A build served from the Nix cache contacts no token** (§7.2); `nix build --check` forces
  the check.
- **The lock is the trust root, and is not signed.** Whoever can change `keys.lock` (or
  `keys.toml`) can re-pin an object. Until the lock is signed (OPEN.md), both files must live in version control whose history is signed and reviewed.
- **A commitment ID lets anyone holding the lock test guesses of a low-entropy secret.** The
  ID is SHA-256 of a MAC, under the key, of a public label (§3.3): for a random key it reveals
  nothing usable, but for a passphrase or other guessable value held as `CKK_GENERIC_SECRET`
  (or an HMAC key type) each guess can be checked offline against the lock. Private data
  objects are not hashed for this reason; secret keys are, on the assumption that they are
  random. Do not commit a lock that pins a guessable secret (review A9).
- **`tpm-certify` is experimental and pending review** (review A8): it reads tpm2-pkcs11's
  private store (sqlite schema, YAML attributes, the sealed wrapping key), which the module
  does not offer as a stable interface; a module version it was not tested with (anything but
  1.10.x) is refused (15). Without the EK certificate chain it proves **the same TPM as at first
  use**: the Attestation Key is trusted on first use and pinned in the lock, so a later
  attestation shows the object still sits in the TPM that held the AK then — not that this TPM
  is genuine hardware from a known vendor.
- **`token-asserted` bindings are unproven.** With the opt-in or `publicOnly`, a private key is
  tied to its identity only by the token's word (H1 is fixed for every `pop-*` proof —
  `h1_a_private_key_beside_an_unbound_public_object_is_a_conflict`,
  `derive_and_decrypt_only_keys_prove_possession`).
- **`piv-attestation` proves no liveness** (no verifier nonce in Yubico's certificate, §3.7):
  a malicious module could replay an old one. `tpm-certify` is nonce-bound, so it proves the
  object was loaded in that TPM at verify time.
- **The TPM Attestation Key is TOFU** (§3.7): the AK proves "this TPM", not "this genuine TPM",
  until it is chained to the Endorsement Key certificate.
- **The PIV path is verified by hand on one YubiKey, not in CI.** On a YubiKey 5C NFC FIPS
  (firmware 5.7.4, ykcs11 2.7.3): ykcs11 exposes the slot attestation certificate by label
  suffix and shared `CKA_ID`, and the f9 certificate by its bare label, with no login at all;
  the chains (slot → f9 → `Yubico PIV Attestation B 1` → `Yubico Attestation Intermediate B 1`
  → `Yubico Attestation Root 1`) verify, also with openssl; `realise`, `verify`
  and `check` pass on keys generated on device, a tampered ID is 10, a tampered root or an
  opt-out 14, an imported key under a locked attestation 14 and unlocked 15; `autoCreate` with
  `mgmKeyFile` generates; and `C_DestroyObject` was confirmed to leave the key in the slot. The
  shipped example keys are imported, so Yubico attests none of them. The opt-in
  `tests/yubikey.rs` repeats the read-write path on scratch slot `0x95` — last run
  2026-11-12 on an emptied slot, so generation ran — but nothing runs it automatically.
- **Features are self-declared.** Any user allowed to build can require a token's feature; the
  real gate is `allowed-users`.
- **No merge rule for lock fragments.** Updates are serialized by the `<lock>.lck` sidecar (M3)
  and stale entries are collected by `gc` (D3), but two hand-edited lock fragments still need a
  manual `git merge` (S16).
- **p11-kit hides the module behind it,** so the lock records p11-kit as the module.

## 9. Testing

Moved to [DEVELOPMENT.md](DEVELOPMENT.md#testing).

## 10. Frozen identifiers, and what makes a lock portable

A `keys.toml` and its `keys.lock` must verify the same way under any later cakeys, like a
dependency lock. **Lock version 1 is a draft:** it is unpublished and changes in place until every
review passes it; only then is it frozen, and later changes get a new version. The lock records the values that determine each ID: scheme name, commitment
label and the hash itself. Everything else is fixed by definition:

- **Scheme definitions are immutable.** A scheme name (`rfc7093m4`, `certhash`, `valuehash`,
  `commitment`, `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`) always denotes exactly the computation in
  §3. A changed computation is a *new* scheme name, never an edit. The known-answer test
  `scheme_definitions_are_pinned` pins each one: the bytes every commitment scheme feeds the
  token, and the `rfc7093m4` of fixed keys on every curve and RSA (canonical encoding included).
- **The lock records everything else an ID depends on:** the object `type` (key type and length
  feed the commitment label), the commitment label, the spec digest, and as provenance the
  module, token, provider and cakeys version. A changed `keys.toml` is reported as such, never as
  an unexplained hash mismatch.
- **Known answers for scheme mappings:** `commitment_mechanisms_are_pinned` fixes which HMAC hash
  each key type uses and which mechanism each scheme runs.
- **Further frozen identifiers:** the label layout `<label>/<scheme>/<keyType>/<bits>` and the
  mode names;
- the SRI form `sha256-<base64>`;
- the attestation commitment encodings: `cakeys/piv-attestation/v1` and `cakeys/tpm-certify/v1`,
  each a domain tag followed by length-prefixed fields (`attestation_definitions_are_pinned`),
  the attestation scheme names (`piv-attestation`, `tpm-certify`), the lock-record kinds
  (`yubico-piv`, `tpm-certify`) and the pinned anchors: the embedded Yubico root SPKIs
  (`the_yubico_roots_are_pinned`) and the AK handle `0x81000016` (`DEFAULT_AK_HANDLE`);
- the spec digest JSON shape (`"v":1`, camelCase, `keyType` omitted when empty, `certificateType`
  and `publicAttributes` only when set; the certificate digest changed with `certificateType`,
  since the v1 lock is a draft);
- binding names (`pop-sign`, `pop-sign-pin`, `pop-ecdh`, `pop-decrypt`, `pop-unwrap`, `token-asserted`) and their rank (the
  `pop-*` methods share the top rank). The challenge layout
  (`cakeys/pop/v1`) is pinned by `message_layout_is_pinned`, though nothing stored depends on it;
- lock field names (`objects`, `ids`, `realisations`, `object`, `locator`, `specDigest`,
  `schemes`, `pairs`, `publicOnly`, `binding`, `policy`, `immutables`, `observation`, `observed`,
  `provenance`, `origin`, `observations`, `provider`, `cakeysVersion`, `profile`,
  `module`, `token`, `mechanisms`, `uri`);
- `keys.toml` keys;
- exit codes;
- the URI shape.

The project was renamed from `key-mgmnt` on 2026-11-11 (crates, binary, NixOS options, units,
`CAKEYS_*` variables); no identity changed.

The migration method names, exposure levels and file formats are frozen the same way
([CAMIGRATE.md](CAMIGRATE.md#frozen-names-and-formats)), pinned by `method_names_are_pinned_and_round_trip`.
