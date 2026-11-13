# cakeys design (state at 2026-11-13)

This is the authoritative description of what is built. `PLAN.md` is the roadmap and history;
where the two disagree, this document wins. Review findings and open issues are tracked in
`docs/REVIEW-2026-11-11.md` (code) and `docs/REVIEW-2026-11-13.md` (architecture); the map of
the repository is `docs/ARCHITECTURE.md`. Visual overviews of the model, the verbs and the Nix loop are in
`docs/diagrams.md`.

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
| `commit-at-creation`, `host-at-import`, `token-specific` | **not implemented**. Need an explicit per-token `identity.allow` opt-in and are refused before anything is created — `weak_modes_need_per_token_opt_in`. |

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
     PIN that opened the session, never retried
     ([`CKA_ALWAYS_AUTHENTICATE.md`](CKA_ALWAYS_AUTHENTICATE.md)). It is multi-part because
     cryptoki 0.12 has no other point for the login, so the single-part-only mechanisms
     (`CKM_EDDSA`, raw `CKM_ECDSA`) and a module that refuses to sign in parts (SoftHSM's
     `CKM_ECDSA_SHA*`) are refused (15); a declared always-authenticate Edwards key is invalid
     (17). A cryptoki patch for a single-part sign after `C_SignInit` would lift both.
   - `pop-ecdh` (EC keys that only derive): the host generates an ephemeral key on the same curve
     and MACs the challenge with HMAC-SHA256 under the ECDH shared secret; the token derives the
     same secret with `CKM_ECDH1_DERIVE` into a non-extractable session key and MACs the same
     challenge. The MACs agree only for the matching private key.
   - `pop-decrypt` (RSA keys that only decrypt): the host encrypts the challenge to the public key
     with RSA-OAEP (SHA-1, MGF1-SHA1 — the PKCS#11 baseline; SoftHSM implements no other OAEP);
     the token decrypts with `CKM_RSA_PKCS_OAEP`. The plaintext matches only for the matching
     private key.
3. The host checks the proof with RustCrypto against the same canonical SPKI it hashes into
   `rfc7093m4` (signature verification, MAC comparison, plaintext comparison — all constant
   time where it matters). No proof value is ever stored.

Outcomes:

- **A proof that does not verify is a conflict (exit 13):** the private key under the locator
  is not the one the identity names. This also applies to `delete`, so If-Match cannot pass on a
  public object beside an unrelated key.
- **A token that refuses** (no `CKA_SIGN`/`CKA_DERIVE`/`CKA_DECRYPT`, missing mechanism) is exit
  15. A token error is 16, as is a failed context-specific login. `pop-ecdh` and `pop-decrypt`
  have no per-use login: a `CKA_ALWAYS_AUTHENTICATE` key that only derives or decrypts is refused
  (16).
- **The spec must declare the capability the proof uses** — `CKA_SIGN = true` for `pop-sign`,
  `CKA_DERIVE = true` for `pop-ecdh` (Weierstrass EC keys only), `CKA_DECRYPT = true` for
  `pop-decrypt` (RSA only) — or opt out per token with `binding = "token-asserted"`; otherwise it
  is invalid (exit 17). The rule uses declared attributes only, like `declared_commits`.
- **Opting out is needed** for keys with no provable capability, Ed448 (no RustCrypto verifier
  or ECDH yet), and tpm2-pkcs11 1.10.1 P-521 keys: its `C_SignInit` parses its own malformed
  `CKA_EC_POINT` and fails (`upstream/tpm2-pkcs11` fixes both).
- **`publicOnly` implies `token-asserted`.**
- **`pop-sign-pin` is recorded, never configured:** `binding = "pop-sign-pin"` in keys.toml is
  invalid (17); `pop-sign` (the default) becomes it on an always-authenticate key.

The lock records the binding per realisation (`pop-sign`, `pop-sign-pin`, `pop-ecdh`,
`pop-decrypt` or `token-asserted`). The `pop-*` methods share the top rank — each proves possession of the same
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

```toml
[tokens.<name>]
module = "/path/libfoo.so"     # or --module <name>=<path>; $NAME or ${NAME} reads the path from the environment (17 if unset)
provider = "tpm2-pkcs11"       # optional; auto-detected (§6.2)
tokenLabel = "..."
pinFile = "/path" | pinEnv = "VAR"     # optional; pinEnv wins if both are set; pinFile may be $NAME: the path, from the environment
mgmKeyFile = "/path" | mgmKeyEnv = "VAR"  # optional; admin (SO) credential for modules that create keys only as SO (ykcs11: the PIV management key in hex, or the PIN when the management key is PIN-protected); mgmKeyEnv wins; mgmKeyFile may be $NAME; needs pinFile/pinEnv (17)
systemFeature = "token-<name>"         # read by the Nix library only

[tokens.<name>.options]        # the provider's own settings, checked when the token opens (17 for an unknown name, or any option on a provider that takes none)
tcti = "device:/dev/tpmrm0"    # tpm2-pkcs11: TPM2_Certify TCTI (default: the module's $TPM2_PKCS11_TCTI, then $TPM2TOOLS_TCTI, $TCTI)
tpm2Store = "~/.tpm2_pkcs11"   # tpm2-pkcs11: the module's sqlite store (default: where tpm2-pkcs11 looks)
akHandle = "0x81000016"        # tpm2-pkcs11: cakeys' Attestation Key handle (§3.7)

[objects.<name>]
class = "CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY" | "CKO_SECRET_KEY" | "CKO_CERTIFICATE" | "CKO_DATA"
keyType = "CKK_EC" | ...        # keys; certificates and data objects take none
certificateType = "CKC_X_509"   # certificates only (exit 17 otherwise)
curve = "..." ; modulusBits = N ; valueLen = BYTES   # curve names are canonicalized on load (P-256 -> secp256r1); valueLen at most 2^32 - 1 (17)

[specs.<name>]
object = "<object>"
attributes = { CKA_SIGN = true, ... }   # settable booleans the class may carry (PKCS#11 3.2 §4), or CKA_ALLOWED_MECHANISMS = ["CKM_..."] on key objects; a wrong name or class is exit 17
publicAttributes = { CKA_VERIFY = true, ... }   # private keys only: policy of the public key object; checked on it, in the digest only when present
tokens.<token> = { locator = { CKA_LABEL = "...", CKA_ID = "hex" }, autoCreate = bool, publicOnly = bool, binding = "pop-ecdh" | "pop-decrypt" | "token-asserted", attestation = bool, identity.allow = [...] }
```

`tokens.<t>.attestation = true` (in a spec's token entry) opts into the attestation commitment
(§3.7). The tpm2-pkcs11 settings of the native certify path (`tcti`, `tpm2Store`, `akHandle`)
live in the token's `[tokens.<name>.options]` (§3.7; `Tpm2Options`).

What may be created and adopted:

- **References are checked at load** (exit 17): a spec's `object` must name an `[objects.<name>]`
  table — also when nothing uses the spec — and a `$NAME`/`${NAME}` path reference (in `pinFile`
  or `module`) must name a set environment variable; one shared `keys.toml` can then carry
  machine-specific paths. `pinEnv = "VAR"` remains the way to pass the *PIN itself* through the
  environment — `env_references_and_object_refs_are_checked_at_load`,
  `pin_file_path_can_come_from_the_environment`.
- **The admin credential (`mgmKeyFile`/`mgmKeyEnv`) is read only to create or delete, and only where the module requires it.** A
  provider declares that its module creates and destroys objects only in an SO session
  (ykcs11 does); on any other provider the field is refused (17) when the token opens, since an
  SO there cannot do what the user does — `admin_credential_is_refused_where_the_user_creates_keys`.
  Login state is per token, so the step logs the user out, logs in as SO, generates (or
  destroys), logs out and logs the user back in; the SO credential is read just before and
  zeroized after. `resolve`, `verify` and `check` never read it.
- **`autoCreate`** is allowed for private and secret keys only. Certificates, public keys and data
  objects are adopted — `adoption_rules_are_validated`, `standalone_public_key_objects`,
  `data_objects_…`. When the lock already pins the object's material (ids recorded, from this or
  another token), `autoCreate` is refused (14) before anything is created: generated material
  could never match (D1) — `autocreate_never_fights_a_locked_identity`. Put the same material
  under the locator instead, or give the token's key its own object name.
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

```toml
version = 1                          # required; any other version is refused (v1 is a draft, §10)
[objects.<object>]
commitmentLabel = "key-management/v1" # required when ids holds a commitment scheme
[objects.<object>.type]              # required with ids: the type the IDs were computed for
class = "..." ; keyType = "..." ; certificateType = "..." ; curve = "..." ; valueLen = N ; modulusBits = N
[objects.<object>.ids]
rfc7093m4 = "sha256-..."            # scheme -> SRI
# pairs = ["<object>"]              # (in [objects.<object>]) objects sharing its rfc7093m4: key <-> certificate

# Compared: verification fails (14) when keys.toml or the token disagrees. All required.
[realisations.<spec>.<token>]
object = "<object>"                 # the object this spec realised
locator = { CKA_LABEL = "...", CKA_ID = "hex" }  # where it was found
specDigest = "sha256-..."
mode = "direct"                      # a weaker mode is refused
schemes = ["rfc7093m4"]              # schemes this realisation computed and matched; fewer later is refused
publicOnly = true                    # only when set
binding = "pop-sign"                 # private keys: pop-sign | pop-sign-pin | pop-ecdh | pop-decrypt | token-asserted (§3.6)
attestation = { kind = "tpm-certify", root = "sha256-...", id = "sha256-..." }   # §3.7: only when the spec opted in; the per-device attestation ID and its anchor; a change fails (14 anchor, 10 ID), also when the lock is written
[realisations.<spec>.<token>.policy] # every attribute of the class the token shows: booleans, plus CKA_ALLOWED_MECHANISMS on key objects
CKA_SIGN = true ; CKA_DECRYPT = true ; CKA_EXTRACTABLE = false ; ...
[realisations.<spec>.<token>.immutables] # keys: fixed at creation
CKA_LOCAL = true ; CKA_NEVER_EXTRACTABLE = true ; CKA_ALWAYS_SENSITIVE = true ; CKA_KEY_GEN_MECHANISM = "CKM_..."

# Observed: facts about the token; never change a verdict (optional).
[realisations.<spec>.<token>.observed]
uri = "pkcs11:token=...;serial=...;object=...;id=%..;type=private|public|cert|secret-key|data"
session = "user"                     # user (logged in) or public: what the duplicate-ID check could see
mechanisms = ["CKM_..."]             # usable mechanisms; feeds functions.<token> in Nix

# Provenance: what produced the record; differences warn or note (optional).
[realisations.<spec>.<token>.provenance]
provider = "softhsm"
cakeysVersion = "0.1.0"
[realisations.<spec>.<token>.provenance.module] # C_GetInfo, and the file the loader mapped
path = "/nix/store/…/libsofthsm2.so" ; hash = "sha256-…" ; description = "..." ; manufacturer = "..." ; version = "M.m" ; cryptoki = "M.m"
[realisations.<spec>.<token>.provenance.token]  # C_GetTokenInfo
model = "..." ; serial = "..." ; firmware = "M.m"
```

- **Every realisation field has one class:** compared, observed or provenance. Removing `observed`
  and `provenance` changes no verdict, and a lock without `version` or a compared field is
  invalid (exit 17) — `observed_and_provenance_never_change_a_verdict`. An observed mechanism the
  token no longer offers is a warning.
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
- **Provenance:** a different module build identity or token is a *warning*, and so is a
  different module file `hash` at the same `path` (the file replaced in place, which a path
  outside the Nix store cannot show); only a different module file `path` is a *note*. None
  fails — `module_and_token_provenance_warn_but_do_not_fail`. The `path` is the file the dynamic
  loader mapped, symlinks resolved, whatever named it (`$NAME`, `--module`, a bare name found
  by the library search).
- **The spec digest** is the SHA-256 of canonical JSON `{"v":1,"type":<object, camelCase>,
  "attributes":<…>}`, with keys sorted at every level explicitly (independent of serde_json
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

## 5. Verbs (HTTP-like) and exit codes

| Verb | Semantics |
|---|---|
| `validate` | Static check of modes, opt-ins, types and provider names; touches no token. Then the capability-profile gate (docs/PROVIDERS.md phase 4): each spec's needs — its commitments' mechanisms, generating its type, curve and size when `autoCreate`, an attestation — against its token's profiles, resolved from the lock's recorded module and token or keys.toml's `provider`; a profile's *no* is refused (15) naming the profile, *unknown* is a note. |
| `resolve <spec> --token` | GET: find (exactly one), check type and policy, compute IDs, print JSON. Never writes. For a private key, every public key object under the locator must hold its own public key — a consumer may select the public half by the locator alone — else a conflict (13, `a_foreign_public_key_conflicts_and_is_never_deleted`); `verify`, `realise` and `check` resolve the same way. |
| `verify <spec> --token` | GET with If-Match against the lock; prints the URI. |
| `realise <spec> --token [--no-update-lock]` | PUT, recording what the lock lacks (§3.5), and prints the resolved JSON. If absent and `autoCreate`: refused (14) when the lock already pins the object's material — generated material could never match (D1, `autocreate_never_fights_a_locked_identity`). **If-None-Match** — never create when anything sits under the locator (`never_create_over_an_occupied_locator`), nor from a session without login, which cannot see private objects there (16). Then create, compute and compare. If the identity of a just-created object cannot be established, it is destroyed (`tpm2_identity_failure_after_create_leaves_nothing`); on a module that cannot delete keys (ykcs11) the key stays and the message says so. Re-running never duplicates (`ec_lifecycle`). |
| `create [<spec>] [--token T] [--no-update-lock]` | PUT, asked for explicitly: every selected (spec, token) pair whose object the lock does not pin yet is created and recorded as `realise` would with `autoCreate`, which only opts the first-use flows (`realise`, `check`) into creating; pinned, adopted-only (certificates, public keys, data) and `publicOnly` pairs are skipped with a note. Naming both the spec and `--token` creates that pair or says why not (a pinned object its token lost: 14). A name that selects nothing is refused (an unknown spec 11, an unknown token 17, a spec without that token 11), never an empty success. One token is open at a time, so tokens of one module follow each other. Prints the realised objects as a JSON array; what was created before a failure — opening the next token included — is still recorded (`create_makes_keys_without_autocreate`, `create_records_what_it_made_before_a_failure`). |
| `delete <spec> --token [--if-match ID] [--no-update-lock]` | DELETE with If-Match. Absent is success, even without a lock — but a session without login cannot see a private object, so it never reports one absent (16); a present object with no expected ID is never deleted (`ec_lifecycle`), and only what was identified is removed: a private key's public half only when it holds the same key, never another key's public object under the locator (`delete_removes_only_what_it_identified`); a key on a module whose delete leaves it in place (ykcs11) is refused (15), never claimed. Unless `--no-update-lock`, it removes the realisation but keeps `objects.<name>.ids`, since the material may live on other tokens. |
| `check <obj>[.id.<scheme>] [--token] [--spec]` | The pseudo-FOD pre-use check: realise without writing the lock, print the URI. Schemes the spec or token can never compute are refused before anything is created (`scheme_the_token_lacks_is_refused_before_create`). |
| `gc [--apply]` | Print lock entries `keys.toml` no longer names, as table names; `--apply` removes exactly what it printed, holding the update lock (M3). Live objects keep their `ids` (`gc_prints_then_removes_stale_entries`). |
| `caps --token` | Provider and usable mechanisms, as JSON. |
| `export`, `migrate` `--dry-run`; `transport` | Plan moving objects to a target (MIGRATE.md): per object the method, the exposure on the way, or why it cannot move. Only planning is implemented; `transport` writes a target's transport file. |
| `supports [--profile \| --token] NAME` | Ask the capability profiles (docs/PROVIDERS.md) what a module supports: pure data, no token touched; 0 yes, 15 no, 16 unknown. With `--profile` it needs no keys.toml. |
| `probe --token [--write] [--diff P] [--out F]` | Generate a token's capability profile by probing it; `--write` only on a token marked `scratch` (17 otherwise); `--diff` drift is 15. |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | ok |
| 10 | hash mismatch; prints `got: sha256-…`, which is also first use |
| 11 | not found |
| 12 | ambiguous |
| 13 | conflict |
| 14 | precondition failed |
| 15 | unsupported |
| 16 | unavailable |
| 17 | invalid config, lock, spec or token options |
| 1 | I/O or other |
| 2 | command-line usage (clap) |

## 6. Architecture

### 6.1 Crates

| Crate | Role |
|---|---|
| `cakeys-core` | No `cryptoki`, no token access: config (`config`, typed classes, key types and schemes in `types`/`id`), the boolean-attribute table (`attrs`), CA-IDs (`id`), proof-of-possession host math and signature verification (`pop`, `sig`), what a spec asks for (`plan`: `Target`, `plan_mode`), and the lock rules (`reconcile`: `compare`, `record`, `Notes`), unit-tested without an HSM |
| `cakeys-profile` | Capability profiles as data (docs/PROVIDERS.md): the baseline generated from the vendored PKCS#11 headers, the embedded module and layer profiles (`profiles/`), the effective view of a stack (`Effective`, `Verdict`) and the profile diff. No token access |
| `cakeys-pkcs11` | the `cryptoki` token layer (`token/`: session and SO step, policy, generation, identity, proof of possession, URIs), the verbs (`ops`, with `create` over its selected pairs; `supports`; `probe`; `migrate`, the move planning), profile resolution and the static gate (`resolution`, `binding`, `gate`), `Provider` and `Registry`, and the built-in providers without code of their own (`providers`: softhsm, kryoptic, p11-kit) |
| `cakeys-{ykcs11,tpm2-pkcs11}` | providers with native paths and dependencies of their own (Yubico roots; tss-esapi, sqlite) |
| `cakeys` (crates/cli) | Arguments, files and printing only — the verbs' logic is in `cakeys-pkcs11`, so another front end need not reimplement it (`validate`'s loop over the gate is the one exception left). CLI as a library: `main(registry)`, `default_registry()`; `examples/custom-provider.rs`. Cargo features `ykcs11` and `tpm2` (both default) link those providers; `checks.minimal` builds without them, and so without tpm2-tss and sqlite |

### 6.2 Providers

- **Hooks:** `name`, `matches(&ModuleInfo)`, and optionally `mechanisms` (filter) and
  `migration` (both overridden by no in-tree provider today: the capability profiles answer
  them; kept for real-world HSM providers, review A4), `ec_point` (repair), `hint` (error advice), `check_options` (the token's `[tokens.<t>.options]`; the
  default refuses any), `manages_as_so`/`check_create`/`keeps_destroyed_keys` (key
  management on modules that create only as SO or cannot delete keys: ykcs11) and
  `attestation`/`attest` (§3.7).
- **Selection:** an explicit `provider` wins; an unknown name is exit 17. Otherwise the first
  registered provider that matches, else `generic` — `provider_is_detected_or_named`, registry unit
  test.
- **The fix-up rule:** a hook must return exactly what a spec-compliant module would, so
  identities are portable. That is also why the provider never takes part in an identity: the
  lock records it only as provenance (`provenance.provider`, §4.2), where a change warns.

| Provider | Quirks handled or recorded |
|---|---|
| softhsm | none (reference); attests nothing |
| kryoptic | none to fix (PKCS#11 3.2 reference): Edwards `CKA_EC_POINT` raw (DER with `KRYOPTIC_EC_POINT_ENCODING=DER`; same identity); private keys carry their own `CKA_PUBLIC_KEY_INFO`, so a swapped key is refused (13) by the cross-check before the proof of possession; library version 0.0 in `C_GetInfo`; no secp256k1 or brainpool generation (15); attests nothing |
| ykcs11 | `CKA_PUBLIC_KEY_INFO` length 0 then `CKR_ARGUMENTS_BAD` (tolerated generically); fixed PIV slot IDs and labels: `autoCreate` needs a locator of `CKA_ID` alone naming a key slot (`01`–`04`: 9a/9c/9d/9e, `05`–`18`: 82–95; 17 otherwise) and `mgmKeyFile`/`mgmKeyEnv` (the management key in hex, or the PIN on a PIN-protected-management-key device), since ykcs11 generates only as SO; **keys cannot be deleted** — `C_DestroyObject` clears only the slot's certificate and the key stays, so `delete` (and the cleanup after a failed `realise`) refuses (15), naming `ykman piv keys delete <slot>`; the `piv-attestation` commitment: per-slot attestation certificates found by their label/`CKA_ID`, chain-verified to the embedded Yubico roots (`roots/`, §3.7) |
| tpm2-pkcs11 | drops `AES_KEY_GEN`/`GENERIC_SECRET_KEY_GEN` (`C_GenerateKey` unsupported); repairs the malformed P-521 `CKA_EC_POINT` (`04 85 …`; upstream draft in `upstream/tpm2-pkcs11/`) — `tpm2_*` tests; the `tpm-certify` commitment: a native `TPM2_Certify` through tss-esapi and the module's sqlite store (§3.7) |
| p11-kit | detects the proxy; the RPC drops AES key wrap and EdDSA/Edwards mechanisms; the module behind it is hidden (set `provider` explicitly) — `p11kit_*` tests; attests nothing itself (what the proxied module exposes decides, but the provider name does not reach it: opt in only against the real module) |

### 6.3 cryptoki patch

cryptoki ≤ 0.12.1 gives `KeyType::SHA224/384/512_HMAC` the value of `CKK_SHA256_HMAC`. The Nix
build patches it with `nix/patches/cryptoki-hmac-key-types.patch`, applied in `postPatch` to
`$cargoDepsCopy`. Without the patch, those types are refused (`hmac_key_type`), and tests skip
unless required. Upstream draft: `upstream/rust-cryptoki/`.

### 6.4 Dependencies

Policy: always the latest release. Audit on every dependency change by comparing
`[workspace.dependencies]` with crates.io, and the flake inputs (nixpkgs, treefmt-nix).

- **2026-11-11:** every crate is on its latest release (cryptoki 0.12.1, RustCrypto 0.14/pkcs8 0.11
  generation, toml 1.x, base64 0.23, clap 4, serde 1, thiserror 2, anyhow 1). nixpkgs is from
  2026-11-06.
- **Pinned on purpose:** none. The cryptoki HMAC key-type patch is a local fix on top of the latest
  release.
- **Toolchain:** edition 2024, `rust-version = 1.89` (the workspace's MSRV; Nix builds with the
  nixpkgs rustc).

## 7. Nix integration

### 7.1 Library (`lib.mkKeys`, builtins only)

One calling convention: **every object is a function**. The call resolves the object's one
(spec, token) pair — the arguments are optional when there is exactly one — and returns plain
data, so consumers destructure once and reuse:

```nix
signing = keys.signing { token = "softhsm"; };      # { } when the object has one pair
shared  = keys.shared { token = "softhsm"; spec = "shared-sign"; };  # several specs on one token
```

- The result carries `type`, `id.<scheme>` (`pubkeyhash` is an input alias), the resolved
  `spec`/`token`, and the pair's realisation: `uri`, `mode`, `specDigest`, `module`, `tokenInfo`,
  `functions` (mechanism → `true`), `requiredSystemFeatures` and `check`.
- **`check`** is the shell command for the pre-use check (prints the URI); `scheme = "certhash"`
  requires that identity, and the resolved pair is passed explicitly. Interpolating config, lock
  and module makes them build inputs. Like `id`, `type` and `requiredSystemFeatures`, it is usable
  before anything is recorded in the lock — the first-use pseudo-FOD flow; only the realisation's
  own fields throw on a missing record.
- A call that does not name exactly one pair throws, listing the choices — so does a missing
  realisation, naming the `realise` command to run.
- Tested by `checks.lib` (synthetic fixture) and `checks.vm` (consumer built in the guest sandbox).

### 7.2 Pseudo-FOD check

A consumer derivation requires the token's feature and runs `check` before using the URI.

1. **First use** creates the key (with `autoCreate`) and fails with `got:` — `check` never
   writes, and in the sandbox it could not.
2. Record the ID out of band (`realise`, outside the sandbox; it writes the lock by default).
3. Every later build verifies first.

**Caveat:** a cached consumer is not rebuilt, so the token is not re-contacted; `nix build --check`
forces it. The VM test covers all of this.

### 7.3 NixOS module (`nixosModules.default`, `services.cakeys`)

- **`tokens.<n>.{systemFeature, sandboxPaths, pcscd}`.** The features are added to
  `system-features`. Paths are **not** global `extra-sandbox-paths`: a pre-build-hook
  (`nix/sandbox-hook.sh`, bash + jq over `nix derivation show`) grants them only to builds whose
  `requiredSystemFeatures` name the token's feature.
  - It reads plain, structured-attrs (JSON v4) and `env.__json` derivations.
  - It emits only existing paths from the module's map.
  - It always exits 0 and grants nothing on error.
  - Test: `checks.module`, *the hook grants token paths only to builds requiring the token's feature*.
- **`sandbox.pcscd.enable`:** pcscd, plus a polkit rule for nixbld or the auto-allocated UID range,
  plus `PrivateUsers=false` with auto UIDs.
- **`sandbox.tpm2.enable`:** a udev ACL on `/dev/tpmrm*` for every build GID: the nixbld GID, or,
  with `auto-allocate-uids`, each 65 536-ID slot's first UID, which is also its GID. Test:
  `checks.tpm`, with auto UIDs, uid-range, nixbld, and a stripped-ACL control.
- **`sandbox.uidRange.enable`:** `auto-allocate-uids` and the `uid-range` feature.
- **`checks.<n>`:** a oneshot `cakeys-check-<n>` unit running `check`, required by the
  units that use the key — `checks.module`.

### 7.4 What real builds may reach

- **Allowed:** a **p11-kit forwarding socket** (`p11-kit server` outside the sandbox) or a **real
  TPM** (`/dev/tpmrm0`).
- **Never** a token database: SoftHSM files allow offline PIN guessing and key extraction.
- **SoftHSM paths in tests are for testing only.**
- **PINs:** p11-kit login is per client (`p11kit_login_is_per_client`). A build that uses private
  objects needs the PIN, through a granted file; `publicOnly` needs none.

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
- **Weak identity modes need an explicit per-token opt-in.** Downgrades fail.
- **Material is linked only through a shared scheme.**
- **The lock never holds token outputs, only their hashes.** Private data objects are not hashed.
- **Lock updates are serialized** by the advisory `<lock>.lck` sidecar; readers get consistent
  snapshots through the atomic rename — `update_lock_waits_for_the_sidecar_lock`.
- **Refused operations leave nothing behind:** checks before creating, and cleanup after a failed
  identity — except a key on a module that cannot delete keys (ykcs11), which stays and is
  reported.
- **Token paths reach only builds that require the token's feature.**

### 8.2 Not enforced / known gaps

See `docs/REVIEW-2026-11-11.md` and, for the threat model these follow from,
`docs/REVIEW-2026-11-13.md`.

- **The check is not the use.** A consumer opens the key by its URI after `check` returns; a
  key swapped in between is not seen until the next check. This is the contract of a file or
  an HTTP resource — checked, then used — and is accepted as such (docs/CONTRACT.md, "The gap
  between check and use").
- **A build served from the Nix cache contacts no token** (§7.2); `nix build --check` forces
  the check.
- **The lock is the trust root, and is not signed.** Whoever can change `keys.lock` (or
  `keys.toml`) can re-pin an object. Until the lock is signed (docs/SCOPE.md, "Signing the lock
  file"), both files must live in version control whose history is signed and reviewed.
- **A commitment ID lets anyone holding the lock test guesses of a low-entropy secret.** The
  ID is SHA-256 of a MAC, under the key, of a public label (§3.3): for a random key it reveals
  nothing usable, but for a passphrase or other guessable value held as `CKK_GENERIC_SECRET`
  (or an HMAC key type) each guess can be checked offline against the lock. Private data
  objects are not hashed for this reason; secret keys are, on the assumption that they are
  random. Do not commit a lock that pins a guessable secret (review A9).
- **`tpm-certify` is experimental and pending review** (review A8): it reads tpm2-pkcs11's
  private store (sqlite schema, YAML attributes, the sealed wrapping key), which the module
  does not offer as a stable interface, and it does not yet refuse a module version it was not
  tested with.
- **The schema accepts options that are not implemented** (review A6): `identity.allow` and
  the modes `commit-at-creation`, `host-at-import` and `token-specific` parse and validate,
  then every verb refuses them (15).
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
  `tests/yubikey.rs` (§9) repeats the read-write path on scratch slot `0x95` — last run
  2026-11-12 on an emptied slot, so generation ran — but nothing runs it automatically.
- **Features are self-declared.** Any user allowed to build can require a token's feature; the
  real gate is `allowed-users`.
- **No merge rule for lock fragments.** Updates are serialized by the `<lock>.lck` sidecar (M3)
  and stale entries are collected by `gc` (D3), but two hand-edited lock fragments still need a
  manual `git merge` (S16).
- **p11-kit hides the module behind it,** so the lock records p11-kit as the module.

## 9. Testing

| Suite | Where | What |
|---|---|---|
| unit | `cargo test --workspace` | digests (pinned), curves and OIDs, SPKI round-trips, registry, P-521 fix-up, hex parsing, proof-of-possession host math (both ECDH MAC sides), the signature verifiers, the deprecation register and scheme names, AES strength order, the observed policy vectors, the attestation scheme definitions and lock invariants, the lock rules (first use, what a write may override, attestation changes, provenance warnings), the PIV chain verifier (fixture chain + Yubico's own roots and intermediates) |
| `crates/core/tests/properties.rs` | `cargo test --workspace` | proptest: recording then comparing passes and a second write changes nothing; after a recorded realisation, another material is 10 and a weaker binding or replaced object 14 in both modes, drift fails only a compare, and a successful write never overwrites a locked ID; material links only through a shared scheme (disjoint 14, other material 10, else gaps filled); the attestation and commitment-label encodings are injective; `sri`/`is_sri` agree; key and certificate parsers and the loaders never panic. Mutation-checked: disabling the binding-downgrade or the shared-scheme rule fails it |
| `checks.fuzz`, `apps.fuzz` | package build / host | cargo-fuzz targets (`fuzz/`: `public_key`, `certificate`, `lock`, `config`) on the stable rustc (`RUSTC_BOOTSTRAP=1`, no sanitizer, debug assertions): the check runs 100 000 inputs per target from a fixed seed and the fixtures; `nix run .#fuzz -- <target> [libFuzzer flags]` runs one as long as wanted |
| `tests/softhsm.rs`, `tests/kryoptic.rs` | package build | one shared suite (`tests/reference/`) against each software reference: lifecycle, every type and scheme against independent oracles (hand-written DER encoder, openssl-hashed fixtures, RustCrypto `hmac`/`cmac`/`aes`/`aes-kw`); the same verdicts on both, with each token's facts in its `Reference` descriptor (`tests/common/`) |
| `tests/tpm2.rs` | package build, `nix/tpm2-test-env.sh` | swtpm + tpm2-abrmd + tpm2-pkcs11; the native `tpm-certify` attestation (AK provisioning and validation, reads that never provision, a lost attestation as a downgrade, cross-checks), one material attested on two tokens with an attestation each, and the travel of attested material to SoftHSM through the shared portable scheme |
| `tests/p11kit.rs` | package build, `nix/p11kit-test-env.sh` | SoftHSM behind `p11-kit server`, compared with direct access |
| `tests/references.rs` | package build | cross-reference: the same material (the P-256 and RSA fixtures, P-384/P-521/Ed25519/Ed448 exported from one reference, AES, generic secret and HMAC values, a certificate, a data object) planted on SoftHSM, kryoptic (raw and DER Edwards points), SoftHSM behind p11-kit and — what `tpm2_ptool` imports — tpm2-pkcs11, realised into one lock: one identity per scheme everywhere; and the same verdict for the same scenario (absent 11, two objects 12, another type 13, a swapped private key 13) |
| `tests/yubikey.rs` | opt-in, never in the Nix build (`CAKEYS_TEST_YUBIKEY_MODULE`, `_PIN`, `_MGM` — file paths; the secrets are only ever read from them) | a real YubiKey, read-write: generate into the scratch PIV slot `0x95` in an SO step, then (back as the user) attest it and prove possession by signing, record, verify; `delete` refused (15) with the realisation kept; re-realise idempotent — each CLI run bounded, so a touch or PIN prompt fails instead of waiting (`rw_lifecycle_generates_attests_proves_and_refuses_delete_without_touch`) |
| `checks.vm` / `test-nspawn` | QEMU / systemd-nspawn | the CLI flow; in the VM also the pseudo-FOD consumer built in the guest sandbox |
| `checks.module`, `checks.tpm`, `checks.lib` | QEMU / eval | module, hook, pcscd, TPM ACL, Nix library |
| `checks.minimal` | package build | the CLI without its `tpm2`/`ykcs11` features builds without tpm2-tss and sqlite |
| `checks.formatting` | treefmt | `nix fmt` would change nothing: the formatters and linters in `treefmt.nix` (rustfmt with `rustfmt.toml`, nixfmt, taplo, shfmt, rumdl, keep-sorted, statix, deadnix, shellcheck, typos) |
| `scripts/xversion.sh` | by hand, per refactor | a lock recorded by one build verifies, compares and re-records byte-identically with another (every class) |

Hardware: the YubiKey example lock is verified read-only (no PIN), and `tests/yubikey.rs` exercises
a real YubiKey read-write when opted in (§9 table above). `packages.test-nspawn` needs the
`uid-range` feature, so it is outside `checks`.

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
- binding names (`pop-sign`, `pop-sign-pin`, `pop-ecdh`, `pop-decrypt`, `token-asserted`) and their rank (the
  `pop-*` methods share the top rank). The challenge layout
  (`cakeys/pop/v1`) is pinned by `message_layout_is_pinned`, though nothing stored depends on it;
- lock field names (`objects`, `ids`, `realisations`, `object`, `locator`, `specDigest`,
  `schemes`, `pairs`, `publicOnly`, `binding`, `policy`, `immutables`, `observed`, `provenance`,
  `module`, `token`, `mechanisms`, `uri`);
- `keys.toml` keys;
- exit codes;
- the URI shape.

**Renamed on 2026-11-11 (`key-mgmnt` → `cakeys`).** The rename changed only names:

- crates `key-mgmnt-*` → `cakeys-*`;
- the binary `key-mgmnt` → `cakeys`;
- `services.key-management` → `services.cakeys`;
- units `key-management-check-*` → `cakeys-check-*`;
- the hook `key-mgmnt-sandbox-hook` → `cakeys-sandbox-hook`;
- env vars `KM_*` → `CAKEYS_*` (`CAKEYS_CONFIG`, `CAKEYS_LOCK`, test variables);
- `mkKeys { keyMgmnt }` → `mkKeys { cakeys }`.

Existing locks and IDs stay valid. `PLAN.md` keeps the old name in its history.
