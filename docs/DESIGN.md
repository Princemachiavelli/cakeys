# cakeys design (state at 2026-11-11)

This is the authoritative description of what is built. `PLAN.md` is the roadmap and history;
where the two disagree, this document wins. Review findings and open issues are tracked in
`docs/REVIEW-2026-11-11.md`. Visual overviews of the model, the verbs and the Nix loop are in
`docs/diagrams.md`.

## 1. Purpose

Declare PKCS#11 (and later TPM) objects in a file, and address them by a **content-addressed
identity (CA-ID)**: a hash of the object's material, not a name. Names (labels, IDs, URIs, slot
numbers) are only *locators*: arbitrary, mutable, and not identity. A lock file records each
object's CA-IDs. Every use first proves that the token still holds that material. In Nix this
check runs inside the build sandbox as a pseudo fixed-output check.

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

- **Commitment schemes never reveal what the token computed.** The lock stores only SHA-256 of the
  token's output, never a MAC or ciphertext under the key — `aes_commitments_…` asserts the raw
  CMAC is absent from the lock.
- **Which commitment schemes are computed** follows the spec's *declared* usage bits, never token
  defaults. The preference order (the first computed is the primary scheme) is
  `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`.
- **Only mechanisms the token offers are used.** If none fits, the result is *unsupported* (exit 15).

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
  `realise --update-lock` never records a *new* identity under it: migrate by realising a spec that
  computes the replacement. (`gc` will not drop the old entry: the identity is still true.)
- **No scheme is deprecated today.** The register is `DEPRECATED_SCHEMES` in
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
- **`--update-lock` only fills gaps.** It never overwrites a locked ID.
- **A computed scheme missing from an otherwise matching lock is a note.** This happens, for
  example, when a newer version computes more schemes.
  - With nothing to compare, it is first use: hash mismatch (exit 10), printing `got:`.
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
  15. A token error is 16. A key with `CKA_ALWAYS_AUTHENTICATE` is refused (16) rather than
  spending a PIN entry each run.
- **The spec must declare the capability the proof uses** — `CKA_SIGN = true` for `pop-sign`,
  `CKA_DERIVE = true` for `pop-ecdh` (Weierstrass EC keys only), `CKA_DECRYPT = true` for
  `pop-decrypt` (RSA only) — or opt out per token with `binding = "token-asserted"`; otherwise it
  is invalid (exit 17). The rule uses declared attributes only, like `declared_commits`.
- **Opting out is needed** for keys with no provable capability, Ed448 (no RustCrypto verifier
  or ECDH yet), and tpm2-pkcs11 1.10.1 P-521 keys: its `C_SignInit` parses its own malformed
  `CKA_EC_POINT` and fails (`upstream/tpm2-pkcs11` fixes both).
- **`publicOnly` implies `token-asserted`.**

The lock records the binding per realisation (`pop-sign`, `pop-ecdh`, `pop-decrypt` or
`token-asserted`). The `pop-*` methods share the top rank — each proves possession of the same
key — so a realisation never weakens unless it drops to `token-asserted`, which is refused
(exit 14), also under `--update-lock` — `binding_downgrade_is_refused`.

## 4. Files

### 4.1 `keys.toml`
```toml
[tokens.<name>]
module = "/path/libfoo.so"     # or --module <name>=<path>; $NAME or ${NAME} reads the path from the environment (17 if unset)
provider = "tpm2-pkcs11"       # optional; auto-detected (§6.2)
tokenLabel = "..."
pinFile = "/path" | pinEnv = "VAR"     # optional; pinEnv wins if both are set; pinFile may be $NAME: the path, from the environment
mgmKeyFile = "/path" | mgmKeyEnv = "VAR"  # optional; the admin credential for modules whose management operations need one (§6.2 ykcs11)
systemFeature = "token-<name>"         # read by the Nix library only

[objects.<name>]
class = "CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY" | "CKO_SECRET_KEY" | "CKO_CERTIFICATE" | "CKO_DATA"
keyType = "CKK_EC" | ...        # keys; certificates and data objects take none
certificateType = "CKC_X_509"   # certificates only (exit 17 otherwise)
curve = "..." ; modulusBits = N ; valueLen = BYTES   # curve names are canonicalized on load (P-256 -> secp256r1)

[specs.<name>]
object = "<object>"
attributes = { CKA_SIGN = true, ... }   # settable booleans the class may carry (PKCS#11 3.2 §4), or CKA_ALLOWED_MECHANISMS = ["CKM_..."] on key objects; a wrong name or class is exit 17
publicAttributes = { CKA_VERIFY = true, ... }   # private keys only: policy of the public key object; checked on it, in the digest only when present
tokens.<token> = { locator = { CKA_LABEL = "...", CKA_ID = "hex" }, autoCreate = bool, publicOnly = bool, binding = "pop-ecdh" | "pop-decrypt" | "token-asserted", identity.allow = [...] }
```

What may be created and adopted:
- **References are checked at load** (exit 17): a spec's `object` must name an `[objects.<name>]`
  table — also when nothing uses the spec — and a `$NAME`/`${NAME}` path reference (in `pinFile`
  or `module`) must name a set environment variable; one shared `keys.toml` can then carry
  machine-specific paths. `pinEnv = "VAR"` remains the way to pass the *PIN itself* through the
  environment — `env_references_and_object_refs_are_checked_at_load`,
  `pin_file_path_can_come_from_the_environment`.
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
- **`CKA_ALWAYS_AUTHENTICATE = true` refuses `binding = "pop-sign"`** (exit 17): proving possession
  would spend a PIN entry per run. A key that carries the attribute without declaring it is refused
  at run time (16, §3.6).
- **`CKA_TRUSTED = true` refuses `autoCreate`** (exit 17): generation cannot set it.
- **Not expressible:** `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`, `CKA_DERIVE_TEMPLATE` and
  `CKA_CERTIFICATE_CATEGORY` — cryptoki 0.12 maps none of them.

### 4.2 `keys.lock` (input, updated in place)
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
binding = "pop-sign"                 # private keys: pop-sign | pop-ecdh | pop-decrypt | token-asserted (§3.6)
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
[realisations.<spec>.<token>.provenance.module] # C_GetInfo and the loaded file
path = "..." ; description = "..." ; manufacturer = "..." ; version = "M.m" ; cryptoki = "M.m"
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
  until `realise --update-lock`; a newly readable one is a note. With `publicOnly`, this is the
  public object's vector.
- **Immutables** (`CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`,
  `CKA_KEY_GEN_MECHANISM`) are compared the same way. A flag that was `true` and is not any more
  means the object was replaced (for example, the same material re-imported). That is refused
  even under `--update-lock`, like a downgrade — `policy_drift_and_replaced_objects_are_refused`.
- **Loading checks the lock's own invariants** (exit 17, never a hash mismatch) —
  `lock_invariants_are_checked`:
  - every ID and `specDigest` is a `sha256-` SRI digest of 32 bytes; a `commitmentLabel` is
    non-empty printable ASCII;
  - a realisation's `object` is in the lock, and its `schemes` are among that object's IDs;
  - **one object per material:** no two objects of one class share an ID under one scheme
    (a certificate's `rfc7093m4` is exempt: it names the subject key, which renewed
    certificates share). `realise --update-lock` refuses to record a second name (exit 14);
  - **`pairs`** makes the key ↔ certificate relation explicit: objects that share an
    `rfc7093m4`. A listed partner present in the file must share it and list back; one that is
    absent may live in another fragment, so locks still split and join per object. Partners
    present but unlisted are a note, and `--update-lock` records them;
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
- **Provenance:** a different module build identity or token is a *warning*; only a different
  module file is a *note*. Neither fails — `module_and_token_provenance_warn_but_do_not_fail`.
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
  digest fails `verify`/`check` (exit 14, naming each change) until `realise --update-lock`
  re-records it, like a lockfile that is out of date — `s4_a_public_only_flip_is_a_spec_change`,
  `s8_a_retargeted_spec_is_a_spec_change`. A changed locator or object is never reported as an
  unexplained hash mismatch.
- **A changed object type** in `keys.toml` is refused with exit 14, naming the change, also under
  `--update-lock`: different material needs a new object name. Curve aliases are canonicalized on
  load (in `keys.toml` and in the lock's recorded types), so they are the same type and need
  nothing — `the_lock_pins_type_spec_provenance_and_schemes`.
- **Provenance:** a different `provider` is a warning; a different `cakeysVersion` is a note.
- **Locked schemes that are not checked** are reported: unknown to this cakeys → warning, naming
  the scheme; known but not computable for this spec on this token → note.

## 5. Verbs (HTTP-like) and exit codes

| Verb | Semantics |
|---|---|
| `validate` | Static check of modes, opt-ins, types and provider names; touches no token. |
| `resolve <spec> --token` | GET: find (exactly one), check type and policy, compute IDs, print JSON. Never writes. |
| `verify <spec> --token` | GET with If-Match against the lock; prints the URI. |
| `realise <spec> --token [--update-lock]` | PUT. If absent and `autoCreate`: refused (14) when the lock already pins the object's material — generated material could never match (D1, `autocreate_never_fights_a_locked_identity`). **If-None-Match** — never create when anything sits under the locator (`never_create_over_an_occupied_locator`). Then create, compute and compare. If the identity of a just-created object cannot be established, it is destroyed (`tpm2_identity_failure_after_create_leaves_nothing`). Re-running never duplicates (`ec_lifecycle`). |
| `delete <spec> --token [--if-match ID] [--update-lock]` | DELETE with If-Match. Absent is success, even without a lock; a present object with no expected ID is never deleted (`ec_lifecycle`). `--update-lock` removes the realisation but keeps `objects.<name>.ids`, since the material may live on other tokens. |
| `check <obj>[.id.<scheme>] [--token] [--spec]` | The pseudo-FOD pre-use check: realise without writing the lock, print the URI. Schemes the spec or token can never compute are refused before anything is created (`scheme_the_token_lacks_is_refused_before_create`). |
| `gc [--apply]` | Print lock entries `keys.toml` no longer names, as table names; `--apply` removes exactly what it printed, holding the update lock (M3). Live objects keep their `ids` (`gc_prints_then_removes_stale_entries`). |
| `caps --token` | Provider and usable mechanisms, as JSON. |

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
| 17 | invalid spec |
| 1 | other |

## 6. Architecture

### 6.1 Crates
| Crate | Role |
|---|---|
| `cakeys-core` | config, lock, errors and exit codes, CA-IDs. No `cryptoki`. |
| `cakeys-pkcs11` | the `cryptoki` token layer (`token.rs`), verbs (`ops.rs`), `Provider` and `Registry` |
| `cakeys-{softhsm,ykcs11,tpm2-pkcs11,p11-kit}` | one provider per module |
| `cakeys` (crates/cli) | CLI as a library: `main(registry)`, `default_registry()`; `examples/custom-provider.rs` |

### 6.2 Providers
- **Hooks:** `name`, `matches(&ModuleInfo)`, and optionally `mechanisms` (filter), `ec_point`
  (repair), `hint` (error advice) and `login` (the credential model).
- **Selection:** an explicit `provider` wins; an unknown name is exit 17. Otherwise the first
  registered provider that matches, else `generic` — `provider_is_detected_or_named`, registry unit
  test.
- **The fix-up rule:** a hook must return exactly what a spec-compliant module would, so
  identities are portable. That is also why the provider is not recorded in the lock.

| Provider | Quirks handled or recorded |
|---|---|
| softhsm | none (reference) |
| ykcs11 | `CKA_PUBLIC_KEY_INFO` length 0 then `CKR_ARGUMENTS_BAD` (tolerated generically); fixed PIV slot IDs; **one login state per token**: its management operations (generate, import, delete) need the SO state, so with `mgmKeyFile`/`mgmKeyEnv` set, the `login` hook logs in as SO with that credential instead of as the user — the hex management key, or the PIN on a PIN-protected-management-key device, whose SO login also card-verifies the PIN so signing and `autoCreate` work in one unattended run. Without an admin credential this is the default user login. The RW suite pins it: `rw_lifecycle_generates_proves_and_deletes_without_touch` |
| tpm2-pkcs11 | drops `AES_KEY_GEN`/`GENERIC_SECRET_KEY_GEN` (`C_GenerateKey` unsupported); repairs the malformed P-521 `CKA_EC_POINT` (`04 85 …`; upstream draft in `upstream/tpm2-pkcs11/`) — `tpm2_*` tests |
| p11-kit | detects the proxy; the RPC drops AES key wrap and EdDSA/Edwards mechanisms; the module behind it is hidden (set `provider` explicitly) — `p11kit_*` tests |

### 6.3 cryptoki patch
cryptoki ≤ 0.12.1 gives `KeyType::SHA224/384/512_HMAC` the value of `CKK_SHA256_HMAC`. The Nix
build patches it with `nix/patches/cryptoki-hmac-key-types.patch`, applied in `postPatch` to
`$cargoDepsCopy`. Without the patch, those types are refused (`hmac_key_type`), and tests skip
unless required. Upstream draft: `upstream/rust-cryptoki/`.

### 6.4 Dependencies
Policy: always the latest release. Audit on every dependency change by comparing
`[workspace.dependencies]` with crates.io, and the flake's nixpkgs input.
- **2026-11-11:** every crate is on its latest release (cryptoki 0.12.1, RustCrypto 0.14/pkcs8 0.11
  generation, toml 1.x, base64 0.23, clap 4, serde 1, thiserror 2, anyhow 1). nixpkgs is from
  2026-11-06.
- **Pinned on purpose:** none. The cryptoki HMAC key-type patch is a local fix on top of the latest
  release.

## 7. Nix integration

### 7.1 Library (`lib.mkKeys`, builtins only)
Per object it exposes `type`, `id.<scheme>`, and `specs.<spec>.{uri,mode,specDigest,module,tokenInfo,functions,rsf}.<token>`.
- **Per-token shortcuts** throw if several specs share a token.
- **`check { token?, spec?, scheme? }`** gives the shell command for the pre-use check.
  Interpolating config, lock and module makes them build inputs. `scheme = null` verifies whatever
  the spec computes.
- **`rsf`** gives the token's system feature, for `requiredSystemFeatures`.
- Tested by `checks.lib` (synthetic fixture) and `checks.vm` (consumer built in the guest sandbox).

### 7.2 Pseudo-FOD check
A consumer derivation requires the token's feature and runs `check` before using the URI.
1. **First use** creates the key (with `autoCreate`) and fails with `got:`.
2. Record the ID out of band (`realise --update-lock`).
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
- **Weak identity modes need an explicit per-token opt-in.** Downgrades fail.
- **Material is linked only through a shared scheme.**
- **The lock never holds token outputs, only their hashes.** Private data objects are not hashed.
- **Lock updates are serialized** by the advisory `<lock>.lck` sidecar; readers get consistent
  snapshots through the atomic rename — `update_lock_waits_for_the_sidecar_lock`.
- **Refused operations leave nothing behind:** checks before creating, and cleanup after a failed
  identity.
- **Token paths reach only builds that require the token's feature.**

### 8.2 Not enforced / known gaps
See `docs/REVIEW-2026-11-11.md`.
- **`token-asserted` bindings are unproven.** With the opt-in or `publicOnly`, a private key is
  tied to its identity only by the token's word (H1 is fixed for every `pop-*` proof —
  `h1_a_private_key_beside_an_unbound_public_object_is_a_conflict`,
  `derive_and_decrypt_only_keys_prove_possession`).
- **Features are self-declared.** Any user allowed to build can require a token's feature; the
  real gate is `allowed-users`.
- **No merge rule for lock fragments.** Updates are serialized by the `<lock>.lck` sidecar (M3)
  and stale entries are collected by `gc` (D3), but two hand-edited lock fragments still need a
  manual `git merge` (S16).
- **p11-kit hides the module behind it,** so the lock records p11-kit as the module.

## 9. Testing
| Suite | Where | What |
|---|---|---|
| unit | `cargo test --workspace` | digests (pinned), curves and OIDs, SPKI round-trips, registry, P-521 fix-up, hex parsing, proof-of-possession host math (both ECDH MAC sides), the deprecation register and AES strength order |
| `tests/softhsm.rs` | package build | SoftHSM: lifecycle, every type and scheme against independent oracles (hand-written DER encoder, openssl-hashed fixtures, RustCrypto `hmac`/`cmac`/`aes`/`aes-kw`) |
| `tests/tpm2.rs` | package build, `nix/tpm2-test-env.sh` | swtpm + tpm2-abrmd + tpm2-pkcs11 |
| `tests/p11kit.rs` | package build, `nix/p11kit-test-env.sh` | SoftHSM behind `p11-kit server`, compared with direct access |
| `tests/yubikey.rs` | opt-in, never in the Nix build (`CAKEYS_TEST_YUBIKEY_MODULE`, `_PIN`, `_MGM` — file paths; the secrets are only ever read from them) | a real YubiKey, read-write: generate into the scratch PIV slot `0x95` under the SO credential, prove possession by signing in the same run, record, verify, delete, re-adopt — each CLI run bounded, so a touch or PIN prompt fails instead of waiting (`rw_lifecycle_generates_proves_and_deletes_without_touch`) |
| `checks.vm` / `test-nspawn` | QEMU / systemd-nspawn | the CLI flow; in the VM also the pseudo-FOD consumer built in the guest sandbox |
| `checks.module`, `checks.tpm`, `checks.lib` | QEMU / eval | module, hook, pcscd, TPM ACL, Nix library |

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
- the spec digest JSON shape (`"v":1`, camelCase, `keyType` omitted when empty, `certificateType`
  and `publicAttributes` only when set; the certificate digest changed with `certificateType`,
  since the v1 lock is a draft);
- binding names (`pop-sign`, `pop-ecdh`, `pop-decrypt`, `token-asserted`) and their rank (the
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
