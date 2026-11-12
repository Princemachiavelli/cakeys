# cakeys design (state at 2026-11-11)

This is the authoritative description of what is built. `PLAN.md` is the roadmap and history;
where the two disagree, this document wins. Review findings and open issues are tracked in
`docs/REVIEW-2026-11-11.md`.

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
| `pubkeyhash` | private/public keys, certificates | SHA-256 of the canonical DER SubjectPublicKeyInfo (§3.2) | readable public key | `curves_and_rsa_sizes_…`, `adopt_*`, `standalone_public_key_objects`, VM oracle (pkcs11-tool + openssl) |
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

### 3.2 Public keys
Public keys are decoded and re-encoded by RustCrypto crates, so provider encoding quirks never
change a hash:
- `p256`, `p384`, `p521`, `k256`, `bp256`, `bp384`;
- `ed25519-dalek`, `ed448` (length check only: there is no stable Ed448 arithmetic crate);
- `rsa` (1024–8192 bits).

Where the public key comes from, in order:
1. `CKA_PUBLIC_KEY_INFO` on the object. Errors are treated as absent: ykcs11 reports length 0, then
   fails.
2. RSA modulus and exponent, or `CKA_EC_PARAMS`/`CKA_EC_POINT`. The point may be a DER OCTET STRING
   or raw.
3. Otherwise, the single public-key object under the same locator.
   **Known gap H1:** that object is not cryptographically bound to the private key (§8.2).

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

## 4. Files

### 4.1 `keys.toml`
```toml
[tokens.<name>]
module = "/path/libfoo.so"     # or --module <name>=<path>
provider = "tpm2-pkcs11"       # optional; auto-detected (§6.2)
tokenLabel = "..."
pinFile = "/path" | pinEnv = "VAR"     # optional; pinEnv wins if both are set
systemFeature = "token-<name>"         # read by the Nix library only

[objects.<name>]
class = "CKO_PRIVATE_KEY" | "CKO_PUBLIC_KEY" | "CKO_SECRET_KEY" | "CKO_CERTIFICATE" | "CKO_DATA"
keyType = "CKK_EC" | ... ; certificateType = "CKC_X_509"   # none for data objects
curve = "..." ; modulusBits = N ; valueLen = BYTES

[specs.<name>]
object = "<object>"
attributes = { CKA_SIGN = true, ... }   # CKA_SIGN/VERIFY/ENCRYPT/DECRYPT/WRAP/UNWRAP/DERIVE/SENSITIVE/EXTRACTABLE/MODIFIABLE/PRIVATE
tokens.<token> = { locator = { CKA_LABEL = "...", CKA_ID = "hex" }, autoCreate = bool, publicOnly = bool, identity.allow = [...] }
```

What may be created and adopted:
- **`autoCreate`** is allowed for private and secret keys only. Certificates, public keys and data
  objects are adopted — `adoption_rules_are_validated`, `standalone_public_key_objects`,
  `data_objects_…`.
- **`CKK_SHA*_HMAC` keys** cannot be generated (PKCS#11 has no mechanism for them) —
  `hmac_key_types_commit_with_their_own_hash`.
- **`publicOnly`** verifies a private key through its public-key object, without login (it spares
  PIV PIN retries). It forbids `autoCreate` and policy attributes, and `delete` refuses it —
  `adopt_certificate_and_public_only_key`.

### 4.2 `keys.lock` (input, updated in place)
```toml
version = 1                          # any other version is refused
[objects.<object>]
commitmentLabel = "key-management/v1" # required when ids holds a commitment scheme
[objects.<object>.type]              # required with ids: the type the IDs were computed for
class = "..." ; keyType = "..." ; curve = "..." ; valueLen = N ; modulusBits = N
[objects.<object>.ids]
pubkeyhash = "sha256-..."            # scheme -> SRI
[realisations.<spec>.<token>]
specDigest = "sha256-..."
mode = "direct"
publicOnly = true                    # only when set
uri = "pkcs11:token=...;object=...;id=%..;type=private|public|cert|secret-key|data"
mechanisms = ["CKM_..."]             # usable mechanisms at realisation time
provider = "softhsm"                 # provider that handled the module (provenance)
cakeysVersion = "0.1.0"              # cakeys that realised it (provenance)
[realisations.<spec>.<token>.module] # C_GetInfo and the loaded file (provenance)
path = "..." ; description = "..." ; manufacturer = "..." ; version = "M.m" ; cryptoki = "M.m"
[realisations.<spec>.<token>.token]  # C_GetTokenInfo
model = "..." ; serial = "..." ; firmware = "M.m"
```

- **Writes are atomic** (temporary file, then rename), but there is no locking (finding M3).
- **URIs are pure locators** (RFC 7512), with no `module-path`.
- **Versions** are raw `CK_VERSION` major.minor (ykcs11 2.7.3 → `2.73`).
- **Provenance:** a different module build identity or token is a *warning*; only a different
  module file is a *note*. Neither fails — `module_and_token_provenance_warn_but_do_not_fail`.
- **The spec digest** is the SHA-256 of canonical JSON `{"v":1,"type":<object, camelCase, empty
  keyType omitted>,"attributes":<…>}`, with keys sorted at every level explicitly (independent of
  serde_json features). Pinned by `spec_digests_are_pinned`. **It is compared:** a spec changed
  since it was realised fails `verify`/`check` (exit 14) until `realise --update-lock` re-records
  it, like a lockfile that is out of date.
- **A changed object type** in `keys.toml` (anything in `type`, curve aliases included) is refused
  with exit 14, naming the change, also under `--update-lock`: different material needs a new
  object name. Test: `the_lock_pins_type_spec_provenance_and_schemes`.
- **Provenance:** a different `provider` is a warning; a different `cakeysVersion` is a note.
- **Locked schemes that are not checked** are reported: unknown to this cakeys → warning, naming
  the scheme; known but not computable for this spec on this token → note.

## 5. Verbs (HTTP-like) and exit codes

| Verb | Semantics |
|---|---|
| `validate` | Static check of modes, opt-ins, types and provider names; touches no token. |
| `resolve <spec> --token` | GET: find (exactly one), check type and policy, compute IDs, print JSON. Never writes. |
| `verify <spec> --token` | GET with If-Match against the lock; prints the URI. |
| `realise <spec> --token [--update-lock]` | PUT. If absent and `autoCreate`: **If-None-Match** — never create when anything sits under the locator (`never_create_over_an_occupied_locator`). Then create, compute and compare. If the identity of a just-created object cannot be established, it is destroyed (`tpm2_identity_failure_after_create_leaves_nothing`). Re-running never duplicates (`ec_lifecycle`). |
| `delete <spec> --token [--if-match ID] [--update-lock]` | DELETE with If-Match. Absent is success, even without a lock; a present object with no expected ID is never deleted (`ec_lifecycle`). `--update-lock` removes the realisation but keeps `objects.<name>.ids`, since the material may live on other tokens. |
| `check <obj>[.id.<scheme>] [--token] [--spec]` | The pseudo-FOD pre-use check: realise without writing the lock, print the URI. Schemes the spec or token can never compute are refused before anything is created (`scheme_the_token_lacks_is_refused_before_create`). |
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
  (repair) and `hint` (error advice).
- **Selection:** an explicit `provider` wins; an unknown name is exit 17. Otherwise the first
  registered provider that matches, else `generic` — `provider_is_detected_or_named`, registry unit
  test.
- **The fix-up rule:** a hook must return exactly what a spec-compliant module would, so
  identities are portable. That is also why the provider is not recorded in the lock.

| Provider | Quirks handled or recorded |
|---|---|
| softhsm | none (reference) |
| ykcs11 | `CKA_PUBLIC_KEY_INFO` length 0 then `CKR_ARGUMENTS_BAD` (tolerated generically); fixed PIV slot IDs |
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
- **Weak identity modes need an explicit per-token opt-in.** Downgrades fail.
- **Material is linked only through a shared scheme.**
- **The lock never holds token outputs, only their hashes.** Private data objects are not hashed.
- **Refused operations leave nothing behind:** checks before creating, and cleanup after a failed
  identity.
- **Token paths reach only builds that require the token's feature.**

### 8.2 Not enforced / known gaps
See `docs/REVIEW-2026-11-11.md`.
- **H1: EC/Edwards private keys on SoftHSM.** Their identity comes from an unbound public object
  under the locator. Reproduced by `known_gap_ec_private_identity_comes_from_an_unbound_public_object`.
- **Features are self-declared.** Any user allowed to build can require a token's feature; the
  real gate is `allowed-users`.
- **There is no lock GC, and no locking.**
- **p11-kit hides the module behind it,** so the lock records p11-kit as the module.

## 9. Testing
| Suite | Where | What |
|---|---|---|
| unit | `cargo test --workspace` | digests (pinned), curves and OIDs, SPKI round-trips, registry, P-521 fix-up, hex parsing |
| `tests/softhsm.rs` | package build | SoftHSM: lifecycle, every type and scheme against independent oracles (hand-written DER encoder, openssl-hashed fixtures, RustCrypto `hmac`/`cmac`/`aes`/`aes-kw`) |
| `tests/tpm2.rs` | package build, `nix/tpm2-test-env.sh` | swtpm + tpm2-abrmd + tpm2-pkcs11 |
| `tests/p11kit.rs` | package build, `nix/p11kit-test-env.sh` | SoftHSM behind `p11-kit server`, compared with direct access |
| `checks.vm` / `test-nspawn` | QEMU / systemd-nspawn | the CLI flow; in the VM also the pseudo-FOD consumer built in the guest sandbox |
| `checks.module`, `checks.tpm`, `checks.lib` | QEMU / eval | module, hook, pcscd, TPM ACL, Nix library |

Hardware: the YubiKey example lock is verified read-only (no PIN). `packages.test-nspawn` needs the
`uid-range` feature, so it is outside `checks`.

## 10. Frozen identifiers, and what makes a lock portable
A `keys.toml` and its `keys.lock` must verify the same way under any later cakeys, like a
dependency lock. The lock records the values that determine each ID: scheme name, commitment
label and the hash itself. Everything else is fixed by definition:
- **Scheme definitions are immutable.** A scheme name (`pubkeyhash`, `certhash`, `valuehash`,
  `commitment`, `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`) always denotes exactly the computation in
  §3. A changed computation is a *new* scheme name, never an edit. The known-answer test
  `scheme_definitions_are_pinned` pins each one: the bytes every commitment scheme feeds the
  token, and the `pubkeyhash` of fixed keys on every curve and RSA (canonical encoding included).
- **The lock records everything else an ID depends on:** the object `type` (key type and length
  feed the commitment label), the commitment label, the spec digest, and as provenance the
  module, token, provider and cakeys version. A changed `keys.toml` is reported as such, never as
  an unexplained hash mismatch.
- **Known answers for scheme mappings:** `commitment_mechanisms_are_pinned` fixes which HMAC hash
  each key type uses and which mechanism each scheme runs.
- **Further frozen identifiers:** the label layout `<label>/<scheme>/<keyType>/<bits>` and the
  mode names;
- the SRI form `sha256-<base64>`;
- the spec digest JSON shape (`"v":1`, camelCase, empty `keyType` omitted);
- lock field names (`objects`, `ids`, `realisations`, `specDigest`, `publicOnly`, `module`,
  `token`, `mechanisms`, `uri`);
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
