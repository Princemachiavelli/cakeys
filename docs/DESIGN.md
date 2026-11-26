# cakeys design: identity and the lock

This document describes how cakeys identifies objects and what its lock guarantees. Each tool has
its own document: [CAKEYS.md](CAKEYS.md) (the verbs, the exit codes and the Nix integration),
[CAPROBE.md](CAPROBE.md) (capability profiles) and [CAMIGRATE.md](CAMIGRATE.md) (moving keys).
The annotated file references are [CONFIG.md](CONFIG.md) and [LOCK.md](LOCK.md), the map of the
crates is [ARCHITECTURE.md](ARCHITECTURE.md), and the diagrams are in [diagrams.md](diagrams.md).
The section numbers do not change, because the code cites them. A section that moved to another
document leaves a pointer to its new place.

## 1. Purpose

cakeys declares PKCS#11 objects (and, later, TPM objects) in a file, and it addresses them by a
**content-addressed identity (CA-ID)**: a hash of the object's material, not a name. Names
(labels, IDs, URIs, slot numbers) are only *locators*. They are arbitrary and can change, and
they are not the identity. A lock file records each object's CA-IDs. A check before each use
proves that the token still holds that material. The guarantee is therefore *verified at check
time*, and §8.2 describes the gap between the check and the use. In Nix, this check runs inside
the build sandbox as a pseudo fixed-output check.

## 2. Model

| Level | What it is | Identified by |
|---|---|---|
| **Object** (`[objects.<name>]`) | The material and its intrinsic type: the class, the key type, and the curve or size. | CA-IDs in `keys.lock` (`objects.<name>.ids`) |
| **Spec** (`[specs.<name>]`) | The policy for one use of an object: boolean `CKA_*` attributes. Several specs may share one object. | The spec digest: the SHA-256 of the canonical JSON of the type and the attributes |
| **Realisation** (per spec × token) | The object on one token, found through a locator. | The locator (`CKA_LABEL`, `CKA_ID` or both), recorded with the mode, the URI and the provenance |

- **The object name is an internal handle.** It is never written to the token.
- **Locators** are a `CKA_LABEL`, a hex `CKA_ID`, or both, as the user chooses them. A locator
  must match exactly one object.
  - When several objects match, the result is *ambiguous* (exit 12): `conflicts_and_ambiguity`.
  - The live object's class, key type, curve or size, and every policy attribute must match the spec; otherwise the result is a *conflict* (exit 13): `conflicts_and_ambiguity`, `curves_and_rsa_sizes_match_an_independent_der_oracle`.

## 3. Identity

### 3.1 Schemes

Each scheme is one kind of CA-ID, stored as `sha256-<base64>` (SRI). The lock may hold several
CA-IDs per object.

| Scheme | Objects | Input | Requires | Tests |
|---|---|---|---|---|
| `rfc7093m4` (input alias `pubkeyhash`) | private and public keys, certificates | RFC 7093 §2 method 4: the hash (here SHA-256, which the SRI prefix names) of the DER SubjectPublicKeyInfo, computed over the *canonical* SPKI (re-encoded, with EC points uncompressed; §3.2) | a readable public key | `curves_and_rsa_sizes_…`, `adopt_*`, `standalone_public_key_objects`, the VM oracle (pkcs11-tool and openssl) |
| `certhash` | X.509 certificates | the SHA-256 of the certificate's DER | a readable `CKA_VALUE` | `adopt_certificate_…`, `adopt_ec_and_edwards_certificates` |
| `valuehash` | data objects | the SHA-256 of `CKA_VALUE` (equal to Nix's flat fixed-output hash) | `CKA_PRIVATE=false`, or a spec that declares `CKA_PRIVATE = true` (the value is then read under the login; §8.2) | `data_objects_are_identified_by_their_public_value`, `private_data_objects_are_identified_when_declared`, `tpm2_private_data_object_is_identified_by_its_value` |
| `commitment` | generic secrets, `CKK_SHA*_HMAC` | an HMAC over the label (§3.3), with the key type's hash | `CKA_SIGN` | `secret_commitments_match_host_hmac`, `hmac_key_types_commit_with_their_own_hash`, `tpm2_imported_keys_…` |
| `cmac` | AES | an AES-CMAC over the label | `CKA_SIGN` | `aes_commitments_match_host_oracles` |
| `kcv-ecb` | AES, DES3 | the ECB encryption (`CKM_AES_ECB`, `CKM_DES3_ECB`) of one block: the first 16 (AES) or 8 (DES3) bytes of SHA-256(label) | `CKA_ENCRYPT` | the same tests, and `tpm2_aes_key_is_identified_by_its_kcv`, `des3_check_values_match_host_oracles` |
| `kcv-ecb-dec` | AES, DES3 | the ECB *decryption* of such a block | `CKA_DECRYPT` | `aes_128_192_and_decrypt_only_match_host_oracles`, `des3_check_values_match_host_oracles` |
| `kw` | AES | the RFC 3394 key wrap of a fixed key (SHA-256(label)) | `CKA_WRAP` | `aes_commitments_match_host_oracles` |
| `piv-attestation` | private and public keys (YubiKey PIV) | a canonical digest of what the slot's attestation certificate asserts (§3.7), verified to the pinned Yubico root; one per realisation | the opt-in `attestation = true` (reading the certificates needs no login) | `fixture_chain_verifies_and_pins`, `the_yubico_roots_are_pinned`, `issuers_must_be_cas_within_their_path_length` |
| `tpm-certify` | private keys on tpm2-pkcs11 tokens, and HMAC and generic secret keys through the store path | a canonical digest of the Name and the qualified Name that a native `TPM2_Certify` attests (§3.7). The host verifies it against a provisioned AK, and it is bound to the material: to a private key's SPKI, or to a secret key's HMAC commitment, which the certified object computes again. One per realisation | the opt-in `attestation = true`, the module's TCTI and store, and the PIN | `tpm2_keys_attest_their_tpm_residence`, `tpm2_each_token_pins_its_own_attestation`, `tpm2_attested_material_travels_to_a_second_hsm` |

- **Commitment schemes never reveal what the token computed.** The lock stores only the SHA-256
  of the token's output, never a MAC or a ciphertext under the key. `aes_commitments_…` asserts
  that the raw CMAC is not in the lock.
- **Which commitment schemes are computed** depends on the spec's *declared* usage attributes,
  never on the token's defaults. The order of preference is `cmac`, `kcv-ecb`, `kcv-ecb-dec`,
  `kw`, and the first scheme computed is the primary scheme.
- **A DES3 check value is not the payment industry's KCV** (the DES3-ECB encryption of a zero
  block, printed as three bytes). That block contains no label and no key type, and HSMs give it
  out freely. The lock's hash of a whole block also could not be compared with three printed
  bytes. So `kcv-ecb` keeps one construction for both ciphers, and the key type in the label
  distinguishes them.
- **Only mechanisms that the token offers are used.** If none fits, the result is *unsupported*
  (exit 15).
- **Attestation schemes are computed only after an explicit opt-in** (`attestation = true` on the
  spec's token entry, §3.7), because they promise provenance signed by a TPM or a vendor from then
  on. Without the opt-in, a run that cannot attest
  would turn every realisation that was attested before into a downgrade.

**Scheme strength and deprecation** (finding S15). The table lists, per class, the schemes in the
order in which cakeys prefers them. The first scheme computed is the primary identity, and cakeys
computes a weaker scheme only when the spec's declared usage attributes allow nothing stronger:

| Class | Schemes, strongest first | Why the order |
|---|---|---|
| private and public keys | `rfc7093m4` | The host verifies it against the material that it hashes, and the private half proves possession (§3.6). |
| certificates | `certhash`, then `rfc7093m4` | `certhash` pins the exact bytes. `rfc7093m4` only names the subject key, which renewed certificates share. |
| data objects | `valuehash` | The SHA-256 of the content, equal to Nix's flat fixed-output hash. |
| generic secret, `CKK_SHA*_HMAC` | `commitment` | An HMAC over the domain-separated label (§3.3), with the key type's hash. |
| AES | `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw` | CMAC is a PRF over the whole label. Each KCV exposes one ECB relation for a fixed block. `kw` needs the wrap of a fixed key. |
| DES3 (`CKK_DES3`, 24 bytes) | `kcv-ecb`, `kcv-ecb-dec` | The same order as for AES. There is no `cmac` yet (`CKM_DES3_CMAC` needs a cryptoki patch, [OPEN.md](OPEN.md)), and AES key wrap does not apply. |

Deprecation:

- **A changed or weakened computation gets a new scheme name, never an edit** (§10). The old
  name keeps the meaning that it had. go.sum uses the same rule for its `h1` and `h2` hashes.
- **A deprecated scheme still verifies the identities that are already locked under it**, with a
  warning, but
  `lock` never records a *new* identity under it. To migrate, realise a spec that computes the
  replacement scheme. (`gc` does not remove the old entry, because the identity is still true.)
- **No scheme is deprecated today.** The register is `Scheme::DEPRECATED` in
  `crates/core/src/id.rs`, and `the_deprecation_register_is_pinned` pins it as empty.
  `aes_commit_strength_order_is_pinned` pins the AES order above.

### 3.2 Public keys

RustCrypto crates decode and re-encode public keys, so a provider's encoding quirks never change
a hash:

- `p256`, `p384`, `p521`, `k256`, `bp256`, `bp384`;
- `ed25519-dalek`, `ed448` (only a length check, because there is no stable crate for Ed448
  arithmetic);
- `rsa` (1024–8192 bits).

cakeys takes the public key from the first of these sources that exists. The order puts key
material first, and what the module only asserts after it:

1. The object's own material: the RSA modulus and exponent, or `CKA_EC_PARAMS` and
   `CKA_EC_POINT`. The point may be a DER OCTET STRING or raw bytes.
2. Otherwise, the material of the single public-key object under the same locator (SoftHSM EC and
   Edwards private keys carry no point). Proof of possession binds the private key to it (§3.6).
3. Otherwise, `CKA_PUBLIC_KEY_INFO`. An error counts as an absent value, because ykcs11 reports a
   length of 0 and then fails.
4. Otherwise, the subject key of the single certificate under the same locator. This covers an
   imported key whose importer wrote only the certificate beside it (a PIV-style slot, a PKCS #12
   import). The certificate takes the place of a public key object, and it is not trusted more
   than one. When none of these sources exists, an EC private key has no public half (11).

Wherever `CKA_PUBLIC_KEY_INFO` is present, it must agree with the material; otherwise the result
is a conflict (exit 13), because a module may let it be set without a check
(`h1b_a_forged_public_key_info_is_a_conflict`). A substitute source (2 to 4) must hold a key of
the private key's own type and curve; otherwise the result is a conflict (13). Under
`token-asserted`, only this check stops another key's certificate from naming the key
(`a_certificate_stands_in_for_an_imported_keys_public_half`).

Supported curves:

- `CKK_EC`: secp256r1 (alias prime256v1, P-256), secp384r1, secp521r1, secp256k1, brainpoolP256r1,
  brainpoolP384r1.
- `CKK_EC_EDWARDS`: edwards25519, edwards448.
- brainpoolP512r1 is refused (15), because no crate under a license that the workspace accepts
  implements it. RustCrypto has not released one ([OPEN.md](OPEN.md)):
  `brainpool_p512_is_refused_clearly`.

### 3.3 Commitment label

The token computes its commitment over `<commitment label>/<scheme>/<keyType>/<bits>`, which
`crates/core/src/id.rs` builds.

- **The lock records the commitment label per object** (`objects.<name>.commitmentLabel`), and
  verification always uses the recorded value. The code supplies the default
  (`DEFAULT_COMMITMENT_LABEL = "key-management/v1"`) only for objects that the lock does not know
  yet. A future default, or a configurable label such as the planned keystore `idPrefix`,
  therefore never breaks an
  existing lock. Each object in the lock is self-contained, so lock files can be joined or split
  per object. The test `commitment_label_comes_from_the_lock` proves that a non-default label in
  the lock is used, and that commitment IDs without a label are refused (exit 17).
- **The label is never written to a token.** It is only the fixed message that the token MACs or
  encrypts to compute a secret key's ID. Labels, `CKA_ID`s, attributes and URIs remain the
  user's. A distinctive string prevents the operation from coinciding with another protocol's use
  of the key.
- **The key type is part of the label,** so the same bytes held as two types never share an ID.
- **`bits`** is `8 × valueLen`. It is 0 when `valueLen` is not set (finding L11). For a key type
  that fixes its length, cakeys fills in the length when keys.toml leaves it out (`CKK_DES3`: 24
  bytes, so 192 bits; any other `valueLen` is refused with 17). cakeys checks that length as part
  of the key type, because the token keeps no `CKA_VALUE_LEN` for such a key.

### 3.4 Identity modes

The modes are listed from the strongest to the weakest. The lock records the mode per realisation,
and a downgrade fails (exit 14): `downgrade_is_an_error`.

| Mode | Used for |
|---|---|
| `direct` | public keys, certificates, data objects (a hash of public material) |
| `commitment` | secret keys whose declared usage attributes allow a commitment scheme that their declared `CKA_ALLOWED_MECHANISMS` (if any) also allows. Only those schemes are computed |
| `wrap-rebind` | extractable secret keys without such attributes. The key is wrapped under a session KEK, and unwrapped as a session copy that allows every scheme of its type. The copy computes the commitments, and then both session objects are destroyed. This mode computes every scheme (AES: all four; DES3: both check values). |

A secret key that fits none of these modes is refused at validation (17). Such a key is not
extractable, and either it has no usage attribute that a commitment scheme can use (derive-only,
unwrap-only), or its declared `CKA_ALLOWED_MECHANISMS` allows none of the commitments that its
attributes enable (only modes with a random IV). The message names the spec change that would make
the key identifiable (`a_secret_key_without_a_reverifiable_identity_is_refused`).

**Weaker modes may have to come back** (review A6 removed them before they were built). Such keys
are common in real deployments, especially existing and legacy keys that cakeys did not create and
cannot declare again. Tests that are built from clean keys must therefore not decide what cakeys
can adopt. Each candidate mode gives up the ability to verify the key again:
`commit-at-creation` (compute the commitment once, then remove the usage attribute),
`host-at-import` (hash the plaintext before an import), and `token-specific` (an identity that only
one token can compute, such as a TPM Name). If these modes return, they get their own names, rank
below `wrap-rebind`, and report an assurance that says that the token is not checked again
([OPEN.md](OPEN.md)).

### 3.5 Linking and upgrades

- **Identities are linked only through a shared scheme.** If an object already has locked IDs and
  none of the computed schemes is among them, `lock` fails (exit 14) and does not attach new IDs
  (`disjoint_schemes_never_link_material`).
- **`lock`, `create` and `delete` write the lock by default, and a write only fills gaps.**
  `lock` is the verb that writes the lock: it never creates the object, and of cakeys' verbs,
  `create` is the one that makes keys (2026-11-15; `lock` may provision a TPM Attestation Key,
  §3.7). What the lock lacks is recorded (including on first use), but a locked ID, anchor,
  binding, type or immutable is never overwritten. Such changes fail even when the lock is
  written. `lock --dry-run`, `delete --dry-run` and `create --dry-run` open the token read-only,
  ask what the run asks before it writes, and write nothing (review 2026-11-24 C-4: the create dry
  run once planned without the token and passed where the run refused).
  `create --no-update-lock` creates without recording. First use is trust on first use, so the review is
  the diff of `keys.lock`. A run that wrote the lock exits 22, never 0, so that a caller handles
  that review deliberately. A lock that does not exist is refused (17) unless `--new-lock` is
  given, so a mistyped `--lock` never starts a second lock (review 2026-11-23, C-4).
- **Every pair that a verb reaches gets a row, and all rows have one shape** (`Outcome`,
  cli-common; review 2026-11-24 C-1). The row holds the pair's outcome, its exit code, the rule
  that refused it, and whether the device failed. A caller, and the dry-run twin of the test
  harness, can therefore read what happened to each pair from the rows alone. The run's exit code
  follows from the rows: 0 (22 when the lock was written), the code of the one failure, or 20
  when the plan was refused more than once. camigrate's `import` and `migrate` print the same rows
  (with the `method`), and they exit with the code of the first failure (review 2026-11-24 D-9).
- **A test checks each dry run against its run** (review 2026-11-24 §1.4, C-4). The test
  harness's twin runs camigrate's moves and cakeys' `create`, `delete`, `lock` and `gc` first as
  a dry run, which must leave the lock and the tokens unchanged, and then for real. The real run
  must end as the dry run did, unless a row ends with a device failure or with a rule that the dry
  run named as deferred (in a plan's or a row's `deferred`; for example, a sealed import defers
  `unwraps` and `identity`, which only the target's unwrap decides). The harness does not accept
  a difference because of what the run prints on stderr.
- **A write that replaces a realisation reports each change that it accepted,** with one line
  for each (`re-recorded …`). A change in keys.toml (locator, object, `publicOnly`, spec digest)
  and a policy attribute that the lock did not record are notes. A policy attribute or an
  immutable that changed on the token, which nobody edited, is a warning
  (`a_write_says_what_it_rerecorded`).
- **Declare what must not drift; everything else is observed** (decided 2026-11-15). `lock`
  is the verb that writes the lock, and it records what is there now, with no `--accept-drift`
  option. What it records again falls into three kinds, and none of them needs a check that stops
  the run. The module, its versions, the provider, the mechanisms and the token's information are
  recorded again with a note or a warning. The author's own change to keys.toml (locator, object,
  `publicOnly`, spec digest) is recorded again with a note, and the diff of keys.toml is its
  review. A policy attribute that the spec does not declare is recorded again with a warning. To
  make such an attribute a gate, declare it. A declared attribute that the token does not show
  is a conflict (13), and it is never recorded again.
  IDs, downgrades, immutables, attestations and types stay refused even when the lock is written.
- **Where the lock cannot be written, a writing run is refused (21) before any token is
  opened**, so that a key is never created and then left unrecorded. The message names
  `--dry-run`. The lock cannot be written inside a Nix build sandbox (`NIX_BUILD_TOP` is set
  without `IN_NIX_SHELL`, which `nix develop` also sets, and without
  `CAKEYS_ALLOW_NIX_STORE_KEYS=1`, docs/FILE.md), because a write there would be lost with the
  build. It also cannot be written when the lock file or its
  directory is not writable (`access(2)`). `check` and `resolve` never write and are unaffected
  (`lock_is_written_by_default_and_refused_where_it_cannot_be`).
- **A computed scheme that is missing from an otherwise matching lock is a note.** This happens,
  for example, when a newer version computes more schemes.
  - When there is nothing to compare, it is a first use: `lock` records it, and `lock --dry-run`
    and `check` fail as a first use (exit 18, unless a mismatch gives 10) and print `got:`.
  - An explicitly requested `check <obj>.id.<scheme>` needs that scheme to be locked.
  - Test: `a_new_scheme_missing_from_the_lock_is_a_note_unless_requested`.

### 3.6 Proof of possession (`binding`)

A private key's identity hashes a public key, which may come from a separate object (§3.2). Each
time cakeys resolves a private key (`resolve`, `lock`, `check`, `delete`), it binds the key to
its identity:

1. The host builds a challenge, `"cakeys/pop/v1\0" ‖ SHA-256(SPKI) ‖ 32-byte nonce`, with a
   nonce from the OS RNG (`crates/core/src/pop.rs`).
2. With the private-key object that it finds under the locator, the token proves that it holds
   the private half of that SPKI. It uses whichever capability the key has, as the spec's
   `binding` names it:
   - `pop-sign` (the default): the token signs the challenge:
     - ECDSA with the curve's hash (P-256, secp256k1, brainpoolP256r1: SHA-256; P-384,
       brainpoolP384r1: SHA-384; P-521: SHA-512): `CKM_ECDSA_SHA*` if the token offers it,
       otherwise `CKM_ECDSA` over the host's digest;
     - Ed25519: `CKM_EDDSA` (pure);
     - RSA: `CKM_SHA256_RSA_PKCS`, otherwise raw `CKM_RSA_PKCS` over the host's SHA-256
       `DigestInfo` (which gives the same signature). A key whose `CKA_ALLOWED_MECHANISMS` names
       another signature mechanism proves possession with that mechanism (Cloud KMS binds each
       key to one mechanism [run]). That mechanism may be v1.5 over SHA-384 or SHA-512, raw
       signing over the `DigestInfo` of the hash that the list names beside it, or PSS (MGF1
       with the same hash, and a salt as long as the hash). The token either hashes the
       challenge itself or signs the host's digest, and the host verifies the signature when it
       binds the key.

     The token must offer the mechanism, and the key's own `CKA_ALLOWED_MECHANISMS`, where it
     can be read, must allow it. A key that is restricted to `CKM_ECDSA` or `CKM_RSA_PKCS`
     proves possession through the fallback (the object matrix, OPEN.md). Every binding below
     chooses its mechanism in the same way. When the list allows none of a binding's
     mechanisms, the binding is refused, and the message names those mechanisms. The refusal
     comes at load (17) when the spec declares the list (`plan::proof_mechanisms`), and on the
     token (15) when only the object carries the list. A proof records only its binding,
     never the mechanism.

     When the token reports `CKA_ALWAYS_AUTHENTICATE` on a key (whether the spec declares it or
     not), the same proof runs under the key's per-use policy, and the lock records it as
     **`pop-sign-pin`**: `C_SignInit → C_Login(CKU_CONTEXT_SPECIFIC) → C_Sign`. The login runs
     once, with the PIN that opened the session, and it is
     never retried. The single-part `C_Sign` after `C_SignInit` is cryptoki's
     `Session::sign_single` (on cryptoki's main branch, and not released in 0.12.1), and every
     signing mechanism offers it. camigrate applies the same check as the proof to a move that
     is planned onto such a key (`proof_refusal`). The other proofs have no per-use login. A
     spec that declares `CKA_ALWAYS_AUTHENTICATE` with one of them is invalid (17), and a key
     that the token reports as always-authenticate without that declaration is unavailable
     (16).
   - `pop-ecdh` (EC keys that only derive): the host generates an ephemeral key on the same
     curve, and it MACs the challenge with HMAC-SHA256 under the ECDH shared secret. The token
     derives the same secret with `CKM_ECDH1_DERIVE` into a non-extractable session key, and it
     MACs the same challenge. The two MACs agree only for the matching private key.
     - **Extractable variant.** Some tokens have no HMAC. Other tokens derive only into an
       extractable secret, or cannot MAC with a sealed one, and their module profile says
       `derive.ecdh.sealed` no (ykcs11, tpm2-pkcs11 1.10 [run]). On those tokens, the token
       derives into an extractable session secret, and the host reads its `CKA_VALUE` and
       compares it in constant time with the shared secret that the host computed. The secret
       belongs to a single-use ephemeral key that the host generated, so reading it reveals
       nothing that the host did not already hold. The binding is still `pop-ecdh`. Where the
       profile does not say, cakeys tries the sealed form first. It tries the extractable form
       when the module refuses to derive into a sealed secret (a template refusal:
       `CKR_ATTRIBUTE_VALUE_INVALID`, `CKR_ATTRIBUTE_TYPE_INVALID`, `CKR_TEMPLATE_INCONSISTENT`,
       `CKR_TEMPLATE_INCOMPLETE`), or when the module will not MAC with a sealed secret. A key
       that may not derive, or a derivation that ran and failed, is never retried
       (`an_ecdh_proof_falls_back_to_the_extractable_secret`).
     - **Read-write session (an exception to M1).** tpm2-pkcs11 keeps derived secrets as rows
       in its store, so it refuses `C_DeriveKey` in a read-only session (`derive.ecdh.read-only`
       no). The proof of a read-only verb (`resolve`, `check`) then derives in a read-write
       session that cakeys opens for it, and cakeys destroys the row again afterward. That is
       the one write that a read-only verb makes. Where the store itself is read-only (for
       example, when a sandbox mounts it read-only), `pop-ecdh` stays unavailable (16) on such
       a token.
     - **Misreported attribute.** ykcs11 reports `CKA_DERIVE = false` on every key from a
       fixed table, although its keys can derive. The provider repairs the reported value
       (`Provider::policy_flag`), so `CKA_DERIVE = true` passes the check and is recorded. A
       lock that was recorded before that repair fails `check` once (14, "CKA_DERIVE false ->
       true"), and `lock` records the value again.
   - `pop-decrypt` (RSA keys that only decrypt): the host encrypts a fresh 32-byte secret to the
     public key with RSA-OAEP (SHA-1 and MGF1-SHA1, which is the PKCS#11 baseline; SoftHSM
     implements no other OAEP). It does not encrypt the 78-byte challenge, because OAEP-SHA-256
     cannot carry 78 bytes in a 1024-bit key. The token decrypts with `CKM_RSA_PKCS_OAEP`. When
     a token refuses the hash's parameters before it decrypts, cakeys asks it again with
     SHA-256 and then with SHA-512, and it encrypts the same secret again under each hash
     (Cloud KMS binds each key to one hash, which `CKA_ALLOWED_MECHANISMS` cannot express
     [run]). A decryption that began and
     failed is never retried, since a module may leave it active (tpm2-pkcs11 [run]).
     `pop-unwrap` tries the hashes in the same way. Where the token or the key's
     `CKA_ALLOWED_MECHANISMS` offers only `CKM_RSA_PKCS`, the host encrypts with PKCS #1 v1.5
     instead. The plaintext matches only for the matching private key.
   - `pop-unwrap` (RSA keys that only unwrap, such as transport keys, CAMIGRATE.md D3): the host
     wraps a fresh 32-byte secret to the public key with the same OAEP. The token unwraps it with
     `CKM_RSA_PKCS_OAEP` into a sensitive, non-extractable session `CKK_GENERIC_SECRET`, and it
     computes HMAC-SHA256 over the challenge with that key. The host checks the result against
     its own MAC. No plaintext leaves the token, so the key needs no `CKA_DECRYPT`.
3. The host checks the proof with RustCrypto against the same canonical SPKI that it hashes into
   `rfc7093m4`. It verifies a signature, compares a MAC or compares a plaintext, in constant
   time where that matters. No proof value is ever stored.

Outcomes:

- **A proof that does not verify is a conflict (exit 13):** the private key under the locator
  is not the key that the identity names. This rule also applies to `delete`, so an If-Match
  check cannot pass on a public object that sits beside an unrelated key.
- **A token that refuses** (because the key has no `CKA_SIGN`/`CKA_DERIVE`/`CKA_DECRYPT`/
  `CKA_UNWRAP`, or the token has no such mechanism) gives exit 15. A token error gives 16, and
  so does a failed context-specific login. `pop-ecdh`, `pop-decrypt` and `pop-unwrap` have no
  per-use login, so a `CKA_ALWAYS_AUTHENTICATE` key that only derives, decrypts or unwraps is
  refused (16).
- **The spec must declare the capability that the proof uses:** `CKA_SIGN = true` for
  `pop-sign`, `CKA_DERIVE = true` for `pop-ecdh` (Weierstrass EC keys only),
  `CKA_DECRYPT = true` for `pop-decrypt`, and `CKA_UNWRAP = true` for `pop-unwrap` (RSA only).
  Otherwise, the
  spec must opt out per token with `binding = "token-asserted"`, or it is invalid (exit 17).
  The rule uses only the declared attributes, as `declared_commits` does.
- **Opting out is needed** for keys with no provable capability, for Ed448 (RustCrypto has no
  verifier or ECDH for it yet), and for tpm2-pkcs11 1.10.1 P-521 keys. That module's
  `C_SignInit` parses the module's own malformed `CKA_EC_POINT` and fails
  (`upstream/tpm2-pkcs11` fixes both the point and the failure).
- **`publicOnly` implies `token-asserted`.** A proof that is configured beside it (`pop-ecdh`,
  `pop-decrypt`, `pop-unwrap`, `pop-sign`) is invalid (17), and cakeys never overrides it
  silently.
- **PIN retries.** A run spends at most one failed PIN attempt, and it never spends the last one.
  The login at token open refuses (16) once the token reports `CKF_USER_PIN_LOCKED` or
  `CKF_USER_PIN_FINAL_TRY`. The context-specific login reuses the PIN that already logged in,
  so it cannot be wrong (a successful login resets PIV's counter). `CKF_USER_PIN_COUNT_LOW` is a
  warning. PKCS#11 does not show a slot's PIV *touch* policy, and cakeys does not handle it
  (OPEN.md).
- **A login counts only when the session shows it.** After every `C_Login` that the module
  accepts (the user's login at open, the SO step's login, and the user's login again after the
  SO step), `C_GetSessionInfo` must show the login. A
  session that is left public hides every private object, so a search would read a key as
  absent, and `delete` would drop its realisation. The result is therefore unavailable (16)
  instead (review 2026-11-24, found through the Phase 2 design;
  `a_login_the_session_does_not_show_is_unavailable`).
- **`pop-sign-pin` is recorded, never configured:** `binding = "pop-sign-pin"` in keys.toml is
  invalid (17), and `pop-sign` (the default) becomes `pop-sign-pin` on an
  always-authenticate key.

The lock records the binding per realisation (`pop-sign`, `pop-sign-pin`, `pop-ecdh`,
`pop-decrypt`, `pop-unwrap` or `token-asserted`). The `pop-*` methods share the top rank, because
each of them proves possession of the same key. A realisation therefore
never weakens unless it drops to `token-asserted`, and that drop is refused (exit 14), also when
the lock is written (`binding_downgrade_is_refused`). Another spec whose locator finds the same
token object (the same object, token and locator) must have the same binding, attestation and
mode, so a second spec cannot record that object with a weaker binding. A spec with another
locator realises another copy, which may differ
(`a_second_spec_of_the_same_object_cannot_record_it_weaker`).

### 3.7 Attestation commitments (`piv-attestation`, `tpm-certify`)

Attestation is *signed provenance*: a vendor or the TPM signs a statement of what a key is and
where it was made, and the host verifies the signature to a pinned anchor. Two schemes turn an
attestation into a content-addressed identity, one for each token type that can produce one:

| Scheme | Token | Evidence | Anchor pinned in the lock |
|---|---|---|---|
| `piv-attestation` | YubiKey PIV (ykcs11) | The evidence is the slot's attestation certificate, which ykcs11 makes on demand and which the device attestation key in slot f9 signs. cakeys verifies it to a pinned Yubico root, never to f9 alone, because a holder of the management key can overwrite f9. The chain must pass through Yubico's *PIV* intermediates only (the pool's FIDO, OpenPGP, SD and YubiHSM CAs are excluded). Every issuer must be a CA within its `pathLen`, and its `keyUsage`, when present, must include `keyCertSign`. No certificate of the chain may have a critical extension that cakeys does not process. These rules also cover the device certificate as the slot's issuer and the slot certificate itself, because one `chain::link` checks every link (review 2026-11-24 A-7: the slot link once checked only the signature) (RFC 5280 §4.2). The same walk checks an EK certificate, which must also name `tcg-kp-EKCertificate` when it names purposes. Under `check`, every certificate must also be within its validity period (by the system clock, `--at`, or `--ignore-validity`), while every other verb only warns about a chain outside its dates. Yubico attests only keys generated on the device. ykcs11 makes the certificate when it lists the slot, with no login. | The Yubico root's SPKI. |
| `tpm-certify` | tpm2-pkcs11 tokens | The evidence is a `TPM2_Certify` over the object's Name with a fresh random nonce, and the host verifies it. A module with the vendor mechanism `CKM_TPM2_CERTIFY` (upstream/tpm2-pkcs11/) runs the certify itself (`C_Sign` on the object). Its signer is a persistent AK by handle, or, with `options.akLabel`, a token object through `CKM_TPM2_CERTIFY_OBJECT`, which needs no TCTI or store. The object's public area is its `CKA_TPM2_PUB_BLOB`, and the statement must carry that area's Name. cakeys attests an object on any other module natively (tss-esapi), as follows. It reads the object's TPM blobs (read-only) from the module's own store, which is `options.tpm2Store`, or otherwise the store that the module itself finds. It loads the blobs under the token's primary over the module's TCTI (`options.tcti`, otherwise `$TPM2_PKCS11_TCTI`, `$TPM2TOOLS_TCTI` or `$TCTI`). `TPM2_Load` validates their integrity again, the certify signs their Name, and the nonce makes the response fresh. A secret key has no public key to cross-check, so the loaded object computes the key's HMAC commitment again (`TPM2_HMAC` over the commitment's input), and the result must equal the commitment that the module computed. A store row or a module that points at another TPM object is therefore refused (13), not attested (review 2026-11-23 B-1, `tpm2_a_secret_keys_attestation_is_bound_to_its_material`). cakeys refuses (15) a secret key without an HMAC commitment (AES, Triple DES), a SHA-224 HMAC key (the TPM defines no SHA-224), and any secret key through the module's own certify, which never lets cakeys load the object. cakeys flushes each transient object that it loads, so TCTIs without a resource manager do not fill the TPM. No test observes this, because the suites run under tpm2-abrmd, which also flushes. | The EK certificate's root, when an EK certificate verifies and the AK activates a credential with that EK (§3.7). Otherwise, the Attestation Key's SPKI. |

- **The commitment hashes asserted content, never signed bytes.** A PIV certificate is made again
  in each session, with a random serial and a randomized ECDSA signature, and a `TPMS_ATTEST`
  carries a nonce and a clock value that change on each run. `piv-attestation` therefore hashes
  the certificate's stable claims (the issuer SPKI, the subject SPKI, the firmware, the serial,
  the PIN and touch policy, and the form factor extensions). `tpm-certify` hashes the attested
  Name and qualified Name (`cakeys/tpm-certify/v1`, `id.rs`), and
  `attestation_definitions_are_pinned` pins both definitions. The Name is
  `nameAlg ‖ H(TPMT_PUBLIC)`, so it covers the key, every `objectAttributes` bit and the
  `authPolicy`.
- **An attestation includes the key identity by construction.** The PIV certificate's subject
  SPKI *is* the attested key, and the TPM Name covers the public area. Both schemes cross-check
  the attested key at compute time against the SPKI that the object's `rfc7093m4` hashes. An
  attestation of other material is a conflict (13), and cakeys never accepts it as additional
  evidence. An asymmetric key is never attested without that SPKI. Symmetric keys (which PIV
  cannot attest, but the TPM can) have no SPKI. For them, the portable identity is the
  commitment scheme, and the cross-check is that the module's `CKA_LOCAL`/`CKA_EXTRACTABLE`
  match the signed `objectAttributes`.
- **An attestation ID belongs to one device, so the lock records it on the realisation.** The
  same material on two tokens either cannot be attested on the second token (PIV attests only
  keys generated on the device), or it is attested with a *different* ID. `TPM2_Certify`
  certifies imported objects too, and a TPM's qualified Name names its own hierarchy. An
  imported HMAC key's Name even differs on each import (because of a fresh `seedValue`). The
  lock therefore records the attestation ID with the realisation that computed it
  (`attestation.id`), never in `objects.<name>.ids`, where a second TPM's ID would collide with
  the first TPM's ID (`tpm2_each_token_pins_its_own_attestation`). `tpm-certify` proves
  *residence* in that TPM, not generation there. `sensitiveDataOrigin` (`CKA_LOCAL`) is part of
  the Name, so an imported key's ID shows that the key was imported.
- **Attestation never replaces portable identity, and it is never the only identity.**
  A realisation with an attestation must also match a portable scheme (`rfc7093m4` for keys, a
  commitment for secret keys), and an object's `ids` never hold an attestation scheme. Loading
  enforces both rules (exit 17). The realisations of one material on several tokens are joined
  through that shared portable scheme. Each realisation keeps its own attestation, and a token
  that cannot attest (SoftHSM) verifies through the portable scheme alone. Material still links
  only through shared schemes (§3.5).
- **The opt-in is per spec and token** (`tokens.<t>.attestation = true` in the spec's token
  entry). Once a realisation's attestation is locked, a run that cannot attest (because the TPM
  is unreachable, or there is no PIN, no Attestation Key or no attestation certificate) fails
  (14) as a scheme downgrade, while evidence that is *wrong* keeps its own code (13). The user
  chooses this strictness by opting in, so it does not apply unexpectedly, and it works in one
  direction only. Opting out again (`attestation = false`) is also a downgrade, even when the
  lock is written, and so is a second spec of the same token object without the opt-in (§3.6).
  A realisation that should stop attesting needs a new object name. A provider that attests
  nothing (SoftHSM, kryoptic, p11-kit) refuses the opt-in up front (15, before anything is
  created). A provider also refuses it for a class that it cannot attest (PIV: asymmetric keys
  only; TPM: private and secret keys, because a public-key object is stored without a private
  blob, and `TPM2_Certify` cannot attest a public-only area).
- **The lock pins the attestation** per realisation: `attestation = { kind = "yubico-piv" |
  "tpm-certify", root = <SRI of the anchor's SPKI>, id = <the attestation ID> }`. A changed
  anchor (a re-provisioned TPM, or another device that signs the same claims) fails (14). A
  changed ID under the same anchor (because the attested object was replaced, or its attributes
  or policy changed) fails (10). Both fail even when the lock is written, as immutables do, and
  the material needs a new object name.
- **The TPM Attestation Key** is a restricted signing key (P-256, ECDSA-SHA256, empty auth,
  owner hierarchy). cakeys provisions it at a persistent handle and never uses it for anything
  but certify, because a restricted key signs only structures that the TPM generated. Only
  `lock` (and `create`, through `lock`) provisions it.
  `resolve` and `check` never change the TPM, and they
  fail (16, or 14 once the attestation is locked) when the AK is missing;
  `tpm2_keys_attest_their_tpm_residence` compares the persistent handles before and after a
  `check`. A key that is already at the handle is used only if its public area is exactly
  cakeys' template (a restricted sign-only P-256 key, fixedTPM, with an empty policy). Anything
  else is a conflict (13), because an unrestricted key at the handle could sign a forged
  attestation. The handle defaults to `0x81000016` (cakeys-tpm2-pkcs11 `DEFAULT_AK_HANDLE`),
  and it can be configured per token (`options.akHandle`, `0x`-prefixed, in the owner
  persistent range). With `options.akLabel`, the AK is instead a private key object of the
  token (a restricted P-256 key that the module makes in the TPM). cakeys finds it by that
  label and checks that it is restricted and fixed to the TPM and to its parent.
  `lock` makes it, and reads never do. cakeys does not check its `qualifiedSigner`, which is
  `H(QN(primary) ‖ Name(AK))`, because the host does not have the Name of the module's primary
  without the TPM or the store. The signature under the pinned key therefore identifies the
  signer. (For the persistent AK, whose primary is in the owner hierarchy, the
  `qualifiedSigner` is `H(0x40000001 ‖ Name)`, and the host compares it with what the TPM
  reads.) Trust in the AK is TOFU through the pinned `root`, unless the EK → AK activation in
  the next paragraph chains it to the manufacturer. With `akLabel`, the TOFU trusts the module,
  not the TPM: the AK's public area and its restricted and fixedTPM attributes are what the
  module reports (`CKA_TPM2_PUB_BLOB`), and cakeys never reads them from the TPM. The module
  route also takes no EK activation, so a module with no TPM behind it could sign any
  statement under a key that it made. Every run that attests this way prints a warning that says so.
  `akHandle` reads the AK from the TPM (review 2026-11-23 B-2).
- **EK → AK activation** (review D5). With an Endorsement Key certificate, every attestation
  proves that the AK resides in a TPM that its manufacturer certified. The certificate is
  `options.ekCertificate` (a PEM file, with the leaf first and then the intermediates), or
  otherwise the certificate that the TPM keeps in NV (0x01c0000a, then 0x01c00002). It must
  verify to a built-in root (crates/tpm2-pkcs11/roots: AMD fTPM, RSA and ECC) or to
  `options.ekRoots`, and cakeys judges its dates as it judges the PIV chain's dates. The host
  then makes a credential (the computation of `TPM2_MakeCredential`, in attest/credential.rs) to
  the certificate's key. The credential is bound to the Name of the AK public area whose key
  verified the certify, never to a Name that the TPM reports. cakeys recreates the EK from the
  TCG default template (with an empty endorsement auth; its key must be the certificate's key),
  and the TPM activates the credential (`TPM2_ActivateCredential`, with the EK's policy
  satisfied by `PolicySecret(endorsement)`). Only a TPM that holds that EK and an object of
  that Name recovers the secret, and the AK is fixedTPM. The lock's `root` is then the SPKI
  digest of the manufacturer's root, not the AK's SPKI digest. A TPM that loses its
  certificate, or an AK that cannot activate, therefore no longer matches (14, or 13 for a
  refused activation). A named `ekCertificate` that does not verify is refused (13). A
  certificate that is found only in NV and reaches no anchor (because the manufacturer has no
  built-in root, or because NV does not hold the intermediates) leaves the AK trusted on first
  use, pinned by its own SPKI digest as before. With a verified EK, the run's authorizations
  also go through an HMAC session that is salted to the EK. ESYS encrypts the salt to the EK
  public area that `CreatePrimary` returned, which must be the certificate's key, so only that
  TPM learns the session key. The PIN-derived seal auth and the object's auth never
  cross the transport (the session sends an HMAC, not a password). The unsealed wrapping key
  crosses the transport encrypted (`encrypt` on the unseal), and
  every response that the session covers carries an HMAC that ESYS checks
  (`tpm2_the_salted_session_keeps_the_token_secrets_off_the_wire` reads swtpm's log of the
  traffic). Without a verified EK, cakeys uses password sessions, as before. A realisation that
  was locked on first use keeps its anchor: adding `ekCertificate` later is an anchor change,
  which even `lock` refuses (14). To move the anchor to the manufacturer, delete that
  realisation's `attestation` table from `keys.lock` (a reviewed diff), and then `lock` records
  the new root. Nothing persists, because cakeys flushes the EK and the policy session. Tests:
  on swtpm with a test CA (`tpm2_attestation_activates_a_credential_to_the_certified_ek`), and
  on the AMD fTPM with its fetched certificate (`keys_attest_to_the_manufacturer_on_the_real_tpm`).
- **What each scheme proves, and what it does not.** `tpm-certify` is bound to freshness by the
  nonce: it proves that the object was loaded in that TPM *at verify time*, with the certified
  attributes. `piv-attestation` has no verifier nonce (Yubico's certificate carries none), so it
  proves the claims but not liveness: a malicious module could replay an old certificate. It is
  [attested] provenance, not [crypto] proof of presence. Neither scheme can say anything about
  other tokens, so exclusivity stays [unobservable] (§8.2).
- **Vendor HSM attestations** (Luna PKC, Google Cloud HSM, nShield) use out-of-band formats
  that have not been researched (see the review's gap). Each one is reserved for a future
  scheme, and cakeys never guesses a format.

## 4. Files

### 4.1 `keys.toml`

[`CONFIG.md`](CONFIG.md) annotates this file and gives the reasons behind each table.

The rules below decide what may be created and adopted:

- **References are checked at load** (exit 17). A spec's `object` must name an
  `[objects.<name>]` table, even when nothing uses the spec. A `$NAME`/`${NAME}` path reference
  (in `pinFile`, `soCredentialFile` or `module`) must be well formed, and it must name a set
  environment variable only where the path is used (a login, or the opening of a token). A check
  that opens no token therefore needs none of these variables, and one shared `keys.toml` can
  carry machine-specific paths. `pinEnv = "VAR"` remains the way to pass the *PIN itself* through
  the environment (`env_references_and_object_refs_are_checked_at_load`,
  `pin_file_path_can_come_from_the_environment`).
- **The admin credential (`soCredentialFile`/`soCredentialEnv`) is read only by a step that needs the SO.** A
  provider declares that its module creates and destroys objects only in an SO session (ykcs11
  does). On other modules, the user creates and deletes objects, and only
  `camigrate transport --trust-on` (CAMIGRATE.md D2) reads the credential (the SO PIN)
  (`admin_credential_is_read_only_by_security_officer_steps`). Login state is per token, so the
  step logs the user out, logs in as the SO, generates (or destroys), logs out, and logs the user
  back in. The SO credential is read just before the step and zeroized after it.
  `resolve` and `check` never read it.
- **Of cakeys' verbs, only `create` makes the keys that keys.toml declares,** and only on a pair
  whose `origin` is `create`. `lock` and `check` find what is there (2026-11-15: `check` is a
  read), and `lock` may provision a TPM Attestation Key (§3.7). Certificates, public keys and
  data objects are adopted or imported, and cakeys never creates them
  (`adoption_rules_are_validated`, `standalone_public_key_objects`, `data_objects_…`). When the
  lock already pins the object's material (with IDs recorded from this token or from another
  token), `create` is refused (14) before anything is created, because generated material could
  never match (D1) (`create_never_fights_a_locked_identity`). Put the same material under the
  locator instead, or give the token's key its own object name.
- **`origin`** says how an object comes to be on each token (2026-11-15; it replaces `createOn`
  and `autoCreate`). The value is `create` (`cakeys create` generates the object there), `import`
  (camigrate brings the material from the place where it was created, and a move puts it on no
  other pair) or `adopt` (the object is already there). A private or secret key states its
  origin, and any other object is adopted unless it says `import`. At most one pair of an object
  says `create`. That pair settles where the object's material originates and with whose policy,
  so no order of a run decides either question (otherwise the load fails with 17)
  (`origins_say_how_an_object_comes_to_be_on_a_token`, `create_happens_where_origin_says_create`).
  Like the locator, `origin` is not part of the object's type or the spec digest. A fourth value
  is `file` (2026-11-16, [FILE.md](FILE.md)): the material originates in the file that the
  object's `migrate.file` names, and camigrate brings it from there. Any number of pairs may say
  `file`, and an object that originates in a file is
  never also created (17) (`objects_born_in_files_read_their_migrate_file`,
  `files_populate_tokens_with_their_material`).
- **`create` checks the profiles before it makes anything:** every pair that it would create goes
  through the static gate first, and a profile's *no* refuses the run before any token is opened
  (15), unless `--skip-unsupported` is given
  (`create_checks_the_profiles_before_it_makes_anything`).
- **`CKK_SHA*_HMAC` keys** cannot be generated, because PKCS#11 has no mechanism for them
  (`hmac_key_types_commit_with_their_own_hash`).
- **`publicOnly`** verifies a private key through its public-key object, without a login (which
  spares PIV PIN retries). It forbids policy attributes, `create` never makes it, and `delete` refuses it
  (`adopt_certificate_and_public_only_key`).
- **`binding = "token-asserted"`** skips the proof of possession for a private key (§3.6).
- **Declared attribute names must fit the class** (PKCS#11 3.2 §4). Every class may carry the
  common `CKA_PRIVATE`, `CKA_MODIFIABLE`, `CKA_COPYABLE` and `CKA_DESTROYABLE`. Private keys add
  `CKA_SIGN`, `CKA_SIGN_RECOVER`, `CKA_DECRYPT`, `CKA_UNWRAP`, `CKA_DERIVE`, `CKA_SENSITIVE`,
  `CKA_EXTRACTABLE`, `CKA_ALWAYS_AUTHENTICATE` and `CKA_WRAP_WITH_TRUSTED`. Public keys add
  `CKA_VERIFY`, `CKA_VERIFY_RECOVER`, `CKA_ENCRYPT`, `CKA_WRAP`, `CKA_DERIVE` and `CKA_TRUSTED`.
  Secret keys may carry all of the key booleans, certificates add `CKA_TRUSTED`, and
  `CKA_ALLOWED_MECHANISMS` is allowed only on key objects. Any other attribute is invalid (exit
  17) (`attributes_are_validated_per_class`). Certificates therefore take policy attributes:
  declare what the object shows. (`CKA_TRUSTED = true` must match an object that the token's
  security officer already trusted, because users cannot set it.)
- **`CKA_ALWAYS_AUTHENTICATE = true` proves possession with a PIN per use** (`pop-sign-pin`,
  §3.6). A successful context-specific login with the session's PIN spends no retry, and every key type
  signs single-part after it (with the patched cryptoki)
  (`always_authenticate_keys_prove_possession_with_a_per_use_pin`).
- **`CKA_TRUSTED = true` refuses `create`** (exit 17), because generation cannot set it. Such a
  key is adopted.
- **Not expressible:** keys.toml cannot express `CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`,
  `CKA_DERIVE_TEMPLATE` or `CKA_CERTIFICATE_CATEGORY`, because cryptoki 0.12 maps none of them.

### 4.2 `keys.lock` (input, updated in place)

[`LOCK.md`](LOCK.md) annotates this file and gives the reasons behind each table.

- **Every realisation field has one class:** compared, observed or provenance. Removing
  `observed`, `observation`, `provenance` and the `observations` table changes no verdict, and a
  lock without `version` or without a compared field is invalid (exit 17)
  (`observed_and_provenance_never_change_a_verdict`). An observed mechanism that the token no
  longer offers is a warning.
- **The observation table only removes duplicates.** A realisation still says exactly what it was
  recorded with, so two realisations that were recorded through different module builds name two
  entries. An entry's key is not recomputed on load, and an entry is the one lock table that
  keeps TOML keys that this version of cakeys does not know. A realisation that names a missing
  entry is invalid (17). A write and `gc` drop the entries that nothing names. A token's
  observation (`Lock::token_observation`, for the static gate and for `export` from the lock) is
  known only when all of its realisations name one entry. Otherwise, the caller says so and names
  `lock`.
- **The policy vector is closed-world.** The spec declares the attributes that it requires. The lock
  records every attribute that the object shows for its class, whether it is declared or not. This
  includes the booleans (SoftHSM EC private keys, for example, default to `CKA_DECRYPT`,
  `CKA_UNWRAP` and `CKA_SIGN_RECOVER`) and, on key objects, `CKA_ALLOWED_MECHANISMS` when the
  token reports a non-empty list. A recorded attribute that changes or becomes unreadable fails
  `check` (exit 14) until `lock` runs, and a newly readable attribute is a note. With
  `publicOnly`, this is the public object's vector.
- **Immutables** (`CKA_LOCAL`, `CKA_NEVER_EXTRACTABLE`, `CKA_ALWAYS_SENSITIVE`,
  `CKA_KEY_GEN_MECHANISM`) are compared in the same way. A flag that was `true` and is no longer
  `true` means that the object was replaced (for example, the same material was imported again).
  That is refused even when the lock is written, as a downgrade is
  (`policy_drift_and_replaced_objects_are_refused`).
- **Loading checks the lock's own invariants** (exit 17, never a hash mismatch), and
  `lock_invariants_are_checked` tests them:
  - every ID and `specDigest` is a `sha256-` SRI digest of 32 bytes, and a `commitmentLabel` is
    non-empty printable ASCII;
  - a realisation's `object` is in the lock, and its `schemes` are among that object's IDs;
  - **one object per material:** no two objects of one class share an ID under one scheme (a
    certificate's `rfc7093m4` is exempt, because it names the subject key, which renewed
    certificates share). `lock` refuses to record a second name (exit 14);
  - **`pairs`** makes the key ↔ certificate relation explicit by listing the objects that share
    an `rfc7093m4`. A listed partner that is present in the file must share it and list the
    object back. A listed partner that is absent may live in another fragment, so locks can still
    be split and joined per object. Partners that are present but unlisted are a note, and `lock`
    records them;
  - a private-key realisation records its `binding`, and no other class has one.
- **`schemes`** records which schemes a realisation computed and matched, so the lock shows which
  realisation established which ID. A realisation that later computes fewer schemes is refused
  like a mode downgrade (exit 14).
- **Writes are atomic** (a temporary file, then a rename). A run that may update the lock holds
  an advisory exclusive lock on `<lock>.lck` across its read-modify-write (finding M3), so
  concurrent updaters on different tokens wait in turn instead of losing each other's
  realisations. A run that waits says so first:
  `note: waiting for <lock>.lck`. Readers never take that lock,
  because the rename makes each read a consistent snapshot. A leftover `.lck` is harmless,
  because the lock is advisory and is released when its holder exits
  (`update_lock_waits_for_the_sidecar_lock`). cakeys opens an existing `.lck` read-only,
  so another user's `.lck` never refuses the run. The guard,
  the write and the writability check go to the file that the lock path resolves to: a symlinked
  lock is written through, and its two names share one guard. A rewritten lock keeps the old
  lock's mode, and also its owner and group as far as the writer may set them
  (`a_saved_lock_keeps_its_mode_and_a_read_only_sidecar_guards`).
- **`gc`** collects the entries that the config no longer names (finding D3): every
  `[realisations.<spec>.<token>]` whose spec dropped the token, and every `[objects.<name>]` that
  is gone from `keys.toml`. It prints the stale table names and removes exactly those tables
  (`--dry-run` only prints them). Live objects keep their `ids`, since the same material may
  live on other tokens or come back.
- **URIs are pure locators** (RFC 7512), with no `module-path`. They carry the token `serial`,
  because tokens may share a label, and they always carry the object `type`.
- **One private key per `CKA_ID`.** Consumers such as OpenSSH pick the first private key whose
  `CKA_ID` matches. With a login, another private key under the same `CKA_ID` as a private key,
  public key or certificate that is being resolved is ambiguous (exit 12). A public session
  cannot see private keys, so `observed.session` records which view the check had, and a change
  from `user` to `public` gives a warning (`a_second_private_key_under_the_same_id_is_ambiguous`).
- **Versions** are raw `CK_VERSION` major.minor values (ykcs11 2.7.3 → `2.73`).
- **Observations:** a different module build identity or token is a *warning*, and so is a
  different module file `hash` at the same `path` (the file was replaced in place, which a path
  outside the Nix store cannot show). Only a different module file `path` is a *note*. None of
  these fails (`module_and_token_provenance_warn_but_do_not_fail`). The `path` is the file that
  the dynamic loader mapped, with symlinks resolved, whatever named it (`$NAME`, `--module`, or a
  bare name that the library search found).
- **The spec digest** is the SHA-256 of the RFC 8785 (JCS) form of
  `{"v":1,"type":<object, camelCase>, "attributes":<…>}`, with keys sorted at every level and no
  whitespace (`serde_jcs`; the switch to serde_jcs left the pinned digests unchanged). Attribute
  values are typed: booleans, and `CKA_ALLOWED_MECHANISMS` as a sorted, duplicate-free list.
  `certificateType` and `publicAttributes` take part only when they are set, under their own
  keys. Curves are canonical (`secp256r1`, never an alias), so a curve alias is the same type and
  gives the same digest. `spec_digests_are_pinned` pins the digests.
- **A realisation record is required.** `check` of a (spec, token) pair that the lock does not
  record fails (exit 14), even when the material matches the locked IDs, because the lock
  describes where objects live, not only what they are
  (`s3_an_unrecorded_token_is_a_precondition_failure`). First use, with no locked IDs to compare,
  gives exit 18 with `got:`.
- **The record is compared** with keys.toml. A different `object`, `locator`, `publicOnly` or
  spec digest fails `check` (exit 14, and the message names each change) until `lock` records
  the realisation again (`s4_a_public_only_flip_is_a_spec_change`,
  `s8_a_retargeted_spec_is_a_spec_change`). A changed locator or object is never reported as an
  unexplained hash mismatch.
- **A changed object type** in `keys.toml` is refused with exit 14, and the message names the
  change. The refusal also holds when the lock is written, because different material needs a
  new object name. Curve aliases are canonicalized on load (in `keys.toml` and in the lock's
  recorded types), so they are the same type and need no change
  (`the_lock_pins_type_spec_provenance_and_schemes`).
- **Provenance:** a different `provider` is a warning, and a different `cakeysVersion` is a note.
- **Locked schemes that are not checked** are reported. A scheme that this cakeys does not know
  gives a warning that names the scheme. A scheme that it knows but cannot compute for this spec
  on this token gives a note.

## 5. Verbs and exit codes

This section moved to [CAKEYS.md](CAKEYS.md#verbs).

## 6. Architecture

This section moved to [ARCHITECTURE.md](ARCHITECTURE.md), which describes the crates, the
providers, the cryptoki patches and the dependencies.

## 7. Nix integration

This section moved to [CAKEYS.md](CAKEYS.md#nix-integration), which describes the library, the
pseudo-FOD check, the NixOS module and what real builds may reach.

## 8. Security model

### 8.1 Enforced (with tests)

Each bullet names the tests that enforce it, and `checks.claims` fails on a bullet that names
none. The liar matrix (`liars_<class>`, `crates/cli/tests/liars.rs`) runs each verb against a
module that gives each kind of false answer about each kind of object.

- **Identity is the CA-ID.** Every check recomputes it from the token and compares it with the
  lock. On every reference token, the identity is the one that the host computes
  (`asymmetric_material_has_one_identity_on_every_reference`). A lock that pins another ID is a
  mismatch (`observed_and_provenance_never_change_a_verdict`), and so is another object that is
  found in its place (`liars_other`).
- **Locators never create over occupied slots** (If-None-Match), and never match more than one
  object (`never_create_over_an_occupied_locator`,
  `a_second_private_key_under_the_same_id_is_ambiguous`; a second object under the locator in
  `liars_other`).
- **The type and the policy of the live object** must match the spec
  (`the_live_object_must_be_what_the_spec_says`, `policy_drift_and_replaced_objects_are_refused`;
  a flipped flag in `liars_flag`).
- **Private keys prove possession** of the key that their identity names, unless the spec opts
  out per token. The binding is recorded and cannot weaken (§3.6;
  `derive_and_decrypt_only_keys_prove_possession`,
  `h1_a_private_key_beside_an_unbound_public_object_is_a_conflict`,
  `binding_downgrade_is_refused`; another key that answers, for each binding, in `liars_other`).
- **Attestation commitments are verified evidence, never a standalone identity** (§3.7). The host
  checks the chain or the signature against the pinned anchor, the attested key must be the
  material that the object's portable scheme names, and the lock pins the attestation per
  realisation beside a portable scheme. The same material on another token therefore verifies
  there through the portable scheme, whether that token attests it or not
  (`attestation_is_per_realisation_and_never_alone`,
  `tpm2_attested_material_travels_to_a_second_hsm`,
  `a_slot_certificate_signed_by_another_key_is_refused`, `a_statement_by_another_signer_is_refused`,
  `the_material_is_the_attested_blobs_not_read_publics`).
- **Identity modes never weaken.** A downgrade fails (§3.4; `downgrade_is_an_error`,
  `the_same_or_more_passes_and_less_is_a_downgrade`).
- **Material is linked only through a shared scheme** (`material_links_only_through_a_shared_scheme`,
  `disjoint_schemes_never_link_material`).
- **The lock never holds token outputs, only their hashes** (`a_lock_holds_no_token_output`). A
  private data object is hashed only when its spec declares `CKA_PRIVATE = true` (§8.2;
  `private_data_objects_are_identified_when_declared`).
- **Lock updates are serialized** by the advisory `<lock>.lck` sidecar, and readers get
  consistent snapshots through the atomic rename (`update_lock_waits_for_the_sidecar_lock`).
- **Refused operations leave nothing behind:** cakeys checks before it creates, and it cleans up
  after an identity fails. The exception is a key on a module that cannot delete keys (ykcs11),
  which stays and is reported (`create_checks_the_profiles_before_it_makes_anything`,
  `a_creation_that_cannot_be_identified_is_undone_or_reported`,
  `a_creation_that_fails_after_the_write_is_undone`,
  `tpm2_identity_failure_after_create_leaves_nothing`, `a_move_the_module_fails_is_refused_and_undone`;
  every refusal cell of the liar matrix asserts the lock and the token as they were).
- **A provider's operation runs after core's rules, never instead of them** (review 2026-11-24
  B-2). `Token::create` and `Token::destroy` ask `placement` or `deletion`, and they enter the
  SO session that `manages_as_so` asks for. They then call the provider's `create` or `destroy`
  with a `Checked` request that no other crate can build, so an override cannot skip either
  step. The gate, the live checks and the capability check ask the same named rules
  (`ops::Rule`; `k1_placement_comes_before_create_on_every_path`,
  `placement_holds_on_every_path`, `a_provider_override_runs_as_so_where_the_module_needs_it`).
- **A destroy is verified, never taken on the module's word** (review 2026-11-24 B-13). When a
  provider or a module profile says that the module keeps what it is asked to remove
  (`Provider::deletion`, `delete.<class> = no`), cakeys refuses the delete before anything is
  destroyed, in a dry run too (`delete-refused`, 15). After every destroy, cakeys looks under the
  locator again. An object that is still there gives `delete-kept` (16), and the lock keeps the
  realisation (`a_delete_the_module_did_not_do_keeps_the_lock`,
  `a_profile_row_that_says_the_module_keeps_keys_refuses_the_delete`,
  `k5_a_destroy_the_module_did_not_do_keeps_the_lock`,
  `k6_a_profile_no_refuses_the_delete_before_any_destroy`).
- **A provider adjusts templates and repairs reads only where it may** (review 2026-11-24
  B-3). A template comes back from `Provider::template` with its security attributes as cakeys
  built them or tightened (a restriction set to true, or a permission set to false). Any other
  change to `CKA_TOKEN`, `CKA_PRIVATE`, `CKA_SENSITIVE`, `CKA_EXTRACTABLE`,
  `CKA_WRAP_WITH_TRUSTED`, `CKA_TRUSTED`, `CKA_ID`, `CKA_LABEL`, `CKA_MODIFIABLE`,
  `CKA_COPYABLE` or `CKA_DESTROYABLE` is refused (17) before anything is made
  (`a_provider_changes_no_security_attribute_but_to_tighten_it`,
  `a_provider_cannot_loosen_a_session_key`, `k2_templates_keep_their_security_attributes`). A
  provider repairs a policy flag only for the (attribute, private key type) pairs that it
  declares (`Provider::repairs`; for ykcs11, `CKA_DERIVE` of EC and X25519 keys;
  `a_repair_applies_only_where_it_is_declared`, `k3_repairs_are_declared_and_idempotent`). A
  session key's template has its own type, `templates::SessionTemplate`. Only
  `templates::session` and `rebind_copy` build it, and cakeys asks the provider to adjust it as
  the key that it was built for (`adjusted_session`). Each session key's `CKA_TOKEN`,
  `CKA_SENSITIVE` and `CKA_EXTRACTABLE` are fixed (review 2026-11-24 B-8;
  `each_session_key_is_sealed_as_its_purpose_says`, `k2_session_keys_read_back_as_built`).
- **Token paths reach only builds that require the token's feature** (`checks.module`, its
  subtest "the hook grants token paths only to builds requiring the token's feature"; a NixOS
  test, tier T1).

### 8.2 Not enforced / known gaps

The reviews that found these gaps are archived: `docs/archive/REVIEW-2026-11-11.md` (the code) and
`docs/archive/REVIEW-2026-11-13.md` (the threat model).

- **The check is not the use.** A consumer opens the key by its URI after `check` returns, and a
  key that is swapped in between is not seen until the next check. A file or an HTTP resource has
  the same contract (it is checked, then used), and cakeys accepts the gap on the same terms
  ([CAKEYS.md](CAKEYS.md#the-contract-with-programs-that-use-keys)).
- **A build served from the Nix cache contacts no token** (§7.2). `nix build --check` forces
  the check.
- **The lock is the trust root, and it is not signed.** Whoever can change `keys.lock` (or
  `keys.toml`) can re-pin an object. Until the lock is signed (OPEN.md), both files must live in
  version control whose history is signed and reviewed.
- **A commitment ID lets anyone who holds the lock test guesses of a low-entropy secret.** The
  ID is the SHA-256 of a MAC, under the key, of a public label (§3.3). For a random key, it
  reveals nothing usable. For a passphrase or another guessable value that is held as
  `CKK_GENERIC_SECRET` (or as an HMAC key type), each guess can be checked offline against the
  lock. A private data object's `valuehash` is a plain SHA-256 of its value, so cakeys computes
  it only when the spec declares `CKA_PRIVATE = true`. That declaration is the author's
  statement, reviewed with keys.toml, that the value is random (a token or an
  application secret, never a password or PIN). Without the declaration, the object is
  refused (15). Secret keys are hashed on the same assumption without a declaration. Do not
  commit a lock that pins a guessable secret (review A9).
- **`tpm-certify` is experimental and pending review** (review A8). It reads tpm2-pkcs11's
  private store (the sqlite schema, the YAML attributes, and the sealed wrapping key), which the
  module does not offer as a stable interface. A module version that it was not tested with
  (anything other than 1.10.x) is refused (15). Without an EK certificate that verifies (§3.7,
  EK → AK activation), it proves **the same TPM as at first use**: the Attestation Key is trusted
  on first use and pinned in the lock, so a later attestation shows that the object still sits
  in the TPM that held the AK then. It does not show that this TPM is genuine hardware from a
  known vendor.
- **`token-asserted` bindings are unproven.** With the opt-in or `publicOnly`, only the token's
  report ties a private key to its identity. (H1 is fixed for every `pop-*` proof:
  `h1_a_private_key_beside_an_unbound_public_object_is_a_conflict`,
  `derive_and_decrypt_only_keys_prove_possession`.)
- **Policy and uniqueness are what the module reports.** The `pop-*` proofs bind the material,
  not `CKA_EXTRACTABLE` or `CKA_SENSITIVE`, and "never more than one object" holds only if the
  module's search returns every match exactly once. native-pkcs11 reports a constant policy for
  any keychain key, and its searches both hide duplicates and show one key twice (PLAN.md A0b).
  A provider can repair a known misreport, as `policy_flag` does for ykcs11's `CKA_DERIVE`, but
  it cannot repair the report of a module that does not know the true value.
- **`piv-attestation` proves no liveness** (Yubico's certificate has no verifier nonce, §3.7):
  a malicious module could replay an old certificate. `tpm-certify` is bound to a nonce, so it
  proves that the object was loaded in that TPM at verify time.
- **The TPM Attestation Key is TOFU without an EK certificate** (§3.7). The AK proves "this
  TPM", not "this genuine TPM", unless an EK certificate verifies to a known root
  (`ekCertificate`, NV) and the AK activates a credential with that EK. The built-in roots are
  AMD's fTPM roots only, and other manufacturers need `ekRoots`. Without a verified EK, the TPM
  transport is also unauthenticated: it uses password sessions, and the token's unsealed
  wrapping key crosses it in the clear.
- **The PIV path is verified by hand on one YubiKey, not in CI.** The results on a YubiKey 5C
  NFC FIPS (firmware 5.7.4, ykcs11 2.7.3) are these. ykcs11 exposes the slot attestation
  certificate by a label suffix and a shared `CKA_ID`, and the f9 certificate by its bare label,
  with no login at all. The chains (slot → f9 → `Yubico PIV Attestation B 1` →
  `Yubico Attestation Intermediate B 1` → `Yubico Attestation Root 1`) verify, also with
  openssl. `lock` and `check` pass on keys that were generated on the device. A tampered ID gives
  10, a tampered root or an opt-out gives 14, and an imported key under a locked attestation
  gives 14 (15 when the attestation is not locked). Creating with `soCredentialFile` generates a
  key. `C_DestroyObject` was confirmed to leave the key in the slot. The shipped example keys
  are imported, so Yubico attests none of them. The opt-in `tests/yubikey.rs` repeats the
  read-write path on scratch slot `0x95`. It last ran on 2026-11-12 on an emptied slot, so
  generation ran, but nothing runs it automatically.
- **Features are self-declared.** Any user who is allowed to build can require a token's
  feature, and the real gate is `allowed-users`.
- **No merge rule for lock fragments.** The `<lock>.lck` sidecar serializes updates (M3), and
  `gc` collects stale entries (D3), but two hand-edited lock fragments still need a manual
  `git merge` (S16).
- **p11-kit hides the module behind it,** so the lock records p11-kit as the module.

## 9. Testing

This section moved to [DEVELOPMENT.md](DEVELOPMENT.md#testing).

## 10. Frozen identifiers, and what makes a lock portable

A `keys.toml` and its `keys.lock` must verify the same way under any later cakeys, as a
dependency lock does. **Lock version 1 is a draft:** it is unpublished and changes in place until every
review passes it. Only then is it frozen, and later changes get a new version. The lock records
the values that determine each ID: the scheme name, the commitment label and the hash itself.
Definitions fix everything else:

- **Scheme definitions are immutable.** A scheme name (`rfc7093m4`, `certhash`, `valuehash`,
  `commitment`, `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`) always denotes exactly the computation in
  §3. A changed computation gets a *new* scheme name, never an edit. The known-answer test
  `scheme_definitions_are_pinned` pins each one: the bytes every commitment scheme feeds the
  token (for each key type that it takes: `kcv-ecb` and `kcv-ecb-dec` on AES and DES3), and the
  `rfc7093m4` of fixed keys on every curve and RSA (including the canonical encoding). A new key
  type under an existing scheme is an addition to its definition, never a change for the types
  that it already took.
- **The lock records everything else an ID depends on:** the object `type` (the key type and
  length feed the commitment label), the commitment label, the spec digest, and, as provenance,
  the module, the token, the provider and the cakeys version. A changed `keys.toml` is reported
  as a change, never as an unexplained hash mismatch.
- **Known answers for scheme mappings:** `commitment_mechanisms_are_pinned` fixes which HMAC hash
  each key type uses and which mechanism each scheme runs.
- **Further frozen identifiers:** the label layout `<label>/<scheme>/<keyType>/<bits>` and the
  mode names;
- the SRI form `sha256-<base64>`;
- the attestation commitment encodings `cakeys/piv-attestation/v1` and `cakeys/tpm-certify/v1`,
  each a domain tag followed by length-prefixed fields (`attestation_definitions_are_pinned`);
  the attestation scheme names (`piv-attestation`, `tpm-certify`); the lock-record kinds
  (`yubico-piv`, `tpm-certify`); and the pinned anchors, which are the embedded Yubico root SPKIs
  (`the_yubico_roots_are_pinned`) and the AK handle `0x81000016` (`DEFAULT_AK_HANDLE`);
- the spec digest JSON shape (`"v":1`, camelCase, `keyType` omitted when it is empty,
  `certificateType` and `publicAttributes` only when they are set). The certificate digest
  changed with `certificateType`, which was allowed because the v1 lock is a draft;
- the binding names (`pop-sign`, `pop-sign-pin`, `pop-ecdh`, `pop-decrypt`, `pop-unwrap`,
  `token-asserted`) and their rank (the `pop-*` methods share the top rank). The challenge layout
  (`cakeys/pop/v1`) is pinned by `message_layout_is_pinned`, although nothing stored depends on it;
- the lock field names: `version`; `objects` with `type` (`class`, `keyType`, `curve`,
  `modulusBits`, `valueLen`, `certificateType`), `ids`, `commitmentLabel`, `publicKey`;
  `realisations` with `object`, `locator`, `specDigest`, `mode`, `schemes`, `pairs`, `publicOnly`,
  `binding`, `policy`, `immutables`, `attestation` (`kind`, `root`, `id`), `observation`,
  `observed` (`uri`, `session`) and `provenance` (`origin`: `from`, `method`, `exposure`,
  `declared`); `observations` with `provider`, `cakeysVersion`, `profile`, `mechanisms`,
  `module` (`path`, `hash`, `description`, `manufacturer`, `version`, `cryptoki`), `token`
  (`model`, `serial`, `firmware`, ...) and `capabilities` (`answer`, `evidence`, `via`);
- the `keys.toml` keys;
- the exit codes;
- the URI shape.

The project was renamed from `key-mgmnt` on 2026-11-11 (the crates, the binary, the NixOS options,
the units and the `CAKEYS_*` variables). No identity changed.

The migration method names, exposure levels and file formats are frozen in the same way
([CAMIGRATE.md](CAMIGRATE.md#frozen-names-and-formats)), and
`method_names_are_pinned_and_round_trip` pins them.
