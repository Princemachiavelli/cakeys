# Export and import (plan, 2026-11-12)

Native `export` and `import` for every backend: move key material from one token to another,
with token-to-token key wrapping where both sides support it and vendor tooling where they do
not; a `--dry-run` that says what can and cannot move, and how; and an export that is shaped for
its intended target. cakeys already *verifies* a copy (realise on the second token against the
locked IDs, [`docs/USE_CASE.md`](docs/USE_CASE.md)); this plan makes it *make* the copy.

Evidence tags on every backend claim: **[run]** verified by running it (the spike below),
**[src]** read in the module's source, **[todo]** still to verify.

## How complex

About **5k lines** (≈2.8k production, ≈2.3k tests) and **4½–6½ weeks** for one person, for
phases 0–5 below: dry-run, public objects, token-to-token wrapping between PKCS#11 modules
(with token-enforced trusted wrapping), plaintext-through-host imports into tpm2-pkcs11 and a
YubiKey, and passphrase-protected files. That is +55% on today's ≈5k production lines. The
native TPM duplication format (phase 6) is another ≈1k lines and 1½–2 weeks, and the riskiest
piece; vendor providers (phase 7) get their hook in phase 1 and their methods with hardware.

What drives the risk:

1. **Per-module template rules.** A two-module spike already found two: SoftHSM refuses
   `CKA_VALUE_LEN` in an unwrap template; kryoptic gives an unwrapped key no usage unless the
   template asks for it. Every backend will have more; the reference tokens and the
   cross-reference tests are how they get found.
2. **The security model.** Export exists only for keys created extractable, and an extractable
   key can be wrapped by anyone who can log in. What the plan can and cannot promise is
   decision D2 below; it needs a review before phase 3 ships.
3. **The TPM duplication format** (phase 6): KDFa, an encrypted seed, an outer wrap and its HMAC,
   built on the host to a target TPM's parent key.
4. **cryptoki gaps.** cryptoki 0.12 has no `CKM_AES_KEY_WRAP_KWP` (0x210B) [run], and raw
   mechanism IDs are accepted only in the vendor range [src]: a local patch and an upstream PR,
   like the HMAC key-type fix (`upstream/rust-cryptoki/`).

## What the backends can do

| Backend | Export (source) | Import (target) |
|---|---|---|
| SoftHSM 2.7 | `C_WrapKey`: AES-KW, AES-KW-PAD (RFC 5649), RSA-OAEP with SHA-1 only (SHA-256 is `CKR_ARGUMENTS_BAD`) [run] | `C_UnwrapKey` with the same [run]; `C_CreateObject` from plaintext [run] |
| kryoptic 1.5.4 | `C_WrapKey`: AES-KW, AES-KWP (0x210B), AES-KW-PKCS7, AES-GCM, RSA-OAEP SHA-1 and SHA-256 [run] | `C_UnwrapKey` with the same [run]; `C_CreateObject` [run] |
| p11-kit (forwarding) | whatever the module behind offers, minus what the RPC drops: AES-KW and AES-KW-PAD are dropped (DESIGN §6.2) [run, earlier]; whether `C_WrapKey` with OAEP is forwarded [todo] | the same limits [todo] |
| tpm2-pkcs11 1.10 | never: `C_WrapKey` and `C_UnwrapKey` are unsupported [src]; its keys are bound to the TPM [todo: fixedTPM/fixedParent] | `tpm2_ptool import` of EC, RSA and HMAC keys from plaintext [run, `tests/tpm2.rs`], not AES and not P-521 [run, earlier]; `C_CreateObject` makes only RSA public keys, certificates, data objects and secret-key *records* that are not TPM keys [src] — not an import path; native `TPM2_Import` of a duplication blob [todo] |
| YubiKey PIV (ykcs11 2.7) | never: `C_WrapKey` is unsupported [src], and PIV keys never leave the device | `C_CreateObject` as SO of RSA 1024–4096, EC P-256/P-384 (the curve inferred from the scalar's length) and Ed25519 private keys, and certificates [src]; from plaintext only; imported keys are never attested [src] |
| Vendor HSMs (Luna, CloudHSM, nShield) | vendor wrap mechanisms and tools; CloudHSM offers `CKM_RSA_AES_KEY_WRAP` [todo] | likewise [todo] |

Neither SoftHSM nor kryoptic offers `CKM_RSA_AES_KEY_WRAP` [run]: wrapping to a target's public
key is composed from its two halves (decision D4).

## Spike (2026-11-12, SoftHSM 2.7.0 ↔ kryoptic 1.5.4, pkcs11-tool)

| Path                                                                                                                                                                                                            | Result                                                                                                                                               |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| AES-KW, both directions, a 32-byte AES key                                                                                                                                                                      | same bytes after unwrap                                                                                                                              |
| SoftHSM AES-KW-PAD (0x210A) ↔ kryoptic AES-KWP (0x210B), both directions, 20- and 32-byte secrets                                                                                                               | same bytes: one format (RFC 5649), two mechanism IDs                                                                                                 |
| EC P-256 private key (the `tpm-import-p256` fixture) wrapped with PAD/KWP, both directions                                                                                                                      | the unwrapped key signs a message that verifies against the fixture's public key                                                                     |
| RSA-OAEP (SHA-1, MGF1-SHA1) carrying a 32-byte KEK to an RSA-3072 key on the other token, both directions                                                                                                       | same bytes                                                                                                                                           |
| RSA-OAEP SHA-256                                                                                                                                                                                                | kryoptic ↔ kryoptic only; SoftHSM refuses it                                                                                                         |
| Unwrap templates                                                                                                                                                                                                | SoftHSM refuses `CKA_VALUE_LEN` (`CKR_ATTRIBUTE_READ_ONLY`); kryoptic sets no `CKA_SIGN` on an unwrapped private key unless the template does        |
| RSA-2048 private key (the `tpm-import-rsa2048` fixture), PAD/KWP, both directions                                                                                                                               | the unwrapped key signs (`CKM_SHA256_RSA_PKCS`) for the fixture's public key                                                                         |
| The composed method end to end: a fresh AES KEK on the source, RSA-OAEP-wrapped to the target's RSA-3072 transport key; the P-256 key wrapped under the KEK (PAD/KWP); the target unwraps the KEK, then the key | works SoftHSM → kryoptic and kryoptic → SoftHSM (OAEP SHA-1), kryoptic → kryoptic (OAEP SHA-256); the key signs for the fixture's public key         |
| A 32-byte generic secret, AES-KW, both directions                                                                                                                                                               | same bytes                                                                                                                                           |
| p11-kit forwarding SoftHSM: mechanisms that can wrap                                                                                                                                                            | only `CKM_RSA_PKCS`, `CKM_RSA_PKCS_OAEP` and `CKM_DES_ECB`: AES-KW and AES-KW-PAD are dropped, so private keys have no `sealed` path through p11-kit |

Still [todo]: Edwards private keys (pkcs11-tool cannot unwrap `CKK_EC_EDWARDS`; phase 3 tests it
with cakeys' own unwrap), OAEP wrapping through p11-kit (pkcs11-tool failed to generate a key
pair through the client, which cakeys' own p11-kit suite does; phase 3), the `CKK_SHA*_HMAC` key
types (generic secrets work), and `CKA_WRAP_WITH_TRUSTED` per module (phase 3b).

### Phase 0 results (2026-11-12)

- The spike above, completed except the [todo] items, which move to the phases that build them.
- `nix/patches/cryptoki-aes-key-wrap-kwp.patch` adds `MechanismType::AES_KEY_WRAP_KWP` and
  `Mechanism::AesKeyWrapKwp` to cryptoki 0.12.1 (applied in `postPatch` like the HMAC fix; the
  constant was already in cryptoki-sys 0.5); upstream draft in
  `upstream/rust-cryptoki/PR-KWP.md`. Unlike the HMAC fix, it adds an enum variant, so a plain
  `cargo build` without the patch cannot name it: phase 3, the first code that wraps, either
  vendors the patched crate through `[patch.crates-io]` (if upstream has not released it by
  then) or keeps the method unavailable in unpatched builds.
- The names and formats below are frozen.

### Phase 1 results (2026-11-12)

The planner and `--dry-run`; nothing moves yet.

Since WORKPLAN stage 3 all of it is `camigrate`'s (docs/SCOPE.md, "Three tools"): the planner
(`plan()`, `Material`, `Allow`, `FileFormat`) is crates/camigrate/src/plan.rs, the transport file
crates/camigrate/src/transport.rs, what was `cakeys_pkcs11::migrate` crates/camigrate/src/tokens.rs,
the verbs `camigrate export`, `migrate` and `transport`, and the dry-run matrix
crates/camigrate/tests/dry_run.rs. `cakeys_core::migrate` keeps what the lock and the providers
name: the frozen `Exposure` and `Method` names with their pinning test, and the capability model
the `Provider::migration` hook returns. The bullets below name the places as built.

- `cakeys_core::migrate`: the frozen `Exposure` and `Method` names (pinned by a unit test), the
  capability model (`Side`, `Accept`, `PlaintextImport`, `VendorMethod`), and `plan()`, pure,
  with ten unit tests: sealed between the software references (SHA-1 OAEP with `SoftHSM`,
  SHA-256 between kryoptic tokens), exportability fixed at creation, public objects, the direct
  OAEP method without AES key wrap (p11-kit), host paths behind the flag and only for types the
  target takes, `CKA_WRAP_WITH_TRUSTED` (enforced with a trusted transport, else impossible, never
  through the host), files, and vendor methods at their declared level. The transport file
  (`Transport`) checks that its identity is the hash of its public key.
- `Provider::migration` (pkcs11): the generic PKCS#11 profile by default; `SoftHSM` OAEP SHA-1
  only; ykcs11 never exports and imports certificates and RSA 1024–4096, P-256/384 and Ed25519
  keys from plaintext; tpm2-pkcs11 never exports, imports EC P-256/384, RSA up to 3072 and the
  HMAC key types through `tpm2_ptool`, and certificates, data and RSA public keys. This is the
  hook vendor crates add their methods through (D10).
- `cakeys_pkcs11::migrate`: each side's capabilities from the open token, else from the lock
  (the recorded provider and observed mechanisms), else from a transport file; the source's
  objects from the lock; the transport key (`transport`), which must be an RSA private key that
  may unwrap, is not extractable, and verifies against the lock.
- CLI: `export [<object>] --token <t> (--target <t> | --transport <file> | --to-file pkcs8|pkcs12)`,
  `migrate [<object>] --from <a> --to <b>`, both with `--dry-run [--json]
  [--allow-host-plaintext]`, exit 15 when any object cannot move as invoked; without
  `--dry-run` they are refused (15) until phase 2. `transport <spec> --token <t> [--out <file>]`.
- Tests (`tests/references.rs`, every reference): the plan per target (sealed softhsm→kryoptic
  with SHA-1 and kryoptic→kryoptic with SHA-256, `tpm2-ptool` behind the flag with the residence
  note, `host-pkcs8` into p11-kit, `pkcs12` to a file, a non-extractable key refused, a mixed run
  is 15); the transport file carries the locked identity, an export plans from it alone, an
  edited one is refused (17), and only an RSA private key can be a transport key.

Not yet, carried to later phases: `import --dry-run` (it needs a bundle: phase 3), the planner
does not know whether a target's module supports a curve it has no list for (checked at import),
and a transport key proves possession only with `pop-decrypt` today (it needs `CKA_DECRYPT`,
hence the note recommending an unwrap-only key; an unwrap-based proof would remove that).

### Frozen names and formats

Exposure levels (D2): `public`, `enforced`, `sealed`, `host`, `file`; a plan that cannot move an
object says `impossible` with its reasons.

Methods (D4): `public`, `rsa-oaep-sha1+aes-kwp`, `rsa-oaep-sha256+aes-kwp`, `rsa-oaep-sha1`,
`rsa-oaep-sha256`, `host-pkcs8`, `host-raw`, `tpm2-ptool`, `piv-import`, `tpm-duplicate`,
`pkcs8-pbes2`, `pkcs12`, and `vendor:<provider>/<name>`. `host-pkcs8` and `host-raw` are the
host path into a PKCS#11 target (`C_CreateObject`); `tpm2-ptool` and `piv-import` are the host
path into those providers.

The transport file (`camigrate transport`, D3):

```toml
format = "cakeys-transport"
version = 1
token = "kryoptic"              # the target token's name in keys.toml
provider = "kryoptic"
object = "import-kek"           # the transport key's object, realised and locked on the target
rfc7093m4 = "sha256-..."        # its locked identity: SHA-256 of the canonical SPKI below
spki = "<base64 DER>"           # the public key the source wraps to
trusted = false                 # marked CKA_TRUSTED on the source (phase 3b)
mechanisms = ["CKM_AES_KEY_WRAP_KWP", "CKM_RSA_PKCS_OAEP"]   # the target's, for offline planning
```

The export bundle (`camigrate export`, D5), one per object:

```toml
format = "cakeys-export"
version = 1
object = "signing"
method = "rsa-oaep-sha1+aes-kwp"
exposure = "sealed"
commitmentLabel = "key-management/v1"   # secret keys, as in the lock
[type]                                  # as in the lock
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"
[ids]                                   # as in the source's lock; import must reproduce them
rfc7093m4 = "sha256-..."
[source]                                # provenance, as in the source realisation
token = "softhsm"
provider = "softhsm"
[transport]                             # the key the material is wrapped to
object = "import-kek"
rfc7093m4 = "sha256-..."
[wrapped]                               # base64; `value` instead for `public`
kek = "..."                             # the AES KEK under RSA-OAEP
key = "..."                             # the key under the KEK (RFC 5649)
```

The lock's target realisation (D7):

```toml
[realisations.<spec>.<token>.provenance.origin]
from = "softhsm"
method = "rsa-oaep-sha1+aes-kwp"
exposure = "sealed"
declared = true                         # only for a vendor method: its level as declared
```

## Decisions

**D1. Exportability is decided when a key is created.** A key with `CKA_EXTRACTABLE = false` can
never be exported, and `CKA_NEVER_EXTRACTABLE` is an immutable in the lock: once true, a key
that later claims otherwise was replaced. Every spec cakeys ships today declares
`CKA_EXTRACTABLE = false`, so none of those keys can move. A key meant to migrate must be
declared extractable from the start; `--dry-run` says this first, per object.

**D2. Exposure is named honestly, per object, strongest first.**

- `public`: certificates, public keys, public data objects. Nothing secret moves.
- `enforced`: `sealed`, and the source token itself allows no other wrapping: the key carries
  `CKA_WRAP_WITH_TRUSTED`, and the only wrapping keys the token accepts are ones its SO marked
  `CKA_TRUSTED` (the transport key, D3).
- `sealed`: the material leaves the source only wrapped under a key that lives on the target
  token, and is unwrapped there. The host never sees it. The default.
- `host`: the material is in plaintext in cakeys' memory, never on disk or the wire, and
  zeroized after. Needed wherever the target only imports plaintext (a YubiKey, `tpm2_ptool`,
  the TPM duplication format built on the host). Only with `--allow-host-plaintext`.
- `file`: the material leaves as a passphrase-protected file (PKCS#8 or PKCS#12, D4) for a target
  cakeys cannot reach. Plaintext-equivalent at rest, guarded only by the passphrase. Only with
  `--allow-host-plaintext` and a `--passphrase-file`.
- `impossible`: not extractable, a source that never exports, a key type the target lacks.

Why `enforced` is its own level: a key with only `CKA_EXTRACTABLE = true` can be wrapped by any
logged-in session under a key that session made, so `sealed` describes what cakeys does, not
what an attacker with the PIN could do. `CKA_WRAP_WITH_TRUSTED` is the one restriction the token
enforces (decided 2026-11-12: supported, phase 3b). It needs the SO on the source: the admin
credential (`mgmKeyFile`, today refused outside ykcs11) becomes allowed on PKCS#11 modules for
this step, which marks the transport key trusted on the source (`camigrate transport --trusted`).
How each module scopes `CKA_TRUSTED` to the key that wraps (the transport public key for direct
OAEP, the per-export KEK for the composed method) is [todo] per module.

**D3. The transport key is an ordinary locked object.** The target holds an RSA key pair
(`CKA_UNWRAP = true`, `CKA_DECRYPT = false`, non-extractable) declared in keys.toml like any
other key and realised there; its `rfc7093m4` is in the reviewed lock. The source wraps only to a
public key whose hash matches the locked identity, so the lock is the authenticated channel,
with no new trust mechanism. On a TPM target the transport key can also carry a `tpm-certify`
attestation (TPM residence of the unwrapping key).

`camigrate transport <spec> --token <target> --out <file>` writes what an offline export needs: the
public key, its identity, the target's provider and mechanisms. When both tokens are reachable
from one host, export reads that directly.

**D4. Methods have frozen names, like schemes.** The method is chosen from the source's export
capabilities intersected with the target's import capabilities. The target comes from
`--target <token>`, using its live mechanisms, else the lock's `observed.mechanisms` for that
token, else the transport file.

| Method | Material | How |
|---|---|---|
| `public` | certificates, public keys, data | the DER or value, then `C_CreateObject` |
| `rsa-oaep-sha1+aes-kwp`, `rsa-oaep-sha256+aes-kwp` | private and secret keys | a fresh AES KEK made on the source, wrapped to the transport key with RSA-OAEP; the key wrapped under the KEK with RFC 5649 (`AES_KEY_WRAP_PAD` or `_KWP`, whichever each side names); the KEK destroyed. `CKM_RSA_AES_KEY_WRAP` where offered |
| `rsa-oaep-sha1`, `rsa-oaep-sha256` | small secret keys (an AES key fits in one RSA block) | the key wrapped to the transport key directly: the path through p11-kit, whose RPC drops AES key wrap |
| `host-pkcs8`, `host-raw` | private keys, secret keys | the key wrapped to a session KEK cakeys made, unwrapped in memory: `host` exposure |
| `tpm2-ptool` | EC (not P-521), RSA, HMAC | `host-pkcs8`/`host-raw`, then `tpm2_ptool import` |
| `piv-import` | RSA, EC P-256/384, Ed25519 | `host-pkcs8`, then ykcs11 `C_CreateObject` as SO into the slot the locator names |
| `tpm-duplicate` | keys for a TPM target | a duplication blob built on the host to the target parent's public key (phase 6) |
| `pkcs8-pbes2` | private keys | `host-pkcs8`, written as an EncryptedPrivateKeyInfo (PBES2: PBKDF2-HMAC-SHA256 or scrypt, AES-256) under the passphrase: `file` exposure (decided 2026-11-12, phase 4b) |
| `pkcs12` | a private key with its certificate | `host-pkcs8` and the certificate, as a PKCS#12 file under the passphrase (what Java, Windows and cloud key vaults import): `file` exposure |
| `vendor:<provider>/<name>` | as the provider declares | a provider crate's own path (D10) |

The OAEP hash is the strongest both sides support: SHA-256 between kryoptic tokens, SHA-1 with
SoftHSM. Import also reads `pkcs8-pbes2` and `pkcs12` files (`host` exposure on the way in).
The method names are frozen once released, recorded in DESIGN §10.

**D5. The bundle is a new versioned file.** Export writes one TOML file per object, never
plaintext: the version, the object's type, IDs and commitment label (from the source lock), the
source's provenance, the method, the transport key's identity, and the wrapped blobs (base64).
RFC 5649 authenticates the key bytes, and import recomputes the identity on the target, so a
tampered or swapped blob fails either way. The bundle may cross untrusted channels.

**D6. Import is a realise that creates from a bundle.**

- It keeps If-None-Match: never into an occupied locator.
- It is the sanctioned exception to "`autoCreate` is refused when the lock already pins the
  material" (review finding D1, DESIGN §4.1): that refusal exists because generated material could not
  match, while imported material must.
- After creating, it realises and compares with the bundle's and the lock's IDs; a mismatch
  destroys what it created.
- ykcs11 cannot delete a key (its `C_DestroyObject` leaves it), so on `host` paths cakeys
  computes the identities from the plaintext *before* anything reaches the token, and refuses a
  mismatch there. For a YubiKey, that check is the only safety net.
- The target spec's attributes are the unwrap template, explicit and complete (kryoptic sets no
  usage otherwise), adjusted per provider (SoftHSM: no `CKA_VALUE_LEN`). A provider hook owns
  those rules.

**D7. The lock changes only on the target.** The target realisation gains
`provenance.origin = { from = "<token>", method = "<method>", exposure = "<level>" }` (D2; for a vendor
method, the level it declared):
provenance, so it never decides a verdict. The source's lock entry is unchanged: the lock
records state, not events. Lock v1 is still a draft, so this changes it in place; the
cross-version check (`scripts/xversion.sh`) must still re-record existing locks byte-identically.

**D8. Export and import are admin operations.** They are refused inside the Nix build sandbox,
like a lock write. A YubiKey import needs the admin credential (`mgmKeyFile`). It can never
carry an attestation, so `attestation = true` on that target is refused up front. A TPM import
attests residence, not generation (`CKA_LOCAL` is false, and the Name says so).

**D9. `--dry-run` is the real planner.** A planner turns (objects, source, target) into a
per-object plan: method, exposure, and the reasons for everything impossible. The real run
executes the same plan. `--dry-run` prints it as a table, or as JSON with `--json`, and exits 15
when anything is impossible. Because both share one code path, the main test is a property: for
every source, target and class in the reference matrix, the dry-run verdict equals the outcome.

**D10. Provider crates add their own methods, under a declared exposure.** A provider (the
quirks crate of a vendor HSM: Luna, CloudHSM, nShield, or a vendor's own tooling) can contribute
export and import methods next to the built-in ones, named `vendor:<provider>/<name>` and frozen
like the built-ins. Each declares the exposure level it achieves (D2), the classes and key types
it moves, and what it needs (mechanisms, a tool on `PATH`, the admin credential). The planner
treats them like built-ins, preferring the strongest exposure, and `--dry-run` lists them with
their declared level, marked as declared: cakeys cannot check a vendor's claim, so it records it
(`provenance.origin`) rather than vouching for it. What a vendor method never decides is the
identity: after any import, cakeys realises the object as usual, and the identity, its mode
(`direct`, `commitment`, …) and the binding come from that realise against the lock, exactly as
for a key that was never moved.

## Command line

```console
$ camigrate transport import-kek --token kryoptic --out kryoptic.transport.toml
$ camigrate export signing --token softhsm --target kryoptic [--transport kryoptic.transport.toml] \
    --out signing.export.toml [--dry-run] [--allow-host-plaintext]
$ camigrate import signing-kry --token kryoptic --in signing.export.toml [--dry-run] [--no-update-lock]
$ camigrate migrate signing --from softhsm --to kryoptic [--spec signing-kry] [--dry-run]
```

`migrate` is export plus import in one process when both tokens are reachable, with no bundle on
disk. `--dry-run` without objects plans every object the source token holds a realisation for.

## Phases

| Phase | Scope | Estimate |
|---|---|---|
| 0 | **Done 2026-11-12.** Finish the spike [todo items above]; cryptoki KWP patch and upstream PR draft; freeze method names, the bundle format and `origin` | 2–3 days |
| 1 | **Done 2026-11-12.** Planner and `--dry-run` (core: capabilities, method choice, reasons); the provider hook for import/export capabilities and vendor methods (D10); the transport file; no material moves. Useful alone: it answers "what could move, and how?" | ≈700 + 500 lines, 4–5 days |
| 2 | `public`: certificates, public keys, data objects | ≈200 + 200, 1–2 days |
| 3 | `sealed` between PKCS#11 modules: the `transport` verb, the composed RSA-OAEP + AES-KWP method, the direct OAEP method, bundles, import with identity check and cleanup, `migrate` | ≈800 + 700, 6–8 days |
| 3b | `enforced`: the admin credential on PKCS#11 modules, `transport --trusted`, `CKA_WRAP_WITH_TRUSTED` keys | ≈300 + 250, 3–4 days |
| 4 | `host` paths: `--allow-host-plaintext`, zeroized buffers, and tpm2-pkcs11 import through `tpm2_ptool` (a runtime dependency for that provider) | ≈350 + 300, 3–4 days |
| 4b | `file`: `pkcs8-pbes2` and `pkcs12` export and import, `--passphrase-file` | ≈300 + 250, 3–4 days |
| 5 | YubiKey import through ykcs11 as SO, identities checked on the host first; the hardware test overwrites scratch slot 0x95 (ask before running) | ≈250 + 200, 2–3 days |
| 6 | Native `tpm-duplicate`: a host-built duplication blob, `TPM2_Import` through tss-esapi | ≈600 + 400, 6–10 days |
| 7 | Vendor methods (D10) for Luna, CloudHSM, nShield and others, in their provider crates, over their mechanisms and tools | with hardware |

## Tests

- **The dry-run property** (D9), over the reference matrix in `tests/references.rs`: SoftHSM,
  kryoptic (raw and DER points), p11-kit and tpm2-pkcs11 as sources and targets, every class.
  The plan's verdict equals the outcome.
- **Identity continuity**: every successful import realises into the source's lock with the same
  IDs; the cross-reference tests already compare them.
- **Refusals**: non-extractable keys, a source that never exports, a target missing the curve
  (kryoptic: secp256k1) or the mechanism (p11-kit: AES key wrap), `host` paths without the flag,
  an occupied locator, a transport key whose public key does not match the lock, a tampered
  bundle, `attestation = true` on a YubiKey import.
- **Cleanup**: a failed import leaves nothing behind (and, on a YubiKey, writes nothing).
- **Formats**: a property test and a fuzz target for the bundle parser; known-answer tests pin the
  method encodings, like `scheme_definitions_are_pinned`.
- **Vendor methods**: a test provider declares a method; `--dry-run` lists it under its declared
  level, the run uses it, and the realise after import alone decides the identity.
- **Hardware**: an opt-in YubiKey import into slot 0x95 (`tests/yubikey.rs`).

## Open questions

Decided 2026-11-12: `CKA_WRAP_WITH_TRUSTED` is supported (D2, phase 3b), and export offers
passphrase-protected PKCS#8 and PKCS#12 files (D4, phase 4b).

1. Batch behaviour: one bundle per object, or one per run? (Per object keeps the identity check
   per object, and partial failures simple.)
2. Does a migrated key keep its object name on the target? (Yes, if it is the same material:
   that is the lock's model. A different object name would be different material.)
