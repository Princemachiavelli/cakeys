# Export and import (plan, 2026-11-12)

Native `export` and `import` for every backend: move key material from one token to another,
with token-to-token key wrapping where both sides support it and vendor tooling where they do
not; a `--dry-run` that says what can and cannot move, and how; and an export that is shaped for
its intended target. cakeys already *verifies* a copy (realise on the second token against the
locked IDs, [`docs/USE_CASE.md`](docs/USE_CASE.md)); this plan makes it *make* the copy.

Evidence tags on every backend claim: **[run]** verified by running it (the spike below),
**[src]** read in the module's source, **[todo]** still to verify.

## How complex

About **4k lines** (≈2.2k production, ≈1.8k tests) and **3½–5 weeks** for one person, for
phases 0–5 below: dry-run, public objects, token-to-token wrapping between PKCS#11 modules,
plaintext-through-host imports into tpm2-pkcs11 and a YubiKey. That is +45% on today's ≈5k
production lines. The native TPM duplication format (phase 6) is another ≈1k lines and 1½–2
weeks, and the riskiest piece; vendor HSMs (phase 7) wait for hardware.

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

| Path | Result |
|---|---|
| AES-KW, both directions, a 32-byte AES key | same bytes after unwrap |
| SoftHSM AES-KW-PAD (0x210A) ↔ kryoptic AES-KWP (0x210B), both directions, 20- and 32-byte secrets | same bytes: one format (RFC 5649), two mechanism IDs |
| EC P-256 private key (the `tpm-import-p256` fixture) wrapped with PAD/KWP, both directions | the unwrapped key signs a message that verifies against the fixture's public key |
| RSA-OAEP (SHA-1, MGF1-SHA1) carrying a 32-byte KEK to an RSA-3072 key on the other token, both directions | same bytes |
| RSA-OAEP SHA-256 | kryoptic ↔ kryoptic only; SoftHSM refuses it |
| Unwrap templates | SoftHSM refuses `CKA_VALUE_LEN` (`CKR_ATTRIBUTE_READ_ONLY`); kryoptic sets no `CKA_SIGN` on an unwrapped private key unless the template does |

Not covered yet [todo]: RSA and Edwards private keys, HMAC key types, p11-kit, and the
composed two-step wrap end to end (both halves work separately).

## Decisions

**D1. Exportability is decided when a key is created.** A key with `CKA_EXTRACTABLE = false` can
never be exported, and `CKA_NEVER_EXTRACTABLE` is an immutable in the lock: once true, a key
that later claims otherwise was replaced. Every spec cakeys ships today declares
`CKA_EXTRACTABLE = false`, so none of those keys can move. A key meant to migrate must be
declared extractable from the start; `--dry-run` says this first, per object.

**D2. Exposure is named honestly, per object, in four levels.**

- `public`: certificates, public keys, public data objects. Nothing secret moves.
- `sealed`: the material leaves the source only wrapped under a key that lives on the target
  token, and is unwrapped there. The host never sees it. This is the default and the goal.
- `host`: the material is in plaintext in cakeys' memory, never on disk or the wire, and
  zeroized after. Needed wherever the target only imports plaintext (a YubiKey, `tpm2_ptool`,
  the TPM duplication format built on the host). Only with `--allow-host-plaintext`.
- `impossible`: not extractable, a source that never exports, a key type the target lacks.

What the token enforces is weaker than "sealed" suggests: a key with `CKA_EXTRACTABLE = true` can
be wrapped by any logged-in session under a key that session made, so "sealed" describes what
cakeys does, not what an attacker with the PIN could do. The one token-enforced restriction is
`CKA_WRAP_WITH_TRUSTED`, with a transport key the SO marked `CKA_TRUSTED`. Supporting it needs the
SO credential on PKCS#11 modules other than ykcs11 (today `mgmKeyFile` is refused there): its own
phase if wanted (open question 1).

**D3. The transport key is an ordinary locked object.** The target holds an RSA key pair
(`CKA_UNWRAP = true`, `CKA_DECRYPT = false`, non-extractable) declared in keys.toml like any
other key and realised there; its `rfc7093m4` is in the reviewed lock. The source wraps only to a
public key whose hash matches the locked identity, so the lock is the authenticated channel,
with no new trust mechanism. On a TPM target the transport key can also carry a `tpm-certify`
attestation (TPM residence of the unwrapping key).

`cakeys transport <spec> --token <target> --out <file>` writes what an offline export needs: the
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

The OAEP hash is the strongest both sides support: SHA-256 between kryoptic tokens, SHA-1 with
SoftHSM. The method names are frozen once released, recorded in DESIGN §10.

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
`provenance.origin = { from = "<token>", method = "<method>", exposure = "sealed" | "host" }`:
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

## Command line

```console
$ cakeys transport import-kek --token kryoptic --out kryoptic.transport.toml
$ cakeys export signing --token softhsm --target kryoptic [--transport kryoptic.transport.toml] \
    --out signing.export.toml [--dry-run] [--allow-host-plaintext]
$ cakeys import signing-kry --token kryoptic --in signing.export.toml [--dry-run] [--no-update-lock]
$ cakeys migrate signing --from softhsm --to kryoptic [--spec signing-kry] [--dry-run]
```

`migrate` is export plus import in one process when both tokens are reachable, with no bundle on
disk. `--dry-run` without objects plans every object the source token holds a realisation for.

## Phases

| Phase | Scope | Estimate |
|---|---|---|
| 0 | Finish the spike [todo items above]; cryptoki KWP patch and upstream PR draft; freeze method names, the bundle format and `origin` | 2–3 days |
| 1 | Planner and `--dry-run` (core: capabilities, method choice, reasons); the transport file; no material moves. Useful alone: it answers "what could move, and how?" | ≈600 + 400 lines, 4–5 days |
| 2 | `public`: certificates, public keys, data objects | ≈200 + 200, 1–2 days |
| 3 | `sealed` between PKCS#11 modules: the `transport` verb, the composed RSA-OAEP + AES-KWP method, the direct OAEP method, bundles, import with identity check and cleanup, `migrate` | ≈800 + 700, 6–8 days |
| 4 | `host` paths: `--allow-host-plaintext`, zeroized buffers, and tpm2-pkcs11 import through `tpm2_ptool` (a runtime dependency for that provider) | ≈350 + 300, 3–4 days |
| 5 | YubiKey import through ykcs11 as SO, identities checked on the host first; the hardware test overwrites scratch slot 0x95 (ask before running) | ≈250 + 200, 2–3 days |
| 6 | Native `tpm-duplicate`: a host-built duplication blob, `TPM2_Import` through tss-esapi | ≈600 + 400, 6–10 days |
| 7 | Vendor HSM providers (Luna, CloudHSM, nShield): provider hooks over their mechanisms and tools | design only until hardware |

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
- **Hardware**: an opt-in YubiKey import into slot 0x95 (`tests/yubikey.rs`).

## Open questions

1. `CKA_WRAP_WITH_TRUSTED`: worth the SO-credential work on PKCS#11 modules, so "sealed" becomes
   token-enforced? (D2)
2. Should export also offer a passphrase-protected PKCS#8 or PKCS#12 file, for targets cakeys
   cannot reach? This is a plaintext-equivalent at rest; probably not by default.
3. Batch behaviour: one bundle per object, or one per run? (Per object keeps the identity check
   per object, and partial failures simple.)
4. Does a migrated key keep its object name on the target? (Yes, if it is the same material:
   that is the lock's model. A different object name would be different material.)
