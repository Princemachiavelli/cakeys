# camigrate: moving keys between tokens

`camigrate` moves key material from one token to another: token-to-token key wrapping where
both modules support it, the host or a passphrase-protected file where they do not, and a
`--dry-run` that says per object what can move and how. It is the only tool that handles key
material; a `cakeys` build carries no migration code. `cakeys` *verifies* a copy (realise on the
second token against the locked IDs); `camigrate` *makes* it, then records it through the same
realise code path.

Evidence tags on backend claims: **[run]** verified by running it, **[src]** read in the
module's source, **[todo]** still to verify.

## Command line

```console
$ camigrate transport <spec> --token <target> [--out <file>]       # the transport key's public half, for offline exports
$ camigrate transport <spec> --token <target> --trusted <source>   # the source's SO trusts it (enforced)
$ camigrate export [<object> ...] --token <source> (--target <t> | --transport <file>) \
    [--transport-key <spec>] --out <bundle> [--dry-run [--json]] [--allow-host-plaintext]
$ camigrate export <object> --token <source> --to-file pkcs8|pkcs12 --out <file> \
    --passphrase-file <file> --allow-host-plaintext
$ camigrate import --token <target> --in <bundle|file> [--spec <s> ...] [--dry-run] \
    [--passphrase-file <file> --allow-host-plaintext]
$ camigrate migrate [<object> ...] --from <a> --to <b> [--spec <s>] [--transport-key <spec>] \
    [--dry-run [--json]] [--allow-host-plaintext]
```

- `migrate` is export then import in one process, the bundle in memory, when both tokens are
  reachable from this host. Without objects it plans every object the source holds a
  realisation of.
- `--dry-run` prints the plan (a table, or JSON) and changes nothing. The real run executes the
  same plan (D9).
- Every writing verb is refused inside a Nix build (D8). The lock is written under `cakeys`'
  rules (the `.lck` sidecar lock, written whole or not at all).

Exit codes (the table: [CAKEYS.md](CAKEYS.md#exit-codes)): 0 done; 10 the material's identity
differs from the lock (also a wrong passphrase); 13 the target refused (a tampered bundle, a
failed proof of possession, an occupied PIV slot); 14 the lock pins no IDs for the object; 15
an object cannot move as invoked, or the target lacks a capability; 17 invalid input (keys.toml,
a transport file, a bundle, another key's IDs).

## Decisions

**D1. Exportability is decided when a key is created.** A key with `CKA_EXTRACTABLE = false`
never moves, and `CKA_NEVER_EXTRACTABLE` is an immutable in the lock: once true, a key that
later claims otherwise was replaced. A key meant to migrate is declared extractable from the
start, on its one creation token (`createOn`); `--dry-run` says this first, per object.

**D2. Exposure is named honestly, per object, strongest first.** The names are frozen.

| Exposure | What it means |
|---|---|
| `public` | Certificates, public keys, public data objects. Nothing secret moves. |
| `enforced` | `sealed`, and the source token allows no other wrapping: the key carries `CKA_WRAP_WITH_TRUSTED`, and the only wrapping key the source trusts is the target's transport key (D3). |
| `sealed` | The material leaves the source only wrapped under a key that lives on the target, and is unwrapped there. The host never sees it. The default. |
| `host` | Plaintext in camigrate's memory, never on disk or the wire, zeroized after. Wherever the target imports only plaintext (a YubiKey, `tpm2_ptool`). Only with `--allow-host-plaintext`, and only within `migrate`. |
| `file` | A passphrase-protected file (PKCS#8 or PKCS#12) for a target camigrate cannot reach. Plaintext-equivalent at rest. Only with `--allow-host-plaintext` and `--passphrase-file`. |
| `impossible` | Not extractable, a source that never exports, a type or proof the target lacks. The plan gives the reasons. |

`enforced` is its own level because a key with only `CKA_EXTRACTABLE = true` can be wrapped by
any logged-in session under a key that session made: `sealed` describes what camigrate does,
not what someone holding the PIN could do. `CKA_WRAP_WITH_TRUSTED` is the restriction the token
itself enforces. It needs the source's SO once per transport key (`transport --trusted`, with
the admin credential `mgmKeyFile`/`mgmKeyEnv`, read only by SO steps).

**D3. The transport key is an ordinary locked object.** The target holds an RSA key pair
(`CKA_UNWRAP = true`, non-extractable) declared in keys.toml like any other key and named by the
target token's `transportWith`. Nothing is picked by what a key can do; `--transport-key`
overrides it per run. Its `rfc7093m4` is in the reviewed lock, and the source wraps only to a
public key that hashes to it: the lock is the authenticated channel.

- **The lock records its public key** (`objects.<name>.publicKey`, base64 SPKI) when it is
  realised as a `transportWith` key, held to its `rfc7093m4` on load. Any host can then plan and
  export to that token from the lock alone. A target with no recorded public key is planned as
  blocked.
- **It proves possession by unwrapping** (`binding = "pop-unwrap"`), so it needs no
  `CKA_DECRYPT`. SoftHSM and kryoptic do it [run]; tpm2-pkcs11 and ykcs11 never unwrap, so it is
  refused there (15) before anything is generated [run]. A transport key that also decrypts is
  warned about: the target's PIN holder could `C_Decrypt` a bundle's key-encryption key. (That
  PIN holder can extract an extractable moved key anyway; sealed protects the material on the
  way, not from the target.)
- A transport file (`transport --out`) is used only when the source's lock pins its key; one that
  is merely self-consistent is refused (17). Whether a source *trusts* the key is looked up on
  the source, never claimed by the file.
- **[todo] `CKA_UNWRAP_TEMPLATE`.** A template forcing non-extractable on what the transport key
  unwraps would keep even the PIN holder from reading the key-encryption key. cryptoki 0.12 can
  neither read nor set array attributes, and a strict template would break the direct-OAEP path
  (OPEN.md).

**D4. Methods have frozen names, like schemes.** The method is the source's export capabilities
intersected with the target's import capabilities: the target's live mechanisms, else the lock's
observed mechanisms for it, else a transport file. The OAEP hash is the strongest both support
(SHA-256 between kryoptic tokens, SHA-1 with SoftHSM).

| Method | Material | How |
|---|---|---|
| `public` | certificates, public keys, data | the bytes, then `C_CreateObject` |
| `rsa-oaep-sha1+aes-kwp`, `rsa-oaep-sha256+aes-kwp` | private and secret keys | a fresh AES-256 KEK on the source, wrapped to the transport key with RSA-OAEP; the key wrapped under it with RFC 5649 (`AES_KEY_WRAP_PAD` or `_KWP`, whichever each side names). `CKM_RSA_AES_KEY_WRAP` does both for `enforced` |
| `rsa-oaep-sha1`, `rsa-oaep-sha256` | small secret keys | the key wrapped to the transport key directly: the path through p11-kit, whose RPC drops AES key wrap |
| `host-pkcs8`, `host-raw` | private, secret keys | extracted through the host (a session KEK camigrate made), then `C_CreateObject`: `host` |
| `tpm2-ptool` | EC (not P-521), RSA, HMAC | the host path, then `tpm2_ptool import` |
| `piv-import` | RSA, EC P-256/384, Ed25519 | the host path, then ykcs11 `C_CreateObject` as SO into the slot the locator names |
| `pkcs8-pbes2` | private keys | the host path, written as an EncryptedPrivateKeyInfo: `file` |
| `pkcs12` | a private key and its certificate | the host path, written as PKCS#12: `file` |
| `tpm-duplicate` | keys for a TPM target | not built: a duplication blob built on the host to the target parent's public key |
| `vendor:<provider>/<name>` | as the provider declares | a provider crate's own path (D10) |

**D5. The bundle is a versioned file, one per export** (a source and a target), never
plaintext. RFC 5649 authenticates the key bytes and import recomputes every identity on the
target, so a tampered or swapped blob fails either way, and the bundle may cross untrusted
channels. A wrapped private key is the PKCS#8 `C_WrapKey` emits; PKCS#12 or a CMS key package
would need the plaintext on the host, which sealed avoids. Named objects export all or nothing;
without names, export takes what can move and warns about the rest (a spec's `noExport = true`
keeps its object home and silences the warning). Import takes each entry on its own, reports
every failure, and exits with the first.

**D6. Import is a realise that creates from a bundle.**

- If-None-Match per class: never over an object of its class under the locator. A key, its
  public key and its certificate share one `CKA_ID` by PKCS#11 convention, so they move into one
  locator in any order; a public key object already holding the key's public key is reused,
  never duplicated. `autoCreate` still refuses over anything under the locator.
- It is the sanctioned exception to "`autoCreate` is refused when the lock already pins the
  material": generated material could not match, imported material must.
- After creating, it realises and compares with the bundle's and the lock's IDs; a mismatch
  removes exactly what it created. On every `host` path the identity is checked on the host
  first (10 before anything is written): ykcs11 cannot erase a key, so for a YubiKey that check
  is the only safety net.
- The target spec's attributes are the unwrap template, explicit and complete (kryoptic sets no
  usage otherwise), less what the profile's `unwrap.refuse` lists (SoftHSM: `CKA_VALUE_LEN`).

**D7. The lock changes only on the target.** The target realisation gains
`provenance.origin = { from, method, exposure }` (`declared = true` for a vendor method):
provenance, never a verdict. The source's entry is unchanged: the lock records state, not
events.

**D8. Export and import are admin operations.** Refused inside the Nix build sandbox, like a
lock write. A YubiKey import needs the admin credential and can never carry an attestation, so
`attestation = true` on that target is refused at planning. A TPM import attests residence, not
generation (`CKA_LOCAL` is false).

**D9. `--dry-run` is the real planner.** One code path turns (objects, source, target) into a
per-object plan: method, exposure, and the reasons for everything impossible. The plan also
blocks what the target could not prove afterwards (its spec's binding needs a mechanism the
target lacks, e.g. Ed25519 through p11-kit). The main test is a property: for every source,
target and class in the reference matrix, the dry-run verdict is the outcome.

**D10. Provider crates add their own methods, under a declared exposure.** A vendor provider
(Luna, CloudHSM, nShield, a vendor tool) contributes methods named `vendor:<provider>/<name>`,
frozen like the built-ins, each declaring its exposure, the types it moves and what it needs.
The planner prefers the strongest exposure; `--dry-run` marks a vendor level as declared, and
the lock records it as declared, since camigrate cannot check it. The identity is never the
vendor's: after any import camigrate realises the object as for a key that never moved.

## Frozen names and formats

The transport file (`camigrate transport --out`, D3):

```toml
format = "cakeys-transport"
version = 1
token = "kryoptic"              # the target token's name in keys.toml
provider = "kryoptic"
object = "import-kek"           # the transport key's object, realised and locked on the target
rfc7093m4 = "sha256-..."        # its locked identity: SHA-256 of the canonical SPKI below
spki = "<base64 DER>"           # the public key the source wraps to
mechanisms = ["CKM_AES_KEY_WRAP_KWP", "CKM_RSA_PKCS_OAEP"]   # the target's, for offline planning
```

The export bundle (D5):

```toml
format = "cakeys-export"
version = 1
kek = "..."                             # the AES KEK under RSA-OAEP, shared by the sealed keys; absent if none
[source]                                # provenance, as in the source realisation
token = "softhsm"
provider = "softhsm"
[transport]                             # the key the material is wrapped to
object = "import-kek"
rfc7093m4 = "sha256-..."
[[keys]]                                # one per key, each object once
object = "signing"
method = "rsa-oaep-sha1+aes-kwp"
exposure = "sealed"
commitmentLabel = "key-management/v1"   # secret keys, as in the lock
publicKey = "<base64 SPKI DER>"         # private keys: the public half the target creates; its hash is ids.rfc7093m4
# kek = "..."                           # an `enforced` key's own KEK (CKM_RSA_AES_KEY_WRAP's first part)
wrapped = "..."                         # base64: the key under the KEK (RFC 5649), or under RSA-OAEP directly
[keys.type]                             # as in the lock
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"
[keys.ids]                              # as in the source's lock; import must reproduce them
rfc7093m4 = "sha256-..."
[[keys]]                                # a public object travels as it is
object = "signing-cert"
method = "public"
exposure = "public"
value = "..."                           # base64: a certificate's DER, a public key's SPKI, a data object's value
[keys.type]
class = "CKO_CERTIFICATE"
certificateType = "CKC_X_509"
[keys.ids]
rfc7093m4 = "sha256-..."
```

Key files: `pkcs8-pbes2` is a PEM `ENCRYPTED PRIVATE KEY` (PBES2, PBKDF2-HMAC-SHA256 with 600 000
iterations, AES-256-CBC). `pkcs12` holds the same encrypted key in a shrouded key bag beside the
certificate the lock pairs with the object, both tagged with one `localKeyId`, under an
HMAC-SHA256 MAC (PKCS#12 KDF, 10 000 iterations). One key per file, mode 0600. An imported file
names no object: the key's `rfc7093m4` finds the locked private key.

The lock's target realisation (D7):

```toml
[realisations.<spec>.<token>.provenance.origin]
from = "softhsm"
method = "rsa-oaep-sha1+aes-kwp"
exposure = "sealed"
declared = true                         # only for a vendor method: its level as declared
```

## What the backends can do

| Backend | Export (source) | Import (target) |
|---|---|---|
| SoftHSM 2.7 | `C_WrapKey`: AES-KW, AES-KW-PAD (RFC 5649), RSA-OAEP SHA-1 only [run]; `CKM_RSA_AES_KEY_WRAP`, and the SO can create a trusted RSA public key [run] | `C_UnwrapKey` [run], but an unwrapped secret key's `CKA_VALUE_LEN` reads 0 and is refused in the template [src], so sealed secret keys into SoftHSM are blocked (`secret-unwraps = false`); `C_CreateObject` [run] |
| kryoptic 1.5.4 | `C_WrapKey`: AES-KW, AES-KWP, AES-GCM, RSA-OAEP SHA-1 and SHA-256 [run]; cannot make an RSA public key trusted, so never an `enforced` source (`trusted-wrap = false`) [run] | `C_UnwrapKey` (sets no usage unless the template asks) [run]; `C_CreateObject` [run] |
| p11-kit | what the module behind offers, minus what the RPC drops: AES-KW, AES-KW-PAD, `CKM_RSA_AES_KEY_WRAP`, `CKM_EDDSA` [run] | the same limits; the module behind is unknown until keys.toml names its `provider` (the plan warns) |
| tpm2-pkcs11 1.10 | never: no `C_WrapKey`/`C_UnwrapKey` [src] | `tpm2_ptool import` of EC (not P-521), RSA and HMAC keys [run]; data objects only private [src] |
| YubiKey PIV (ykcs11 2.7) | never [src] | `C_CreateObject` as SO of RSA 1024–4096, EC P-256/384, Ed25519 and certificates [src, run]; no public key objects; imported keys are never attested |
| Vendor HSMs | vendor mechanisms and tools [todo] | likewise [todo] |

## Results

All phases ran on 2026-11-12 (0, 1) and 2026-11-14 (2–5); the test names are in
`crates/camigrate/tests/`.

| Phase | Built | Found or decided |
|---|---|---|
| 0 | The spike (pkcs11-tool, SoftHSM ↔ kryoptic) and the cryptoki KWP patch (`nix/patches/cryptoki-aes-key-wrap-kwp.patch`, upstream draft `upstream/rust-cryptoki/PR-KWP.md`) | SoftHSM's AES-KW-PAD and kryoptic's AES-KWP are one format (RFC 5649) under two IDs; EC and RSA keys wrapped either way still sign for their fixtures; the composed method works both ways [run] |
| 1 | The planner and `--dry-run`; `Provider::migration`, the capability hook vendor crates use (D10); the transport file | — |
| 2 | `public` moves (`public.rs`), recorded through `ops::realise_import` | tpm2-pkcs11 creates data objects only private, so its profiles no longer accept public `CKO_DATA` |
| 3 | `sealed` (`sealed.rs`): bundles, `export --out`, `import`, `migrate`; one creation token per object (`createOn`); `transportWith` and `pop-unwrap` | SoftHSM's unwrapped `CKA_VALUE_LEN` (`secret-unwraps = false`); p11-kit needs its `provider` named (the layer's `requires-provider`) |
| 3b | `enforced`: `transport --trusted`, `CKM_RSA_AES_KEY_WRAP` (third cryptoki patch, `nix/patches/cryptoki-rsa-aes-key-wrap.patch`), the bundle's per-entry `kek` | both modules refuse a wrap-with-trusted key under an untrusted key; `CKA_TRUSTED` is set only at creation and only by the SO; kryoptic cannot trust an RSA public key [run: one-off PyKCS11 and Rust test programs, not kept, recorded in the profiles' `[manual."trusted-wrap"]`] |
| 4 | `host` (`host.rs`): `Token::extract`, `cakeys_core::plaintext`, `tpm2-ptool` through an in-memory file (`/proc/<pid>/fd/N`, since `tpm2_import` inherits no descriptor) | the key enters `tpm2_ptool`'s Python process, and its user PIN is on that process's command line (no other option [src]): both stated as plan notes. The planner blocks moves the target could not prove (Ed25519 into p11-kit) |
| 4b | `file` (`file.rs`): `pkcs8-pbes2` and `pkcs12` export and import; `pkcs5`, `pkcs12` 0.2 and `cms` 0.3 (release candidates, same RustCrypto line as `der` 0.8) | a wrong passphrase is 10 and leaves nothing |
| 5 | `piv-import`, as SO, the identity checked on the host first | YubiKey 5C NFC FIPS 5.7.4, ykcs11 2.7.3 (`tests/yubikey.rs`, opt-in): a P-256 key from SoftHSM moved into retired slot 95 and proved possession; a second import into the occupied slot was refused (13) before anything was written. The slot was emptied by hand beforehand (no delete in ykcs11) |

Not built: phase 6, native `tpm-duplicate` (a host-built duplication blob, `TPM2_Import` through
tss-esapi), and phase 7, vendor methods, which wait for hardware. Both are in [OPEN.md](OPEN.md).

## Tests

- **The dry-run property** (D9), over the reference matrix: SoftHSM, kryoptic, p11-kit and
  swtpm/tpm2-pkcs11 as sources and targets, every class and the key types each takes. A ready
  move exits 0, records its `origin`, and `cakeys verify` accepts it on the target with its proof
  of possession; a blocked one is 15 with nothing changed.
- **Refusals**, each with its pinned exit code: non-extractable keys, a source that never
  exports, a target missing a curve or mechanism, host paths without the flag, an occupied
  locator, a transport key the lock does not pin, tampered or swapped blobs, another key's IDs,
  `attestation = true` on a YubiKey import, a wrong passphrase.
- **Cleanup**: a failed import leaves nothing behind.
- **Formats**: unit, property and fuzz tests for the bundle parser; round trips of both key file
  formats.
