# keys.toml, explained

`keys.toml` is what you write: which tokens exist, what key material you expect, and what each
use of that material must look like. cakeys never writes it. What cakeys *observes* goes into
`keys.lock` ([`LOCK.md`](LOCK.md)). The normative reference is [`DESIGN.md`](DESIGN.md) §4.1;
this page explains the same thing by example.

## Three kinds of table, and why they are separate

| Table | Answers | Example |
|---|---|---|
| `[tokens.<name>]` | *Where* is a token, and how do I log in? | a module path, a token label, a PIN file |
| `[objects.<name>]` | *What* is the material: its class and intrinsic type | an EC P-256 private key |
| `[specs.<name>]` | *How* is the material used: the policy one use requires, and where to find it on each token | "this key, sign-only, non-extractable, under label `signing` on token `softhsm`" |

They are separate because they change independently, and each change means something different:

- **The object is the material.** Its type (class, key type, curve, size) is intrinsic: a P-256
  key cannot become a P-384 key. The object's name is an internal handle; it is never written
  to a token. The lock pins the object's identity (a hash of the material), so changing its
  type is refused: different material needs a new object name.
- **A spec is policy about an object.** Several specs may share one object, for example the same
  key used sign-only by one service and sign-and-decrypt by another. Changing a spec's policy
  is a reviewable change (the lock records a digest of it), not new material.
- **The locator is where, not what.** `CKA_LABEL` and `CKA_ID` are names a token holds; they can
  be changed or reused, so they only *find* an object. The identity is the hash. That is why the
  locator lives in the spec's per-token entry, not in the object.
- **A token is just how to reach it.** Moving a token's module path or PIN file changes nothing
  about the keys on it.

## An annotated example

Valid as it stands (`cakeys validate` accepts it with `TPM_PIN_FILE` set); every comment explains
the line below it or to its left. Not every key is shown for every table, only one of each kind
plus the less obvious ones.

```toml
# ── Tokens ──────────────────────────────────────────────────────────────────────────────

[tokens.softhsm]
# The PKCS#11 module, which is per machine: a path; "$NAME"/"${NAME}", read from the environment
# when the token is opened; or left out and given per run with `--module softhsm=<path>` (what
# lib.mkKeys's `modules.softhsm` passes in a Nix build; it also replaces a configured one). A bare
# file name is the dynamic loader's search (LD_LIBRARY_PATH; on NixOS nothing else). The lock
# records the file actually loaded and its hash, as provenance only.
module = "/run/current-system/sw/lib/softhsm/libsofthsm2.so"
# Which token of the module: matched against C_GetTokenInfo's label.
tokenLabel = "main"
# The user PIN, read from a file (or `pinEnv = "VAR"`: the PIN itself from the environment).
# Without a PIN cakeys opens a public session and sees only public objects.
pinFile = "/var/lib/softhsm/pin"
# Marks the token expendable for `caprobe probe --write` (docs/PROVIDERS.md): its write probes
# generate, wrap, unwrap and destroy objects, so they run only on a token marked scratch and
# are refused (17) on any other. No other verb reads it. Never on a token holding real keys:
# scratch = true

[tokens.tpm]
module = "/run/current-system/sw/lib/libtpm2_pkcs11.so"
tokenLabel = "host"
# `$NAME` or `${NAME}` takes the path from the environment, so one keys.toml can serve machines
# with different paths. An unset variable is refused when the file loads (17), not at login.
pinFile = "$TPM_PIN_FILE"
# Optional: the provider (the module's quirks profile, DESIGN §6.2) is normally detected from
# C_GetInfo; naming it is needed behind p11-kit, which hides the module behind it.
provider = "tpm2-pkcs11"
# Delta capability layers between cakeys and the token (docs/PROVIDERS.md), by name or family:
# hand-maintained facts factored out of an observed profile (swtpm's RSA cap), or anything else
# the stack applies. The module profile itself — what this module does on this kind of
# hardware — is chosen from C_GetInfo and C_GetTokenInfo, not named here. The cryptoki binding
# layer is always applied (and heals itself when its fix is in); p11-kit is detected from the
# module. Unknown names refuse (17). This token is a real TPM, so not swtpm's:
# profiles = ["swtpm"]
# The Nix library's feature name for builds that need this token (default "token-<name>").
systemFeature = "token-tpm"

# The provider's own settings. Each provider checks its own; one that takes none refuses any
# (17). tpm2-pkcs11's (`tcti`, `tpm2Store`, `akHandle`) serve its native TPM2_Certify
# attestation path (§3.7).
[tokens.tpm.options]
tcti = "device:/dev/tpmrm0"
akHandle = "0x81000016"

[tokens.yubikey]
tokenLabel = "YubiKey PIV #39189318"
pinFile = "/run/secrets/piv-pin"
# The admin (SO) credential, for modules that create keys only as SO (ykcs11: the PIV
# management key in hex, or the PIN when the management key is PIN-protected). Read only to
# create or delete, and only where the provider needs it; refused elsewhere (17). The hex
# management key logs in without a PIN verification, so it spends no PIN retry; the PIN does.
mgmKeyFile = "/run/secrets/piv-mgm"
# A device like this holds real keys beside expendable ones, so `scratch` cannot mark it. For a
# module that creates only as SO into slots named by CKA_ID (ykcs11), `scratchId` names the one
# slot `probe --write` may overwrite (hex CKA_ID: 17 is retired slot 94). Each probe generation
# replaces the slot's key and the last one stays (PIV cannot erase a key). The probe refuses a
# slot holding anything but ykcs11's own placeholder from an earlier generation (17), so a typo
# never reaches a real key. No other verb reads it.
# scratchId = "17"

# ── Objects: the material ───────────────────────────────────────────────────────────────

[objects.signing]
# The PKCS#11 class: CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY, CKO_CERTIFICATE, CKO_DATA.
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
# Canonicalized on load: "P-256" and "prime256v1" are the same type as "secp256r1".
curve = "secp256r1"
# Where the key is born, when its specs name several tokens: `create` and `autoCreate` generate
# it only on this token, and the others get the same material by import (`camigrate migrate`).
# Only this token may set `autoCreate` (17 otherwise); without `createOn`, at most one token
# may. Not part of the type: the lock and the spec digest never see it.
createOn = "softhsm"

[objects.agreement]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp384r1"

[objects.backup-kek]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
# Bytes. Part of the type, and of the commitment label a secret key's identity is computed on.
valueLen = 32

[objects.firmware-cert]
class = "CKO_CERTIFICATE"
# Certificates take a certificate type instead of a key type.
certificateType = "CKC_X_509"

[objects.release-note]
# A public data object: identified by the SHA-256 of its value (the same hash as a Nix flat
# fixed-output derivation of the content).
class = "CKO_DATA"

# ── Specs: one use of an object, and where it lives on each token ──────────────────────

[specs.signing-soft]
object = "signing"
# The policy this use requires: boolean CKA_* attributes the class may carry (a wrong name or
# class is 17). The token must show exactly these; everything else it shows is recorded in the
# lock, and later drift is reported.
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
# Private keys only: the policy of the matching public key object.
publicAttributes = { CKA_VERIFY = true }
# Where it lives on `softhsm`: a locator (must match exactly one object, or 12), and
# `autoCreate` to let first use (`realise`, `check`) generate it when the locator is empty (never
# over an occupied one). `cakeys create` generates it explicitly either way.
tokens.softhsm = { locator = { CKA_LABEL = "signing", CKA_ID = "0e" }, autoCreate = true }

[specs.backup-kek-wrap]
object = "backup-kek"
# The declared usage bits choose the secret key's identity schemes: CKA_SIGN gives `cmac`,
# CKA_ENCRYPT `kcv-ecb`, CKA_DECRYPT `kcv-ecb-dec`, CKA_WRAP `kw` (DESIGN §3.1). Token defaults
# never do. CKA_ALLOWED_MECHANISMS is the one list-valued attribute (key objects only).
attributes = { CKA_SIGN = true, CKA_WRAP = true, CKA_EXTRACTABLE = false, CKA_ALLOWED_MECHANISMS = ["CKM_AES_CMAC", "CKM_AES_KEY_WRAP"] }
tokens.softhsm = { locator = { CKA_LABEL = "backup-kek" }, autoCreate = true }

[specs.signing-tpm]
object = "signing"
attributes = { CKA_SIGN = true }
# The same object on another token: the same material must hash to the same identity there.
# `attestation = true` also pins signed provenance from the TPM (tpm-certify, §3.7): once
# locked, losing it is a downgrade.
tokens.tpm = { locator = { CKA_LABEL = "signing" }, attestation = true }

[specs.agreement-soft]
object = "agreement"
attributes = { CKA_DERIVE = true }
# Proof of possession (§3.6): by default the token signs a fresh challenge (`pop-sign`). A key
# that can only derive proves it by ECDH (`pop-ecdh`), an RSA key that can only decrypt by
# OAEP (`pop-decrypt`); `token-asserted` opts out (recorded, and never a silent downgrade).
tokens.softhsm = { locator = { CKA_LABEL = "derive-only" }, binding = "pop-ecdh" }

[specs.firmware-cert-piv]
object = "firmware-cert"
tokens.yubikey = { locator = { CKA_LABEL = "X.509 Certificate for Retired Key 1" } }

[specs.signing-piv]
object = "signing"
# `publicOnly` identifies a private key through its public key object, without logging in
# (spares PIV PIN retries). It implies `token-asserted` and forbids policy attributes.
tokens.yubikey = { locator = { CKA_ID = "05" }, publicOnly = true }

[specs.release-note]
object = "release-note"
tokens.softhsm = { locator = { CKA_LABEL = "release-note" } }
```

## Rules worth knowing

- **Each spec names exactly one object; one spec has at most one realisation per token.** A
  realisation is the pair (spec, token): the lock records one per pair.
- **References are checked at load (17):** a spec's `object` must exist, even if nothing uses the
  spec; a `$NAME` path reference must name a set variable.
- **`autoCreate` is for private and secret keys**, and only opts the first-use flows in; `cakeys
  create` makes them explicitly without it. Certificates, public keys and data objects are
  adopted. When the lock already pins the object's material, creating is refused (14): newly
  generated material could never match.
- **One birthplace per object:** an object whose specs name several tokens is generated on its
  `createOn` token only; `autoCreate` elsewhere, or on several tokens without `createOn`, is
  invalid (17). The other tokens get the same material by import (`camigrate`).
- **Weak identity modes need `identity.allow`** on the spec's token entry (for example
  `identity = { allow = ["commit-at-creation"] }`); none is implemented yet, and they are refused
  before anything is created.

For the lock that `realise` writes from this, see [`LOCK.md`](LOCK.md). A real, small pair of
files is [`examples/yubikey-secureboot.toml`](../examples/yubikey-secureboot.toml) and its lock.
