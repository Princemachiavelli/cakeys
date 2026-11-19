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

A name is letters, digits, `-` and `_`, starting with a letter or digit; anything else is
refused when the file loads (17). `check` splits `<object>.id.<scheme>` on its dots, the lock
nests tables by name, and the Nix library puts names in a shell command.

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
# Optional, top level: directories of module profiles (docs/CAPROBE.md) to load beside the
# ones cakeys embeds, so a new vendor needs a profile file, not a rebuild. They only add; one
# that would replace an embedded profile, a layer or the baseline is refused (17). `$NAME` as for
# pinFile. Empty here: the embedded profiles cover every token below.
profileDirs = []

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
# Optional: its serial number too, when two of the module's tokens carry the label (12 without
# it, naming their serials). The lock's URI records it either way.
# tokenSerial = "4f3c2a1b9e8d7c6a"
# The user PIN, read from a file (or `pinEnv = "VAR"`: the PIN itself from the environment).
# Without a PIN cakeys opens a public session and sees only public objects.
pinFile = "/var/lib/softhsm/pin"
# What only one tool reads sits in that tool's table, here inline: `probe` (caprobe), `migrate`
# (camigrate) and `nix` (the Nix library); cakeys reads none of them.
# probe.scratch marks the token expendable for `caprobe probe --write` (docs/CAPROBE.md): its
# write probes generate, wrap, unwrap and destroy objects, so they run only on a token marked
# scratch and are refused (17) on any other. Never on a token holding real keys:
# probe = { scratch = true }
# migrate.transportWith is the spec of this token's transport key (docs/CAMIGRATE.md D3): sealed moves to this token wrap to it,
# never to a key picked by what it can do (`camigrate --transport-key` overrides it per run). It
# must realise an RSA private key here declaring CKA_UNWRAP = true and CKA_EXTRACTABLE = false
# (else 17); realising it records its public key in the lock, so any host exports to this token
# from the lock alone. `binding = "pop-unwrap"` proves it without CKA_DECRYPT.
# migrate = { transportWith = "transport-softhsm" }

[tokens.tpm]
module = "/run/current-system/sw/lib/libtpm2_pkcs11.so"
tokenLabel = "host"
# `$NAME` or `${NAME}` takes the path from the environment, so one keys.toml can serve machines
# with different paths. An unset variable is refused when the file loads (17), not at login.
pinFile = "$TPM_PIN_FILE"
# Optional: the provider (the module's quirks profile, ARCHITECTURE.md "Providers") is normally detected from
# C_GetInfo; naming it is needed behind p11-kit, which hides the module behind it. A provider with
# code (ykcs11, tpm2-pkcs11, kmsp11, aws-cloudhsm) or a module profile family (softhsm, kryoptic,
# or one a profileDirs entry brings): docs/CAPROBE.md. A family, never one profile (17).
provider = "tpm2-pkcs11"
# Optional: one module profile by its full name, among profiles that tie on
# C_GetInfo/C_GetTokenInfo (PKCS#11 reports no FIPS mode): an AWS CloudHSM non-FIPS cluster is
# `moduleProfile = "aws-cloudhsm/5.18+hsm2m-non-fips"` (a FIPS one resolves to its profile
# unnamed). Its family is the provider when `provider` is unset. Unknown names are 17.
# moduleProfile = "tpm2-pkcs11/1.10+amd-ftpm"
# Delta capability layers between cakeys and the token (docs/CAPROBE.md), by name or family:
# hand-maintained facts factored out of an observed profile (swtpm's RSA cap), or anything else
# the stack applies. The module profile itself — what this module does on this kind of
# hardware — is chosen from C_GetInfo and C_GetTokenInfo, not named here. The cryptoki binding
# layer is always applied (and heals itself when its fix is in); p11-kit is detected from the
# module. Unknown names refuse (17). This token is a real TPM, so not swtpm's:
# profiles = ["swtpm"]
# nix.systemFeature: the Nix system feature builds that need this token require. Default:
# lib.mkKeys's `featurePrefix` (default "token-") and the token's name, which is what the NixOS
# module advertises for its token of that name; set it when the host names the token differently.
nix = { systemFeature = "token-tpm" }

# The provider's own settings. Each provider checks its own; one that takes none refuses any
# (17). tpm2-pkcs11's (`tcti`, `tpm2Store`, `akHandle`, `akLabel`) serve its TPM2_Certify
# attestation (§3.7). A module that has the CKM_TPM2_CERTIFY vendor mechanism certifies for us
# (no `tpm2Store`); an older one is read through its store, with `tcti`.
# `akHandle` is the persistent Attestation Key (the default); `akLabel` instead names an
# Attestation Key that is an object of the token, made by `lock` (CKM_TPM2_AK_PAIR_GEN) and used
# without `tcti` or `tpm2Store` (a module with CKM_TPM2_CERTIFY_OBJECT only, 15 otherwise). It is
# another key, so another `attestation.root`: switching to it is re-locking. Not both.
[tokens.tpm.options]
tcti = "device:/dev/tpmrm0"
akHandle = "0x81000016"
# akLabel = "cakeys-ak"

[tokens.yubikey]
tokenLabel = "YubiKey PIV #39189318"
pinFile = "/run/secrets/piv-pin"
# The Security Officer credential, from a file (or `soCredentialEnv = "VAR"`), read only by a
# step that needs the SO: create or delete on a module
# that does those only as SO (ykcs11: the PIV management key in hex, or the PIN when the
# management key is PIN-protected), and `camigrate transport --trusted` on any module (its SO
# PIN; docs/CAMIGRATE.md D2). The hex management key logs in without a PIN verification, so it spends
# no PIN retry; the PIN does.
soCredentialFile = "/run/secrets/piv-mgm"
# A device like this holds real keys beside expendable ones, so probe.scratch cannot mark it. For
# a module that creates only as SO into slots named by CKA_ID (ykcs11), probe.scratchId names the one
# slot `probe --write` may overwrite (hex CKA_ID: 17 is retired slot 94). Each probe generation
# replaces the slot's key and the last one stays (PIV cannot erase a key). The probe refuses a
# slot holding anything but ykcs11's own placeholder from an earlier generation (17), so a typo
# never reaches a real key. No other verb reads it.
# probe = { scratchId = "17" }

# ── Objects: the material ───────────────────────────────────────────────────────────────

[objects.signing]
# The PKCS#11 class: CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY, CKO_CERTIFICATE, CKO_DATA.
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
# Canonicalized on load: "P-256" and "prime256v1" are the same type as "secp256r1".
curve = "secp256r1"

[objects.agreement]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp384r1"

[objects.backup-kek]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
# Bytes. Part of the type, and of the commitment label a secret key's identity is computed on.
valueLen = 32

[objects.pin-key]
class = "CKO_SECRET_KEY"
# Triple DES, as payment HSMs hold it. The key type fixes the length (24 bytes), so valueLen is
# left out (or written 24; anything else is 17). Its identity is a check value: CKA_ENCRYPT gives
# `kcv-ecb`, CKA_DECRYPT `kcv-ecb-dec`; a DES3 key that may only sign or wrap has none yet.
keyType = "CKK_DES3"

[objects.firmware-cert]
class = "CKO_CERTIFICATE"
# Certificates take a certificate type instead of a key type.
certificateType = "CKC_X_509"

[objects.release-note]
# A public data object: identified by the SHA-256 of its value (the same hash as a Nix flat
# fixed-output derivation of the content). A private one (CKA_PRIVATE = true) is identified the
# same way, read under the login, only when its spec declares CKA_PRIVATE = true: anyone with the
# lock can test guesses against the hash offline, so declare it only for a random value.
class = "CKO_DATA"

[objects.web-tls]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"
# migrate.file: the file this object's material is born in, for the pairs that say
# origin = "file" (docs/FILE.md). Only camigrate reads it, and it is no part of the type the lock
# pins. Any format a deployment holds, told by content: PEM or DER PKCS#8, PKCS#1, SEC1, encrypted
# PKCS#8, PKCS#12, a certificate or public key; a data object's file is its bytes. A secret key's
# file is its value's bytes, or hex or base64 of them: told by valueLen, or said by
# migrate.encoding = "raw", "hex" or "base64"; it needs one of the two (17).
# `$NAME` resolves when camigrate reads it, so hosts that only check need not set it. A key's
# file may not be in /nix/store (17), unless CAKEYS_ALLOW_NIX_STORE_KEYS=1 says the keys are
# throwaway (docs/FILE.md). An encrypted file names its passphrase as a token names its
# PIN: passphraseFile or passphraseEnv.
migrate = { file = "$WEB_TLS_KEY" }

# ── Specs: one use of an object, and where it lives on each token ──────────────────────

[specs.signing-soft]
object = "signing"
# The policy this use requires: boolean CKA_* attributes the class may carry (a wrong name or
# class is 17). The token must show exactly these; everything else it shows is recorded in the
# lock, and later drift is reported.
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
# Private keys only: the policy of the matching public key object.
publicAttributes = { CKA_VERIFY = true }
# migrate.noExport: the object never leaves the tokens this spec realises it on: camigrate refuses to export or
# migrate it from them (15), and `export` without names leaves it out quietly (an extractable
# key otherwise moves; a non-extractable one is left out with a warning). Not in the spec digest.
# migrate = { noExport = true }
# Where it lives on `softhsm`: a locator (must match exactly one object, or 12), and how it comes
# to be there, `origin` (required for private and secret keys):
#   "create"  `cakeys create` generates it here, when the locator is empty (never over an
#             occupied one). At most one pair per object: where its material is born, and with
#             whose policy. Every other verb only finds it.
#   "import"  camigrate brings the material here from the token that created it.
#   "file"    camigrate brings it here from the object's migrate.file (`camigrate import
#             --token <t>`), where the material is born; any number of pairs may say it.
#   "adopt"   it is already there, put there by something cakeys does not run.
# Like the locator, it is not part of the spec digest.
tokens.softhsm = { locator = { CKA_LABEL = "signing", CKA_ID = "0e" }, origin = "create" }

[specs.backup-kek-wrap]
object = "backup-kek"
# The declared usage bits choose the secret key's identity schemes: CKA_SIGN gives `cmac`,
# CKA_ENCRYPT `kcv-ecb`, CKA_DECRYPT `kcv-ecb-dec`, CKA_WRAP `kw` (DESIGN §3.1). Token defaults
# never do. CKA_ALLOWED_MECHANISMS is the one list-valued attribute (key objects only).
attributes = { CKA_SIGN = true, CKA_WRAP = true, CKA_EXTRACTABLE = false, CKA_ALLOWED_MECHANISMS = ["CKM_AES_CMAC", "CKM_AES_KEY_WRAP"] }
tokens.softhsm = { locator = { CKA_LABEL = "backup-kek" }, origin = "create" }

[specs.signing-tpm]
object = "signing"
attributes = { CKA_SIGN = true }
# The same object on another token: the same material must hash to the same identity there, so
# it is imported from where it was created (`camigrate migrate signing --from softhsm --to tpm`).
# `attestation = true` also pins signed provenance from the TPM (tpm-certify, §3.7): once
# locked, losing it is a downgrade.
tokens.tpm = { locator = { CKA_LABEL = "signing" }, origin = "import", attestation = true }

[specs.agreement-soft]
object = "agreement"
attributes = { CKA_DERIVE = true }
# Proof of possession (§3.6): by default the token signs a fresh challenge (`pop-sign`). A key
# that can only derive proves it by ECDH (`pop-ecdh`), an RSA key that can only decrypt by
# OAEP (`pop-decrypt`), one that can only unwrap by unwrapping a host secret (`pop-unwrap`);
# `token-asserted` opts out (recorded, and never a silent downgrade).
tokens.softhsm = { locator = { CKA_LABEL = "derive-only" }, origin = "adopt", binding = "pop-ecdh" }

[specs.firmware-cert-piv]
object = "firmware-cert"
# A certificate, public key or data object is adopted unless it says origin = "import".
tokens.yubikey = { locator = { CKA_LABEL = "X.509 Certificate for Retired Key 1" } }

[specs.signing-piv]
object = "signing"
# `publicOnly` identifies a private key through its public key object, without logging in
# (spares PIV PIN retries). It implies `token-asserted` and `origin = "adopt"`, and forbids policy
# attributes.
tokens.yubikey = { locator = { CKA_ID = "05" }, publicOnly = true }

[specs.release-note]
object = "release-note"
tokens.softhsm = { locator = { CKA_LABEL = "release-note" } }

[specs.web-tls]
object = "web-tls"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }
# Born in its file: the first import pins its identity from the file, and every other pair and
# later run must match it (10 otherwise, before anything is written).
tokens.softhsm = { locator = { CKA_LABEL = "web-tls" }, origin = "file" }
```

## Rules worth knowing

- **Each spec names exactly one object; one spec has at most one realisation per token.** A
  realisation is the pair (spec, token): the lock records one per pair.
- **References are checked at load (17):** a spec's `object` must exist, even if nothing uses the
  spec; a `$NAME` path reference must name a set variable.
- **A private data object needs `CKA_PRIVATE = true` declared** in its spec, or it is refused
  (15): its `valuehash` would let anyone with the lock test guesses of the value offline
  (DESIGN §8.2). camigrate moves no private data object (15).
- **Only `cakeys create` makes keys, and only where `origin = "create"`;** `lock` and
  `check` find what is there, and camigrate moves material only onto a pair that says
  `origin = "import"`. Certificates, public keys, data objects, `publicOnly` adoptions and
  `CKA_TRUSTED` keys are never `create` (17 at load). When the lock already pins the object's
  material, creating is refused (14): newly generated material could never match.
- **One birthplace per object:** at most one pair of an object, across all its specs and
  tokens, says `origin = "create"` (17 at load otherwise). That pair says where the material is
  born and with whose policy, so no order of a run decides either; the other pairs import or
  adopt it. A file is a birthplace too: an object with `migrate.file` has no `create` pair, and
  `origin = "file"` needs one (17); every pair saying it reads that one file.
- **`create` checks before it makes anything:** each pair it would create is checked against
  the token's capability profiles before any token is opened. A pair they say cannot be made
  refuses the whole run (15), and nothing is created; `--skip-unsupported` creates the rest and
  warns; `--dry-run` prints what each pair would get and why, and writes nothing.
- **Declare what must not drift; everything else is observed.** `attributes` is the gate: a
  declared attribute the token does not show is a conflict (13), and `lock` never re-records
  it. Every other attribute the token shows is recorded in the lock, and when it changes
  `lock` re-records it with a warning, as it does a new module version or mechanism list
  (DESIGN §3.5). An attribute that matters goes in `attributes`.
- **A secret key needs an identity the token can recompute:** a declared usage bit a commitment
  can use (`CKA_SIGN`, `CKA_ENCRYPT`, `CKA_DECRYPT`, `CKA_WRAP` on AES; `CKA_ENCRYPT`,
  `CKA_DECRYPT` on DES3; `CKA_SIGN` on generic secrets and HMAC keys), or `CKA_EXTRACTABLE =
  true`. Otherwise the spec is invalid (17); DESIGN §3.4 says why, and what may change.

For the lock that `lock` writes from this, see [`LOCK.md`](LOCK.md). A real, small pair of
files is [`examples/yubikey-secureboot.toml`](../examples/yubikey-secureboot.toml) and its lock;
[`examples/`](../examples/README.md) has runnable ones, among them every kind of object on every
kind of token.
