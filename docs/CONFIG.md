# keys.toml, explained

You write `keys.toml`. It says which tokens exist, what key material you expect, and what each
use of that material must look like. cakeys never writes it. What cakeys *observes* goes into
`keys.lock` ([`LOCK.md`](LOCK.md)). The normative reference is [`DESIGN.md`](DESIGN.md) §4.1,
and this page explains the same rules by example.

## Three kinds of table, and why they are separate

| Table | Answers | Example |
|---|---|---|
| `[tokens.<name>]` | *Where* is a token, and how do I log in to it? | a module path, a token label, a PIN file |
| `[objects.<name>]` | *What* is the material: its class and its intrinsic type | an EC P-256 private key |
| `[specs.<name>]` | *How* is the material used: the policy that one use requires, and where to find the material on each token | "this key, sign-only, non-extractable, under label `signing` on token `softhsm`" |

A name consists of letters, digits, `-` and `_`, and starts with a letter or a digit. Any other
name is refused when the file loads (17). The restriction exists because `check` splits
`<object>.id.<scheme>` on its dots, the lock nests tables by name, and the Nix library puts names
in a shell command.

The tables are separate because they change independently, and each kind of change means
something different:

- **The object is the material.** Its type (class, key type, curve, size) is intrinsic: a P-256
  key cannot become a P-384 key. The object's name is an internal handle, and it is never written
  to a token. The lock pins the object's identity (a hash of the material), so a change of its
  type is refused. Different material needs a new object name.
- **A spec is policy about an object.** Several specs may share one object. For example, one
  service may use a key only for signing, and another service may use the same key for signing
  and decryption. A change to a spec's policy is a change that a reviewer sees (the lock records
  a digest of the policy), not new material.
- **The locator says where the object is, not what it is.** `CKA_LABEL` and `CKA_ID` are names
  that a token holds. They can be changed or reused, so they are used only to *find* an object.
  The identity is the hash. For this reason, the locator is in the spec's entry for each token,
  not in the object.
- **A token entry only says how to reach the token.** A change to a token's module path or PIN
  file changes nothing about the keys on it.

## An annotated example

The example is valid as it stands: it loads with no environment variable set
(`the_annotated_config_example_loads`). Each comment explains the line below it or the line to
its left. The example does not show every key of every table; it shows one table of each kind and
the less obvious keys.

```toml
# Optional, at the top level: directories of module profiles (docs/CAPROBE.md) to load in addition
# to the profiles that cakeys embeds, so that a new vendor needs a profile file and not a rebuild.
# These directories can only add profiles. A profile that would replace an embedded profile, a
# layer or the baseline is refused (17). `$NAME` works as it does for pinFile. The list is empty
# here, because the embedded profiles cover every token below.
profileDirs = []

# ── Tokens ──────────────────────────────────────────────────────────────────────────────

[tokens.softhsm]
# The PKCS#11 module, which differs from machine to machine. It is one of three things: a path;
# "$NAME" or "${NAME}", which is read from the environment when the token is opened; or nothing,
# in which case each run gives it with `--module softhsm=<path>`. In a Nix build, lib.mkKeys's
# `modules.softhsm` passes that option, and the option also replaces a configured module. A bare
# file name is searched for by the dynamic loader (LD_LIBRARY_PATH; on NixOS, nothing else). The
# lock records the file that was actually loaded and its hash, as provenance only.
module = "/run/current-system/sw/lib/softhsm/libsofthsm2.so"
# Which token of the module to use: cakeys compares this with the label from C_GetTokenInfo.
tokenLabel = "main"
# Optional: the token's serial number as well, for when two of the module's tokens carry the same
# label. Without it, such a token is ambiguous (12), and the message names both serial numbers.
# The lock's URI records the serial number in either case.
# tokenSerial = "4f3c2a1b9e8d7c6a"
# The user PIN, read from a file. (With `pinEnv = "VAR"`, the environment variable holds the PIN
# itself.) Without a PIN, cakeys opens a public session and sees only public objects. A file that
# holds a secret (a PIN, an SO credential, or a key file's passphrase) holds one line, and cakeys
# drops its trailing line ending. A second line makes the file invalid (17). An unset variable or
# an unreadable file is unavailable (16). No secret file may resolve into /nix/store, because
# anyone on the host can read that directory (17, docs/FILE.md).
pinFile = "/var/lib/softhsm/pin"
# A setting that only one tool reads is in that tool's table, here written inline: `probe`
# (caprobe), `migrate` (camigrate) and `nix` (the Nix library). cakeys reads none of them.
# probe.scratch marks the token as expendable for `caprobe probe --write-probes`
# (docs/CAPROBE.md). The write probes generate, wrap, unwrap and destroy objects, so they run only
# on a token that is marked as scratch, and they are refused (17) on any other token. Never set it
# on a token that holds real keys:
# probe = { scratch = true }
# migrate.transportWith is the spec of this token's transport key (docs/CAMIGRATE.md D3). Sealed
# moves to this token wrap to this key, and never to a key that camigrate picks by what the key
# can do (`camigrate --transport-spec` overrides it for one run). The spec must realise an RSA
# private key on this token that declares CKA_UNWRAP = true and CKA_EXTRACTABLE = false (17
# otherwise). When the key is realised, the lock records its public key, so any host can export
# to this token from the lock alone. `binding = "pop-unwrap"` proves possession of the key without
# CKA_DECRYPT.
# migrate = { transportWith = "transport-softhsm" }

[tokens.tpm]
module = "/run/current-system/sw/lib/libtpm2_pkcs11.so"
tokenLabel = "host"
# `$NAME` or `${NAME}` takes the path from the environment, so that one keys.toml can serve
# machines with different paths. A malformed reference is refused when the file loads (17). An
# unset variable is unavailable (16) at the point where the file is read, which is at login. For
# this reason `validate`, which opens no token, needs no PIN variable.
pinFile = "$TPM_PIN_FILE"
# Optional: the provider (the profile of the module's quirks, ARCHITECTURE.md "Providers").
# cakeys normally detects it from C_GetInfo. Behind p11-kit, which hides the module behind it, it
# must be named. The value is either a provider with code (ykcs11, tpm2-pkcs11, kmsp11,
# aws-cloudhsm) or a family of module profiles (softhsm, kryoptic, or a family that a
# profileDirs entry adds): see docs/CAPROBE.md. It must be a family, never one profile (17).
provider = "tpm2-pkcs11"
# Optional: one module profile, by its full name, for a choice among profiles that tie on
# C_GetInfo and C_GetTokenInfo (PKCS#11 reports no FIPS mode). For example, an AWS CloudHSM
# non-FIPS cluster needs `moduleProfile = "aws-cloudhsm/5.18+hsm2m-non-fips"`, while a FIPS
# cluster resolves to its profile without a name. When `provider` is not set, the profile's
# family is the provider. An unknown name is refused (17).
# moduleProfile = "tpm2-pkcs11/1.10+amd-ftpm"
# Delta capability layers between cakeys and the token (docs/CAPROBE.md), by name or by family.
# A layer holds facts that a person maintains by hand and that were separated out of an observed
# profile (for example, swtpm's limit on RSA sizes), or anything else that the stack applies. The
# module profile itself, which describes what this module does on this kind of hardware, is
# chosen from C_GetInfo and C_GetTokenInfo, and is not named here. The layer of the cryptoki
# binding is always applied, and it subtracts nothing once the binding has its fix. cakeys
# detects p11-kit from the module. An unknown name is refused (17). This token is a real TPM, so
# swtpm's layer does not apply:
# profiles = ["swtpm"]
# nix.systemFeature is the Nix system feature that a build requires when it needs this token. The
# default is lib.mkKeys's `featurePrefix` (default "token-") followed by the token's name, which
# is what the NixOS module advertises for its token of that name. Set it when the host names the
# token differently.
nix = { systemFeature = "token-tpm" }

# The provider's own settings. Each provider checks its own settings, and a provider that takes
# none refuses any setting (17). The settings of tpm2-pkcs11 (`tcti`, `tpm2Store`, `akHandle`,
# `akLabel`, `ekCertificate`, `ekRoots`) serve its TPM2_Certify attestation (§3.7). A module that
# has the CKM_TPM2_CERTIFY vendor mechanism certifies the key itself, so it needs no `tpm2Store`.
# cakeys reads an older module through its store, with `tcti`. `akHandle` names the persistent
# Attestation Key (the default). `akLabel` instead names an Attestation Key that is an object of
# the token, which `lock` makes (CKM_TPM2_AK_PAIR_GEN) and uses without `tcti` or `tpm2Store`.
# `akLabel` needs a module with CKM_TPM2_CERTIFY_OBJECT (15 otherwise). Such a key is a different
# key, so it has a different `attestation.root`, and a switch to it means re-locking. Do not set
# both `akHandle` and `akLabel`.
# `ekCertificate` names the TPM's EK certificate and its intermediate certificates (PEM). With
# it, every attestation also proves that the AK is in that TPM, and the lock pins the
# manufacturer's root certificate. The chain must verify to a built-in root (AMD fTPM) or to a
# root in `ekRoots` (a PEM file of additional roots).
[tokens.tpm.options]
tcti = "device:/dev/tpmrm0"
akHandle = "0x81000016"
# akLabel = "cakeys-ak"
ekCertificate = "/etc/cakeys/ek.pem"

[tokens.yubikey]
tokenLabel = "YubiKey PIV #39189318"
pinFile = "/run/secrets/piv-pin"
# The Security Officer credential, read from a file (or from `soCredentialEnv = "VAR"`). Only a
# step that needs the SO reads it. Such steps are a create or a delete on a module that does
# these only as the SO (for ykcs11, the credential is the PIV management key in hex, or the PIN
# when the management key is protected by the PIN), and `camigrate transport --trust-on` on any
# module (with the SO PIN; docs/CAMIGRATE.md D2). The hex management key logs in without a PIN
# verification, so it uses up no PIN retry; the PIN does use one.
soCredentialFile = "/run/secrets/piv-mgm"
# A device like this holds real keys beside expendable ones, so probe.scratch cannot mark it. For
# a module that creates keys only as the SO, into slots named by CKA_ID (ykcs11), probe.scratchId
# names the one slot that `probe --write-probes` may overwrite (a hex CKA_ID: 17 is retired slot
# 94). Each generation by the probe replaces the slot's key, and the last key stays there,
# because PIV cannot erase a key. The probe refuses a slot that holds anything other than what
# an earlier probe run left there: its own mark certificate (CN=cakeys-probe) over the slot's key,
# and the device's attestation of the slot (17). In this way a typo cannot reach a real key. No
# other verb reads this setting.
# probe = { scratchId = "17" }

# ── Objects: the material ───────────────────────────────────────────────────────────────

[objects.signing]
# The PKCS#11 class: CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY, CKO_CERTIFICATE or CKO_DATA.
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
# cakeys canonicalizes the curve when the file loads: "P-256" and "prime256v1" are the same type
# as "secp256r1".
curve = "secp256r1"

[objects.agreement]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp384r1"

[objects.backup-kek]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
# The length in bytes. It is part of the type, and part of the commitment label on which a secret
# key's identity is computed.
valueLen = 32

[objects.pin-key]
class = "CKO_SECRET_KEY"
# Triple DES, as payment HSMs hold it. The key type fixes the length (24 bytes), so valueLen is
# left out (or written as 24; any other value is refused with 17). The key's identity is a check
# value: CKA_ENCRYPT gives `kcv-ecb`, and CKA_DECRYPT gives `kcv-ecb-dec`. A DES3 key that may only
# sign or wrap has no identity scheme yet.
keyType = "CKK_DES3"

[objects.firmware-cert]
class = "CKO_CERTIFICATE"
# A certificate takes a certificate type instead of a key type.
certificateType = "CKC_X_509"

[objects.release-note]
# A public data object. It is identified by the SHA-256 of its value, which is the same hash as
# that of a Nix flat fixed-output derivation of the content. A private data object
# (CKA_PRIVATE = true) is identified in the same way, read under the login, but only when its spec
# declares CKA_PRIVATE = true. Anyone with the lock can test guesses against the hash offline, so
# declare it only for a random value.
class = "CKO_DATA"

[objects.web-tls]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"
# migrate.file names the file in which this object's material is born, for the pairs that say
# origin = "file" (docs/FILE.md). Only camigrate reads it, and it is not part of the type that the
# lock pins. The file may be in any format that a deployment holds, and camigrate tells the format
# from the content: PEM or DER PKCS#8, PKCS#1, SEC1, encrypted PKCS#8, PKCS#12, a certificate or a
# public key. A data object's file holds its bytes. A secret key's file holds its value's bytes,
# or the hex or base64 form of them. camigrate tells the form from valueLen, or from
# migrate.encoding = "raw", "hex" or "base64", and it needs one of the two (17).
# `$NAME` is resolved when camigrate reads the file, so hosts that only check need not set it. A
# key's file, and any passphraseFile, may not resolve into /nix/store (17), whether directly or
# through a symlink or `..`, unless CAKEYS_ALLOW_NIX_STORE_KEYS=1 declares that the keys are
# disposable (docs/FILE.md). An encrypted file names its passphrase in the same way as a token
# names its PIN: with passphraseFile or passphraseEnv.
migrate = { file = "$WEB_TLS_KEY" }

# ── Specs: one use of an object, and where it lives on each token ──────────────────────

[specs.signing-soft]
object = "signing"
# The policy that this use requires: boolean CKA_* attributes that the class may carry (a wrong
# name or class is refused with 17). The token must show exactly these values. The lock records
# every other attribute that the token shows, and cakeys reports a later change of them as drift.
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
# For private keys only: the policy of the matching public key object.
publicAttributes = { CKA_VERIFY = true }
# migrate.noExport means that the object never leaves the tokens on which this spec realises it.
# camigrate refuses to export or migrate it from them (15), and an `export` or `migrate` without
# names leaves it out without a warning. (Without this setting, an extractable key moves, and a
# non-extractable key is left out with a warning.) A token's transport key
# (`migrate.transportWith`) stays on its token in this way without this setting. The setting is
# not part of the spec digest.
# migrate = { noExport = true }
# Where the object is on `softhsm`: a locator (it must match exactly one object, or the run fails
# with 12), and how the object comes to be there, `origin` (required for private and secret keys):
#   "create"  `cakeys create` generates it here when the locator is empty (never over an
#             occupied locator). An object has at most one such pair, which decides where its
#             material is born and under which policy. Every other verb only finds it.
#   "import"  camigrate brings the material here from the token that created it.
#   "file"    camigrate brings the material here from the object's migrate.file (`camigrate
#             import --token <t>`), where the material is born. Any number of pairs may say it.
#   "adopt"   the object is already there, and something that cakeys does not run put it there.
# Like the locator, `origin` is not part of the spec digest.
tokens.softhsm = { locator = { CKA_LABEL = "signing", CKA_ID = "0e" }, origin = "create" }

[specs.backup-kek-wrap]
object = "backup-kek"
# The declared usage attributes choose the secret key's identity schemes: CKA_SIGN gives `cmac`,
# CKA_ENCRYPT gives `kcv-ecb`, CKA_DECRYPT gives `kcv-ecb-dec`, and CKA_WRAP gives `kw` (DESIGN
# §3.1). The token's default attributes never choose a scheme. CKA_ALLOWED_MECHANISMS is the one
# attribute whose value is a list (for key objects only).
attributes = { CKA_SIGN = true, CKA_WRAP = true, CKA_EXTRACTABLE = false, CKA_ALLOWED_MECHANISMS = ["CKM_AES_CMAC", "CKM_AES_KEY_WRAP"] }
tokens.softhsm = { locator = { CKA_LABEL = "backup-kek" }, origin = "create" }

[specs.signing-tpm]
object = "signing"
attributes = { CKA_SIGN = true }
# The same object on another token. The same material must hash to the same identity there, so
# it is imported from the token where it was created
# (`camigrate migrate signing --from softhsm --to tpm`). `attestation = true` also pins signed
# provenance from the TPM (tpm-certify, §3.7). Once it is locked, a loss of the attestation is a
# downgrade.
tokens.tpm = { locator = { CKA_LABEL = "signing" }, origin = "import", attestation = true }

[specs.agreement-soft]
object = "agreement"
attributes = { CKA_DERIVE = true }
# Proof of possession (§3.6): by default, the token signs a fresh challenge (`pop-sign`). A key
# that can only derive proves possession by ECDH (`pop-ecdh`). An RSA key that can only decrypt
# proves it by OAEP (`pop-decrypt`), and a key that can only unwrap proves it by unwrapping a host
# secret (`pop-unwrap`). `token-asserted` opts out of the proof. The lock records this choice, so
# the opt-out is never a silent downgrade.
tokens.softhsm = { locator = { CKA_LABEL = "derive-only" }, origin = "adopt", binding = "pop-ecdh" }

[specs.firmware-cert-piv]
object = "firmware-cert"
# A certificate, a public key or a data object is adopted unless its pair says origin = "import".
tokens.yubikey = { locator = { CKA_LABEL = "X.509 Certificate for Retired Key 1" } }

[specs.signing-piv]
object = "signing"
# `publicOnly` identifies a private key through its public key object, without a login, which
# saves PIV PIN retries. It implies `token-asserted` and `origin = "adopt"`, and it does not allow
# policy attributes. A configured proof (`binding = "pop-ecdh"`, …) beside it is invalid (17).
tokens.yubikey = { locator = { CKA_ID = "05" }, publicOnly = true }

[specs.release-note]
object = "release-note"
tokens.softhsm = { locator = { CKA_LABEL = "release-note" } }

[specs.web-tls]
object = "web-tls"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }
# The material is born in its file. The first import pins its identity from the file, and every
# other pair and every later run must match that identity (10 otherwise, before anything is
# written).
tokens.softhsm = { locator = { CKA_LABEL = "web-tls" }, origin = "file" }
```

## Rules worth knowing

- **Each spec names exactly one object, and one spec has at most one realisation per token.** A
  realisation is the pair (spec, token), and the lock records one realisation per pair.
- **Everything that loads is usable (17 at load).** The loader checks these rules:
  - A spec's `object` must exist, even if nothing uses the spec.
  - A `$NAME` path reference must be well formed. Whether the variable is set is checked where
    the file is read (16).
  - Every token that a spec names must be in `[tokens]`.
  - A locator names `CKA_LABEL` or `CKA_ID`, and a `CKA_ID` is hex. The ID is stored in lower
    case, so `0A` and `0a` are one locator, and an empty ID is a real object's ID.
  - An AES `valueLen` is 16, 24 or 32, and no secret key's `valueLen` is 0.
  - Every (spec, token) pair passes the planning checks that `validate` and each verb would
    otherwise make only when they reached that pair.
- **A private data object needs `CKA_PRIVATE = true` declared** in its spec, or it is refused
  (15). Without this rule, its `valuehash` would let anyone with the lock test guesses of the
  value offline (DESIGN §8.2). camigrate moves no private data object (15).
- **Of cakeys' verbs, only `create` makes the keys that keys.toml declares, and only where
  `origin = "create"`.** `lock` and `check` find what is there, and camigrate moves material only
  onto a pair that says `origin = "import"`. Certificates, public keys, data objects, `publicOnly`
  adoptions and `CKA_TRUSTED` keys can never have `origin = "create"` (17 at load). When the lock
  already pins the object's material, `create` is refused (14), because newly generated material
  could never match.
- **Each object has one birthplace.** Across all of an object's specs and tokens, at most one
  pair says `origin = "create"` (17 at load otherwise). That pair says where the material is born
  and under which policy, so the order of a run decides neither. The other pairs import or adopt
  the material. A file is also a birthplace: an object with `migrate.file` has no `create` pair,
  and `origin = "file"` needs a `migrate.file` (17). Every pair that says `origin = "file"` reads
  that one file.
- **`create` checks before it makes anything.** Before it opens any token, it checks each pair
  that it would create against the token's capability profiles. When the profiles say that a
  pair cannot be made, the whole run is refused (15), and nothing is created. With
  `--skip-unsupported`, `create` creates the other pairs and prints a warning. With `--dry-run`,
  it prints what each pair would get and why, and it writes nothing.
- **Declare what must not drift; everything else is observed.** `attributes` is the check: a
  declared attribute that the token does not show is a conflict (13), and `lock` never records it
  again. The lock records every other attribute that the token shows. When such an attribute
  changes, `lock` records it again and prints a warning, as it does for a new module version or a
  new mechanism list (DESIGN §3.5). An attribute that matters belongs in `attributes`.
- **A secret key needs an identity that the token can recompute.** Its spec must declare a usage
  attribute that a commitment can use (`CKA_SIGN`, `CKA_ENCRYPT`, `CKA_DECRYPT` or `CKA_WRAP` on
  AES; `CKA_ENCRYPT` or `CKA_DECRYPT` on DES3; `CKA_SIGN` on generic secrets and HMAC keys), or
  `CKA_EXTRACTABLE = true`. Otherwise the spec is invalid (17). DESIGN §3.4 says why, and what may
  change.

For the lock that `lock` writes from this file, see [`LOCK.md`](LOCK.md). A real, small pair of
files is [`examples/yubikey-secureboot.toml`](../examples/yubikey-secureboot.toml) and its lock.
[`examples/`](../examples/README.md) has runnable examples, among them every kind of object on
every kind of token.
