# keys.lock, explained

`keys.lock` is the file in which cakeys records what each object's material *is* (its
content-addressed identities), and where and how each spec found that material on each token.
You review the diff of the lock as you review the diff of any lockfile, and you commit it. Every
later use checks the token against it. The normative reference is [`DESIGN.md`](DESIGN.md) §4.2,
and this page explains the lock with examples. [`CONFIG.md`](CONFIG.md) describes the file that
you write.

cakeys rewrites the whole lock each time it writes, so comments in a real `keys.lock` would be
lost at the next `lock`. The annotations below therefore exist only on this page.

## Two halves: what the material is, and where it lives

| Table | Answers | Keyed by |
|---|---|---|
| `[objects.<object>]` | What is this material? The table holds its type and its identities. | the object name from keys.toml |
| `[realisations.<spec>.<token>]` | Where and how did this spec find the material on this token? | (spec, token) |
| `[observations."<key>"]` | What did a realisation see of its module and token? | the SHA-256 of the entry itself |

The tables are separate because the material and its placement are independent. The same
material can be on several tokens (one object, several realisations). A realisation can be
removed (`delete` drops it), while the material's identity stays known for the other tokens.
Each object is self-contained, so lock files can be split and joined per object. The
observations are a third, supporting table: it holds each distinct observation once, and the
realisations that were recorded with an observation name it.

## Objects

These are excerpts of a real lock: the lock that `scripts/xversion.sh record` writes on SoftHSM,
with one object of every class.

```toml
# The lock schema. cakeys refuses any other version (17). Version 1 is still a draft (DESIGN §10).
version = 1

[objects.ec]
# The objects of another class that share this key's public key: here, the public key object
# `ecpub` (for a certificate, its subject key). Both sides must list each other. A partner that
# is absent from this file may be in another lock fragment, so locks can still be split and
# joined (§4.2).
pairs = ["ecpub"]
# A transport key (a token's `migrate.transportWith`, docs/CAMIGRATE.md D3) also records its
# public key, as the base64 of the canonical SPKI, so that a source can export to its token from
# the lock alone. On load, cakeys checks the key against `ids.rfc7093m4` (a mismatch is 17), so
# the identity vouches for it.
# publicKey = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA..."

# The type for which the identities were computed, copied from keys.toml when the object was
# first recorded. It is deliberately kept apart from `ids`: a different type is different
# material, so a type change in keys.toml is refused (14) with "type changed", and it is never
# reported as an unexplained hash mismatch.
[objects.ec.type]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"   # canonical: keys.toml said "P-256"

# The identities: a map from scheme to SRI hash (sha256-<base64>). One object may have several
# identities, one per scheme. Material is linked to another token's copy only through a scheme
# that both compute.
[objects.ec.ids]
rfc7093m4 = "sha256-o7TM2/7T7zkp11y8VqqoC7aFJ5B5Uo6OPTmu2g3mkLI="   # SHA-256 of the canonical SPKI

[objects.aes]
# A secret key is identified by what the token computes over a fixed label (a commitment). The
# label is recorded per object, so a future default can never change existing IDs.
commitmentLabel = "key-management/v1"

[objects.aes.type]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[objects.aes.ids]
# Only the schemes that the spec's *declared* usage attributes allow: CKA_SIGN gives cmac, and
# CKA_ENCRYPT gives kcv-ecb. The token also reports CKA_DECRYPT = true by default, but defaults
# never choose a scheme, so there is no kcv-ecb-dec. Each ID is the SHA-256 of the token's
# output, never the output itself (a MAC or a ciphertext under the key).
cmac = "sha256-U+z6FH10sb4sC3p/oBtdfycPFwr9xPYO40kGMd8BYIA="
kcv-ecb = "sha256-pmbMg9OyHvW7WFjH4ah8rhAUqQiZBGMatbXaapkV9Uo="

[objects.cert.ids]
certhash = "sha256-lXNE6ciIfLkwGf6kf84qfibQ08d5fkPuGNKQ5KnyTMM="    # SHA-256 of the DER
rfc7093m4 = "sha256-8DQBv2fMc+z0Q5uxky0+5t9TS6MAHO07fNMqG9thHtM="   # the identity of its subject key

[objects.data.ids]
valuehash = "sha256-TyepRDGGU8gW0rMMBWqSssutoJyBwJQwoYZw8UQ5VoU="   # SHA-256 of CKA_VALUE
```

## A realisation

Every realisation field belongs to one of three classes. The classes are separate because they
mean different things to a verdict:

| Class | Fields | On a difference |
|---|---|---|
| **Compared** | `object`, `locator`, `specDigest`, `mode`, `schemes`, `binding`, `attestation`, `policy`, `immutables` | The run fails (14, or 10 for an identity) until the difference is reviewed and recorded again. |
| **Observed** | `observed.*`, and the `observation` entry that it names | These are facts about the object and the token, and a difference is a warning or a note. |
| **Provenance** | `provenance.origin` | This is the object's history (an import), and it never decides a verdict. |

Removing `observed`, `observation`, `provenance` and the whole `observations` table changes no
verdict, and a test checks this. A realisation that names an entry that the lock lacks makes the
lock invalid (17). The compared fields are required.

```toml
[realisations.ec.soft]
# The object that this spec realised. A spec that is retargeted to another object is reported as
# such (14).
object = "ec"
# The SHA-256 of the spec's canonical JSON (the object type and its declared attributes). A
# changed spec fails `check` (14, "changed in keys.toml") until `lock` records it again.
specDigest = "sha256-2NHAGifN/zSvJ77DXQKy3lmAaVkj5Ci1IxO7QSius0A="
# How the identity was established, from the strongest mode to the weakest: direct (a hash of
# public material), commitment (the token computes over a label), and wrap-rebind (through a
# temporary copy of an extractable key). A weaker mode later is a downgrade (14).
mode = "direct"
# The schemes that this realisation computed and matched. Computing fewer schemes later is a
# downgrade (14).
schemes = ["rfc7093m4"]
# How the private key was bound to the public key that its identity hashes. With pop-sign, the
# token signed a fresh challenge that the host verified. The other values are pop-sign-pin
# (when the key is CKA_ALWAYS_AUTHENTICATE and each signature took a context-specific login),
# pop-ecdh, pop-decrypt and pop-unwrap. `token-asserted` means that only the token's report
# binds the key. A change from any pop-* binding to token-asserted is refused (14). The lock does
# not store the `assurance` that `lock` and the Nix view report; cakeys derives it from the
# binding, the class and the attestation kind. A pop-* binding (or a tpm-certify attestation) is
# a "proof" that no replay passes. A secret key's commitment is a "fingerprint" that anyone who
# saw it can replay. Public bytes are "public" (docs/archive/REVIEW-2026-11-13.md, "Replay").
binding = "pop-sign"
# The observation that this realisation was recorded with: a key of the `observations` table
# (below). It never decides a verdict.
observation = "sha256-…"

# Where the object was found. The locator is recorded so that a moved locator is reported as a
# moved locator (14), not as an unexplained hash mismatch.
[realisations.ec.soft.locator]
CKA_LABEL = "ec"
CKA_ID = "0e"

# Policy: every boolean that the class may carry and that the token shows (closed-world),
# whether declared or not. Here, SoftHSM's defaults CKA_DECRYPT, CKA_UNWRAP and
# CKA_SIGN_RECOVER = true are visible too. These attributes *can* change on a token
# (C_SetAttributeValue), so a change is drift to review (14), and `lock` records it again.
[realisations.ec.soft.policy]
CKA_SIGN = true
CKA_SENSITIVE = true
CKA_EXTRACTABLE = false
CKA_DECRYPT = true          # a token default that the spec did not ask for
# ... the rest of the class's booleans

# Immutables: the token set them when it made the key, and no operation can make them true
# again. They are kept apart from the policy because their meaning differs. A flag that was true
# and is no longer true means that the object was *replaced* (for example, imported again). That
# is refused even when the lock is written, and the material needs a new object name.
[realisations.ec.soft.immutables]
CKA_LOCAL = true                            # generated on this token
CKA_NEVER_EXTRACTABLE = true
CKA_ALWAYS_SENSITIVE = true
CKA_KEY_GEN_MECHANISM = "CKM_EC_KEY_PAIR_GEN"

# Observed: facts about the object at the time, which never decide a verdict.
[realisations.ec.soft.observed]
# The RFC 7512 URI that consumers use: a pure locator (with the token serial, never a module
# path).
uri = "pkcs11:token=xv;serial=b19136a55523f406;object=ec;id=%0E;type=private"
# What the duplicate-CKA_ID check could see: "user" (logged in) or "public". A change from user
# to public gives a warning, because a public session cannot see a second private key under the
# same CKA_ID.
session = "user"
```

An object that `camigrate` moved in also records where it came from (public objects record it
too, since phase 2 in docs/CAMIGRATE.md). This record is the object's history, so recording the
same object again keeps it:

```toml
[realisations.ec.soft.provenance.origin]
from = "softhsm"                    # the source token
method = "rsa-oaep-sha1+aes-kwp"    # a method name (docs/CAMIGRATE.md, "Frozen names and formats")
exposure = "sealed"                 # the exposure level of the path
declared = true                     # only for a vendor method: the level is the vendor's own declaration
```

## Observations

What a realisation saw of its module and token is stored once per distinct value. The entry's
key is the SRI SHA-256 of the entry's canonical JSON (RFC 8785, as for the spec digest).
Realisations that were recorded with the same module build, token, provider, cakeys version and
mechanism list name the same entry, and a realisation that was recorded through another module
names another entry. A module update therefore shows in the diff as one new entry, and as one
changed `observation` line for each realisation that is recorded again. A write drops the
entries that no realisation names any more, and so does `gc`.

```toml
[observations."sha256-…"]
# Which software interpreted the token: the cakeys provider and the cakeys version. A different
# provider gives a warning, and a different cakeys version gives a note.
provider = "softhsm"
cakeysVersion = "0.1.0"
# The module capability profile that the token resolved to (docs/CAPROBE.md D8). It is absent
# when no profile is committed for the token. A different profile gives a note.
profile = "softhsm/2.7"
# The mechanisms that the token offered (the Nix library's `functions`). A mechanism that
# disappears gives a warning.
mechanisms = ["CKM_ECDSA", "CKM_ECDSA_SHA256"]   # ... trimmed

# Which PKCS#11 library answered: C_GetInfo, and the file that the dynamic loader mapped, with
# its hash. The path has its symlinks resolved, whatever named the file: keys.toml's module, its
# $NAME, --module, or a bare name that the library search found. A different build identity
# (description, manufacturer, version, cryptoki) gives a warning, and so does a different hash
# at the same path (the file was replaced in place, which a path outside the Nix store cannot
# show). The same build at another path, such as after a Nix rebuild, gives only a note.
[observations."sha256-…".module]
path = "/nix/store/xb35g93pcvyyjrpjq1l6brdx6x8v3z6w-softhsm-2.7.0/lib/softhsm/libsofthsm2.so"
hash = "sha256-Pwmq/S/L0HNdKn4lLgttPZw1nUufTAT2+wgyB3cYOZk="
description = "Implementation of PKCS11"
manufacturer = "SoftHSM"
version = "2.7"      # raw CK_VERSION major.minor (ykcs11 2.7.3 shows as "2.73")
cryptoki = "3.2"

# Which device answered (C_GetTokenInfo). A different token gives a warning.
[observations."sha256-…".token]
model = "SoftHSM v2"
serial = "b19136a55523f406"
firmware = "2.7"

# What this token answered about cakeys' operations, in the row form of a capability profile
# (docs/CAPROBE.md): the proof that each realisation gave, and the generation that each `create`
# made. These rows are not part of the entry's key, and they are merged as runs record more, so
# the entry stays one entry.
[observations."sha256-…".capabilities]
"prove.pop-sign.CKK_EC.secp256r1" = { answer = "yes" }
"generate.CKK_EC.secp256r1" = { answer = "yes" }
```

The `capabilities` are this deployment's own answers. `validate`, `create` (its gate, and the
generation on the token) and camigrate's planner read them before the module profile of the
token's kind: the recorded answers decide, and the profile is only the prior. When a curve is
recorded with `via = "by-name"`, a generation of that curve is retried with the curve's name. A
recorded *no* refuses in the same place as a profile's *no*. A recorded answer that names no
`via` keeps the profile's `via`. The capabilities are observations (DESIGN §3.5): they never change a verdict of `check` or `lock`,
and a run that records none leaves them as they were. A run records only what it demonstrated,
so today they only ever say *yes*.

An entry is the one lock table that accepts TOML keys that this version of cakeys does not know
(keys from a newer version). Such keys load with a warning, and they are kept when the lock is
rewritten. An unknown key anywhere else is refused (17). The entry's key is not recomputed on
load, so such an entry keeps its key.

cakeys can say which entry is a token's *current* entry only when every realisation on the token
names the same entry. Otherwise, `validate`'s profile gate and `export --dry-run` for a token
that does not open say so, and they name `lock`, which records each realisation again with what
it sees now.

Two more realisation shapes are worth seeing:

```toml
# A secret key, identified by commitments. Its policy carries the one attribute whose value is a
# list.
[realisations.aes.soft]
mode = "commitment"
schemes = ["cmac", "kcv-ecb"]
[realisations.aes.soft.policy]
CKA_ALLOWED_MECHANISMS = ["CKM_AES_CMAC", "CKM_AES_ECB"]   # sorted, without duplicates

# A key whose spec declares no usage attribute that allows a commitment, but which is
# extractable. cakeys wraps it under a session key into a temporary copy that may compute every
# scheme, and then destroys both. This mode is weaker than `commitment`, so the lock records it
# as its own mode.
[realisations.wrapped.soft]
mode = "wrap-rebind"
schemes = ["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"]
```

The last example is an attestation from a YubiKey realisation with `attestation = true` (§3.7):

```toml
# Signed provenance for *this* device, so the lock records it on the realisation, not in the
# object's ids: the same material on another token gives a different attestation or none at all.
# It never replaces the portable identity (rfc7093m4 here), and both must match.
[realisations.rw-test-yubikey.yubikey.attestation]
kind = "yubico-piv"     # or "tpm-certify"
# The trust anchor to which the evidence was verified: the Yubico root's SPKI (for a TPM, the
# Attestation Key's SPKI). A different anchor fails (14).
root = "sha256-H0PiuI6WSl0DuAWLuqztaBmcklYgDxuyjqqy+CoeBvI="
# The canonical digest of what the attestation asserts (the firmware, the serial, the PIN and
# touch policy, and the attested key). A different ID under the same anchor fails (10).
id = "sha256-ZksMSOtJ2hgO/UZqtKLLVWmYXOko4O1YP0F3lhXVDA4="
```

## How a write behaves

`lock`, `create` and `delete` write the lock by default. `lock --dry-run` and `delete --dry-run`
only compare, and `create --no-update-lock` records nothing. A run that wrote the lock exits 22,
even when a pair failed after the write. In that case, the failed pair's row keeps its own code,
and a note on stderr says why the run exits 22. A lock that does not exist is refused (17)
unless `--new-lock` is given (CAKEYS.md, "Exit codes"). A write only *fills gaps*: what the lock
lacks is recorded (including on first use), but a locked ID, type, binding, attestation or
immutable is never overwritten. Such changes fail even when the lock is written, because
different material needs a new object name. Policy drift and spec drift, which can be
legitimate, are recorded again by a write after you review the diff. The property tests
(`crates/core/tests/properties.rs`) check exactly these rules.

cakeys checks these lock invariants on load (17):

- every ID and digest is a 32-byte SRI;
- a realisation's `object` exists, and its `schemes` are among the object's IDs;
- no two objects of one class share an ID under one scheme (one object per material);
- `pairs` are mutual where both sides are present;
- only private-key realisations have a `binding`;
- an attestation never stands without a portable scheme;
- a realisation's `observation` is a key of the `observations` table;
- an `origin` names a known method.

A real lock to read alongside this page is
[`examples/yubikey-secureboot.lock`](../examples/yubikey-secureboot.lock). It holds RSA keys and
their certificates, which were adopted read-only with `publicOnly`.
