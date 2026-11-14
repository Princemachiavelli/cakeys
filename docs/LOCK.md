# keys.lock, explained

`keys.lock` is what cakeys records: what each object's material *is* (its content-addressed
identities), and where and how each spec found it on each token. You review it like any lockfile
diff and commit it; every later use checks the token against it. The normative reference is
[`DESIGN.md`](DESIGN.md) §4.2; this page explains it by example. For the file you write, see
[`CONFIG.md`](CONFIG.md).

cakeys rewrites the lock as a whole, so comments in a real `keys.lock` would be lost on the next
`realise`; the annotations below live only here.

## Two halves: what the material is, and where it lives

| Table | Answers | Keyed by |
|---|---|---|
| `[objects.<object>]` | What is this material? Its type and its identities. | the object name from keys.toml |
| `[realisations.<spec>.<token>]` | Where and how did this spec find it on this token? | (spec, token) |
| `[observations."<key>"]` | What did a realisation see of its module and token? | the SHA-256 of the entry itself |

They are separate because material and placement are independent. The same material can live on
several tokens (one object, several realisations), and a realisation can be removed (`delete`
drops it) while the material's identity stays known for the other tokens. Each object is
self-contained, so lock files can be split and joined per object. The observations are a third,
supporting table: each distinct observation once, named by the realisations recorded with it.

## Objects

Excerpts of a real lock (the one `scripts/xversion.sh record` writes on SoftHSM: one object of
every class).

```toml
# The lock schema. Any other version is refused (17). Version 1 is still a draft (DESIGN §10).
version = 1

[objects.ec]
# Objects of another class that share this key's public key: here the public key object `ecpub`
# (for a certificate, its subject key). It must be listed on both sides; a partner absent from
# this file may live in another lock fragment, so locks still split and join (§4.2).
pairs = ["ecpub"]
# A transport key (a token's `transportWith`, MIGRATE.md D3) also records its public key, base64
# of the canonical SPKI, so a source exports to its token from the lock alone. It is checked on
# load against `ids.rfc7093m4` (a mismatch is 17): the identity vouches for it.
# publicKey = "MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA..."

# The type the identities were computed for, copied from keys.toml when first recorded. Kept
# apart from `ids` on purpose: a different type is different material, so a keys.toml type
# change is refused (14) with "type changed", never reported as a puzzling hash mismatch.
[objects.ec.type]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"   # canonical: keys.toml said "P-256"

# The identities: scheme -> SRI hash (sha256-<base64>). One object may have several, one per
# scheme; material links to another token's copy only through a scheme both compute.
[objects.ec.ids]
rfc7093m4 = "sha256-o7TM2/7T7zkp11y8VqqoC7aFJ5B5Uo6OPTmu2g3mkLI="   # SHA-256 of the canonical SPKI

[objects.aes]
# Secret keys are identified by what the token computes over a fixed label (a commitment). The
# label is recorded per object, so a future default can never change existing IDs.
commitmentLabel = "key-management/v1"

[objects.aes.type]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[objects.aes.ids]
# Only the schemes the spec's *declared* usage bits allow: CKA_SIGN -> cmac, CKA_ENCRYPT ->
# kcv-ecb. The token also reports CKA_DECRYPT = true by default, but defaults never choose a
# scheme, so there is no kcv-ecb-dec. Each is SHA-256 of the token's output, never the output
# itself (a MAC or ciphertext under the key).
cmac = "sha256-U+z6FH10sb4sC3p/oBtdfycPFwr9xPYO40kGMd8BYIA="
kcv-ecb = "sha256-pmbMg9OyHvW7WFjH4ah8rhAUqQiZBGMatbXaapkV9Uo="

[objects.cert.ids]
certhash = "sha256-lXNE6ciIfLkwGf6kf84qfibQ08d5fkPuGNKQ5KnyTMM="    # SHA-256 of the DER
rfc7093m4 = "sha256-8DQBv2fMc+z0Q5uxky0+5t9TS6MAHO07fNMqG9thHtM="   # its subject key's identity

[objects.data.ids]
valuehash = "sha256-TyepRDGGU8gW0rMMBWqSssutoJyBwJQwoYZw8UQ5VoU="   # SHA-256 of CKA_VALUE
```

## A realisation

Every realisation field belongs to one of three classes, and they are separate tables because
they mean different things to a verdict:

| Class | Fields | On a difference |
|---|---|---|
| **Compared** | `object`, `locator`, `specDigest`, `mode`, `schemes`, `binding`, `attestation`, `policy`, `immutables` | the run fails (14, or 10 for an identity), until reviewed and re-recorded |
| **Observed** | `observed.*`, and the `observation` entry it names | facts about the object and the token; a warning or a note |
| **Provenance** | `provenance.origin` | the object's history (an import); never a verdict |

Removing `observed`, `observation`, `provenance` and the whole `observations` table changes no
verdict (tested); a realisation naming an entry the lock lacks is an invalid lock (17). The
compared fields are required.

```toml
[realisations.ec.soft]
# The object this spec realised. A spec retargeted to another object is reported as such (14).
object = "ec"
# SHA-256 of the spec's canonical JSON (the object type plus its declared attributes). A changed
# spec fails `verify` (14, "changed in keys.toml") until `realise` re-records it.
specDigest = "sha256-2NHAGifN/zSvJ77DXQKy3lmAaVkj5Ci1IxO7QSius0A="
# How the identity was established, strongest first: direct (a hash of public material),
# commitment (the token computes over a label), wrap-rebind (through a temporary copy of an
# extractable key). A weaker mode later is a downgrade (14).
mode = "direct"
# The schemes this realisation computed and matched: computing fewer later is a downgrade (14).
schemes = ["rfc7093m4"]
# How the private key was bound to the public key its identity hashes: the token signed a fresh
# challenge the host verified (pop-sign; pop-sign-pin when the key is CKA_ALWAYS_AUTHENTICATE and
# each signature took a context-specific login; or pop-ecdh, pop-decrypt). `token-asserted` means the
# token's word only. Dropping from any pop-* to token-asserted is refused (14). Not stored, but
# derived from the binding, the class and the attestation kind: the `assurance` that `realise`
# and the Nix view report. A pop-* binding (or a tpm-certify attestation) is a "proof" no replay
# passes; a secret key's commitment is a "fingerprint" that anything which saw it can replay;
# public bytes are "public" (docs/REVIEW-2026-11-13.md, "Replay").
binding = "pop-sign"
# The observation this realisation was recorded with: a key of the `observations` table
# (below). Never a verdict.
observation = "sha256-…"

# Where it was found. Recorded so a moved locator is reported as a moved locator (14), not as an
# unexplained hash mismatch.
[realisations.ec.soft.locator]
CKA_LABEL = "ec"
CKA_ID = "0e"

# Policy: every boolean the class may carry that the token shows (closed-world), declared or not;
# here SoftHSM's defaults CKA_DECRYPT, CKA_UNWRAP, CKA_SIGN_RECOVER = true are visible too. These
# attributes *can* change on a token (C_SetAttributeValue), so a change is drift to review (14),
# which `realise` re-records.
[realisations.ec.soft.policy]
CKA_SIGN = true
CKA_SENSITIVE = true
CKA_EXTRACTABLE = false
CKA_DECRYPT = true          # a token default the spec did not ask for
# ... the rest of the class's booleans

# Immutables: set by the token when the key was made, and no operation can make them true again.
# Kept apart from policy because the meaning differs: a flag that was true and is not any more
# means the object was *replaced* (e.g. re-imported), which is refused even when writing the lock
# — the material needs a new object name.
[realisations.ec.soft.immutables]
CKA_LOCAL = true                            # generated on this token
CKA_NEVER_EXTRACTABLE = true
CKA_ALWAYS_SENSITIVE = true
CKA_KEY_GEN_MECHANISM = "CKM_EC_KEY_PAIR_GEN"

# Observed: facts about the object at the time, which never decide a verdict.
[realisations.ec.soft.observed]
# The RFC 7512 URI consumers use: a pure locator (the token serial, never a module path).
uri = "pkcs11:token=xv;serial=b19136a55523f406;object=ec;id=%0E;type=private"
# What the duplicate-CKA_ID check could see: "user" (logged in) or "public". Going from user to
# public warns: a public session cannot see a second private key under the same CKA_ID.
session = "user"
```

An object moved in by `camigrate` (public objects since MIGRATE phase 2) also records where it came from. It is
the object's history, so re-recording the same object keeps it:

```toml
[realisations.ec.soft.provenance.origin]
from = "softhsm"                    # the source token
method = "rsa-oaep-sha1+aes-kwp"    # a method name (MIGRATE.md, "Frozen names and formats")
exposure = "sealed"                 # the exposure level the path had
declared = true                     # only for a vendor method: the level is its own declaration
```

## Observations

What a realisation saw of its module and token is stored once per distinct value, keyed by the
SRI SHA-256 of the entry's canonical JSON (RFC 8785, as the spec digest). Realisations recorded
with the same module build, token, provider, cakeys version and mechanism list name the same
entry; one recorded through another module names another. A module update therefore shows in the
diff as one new entry and one changed `observation` line per realisation re-recorded. A write
drops the entries no realisation names any more, and so does `gc`.

```toml
[observations."sha256-…"]
# Which software interpreted the token: the cakeys provider and version. A different provider
# warns; a different cakeys version is a note.
provider = "softhsm"
cakeysVersion = "0.1.0"
# The module capability profile the token resolved to (PROVIDERS.md D8); absent when none is
# committed for it. Another profile is a note.
profile = "softhsm/2.7"
# Mechanisms the token offered (the Nix library's `functions`); one that vanishes warns.
mechanisms = ["CKM_ECDSA", "CKM_ECDSA_SHA256"]   # ... trimmed

# Which PKCS#11 library answered: C_GetInfo, and the file the dynamic loader mapped (symlinks
# resolved, whatever named it: keys.toml's module, its $NAME, --module or a bare name found by
# the library search) with its hash. A different build identity (description, manufacturer,
# version, cryptoki) warns, and so does another hash at the same path (replaced in place, which
# a path outside the Nix store cannot show); the same build from another path — a Nix rebuild —
# is only a note.
[observations."sha256-…".module]
path = "/nix/store/xb35g93pcvyyjrpjq1l6brdx6x8v3z6w-softhsm-2.7.0/lib/softhsm/libsofthsm2.so"
hash = "sha256-Pwmq/S/L0HNdKn4lLgttPZw1nUufTAT2+wgyB3cYOZk="
description = "Implementation of PKCS11"
manufacturer = "SoftHSM"
version = "2.7"      # raw CK_VERSION major.minor (ykcs11 2.7.3 shows as "2.73")
cryptoki = "3.2"

# Which device (C_GetTokenInfo). A different token warns.
[observations."sha256-…".token]
model = "SoftHSM v2"
serial = "b19136a55523f406"
firmware = "2.7"
```

An entry is the one lock table that takes keys this cakeys does not know (a newer version's):
they load with a warning and are kept when the lock is rewritten. An unknown key anywhere else is
refused (17). The key is not recomputed on load, so such an entry keeps its key.

Which entry is a token's *current* one is answered only when every realisation on the token
names the same entry. Otherwise `validate`'s profile gate and `export --dry-run` for a token that
does not open say so and name `realise`, which re-records each realisation with what it sees now.

Two more realisation shapes worth seeing:

```toml
# A secret key, identified by commitments; its policy carries the one list-valued attribute.
[realisations.aes.soft]
mode = "commitment"
schemes = ["cmac", "kcv-ecb"]
[realisations.aes.soft.policy]
CKA_ALLOWED_MECHANISMS = ["CKM_AES_CMAC", "CKM_AES_ECB"]   # sorted, duplicate-free

# A key whose spec declares no usage bit that allows a commitment, but which is extractable:
# wrapped under a session key into a temporary copy that may compute every scheme, then both
# destroyed. Weaker than `commitment`, so recorded as its own mode.
[realisations.wrapped.soft]
mode = "wrap-rebind"
schemes = ["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"]
```

And an attestation, from a YubiKey realisation with `attestation = true` (§3.7):

```toml
# Signed provenance for *this* device, so it lives on the realisation, not in the object's ids:
# the same material on another token attests differently or not at all. It never replaces the
# portable identity (rfc7093m4 here) — both must match.
[realisations.rw-test-yubikey.yubikey.attestation]
kind = "yubico-piv"     # or "tpm-certify"
# The trust anchor the evidence was verified to: the Yubico root's SPKI (for a TPM, the
# Attestation Key's). Another anchor fails (14).
root = "sha256-H0PiuI6WSl0DuAWLuqztaBmcklYgDxuyjqqy+CoeBvI="
# The canonical digest of what the attestation asserts (firmware, serial, PIN and touch policy,
# the attested key). Another ID under the same anchor fails (10).
id = "sha256-ZksMSOtJ2hgO/UZqtKLLVWmYXOko4O1YP0F3lhXVDA4="
```

## How a write behaves

`realise` and `delete` write the lock by default (`--no-update-lock` compares only), and a write
only *fills gaps*: what the lock lacks is recorded (first use included), but a locked ID, type,
binding, attestation or immutable is never overwritten. Those changes fail even when the lock is
written — different material needs a new object name. Policy and spec drift, which can be
legitimate, are re-recorded by a write after you review the diff. The property tests
(`crates/core/tests/properties.rs`) check exactly these rules.

Lock invariants are checked on load (17): every ID and digest is a 32-byte SRI; a realisation's
`object` exists and its `schemes` are among the object's IDs; no two objects of one class share
an ID under one scheme (one object per material); `pairs` are mutual where both sides are present;
only private-key realisations have a `binding`; an attestation never stands without a portable
scheme; a realisation's `observation` is a key of the `observations` table; an `origin` names a
known method.

A real lock to read alongside: [`examples/yubikey-secureboot.lock`](../examples/yubikey-secureboot.lock)
(RSA keys and their certificates, adopted read-only with `publicOnly`).
