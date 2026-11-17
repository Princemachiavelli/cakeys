# Key files as an origin

Planned 2026-11-16, against `origin/main` at `2120ec1`. Built the same day: F1–F6, stages F-a
to F-c, the raw files of F-d and cakeys' side of F-e. See "Built" at the end for what was
left out and why. "Where things stand" describes the code before this work.

**Goal.** A key or other object can be *born in a file*: a PEM or DER on disk that existed
before any token did. The first use is populating SoftHSM tokens from the key files and
certificates a deployment already holds. Today that takes `pkcs11-tool --write-object` and
an `origin = "adopt"` pair, so nothing records where the material came from, and nothing
checks that a second token got the same key.

Evidence tags, as in [CAPROBE.md](CAPROBE.md): **[run]** verified in this repo, **[src]** read
in this repo's source, **[todo]** not verified yet.

## Where things stand

- `origin` is per pair (spec × token) and has three values: `create`, `import` and `adopt`
  (`KeyOrigin`, `crates/core/src/config.rs`). At most one pair per object says `create`, which
  makes it the object's birthplace (`check_origins`) [src].
- camigrate already reads key files. `camigrate import --in <file> --passphrase-file` reads two
  formats: an encrypted PKCS#8 PEM (`pkcs8-pbes2`) and a PKCS#12 (`pkcs12`)
  (`crates/camigrate/src/file.rs`). It then creates the key through
  `host::create_and_record` and records `provenance.origin = { from = "file", method, exposure
  = "file" }` [src].
- That path has two limits:
  1. **It finds its object by the lock.** It needs a locked private key with the file's
     `rfc7093m4`, otherwise it exits 14. `create_and_record` also refuses a private key the lock
     pins nothing for (`HashMismatch`, 10) [src]. So a file can only re-import material that a
     token created first. It can never be where the material starts.
  2. **It reads only the formats camigrate writes.** Deployments mostly hold something else:
     plain `PRIVATE KEY`, `RSA PRIVATE KEY` (PKCS#1) and `EC PRIVATE KEY` (SEC1). A PEM with a
     key and its certificate is common too. Even OpenSSL's own default PKCS#12 does not read:
     `openssl pkcs12 -export` (3.5.9) puts the certificate bag in a PBES2-encrypted container
     [run], and the reader takes only plain `data` containers (`octets`, "not data") [src].
- cakeys handles no key material: a `cakeys` build carries no migration code
  ([CAMIGRATE.md](CAMIGRATE.md)). That stays true. Every verb here is camigrate's.
- Token initialisation (`softhsm2-util --init-token`) stays outside cakeys, as it is today.

## Decisions

**F1. `origin = "file"` is a fourth origin.** It is the birthplace of an object whose
material starts outside any token. It is a birthplace like `create`, so the one-birthplace rule
covers it: an object has `create` pairs or `file` pairs, never both (17 at load). Unlike
`create`, an object may have several `file` pairs, because the material is fixed by the file
and every pair reads the same bytes. Populating several SoftHSM tokens from one PEM is the
point. The object's other pairs may still `import` it from a token, or `adopt` it.

**F2. The path is on the object, in its `migrate` table.** One object is one material, and
here one file. Putting the path on the object means two tokens can never be populated from
two different files under one object name. Only camigrate reads it, so it goes in the
`migrate` table (review C3: a tool's settings sit in that tool's table). cakeys reads only the
pair's `origin`.

```toml
[objects.web-tls]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"
# Where the material is born. `$NAME`/`${NAME}` as for `module`: resolved when camigrate reads
# it, not at load, so hosts that only `check` load the same keys.toml without the file.
migrate = { file = "$WEB_TLS_KEY" }

[objects.web-tls-cert]
class = "CKO_CERTIFICATE"
certificateType = "CKC_X_509"
# The same file may serve several objects: each takes the block of its own class (F4).
migrate = { file = "$WEB_TLS_KEY" }

[objects.legacy-signing]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
# An encrypted file names its passphrase like a token names its PIN: passphraseFile or
# passphraseEnv. `camigrate import --passphrase-file` overrides it for one run.
migrate = { file = "/run/secrets/legacy.p12", passphraseFile = "/run/secrets/legacy.pass" }

[specs.web-tls]
object = "web-tls"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
tokens.softhsm-a = { locator = { CKA_LABEL = "web-tls", CKA_ID = "01" }, origin = "file" }
tokens.softhsm-b = { locator = { CKA_LABEL = "web-tls", CKA_ID = "01" }, origin = "file" }

[specs.web-tls-cert]
object = "web-tls-cert"
tokens.softhsm-a = { locator = { CKA_LABEL = "web-tls", CKA_ID = "01" }, origin = "file" }
```

Load rules (17):

- `origin = "file"` only on an object with `migrate.file`.
- An object with `migrate.file` has no `create` pair.
- `publicOnly` pairs are never `file`, as they are never `import`.
- `attestation = true` on a `file` pair is refused when the provider cannot attest an
  imported key (ykcs11), as camigrate D8 already does for imports.
- A private or secret key's `migrate.file` may not be under `/nix/store`, which is
  world-readable. A literal path is checked at load (17). A `$NAME` path is checked when
  camigrate resolves it, with the same exit code. The Nix library must pass the path as a
  string, never as a Nix path, which it would copy into the store. A certificate, public key
  or public data object from the store is fine.
- Unchanged: certificates, public keys and data objects default to `adopt`. They may now also
  say `file`.

The `migrate` table is in no digest, and it is not part of the type the lock pins. The lock's
`objects.<o>.type` is a serialised `ObjectCfg` [src], so the table goes on a keys.toml-only
wrapper around `ObjectCfg`, never into `ObjectCfg` itself. Otherwise a per-machine path would
churn the lock. The same holds for `passphraseFile` and `passphraseEnv`.

Rejected alternative: the path on each pair (`origin = { file = "..." }`). It reads well for
one token. But it lets two pairs of one object name two files, and then the lock is the only
thing that notices.

**F3. The file's identity is the object's first use.** When the lock pins nothing for the
object, the file sets its identity. The first `file` pair imported records the identity
through `ops::lock_import`, with `LockWrite::Record`, the same path `cakeys lock` uses for an
adopted key. It exits 0; 18 stays `check`'s alone. Once the lock pins the identity, the file
is checked against the lock on the host before anything is written (10). That check covers
every pair not realised yet, on any token and in any later run. A pair already realised is
verified on its token and its file is not read again, so a file replaced on disk is caught
only when it is next imported somewhere. Reading it on every re-run would need
`--allow-host-plaintext` on every re-run. New material needs a new object name, as
[CONFIG.md](CONFIG.md) already says for any object.

- A private key is identified by `rfc7093m4` of the SPKI derived from the file's key, which
  is computed already (`plaintext::spki_of_pkcs8`). After the import, the token's own public
  half has to hash to the same value.
- A secret key's commitments (`cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`, HMAC) are computed on the
  host from the plaintext, under the object's commitment label. The token then has to compute
  the same ones. That is new code in `cakeys_core::id`: the host side of each scheme the spec's
  usage bits choose (DESIGN §3.1), using RustCrypto's `aes`, `cmac`, `hmac` and `des`. It gives
  a secret key the same check before writing that a private key already gets.
- Certificates, public keys and data objects are identified as today (`certhash`, the SPKI's
  `rfc7093m4`, `valuehash`), computed on the host from the bytes before `C_CreateObject`.

**F4. Formats are what deployments hold, recognised by content, not by extension.** Every
private-key format is normalised on the host to PKCS#8 `PrivateKeyInfo`, so `private_from_pkcs8`
and `create_and_record` stay the one path. Each object reads its file on its own, so a
PKCS#12 two objects name is opened twice (its KDF runs twice).

| In the file | Read as | Method recorded |
|---|---|---|
| `PRIVATE KEY` PEM, or PKCS#8 DER | the key | `pkcs8` (new) |
| `RSA PRIVATE KEY` PEM, or PKCS#1 DER | the key, wrapped into PKCS#8 | `pkcs1` (new) |
| `EC PRIVATE KEY` PEM, or SEC1 DER | the key; the curve from its parameters must equal the object's (17), and a SEC1 key without parameters takes the object's curve | `sec1` (new) |
| `ENCRYPTED PRIVATE KEY` PEM | as today | `pkcs8-pbes2` |
| PKCS#12 | as today, plus a PBES2-encrypted certificate container, which is OpenSSL 3's default; it is decrypted under the file's passphrase. Certificate bags beyond the first are candidates for F4's leaf rule | `pkcs12` |
| `CERTIFICATE` PEM, or X.509 DER | a certificate | `public` |
| `PUBLIC KEY` PEM, or SPKI DER | a public key | `public` |
| any bytes (a `CKO_DATA` object) | the value, as it is | `public`, or `raw` for a private data object |
| a `CKO_SECRET_KEY`'s value: its bytes, or hex or base64 text of them | the key value, `valueLen` long; see "Secret-key files" below | `raw` (new), whatever the spelling |

- **Secret-key files** hold the value's bytes, or hex digits (either case) or padded standard
  base64 of them. Whitespace anywhere in text is ignored, since `xxd -p` and base64 tools wrap
  their lines.
  - `migrate.encoding = "raw" | "hex" | "base64"` says which. The value read must then be
    `valueLen` long, when the object has one.
  - Without it, the object's `valueLen` decides by length. Exactly `valueLen` bytes are the value,
    checked first and on the untouched bytes, because a key's bytes may include whitespace.
    Otherwise the file is hex of `valueLen` bytes (2 × `valueLen` digits) or base64 of them
    (4 × ⌈`valueLen`/3⌉ characters). Those lengths never coincide, and a refusal (17) names
    each one.
  - Load refuses (17) a secret key with `migrate.file` and neither `valueLen` nor `encoding`. A
    key type's fixed length counts as a `valueLen` (DES3: 24). Without either, nothing tells
    the spellings apart: a 32-character AES file could be the bytes of an AES-256 key, hex of
    an AES-128 key or base64 of an AES-192 one. The first file read pins the object's identity
    (F3), so a guess would be pinned for good.
  - The method stays `raw`, as a key's PEM and DER both record `pkcs8`. The encoding is in no
    digest, like `file`.
  - `encoding` applies to secret keys only (17 elsewhere). A data object's value is its file's
    bytes, hex text included.
- **A file with several PEM blocks** (key, leaf, chain) serves each object the block of its
  class.
  - A private key object takes the file's one private key; two keys in one file are 17.
  - A certificate object takes the one certificate whose public key is the file's private key
    when the file has one. Otherwise it takes the only certificate; several with no key are
    17.
  - A public key object takes a `PUBLIC KEY` block when there is one, else the public half of
    the file's private key. A private key's own public half needs no object of its own:
    `create_and_record` makes it, as now.
- **Refused, each with the command that converts it (17):**
  - OpenSSL's legacy encrypted PEM (`Proc-Type: 4,ENCRYPTED` with `DEK-Info`, a one-pass MD5
    KDF): `openssl pkcs8 -topk8 -v2 aes-256-cbc`.
  - `OPENSSH PRIVATE KEY`: `ssh-keygen -p -m PKCS8`.
  - A PKCS#12 from before OpenSSL 3, or from `-legacy` (a SHA-1 MAC, RC2 or 3DES bags): the MAC
    is refused as today, and so is any non-PBES2 bag. Re-export it:
    `openssl pkcs12 -in old.p12 -legacy -nodes | openssl pkcs12 -export -out new.p12`.
- Every new method name joins `Method::from_name` and its frozen list. Otherwise a lock
  carrying it would fail load (`provenance origin method '…' is unknown`, config.rs) [src].

**F5. Exposure is `file`, and the flags stay what they mean today.** This amends
[CAMIGRATE.md](CAMIGRATE.md):

- D2's `file` row covers a plain PEM as well as a passphrase-protected file. Both are
  plaintext-equivalent at rest.
- D4's frozen method table gains `pkcs8`, `pkcs1`, `sec1` and `raw`.
- D1's "a move lands only on an `import` pair" gains "or, from a file, on a `file` pair".
- D2's `public` row says a private data object has no method (15). From a file it now has
  one, `raw`, with exposure `file`. Between tokens it still has none.

A private or secret key read from a file is plaintext on the host, so its import needs `--allow-host-plaintext`, as
the `file` exposure always has. A passphrase is needed only for the encrypted formats.
Certificates, public keys and public data objects need neither: their exposure is `public`.
The lock records `provenance.origin = { from = "file", method, exposure }`, the same table an
import from a key file writes today. The file's path is never recorded, since it is per
machine. What a file-born key shows is recorded like any import: `CKA_LOCAL = false`,
`CKA_ALWAYS_SENSITIVE = false` and `CKA_NEVER_EXTRACTABLE = false` (immutables, never
declared, `attrs.rs`) [src].

**F6. One verb: `camigrate import --token <t>` without `--in`.**

```console
$ camigrate import --token <t> [<object> ...] [--spec <s> ...] [--dry-run] \
    [--allow-host-plaintext] [--passphrase-file <file>]
```

- Without `--in`, it imports every pair on `<t>` that says `origin = "file"`, each from its
  object's `migrate.file`. Naming objects narrows the run.
- With `--in`, it keeps today's meaning: the lock must already pin the key (14 otherwise), and
  the key may now also land on a `file` pair. First use comes only from the object's declared
  `migrate.file`, never from `--in`. Otherwise a mistaken `--in` could pin the wrong key, and
  the declared file would then fail with 10 for good.
- `--dry-run` is the planner, as in D9. Per object it checks:
  1. that the file is there and opens;
  2. its format and method;
  3. its identity against the lock (first use, or 10);
  4. the target's capability profile (`C_CreateObject` of the class and key type; the rows the
     `host` path already consults);
  5. that the locator is free.

  It writes nothing.
- Each pair is taken on its own, as in camigrate D5 for import: every failure is reported, and
  the run exits with the first. A pair already realised and verified is `AlreadyThere`, so a
  re-run of the whole token is a no-op.
- Today a key file lands only on an `import` pair (`import_target`, `specs_import`,
  `no_import_pair` in `crates/camigrate/src/lib.rs`) [src]. Those checks take `file` pairs too,
  but only when the bytes come from a file: `migrate` from a token still needs `import`.
- `cakeys create` passes over `file` pairs, giving a reason as it does for `import` pairs
  (`ops.rs`, the `KeyOrigin` match) [src]. `cakeys lock` and
  `check` on a `file` pair whose object is missing say what makes it: `camigrate import --token
  <t> <object>`. Today's NotFound text names `cakeys create`.
- Refused inside a Nix build, as is every writing verb (camigrate D8).

## Stages

| Stage | What | Size | Depends on |
|---|---|---|---|
| F-a | `KeyOrigin::File`, the object's `migrate` table (`file`, `passphraseFile`, `passphraseEnv`) on a keys.toml wrapper outside the locked type, the F2 load rules; CONFIG.md, DESIGN §4.1, CAMIGRATE.md D1/D2/D4 (F5) and the annotated example | S | — |
| F-b | Formats: a `keyfile` reader in camigrate (PEM blocks and DER sniffing, PKCS#1 and SEC1 into PKCS#8, the refusals with their hints); new `Method`s; unit, property and fuzz tests (a `keyfile` fuzz target beside the bundle's) | M | — |
| F-c | First use (F3) for private keys and public objects: `create_and_record` and `public::create` take "the lock pins nothing, this pair is a birthplace"; `import` without `--in`; the dry run | M | F-a, F-b |
| F-d | Host-side commitments for secret keys (F3), and `raw` secret-key and private data-object files | M | F-c |
| F-e | cakeys' messages for missing `file` pairs; `create` passing over them; the Nix library, NixOS module and docs (a populate unit that runs `camigrate import` after token init, outside the build) | S | F-c |

S is a day or less, M two to four days.

## Tests

On SoftHSM, through `scripts/local-tests.sh`, with kryoptic as a second target where it is
cheap. Existing fixtures: `crates/cli/tests/fixtures/tpm-import-p256.pem` and `adopt-cert.der`.
New fixtures are generated in the test with `openssl` into a temporary directory, so the
legacy formats come from the tool that writes them in the field.

- **Population.** One P-256 PEM key plus certificate populates two SoftHSM tokens. The first
  pair records the identity, the second verifies against it, and `cakeys check` then passes on
  both.
- **Re-run.** A second `import --token` writes nothing and exits 0.
- **Changed file.** Another key under a pinned object gives 10, with nothing written on the
  token, checked by listing its objects.
- **Formats.** Each row of F4 round-trips to the same `rfc7093m4`: PKCS#8, PKCS#1, SEC1 with
  and without parameters, encrypted PKCS#8 and PKCS#12. Ed25519 through PKCS#8. Each refusal
  gives its exit code and hint.
- **PKCS#12 from OpenSSL.** A default `openssl pkcs12 -export`, with its encrypted certificate
  container, imports the key and its certificate. A `-legacy` export is 17, with the re-export
  hint.
- **Secret keys.** An AES-256 raw file whose host commitments match the token's. The same key
  as hex and as base64, with and without `encoding`, imports as that key; an encoding said
  wrongly is 17 (`every_spelling_of_a_secret_key_imports_as_the_same_key`).
- **Private data objects.** One with `CKA_PRIVATE = true` imports only behind
  `--allow-host-plaintext`, and its `valuehash` is read back under the login.
- **The file is left alone.** After a run, success or failure, the source file's bytes and mode
  are unchanged.
- **Load rules.** Each F2 rule's 17, including `create` beside `file`, a `/nix/store` key path,
  and `file` without `migrate.file`; and F4's: a secret key's file with neither `valueLen` nor
  `encoding`, and `encoding` on another class or without `migrate.file`.
- **Dry run.** For every fixture × {SoftHSM, kryoptic}, the dry-run verdict is the outcome
  (D9's property, extended to a file source).

## Settled (2026-11-16)

1. **Private data objects come from a file.** They need `--allow-host-plaintext`, the method
   is `raw` and the exposure `file`. Load already requires the spec to declare
   `CKA_PRIVATE = true`, which is the promise `lock` relies on: the value is random, so its
   `valuehash` in the lock tells nothing. Between tokens camigrate still moves none (15,
   OPEN.md).
2. **Older PKCS#12 is refused** (17), with the re-export command in the message (F4). A SHA-1
   MAC and RC2 or 3DES bags are not read, not even with a warning.
3. **Secret-key files may be hex or base64; data files are bytes only.** Revised later on
   2026-11-16. The first answer was bytes only, with no `encoding` setting and a hint for a
   file of hex digits. Deployments hold keys as text, so a secret key's file is now its bytes,
   hex or base64, told by `valueLen` or said by `migrate.encoding`, and load requires one of
   the two (F4, "Secret-key files"). Both stay, though `valueLen` alone always decides: an
   encoding said outright needs no length.
4. **camigrate deletes nothing.** It never removes, shreds, moves or rewrites a source file, and
   it does not track one. A deployment that wants the file gone after populating removes it
   itself, or serves it from a secrets manager's runtime path so it is never at rest outside
   it.

## Built (2026-11-16)

Where each part lives:

- **Config (F1, F2):** `KeyOrigin::File`, `ObjectMigrateCfg` and `Config::object_migrate`, kept
  apart from `ObjectCfg` by a keys.toml-only `ObjectEntry`. `Config::object_file` resolves the
  path and keeps secret material out of `/nix/store`; `check_origins` holds the load rules
  (`crates/core/src/config.rs`).
- **First use (F3):** `reconcile` lets a `file` pair's import be a first use. camigrate puts
  the IDs the host computes from the file into the lock before the token is written, so the
  token must show exactly them. The lock is restored when it does not (`from_its_file`,
  `crates/camigrate/src/lib.rs`).
- **Formats (F4):** `crates/camigrate/src/keyfile.rs`. In `file.rs`, PKCS#12 now reads
  OpenSSL 3's encrypted certificate container and every certificate bag, and refuses legacy
  schemes with the re-export hint. The new methods are `pkcs8`, `pkcs1`, `sec1` and `raw`
  (`crates/core/src/migrate.rs`). A secret key's hex or base64 file: `secret` and `detect` in
  `keyfile.rs`, `migrate.encoding` (`Encoding`) and its load rules in `config.rs`.
- **The verb (F6):** `camigrate import --token <t> [<object> ...]`.
  - `--in` now lands on `file` pairs too.
  - cakeys' `create` passes over `file` pairs.
  - When a `file` pair's object is missing, `lock` and `check` name the command that brings it
    (`absent`, `crates/pkcs11/src/ops.rs`).

Found by running it: SoftHSM makes a data object private unless told otherwise [run]. So a
data object whose spec declares no `CKA_PRIVATE` is now created with `CKA_PRIVATE = false`
(`public::template`). This applies to moves between tokens too.

Tests:

- `keyfile.rs`'s unit tests cover every format, refusal and type check against fixtures that
  OpenSSL 3.5.9 wrote (`crates/camigrate/tests/fixtures/keyfiles/`, made by `make.sh` there).
- `objects_born_in_files_read_their_migrate_file` covers the load rules.
- `crates/camigrate/tests/from_files.rs` runs on SoftHSM, with kryoptic as the second token
  where it is set up. It covers:
  - population;
  - a re-run;
  - the same material on a second token;
  - another key under a pinned object (10, nothing written);
  - every private-key format as the same key;
  - the passphrase from keys.toml or the command line;
  - a legacy PKCS#12 refused.

Not built:

- **Host-side commitments for secret keys (F3, F-d).**
  - What happens instead: the first token's commitments pin a secret key. Every later token is
    checked after it creates the key, and what it made is removed on a mismatch, as for any
    import.
  - Why that is enough for now: every token here that takes a secret key can delete one. A
    host-side check matters for a token that cannot.
- **The capability profile in the dry run (F6, item 4).** The dry run checks the file, its
  format, its identity and the locator. A token that refuses the object is met when the object
  is created, and what was made is removed again.
- **A `keyfile` fuzz target, and a property test over formats.** The unit tests use fixed
  fixtures only.
- **The NixOS populate unit (F-e).**

The Nix library (`nix/lib.nix`) reads keys.toml with `fromTOML`, and its `type` now drops an
object's `migrate` table (checked in `checks.nix`'s `lib`). Any other use of the path is
camigrate's. A keys.toml written from Nix that interpolates a key file (`"${./k.pem}"`) puts the
key into the store. The store refusal then turns it away when camigrate reads it.

Also from this work:

- A key and its certificate taken from one encrypted file each name the passphrase: each
  object's own `passphraseFile` or `passphraseEnv`, or one `--passphrase-file` for the run.
- A certificate or public key read from a file that also holds a private key needs
  `--allow-host-plaintext`, because finding it decodes the key (`keyfile::holds_private_key`).
