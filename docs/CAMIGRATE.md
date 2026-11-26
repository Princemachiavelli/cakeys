# camigrate: moving keys between tokens

`camigrate` moves key material from one token to another. It wraps the key from token to token
where both modules support key wrapping. Where they do not, it moves the material through the
host or through a passphrase-protected file. Its `--dry-run` says, for each object, whether the
object can move and how. camigrate is the only tool that handles key material, and a `cakeys`
build contains no migration code. `cakeys` *verifies* a copy: `lock` on the second token compares
the material with the locked IDs. `camigrate` *makes* the copy, and then records it through the
same lock code path.

The claims about backends carry tags that say where they come from: **[run]** means that it was
verified by running it, **[src]** means that it was read in the module's source code, and
**[todo]** means that it is not verified yet.

## Command line

```console
$ camigrate transport [<object>] [--spec <s>] --token <target> [--out <file>]  # the transport key's public half, for offline exports
$ camigrate transport [<object>] [--spec <s>] --token <target> --trust-on <source>  # the source's SO trusts it (enforced)
$ camigrate export [<object> ...] --from <source> --to <t> [--to-transport-file <file>] \
    [--transport-spec <spec>] [--out <bundle>] [--dry-run] [--allow-host-plaintext]
$ camigrate export <object> --from <source> --to-key-file pkcs8|pkcs12 --out <file> \
    --passphrase-file <file> --allow-host-plaintext
$ camigrate import [<object> ...] --to <target> --in <bundle|file> [--spec <s> ...] [--dry-run] \
    [--transport-spec <spec>] [--passphrase-file <file> --allow-host-plaintext]  # a bundle or a key file, told apart by content
$ camigrate import [<object> ...] --to <target> [--spec <s> ...] [--dry-run] \
    [--allow-host-plaintext] [--passphrase-file <file>]       # objects born in files (FILE.md)
$ camigrate migrate [<object> ...] --from <a> --to <b> [--spec <s> ...] [--transport-spec <spec>] \
    [--dry-run] [--allow-host-plaintext]
```

Every verb takes cakeys' global options: `-c`, `-l`, `--module`, `--new-lock` (without it, a lock
that does not exist is refused with 17) and `--json`, which prints the `--dry-run` plans of
`export` and `migrate` as JSON. `import` and `migrate` print one JSON result per object, as an
array, whatever `--json` says. A run that wrote the lock exits 22, even when an object failed
after the write (CAKEYS.md, "Exit codes").

- `migrate` runs an export and then an import in one process, with the bundle in memory. It
  needs both tokens to be reachable from this host. It moves the objects that it names. When no
  object is named, it plans every object of which the source holds a realisation.
- `--dry-run` prints the plan, as a table or as JSON, and changes nothing. The real run executes
  the same plan (D9) and exits with the same code as the dry run. An `export` without names
  takes the objects that can move, so its dry run exits 15 only when no object can move,
  including when there is no object at all. An export to a key file with nothing to put in it
  exits 17. On `import`, `--dry-run` checks the bundle or the key file against the lock and the
  token, and it imports nothing. The dry run of an `import` or a `migrate` opens the token that
  it would write in read-only mode, and it refuses a write-protected token
  (`CKF_WRITE_PROTECTED`, 15) in the same way as the run does. The dry run of an `export` or a
  `migrate` also finds each object that it would move under its locator on the source, and it
  verifies the object against the lock with the functions that the run uses, so a second object
  under the locator is refused with 12 by both. A dry run that fails before its plans exist
  prints a blocked plan for each object, with the failure as the reason.
- `--spec` names the spec under which to realise an object, when the object has several specs on
  the target. A `--spec` that selects nothing (an unknown spec, or a spec of an object that is not
  moving there) is refused (17).
- `transport` names its key in the same way as cakeys' verbs name an object (CAKEYS.md): by the
  object, narrowed by `--spec`. When the object is left out, `transport` uses the token's
  `migrate.transportWith`. A name that keys.toml does not contain, or a token that names no
  transport key, is refused with 17.
- A bundle that holds only public objects needs no transport key and names none.
- `--to-transport-file` is the transport file of `--to`, for a token that this host cannot reach.
  A transport file of another token is refused (17). A bundle names the token that it is for
  (`target`), as the export's `wrote` line does, and `import` refuses the bundle on any other
  token (14).
- A key file holds one key. A PKCS#12 file also holds the certificate that the lock pairs with
  the key on the source. A plan that puts several keys into one file, or a plan for a PKCS#12
  file without a paired certificate, is blocked.
- A refused move says, for each blocked object, why it is blocked, as its `--dry-run` would.
- A transport key has at least 2048 bits. This rule applies to keys.toml, to a transport file and
  to a key found on a token.
- Every verb that writes is refused inside a Nix build (D8). The lock is written under `cakeys`'
  rules: camigrate holds the `.lck` sidecar lock, and it writes the lock file whole or not at all.

The exit codes are the shared ones (see the table in [CAKEYS.md](CAKEYS.md#exit-codes)):

- 0: done.
- 10: the identity of the material differs from the lock.
- 11: a token, an object or a key was not found.
- 12: a name is ambiguous.
- 13: the target refused. It found a bundle's blobs invalid, tampered with or wrapped to another
  key; a proof of possession failed; or the locator or the PIV slot is occupied.
- 14: the lock pins no IDs for the object, or a bundle is for another target or is sealed to a
  key other than the target's transport key.
- 15: an object cannot move as invoked, or the target lacks a capability. This includes an
  unwrap mechanism or an unwrap template that the target refuses.
- 16: the module or the device failed. A failed unwrap is reported in this way, as a bundle that
  may be damaged, because kryoptic reports a tampered blob as `CKR_DEVICE_ERROR`.
- 17: invalid input: keys.toml, a transport file, a bundle, another key's IDs, or a key file that
  does not open with the given passphrase. Exit code 10 is kept for material that differs from
  the lock.
- 21: a writing run cannot write the lock.
- 1: anything else (IO errors).

`import`, `migrate` and `import` from files print one row per object on stdout, as a JSON array,
whatever happens to each object. Each row is cakeys' row (its `exit`, the `rule` that refused it,
whether the `device` failed, and the `error`), together with the `method` by which the object
moved. A run that ends before it moves the first object prints these rows too, one for each object
that the run was to move, with the exit code and the reason of the failure. These are the objects
that the run names, or else the keys of the bundle, the objects that are born in files, or the
objects that the lock realises on the source. Such a failure is a `--spec` that selects nothing, a
token that does not open or that fails a search, or plans that are refused. When a named object is
blocked, no object moves, and the row of each object that could have moved says `ready`. A key
file's refusals are rows too. When an object reached its token but could not be recorded because
the lock could not be saved, its row has the exit code 21 and the rule `lock-writable`, and it says
how to record the object. No object after it moves. The run exits with the code of the first
failure, or with 22 if it recorded any object. In that case, the row of each failed object shows
that object's code, and a note on stderr says why the run exits 22.
In this way, a written lock is never hidden.
When no rule refused an object, the row's `rule` names the check that refused it ([CAKEYS.md](CAKEYS.md#rules-and-checks)).

A dry run's plans (`--json`) and rows name the checks that only the run decides (`deferred`). For
a sealed move, these checks are `import.unwraps` and `import.identity`. `import.unwraps` checks
that the blob is intact: it fails with 13, or with 16 when the module says only that the unwrap
failed. `import.identity` checks that what was unwrapped is the key that the lock pins: it fails
with 10, or with 13 when the key's proof of possession fails. For a host move or a file move, the
deferred check is `import.identity`, which checks that what the source handed over is the locked
key (10). The run therefore ends with the same code as its dry run, with the code of one of these
deferred checks, or with a device failure.

## Decisions

**D1. Exportability is decided when a key is created.** A key with `CKA_EXTRACTABLE = false`
never moves, and the lock treats `CKA_NEVER_EXTRACTABLE` as immutable: once it is true, a key that
later reports otherwise has been replaced. A key that is meant to migrate is declared extractable
from the start, on its one creation pair (`origin = "create"`). `--dry-run` reports this first,
for each object. A move lands only on a pair that says `origin = "import"` (17 otherwise), or,
when the move comes from a file, on a pair that says `origin = "file"` ([FILE.md](FILE.md)).

**D2. Exposure is named accurately, for each object, from the strongest level to the
weakest.** The names are frozen.

| Exposure | What it means |
|---|---|
| `public` | Certificates, public keys and public data objects. Nothing secret moves. A private data object has no method between tokens (15, [OPEN.md](OPEN.md)), and a data object that the source's lock does not record as `CKA_PRIVATE = false` counts as private. A data object that comes from its own file, and whose spec does not declare it public, moves by `raw` with the exposure `file`. |
| `enforced` | `sealed`, and in addition the source token allows no other wrapping: the key carries `CKA_WRAP_WITH_TRUSTED`, and the only wrapping key that the source trusts is the target's transport key (D3). |
| `sealed` | The material leaves the source only in wrapped form, under a key that is stored on the target, and the target unwraps it. The host never sees the material. This is the default. |
| `host` | The plaintext is in camigrate's memory, in buffers that are wiped when they are dropped (`Zeroizing`, `cakeys_core::plaintext`). camigrate hands it only to the target's import: `C_CreateObject`, which crosses p11-kit's socket when the module is forwarded, or `tpm2_ptool` through an in-memory file (phase 4 in Results, below). This level is used wherever the target imports only plaintext (a YubiKey, `tpm2_ptool`). It is allowed only with `--allow-host-plaintext`, and only within `migrate`. |
| `file` | A passphrase-protected file (PKCS#8 or PKCS#12) for a target that camigrate cannot reach, or the file in which an object is born, plain or encrypted ([FILE.md](FILE.md)). At rest, such a file is equivalent to plaintext. It is allowed only with `--allow-host-plaintext`, and a passphrase is used only for an encrypted file. |
| `impossible` | The key is not extractable, the source never exports, or the target lacks a type or a proof that the move needs. The plan gives the reasons. |

`enforced` is a separate level because any logged-in session can wrap a key that has only
`CKA_EXTRACTABLE = true` under a key that the session made. `sealed` describes what camigrate
does, not what someone who holds the PIN could do. `CKA_WRAP_WITH_TRUSTED` is the restriction that
the token itself enforces. A key whose lock does not record this attribute as `false` is planned
as a key that carries it, in the same way as a key whose `CKA_EXTRACTABLE` is not recorded is
planned as a key that stays on its token. In both cases, an attribute that the lock does not
record counts as the restriction. `enforced` needs the source's SO once per transport key
(`transport --trust-on`, with the admin credential `soCredentialFile`/`soCredentialEnv`, which
only SO steps read).

**D3. The transport key is an ordinary locked object.** The target holds an RSA key pair
(`CKA_UNWRAP = true`, not extractable) that keys.toml declares like any other key, and that the
target token's `migrate.transportWith` names. camigrate does not choose a key by what the key can
do, and `--transport-spec` overrides the choice for one run. The key's `rfc7093m4` is in the
reviewed lock, and the source wraps only to a public key whose hash equals it. In this way the
reviewed lock authenticates the public key. A transport file must pass the same check. It must be
the file of the token that `--to` names (17 otherwise), because the genuine file of another target
binds its own token's key just as well (`transport_files_are_bound_to_the_target_named`). Its
object must be the transport key that `transportWith` (or `--transport-spec`) names for that
token, realised there. It is not enough that the lock pins the key, because whoever swapped the
file may hold that key (`a_transport_file_of_another_pinned_key_is_refused`). An import requires a
bundle's transport key to be the same key (14 otherwise;
`bundles_are_bound_to_the_targets_transport_key`), and `transport --trust-on` applies the same rule
to the lock's key, including its size (`locked_transport_keys_are_held_to_one_rule`). The lock
must record the key as allowed to unwrap and as not extractable. A realisation that records no
`CKA_EXTRACTABLE` does not count as a transport key (14, or a blocked plan).

- **The lock records its public key** (`objects.<name>.publicKey`, a base64 SPKI) when the key is
  realised as a `migrate.transportWith` key, and the lock checks it against the key's `rfc7093m4`
  when it loads. Any host can then plan and export to that token from the lock alone. A target
  without a recorded public key is planned as blocked.
- **It proves possession by unwrapping** (`binding = "pop-unwrap"`), so it needs no
  `CKA_DECRYPT`. SoftHSM and kryoptic can do this [run]. tpm2-pkcs11 and ykcs11 never unwrap, so
  a transport key on them is refused (15) before anything is generated [run]. camigrate warns about
  a transport key that also decrypts, or whose `CKA_DECRYPT` the lock does not record, because the
  holder of the target's PIN could then `C_Decrypt` a bundle's key-encryption key. (That PIN
  holder can extract an extractable moved key anyway. A sealed move protects the material on its
  way, not from the target.)
- A transport file (`transport --out`) is used only when the source's lock pins its key. A file
  that is only consistent with itself is refused (17). Whether a source *trusts* the key is looked
  up on the source; the file never states it.
- **[todo] `CKA_UNWRAP_TEMPLATE`.** A template that makes each key that the transport key unwraps
  non-extractable would keep even the PIN holder from reading the key-encryption key. cryptoki
  0.12 can neither read nor set array attributes, and a strict template would break the
  direct-OAEP path (OPEN.md).

**D4. Methods have frozen names, like schemes.** camigrate chooses the method from the
intersection of the source's export capabilities and the target's import capabilities. It takes
the target's capabilities from the target's live mechanisms. When those are not available, it
takes them from the mechanisms that the lock observed for the target, and otherwise from a
transport file. The OAEP hash is the strongest hash that both sides support (SHA-256 between
kryoptic tokens, SHA-1 with SoftHSM). A probed row (`import.*`, `create.*`, `export.*`,
`unwrap.*`) decides for the type that it covers. A row that the probe could not decide (a no whose
evidence is a device failure, or an `[untested]` entry with the reason `device` or `cakeys`) is
unknown. The plan refuses such a row (15) as an unsupported capability, and it names the re-probe
that is needed.

| Method | Material | How |
|---|---|---|
| `public` | certificates, public keys, data | The bytes are copied, and the target creates the object with `C_CreateObject`. |
| `rsa-oaep-sha1+aes-kwp`, `rsa-oaep-sha256+aes-kwp` | private and secret keys | The source makes a fresh AES-256 KEK and wraps it to the transport key with RSA-OAEP. It wraps the key under the KEK with RFC 5649 (`AES_KEY_WRAP_PAD` or `_KWP`, whichever name each side uses). For `enforced`, and on a side that has no AES key wrap of its own (AWS CloudHSM's profile subtracts both), `CKM_RSA_AES_KEY_WRAP` does both steps and produces the same bytes: the KEK blob, then the key blob [run]. |
| `rsa-oaep-sha1`, `rsa-oaep-sha256` | small secret keys | The key is wrapped to the transport key directly. This is the path through p11-kit, whose RPC protocol drops AES key wrap. |
| `host-pkcs8`, `host-raw` | private, secret keys | The source wraps the key under a session KEK that camigrate made, camigrate unwraps it in memory on the host, and the target creates it with `C_CreateObject`. The exposure is `host`. |
| `tpm2-ptool` | EC (not P-521), RSA, HMAC | The host path, followed by `tpm2_ptool import`. |
| `piv-import` | RSA, EC P-256/384, Ed25519 | The host path, followed by ykcs11's `C_CreateObject` as the SO, into the slot that the locator names. |
| `pkcs8-pbes2` | private keys | The host path, and then the key is written as an EncryptedPrivateKeyInfo. The exposure is `file`. |
| `pkcs12` | a private key and its certificate | The host path, and then the key is written as PKCS#12. The exposure is `file`. |
| `pkcs8`, `pkcs1`, `sec1` | private keys | The key is read from the file in which the object is born (PEM or DER), normalized to PKCS#8, and then moved by the host path. The exposure is `file` ([FILE.md](FILE.md)). |
| `raw` | secret keys, private data objects | The file's bytes are used as they are, and the target creates the object with `C_CreateObject`. The exposure is `file`. |
| `tpm-duplicate` | keys for a TPM target | Not built. A duplication blob would be built on the host for the public key of the target's parent key. |
| `vendor:<provider>/<name>` | as the provider declares | A provider crate's own path (D10). |

**D5. The bundle is a versioned file, one per export** (for one source and one target), and it
never contains plaintext. RFC 5649 authenticates the key bytes, but not who wrapped them: the
transport key is public, so anyone can seal a key of their own to it.
Import recomputes every identity on the target and proves the binding, so a tampered or swapped
blob fails, and the bundle may cross untrusted channels. The exception is a key that nothing
proves. For an EC or Edwards private key under `binding = "token-asserted"`, the identity would
come from the public half that the bundle's own `publicKey` creates (a target such as SoftHSM
keeps no point with the private key), so `import --in` refuses such a key (14). `migrate`,
whose bundle never leaves the process, moves it. A wrapped private key is the PKCS#8 that
`C_WrapKey` produces. PKCS#12 or a CMS key package would need the plaintext on the host, which a
sealed move avoids. Named objects export all or nothing. Without names, export takes the objects
that can move and warns about the rest. A spec's `migrate.noExport = true` keeps its object on
its token and silences the warning, and by default a token's transport key also stays on its
token in this way. Import handles each entry on its own, reports every failure, and exits with
the code of the first failure, or with 22 if it recorded any object. The bundle names the token that it is for (`target`, version 2),
and `import` refuses the bundle on another token (14). Its keys unwrap only under the target's
transport key (its `transportWith`, or the `--transport-spec` that the export named),
never under whichever key the bundle names (14). A version-1 bundle names no target. camigrate
still reads it, checks it only against the target's transport key, and prints a warning.

**D6. Import is a `lock` that creates the objects from a bundle.**

- Import applies If-None-Match per object class: it never creates an object over an object of the
  same class under the locator. By PKCS#11 convention, a key, its public key and its certificate
  share one `CKA_ID`, so they move into one locator in any order. A public key object that
  already holds the key's public key is reused and never duplicated. `cakeys create` still refuses
  to create over anything under the locator.
- Import is the permitted exception to the rule that "`create` is refused when the lock already
  pins the material". Generated material could not match the lock, but imported material must
  match it.
- After it creates the objects, import realises them and compares the result with the bundle's
  IDs and the lock's IDs. A mismatch removes exactly what it created. Wherever a key is plaintext
  on the host (a `host` move, or a key file that `export --to-key-file` writes or that `import`
  reads), camigrate first checks the key's identity on the host, and it exits with 10 before
  anything is written.
  It computes a private key's `rfc7093m4` and every commitment that the lock pins for a secret key
  (`ops::check_identity`). ykcs11 cannot erase a key, so for a YubiKey this check is the only
  protection against importing a wrong key. For a key file, it is the only check at all, because
  whoever imports the file does not compare it with the lock.
- The unwrap template consists of the target spec's attributes, stated explicitly and completely,
  because kryoptic sets no usage attributes otherwise. The template leaves out each attribute
  whose `unwrap.template.*` row answers no (SoftHSM: `CKA_VALUE_LEN`).

**D7. The lock changes only on the target.** The target realisation gains
`provenance.origin = { from, method, exposure }` (with `declared = true` for a vendor method).
This record is provenance and never changes a verdict. The lock records state, not events, so
the source's entry does not change.

**D8. Export and import are admin operations.** They are refused inside the Nix build sandbox, as
a lock write is, unless the build declares that its keys are disposable
(`CAKEYS_ALLOW_NIX_STORE_KEYS=1`, docs/FILE.md). A YubiKey import needs the admin
credential and can never carry an attestation, so `attestation = true` on that target is refused
when the plan is made. A TPM import attests that the key resides in the TPM, not that the TPM
generated it (`CKA_LOCAL` is false).

**D9. `--dry-run` is the real planner.** One code path turns (objects, source, target) into a plan
for each object: the method, the exposure, and the reasons for everything that is impossible. The
plan also blocks a move whose result the target could not prove afterwards, because the spec's
binding needs a mechanism that the target lacks (for example, Ed25519 through p11-kit). The
planner asks the rules that each import asks before its write, with the same functions, on the
target that `--to` names, whether the export reaches that target or only its transport file.
These rules decide where the module can place the key (a PIV slot by `CKA_ID`, not f9: 17) and
the attestation that the spec opts into (15). On a target that a `migrate` reaches, the planner
also runs the import's own checks and checks that the locator is empty (13). A blocked plan exits
with the code of the refusal that blocked it, so the dry run exits as the run would. A rule that
the planner cannot decide (for example, because the provider is not in this build) is reported as
deferred. The main test is a property: for every source, target and class in the reference
matrix, the dry-run verdict equals the outcome.

**D10. Provider crates add their own methods, under a declared exposure.** A vendor provider
(Luna, CloudHSM, nShield, a vendor tool) contributes methods named `vendor:<provider>/<name>`.
Their names are frozen like those of the built-in methods, and each method declares its exposure,
the types that it moves and what it needs. The planner prefers the strongest exposure.
`--dry-run` marks a vendor's level as declared, and the lock records it as declared, because
camigrate cannot check it. The identity never comes from the vendor: after any import, camigrate
realises the object in the same way as a key that never moved.

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
version = 2                             # 2 names its target; version 1, which does not, is read with a warning
kek = "..."                             # the AES KEK under RSA-OAEP, shared by the sealed keys; absent if none
target = "kryoptic"                     # the token it is for, as the export named it (--to); import refuses it elsewhere
[source]                                # provenance, as in the source realisation
token = "softhsm"
provider = "softhsm"
[transport]                             # the key the keys are wrapped to; absent when only public objects travel
object = "import-kek"
rfc7093m4 = "sha256-..."
[[keys]]                                # one per key, each object once
object = "signing"
method = "rsa-oaep-sha1+aes-kwp"
exposure = "sealed"                     # what its method can be: sealed or enforced for a wrapped key (an own
                                        # kek means enforced), public for a public object; anything else is 17
commitmentLabel = "key-management/v1"   # secret keys, as in the lock
publicKey = "<base64 SPKI DER>"         # private keys: the public half the target creates; its hash is ids.rfc7093m4
# kek = "..."                           # a key's own KEK (CKM_RSA_AES_KEY_WRAP's first part): enforced, or from a source with no RFC 5649
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

Key files: a `pkcs8-pbes2` file is a PEM `ENCRYPTED PRIVATE KEY` (PBES2, PBKDF2-HMAC-SHA256 with
600 000 iterations, AES-256-CBC). A `pkcs12` file holds the same encrypted key in a shrouded key
bag, beside the certificate that the lock pairs with the object. Both are tagged with one
`localKeyId`, under an HMAC-SHA256 MAC (PKCS#12 KDF with 600 000 iterations, as many as for the
key). Each file holds one key and has mode 0600. An imported file names no object: camigrate finds
the locked private key by the key's `rfc7093m4`. A file that asks for more than 10 000 000 KDF
iterations is refused.

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
| SoftHSM 2.7 | `C_WrapKey` with AES-KW, AES-KW-PAD (RFC 5649), and RSA-OAEP with SHA-1 only [run]. Offers `CKM_RSA_AES_KEY_WRAP`, and the SO can create a trusted RSA public key [run] | `C_UnwrapKey` [run], but the `CKA_VALUE_LEN` of an unwrapped secret key reads 0, and the attribute is refused in the template [src]. Therefore sealed moves of secret keys into SoftHSM are blocked (`move.secret-unwrap` is no). `C_CreateObject` [run] |
| kryoptic 1.5.4 | `C_WrapKey` with AES-KW, AES-KWP, AES-GCM, and RSA-OAEP with SHA-1 and SHA-256 [run]. It cannot make an RSA public key trusted, so it is never an `enforced` source (`move.trusted-wrap` is no) [run] | `C_UnwrapKey`, which sets no usage attributes unless the template asks for them [run]. `C_CreateObject` [run] |
| p11-kit | What the module behind it offers, minus what the RPC protocol drops: AES-KW, AES-KW-PAD, `CKM_RSA_AES_KEY_WRAP` and `CKM_EDDSA` [run] | The same limits. The module behind it is unknown until keys.toml names its `provider`, and the plan warns until then |
| AWS CloudHSM 5.18 (hsm2m, FIPS and non-FIPS) | Lists `CKM_AES_KEY_WRAP` and `_PAD` with `CKF_WRAP \| CKF_UNWRAP`, but refuses both (`CKR_MECHANISM_INVALID`), and names no `_KWP` [run]. The client log asks for a mapping for the first one, `configure-pkcs11 --aes-key-wrap-mapping` [doc], which has not been tried. The probe subtracts them, and the composed method uses `CKM_RSA_AES_KEY_WRAP` (OAEP with SHA-1 or SHA-256, with RFC 5649 inside) [run]. Its vendor mechanism `0x8000216F` ("zero pad") is also RFC 5649, and `0x8000210A` is RFC 3394 over PKCS#5 padding [run]; camigrate uses neither | `C_UnwrapKey` with `CKM_RSA_AES_KEY_WRAP` [run]. Public halves only as private objects (`CKA_PRIVATE = false` is refused) [run]. It never imports Ed25519, which it holds as `CKK_EC` (a `CKK_EC_EDWARDS` public half is refused: `migration.refuses`), although it exports Ed25519 keys [run] |
| tpm2-pkcs11 1.10 | Never: it has no `C_WrapKey` or `C_UnwrapKey` [src] | `tpm2_ptool import` of EC (not P-521), RSA and HMAC keys [run]. Data objects only as private objects [src] |
| YubiKey PIV (ykcs11 2.7) | Never [src] | `C_CreateObject` as the SO, for RSA 1024–4096, EC P-256/384, Ed25519 and certificates [src, run]. No public key objects. Imported keys are never attested |
| Vendor HSMs | Vendor mechanisms and tools [todo] | The same [todo] |

## Results

Phases 0 and 1 ran on 2026-11-12, and phases 2 to 5 ran on 2026-11-14. The test names are in
`crates/camigrate/tests/`.

| Phase | Built | Found or decided |
|---|---|---|
| 0 | The spike (pkcs11-tool, SoftHSM ↔ kryoptic), and the cryptoki KWP patch (`nix/patches/cryptoki-aes-key-wrap-kwp.patch`, upstream draft `upstream/rust-cryptoki/PR-KWP.md`) | SoftHSM's AES-KW-PAD and kryoptic's AES-KWP are one format (RFC 5649) under two IDs. EC and RSA keys that were wrapped either way still sign correctly for their fixtures. The composed method works in both directions [run] |
| 1 | The planner and `--dry-run`; the capability hook that vendor crates used (D10; it has since been folded into the profiles, `Side::pkcs11`); the transport file | — |
| 2 | `public` moves (`public.rs`), recorded through `ops::lock_import` | tpm2-pkcs11 creates data objects only as private objects, so its profiles no longer accept public `CKO_DATA` |
| 3 | `sealed` (`sealed.rs`): bundles, `export --out`, `import`, `migrate`; one creation pair per object (`origin = "create"`), and targets with `origin = "import"`; `migrate.transportWith` and `pop-unwrap` | SoftHSM's `CKA_VALUE_LEN` after an unwrap (`move.secret-unwrap` is no); p11-kit needs its `provider` to be named (the layer's `requires-provider`) |
| 3b | `enforced`: `transport --trust-on`, `CKM_RSA_AES_KEY_WRAP` (the third cryptoki patch, `nix/patches/cryptoki-rsa-aes-key-wrap.patch`), and the bundle's per-entry `kek` | Both modules refuse to wrap a wrap-with-trusted key under an untrusted key. `CKA_TRUSTED` is set only at creation and only by the SO. kryoptic cannot trust an RSA public key [run: one-off PyKCS11 and Rust test programs, which were not kept; the results are recorded in the profiles' `[manual."trusted-wrap"]`] |
| 4 | `host` (`host.rs`): `Token::extract`, `cakeys_core::plaintext`, and `tpm2-ptool` through an in-memory file (`/proc/<pid>/fd/N`, because `tpm2_import` inherits no file descriptor) | The key enters `tpm2_ptool`'s Python process, and the user PIN is on that process's command line (there is no other option [src]). The plan states both facts as notes. The planner blocks moves whose result the target could not prove (Ed25519 into p11-kit) |
| 4b | `file` (`file.rs`): `pkcs8-pbes2` and `pkcs12` export and import; the crates `pkcs5`, `pkcs12` 0.2 and `cms` 0.3 (release candidates from the same RustCrypto line as `der` 0.8) | A wrong passphrase exits 17 and leaves nothing behind |
| 5 | `piv-import`, as the SO, with the identity checked on the host first | YubiKey 5C NFC FIPS 5.7.4, ykcs11 2.7.3 (`tests/yubikey.rs`, opt-in): a P-256 key from SoftHSM moved into retired slot 95 and proved possession. A second import into the occupied slot was refused (13) before anything was written. The slot was emptied by hand beforehand, because ykcs11 has no delete |

Two phases are not built: phase 6, the native `tpm-duplicate` (a duplication blob built on the
host, and `TPM2_Import` through tss-esapi), and phase 7, the vendor methods, which wait for
hardware. Both are in [OPEN.md](OPEN.md).

## Tests

- **The dry-run property** (D9) runs over the reference matrix: SoftHSM, kryoptic, p11-kit and
  swtpm/tpm2-pkcs11 as sources and as targets, every class, and the key types that each token
  takes. A move that is ready exits 22 (the lock was written) and records its `origin`, and
  `cakeys check` accepts it on the target with its proof of possession. A blocked move exits with
  the code of the refusal that blocked it (15, or the rule's own code: 17 for a PIV slot, 13 for
  an occupied locator), and nothing changes.
- **Refusals**, each with its pinned exit code: non-extractable keys, a source that never
  exports, a target that lacks a curve or a mechanism, host paths without the flag, an occupied
  locator, a transport key that the lock does not pin, a transport file or a bundle of another
  target, tampered or swapped blobs, another key's IDs, `attestation = true` on a YubiKey import,
  and a wrong passphrase.
- **Cleanup**: a failed import leaves nothing behind.
- **Formats**: unit, property and fuzz tests for the bundle parser, and round trips of both key
  file formats.
