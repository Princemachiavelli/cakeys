# Probed import and export

Planned 2026-11-16, against `origin/main` at `0b433d0`. Built the same day: P-a to P-e. See
"Built" at the end for where each part lives and where it departs from this plan.

**Goal.** caprobe measures what each object type can do to get into and out of a token, the
way it already measures generation and proofs. The hand-written rows that say this today, a
profile's `[migration]` table and its `move.*` rows, are replaced by probe output. That output
is regenerated and diffed like every other probed row. camigrate's planner then reads
measurements, not claims (`create`'s gate and `validate` are still to follow; "Built").

Evidence tags, as in [CAPROBE.md](CAPROBE.md): **[run]** verified in this repo, **[src]** read
in this repo's source, **[todo]** not verified yet.

## Where things stand

- **The probe imports nothing.** Its write probes generate keys (`Token::create`), prove
  possession, wrap and unwrap, and check deletion (`write_probes`,
  `crates/caprobe/src/probe.rs:655`). No probe calls `C_CreateObject` with key material, a
  certificate or a data value, or calls a provider's `import_plaintext` [src].
- **It exports one kind of key.** Every wrap probe wraps the same generated AES key:
  `probe_wrapping` (RSA-OAEP per hash, `probe.rs:1497`) and `probe_key_wraps` (each advertised
  key wrap, `probe.rs:1583`). No EC, Edwards or RSA private key and no other secret-key type
  is ever wrapped [src].
- **`move.*` rows are claims.** `move.export`, `move.unwrap`, `move.secret-unwrap` and
  `move.trusted-wrap` are `Capability::Move` (`crates/profile/src/capability.rs`).
  `Capability::probed()` is false for them, so the probe keeps them across regenerations and
  the diff never compares them [src]. In the committed profiles:
  - ykcs11 and both tpm2-pkcs11 profiles: `move.export` no, `move.unwrap` no;
  - SoftHSM: `move.secret-unwrap` no, because an unwrapped secret key reads `CKA_VALUE_LEN = 0` [run];
  - kryoptic: `move.trusted-wrap` no.
- **`[migration]` is hand-written** (`Migration`, `crates/profile/src/profile.rs:168`). It too
  is kept across regenerations and never compared [src].
  - `plaintext-import` is `create-object`, `tpm2-ptool` or `piv-import`. `plaintext-accepts` is
    rows of class, key types, curves and a min/max RSA size: what that path takes.
  - `public-accepts` lists the public classes `C_CreateObject` takes. Empty means every
    spec-compliant class.
  - `refuses` lists keys the module takes in by no import at all. Its one row: AWS CloudHSM
    refuses a `CKK_EC_EDWARDS` template [run].
  - Only ykcs11, tpm2-pkcs11 (swtpm and fTPM), aws-cloudhsm (non-FIPS) and the `swtpm` hardware
    profile carry rows. SoftHSM, kryoptic and kmsp11 fall back to the spec-compliant default.
- **What reads them** [src], each of which this plan changes:
  - `side_of`, `crates/camigrate/src/tokens.rs`: builds the planner's `Side` from the
    `move.*` rows and every `[migration]` field.
  - `Side::pkcs11`, `crates/core/src/migrate.rs`: the spec-compliant default when a row is
    absent. It exports, unwraps and imports public objects and plaintext keys with
    `C_CreateObject`.
  - `host()` (`crates/camigrate/src/plan.rs:337`) and the `refuses` block (`plan.rs:155`):
    the host path's import and its refusal.
  - `Token::accepts_public_key_objects`, `crates/pkcs11/src/token/host.rs`: reads
    `public-accepts`.
  - `Token::proof_side`, `crates/pkcs11/src/token/possession.rs:409`: `pop-unwrap` is refused
    where `move.unwrap` says no.
- **A deployment's own answers come first.** A lock's observation `capabilities` (docs/LOCK.md)
  decide before the module profile. Today they hold only `prove.*` and `generate.*` yes rows [src].

## Decisions

**M1. One probed row per object type and way in or out.** These are new `Capability`
variants, named like `generate.*`. Each name says the class, the key type and its curve or
size:

| Row | Means | `via` |
|---|---|---|
| `import.<CKK>.<on>` | A plaintext private key of this type gets in, and the token then shows that key | the path: `create-object`, `tpm2-ptool`, `piv-import` |
| `import.<CKK>.<len>` for secret keys | A secret key's value gets in, and the token computes the same KCV or HMAC as the host | as above |
| `create.CKO_PUBLIC_KEY.<CKK>.<on>` | `C_CreateObject` of a public key from its SPKI | — |
| `create.CKO_CERTIFICATE`, `create.CKO_DATA` | `C_CreateObject` of a certificate or a data object | — |
| `export.host.<CKK>.<on>` | An extractable key of this type is handed to the host by RFC 5649 (`Token::extract`) and is the material | the wrap mechanism |
| `export.sealed.<CKK>.<on>` | An extractable key of this type is wrapped toward another token's RSA key (`CKM_RSA_AES_KEY_WRAP`, or RSA-OAEP for a secret key) and unwraps to the material | the wrap mechanism |
| `unwrap.<CKK>.<on>` | `C_UnwrapKey` brings this type in, and it is the material wrapped | the wrap mechanism |
| `delete.<CKO>` | `C_DestroyObject` really removes an object of this class (the leftover check) | — |

- Two export rows, so a module that does one and not the other is described as it is: AWS
  CloudHSM refuses `CKM_AES_KEY_WRAP_PAD` but round-trips `CKM_RSA_AES_KEY_WRAP` [run].
- `<on>` is what `generate.*` already uses: a curve name, or a size in the unit the key type's
  own attribute uses. RSA is in bits (`CKA_MODULUS_BITS`, keys.toml's `modulusBits`:
  `import.CKK_RSA.2048`). A key type sized by `CKA_VALUE_LEN` is in bytes (keys.toml's
  `valueLen`: `import.CKK_AES.32`). The key type in the row names the unit, so parsing stays
  unambiguous (`On::Bits`, `On::Bytes`), and neither unit is converted to the other.
- `unwrap.template.CKA_VALUE_LEN` keeps its name. `Capability::parse` tells the two apart by
  the second part: `template.` or a `CKK_` name.
- `parse` takes a key type and a curve or size, as for `generate.*`. The probe tries the
  baseline curves, the RSA sizes `generate.*` tries up to `--rsa-max-bits` (`RSA_SIZES`), and
  AES 16, 24 and 32.
- `plaintext-import`'s path becomes the import row's `via`. So "how it imports" is said per
  type, and a module that imports some types one way and others another can be described.

**M2. Evidence is a round trip, checked on the host.** This is the probe's existing rule: a
wrap counts only when it unwraps back, and a proof only when the host verifies it.

- An **import** is yes when the token's object is the material given. For a private key, its
  public half's `rfc7093m4` equals the host's SPKI hash: the check `create_and_record` makes.
  For a secret key, the token's `kcv-ecb` (or HMAC commitment) equals the one computed on the
  host from the value. That needs the host-side commitments FILE.md F3 lists as not built yet,
  but a KCV for AES alone is a single AES-ECB block of zeros.
- An **export** is yes when the wrapped bytes unwrap to the same material. On the host, that
  means through `Token::extract` (RFC 5649 only, `host_extractable`). Or it is unwrapped back
  on the same token, and both copies show the same identity.
- A refusal's `CKR_*` is the *no* row's evidence. As today, a failure caused by an earlier
  operation (`CKR_OPERATION_ACTIVE`) is undetermined, never a row.
- An import is *no* only when every path the provider has was tried: `C_CreateObject`, then
  the provider's own `import_plaintext` where it has one (tpm2-pkcs11's `tpm2_ptool`), the
  path that worked in `via`. A path the probe cannot try writes no row and says why in
  `undetermined`. Otherwise a module that refuses `C_CreateObject` but imports its own way
  would read as importing nothing.
- One imported key proves several rows. It is imported extractable, then exported to the host
  and toward the transport key, and that blob is unwrapped back. Each step is compared with
  the embedded bytes.
- The keys imported are **fixed test keys embedded in caprobe**, never generated on the host.
  The profile must regenerate byte for byte, and generating a 16384-bit RSA key on the host
  would take minutes. The rows record answers, never key material; the keys are test keys and
  no secret. There is one per baseline curve, one per size in `RSA_SIZES`, and AES of 16, 24
  and 32 bytes. Like generation, RSA import stops at `--rsa-max-bits`, and the gate answers
  unknown above it.

**M3. Each hand-written row maps to probed ones.**

| Today | Becomes |
|---|---|
| `plaintext-import` + `plaintext-accepts` | `import.*` rows; the path in `via` |
| `public-accepts` | `create.*` rows |
| `refuses` ("by any import") | *no* on `import.*` and on `unwrap.*` for that type |
| `move.export` | any `export.*` yes; per type where the planner asks per type |
| `move.unwrap` | any `unwrap.*` yes (`proof_side` keeps reading the summary) |
| `move.secret-unwrap` | stays a claim for now: the reference SoftHSM carries the fix stock 2.7 lacks ("Built") |
| `move.trusted-wrap` | stays a claim unless the scratch token has an SO credential: marking a transport key `CKA_TRUSTED` needs SO login |

**M4. Precedence while both exist.** A lock observation decides first. A probed row comes
next, then a hand-written row, and then the spec-compliant default.

- During the change both kinds may sit in one profile. When a probed row contradicts a
  hand-written one, caprobe adds a note and the probed row wins. It is not a diff failure,
  because the hand-written row is what is being retired.
- "Unknown means try" holds only where a failed attempt can be undone. On a module that
  cannot delete a key (ykcs11), an unknown `import.*` is refused in the plan, never tried.
  Today nothing the planner reads says which modules cannot delete. A failed destroy is found
  at run time (`ops.rs`, `host.rs`), and the probe's leftover check writes only a note
  (`notes.destroy`). So P-d also makes "delete really deletes" a probed row (`delete.<class>`).

**M5. Hardware and cloud are probed by hand, under the rules.**

- **YubiKey.** Imports go only into the scratch slot (`probe.scratchId = "17"`; retired slots
  90–95 only, never 82–84). PIV cannot erase a key. Today the probe refuses a slot that holds
  anything but the provider's placeholder, so after an import it would refuse its next run.
  And a known private key would be left on a real device. So the import probe imports as SO
  into the scratch slot and ends by overwriting it with a freshly generated placeholder
  (settled 3).
- **fTPM.** `tpm2_ptool import` runs only through `nix/ftpm-test-env.sh`. Record
  `tpm2_getcap handles-persistent` before and after, and check `TPM2_PT_LOCKOUT_COUNTER` is
  still 0. An imported key is invisible to the open token (`Token::import_plaintext`), so the
  probe opens it again. The user runs this probe; it never runs in a check.
- **Cloud KMS (kmsp11).** Its keys are bound (`probe_bound`), and import there is a Cloud KMS
  import job, not PKCS#11. Out of scope: its profile keeps no `import.*` rows, and the
  planner's default for it stays as today.
- **AWS CloudHSM.** `scripts/cloud/aws.sh probe` regenerates both profiles; it costs a
  cluster run. Its known refusal, Ed25519 in, must come out of the probe as
  `import.CKK_EC_EDWARDS.edwards25519` no and `unwrap.…` no before `refuses` is removed.

## Stages

| Stage | What | Size | Depends on |
|---|---|---|---|
| P-a | `Capability` variants `Import`, `Create`, `Export`, `Unwrap` (M1) and `Delete` (M4), the last from the existing leftover check: parse, Display, `probed()`, the type and size constants, round-trip tests | S | — |
| P-b | Import probes (M2): embedded test keys per baseline curve, RSA size and AES length; `import.*` through the provider's own path (`Token::import_plaintext` or `C_CreateObject`), `create.*` for public objects; identity checked on the host; everything destroyed | M | P-a |
| P-c | Export and unwrap probes: each imported extractable key handed to the host (RFC 5649) and wrapped toward the transport key the ways camigrate moves it, then unwrapped back | M | P-a |
| P-d | Consumers read rows (M3, M4): `side_of`, `Side::pkcs11`, `host()`, the `refuses` block, `accepts_public_key_objects`, `proof_side`; per-type lookups in place of `Accept::covers` lists | M | P-a |
| P-e | Reference profiles regenerated with the Nix-built binary only (`scripts/regen-profiles.sh`): SoftHSM, kryoptic, p11-kit, swtpm. `spec-coverage` regenerated with them, since the new probes reach more of the spec (5c2a0bd: a stale `spec-coverage` failed the crane check) | S | P-b, P-c |
| P-f | Hardware and cloud profiles regenerated by the user (M5): YubiKey, fTPM, AWS CloudHSM | M | P-e |
| P-g | Hand-written rows removed: `plaintext-accepts`, `public-accepts`, `refuses`, `move.export`, `move.unwrap`, `move.secret-unwrap`. Updates `crates/profile/src/lib.rs:296` (asserts ykcs11's three accept rows) and `crates/profile/tests/answers.rs`'s output. CAPROBE.md and CAMIGRATE.md D2/D10 rewritten | S | P-d, P-f |
| P-h | Optional: camigrate records `import.*` and `export.*` yes rows in the token's lock observation, as `create` records `generate.*` | S | P-d |

## Tests

- **Rows round-trip.** Every new row parses and prints back. A name the probe never tries is
  refused (`capability.rs`'s parse tests).
- **The reference profiles say what the modules do.** SoftHSM imports every baseline type the
  host reads; kryoptic every one but brainpool and secp256k1, which it does not generate
  either. The conformance tests hold the regenerated profiles to that. p11-kit's layer
  subtracts what its RPC drops.
- **The planner's verdicts do not change** for any committed profile between P-d and P-g. The
  dry-run property (`crates/camigrate/tests/dry_run.rs`) runs against both the hand-written
  and the probed rows.
- **Nothing is left behind.** After a probe the token holds what it held before. On a module
  that cannot delete keys, the scratch slot holds a placeholder again.

## Settled (2026-11-16)

1. **Two export rows**, `export.host.*` and `export.sealed.*`, so a module that does either
   alone is described as it is (M1).
2. **Each key type's own unit**: bits for RSA, bytes for `valueLen` types. These are the units
   of the key's PKCS#11 attribute and of its keys.toml field, so nothing is converted (M1).
3. **The YubiKey is probed in its scratch slot**, which ends holding a fresh placeholder (M5).
4. **Row names in a lock are provenance.** If P-h records them in observations, they stay as
   written there; lock version 1 is still a draft (DESIGN §10).
5. **RSA import sizes follow `--rsa-max-bits`**, as generation does (M2).

## Built (2026-11-16)

Where each part lives:

- **Rows (P-a):** `Capability::{Import, Create, Export, Unwrap, Delete}`, `Way` and
  `On::Bytes` in `crates/profile/src/capability.rs`. They are appended after the existing
  variants, so the rows of every committed profile keep their order. A pair profile drops them
  on other hardware with the generation rows (`clear_hardware_rows`).
- **Probes (P-b, P-c):** `crates/caprobe/src/probe/moves.rs`, run after the wrap probes. The
  test keys and their `make.sh` are in `crates/caprobe/fixtures/import`. The deletion rows come
  from the leftover check (`destroy_all` in `probe.rs`). Each provider names its import path
  (`Provider::plaintext_import`). Public objects are built by `cakeys_pkcs11::token::
  public_object_attrs`, which camigrate now shares.
- **Readers (P-d):** `Side::probed` (`ProbedWays`, `crates/core/src/migrate.rs`), filled by
  `probed_of` (`crates/camigrate/src/tokens.rs`). The planner's `public`, `stays`, `sealed`,
  `host` and `host_extractable` (`crates/camigrate/src/plan.rs`) let a covering row decide. So
  do `Profile::unwraps` (the proof check) and `Profile::creates_public_keys`
  (`accepts_public_key_objects`).
- **Profiles (P-e):** the SoftHSM, kryoptic and swtpm reference profiles regenerated with
  `scripts/regen-profiles.sh`, and `spec-coverage` with `scripts/coverage-file.sh`.

Where it departs from the plan:

- **RSA import stops at 8192 bits and starts at 1024.** The rsa crate takes no public key
  outside that range, so cakeys identifies no such key, and those sizes are left out with a
  note rather than embedded.
- **`move.secret-unwrap` stays a claim.** The reference suites run SoftHSM with the upstream
  fix (#925, `nix/softhsm-unwrap-value-len.nix`), while deployments run stock 2.7. A row that
  read `CKA_VALUE_LEN` after an unwrap would describe one build only, so `unwrap.*` checks the
  material alone.
- **`tpm2_ptool` imports are not probed yet.** What the tool writes is seen only once the token
  is opened again, which the probe does not do. tpm2-pkcs11 profiles have no `import.*` rows,
  and their hand-written `plaintext-accepts` keep deciding.
- **The sealed exports name camigrate's methods** (`rsa-oaep-sha256+aes-kwp`, and
  `rsa-oaep-sha256` for a secret key directly), tried in camigrate's order with
  `CKM_RSA_AES_KEY_WRAP` last. kryoptic has no `CKM_RSA_AES_KEY_WRAP` but moves every key by
  the composed method.
- **Only the planner, the proof check and `accepts_public_key_objects` read the new rows.**
  `validate` and `create`'s gate do not yet. Nothing reads the `delete.*` rows either, so M4's
  rule (an unknown import refused on a module that cannot delete) is not built.
- **The YubiKey path imports as SO in the scratch slot**, never touches PIV data objects, and
  ends by generating a placeholder again.

## Hardware (P-f, 2026-11-17)

The YubiKey and the fTPM profiles were regenerated under docs/DEVELOPMENT.md's hardware rules;
the cloud profiles are still to do.

- **YubiKey 5C NFC FIPS 5.7.4, ykcs11 2.7.3** (PIV in FIPS-approved mode): slot 94 cleared
  before and after (key and certificate, by yubikit with the management key file); slots
  82–84 unchanged (fingerprints compared), PIN tries 3/3. P-256 and P-384 import; P-521,
  secp256k1, brainpool, Ed25519 and RSA 1024–4096 are refused with `CKR_DEVICE_ERROR`; a
  certificate is created. These rows now decide over the hand-written `plaintext-accepts`,
  which claimed RSA 1024–4096 and was never run (camigrate's test imports P-256 only). Open:
  whether Ed25519 fails because cakeys names the curve by OID where the device generates it
  only by name, and whether RSA is the approved mode's refusal or cakeys' template.
- **AMD fTPM 3.87, tpm2-pkcs11 1.10** (through `nix/ftpm-test-env.sh`, a transient primary):
  persistent handles unchanged (0x81000001, 0x81000002, 0x81010001, cakeys' 0x81000016),
  `TPM2_PT_LOCKOUT_COUNTER` 0 before and after. A certificate is created; a public data object
  is refused (tpm2-pkcs11 requires `CKA_PRIVATE`). No `delete.*` rows: the leftover count found
  nothing to count, likely because a failed operation left the session busy; the probe should
  say so rather than write nothing.
