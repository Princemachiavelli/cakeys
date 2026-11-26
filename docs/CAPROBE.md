# caprobe: capability profiles and the probe

The tools keep what a PKCS#11 module can actually do as data, not as provider code. This data
says which mechanisms work, which curves the module generates, which OAEP hashes it implements,
and which attributes it accepts in an unwrap template. Each module on its hardware has one
*capability profile*, and each layer between cakeys and the token has one too. `caprobe` measures
modules and writes these profiles, and `cakeys` and `camigrate` read them. `caprobe` is the only
tool that creates and destroys scratch objects.

Each fact in this document carries a tag that says where it comes from. **[run]** means that a run
in this repository verified it. **[spec]** means that the OASIS PKCS #11 standard or the TCG TPM2
standard states it. **[src]** means that it was read in a module's source code. **[todo]** means
that it is not verified yet.

## Command line

```console
$ caprobe supports [<CKM_*|CKK_*|CKP_*|curve>] (--profile <p> | --token <t>) [--layer <l> ...] \
    [--bits <n>] [--class pq|hmac|key-wrap|oaep] [--oaep] [--profiles <dir>]
$ caprobe caps --token <t>
$ caprobe probe --token <t> [--write-probes] [--out <file> [--accept]] [--diff <profile>] [--name <profile>] [--profiles <dir>]
$ caprobe regenerate <profile> --token <t> --out <file> [--accept] [--profiles <dir>]
```

- `supports` answers from the profiles alone. It does not open a token, and with `--profile` it
  needs no keys.toml. Each answer names the profile that decided it, for example "no: cryptoki
  (unpatched build) subtracts it". The exit code is 0 for yes, 15 for no and 16 for unknown.
  With `--token`, `supports` resolves the token's stack of profiles in the same way as
  `cakeys validate` and `create`'s gate do (`gate::stack`). The stack is the token's provider (or
  its `moduleProfile`) and the `profiles` layers that keys.toml configures for the token. These
  profiles come from the one profile set that every tool loads: the embedded profiles, then the
  profiles in `profileDirs`, then the profiles in `--profiles`. `supports` never reads keys.lock,
  so it answers as `validate` does for a token of which the lock records nothing. Because the
  lock records no module, the rows that the hardware decides are unknown.
  When the question names a key type without a curve or a size, the answer is yes if some row of
  that key type generated a key or if the module reports the key type. The answer is no if
  every row of that key type says no.
- `caps` prints the token's provider, its resolved stack of profiles and its usable mechanisms as
  JSON.
- `probe` measures a token and generates its profile (see below). With `--diff`, `probe` prints
  each difference in the rows that it can observe, and it exits with 15 if there is a difference.
- `regenerate` is the one command that regenerates a committed module profile. It runs `probe`
  with the write probes, with RSA sizes up to 4096 bits (`REGENERATE_RSA_MAX_BITS`), with
  `--name <profile>`, with a `--diff` against that profile when the profile set contains it, and
  with `--out`. It writes the output file in the same way as `probe --out` does
  (`cakeys_profile::regenerate::write`): when a file already exists at that path and differs from
  the new profile, the new profile is written beside it as `<file>.new`, unless `--accept` is
  given. `<profile>` must be a full name such as `softhsm/2.7`, and a family name is refused (17).
  Every script and the conformance tests call `regenerate`, so no script keeps a copy of its flags
  that could come to differ (review 2026-11-24 E-8). `checks.ledger` checks that the scripts call
  it.

The other exit codes are the shared codes in [CAKEYS.md](CAKEYS.md#exit-codes). Exit code 17 also
covers a write probe on a token that keys.toml does not mark as scratch.

To regenerate the committed profiles, run `caprobe regenerate` in the place that
`profiles/LEDGER.toml` names for each profile (see ["The ledger"](#the-ledger)).
`scripts/regen-profiles.sh` sets up the three reference tokens in the same way as the check phase
does, and it regenerates their files. The other profiles need the device or the cloud service.
Only the Nix-built binary contains the patched cryptoki that the probe needs.

## Why data, and what stays code

| Fact | Example | Medium |
|---|---|---|
| Behavior that a module shows through PKCS#11 | the usable mechanisms; the OAEP hashes that it actually implements (SoftHSM implements only SHA-1 [run]); the curves that it can generate (kryoptic cannot generate secp256k1 [run]); the attributes that it accepts in an unwrap template; the operations that need a Security Officer (SO) login; what a delete does | profile data |
| Behavior outside PKCS#11, or behavior that cakeys must correct | the repair of tpm2-pkcs11's P-521 points; PIV attestation and its pinned root certificates; `TPM2_Certify`; `tpm2_ptool` | provider code |

The `Provider` hooks that change behavior or reach outside the module stay code. These hooks are
`ec_point`, `key_type`, `policy_flag`, `stand_in`, `template`, `create`, `destroy`, `attestation`,
`check_options`, `plaintext_import`, `bound_keys` and `generation`. A vendor whose module needs no
corrections needs no Rust code. When no code provider claims a module, cakeys looks for the module
profile whose `[match] manufacturer` is the manufacturer that the module reports, and the family
of that profile names the provider (`provider::Data`). `softhsm` and `kryoptic` are such data
providers, and `provider = "<family>"` in keys.toml selects one by name. When two families claim
the same manufacturer, cakeys refuses the token (17) until `provider` names one of them. A family
whose provider is code (`CODE_FAMILIES`) is never a data provider.
When the build does not contain that code, a token of that family is refused (17).

## The format: deltas over a spec baseline

**The baseline** (`profiles/baselines/pkcs11-3.2.toml`) is generated from the OASIS 3.2 headers.
The headers are vendored unmodified at `profiles/baselines/headers/pkcs11-3.2/`, and a test pins
the baseline (`CAKEYS_UPDATE_BASELINE=1` regenerates it beside the committed file, and
`CAKEYS_ACCEPT=1` replaces the committed file). The baseline is the vocabulary of one revision of
the specification. It maps each name to its ID for every mechanism, key type, attribute (including
the array attributes), object class, curve, function and parameter set, and for the other
constant families: return values, flags, user types, session states, certificate and
hardware-feature types, MGFs and IV generators, KDFs, sources, notifications, and trust and
validation types. It groups these names into classes (`pq`, `hmac`, `key-wrap`, `oaep`). The
baseline validates names and answers queries by class. It never claims what a vendor supports.

**A module profile** (`mode = "observed"`, `profiles/modules/<family>/<version>[+<hardware>].toml`)
records what a probe measured, as differences from what the module itself advertises:

```toml
profile = "softhsm/2.7"
mode = "observed"
advertise = ["CKM_AES_CBC", "..."]         # what C_GetMechanismList returns
# subtract = { mechanisms = [...] }        # listed but unusable; `add` for usable but unlisted
[match]
manufacturer = "SoftHSM"
module-version = "2.7"
model = "SoftHSM v2"
firmware = "2.7"
[capabilities]                             # one row type: what cakeys' operations do here
"generate.CKK_EC.secp256r1" = { answer = "yes", by = "host" }
"generate.CKK_EC_EDWARDS.edwards25519" = { answer = "yes", by = "host", via = "by-name" }
"generate.CKK_RSA.2048" = { answer = "yes", by = "host" }
"wrap.rsa-oaep.SHA-256" = { answer = "no", by = "module", evidence = "CKR_ARGUMENTS_BAD" }
"decrypt.rsa-oaep.SHA-1" = { answer = "yes", by = "host" }
"unwrap.template.CKA_VALUE_LEN" = { answer = "no", by = "module" }   # refused in an unwrap template
"derive.ecdh.sealed" = { answer = "yes", by = "host" }   # also derive.ecdh.read-only
"move.secret-unwrap" = { answer = "no" }              # move.*: hand-written claims
[reported."CKK_RSA"]                       # the sizes C_GetMechanismInfo reports
min-bits = 512
max-bits = 16384
[migration]                                # hand-written: what the import paths take
plaintext-import = "create-object"
[notes]                                    # what the probe saw, as CKR_* names
[manual."secret-unwraps"]                  # findings a person made: `finding` and `evidence`
```

A capability row has the form `"<capability>" = { answer, by, evidence, via }`. `answer` is `yes`
or `no`. `by` says who showed the answer, `evidence` says what shows it, and `via` says how the
operation succeeded when there is more than one way. The capabilities name cakeys' operations
(`crates/profile/src/capability.rs`):

- a generation per key type and per curve or size;
- a wrap and a decryption per OAEP hash;
- an attribute in an unwrap template;
- ECDH into a sealed secret, and ECDH in a read-only session;
- the moves;
- a proof of possession per binding and key (`prove.pop-ecdh.CKK_EC.secp256r1`);
- per key type and per curve or size, how a key gets into and out of the token: an import from
  plaintext (`import.CKK_AES.32`, where `via` names the path), a public object created from its
  value (`create.CKO_CERTIFICATE`), an export to the host or a wrap toward another token
  (`export.host.*`, `export.sealed.*`, where `via` names camigrate's method), an unwrap
  (`unwrap.*`), and a delete per object class (`delete.CKO_PRIVATE_KEY`).

[What the probe measures](#what-the-probe-measures) lists these rows. A size is in the key type's
own unit: bits for RSA, and bytes for a key type with a `valueLen`. The probe measures the proofs
with the same code that the verbs use (`Token::prove_binding`), on a token that it opened without
a module profile (`Token::unprofiled`). Therefore the probe records what the module does, not
what the committed profile already says. The probe generates the key types that cakeys manages
in the same way (`Token::create`, which runs the provider's create operation), and it records
each refusal as the row's evidence. To add a capability, a developer adds a variant in
`capability.rs` and the operation that tests it. The emitter, the diff and the stack algebra do
not change.

*An absent row means unknown*: nobody probed the capability and nobody claimed it. This default
agrees with the specification. A row can name a key type, a proof (`pop-*`), an OAEP hash or a
template attribute (`CKA_*`) that this version of cakeys does not know. Such a row loads unchanged
and answers no question, so a profile from a newer cakeys still loads. Only a row whose shape is
wrong is refused. A probe from this cakeys never writes such a row, so `--diff` reports the row and
a regeneration drops it.

**Provenance** (review 2026-11-24 E-2 to E-5). The value of `by` says who checked the answer:

- `host` means that the host checked the outcome. The host verified a signature, read back or
  compared a key, recomputed a commitment, or found that the module's answer was wrong.
- `module` means that the row records the module's own refusal.
- `unverified` means a yes for which only the module vouches. Examples are a commitment or a
  cipher mode that the host does not recompute, a secret import that only the module's own
  commitment checks, and an unwrap that is checked only against the module's own blob.

A sealed export wraps the key toward the imported `rsa-2048` test key. Its row is `host` only
when the host decodes the blob back to the key: first with RFC 8017 OAEP, and then with RFC 5649
under the key-encryption key (KEK). When the host cannot decode a blob, the row is a `host` no,
because another token reads only that encoding (review 2026-11-24 E-3). camigrate accepts an
`unverified` yes when it plans, and it defers the rule `capability` to the run. A `yes` is never
`module`, and a `no` is never `unverified`. A profile with a `module` no whose evidence is a
device failure is refused when it loads (`Row::problem`).

A step can fail with a return value that reports a fault of the device, the token or the session
(`DEVICE_FAILED_RV`: `CKR_DEVICE_ERROR`, `CKR_GENERAL_ERROR`, `CKR_HOST_MEMORY`, ...). Such a
failure is not the module's answer. The probe then writes no row. Instead, it writes an
`[untested]` entry under the capability with `why = "device"`. When cakeys itself refused a step
before it asked the module, the entry has `why = "cakeys"`. Examples are a provider's template, a
missing host verifier for Ed448, and a key that no binding names. Both kinds of entry read as
*unknown*. The tools refuse them in the same way as a no (15), and the message names the re-probe
that is needed (T2 in `profiles/LEDGER.toml`). Such a capability is never planned as a yes. A
mechanism that signs, but whose signatures the host cannot verify (SHA-1, raw RSA), gets an
`[untested]` entry with `why = "unverified"`.

A row without `by` is a legacy row. Either it was probed before provenance existed (the hardware
and cloud profiles, until they are probed again), or it was written by hand (`move.*`). A legacy
row decides as it did before, with one exception: a legacy `no` whose evidence names a device
failure reads as unknown and is refused (15) with the same note. The committed profiles have such
rows in two places: 4 rows of tpm2-pkcs11 on amd-ftpm, and 10 import rows of ykcs11
(`the_committed_device_failures_are_these`). A cakeys from before provenance cannot load a profile
that has `by` fields, because it refuses an unknown field (17). Therefore a profile in
`profileDirs` that this caprobe regenerated needs this version of cakeys.

A shipped profile describes a kind of token. The lock records what each deployment's own token
answered, in an observation's `capabilities` (docs/LOCK.md): the proofs that `lock` performed and
the generations that `create` performed. In `validate`, in `create`'s gate and in camigrate's
planner, these recorded answers decide before the profile's answers do. A *no* from the profile
or from the token causes a refusal. *Unknown* means that the tool tries the operation, except for
an operation that cannot be undone.

`[migration]`, the `move.*` rows and `[manual]` are written by hand. The probe keeps them, and
the diff never compares them, so a reader always knows which rows were observed. `--out` copies
these parts only from an existing file of the profile that was just probed. A file of another
family is refused (17). A file of another profile name in the same family is also refused, unless
`--name` says which profile it is. When a file already exists at the `--out` path and the new
profile differs from it, the file is replaced only with `--accept`. Without `--accept`, the new
profile is written beside the file as `<file>.new` for review ([DEVELOPMENT.md](DEVELOPMENT.md),
"Golden files"). When a probed `import.*`, `create.*`, `export.*` or `unwrap.*` row covers an
object's type, that row decides before `[migration]` and `move.*` do. `[migration]` and `move.*`
answer for the other types until every committed profile has the probed rows
([archive/CAPROBE_MIGRATION.md](archive/CAPROBE_MIGRATION.md) M4).

A mechanism that the module advertises, but that no row measures, is listed in `[untested]` with
a reason (`cryptoki`, `vendor`, `hardware`, `cloud`, `scope`, `unprobed`). It reads as *unknown*,
never as *yes*. The probe also measures the commitments that cakeys computes (`commit.*`), the
symmetric modes (`crypt.*`), the key derivations (`derive.CKM_*`), the attributes (`attr.*`) and
the post-quantum mechanisms. `[mechanism-info]` and `[claims]` record what the module reports
about itself, and the diff never compares them. [What the probe measures](#what-the-probe-measures)
lists what is built and what is still open.

**Layers** (`mode = "delta"`, in `profiles/layers/` and `profiles/hardware/`) pass on everything
except what they subtract:

- `p11-kit/0.26`: its RPC protocol drops AES key wrap, `CKM_RSA_AES_KEY_WRAP`, Edwards generation
  and `CKM_EDDSA`, among other mechanisms [run]. The layer is marked `requires-provider = true`,
  because it hides the module behind it. No profile of that module applies until keys.toml names
  the module's `provider`, and plans print a warning until it does.
- `cryptoki/0.12` is the layer of the Rust binding, and every stack includes it. What it
  subtracts is decided at run time. A binding with the fix for the HMAC key types (the Nix
  patches, or the upstream release once it exists) subtracts nothing, so the layer stops
  subtracting without a change to the profile.
- `swtpm`: the default-v1 profile of libtpms refuses RSA-4096 [run]. Hardware layers are made by
  hand: each one separates the hardware's part from an observed pair of a module and its hardware.
  A hardware layer is never the output of a probe.

`supports(x)` is the intersection over the stack. When any layer subtracts `x`, the answer is no;
otherwise the module profile decides. The binary embeds the profiles that this repository ships.

- **`caprobe --profiles <dir>`** adds profiles or replaces existing ones, because a regeneration
  must replace a profile.
- **keys.toml's `profileDirs`** add module profiles at run time for all three tools. They let a
  user add a new vendor and its provider without a rebuild. They can only add profiles: they may
  not replace an embedded profile, a layer or the baseline. Those belong to this repository, and
  each was measured as `profiles/LEDGER.toml` records. The run says which profiles came from
  `profileDirs`.

## What the probe measures

This section lists what the profile-coverage plan and the probed-move plan built. Their history is
in [archive/CAPROBE_PROFILE_COVERAGE.md](archive/CAPROBE_PROFILE_COVERAGE.md) and
[archive/CAPROBE_MIGRATION.md](archive/CAPROBE_MIGRATION.md). The work that is still open is in
OPEN.md, under "More probes".

- **`[untested]`** lists each mechanism that the module advertises but that no row measures, with
  the reason (`cryptoki`, `vendor`, `hardware`, `cloud`, `scope`, `unprobed`, `unverified`). The
  probe computes the reason from what it tried. `[untested]` also lists each capability that the
  probe could not decide, with the reason `device` or `cakeys` (see Provenance, above). An entry
  reads as *unknown*, never as *yes*. The exception is `scope`, which covers the digests that the
  tools compute on the host: such a mechanism keeps the answer that the module's advertisement
  gives. `Profile::untested_problems` and an emitter test keep the entries consistent. The limits
  of cryptoki itself (`CKM_AES_CFB128`, `CKM_XEDDSA`, `CKM_AES_KEY_WRAP_KWP`) are notes and
  subtractions in `profiles/layers/cryptoki.toml`, and the layer of the patched binding is in
  `binding.rs`.
- **Secret keys**: the probe computes `commit.<kind>.<key type>.<bytes>` with the verbs' own
  `Token::commit`. It computes each commitment twice on one key, and once on a second key, to
  check that the value stays the same for one key and differs between keys. The gate
  refuses only when every commitment that a spec declares is measured as *no*. The probe also
  writes import, export and unwrap rows for generic secrets, the five HMAC types and Triple DES,
  and checks them by their commitment (and an AES key by its check value on the host).
- **Reported, never compared**: `[mechanism-info]` records what `C_GetMechanismInfo` returns.
  `[claims]` records the token flags, the session limits, the PIN length, the interface version,
  and the numbers of hardware-feature, profile and validation objects. A generation outside the
  reported range is recorded as a note. The probe also measures `attr.read.*` and
  `attr.set.CKA_ALLOWED_MECHANISMS` (`via = "enforced"`) as capability rows.
- **Operations**: `crypt.*` rows test AES CBC, CBC-PAD, CTR and GCM, and Triple DES CBC and
  CBC-PAD, each as a round trip on the token. `derive.CKM_*` rows test HKDF, the three
  concatenations, XOR, extract-key-from-key and AES-CBC-encrypt-data, each compared with the
  host's result. The probe also tests Montgomery ECDH, the generation of `CKK_DES2` and `CKK_HKDF`
  keys, and ML-DSA, ML-KEM and SLH-DSA per parameter set. For these, it tests every listed pure
  and hashed signing variant, verified on the token, and encapsulation and decapsulation.
- **Moves** (`crates/caprobe/src/probe/moves.rs`, run after the wrap probes): the rows `import.*`,
  `create.*`, `export.*`, `unwrap.*` and `delete.*` (`Capability::{Import, Create, Export,
  Unwrap, Delete}`), measured with the fixed keys in `crates/caprobe/fixtures/import`.
  camigrate's planner reads these rows through `Side::probed`, and so do `Profile::unwraps` and
  `Profile::creates_public_keys`. The move probes differ from a plain measurement in these ways:
  - The RSA import probes use sizes from 1024 to 8192 bits, because the rsa crate accepts no
    public key outside that range.
  - `move.secret-unwrap` stays a hand-written claim. The reference suites run SoftHSM with the
    upstream `CKA_VALUE_LEN` fix, but deployments run the unmodified 2.7 release, so the
    `unwrap.*` rows check only the key material.
  - The probe does not test imports through `tpm2_ptool`, because the token would have to be
    reopened. Therefore the tpm2-pkcs11 profiles have no `import.*` rows, and their hand-written
    `plaintext-accepts` entries decide.
  - The sealed-export rows name camigrate's methods. The probe tries them in camigrate's order,
    with `CKM_RSA_AES_KEY_WRAP` last.
  - Only the planner, the proof check and `accepts_public_key_objects` read the move rows.
    `validate` and `create`'s gate do not read them yet. The delete's rule (`deletion`) reads
    `delete.*`: a row that answers no refuses the delete before anything is destroyed
    (`k6_a_profile_no_refuses_the_delete_before_any_destroy`).
  - On a YubiKey, the probe imports keys as the SO, and only into the scratch slot. It writes into
    that slot the keys that it probes, its test certificate, and last its own mark certificate
    (`CN=cakeys-probe`). The mark certificate replaces the placeholder certificate that ykcs11
    writes with each key that it generates
    (`only_the_slots_attestation_sits_beside_the_probes_certificate`).

## Coverage

`spec-coverage/cakeys.toml` gives every row of the baseline exactly one status (PLAN.md A1). The
file is generated and never edited by hand.
A test pins it in the same way as the baseline:

| Status | Meaning |
|---|---|
| `used` | a call by cakeys, caprobe or camigrate reached the row in the traced test run |
| `out-of-scope`, `gap` | a rule kept by hand in `spec-coverage/manual.toml`, with its reason (a gap names its item in OPEN.md) |

- **The trace** comes from running the test suites with every module behind a tracing p11-fault
  (`nix/test-tokens.sh` with `CAKEYS_TRACE_DIR`). For each call, the trace records the function,
  the return value, the mechanism (with its OAEP or PSS hash and MGF, its OAEP source or its ECDH
  KDF), the types of the template attributes, the object classes, the key and certificate types,
  the user type, and the flags that the call passed or read back. Only the tools' own calls
  count. The calls of a test harness, pkcs11-tool, `p11-kit remote` or OpenSSL do not count. The
  tests that run their own p11-fault are not traced, and nix/test-tokens.sh names them, because
  the calls of their hooks would count as calls of the tool.
- **The check**: the test run of every build regenerates the file from the baseline, from
  `manual.toml` and from the committed file's own `used` rows, and compares the result with the
  committed file (`crates/caprobe/src/coverage.rs`). The check fails on a row without a status, on
  a manual rule that matches nothing, on a manual rule that names a used row (by its name, or by a
  pattern whose rows are all used), and on a file that differs. The check does not verify that
  the `used` rows are still the rows that a traced run reaches; the report does that, because the
  check would need a second full traced run in each build.
- **Regenerate** (this produces a report and is never a check): run `nix build .#spec-coverage`
  and then copy `result/cakeys.toml` over the committed file, or run `scripts/coverage-file.sh`
  outside Nix. Both also write `coverage-report.txt`. The report lists the tests behind each used
  row, and what the trace reached that the baseline does not name (vendor mechanisms, return
  values and functions).
- **What it cannot see**: `C_GetInterface`, because p11-fault exports only the 2.40 entry point,
  so the traced run uses the 2.40 function table; and the calls that only a hardware suite makes,
  because the YubiKey and the real TPM are never traced.

## Decisions

- **D1.** The baselines are generated from the OASIS PKCS #11 headers, with one file per revision
  of the specification. Each file is committed, and a test pins it. Post-quantum parameter sets
  are rows of their own.
- **D2.** Module profiles record differences from what the module advertises, not from the whole
  specification. This keeps the files small, and `C_GetMechanismList` remains the reference for
  detecting drift.
- **D3.** There are two modes: `observed` for a module on its hardware, and `delta` for a layer.
  The effective support is the intersection over the stack. The cryptoki binding is a layer too.
- **D4.** Claims and observations are kept apart. A token's `CKO_PROFILE` (`CKP_*`) claims are to
  be recorded and verified, and never trusted. This is not built yet.
- **D5.** Probes write profiles, and the committed TOML is what every tool queries. Write probes
  produce the profiles in advance, outside any cakeys run, and they run only on a token or a slot
  that is marked as scratch.
  `cakeys` does not compare a profile with the live token (decided 2026-11-13); the operator runs
  `caprobe probe --diff` for that.
- **D6.** Behavior hooks and vendor tools stay code. A profile that needs no hooks needs no crate.
- **D7.** The documents say *capability profile*, so that the term is not confused with the
  specification's `CKP_*` conformance profiles.
- **D8.** The lock records the name of the resolved profile in the observation
  (`observations.<key>.profile`), so that drift warnings and `caps` can name it.
- **D9.** A profile matches on four keys: the manufacturer and the module version (from
  `C_GetInfo`; the version is omitted when the module reports it as 0.0), and the token model and
  the firmware (from `C_GetTokenInfo`). Resolution prefers the profile that matches the most keys,
  and it adds a note when the evidence is weak. A profile never matches on a digest of the module,
  because a rebuild of the same module has another hash and behaves the same.
- **D10.** A probe measures a module and its hardware together, and PKCS#11 does not say whether a
  refusal comes from the module or from the hardware. Therefore an observed profile describes a
  pair, named with the module first (`tpm2-pkcs11/1.10+swtpm`); software tokens keep plain names.
  A token whose hardware has no recorded pair yet resolves the nearest pair, but it uses only what
  the module advertises and what this repository claims of the module (`move.*`). Every measured
  row answers unknown. Pairs are ranked first by a hardware layer that the configuration names,
  and then by model and firmware. A module version that no pair of its family records (for
  example, after a client library update) is not an error either. The nearest recorded version is
  used in the same way, for the module rows only, with a note that names `caprobe probe`. No
  profile is ever required to open a token.
- **D11.** Profiles are TOML, like keys.toml and the lock, so Nix can read them directly. p11-kit's
  `.module` files cannot hold mechanism lists or evidence.
- **D12.** A token's *mode* (FIPS-approved or not) is a key to match on, like its firmware. It is
  entered as data in `[match.fields]`. The standard fields come from PKCS#11 3.2 (`CKO_VALIDATION`
  objects, `C_GetSessionValidationFlags`, `CKF_ERROR_STATE`), and the vendor fields come from a
  provider hook that observes them (`"ykcs11.fips-mode"`, a TPM's `TPM_PT_MODES`). One generic
  match rule applies to every field. A requirement for a mode is a policy, which is checked
  against the live token when it is opened (`tokens.<t>.require = { fips = "approved" }`; exit 14
  when the token does not meet it). This is not built (OPEN.md).

## The probe

- **Read-only probes** are safe on any token: `C_GetInfo`, `C_GetTokenInfo` (the profile never
  records the serial number, so a profile regenerates identically), `C_GetMechanismList`, and
  `C_GetMechanismInfo` for the RSA sizes.
- **Write probes** run only with `--write-probes`, only on a token that keys.toml marks
  `probe.scratch = true`, and only when logged in; otherwise caprobe refuses with 17. They generate
  a key pair per baseline curve, and per RSA size from 512 to 16384 bits (512, 1024, 1536, 2048,
  3072, 4096, 6144, 8192, 12288, 16384), whatever sizes the module reports. What the module
  reports is recorded as a claim in `[reported."CKK_RSA"]`, and the only limit on the sizes is
  cryptoki's. `--rsa-max-bits` stops at a smaller size. Every regeneration stops at 4096 bits,
  the size that `caprobe regenerate` uses (`[regen]` in `profiles/LEDGER.toml`; `checks.ledger`
  checks that the verb and each script use it). A software token needs more than a minute for
  16384 bits, so the committed profiles stop at 4096 bits, and the gate answers unknown above it.
  The cloud profiles keep their rows up to 16384 bits from before this rule (review 2026-11-24
  E-8) until their next probe. The probe also tries a curve family whose generation mechanism the
  module does not list, and it writes an `add` row when the generation succeeds.
  For each key that generates with its usage attributes, the probe proves possession by every
  binding of its kind, and it writes a `prove.*` row for each binding. Every secret key type that
  cakeys manages (AES, generic secret, Triple DES and the five hash-bound HMAC types), and for
  which the module lists a generation mechanism, is generated as the verbs generate it
  (`Token::create`) at a range of lengths in bytes. Each length gets a
  `generate.<key type>.<bytes>` row with yes or no. AES is tried at 8, 16, 24, 32, 48 and 64
  bytes: the three lengths that AES defines, and lengths that a module should refuse. A generic
  secret and an HMAC key are tried at 1 to 1024 bytes, and Triple DES at the 24 bytes that its
  type fixes. The gate answers for each length that the probe tried. For a length between two
  lengths that generated, it answers only when the key type allows any length, which AES never
  does. A generation mechanism that generates no length is a `subtract` row.
  The write probes also test RSA-OAEP with SHA-1 and SHA-256, and they count a hash only when the
  key unwraps back. They round-trip each advertised key wrap (`CKM_AES_KEY_WRAP`, `_PAD`, `_KWP`,
  and `CKM_RSA_AES_KEY_WRAP` under the RSA key). A key wrap is a `subtract` row only when the
  module refuses it as a mechanism (`CKR_MECHANISM_INVALID`, `CKR_FUNCTION_NOT_SUPPORTED`), and a
  note otherwise. The flags that `C_GetMechanismInfo` reports are not evidence (AWS CloudHSM [run]).
  They test the `CKA_VALUE_LEN` unwrap rule. They import fixed test keys
  (`crates/caprobe/fixtures/import`), then export them to the host and wrap them toward the RSA
  key and back, and check each result on the host. They create a certificate and a data object.
  They check that a delete really deletes, and they write a `delete.<class>` row for each object
  class that the probes made.
  On the first key of each kind, the probe tries every signing, ECDH and decryption
  mechanism that it knows, whether the module lists it or not. On a key that is bound to some
  mechanisms (Cloud KMS), it tries only those. It checks each result on the host where cakeys can
  verify it. An advertised mechanism that fails on every key is a `subtract` row, and a mechanism
  that fails on some keys is a note. A mechanism that the module does not list but runs is an
  `add` row (SoftHSM and kryoptic sign with `CKM_ECDSA_SHA224` and `CKM_SHA224_RSA_PKCS`, which
  neither of them lists [run]). A failure never becomes a row when an earlier operation leaves
  the session busy (`CKR_OPERATION_ACTIVE`; tpm2-pkcs11 leaves a failed operation active [run]):
  such a failure is undetermined.
  Some standard mechanisms are not listed by the module, but the provider runs them in its own
  way (the mechanisms for which `Provider::stand_in` answers: AWS CloudHSM's Ed25519 generation
  and EdDSA). The probe tests such a mechanism through the stand-in, and it writes an `add` row when the
  mechanism works and the host verifies the signature. Only that `add` row makes the token count
  the mechanism as offered.
  Every run destroys what it made. Notes carry `CKR_*` names, which stay the same across releases
  of the binding.
- **SO-only modules** (ykcs11): `tokens.<t>.probe.scratchId` names the one slot that write probes
  may generate into. The slot must be empty, or it must hold the probe's own certificate
  (`CN=cakeys-probe`), which every slot run writes there last. The probe issues one such
  certificate over each key that the slot holds, and the P-256 test key signs it, so the same key
  gets the same bytes. Beside these certificates, the slot may hold only those keys (or the
  probe's own test keys), the probe's test certificate, and at most the device's attestation of
  the slot. caprobe refuses anything else (17) before it writes. It also refuses a marked slot whose key is another key,
  for example a key that `ykman piv keys generate` put there. ykcs11's placeholder certificate is
  not a mark, because ykcs11 writes one for every key it generates, including a real key. A run
  that stops before its last step leaves the slot unmarked, and caprobe refuses the slot until it
  is emptied (`scripts/yubikey-empty-slots.py`). A `scratchId` that is the `CKA_ID` of a locator
  that keys.toml has on that token is invalid when keys.toml loads. The slot gets no delete or
  wrap probes, because PIV cannot erase a key.
- **RSA sizes**: a size that was observed decides. A size outside the reported range is no. A
  size between two sizes that generated is yes, if no size that was tried between them was
  refused. Any other size is unknown. For example, a TPM generates only its discrete sizes: on
  swtpm, 1024 is yes and 1536 is no, so 1280 is unknown.
- **The diff** compares the match keys, `advertise`, `reported`, `subtract`, `add`, `restrict`,
  `[untested]` (with each mechanism's reason) and every probed capability row (its answer and
  `via`). Without `--write-probes`, it compares only what a read-only probe sees.
- **Only the Nix-built binary may write or diff a profile**, because an unpatched binding hides
  the mechanisms that it cannot name (kryoptic's `CKM_AES_KEY_WRAP_KWP` [run]).

## What the probes found

| Profile | Findings |
|---|---|
| `softhsm/2.7` | Implements OAEP only with SHA-1, for wrapping and for decryption (SHA-256 fails with `CKR_ARGUMENTS_BAD`). Generates every baseline curve. Reports RSA sizes from 512 to 16384 bits. Generates AES keys of 16, 24 and 32 bytes, and refuses 8, 48 and 64 bytes (`CKR_ATTRIBUTE_VALUE_INVALID`). Generates a generic secret of 1 to 1024 bytes, and Triple DES at 24 bytes. Has no `CKM_SHA*_KEY_GEN`, so it generates no hash-bound HMAC key. The `CKA_VALUE_LEN` of an unwrapped secret key reads 0 (`move.secret-unwrap` is no; an upstream issue is still to be filed). Offers `CKM_RSA_AES_KEY_WRAP`. The SO can create a trusted RSA public key |
| `kryoptic/1.5` | Reports module version 0.0, so the profile matches by the firmware, which holds the real version. Implements OAEP with SHA-1 and SHA-256. Refuses secp256k1 and brainpool. Advertises the PKCS#11 3.2 post-quantum mechanisms, which are not probed yet. Generates every secret key type that it lists, including the five hash-bound HMAC types, at 1 to 1024 bytes. Generates AES keys at 8, 16, 24, 32, 48 and 64 bytes alike, because it does not check the length (softhsm refuses the three lengths that AES does not define). Has no Triple DES. Cannot make an RSA public key trusted (`move.trusted-wrap` is no) |
| `tpm2-pkcs11/1.10+swtpm` | Reports Cryptoki 2.40. Advertises `CKM_AES_KEY_GEN`, but the call fails with `CKR_FUNCTION_NOT_SUPPORTED`. Has no Edwards curves. Generates RSA from 1024 to 3072 bits. A derived secret cannot sign (it has no `CKA_ALLOWED_MECHANISMS`), leaks a reference, and stays as a row in the module's store. Therefore `pop-ecdh` uses the extractable path (`derive.sealed = false`) in a read-write session (`derive.read-only = false`). Never wraps or unwraps |
| `tpm2-pkcs11/1.10+amd-ftpm` | Generates P-256, P-384, and RSA up to 2048 bits. Supports only SHA-1 and SHA-256, so ECDSA and RSA-PSS with SHA-384 or SHA-512 are `subtract` rows. Such a failed `C_Sign` or `C_Decrypt` leaves its operation active on the session: the next `C_SignInit` fails with `CKR_OPERATION_ACTIVE` [run]. For this reason, the probe proves possession before it runs its mechanism probes. `pop-sign`, `pop-decrypt` and `pop-ecdh` prove possession, and `pop-unwrap` fails with `CKR_FUNCTION_NOT_SUPPORTED`. Needs tpm2-abrmd, because the 3 slots of the kernel resource manager run out on objects that cannot be destroyed (`[manual.resource-manager]`) |
| `ykcs11/2.7` (YubiKey 5C NFC FIPS, 5.7.4) | Reports version 2.73 and manufacturer `Yubico (www.yubico.com)`. Generates P-256, P-384, Ed25519 (by name only), and RSA from 2048 to 4096 bits. Refuses RSA-1024, P-521, secp256k1, brainpool, Ed448 and X25519 (its X25519 template requires a malformed `PrintableString` [src]). Derives with ECDH only into an extractable secret, and has no HMAC. Every key reports `CKA_DERIVE = false`, which its provider's `repair` corrects. OAEP decrypts with SHA-1, SHA-256 and SHA-512. Nothing unwraps: `pop-sign`, `pop-decrypt` and `pop-ecdh` prove possession, and `pop-unwrap` cannot. FIPS mode is a `[manual]` finding until D12 is built |
| `aws-cloudhsm/5.18+hsm2m-fips` (AWS CloudHSM, us-west-1, 2026-11-15) | Reports manufacturer `CloudHSM`, model `LS2`, firmware 10.23 and Cryptoki 2.40. Refuses a public key with `CKA_PRIVATE = false`. A public key generated without that attribute reads `CKA_PRIVATE = true` (the probe retries without it and records a note). Generates P-256, P-384, P-521, secp256k1, and RSA from 2048 to 4096 bits. Refuses RSA-1024, brainpool, and every Edwards and Montgomery curve. OAEP wraps with SHA-1 and SHA-256, and decrypts with SHA-1, SHA-256 and SHA-512. `CKM_ECDSA_SHA1` fails, because FIPS mode refuses an 80-bit digest on a 128-bit key (see the client option `enable_ecdsa_with_weak_hash`). Raw ECDH needs the client option `ecdh_without_kdf`, which `aws.sh activate` sets. The derived secret refuses `CKA_EXTRACTABLE = false`, so the template drops that attribute and adds `CKA_VALUE_LEN` (`derive.template`). The derived secret reads as sensitive and extractable, and it computes MACs (`derive.sealed`). Derivation needs a read-write session. `CKM_AES_KEY_WRAP` and `_PAD` are listed with `CKF_WRAP \| CKF_UNWRAP` but are refused (`subtract`) [run]. The client option `--aes-key-wrap-mapping` maps the first of them to a vendor padding [doc], but nobody has tried it. `CKM_RSA_AES_KEY_WRAP` round-trips, and camigrate moves keys with it. Even a session object needs a read-write session (camigrate's `Access::Scratch`). The module lists vendor mechanisms (EdDSA `0x80001057`, ML-DSA, AES-GCM, `0x8000216F` = RFC 5649, `0x8000210A` = RFC 3394 over PKCS#5 padding), but cryptoki drops vendor IDs from the list [run]. RSA PKCS#1 v1.5 decryption fails. An unwrap template may not contain `CKA_VALUE_LEN`. Regenerated by `scripts/cloud/aws.sh probe` |
| `aws-cloudhsm/5.18+hsm2m-non-fips` (same, a NON_FIPS cluster) | The same as the FIPS profile, except that `CKM_ECDSA_SHA1` and RSA PKCS#1 v1.5 decryption work. Ed25519 works through the aws-cloudhsm provider's stand-ins, which the probe measures and records in `add` (`CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKM_EDDSA`). The module lists neither mechanism. It generates an Ed25519 key with `CKM_EC_KEY_PAIR_GEN` and the Ed25519 OID, reports the key as `CKK_EC` with the whole SPKI as `CKA_EC_POINT`, and signs pure Ed25519 with the vendor mechanism `0x80001057` (with no parameters) [run]. The module never imports an Ed25519 key (`[migration] refuses`: a `CKK_EC_EDWARDS` public half fails with `CKR_ATTRIBUTE_VALUE_INVALID` [run]), but it exports one. The FIPS cluster refuses the stand-in generation (`CKR_ATTRIBUTE_VALUE_INVALID`, "Ed25519 key generation not available"), so its profile adds nothing, and cakeys refuses an Ed25519 key there before it creates anything. The match keys of this profile equal those of the FIPS profile, because PKCS#11 reports no mode (D12). A tie resolves to the FIPS profile, which is embedded first and is the stricter one, and the run says so in a note that names both profiles (`caprobe caps` lists the note). A NON_FIPS cluster selects this profile with `moduleProfile` (`aws.sh cakeys` and `camigrate` do this). Regenerated by `CAKEYS_AWS_MODE=NON_FIPS scripts/cloud/aws.sh probe` |
| `kmsp11/1.9+hsm`, `kmsp11/1.9+hsm-fips` (Google Cloud KMS, HSM protection level, us-west1, 2026-11-15) | Probed through the provider's bound keys: one key per Cloud KMS algorithm, each with its own mechanisms. The FIPS build of the library measures the same and reports the same `C_GetInfo` (`Google`, 1.9, `Cloud KMS Token`, firmware 0.0). Therefore the FIPS profile is embedded first, and the two profiles tie. Generates P-256 and P-384 (for signing only), and RSA from 2048 to 4096 bits. RSA-1024, P-521, secp256k1 and brainpool have no Cloud KMS algorithm (a generation without an algorithm fails with `CKR_TEMPLATE_INCOMPLETE`). Edwards and Montgomery curves fail with `CKR_MECHANISM_INVALID`. OAEP decrypts with SHA-256 or SHA-512, and each key decrypts only with the hash of its algorithm (`CKR_MECHANISM_PARAM_INVALID` for the others). There is no wrap, unwrap or derive. `C_GetMechanismList` repeats `CKM_RSA_PKCS_KEY_PAIR_GEN` 24 times. `C_DestroyObject` removes a key version from view. Regenerated by `scripts/cloud/gcp.sh probe --write` |
| `p11-kit/0.26` (layer) | Hides eight of SoftHSM's mechanisms, and also `CKM_RSA_AES_KEY_WRAP`. Reports version 1.1; cakeys detects it by its manufacturer |

## The ledger

`profiles/LEDGER.toml` records what was measured on hardware or in a cloud, which no build
repeats: the hardware and cloud profiles, the device certificates that the tests read, and the
example YubiKey lock. It also lists the profiles that a build probes again (`verified-by`), so
every module profile has an entry. Each entry names the command that regenerates its file
(`regen`). The header of a profile refers to the ledger instead of stating either fact itself
(review 2026-11-24 E-7, E-8).

For a file that no build derives again, the entry records its run in `[artifact.probed]`: the
commit, the date, the hash of the file as the run wrote it, and the hash of the code on its path
at that time. The entry also records every hand edit since then (`[[artifact.hand-edits]]`) and
the hash of the file now (`hash`). `code` lists the globs of the files whose change can change the
file. For a profile, these are the probe, the token operations that it drives, the host-side
checks and the provider crate (`[groups] probe`). For a cloud profile, they also include its
script and the build of its module. `code` does not list the emitter, because every build checks
the committed text against the emitter.

`code` also names the single entries of the lock files that pin what a run used, not whole lock
files, so that a version bump marks as stale only the files that it can change:

- `Cargo.lock#cryptoki` and `Cargo.lock#cryptoki-sys`, the binding, for every profile and the
  lock (`[groups] probe` and `lock`, together with the binding's patches);
- `flake.lock#nixpkgs`, the nixpkgs that builds ykcs11 and the tpm2-pkcs11 stack for the host's
  TPM (`[groups] nixpkgs`). SoftHSM, kryoptic and tpm2-pkcs11 on swtpm also come from it, but
  every build probes them again;
- the cloud modules, which are vendor builds pinned by version and hash in `nix/kmsp11.nix` and
  `nix/cloudhsm.nix`, are tracked through those whole files.

`checks.ledger` (`nix/ledger.py`, run in CI's light job, or locally with
`nix develop -c python3 -I nix/ledger.py .`) hashes the files in the working tree, not the git
objects. In the code's hash, a Rust file counts as its sequence of tokens. A change to a comment,
a doc comment or rustfmt's spacing does not change the hash, while a change to a literal or to any
other token does, including a new order of imports. Any other file counts byte for byte, and an
entry of a lock file counts as its parsed value. The check fails when:

- a file changed and its entry did not;
- a file is not its run's output, and no hand-edit row records the difference;
- the code on a file's path changed since the run, and no `[artifact.acknowledged]` names the
  hash of that code together with who acknowledged it, why, and what still needs a run on the
  hardware (`reprobe`);
- a module profile has no entry, or a glob matches no file;
- a regeneration does not use `caprobe regenerate`: a `[regen]` source that does not call it or
  that passes its flags (`--write-probes`, `--rsa-max-bits`) itself, a `regen` command that names
  these flags, or a verb whose RSA size is not `[regen] rsa-max-bits`.

An acknowledgement is the step that a reviewer sees: the diff contains the new code hash and the
reason, and the check reports the file as `STALE` until the next run. After a run on the
hardware, set `by` and `date` in `[artifact.probed]`, remove the hand edits and the
acknowledgement, and copy the file's hash (`hash`, `probed.hash`) and the code's hash
(`probed.code-hash`) from what the check then prints. On 2026-11-25, every hardware and cloud
profile and the lock are stale, and each of them is acknowledged.

The files that a build regenerates and compares with the committed copy are golden files: the
`verified-by` profiles, the tables of the object matrix, `spec-coverage/cakeys.toml` and the
baseline. The code under test writes them. Therefore, when the commit that changes the code also
regenerates the file, the expected value changes together with the code (review 2026-11-24 C-8).
Each golden file has a `[golden."<path>"]` entry. The entry names its `generator` (globs, as in
`code`) and has one record for each change, either `[[golden."<path>".regenerated]]` or
`[[golden."<path>".hand-edits]]`. Each record names the hash of the file that it produced
(`hash`), who made the change, and each row that changed, with its previous value (`was`) and the
reason why the new value is right (`why`). `checks.ledger` fails when no record names a golden
file as it is now, when a `why` is empty or `"TODO"`, and when a listed row did not change. In CI,
`nix/golden-rows.py` checks that each record lists exactly the rows that its own change moved,
and that each change in the pull request has a record ([DEVELOPMENT.md](DEVELOPMENT.md), "Golden
files").

## Tests

- **Algebra and the baseline**: tests cover the modes, the intersection and the queries by class.
  A test checks that the baseline that the vendored headers generate equals the committed one,
  and it compares the parsed files (`CAKEYS_UPDATE_BASELINE=1` regenerates it). Tests pin the
  spellings that must not change. `checks.profiles` runs the pinned `supports` cases against the
  built binary, including an unpatched binding that the tests model through `--profiles`.
- **Conformance** tests run in the check phase of every Nix build. A fresh probe of SoftHSM, of
  kryoptic and of tpm2-pkcs11 on swtpm conforms to its committed profile and regenerates the
  profile byte for byte. The scratch guard refuses write probes on a token that keys.toml does not
  mark as scratch. Through p11-kit, SoftHSM advertises its profile minus the p11-kit layer. The
  YubiKey and fTPM checks are opt-in, and the cloud profiles have none: `checks.ledger` reports
  when the code on their path changed since their last run.
- **Drift**: a test edits one row and checks that the diff is not empty and names that row.
- **The static gate** (`cakeys validate`, and `cakeys create` before it opens a token): with no
  token present, the gate refuses kryoptic generating secp256k1 for a pair with
  `origin = "create"`, and a `kw` commitment through p11-kit, and the refusal names the profile
  that decided. The gate never asks about generation for an adopted or imported key.
