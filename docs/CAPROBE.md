# caprobe: capability profiles and the probe

What a PKCS#11 module can really do — which mechanisms work, which curves it generates, which
OAEP hashes it implements, its unwrap-template rules — is data, not provider code: a
*capability profile* per module on its hardware, and one per layer between cakeys and the token.
`caprobe` measures modules and writes those profiles; `cakeys` and `camigrate` read them. It is
the only tool that creates and destroys scratch objects.

Evidence tags: **[run]** verified in this repo, **[spec]** the OASIS PKCS #11 and TCG TPM2
standards, **[src]** read in a module's source, **[todo]** still to verify.

## Command line

```console
$ caprobe supports [<CKM_*|CKK_*|CKP_*|curve>] (--profile <p> | --token <t>) [--layer <l> ...] \
    [--bits <n>] [--class pq|hmac|key-wrap|oaep] [--oaep] [--profiles <dir>]
$ caprobe caps --token <t>
$ caprobe probe --token <t> [--write] [--out <file>] [--diff <profile>] [--name <profile>] [--profiles <dir>]
```

- `supports` asks the profiles alone; no token is touched, and `--profile` needs no keys.toml.
  Answers cite the deciding profile ("no: cryptoki (unpatched build) subtracts it"). Exit 0 yes,
  15 no, 16 unknown.
- `caps` prints a token's provider, its resolved stack of profiles and its usable mechanisms as
  JSON.
- `probe` generates a token's profile (below). With `--diff`, any difference in the observable
  rows is printed and the exit is 15.

Other exit codes are the shared ones ([CAKEYS.md](CAKEYS.md#exit-codes)); 17 includes a write
probe on a token not marked scratch.

Regenerating the committed profiles: `scripts/regen-profiles.sh` sets up the three reference
tokens as the check phase does and regenerates their files; the YubiKey test regenerates
ykcs11/2.7. Only the Nix-built binary carries the patched cryptoki the probe needs.

## Why data, and what stays code

| Fact | Example | Medium |
|---|---|---|
| What a module shows through PKCS#11 | usable mechanisms; OAEP hashes actually implemented (SoftHSM: SHA-1 only [run]); generatable curves (kryoptic: no secp256k1 [run]); unwrap-template rules; SO-login needs; delete semantics | profile data |
| Behaviour outside PKCS#11, or that must be rewritten | tpm2's P-521 point repair; PIV attestation and its pinned roots; `TPM2_Certify`; `tpm2_ptool` | provider code |

The `Provider` hooks that rewrite behaviour or reach outside the module (`ec_point`, `attest`,
`check_create`, `check_options`, `policy_flag`, `import_plaintext`) stay code. A vendor whose
module needs no fix-ups needs no Rust: `provider = "<profile>"`.

## The format: deltas over a spec baseline

**The baseline** (`profiles/baselines/pkcs11-3.2.toml`) is generated from the OASIS 3.2 headers,
vendored unmodified at `profiles/baselines/headers/pkcs11-3.2/`, and pinned by a test
(`CAKEYS_UPDATE_BASELINE=1` rewrites it). It is the vocabulary of one spec revision: every
mechanism, key type, attribute, curve, function and parameter set, name → ID, grouped into
classes (`pq`, `hmac`, `key-wrap`, `oaep`). It validates names and powers by-class queries; it
never claims what a vendor supports.

**A module profile** (`mode = "observed"`, `profiles/modules/<family>/<version>[+<hardware>].toml`)
records what a probe measured, as deltas against the module's own advertisement:

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
[wrap]
oaep = ["SHA-1"]                           # parameters actually implemented
[unwrap]
refuse = ["CKA_VALUE_LEN"]                 # template rules
[derive]
sealed = true                              # also decrypt.oaep, derive.key-attribute, derive.read-only
[generate."CKK_RSA"]
min-bits = 512                             # also can/cannot per curve under CKK_EC, CKK_EC_EDWARDS, ...
can-bits = [1024, 2048, 3072, 4096]
[migration]                                # hand-written claims the probe does not observe
secret-unwraps = false
[notes]                                    # what the probe saw, as CKR_* names
[manual."secret-unwraps"]                  # findings a person made: `finding` and `evidence`
```

`[migration]` and `[manual]` are written by hand; the probe preserves them and the diff never
compares them, so a reader always knows which rows were observed. *Absent is not empty*: an
unprobed `wrap.oaep` is a spec-compliant default, `[]` means probed and nothing worked.

**Layers** (`mode = "delta"`, `profiles/layers/`, `profiles/hardware/`) forward everything except
what they subtract:

- `p11-kit/0.26`: its RPC drops AES key wrap, `CKM_RSA_AES_KEY_WRAP`, Edwards generation and
  `CKM_EDDSA`, among others [run]. It is marked `requires-provider = true`: it hides the module
  behind it, so nothing about that module applies until keys.toml names its `provider`, and
  plans warn until it does.
- `cryptoki/0.12`, the binding layer, injected into every stack. What it subtracts is decided at
  run time: a binding with the HMAC key-type fix (the Nix patches, or upstream once released)
  subtracts nothing, so the layer heals itself.
- `swtpm`: libtpms's default-v1 profile refuses RSA-4096 [run]. Hardware layers are hand-made
  factorings of an observed module-on-hardware pair, never probe output.

`supports(x)` is the intersection over the stack: any layer's subtraction kills it; otherwise the
module profile decides. The binary embeds the profiles this repo ships; `--profiles <dir>` adds
or replaces entries, so vendors and users can keep their own.

## Decisions

- **D1.** Baselines are generated from the PKCS #11 OASIS headers, one file per spec revision,
  committed and pinned. PQ parameter sets are first-class rows.
- **D2.** Module profiles record deltas against the module's advertisement, not against the
  whole spec: small files, and `C_GetMechanismList` stays the drift baseline.
- **D3.** Two modes: `observed` (module on hardware) and `delta` (layers). Effective support is
  the intersection over the stack. The cryptoki binding is a layer too.
- **D4.** Claims and observations are kept apart: a token's `CKO_PROFILE` (`CKP_*`) claims are
  to be recorded and verified, never trusted. Not built yet.
- **D5.** Probes write profiles; the committed TOML is what everything queries. Write probes are
  the offline compiler, scratch-guarded. A read-only check at every token open is possible but
  not built.
- **D6.** Behaviour hooks and vendor tools stay code. A profile with no hooks needs no crate.
- **D7.** Say *capability profile*, to keep clear of the spec's `CKP_*` conformance profiles.
- **D8.** The lock records the resolved profile name in the observation (`observed.profile`), so
  drift warnings and `caps` name it.
- **D9.** A profile matches on four keys: manufacturer, module version (`C_GetInfo`; omitted when
  the module hides it as 0.0), token model and firmware (`C_GetTokenInfo`). Resolution prefers
  the profile matching the most, with a note when the evidence is weak. Never a module digest: a
  rebuild of the same module is another hash with no behavioural difference.
- **D10.** A probe measures a module and its hardware together, and nothing in PKCS#11 says whose
  refusal is whose. So an observed profile is a pair, named module first
  (`tpm2-pkcs11/1.10+swtpm`; software tokens keep plain names). A token whose hardware has no
  pair yet resolves the nearest one for what the module advertises only: generation and wrapping
  answer unknown. Pairs rank by a hardware layer the config names, then model and firmware.
- **D11.** TOML, like keys.toml and the lock, so Nix reads profiles directly. p11-kit's `.module`
  files cannot carry mechanism lists or evidence.
- **D12.** A token's *mode* (FIPS-approved or not) is a match axis like its firmware, entered as
  data in `[match.fields]`: standard fields from PKCS#11 3.2 (`CKO_VALIDATION` objects,
  `C_GetSessionValidationFlags`, `CKF_ERROR_STATE`), vendor fields through an observing provider
  hook (`"ykcs11.fips-mode"`, a TPM's `TPM_PT_MODES`). One generic match rule for every field.
  Requiring a mode is policy, checked against the live token at open
  (`tokens.<t>.require = { fips = "approved" }`, 14 when unmet). Not built (OPEN.md).

## The probe

- **Read-only probes**, safe on any token: `C_GetInfo`, `C_GetTokenInfo` (never the serial, so a
  profile regenerates identically), `C_GetMechanismList`, and `C_GetMechanismInfo` for RSA sizes.
- **Write probes**, only with `--write` on a token keys.toml marks `scratch = true`, logged in
  (refused with 17 otherwise): key pairs per baseline curve and per RSA size 1024–4096; the
  advertised secret-key generation; RSA-OAEP SHA-1 and SHA-256, counted only when the key unwraps
  back; the `CKA_VALUE_LEN` unwrap rule; delete-really-deletes. On the first key of each kind,
  every advertised signing, ECDH and decryption mechanism, checked on the host where cakeys can
  verify. A mechanism that fails on every key is a `subtract` row, a partial failure a note.
  Every run destroys what it made. Notes carry `CKR_*` names, stable across binding releases.
- **SO-only modules** (ykcs11): `tokens.<t>.scratchId` names the one slot write probes may
  generate into. The slot must be empty or hold the provider's own placeholder; anything else is
  refused (17) before a write. No delete or wrap probes there: PIV cannot erase a key.
- **RSA sizes**: an observed size decides; outside the reported range is no; between two that
  generated is yes; otherwise unknown.
- **The diff** compares the match keys, `advertise`, the generate rows, `subtract`, `wrap.oaep`,
  `unwrap.refuse` and `restrict`; without `--write`, only what a read-only probe sees.
- **Only the Nix-built binary may write or diff a profile**: an unpatched binding hides
  mechanisms it cannot name (kryoptic's `CKM_AES_KEY_WRAP_KWP` [run]).

## What the probes found

| Profile | Findings |
|---|---|
| `softhsm/2.7` | OAEP SHA-1 only, for wrapping and decryption (SHA-256 is `CKR_ARGUMENTS_BAD`); every baseline curve generates; RSA 512–16384 reported. An unwrapped secret key's `CKA_VALUE_LEN` reads 0 (`secret-unwraps = false`, an upstream issue to file). Offers `CKM_RSA_AES_KEY_WRAP`; the SO can create a trusted RSA public key |
| `kryoptic/1.5` | Reports module version 0.0, matched by firmware (its real version). OAEP SHA-1 and SHA-256; secp256k1 and brainpool refused; advertises the 3.2 PQ mechanisms (not yet probed). Cannot make an RSA public key trusted (`trusted-wrap = false`) |
| `tpm2-pkcs11/1.10+swtpm` | Reports Cryptoki 2.40. `CKM_AES_KEY_GEN` advertised but `CKR_FUNCTION_NOT_SUPPORTED`; no Edwards; RSA 1024–3072. Derived secrets cannot sign (no `CKA_ALLOWED_MECHANISMS`), leak a reference and stay as store rows, so `pop-ecdh` takes the extractable path (`derive.sealed = false`) in a read-write session (`derive.read-only = false`). Never wraps or unwraps |
| `tpm2-pkcs11/1.10+amd-ftpm` | P-256, P-384, RSA up to 2048; SHA-1 and SHA-256 only, so SHA-384/512 ECDSA and RSA-PSS are `subtract` rows. Needs tpm2-abrmd: the kernel resource manager's 3 slots run out on undestroyable objects (`[manual.resource-manager]`) |
| `ykcs11/2.7` (YubiKey 5C NFC FIPS, 5.7.4) | Reports version 2.73, manufacturer `Yubico (www.yubico.com)`. P-256, P-384, Ed25519 (by name only), RSA 2048–4096; refuses RSA-1024, P-521, secp256k1, brainpool, Ed448, X25519 (its template wants a malformed `PrintableString` [src]). ECDH only into an extractable secret, no HMAC; every key reports `CKA_DERIVE = false` (repaired by `policy_flag`). Nothing unwraps. FIPS mode is a `[manual]` finding until D12 |
| `p11-kit/0.26` (layer) | Hides eight of SoftHSM's mechanisms, plus `CKM_RSA_AES_KEY_WRAP`; reports version 1.1 (detected by manufacturer) |

## Tests

- **Algebra and the baseline**: modes, intersection, by-class queries; the baseline regenerates
  byte for byte; frozen spellings are pinned. `checks.profiles` runs the pinned `supports` cases
  against the built binary, including an unpatched binding modelled through `--profiles`.
- **Conformance**, in every Nix build's check phase: a fresh probe of SoftHSM, kryoptic and
  tpm2-pkcs11-on-swtpm conforms to its committed profile and regenerates it byte for byte; the
  scratch guard refuses; through p11-kit SoftHSM advertises its profile minus the layer. The
  YubiKey and fTPM checks are opt-in.
- **Drift**: one edited row makes the diff non-empty and names the row.
- **The static gate** (`cakeys validate`): kryoptic generating secp256k1, or a `kw` commitment
  through p11-kit, is refused naming the deciding profile, with no token present.
