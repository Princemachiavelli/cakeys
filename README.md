# cakeys

Content-addressed identity for PKCS#11 objects, as a Nix flake.

Declare keys, certificates and data objects in `keys.toml`. cakeys finds them on a token by a
locator (`CKA_LABEL`/`CKA_ID`), identifies them by a **hash of their material** (a CA-ID), and
records that hash in `keys.lock`. A label or URI can be changed or reused; the hash cannot. A
check before each use, including inside a Nix build sandbox, verifies that the token still holds
exactly that material; a private key also proves possession of it, by signing, deriving,
decrypting or unwrapping a fresh challenge the host checks.

Status: proof of concept, x86_64-linux, lock format `version = 1` still a draft. Tested against
SoftHSM, kryoptic, tpm2-pkcs11 (swtpm) and SoftHSM behind p11-kit in every Nix build, and by hand
on a YubiKey 5C NFC FIPS and an AMD fTPM. `nix run .#demo` walks through it on throwaway tokens.

## Three tools

| Tool | Job | Verbs | Document |
|---|---|---|---|
| `cakeys` | Pins and verifies | `validate`, `resolve`, `verify`, `realise`, `create`, `delete`, `gc`, `check`; the Nix library and NixOS module | [docs/CAKEYS.md](docs/CAKEYS.md) |
| `caprobe` | Measures modules into capability profiles; the only tool that creates scratch objects | `probe`, `supports`, `caps` | [docs/CAPROBE.md](docs/CAPROBE.md) |
| `camigrate` | Moves keys between tokens; the only tool that handles key material | `export`, `import`, `migrate`, `transport` | [docs/CAMIGRATE.md](docs/CAMIGRATE.md) |

All three share one workspace, one flake (`nix run .#caprobe`, `.#camigrate`) and the exit codes.
A `cakeys` build carries no probe or migration code.

## What it is for

- **A copy is really a copy.** Cloned HSM A onto B, or moved keys between vendors: realise each
  token into one lock, and B's copy must hash to A's locked identities (10 otherwise).
- **A key is what the software was tested with.** The spec declares type and policy (sign-only,
  non-extractable, …): another type is refused (13), policy drift reported (14), and a key
  generated on the device tells itself apart from an imported one (`CKA_LOCAL`, attestation).
- **An old backup still holds the material.** `verify` recomputes every identity from the token;
  labels only locate.
- **A module update changed something.** The lock records the module and token behind each
  entry, and `caprobe probe --diff` compares a token with its committed capability profile.
- **A signing build signs with the pinned key.** The build runs `cakeys check` first, like a
  fixed-output derivation, and the NixOS module grants a token only to builds that require it.
- **A service never starts with the wrong key.** `services.cakeys.checks.<name>` gates units on
  the identity check.
- **Keys move between tokens honestly.** `camigrate` says per object how it can move (`sealed`
  under a key on the target, `enforced` by the source token, through the host, or as a file), and
  the import is verified against the lock.

cakeys records and verifies; it does not decide how keys are managed. Out of scope: crypto
implementations and key generation on the host, rotation and approval policy, storing secrets or
PINs, being a PKCS#11 module, CA work, and proving a key exists nowhere else. Anything true of
one vendor lives in its provider crate, behind the `Provider` trait.

## Example

```toml
# keys.toml
[tokens.softhsm]
module = "/run/current-system/sw/lib/softhsm/libsofthsm2.so"
tokenLabel = "main"
pinFile = "/var/lib/softhsm/pin"

[objects.signing]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.signing-soft]
object = "signing"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
tokens.softhsm = { locator = { CKA_LABEL = "signing" }, autoCreate = true }
```

```console
$ cakeys -c keys.toml realise signing-soft --token softhsm --no-update-lock
created 'signing' (spec 'signing-soft') on token 'softhsm'
error: hash mismatch in identity of 'signing' (spec 'signing-soft') on token 'softhsm':
  specified: <none>
     got:    sha256-…            # compare only: like a fixed-output derivation
$ cakeys -c keys.toml realise signing-soft --token softhsm   # record it (the default), print the resolved JSON; review the keys.lock diff
$ cakeys -c keys.toml check signing     # later: verify, then print the URI (never writes)
pkcs11:token=main;serial=...;object=signing;type=private
```

`realise` and `delete` write the lock by default, filling gaps only — a locked ID is never
overwritten. A realisation that changed (its locator, spec or policy attributes) is re-recorded,
and each accepted change is printed (`re-recorded …`). Where the lock cannot be written (a Nix build sandbox, a read-only lock or
directory) they refuse up front unless `--no-update-lock` is passed.

## Supported objects

| Class | Types | Identity |
|---|---|---|
| private/public keys | EC P-256/384/521, secp256k1, brainpoolP256r1/P384r1; Ed25519/Ed448; RSA 1024–8192 | `rfc7093m4` (SHA-256 of canonical SPKI) |
| certificates | X.509 | `certhash` plus the subject key's `rfc7093m4` |
| secret keys | AES-128/192/256; generic secrets; `CKK_SHA{1,224,256,384,512}_HMAC` | on-token commitments: `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`, `commitment` (HMAC) |
| data objects | public `CKO_DATA` | `valuehash` (SHA-256 of the value) |

Opt-in attestation (`attestation = true` on a spec's token entry) adds signed provenance:
`piv-attestation` (YubiKey PIV, verified to the pinned Yubico root) and `tpm-certify`
(tpm2-pkcs11, a native `TPM2_Certify`). It is recorded per realisation beside the portable ID,
never instead of it.

## Nix

```nix
let
  keys = cakeys.lib.mkKeys {
    config = ./keys.toml;
    lock = ./keys.lock;
    cakeys = cakeys.packages.x86_64-linux.default;
    modules.softhsm = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
  };
  # One calling convention: the object is a function naming its (spec, token) pair
  # (the arguments are optional when the object has exactly one).
  signing = keys.signing { token = "softhsm"; };
in
pkgs.runCommand "signed-artifact" {
  # Only hosts that advertise the token's feature build this.
  requiredSystemFeatures = signing.requiredSystemFeatures;
} ''
  # Pre-use check: fails the build unless the token holds the locked material.
  uri=$(${signing.check})
  # ... sign with "$uri" ...
''
```

`signing` is plain data from the resolved pair: `id.<scheme>`, `uri`, `mode`, `specDigest`,
`module`, `tokenInfo`, `functions`, `assurance`, `requiredSystemFeatures` and `check` (use
`scheme = "certhash"` to require one identity). `assurance` says what the check establishes
against a token that may lie: `proof` (a fresh challenge), `fingerprint` (a secret key's
commitment: replayable by whatever saw it once) or `public` (public bytes), (DESIGN §3.6, §3.7).

A cached consumer is not rebuilt, so the token is not re-contacted; `nix build --check` forces it.

The NixOS module (`nixosModules.default`, `services.cakeys`) gives a token's sandbox paths,
and pcscd or the TPM, **only to builds that require that token's feature** (through a
pre-build-hook). It also defines check units that gate services on the key's identity. Real builds
reach tokens only through p11-kit forwarding or a real TPM, never through a token database.

## Documentation

| | |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | Identity schemes, the lock rules, proof of possession, attestation, the security model |
| [docs/CONFIG.md](docs/CONFIG.md), [docs/LOCK.md](docs/LOCK.md) | `keys.toml` and `keys.lock`, annotated |
| [docs/CAKEYS.md](docs/CAKEYS.md), [docs/CAPROBE.md](docs/CAPROBE.md), [docs/CAMIGRATE.md](docs/CAMIGRATE.md) | The three tools |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Crates, control flow, providers |
| [docs/diagrams.md](docs/diagrams.md) | The model, a verb, proof of possession, the Nix loop |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Building, testing, the hardware rules |
| [docs/OPEN.md](docs/OPEN.md) | Open and parked items |
| `docs/archive/`, `reports/`, `research_notes/` | Dated reviews, working notes, the lock-format research |

## Development

```console
$ nix flake check                # every check: token suites, VMs, module, minimal build, formatting, fuzz smoke run
$ nix build .#checks-crane-only  # the same without the fuzz smoke run, on the crane build
$ nix build .#cakeys             # the regular buildRustPackage build
$ nix fmt                        # treefmt.nix
$ nix run .#demo                 # the walkthrough (nix/demo.sh)
$ nix run .#fuzz -- lock         # fuzz one target until stopped
$ nix develop                    # cargo, clippy, softhsm, kryoptic, opensc
```

Plain `cargo test` skips the token suites and builds cryptoki without the local patches, which
the Nix build applies ([docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)). The `tpm2` and `ykcs11`
providers are default cargo features; third-party providers can be linked in
(`crates/cli/examples/custom-provider.rs`).

License: MIT OR Apache-2.0.
