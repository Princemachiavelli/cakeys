# cakeys

[![checks](https://github.com/Princemachiavelli/cakeys/actions/workflows/checks.yml/badge.svg)](https://github.com/Princemachiavelli/cakeys/actions/workflows/checks.yml)
[![License](https://img.shields.io/github/license/Princemachiavelli/cakeys)](LICENSE)
[![MSRV](https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2FPrincemachiavelli%2Fcakeys%2Fmain%2FCargo.toml&query=%24.workspace.package%5B%22rust-version%22%5D&label=MSRV&prefix=rustc%20)](Cargo.toml)
[![coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FPrincemachiavelli%2Fcakeys%2Fbadges%2Fcoverage.json)](docs/DEVELOPMENT.md#testing)
[![mutants caught](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FPrincemachiavelli%2Fcakeys%2Fbadges%2Fmutants.json)](docs/archive/COVERAGE_PLAN.md#mutation-report-2026-11-15)

cakeys provides content-addressed identity for PKCS#11 objects, as a Nix flake.

You declare keys, certificates and data objects in `keys.toml`. cakeys finds them on a token by a
locator (`CKA_LABEL`/`CKA_ID`), identifies them by a **hash of their material** (a CA-ID), and
records that hash in `keys.lock`. A label or a URI can be changed or reused, but the hash cannot.
A check before each use, including a check inside a Nix build sandbox, verifies that the token
still holds exactly that material. A private key also proves possession of the material: it
signs, derives from, decrypts or unwraps a fresh challenge, and the host checks the result.

Status: cakeys is a proof of concept. It runs on x86_64-linux, aarch64-linux and aarch64-darwin
(without the TPM provider), and the lock format `version = 1` is still a draft. Every Nix build
tests it against SoftHSM, kryoptic, tpm2-pkcs11 (swtpm) and SoftHSM behind p11-kit, and it was
tested by hand on a YubiKey 5C NFC FIPS and an AMD fTPM. `nix run .#demo` demonstrates it step
by step on throwaway tokens.

## Three tools

| Tool | Job | Verbs | Document |
|---|---|---|---|
| `cakeys` | It pins and verifies keys. | `validate`, `resolve`, `lock`, `create`, `delete`, `gc`, `check`; the Nix library and NixOS module | [docs/CAKEYS.md](docs/CAKEYS.md) |
| `caprobe` | It measures modules and writes capability profiles. It is the only tool that creates scratch objects. | `probe`, `supports`, `caps` | [docs/CAPROBE.md](docs/CAPROBE.md) |
| `camigrate` | It moves keys between tokens. It is the only tool that handles key material. | `export`, `import`, `migrate`, `transport` | [docs/CAMIGRATE.md](docs/CAMIGRATE.md) |

All three tools share one workspace, one flake (`nix run .#caprobe`, `.#camigrate`) and the exit
codes. A `cakeys` build contains no probe or migration code.

## What it is for

- **A copy holds the same material.** When you clone HSM A onto HSM B, or move keys between
  vendors, lock each token into one lock. B's copy must then hash to A's locked identities
  (otherwise the result is 10).
- **A key is the kind of key that the software was tested with.** The spec declares the type and
  the policy (sign-only, non-extractable, …). Another type is refused (13), policy drift is
  reported (14), and a key that was generated on the device can be distinguished from an
  imported key (`CKA_LOCAL`, attestation).
- **An old backup still holds the material.** `check` recomputes every identity from the token,
  and labels only locate the objects.
- **A module update that changed something is detected.** The lock records the module and the
  token behind each entry, and `caprobe probe --diff` compares a token with its committed
  capability profile.
- **A signing build signs with the pinned key.** The build runs `cakeys check` first, as a pseudo
  fixed-output check, and the NixOS module grants a token only to the builds that require it.
- **A service never starts with the wrong key.** `services.cakeys.checks.<name>` makes units
  depend on the identity check.
- **A move between tokens is stated and verified.** `camigrate` says for each object how it can
  move (`sealed` under a key on the target, `enforced` by the source token, through the host, or
  as a file), and the import is verified against the lock.

cakeys records and verifies, and it does not decide how keys are managed. These things are out
of scope: crypto implementations and key generation on the host, rotation and approval policy,
the storage of secrets or PINs, acting as a PKCS#11 module, CA work, and proving that a key
exists nowhere else. Anything that is true of only one vendor is in that vendor's provider
crate, behind the `Provider` trait.

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
tokens.softhsm = { locator = { CKA_LABEL = "signing" }, origin = "create" }
```

```console
$ cakeys -c keys.toml --new-lock create signing --no-update-lock   # no keys.lock yet: --new-lock
created 'signing' (spec 'signing-soft') on token 'softhsm'
error: first use of 'signing' (spec 'signing-soft') on token 'softhsm': the lock pins no identity for it yet; review, then `lock` records it
     got:    sha256-…            # exit 18, compare only: like a fixed-output derivation
$ cakeys -c keys.toml --new-lock lock signing   # record it, print the resolved JSON; exit 22: review the keys.lock diff
$ cakeys -c keys.toml check signing     # later: verify, then print the URI (never writes)
pkcs11:token=main;serial=...;object=signing;type=private
```

Every verb names the object, and `--spec` and `--token` narrow the address where keys.toml
realises the object more than once. Of cakeys' verbs, only `create` makes the keys that
keys.toml declares, and only where keys.toml says `origin = "create"`. `lock` and `check` find
what is there (`lock` may also provision a TPM Attestation Key, DESIGN §3.7). `create`, `lock`
and `delete` write the lock by default, and they only fill gaps: a locked ID is never
overwritten. A realisation that changed (its locator, its spec or its policy attributes) is
recorded again, and each accepted change is printed (`re-recorded …`). Where the lock cannot be
written (in a Nix build sandbox, or with a read-only lock or directory), these verbs refuse to
run (21) before they start, unless they are told not to write (`lock --dry-run`,
`delete --dry-run`, `create --no-update-lock`). A run that wrote the lock exits 22, never 0, so
that a script reviews the change deliberately. The run exits 22 even when a pair failed after
the write: the failed pair's row keeps its own code, and a note on stderr says why the run exits
22. A lock that does not exist is refused (17) unless `--new-lock` is given, so a mistyped
`--lock` never starts a second lock.

## Supported objects

| Class | Types | Identity |
|---|---|---|
| private/public keys | EC P-256/384/521, secp256k1, brainpoolP256r1/P384r1; Ed25519/Ed448; RSA 1024–8192 | `rfc7093m4` (SHA-256 of canonical SPKI) |
| certificates | X.509 | `certhash` plus the subject key's `rfc7093m4` |
| secret keys | AES-128/192/256; Triple DES (`CKK_DES3`); generic secrets; `CKK_SHA{1,224,256,384,512}_HMAC` | on-token commitments: `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`, `commitment` (HMAC); DES3 by `kcv-ecb`, `kcv-ecb-dec` |
| data objects | `CKO_DATA`: public, or private when the spec declares `CKA_PRIVATE = true` | `valuehash` (SHA-256 of the value) |

Attestation is opt-in (`attestation = true` on a spec's token entry), and it adds signed
provenance: `piv-attestation` (YubiKey PIV, verified to the pinned Yubico root) and `tpm-certify`
(tpm2-pkcs11, a native `TPM2_Certify`). The lock records an attestation per realisation beside
the portable ID, never instead of it.

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

`signing` is plain data that holds only what evaluation knows without the token: `type`,
`id.<scheme>`, the resolved `spec` and `token`, `requiredSystemFeatures` and `check`. Use
`scheme = "certhash"` to require one identity, and `checkArgs` for `cakeys check`'s own flags.
The URI that a consumer uses is the one that `check` prints after it has verified the key, never
a URI read from the lock. `cakeys resolve` reports the rest, including `assurance`, which says
what the check establishes against a token that may report false values (DESIGN §3.6, §3.7).

A cached consumer is not rebuilt, so the token is not contacted again; `nix build --check`
forces the check.

The NixOS module (`nixosModules.default`, `services.cakeys`) gives a token's sandbox paths, and
pcscd or the TPM, **only to builds that require that token's feature** (through a
pre-build-hook). However, the pcscd and TPM grants apply to the whole host: pcscd serves every
reader, and `/dev/tpmrm0` is the whole TPM. A build that is granted either one therefore reaches
every card that is plugged in, or every TPM object that its authorization allows, not only that
token's objects. The module also defines check units that make services depend on the key's
identity. Real builds reach tokens only through p11-kit forwarding or a real TPM, never through
a token database.

## Documentation

| | |
|---|---|
| [docs/DESIGN.md](docs/DESIGN.md) | Identity schemes, the lock rules, proof of possession, attestation, the security model |
| [docs/CONFIG.md](docs/CONFIG.md), [docs/LOCK.md](docs/LOCK.md) | `keys.toml` and `keys.lock`, annotated |
| [docs/CAKEYS.md](docs/CAKEYS.md), [docs/CAPROBE.md](docs/CAPROBE.md), [docs/CAMIGRATE.md](docs/CAMIGRATE.md) | The three tools |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Crates, control flow, providers |
| [docs/diagrams.md](docs/diagrams.md) | The model, a verb, proof of possession, the Nix loop |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) | Building, testing, the hardware rules |
| [docs/REVIEWING.md](docs/REVIEWING.md) | How a finding is fixed (by class) and how a review is run |
| [docs/OPEN.md](docs/OPEN.md) | Open and parked items |
| `docs/archive/`, `reports/`, `research_notes/` | Dated reviews and plans still cited, the lock-format research |

## Development

```console
$ nix flake check                # every check: token suites, VMs, module, minimal build, formatting, fuzz smoke run
$ nix build .#checks-crane-only  # the same without the fuzz smoke run, on the crane build
$ nix build .#cakeys             # what users get: the checks' crane build, its tests not rerun
$ nix fmt                        # treefmt.nix
$ nix run .#demo                 # the walkthrough (nix/demo.sh)
$ nix run .#fuzz -- lock         # fuzz one target until stopped
$ nix develop                    # cargo, clippy, softhsm, kryoptic, opensc
```

Plain `cargo test` skips the token suites, and it builds cryptoki without the local patches,
which the Nix build applies ([docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)). The `tpm2` and
`ykcs11` providers are default cargo features, and third-party providers can be linked in
(`crates/cli/examples/custom-provider.rs`).

License: BSD-3-Clause ([LICENSE](LICENSE)).
