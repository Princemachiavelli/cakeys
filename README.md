# cakeys

Content-addressed identity for PKCS#11 (and later TPM) objects, as a Nix flake.

Declare keys, certificates and data objects in `keys.toml`. cakeys finds them on a token by a
locator (`CKA_LABEL`/`CKA_ID`), identifies them by a **hash of their material** (a CA-ID), and
records that hash in `keys.lock`. A label or URI can be changed or reused; the hash cannot. Every
use, including inside a Nix build sandbox, first checks that the token still holds exactly that
material. A private key also proves possession: by signing, deriving (ECDH) or decrypting (OAEP) a
fresh challenge — whichever capability the key declares — which the host checks against the public
key it hashed.

Status: proof of concept.
- **Tested** against SoftHSM, tpm2-pkcs11 (swtpm, QEMU vTPM) and SoftHSM behind p11-kit forwarding.
- **Verified read-only** against a YubiKey (PIV).
- **Design and current state:** [`docs/DESIGN.md`](docs/DESIGN.md).
- **At a glance (diagrams):** [`docs/diagrams.md`](docs/diagrams.md).
- **Open review findings:** [`docs/REVIEW-2026-11-11.md`](docs/REVIEW-2026-11-11.md).
- **Roadmap and history:** [`PLAN.md`](PLAN.md).

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
$ cakeys -c keys.toml realise signing-soft --token softhsm
created 'signing' (spec 'signing-soft') on token 'softhsm'
error: hash mismatch in identity of 'signing' (spec 'signing-soft') on token 'softhsm':
  specified: <none>
     got:    sha256-…            # first use: like a fixed-output derivation
$ cakeys -c keys.toml realise signing-soft --token softhsm --update-lock   # record it
$ cakeys -c keys.toml check signing     # later: verify, then print the URI
pkcs11:token=main;serial=...;object=signing;type=private
```

Verbs:
- `validate`, `resolve`, `verify`, `realise [--update-lock]`, `delete [--if-match] [--update-lock]`,
  `check <object>[.id.<scheme>]`, `gc [--apply]` and `caps`.
- They behave like HTTP verbs: safe to repeat, never create over an occupied locator, never delete
  an unexpected object. `gc` prints lock entries the config no longer names and removes exactly
  what it printed with `--apply`.
- Exit codes: 10 hash mismatch, 11 not found, 12 ambiguous, 13 conflict, 14 precondition failed,
  15 unsupported, 16 unavailable, 17 invalid spec.

## Supported objects

| Class | Types | Identity |
|---|---|---|
| private/public keys | EC P-256/384/521, secp256k1, brainpoolP256r1/P384r1; Ed25519/Ed448; RSA 1024–8192 | `rfc7093m4` (SHA-256 of canonical SPKI) |
| certificates | X.509 | `certhash` plus the subject key's `rfc7093m4` |
| secret keys | AES-128/192/256; generic secrets; `CKK_SHA{1,224,256,384,512}_HMAC` | on-token commitments: `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`, `commitment` (HMAC) |
| data objects | public `CKO_DATA` | `valuehash` (SHA-256 of the value) |

## Nix

```nix
let
  keys = cakeys.lib.mkKeys {
    config = ./keys.toml;
    lock = ./keys.lock;
    cakeys = cakeys.packages.x86_64-linux.default;
    modules.softhsm = "${pkgs.softhsm}/lib/softhsm/libsofthsm2.so";
  };
in
pkgs.runCommand "signed-artifact" {
  # Only hosts that advertise the token's feature build this.
  requiredSystemFeatures = keys.signing.rsf.softhsm;
} ''
  # Pre-use check: fails the build unless the token holds the locked material.
  uri=$(${keys.signing.check { token = "softhsm"; }})
  # ... sign with "$uri" ...
''
```

A cached consumer is not rebuilt, so the token is not re-contacted; `nix build --check` forces it.

The NixOS module (`nixosModules.default`, `services.cakeys`) gives a token's sandbox paths,
and pcscd or the TPM, **only to builds that require that token's feature** (through a
pre-build-hook). It also defines check units that gate services on the key's identity. Real builds
reach tokens only through p11-kit forwarding or a real TPM, never through a token database.

## Development

```console
$ nix flake check            # unit, SoftHSM, tpm2-pkcs11 (swtpm), p11-kit, VM, module and TPM ACL tests
$ nix build .#test-nspawn    # the same flow in systemd-nspawn (needs the uid-range feature)
$ nix develop                # cargo, clippy, softhsm, opensc
```

Plain `cargo test` skips the token suites unless `CAKEYS_TEST_MODULE` and friends are set (see the
test file headers). It also builds cryptoki without the local HMAC key-type patch, which the Nix
build applies. Third-party providers can be linked in: see
`crates/cli/examples/custom-provider.rs`.

License: MIT OR Apache-2.0.
