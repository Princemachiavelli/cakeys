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
- **Tested by hand on a YubiKey 5** (PIV through ykcs11), not in CI: adopted keys verify
  read-only, and an opt-in read-write suite generates a key in a scratch slot (as SO with the
  management key), attests it, proves possession and verifies it.
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
overwritten. Where the lock cannot be written (a Nix build sandbox, a read-only lock or
directory) they refuse up front unless `--no-update-lock` is passed.

Verbs:

- `validate`, `resolve`, `verify`, `realise [--no-update-lock]`, `delete [--if-match] [--no-update-lock]`,
  `check <object>[.id.<scheme>]`, `gc [--apply]` and `caps`.
- They behave like HTTP verbs: safe to repeat, never create over an occupied locator, never delete
  an unexpected object. `gc` prints lock entries the config no longer names and removes exactly
  what it printed with `--apply`.
- Exit codes: 10 hash mismatch, 11 not found, 12 ambiguous, 13 conflict, 14 precondition failed,
  15 unsupported, 16 unavailable, 17 invalid config, lock or spec; 1 I/O or other, 2 usage.

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
  requiredSystemFeatures = signing.rsf;
} ''
  # Pre-use check: fails the build unless the token holds the locked material.
  uri=$(${signing.check})
  # ... sign with "$uri" ...
''
```

`signing` is plain data from the resolved pair: `id.<scheme>`, `uri`, `mode`, `specDigest`,
`module`, `tokenInfo`, `functions`, `rsf` and `check` (use `scheme = "certhash"` to require one
identity).

A cached consumer is not rebuilt, so the token is not re-contacted; `nix build --check` forces it.

The NixOS module (`nixosModules.default`, `services.cakeys`) gives a token's sandbox paths,
and pcscd or the TPM, **only to builds that require that token's feature** (through a
pre-build-hook). It also defines check units that gate services on the key's identity. Real builds
reach tokens only through p11-kit forwarding or a real TPM, never through a token database.

## Development

```console
$ nix flake check            # unit, SoftHSM, tpm2-pkcs11 (swtpm), p11-kit, VM, module and TPM ACL tests, minimal build, formatting
$ nix fmt                    # treefmt.nix: rustfmt, nixfmt, taplo, shfmt, rumdl, keep-sorted; statix, deadnix, shellcheck, typos
$ nix build .#test-nspawn    # the same flow in systemd-nspawn (needs the uid-range feature)
$ nix develop                # cargo, clippy, softhsm, opensc
```

Plain `cargo test` skips the token suites unless `CAKEYS_TEST_MODULE` and friends are set (see the
test file headers). It also builds cryptoki without the local HMAC key-type patch, which the Nix
build applies. The `tpm2` and `ykcs11` providers are default cargo features;
`--no-default-features` builds without tpm2-tss and sqlite. Third-party providers can be linked
in: see `crates/cli/examples/custom-provider.rs`.

License: MIT OR Apache-2.0.
