# Examples

Each directory is a keys.toml and a `run.sh` that plays it on throwaway tokens. Each step
requires its exit code, so an example that no longer matches cakeys fails. `checks.examples`
runs all of them in the build sandbox and evaluates their Nix files (`nix build
.#checks.x86_64-linux.examples -L` shows every step). The software TPM is swtpm.

| Example | Shows |
|---|---|
| [`every-object/`](every-object/keys.toml) | Every kind of object cakeys pins: EC (P-256/384/521), Ed25519, Ed448, RSA, AES, generic secret, HMAC and DES3 keys, a certificate, a public key and a data object. Each is born once, on SoftHSM (`create`) or in a file, then imported onto every other kind of token. To kryoptic it moves sealed, to tpm2-pkcs11 through the host, and a YubiKey's pairs are validated against its profile. The dry-run plans say which types a token refuses, and why. |
| [`tls/`](tls/keys.toml) | A TLS server key born in a TPM. A CSR is made from it through pkcs11-provider, and a TLS 1.3 handshake runs on the key file `cakeys check` writes. A key swapped behind cakeys' back fails the check that gates the server. [`configuration.nix`](tls/configuration.nix) is the NixOS side: a check unit that the server's unit requires. The certificate is not pinned: it rotates, the key must not. |
| [`secure-boot/`](secure-boot/keys.toml) | UEFI Secure Boot keys: PK and KEK generated and attested on a YubiKey, db in the build host's TPM. db's certificate is issued from a CSR the TPM signs. `systemd-sbsign` signs an EFI binary with db through the checked URI, and `sbverify` checks it chains to KEK. [`sign.nix`](secure-boot/sign.nix) is that signing as a Nix build, which runs only on the host with the token and checks db first. |
| [`programs/`](programs/keys.toml) | A program in another language ([`sign.py`](programs/sign.py), Python with python-pkcs11). It names a cakeys object, gets the URI from `cakeys check`, and signs with its own PKCS#11 library. When the check fails, the program fails with the check's exit code and never uses the key. |
| [`yubikey-secureboot.toml`](yubikey-secureboot.toml) | Adopting existing Secure Boot keys on a YubiKey, read-only, with [the lock](yubikey-secureboot.lock) a real device produced. |

To run one by hand outside Nix, put `cakeys`, `camigrate` and the token tools on `PATH`, and
set the variables its `run.sh` names. `KEEP=1` keeps the working directory, with its tokens,
keys.toml and keys.lock.

What the files mean: [docs/CONFIG.md](../docs/CONFIG.md) (keys.toml),
[docs/LOCK.md](../docs/LOCK.md) (keys.lock), [docs/CAMIGRATE.md](../docs/CAMIGRATE.md) (moves),
[docs/CAKEYS.md](../docs/CAKEYS.md) (programs, Nix and NixOS).
