# Review: examples/secure-boot/run.sh (45 lines)

Reviewed 2026-11-18 [read]. Summary: the db key on a software TPM: created, a CSR signed through
pkcs11-provider, a certificate from a stand-in KEK, an EFI binary signed with systemd-sbsign
using the URI `check` printed, and `sbverify` against KEK. Mirrors sign.nix's build.

## Findings

None in this file. Its `EFI_STUB` comes from nix/examples.nix, which hard-codes the x86_64 stub
(REVIEW_nix_examples.nix.md F1); the comment at line 10 names `linuxx64.efi.stub` only as an
example.

## Design

None.

## Checked, no issue

- `env -u OPENSSL_CONF` before systemd-sbsign, so the provider is loaded the way sign.nix's build
  loads it, not through lib.sh's OpenSSL config.
