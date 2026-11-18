# Review: examples/tls/configuration.nix (85 lines)

Reviewed 2026-11-18 [read]. Summary: the NixOS side of the TLS example: a `services.cakeys.checks`
entry writing pkcs11-provider's key file (0640, group `web`) and gating `web.service`, an
`openssl s_server` stand-in running as `web` with the TPM through tpm2-pkcs11. Evaluated by
checks.examples.

## Findings

### F1. The server must read tpm2-pkcs11's store, which the comment does not mention — nit

`examples/tls/configuration.nix:15`, `:63-69`. Both units use `TPM2_PKCS11_STORE=/var/lib/tpm2-pkcs11`;
the store is created by root in the one-time setup, and the `web` user gets the TPM device (`tss`)
and is told to read the PIN file, but not the store (tpm2-pkcs11 opens its sqlite database, which
may also need write access for its journal). A store left root-only makes the server fail at its
first key load. Uncertain how tpm2-pkcs11 opens the database read-only; name the ownership in the
setup comment. [read]

### F2. Inherits the module's restart gap — nit

`examples/tls/configuration.nix:59`. `requiredBy = [ "web.service" ]` is checked once per boot; a
`systemctl restart web` after a TPM change is not re-checked (REVIEW_nix_module.nix.md F1). [read]

## Design

None.

## Checked, no issue

- The key file holds the URI with `pin-source`, no secret; written only on a passing check.
