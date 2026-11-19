# Review: nix/test.nix (222 lines)

Reviewed 2026-11-18 [read]. Summary: NixOS integration test on SoftHSM, as a QEMU VM (with the
pseudo-FOD consumer built inside the guest's sandbox through the module's hook) or an nspawn
container (CLI only). Covers first use (18), out-of-band recording, an independent
pkcs11-tool/openssl oracle, wrap-rebind, DELETE with If-Match, and the cached-consumer caveat.

## Findings

### F1. The token store is made world-writable — nit

`nix/test.nix:80`, `:105`, `:128`. `0777` tmpfiles and `chmod -R a+rwX` before every build so the
nixbld builder can use the SoftHSM files. Test-only, but it means the VM test exercises exactly
the configuration docs/CAKEYS.md ("What real builds may reach") says never to deploy (a token
database inside the sandbox), and not the recommended p11-kit socket. A comment saying so would
stop it being copied. [read]

**Fixed (2026-11-18):** comment: test-only, not a configuration to copy.

## Design

- Duplicated setup with nix/module-test.nix and nix/tpm-test.nix: see
  REVIEW_nix_module-test.nix.md F2.

## Checked, no issue

- ISSUES.md "To test: create and exit 19": each key is created once (`create ... --no-update-lock`
  expecting 18, then `lock --update-lock`); unaffected by B2.
- Exit codes asserted exactly (`expect`), and the oracle compares the base64 SHA-256 of the
  canonical SPKI with the lock.
- The container variant mounts a tmpfs on `/var` only when it is not writable.
