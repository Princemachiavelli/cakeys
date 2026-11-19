# Review: examples/secure-boot/sign.nix (56 lines)

Reviewed 2026-11-18 [read]. Summary: a derivation that signs a UKI with the TPM-held db key on the
host advertising the token feature: `requiredSystemFeatures` from mkKeys, the pre-use check, then
systemd-sbsign with the verified URI and the PIN by reference. A clear example of the pseudo-FOD
pattern.

## Findings

### F1. The lock it names is not in the repository — nit

`examples/secure-boot/sign.nix:29`. `lock = ./keys.lock` is "recorded ... and committed" by the
user; in this repository the file does not exist, so nix/lib.nix silently treats it as no lock and
checks.examples evaluates a check without `--lock` (REVIEW_nix_lib.nix.md F1). For a reader copying
the example that is right; for the check it means the evaluated command is not the one a
deployment runs. [read]

**Fixed (2026-11-18):** `lock` is an argument (the host's own); checks.examples passes a version-1 stand-in.

## Design

- The build reads the PIN from `/etc/secure-boot/tpm-pin`, granted through the token's
  `sandboxPaths`; the PIN never enters the store (`--uri-pin source`).

## Checked, no issue

- `uri=$(${db.check})` under the builder's `set -e`: a failed check stops the build before signing.
