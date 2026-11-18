# Review: nix/cloudhsm.nix (102 lines)

Reviewed 2026-11-18 [read]. Summary: the AWS CloudHSM Client SDK 5 packages (PKCS#11 library,
CLI, OpenSSL engine and provider) from AWS's Ubuntu 26.04 debs, pinned by AWS's published SHA-256,
unfree, x86_64-linux only, autoPatchelf'd. Straightforward.

## Findings

None.

## Design

- The repository carries URLs and hashes, never the files; `pkgsCloudhsm` allows exactly these
  unfree names (flake.nix:64-67).

## Checked, no issue

- Every `src` has a fixed hash; nothing is fetched unpinned.
- The OpenSSL module symlinks are relative within `$out/lib`.
