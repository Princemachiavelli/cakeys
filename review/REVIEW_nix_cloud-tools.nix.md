# Review: nix/cloud-tools.nix (26 lines)

Reviewed 2026-11-18 [read]. Summary: a `symlinkJoin` of OpenTofu (with the AWS and Google
providers from nixpkgs, so `tofu init` downloads nothing), the AWS CLI, gcloud, jq, curl and
OpenSSL for scripts/cloud/. Nothing to report.

## Findings

None.

## Design

None.

## Checked, no issue

- Providers come from nixpkgs via `withPlugins`, pinned by the flake.lock.
