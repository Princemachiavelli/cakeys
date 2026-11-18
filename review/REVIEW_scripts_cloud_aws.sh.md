# Review: scripts/cloud/aws.sh (492 lines)

Reviewed 2026-11-18 [read]. Summary: the CloudHSM test bed: OpenTofu for VPC, cluster, HSM and a
NixOS runner; cluster init with a self-made CA; activation and a crypto user; a write probe,
cakeys and camigrate on the runner; guarded destroy and park; a region-wide `status`. The guard
against a plan that deletes the cluster, the separate state per mode, and passwords travelling
on SSH's stdin are well thought out. Findings are minor.

## Findings

### F1. The crypto user's PIN can be left on the runner — nit

`scripts/cloud/aws.sh:330`, `:352`, `:384`. `probe` writes `caprobe:<password>` to
/run/caprobe/pin and removes it after the probe, but any failing `runner` step in between (the
`tar` of profiles, the `install` of the old profile) exits under `set -e` before the `rm`.
`tool` writes /run/cakeys/pin and never removes it. It is tmpfs on a short-lived runner reachable
only from this machine's address, hence nit; a `trap 'runner rm -f ...' RETURN` would make it
deterministic. [read]

### F2. `out` swallows OpenTofu errors — nit

`scripts/cloud/aws.sh:97`. `tofu output -raw "$1" 2>/dev/null || true`: a broken state or backend
yields an empty value, and later commands fail far from the cause (`ssh root@` with no host,
"no cluster: run create"). Distinguish "no such output" from a failing `tofu`. [read]

## Design

- The admin and crypto-user passwords and the CA key sit unencrypted in the state directory, and
  are cloudhsm-cli arguments on the runner while it runs; both are stated in the header and
  comments (lines 18-24, 288-289). Acceptable for a throwaway test bed.
- Binary building is repeated with gcp.sh (see REVIEW_scripts_cloud_gcp.sh.md, Design).

## Checked, no issue

- `apply_guarded` refuses any plan whose actions delete `aws_cloudhsm_v2_cluster.this` and
  remembers the var file before applying.
- `destroy` without `--park` refuses an initialized cluster unless `--yes`, and records the
  cluster ID so an interrupted destroy can still delete its backups.
- `status` fails (non-zero) if the AWS calls fail, so it errs towards "something bills".
- `printf -v args '%q '` quotes the user's arguments for the remote shell.
