# Review: scripts/cloud/gcp.sh (222 lines)

Reviewed 2026-11-18 [read]. Summary: the Cloud KMS test bed: OpenTofu for the key ring, caprobe
read-only or write probes through both libkmsp11 builds, cakeys against pre-created keys, and
`status`/`destroy` for the key versions that bill. Careful about cost (24-hour destroy duration,
preflight refusing a write probe on keys libkmsp11 would create with 30 days). The billing guard
itself fails open.

## Findings

### F1. `live_versions` hides gcloud failures, so `status` reports "nothing billing" when it cannot tell — risk

**Verification:** confirmed. scripts/cloud/gcp.sh:83 runs `gcloud kms keys list` as a `for` word list, whose failure errexit ignores even with `inherit_errexit` (:36-37); a loop with no iterations returns 0, so `status` (:194-203) prints "none" and exits 0, and `destroy`/the `--write` guard (:186) see nothing. Mitigation only: the outer gcloud's stderr is not suppressed, so its error is printed. [read]
`scripts/cloud/gcp.sh:81-87`, used by `status` (194-203), `destroy` (205-210) and the end of
`probe --write` (186-190). Each `versions list` ends in `2>/dev/null || true`, and the outer
`gcloud kms keys list` runs in a `for ... in $(...)` word list, where a failing command
substitution does not trip `errexit` even with `inherit_errexit`. With expired credentials, a
wrong project or an API error, `live_versions` prints nothing: `status` prints "none" and exits 0,
`destroy` destroys nothing and says nothing, and a write probe does not warn that it left billing
versions. Assign the key list to a variable first (`keys=$(gcloud ...)`, which errexit covers) and
let `versions list` errors through, so the guard fails closed. [read]

### F2. `destroy` shadows the global `state` — nit

`scripts/cloud/gcp.sh:206`. `local name state` reuses the name of the state directory variable
(line 41). Harmless today (nothing in the loop reads the directory), a trap for the next edit;
rename the loop variable. [read]

### F3. Roundabout config path — nit

`scripts/cloud/gcp.sh:141`. `"$tf/../gcp/cakeys.toml"` is `$tf/cakeys.toml`. [read]

## Design

- The caprobe/cakeys binary is built with the same `getFlake ... overrideAttrs { doCheck = false; }`
  expression in four places across gcp.sh and aws.sh, and in regen-profiles.sh's header; a flake
  attribute (`packages.cakeys-unchecked`) would make it one name.

## Checked, no issue

- libkmsp11's config is written under `umask 077` in a subshell (it refuses group-writable files).
- `preflight` compares the table's labels with keys that have the 24-hour duration, via `comm`.
- Credentials come from ADC files by path; no secret is put on a command line.
