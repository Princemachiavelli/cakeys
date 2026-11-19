# Review: crates/cli/tests/cloud.rs (247 lines)

Reviewed 2026-11-18 [read]. Summary: opt-in end-to-end tests against AWS CloudHSM and GCP Cloud
KMS through `scripts/cloud/*.sh`. Each run has its own labels and lock, and everything it created
is deleted even when an assertion fails (`with_cleanup` catches and re-raises the panic). Careful
about cost and cleanup, with small gaps.

## Findings

### F1. The AWS lock is written to `/tmp`, outside the directory cleanup removes — practice

`cloud.rs:126`: `/tmp/cakeys-{id}.lock` and its `.lck` sidecar are outside `dir`, the only thing
cleanup removes (`:194`). Every run leaves two files behind. Put the lock in `dir`, as the GCP test
does (`:212`). [read]

### F2. Cleanup covers only keys whose `create` or `migrate` returned 0 — nit

`cloud.rs:152-154, 172, 177-181, 224-226`. A spec is pushed onto `created` only after its command
succeeds. A `create` that fails after generating relies on cakeys' own undo ("removed N object(s)
just created", tested in fault.rs) or on the lock record it writes before failing. A `migrate` that
copies and then fails, or a dropped connection, can leave a labelled, billed key that cleanup never
visits. GCP catches this through `gcp.sh status`; AWS has no such check. Fix: push before running.
Cleanup already logs and tolerates a failed `delete`. [read]

### F3. The exit codes are cited from a document that does not exist — nit

`cloud.rs:25` cites "docs/CLI.md exit codes". There is no docs/CLI.md; the codes are in
docs/CAKEYS.md. [read]

**Fixed (2026-11-18):** cloud.rs cites docs/CAKEYS.md's exit codes. No test.

## Design

None.

## Checked, no issue

- `with_cleanup` runs cleanup on panic and re-raises; GCP's status is checked after cleanup.
- Labels and lock are per run (`run_id()` plus mode), so two clusters tested at once never meet.
- `asked` skips inside a Nix build and prints its reason otherwise. No require variable, by design
  (opt-in, billed).

## Resolutions (2026-11-18)

- F1 **Fixed (2026-11-18):** the AWS lock is `dir/keys.lock`, which cleanup removes. Test: `aws_cloudhsm_end_to_end` (not run: cloud).
- F2 **Fixed (2026-11-18):** each key is pushed for cleanup before its create or migrate. Tests: both cloud tests (not run).
