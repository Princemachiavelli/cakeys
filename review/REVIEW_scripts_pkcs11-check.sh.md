# Review: scripts/pkcs11-check.sh (146 lines)

Reviewed 2026-11-18 [read]. Summary: runs the third-party pkcs11-check suite against SoftHSM,
kryoptic or tpm2-pkcs11 (over swtpm) on throwaway tokens in one of three passes, then summarises
it beside the caprobe profile. Ad hoc by design (never a check). Cleanup is trapped before the
TPM starts.

## Findings

### F1. A run that produces nothing can report the previous run's results — risk

**Verification:** confirmed. `$out` is a fixed default (scripts/pkcs11-check.sh:35), only `mkdir -p`'d (:59), and nothing removes the old results.json/report.jsonl/coverage.json, so the guard at :141 passes on a stale file and :145 summarises it with exit 0, against the header (:17-18). Impact is bounded: the tool is an ad hoc report, and run.log (rewritten at :135) shows the real exit code. [read]
`scripts/pkcs11-check.sh:59`, `:141-145`. `$out` (default `./pkcs11-check-<module>-<pass>`) is
created with `mkdir -p` and never emptied. If pkcs11-check dies before writing `results.json`, the
guard finds the previous run's file, `pkcs11-check-compare.py` summarises stale results, and the
script exits 0, contrary to its header ("nonzero when the run produced no results", lines 17-18).
Remove `results.json`, `report.jsonl` and `coverage.json` from `$out` before the run, or write
into a fresh directory and move it into place. [read]

**Fixed (2026-11-18):** old results.json, report.jsonl, coverage.json, run.log, summary.md removed before the run. Test: stub pkcs11-check over a stale results.json exits 1 (old: passed the guard).

### F2. `--out` without a value is an unbound-variable error — nit

`scripts/pkcs11-check.sh:39`. `--out` as the last argument hits `set -u` on `$2` instead of the
usage text. Check `$# -ge 2` first. [read]

**Fixed (2026-11-18):** `--out` without a value gives usage (old: looped forever on the unbound $2).

## Design

None.

## Checked, no issue

- `pipefail` keeps pkcs11-check's status through `tee`, and it is recorded, not fatal, as the
  header promises.
- The TPM stack is torn down by the trap whenever it was started (`tpm_up` set before `up`).
