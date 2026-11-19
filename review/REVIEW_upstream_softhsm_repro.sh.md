# Review: upstream/softhsm/repro.sh (16 lines)

Reviewed 2026-11-18 [read]. Summary: SoftHSMv2 #628 reproduction: a throwaway token and
repro.py's unwrap round trips against a given libsofthsm2.so; exits 1 while CKA_VALUE_LEN reads 0.
Used by checks.softhsm-unwrap-value-len. Nothing to report.

## Findings

None.

## Design

None.

## Checked, no issue

- `mktemp -d` with a removal trap; the module defaults to the one beside `softhsm2-util`.
