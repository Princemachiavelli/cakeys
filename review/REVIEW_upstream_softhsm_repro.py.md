# Review: upstream/softhsm/repro.py (47 lines)

Reviewed 2026-11-18 [read]. Summary: wraps a fresh AES-256 key under AES-KW, AES-KWP and RSA-OAEP,
unwraps each, and compares CKA_VALUE_LEN and CKA_VALUE with the original; exits 1 on any mismatch.
Clear and minimal.

## Findings

None.

## Design

None.

## Checked, no issue

- It checks the value as well as the length, so a patch that set the length without the right
  material would still fail.
- Each unwrapped key is destroyed; the wrapping keys are session objects.
