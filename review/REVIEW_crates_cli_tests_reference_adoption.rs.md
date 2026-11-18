# Review: crates/cli/tests/reference/adoption.rs (255 lines)

Reviewed 2026-11-18 [read]. Summary: adoption tests. A certificate standing in for an imported
key's public half (and refused when it is another key's), a PIV-like certificate plus public key
read without login, lock fragments split and joined, the RSA private and public-only paths
agreeing, and P-384/Ed25519 certificates. The identities are pinned to openssl-computed hashes,
which makes these strong oracle tests. No real issues.

## Findings

### F1. Some assertions carry no message — nit

`reference/adoption.rs:121` and `:159` assert `contains(..)` on output without printing it. On a
failure the log shows the run (`km_env` prints it), but the assertion line does not say which
expectation failed. `:117` re-reads the lock right after `:114` for no reason. [read]

## Design

None.

## Checked, no issue

- `a_certificate_stands_in_for_an_imported_keys_public_half`: both the `token-asserted` and the
  `pop-sign` variants of the wrong certificate are refused (13) with the type mismatch named, so the
  refusal does not depend on the proof.
- `adopt_certificate_and_public_only_key`: `pairs` are asserted in both directions, fragments
  rejoin to the full lock byte-equal (`:150`), and a one-sided `pairs` is 17.
- The fixture hashes are independent (openssl), not produced by cakeys.
