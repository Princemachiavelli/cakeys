# Review: fuzz/fuzz_targets/piv_chain.rs (10 lines)

Reviewed 2026-11-18 [read]. Summary: a two-byte length, slot certificate DER and device
certificate DER, verified as `check` verifies a PIV chain (Yubico's roots, then the fixture
root) at a fixed time (`crates/ykcs11/src/attest.rs:221`, so runs are deterministic). Property:
"never a panic" only. No findings.

## Findings

None.

## Design

- Any mutation inside a signed TBS breaks its signature, so the fuzzer reaches the chain logic
  (name links, `basicConstraints`, path length, dates) only with the unmodified fixture; what it
  really exercises is DER parsing of the two certificates and whatever is read before the
  signature checks. The chain rules themselves are better covered by constructed-certificate
  unit tests than by this target. Appropriate as a panic smoke test.

## Checked, no issue

- `split_at_checked` on the length prefix: short input refused, not indexed.
