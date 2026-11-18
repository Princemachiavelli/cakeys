# Review: crates/profile/src/embedded.rs (37 lines)

Reviewed 2026-11-18 [read]. Summary: the `include_str!` list of the baseline and twelve
profiles this build ships. No findings.

## Findings

None.

## Design

- The order carries meaning (a FIPS twin before its non-FIPS twin so a tie takes it,
  `:18`, `:23`); that ordering contract lives only in comments and in
  `embedded_profiles_load_and_answer`'s name list (`lib.rs:279`), which does pin it.
- Embedding from `../../../profiles` keeps the crate unpublishable (ISSUES.md PUBLISH_REVIEW,
  deferred).

## Checked, no issue

- Every file under `profiles/{hardware,layers,modules}` is listed (12), matching the test's list.
- `Set::add` would silently replace a duplicate name, but the test's exact list catches one.
