# Reviewing and fixing

How a finding is fixed and how a review is run.

The rules come from the 2026-11-24 review ([summary](archive/REVIEW-2026-11-24.md)). Over six
reviews:

- 85% of fixes came with a test, but only 11% of those tests covered the class. 88% of fixes had
  a sibling, an incomplete fix or a recurrence found later.
- 45% of the Rust was last written by a review fix, and 87% of that review's findings cite such
  lines.

A test that pins the reported input does not stop the next instance. The rules below are there
to fix the class instead.

## Fixing a finding

A finding is closed only when all four hold:

1. **The class is named.** Use the escape codes below in the commit body: what kind of defect
   it is, and why no test caught it.
2. **The siblings are searched for, and the search is recorded.** Record the `rg` pattern and
   its hit count in the commit body. Search every language the rule is spelled in: Rust, Nix,
   shell, the docs and the examples. Fix every sibling, or list the ones left and why.
3. **The test covers the rule, not the reported input, and it was seen failing.**
   - Write a table over every entry path (real run, `--dry-run`, validate, probe, migrate, each
     provider), or a property over the inputs.
   - Run it against the unfixed code, or with the rule mutated, and record that red run.
   - A test never seen failing does not count.
4. **The gate's first tier is green** ([DEVELOPMENT.md](DEVELOPMENT.md)). Nothing merges
   unbuilt. A fix that can only be verified on hardware says so in `Not run:`, and the
   [ledger](CAPROBE.md#the-ledger) records it.

Prefer the change that removes the class to the test that detects it: a type that cannot hold
the bad state, or a rule checked inside the operation instead of at each caller.

## Commit trailers

Every commit says what verified it:

```text
Ran: `nix develop -c cargo test -p cakeys-core` 131 passed; the new test red before the fix
Not run: `nix build .#checks.x86_64-linux.examples` (Linux, CI)
```

`Ran:` lists each command and its result. `Not run:` gives the exact command that would verify
the rest. A commit with neither has verified nothing: 84% of commits before 2026-11-24 said
nothing about what ran.

## Running a review

- **Start from what runs.** Read CI's state for the reviewed commit, run the first tier, and
  read the [ledger](CAPROBE.md#the-ledger) for what is stale. A review that does not know what
  is red reviews the wrong tree.
- **Ask why each finding escaped.** Every finding names its escape codes, its siblings (counted)
  and a class fix as well as an instance fix. The template is the 2026-11-24 review's
  [criteria](archive/REVIEW-2026-11-24/criteria.md).
- **Do a mutation pass.** For each security- or correctness-critical decision in a file, ask:
  if it were flipped, which test would fail? A decision with no failing test is a finding even
  when the code is right.
- **Audit the entry points.** For each rule, list every path that reaches the same operation. A
  rule enforced on only some of them is a finding.
- **Report classes.** Group findings by class with their sibling lists, so the fixes go by
  class.
- **Audit the last round's fixes.** For each one, decide whether it holds, covers the instance
  only, is wrong, or regressed. The rate of class-level tests and the rate of later siblings
  (the [2026-11-24 F report](archive/REVIEW-2026-11-24/F.md), §2.1) are the numbers to improve.

## Escape codes

| Code | Meaning |
|---|---|
| T-ABSENT | No test reaches the path. |
| T-ORACLE | A test reaches it but asserts the wrong thing: an exit code, prose or a count instead of the result. |
| T-TAUTO | The expected value comes from the code under test. |
| T-GATED | The test exists but skips, or no runner runs it: it needs a token, hardware, cloud or a platform. |
| T-FRIENDLY | Only a well-behaved token, module or file exercises it; the lying case is not modelled. |
| T-INSTANCE | The regression test covers the reported instance only. |
| D-MULTIPATH | The rule is enforced on one entry path, and others skip or re-implement it. |
| D-PARALLEL | Hand-synced tables, lists or docs that must agree. |
| D-TYPES | An invalid state can be represented, and validity rests on call-site discipline. |
| D-SEAM | A hook's default or override changes semantics silently. |
| D-FAILOPEN | An error, an absence or "unknown" becomes a verdict (yes, no, ok, a default). |
| D-DOCS | A doc or comment states a guarantee nothing checks. |
| P-UNRUN | The fix was written without building or running it. |
| P-REVIEW | A prior review read the code and missed the finding. |
