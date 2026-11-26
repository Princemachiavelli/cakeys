# Reviewing and fixing

This document describes how a finding is fixed and how a review is run.

The rules come from the 2026-11-24 review ([summary](archive/REVIEW-2026-11-24.md)). That review
audited 41 fixes from the six earlier reviews and measured the following:

- 85% of the fixes came with a test, but only 11% of those tests covered the class of the defect.
  88% of the fixes had a sibling, an incomplete fix or a recurrence that a later review found.
- At the time of the review, 45% of the lines of Rust in `crates/` had last been changed by a
  commit that fixed a review finding, and 87% of the review's own findings cite at least one such
  line.

A test that pins the reported input does not stop the next instance of the same defect. The rules
below exist so that a fix covers the class of the defect instead.

## Fixing a finding

A finding is closed only when all four of the following conditions hold:

1. **The class is named.** Use the escape codes below in the commit body. The codes say what kind
   of defect it is and why no test caught it.
2. **The siblings are searched for, and the search is recorded.** Record the `rg` pattern and its
   hit count in the commit body. Search every language in which the rule is written: Rust, Nix,
   shell, the docs and the examples. Fix every sibling, or list the siblings that are left and the
   reason for each.
3. **The test covers the rule, not the reported input, and it was seen failing.**
   - Write a table of cases over every entry path (a real run, `--dry-run`, validate, probe,
     migrate, each provider), or a property over the inputs.
   - Run the test against the unfixed code, or with the rule mutated, and record that failing run
     in `Ran:`.
   - A test that was never seen failing does not count.
4. **The gate's first tier passes** ([DEVELOPMENT.md](DEVELOPMENT.md)). Nothing merges without
   being built. When a fix can only be verified on hardware, the commit says so in `Not run:`, and
   the [ledger](CAPROBE.md#the-ledger) records it.

Prefer the change that removes the class to the test that detects it. Examples of such a change
are a type that cannot hold the bad state, and a rule that is checked inside the operation instead
of at each caller.

## Commit trailers

Every commit says what verified it:

```text
Ran: `nix develop -c cargo test -p cakeys-core` 131 passed; the new test red before the fix
Not run: `nix build .#checks.x86_64-linux.examples` (Linux, CI)
```

`Ran:` lists each command and its result. `Not run:` gives the exact command that would verify
the rest. A commit with neither trailer has verified nothing. Before 2026-11-24, 84% of the
commits (340 of 406) said nothing about what ran.

## Running a review

- **Start from what runs.** Read CI's state for the commit under review, run the first tier, and
  read the [ledger](CAPROBE.md#the-ledger) for the results that are stale. A review that does not
  know which checks fail cannot tell which parts of the code it reads are built and tested.
- **Start from the survivors.** A survivor is a mutant that no test caught: a small change that
  cargo-mutants made to the code, such as `==` replaced by `!=`, with which every test still
  passed. A survivor marks a decision in the code that no test checks.
  - For the files under review, read `missed.md` from the last monthly sweep (the artifact
    `mutants-missed` of `.github/workflows/mutants.yml`) and the entries with `reviewed = false`
    in `nix/mutants-baseline.toml`. `missed.md` lists the `Check` and `Rule` variants that each
    function names, so start with the functions that make a named security decision.
  - Turn each survivor into exactly one of three things. The first is a test that fails on the
    mutant and was seen failing, in a commit that also deletes the baseline entry and lowers `max`
    by one. The second is a finding, because no test checks the decision. The third is a reviewed
    reason: replace the seeded `why` with the reason that the mutant needs no test, and set
    `reviewed = true`.
  - [DEVELOPMENT.md](DEVELOPMENT.md#mutation-testing) describes the mutation gate.
- **Ask why each finding escaped.** Every finding names its escape codes, its siblings (with their
  count), and a fix of the class as well as a fix of the instance. The 2026-11-24 review's
  [criteria](archive/REVIEW-2026-11-24/criteria.md) are the template.
- **Do a mutation pass by hand only where no tier mutates.** For each decision that is critical to
  security or correctness in a file that `nix/mutants-scopes.toml` leaves out, ask which test
  would fail if the decision were reversed. A decision for which no test would fail is a finding,
  even when the code is right.
- **Audit the entry points.** For each rule, list every path that reaches the same operation. A
  rule that is enforced on only some of those paths is a finding.
- **Report classes.** Group the findings by class, each with its list of siblings, so that the
  fixes are made by class.
- **Audit the last round's fixes.** For each fix, decide whether it holds, covers the instance
  only, is wrong, or regressed. The rate of tests that cover the class and the rate of siblings
  found later (the [2026-11-24 F report](archive/REVIEW-2026-11-24/F.md), §2.1) are the numbers to
  improve.

## Escape codes

| Code | Meaning |
|---|---|
| T-ABSENT | No test reaches the path. |
| T-ORACLE | A test reaches the path, but it asserts the wrong thing: an exit code, prose or a count instead of the result. |
| T-TAUTO | The expected value comes from the code under test. |
| T-GATED | The test exists, but it skips or no runner runs it, because it needs a token, hardware, a cloud account or a particular platform. |
| T-FRIENDLY | Only a well-behaved token, module or file exercises the path. No test models a module that returns false data, or a crafted or unusual input. |
| T-INSTANCE | The regression test covers only the reported instance. |
| D-MULTIPATH | The rule is enforced on one entry path, and other paths skip it or implement it again. |
| D-PARALLEL | Tables, lists or docs that must agree are kept in agreement by hand. |
| D-TYPES | An invalid state can be represented, and validity depends on every caller checking it. |
| D-SEAM | The default of a hook, or an override of it, changes the meaning of an operation without saying so. |
| D-FAILOPEN | An error, an absence or "unknown" becomes a definite verdict (yes, no, ok, or a default). |
| D-DOCS | A doc or comment states a guarantee that nothing checks. |
| P-UNRUN | The fix was written without building it or running it. |
| P-REVIEW | A prior review read the code and missed the finding. |
