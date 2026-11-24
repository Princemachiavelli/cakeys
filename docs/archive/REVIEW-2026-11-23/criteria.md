# cakeys review — criteria (2026-11-23)

Repo: ~/srcs/cakeys @ 4304989 (main). Read-only review: do not edit the repo, do not run cargo/nix
builds or tests (user rule: no long builds), never search /nix/store. git, rg/grep and reading are fine.

## Context to read first

- README.md, docs/ARCHITECTURE.md (crate map, Provider seams), docs/DESIGN.md (identity, lock rules,
  security model §8), docs/OPEN.md (known open items: do not report these as new; you may challenge them).
- Prior per-file review: review/REVIEW_<path with / replaced by _>.md (2026-11-18). Read the one for each
  file before reviewing it. Do not re-report findings marked "Fixed" unless the fix is wrong/incomplete or
  regressed (then say so, citing the prior ID). Unfixed prior findings: list as "still open: <prior ID>"
  in one line, not as new findings.

## Criteria (apply each to every file)

1. Correctness: logic errors; PKCS#11 semantics (CK_RV handling, session/login state, handle lifetime,
   two-call attribute reads, CKR_BUFFER_TOO_SMALL, read-only vs RW sessions); exit-code mapping; edge
   cases (empty, duplicates, odd names); panics on untrusted input (unwrap/expect/index/slice on token
   data, files, DER); cleanup/rollback on failure paths; ordering/atomicity of lock writes.
2. Security: can a lying or hostile token/module/file make a check pass that should fail (identity,
   proof of possession, attestation chain, freshness of challenges)? Secret handling (zeroize, PINs and
   passphrases in argv/env/logs/output/error messages, file modes of written key files/bundles), TOCTOU
   and symlinks on lock/key files, unsafe soundness, parsing of untrusted input (TOML, DER, attributes).
3. Design and architecture: layer boundaries as ARCHITECTURE.md states them (core never touches a token;
   vendor logic only in provider crates); seams/abstractions with one user; leaky or overlapping seams;
   state that could be encoded in types; places where code and docs disagree.
4. Complexity reduction (high priority): dead or test-only code in src, over-general APIs, needless
   indirection, long functions doing several jobs, hand-synced parallel tables/enums, duplicated logic
   across crates or tests, features/flags/options that exist for one case, comments that restate code
   at length. Propose concrete deletions/merges and estimate lines saved.
5. Consistency: naming of verbs/flags/types/errors; error message style; exit-code usage; the same
   operation done differently in two places; doc-vs-code drift.
6. CLI UX (cakeys, caprobe, camigrate): verb and flag naming across the three tools, positional vs flag,
   required vs optional, single vs repeatable, redundant/no-op flags, surprising or unsafe defaults,
   help text clarity and jargon, stdout vs stderr, JSON vs text, dry-run coverage, destructive actions,
   env vars, error messages a user can act on.
7. Rust practice: error types (stringly typed, lost context), unwrap/expect in library code, visibility
   leaks, #[expect] used where a fix is simple, needless clones, test quality (tests that cannot fail,
   asserting on prose, flaky timing, missing failure-path tests, duplicated fixtures).
8. Nix/CI/scripts: correctness, reproducibility, regular-vs-crane duplication, shell robustness
   (set -euo pipefail, quoting, traps), checks that cannot fail.

## Evidence bar

Every finding must be traced in the code: cite file:line, the concrete input/state that triggers it, and
what goes wrong. Mark each finding `verified` (you traced the path end to end) or `plausible` (you could
not fully confirm). No speculative style opinions without a concrete cost.

## Severity

- critical: identity/possession/attestation check can be fooled, secret leak, data loss of keys/lock.
- high: wrong result, crash, or misleading success reachable by a user in normal use.
- medium: latent bug, confusing or inconsistent UX, significant avoidable complexity.
- low: nit, minor inconsistency, small cleanup.

## Output format (write to your file in the job tmp dir)

```text
# Area <X>: <name>
## Summary (5-10 lines: overall quality, biggest risks, biggest simplification wins)
## Findings
### <X>-<n>. <one-line title> — <severity> — <category 1-8> — <verified|plausible>
`path:line[-line]`
What is wrong, the triggering input/state, the consequence. Suggested fix (concrete).
## Complexity reduction proposals (ranked, with estimated lines saved)
## Still open from the 2026-11-18 review (one line each)
## Cross-area notes (issues seen in another agent's files; one line each, no deep dive)
## Files reviewed (every file in scope, with one line each: "clean" or finding IDs)
```
