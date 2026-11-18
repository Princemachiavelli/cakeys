# Review: .github/workflows/reports.yml (78 lines)

Reviewed 2026-11-18 [read]. Summary: builds `packages.coverage` on every push to main and
`packages.mutants` weekly (both on a manual run), reduces each to a shields.io JSON with
scripts/badges.sh, and pushes it to a `badges` branch with a fetch-and-retry loop (no force push).
Pinned actions, credentials not persisted.

## Findings

### F1. The write token's job also builds and runs repository code — practice

`.github/workflows/reports.yml:30-31`, `:49-50`. `permissions: contents: write` applies to the
whole job, including `nix build` of the coverage/mutants derivations and the two third-party
Nix actions. The token is passed explicitly only to the push step, so this is least-privilege
hygiene rather than a known leak, but the job's trigger set (push to main, schedule, dispatch)
means anything merged runs next to a write-scoped token. Split into a `build` job
(`contents: read`) that uploads `badge.json` as an artifact and a small `publish` job
(`contents: write`) that only downloads and pushes. [read]

## Design

- A badge job that fails leaves the old badge in place (stated in the header): the README can
  show a stale number with no sign of it. Including the commit in the JSON's message, or the
  date, would show staleness.

## Checked, no issue

- The matrix runs coverage only on push and both reports on schedule/dispatch; per-report
  concurrency keeps the newest run.
- The push loop re-fetches before each attempt and never forces; an orphan branch is created only
  when the fetch fails, and a non-fast-forward push of it is rejected.
- `persist-credentials: false`; the token reaches git only through a per-repository
  `http.extraheader` in a temporary clone.
