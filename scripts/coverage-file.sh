#!/usr/bin/env bash
# Regenerate spec-coverage/cakeys.toml (docs/CAPROBE.md, "Coverage"; docs/PLAN.md A1): run
# every suite with each module behind a tracing p11-fault (scripts/local-tests.sh with
# CAKEYS_TRACE_DIR), then rewrite the file from that trace, the baseline, the profiles and
# spec-coverage/manual.toml. The tests behind each used row are written beside the trace,
# in coverage-report.txt.
#
#   scripts/coverage-file.sh [trace directory]     default: target/coverage-trace
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
[ -n "${IN_NIX_SHELL:-}" ] || exec nix develop "$repo" -c "$0" "$@"
cd "$repo"
trace=$(realpath -m "${1:-target/coverage-trace}")
# Only an earlier trace (nix/test-tokens.sh makes shims/ in it) or an empty directory is
# replaced: a mistyped argument is not deleted.
if [ -d "$trace" ] && [ ! -d "$trace/shims" ] && [ -n "$(ls -A "$trace")" ]; then
  echo "coverage-file: $trace is not empty and holds no shims/: not a trace, so not removed" >&2
  exit 1
fi
rm -rf "$trace"
mkdir -p "$trace"
# Not traced: the coverage test (it checks the file it is about to rewrite), and the tests
# nix/test-tokens.sh leaves untraced (those that run their own p11-fault).
CAKEYS_TRACE_DIR=$trace scripts/local-tests.sh -E \
  'not (binary(fault) | test(tpm2_attestation_says_what_it_lacks) | test(committed_coverage_is_generated_from_the_trace))'
# The rewrite through local-tests too, so it reuses that build (the same tree copy, features and
# target directory) instead of building the workspace again here. The test rewrites the file in
# the tree copy it runs in; it is copied back.
CAKEYS_COVERAGE_TRACE=$trace CAKEYS_UPDATE_COVERAGE=1 scripts/local-tests.sh -E \
  'package(caprobe) & kind(lib) & test(committed_coverage_is_generated_from_the_trace)'
cp target/local-tests/tree/spec-coverage/cakeys.toml spec-coverage/cakeys.toml
git -C "$repo" diff --stat -- spec-coverage/cakeys.toml
echo "coverage-file: the tests behind each used row: $trace/coverage-report.txt"
