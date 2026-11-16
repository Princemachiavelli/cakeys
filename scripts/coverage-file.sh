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
rm -rf "$trace"
mkdir -p "$trace"
# Not traced: the coverage test (it checks the file it is about to rewrite), and the tests
# nix/test-tokens.sh leaves untraced (those that run their own p11-fault).
CAKEYS_TRACE_DIR=$trace scripts/local-tests.sh -E \
  'not (binary(fault) | test(tpm2_attestation_says_what_it_lacks) | test(committed_coverage_is_generated_from_the_trace))'
CAKEYS_COVERAGE_TRACE=$trace CAKEYS_UPDATE_COVERAGE=1 \
  cargo test -q -p caprobe --lib committed_coverage_is_generated_from_the_trace
git -C "$repo" diff --stat -- spec-coverage/cakeys.toml
echo "coverage-file: the tests behind each used row: $trace/coverage-report.txt"
