#!/usr/bin/env bash
# Regenerate profiles/coverage/cakeys.toml (docs/CAPROBE.md, "Coverage"; docs/PLAN.md A1): run
# every suite with each module behind a tracing p11-fault (scripts/local-tests.sh with
# CAKEYS_TRACE_DIR), then rewrite the file from that trace, the baseline, the profiles and
# profiles/coverage/manual.toml. The tests behind each used row are written beside the trace,
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
# The coverage test itself checks the file it is about to rewrite: not part of the traced run.
CAKEYS_TRACE_DIR=$trace scripts/local-tests.sh -E 'not test(committed_coverage_is_generated_from_the_trace)'
CAKEYS_COVERAGE_TRACE=$trace CAKEYS_UPDATE_COVERAGE=1 \
  cargo test -q -p caprobe --lib committed_coverage_is_generated_from_the_trace
git -C "$repo" diff --stat -- profiles/coverage/cakeys.toml
echo "coverage-file: the tests behind each used row: $trace/coverage-report.txt"
