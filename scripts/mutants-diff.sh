#!/usr/bin/env bash
# A pull request's mutation gate, here (.github/workflows/mutants.yml): the mutants in the lines
# this tree changes since BASE (origin/main by default; uncommitted changes to tracked files
# included, as the flake sees them), built as cakeys-crane.mutantsDiff (nix/package-crane.nix)
# for Linux on this machine's builder, never a remote one, then held to the baseline by
# packages.mutants-gate.
#
#   scripts/mutants-diff.sh [--tokens] [BASE]
#
# The unit tier by default: minutes. --tokens adds the token tier, which CI refuses over 120
# mutants: its first pass (the token tier's files under their package's own tests), then what
# that left under the token suites, minutes a mutant. Record the run in the commit's `Ran:`.
# The reports stay as result-mutants-<tier>.
set -euo pipefail

tokens=
if [ "${1:-}" = --tokens ]; then
  tokens=1
  shift
fi
[ $# -le 1 ] || {
  echo "usage: $0 [--tokens] [BASE]" >&2
  exit 2
}
base=${1:-origin/main}
cd "$(git rev-parse --show-toplevel)"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git diff --merge-base "$base" -- 'crates/**/*.rs' >"$tmp/changes.diff"
if [ ! -s "$tmp/changes.diff" ]; then
  echo "$0: no Rust source changed since $base: nothing to mutate"
  exit 0
fi
system=$(nix eval --impure --raw --expr builtins.currentSystem)
case $system in *-darwin) system=aarch64-linux ;; esac

build() {
  nix build --option builders '' -L --impure --out-link "result-mutants-$1" --expr \
    "(builtins.getFlake \"git+file://$PWD\").packages.$system.cakeys-crane.mutantsDiff { diff = builtins.path { path = \"$tmp/changes.diff\"; name = \"changes.diff\"; }; tier = \"$1\"; }"
}

build unit
reports=(result-mutants-unit)
if [ -n "$tokens" ]; then
  build tokens-first
  echo "$0: $(cat result-mutants-tokens-first/*/missed.txt result-mutants-tokens-first/*/timeout.txt | wc -l) mutants left for the token tier"
  # Its earlier report is the first pass over the same diff: the one just built.
  build tokens
  reports+=(result-mutants-tokens-first result-mutants-tokens)
fi
nix run .#mutants-gate -- --mode diff "${reports[@]}"
