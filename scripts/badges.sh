#!/usr/bin/env bash
# A report's number as a shields.io endpoint file (https://shields.io/badges/endpoint-badge),
# on stdout: the README's badges read them from the `badges` branch, where
# .github/workflows/reports.yml (coverage) and mutants.yml (mutants) push them.
#
#   scripts/badges.sh coverage <nix build .#coverage result>    lines covered, of all lines
#   scripts/badges.sh mutants <nix build .#mutants result>      mutants caught, of the viable ones
set -euo pipefail

[ $# -eq 2 ] && [ -d "$2" ] || {
  echo "usage: $0 coverage|mutants <report directory>" >&2
  exit 2
}

case $1 in
coverage)
  # lcov.info's per-file sums are summary.txt's TOTAL line.
  read -r hit all < <(awk -F: '/^LH:/ { h += $2 } /^LF:/ { f += $2 } END { print h + 0, f + 0 }' "$2/lcov.info")
  label=coverage
  ;;
mutants)
  # One directory per package. A timeout is a mutant the tests did not catch; an unviable one
  # (it does not build) is not a test of anything.
  hit=$(cat "$2"/*/caught.txt | wc -l)
  all=$(cat "$2"/*/caught.txt "$2"/*/missed.txt "$2"/*/timeout.txt | wc -l)
  label="mutants caught"
  ;;
*)
  echo "usage: $0 coverage|mutants <report directory>" >&2
  exit 2
  ;;
esac

[ "$all" -gt 0 ] || {
  echo "$0: no $1 in $2" >&2
  exit 1
}

# Tenths of a percent, rounded down, so 99.96% is not shown as 100%.
tenths=$((hit * 1000 / all))
color=red
for step in 950:brightgreen 900:green 800:yellowgreen 700:yellow 600:orange; do
  [ "$tenths" -ge "${step%%:*}" ] && {
    color=${step#*:}
    break
  }
done
printf '{"schemaVersion":1,"label":"%s","message":"%d.%d%%","color":"%s"}\n' \
  "$label" $((tenths / 10)) $((tenths % 10)) "$color"
