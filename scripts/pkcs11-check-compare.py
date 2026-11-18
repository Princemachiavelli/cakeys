#!/usr/bin/env python3
"""A pkcs11-check run set beside a caprobe profile: `pkcs11-check-compare.py <run dir> <profile.toml>`.

Reads the run's results.json, coverage.json and report.jsonl (pkcs11-check's own artifacts) and
writes Markdown to stdout: the run's counts; the mechanisms the module listed against the
profile's `advertise`, and the profile's subtractions pkcs11-check still invoked; and every
failure and expected failure grouped by test file and reason, skips grouped too. The raw
material for triage (docs/PLAN.md A6), not a verdict: which finding contradicts the profile
is for a person to decide.
"""

import json
import re
import sys
import tomllib
from collections import Counter
from pathlib import Path


def load(run: Path, name: str):
    path = run / name
    return json.loads(path.read_text()) if path.exists() else {}


def groups(run: Path) -> Counter:
    """(test file, outcome, reason) -> count, parametrisations and numbers folded together."""
    found = Counter()
    report = run / "report.jsonl"
    if not report.exists():
        return found
    for line in report.read_text(encoding="utf-8").splitlines():
        r = json.loads(line)
        if r.get("$report_type") != "TestReport":
            continue
        when, outcome = r.get("when"), r.get("outcome")
        if outcome == "passed" or (when == "teardown" and outcome != "failed"):
            continue
        nodeid = r.get("nodeid", "").split("testcases/")[-1]
        longrepr = r.get("longrepr")
        if isinstance(longrepr, list):
            message = str(longrepr[-1])
        elif isinstance(longrepr, dict):
            message = (longrepr.get("reprcrash") or {}).get("message", "")
        else:
            message = str(longrepr or "")
        message = " ".join(message.split())
        kind = "xfail" if outcome == "skipped" and "XFailed" in message else outcome
        reason = re.sub(r"\[[^\]]*\]", "[..]", message)
        reason = re.sub(r"0x[0-9a-fA-F]+|\d+", "N", reason)[:200]
        found[(nodeid.split("::")[0], kind, reason)] += 1
    return found


def names(items) -> str:
    return ", ".join(f"`{m}`" for m in sorted(items)) or "none"


def main() -> None:
    run, profile_path = Path(sys.argv[1]), Path(sys.argv[2])
    profile = tomllib.loads(profile_path.read_text())
    results, coverage = load(run, "results.json"), load(run, "coverage.json")
    mechanisms = coverage.get("mechanism_coverage", {})
    summary = results.get("summary", {})

    print(f"# pkcs11-check against `{profile.get('profile')}`\n")
    print(f"Run: `{run}`; profile: `{profile_path.parent.name}/{profile_path.name}`.\n")
    counts = ", ".join(f"{k} {v}" for k, v in summary.items() if isinstance(v, int) and v)
    print(f"Outcomes: {counts or 'no results.json'}.\n")

    print("## Mechanisms\n")
    listed = set(mechanisms.get("advertised_names", []))
    advertised = set(profile.get("advertise", []))
    subtracted = set((profile.get("subtract") or {}).get("mechanisms", []))
    invoked = mechanisms.get("invoked_counts", {})
    if not listed:
        print("No mechanism list in coverage.json.\n")
    else:
        print(f"- Listed by the module, not in the profile's `advertise`: {names(listed - advertised)}")
        print(
            "- In the profile's `advertise`, not listed by the module as pkcs11-check reads it: "
            f"{names(advertised - listed)}"
        )
    print(
        "- Subtracted by the profile (listed, unusable) and still invoked by pkcs11-check, with its "
        "call count (invoked is not succeeded: see the failures below): "
        + (", ".join(f"`{m}` ({invoked[m]})" for m in sorted(subtracted & invoked.keys())) or "none")
    )
    print(f"- Added by the profile (usable, unlisted): {names(profile.get('add', []))}\n")

    found = groups(run)
    order = {"failed": 0, "error": 1, "xfail": 2, "skipped": 3}
    for title, kinds in [("Failures and expected failures", {"failed", "error", "xfail"}), ("Skips", {"skipped"})]:
        print(f"## {title}, by test file and reason\n")
        rows = [(k, n) for k, n in found.items() if k[1] in kinds]
        if not rows:
            print("None.\n")
            continue
        print("| Outcome | Count | File | Reason |\n|---|---|---|---|")
        for (file, kind, reason), n in sorted(rows, key=lambda kn: (order[kn[0][1]], kn[0][0], -kn[1])):
            print(f"| {kind} | {n} | `{file}` | {reason.replace('|', '/')} |")
        print()


if __name__ == "__main__":
    main()
