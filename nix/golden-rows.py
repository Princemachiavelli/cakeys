"""The rows each golden file's change moved, against its record (CI's light job).

checks.ledger (nix/ledger.py) holds each golden file to the record that names it, in the
sandbox, which has no git: it can see that a listed row moved, but not that every moved row is
listed. This reads the file at a base revision and now, takes the exact set of rows that moved
(nix/ledger.py's `rows`: added, removed or changed), and fails when the record that names the
file now lists another set, or says a row `was` other than it was at the base (review
2026-11-24 C-8). Each moved row, old -> new, with its why, goes to $GITHUB_STEP_SUMMARY when
that is set, so a review reads verdicts rather than TOML lines.

`--stub` writes the record to fill in instead: for each golden file that differs from the base
(default HEAD), or whose regeneration waits beside it as `<file>.new` (then against the file),
a [[regenerated]] record with the new file's hash, the generator's code-hash now, and every
moved row with what it was and why = "TODO", which checks.ledger refuses until written.

Usage: python3 -I golden-rows.py [--base REV] [--stub] [ROOT]. Exits 1 on a failure.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import tomllib

_spec = importlib.util.spec_from_file_location("ledger", pathlib.Path(__file__).with_name("ledger.py"))
ledger = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ledger)

ABSENT = object()
BARE = re.compile(r"[A-Za-z0-9_-]+")


def at_base(root, rev, path):
    """`path`'s text at `rev`, or None where it did not exist."""
    p = subprocess.run(["git", "-C", str(root), "show", f"{rev}:{path}"], capture_output=True)
    if p.returncode:
        exists = subprocess.run(["git", "-C", str(root), "cat-file", "-e", f"{rev}^{{commit}}"], capture_output=True)
        if exists.returncode:
            sys.exit(f"golden-rows: {rev} is no revision of {root}")
        return None
    return p.stdout.decode()


def moved(old, new):
    """The rows that moved from `old` to `new` (texts; None for no file): key -> (was, now), each
    ABSENT where there was or is no such row."""
    before = ledger.rows(old) if old is not None else {}
    after = ledger.rows(new)
    return {
        k: (before.get(k, ABSENT), after.get(k, ABSENT))
        for k in sorted(set(before) | set(after))
        if before.get(k, ABSENT) != after.get(k, ABSENT)
    }


def toml(value):
    """`value` as a TOML value, on one line."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ", ".join(toml(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{key(k)} = {toml(v)}" for k, v in value.items()) + " }"
    raise TypeError(f"no TOML for {value!r}")


def key(k):
    return k if BARE.fullmatch(k) else json.dumps(k, ensure_ascii=False)


def shown(value):
    return "(none)" if value is ABSENT else toml(value)


def stub(root, path, entry, groups, text, rows_moved):
    """The [[regenerated]] record of `path` as `text`, its whys left for a person to write."""
    files, entries, _ = ledger.code_files(root, entry.get("generator", []), groups)
    out = [
        f'[[golden."{path}".regenerated]]',
        'by = "TODO: the commit or package"',
        f'hash = "sha256:{hashlib.sha256(text.encode()).hexdigest()}"',
        f'code-hash = "{ledger.code_hash(root, files, entries)}"',
        f'[golden."{path}".regenerated.rows]',
    ]
    for k, (was, now) in rows_moved.items():
        out.append(f"# now: {shown(now)}")
        fields = ([] if was is ABSENT else [f"was = {toml(was)}"]) + ['why = "TODO"']
        out.append(f"{key(k)} = {{ {', '.join(fields)} }}")
    return "\n".join(out) + "\n"


def check(root, path, entry, rows_moved, base, watched):
    """The failures of `path`'s record against the rows that moved since `base`, and the summary
    lines. A file the ledger did not watch at `base` (`watched`) starts with a first record that
    lists no row: what it was before is no one's verdict."""
    found, why = ledger.accepting(entry, ledger.file_hash(root / path))
    if not found:
        return [f"{path}: {why}"], []
    kind, record, _ = found
    if path not in watched and kind == "regenerated" and record is entry["regenerated"][0]:
        print(f"golden-rows: {path}: the ledger's first record, which starts watching it")
        return [], []
    listed = record.get("rows") if isinstance(record.get("rows"), dict) else {}
    where = f"{path}: [[{kind}]] {record.get('by', '?')}"
    misses, summary = [], []
    for k in sorted(set(rows_moved) - set(listed)):
        was, now = rows_moved[k]
        misses.append(f"{where}: row {k!r} moved since {base} ({shown(was)} -> {shown(now)}) and is not listed")
    for k in sorted(set(listed) - set(rows_moved)):
        misses.append(f"{where}: row {k!r} is listed, but did not move since {base}")
    for k in sorted(set(listed) & set(rows_moved)):
        row, (was, now) = listed[k], rows_moved[k]
        said = row.get("was", ABSENT) if isinstance(row, dict) else ABSENT
        if said != was:
            misses.append(f"{where}: row {k!r} says it was {shown(said)}, but at {base} it was {shown(was)}")
        why = row.get("why", "") if isinstance(row, dict) else ""
        cells = (f"`{path}`", f"`{k}`", shown(was), shown(now), why)
        summary.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    return misses, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", default="HEAD", help="the revision to compare with (default HEAD)")
    parser.add_argument("--stub", action="store_true", help="print the record to fill in for each change")
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()
    root = pathlib.Path(args.root).resolve()
    led = tomllib.loads((root / ledger.LEDGER).read_text())
    groups = led.get("groups", {})
    misses, summary, stubs = [], [], []
    then = at_base(root, args.base, ledger.LEDGER)
    watched = set(tomllib.loads(then).get("golden", {})) if then is not None else set()
    for path, entry in sorted(led.get("golden", {}).items()):
        file = root / path
        pending = file.with_name(file.name + ".new")
        if args.stub and pending.is_file():
            old, new, against = file.read_text() if file.is_file() else None, pending.read_text(), path
        else:
            old, new, against = at_base(root, args.base, path), file.read_text() if file.is_file() else None, args.base
        if new is None or old == new:
            continue
        rows_moved = moved(old, new)
        if args.stub:
            stubs.append(f"# {path}: {len(rows_moved)} rows moved since {against}\n{stub(root, path, entry, groups, new, rows_moved)}")
            continue
        m, s = check(root, path, entry, rows_moved, args.base, watched)
        misses += m
        summary += s
        if not m and s:
            print(f"golden-rows: {path}: {len(rows_moved)} rows moved since {args.base}, as its record lists")
    if args.stub:
        print("\n".join(stubs) if stubs else "golden-rows: no golden file moved")
        return 0
    if summary and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write("## Golden rows moved\n\n| File | Row | Was | Now | Why |\n|---|---|---|---|---|\n")
            f.write("\n".join(summary) + "\n")
    for line in misses:
        print(line)
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main())
