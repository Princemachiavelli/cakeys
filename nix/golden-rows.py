"""The rows that each change of a golden file moved, against the records of the file (CI's light
job).

checks.ledger (nix/ledger.py) runs in the Nix sandbox, which has no git. It can check that each
row that a record lists moved, but it cannot check that a record lists every row that moved. This
script reads each golden file in every commit of `BASE..HEAD`, and in the working tree as one more
change on top of HEAD (review 2026-11-24 C-8). A change of the file is a commit whose version of
the file differs from the version in the commit's first parent. A version is the file's hash, as
nix/ledger.py computes it. The rows of a version are nix/ledger.py's `rows`, and a row moved when
it was added, removed or changed. The script fails on a golden file when one of these rules is
broken:

1. Each record that the ledger at BASE did not have lists exactly the rows that moved in one
   change: the first change, in topological order, whose new version has the record's hash. Each
   listed row's `was` is the row's value in the first parent of that change. The first parent is
   used so that a merge record lists what the merge moved on the branch that it merged into. A
   record whose hash no change made fails.
2. When the ledger did not watch the file at BASE, the file's first [[regenerated]] record starts
   to watch it. That record lists no row, because the file's earlier versions have no records,
   and rule 1 does not apply to it.
3. Each change of the file in a commit whose ledger watches the file (or when the ledger watched
   it at BASE) makes a version that a record names. A change without a record therefore fails
   even when a later change moves the same rows again and has a record.
4. Each row that moved between BASE (or, for a file that the ledger did not watch at BASE, the
   version that its first record names) and the file now is listed by a record that the ledger at
   BASE did not have.

For a range with one change and one record, rules 1 and 4 require what the earlier version of
this script required: the record lists exactly the rows that moved since BASE, each with its value
at BASE. When the check passes, each row that a record lists goes to $GITHUB_STEP_SUMMARY (when
that variable is set), with its old value, its new value and its why, so that a reviewer reads
the values rather than TOML lines.

`--stub` prints the record to fill in instead. It does so for each golden file that differs from
BASE (default HEAD), and for each golden file whose regeneration waits beside it as `<file>.new`.
The stub compares `<file>.new` with the file, or else it compares the file with the first parent
of the first change that made its current version, as rule 1 does. The stub is a [[regenerated]]
record with the new file's hash, the generator's code-hash now, and every moved row with its old
value and why = "TODO". checks.ledger refuses the stub until a person writes each why.

Usage: python3 -I golden-rows.py [--base REV] [--stub] [ROOT]. Exits 1 on a failure.
"""

import argparse
import collections
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
KINDS = ("regenerated", "hand-edits")


def git(root, *args, stdin=None):
    """The standard output of `git args` in `root`, as bytes. A failure of git ends the script."""
    p = subprocess.run(["git", "-C", str(root), *args], input=stdin, capture_output=True)
    if p.returncode:
        sys.exit(f"golden-rows: git {' '.join(args)}: {p.stderr.decode().strip()}")
    return p.stdout


def at_base(root, rev, path):
    """`path`'s text at `rev`, or None where it did not exist."""
    p = subprocess.run(["git", "-C", str(root), "show", f"{rev}:{path}"], capture_output=True)
    if p.returncode:
        exists = subprocess.run(["git", "-C", str(root), "cat-file", "-e", f"{rev}^{{commit}}"], capture_output=True)
        if exists.returncode:
            sys.exit(f"golden-rows: {rev} is no revision of {root}")
        return None
    return p.stdout.decode()


# One change of a file: `rev` is the commit (None for the working tree), `parent` is its first
# parent (HEAD for the working tree), and `before` and `after` are the file's versions in the
# parent and in the change (None where there is no file).
Step = collections.namedtuple("Step", "rev parent before after")


def label(step):
    return "the working tree" if step.rev is None else f"commit {step.rev[:12]}"


def counted(n):
    return "1 row" if n == 1 else f"{n} rows"


class History:
    """The versions of the golden files in the commits of `base..HEAD`, in their first parents, at
    `base`, at HEAD and in the working tree. `text` returns the text of each version read."""

    def __init__(self, root, base, paths):
        self.root, self.texts, self.versions, self.ledgers = root, {}, {}, {}
        out = git(root, "rev-list", "--topo-order", "--reverse", "--parents", f"{base}..HEAD").decode()
        # Each commit, oldest first, with its first parent (None for a commit without parents).
        self.commits = [(c, (ps or [None])[0]) for c, *ps in (line.split() for line in out.splitlines())]
        revs = sorted({base, "HEAD"} | {c for c, _ in self.commits} | {p for _, p in self.commits if p})
        query = [(r, p) for r in revs for p in (ledger.LEDGER, *paths)]
        lines = "".join(f"{r}:{p}\n" for r, p in query).encode()
        answer = git(root, "cat-file", "--batch-check=%(objectname)", stdin=lines).decode().splitlines()
        self.blobs = {q: None if line.endswith(" missing") else line for q, line in zip(query, answer, strict=True)}
        self.now = {p: self.keep((root / p).read_bytes()) if (root / p).is_file() else None for p in paths}

    def keep(self, data):
        version = "sha256:" + hashlib.sha256(data).hexdigest()
        self.texts[version] = data.decode()
        return version

    def text(self, version):
        return None if version is None else self.texts[version]

    def version(self, rev, path):
        """The version of `path` at `rev`, which is one of the revisions that `__init__` read."""
        blob = self.blobs[(rev, path)]
        if blob is None:
            return None
        if blob not in self.versions:
            self.versions[blob] = self.keep(git(self.root, "cat-file", "blob", blob))
        return self.versions[blob]

    def steps(self, path):
        """The changes of `path`, oldest first: each commit whose version differs from its first
        parent's, then the working tree when it differs from HEAD."""
        steps = [Step(c, p, self.version(p, path) if p else None, self.version(c, path)) for c, p in self.commits]
        steps.append(Step(None, "HEAD", self.version("HEAD", path), self.now[path]))
        return [s for s in steps if s.before != s.after]

    def watches(self, step, path):
        """Whether the ledger in `step`'s commit has an entry for `path`. The working tree's ledger
        has one, and a ledger that does not parse counts as having one."""
        if step.rev is None:
            return True
        blob = self.blobs[(step.rev, ledger.LEDGER)]
        if blob is None:
            return False
        if blob not in self.ledgers:
            try:
                self.ledgers[blob] = set(tomllib.loads(git(self.root, "cat-file", "blob", blob).decode()).get("golden", {}))
            except tomllib.TOMLDecodeError:
                self.ledgers[blob] = None
        return self.ledgers[blob] is None or path in self.ledgers[blob]


def moved(old, new):
    """The rows that moved from `old` to `new` (texts; None for no file): key -> (was, now), each
    ABSENT where there was or is no such row."""
    before = ledger.rows(old) if old is not None else {}
    after = ledger.rows(new) if new is not None else {}
    return {
        k: (before.get(k, ABSENT), after.get(k, ABSENT))
        for k in sorted(set(before) | set(after))
        if before.get(k, ABSENT) != after.get(k, ABSENT)
    }


def added(entry, then):
    """The records of `entry`, as (kind, record) pairs, that the base's entry `then` did not have.
    A record is the base's when the base has a record of the same kind with the same hash, so a
    record whose `why` was corrected is still the base's. When several records of one kind have
    one hash, the later ones beyond the base's count are the added ones."""
    out = []
    for kind in KINDS:
        old = collections.Counter(r.get("hash") for r in (then or {}).get(kind, []))
        for record in entry.get(kind, []):
            if old[record.get("hash")]:
                old[record.get("hash")] -= 1
            else:
                out.append((kind, record))
    return out


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


def check(path, entry, new, watched, history, base):
    """The failures of `path`'s records against the file's changes since `base`, the summary lines,
    and the lines to print when the records pass. `new` holds the records that the ledger at `base`
    did not have, and `watched` says whether that ledger had an entry for `path`. The module's
    docstring states the rules."""
    now = history.now[path]
    found, why = ledger.accepting(entry, now)
    if not found:
        return [f"{path}: {why}"], [], []
    misses, summary, notes = [], [], []
    steps = history.steps(path)
    named = {r.get("hash") for kind in KINDS for r in entry.get(kind, [])}
    for step in steps:
        if step.after is not None and step.after not in named and (watched or history.watches(step, path)):
            misses.append(
                f'{path}: {label(step)} changed the file to a version that no record names (hash = "{step.after}"): '
                "a change without a record. Add a record with that hash and the rows that this change moved"
            )
    made = {}
    for step in steps:
        made.setdefault(step.after, step)
    start, since = history.version(base, path), base
    first = (entry.get("regenerated") or [None])[0]
    listed, reported, checked = set(), set(), 0
    for kind, record in new:
        rows = record.get("rows") if isinstance(record.get("rows"), dict) else {}
        where = f"{path}: [[{kind}]] {record.get('by', '?')}"
        if not watched and record is first:
            notes.append(f"golden-rows: {path}: the ledger's first record, which starts watching it")
            start, since = record.get("hash"), "the version that the ledger's first record names"
            for k in sorted(rows):
                misses.append(
                    f"{where}: row {k!r} is listed, but the first record of a file that the ledger did not watch at "
                    f"{base} lists no row, because the file's earlier versions have no records"
                )
            continue
        step = made.get(record.get("hash"))
        if step is None:
            misses.append(f'{where}: the file never had this record\'s hash ("{record.get("hash")}") in a commit since {base} or in the working tree')
            continue
        checked += 1
        listed |= set(rows)
        rows_moved = moved(history.text(step.before), history.text(step.after))
        at = f"{where}, the version made in {label(step)}"
        for k in sorted(set(rows_moved) - set(rows)):
            was, value = rows_moved[k]
            reported.add(k)
            misses.append(f"{at}: row {k!r} moved ({shown(was)} -> {shown(value)}) and is not listed")
        for k in sorted(set(rows) - set(rows_moved)):
            misses.append(f"{at}: row {k!r} is listed, but it did not move")
        for k in sorted(set(rows) & set(rows_moved)):
            row, (was, value) = rows[k], rows_moved[k]
            said = row.get("was", ABSENT) if isinstance(row, dict) else ABSENT
            if said != was:
                misses.append(f"{at}: row {k!r} records its old value as {shown(said)}, but its value before {label(step)} was {shown(was)}")
            why = row.get("why", "") if isinstance(row, dict) else ""
            cells = (f"`{path}`", f"`{k}`", shown(was), shown(value), why)
            summary.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    if start is not None and start not in history.texts:
        # steps() read every version of the file in the range, so the first record names none of them.
        misses.append(f"{path}: the ledger's first record names a version that the file never had since {base}")
        return misses, summary, []
    net = moved(history.text(start), history.text(now))
    for k in sorted(set(net) - listed - reported):
        was, value = net[k]
        misses.append(f"{path}: row {k!r} moved since {since} ({shown(was)} -> {shown(value)}), and no record that this change added lists it")
    if not misses and summary:
        records = "its record lists" if checked == 1 else f"its {checked} new records list"
        notes.append(f"golden-rows: {path}: {counted(len(net))} moved since {since}, as {records}")
    return misses, summary, notes


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
    watched = tomllib.loads(then).get("golden", {}) if then is not None else {}
    entries = led.get("golden", {})
    history = History(root, args.base, sorted(entries))
    for path, entry in sorted(entries.items()):
        file = root / path
        pending = file.with_name(file.name + ".new")
        now = history.now[path]
        if args.stub:
            if pending.is_file():
                old, new, against = history.text(now), pending.read_text(), path
            elif now is None or now == history.version(args.base, path):
                continue
            else:
                step = next((s for s in history.steps(path) if s.after == now), None)
                before = history.version(args.base, path) if step is None else step.before
                old, new, against = history.text(before), history.text(now), args.base if step is None else step.parent[:12]
            rows_moved = moved(old, new)
            stubs.append(f"# {path}: {counted(len(rows_moved))} moved since {against}\n{stub(root, path, entry, groups, new, rows_moved)}")
            continue
        records = added(entry, watched.get(path))
        if now is None or (now == history.version(args.base, path) and not history.steps(path) and not records):
            continue
        m, s, notes = check(path, entry, records, path in watched, history, args.base)
        misses += m
        summary += s
        for line in notes:
            print(line)
    if args.stub:
        print("\n".join(stubs) if stubs else "golden-rows: no golden file moved")
        return 0
    if summary and os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write("## Golden rows moved\n\n| File | Row | Was | New | Why |\n|---|---|---|---|---|\n")
            f.write("\n".join(summary) + "\n")
    for line in misses:
        print(line)
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main())
