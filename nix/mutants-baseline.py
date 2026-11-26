"""The mutation gate (docs/archive/REVIEW-2026-11-24/phase2-3-design.md §5.4): the mutants no test
caught, held to nix/mutants-baseline.toml, the survivors that may stay, each with why.

Usage: python3 -I nix/mutants-baseline.py --mode diff|touched|sweep [--source DIR]
           [--baseline FILE] [--write | --seed] [--merged DIR] [--missed FILE] REPORT...

Each REPORT is an output of cakeys-crane's `mutants` (nix/package-crane.nix): a directory per
scope, holding cargo-mutants' outcomes.json and its lists, and all-mutants.json, the scope's
every mutant. The reports together are one run (the shards of a tier, the token tier's first
pass and the pass on what it left): a mutant any of them caught is caught.

A survivor's key is `<function>: <genre> <original>→<replacement>`, in its file's table: the
original is the text the mutant replaces (none for a function's whole value), whitespace
folded; a mutant outside any function (a constant's value) has no `<function>: `. It has no line or column, so an edit above a mutant does not change its key. The k-th
identical key in a function, counted over the scope's every mutant and not the run's, ends in
` #k`. The source is read from DIR (the checkout the reports were built from; `.` by default).

What fails, by mode:
- diff (a pull request's `--in-diff` run): a survivor the baseline does not list;
- touched (the weekly `--in-diff` run): also an entry whose mutant the run caught;
- sweep (the monthly run of every scope): also an entry no mutant of the run has.
In every mode, more entries than `max` fail: adding one means raising `max` by hand, in the
diff, with its why. Timeouts and unviable mutants are listed, never gated.

`enforce = false` is report mode: what would fail is printed and the exit is 0.
--write removes the entries this mode finds stale and lowers `max` to the entry count; it never
adds an entry and never raises `max`. --seed (sweep mode, report mode only) also adds every
survivor not listed, as `{ why = "seeded <date>", reviewed = false }`, and sets `max` to the
count. --merged DIR writes DIR/all/{caught,missed,timeout,unviable}.txt, one line per mutant of
the run, for scripts/badges.sh.

--missed FILE writes the run's survivors as Markdown, for a review to start from
(docs/REVIEWING.md, "Start from the survivors"). The survivors are grouped by file and by
function. Each function lists the `Check::` and `Rule::` variants that its code names (its
comments left out), which are the named security decisions that the function makes. Each survivor shows its line,
its key without the function, and its baseline status: "new" when the baseline does not list it,
"not reviewed" for an entry with `reviewed = false`, and "reviewed" otherwise, each with the
entry's why.

Exits 0 when the gate passes, 1 when it fails, 2 on bad input.
"""

import argparse
import datetime
import json
import pathlib
import re
import sys
import tomllib

# An original longer than this is cut: the key stays readable, and #k tells apart what the cut
# makes identical.
ORIGINAL_MAX = 120
# A `Check` or `Rule` variant that a function's code names, read with its comments removed
# (cargo-mutants' span of a function starts at its doc comment). `Rule::ALL` is the list of all
# rules, not one rule.
DECISION = re.compile(r"\b(?:Check|Rule)::(?!ALL\b)[A-Z]\w*")
# What a mutant's outcome is when several reports examined it: caught (or unviable, the same
# code) wins, then a timeout, then missed.
RANK = {"CaughtMutant": 3, "Unviable": 3, "Timeout": 2, "MissedMutant": 1}
STATUS = {"CaughtMutant": "caught", "Unviable": "unviable", "Timeout": "timeout", "MissedMutant": "missed"}


class Bad(Exception):
    """Input the gate cannot judge: exit 2."""


def load_reports(reports):
    """The run's outcome per mutant name, the mutants by name (examined or listed), and the
    names caught by an earlier pass that only its name records (`--iterate`)."""
    outcome, known, earlier = {}, {}, set()
    for report in reports:
        scopes = sorted(p for p in pathlib.Path(report).iterdir() if p.is_dir()) if pathlib.Path(report).is_dir() else []
        if not scopes:
            raise Bad(f"{report}: not a mutants report (no scope directories)")
        for scope in scopes:
            if not (scope / "missed.txt").is_file():
                raise Bad(f"{scope}: no missed.txt")
            if (scope / "outcomes.json").is_file():
                for row in json.loads((scope / "outcomes.json").read_text())["outcomes"]:
                    if not isinstance(row["scenario"], dict):
                        continue
                    m, summary = row["scenario"]["Mutant"], row["summary"]
                    if summary not in RANK:
                        raise Bad(f"{scope}: outcome {summary!r} for {m['name']}")
                    known[m["name"]] = m
                    if RANK[summary] > RANK.get(outcome.get(m["name"]), 0):
                        outcome[m["name"]] = summary
            elif any((scope / t).is_file() and (scope / t).read_text().strip() for t in ["missed.txt", "caught.txt"]):
                raise Bad(f"{scope}: mutants listed but no outcomes.json")
            if (scope / "all-mutants.json").is_file():
                for m in json.loads((scope / "all-mutants.json").read_text()):
                    known.setdefault(m["name"], m)
            if (scope / "previously_caught.txt").is_file():
                earlier.update((scope / "previously_caught.txt").read_text().split("\n"))
    earlier.discard("")
    return outcome, known, earlier


class Source:
    def __init__(self, root):
        self.root, self.files = pathlib.Path(root), {}

    def load(self, file):
        if file not in self.files:
            path = self.root / file
            if not path.is_file():
                raise Bad(f"{path}: the reports' source is not here (--source)")
            self.files[file] = path.read_text(encoding="utf-8").split("\n")
        return self.files[file]

    def lines(self, file, first, last):
        """Lines `first` to `last` of the file, counted from 1, both included."""
        return "\n".join(self.load(file)[first - 1 : last])

    def text(self, file, span):
        lines, (s, e) = self.load(file), (span["start"], span["end"])
        try:
            if s["line"] == e["line"]:
                return lines[s["line"] - 1][s["column"] - 1 : e["column"] - 1]
            return "\n".join(
                [lines[s["line"] - 1][s["column"] - 1 :], *lines[s["line"] : e["line"] - 1], lines[e["line"] - 1][: e["column"] - 1]]
            )
        except IndexError:
            raise Bad(f"{file}: no line {e['line']}: the reports' source is not here (--source)") from None


def fold(text):
    text = " ".join(text.split())
    return text if len(text) <= ORIGINAL_MAX else text[: ORIGINAL_MAX - 1] + "…"


def base_key(m, source):
    function = (m.get("function") or {}).get("function_name", "")
    original = ""
    if m["genre"] != "FnValue":
        original = source.text(m["file"], m["span"])
        if m["genre"] == "MatchArm":
            original = original.split("=>", 1)[0]
        # The name says what it replaces: a source that is not the report's shows here.
        if m["genre"] in ("BinaryOperator", "UnaryOperator") and f" {original} " not in m["name"] + " ":
            raise Bad(f"{m['name']}: the source has {original!r} there, not the report's tree (--source)")
    return f"{function + ': ' if function else ''}{m['genre']} {fold(original)}→{fold(m['replacement'])}"


def keys(known, source):
    """(file, key) per mutant name, the k-th identical key in a function (in source order) ending
    in #k."""
    groups = {}
    for name, m in known.items():
        start = m["span"]["start"]
        groups.setdefault((m["file"], base_key(m, source)), []).append((start["line"], start["column"], name))
    out = {}
    for (file, base), members in groups.items():
        for k, (_, _, name) in enumerate(sorted(members), 1):
            out[name] = (file, base if k == 1 else f"{base} #{k}")
    return out


def load_baseline(path):
    try:
        data = tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Bad(f"{path}: {e}") from None
    enforce, ceiling = data.pop("enforce", True), data.pop("max", None)
    if not isinstance(enforce, bool) or not isinstance(ceiling, int):
        raise Bad(f"{path}: needs `max = <entries>` and a boolean `enforce`")
    entries = {}
    for file, table in data.items():
        if not isinstance(table, dict):
            raise Bad(f"{path}: {file!r} is not a file's table")
        for key, value in table.items():
            why = value if isinstance(value, str) else value.get("why") if isinstance(value, dict) else None
            if not isinstance(why, str) or not why.strip():
                raise Bad(f'{path}: {file}: "{key}" needs a why')
            entries[(file, key)] = value
    return enforce, ceiling, entries


def toml_string(s):
    # JSON's escapes are TOML's, and the keys hold no control character (whitespace is folded).
    return json.dumps(s, ensure_ascii=False)


def rewrite(path, remove, add, ceiling):
    """The baseline with the entries `remove` names dropped, `add` ({file: [(key, line)]})
    appended to their tables, and `max` set: line by line, so the comments stay."""
    out, table, last = [], None, {}
    for line in path.read_text().splitlines(keepends=True):
        s = line.strip()
        if s.startswith("["):
            table = next(iter(tomllib.loads(s)))
        elif table is None and re.match(r"max\s*=", s):
            line = re.sub(r"^(\s*max\s*=\s*)\d+", rf"\g<1>{ceiling}", line)
        elif table is not None and s and not s.startswith("#"):
            try:
                (key,) = tomllib.loads(s)
            except (tomllib.TOMLDecodeError, ValueError):
                raise Bad(f"{path}: one entry per line: {s}") from None
            if (table, key) in remove:
                continue
            last[table] = len(out)
        out.append(line)
    for file in sorted(add, reverse=True):
        lines = [f"{line}\n" for _, line in add[file]]
        if file in last:
            out[last[file] + 1 : last[file] + 1] = lines
        else:
            out += ["\n" if out and out[-1].strip() else "", f"[{toml_string(file)}]\n", *lines]
    # A table left with no entry goes, with the blank lines before it.
    text = "".join(out)
    for _ in range(2):
        text = re.sub(r'(?m)\n*^\[[^\n]*\]\n(?=\s*(\[|\Z))', "\n", text)
    path.write_text(text.rstrip("\n") + "\n")
    tomllib.loads(path.read_text())


def cell(text):
    """Text for a Markdown table cell: a `|` would end the cell."""
    return text.replace("|", "\\|")


def missed_markdown(survivors, key, known, entries, source, summary):
    """missed.md: the survivors (mutant names) by file and function, with each function's `Check`
    and `Rule` variants and each survivor's baseline status."""
    functions = {}
    for name in survivors:
        m = known[name]
        f = m.get("function") or {}
        start = (f.get("span") or m["span"])["start"]["line"] if f else 0
        functions.setdefault((m["file"], start, f.get("function_name", "")), []).append(name)
    out = [
        "# Surviving mutants",
        "",
        f"{summary}",
        "",
        "Each row is a mutant that no test caught: the code changed as the row says, and every test",
        "still passed. The baseline column says whether nix/mutants-baseline.toml lists the mutant:",
        '"new" when it does not (the gate fails on it), "not reviewed" for an entry that a sweep',
        'seeded, and "reviewed" for an entry that a person wrote or reviewed. Each new or not reviewed',
        "row needs a test that is seen failing on the mutant, a finding, or a reviewed why",
        '(docs/REVIEWING.md, "Start from the survivors").',
    ]
    last_file = None
    for (file, start, function), names in sorted(functions.items()):
        if file != last_file:
            out += ["", f"## `{file}`"]
            last_file = file
        named = []
        if function:
            span = known[names[0]]["function"]["span"]
            code = re.sub(r"//.*", "", source.lines(file, span["start"]["line"], span["end"]["line"]))
            named = sorted(set(DECISION.findall(code)))
        out += ["", f"### `{function}`, line {start}" if function else "### Outside any function", ""]
        if named:
            out += [f"The checks and rules that the function names: {', '.join(f'`{n}`' for n in named)}.", ""]
        else:
            out += ["The function names no `Check` and no `Rule`.", ""]
        out += ["| Line | Mutant | Baseline |", "|---:|---|---|"]
        for name in sorted(names, key=lambda n: (known[n]["span"]["start"]["line"], known[n]["span"]["start"]["column"], n)):
            file_, k = key[name]
            entry = entries.get((file_, k))
            if entry is None:
                status = "new"
            elif isinstance(entry, str):
                status = f"reviewed: {entry}"
            else:
                status = f"{'reviewed' if entry.get('reviewed', True) else 'not reviewed'}: {entry['why']}"
            shown = k.split(": ", 1)[1] if function and k.startswith(f"{function}: ") else k
            out.append(f"| {known[name]['span']['start']['line']} | `{cell(shown)}` | {cell(status)} |")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mode", required=True, choices=["diff", "touched", "sweep"])
    ap.add_argument("--source", default=".", type=pathlib.Path)
    ap.add_argument("--baseline", type=pathlib.Path)
    edit = ap.add_mutually_exclusive_group()
    edit.add_argument("--write", action="store_true")
    edit.add_argument("--seed", action="store_true")
    ap.add_argument("--merged", type=pathlib.Path)
    ap.add_argument("--missed", type=pathlib.Path)
    ap.add_argument("reports", nargs="+", type=pathlib.Path)
    a = ap.parse_args()
    baseline = a.baseline or a.source / "nix/mutants-baseline.toml"

    outcome, known, earlier = load_reports(a.reports)
    source = Source(a.source)
    key = keys(known, source)
    enforce, ceiling, entries = load_baseline(baseline)
    if a.seed and (enforce or a.mode != "sweep"):
        raise Bad("--seed: only a sweep's run seeds the baseline, and only in report mode (enforce = false)")

    by_status = {s: sorted(n for n, o in outcome.items() if o == s) for s in RANK}
    survivors = {key[n] for n in by_status["MissedMutant"]}
    caught = {key[n] for s in ("CaughtMutant", "Unviable") for n in by_status[s]}
    unlisted = sorted(survivors - entries.keys())
    stale = {e for e in entries if e in caught and e not in survivors} if a.mode != "diff" else set()
    if a.mode == "sweep":
        stale |= {e for e in entries if e not in survivors and e not in caught and e not in {key[n] for n in outcome}}
    noted = sorted(e for e in entries if e in caught and e not in survivors) if a.mode == "diff" else []

    if a.write or a.seed:
        remove = stale | set(noted)
        add = {}
        if a.seed:
            when = datetime.date.today().isoformat()
            for file, k in unlisted:
                add.setdefault(file, []).append((k, f'{toml_string(k)} = {{ why = "seeded {when}", reviewed = false }}'))
        count = len(entries) - len(remove) + sum(map(len, add.values()))
        rewrite(baseline, remove, add, count if a.seed else min(ceiling, count))
        enforce, ceiling, entries = load_baseline(baseline)
        unlisted = sorted(survivors - entries.keys())
        stale = {e for e in stale if e in entries}

    caught_n = len(by_status["CaughtMutant"]) + len(earlier - outcome.keys())
    summary = (
        f"mutants gate ({a.mode}): {len(outcome)} examined: {caught_n} caught, {len(survivors)} missed "
        f"({len(survivors & entries.keys())} listed), {len(by_status['Timeout'])} timeout, "
        f"{len(by_status['Unviable'])} unviable; the baseline has {len(entries)} entries, max = {ceiling}"
    )
    print(summary)
    if a.missed:
        a.missed.write_text(missed_markdown(by_status["MissedMutant"], key, known, entries, source, summary))
    failures = 0

    def section(title, items, fail):
        nonlocal failures
        if not items:
            return
        failures += len(items) if fail else 0
        print(f"\n{'FAIL' if fail else 'note'}: {title}:")
        for file, k in items:
            print(f'  {file}: "{k}"')

    section("survivors the baseline does not list (a test that catches each, or an entry with its why)", unlisted, True)
    section("entries that no longer survive (--write removes them)", sorted(stale), True)
    section("entries whose mutant this run caught (--write removes them)", noted, False)
    section("timeouts (a hang, not gated)", sorted({key[n] for n in by_status["Timeout"]}), False)
    if len(entries) > ceiling:
        failures += 1
        print(f"\nFAIL: the baseline has {len(entries)} entries, over max = {ceiling}: raise max by hand, in the diff, with each entry's why")

    if a.merged:
        status = {n: STATUS[o] for n, o in outcome.items()} | {n: "caught" for n in earlier - outcome.keys()}
        (a.merged / "all").mkdir(parents=True, exist_ok=True)
        for s in STATUS.values():
            (a.merged / "all" / f"{s}.txt").write_text("".join(f"{n}\n" for n in sorted(status) if status[n] == s))

    if failures and not enforce:
        print("\nreport mode (enforce = false): this would fail; it passes until the baseline is seeded")
        return 0
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Bad as e:
        print(f"mutants-baseline: {e}", file=sys.stderr)
        sys.exit(2)
