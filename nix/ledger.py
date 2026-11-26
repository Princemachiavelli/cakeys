"""What was measured on hardware, and what changed since (checks.ledger).

profiles/LEDGER.toml lists the data a run on hardware or a cloud produced and no build repeats
(module profiles, captured certificates, a lock), and the module profiles a build re-probes
(`verified-by`). For each of the first kind it records the run (`[artifact.probed]`: which
commit, when, the file as the run wrote it and the code on its path then), every hand edit
since, and the file as it is now. This fails when:

- a file is not the one the ledger records (`hash`): a run or a hand edit the ledger does not
  say;
- a file is not what its run wrote and no `[[artifact.hand-edits]]` row says so, or such rows
  stand beside a file that is the run's output again;
- the code on its path (`code`: globs from the root, `@name` for a `[groups]` list, and lock
  entries, `Cargo.lock#<package>` or `flake.lock#<input>`) changed since the run, unless
  `[artifact.acknowledged]` names that code's hash with who, why and what still needs a run on
  the hardware. An acknowledgement of other code fails as well, and so does one beside code
  that is the run's again;
- a module profile under profiles/modules/ has no entry, or a path or glob names no file, or a
  table has a key this script does not read;
- a regeneration probes other RSA sizes than the rest (review 2026-11-24 E-8): each file in
  `[regen] sources` must pass `--rsa-max-bits` with `[regen] rsa-max-bits` and no other value,
  and an artifact's `regen` may name no other value and no file that is not there.

It also holds the golden files, which a build regenerates and compares with (`GOLDEN`, and
every `verified-by` profile; review 2026-11-24 C-8: the code under test writes them, so a
regeneration in the same commit as the code moves the expectation with it). Each has a
`[golden."<path>"]` entry: `generator`, the globs that write it (as `code`), and its records,
`[[golden."<path>".regenerated]]` for a run of the generator and `[[golden."<path>".hand-edits]]`
for an edit by hand, oldest first. Each record names the file it made (`hash`), who (`by`) and
the rows that moved (`rows = { "<row key>" = { was = <old value>, why = "<why it is right>" } }`,
`was` left out for a row it adds; `rows()` says what a row is), and a regeneration the
generator's hash then (`code-hash`). This fails when:

- a golden file has no entry, or no record names the file as it is: a change without a record;
- the record that names it lists a row the file does not have and did not have, a row whose
  value `was` already (unchanged), or a `why` that is empty or `"TODO"`, or lists no row and
  says no `why` of its own;
- a regeneration names the code-hash of the one before it: the generator did not move, so the
  change was made by hand.

Which rows moved, exactly, needs the file before the change: nix/golden-rows.py checks that in
CI, from git. A generator that moved while its output did not needs nothing.

The hashes are of the files in the tree, not git's: the Nix sandbox has no .git. A failure
prints the hash to record. In the code's hash a Rust source counts as its tokens, so a comment,
a doc comment or rustfmt's spacing changes nothing, and a literal or any other token does; every
other file counts byte for byte. A lock entry counts as its parsed value: the package's rows of
that name in a Cargo.lock, or the locked source of the root input of that name in a flake.lock,
so a bump of the rest of the lock changes nothing.

Usage: python3 -I ledger.py ROOT. Prints each artifact's state and every failure; exits 1 on a
failure.
"""

import hashlib
import json
import pathlib
import re
import sys
import tomllib

LEDGER = "profiles/LEDGER.toml"
# The size flag with its value, as a shell line or a Rust argument list writes it.
RSA_FLAG = re.compile(r"--rsa-max-bits[\"',\s]*(\d+)")
# A repository path in a `regen` command.
REPO_PATH = re.compile(r"\b(?:crates|examples|nix|profiles|scripts)/[\w.+/-]*\w")
# A lock entry in `code`: a lock file and the name of the entry in it.
LOCK_ENTRY = re.compile(r"(?P<file>(?:[\w.+-]+/)*(?P<kind>Cargo|flake)\.lock)#(?P<name>[\w.+-]+)")
# A Rust token, as rustc splits one from the next. Strings, raw strings and block comments are
# read on by `rust_tokens`; a punctuation run is read longest first, so `&&` and `& &` differ.
RUST_TOKEN = re.compile(
    r"""(?P<space>\s+)
    | (?P<line>//[^\n]*)
    | (?P<block>/\*)
    | (?P<raw>[bc]?r(?P<hashes>\#*)")
    | (?P<string>[bc]?")
    | (?P<char>b?'(?:\\(?:u\{[0-9a-fA-F_]*\}|.)|[^\\'\n])')
    | (?P<word>\w+)
    | (?P<punct><<=|>>=|\.\.\.|\.\.=|::|->|=>|==|!=|<=|>=|&&|\|\||[-+*/%^&|]=|<<|>>|\.\.|.)""",
    re.X | re.S,
)

# The golden files besides the `verified-by` profiles: each needs a [golden."<path>"] entry.
GOLDEN = ("spec-coverage/objects/*.toml", "spec-coverage/cakeys.toml", "profiles/baselines/*.toml")
# A why no one wrote: empty, or the placeholder nix/golden-rows.py --stub leaves.
UNWRITTEN = re.compile(r"\s*(TODO\b.*)?", re.I | re.S)

# The keys each table may have: a near miss (`acknowledgement`) fails rather than being ignored.
KEYS = {
    "ledger": {"regen", "groups", "artifact", "golden"},
    "regen": {"rsa-max-bits", "sources"},
    "artifact": {"path", "from", "regen", "verified-by", "code", "hash", "probed", "hand-edits", "acknowledged"},
    "probed": {"by", "date", "hash", "code-hash"},
    "hand-edits": {"by", "what"},
    "acknowledged": {"code-hash", "by", "why", "reprobe"},
    "golden": {"generator", "regenerated", "hand-edits"},
    "regenerated": {"by", "hash", "code-hash", "why", "rows"},
    "golden hand-edit": {"by", "hash", "why", "rows"},
    "row": {"was", "why"},
}


def file_hash(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def rust_tokens(text):
    """`text`'s tokens without its comments (doc comments too) and the whitespace between them."""
    tokens, i = [], 0
    while i < len(text):
        m = RUST_TOKEN.match(text, i)
        start, i = i, m.end()
        if m["line"] or m["space"]:
            continue
        if m["block"]:  # Rust's block comments nest
            depth = 1
            while depth and i < len(text):
                step = text[i : i + 2]
                depth += {"/*": 1, "*/": -1}.get(step, 0)
                i += 2 if step in ("/*", "*/") else 1
            continue
        if m["raw"]:
            end = text.find('"' + m["hashes"], i)
            i = len(text) if end < 0 else end + 1 + len(m["hashes"])
        elif m["string"]:
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
            i += 1
        tokens.append(text[start:i])
    return tokens


def source_hash(path):
    """A file's hash in the code's: a Rust source's tokens, any other file's bytes."""
    if path.suffix != ".rs":
        return file_hash(path)
    text = path.read_bytes().decode("utf-8", "surrogateescape")
    tokens = "".join(f"{len(t)}:{t}" for t in rust_tokens(text))
    return "rust-tokens:sha256:" + hashlib.sha256(tokens.encode("utf-8", "surrogateescape")).hexdigest()


def lock_entry(root, selector):
    """The lock entry `selector` names, as canonical JSON; None when there is no such entry."""
    m = LOCK_ENTRY.fullmatch(selector)
    try:
        text = (root / m["file"]).read_text()
        if m["kind"] == "Cargo":
            rows = [p for p in tomllib.loads(text).get("package", []) if p.get("name") == m["name"]]
            return json.dumps(rows, sort_keys=True) if rows else None
        lock = json.loads(text)
        nodes, node, path = lock["nodes"], lock["root"], [m["name"]]
        while path:
            node = nodes[node]["inputs"][path.pop(0)]
            if isinstance(node, list):  # an input that follows another: a path from the root
                node, path = lock["root"], node + path
        return json.dumps(nodes[node]["locked"], sort_keys=True)
    except (OSError, ValueError, KeyError, TypeError, tomllib.TOMLDecodeError):
        return None


def code_files(root, patterns, groups):
    """The files and the lock entries `patterns` name under `root`, and what names nothing."""
    files, entries, empty = set(), {}, []
    for pattern in patterns:
        if pattern.startswith("@") and pattern[1:] not in groups:
            empty.append(f"glob {pattern} (no such group) names no file")
            continue
        for glob in groups[pattern[1:]] if pattern.startswith("@") else [pattern]:
            if LOCK_ENTRY.fullmatch(glob):
                entries[glob] = lock_entry(root, glob)
                if entries[glob] is None:
                    empty.append(f"entry {glob} names nothing")
                continue
            found = {p for p in root.glob(glob) if p.is_file()}
            if not found:
                empty.append(f"glob {glob} names no file")
            files |= found
    return sorted(files), entries, empty


def code_hash(root, files, entries):
    """One hash over each file's path and content, and each lock entry: a file added, removed,
    renamed or changed, or an entry bumped, changes it."""
    h = hashlib.sha256()
    for f in files:
        h.update(f"{f.relative_to(root).as_posix()}\0{source_hash(f)}\n".encode())
    for name, value in sorted(entries.items()):
        h.update(f"{name}\0{value}\n".encode())
    return "sha256:" + h.hexdigest()


def check_regen(root, regen, misses):
    """Every regeneration path probes RSA up to the one size."""
    unknown(regen, "regen", f"{LEDGER}: [regen]", misses)
    bits = str(regen.get("rsa-max-bits"))
    for src in regen.get("sources", []):
        where = f"{LEDGER}: [regen] {src}"
        if not (root / src).is_file():
            misses.append(f"{where}: no such file")
            continue
        found = set(RSA_FLAG.findall((root / src).read_text()))
        if not found:
            misses.append(f"{where}: passes no --rsa-max-bits, so it probes to caprobe's default, not {bits}")
        for other in sorted(found - {bits}):
            misses.append(f"{where}: probes RSA up to {other}, not {bits}")
    return bits


def unknown(table, kind, where, misses):
    for k in sorted(set(table) - KEYS[kind]):
        misses.append(f"{where}: `{k}` is no key of {kind}")


def rows(text):
    """A golden file's rows, by key: each key of a table as `<table>.<key>`, with its whole value
    (a profile's capability, a matrix row, a coverage status, a baseline ID); each member of a
    top-level list as `<list>.<member>` = true; any other top-level key as itself. A `summary`
    table counts the rows, so it is none of them."""
    out = {}
    for key, value in tomllib.loads(text).items():
        if key == "summary":
            continue
        if isinstance(value, dict):
            out.update({f"{key}.{k}": v for k, v in value.items()})
        elif isinstance(value, list) and all(isinstance(v, (str, int, float, bool)) for v in value):
            out.update({f"{key}.{v}": True for v in value})
        else:
            out[key] = value
    return out


def golden_paths(root, ledger):
    """The golden files: `GOLDEN`'s and the `verified-by` profiles."""
    paths = {p.relative_to(root).as_posix() for g in GOLDEN for p in root.glob(g) if p.is_file()}
    return paths | {a.get("path") for a in ledger.get("artifact", []) if "verified-by" in a}


def accepting(entry, now):
    """The record that names the file as it is (the last such of its kind), its kind, and the
    regeneration before it, if it is one; or the failure."""
    found = []
    for kind in ("regenerated", "hand-edits"):
        records = entry.get(kind, [])
        at = max((i for i, r in enumerate(records) if r.get("hash") == now), default=None)
        if at is not None:
            found.append((kind, records[at], records[at - 1] if kind == "regenerated" and at else None))
    if len(found) == 2:
        return None, "a regeneration and a hand edit both name the file as it is: one is wrong"
    if not found:
        return None, (
            f'no record names the file as it is (hash = "{now}"): a change without a record. '
            'Add a [[regenerated]] or [[hand-edits]] record with that hash, its rows and why '
            "(nix/golden-rows.py --stub writes one)"
        )
    return found[0], None


def check_record(text, record, kind, where, misses):
    """The record that names the file as it is: each row it lists moved, and says why."""
    for k in ("by", "hash"):
        if not record.get(k):
            misses.append(f"{where}: no `{k}`")
    if kind == "regenerated" and not record.get("code-hash"):
        misses.append(f"{where}: no `code-hash`: the generator's hash then")
    listed = record.get("rows")
    if not isinstance(listed, dict):
        misses.append(f'{where}: no `rows` (rows = {{ "<row key>" = {{ was = <old value>, why = "…" }} }})')
        return
    if not listed and UNWRITTEN.fullmatch(record.get("why", "")):
        misses.append(f"{where}: no row moved, so the record says why it changed the file (`why`)")
    if "why" in record and UNWRITTEN.fullmatch(record["why"]):
        misses.append(f"{where}: its `why` is not written")
    try:
        have = rows(text)
    except tomllib.TOMLDecodeError as e:
        misses.append(f"{where}: the file does not parse, so its rows cannot be read: {e}")
        return
    for key, row in listed.items():
        at = f"{where}: row {key!r}"
        if not isinstance(row, dict):
            misses.append(f'{at}: is no {{ was = …, why = "…" }} table')
            continue
        unknown(row, "row", at, misses)
        if UNWRITTEN.fullmatch(str(row.get("why", ""))):
            misses.append(f"{at}: its `why` is not written")
        if key not in have and "was" not in row:
            misses.append(f"{at}: the file has no such row, and the record says it had none (`was`)")
        elif key in have and "was" in row and row["was"] == have[key]:
            misses.append(f"{at}: unchanged ({have[key]!r}): list only the rows that moved")


def check_golden(root, ledger, groups, report, misses):
    """The golden files: each has an entry, and a record that names it as it is."""
    entries = ledger.get("golden", {})
    for path in sorted(golden_paths(root, ledger) - set(entries)):
        misses.append(f"{LEDGER}: {path} is a golden file without a [golden] entry: name its generator and record it")
    for path, entry in sorted(entries.items()):
        where = f'{LEDGER}: [golden."{path}"]'
        unknown(entry, "golden", where, misses)
        for kind, key in (("regenerated", "regenerated"), ("hand-edits", "golden hand-edit")):
            for r in entry.get(kind, []):
                unknown(r, key, f"{where} [[{kind}]]", misses)
        if not entry.get("generator"):
            misses.append(f"{where}: no `generator`: the globs whose change can change the file")
        files, entries_, empty = code_files(root, entry.get("generator", []), groups)
        for what in empty:
            misses.append(f"{where}: generator {what}")
        if not (root / path).is_file():
            misses.append(f"{where}: no such file")
            continue
        now = file_hash(root / path)
        found, why = accepting(entry, now)
        if not found:
            misses.append(f"{where}: {why}")
            continue
        kind, record, before = found
        at = f"{where} [[{kind}]] {record.get('by', '?')}"
        if before is not None and before.get("code-hash") == record.get("code-hash"):
            misses.append(f"{at}: the generator is the previous regeneration's ({before.get('by')}): record it as a hand edit")
        check_record((root / path).read_text(), record, kind, at, misses)
        state = f"{kind} by {record.get('by')}"
        code = code_hash(root, files, entries_)
        if kind == "regenerated" and code != record.get("code-hash"):
            state += f"; the generator moved since (now {code}), its output did not"
        report.append(f"golden  {path}: {state}")


def check(root):
    """The report lines and the failures."""
    try:
        ledger = tomllib.loads((root / LEDGER).read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        return [], [f"{LEDGER}: {e}"]
    report, misses = [], []
    unknown(ledger, "ledger", LEDGER, misses)
    if "regen" not in ledger:
        misses.append(f"{LEDGER}: no [regen]")
    bits = check_regen(root, ledger.get("regen", {}), misses)
    groups = ledger.get("groups", {})
    for name in groups:
        if name.startswith("@") or not isinstance(groups[name], list):
            misses.append(f"{LEDGER}: [groups] {name} is no list of globs")
    seen = set()
    for a in ledger.get("artifact", []):
        path = a.get("path", "")
        where = f"{LEDGER}: {path or '[[artifact]] without a path'}"
        unknown(a, "artifact", where, misses)
        if path in seen:
            misses.append(f"{where}: listed twice")
        seen.add(path)
        for k in ("path", "from", "regen"):
            if not a.get(k):
                misses.append(f"{where}: no `{k}`")
        for other in sorted(set(RSA_FLAG.findall(a.get("regen", ""))) - {bits}):
            misses.append(f"{where}: its regen probes RSA up to {other}, not {bits}")
        for named in REPO_PATH.findall(a.get("regen", "")):
            if not (root / named).exists():
                misses.append(f"{where}: its regen names {named}, which does not exist")
        if not (root / path).is_file():
            misses.append(f"{where}: no such file")
            continue
        if "verified-by" in a:
            extra = sorted(set(a) & {"code", "hash", "probed", "hand-edits", "acknowledged"})
            if extra:
                misses.append(f"{where}: a build re-derives it (`verified-by`), so it records no run: drop {extra}")
            report.append(f"build-verified  {path}: {a['verified-by']}")
            continue
        check_run(root, a, path, where, groups, report, misses)
    modules = root / "profiles" / "modules"
    for p in sorted(modules.glob("*/*.toml")) if modules.is_dir() else []:
        rel = p.relative_to(root).as_posix()
        if rel not in seen:
            misses.append(f"{LEDGER}: {rel} has no [[artifact]]: say what verifies it")
    check_golden(root, ledger, groups, report, misses)
    return report, misses


def check_run(root, a, path, where, groups, report, misses):
    """An artifact from a run no build repeats: its file, its hand edits and its code."""
    probed, edits, ack = a.get("probed", {}), a.get("hand-edits", []), a.get("acknowledged")
    unknown(probed, "probed", f"{where}: [artifact.probed]", misses)
    if ack:
        unknown(ack, "acknowledged", f"{where}: [artifact.acknowledged]", misses)
        for k in ("code-hash", "by", "why", "reprobe"):
            if not ack.get(k):
                misses.append(f"{where}: [artifact.acknowledged] has no `{k}`")
    for e in edits:
        unknown(e, "hand-edits", f"{where}: [[artifact.hand-edits]]", misses)
        if not (e.get("by") and e.get("what")):
            misses.append(f"{where}: a [[artifact.hand-edits]] row needs `by` and `what`")
    for k in ("by", "date", "hash"):
        if not probed.get(k):
            misses.append(f"{where}: [artifact.probed] has no `{k}`")
    if "code" not in a:
        misses.append(f"{where}: no `code`: the globs whose change can change it, or [] for none")
    now = file_hash(root / path)
    if a.get("hash") != now:
        misses.append(
            f'{where}: the file is not the one recorded (now hash = "{now}"): record a run in '
            "[artifact.probed], or a hand edit in [[artifact.hand-edits]], and the hash"
        )
    if now != probed.get("hash") and not edits:
        misses.append(f"{where}: not what the run ({probed.get('by')}) wrote, and no [[artifact.hand-edits]] row says so")
    if now == probed.get("hash") and edits:
        misses.append(f"{where}: [[artifact.hand-edits]] rows, but the file is what the run wrote: drop them")
    state = f"probed {probed.get('by')} ({probed.get('date')})"
    if edits:
        state += f", hand-edited since by {', '.join(e.get('by', '?') for e in edits)}"
    files, entries, empty = code_files(root, a.get("code", []), groups)
    for what in empty:
        misses.append(f"{where}: code {what}")
    if not a.get("code"):
        if "code-hash" in probed or ack:
            misses.append(f"{where}: no code on its path, so no code-hash and no [artifact.acknowledged]")
        report.append(f"captured  {path}: {state}")
        return
    code = code_hash(root, files, entries)
    if code == probed.get("code-hash"):
        if ack:
            misses.append(f"{where}: [artifact.acknowledged], but the code on its path is the run's: drop it")
        report.append(f"fresh  {path}: {state}")
        return
    if not ack or ack.get("code-hash") != code:
        since = f"it was acknowledged ({ack.get('by')})" if ack else f"the run ({probed.get('by')}, {probed.get('date')})"
        misses.append(
            f"{where}: the code on its path changed since {since}: run it again on the hardware "
            f'({a.get("regen")}), or record [artifact.acknowledged] with code-hash = "{code}", by, why and reprobe'
        )
        return
    report.append(f"STALE  {path}: {state}; the code on its path changed since, acknowledged by {ack.get('by')}")


def main():
    report, misses = check(pathlib.Path(sys.argv[1]))
    for line in report + misses:
        print(line)
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main())
