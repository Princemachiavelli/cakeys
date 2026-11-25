"""Prose stands in for a rule less and less (checks.oracle-count; docs/DEVELOPMENT.md, "Testing").

Each integration test file (crates/*/tests/**/*.rs) has its assertion sites counted
(docs/archive/REVIEW-2026-11-24/phase2-3-design.md §3.5): every `assert!`, `assert_eq!` and
`assert_ne!` (a `prop_` one too), by its subject: the condition, or the two operands, never the
message.

- A prose site asserts on what a tool said: its subject calls `.contains(…)` and reads a tool's
  output, as text or parsed (`stderr`, `stdout`: the fields or the helpers; `rows`,
  `lock_result`), directly or through a name a `let` of the same function bound to it; or its
  subject names a verdict a `let` drew that way (`let warned = stderr(&o).lines().any(|l|
  l.contains(…))`).
- An exit site asserts on an exit code: its subject calls `code(…)` or `.success()`, or names a
  `let` that did.

A refusal's oracle is its exit, the rule its row names and the state it left
(crates/cli/tests/common/state.rs, `Workdir::refused`): exit sites are counted, never limited.
The prose standing in for the rule is what is limited: no file may have more prose sites than
nix/oracle-count.toml gives it, and a file it does not name may have none (review 2026-11-24
C-9). A site is a line of source, not a test: a helper that asserts prose for its callers is one
site.

    python3 -I nix/oracle-count.py ROOT [--manifest FILE]
        Each file's counts; fails on a file with more prose sites than the manifest gives it.
    python3 -I nix/oracle-count.py ROOT --write
        Lowers each number to the file's count, and drops a file with none. It never raises a
        number or adds a file: that is a hand edit, which the diff shows and the commit explains.
        A manifest that is not there is written whole (seeded).

Python 3.11 or later (tomllib): `nix develop -c python3 -I nix/oracle-count.py .`. Exits 1 on a
failure, 2 on a source it cannot read. Its tests are nix/oracle-count-tests.py.
"""

import argparse
import importlib.util
import pathlib
import re
import sys
import tomllib

MANIFEST = "nix/oracle-count.toml"
ASSERT = re.compile(r"(?:prop_)?assert(?:_eq|_ne)?")
# A tool's output, read: the `Output` fields or the helpers of that name
# (crates/cli/tests/common/mod.rs), and the helpers that parse it (`rows`: common/state.rs).
OUTPUT = {"stderr", "stdout"}
PARSERS = {"lock_result", "rows"}

# Read-only in the Nix sandbox, and no file to leave in a checkout.
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("test_count", pathlib.Path(__file__).with_name("test-count.py"))
test_count = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(test_count)
Unreadable = test_count.Unreadable


def calls(toks, name, method):
    """Whether `toks` call `name`: as a method (`.name(`) when `method`, else in any form."""
    for i in range(len(toks) - 1):
        if toks[i] == ("id", name) and toks[i + 1] == ("p", "("):
            if not method or (i > 0 and toks[i - 1] == ("p", ".")):
                return True
    return False


def kinds(toks, bound):
    """What an expression is, given the kinds of the names bound before it: a set of "output"
    (a tool's output, as text or parsed), "prose" (a `.contains(…)` verdict on it), "exit" (an
    exit code, or a verdict on one)."""
    ids = {v for k, v in toks if k == "id"}
    named = set().union(*(bound.get(v, set()) for v in ids))
    out = set()
    output = bool(ids & OUTPUT) or any(calls(toks, p, False) for p in PARSERS) or "output" in named
    if (output and calls(toks, "contains", True)) or "prose" in named:
        out.add("prose")
    elif output:
        out.add("output")
    if calls(toks, "code", False) or calls(toks, "success", True) or "exit" in named:
        out.add("exit")
    return out


def until(toks, i, stops):
    """The index of the first token from `i` on that is one of `stops` at depth 0, or the end."""
    depth = 0
    while i < len(toks):
        k, v = toks[i]
        if depth == 0 and k == "p" and v in stops:
            return i
        if k == "p" and v in "([{":
            depth += 1
        elif k == "p" and v in ")]}":
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return i


def arguments(toks, i):
    """The arguments of the macro call whose `(` is at `i`, and the index after its `)`."""
    args, at = [], i + 1
    while True:
        end = until(toks, at, ",")
        if end >= len(toks):
            raise Unreadable("an assertion that does not end")
        args.append(toks[at:end])
        if toks[end] == ("p", ")"):
            return [a for a in args if a], end + 1
        at = end + 1


def bindings(pattern):
    """The names a `let` pattern binds: its lowercase identifiers, not a path's or a variant's
    (`Some(x)`, `Kind::A`), and none of its type annotation's."""
    pattern = pattern[: until(pattern, 0, ":")]
    out = []
    for i, (k, v) in enumerate(pattern):
        nxt = pattern[i + 1] if i + 1 < len(pattern) else (None, None)
        if k != "id" or v in ("mut", "ref", "box") or not (v[0].islower() or v[0] == "_"):
            continue
        if nxt in (("p", "("), ("p", "{"), ("p", ":")) or (i and pattern[i - 1] == ("p", ":")):
            continue
        out.append(v)
    return out


def sites(text, where):
    """The file's assertion sites: (prose, exit) counts."""
    toks = test_count.tokens(text, where)
    prose = exits = 0
    bound = {}  # name -> kinds, within the function being read
    depth, fn_depth = 0, None
    i = 0
    while i < len(toks):
        k, v = toks[i]
        if (k, v) == ("p", "{"):
            depth += 1
        elif (k, v) == ("p", "}"):
            depth -= 1
            if fn_depth is not None and depth < fn_depth:
                fn_depth, bound = None, {}
        elif (k, v) == ("id", "fn") and fn_depth is None:
            # The function's body opens at the next `{` that is not inside its signature's parens.
            j = until(toks, i + 1, "{;")
            if j < len(toks) and toks[j] == ("p", "{"):
                fn_depth = depth + 1
        elif (k, v) == ("id", "let"):
            eq = until(toks, i + 1, "=;")
            if eq < len(toks) and toks[eq] == ("p", "="):
                # An `if let`'s or a `while let`'s expression ends at its block.
                end = until(toks, eq + 1, "{;" if i and toks[i - 1] in (("id", "if"), ("id", "while")) else ";")
                got = kinds(toks[eq + 1 : end], bound)
                for name in bindings(toks[i + 1 : eq]):
                    bound[name] = got
        elif (k, v) == ("id", "for"):
            # A loop's pattern takes what its iterator gives (`for r in rows(&o)`).
            block = until(toks, i + 1, "{;")
            at = next((j for j in range(i + 1, block) if toks[j] == ("id", "in")), None)
            if at is not None:
                got = kinds(toks[at + 1 : block], bound)
                for name in bindings(toks[i + 1 : at]):
                    bound[name] = got
        elif k == "id" and ASSERT.fullmatch(v) and toks[i + 1 : i + 3] == [("p", "!"), ("p", "(")]:
            args, after = arguments(toks, i + 2)
            subject = [t for a in args[: 1 if v.endswith("assert") else 2] for t in a]
            got = kinds(subject, bound)
            prose += "prose" in got
            exits += "exit" in got
            # The arguments may hold closures with assertions of their own.
            i += 3
            continue
        i += 1
    return prose, exits


def count(root):
    """{file relative to ROOT: (prose, exit)} for every integration test file."""
    root = pathlib.Path(root)
    found = {}
    for path in sorted(root.glob("crates/*/tests/**/*.rs")):
        rel = path.relative_to(root).as_posix()
        try:
            text = path.read_text()
        except OSError as e:
            raise Unreadable(f"{rel}: {e.strerror}") from None
        found[rel] = sites(text, rel)
    return found


def read_manifest(path):
    try:
        text = pathlib.Path(path).read_text()
    except OSError as e:
        raise Unreadable(f"{path}: {e.strerror}") from None
    return {k: int(v) for k, v in tomllib.loads(text).items()}


def write_manifest(path, found):
    """Each number lowered to its file's count, a file with none dropped; none raised, none
    added. A manifest that is not there is seeded with every file that has a prose site."""
    p = pathlib.Path(path)
    if p.exists():
        lines = p.read_text().splitlines(keepends=True)
        header = "".join(ln for ln in lines if ln.startswith("#"))
        old = read_manifest(path)
        new = {f: min(n, found.get(f, (0, 0))[0]) for f, n in old.items()}
    else:
        header = ""
        new = {f: prose for f, (prose, _) in found.items()}
    body = "".join(f'"{f}" = {n}\n' for f, n in sorted(new.items()) if n)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(header + ("\n" if header else "") + body)


def check(root, manifest_path):
    found = count(root)
    most = read_manifest(manifest_path)
    over = []
    print(f"{'test file':<56} {'prose':>5} {'most':>5} {'exit':>5}")
    for f in sorted(set(found) | set(most)):
        prose, exits = found.get(f, (0, 0))
        if not prose and not exits and f not in most:
            continue
        print(f"{f:<56} {prose:>5} {most.get(f, 0):>5} {exits:>5}")
        if prose > most.get(f, 0):
            over.append((f, prose, most.get(f, 0)))
    prose, exits = sum(p for p, _ in found.values()), sum(e for _, e in found.values())
    print(f"oracle-count: {prose} prose sites (at most {sum(most.values())}), {exits} exit sites, {len(found)} files")
    lower = sum(most.values()) - sum(min(found.get(f, (0, 0))[0], n) for f, n in most.items())
    if lower:
        print(f"oracle-count: {lower} fewer than the manifest allows: lower it (--write)")
    for f, prose, allowed in over:
        print(f"{f}: {prose} prose assertion sites, {manifest_path} allows {allowed}", file=sys.stderr)
    if over:
        print(
            "\nA prose assertion was added: assert the exit, the rule the row names and the state the run left "
            "(crates/cli/tests/common/state.rs, `Workdir::refused`) instead, or raise the number in this diff "
            "and say why.",
            file=sys.stderr,
        )
        return 1
    return 0


def main():
    p = argparse.ArgumentParser(description="Count each test file's prose and exit assertions (the docstring).")
    p.add_argument("root")
    p.add_argument("--manifest")
    p.add_argument("--write", action="store_true")
    a = p.parse_args()
    manifest = a.manifest or str(pathlib.Path(a.root) / MANIFEST)
    try:
        if a.write:
            write_manifest(manifest, count(a.root))
            return 0
        return check(a.root, manifest)
    except Unreadable as e:
        print(f"oracle-count: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
