"""Every test binary keeps its tests (checks.test-count; docs/DEVELOPMENT.md, "Testing").

The tests of each test binary in the workspace are counted from the source, under the name
cargo-nextest gives the binary (`cakeys-core`, `cakeys::fault`, `cakeys::bin/cakeys`): every
function marked `#[test]` (a `proptest!` case carries it too) or `#[<runtime>::test]`, in the
files the binary's root reaches through `mod` (`#[path]` followed), whatever its `cfg`. So a test
compiled out on one platform still counts there, and a loss shows on every platform. A test
attribute this script cannot count (`#[rstest]`, `#[test_case]`, a test inside `macro_rules!`)
is an error, not a guess.

    python3 -I nix/test-count.py ROOT [--manifest FILE] [--base REV|DIR]
        Each binary has at least the tests the manifest (ROOT/nix/test-count.toml) gives it. A
        test that disappears fails here unless the same diff lowers the manifest, where a
        reviewer sees it; a new test needs no edit. The tests gone are named from --base (a git
        revision of ROOT, or a source tree): by default, the commit that last changed the
        manifest.
    python3 -I nix/test-count.py ROOT --write
        Writes the manifest from the source as it is.
    python3 -I nix/test-count.py ROOT --junit FILE [--skips FILE] [--partial] [-- CARGO ARGS]
        What a cargo-nextest run ran, from its JUnit report (`.config/nextest.toml`), and what it
        skipped (the lines crates/test-skip.rs appends to FILE), per binary. CARGO ARGS are the
        run's own (--workspace, --exclude, --features, --no-default-features): every binary they
        build must have run each test its source has, and no other. --partial is for a filtered
        run: it reports, and compares nothing.

Python 3.11 or later (tomllib): `nix develop -c python3 -I nix/test-count.py .`. Exits 1 on a
failure, 2 on a source it cannot read.
"""

import argparse
import collections
import contextlib
import io
import pathlib
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import xml.etree.ElementTree as ET

MANIFEST = "nix/test-count.toml"

# The test attributes counted: `#[test]` and a runtime's (`#[tokio::test]`). The ones below make
# a number of tests the source does not show, or one per attribute: refused until counted here.
UNCOUNTED = {"rstest", "test_case", "quickcheck", "test_matrix"}


class Unreadable(Exception):
    """A source this script cannot follow: exit 2, never a count."""


LEX = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<line>//[^\n]*)
  | (?P<block>/\*)
  | (?P<raw>(?:b|c)?r(?P<hashes>\#*)")
  | (?P<str>(?:b|c)?")
  | (?P<char>'(?:\\(?:x[0-9A-Fa-f]{2}|u\{[0-9A-Fa-f_]+\}|.)|[^\\'\n])')
  | (?P<life>')
  | (?P<id>(?:r\#)?[A-Za-z0-9_]+)
  | (?P<p>.)
    """,
    re.X | re.S,
)
STRING_BODY = re.compile(r'(?:[^"\\]|\\.)*"', re.S)


def tokens(text, where):
    """The tokens of a Rust source that matter here: ("id", name), ("str", value) and ("p",
    punctuation); comments, whitespace, character literals and lifetimes are dropped."""
    out = []
    at, end = 0, len(text)
    while at < end:
        m = LEX.match(text, at)
        kind = m.lastgroup
        if kind == "hashes":
            kind = "raw"
        if kind == "block":
            depth, at = 1, m.end()
            while depth:
                opens, closes = text.find("/*", at), text.find("*/", at)
                if closes < 0:
                    raise Unreadable(f"{where}: a block comment that does not end")
                if 0 <= opens < closes:
                    depth, at = depth + 1, opens + 2
                else:
                    depth, at = depth - 1, closes + 2
            continue
        if kind == "raw":
            close = '"' + m.group("hashes")
            stop = text.find(close, m.end())
            if stop < 0:
                raise Unreadable(f"{where}: a raw string that does not end")
            out.append(("str", text[m.end() : stop]))
            at = stop + len(close)
            continue
        if kind == "str":
            body = STRING_BODY.match(text, m.end())
            if not body:
                raise Unreadable(f"{where}: a string that does not end")
            out.append(("str", body.group(0)[:-1]))
            at = body.end()
            continue
        if kind == "id":
            out.append(("id", m.group("id").removeprefix("r#")))
        elif kind == "p":
            out.append(("p", m.group("p")))
        at = m.end()
    return out


def attribute(toks, at):
    """The attribute whose `[` is at `at`: (its path, its string, the index after its `]`)."""
    depth, i = 0, at
    while True:
        if i >= len(toks):
            raise Unreadable("an attribute that does not end")
        kind, value = toks[i]
        if kind == "p" and value == "[":
            depth += 1
        elif kind == "p" and value == "]":
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = toks[at + 1 : i]
    path = []
    for kind, value in body:
        if kind == "id":
            path.append(value)
        elif (kind, value) != ("p", ":"):
            break
    string = next((v for k, v in body if k == "str"), None)
    return "::".join(path), string, i + 1


def scan(text, where):
    """One file's items: its tests as (inline module path, name, ignored) and its `mod`
    declarations as (inline module path, name, `#[path]` or None)."""
    toks = tokens(text, where)
    tests, mods = [], []
    inline = []  # (name, depth inside its braces)
    pending = []  # the attributes since the last item
    opening = None  # the name of an inline module whose `{` comes next
    depth, i = 0, 0
    while i < len(toks):
        kind, value = toks[i]
        nxt = toks[i + 1] if i + 1 < len(toks) else (None, None)
        if (kind, value) == ("p", "#"):
            bang = nxt == ("p", "!")
            start = i + 2 if bang else i + 1
            if start < len(toks) and toks[start] == ("p", "["):
                path, string, i = attribute(toks, start)
                if not bang:
                    pending.append((path, string))
                continue
        elif kind == "id" and value == "macro_rules" and nxt == ("p", "!"):
            # A macro's definition: skipped whole. A test inside it is made once per use.
            j, nested = i + 3, 0
            while j < len(toks):
                k, v = toks[j]
                if k == "p" and v in "([{":
                    nested += 1
                elif k == "p" and v in ")]}":
                    nested -= 1
                    if nested == 0:
                        break
                elif k == "id" and v == "test" and toks[j - 1] == ("p", "["):
                    raise Unreadable(f"{where}: a #[test] inside macro_rules! {toks[i + 2][1]}: count it here")
                j += 1
            i, pending = j + 1, []
            continue
        elif kind == "id" and value == "mod" and nxt[0] == "id":
            path = next((s for p, s in pending if p == "path"), None)
            after = toks[i + 2] if i + 2 < len(toks) else (None, None)
            if after == ("p", ";"):
                if path is not None and inline:
                    raise Unreadable(f"{where}: #[path] inside an inline module: follow it here")
                mods.append((tuple(n for n, _ in inline), nxt[1], path))
            elif after == ("p", "{"):
                opening = nxt[1]
            pending = []
            i += 2
            continue
        elif kind == "id" and value == "fn" and nxt[0] == "id":
            paths = [p for p, _ in pending]
            uncounted = [p for p in paths if p.split("::")[-1] in UNCOUNTED]
            if uncounted:
                raise Unreadable(f"{where}: #[{uncounted[0]}] on {nxt[1]}: count its tests here")
            if any(p == "test" or p.endswith("::test") for p in paths):
                tests.append((tuple(n for n, _ in inline), nxt[1], "ignore" in paths))
            pending = []
            i += 2
            continue
        elif kind == "p" and value == "{":
            depth += 1
            if opening is not None:
                inline.append((opening, depth))
                opening = None
            pending = []
        elif kind == "p" and value == "}":
            if inline and inline[-1][1] == depth:
                inline.pop()
            depth -= 1
            pending = []
        elif kind == "p" and value in ";,":
            pending = []
        i += 1
    return tests, mods


class Tree:
    """A source tree: its files read once, by path relative to its root."""

    def __init__(self, root):
        self.root = pathlib.Path(root)
        self.texts = {}

    def exists(self, rel):
        return (self.root / rel).is_file()

    def text(self, rel):
        if rel not in self.texts:
            try:
                self.texts[rel] = (self.root / rel).read_text()
            except OSError as e:
                raise Unreadable(f"{rel}: {e.strerror}") from None
        return self.texts[rel]

    def glob(self, rel_dir, pattern):
        """The paths under `rel_dir` that `pattern` matches, relative to `rel_dir`."""
        d = self.root / rel_dir
        return sorted(p.relative_to(d).as_posix() for p in d.glob(pattern)) if d.is_dir() else []


def target_tests(tree, root_file):
    """Every test the target rooted at `root_file` has: (name, ignored, file)."""
    found = []

    def visit(rel, modpath, child_dir, chain):
        if rel in chain:
            raise Unreadable(f"{rel}: a module cycle")
        tests, mods = scan(tree.text(rel), rel)
        for inline, name, ignored in tests:
            found.append(("::".join(modpath + inline + (name,)), ignored, rel))
        for inline, name, path in mods:
            if path is not None:
                # Relative to the declaring file's directory; the file loaded is read like a
                # mod.rs, its own modules beside it.
                child = posixpath.normpath(posixpath.join(posixpath.dirname(rel), path))
                below = posixpath.dirname(child)
            else:
                d = posixpath.join(child_dir, *inline)
                choices = [posixpath.join(d, name + ".rs"), posixpath.join(d, name, "mod.rs")]
                child = next((c for c in choices if tree.exists(c)), None)
                if child is None:
                    raise Unreadable(f"{rel}: mod {name}: neither {choices[0]} nor {choices[1]}")
                below = posixpath.join(d, name)
            visit(child, modpath + inline + (name,), below, chain | {rel})

    visit(root_file, (), posixpath.dirname(root_file), frozenset())
    return found


def package_targets(tree, pkg_dir):
    """The package's name and its test binaries as {nextest name: (root file, required features)},
    by Cargo's target discovery and its [lib], [[bin]] and [[test]] tables."""
    manifest = tomllib.loads(tree.text(posixpath.join(pkg_dir, "Cargo.toml")))
    package = manifest["package"]
    name = package["name"]
    targets = {}
    lib = manifest.get("lib", {})
    lib_path = lib.get("path", "src/lib.rs")
    if tree.exists(posixpath.join(pkg_dir, lib_path)) and lib.get("test", True):
        targets[name] = (lib_path, ())

    # Cargo's discovery (paths relative to the package), then the tables, which name a
    # discovered target to add to it (`required-features`) or a target of their own.
    found = {"bin": {}, "test": {}}
    if package.get("autobins", True):
        if tree.exists(posixpath.join(pkg_dir, "src/main.rs")):
            found["bin"][name] = "src/main.rs"
        for p in tree.glob(posixpath.join(pkg_dir, "src/bin"), "*.rs"):
            found["bin"][p[:-3]] = f"src/bin/{p}"
        for p in tree.glob(posixpath.join(pkg_dir, "src/bin"), "*/main.rs"):
            found["bin"][posixpath.dirname(p)] = f"src/bin/{p}"
    if package.get("autotests", True):
        for p in tree.glob(posixpath.join(pkg_dir, "tests"), "*.rs"):
            found["test"][p[:-3]] = f"tests/{p}"
        for p in tree.glob(posixpath.join(pkg_dir, "tests"), "*/main.rs"):
            found["test"][posixpath.dirname(p)] = f"tests/{p}"
    for kind, prefix in (("bin", "bin/"), ("test", "")):
        tables = {t["name"]: t for t in manifest.get(kind, [])}
        for n in sorted(set(found[kind]) | set(tables)):
            t = tables.get(n, {})
            default = found[kind].get(n) or ("src/main.rs" if n == name else f"src/bin/{n}.rs")
            if kind == "test":
                default = found[kind].get(n, f"tests/{n}.rs")
            # A target without libtest (`harness = false`) runs its own way: no #[test] counts.
            if t.get("test", True) and t.get("harness", True):
                targets[f"{name}::{prefix}{n}"] = (t.get("path", default), tuple(t.get("required-features", ())))
    return name, manifest.get("features", {}), {b: (posixpath.join(pkg_dir, p), r) for b, (p, r) in targets.items()}


def members(tree):
    """The workspace's member directories, its default members among them."""
    ws = tomllib.loads(tree.text("Cargo.toml"))["workspace"]
    out = []
    for pattern in ws.get("members", []):
        matched = [m for m in tree.glob(".", pattern) if tree.exists(posixpath.join(m, "Cargo.toml"))]
        if not matched:
            raise Unreadable(f"Cargo.toml: the member {pattern} has no Cargo.toml")
        out += matched
    exclude = set(ws.get("exclude", []))
    return [m for m in dict.fromkeys(out) if m not in exclude], ws.get("default-members", [])


def count(tree):
    """{nextest binary name: Binary} for the whole workspace."""
    found = {}
    dirs, defaults = members(tree)
    for d in dirs:
        package, features, targets = package_targets(tree, d)
        for binary, (root, needs) in targets.items():
            if not tree.exists(root):
                raise Unreadable(f"{binary}: {root} is not there")
            found[binary] = Binary(package, d in defaults, features, needs, target_tests(tree, root))
    return found


class Binary:
    def __init__(self, package, default, features, needs, tests):
        self.package, self.default, self.features, self.needs = package, default, features, needs
        self.tests = tests
        self.names = collections.Counter(n for n, _, _ in tests)
        self.run = collections.Counter(n for n, ignored, _ in tests if not ignored)


def read_manifest(path):
    try:
        text = pathlib.Path(path).read_text()
    except OSError as e:
        raise Unreadable(f"{path}: {e.strerror}") from None
    return text, {k: int(v) for k, v in tomllib.loads(text).items()}


def key(binary):
    return binary if re.fullmatch(r"[A-Za-z0-9_-]+", binary) else f'"{binary}"'


def write_manifest(path, binaries):
    """The manifest with every binary that has a test, its comment header kept."""
    try:
        header = "".join(
            ln for ln in pathlib.Path(path).read_text().splitlines(keepends=True) if ln.startswith("#")
        )
    except OSError:
        header = ""
    body = "".join(f"{key(b)} = {len(x.tests)}\n" for b, x in sorted(binaries.items()) if x.tests)
    pathlib.Path(path).write_text(header + ("\n" if header else "") + body)


def base_tree(root, base, stack):
    """The tree --base names: a directory as it is, or a git revision of ROOT's repository."""
    if pathlib.Path(base).is_dir():
        return Tree(base)
    # The workspace's manifest, and the directories its members are in.
    git = ["git", "-C", str(root)]
    workspace = subprocess.run([*git, "show", f"{base}:Cargo.toml"], capture_output=True, text=True)
    if workspace.returncode:
        raise Unreadable(f"--base {base}: {workspace.stderr.strip()}")
    tops = {m.split("/")[0] for m in tomllib.loads(workspace.stdout)["workspace"].get("members", [])}
    archive = subprocess.run([*git, "archive", "--format=tar", base, "Cargo.toml", *sorted(tops)], capture_output=True)
    if archive.returncode:
        raise Unreadable(f"--base {base}: {archive.stderr.decode().strip()}")
    d = stack.enter_context(tempfile.TemporaryDirectory())
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as t:
        t.extractall(d, filter="data")
    return Tree(d)


def default_base(root, manifest):
    """The commit that last changed the manifest, if ROOT is a git checkout that has one."""
    try:
        rel = pathlib.Path(manifest).resolve().relative_to(pathlib.Path(root).resolve())
        got = subprocess.run(
            ["git", "-C", str(root), "log", "-1", "--format=%H", "--", str(rel)], capture_output=True, text=True
        )
    except (ValueError, OSError):
        return None
    return got.stdout.strip() or None


def gone(before, now, binary):
    """The tests of `binary` in `before` that `now` lacks: (name, where it went or None)."""
    lost = before[binary].names - (now[binary].names if binary in now else collections.Counter())
    elsewhere = collections.defaultdict(list)
    for b, x in now.items():
        for n in x.names:
            elsewhere[n.rsplit("::", 1)[-1]].append(n if b == binary else f"{b} {n}")
    out = []
    for name in sorted(lost.elements()):
        moved = elsewhere.get(name.rsplit("::", 1)[-1])
        out.append((name, moved[0] if moved else None))
    return out


def check(root, manifest_path, base):
    binaries = count(Tree(root))
    text, minimum = read_manifest(manifest_path)
    failures = []
    for binary in sorted(set(minimum) | set(binaries)):
        has = len(binaries[binary].tests) if binary in binaries else 0
        want = minimum.get(binary, 0)
        print(f"{binary:<32} {has:>5} {'(at least ' + str(want) + ')' if want else ''}")
        if has < want:
            failures.append(binary)
    total = sum(len(x.tests) for x in binaries.values())
    packages = {x.package for x in binaries.values()}
    print(f"test-count: {total} tests in {len(binaries)} binaries of {len(packages)} packages")
    if not failures:
        return 0
    print(file=sys.stderr)
    base = base or default_base(root, manifest_path)
    with contextlib.ExitStack() as stack:
        before = count(base_tree(root, base, stack)) if base else None
        for binary in failures:
            has = len(binaries[binary].tests) if binary in binaries else 0
            print(f"{binary}: {has} tests, {manifest_path} says at least {minimum[binary]}", file=sys.stderr)
            if before is None or binary not in before:
                continue
            lost = gone(before, binaries, binary)
            for name, moved in lost:
                if moved is None:
                    print(f"  gone since {base[:12]}: {name}", file=sys.stderr)
            moved = sum(1 for _, m in lost if m is not None)
            if moved:
                print(f"  and {moved} moved or renamed within the workspace since {base[:12]}", file=sys.stderr)
    if before is None:
        print("(to name the tests gone: --base REV, in a git checkout)", file=sys.stderr)
    print(
        f"\nA test went: bring it back, or lower {MANIFEST} in this diff (--write) and say why.",
        file=sys.stderr,
    )
    return 1


def left_out(binary, selected):
    """Why the cargo arguments `selected` do not build `binary` (its package not selected, or a
    required feature off), or None: they build it."""
    if binary.package in selected["exclude"]:
        return "its package excluded"
    if selected["packages"]:
        if binary.package not in selected["packages"]:
            return "its package not selected"
    elif not selected["workspace"] and not binary.default:
        return "not a default member"
    if selected["all"]:
        return None
    on = set() if selected["no_default"] else {"default"}
    for f in selected["features"]:
        pkg, _, feat = f.rpartition("/")
        if not pkg or pkg == binary.package:
            on.add(feat)
    todo = list(on)
    while todo:
        for implied in binary.features.get(todo.pop(), []):
            if "/" not in implied and not implied.startswith("dep:") and implied not in on:
                on.add(implied)
                todo.append(implied)
    off = [f for f in binary.needs if f not in on]
    return f"needs {', '.join(off)}" if off else None


def cargo_selection(args):
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--workspace", "--all", action="store_true")
    p.add_argument("--exclude", action="append", default=[])
    p.add_argument("-p", "--package", action="append", default=[])
    p.add_argument("-F", "--features", action="append", default=[])
    p.add_argument("--all-features", action="store_true")
    p.add_argument("--no-default-features", action="store_true")
    known, _ = p.parse_known_args(args)
    return {
        "workspace": known.workspace,
        "exclude": set(known.exclude),
        "packages": set(known.package),
        "features": [f for fs in known.features for f in re.split(r"[ ,]+", fs) if f],
        "all": known.all_features,
        "no_default": known.no_default_features,
    }


def report(root, junit, skips, partial, cargo_args):
    """What the run ran and skipped, per binary; 1 when a binary it built did not run exactly the
    tests its source has."""
    binaries = count(Tree(root))
    try:
        suites = ET.parse(junit).getroot().iter("testsuite")
    except (OSError, ET.ParseError) as e:
        raise Unreadable(f"{junit}: {e}") from None
    ran = {s.get("name"): collections.Counter(c.get("name") for c in s.iter("testcase")) for s in suites}
    skipped = collections.defaultdict(set)
    if skips:
        try:
            lines = pathlib.Path(skips).read_text().splitlines()
        except OSError as e:
            raise Unreadable(f"{skips}: {e.strerror}") from None
        for line in lines:
            binary, test, _ = (line.split("\t") + ["", ""])[:3]
            skipped[binary].add(test)
    selected = cargo_selection(cargo_args)
    failures = []
    print(f"{'test binary':<32} {'ran':>5} {'skipped':>8}")
    for binary in sorted(set(binaries) | set(ran)):
        x = binaries.get(binary)
        if binary not in ran:
            if x is None or not x.tests:
                continue
            why = left_out(x, selected)
            if why:
                print(f"{binary:<32} {'-':>5} {'':>8} not built here ({why})")
            elif not partial:
                failures.append(f"{binary}: built by this run, and it ran none of its {sum(x.run.values())} tests")
                print(f"{binary:<32} {'-':>5} {'':>8} NOT RUN")
            continue
        n_skipped = len(skipped.get(binary, ()))
        print(f"{binary:<32} {sum(ran[binary].values()):>5} {n_skipped:>8}")
        if partial:
            continue
        expected = x.run if x is not None else collections.Counter()
        missing, extra = expected - ran[binary], ran[binary] - expected
        if missing or extra:
            what = [f"{binary}: ran {sum(ran[binary].values())} tests, its source has {sum(expected.values())}"]
            what += [f"  not run: {n}" for n in sorted(missing.elements())]
            what += [f"  not in the source: {n}" for n in sorted(extra.elements())]
            failures.append("\n".join(what))
    for binary in sorted(set(skipped) - set(ran)):
        failures.append(f"{binary}: the skip log names it, the JUnit report does not")
    total = sum(sum(c.values()) for c in ran.values())
    n_skips = sum(len(s) for s in skipped.values())
    print(f"test-count: {total} tests ran in {len(ran)} binaries, {n_skips} of them skipped")
    for binary in sorted(skipped):
        for test in sorted(skipped[binary]):
            print(f"  skipped: {binary} {test}")
    for f in failures:
        print(f, file=sys.stderr)
    return 1 if failures else 0


def main():
    argv = sys.argv[1:]
    cargo_args = argv[argv.index("--") + 1 :] if "--" in argv else []
    argv = argv[: argv.index("--")] if "--" in argv else argv
    p = argparse.ArgumentParser(description="Count each test binary's tests (see the module docstring).")
    p.add_argument("root")
    p.add_argument("--manifest")
    p.add_argument("--write", action="store_true")
    p.add_argument("--base")
    p.add_argument("--junit")
    p.add_argument("--skips")
    p.add_argument("--partial", action="store_true")
    a = p.parse_args(argv)
    manifest = a.manifest or str(pathlib.Path(a.root) / MANIFEST)
    try:
        if a.write:
            write_manifest(manifest, count(Tree(a.root)))
            return 0
        if a.junit:
            return report(a.root, a.junit, a.skips, a.partial, cargo_args)
        return check(a.root, manifest, a.base)
    except Unreadable as e:
        print(f"test-count: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
