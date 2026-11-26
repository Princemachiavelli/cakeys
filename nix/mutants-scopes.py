"""Every source file of the workspace is in a tier of the mutation gate or is left out with a
reason (checks.mutants-scopes). The tiers and the reasons are in nix/mutants-scopes.toml.

The check fails in these cases:
- A source file of a workspace crate (a `.rs` file under the `src` directory of a member that
  Cargo.toml's `workspace.members` lists) is in no scope and is not left out. A new crate, a new
  file, and the new name of a renamed file fail this way.
- A file is in two scopes, or is both in a scope and left out.
- A pattern of a scope or of `left-out` matches no source file of the workspace. The old name of
  a renamed file, or a deleted file, fails this way.
- A scope names a package that is not a workspace crate, or a file outside that package.
- A part of a scope's `re` (the regular expression split at each `|`) matches no function of the
  scope's files. A function is matched by its name (`find`) and by its type's name with `::`
  (`Draft::`), as cargo-mutants names a mutant. The old name of a renamed function fails this way.
- A `left-out` entry has an empty reason.

The function names come from the source text with every `#[cfg(test)]` item removed
(cargo-mutants does not mutate test code), not from a parser: every `fn` name, and the type of
every `impl` block.

Usage: python3 -I nix/mutants-scopes.py ROOT. Prints each failure and exits 1 if there is one,
and exits 2 when nix/mutants-scopes.toml or a Cargo.toml cannot be read. Its tests are
nix/mutants-scopes-tests.py.
"""

import pathlib
import re
import sys
import tomllib

SCOPES = "nix/mutants-scopes.toml"
TIERS = ("unit", "tokens")
SCOPE_KEYS = {"package", "files", "re", "name"}
FN = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
# `impl Type`, `impl<T> Type<T>`, `impl Trait for Type`: the type is the last path segment
# before the generics or the opening brace.
IMPL = re.compile(r"(?m)^\s*(?:unsafe\s+)?impl\b(?:\s*<[^{]*?>)?\s+(?:[^{]*?\bfor\s+)?(?:[\w:]+::)?([A-Za-z_]\w*)")


class Bad(Exception):
    """Input that the check cannot read: exit 2."""


def glob_regex(pattern):
    """A path pattern as a regular expression: `**/` is any number of directories, `*` any part
    of one name, `?` one character of a name."""
    out, i = [], 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out) + r"\Z")


def read_toml(path):
    try:
        return tomllib.loads(path.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Bad(f"{path}: {e}") from None


def crates(root):
    """The workspace members: package name -> the member's directory, relative to ROOT."""
    members = read_toml(root / "Cargo.toml").get("workspace", {}).get("members", [])
    out = {}
    for member in members:
        name = read_toml(root / member / "Cargo.toml").get("package", {}).get("name")
        if not name:
            raise Bad(f"{member}/Cargo.toml: no package name")
        out[name] = member.rstrip("/")
    return out


def sources(root, members):
    """Every `.rs` file under each member's `src` directory, relative to ROOT."""
    return sorted(p.relative_to(root).as_posix() for d in members.values() for p in (root / d / "src").rglob("*.rs"))


def without_tests(text):
    """The source text with each `#[cfg(test)]` item removed, from the attribute to the closing
    brace that matches the item's first opening brace, or to the first `;` of an item that has no
    body. An item inside a module removes only that item, so the functions after it stay."""
    out, i = [], 0
    while (j := text.find("#[cfg(test)]", i)) != -1:
        out.append(text[i:j])
        brace, semi = text.find("{", j), text.find(";", j)
        if brace == -1 or (semi != -1 and semi < brace):
            i = len(text) if semi == -1 else semi + 1
            continue
        depth, k = 0, brace
        for k in range(brace, len(text)):
            depth += {"{": 1, "}": -1}.get(text[k], 0)
            if depth == 0:
                break
        i = k + 1
    out.append(text[i:])
    return "".join(out)


def functions(root, files):
    """The names that a part of `re` may match in these files: each `fn` name and each `Type::`
    of an `impl` block, with every `#[cfg(test)]` item removed."""
    names = set()
    for f in files:
        text = without_tests((root / f).read_text(encoding="utf-8"))
        names |= set(FN.findall(text))
        names |= {f"{t}::" for t in IMPL.findall(text)}
    return names


def alternatives(regex):
    """The parts of a regular expression between the `|` signs that no group encloses."""
    parts, depth, start = [], 0, 0
    for i, c in enumerate(regex):
        if c == "(" and (i == 0 or regex[i - 1] != "\\"):
            depth += 1
        elif c == ")" and (i == 0 or regex[i - 1] != "\\"):
            depth -= 1
        elif c == "|" and depth == 0:
            parts.append(regex[start:i])
            start = i + 1
    return parts + [regex[start:]]


def check(root):
    """The failures, one line each."""
    data = read_toml(root / SCOPES)
    unknown = set(data) - {*TIERS, "left-out"}
    if unknown:
        raise Bad(f"{SCOPES}: unknown tables {sorted(unknown)}; the tiers are {list(TIERS)}, and `left-out`")
    members = crates(root)
    files = sources(root, members)
    failures = []
    # Each source file -> the scopes and left-out entries that take it.
    taken = {f: [] for f in files}

    for tier in TIERS:
        for i, scope in enumerate(data.get(tier, [])):
            label = f"[[{tier}]] {scope.get('name') or scope.get('package')}"
            if set(scope) - SCOPE_KEYS or not isinstance(scope.get("files"), list):
                raise Bad(f"{SCOPES}: {tier} scope {i + 1}: needs `package` and `files`, and may have `re` and `name` only")
            package = scope.get("package")
            if package not in members:
                failures.append(f"{label}: {package!r} is not a workspace crate (Cargo.toml, workspace.members)")
                continue
            matched = set()
            for pattern in scope["files"]:
                if not pattern.startswith(members[package] + "/"):
                    failures.append(f"{label}: {pattern} is not a file of {package} ({members[package]})")
                    continue
                hits = [f for f in files if glob_regex(pattern).match(f)]
                if not hits:
                    failures.append(f"{label}: {pattern} matches no source file (renamed or deleted?)")
                matched.update(hits)
            for f in matched:
                taken[f].append(label)
            if "re" in scope:
                names = functions(root, sorted(matched))
                for part in alternatives(scope["re"]):
                    if not any(re.search(part, n) for n in names):
                        failures.append(f"{label}: re part {part!r} matches no function in {sorted(matched)} (renamed or moved?)")

    for pattern, why in data.get("left-out", {}).items():
        if not isinstance(why, str) or not why.strip():
            failures.append(f'[left-out] "{pattern}": needs a reason')
        hits = [f for f in files if glob_regex(pattern).match(f)]
        if not hits:
            failures.append(f'[left-out] "{pattern}" matches no source file (renamed or deleted?)')
        for f in hits:
            taken[f].append("[left-out]")

    for f, by in taken.items():
        if not by:
            failures.append(f"{f}: in no scope of a tier and not left out: add it to a scope, or to [left-out] with the reason")
        elif len(by) > 1:
            failures.append(f"{f}: taken more than once, by {', '.join(by)}")
    return failures, len(files)


def main():
    if len(sys.argv) != 2:
        print("usage: python3 -I nix/mutants-scopes.py ROOT", file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1])
    try:
        failures, count = check(root)
    except Bad as e:
        print(f"mutants-scopes: {e}", file=sys.stderr)
        return 2
    for line in failures:
        print(f"mutants-scopes: {line}")
    if failures:
        print(f"mutants-scopes: {len(failures)} failures ({SCOPES})")
        return 1
    print(f"mutants-scopes: each of the {count} source files is in one scope or left out")
    return 0


if __name__ == "__main__":
    sys.exit(main())
