"""A universal claim of the docs names the test that holds it (checks.claims; docs/claims.toml).

A line of the documents that say what the tools guarantee (DOCUMENTS) is a claim when it speaks
for every case (every, never, always, the one way, the only way, no other, nothing can or may)
about a security subject (plaintext, a PIN, a secret or private key, overwriting, deleting or
destroying, identity, attestation, the lock, a refusal, what is left, extracted or written, a
bundle, a transport key, a slot, the scratch slot). Fenced code is not read. Each claim is
either

- registered in the register: an entry whose `says`, a phrase found once in its `doc`
  (whitespace and line breaks aside), is on the claim's line, with
  - `kind = "enforced"` and `tests`, each a `fn` in crates/ or fuzz/ (nix/doc-references.py's
    index) or a check of checks.nix as `checks.<name>` (a NixOS or Nix test), and optionally
    the entry `paths` those tests cover; or
  - `kind = "descriptive"` and `why` it is no guarantee a test can hold;
- or unregistered, and counted against the register's `max-unregistered`. More fails, and so
  does fewer, until the register is lowered to the count: the number moves only in a diff a
  reviewer sees, and nix/claims-test.py keeps it at or below its seed.

An entry may register a claim the words miss (DESIGN.md §8.1's bullets). A claim is softened in
its document: the line stops matching, or its entry becomes descriptive.

DESIGN.md §8.1, "Enforced (with tests)", is held to its heading (ENFORCED): each of its bullets
names in backticks a test that holds it, a `fn` marked `#[test]` (or a runtime's
`#[tokio::test]`) in crates/ or fuzz/, or a check of checks.nix as `checks.<name>` (a NixOS
test). A bullet no test holds goes to §8.2, the known gaps.

Usage: python3 -I nix/claims.py ROOT [--list]. --list prints the unregistered claims. Exits 1
on a failure. Its tests are nix/claims-test.py.
"""

import importlib.util
import pathlib
import re
import sys
import tomllib

REGISTER = "docs/claims.toml"
# The documents that say what the tools guarantee.
DOCUMENTS = ["docs/CAKEYS.md", "docs/CAMIGRATE.md", "docs/CAPROBE.md", "docs/DESIGN.md"]
UNIVERSAL = re.compile(r"\b(?:every\w*|never|always|the one way|only way|no other|nothing (?:can|may))\b", re.I)
SUBJECT = re.compile(
    r"plaintext|\bPINs?\b|secret|private|overwrit|delete|destroy|identit|attest|\block|refus|in (?:the )?clear"
    r"|\bleav|extract|bundle|transport|\bslot|scratch|\bwrit",
    re.I,
)
# The section held to its heading: (document, heading), each bullet naming a test.
ENFORCED = ("docs/DESIGN.md", "### 8.1 Enforced (with tests)")
# A test: a fn whose attributes include `#[test]` or a runtime's `#[tokio::test]`.
TEST = re.compile(
    r"#\s*\[\s*(?:\w+\s*::\s*)?test\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*"
    r"(?:pub(?:\s*\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)"
)
NAMED = re.compile(r"`([A-Za-z_]\w*)(?:\(\))?`")
# The flake's checks, and a bullet's name of one.
CHECKS = "checks.nix"
CHECK = re.compile(r"(?m)^  (?:([A-Za-z][\w-]*) =|inherit (?:\([^)]*\) )?([\w\s-]+);)")
NAMED_CHECK = re.compile(r"`checks\.([A-Za-z][\w-]*)`")
# What each kind of entry needs, and may have.
KINDS = {"enforced": ({"tests"}, {"paths"}), "descriptive": ({"why"}, set())}
COMMON = {"doc", "says", "kind"}

# Read-only in the Nix sandbox, and no file to leave in a checkout.
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("doc_references", pathlib.Path(__file__).with_name("doc-references.py"))
doc_references = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(doc_references)


def claims(text):
    """The numbers of the lines of a document that are claims, with their text."""
    out, fenced = [], False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        elif not fenced and UNIVERSAL.search(line) and SUBJECT.search(line):
            out.append((n, line.strip()))
    return out


def tests(root):
    """The names of the tests in crates/ and fuzz/ (TEST)."""
    return {
        name
        for p in doc_references.rust_sources(root)
        for name in TEST.findall(doc_references.NOT_CODE.sub(" ", p.read_text(errors="replace")))
    }


def checks(root):
    """The names of the checks checks.nix defines or inherits, at its top level."""
    try:
        text = (root / CHECKS).read_text()
    except OSError:
        return set()
    return {name for one, many in CHECK.findall(text) for name in ([one] if one else many.split())}


def bullets(text, heading):
    """The bullets of the section under `heading`, each (its first line, its text joined), or
    None without the heading. Fenced code is not read."""
    out, fenced = None, False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
        elif fenced:
            continue
        elif line.startswith("#"):
            if out is not None:
                break
            if line.strip() == heading:
                out = []
        elif out is not None and line.startswith(("- ", "* ")):
            out.append((n, line[2:].strip()))
        elif out and line.startswith(" ") and line.strip():
            out[-1] = (out[-1][0], f"{out[-1][1]} {line.strip()}")
    return out


def unheld(root, text):
    """ENFORCED's failures in its document's `text`: each bullet that names no test."""
    doc, heading = ENFORCED
    found = bullets(text, heading)
    if not found:
        return [f"{doc} has no bullets under {heading!r}: claims.py's ENFORCED names it"]
    known, nixos = tests(root), checks(root)
    return [
        f"{doc}:{n}: a bullet of {heading!r} names no test in backticks (a `#[test]` fn, or `checks.<name>`): "
        f"name the one that holds it, or move it to the known gaps ({bullet[:60]}…)"
        for n, bullet in found
        if not any(name in known for name in NAMED.findall(bullet))
        and not any(name in nixos for name in NAMED_CHECK.findall(bullet))
    ]


def check(root):
    """(failures, unregistered claims, registered entries)."""
    failures = []
    try:
        register = tomllib.loads((root / REGISTER).read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        return [f"{REGISTER}: {e}"], [], 0
    fns = doc_references.index(root)[1] | {f"checks.{name}" for name in checks(root)}
    texts = {}
    registered = set()  # (doc, line)
    entries = register.get("claim", [])
    for i, entry in enumerate(entries, 1):
        where = f"{REGISTER}: claim {i} ({entry.get('says', '?')!r})"
        kind = entry.get("kind")
        if kind not in KINDS:
            failures.append(f"{where}: kind is {kind!r}, not one of {', '.join(sorted(KINDS))}")
            continue
        needs, may = KINDS[kind]
        if missing := sorted((COMMON | needs) - {k for k, v in entry.items() if v}):
            failures.append(f'{where}: kind "{kind}" needs {", ".join(missing)}')
            continue
        if extra := sorted(set(entry) - COMMON - needs - may):
            failures.append(f'{where}: kind "{kind}" takes no {", ".join(extra)}')
        if not all(isinstance(t, str) for t in entry.get("tests", [])) or isinstance(entry.get("tests"), str):
            failures.append(f"{where}: tests is a list of fn names")
            continue
        doc = entry["doc"]
        if doc not in texts:
            try:
                texts[doc] = (root / doc).read_text()
            except OSError:
                failures.append(f"{where}: {doc} does not exist")
                continue
        phrase = re.compile(r"\s+".join(map(re.escape, entry["says"].split())))
        found = list(phrase.finditer(texts[doc]))
        if len(found) != 1:
            failures.append(f"{where}: found {len(found)} times in {doc}, not once")
            continue
        first = texts[doc].count("\n", 0, found[0].start()) + 1
        last = texts[doc].count("\n", 0, found[0].end()) + 1
        lines = {(doc, n) for n in range(first, last + 1)}
        if lines & registered:
            failures.append(f"{where}: {doc}:{first} is registered already")
        registered |= lines
        for test in entry.get("tests", []):
            if test not in fns:
                failures.append(f"{where}: `{test}` is no fn in crates/ or fuzz/, nor a check of {CHECKS}")

    unregistered = []
    for doc in DOCUMENTS:
        try:
            text = texts.get(doc) or (root / doc).read_text()
        except OSError:
            failures.append(f"{doc} does not exist: claims.py's DOCUMENTS names it")
            continue
        unregistered += [f"{doc}:{n}: {line}" for n, line in claims(text) if (doc, n) not in registered]
        if doc == ENFORCED[0]:
            failures += unheld(root, text)
    most = register.get("max-unregistered")
    if not isinstance(most, int) or isinstance(most, bool) or most < 0:
        failures.append(f"{REGISTER}: max-unregistered is {most!r}, not a count")
    elif len(unregistered) > most:
        failures.append(
            f"{len(unregistered)} unregistered claims, more than max-unregistered ({most}): register the new one in "
            f"{REGISTER} with its tests, or soften it (--list names them all)"
        )
    elif len(unregistered) < most:
        failures.append(f"{len(unregistered)} unregistered claims: lower max-unregistered in {REGISTER} from {most} to {len(unregistered)}")
    return failures, unregistered, len(entries)


if __name__ == "__main__":
    root = pathlib.Path(sys.argv[1])
    failures, unregistered, entries = check(root)
    if "--list" in sys.argv[2:]:
        print("\n".join(unregistered))
    for f in failures:
        print(f"claims: {f}", file=sys.stderr)
    print(f"{entries} claims registered, {len(unregistered)} unregistered")
    sys.exit(1 if failures else 0)
