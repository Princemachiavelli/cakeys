"""What the documentation cites must exist (checks.doc-references).

- A name cited in backticks (`()` or a macro's `!` allowed after it) is in the index below:
  - in the docs, a snake name of four or more words (a test or function) is a `fn`;
  - in a Rust comment (a line that starts with `//`, `///` or `//!`), a snake name with an `_`,
    of any length, is in the index;
  - in both, each segment of a path `A::b(::c)*` is, unless the path starts at another crate.
  A rename that leaves a doc or a comment naming the old item fails here.
- A `docs/*.md` file or a Rust source (`crates/…/*.rs`, `fuzz/fuzz_targets/*.rs`) cited anywhere
  (docs, Rust sources, scripts, Nix) exists.
- A relative Markdown link in a document resolves to a file.

The index is a regex reading of the Rust sources' code (comments and strings left out), not a
parser. It holds what the code defines: an item (`fn`, `struct`, `enum`, `trait`, `type`,
`const`, `static`, `mod`, `union`, `macro_rules!`), a field, a variant, a function's parameter,
a source file or crate (a module), and a shell function of nix/ and scripts/. And what the code
uses as only an item can be used: a name after `.` or `::`, before `::` or `!`, in a `use` or an
attribute, or not snake case (Rust's lints keep locals snake case). The code compiles, so a name
it uses and does not define is std's, a dependency's or cryptoki's: none of those is listed.

A path from another crate (`std`, `core`, `alloc`, or a dependency a Cargo.toml names) is that
crate's, and PKCS#11's names (`CKA_ID`, `C_Login`) are not snake case. What is left, a name of
software the code never names (a tool, a C function, an option), is listed below with what it
is, so a new one is decided, not silently passed. An entry no citation needs fails, so the lists
hold only what is cited.

Usage: python3 doc-references.py ROOT. Prints every miss and exits 1 if there is one. Its tests
are nix/doc-references-test.py.
"""

import pathlib
import re
import sys
import tomllib

# Names of other software the docs and comments quote, which no code here names.
FOREIGN_NAMES = {
    "aes256_gcm_decrypt": "a tpm2-pkcs11 C function (utils.c)",
    "db_for_path": "a tpm2-pkcs11 C function (db.c)",
    "db_init_new": "a tpm2-pkcs11 C function (db.c)",
    "disable_key_availability_check": "an AWS CloudHSM client option",
    "enable_ecdsa_with_weak_hash": "an AWS CloudHSM client option",
    "experimental_create_multiple_versions": "a Google kmsp11 option",
    "finalize_fixed_core": "a method of RustCrypto digest's FixedOutputCore",
    "plat_get_rotpk_info": "a Trusted Firmware-A platform hook",
    "pvtkey_objects": "a ykcs11 C table (yubico-piv-tool, ykcs11/objects.c)",
    "set_esys_auth": "a tpm2-pkcs11 C function (tpm.c)",
    "ssl_util_hash_pass": "a tpm2-pkcs11 C function (utils.c)",
    "sun_path": "the path field of POSIX's sockaddr_un",
    "tee_otp_get_hw_unique_key": "an OP-TEE platform hook",
    "token_generate_key": "a ykcs11 C function (yubico-piv-tool, ykcs11/token.c)",
    "backend_token_unseal_wrapping_key": "tpm2-pkcs11's login unseal (backend.c)",
    "tpm2_import": "a tpm2-tools command, which tpm2_ptool runs",
    "tpm2_ptool": "tpm2-pkcs11's key and token tool",
    "yubihsm_pkcs11": "the YubiHSM 2 PKCS#11 module",
}
# (citing file, name): a name a history cites as gone.
GONE_NAMES = {
    ("ISSUES.md", "names_agree"): "the 2026-11-17 test; the entry says every_variant_has_its_value replaced it",
    ("ISSUES.md", "spki_curve"): "the dispatcher the entry says KeyAlg::of_spki replaced",
}
# Names of ours cited after they went, until the citation is fixed: name, what it became. It only
# shrinks (nix/doc-references-test.py), and an entry that resolves or that nothing cites fails.
KNOWN_STALE = {}
# (citing file, cited path): files that are not this repository's, or are cited as gone.
FOREIGN_PATHS = {
    ("docs/OPEN.md", "docs/PROVIDERS.md"): "a plan named as kept only in git history",
    ("docs/OPEN.md", "docs/VENDOR.md"): "the tpm2-pkcs11 fork's interface document, in its repository",
    ("docs/PLAN.md", "docs/rv-trace-design.md"): "pkcs11-check's design note, in its repository",
}

# Comments, strings and character literals: what the index does not read.
NOT_CODE = re.compile(
    r"""//[^\n]*|/\*.*?\*/|(?:b|c)?r(?P<h>\#*)".*?"(?P=h)|(?:b|c)?"(?:[^"\\]|\\.)*"|'(?:\\.|[^\\'\n])'""",
    re.S | re.X,
)
TOKEN = re.compile(r"[A-Za-z_]\w*|\d\w*|::|\S")
ITEM = {"fn", "struct", "enum", "trait", "type", "const", "static", "mod", "union"}
SNAKE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
# A path's segment that names no item.
PATH_KEYWORDS = {"crate", "self", "super", "Self"}

# A backticked name or path.
NAME = re.compile(r"`((?:[A-Za-z_]\w*::)*[A-Za-z_]\w*)(?:\(\)|!)?`")
DOC_TEST = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+){3,}")
# Not part of a URL or of another path.
DOC_PATH = re.compile(r"(?<![\w/.-])docs/[A-Za-z0-9_./-]+?\.md\b")
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
# A Rust source: `crates/core/src/config/mod.rs`, `core/src/config/lock.rs` (under crates/),
# `fuzz/fuzz_targets/lock.rs`. A split or a rename that leaves the citation behind fails here.
SOURCE_PATH = re.compile(r"(?<![\w/.-])((?:crates/)?[a-z0-9_-]+/(?:src|tests|fuzz_targets)/[A-Za-z0-9_./-]*?\.rs)\b")


def rust_sources(root):
    return sorted(p for d in ("crates", "fuzz") for p in (root / d).rglob("*.rs") if "target" not in p.parts)


def scan(code, names, fns):
    """Adds what one source's code (comments and strings removed) defines or uses as an item to
    `names`, and its functions to `fns`."""
    toks = TOKEN.findall(code)
    bodies = []  # the struct, enum and union bodies open: (keyword, brace depth)
    braces = parens = brackets = 0
    pending = None  # the keyword of a struct, enum or union whose body may come next
    signature = None  # the paren depth of the parameters of the fn being read
    attribute = None  # the bracket depth of the attribute being read
    use = False
    for i, t in enumerate(toks):
        prev = toks[i - 1] if i > 0 else ""
        prev2 = toks[i - 2] if i > 1 else ""
        nxt = toks[i + 1] if i + 1 < len(toks) else ""
        nxt2 = toks[i + 2] if i + 2 < len(toks) else ""
        if t == "{":
            braces += 1
            if pending:
                bodies.append((pending, braces))
            pending = signature = None
        elif t == "}":
            if bodies and bodies[-1][1] == braces:
                bodies.pop()
            braces -= 1
        elif t == "(":
            parens += 1
        elif t == ")":
            parens -= 1
            if signature is not None and parens < signature:
                signature = None
        elif t == "[":
            brackets += 1
            if prev == "#" or (prev == "!" and prev2 == "#"):
                attribute = brackets
        elif t == "]":
            if attribute == brackets:
                attribute = None
            brackets -= 1
        elif t == ";":
            pending = signature = None
            use = False
        if not (t[0].isalpha() or t[0] == "_"):
            continue
        use = use or t == "use"
        defined = (
            (prev in ITEM and prev2 != "'")
            or (prev == "!" and prev2 == "macro_rules")
            or (signature is not None and parens == signature and nxt == ":")
            or (bodies and nxt == ":" and braces >= bodies[-1][1])
            or (bodies and bodies[-1] == ("enum", braces) and parens == 0 and prev in ("{", ",", "]"))
        )
        used = (
            use
            or attribute is not None
            or (prev == "." and prev2 != ".")
            or "::" in (prev, nxt)
            or (nxt == "!" and nxt2 != "=")
            or not SNAKE.fullmatch(t)
        )
        if defined or used:
            names.add(t)
        if prev == "fn":
            fns.add(t)
            signature = parens + 1
        if prev in ("struct", "enum", "union"):
            pending = prev


def crates(root):
    """(ours, others): the workspace's crates, and every other crate a Cargo.toml depends on
    with std's, as code spells them."""
    ours, deps = set(), set()
    for m in [root / "Cargo.toml", *(root / "crates").glob("*/Cargo.toml"), root / "fuzz/Cargo.toml"]:
        if not m.exists():
            continue
        t = tomllib.loads(m.read_text())
        ours |= {t.get("package", {}).get("name", ""), t.get("lib", {}).get("name", "")}
        for table in [t, t.get("workspace", {}), *t.get("target", {}).values()]:
            for kind in ("dependencies", "dev-dependencies", "build-dependencies"):
                deps.update(table.get(kind, {}))
    ours = {c.replace("-", "_") for c in ours if c}
    return ours, ({d.replace("-", "_") for d in deps} - ours) | {"std", "core", "alloc", "proc_macro"}


def index(root):
    """(names, fns, other crates): what the Rust sources define or use as an item, their
    functions, and the crates not ours that a path may start at."""
    names, fns = set(), set()
    for p in rust_sources(root):
        scan(NOT_CODE.sub(" ", p.read_text(errors="replace")), names, fns)
        if p.stem in ("mod", "main"):
            names.add(p.parent.name)
        elif p.stem != "lib":
            names.add(p.stem)
    ours, others = crates(root)
    names |= ours | {d.name.replace("-", "_") for d in (root / "crates").glob("*") if d.is_dir()}
    for p in [*(root / "nix").rglob("*.sh"), *(root / "scripts").rglob("*.sh")]:
        names.update(re.findall(r"(?m)^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{", p.read_text()))
    return names, fns, others


def check(root, foreign_names=FOREIGN_NAMES, gone_names=GONE_NAMES, known_stale=KNOWN_STALE, foreign_paths=FOREIGN_PATHS):
    """Every miss under ROOT, one `file:line: what` each."""
    names, fns, others = index(root)
    # The documents held to their citations: the current docs, not archived reviews or reports.
    docs = sorted(p for p in [*(root / "docs").glob("*.md"), root / "ISSUES.md", root / "README.md"] if p.exists())
    rust = rust_sources(root)
    # Not this script, nor a script's tests: their fixtures cite the trees they write.
    cites = (
        docs
        + rust
        + sorted(
            p
            for p in [*(root / "nix").rglob("*"), *(root / "scripts").rglob("*"), *root.glob("*.nix")]
            if p.is_file()
            and p.suffix in (".nix", ".sh", ".py", "")
            and p.name != "doc-references.py"
            and not p.name.endswith(("-test.py", "-tests.py"))
        )
    )
    misses, needed = [], set()

    def resolves(rel, name, known):
        if name in known:
            return True
        for key, listed in [(name, foreign_names), ((str(rel), name), gone_names), (name, known_stale)]:
            if key in listed:
                needed.add(key)
                return True
        return False

    def names_in(rel, n, line, comment):
        for m in NAME.finditer(line):
            cited = m.group(1)
            segments = cited.split("::")
            if len(segments) > 1:
                if segments[0] in others:
                    continue
                for s in segments:
                    if s not in PATH_KEYWORDS and not resolves(rel, s, names):
                        misses.append(f"{rel}:{n}: `{cited}`: `{s}` is named nowhere in crates/ or fuzz/")
            elif comment and "_" in cited and SNAKE.fullmatch(cited):
                if not resolves(rel, cited, names):
                    misses.append(f"{rel}:{n}: `{cited}` is named nowhere in crates/ or fuzz/")
            elif not comment and DOC_TEST.fullmatch(cited) and not resolves(rel, cited, fns):
                misses.append(f"{rel}:{n}: `{cited}` is no fn in crates/ or fuzz/")

    for p in docs:
        rel = p.relative_to(root)
        for n, line in enumerate(p.read_text().splitlines(), 1):
            names_in(rel, n, line, comment=False)
            for m in LINK.finditer(line):
                target = m.group(1)
                if "://" in target or target.startswith("mailto:"):
                    continue
                if not (p.parent / target).exists():
                    misses.append(f"{rel}:{n}: link to {target}, which does not exist")

    for p in rust:
        rel = p.relative_to(root)
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            if line.lstrip().startswith("//"):
                names_in(rel, n, line, comment=True)

    for p in cites:
        rel = p.relative_to(root)
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            for m in DOC_PATH.finditer(line):
                key = (str(rel), m.group(0))
                if (root / m.group(0)).exists():
                    continue
                if key in foreign_paths:
                    needed.add(key)
                else:
                    misses.append(f"{rel}:{n}: cites {m.group(0)}, which does not exist")
            for m in SOURCE_PATH.finditer(line):
                cited = m.group(1)
                if not any((root / base / cited).exists() for base in (".", "crates")):
                    misses.append(f"{rel}:{n}: cites {cited}, which does not exist")

    for listed, what in [(foreign_names, "FOREIGN_NAMES"), (gone_names, "GONE_NAMES"), (foreign_paths, "FOREIGN_PATHS")]:
        misses += [f"doc-references.py: {what} lists {key}, which no citation needs" for key in sorted(listed) if key not in needed]
    for name in sorted(known_stale):
        if name in names:
            misses.append(f"doc-references.py: KNOWN_STALE lists {name}, which resolves now: remove it")
        elif name not in needed:
            misses.append(f"doc-references.py: KNOWN_STALE lists {name}, which nothing cites now: remove it")
    return misses


if __name__ == "__main__":
    found = check(pathlib.Path(sys.argv[1]))
    for m in found:
        print(m)
    sys.exit(1 if found else 0)
