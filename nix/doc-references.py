"""What the documentation cites must exist (checks.doc-references).

- A test or function the docs name in backticks (`a_name_of_four_or_more_words`, a path's last
  segment, `()` allowed) is a `fn` of that name somewhere in the Rust sources. A rename that
  leaves the docs naming the old test fails here.
- A `docs/*.md` file or a Rust source (`crates/…/*.rs`, `fuzz/fuzz_targets/*.rs`) cited anywhere
  (docs, Rust sources, scripts, Nix) exists.
- A relative Markdown link in a document resolves to a file.

A name or file that is not ours (another project's option or path, a file named as gone) is
listed below with what it is, so a new one is decided, not silently passed.

Usage: python3 doc-references.py ROOT. Prints every miss and exits 1 if there is one.
"""

import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])

# Names of other software the docs quote.
FOREIGN_NAMES = {
    "enable_ecdsa_with_weak_hash": "an AWS CloudHSM client option",
    "experimental_create_multiple_versions": "a Google kmsp11 option",
    "disable_key_availability_check": "an AWS CloudHSM client option",
    "tee_otp_get_hw_unique_key": "an OP-TEE platform hook",
    "plat_get_rotpk_info": "a Trusted Firmware-A platform hook",
}
# (citing file, cited path): files that are not this repository's, or are cited as gone.
FOREIGN_PATHS = {
    ("docs/OPEN.md", "docs/PROVIDERS.md"): "a plan named as kept only in git history",
    ("docs/PLAN.md", "docs/rv-trace-design.md"): "pkcs11-check's design note, in its repository",
}

# The documents held to their citations: the current docs, not archived reviews or reports.
docs = sorted(
    [p for p in (root / "docs").glob("*.md")] + [root / "ISSUES.md", root / "README.md"]
)
rust = sorted(p for d in ("crates", "fuzz") for p in (root / d).rglob("*.rs"))
cites = docs + rust + sorted(
    p
    for p in [*(root / "nix").rglob("*"), *(root / "scripts").rglob("*"), *root.glob("*.nix")]
    if p.is_file() and p.suffix in (".nix", ".sh", ".py", "") and p.name != "doc-references.py"
)

fns = set()
for p in rust:
    fns.update(re.findall(r"\bfn\s+([a-z_][a-z0-9_]*)", p.read_text(errors="replace")))

misses = []
name = re.compile(r"`(?:[A-Za-z0-9_]+::)*([a-z][a-z0-9]*(?:_[a-z0-9]+){3,})(?:\(\))?`")
# Not part of a URL or of another path.
doc_path = re.compile(r"(?<![\w/.-])docs/[A-Za-z0-9_./-]+?\.md\b")
link = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
# A Rust source: `crates/core/src/config/mod.rs`, `core/src/config/lock.rs` (under crates/),
# `fuzz/fuzz_targets/lock.rs`. A split or a rename that leaves the citation behind fails here.
source_path = re.compile(r"(?<![\w/.-])((?:crates/)?[a-z0-9_-]+/(?:src|tests|fuzz_targets)/[A-Za-z0-9_./-]*?\.rs)\b")

for p in docs:
    text = p.read_text()
    rel = p.relative_to(root)
    for n, line in enumerate(text.splitlines(), 1):
        for m in name.finditer(line):
            if m.group(1) not in fns and m.group(1) not in FOREIGN_NAMES:
                misses.append(f"{rel}:{n}: `{m.group(1)}` is no fn in crates/ or fuzz/")
        for m in link.finditer(line):
            target = m.group(1)
            if "://" in target or target.startswith("mailto:"):
                continue
            if not (p.parent / target).exists():
                misses.append(f"{rel}:{n}: link to {target}, which does not exist")

for p in cites:
    rel = p.relative_to(root)
    for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
        for m in doc_path.finditer(line):
            if not (root / m.group(0)).exists() and (str(rel), m.group(0)) not in FOREIGN_PATHS:
                misses.append(f"{rel}:{n}: cites {m.group(0)}, which does not exist")
        for m in source_path.finditer(line):
            cited = m.group(1)
            if not any((root / base / cited).exists() for base in (".", "crates")):
                misses.append(f"{rel}:{n}: cites {cited}, which does not exist")

for m in misses:
    print(m)
sys.exit(1 if misses else 0)
