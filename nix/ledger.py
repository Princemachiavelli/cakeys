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
- the code on its path (`code`: globs from the root, `@name` for a `[groups]` list) changed
  since the run, unless `[artifact.acknowledged]` names that code's hash with who, why and what
  still needs a run on the hardware. An acknowledgement of other code fails as well, and so
  does one beside code that is the run's again;
- a module profile under profiles/modules/ has no entry, or a path or glob names no file, or a
  table has a key this script does not read;
- a regeneration probes other RSA sizes than the rest (review 2026-11-24 E-8): each file in
  `[regen] sources` must pass `--rsa-max-bits` with `[regen] rsa-max-bits` and no other value,
  and an artifact's `regen` may name no other value and no file that is not there.

The hashes are of the files in the tree, not git's: the Nix sandbox has no .git. A failure
prints the hash to record.

Usage: python3 -I ledger.py ROOT. Prints each artifact's state and every failure; exits 1 on a
failure.
"""

import hashlib
import pathlib
import re
import sys
import tomllib

LEDGER = "profiles/LEDGER.toml"
# The size flag with its value, as a shell line or a Rust argument list writes it.
RSA_FLAG = re.compile(r"--rsa-max-bits[\"',\s]*(\d+)")
# A repository path in a `regen` command.
REPO_PATH = re.compile(r"\b(?:crates|examples|nix|profiles|scripts)/[\w.+/-]*\w")

# The keys each table may have: a near miss (`acknowledgement`) fails rather than being ignored.
KEYS = {
    "ledger": {"regen", "groups", "artifact"},
    "regen": {"rsa-max-bits", "sources"},
    "artifact": {"path", "from", "regen", "verified-by", "code", "hash", "probed", "hand-edits", "acknowledged"},
    "probed": {"by", "date", "hash", "code-hash"},
    "hand-edits": {"by", "what"},
    "acknowledged": {"code-hash", "by", "why", "reprobe"},
}


def file_hash(path):
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def code_files(root, patterns, groups):
    """The files `patterns` name under `root`, and the patterns that name none."""
    files, empty = set(), []
    for pattern in patterns:
        if pattern.startswith("@") and pattern[1:] not in groups:
            empty.append(f"{pattern} (no such group)")
            continue
        for glob in groups[pattern[1:]] if pattern.startswith("@") else [pattern]:
            found = {p for p in root.glob(glob) if p.is_file()}
            if not found:
                empty.append(glob)
            files |= found
    return sorted(files), empty


def code_hash(root, files):
    """One hash over each file's path and content: a file added, removed, renamed or changed
    changes it."""
    h = hashlib.sha256()
    for f in files:
        h.update(f"{f.relative_to(root).as_posix()}\0{file_hash(f)}\n".encode())
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
    files, empty = code_files(root, a.get("code", []), groups)
    for glob in empty:
        misses.append(f"{where}: code glob {glob} names no file")
    if not a.get("code"):
        if "code-hash" in probed or ack:
            misses.append(f"{where}: no code on its path, so no code-hash and no [artifact.acknowledged]")
        report.append(f"captured  {path}: {state}")
        return
    code = code_hash(root, files)
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
