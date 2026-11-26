//! What the docs say an error exits with is what it exits with: `read_lock`'s doc said 18 for
//! the 14 it returns (review D2). Every `` `Variant` (NN) `` in the workspace's sources names a
//! `KmError` variant and the code [`KmError::exit_code`] gives it.

use cakeys_core::KmError;
use std::path::{Path, PathBuf};

fn code_of(variant: &str) -> Option<u8> {
    KmError::every_variant().into_iter().find(|(name, _)| *name == variant).map(|(_, e)| e.exit_code())
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn documented_exit_codes_are_the_ones_returned() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    for krate in std::fs::read_dir(crates).unwrap() {
        let src = krate.unwrap().path().join("src");
        if src.is_dir() {
            sources(&src, &mut files);
        }
    }
    let (mut checked, mut wrong) = (0, Vec::new());
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        for (n, line) in text.lines().enumerate() {
            let mut rest = line;
            while let Some(at) = rest.find('`') {
                rest = &rest[at + 1..];
                let Some(end) = rest.find('`') else { break };
                let (name, after) = (&rest[..end], &rest[end + 1..]);
                rest = after;
                let Some(code) = code_of(name) else { continue };
                let Some(digits) = after.strip_prefix(" (").and_then(|a| a.split_once(')')).map(|(d, _)| d) else {
                    continue;
                };
                let Ok(said) = digits.parse::<u8>() else { continue };
                checked += 1;
                if said != code {
                    wrong.push(format!("{}:{}: `{name}` ({said}), but it exits {code}", file.display(), n + 1));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(checked > 30, "only {checked} documented codes found: the scan no longer reads the docs");
}

/// `EXIT_CODES`, the table every `--help` renders, holds every code an error exits with, the
/// lock-written code, 0 and 2, and no other; docs/CAKEYS.md's exit-code table lists the same,
/// each under the table's name for it: its words up to the first `:`, all of them when it has
/// none, backticks aside (review 2026-11-24 C-13: rows 1, 17 and 21 said other words).
#[test]
fn the_exit_code_table_lists_every_code() {
    use std::collections::{BTreeMap, BTreeSet};
    let doc = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/CAKEYS.md");
    let doc = std::fs::read_to_string(&doc).unwrap_or_else(|e| panic!("{}: {e}", doc.display()));
    let rows: BTreeMap<u8, &str> = doc
        .lines()
        .filter_map(|l| {
            let (n, rest) = l.strip_prefix("| ")?.split_once(" |")?;
            Some((n.parse().ok()?, rest.split(" |").next()?.trim()))
        })
        .collect();
    let table: BTreeSet<u8> = rows.keys().copied().collect();
    let name = |means: &str| means.replace('`', "").split(':').next().unwrap_or_default().trim().to_owned();
    for (code, means) in cakeys_core::EXIT_CODES {
        let row = rows.get(&code).map_or_else(String::new, |r| name(r));
        assert_eq!(row, name(means), "docs/CAKEYS.md's exit {code} (left) is not EXIT_CODES' (right)");
    }
    let errors: Vec<u8> = KmError::every_variant().iter().map(|(_, e)| e.exit_code()).filter(|c| *c >= 10).collect();
    let mut codes: BTreeSet<u8> = errors.iter().copied().collect();
    assert_eq!(codes.len(), errors.len(), "two variants share a code");
    assert!(!codes.contains(&cakeys_core::LOCK_WRITTEN), "an error exits with the lock-written code");
    codes.extend([0, 1, 2, cakeys_core::LOCK_WRITTEN]);
    let listed: BTreeSet<u8> = cakeys_core::EXIT_CODES.iter().map(|(c, _)| *c).collect();
    assert_eq!(listed, codes, "EXIT_CODES (left) is not the codes the tools exit with (right)");
    assert_eq!(table, codes, "docs/CAKEYS.md's exit codes (left) are not the ones the tools exit with (right)");
}
