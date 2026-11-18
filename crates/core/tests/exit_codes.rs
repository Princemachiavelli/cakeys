//! What the docs say an error exits with is what it exits with: `read_lock`'s doc said 18 for
//! the 14 it returns (review D2). Every `` `Variant` (NN) `` in the workspace's sources names a
//! `KmError` variant and the code [`KmError::exit_code`] gives it.

use cakeys_core::KmError;
use std::path::{Path, PathBuf};

fn code_of(variant: &str) -> Option<u8> {
    let s = String::new;
    let e = match variant {
        "HashMismatch" => KmError::HashMismatch { what: s(), expected: s(), got: s() },
        "FirstUse" => KmError::FirstUse { what: s(), got: s() },
        "NotFound" => KmError::NotFound("".into()),
        "Ambiguous" => KmError::Ambiguous("".into()),
        "Conflict" => KmError::Conflict("".into()),
        "PreconditionFailed" => KmError::PreconditionFailed("".into()),
        "Unsupported" => KmError::Unsupported("".into()),
        "Unavailable" => KmError::Unavailable("".into()),
        "Validation" => KmError::Validation("".into()),
        "Exists" => KmError::Exists("".into()),
        "ObjectsFailed" => KmError::ObjectsFailed("".into()),
        "Io" => KmError::Io("".into()),
        _ => return None,
    };
    Some(e.exit_code())
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
