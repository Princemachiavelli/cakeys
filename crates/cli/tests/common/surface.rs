//! The command-line surface test, which the three tools share. It checks that an integration test
//! of the tool uses every verb and every flag that clap defines. It reads the test sources, so it
//! shows only that a test names the verb or flag, not what the test proves with it. It is a
//! minimum below the coverage report (docs/DEVELOPMENT.md), and it is cheap enough to run on every
//! build. Tests nearly always name every verb (`"lock"`, `"check"`), so the check matters mostly
//! for the flags. A flag that only one verb defines counts for that verb wherever a test spells
//! it. A flag that several verbs define is checked per verb, as `verb --flag`, and it counts as
//! used only where one function names both the verb and the flag (review 2026-11-23 D-23:
//! `supports --profiles` covered `probe --profiles`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Collects the verbs, their visible aliases and the long flags of `cmd` and its subcommands, as
/// a test would write them (`lock`, `check`, `--dry-run`), without clap's own (`help`, `--help`,
/// `--version`). A short flag (`-c`) is only another spelling of its long flag, which clap alone
/// parses, so it is not counted separately.
fn surface(cmd: &clap::Command, out: &mut BTreeSet<String>) {
    for arg in cmd.get_arguments() {
        if let Some(long) = arg.get_long().filter(|l| !matches!(*l, "help" | "version")) {
            out.insert(format!("--{long}"));
        }
    }
    for sub in cmd.get_subcommands().filter(|s| s.get_name() != "help") {
        out.insert(sub.get_name().to_owned());
        out.extend(sub.get_visible_aliases().map(str::to_owned));
        surface(sub, out);
    }
}

/// Returns each long flag that more than one of `cmd`'s verbs defines, with those verbs. A global
/// flag does not belong to any verb.
fn shared_flags(cmd: &clap::Command) -> BTreeMap<String, Vec<String>> {
    let global: BTreeSet<&str> = cmd.get_arguments().filter_map(clap::Arg::get_long).collect();
    let mut by_flag = BTreeMap::<String, Vec<String>>::new();
    for sub in cmd.get_subcommands().filter(|s| s.get_name() != "help") {
        let mut flags = BTreeSet::new();
        surface(sub, &mut flags);
        for flag in flags.into_iter().filter(|f| f.strip_prefix("--").is_some_and(|l| !global.contains(l))) {
            by_flag.entry(flag).or_default().push(sub.get_name().to_owned());
        }
    }
    by_flag.retain(|_, verbs| verbs.len() > 1);
    by_flag
}

/// Splits `text` at each `fn`, so that each piece holds one test or one helper. A test builds its
/// arguments from variables and helpers (`[&unlocked[..], &["--dry-run"]].concat()`,
/// `ask(&["--token", ..])`), so a verb and its flag count as one test's when one function names
/// both.
fn functions(text: &str) -> Vec<String> {
    let mut found = vec![String::new()];
    for line in text.lines() {
        let l = line.trim_start();
        if l.starts_with("fn ") || l.starts_with("pub fn ") {
            found.push(String::new());
        }
        let last = found.last_mut().unwrap();
        last.push_str(line);
        last.push('\n');
    }
    found
}

/// Concatenates every `.rs` file under `dir`, except the surface tests and the shared harness
/// (`common/`), without their comment lines. A flag that a comment quotes, or that a helper of
/// the shared harness spells, is not a flag that this tool's tests use.
fn sources(dir: &Path, out: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() && path.file_name().is_some_and(|n| n != "common") {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") && path.file_name().is_some_and(|n| n != "surface.rs") {
            let text = std::fs::read_to_string(&path).unwrap_or_default();
            for line in text.lines().filter(|l| !l.trim_start().starts_with("//")) {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
}

/// Fails when a verb or flag of `cmd` appears as a string literal in no integration test under
/// `tests` (this tool's `tests/`). The shared harness (cli/tests/common) does not count, because a
/// flag that the harness spells is not a test of any tool: cakeys' own `--module`, which the
/// harness spells, once counted as a test of caprobe's `--module` (review D9). `untested` lists
/// the verbs and flags that are knowingly left out, each with its reason. An entry that is tested
/// after all, or that clap no longer defines, also fails, so the list cannot become stale.
///
/// # Panics
///
/// Panics with the names that no test uses, or with the stale `untested` entries.
pub fn assert_covered(cmd: &clap::Command, tests: &Path, untested: &[(&str, &str)]) {
    let mut names = BTreeSet::new();
    surface(cmd, &mut names);
    let mut text = String::new();
    sources(tests, &mut text);
    // The name counts when it is an argument of its own (`"--dry-run"`), or the start of one
    // (`"--module={path}"`, `"--label kmtest"`).
    let spelled = |text: &str, name: &str| {
        [format!("\"{name}\""), format!("\"{name}="), format!("\"{name} ")].iter().any(|form| text.contains(form))
    };
    let functions = functions(&text);
    // A shared flag, `verb --flag`, counts only when one function names both.
    let used = |name: &str| match name.split_once(" --") {
        Some((verb, flag)) => {
            let flag = format!("--{flag}");
            functions.iter().any(|f| spelled(f, verb) && spelled(f, &flag))
        }
        None => spelled(&text, name),
    };
    for (flag, verbs) in shared_flags(cmd) {
        names.remove(&flag);
        names.extend(verbs.iter().map(|v| format!("{v} {flag}")));
    }
    let excused: BTreeSet<&str> = untested.iter().map(|(name, _)| *name).collect();
    let missing: Vec<&String> = names.iter().filter(|n| !used(n) && !excused.contains(n.as_str())).collect();
    assert!(missing.is_empty(), "no integration test of {} uses: {missing:?}", cmd.get_name());
    let stale: Vec<&&str> = excused.iter().filter(|n| !names.contains(**n) || used(n)).collect();
    assert!(stale.is_empty(), "listed as untested, but tested or gone from {}: {stale:?}", cmd.get_name());
}
