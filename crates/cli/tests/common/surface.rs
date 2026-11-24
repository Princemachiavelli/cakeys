//! The command-line surface test, shared by the three tools: every verb and every flag clap
//! defines is used by an integration test of that tool. It reads the test sources, so it says
//! that a test names the verb or flag, not what the test proves with it: a floor under the
//! coverage report (docs/DEVELOPMENT.md), cheap enough to run on every build. A verb is nearly
//! always named (`"lock"`, `"check"`); the flags are what it holds to a test. A flag one verb
//! defines is that verb's wherever a test spells it; a flag several verbs define is held per
//! verb, as `verb --flag`, used where one function names both (review 2026-11-23 D-23:
//! `supports --profiles` covered `probe --profiles`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The verbs, their visible aliases and the long flags of `cmd` and its subcommands, as a test
/// would write them (`lock`, `check`, `--dry-run`), less clap's own (`help`, `--help`,
/// `--version`). A short flag (`-c`) is its long flag's other spelling, parsed by clap alone: not
/// a surface of its own.
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

/// Each long flag that more than one of `cmd`'s verbs defines (a global flag is not a verb's),
/// with those verbs.
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

/// `text` cut at each `fn`: one test, or one helper, apiece. A test builds its arguments from
/// variables and helpers (`[&unlocked[..], &["--dry-run"]].concat()`, `ask(&["--token", ..])`),
/// so a verb and its flag are one test's when one function names both.
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

/// Every `.rs` file under `dir` but the surface tests and the shared harness (`common/`),
/// concatenated without its comment lines: a flag a comment quotes, or a helper any tool's tests
/// call spells, is no flag this tool's tests use.
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

/// Fail when a verb or flag of `cmd` appears as a string literal in no integration test under
/// `tests`, this tool's `tests/`, the shared harness (cli/tests/common) left out: a flag the
/// harness spells, as cakeys' own `--module` did for caprobe's, is no tool's test (review D9).
/// `untested` lists the ones knowingly
/// left out, each with why; one that is tested after all, or that clap no longer defines, fails
/// too, so the list cannot go stale.
///
/// # Panics
///
/// With the names no test uses, or the stale `untested` entries.
pub fn assert_covered(cmd: &clap::Command, tests: &Path, untested: &[(&str, &str)]) {
    let mut names = BTreeSet::new();
    surface(cmd, &mut names);
    let mut text = String::new();
    sources(tests, &mut text);
    // As an argument of its own (`"--dry-run"`), or the start of one (`"--module={path}"`,
    // `"--label kmtest"`).
    let spelled = |text: &str, name: &str| {
        [format!("\"{name}\""), format!("\"{name}="), format!("\"{name} ")].iter().any(|form| text.contains(form))
    };
    let functions = functions(&text);
    // A shared flag, `verb --flag`: both in one function.
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
