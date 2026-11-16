//! The command-line surface test, shared by the three tools: every verb and every flag clap
//! defines is used by an integration test of that tool. It reads the test sources, so it says
//! that a test names the verb or flag, not what the test proves with it: a floor under the
//! coverage report (docs/DEVELOPMENT.md), cheap enough to run on every build.

use std::collections::BTreeSet;
use std::path::Path;

/// The verbs and long flags of `cmd` and its subcommands, as a test would write them
/// (`lock`, `--dry-run`), less clap's own (`help`, `--help`, `--version`).
fn surface(cmd: &clap::Command, out: &mut BTreeSet<String>) {
    for arg in cmd.get_arguments() {
        if let Some(long) = arg.get_long().filter(|l| !matches!(*l, "help" | "version")) {
            out.insert(format!("--{long}"));
        }
    }
    for sub in cmd.get_subcommands().filter(|s| s.get_name() != "help") {
        out.insert(sub.get_name().to_owned());
        surface(sub, out);
    }
}

/// Every `.rs` file under `dir`, concatenated.
fn sources(dir: &Path, out: &mut String) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") && path.file_name().is_some_and(|n| n != "surface.rs") {
            out.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
        }
    }
}

/// Fail when a verb or flag of `cmd` appears as a string literal in no integration test under
/// `tests` (this tool's `tests/`) or the shared harness. `untested` lists the ones knowingly
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
    sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../cli/tests/common"), &mut text);
    // As an argument of its own (`"--dry-run"`), or the start of one (`"--module={path}"`,
    // `"--label kmtest"`).
    let used = |name: &str| {
        [format!("\"{name}\""), format!("\"{name}="), format!("\"{name} ")].iter().any(|form| text.contains(form))
    };
    let excused: BTreeSet<&str> = untested.iter().map(|(name, _)| *name).collect();
    let missing: Vec<&String> = names.iter().filter(|n| !used(n) && !excused.contains(n.as_str())).collect();
    assert!(missing.is_empty(), "no integration test of {} uses: {missing:?}", cmd.get_name());
    let stale: Vec<&&str> = excused.iter().filter(|n| !names.contains(**n) || used(n)).collect();
    assert!(stale.is_empty(), "listed as untested, but tested or gone from {}: {stale:?}", cmd.get_name());
}
