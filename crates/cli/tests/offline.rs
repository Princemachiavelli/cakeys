//! What `cakeys` decides from keys.toml and the lock alone, opening no token, so these run
//! everywhere: the `--module` overrides every tool parses, `validate`'s stdout and `gc`'s
//! lines.

mod common;

use common::*;
use std::process::Output;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn stdout_lines(o: &Output) -> Vec<String> {
    String::from_utf8_lossy(&o.stdout).lines().map(str::to_owned).collect()
}

/// `--module TOKEN=PATH` (cli-common `module_overrides`): each malformed or misdirected override
/// is invalid (17), refused before any token opens, naming why: a missing `=`, an empty half, a
/// token keys.toml does not name (a typo would leave keys.toml's module in place), and a token
/// given twice.
#[test]
fn an_override_that_cannot_apply_is_invalid() {
    let w = Workdir::new("module-override-invalid");
    w.write_config("[tokens.ref]\ntokenLabel = \"ref\"\nmodule = \"/nonexistent/libref.so\"\n");
    for (args, why) in [
        (&["ref"][..], "expects TOKEN=PATH"),
        (&["=/lib/x.so"][..], "neither of them empty"),
        (&["ref="][..], "neither of them empty"),
        (&["rfe=/lib/x.so"][..], "keys.toml names no token 'rfe'"),
        (&["ref=/lib/one.so", "ref=/lib/two.so"][..], "given a module twice"),
    ] {
        let mut cmd: Vec<&str> = args.iter().flat_map(|a| ["--module", a]).collect();
        cmd.push("validate");
        let o = w.km(&cmd);
        assert!(code(&o) == 17 && stderr(&o).contains(why), "{args:?}: {}", stderr(&o));
    }
}

/// `validate` that passes prints one `<spec> on <token>: mode <mode>` line per pair on stdout,
/// or with `--json` one `{spec, token, mode}` per pair; one the gate refuses (15) prints nothing
/// there, as stdout carries only a result.
#[test]
fn validate_prints_the_modes_only_when_it_passes() {
    let run = |config: &str| Run::new(BIN, std::path::Path::new(&format!("{FIXTURES}/{config}"))).output(&["validate"]);
    let passed = run("keys.toml");
    assert_eq!(code(&passed), 0, "{}", stderr(&passed));
    let lines = stdout_lines(&passed);
    assert_ne!(lines, Vec::<String>::new());
    for l in &lines {
        let (pair, mode) = l.split_once(": mode ").unwrap_or_else(|| panic!("not a mode line: {l:?}"));
        assert!(pair.contains(" on ") && !mode.is_empty(), "{l:?}");
    }
    let json = Run::new(BIN, std::path::Path::new(&format!("{FIXTURES}/keys.toml"))).output(&["--json", "validate"]);
    assert_eq!(code(&json), 0, "{}", stderr(&json));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&json.stdout).unwrap();
    let as_lines: Vec<String> = rows
        .iter()
        .map(|r| {
            format!(
                "{} on {}: mode {}",
                r["spec"].as_str().unwrap(),
                r["token"].as_str().unwrap(),
                r["mode"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(as_lines, lines);
    // Several refusals: 20, each listed with its own code (review 2026-11-24 §1.4: the one
    // refusal's code, or 20; it was 15 whatever the codes).
    let refused = run("gate.toml");
    assert_eq!(code(&refused), 20, "{}", stderr(&refused));
    assert!(stderr(&refused).lines().any(|l| l.starts_with("exit 15: ")), "{}", stderr(&refused));
    assert_eq!(stdout_lines(&refused), Vec::<String>::new());
}

/// `gc` prints the stale entries on stdout (`--json`: as an array), and says what it did as every
/// writing verb does, through the run's notes: it removes them and saves the lock with the same
/// `updated <lock>` line, and exits 22; `--dry-run` only prints them (review 2026-11-23 C-4: `gc`
/// was the one verb that wrote only when asked).
#[test]
fn gc_says_what_it_did_through_the_notes() {
    let w = Workdir::new("gc-notes");
    let lock = w.dir.join("keys.lock");
    std::fs::copy(format!("{FIXTURES}/keys.lock"), &lock).unwrap();
    w.write_config("");
    let looked = w.km(&["gc", "--dry-run"]);
    assert_eq!(code(&looked), 0, "{}", stderr(&looked));
    let stale = stdout_lines(&looked);
    assert!(stale.iter().any(|l| l == "objects.signing"), "{stale:?}");
    assert_eq!(
        stderr(&looked).lines().collect::<Vec<_>>(),
        [format!("note: gc: {} stale entries; run without --dry-run to remove them", stale.len())]
    );
    let json = w.km(&["--json", "gc", "--dry-run"]);
    assert_eq!(serde_json::from_slice::<Vec<String>>(&json.stdout).unwrap(), stale);
    let applied = w.km(&["gc"]);
    assert_eq!(code(&applied), 22, "{}", stderr(&applied));
    assert_eq!(stdout_lines(&applied), stale);
    assert_eq!(
        stderr(&applied).lines().collect::<Vec<_>>(),
        [format!("gc: removed {} stale entries", stale.len()), format!("updated {}", lock.display())]
    );
    let left = w.lock();
    let empty = |k: &str| left.get(k).is_none_or(|t| t.as_table().is_some_and(toml::Table::is_empty));
    assert!(empty("objects") && empty("realisations") && empty("observations"), "{left:?}");
    let again = w.km(&["gc"]);
    assert_eq!(code(&again), 0);
    assert_eq!(stdout_lines(&again), Vec::<String>::new());
    assert_eq!(
        stderr(&again).lines().collect::<Vec<_>>(),
        ["note: gc: nothing to collect: every lock entry is named by the config"]
    );
}
