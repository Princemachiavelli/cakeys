//! The test harness's own tests (crates/cli/tests/common): the `YubiKey` latch, the scrubbed
//! environment, the opt-in variables, bounded runs, and the lints over every crate's test
//! sources. Moved out of tests/validate.rs, whose header is the static gate (review 2026-11-23
//! D-21). No token, module or environment needed.

mod common;

use common::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Output;

/// Every `.rs` file under `dir`, with its text.
fn sources(dir: &Path) -> Vec<(PathBuf, String)> {
    let Ok(files) = std::fs::read_dir(dir) else { return vec![] };
    let mut stack: Vec<_> = files.map(|f| f.unwrap().path()).collect();
    let mut found = vec![];
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            stack.extend(std::fs::read_dir(&path).unwrap().map(|f| f.unwrap().path()));
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            found.push((path, text));
        }
    }
    found
}

/// The integration tests of every crate in the workspace, with their text.
fn workspace_tests() -> Vec<(PathBuf, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    std::fs::read_dir(crates).unwrap().flat_map(|k| sources(&k.unwrap().path().join("tests"))).collect()
}

/// One failed `YubiKey` login stops every later one (review yubikey.rs F1; the PIN has three
/// tries): a run that reports any `CKR_PIN_*` fails its test and latches the device off, and the
/// next test's turn refuses before it logs in. Holding the turn, no `YubiKey` test runs while
/// this one sets and clears the latch; no device is needed.
#[test]
fn a_failed_yubikey_login_stops_every_later_one() {
    use std::os::unix::process::ExitStatusExt as _;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    let turn = YubikeyTurn::take();
    let ran = |stderr: &str| Output {
        status: std::process::ExitStatus::from_raw(16 << 8),
        stdout: vec![],
        stderr: stderr.into(),
    };
    // Other failures are the test's own: no latch.
    assert!(
        catch_unwind(AssertUnwindSafe(|| turn.checked(ran("error: unavailable: C_Sign: CKR_DEVICE_ERROR")))).is_ok()
    );
    assert!(!yubikey_latch().exists());
    let failed = catch_unwind(AssertUnwindSafe(|| turn.checked(ran("error: unavailable: C_Login: CKR_PIN_INCORRECT"))));
    let latched = std::fs::read_to_string(yubikey_latch());
    let refused = catch_unwind(AssertUnwindSafe(|| turn.refuse_if_latched()));
    // Cleared before the checks, so a failed one leaves no latch for the next test; one that
    // was never written fails the check below, not this removal (review 2026-11-23 D-21).
    let _ = std::fs::remove_file(yubikey_latch());
    assert!(failed.is_err(), "a failed login passed its test");
    assert_eq!(latched.ok().as_deref(), Some("CKR_PIN_INCORRECT\n"), "the failed login wrote no latch");
    assert!(refused.is_err(), "the next test would log in again");
    turn.refuse_if_latched();
}

/// No test hands a tool the developer's own keys.toml or lock (review common/mod.rs F1): under
/// the per-test runner (nix/test-tokens.sh, which sets `CAKEYS_TOKEN_TEMPLATE`) no test process
/// has them, and every run started by [`tool`] has them removed again.
#[test]
fn no_test_run_sees_a_real_keys_toml_or_lock() {
    if std::env::var_os("CAKEYS_TOKEN_TEMPLATE").is_some() {
        for var in ["CAKEYS_CONFIG", "CAKEYS_LOCK"] {
            assert_eq!(std::env::var_os(var), None, "the per-test runner left {var} set");
        }
    }
    let c = tool(BIN);
    let removed: Vec<_> = c.get_envs().filter(|(_, v)| v.is_none()).map(|(k, _)| k.to_owned()).collect();
    for var in SCRUBBED {
        assert!(removed.iter().any(|k| k == var), "{var} reaches the tool");
    }
}

/// An opted-in suite never passes with nothing compared (review ftpm.rs F1): every test that
/// needs the patched cryptoki asks [`cryptoki_hmac_types_fixed`] with `true` (it never skips),
/// or [`hmac_types_fixed`] with the variable that requires it — never a flag it computes itself,
/// which was a literal `false` or another suite's variable (review common/mod.rs F7) — and none
/// keeps its own check that skips. Every crate's tests, not only this one's (caprobe's computed
/// the flag from `std::env::var` after the fix here).
#[test]
fn no_opted_in_suite_skips_an_unpatched_build() {
    let own = format!("{}0x2c", "SHA384_HMAC) == ");
    let call = format!("{}(", "cryptoki_hmac_types_fixed");
    let found: Vec<_> = workspace_tests()
        .into_iter()
        .filter(|(path, text)| {
            let args = || text.match_indices(&call).map(|(at, _)| &text[at + call.len()..]);
            let computed = args().any(|a| !a.starts_with("true)"));
            (computed || text.contains(&own)) && !path.ends_with("common/mod.rs")
        })
        .map(|(path, _)| path)
        .collect();
    assert!(found.is_empty(), "these skip an unpatched build: {found:?}");
}

/// A hardware opt-in is all or none (review D9): every variable set runs the suite, none skips
/// it, and a half-set one fails naming what is missing, where each suite's own check skipped.
/// Its require variable alone fails too (review ftpm.rs F2): a run that means the suite and
/// lost its variables passed having run nothing. So does a cross-reference test whose missing
/// reference is required (`xref::Env::needs`, as `suite_var` does).
#[test]
fn a_half_set_opt_in_fails() {
    let env = |set: &'static [&'static str]| move |v: &str| set.contains(&v).then(|| format!("{v}-value"));
    let o = OptIn { vars: ["A", "B", "C"], require: "R" };
    assert_eq!(opt_in(o, &env(&["A", "B", "C"])), Ok(Some(["A-value", "B-value", "C-value"].map(String::from))));
    assert_eq!(opt_in(o, &env(&["A", "B", "C", "R"])), Ok(Some(["A-value", "B-value", "C-value"].map(String::from))));
    assert_eq!(opt_in(o, &env(&[])), Ok(None));
    assert_eq!(opt_in(o, &env(&["B"])), Err("A, C not set: the opt-in is A, B, C, all or none".into()));
    assert_eq!(opt_in(o, &env(&["R"])), Err("A, B, C not set: the opt-in is A, B, C, all or none; R is set".into()));
    // A cross-reference test missing a reference skips only while nothing requires that one
    // (review common/mod.rs: `xref::Env::needs` skipped without asking).
    let e = common::xref::Env::over("needs-required", vec![created_ref("softhsm", "unused.so".into())]);
    let set = |vars: &'static [&'static str]| move |v: &str| vars.contains(&v);
    let names = |r: Option<[&common::xref::Ref; 2]>| r.map(|[a, b]| [a.name, b.name]);
    assert_eq!(e.needs_in("t", ["softhsm", "kryoptic"], &set(&[])).map(names), Ok(None));
    assert_eq!(e.needs_in("t", ["softhsm", "kryoptic"], &set(&["CAKEYS_TEST_REQUIRE"])).map(names), Ok(None));
    assert_eq!(
        e.needs_in("t", ["softhsm", "kryoptic-der"], &set(&["CAKEYS_KRYOPTIC_REQUIRE"])).map(names),
        Err("needs the references kryoptic-der (CAKEYS_KRYOPTIC_REQUIRE is set), required but not set up".into())
    );
    let e = common::xref::Env::over("needs-required", vec![e.refs[0].clone(), created_ref("kryoptic", "k.so".into())]);
    let found = e.needs_in("t", ["kryoptic", "softhsm"], &set(&["CAKEYS_KRYOPTIC_REQUIRE"])).map(names);
    assert_eq!(found, Ok(Some(["kryoptic", "softhsm"])));
}

/// A bounded run reads its child's output while the child runs (review common/mod.rs F3): one
/// that writes more than a pipe holds finishes. Read only once it had exited, such a child
/// blocked on its full pipe until the limit, and the failure blamed a touch or PIN prompt.
#[test]
fn a_bounded_run_reads_a_large_output_as_it_comes() {
    let mut big = std::process::Command::new("sh");
    big.args(["-c", "head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2"]);
    let out = output_within(big, std::time::Duration::from_secs(20)).expect("the run outlasted its limit");
    assert!(out.status.success());
    assert_eq!((out.stdout.len(), out.stderr.len()), (300_000, 300_000));
    // And a run that does outlast it is ended, not waited for.
    let mut slow = std::process::Command::new("sleep");
    slow.arg("30");
    let started = std::time::Instant::now();
    assert!(output_within(slow, std::time::Duration::from_millis(200)).is_none());
    assert!(started.elapsed() < std::time::Duration::from_secs(10), "{:?}", started.elapsed());
}

/// One copy of each harness helper, in `tests/common/` (review D9: the suite gate, the suite's
/// `Env` and its `Deref`, `tpm2_ptool`, the P-256 OID and the runs of the binary were each
/// written several times, and drifted: the runs scrubbed different variables). No other file
/// of this crate's tests writes one again.
#[test]
fn the_harness_helpers_are_written_once() {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let copies = [
        ("a suite's own Deref", format!("impl std::ops::{} for", "Deref")),
        ("a raw tpm2_ptool", format!("Command::new(\"{}\")", "tpm2_ptool")),
        ("a run of the binary bypassing Run", format!("{}_BIN_EXE_", "CARGO")),
        ("the P-256 OID", ["0x2a", "0x86", "0x48", "0xce", "0x3d", "0x03", "0x01", "0x07"].join(", ")),
        ("a suite's module read past the gate", format!("{}(\"CAKEYS_", "std::env::var")),
    ];
    let mut found = vec![];
    for (path, text) in sources(&tests) {
        if path.starts_with(tests.join("common")) {
            continue;
        }
        for (what, copy) in &copies {
            let module_var = |at: usize| text[at..].split('"').nth(1).is_some_and(|v| v.ends_with("_MODULE"));
            let hits = text.match_indices(copy.as_str()).filter(|(at, _)| !what.contains("module") || module_var(*at));
            for _ in hits {
                found.push(format!("{}: {what}", path.display()));
            }
        }
    }
    assert!(found.is_empty(), "written again outside tests/common/:\n{}", found.join("\n"));
}

/// A test that puts its own p11-fault in front of a module runs untraced (nix/test-tokens.sh's
/// list): that shim's calls to the module would count as the tool's in the coverage trace, rows
/// cakeys never reaches (`tpm2_identity_failure_after_create_leaves_nothing`, once it used the
/// shim, put `C_GetSessionInfo` there). Every such test outside the `fault` suites is listed.
#[test]
fn every_test_with_its_own_fault_shim_runs_untraced() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../nix/test-tokens.sh");
    let script = std::fs::read_to_string(&script).unwrap_or_else(|e| panic!("{}: {e}", script.display()));
    let case =
        script.lines().find_map(|l| l.trim().strip_suffix(") untraced=1 ;;")).expect("test-tokens.sh's untraced case");
    let untraced: BTreeSet<&str> = case.split(" | ").collect();
    // Spelt here so this file's own text is not a match.
    let (test_attr, shim) = (format!("{}[test]", '#'), format!("{}()", "fault_shim"));
    let mut missing = vec![];
    for (path, text) in workspace_tests() {
        // A suite is a file directly under tests/; the fault suites are untraced whole.
        let suite = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        if suite == "fault" || !path.parent().is_some_and(|p| p.ends_with("tests")) {
            continue;
        }
        for test in text.split(test_attr.as_str()).skip(1) {
            let name = test.split("fn ").nth(1).and_then(|s| s.split('(').next()).unwrap_or_default();
            let named = format!("{suite}/{name}");
            if test.contains(shim.as_str()) && !untraced.contains(named.as_str()) {
                missing.push(named);
            }
        }
    }
    assert!(
        missing.is_empty(),
        "these run their own p11-fault, traced (add them to nix/test-tokens.sh's untraced case): {missing:?}"
    );
}

/// Every hardware suite opts in through [`opted_in`] (review D9): none reads an opt-in variable
/// itself, which is how a half-set opt-in passed silently.
#[test]
fn every_hardware_suite_opts_in_through_the_harness() {
    let mut found = vec![];
    for (path, text) in workspace_tests() {
        if path.ends_with("common/mod.rs") {
            continue;
        }
        for var in FTPM_OPT_IN.vars.iter().chain(&YUBIKEY_OPT_IN.vars) {
            if text.contains(&format!("var(\"{var}\")")) {
                found.push(format!("{}: {var}", path.display()));
            }
        }
    }
    assert!(found.is_empty(), "these read an opt-in variable themselves: {found:?}");
}
