//! The test harness's own tests (crates/cli/tests/common): the `YubiKey` latch, the scrubbed
//! environment, the opt-in variables, bounded runs, the refusal check, and the lints over every
//! crate's test sources. They were moved out of tests/validate.rs, whose header describes the
//! static gate (review 2026-11-23 D-21). They need no token, module or environment.

mod common;

use common::state::{Row, TokenView, refusal};
use common::test_skip::{HARDWARE, TPM};
use common::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Output;

/// Returns every `.rs` file under `dir`, with its text.
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

/// Returns the integration tests of every crate in the workspace, with their text.
fn workspace_tests() -> Vec<(PathBuf, String)> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    std::fs::read_dir(crates).unwrap().flat_map(|k| sources(&k.unwrap().path().join("tests"))).collect()
}

/// The check of the dry-run twin (review 2026-11-24 phase 1, T-1): a real run keeps its dry run's
/// promise when it has the same exit code (0 and 22 count as the same), when a device fails, or
/// when it is refused by a rule that the dry run named as deferred. It never keeps the promise
/// with another refusal, and the text that the run prints never decides. A run that wrote the lock
/// and then failed exits 22 (review 2026-11-24 L5), so the check judges it by the exit code of its
/// failed row and never treats the 22 as a success.
#[test]
fn the_twin_holds_a_run_to_its_dry_runs_exit_and_deferred_rules() {
    use common::xref::Dry;
    let row = |exit: u8, rule: Option<&str>, device: bool| Row {
        exit,
        rule: rule.map(str::to_owned),
        device,
        ..Row::passed("o", "s", "t", "failed")
    };
    let ready = Dry::new(0, vec!["import.unwraps".into()]);
    assert!(ready.kept_by(0, &[]) && ready.kept_by(22, &[]), "the same success");
    let compared = |exit| Dry::new(exit, vec![]).comparing();
    assert!(compared(18).kept_by(22, &[]) && compared(14).kept_by(22, &[]), "what `lock` records");
    assert!(!compared(18).kept_by(0, &[]) && !compared(10).kept_by(22, &[]), "a comparison, then another run");
    assert!(!Dry::new(14, vec![]).kept_by(22, &[]), "a plan refused, then done");
    assert!(!ready.kept_by(13, &[row(13, Some("locator-free"), false)]), "a rule it did not defer");
    assert!(ready.kept_by(13, &[row(13, Some("import.unwraps"), false)]), "a rule it deferred");
    assert!(ready.kept_by(16, &[row(16, None, true)]), "the device");
    assert!(!ready.kept_by(16, &[]), "a 16 without its row");
    assert!(!ready.kept_by(10, &[row(13, Some("import.unwraps"), false)]), "a row of another exit than the run's");
    let refused = Dry::new(17, vec![]);
    assert!(refused.kept_by(17, &[row(17, Some("placement"), false)]));
    assert!(!refused.kept_by(13, &[row(13, Some("locator-free"), false)]), "refused by one rule, then another");
    assert!(!refused.kept_by(0, &[]) && !refused.kept_by(22, &[]), "refused, then done");
    // A run that writes the lock for one pair and then fails another pair exits 22. The check
    // must judge it by the failed row's code and must not treat the 22 as a success.
    let wrote_then = |r: Row| [Row::passed("o", "s", "t", "created"), r];
    let partial = |dry: &Dry, failed: Row| dry.kept_by(22, &wrote_then(failed));
    assert!(
        partial(&Dry::new(13, vec![]), row(13, Some("locator-free"), false)),
        "the dry run refused with the same code and rule"
    );
    assert!(
        !partial(&ready, row(13, Some("locator-free"), false)),
        "a write, then a refusal by a rule the dry run did not defer"
    );
    assert!(
        partial(&ready, row(13, Some("import.unwraps"), false)),
        "a write, then a refusal by a rule the dry run deferred"
    );
    assert!(partial(&ready, row(16, None, true)), "a write, then a device failure");
    assert!(!partial(&refused, row(13, Some("locator-free"), false)), "refused by one rule, then another");
}

/// One failed `YubiKey` login stops every later login (review yubikey.rs F1; the PIN has three
/// tries). A run that reports any `CKR_PIN_*` fails its test and sets the latch that turns the
/// device off for the tests, and the next test's turn refuses before it logs in. Because this
/// test holds the turn, no `YubiKey` test runs while it sets and clears the latch. No device is
/// needed.
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
    // Other failures belong to the test alone, and they set no latch.
    assert!(
        catch_unwind(AssertUnwindSafe(|| turn.checked(ran("error: unavailable: C_Sign: CKR_DEVICE_ERROR")))).is_ok()
    );
    assert!(!yubikey_latch().exists());
    let failed = catch_unwind(AssertUnwindSafe(|| turn.checked(ran("error: unavailable: C_Login: CKR_PIN_INCORRECT"))));
    let latched = std::fs::read_to_string(yubikey_latch());
    let refused = catch_unwind(AssertUnwindSafe(|| turn.refuse_if_latched()));
    // Clear the latch before the checks, so that a failed check leaves no latch for the next
    // test. A latch that was never written fails the check below, and not this removal (review
    // 2026-11-23 D-21).
    let _ = std::fs::remove_file(yubikey_latch());
    assert!(failed.is_err(), "a failed login passed its test");
    assert_eq!(latched.ok().as_deref(), Some("CKR_PIN_INCORRECT\n"), "the failed login wrote no latch");
    assert!(refused.is_err(), "the next test would log in again");
    turn.refuse_if_latched();
}

/// No test gives a tool the developer's own keys.toml or lock (review common/mod.rs F1). Under
/// the per-test runner (nix/test-tokens.sh, which sets `CAKEYS_TOKEN_TEMPLATE`), no test process
/// has their variables, and every run started by [`tool`] removes them again.
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

/// An opted-in suite never passes with nothing compared (review ftpm.rs F1). Every test that
/// needs the patched cryptoki calls [`cryptoki_hmac_types_fixed`] with `true` (so it never
/// skips), or [`hmac_types_fixed`] with the variable that requires it. No test passes a flag that
/// it computes itself, which was once a literal `false` or another suite's variable (review
/// common/mod.rs F7), and no test keeps its own check that skips. This covers the tests of every
/// crate, not only this one (caprobe's tests computed the flag from `std::env::var` after the fix
/// here).
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

/// A hardware opt-in is all or none (review D9). When every variable is set, the suite runs.
/// When none is set, the suite skips. When only some are set, the suite fails and names what is
/// missing, where each suite's own check once skipped. The require variable alone also fails
/// (review ftpm.rs F2), because a run that meant to test the suite but lost its variables passed
/// without running anything. A cross-reference test whose missing reference is required also
/// fails (`xref::Env::needs`, as `suite_var` does).
#[test]
fn a_half_set_opt_in_fails() {
    let env = |set: &'static [&'static str]| move |v: &str| set.contains(&v).then(|| format!("{v}-value"));
    let o = OptIn { vars: ["A", "B", "C"], require: "R" };
    assert_eq!(opt_in(o, &env(&["A", "B", "C"])), Ok(Some(["A-value", "B-value", "C-value"].map(String::from))));
    assert_eq!(opt_in(o, &env(&["A", "B", "C", "R"])), Ok(Some(["A-value", "B-value", "C-value"].map(String::from))));
    assert_eq!(opt_in(o, &env(&[])), Ok(None));
    assert_eq!(opt_in(o, &env(&["B"])), Err("A, C not set: the opt-in is A, B, C, all or none".into()));
    assert_eq!(opt_in(o, &env(&["R"])), Err("A, B, C not set: the opt-in is A, B, C, all or none; R is set".into()));
    // A cross-reference test that misses a reference skips only while nothing requires that
    // reference (review common/mod.rs: `xref::Env::needs` used to skip without checking).
    let e = common::xref::Env::over("needs-required", vec![created_ref("softhsm", "unused.so".into())]);
    let set = |vars: &'static [&'static str]| move |v: &str| vars.contains(&v);
    let names = |r: Result<[&common::xref::Ref; 2], &'static str>| r.map(|[a, b]| [a.name, b.name]);
    assert_eq!(e.needs_in(["softhsm", "kryoptic"], &set(&[])).map(names), Ok(Err("kryoptic")));
    assert_eq!(e.needs_in(["softhsm", "kryoptic"], &set(&["CAKEYS_TEST_REQUIRE"])).map(names), Ok(Err("kryoptic")));
    assert_eq!(
        e.needs_in(["softhsm", "kryoptic-der"], &set(&["CAKEYS_KRYOPTIC_REQUIRE"])).map(names),
        Err("needs the references kryoptic-der (CAKEYS_KRYOPTIC_REQUIRE is set), required but not set up".into())
    );
    // A run that requires everything requires every software reference (review 2026-11-24 C-11).
    assert_eq!(
        e.needs_in(["softhsm", "kryoptic"], &set(&[REQUIRE_ALL])).map(names),
        Err(format!(
            "needs the references kryoptic ({REQUIRE_ALL} is set, and CAKEYS_KRYOPTIC_REQUIRE is no hardware \
             suite's), required but not set up"
        ))
    );
    let e = common::xref::Env::over("needs-required", vec![e.refs[0].clone(), created_ref("kryoptic", "k.so".into())]);
    let found = e.needs_in(["kryoptic", "softhsm"], &set(&["CAKEYS_KRYOPTIC_REQUIRE"])).map(names);
    assert_eq!(found, Ok(Ok(["kryoptic", "softhsm"])));
}

/// A run that requires everything (`CAKEYS_REQUIRE_ALL`, which `test_env` sets for the check phase
/// and for scripts/local-tests.sh) lets a test skip only where it needs hardware or a cloud
/// account. The software TPM counts as hardware only in a build without it. When a suite's own
/// require variable is set, no skip is allowed (review 2026-11-24 C-11: the routing that started
/// the fault suites set their require variable, so a suite that the routing lost skipped and
/// passed).
#[test]
fn a_run_that_requires_everything_lets_only_hardware_skip() {
    let set = |vars: &'static [&'static str]| move |v: &str| vars.contains(&v);
    let software = ["CAKEYS_TEST_REQUIRE", "CAKEYS_KRYOPTIC_REQUIRE", "CAKEYS_P11KIT_REQUIRE", "CAKEYS_FAULT_REQUIRE"];
    for require in software.iter().chain(&[REQUIRE_ALL]).chain(&TPM).chain(&HARDWARE) {
        for tpm in [true, false] {
            assert_eq!(required(require, tpm, &set(&[])), None, "{require}: nothing required");
            assert!(required(require, tpm, &|v| v == *require).is_some(), "{require} set, and it skipped");
        }
    }
    for require in software.iter().chain(&[REQUIRE_ALL]) {
        assert!(required(require, false, &set(&[REQUIRE_ALL])).is_some(), "{require} skipped under {REQUIRE_ALL}");
    }
    for require in TPM {
        assert!(required(require, true, &set(&[REQUIRE_ALL])).is_some(), "{require} skipped in a build with the TPM");
        assert_eq!(required(require, false, &set(&[REQUIRE_ALL])), None, "{require}: a build without the TPM");
    }
    for require in HARDWARE {
        assert_eq!(required(require, true, &set(&[REQUIRE_ALL])), None, "{require} is hardware");
    }
}

/// Every skip goes through [`skip`] (review 2026-11-24 C-11). No test, in any crate, prints its
/// own skip message and returns, which is how ten conditional skips came to have no require
/// variable and to pass under any run. The searched text is built in pieces here, so that this
/// file does not match.
#[test]
fn every_skip_goes_through_the_one_helper() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let own = format!("\"{}ping", "skip");
    let found: Vec<String> = sources(crates)
        .into_iter()
        .filter(|(path, _)| !path.ends_with("test-skip.rs"))
        .flat_map(|(path, text)| {
            let lines: Vec<String> = text
                .lines()
                .enumerate()
                .filter(|(_, l)| l.contains(&own))
                .map(|(n, _)| format!("{}:{}", path.display(), n + 1))
                .collect();
            lines
        })
        .collect();
    assert!(found.is_empty(), "these skip on their own, not through `skip`:\n{}", found.join("\n"));
}

/// A run with a time limit reads its child's output while the child runs (review common/mod.rs
/// F3), so a child that writes more than a pipe holds finishes. When the output was read only
/// after the child exited, such a child blocked on its full pipe until the limit, and the failure
/// message blamed a touch or PIN prompt.
#[test]
fn a_bounded_run_reads_a_large_output_as_it_comes() {
    let mut big = std::process::Command::new("sh");
    big.args(["-c", "head -c 300000 /dev/zero; head -c 300000 /dev/zero >&2"]);
    let out = output_within(big, std::time::Duration::from_secs(20)).expect("the run outlasted its limit");
    assert!(out.status.success());
    assert_eq!((out.stdout.len(), out.stderr.len()), (300_000, 300_000));
    // A run that does outlast the limit is ended, and not waited for.
    let mut slow = std::process::Command::new("sleep");
    slow.arg("30");
    let started = std::time::Instant::now();
    assert!(output_within(slow, std::time::Duration::from_millis(200)).is_none());
    assert!(started.elapsed() < std::time::Duration::from_secs(10), "{:?}", started.elapsed());
}

/// There is one copy of each harness helper, in `tests/common/` (review D9: the suite gate, the
/// suite's `Env` and its `Deref`, `tpm2_ptool`, the P-256 OID and the runs of the binary were
/// each written several times, and the copies diverged: the runs scrubbed different variables).
/// No other file of this crate's tests writes one of them again.
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

/// A test that puts its own p11-fault in front of a module runs without the coverage trace
/// (nix/test-tokens.sh's list). Otherwise, the shim's calls to the module would count as the
/// tool's calls in the coverage trace, as rows that cakeys never reaches
/// (`tpm2_identity_failure_after_create_leaves_nothing`, once it used the shim, put
/// `C_GetSessionInfo` there). Every such test outside the suites that run untraced as a whole
/// must be in the list.
#[test]
fn every_test_with_its_own_fault_shim_runs_untraced() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../nix/test-tokens.sh");
    let script = std::fs::read_to_string(&script).unwrap_or_else(|e| panic!("{}: {e}", script.display()));
    let case =
        script.lines().find_map(|l| l.trim().strip_suffix(") untraced=1 ;;")).expect("test-tokens.sh's untraced case");
    let untraced: BTreeSet<&str> = case.split(" | ").collect();
    // The searched text is built in pieces here, so that this file's own text does not match.
    let (test_attr, shim) = (format!("{}[test]", '#'), format!("{}()", "fault_shim"));
    let mut missing = vec![];
    for (path, text) in workspace_tests() {
        // A suite is a file directly under tests/. A suite that the case names as a whole
        // (`fault/*`, `liars/*`) runs untraced as a whole, in every crate.
        let suite = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        if untraced.contains(format!("{suite}/*").as_str()) || !path.parent().is_some_and(|p| p.ends_with("tests")) {
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

/// Every hardware suite opts in through [`opted_in`] (review D9). No suite reads an opt-in
/// variable itself, which is how a half-set opt-in once passed without a message.
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

/// Returns what a run that `rule` refused with `exit` prints: that exit code, and its one row.
fn refused_by(exit: u8, rule: &str) -> Output {
    use std::os::unix::process::ExitStatusExt as _;
    let row = Row { exit, rule: Some(rule.into()), ..Row::passed("o", "s", "ref", "failed") };
    let stdout = serde_json::to_vec(&[row]).unwrap();
    Output { status: std::process::ExitStatus::from_raw(i32::from(exit) << 8), stdout, stderr: vec![] }
}

/// The refusal check (`Workdir::refused`) fails a refusal that writes the lock (review 2026-11-24
/// C-9: only two tests compared the lock). The refusal's exit code and its row's rule are right,
/// so only the comparison of the lock before and after can fail it. The same refusal without a
/// change to the lock passes first.
#[test]
#[should_panic(expected = "a refusal changed")]
fn a_refusal_that_changes_the_lock_is_caught() {
    let w = Workdir::new("refusal-changes-the-lock");
    let lock = w.dir.join("keys.lock");
    refusal(&[&lock], &[], "a refusal", || refused_by(13, "locator-free"), 13, "locator-free");
    let writes = || {
        std::fs::write(&lock, "version = 1\n\n[objects.k]\nclass = \"CKO_DATA\"\n").unwrap();
        refused_by(13, "locator-free")
    };
    refusal(&[&lock], &[], "a refusal", writes, 13, "locator-free");
}

/// The refusal check fails a refusal that changes the token. Here the token is a database file,
/// as kryoptic's token is (`state::objects`), so no module is needed. The same refusal without a
/// change to the token passes first.
#[test]
#[should_panic(expected = "a refusal changed token kmtest")]
fn a_refusal_that_changes_the_token_is_caught() {
    let w = Workdir::new("refusal-changes-the-token");
    let (lock, db) = (w.dir.join("keys.lock"), w.dir.join("token.sql"));
    std::fs::write(&db, "one object").unwrap();
    let token = || TokenView { name: "kmtest", module: "", label: "kmtest", env: &[], db: vec![db.clone()] };
    refusal(&[&lock], &[token()], "a refusal", || refused_by(14, "pinned-lost"), 14, "pinned-lost");
    let writes = || {
        std::fs::write(&db, "two objects").unwrap();
        refused_by(14, "pinned-lost")
    };
    refusal(&[&lock], &[token()], "a refusal", writes, 14, "pinned-lost");
}

/// The refusal check fails a refusal by another rule than the named one, even with the same exit
/// code. The rule decides, and not the exit code, which several rules share (review 2026-11-24 A
/// root cause 6).
#[test]
#[should_panic(expected = "a refusal: the refused row")]
fn a_refusal_by_another_rule_is_caught() {
    let w = Workdir::new("refusal-by-another-rule");
    let lock = w.dir.join("keys.lock");
    refusal(&[&lock], &[], "a refusal", || refused_by(15, "capability"), 15, "capability");
    refusal(&[&lock], &[], "a refusal", || refused_by(15, "templates"), 15, "capability");
}
