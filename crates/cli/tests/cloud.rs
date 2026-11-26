//! Opt-in end-to-end tests against the cloud HSMs that `scripts/cloud/` maintains
//! (`docs/CLOUD_HSM.md`). The tests run cakeys and camigrate through `aws.sh cakeys|camigrate`
//! and `gcp.sh cakeys`, exactly as a person would by hand. They never create or destroy
//! infrastructure: bring it up first, and park or destroy it afterward. They are skipped
//! ([`test_skip::skip`]) unless they are asked for, and they are always skipped inside a Nix
//! build. `CAKEYS_CLOUD_REQUIRE` makes a skip fail. The tests are asked for as follows:
//!
//! - `CAKEYS_TEST_AWS`: `FIPS`, `NON_FIPS` or `FIPS,NON_FIPS`, the clusters to test. Each cluster
//!   must be up and activated (`CAKEYS_AWS_MODE=<mode> scripts/cloud/aws.sh create`, then
//!   `activate`), and the AWS credentials that the scripts use must be available. The HSMs are
//!   billed by the hour ($1.81/h each in us-west-1) whether or not a test runs, and a run takes
//!   about ten minutes per cluster.
//! - `CAKEYS_TEST_GCP=1`: the Cloud KMS key ring that `scripts/cloud/gcp.sh create` made must
//!   have no live version left (`gcp.sh status`), and `CAKEYS_GCP_PROJECT` must be set. A run adds
//!   one HSM key version to each of five keys and destroys it within minutes, which costs cents.
//!
//! `aws.sh` copies Nix store paths to its runner, so the tools must be Nix builds: `CAKEYS` and
//! `CAMIGRATE` name built binaries (`.#cakeys` without its check phase, which is how `aws.sh`
//! builds them when the variables are unset). `cargo test` builds nothing that the scripts use.
//!
//! Each run uses labels and a lock of its own (`CAKEYS_AWS_CONFIG`/`CAKEYS_AWS_LOCK`,
//! `CAKEYS_GCP_LOCK`), so it never meets another run's keys or the lock that is kept by hand.
//! Each run deletes everything that it created, also when an assertion fails.

#[path = "../../test-skip.rs"]
mod test_skip;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The variable that makes a skip here fail. crates/test-skip.rs treats this as a cloud suite, so
/// a run that requires every other suite does not require this one.
const REQUIRE: &str = "CAKEYS_CLOUD_REQUIRE";

/// The exit code for unsupported (docs/CAKEYS.md, exit codes), with which cakeys refuses a request
/// before it creates anything.
const UNSUPPORTED: i32 = 15;
/// The exit code for a run that succeeded and wrote the lock (docs/CAKEYS.md). Every run here
/// that records something exits with it.
const LOCK_WRITTEN: i32 = 22;

fn scripts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/cloud")
}

/// Runs `script` with `args` and `env`, and returns its output. stderr holds cakeys' notes and
/// errors.
fn run(script: &str, env: &[(&str, &str)], args: &[&str]) -> Output {
    let out = Command::new(scripts().join(script)).envs(env.iter().copied()).args(args).output().unwrap();
    eprintln!(
        "$ {script} {}\n  exit={:?}\n  stderr={}",
        args.join(" "),
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter(|l| !l.contains("is dirty"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    out
}

fn code(o: &Output) -> Option<i32> {
    o.status.code()
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

/// Returns a name for this run, which its labels and its lock carry.
fn run_id() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    format!("ct{secs}")
}

/// Returns the value of `var`, which says what the test run asks for. It returns `None` (the test
/// is skipped) when the variable is unset, and always inside a Nix build, which cannot reach any
/// cloud (review 2026-11-24 C-7: inside a Nix build, it used to return without a message).
fn asked(var: &str) -> Option<String> {
    // A Nix build sets NIX_BUILD_TOP. `nix develop` sets it too, but it also sets IN_NIX_SHELL.
    if std::env::var_os("NIX_BUILD_TOP").is_some() && std::env::var_os("IN_NIX_SHELL").is_none() {
        test_skip::skip(var, REQUIRE, "inside a Nix build, which reaches no cloud");
        return None;
    }
    let v = std::env::var(var).ok().filter(|v| !v.is_empty());
    if v.is_none() {
        test_skip::skip(var, REQUIRE, &format!("{var} not set (crates/cli/tests/cloud.rs)"));
    }
    v
}

/// Runs `body`, then runs `cleanup` whatever `body` did, and then, if `body` panicked, resumes
/// that panic.
fn with_cleanup(body: impl FnOnce(), cleanup: impl FnOnce()) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    cleanup();
    if let Err(e) = outcome {
        std::panic::resume_unwind(e);
    }
}

/// AWS `CloudHSM`, per cluster. Every key kind of `scripts/cloud/aws/cakeys.toml` is created and
/// proven. Ed25519 (through the aws-cloudhsm provider's stand-ins) is created on a non-FIPS
/// cluster, and it is refused before anything is created on a FIPS cluster. camigrate moves keys
/// in each direction between `SoftHSM` and `CloudHSM`, and it moves Ed25519 out of a non-FIPS
/// cluster (with `CKM_RSA_AES_KEY_WRAP`, the only RFC 5649 mechanism of `CloudHSM`). The clusters
/// run in parallel: each has its own runner, lock and `SoftHSM` token, and every cluster runs to
/// its end before the first failure is reported.
#[test]
fn aws_cloudhsm_end_to_end() {
    let Some(modes) = asked("CAKEYS_TEST_AWS") else { return };
    let modes: Vec<&str> = modes.split(',').map(str::trim).collect();
    for mode in &modes {
        assert!(matches!(*mode, "FIPS" | "NON_FIPS"), "CAKEYS_TEST_AWS: {mode} is neither FIPS nor NON_FIPS");
    }
    let outcomes: Vec<_> = std::thread::scope(|s| {
        let runs: Vec<_> = modes.iter().map(|mode| s.spawn(move || aws_cluster(mode))).collect();
        runs.into_iter().map(std::thread::ScopedJoinHandle::join).collect()
    });
    if let Some(Err(e)) = outcomes.into_iter().find(Result::is_err) {
        std::panic::resume_unwind(e);
    }
}

fn aws_cluster(mode: &str) {
    let base = [("CAKEYS_AWS_MODE", mode)];
    let status = run("aws.sh", &base, &["status"]);
    let up = text(&status).lines().any(|l| {
        let words: Vec<&str> = l.split_whitespace().collect();
        words.contains(&"ACTIVE") && words.contains(&mode) && l.trim_end().ends_with("1 HSM")
    });
    assert!(
        up,
        "no ACTIVE {mode} cluster with an HSM: CAKEYS_AWS_MODE={mode} scripts/cloud/aws.sh create, then activate"
    );

    // The ID also includes the mode, because the clusters run in parallel, and each needs a
    // directory of its own here.
    let id = format!("{}-{}", run_id(), mode.to_lowercase().replace('_', ""));
    let dir = std::env::temp_dir().join(format!("cakeys-cloud-{id}"));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("keys.toml");
    let committed = std::fs::read_to_string(scripts().join("aws/cakeys.toml")).unwrap();
    std::fs::write(&config, committed.replace("CKA_LABEL = \"cakeys-", &format!("CKA_LABEL = \"{id}-"))).unwrap();
    let lock = dir.join("keys.lock").to_str().unwrap().to_owned();
    let config = config.to_str().unwrap().to_owned();
    let env = [("CAKEYS_AWS_MODE", mode), ("CAKEYS_AWS_CONFIG", config.as_str()), ("CAKEYS_AWS_LOCK", lock.as_str())];
    let cakeys = |args: &[&str]| run("aws.sh", &env, &[&["cakeys"], args].concat());
    let camigrate = |args: &[&str]| run("aws.sh", &env, &[&["camigrate"], args].concat());

    // Create the transport keys first, because each token's sealed imports are wrapped to that
    // token's own transport key.
    let mut keys = vec![
        ("transport", "cloudhsm"),
        ("softhsm-transport", "softhsm"),
        ("ec-p256", "cloudhsm"),
        ("ec-p384-derive", "cloudhsm"),
        ("rsa-sign", "cloudhsm"),
        ("rsa-decrypt", "cloudhsm"),
        ("aes", "cloudhsm"),
        ("hmac", "cloudhsm"),
        ("outbound", "cloudhsm"),
        ("movable", "softhsm"),
    ];
    if mode == "NON_FIPS" {
        keys.push(("ed25519", "cloudhsm"));
    }
    let created = std::cell::RefCell::new(Vec::new());
    with_cleanup(
        || {
            // Each key is added to the cleanup list before its run, because a run that fails part
            // way may still have made (and billed) a key (review cloud.rs F2). A delete of a key
            // that was never made exits 0.
            for (spec, token) in &keys {
                created.borrow_mut().push((*spec, *token));
                // The run's lock is its own new lock, which the run's first writing command starts.
                let o = cakeys(&["--new-lock", "create", "--spec", spec, "--token", token]);
                assert_eq!(code(&o), Some(LOCK_WRITTEN), "{mode}: create {spec} on {token}: {}", text(&o));
            }
            if mode == "FIPS" {
                // The FIPS profile adds no Ed25519 stand-in, so the create is refused before
                // anything is made.
                let o = cakeys(&["--new-lock", "create", "--spec", "ed25519", "--token", "cloudhsm"]);
                assert_eq!(code(&o), Some(UNSUPPORTED), "{mode}: ed25519: {}", text(&o));
                assert!(text(&o).contains("CKM_EC_EDWARDS_KEY_PAIR_GEN"), "{}", text(&o));
            }
            for (spec, token) in &keys {
                let o = cakeys(&["check", "--spec", spec, "--token", token]);
                assert_eq!(code(&o), Some(0), "{mode}: check {spec} on {token}: {}", text(&o));
            }
            let mut moves = vec![("movable", "softhsm", "cloudhsm"), ("outbound", "cloudhsm", "softhsm")];
            if mode == "NON_FIPS" {
                // Ed25519 moves out of CloudHSM. A move of Ed25519 into CloudHSM is blocked in the
                // plan by the profile's `migration.refuses`.
                moves.push(("ed25519", "cloudhsm", "softhsm"));
                created.borrow_mut().push(("ed-in", "softhsm"));
                let o = cakeys(&["create", "--spec", "ed-in", "--token", "softhsm"]);
                assert_eq!(code(&o), Some(LOCK_WRITTEN), "{mode}: create ed-in on softhsm: {}", text(&o));
                let o = camigrate(&["migrate", "ed-in", "--from", "softhsm", "--to", "cloudhsm", "--dry-run"]);
                assert_eq!(code(&o), Some(UNSUPPORTED), "{mode}: ed-in into cloudhsm: {}", text(&o));
                assert!(text(&o).contains("migration.refuses"), "{}", text(&o));
            }
            for (key, from, to) in moves {
                created.borrow_mut().push((key, to));
                let o = camigrate(&["migrate", key, "--from", from, "--to", to]);
                assert_eq!(code(&o), Some(LOCK_WRITTEN), "{mode}: migrate {key} {from} -> {to}: {}", text(&o));
                assert!(text(&o).contains("rsa-oaep-sha1+aes-kwp"), "{}", text(&o));
                let o = cakeys(&["check", "--spec", key, "--token", to]);
                assert_eq!(code(&o), Some(0), "{mode}: check {key} on {to}: {}", text(&o));
            }
        },
        || {
            // Delete in the reverse order of creation, so that the transport keys, which were
            // created first, are deleted last.
            for (spec, token) in created.borrow().iter().rev() {
                let o = cakeys(&["--new-lock", "delete", "--spec", spec, "--token", token]);
                if !matches!(code(&o), Some(0 | LOCK_WRITTEN)) {
                    eprintln!("cleanup: delete {spec} on {token} ({mode}) failed: {}", text(&o));
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
        },
    );
}

/// Google Cloud KMS: each key that scripts/cloud/gcp/cakeys.toml pre-creates gets one version,
/// which is proven where Cloud KMS allows it and then destroyed. What the kmsp11 provider cannot
/// make (an AES key, a key to prove by unwrapping) is refused before anything exists.
#[test]
fn gcp_cloud_kms_end_to_end() {
    if asked("CAKEYS_TEST_GCP").is_none() {
        return;
    }
    let status = run("gcp.sh", &[], &["status"]);
    assert_eq!(code(&status), Some(0), "live key versions in the ring (gcp.sh status): {}", text(&status));

    let dir = std::env::temp_dir().join(format!("cakeys-cloud-{}", run_id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lock = dir.join("cakeys.lock");
    let env = [("CAKEYS_GCP_LOCK", lock.to_str().unwrap())];
    let cakeys = |args: &[&str]| run("gcp.sh", &env, &[&["cakeys"], args].concat());
    let keys = ["ec-p256", "ec-p384", "rsa-sign", "rsa-decrypt", "hmac"];
    let created = std::cell::RefCell::new(Vec::new());
    with_cleanup(
        || {
            for spec in ["rsa-pop-unwrap", "aes"] {
                // The run's lock is its own new lock, which the run's first writing command starts.
                let o = cakeys(&["--new-lock", "create", "--spec", spec, "--token", "gcp"]);
                assert_eq!(code(&o), Some(UNSUPPORTED), "{spec}: {}", text(&o));
            }
            for spec in keys {
                created.borrow_mut().push(spec);
                let o = cakeys(&["--new-lock", "create", "--spec", spec, "--token", "gcp"]);
                assert_eq!(code(&o), Some(LOCK_WRITTEN), "create {spec}: {}", text(&o));
            }
            for spec in keys {
                let o = cakeys(&["check", "--spec", spec, "--token", "gcp"]);
                assert_eq!(code(&o), Some(0), "check {spec}: {}", text(&o));
            }
        },
        || {
            for spec in created.borrow().iter() {
                let o = cakeys(&["--new-lock", "delete", "--spec", spec, "--token", "gcp"]);
                if !matches!(code(&o), Some(0 | LOCK_WRITTEN)) {
                    eprintln!("cleanup: delete {spec} failed: {}", text(&o));
                }
            }
            let left = run("gcp.sh", &[], &["status"]);
            if code(&left) != Some(0) {
                eprintln!("cleanup: live versions remain; scripts/cloud/gcp.sh destroy removes them: {}", text(&left));
            }
            let _ = std::fs::remove_dir_all(&dir);
        },
    );
}
