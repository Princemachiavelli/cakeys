//! Opt-in end-to-end tests against the cloud HSMs `scripts/cloud/` keeps (`docs/CLOUD_HSM.md`):
//! cakeys and camigrate driven through `aws.sh cakeys|camigrate` and `gcp.sh cakeys`, exactly as
//! by hand. They never create or destroy infrastructure — bring it up first, park or destroy it
//! after — and are skipped unless asked for, and always inside a Nix build:
//!
//! - `CAKEYS_TEST_AWS`: `FIPS`, `NON_FIPS` or `FIPS,NON_FIPS`, the clusters to test, each up
//!   and activated (`CAKEYS_AWS_MODE=<mode> scripts/cloud/aws.sh create`, then `activate`); the
//!   AWS credentials the scripts use. The HSMs bill by the hour ($1.81/h each in us-west-1)
//!   whether or not a test runs; a run takes about ten minutes per cluster.
//! - `CAKEYS_TEST_GCP=1`: the Cloud KMS key ring `scripts/cloud/gcp.sh create` made, with no
//!   live version left (`gcp.sh status`), and `CAKEYS_GCP_PROJECT`. A run adds one HSM key version
//!   to each of five keys and destroys it within minutes: cents.
//!
//! `aws.sh` copies Nix store paths to its runner, so the tools are Nix builds: `CAKEYS` and
//! `CAMIGRATE` name built binaries (`.#cakeys` without its check phase, as `aws.sh` builds them
//! when they are unset). `cargo test` builds nothing the scripts use.
//!
//! Each run takes labels and a lock of its own (`CAKEYS_AWS_CONFIG`/`CAKEYS_AWS_LOCK`,
//! `CAKEYS_GCP_LOCK`), so it never meets another run's keys or the hand-kept lock, and deletes
//! everything it created, also when an assertion fails.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Unsupported: what cakeys refuses before creating anything (docs/CAKEYS.md, exit codes).
const UNSUPPORTED: i32 = 15;

fn scripts() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/cloud")
}

/// `script` with `args` and `env`, its output; stderr carries cakeys' notes and errors.
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

/// A run's own name: what its labels and lock carry.
fn run_id() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    format!("ct{secs}")
}

/// What was asked of a test run: `None` (skip) unless the variable is set, never in a Nix build.
fn asked(var: &str) -> Option<String> {
    // A Nix build sets NIX_BUILD_TOP; `nix develop` does too, with IN_NIX_SHELL.
    if std::env::var_os("NIX_BUILD_TOP").is_some() && std::env::var_os("IN_NIX_SHELL").is_none() {
        return None;
    }
    let v = std::env::var(var).ok().filter(|v| !v.is_empty());
    if v.is_none() {
        eprintln!("skipping: {var} not set (crates/cli/tests/cloud.rs)");
    }
    v
}

/// Run `body`, then `cleanup` whatever `body` did, then fail as `body` failed.
fn with_cleanup(body: impl FnOnce(), cleanup: impl FnOnce()) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
    cleanup();
    if let Err(e) = outcome {
        std::panic::resume_unwind(e);
    }
}

/// AWS `CloudHSM`, per cluster: every key kind of `scripts/cloud/aws/cakeys.toml` created and
/// proven, Ed25519 (the aws-cloudhsm provider's stand-ins) on a non-FIPS cluster and refused
/// before creating on a FIPS one, and keys moved each way between `SoftHSM` and `CloudHSM` (and
/// Ed25519 out of a non-FIPS one) by
/// camigrate (`CKM_RSA_AES_KEY_WRAP`, `CloudHSM`'s only RFC 5649). The clusters run at once:
/// each has its own runner, lock and `SoftHSM` token, and every one runs to its end before the
/// first failure is reported.
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

    // The mode too: the clusters run at once, each with a directory of its own here.
    let id = format!("{}-{}", run_id(), mode.to_lowercase().replace('_', ""));
    let dir = std::env::temp_dir().join(format!("cakeys-cloud-{id}"));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("keys.toml");
    let committed = std::fs::read_to_string(scripts().join("aws/cakeys.toml")).unwrap();
    std::fs::write(&config, committed.replace("CKA_LABEL = \"cakeys-", &format!("CKA_LABEL = \"{id}-"))).unwrap();
    let lock = format!("/tmp/cakeys-{id}.lock");
    let config = config.to_str().unwrap().to_owned();
    let env = [("CAKEYS_AWS_MODE", mode), ("CAKEYS_AWS_CONFIG", config.as_str()), ("CAKEYS_AWS_LOCK", lock.as_str())];
    let cakeys = |args: &[&str]| run("aws.sh", &env, &[&["cakeys"], args].concat());
    let camigrate = |args: &[&str]| run("aws.sh", &env, &[&["camigrate"], args].concat());

    // The transport keys first: each token's sealed imports wrap to its own.
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
            for (spec, token) in &keys {
                let o = cakeys(&["create", "--spec", spec, "--token", token]);
                assert_eq!(code(&o), Some(0), "{mode}: create {spec} on {token}: {}", text(&o));
                created.borrow_mut().push((*spec, *token));
            }
            if mode == "FIPS" {
                // The FIPS profile adds no Ed25519 stand-in: refused before anything is made.
                let o = cakeys(&["create", "--spec", "ed25519", "--token", "cloudhsm"]);
                assert_eq!(code(&o), Some(UNSUPPORTED), "{mode}: ed25519: {}", text(&o));
                assert!(text(&o).contains("CKM_EC_EDWARDS_KEY_PAIR_GEN"), "{}", text(&o));
            }
            for (spec, token) in &keys {
                let o = cakeys(&["verify", "--spec", spec, "--token", token]);
                assert_eq!(code(&o), Some(0), "{mode}: verify {spec} on {token}: {}", text(&o));
            }
            let mut moves = vec![("movable", "softhsm", "cloudhsm"), ("outbound", "cloudhsm", "softhsm")];
            if mode == "NON_FIPS" {
                // Ed25519 moves out; in, the profile's migration.refuses blocks it in the plan.
                moves.push(("ed25519", "cloudhsm", "softhsm"));
                let o = cakeys(&["create", "--spec", "ed-in", "--token", "softhsm"]);
                assert_eq!(code(&o), Some(0), "{mode}: create ed-in on softhsm: {}", text(&o));
                created.borrow_mut().push(("ed-in", "softhsm"));
                let o = camigrate(&["migrate", "ed-in", "--from", "softhsm", "--to", "cloudhsm", "--dry-run"]);
                assert_eq!(code(&o), Some(UNSUPPORTED), "{mode}: ed-in into cloudhsm: {}", text(&o));
                assert!(text(&o).contains("migration.refuses"), "{}", text(&o));
            }
            for (key, from, to) in moves {
                let o = camigrate(&["migrate", key, "--from", from, "--to", to]);
                assert_eq!(code(&o), Some(0), "{mode}: migrate {key} {from} -> {to}: {}", text(&o));
                assert!(text(&o).contains("rsa-oaep-sha1+aes-kwp"), "{}", text(&o));
                created.borrow_mut().push((key, to));
                let o = cakeys(&["verify", "--spec", key, "--token", to]);
                assert_eq!(code(&o), Some(0), "{mode}: verify {key} on {to}: {}", text(&o));
            }
        },
        || {
            // The transport keys last: what was created first goes last.
            for (spec, token) in created.borrow().iter().rev() {
                let o = cakeys(&["delete", "--spec", spec, "--token", token]);
                if code(&o) != Some(0) {
                    eprintln!("cleanup: delete {spec} on {token} ({mode}) failed: {}", text(&o));
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
        },
    );
}

/// Google Cloud KMS: the keys scripts/cloud/gcp/cakeys.toml pre-creates take a version each,
/// proven where Cloud KMS lets them be, then destroyed; what the kmsp11 provider cannot make
/// (an AES key, a key to prove by unwrapping) is refused before anything exists.
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
                let o = cakeys(&["create", "--spec", spec, "--token", "gcp"]);
                assert_eq!(code(&o), Some(UNSUPPORTED), "{spec}: {}", text(&o));
            }
            for spec in keys {
                let o = cakeys(&["create", "--spec", spec, "--token", "gcp"]);
                assert_eq!(code(&o), Some(0), "create {spec}: {}", text(&o));
                created.borrow_mut().push(spec);
            }
            for spec in keys {
                let o = cakeys(&["verify", "--spec", spec, "--token", "gcp"]);
                assert_eq!(code(&o), Some(0), "verify {spec}: {}", text(&o));
            }
        },
        || {
            for spec in created.borrow().iter() {
                let o = cakeys(&["delete", "--spec", spec, "--token", "gcp"]);
                if code(&o) != Some(0) {
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
