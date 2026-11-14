//! caprobe against a real `YubiKey` (PIV, through ykcs11), opt-in; `cakeys`' yubikey suite
//! describes the device's slots and the environment.
//!
//! Needs `CAKEYS_TEST_YUBIKEY_MODULE` (path to libykcs11.so); the write probe also
//! `CAKEYS_TEST_YUBIKEY_PIN` and `CAKEYS_TEST_YUBIKEY_MGM` (paths to files holding the PIV PIN
//! and the admin credential). Skipped when they are unset — never in the Nix build — and the
//! secrets are only ever read by caprobe from these paths. The write probe replaces only retired
//! slot 94 (`CKA_ID` 17, `scratchId`).

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;
use std::time::Duration;

/// The write probe generates every curve and RSA size it tries in one run (74 s measured on a
/// `YubiKey` 5.7.4, RSA-4096 included).
const PROBE_LIMIT: Duration = Duration::from_secs(300);
/// Every other run: a touch or PIN prompt would hang it, so the bound turns one into a failure.
const RUN_LIMIT: Duration = Duration::from_secs(60);

/// Whether this build's cryptoki has the Nix patches the probe needs to write or judge a
/// profile (an unpatched one drops mechanisms it cannot name); a cargo build here has them only
/// in the Nix build. By hand: `nix build .#cakeys`, then `result-caprobe/bin/caprobe probe ...`.
fn patched(what: &str) -> bool {
    let patched = std::os::raw::c_ulong::from(cryptoki::object::KeyType::SHA384_HMAC) == 0x2c;
    if !patched {
        eprintln!("skipping {what}: this build's cryptoki is unpatched");
    }
    patched
}

/// The committed ykcs11/2.7 profile is probe output (docs/PROVIDERS.md phase 3): a fresh write
/// probe in the scratch slot conforms, and regenerating the file changes no byte — its
/// [migration] claims and [manual] findings preserved. A slot holding anything but ykcs11's own
/// placeholder is refused before anything is written (the guard's unit test covers the
/// certificate rules: crates/ykcs11/src/lib.rs). Another firmware, or a device not in
/// FIPS-approved mode, drifts by design (exit 15, the rows named): probe it and record a new
/// pair.
#[test]
fn the_write_probe_conforms_and_regenerates_the_committed_profile() {
    let (Ok(module), Ok(pin), Ok(mgm)) = (
        std::env::var("CAKEYS_TEST_YUBIKEY_MODULE"),
        std::env::var("CAKEYS_TEST_YUBIKEY_PIN"),
        std::env::var("CAKEYS_TEST_YUBIKEY_MGM"),
    ) else {
        eprintln!("skipping the write probe: CAKEYS_TEST_YUBIKEY_MODULE, _PIN and _MGM (file paths) not all set");
        return;
    };
    if !patched("the ykcs11/2.7 write probe") {
        return;
    }
    let w = Workdir::new("yubikey_write_probe");
    w.write_config(&yubikey_token(&module, &pin, &mgm, "scratchId = \"17\""));
    let config = w.dir.join("keys.toml");
    let probe = run_within(&config, &["probe", "--token", "yubikey", "--write", "--diff", "ykcs11/2.7"], PROBE_LIMIT);
    assert_eq!(code(&probe), 0, "{}", String::from_utf8_lossy(&probe.stderr));
    let committed = committed_profile("modules/ykcs11/2.7.toml");
    let copy = w.dir.join("profile.toml");
    std::fs::copy(&committed, &copy).unwrap();
    let out = copy.to_str().unwrap();
    let args = ["probe", "--token", "yubikey", "--write", "--diff", "ykcs11/2.7", "--out", out];
    assert_eq!(code(&run_within(&config, &args, PROBE_LIMIT)), 0);
    assert!(
        std::fs::read(&copy).unwrap() == std::fs::read(&committed).unwrap(),
        "profiles/modules/ykcs11/2.7.toml is not what the probe generates: regenerate it with `caprobe \
         probe --token <yk> --write --diff ykcs11/2.7 --out profiles/modules/ykcs11/2.7.toml`, and \
         put hand findings in [manual]"
    );
}

/// The read-only probe of the device here (docs/PROVIDERS.md D10): ykcs11/2.7's match keys,
/// advertisement and reported RSA range are what this `YubiKey` shows, and the write probes are
/// refused without a scratch slot — `scratch = true` cannot mark a device that holds real keys
/// beside it. Needs only `CAKEYS_TEST_YUBIKEY_MODULE`: no PIN, nothing written; the diff only
/// with the patched cryptoki (the Nix build's).
#[test]
fn the_read_only_probe_conforms() {
    let Ok(module) = std::env::var("CAKEYS_TEST_YUBIKEY_MODULE") else {
        eprintln!("skipping the_read_only_probe_conforms: CAKEYS_TEST_YUBIKEY_MODULE not set");
        return;
    };
    let w = Workdir::new("yubikey-probe");
    // No credentials: the read-only probe needs none, and the write probes must not get far.
    w.write_config(&format!(
        "[tokens.yubikey]\nmodule = \"{module}\"\ntokenLabel = \"{}\"\nscratch = true\n",
        yubikey_label(&module)
    ));
    let km = |args: &[&str]| run_within(&w.dir.join("keys.toml"), args, RUN_LIMIT);
    let write = km(&["probe", "--token", "yubikey", "--write"]);
    assert_eq!(code(&write), 17);
    assert!(stderr(&write).contains("Security Officer"));
    assert!(stderr(&write).contains("scratchId"));
    if !patched("the ykcs11/2.7 read-only diff") {
        return;
    }
    let out = km(&["probe", "--token", "yubikey", "--diff", "ykcs11/2.7"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}
