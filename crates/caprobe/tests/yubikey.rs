//! caprobe against a real `YubiKey` (PIV, through ykcs11), opt-in; `cakeys`' yubikey suite
//! describes the device's slots and the environment.
//!
//! Needs `CAKEYS_TEST_YUBIKEY_MODULE` (path to libykcs11.so); the write probe also
//! `CAKEYS_TEST_YUBIKEY_PIN` and `CAKEYS_TEST_YUBIKEY_MGM` (paths to files holding the PIV PIN
//! and the admin credential). Skipped when they are unset — never in the Nix build — and the
//! secrets are only ever read by caprobe from these paths. The write probe replaces only retired
//! slot 94 (`CKA_ID` 17, `scratchId`). Opted in, both need the patched cryptoki
//! (scripts/local-tests.sh, `nix run .#coverage-full`): a plain cargo build fails, naming the
//! patch.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;
use std::time::Duration;

/// The write probe generates every curve and RSA size it tries in one run (74 s measured on a
/// `YubiKey` 5.7.4, RSA-4096 included).
const PROBE_LIMIT: Duration = Duration::from_secs(300);
/// Every other run: a touch or PIN prompt would hang it, so the bound turns one into a failure.
const RUN_LIMIT: Duration = Duration::from_secs(60);

/// The committed ykcs11/2.7 profile is probe output (docs/CAPROBE.md): a fresh write
/// probe in the scratch slot conforms, and regenerating the file changes no byte — its
/// `[migration]` claims and `[manual]` findings preserved. A slot holding anything but the probe's
/// own certificate (and the slot's attestation) is refused before anything is written: empty
/// slot 94 once after a run that stopped part way, or one from before the probe marked its slot
/// (the reference suite and crates/ykcs11/src/lib.rs cover the rules). Another firmware, or a device not in
/// FIPS-approved mode, drifts by design (exit 15, the rows named): probe it and record a new
/// pair.
#[test]
fn the_write_probe_conforms_and_regenerates_the_committed_profile() {
    let Some([module, pin, mgm]) = yubikey_opted_in("the write probe") else { return };
    // Opted in, an unpatched build fails rather than passing with nothing compared: it drops
    // mechanisms it cannot name (review ftpm.rs F1). Run through scripts/local-tests.sh.
    cryptoki_hmac_types_fixed(true);
    let turn = YubikeyTurn::take();
    let w = Workdir::new("yubikey_write_probe");
    w.write_config(&yubikey_token(&module, &pin, &mgm, "probe = { scratchId = \"17\" }"));
    let config = w.dir.join("keys.toml");
    // The shared conformance check: one write probe, which diffs and regenerates in the same run
    // (review yubikey.rs F2: two, each every curve and RSA size on the device). Hand findings
    // belong in the profile's [manual].
    assert_profile_conforms(
        |args| turn.checked(run_within(&config, args, PROBE_LIMIT)),
        "yubikey",
        "ykcs11/2.7",
        "modules/ykcs11/2.7.toml",
        &w.dir.join("profile.toml"),
    );
}

/// The read-only probe of the device here (docs/CAPROBE.md D10): ykcs11/2.7's match keys,
/// advertisement and reported RSA range are what this `YubiKey` shows, and the write probes are
/// refused without a scratch slot — `probe = { scratch = true }` cannot mark a device that holds real keys
/// beside it. Needs only `CAKEYS_TEST_YUBIKEY_MODULE`: no PIN, nothing written. The diff needs
/// the patched cryptoki (the Nix build's); an unpatched build fails.
#[test]
fn the_read_only_probe_conforms() {
    let Ok(module) = std::env::var("CAKEYS_TEST_YUBIKEY_MODULE") else {
        skip("the_read_only_probe_conforms", YUBIKEY_OPT_IN.require, "CAKEYS_TEST_YUBIKEY_MODULE not set");
        return;
    };
    let w = Workdir::new("yubikey-probe");
    // No credentials: the read-only probe needs none, and the write probes must not get far.
    w.write_config(&format!(
        "[tokens.yubikey]\nmodule = \"{module}\"\ntokenLabel = \"{}\"\nprobe = {{ scratch = true }}\n",
        yubikey_label(&module)
    ));
    let km = |args: &[&str]| run_within(&w.dir.join("keys.toml"), args, RUN_LIMIT);
    let write = km(&["probe", "--token", "yubikey", "--write-probes", "--rsa-max-bits", "4096"]);
    assert_eq!(code(&write), 17, "{}", stderr(&write));
    assert!(stderr(&write).contains("Security Officer"), "{}", stderr(&write));
    assert!(stderr(&write).contains("scratchId"), "{}", stderr(&write));
    cryptoki_hmac_types_fixed(true);
    let out = km(&["probe", "--token", "yubikey", "--diff", "ykcs11/2.7"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
}
