//! Tests of caprobe against a real `YubiKey` (PIV, through ykcs11), which run only when they are
//! opted in. The yubikey suite of `cakeys` describes the device's slots and the environment.
//!
//! The tests need `CAKEYS_TEST_YUBIKEY_MODULE` (the path to libykcs11.so). The write probe also
//! needs `CAKEYS_TEST_YUBIKEY_PIN` and `CAKEYS_TEST_YUBIKEY_MGM` (the paths to files that hold
//! the PIV PIN and the admin credential). The tests are skipped when these variables are unset,
//! so they never run in the Nix build, and only caprobe reads the secrets, from these paths. The
//! write probe replaces only the retired slot 94 (`CKA_ID` 17, `scratchId`). When they are opted
//! in, both tests need the patched cryptoki (scripts/local-tests.sh, `nix run .#coverage-full`):
//! a plain cargo build fails and names the patch.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;
use std::time::Duration;

/// The time limit of the write probe, which generates every curve and RSA size that it tries in
/// one run (74 s measured on a `YubiKey` 5.7.4, including RSA-4096).
const PROBE_LIMIT: Duration = Duration::from_secs(300);
/// The time limit of every other run. A touch or PIN prompt would make the run wait forever, so
/// the limit turns such a prompt into a failure.
const RUN_LIMIT: Duration = Duration::from_secs(60);

/// The committed ykcs11/2.7 profile is probe output (docs/CAPROBE.md). A new write probe in the
/// scratch slot conforms to it, and regenerating the file changes no byte, with its
/// `[migration]` claims and `[manual]` findings kept. A slot that holds anything other than the
/// probe's own certificate (and the slot's attestation) is refused before anything is written.
/// Empty slot 94 once after a run that stopped part way, or after a run from before the probe
/// marked its slot (the reference suite and crates/ykcs11/src/lib.rs cover the rules). Another
/// firmware, or a device that is not in FIPS-approved mode, drifts by design (exit code 15, with
/// the rows named). In that case, probe the device and record a new pair.
#[test]
fn the_write_probe_conforms_and_regenerates_the_committed_profile() {
    let Some([module, pin, mgm]) = yubikey_opted_in("the write probe") else { return };
    // When the test is opted in, an unpatched build fails instead of passing with nothing
    // compared, because an unpatched build drops the mechanisms that it cannot name (review
    // ftpm.rs F1). Run the test through scripts/local-tests.sh.
    cryptoki_hmac_types_fixed(true);
    let turn = YubikeyTurn::take();
    let w = Workdir::new("yubikey_write_probe");
    w.write_config(&yubikey_token(&module, &pin, &mgm, "probe = { scratchId = \"17\" }"));
    let config = w.dir.join("keys.toml");
    // The shared conformance check runs one write probe, which compares and regenerates in the
    // same run. (Review yubikey.rs F2: there were two probes, and each generated every curve and
    // RSA size on the device.) Findings made by hand belong in the profile's [manual].
    assert_profile_conforms(
        |args| turn.checked(run_within(&config, args, PROBE_LIMIT)),
        "yubikey",
        "ykcs11/2.7",
        "modules/ykcs11/2.7.toml",
        &w.dir.join("profile.toml"),
    );
}

/// The read-only probe of the attached device (docs/CAPROBE.md D10). The match keys,
/// advertisement and reported RSA range of ykcs11/2.7 are what this `YubiKey` shows, and the
/// write probes are refused without a scratch slot, because `probe = { scratch = true }` cannot
/// mark a device that also holds real keys. The test needs only `CAKEYS_TEST_YUBIKEY_MODULE`:
/// no PIN is used and nothing is written. The diff needs the patched cryptoki (as the Nix build
/// has it), and an unpatched build fails.
#[test]
fn the_read_only_probe_conforms() {
    let Ok(module) = std::env::var("CAKEYS_TEST_YUBIKEY_MODULE") else {
        skip("the_read_only_probe_conforms", YUBIKEY_OPT_IN.require, "CAKEYS_TEST_YUBIKEY_MODULE not set");
        return;
    };
    let w = Workdir::new("yubikey-probe");
    // The configuration has no credentials, because the read-only probe needs none and the
    // write probes must be refused early.
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
