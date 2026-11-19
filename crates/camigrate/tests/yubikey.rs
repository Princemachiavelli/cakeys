//! docs/CAMIGRATE.md phase 5 on a real `YubiKey`, opt-in: a P-256 key made extractable on `SoftHSM` moves
//! through the host into retired PIV slot 95 (`CKA_ID` 18) as Security Officer (`piv-import`),
//! and `cakeys verify` proves possession there.
//!
//! Needs `CAKEYS_TEST_YUBIKEY_MODULE` (libykcs11.so), `CAKEYS_TEST_YUBIKEY_PIN` and
//! `CAKEYS_TEST_YUBIKEY_MGM` (file paths: the CLI reads them, never this test), and
//! `CAKEYS_TEST_MODULE` (`SoftHSM`, token `kmtest`, user PIN 1234). Skipped when any is unset,
//! so never in the Nix build. Slot 95 must be empty first: ykcs11 cannot erase a key, and the
//! import refuses an occupied slot (13) rather than replace what is there.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;
use std::path::Path;
use std::process::Output;
use std::time::Duration;

/// Each CLI run's bound: a touch or PIN prompt fails the test instead of hanging it (review
/// `yubikey.rs` F1).
const RUN_LIMIT: Duration = Duration::from_secs(60);

#[test]
fn a_key_moves_into_a_piv_slot_through_the_host() {
    let Some([yk, pin, mgm]) = yubikey_opted_in("a_key_moves_into_a_piv_slot_through_the_host") else { return };
    // SoftHSM is the harness's own, set for every run; opted in here, it is required.
    let soft = std::env::var("CAKEYS_TEST_MODULE").expect("CAKEYS_TEST_MODULE (SoftHSM) is required with the YubiKey");
    let turn = YubikeyTurn::take();
    let w = Workdir::new("yubikey-import");
    let config = w.dir.join("keys.toml");
    // Either binary on the test's keys.toml, bounded, its login checked (review `yubikey.rs` F5:
    // its own unbounded runner and directory set-up).
    let run = |bin: &Path, args: &[&str]| -> Output { turn.checked(Run::new(bin, &config).within(args, RUN_LIMIT)) };
    let s = open_session(&soft, "kmtest", "1234");
    s.clear(&["piv-import"]);
    drop(s);
    w.write_config(&format!(
        "[tokens.softhsm]\nmodule = \"{soft}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n\n{}\n\
         [objects.pv]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.pv-soft]\nobject = \"pv\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = true }}\n\
         tokens.softhsm = {{ locator = {{ CKA_LABEL = \"piv-import\" }}, origin = \"create\" }}\n\n\
         [specs.pv-yk]\nobject = \"pv\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.yubikey = {{ locator = {{ CKA_ID = \"18\" }}, origin = \"import\" }}\n",
        w.dir.join("pin").display(),
        yubikey_token(&yk, &pin, &mgm, "")
    ));
    let (cakeys, camigrate) = (sibling("cakeys"), Path::new(BIN));
    let o = run(&cakeys, &["create", "--spec", "pv-soft", "--token", "softhsm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let mv = ["migrate", "pv", "--from", "softhsm", "--to", "yubikey", "--allow-host-plaintext"];
    let o = run(camigrate, &[&mv[..], &["--dry-run", "--json"]].concat());
    let plan: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(
        (plan["plans"][0]["method"].as_str(), plan["plans"][0]["ready"].as_bool()),
        (Some("piv-import"), Some(true)),
        "{plan}"
    );
    let o = run(camigrate, &mv);
    // An earlier run's key still in the slot (review `yubikey.rs` F4): say how to empty it.
    assert_ne!(
        code(&o),
        13,
        "slot 95 is occupied, by an earlier run's key or another: wipe it first (`ykman piv keys delete 95`, or \
         scripts/coverage-full.sh with CAKEYS_YUBIKEY_WIPE_95=1): {}",
        stderr(&o)
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let origin = &w.lock()["realisations"]["pv-yk"]["yubikey"]["provenance"]["origin"];
    assert_eq!((origin["method"].as_str(), origin["exposure"].as_str()), (Some("piv-import"), Some("host")));
    let o = run(&cakeys, &["verify", "--spec", "pv-yk", "--token", "yubikey"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // Again, into the now occupied slot under another lock: refused before anything is written.
    // The source key is still on SoftHSM: the new lock records it (`create` refuses a key that is
    // there and not pinned, 19).
    std::fs::remove_file(w.dir.join("keys.lock")).unwrap();
    let o = run(&cakeys, &["lock", "--spec", "pv-soft", "--token", "softhsm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let before = std::fs::read(w.dir.join("keys.lock")).unwrap();
    let o = run(camigrate, &mv);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    // The lock as it was (review `yubikey.rs` F3: the exit alone was checked).
    assert_eq!(std::fs::read(w.dir.join("keys.lock")).unwrap(), before, "the refused move changed the lock");
}
