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
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn run(bin: &Path, dir: &Path, args: &[&str]) -> Output {
    let out = Command::new(bin)
        .env_remove("NIX_BUILD_TOP")
        .env_remove("IN_NIX_SHELL")
        .arg("--config")
        .arg(dir.join("keys.toml"))
        .args(args)
        .output()
        .unwrap();
    eprintln!("$ {} {}\n  exit={:?}\n  {}", bin.display(), args.join(" "), out.status.code(), stderr(&out).trim());
    out
}

#[test]
fn a_key_moves_into_a_piv_slot_through_the_host() {
    let vars =
        ["CAKEYS_TEST_YUBIKEY_MODULE", "CAKEYS_TEST_YUBIKEY_PIN", "CAKEYS_TEST_YUBIKEY_MGM", "CAKEYS_TEST_MODULE"];
    let Ok([yk, pin, mgm, soft]) =
        vars.map(std::env::var).into_iter().collect::<Result<Vec<_>, _>>().map(|v| <[String; 4]>::try_from(v).unwrap())
    else {
        eprintln!("skipping: {} not all set", vars.join(", "));
        return;
    };
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("yubikey-import");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    let s = open_session(&soft, "kmtest", "1234");
    s.clear(&["piv-import"]);
    drop(s);
    let config = format!(
        "[tokens.softhsm]\nmodule = \"{soft}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n\n{}\n\
         [objects.pv]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\ncreateOn = \"softhsm\"\n\n\
         [specs.pv-soft]\nobject = \"pv\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = true }}\n\
         tokens.softhsm = {{ locator = {{ CKA_LABEL = \"piv-import\" }}, autoCreate = true }}\n\n\
         [specs.pv-yk]\nobject = \"pv\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.yubikey = {{ locator = {{ CKA_ID = \"18\" }} }}\n",
        dir.join("pin").display(),
        yubikey_token(&yk, &pin, &mgm, "")
    );
    std::fs::write(dir.join("keys.toml"), config).unwrap();
    let (cakeys, camigrate) = (sibling("cakeys"), PathBuf::from(BIN));
    let o = run(&cakeys, &dir, &["realise", "pv-soft", "--token", "softhsm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let mv = ["migrate", "pv", "--from", "softhsm", "--to", "yubikey", "--allow-host-plaintext"];
    let o = run(&camigrate, &dir, &[&mv[..], &["--dry-run", "--json"]].concat());
    let plan: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(
        (plan["plans"][0]["method"].as_str(), plan["plans"][0]["ready"].as_bool()),
        (Some("piv-import"), Some(true)),
        "{plan}"
    );
    let o = run(&camigrate, &dir, &mv);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(dir.join("keys.lock")).unwrap()).unwrap();
    let origin = &lock["realisations"]["pv-yk"]["yubikey"]["provenance"]["origin"];
    assert_eq!((origin["method"].as_str(), origin["exposure"].as_str()), (Some("piv-import"), Some("host")));
    let o = run(&cakeys, &dir, &["verify", "pv-yk", "--token", "yubikey"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // Again, into the now occupied slot under another lock: refused before anything is written.
    std::fs::remove_file(dir.join("keys.lock")).unwrap();
    let o = run(&cakeys, &dir, &["realise", "pv-soft", "--token", "softhsm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = run(&camigrate, &dir, &mv);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
}
