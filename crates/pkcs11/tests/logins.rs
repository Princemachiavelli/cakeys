//! Logins a token cannot check again: a refused SO login is not tried a second time (review
//! 2026-11-23 B-11), and an "already logged in" answer validates a PIN only when this process
//! logged in with it (B-12). Skipped without `CAKEYS_TEST_MODULE`.

use cakeys_core::config::TokenCfg;
use cakeys_pkcs11::token::Access;
use cakeys_pkcs11::{ChainTime, Registry, Token};

/// The reference module, or `None` (and a note) where the harness sets none.
fn module() -> Option<String> {
    let Ok(module) = std::env::var("CAKEYS_TEST_MODULE") else {
        assert!(std::env::var("CAKEYS_TEST_REQUIRE").is_err(), "CAKEYS_TEST_MODULE is required");
        eprintln!("skipping logins: CAKEYS_TEST_MODULE is not set");
        return None;
    };
    cakeys_profile::Set::activate_embedded().unwrap();
    Some(module)
}

/// A token of the reference module with this user PIN.
fn open(module: &str, dir: &std::path::Path, pin: &str) -> cakeys_core::Result<Token> {
    let file = dir.join(format!("pin-{pin}"));
    std::fs::write(&file, format!("{pin}\n")).unwrap();
    let cfg: TokenCfg =
        toml::from_str(&format!("module = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n", file.display()))
            .unwrap();
    Token::open("ref", &cfg, None, &Registry::new(), Access::Read, ChainTime::Unchecked)
}

/// The PKCS #11 login state is the process's: a second token of the slot is told "already
/// logged in" whatever PIN it gives, so a wrong one is refused rather than kept, and the same one
/// is accepted.
#[test]
fn an_already_logged_in_slot_checks_the_pin_against_the_first_login() {
    let Some(module) = module() else { return };
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cakeys-pkcs11-already-logged-in");
    std::fs::create_dir_all(&dir).unwrap();
    let first = open(&module, &dir, "1234").unwrap();
    let wrong = open(&module, &dir, "9999").map(drop).unwrap_err().to_string();
    assert!(wrong.contains("already logged in by another session"), "{wrong}");
    open(&module, &dir, "1234").unwrap_or_else(|e| panic!("the same PIN, beside the first: {e}"));
    drop(first);
}

#[test]
fn a_refused_so_credential_is_not_tried_again() {
    let Some(module) = module() else { return };
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cakeys-pkcs11-so-login");
    std::fs::create_dir_all(&dir).unwrap();
    let (pin, so) = (dir.join("pin"), dir.join("so"));
    std::fs::write(&pin, "1234\n").unwrap();
    std::fs::write(&so, "not-the-so-pin\n").unwrap();
    let cfg: TokenCfg = toml::from_str(&format!(
        "module = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nsoCredentialFile = \"{}\"\n",
        pin.display(),
        so.display()
    ))
    .unwrap();
    let tok = Token::open("ref", &cfg, None, &Registry::new(), Access::Write, ChainTime::Unchecked).unwrap();
    let ran = std::cell::Cell::new(0);
    let step = || {
        ran.set(ran.get() + 1);
        Ok(())
    };
    let first = tok.as_so("a step", step).unwrap_err().to_string();
    assert!(first.contains("soCredentialFile"), "the first try logs in and is refused: {first}");
    let second = tok.as_so("a step", step).unwrap_err().to_string();
    assert!(second.contains("refused earlier in this run"), "the second is refused before a login: {second}");
    assert_eq!(ran.get(), 0, "no step ran");
}
