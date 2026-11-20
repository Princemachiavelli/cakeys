//! Tokens and credentials: opening a token as named, PIN sources, the SO credential, PIN
//! counters and provider detection.

use super::*;

/// The provider is detected from `C_GetInfo`, or named in keys.toml; the lock's observation
/// records which handled the realisation.
#[test]
fn provider_is_detected_or_named() {
    let Some(e) = env("provider") else { return };
    e.config(EC.replace("ec-lifecycle", "provider").as_str());
    let lock = ["lock", "--spec", "signing-soft", "--token", "ref", "--update-lock"];
    let provider = || e.observation("signing-soft", "ref")["provider"].as_str().unwrap().to_owned();
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 0);
    assert_eq!(provider(), REF.provider, "auto-detected from C_GetInfo");
    let path = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let named =
        |p: &str| text.replacen("tokenLabel = \"kmtest\"", &format!("tokenLabel = \"kmtest\"\nprovider = \"{p}\""), 1);
    std::fs::write(&path, named("generic")).unwrap();
    assert_eq!(e.code(&lock), 0);
    assert_eq!(provider(), "generic", "explicit choice wins");
    std::fs::write(&path, named("nope")).unwrap();
    assert_eq!(e.code(&["validate"]), 17);
    assert_eq!(e.code(&lock), 17);
}

/// What opening a token refuses before any object is touched: a PIN from an environment
/// variable that is not set (16), and a label that two tokens carry (12).
#[test]
fn tokens_that_cannot_be_opened_as_named_are_refused() {
    let Some(e) = env("token-open") else { return };
    let body = EC.replace("ec-lifecycle", "token-open");
    e.write_config(&format!(
        "{}[tokens.env-pin]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinEnv = \"CAKEYS_TEST_UNSET_PIN\"\n\n{}",
        reference_tokens(&e.module, &e.dir),
        e.module,
        body.replace(
            "tokens.ref = ",
            "tokens.env-pin = { locator = { CKA_LABEL = \"token-open\" }, origin = \"adopt\" }\ntokens.ref = "
        ),
    ));
    let o = e.km(&["lock", "--spec", "signing-soft", "--token", "env-pin", "--no-update-lock"]);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("env var CAKEYS_TEST_UNSET_PIN not set"), "{}", stderr(&o));

    // A second token labelled like the first, in a slot the module keeps free (SoftHSM does;
    // kryoptic has the slots its configuration lists).
    let ctx = Module::open(&e.module);
    let free = ctx.get_all_slots().unwrap().into_iter().find(|slot| {
        ctx.get_slot_info(*slot).unwrap().token_present() && !ctx.get_token_info(*slot).unwrap().token_initialized()
    });
    assert_eq!(free.is_some(), REF.provider == "softhsm");
    if let Some(slot) = free {
        let serial_of = |info: cryptoki::slot::TokenInfo| info.serial_number().trim().to_owned();
        let first = ctx
            .get_slots_with_token()
            .unwrap()
            .into_iter()
            .map(|s| ctx.get_token_info(s).unwrap())
            .find(|i| i.label() == "kmtest" && i.token_initialized())
            .map(serial_of)
            .unwrap();
        ctx.init_token(slot, &AuthPin::new("5678".into()), "kmtest").unwrap();
        let second = serial_of(ctx.get_token_info(slot).unwrap());
        drop(ctx);
        let o = e.km(&["lock", "--spec", "signing-soft", "--token", "ref", "--no-update-lock"]);
        assert_eq!(code(&o), 12, "{}", stderr(&o));
        let said = stderr(&o);
        assert!(said.contains("several tokens labelled 'kmtest'") && said.contains("tokenSerial"), "{said}");
        assert!(said.contains(&format!("'{first}'")) && said.contains(&format!("'{second}'")), "{said}");
        // tokenSerial names one of them: the key is looked for there (and is absent: 11).
        let config = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
        e.write_config(&config.replacen("[tokens.ref]\n", &format!("[tokens.ref]\ntokenSerial = \"{first}\"\n"), 1));
        let o = e.km(&["lock", "--spec", "signing-soft", "--token", "ref", "--no-update-lock"]);
        assert_eq!(code(&o), 11, "{}", stderr(&o));
    }
}

/// `pinFile = "$NAME"` reads the pin file's path from the environment when the PIN is read:
/// unset, `validate` (which opens no token) still passes and a verb that logs in is invalid (17)
/// naming the variable; set, the PIN loads and a private-key `lock` works.
#[test]
fn pin_file_path_can_come_from_the_environment() {
    let Some(e) = env("pin-env") else { return };
    std::fs::write(
        e.dir.join("keys.toml"),
        format!(
            "[tokens.ref]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"$KM_E2E_PIN\"\n\n{}",
            e.module,
            EC.replace("ec-lifecycle", "pin-env")
        ),
    )
    .unwrap();
    // Unset: `validate` touches no token, so it needs no PIN; a verb that logs in is refused,
    // naming the variable.
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = e.km(&["create", "--spec", "signing-soft", "--token", "ref", "--update-lock"]);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    assert!(stderr(&o).contains("KM_E2E_PIN"), "{}", stderr(&o));
    // Set: the pin file loads, the login works, the private key is made and realised.
    let pin = e.dir.join("pin");
    let o = e.km_env(&["create", "--spec", "signing-soft", "--token", "ref", "--update-lock"], &[("KM_E2E_PIN", &pin)]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(e.lock()["realisations"]["signing-soft"]["ref"].is_table());
}

/// The admin credential (`soCredentialFile`/`soCredentialEnv`) is read only by a step that needs the
/// Security Officer: ykcs11's create and delete, and `camigrate transport --trusted` (docs/CAMIGRATE.md
/// D2). `SoftHSM` creates keys as the user, so a create never reads it: a credential file that
/// does not exist is no error. Without a user PIN to return to, it is invalid at load.
#[test]
fn admin_credential_is_read_only_by_security_officer_steps() {
    let Some(e) = env("mgm-key") else { return };
    let pin = e.dir.join("pin");
    let toml = |extra: &str| {
        format!(
            "[tokens.ref]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\n{extra}\n\n{}",
            e.module,
            EC.replace("ec-lifecycle", "mgm-key")
        )
    };
    let missing = e.dir.join("never-read");
    // The key is made under the first credential; under the second it is there and pinned, and
    // `create` verifies it without the credential either.
    for admin in
        [format!("soCredentialFile = \"{}\"", missing.display()), "soCredentialEnv = \"KM_E2E_NEVER_SET\"".to_owned()]
    {
        std::fs::write(e.dir.join("keys.toml"), toml(&format!("pinFile = \"{}\"\n{admin}", pin.display()))).unwrap();
        for (verb, exit) in [("create", 0), ("resolve", 0)] {
            let o = e.km(&[verb, "--spec", "signing-soft", "--token", "ref"]);
            assert_eq!(code(&o), exit, "{admin} {verb}: {}", stderr(&o));
        }
    }
    // No user PIN: invalid at load.
    std::fs::write(e.dir.join("keys.toml"), toml(&format!("soCredentialFile = \"{}\"", missing.display()))).unwrap();
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 17);
    assert!(stderr(&o).contains("needs a user PIN"));
}

/// Resets the user PIN as the SO when dropped (`C_InitPIN` clears the counters and unlocks it).
/// Each test has a token set of its own (nix/test-tokens.sh), so this matters only to a run that
/// shares one, plain `cargo test`: a test that spends PIN tries puts them back, whatever happens
/// in it.
struct ResetPin<'a>(&'a Pkcs11, cryptoki::slot::Slot);

impl ResetPin<'_> {
    fn reset(&self) -> cryptoki::error::Result<()> {
        let s = self.0.open_rw_session(self.1)?;
        s.login(cryptoki::session::UserType::So, Some(&AuthPin::new("5678".into())))?;
        s.init_pin(&AuthPin::new("1234".into()))
    }
}

impl Drop for ResetPin<'_> {
    /// Says why it could not, never panics: it runs while a failed test unwinds, and a second
    /// panic aborts the process, losing the first one's message (review tokens.rs F1).
    fn drop(&mut self) {
        if let Err(err) = self.reset() {
            eprintln!("could not reset the user PIN of slot {}: {err}", self.1);
        }
    }
}

/// A [`ResetPin`] that cannot reset says so and returns; the test's own failure stays the one
/// reported.
#[test]
fn a_pin_reset_that_fails_does_not_panic() {
    let Some(e) = env("pin-reset-fails") else { return };
    let ctx = Module::open(&e.module);
    let nowhere = cryptoki::slot::Slot::try_from(0xdead_u64).unwrap();
    let guard = ResetPin(&ctx, nowhere);
    assert!(guard.reset().is_err(), "slot 0xdead exists");
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(guard))).is_ok());
}

/// One module named two ways — its path and a symlink to it — is one library in this process:
/// both holders share its context (review common/mod.rs F4). Keyed by the name, the second
/// initialized it again and failed.
#[test]
fn a_module_named_two_ways_is_held_once() {
    let Some(e) = env("module-two-names") else { return };
    let link = e.dir.join("linked-module.so");
    std::os::unix::fs::symlink(&e.module, &link).unwrap();
    let direct = open_session(&e.module, "kmtest", "1234");
    let linked = open_session(link.to_str().unwrap(), "kmtest", "1234");
    assert!(direct.find_objects(&[]).is_ok() && linked.find_objects(&[]).is_ok());
}

/// The PIN counters a module reports (M2), after wrong PINs another program sent: a login that
/// failed since the last success is a warning; with one try left, cakeys refuses to spend it on
/// a PIN file that may be wrong (16), and a locked PIN is unavailable (16). `SoftHSM` reports only
/// the first; kryoptic all three (count-low after 6 failures, final try after 9, locked at 10).
#[test]
fn pin_counters_stop_cakeys_before_it_spends_a_try() {
    let Some(e) = env("pin-counters") else { return };
    e.config(&EC.replace("ec-lifecycle", "pin-counters"));
    let ctx = Module::open(&e.module);
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().label() == "kmtest")
        .unwrap();
    let _reset = ResetPin(&ctx, slot);
    let fail_until = |done: &dyn Fn(&cryptoki::slot::TokenInfo) -> bool| {
        for _ in 0..12 {
            if done(&ctx.get_token_info(slot).unwrap()) {
                return true;
            }
            let s = ctx.open_ro_session(slot).unwrap();
            assert!(s.login(cryptoki::session::UserType::User, Some(&AuthPin::new("0000".into()))).is_err());
        }
        done(&ctx.get_token_info(slot).unwrap())
    };
    let r = ["create", "--spec", "signing-soft", "--token", "ref", "--no-update-lock"];
    assert!(fail_until(&|t| t.user_pin_count_low()));
    let o = e.km(&r);
    assert_eq!(code(&o), 18, "{}", stderr(&o));
    assert!(stderr(&o).contains("a user PIN login failed since the last success"), "{}", stderr(&o));
    if REF.provider != "kryoptic" {
        eprintln!("{}: reports only the first counter; kryoptic's suite checks the others", REF.provider);
        return;
    }
    assert!(fail_until(&|t| t.user_pin_final_try()));
    let o = e.km(&r);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("one user PIN try is left"), "{}", stderr(&o));
    assert!(ctx.get_token_info(slot).unwrap().user_pin_final_try(), "cakeys spent the last try");
    assert!(fail_until(&|t| t.user_pin_locked()));
    let o = e.km(&r);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("the user PIN is locked"), "{}", stderr(&o));
}
