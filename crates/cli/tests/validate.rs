//! The static gate (docs/CAPROBE.md): `validate` checks each spec's needs against its
//! token's capability profiles, resolved from keys.toml and the lock — no token, no module,
//! no environment needed, so these run everywhere.

mod common;

use common::*;
use std::process::Output;

const BIN: &str = env!("CARGO_BIN_EXE_cakeys");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn validate(config: &str) -> Output {
    tool(BIN).arg("--config").arg(format!("{FIXTURES}/{config}")).arg("validate").output().unwrap()
}

/// One failed `YubiKey` login stops every later one (review yubikey.rs F1; the PIN has three
/// tries): a run that reports any `CKR_PIN_*` fails its test and latches the device off, and the
/// next test's turn refuses before it logs in. Holding the turn, no `YubiKey` test runs while
/// this one sets and clears the latch; no device is needed.
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
    // Other failures are the test's own: no latch.
    assert!(
        catch_unwind(AssertUnwindSafe(|| turn.checked(ran("error: unavailable: C_Sign: CKR_DEVICE_ERROR")))).is_ok()
    );
    assert!(!yubikey_latch().exists());
    let failed = catch_unwind(AssertUnwindSafe(|| turn.checked(ran("error: unavailable: C_Login: CKR_PIN_INCORRECT"))));
    let latched = std::fs::read_to_string(yubikey_latch());
    let refused = catch_unwind(AssertUnwindSafe(|| turn.refuse_if_latched()));
    std::fs::remove_file(yubikey_latch()).unwrap();
    assert!(failed.is_err(), "a failed login passed its test");
    assert_eq!(latched.unwrap(), "CKR_PIN_INCORRECT\n");
    assert!(refused.is_err(), "the next test would log in again");
    turn.refuse_if_latched();
}

/// No test hands a tool the developer's own keys.toml or lock (review common/mod.rs F1): under
/// the per-test runner (nix/test-tokens.sh, which sets `CAKEYS_TOKEN_TEMPLATE`) no test process
/// has them, and every run started by [`tool`] has them removed again.
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

/// An opted-in suite never passes with nothing compared (review ftpm.rs F1): every test that
/// needs the patched cryptoki asks [`cryptoki_hmac_types_fixed`], whose `require` is `true` or
/// a `*_REQUIRE` variable, never a literal `false`, and none keeps its own check that skips.
#[test]
fn no_opted_in_suite_skips_an_unpatched_build() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut found = vec![];
    for krate in std::fs::read_dir(crates).unwrap() {
        let tests = krate.unwrap().path().join("tests");
        let Ok(files) = std::fs::read_dir(&tests) else { continue };
        let mut stack: Vec<_> = files.map(|f| f.unwrap().path()).collect();
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                stack.extend(std::fs::read_dir(&path).unwrap().map(|f| f.unwrap().path()));
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                let own = format!("{}0x2c", "SHA384_HMAC) == ");
                if text.contains(&format!("{}(false)", "cryptoki_hmac_types_fixed"))
                    || (text.contains(&own) && !path.ends_with("common/mod.rs"))
                {
                    found.push(path);
                }
            }
        }
    }
    assert!(found.is_empty(), "these skip an unpatched build: {found:?}");
}

/// docs/CAPROBE.md's two static-gate cases, each refused (15) naming the profile that decided
/// it: kryoptic asked to generate secp256k1 (`origin = "create"`), and a `kw` commitment through
/// p11-kit. A token nothing is known about is skipped with a note.
#[test]
fn a_profile_no_refuses_and_names_its_profile() {
    let out = validate("gate.toml");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code(&out), 15, "{err}");
    assert!(
        err.contains("'k1' (spec 'k1-kry') on token 'kry': token 'kry' cannot") && err.contains("no — kryoptic/1.5"),
        "{err}"
    );
    assert!(err.contains("2 targets need what the capability profiles say"), "{err}");
    assert!(err.contains("'aes' (spec 'aes-kw')") && err.contains("CKM_AES_KEY_WRAP: no — p11-kit/0.26"), "{err}");
    assert!(err.contains("token 'unknown': no provider named"), "{err}");
    // What the profiles allow passes silently: P-256 on kryoptic.
    assert!(!err.contains("'p256' (spec 'p256-kry') on token 'kry'"), "{err}");
}

/// The lock's recorded module and token are the profile source when keys.toml names no
/// provider: the token's observation resolves softhsm/2.7, whose rows allow every spec
/// (generation it does not record is a note, never a refusal, and asked only of a pair whose
/// origin is `create` and whose object the lock does not pin). The fixture's three `SoftHSM`
/// realisations name three observations, so which is current is not known: a note naming
/// `lock`, and the token is skipped. With one observation it resolves.
#[test]
fn the_lock_resolves_a_token_keys_toml_does_not_name() {
    let out = validate("keys.toml");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code(&out), 0, "{err}");
    assert!(err.contains("token 'softhsm' were recorded with 3 different observations"), "{err}");
    assert!(err.contains("`lock` them") && !err.contains("softhsm/2.7"), "{err}");

    let w = Workdir::new("validate-one-observation");
    // One object the lock does not pin yet, so `create` would make it there.
    let fresh = "\n[objects.fresh]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32\n\n\
                 [specs.fresh]\nobject = \"fresh\"\nattributes = { CKA_SIGN = true }\n\
                 tokens.softhsm = { locator = { CKA_LABEL = \"fresh\" }, origin = \"create\" }\n";
    w.write_config(&(std::fs::read_to_string(format!("{FIXTURES}/keys.toml")).unwrap() + fresh));
    let mut lock: toml::Value =
        toml::from_str(&std::fs::read_to_string(format!("{FIXTURES}/keys.lock")).unwrap()).unwrap();
    for spec in ["shared-sign", "shared-nosign"] {
        lock["realisations"][spec]["softhsm"].as_table_mut().unwrap().remove("observation");
    }
    std::fs::write(w.dir.join("keys.lock"), toml::to_string(&lock).unwrap()).unwrap();
    let out = w.km(&["validate"]);
    let err = stderr(&out);
    assert_eq!(code(&out), 0, "{err}");
    let fresh =
        "'fresh' (spec 'fresh') on token 'softhsm': generation not decided: unknown — module profile softhsm/2.7";
    assert!(err.contains(fresh), "{err}");
    // The lock pins every other object: `create` would make none of them, so no generation is asked.
    assert_eq!(err.lines().filter(|l| l.contains("generation")).count(), 1, "{err}");
}

/// What the gate refuses or leaves open, from keys.toml alone: a hash-bound HMAC key to
/// create (PKCS#11 has no mechanism for it) and an attestation the provider cannot make are
/// refused (15); a provider with no module profile (`generic`) leaves the generation undecided,
/// a note; so does a family whose profiles need the module's version to choose (`tpm2-pkcs11`,
/// whose module nobody has seen yet): one stands in without its hardware rows, never an
/// error; a layer the stack already holds (the binding layer) is not added twice. An adopted
/// key is never asked about generation. A build whose cryptoki maps the SHA-2 HMAC key types
/// wrongly refuses the HMAC key by its type before any profile is asked.
#[test]
fn the_gate_refuses_what_it_can_decide_and_says_what_it_cannot() {
    let w = Workdir::new("validate-gate-cases");
    let token = |name: &str, extra: &str| format!("[tokens.{name}]\ntokenLabel = \"{name}\"\n{extra}\n\n");
    let spec = |name: &str, object: &str, token: &str, extra: &str| {
        let origin = if extra.contains("origin") { "" } else { ", origin = \"create\"" };
        format!(
            "[specs.{name}]\nobject = \"{object}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.{token} = {{ locator = {{ CKA_LABEL = \"{name}\" }}{origin}{extra} }}\n\n"
        )
    };
    let ec = |name: &str| {
        format!("[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n")
    };
    let text = [
        token("soft", "provider = \"softhsm\"\nprofiles = [\"cryptoki/0.12\"]"),
        token("gen", "provider = \"generic\""),
        token("tpm", "provider = \"tpm2-pkcs11\""),
        token("yk", "provider = \"ykcs11\""),
        "[objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n".to_owned(),
        "[objects.mac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA384_HMAC\"\nvalueLen = 48\n\n".to_owned(),
        ec("soft"),
        ec("gen"),
        ec("tpm"),
        spec("mac-soft", "mac", "soft", ""),
        spec("p-soft", "soft", "soft", ", attestation = true"),
        spec("p-gen", "gen", "gen", ""),
        spec("p-tpm", "tpm", "tpm", ""),
        spec("aes-yk", "aes", "yk", ", origin = \"adopt\", attestation = true"),
    ]
    .concat();
    w.write_config(&text);
    let out = w.km(&["validate"]);
    let err = stderr(&out);
    assert_eq!(code(&out), 15, "{err}");
    let hmac = if cakeys_pkcs11::binding::patched() {
        "'mac' (spec 'mac-soft') on token 'soft': token 'soft' cannot do what mode 'commitment' needs \
         (CKM_SHA384_KEY_GEN: no — softhsm/2.7: not advertised)"
    } else {
        "CKK_SHA384_HMAC: this build's cryptoki maps it to CKK_SHA256_HMAC"
    };
    for line in [
        hmac,
        "opts into attestation, but provider 'softhsm' attests nothing on this module",
        "opts into attestation, but provider 'ykcs11' attests only [\"CKO_PRIVATE_KEY\", \"CKO_PUBLIC_KEY\"]",
        "validate: 'gen' (spec 'p-gen') on token 'gen': the profiles do not decide",
        "validate: 'tpm' (spec 'p-tpm') on token 'tpm': generation not decided",
    ] {
        assert!(err.contains(line), "expected {line:?} in\n{err}");
    }
}
