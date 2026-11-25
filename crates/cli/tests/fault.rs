//! `p11-fault` (`crates/p11-fault`, `docs/FAULT_SHIM.md`): the reference suite (`tests/reference/`)
//! through the shim in front of `SoftHSM` with no plan, which must pass as it does directly; a
//! client that is not cakeys (`pkcs11-tool`) through it; and what cakeys does when the module
//! fails a call.
//!
//! Needs what `tests/softhsm.rs` needs, plus `P11_FAULT_MODULE` naming `SoftHSM`, which the per-test
//! runner (nix/test-tokens.sh) sets, and `libp11_fault.so` built beside the test binaries.

mod common;
mod reference;

use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;
use std::fmt::Write as _;
use std::process::Command;

const REF: &common::Reference = &common::FAULT;

/// A test's directory with the reference tokens on the shim, a plan file and a trace file; `None`
/// (skipped) without `P11_FAULT_MODULE`.
fn faulted(name: &str, plan: &str) -> Option<(Workdir, std::path::PathBuf, std::path::PathBuf)> {
    suite_var(REF.module_var, REF.require_var, name)?;
    let w = Workdir::new(name);
    let (plan_path, trace) = (w.dir.join("plan.toml"), w.dir.join("trace.jsonl"));
    std::fs::write(&plan_path, plan).unwrap();
    w.write_config(&(reference_tokens(&fault_shim(), &w.dir) + &EC_SPEC.replace("NAME", name)));
    Some((w, plan_path, trace))
}

const EC_SPEC: &str = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                       [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
                       tokens.ref = { locator = { CKA_LABEL = \"NAME\" }, origin = \"create\" }\n";

/// The lines of the trace whose rule fired: a plan that matched nothing would pass a test for
/// the wrong reason.
fn fired(trace: &std::path::Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(trace).unwrap_or_default();
    text.lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|l| !l["rule"].is_null())
        .collect()
}

/// Any client loads the shim: `pkcs11-tool` lists the token through it, and under a plan that
/// fails `C_GetSlotList` it reports that return value.
#[test]
fn another_client_loads_the_shim_and_meets_its_plan() {
    let Some((_w, plan, trace)) =
        faulted("fault-any-client", "[[rule]]\nfn = \"C_GetSlotList\"\nrv = \"CKR_DEVICE_ERROR\"\n")
    else {
        return;
    };
    let list = |with_plan: bool| {
        let mut c = Command::new("pkcs11-tool");
        c.args(["--module", &fault_shim(), "--list-slots"]).env("P11_FAULT_TRACE", &trace);
        if with_plan {
            c.env("P11_FAULT_PLAN", &plan);
        }
        let o = c.output().expect("pkcs11-tool (opensc) on PATH");
        (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr))
    };
    let (ok, said) = list(false);
    assert!(ok && said.contains("kmtest"), "{said}");
    let (ok, said) = list(true);
    assert!(!ok && said.contains("CKR_DEVICE_ERROR"), "{said}");
    let fired = fired(&trace);
    assert_eq!((fired.len(), fired[0]["fn"].as_str()), (1, Some("C_GetSlotList")), "{fired:?}");
}

/// A copy named `libp11_fault-<tag>.so` reads only its own variables, so shims stack: a tagged
/// one in front of the untagged one in front of `SoftHSM` lists the token and traces through
/// both. A shim told to forward to itself says so and fails, where it used to wait for ever.
#[test]
fn tagged_copies_stack_and_a_shim_cannot_load_itself() {
    let Some((w, _, trace)) = faulted("fault-tagged", "") else { return };
    let tagged = w.dir.join("libp11_fault-outer.so");
    std::fs::copy(fault_shim(), &tagged).unwrap();
    let outer = w.dir.join("outer.jsonl");
    let list = |module: &std::path::Path, env: &[(&str, &std::ffi::OsStr)]| {
        let mut c = Command::new("pkcs11-tool");
        c.arg("--module").arg(module).arg("--list-slots").envs(env.iter().copied());
        let o = c.output().expect("pkcs11-tool (opensc) on PATH");
        (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr))
    };
    // The untagged P11_FAULT_MODULE (SoftHSM, from the runner) is the inner shim's; the outer
    // one forwards to the inner by its own variable.
    let (ok, said) = list(
        &tagged,
        &[
            ("P11_FAULT_MODULE_OUTER", fault_shim().as_ref()),
            ("P11_FAULT_TRACE_OUTER", outer.as_os_str()),
            ("P11_FAULT_TRACE", trace.as_os_str()),
        ],
    );
    assert!(ok && said.contains("kmtest"), "{said}");
    let lines = |p: &std::path::Path| std::fs::read_to_string(p).unwrap_or_default().lines().count();
    assert!(lines(&outer) > 0 && lines(&trace) > 0, "both shims trace: {} {}", lines(&outer), lines(&trace));
    // Untagged variables do not reach a tagged copy: without its own it forwards nowhere.
    let (ok, said) = list(&tagged, &[]);
    assert!(!ok && said.contains("P11_FAULT_MODULE_OUTER names no module"), "{said}");
    // A shim in front of itself fails at once with the reason.
    let (ok, said) = list(fault_shim().as_ref(), &[("P11_FAULT_MODULE", fault_shim().as_ref())]);
    assert!(!ok && said.contains("is this shim itself"), "{said}");
}

/// A module whose `C_DestroyObject` returns `CKR_OK` and destroys nothing (the shim answers
/// without forwarding): `delete` looks again, finds the key under its locator and says so
/// (`delete-kept`, 16), and the lock keeps the realisation, where it once removed it and exited
/// 22 (review 2026-11-24 B-13). The key is still there and still checks.
#[test]
fn a_delete_the_module_does_not_do_keeps_the_lock() {
    let plan = "[[rule]]\nfn = \"C_DestroyObject\"\nrv = \"CKR_OK\"\n";
    let Some((w, plan_path, trace)) = faulted("fault-destroy-kept", plan) else { return };
    assert_eq!(w.code(&["create", "--spec", "k", "--token", "ref"]), 22, "no plan: transparent");
    let lock = w.dir.join("keys.lock");
    let before = std::fs::read(&lock).unwrap();
    let o = w.km_env(
        &["delete", "--spec", "k", "--token", "ref"],
        &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)],
    );
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("still under its locator"), "{}", stderr(&o));
    assert!(fired(&trace).iter().any(|l| l["fn"].as_str() == Some("C_DestroyObject")), "the rule fired");
    assert_eq!(std::fs::read(&lock).unwrap(), before, "the lock keeps the realisation");
    assert_eq!(w.code(&["check", "--spec", "k", "--token", "ref"]), 0, "the key is there and checks");
}

/// A module whose `C_Login` returns `CKR_OK` and leaves the session public (the shim answers
/// without forwarding) hides every private object: `delete` read the key as absent and dropped
/// its realisation (22), `check` called it not found (11). The session's state is read after
/// every login, and a login it does not show is unavailable (16), the lock unchanged (review
/// 2026-11-24, lead-found through the Phase 2 design).
#[test]
fn a_login_the_session_does_not_show_is_unavailable() {
    let plan = "[[rule]]\nfn = \"C_Login\"\nrv = \"CKR_OK\"\n";
    let Some((w, plan_path, trace)) = faulted("fault-login-kept-public", plan) else { return };
    assert_eq!(w.code(&["create", "--spec", "k", "--token", "ref"]), 22, "no plan: transparent");
    let lock = w.dir.join("keys.lock");
    let before = std::fs::read(&lock).unwrap();
    for verb in [["delete", "--spec", "k", "--token", "ref"], ["check", "--spec", "k", "--token", "ref"]] {
        let o = w.km_env(&verb, &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)]);
        assert_eq!(code(&o), 16, "{verb:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("the session is not logged in"), "{verb:?}: {}", stderr(&o));
    }
    assert!(fired(&trace).iter().all(|l| l["fn"].as_str() == Some("C_Login")), "only the login lied");
    assert_eq!(std::fs::read(&lock).unwrap(), before, "the lock keeps the realisation");
    assert_eq!(w.code(&["check", "--spec", "k", "--token", "ref"]), 0, "the key is there and checks");
}

/// cakeys against a module that fails a call it should not: the failing call is named, the exit
/// is unavailable (16), and nothing is recorded. A login refused after the module accepted it
/// is the same. A proof's mechanism the module refuses for the key (`CKR_MECHANISM_INVALID`,
/// as a key policy the module does not report would) is unsupported instead (15), the opt-out
/// named.
#[test]
fn a_failing_module_call_is_unavailable() {
    let plan = "[[rule]]\nfn = \"C_FindObjects\"\nrv = \"CKR_DEVICE_ERROR\"\n\n\
                [[rule]]\nfn = \"C_Login\"\nwhen = \"after\"\nrv = \"CKR_PIN_INCORRECT\"\n";
    let Some((w, plan_path, trace)) = faulted("fault-module-fails", plan) else { return };
    assert_eq!(w.code(&["create", "--spec", "k", "--token", "ref"]), 22, "no plan: transparent");
    let o = w.km_env(
        &["check", "--spec", "k", "--token", "ref"],
        &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)],
    );
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    let said = stderr(&o);
    // Named by its constant, which the `YubiKey` suites' latch reads (`YubikeyTurn::checked`).
    assert!(said.contains("C_Login: CKR_PIN_INCORRECT"), "{said}");
    assert_eq!(failed_login(&said).as_deref(), Some("CKR_PIN_INCORRECT"), "{said}");
    assert_eq!(fired(&trace).last().unwrap()["fn"].as_str(), Some("C_Login"));
    // Logged in without the refusal, the search fails instead.
    let find_only = w.dir.join("find.toml");
    std::fs::write(&find_only, "[[rule]]\nfn = \"C_FindObjects\"\nrv = \"CKR_DEVICE_ERROR\"\n").unwrap();
    let o = w.km_env(
        &["check", "--spec", "k", "--token", "ref"],
        &[("P11_FAULT_PLAN", &find_only), ("P11_FAULT_TRACE", &trace)],
    );
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("C_FindObjects"), "{}", stderr(&o));
    assert_eq!(fired(&trace).last().unwrap()["rv"].as_str(), Some("CKR_DEVICE_ERROR"));
    let refused = w.dir.join("refused.toml");
    std::fs::write(&refused, "[[rule]]\nfn = \"C_SignInit\"\nrv = \"CKR_MECHANISM_INVALID\"\n").unwrap();
    let o = w.km_env(
        &["check", "--spec", "k", "--token", "ref"],
        &[("P11_FAULT_PLAN", &refused), ("P11_FAULT_TRACE", &trace)],
    );
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("refused to sign") && stderr(&o).contains("token-asserted"), "{}", stderr(&o));
    assert_eq!(fired(&trace).last().unwrap()["rv"].as_str(), Some("CKR_MECHANISM_INVALID"));
}

/// A token on the shim holding `k` (P-256, signs), `d` (P-256, derives), `r` (RSA, decrypts) and
/// `u` (RSA, unwraps), each realised and recorded with no plan, and beside each another key of
/// its kind under `<name>-other`, which no spec names.
fn lying(name: &str) -> Option<Workdir> {
    let real = suite_var(REF.module_var, REF.require_var, name)?;
    let w = Workdir::new(name);
    let key = |name: &str, ty: &str, usage: &str, binding: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\n{ty}\n\n[specs.{name}]\nobject = \"{name}\"\n\
             attributes = {{ {usage} = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{name}\" }}, origin = \"create\", binding = \"{binding}\" }}\n\n"
        )
    };
    let (ec, rsa) = ("keyType = \"CKK_EC\"\ncurve = \"secp256r1\"", "keyType = \"CKK_RSA\"\nmodulusBits = 2048");
    w.write_config(
        &[
            reference_tokens(&fault_shim(), &w.dir),
            key("k", ec, "CKA_SIGN", "pop-sign"),
            key("d", ec, "CKA_DERIVE", "pop-ecdh"),
            key("r", rsa, "CKA_DECRYPT", "pop-decrypt"),
            key("u", rsa, "CKA_UNWRAP", "pop-unwrap"),
            key("a", rsa, "CKA_ALWAYS_AUTHENTICATE = true, CKA_SIGN", "pop-sign"),
            key("new", ec, "CKA_SIGN", "pop-sign"),
        ]
        .concat(),
    );
    for spec in ["k", "d", "r", "u", "a"] {
        let o = w.km(&["create", "--spec", spec, "--token", "ref"]);
        assert_eq!(code(&o), 22, "{spec}, no plan: {}", stderr(&o));
    }
    // The other keys, made on the real module itself.
    let s = open_session(&real, "kmtest", "1234");
    let label = |name: &str| Attribute::Label(format!("{name}-other").into_bytes());
    for (name, usage) in [("k", Attribute::Sign(true)), ("d", Attribute::Derive(true))] {
        let public = [Attribute::Token(true), label(name), Attribute::EcParams(P256.to_vec())];
        s.generate_key_pair(&Mechanism::EccKeyPairGen, &public, &[Attribute::Token(true), label(name), usage]).unwrap();
    }
    for (name, usage) in [("r", Attribute::Decrypt(true)), ("u", Attribute::Unwrap(true))] {
        let public = [
            Attribute::Token(true),
            label(name),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![1, 0, 1]),
        ];
        let (_, private) = s
            .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public, &[Attribute::Token(true), label(name), usage])
            .unwrap();
        // The public key the module asserts for it (SoftHSM sets none, and takes any).
        let asserted = Attribute::PublicKeyInfo(oracle_spki(&s, &format!("{name}-other")));
        s.update_attributes(private, &[asserted]).unwrap();
    }
    Some(w)
}

/// What a lying module can and cannot make cakeys accept (docs/DESIGN.md §8.1), one lie per row:
/// the plan, the run, the exit and the reason. Each row's rule is shown fired in the trace.
#[test]
fn a_lying_module_is_refused() {
    let Some(w) = lying("fault-lies") else { return };
    let verify = |spec: &'static str| vec!["check", "--spec", spec, "--token", "ref"];
    // A run that writes the lock where it succeeds: the lie must not reach it (review fault.rs F1).
    let record = |spec: &'static str| vec!["lock", "--spec", spec, "--token", "ref"];
    let point = |change: &str| {
        format!("fn = \"C_GetAttributeValue\"\nof_label = \"k\"\nattribute = \"CKA_EC_POINT\"\n{change}")
    };
    let other =
        |function: &str, key: &str| format!("fn = \"{function}\"\nof_label = \"{key}\"\nuse_label = \"{key}-other\"");
    let cases: Vec<(String, Vec<&str>, i32, &str)> = vec![
        // What the token says of itself.
        (
            "fn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_WRITE_PROTECTED\"]".into(),
            vec!["create", "--spec", "new", "--token", "ref"],
            15,
            "is write-protected",
        ),
        ("fn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_USER_PIN_LOCKED\"]".into(), verify("k"), 16, "PIN is locked"),
        (
            "fn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_USER_PIN_FINAL_TRY\"]".into(),
            verify("k"),
            16,
            "one user PIN try is left",
        ),
        // The public key it shows: gone, malformed, cut short, or another key's.
        (point("drop = true"), verify("k"), 11, "exposes no key material"),
        (point("length = \"unavailable\""), verify("k"), 11, "exposes no key material"),
        (point("truncate = 10"), verify("k"), 13, "is not a P256 point"),
        (point("truncate = 10"), record("k"), 13, "is not a P256 point"),
        (point("from_label = \"k-other\""), verify("k"), 13, "proof of possession failed"),
        (point("from_label = \"k-other\""), record("k"), 13, "proof of possession failed"),
        // A policy attribute that is not what the spec declares.
        (
            "fn = \"C_GetAttributeValue\"\nof_label = \"k\"\nattribute = \"CKA_SIGN\"\nvalue = \"00\"".into(),
            verify("k"),
            13,
            "CKA_SIGN is false",
        ),
        // Another object under the locator.
        ("fn = \"C_FindObjects\"\nadd_label = \"k-other\"".into(), verify("k"), 12, "objects match locator"),
        ("fn = \"C_FindObjects\"\nadd_label = \"k-other\"".into(), record("k"), 12, "objects match locator"),
        // It shows one key and uses another: each proof of possession fails. SoftHSM unwraps
        // under the wrong key with CKR_GENERAL_ERROR, which says nothing of the key: unavailable.
        (other("C_SignInit", "k"), verify("k"), 13, "did not sign for the public key"),
        (other("C_DeriveKey", "d"), verify("d"), 13, "did not derive for the public key"),
        (other("C_DecryptInit", "r"), verify("r"), 13, "did not decrypt what was made for its public key"),
        (other("C_UnwrapKey", "u"), verify("u"), 16, "C_UnwrapKey (proof of possession)"),
        // It asserts another key's CKA_PUBLIC_KEY_INFO on the private key: the material decides.
        (
            "fn = \"C_GetAttributeValue\"\nof_label = \"r\"\nattribute = \"CKA_PUBLIC_KEY_INFO\"\nfrom_label = \"r-other\""
                .into(),
            verify("r"),
            13,
            "disagrees with the key material",
        ),
        // The per-use login of a CKA_ALWAYS_AUTHENTICATE key refused (the second C_Login of the
        // run): unavailable, and not tried again.
        ("fn = \"C_Login\"\ncall = 2\nrv = \"CKR_PIN_INCORRECT\"".into(), verify("a"), 16, "CKR_PIN_INCORRECT; not retried"),
        // The MAC with the derived or unwrapped secret fails.
        ("fn = \"C_Sign\"\nrv = \"CKR_DEVICE_ERROR\"".into(), verify("d"), 16, "C_Sign (ECDH proof of possession)"),
        ("fn = \"C_Sign\"\nrv = \"CKR_DEVICE_ERROR\"".into(), verify("u"), 16, "C_Sign (unwrap proof of possession)"),
        // What it returns is not what the key made: a signature or a plaintext with one byte changed.
        ("fn = \"C_Sign\"\ncall = 2\ncorrupt = true".into(), verify("k"), 13, "did not sign for the public key"),
        ("fn = \"C_Decrypt\"\ncall = 2\ncorrupt = true".into(), verify("r"), 13, "did not decrypt for the public key"),
        // It no longer lists the proof's mechanism.
        (
            "fn = \"C_GetMechanismList\"\nhide_mechanisms = [\"CKM_ECDH1_DERIVE\"]".into(),
            verify("d"),
            15,
            "lacks CKM_ECDH1_DERIVE",
        ),
        // A call that fails where a correct module's never does.
        ("fn = \"C_Sign\"\nrv = \"CKR_DEVICE_ERROR\"".into(), verify("k"), 16, "C_Sign (proof of possession)"),
        (
            "fn = \"C_GetAttributeValue\"\ncall = 1\nrv = \"CKR_DEVICE_ERROR\"".into(),
            verify("k"),
            16,
            "C_GetAttributeValue",
        ),
    ];
    let lock_path = w.dir.join("keys.lock");
    let lock = std::fs::read(&lock_path).unwrap();
    for (i, (rule, args, exit, why)) in cases.iter().enumerate() {
        let (plan, trace) = (w.dir.join("plan.toml"), w.dir.join(format!("trace-{i}.jsonl")));
        std::fs::write(&plan, format!("[[rule]]\n{rule}\n")).unwrap();
        let o = w.km_env(args, &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)]);
        assert_eq!(code(&o), *exit, "{rule}\n{}", stderr(&o));
        assert!(stderr(&o).contains(why), "{rule}\nexpected {why:?} in {}", stderr(&o));
        assert!(!fired(&trace).is_empty(), "the rule never fired:\n{rule}");
        assert_eq!(std::fs::read(&lock_path).unwrap(), lock, "{args:?} refused, and changed the lock:\n{rule}");
    }
    // With no plan, the same token still verifies: every refusal above was the lie's.
    for spec in ["k", "d", "r", "u", "a"] {
        assert_eq!(w.code(&["check", "--spec", spec, "--token", "ref"]), 0, "{spec}");
    }
    // And the writing row, unrefused, does write: the comparison above can fail.
    assert_eq!(w.code(&["create", "--spec", "new", "--token", "ref"]), 22);
    assert_ne!(std::fs::read(&lock_path).unwrap(), lock, "a recorded creation left the lock as it was");
}

/// A rule that does nothing never says it fired (p11-fault hooks.rs F1): `use_label` naming no
/// object fails the call loudly, as `from_label` does, and no trace line claims the rule; it ran
/// the caller's own key under a fired rule, so a test of a lie passed with no lie told.
#[test]
fn a_substitution_of_nothing_is_the_plans_mistake() {
    let Some((w, plan, trace)) =
        faulted("fault-use-nothing", "[[rule]]\nfn = \"C_SignInit\"\nuse_label = \"no-such-key\"\n")
    else {
        return;
    };
    assert_eq!(w.code(&["create", "--spec", "k", "--token", "ref"]), 22);
    let o = w
        .km_env(&["check", "--spec", "k", "--token", "ref"], &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)]);
    // The shim's CKR_GENERAL_ERROR, unavailable like any failed call (docs/FAULT_SHIM.md).
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("p11-fault: use_label: no object labelled no-such-key"), "{}", stderr(&o));
    assert_eq!(fired(&trace), [] as [serde_json::Value; 0], "a rule that substituted nothing is traced as fired");
}

/// Unknown means try (review 2026-11-15 §4): an ECDH proof whose sealed derivation the module
/// refuses, every template of it (`derive_any`: as asked, with its length, without each policy
/// default) or will not MAC with once derived, proves with the extractable secret instead;
/// where that is refused too, both
/// refusals are named. A derivation that ran for another key is a conflict, and one that failed
/// otherwise (a device error, a key that may not derive) is the proof's answer: never retried
/// (review 2026-11-23 B-8).
#[test]
fn an_ecdh_proof_falls_back_to_the_extractable_secret() {
    let Some(w) = lying("fault-ecdh-fallback") else { return };
    let run = |name: &str, plan: &str| {
        let (path, trace) = (w.dir.join(format!("{name}.toml")), w.dir.join(format!("{name}.jsonl")));
        std::fs::write(&path, plan).unwrap();
        let o = w.km_env(
            &["check", "--spec", "d", "--token", "ref"],
            &[("P11_FAULT_PLAN", &path), ("P11_FAULT_TRACE", &trace)],
        );
        (code(&o), stderr(&o), fired(&trace).len())
    };
    let refused = "rv = \"CKR_ATTRIBUTE_VALUE_INVALID\"";
    let sealed = (1..=6).fold(String::new(), |mut s, n| {
        let _ = write!(s, "[[rule]]\nfn = \"C_DeriveKey\"\ncall = {n}\n{refused}\n\n");
        s
    });
    let (exit, said, fired) = run("sealed", &sealed);
    assert_eq!((exit, fired), (0, 6), "{said}");
    // A sealed secret the module derives but will not MAC with (tpm2-pkcs11 [run]): likewise.
    let (exit, said, fired) = run("mac", "[[rule]]\nfn = \"C_SignInit\"\nrv = \"CKR_KEY_FUNCTION_NOT_PERMITTED\"\n");
    assert_eq!((exit, fired), (0, 1), "{said}");
    let (exit, said, _) = run("both", &format!("[[rule]]\nfn = \"C_DeriveKey\"\n{refused}\n"));
    assert_eq!(exit, 16, "{said}");
    assert!(said.contains("C_DeriveKey (proof of possession)") && said.contains("(sealed: "), "{said}");
    let (exit, said, _) = run("other", "[[rule]]\nfn = \"C_DeriveKey\"\nof_label = \"d\"\nuse_label = \"d-other\"\n");
    assert_eq!(exit, 13, "{said}");
    // Every C_DeriveKey fails alike, so each derivation fires the rule: one, never the extractable.
    for (rv, want) in [("CKR_DEVICE_ERROR", 16), ("CKR_KEY_FUNCTION_NOT_PERMITTED", 15)] {
        let (exit, said, fired) = run(rv, &format!("[[rule]]\nfn = \"C_DeriveKey\"\nrv = \"{rv}\"\n"));
        assert_eq!((exit, fired), (want, 1), "{rv}: {said}");
        assert!(said.contains(rv) && !said.contains("(sealed: "), "{rv}: {said}");
    }
}

/// An OAEP proof tries the next hash (SHA-1, SHA-256, SHA-512) only where the token refuses one's
/// parameters before the operation began (Cloud KMS binds each key to one \[run\]): a refused
/// `C_DecryptInit` moves on, here to the hashes `SoftHSM` refuses itself, while a `C_Decrypt` that
/// failed is never tried again (tpm2-pkcs11 leaves such an operation active \[run\]). The unwrap
/// proof alike, on its one call.
#[test]
fn an_oaep_proof_tries_the_next_hash_only_when_refused_before_it_began() {
    let Some(w) = lying("fault-oaep-hash") else { return };
    let run = |name: &str, spec: &str, plan: &str| {
        let (path, trace) = (w.dir.join(format!("{name}.toml")), w.dir.join(format!("{name}.jsonl")));
        std::fs::write(&path, plan).unwrap();
        let o = w.km_env(&["check", spec, "--token", "ref"], &[("P11_FAULT_PLAN", &path), ("P11_FAULT_TRACE", &trace)]);
        (code(&o), stderr(&o), calls(&trace, "C_DecryptInit"), calls(&trace, "C_UnwrapKey"))
    };
    // Every hash refused by the rule, not only the first: the exit is then the rule's, whatever
    // the module does with the others (review fault.rs F3).
    let refused = "rv = \"CKR_MECHANISM_PARAM_INVALID\"";
    let (exit, said, inits, _) = run("init", "r", &format!("[[rule]]\nfn = \"C_DecryptInit\"\n{refused}\n"));
    assert_eq!((exit, inits), (16, 3), "{said}");
    let (exit, said, inits, _) = run("mid", "r", "[[rule]]\nfn = \"C_Decrypt\"\nrv = \"CKR_DEVICE_ERROR\"\n");
    assert_eq!((exit, inits), (16, 1), "{said}");
    let (exit, said, _, unwraps) = run("unwrap", "u", &format!("[[rule]]\nfn = \"C_UnwrapKey\"\n{refused}\n"));
    assert_eq!((exit, unwraps), (16, 3), "{said}");
    // With no plan, SHA-1 proves on the first try, as before.
    let (exit, said, inits, _) = run("none", "r", "");
    assert_eq!((exit, inits), (0, 1), "{said}");
}

/// Refused operations leave nothing behind (docs/DESIGN.md §8.1): a key created and then not
/// identified (its proof of possession fails) is removed again; where the module will not
/// remove it either, cakeys says it is still there.
#[test]
fn a_creation_that_cannot_be_identified_is_undone_or_reported() {
    let Some(w) = lying("fault-undo") else { return };
    let real = std::env::var(REF.module_var).unwrap();
    let left = || open_session(&real, "kmtest", "1234").labelled("new").len();
    let run = |name: &str, plan: &str| {
        let (path, trace) = (w.dir.join(format!("{name}.toml")), w.dir.join(format!("{name}.jsonl")));
        std::fs::write(&path, plan).unwrap();
        let o = w.km_env(
            &["create", "--spec", "new", "--token", "ref", "--no-update-lock"],
            &[("P11_FAULT_PLAN", &path), ("P11_FAULT_TRACE", &trace)],
        );
        assert_eq!(code(&o), 16, "{}", stderr(&o));
        (stderr(&o), fired(&trace).len())
    };
    // The second C_Sign (the first asks the length), after the real call: a C_Sign that fails ends
    // the signing operation, as PKCS#11 has it. Answered instead of the module, or on the length
    // query, the real operation would stay open and refuse the cleanup's search.
    let sign_fails = "[[rule]]\nfn = \"C_Sign\"\ncall = 2\nwhen = \"after\"\nrv = \"CKR_DEVICE_ERROR\"\n";
    let (said, fired_rules) = run("undone", sign_fails);
    assert!(said.contains("removed 2 object(s) just created"), "{said}");
    assert_eq!((left(), fired_rules), (0, 1));
    let (said, fired_rules) =
        run("kept", &format!("{sign_fails}\n[[rule]]\nfn = \"C_DestroyObject\"\nrv = \"CKR_DEVICE_ERROR\"\n"));
    assert!(said.contains("is still on the token"), "{said}");
    assert!(left() == 2 && fired_rules >= 2, "{} left, {fired_rules} fired", left());
    // The key gone from every search once made: not found (11), never a second key made — one
    // generation in the trace, and on the token only the kept pair and this run's (review
    // fault.rs F2: a retry that generated again ended in 11 too).
    let (hidden, trace) = (w.dir.join("hidden.toml"), w.dir.join("hidden.jsonl"));
    std::fs::write(&hidden, "[[rule]]\nfn = \"C_FindObjects\"\nhide_label = \"new\"\n").unwrap();
    let o = w.km_env(
        &["create", "--spec", "new", "--token", "ref", "--no-update-lock"],
        &[("P11_FAULT_PLAN", &hidden), ("P11_FAULT_TRACE", &trace)],
    );
    assert_eq!(code(&o), 11, "{}", stderr(&o));
    assert!(stderr(&o).contains("vanished after creation"), "{}", stderr(&o));
    assert_eq!(calls(&trace, "C_GenerateKeyPair"), 1, "generated again");
    assert_eq!(left(), 4, "the kept pair and this run's, nothing more");
}

/// The calls of `function` in a trace (every call is traced, fired or not).
fn calls(trace: &std::path::Path, function: &str) -> usize {
    let text = std::fs::read_to_string(trace).unwrap_or_default();
    text.lines().filter(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["fn"] == function).count()
}

/// `create` records each key as it is made: killed at the second pair's `C_GenerateKeyPair`,
/// the run leaves the first key on the token and in the lock file, never on the token alone;
/// the next run verifies it and makes the second (docs/REVIEW D2, cli lib.rs F1).
#[test]
fn a_create_killed_part_way_has_recorded_what_it_made() {
    let plan = "[[rule]]\nfn = \"C_GenerateKeyPair\"\ncall = 2\nabort = true\n";
    let Some((w, plan_path, trace)) = faulted("fault-killed-create", plan) else { return };
    let spec = |n: &str| {
        format!(
            "[objects.{n}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.{n}]\nobject = \"{n}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"killed-{n}\" }}, origin = \"create\" }}\n\n"
        )
    };
    w.write_config(&(reference_tokens(&fault_shim(), &w.dir) + &spec("k1") + &spec("k2")));
    let real = std::env::var(REF.module_var).unwrap();
    let on_token = |n: &str| open_session(&real, "kmtest", "1234").labelled(&format!("killed-{n}")).len();
    let create = ["create", "--token", "ref"];
    let o = w.km_env(&create, &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)]);
    assert_eq!(o.status.code(), None, "the plan did not end the run: {}", stderr(&o));
    assert_eq!((on_token("k1"), on_token("k2")), (2, 0), "the first pair's key, both halves");
    let lock = w.lock();
    assert!(lock["realisations"]["k1"].get("ref").is_some(), "made before the kill, not recorded: {lock}");
    assert!(lock["realisations"].get("k2").is_none(), "{lock}");
    let o = w.km(&create);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!((on_token("k1"), on_token("k2")), (2, 2));
}

/// A module that fails after it made the key (ops.rs F2): `C_GenerateKeyPair` generates and then
/// answers `CKR_DEVICE_ERROR`. The locator was empty before, so what is under it is this
/// creation's: removed and said, never left on the token unrecorded for the next run's 19.
#[test]
fn a_creation_that_fails_after_the_write_is_undone() {
    let plan = "[[rule]]\nfn = \"C_GenerateKeyPair\"\nwhen = \"after\"\nrv = \"CKR_DEVICE_ERROR\"\n";
    let Some((w, plan_path, trace)) = faulted("fault-late-error", plan) else { return };
    let real = std::env::var(REF.module_var).unwrap();
    let left = || open_session(&real, "kmtest", "1234").labelled("fault-late-error").len();
    let create = ["create", "--spec", "k", "--token", "ref"];
    let o = w.km_env(&create, &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)]);
    // The module's CKR_DEVICE_ERROR, handed back after the undo.
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert_eq!(fired(&trace).len(), 1, "the generation, once");
    assert!(stderr(&o).contains("removed 2 object(s) just created"), "{}", stderr(&o));
    assert_eq!(left(), 0, "the pair the module made is still under the locator");
    // Nothing left in the way: the next run creates it.
    let o = w.km(&create);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(left(), 2);
}

/// A curve refused by OID is generated once more by name only where the token's profile says
/// only its name generates it (ykcs11's edwards25519), or nothing is known of it (ISSUES.md
/// B18). `SoftHSM`'s profile says it generates edwards25519 by OID: its refusal is reported as
/// it was given, with no second generation on the token.
#[test]
fn a_refused_curve_is_tried_by_name_only_where_the_profile_says_so() {
    let refuse = "[[rule]]\nfn = \"C_GenerateKeyPair\"\nrv = \"CKR_DOMAIN_PARAMS_INVALID\"\n";
    let Some((w, plan, trace)) = faulted("fault-by-name", refuse) else { return };
    w.write_config(
        &(reference_tokens(&fault_shim(), &w.dir)
            + "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"\n\n\
               [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
               tokens.ref = { locator = { CKA_LABEL = \"fault-by-name\" }, origin = \"create\" }\n"),
    );
    let o = w.km_env(
        &["create", "--spec", "k", "--token", "ref", "--no-update-lock"],
        &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)],
    );
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("CKR_DOMAIN_PARAMS_INVALID"), "{}", stderr(&o));
    let text = std::fs::read_to_string(&trace).unwrap();
    let generations = text.lines().filter(|l| l.contains("\"C_GenerateKeyPair\"")).count();
    assert_eq!(generations, 1, "{text}");
}

/// What the lock recorded of a token decides at open, as in `validate` (ISSUES.md B18): a curve
/// an earlier run generated only by name is tried by name again, whatever the shipped profile
/// says, and `create` records `via = "by-name"` for the key it made so. The `SoftHSM` profile has a
/// plain yes for edwards25519; the shim refuses the first generation, by OID.
#[test]
fn a_curve_the_lock_records_by_name_is_tried_by_name() {
    let refuse_first = "[[rule]]\nfn = \"C_GenerateKeyPair\"\ncall = 1\nrv = \"CKR_DOMAIN_PARAMS_INVALID\"\n";
    let Some((w, plan, trace)) = faulted("fault-recorded-by-name", refuse_first) else { return };
    let row = "generate.CKK_EC_EDWARDS.edwards25519";
    let config = std::fs::read_to_string(w.dir.join("keys.toml")).unwrap();
    w.write_config(
        &(config
            + "\n[objects.e]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"\n\n\
               [specs.e]\nobject = \"e\"\nattributes = { CKA_SIGN = true }\n\
               tokens.ref = { locator = { CKA_LABEL = \"fault-recorded-e\" }, origin = \"create\" }\n"),
    );
    // A first key, unfaulted, records the token's observation; an earlier run's by-name answer
    // goes into it.
    assert_eq!(w.code(&["create", "--spec", "k", "--token", "ref"]), 22);
    let lock_path = w.dir.join("keys.lock");
    let mut lock: toml::Table = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
    let observations = lock["observations"].as_table_mut().unwrap();
    assert_eq!(observations.len(), 1, "{observations:?}");
    let observed = observations.iter_mut().next().unwrap().1.as_table_mut().unwrap();
    let answers = observed.entry("capabilities").or_insert_with(|| toml::Table::new().into());
    let by_name: toml::Table = toml::from_str("answer = \"yes\"\nvia = \"by-name\"").unwrap();
    answers.as_table_mut().unwrap().insert(row.into(), by_name.into());
    std::fs::write(&lock_path, toml::to_string(&lock).unwrap()).unwrap();
    let o = w.km_env(
        &["create", "--spec", "e", "--token", "ref"],
        &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)],
    );
    let text = std::fs::read_to_string(&trace).unwrap();
    let generations = text.lines().filter(|l| l.contains("\"C_GenerateKeyPair\"")).count();
    assert_eq!(generations, 2, "{text}\n{}", stderr(&o));
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    // The key made so is recorded so, by this run.
    let lock: toml::Table = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
    let recorded: Vec<_> =
        lock["observations"].as_table().unwrap().values().filter_map(|o| o.get("capabilities")?.get(row)).collect();
    assert!(!recorded.is_empty(), "{lock:?}");
    for r in recorded {
        assert_eq!(r.get("via").and_then(toml::Value::as_str), Some("by-name"), "{lock:?}");
    }
}

/// One resolve reads the key's public key once (review D8): its identity, the check of the public
/// objects under its locator, its attestation and a transport key's `publicKey` all name that one
/// value. Counted on the trace: the `C_GetAttributeValue` calls for `CKA_EC_PARAMS` and
/// `CKA_EC_POINT` together, which only the SPKI makes. cryptoki reads a present value in two
/// calls (its length, then it), so one SPKI of an EC private key is three (its own pair: no
/// point, one call; its public object's: two), and the check of the one public object under the
/// locator two more. It was eight: the SPKI read again by that check.
#[test]
fn a_resolve_reads_the_public_key_once() {
    let Some(w) = lying("fault-spki-once") else { return };
    let (plan, trace) = (w.dir.join("plan.toml"), w.dir.join("trace.jsonl"));
    std::fs::write(&plan, "").unwrap();
    for (args, want) in
        [(&["check", "--spec", "k", "--token", "ref"][..], 5), (&["check", "k", "--token", "ref"][..], 5)]
    {
        let _ = std::fs::remove_file(&trace);
        let o = w.km_env(args, &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)]);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
        let text = std::fs::read_to_string(&trace).unwrap();
        let point_reads = text
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .filter(|c| c["fn"] == "C_GetAttributeValue" && c["attributes"] == serde_json::json!([0x180, 0x181]))
            .count();
        assert_eq!(point_reads, want, "{args:?}");
    }
}

/// A failed attribute read is unavailable (16) wherever in the run it falls, never read as an
/// answer. Each `C_GetAttributeValue` of `resolve`, `check` and `lock` fails in turn with
/// `CKR_DEVICE_ERROR` until the rule no longer fires, and every run exits 16: before, a policy
/// flag read so was left out (14, "changed since it was realised"; `lock` would record it so) and
/// a public key object's point read so was "no key material" (13) (review D7). A module that
/// refuses only the attribute (`CKR_ARGUMENTS_BAD`, as ykcs11 refuses `CKA_PUBLIC_KEY_INFO`)
/// still leaves an optional one out: there the run passes, and `lock` writes what a clean run does.
/// (A policy flag refused so is not what the token can show: `lock` records that.)
#[test]
fn a_failed_attribute_read_is_never_an_answer() {
    const PUBLIC_KEY_INFO: u64 = 0x129;
    const ALLOWED_MECHANISMS: u64 = 0x4000_0600;
    let Some(w) = lying("fault-reads") else { return };
    let lock = w.dir.join("keys.lock");
    let before = std::fs::read(&lock).unwrap();
    let relock = |spec: &'static str| vec!["lock", "--spec", spec, "--token", "ref"];
    // What a clean `lock` writes, from the same lock.
    let clean: Vec<Vec<u8>> = ["k", "r"]
        .iter()
        .map(|spec| {
            std::fs::write(&lock, &before).unwrap();
            assert_eq!(w.code(&relock(spec)), 0, "{spec}");
            std::fs::read(&lock).unwrap()
        })
        .collect();
    let mut wrong = Vec::new();
    for (rv, strict) in [("CKR_DEVICE_ERROR", true), ("CKR_ARGUMENTS_BAD", false)] {
        for (s, spec) in ["k", "r"].into_iter().enumerate() {
            let runs: [(&str, Vec<&str>); 3] = [
                ("check", vec!["check", "--spec", spec, "--token", "ref"]),
                ("check", vec!["check", spec, "--token", "ref"]),
                ("lock", relock(spec)),
            ];
            for (verb, args) in runs {
                for n in 1.. {
                    std::fs::write(&lock, &before).unwrap();
                    let (plan, trace) = (w.dir.join("plan.toml"), w.dir.join(format!("trace-{verb}-{spec}-{n}.jsonl")));
                    let rule = format!("[[rule]]\nfn = \"C_GetAttributeValue\"\ncall = {n}\nrv = \"{rv}\"\n");
                    std::fs::write(&plan, rule).unwrap();
                    let o = w.km_env(&args, &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)]);
                    let Some(hit) = fired(&trace).pop() else {
                        assert!(n > 5, "{verb} {spec}: only {n} reads");
                        break;
                    };
                    let read: Vec<u64> =
                        hit["attributes"].as_array().unwrap().iter().filter_map(serde_json::Value::as_u64).collect();
                    let optional = matches!(read.as_slice(), [PUBLIC_KEY_INFO | ALLOWED_MECHANISMS]);
                    let exit = code(&o);
                    let last = stderr(&o).lines().last().unwrap_or("").to_owned();
                    let said = format!("{rv} {verb} {spec} call {n} {read:x?}: exit {exit}: {last}");
                    if (strict && exit != 16) || (!strict && optional && exit != 0) {
                        wrong.push(said);
                    } else if verb == "lock" && optional && std::fs::read(&lock).unwrap() != clean[s] {
                        wrong.push(format!("{said}: the lock is not what a clean run writes"));
                    }
                }
            }
        }
    }
    std::fs::write(&lock, &before).unwrap();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// A token on the shim for [`each_lie_kind_fires`], each object under its own name as its label
/// and made by cakeys with no plan, so that an object standing in for another differs from it in
/// material alone: `k`, `k2` and `k-other` (P-256, signing); `s` and `s-other` (generic secrets
/// with no usage bit, so identified by wrap-rebind: wrapped, unwrapped as a session copy, an HMAC
/// commitment on the copy); `w` (AES that only wraps: its commitment is a wrap); and `n` (AES),
/// declared and not made. With the real module behind the shim.
fn told(name: &str) -> Option<(Workdir, String)> {
    let real = suite_var(REF.module_var, REF.require_var, name)?;
    let w = Workdir::new(name);
    let object = |name: &str, kind: &str, attributes: &str| {
        format!(
            "[objects.{name}]\n{kind}\n\n[specs.{name}]\nobject = \"{name}\"\nattributes = {{ {attributes} }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{name}\" }}, origin = \"create\" }}\n\n"
        )
    };
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let secret = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32";
    let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
    let rebound = "CKA_SIGN = false, CKA_SENSITIVE = true, CKA_EXTRACTABLE = true";
    let wraps = "CKA_WRAP = true, CKA_UNWRAP = true, CKA_SIGN = false, CKA_ENCRYPT = false, CKA_SENSITIVE = true, \
                 CKA_EXTRACTABLE = false";
    w.write_config(
        &[
            reference_tokens(&fault_shim(), &w.dir),
            object("k", ec, "CKA_SIGN = true"),
            object("k2", ec, "CKA_SIGN = true"),
            object("k-other", ec, "CKA_SIGN = true"),
            object("s", secret, rebound),
            object("s-other", secret, rebound),
            object("w", aes, wraps),
            object("n", aes, "CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false"),
        ]
        .concat(),
    );
    for spec in TOLD {
        let o = w.km(&["create", "--spec", spec, "--token", "ref"]);
        assert_eq!(code(&o), 22, "{spec}, no plan: {}", stderr(&o));
    }
    Some((w, real))
}

/// The objects [`told`] makes.
const TOLD: [&str; 6] = ["k", "k2", "k-other", "s", "s-other", "w"];

/// One row of [`each_lie_kind_fires`].
#[derive(Default)]
struct Lie {
    /// The rule.
    rule: String,
    /// The run it meets.
    run: Vec<&'static str>,
    /// The run's exit, where that is the lie's effect.
    exit: Option<i32>,
    /// What cakeys says.
    says: &'static str,
    /// The functions the trace shows the rule fired on, each of them and no other (`*`: any):
    /// none for a lie aimed past the run, which must not fire.
    fires: &'static [&'static str],
    /// Which call of its function each line the rule fired on was (`n`), where that is the
    /// point: a count of calls.
    n: &'static [u64],
    /// The process's call (`seq`) from which the rule fired on every call, and on none before.
    from_seq: Option<u64>,
}

/// The rows of [`each_lie_kind_fires`]: `signs` is the process's first `C_SignInit` (`seq`) in
/// an honest `check` of `k`.
fn lies(signs: u64) -> Vec<Lie> {
    let (check, lock) = (told_check, told_lock);
    let k_read = "fn = \"C_GetAttributeValue\"\nof_label = \"k\"\nrv = \"CKR_DEVICE_ERROR\"";
    let aes = "fn = \"C_GenerateKey\"\nkey_type = \"CKK_AES\"\nrv = \"CKR_DEVICE_ERROR\"";
    vec![
        // The key wrapped is another (`wrap_label`): the session copy wrap-rebind commits on is
        // another key's, so the identity is not the lock's.
        Lie {
            rule: "fn = \"C_WrapKey\"\nof_label = \"s\"\nwrap_label = \"s-other\"".into(),
            run: check("s"),
            exit: Some(10),
            says: "hash mismatch in identity of",
            fires: &["C_WrapKey"],
            ..Lie::default()
        },
        // A return value for the calls on one object (`of_label`): k's attribute reads fail,
        // and k2's are left alone.
        Lie {
            rule: k_read.into(),
            run: check("k"),
            exit: Some(16),
            says: "C_GetAttributeValue",
            fires: &["C_GetAttributeValue"],
            ..Lie::default()
        },
        Lie { rule: k_read.into(), run: check("k2"), exit: Some(0), ..Lie::default() },
        // `nth` counts the calls that meet the rule's other matchers: the first signing with k is
        // the run's second `C_SignInit`, after k2's.
        Lie {
            rule: "fn = \"C_SignInit\"\nof_label = \"k\"\nnth = 1\nuse_label = \"k-other\"".into(),
            run: lock("k2", "k"),
            exit: Some(13),
            says: "did not sign for the public key",
            fires: &["C_SignInit"],
            n: &[2],
            ..Lie::default()
        },
        // `from`: the third `C_Sign` on, k2's signature (each proof asks the length first, which
        // is no output to change), and not k's.
        Lie {
            rule: "fn = \"C_Sign\"\nfrom = 3\ncorrupt = true".into(),
            run: lock("k", "k2"),
            exit: Some(13),
            says: "did not sign for the public key",
            fires: &["C_Sign"],
            n: &[4],
            ..Lie::default()
        },
        // Every function (`fn = "*"`) from the run's first `C_SignInit` on: the module is gone
        // from there, and was there before.
        Lie {
            rule: format!("fn = \"*\"\nfrom_seq = {signs}\nrv = \"CKR_DEVICE_REMOVED\""),
            run: check("k"),
            exit: Some(16),
            says: "CKR_DEVICE_REMOVED",
            fires: &["*"],
            from_seq: Some(signs),
            ..Lie::default()
        },
        // `mechanism`: the signing mechanism refused, and another left alone.
        Lie {
            rule: "fn = \"C_SignInit\"\nmechanism = \"CKM_ECDSA_SHA256\"\nrv = \"CKR_MECHANISM_INVALID\"".into(),
            run: check("k"),
            exit: Some(15),
            says: "refused to sign",
            fires: &["C_SignInit"],
            ..Lie::default()
        },
        Lie {
            rule: "fn = \"C_SignInit\"\nmechanism = \"CKM_ECDSA\"\nrv = \"CKR_MECHANISM_INVALID\"".into(),
            run: check("k"),
            exit: Some(0),
            ..Lie::default()
        },
        // `class`: the search for the public key fails, and one for another class would not.
        Lie {
            rule: "fn = \"C_FindObjectsInit\"\nclass = \"CKO_PUBLIC_KEY\"\nrv = \"CKR_DEVICE_ERROR\"".into(),
            run: check("k"),
            exit: Some(16),
            says: "C_FindObjects",
            fires: &["C_FindObjectsInit"],
            ..Lie::default()
        },
        Lie {
            rule: "fn = \"C_FindObjectsInit\"\nclass = \"CKO_DATA\"\nrv = \"CKR_DEVICE_ERROR\"".into(),
            run: check("k"),
            exit: Some(0),
            ..Lie::default()
        },
        // `key_type`: generating an AES key fails; wrap-rebind's session KEK, whose template names
        // no key type, is made.
        Lie {
            rule: aes.into(),
            run: vec!["create", "--spec", "n", "--token", "ref"],
            exit: Some(16),
            says: "generating key on",
            fires: &["C_GenerateKey"],
            ..Lie::default()
        },
        Lie { rule: aes.into(), run: check("s"), exit: Some(0), ..Lie::default() },
    ]
}

/// The row of [`each_lie_kind_fires`] for `P11_FAULT_RECORD_VALUES = public`: the trace of a
/// `check` of k records k's EC point as the token (`real`, read directly) holds it, and no value
/// outside the public attributes; any other value is refused, never ignored. What is wrong.
fn public_values_recorded(w: &Workdir, real: &str) -> Vec<String> {
    let mut wrong = Vec::new();
    let values = w.dir.join("values.jsonl");
    let record = |value: &'static str| {
        let env = [("P11_FAULT_TRACE", values.as_path()), ("P11_FAULT_RECORD_VALUES", std::path::Path::new(value))];
        w.km_env(&told_check("k"), &env)
    };
    let o = record("public");
    let text = std::fs::read_to_string(&values).unwrap_or_default();
    let recorded: Vec<(u64, String)> = text
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .flat_map(|l| l["values"].as_array().cloned().unwrap_or_default())
        .map(|v| (v[0].as_u64().unwrap(), v[1].as_str().unwrap().to_owned()))
        .collect();
    let s = open_session(real, "kmtest", "1234");
    let hex = |bytes: &[u8]| {
        bytes.iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    };
    let held: Vec<String> = s
        .labelled("k")
        .into_iter()
        .filter_map(|h| s.get_attributes(h, &[cryptoki::object::AttributeType::EcPoint]).ok())
        .flatten()
        .filter_map(|a| if let Attribute::EcPoint(point) = a { Some(hex(&point)) } else { None })
        .collect();
    // CKA_EC_PARAMS, CKA_EC_POINT, CKA_MODULUS, CKA_PUBLIC_EXPONENT, CKA_PUBLIC_KEY_INFO,
    // CKA_TPM2_PUB_BLOB: the public attributes (p11-fault's record.rs).
    let public = [0x180, 0x181, 0x120, 0x122, 0x129, 0x8F00_0002];
    let points: Vec<&String> = recorded.iter().filter(|(t, _)| *t == 0x181).map(|(_, v)| v).collect();
    let only_public = recorded.iter().all(|(t, _)| public.contains(t));
    if code(&o) != 0 || points.is_empty() || !points.iter().all(|p| held.contains(p)) || !only_public {
        let types: Vec<u64> = recorded.iter().map(|(t, _)| *t).collect();
        wrong.push(format!("values recorded: exit {}, types {types:?}, points {points:?}, held {held:?}", code(&o)));
    }
    let o = record("all");
    if code(&o) == 0 || !stderr(&o).contains("p11-fault: P11_FAULT_RECORD_VALUES = all: only \"public\"") {
        wrong.push(format!("all values: exit {}: {}", code(&o), stderr(&o)));
    }
    wrong
}

/// `check` of one of [`told`]'s objects.
fn told_check(spec: &'static str) -> Vec<&'static str> {
    vec!["check", "--spec", spec, "--token", "ref"]
}

/// `lock` of two of [`told`]'s objects, in this order.
fn told_lock(a: &'static str, b: &'static str) -> Vec<&'static str> {
    vec!["lock", "--spec", a, "--spec", b, "--token", "ref"]
}

/// The rows of [`each_lie_kind_fires`] that change what a search finds or a function returns.
fn output_lies() -> Vec<Lie> {
    let (check, lock) = (told_check, told_lock);
    vec![
        // Another object found under the locator (`replace_label`): k-other's key pair stands
        // for k's, so the identity is not the lock's.
        Lie {
            rule: "fn = \"C_FindObjects\"\nof_label = \"k\"\nreplace_label = \"k-other\"".into(),
            run: check("k"),
            exit: Some(10),
            says: "hash mismatch in identity of",
            fires: &["C_FindObjects"],
            ..Lie::default()
        },
        // A wrap commitment changed (`corrupt` on `C_WrapKey`).
        Lie {
            rule: "fn = \"C_WrapKey\"\ncorrupt = true".into(),
            run: check("w"),
            exit: Some(10),
            says: "hash mismatch in identity of",
            fires: &["C_WrapKey"],
            ..Lie::default()
        },
        // A wrapped blob that round-trips through the module and is not what it made
        // (`transcode`): wrap-rebind, which only unwraps it, still verifies; a wrap commitment,
        // which hashes it, does not.
        Lie {
            rule: "fn = \"C_WrapKey\"\ntranscode = true".into(),
            run: check("s"),
            exit: Some(0),
            fires: &["C_WrapKey", "C_UnwrapKey"],
            ..Lie::default()
        },
        Lie {
            rule: "fn = \"C_WrapKey\"\ntranscode = true".into(),
            run: check("w"),
            exit: Some(10),
            says: "hash mismatch in identity of",
            fires: &["C_WrapKey"],
            ..Lie::default()
        },
        // An earlier output returned again (`replay_output`): k2's proof is k's signature.
        Lie {
            rule: "fn = \"C_Sign\"\nreplay_output = 1".into(),
            run: lock("k", "k2"),
            exit: Some(13),
            says: "did not sign for the public key",
            fires: &["C_Sign"],
            n: &[4],
            ..Lie::default()
        },
    ]
}

/// Each lie kind `p11-fault` tells beyond the first table (`docs/FAULT_SHIM.md`; review 2026-11-24
/// phase 2, L1), one row per kind: the rule, the run it meets, the exit where it is the lie's
/// effect, what cakeys says, and the functions the trace shows the rule fired on. Every row
/// leaves the lock as it was, and with no plan every object still verifies afterwards: each
/// effect was the lie's. Every row is run before any is judged, so one run of the suite names
/// every row that is wrong.
#[test]
fn each_lie_kind_fires() {
    let Some((w, real)) = told("fault-each-lie") else { return };
    let check = |spec: &'static str| vec!["check", "--spec", spec, "--token", "ref"];
    // The run's first `C_SignInit`, honest: the calls up to it are the same under a plan.
    let honest = w.dir.join("honest.jsonl");
    assert_eq!(code(&w.km_env(&check("k"), &[("P11_FAULT_TRACE", &honest)])), 0);
    let lines = std::fs::read_to_string(&honest).unwrap();
    let lines = lines.lines().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap());
    let signs = lines.filter(|l| l["fn"] == "C_SignInit").map(|l| l["seq"].as_u64().unwrap()).next().unwrap();
    let rows = lies(signs).into_iter().chain(output_lies());
    let lock_path = w.dir.join("keys.lock");
    let locked = std::fs::read(&lock_path).unwrap();
    let mut wrong = Vec::new();
    for (i, Lie { rule, run, exit, says, fires, n, from_seq }) in rows.enumerate() {
        let (plan, trace) = (w.dir.join("plan.toml"), w.dir.join(format!("lie-{i}.jsonl")));
        std::fs::write(&plan, format!("[[rule]]\n{rule}\n")).unwrap();
        let o = w.km_env(&run, &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)]);
        let lines = fired(&trace);
        let fired: Vec<String> = lines.iter().map(|l| l["fn"].as_str().unwrap_or("?").to_owned()).collect();
        let said = stderr(&o);
        let named = |f: &String| fires.contains(&"*") || fires.contains(&f.as_str());
        let each = fires.iter().all(|f| *f == "*" || fired.iter().any(|g| g == f));
        let mut as_said = fired.is_empty() == fires.is_empty() && fired.iter().all(named) && each;
        let counts: Vec<u64> = lines.iter().map(|l| l["n"].as_u64().unwrap_or(0)).collect();
        as_said &= n.is_empty() || counts == n;
        if let Some(from) = from_seq {
            let all = std::fs::read_to_string(&trace).unwrap_or_default();
            as_said &= all
                .lines()
                .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
                .all(|l| (l["seq"].as_u64() >= Some(from)) == (l["rule"] == 1 && l["rv"] == "CKR_DEVICE_REMOVED"));
        }
        let kept = std::fs::read(&lock_path).unwrap() == locked;
        if exit.is_some_and(|e| e != code(&o)) || !said.contains(says) || !as_said || !kept {
            wrong.push(format!(
                "row {i}: {rule}\n  {run:?}: exit {}, fired {fired:?} at {counts:?}, lock kept {kept}: {said}",
                code(&o)
            ));
        }
    }
    wrong.extend(public_values_recorded(&w, &real));
    // With no plan, the same token still verifies: every effect above was the lie's.
    for spec in TOLD {
        let o = w.km(&check(spec));
        if code(&o) != 0 {
            wrong.push(format!("{spec} with no plan: exit {}: {}", code(&o), stderr(&o)));
        }
    }
    // OK without effect, on one object (`of_label` on `rv = "CKR_OK"`, phase 2 design §1.1):
    // the delete of k2 is told each destroy happened, and k2's two objects are still on the
    // token. Last, as the lock may change; what cakeys then exits is its own to decide.
    let (plan, trace) = (w.dir.join("plan.toml"), w.dir.join("destroy.jsonl"));
    std::fs::write(&plan, "[[rule]]\nfn = \"C_DestroyObject\"\nof_label = \"k2\"\nrv = \"CKR_OK\"\n").unwrap();
    let o = w.km_env(
        &["delete", "--spec", "k2", "--token", "ref"],
        &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)],
    );
    let destroyed: Vec<serde_json::Value> = fired(&trace).into_iter().map(|l| l["fn"].clone()).collect();
    let left = open_session(&real, "kmtest", "1234").labelled("k2").len();
    if destroyed.is_empty() || destroyed.iter().any(|f| f != "C_DestroyObject") || left != 2 {
        wrong.push(format!("destroy of k2: fired {destroyed:?}, {left} left: exit {}: {}", code(&o), stderr(&o)));
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
