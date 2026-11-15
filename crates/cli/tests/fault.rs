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
                       tokens.ref = { locator = { CKA_LABEL = \"NAME\" }, autoCreate = true }\n";

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
    let Some((w, plan, trace)) =
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
    drop(w);
}

/// cakeys against a module that fails a call it should not: the failing call is named, the exit
/// is unavailable (16), and nothing is recorded. A login refused after the module accepted it
/// is the same.
#[test]
fn a_failing_module_call_is_unavailable() {
    let plan = "[[rule]]\nfn = \"C_FindObjects\"\nrv = \"CKR_DEVICE_ERROR\"\n\n\
                [[rule]]\nfn = \"C_Login\"\nwhen = \"after\"\nrv = \"CKR_PIN_INCORRECT\"\n";
    let Some((w, plan_path, trace)) = faulted("fault-module-fails", plan) else { return };
    assert_eq!(w.code(&["realise", "k", "--token", "ref", "--update-lock"]), 0, "no plan: transparent");
    let o =
        w.km_env(&["verify", "k", "--token", "ref"], &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)]);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    let said = stderr(&o);
    assert!(said.contains("C_Login") && said.contains("PIN is incorrect"), "{said}");
    assert_eq!(fired(&trace).last().unwrap()["fn"].as_str(), Some("C_Login"));
    // Logged in without the refusal, the search fails instead.
    let find_only = w.dir.join("find.toml");
    std::fs::write(&find_only, "[[rule]]\nfn = \"C_FindObjects\"\nrv = \"CKR_DEVICE_ERROR\"\n").unwrap();
    let o =
        w.km_env(&["verify", "k", "--token", "ref"], &[("P11_FAULT_PLAN", &find_only), ("P11_FAULT_TRACE", &trace)]);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("C_FindObjects"), "{}", stderr(&o));
    assert_eq!(fired(&trace).last().unwrap()["rv"].as_str(), Some("CKR_DEVICE_ERROR"));
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
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{name}\" }}, autoCreate = true, binding = \"{binding}\" }}\n\n"
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
            key("new", ec, "CKA_SIGN", "pop-sign"),
        ]
        .concat(),
    );
    for spec in ["k", "d", "r", "u"] {
        let o = w.km(&["realise", spec, "--token", "ref", "--update-lock"]);
        assert_eq!(code(&o), 0, "{spec}, no plan: {}", stderr(&o));
    }
    // The other keys, made on the real module itself.
    let s = open_session(&real, "kmtest", "1234");
    let label = |name: &str| Attribute::Label(format!("{name}-other").into_bytes());
    let p256 = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    for (name, usage) in [("k", Attribute::Sign(true)), ("d", Attribute::Derive(true))] {
        let public = [Attribute::Token(true), label(name), Attribute::EcParams(p256.clone())];
        s.generate_key_pair(&Mechanism::EccKeyPairGen, &public, &[Attribute::Token(true), label(name), usage]).unwrap();
    }
    for (name, usage) in [("r", Attribute::Decrypt(true)), ("u", Attribute::Unwrap(true))] {
        let public = [
            Attribute::Token(true),
            label(name),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![1, 0, 1]),
        ];
        s.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public, &[Attribute::Token(true), label(name), usage])
            .unwrap();
    }
    Some(w)
}

/// What a lying module can and cannot make cakeys accept (docs/DESIGN.md §8.1), one lie per row:
/// the plan, the run, the exit and the reason. Each row's rule is shown fired in the trace.
#[test]
fn a_lying_module_is_refused() {
    let Some(w) = lying("fault-lies") else { return };
    let verify = |spec: &'static str| vec!["verify", spec, "--token", "ref"];
    let point = |change: &str| {
        format!("fn = \"C_GetAttributeValue\"\nof_label = \"k\"\nattribute = \"CKA_EC_POINT\"\n{change}")
    };
    let other =
        |function: &str, key: &str| format!("fn = \"{function}\"\nof_label = \"{key}\"\nuse_label = \"{key}-other\"");
    let cases: Vec<(String, Vec<&str>, i32, &str)> = vec![
        // What the token says of itself.
        (
            "fn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_WRITE_PROTECTED\"]".into(),
            vec!["realise", "new", "--token", "ref", "--no-update-lock"],
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
        (point("from_label = \"k-other\""), verify("k"), 13, "proof of possession failed"),
        // A policy attribute that is not what the spec declares.
        (
            "fn = \"C_GetAttributeValue\"\nof_label = \"k\"\nattribute = \"CKA_SIGN\"\nvalue = \"00\"".into(),
            verify("k"),
            13,
            "CKA_SIGN is false",
        ),
        // Another object under the locator.
        ("fn = \"C_FindObjects\"\nadd_label = \"k-other\"".into(), verify("k"), 12, "objects match locator"),
        // It shows one key and uses another: each proof of possession fails. SoftHSM unwraps
        // under the wrong key with CKR_GENERAL_ERROR, which says nothing of the key: unavailable.
        (other("C_SignInit", "k"), verify("k"), 13, "did not sign for the public key"),
        (other("C_DeriveKey", "d"), verify("d"), 13, "did not derive for the public key"),
        (other("C_DecryptInit", "r"), verify("r"), 13, "did not decrypt what was made for its public key"),
        (other("C_UnwrapKey", "u"), verify("u"), 16, "C_UnwrapKey (proof of possession)"),
        // A call that fails where a correct module's never does.
        ("fn = \"C_Sign\"\nrv = \"CKR_DEVICE_ERROR\"".into(), verify("k"), 16, "C_Sign (proof of possession)"),
        (
            "fn = \"C_GetAttributeValue\"\ncall = 1\nrv = \"CKR_DEVICE_ERROR\"".into(),
            verify("k"),
            16,
            "C_GetAttributeValue",
        ),
    ];
    let lock = std::fs::read(w.dir.join("keys.lock")).unwrap();
    for (i, (rule, args, exit, why)) in cases.iter().enumerate() {
        let (plan, trace) = (w.dir.join("plan.toml"), w.dir.join(format!("trace-{i}.jsonl")));
        std::fs::write(&plan, format!("[[rule]]\n{rule}\n")).unwrap();
        let o = w.km_env(args, &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)]);
        assert_eq!(code(&o), *exit, "{rule}\n{}", stderr(&o));
        assert!(stderr(&o).contains(why), "{rule}\nexpected {why:?} in {}", stderr(&o));
        assert!(!fired(&trace).is_empty(), "the rule never fired:\n{rule}");
    }
    assert_eq!(std::fs::read(w.dir.join("keys.lock")).unwrap(), lock, "a refused run changed the lock");
    // With no plan, the same token still verifies: every refusal above was the lie's.
    for spec in ["k", "d", "r", "u"] {
        assert_eq!(w.code(&["verify", spec, "--token", "ref"]), 0, "{spec}");
    }
}
