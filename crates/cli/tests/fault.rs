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
    assert_eq!(w.code(&["create", "--spec", "k", "--token", "ref", "--update-lock"]), 0, "no plan: transparent");
    let o = w.km_env(
        &["verify", "--spec", "k", "--token", "ref"],
        &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)],
    );
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    let said = stderr(&o);
    assert!(said.contains("C_Login") && said.contains("PIN is incorrect"), "{said}");
    assert_eq!(fired(&trace).last().unwrap()["fn"].as_str(), Some("C_Login"));
    // Logged in without the refusal, the search fails instead.
    let find_only = w.dir.join("find.toml");
    std::fs::write(&find_only, "[[rule]]\nfn = \"C_FindObjects\"\nrv = \"CKR_DEVICE_ERROR\"\n").unwrap();
    let o = w.km_env(
        &["verify", "--spec", "k", "--token", "ref"],
        &[("P11_FAULT_PLAN", &find_only), ("P11_FAULT_TRACE", &trace)],
    );
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("C_FindObjects"), "{}", stderr(&o));
    assert_eq!(fired(&trace).last().unwrap()["rv"].as_str(), Some("CKR_DEVICE_ERROR"));
    let refused = w.dir.join("refused.toml");
    std::fs::write(&refused, "[[rule]]\nfn = \"C_SignInit\"\nrv = \"CKR_MECHANISM_INVALID\"\n").unwrap();
    let o = w.km_env(
        &["verify", "--spec", "k", "--token", "ref"],
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
        let o = w.km(&["create", "--spec", spec, "--token", "ref", "--update-lock"]);
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
    let verify = |spec: &'static str| vec!["verify", "--spec", spec, "--token", "ref"];
    let point = |change: &str| {
        format!("fn = \"C_GetAttributeValue\"\nof_label = \"k\"\nattribute = \"CKA_EC_POINT\"\n{change}")
    };
    let other =
        |function: &str, key: &str| format!("fn = \"{function}\"\nof_label = \"{key}\"\nuse_label = \"{key}-other\"");
    let cases: Vec<(String, Vec<&str>, i32, &str)> = vec![
        // What the token says of itself.
        (
            "fn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_WRITE_PROTECTED\"]".into(),
            vec!["create", "--spec", "new", "--token", "ref", "--no-update-lock"],
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
        ("fn = \"C_Login\"\ncall = 2\nrv = \"CKR_PIN_INCORRECT\"".into(), verify("a"), 16, "not retried"),
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
    for spec in ["k", "d", "r", "u", "a"] {
        assert_eq!(w.code(&["verify", "--spec", spec, "--token", "ref"]), 0, "{spec}");
    }
}

/// Unknown means try (review 2026-11-15 §4): an ECDH proof whose sealed derivation the module
/// refuses, every template of it (`derive_any`: as asked, with its length, without each policy
/// default), proves with the extractable secret instead; where that is refused too, both
/// refusals are named. A derivation that ran for another key is a conflict, never retried.
#[test]
fn an_ecdh_proof_falls_back_to_the_extractable_secret() {
    let Some(w) = lying("fault-ecdh-fallback") else { return };
    let run = |name: &str, plan: &str| {
        let (path, trace) = (w.dir.join(format!("{name}.toml")), w.dir.join(format!("{name}.jsonl")));
        std::fs::write(&path, plan).unwrap();
        let o = w.km_env(
            &["verify", "--spec", "d", "--token", "ref"],
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
    let (exit, said, _) = run("both", &format!("[[rule]]\nfn = \"C_DeriveKey\"\n{refused}\n"));
    assert_eq!(exit, 16, "{said}");
    assert!(said.contains("C_DeriveKey (proof of possession)") && said.contains("(sealed: "), "{said}");
    let (exit, said, _) = run("other", "[[rule]]\nfn = \"C_DeriveKey\"\nof_label = \"d\"\nuse_label = \"d-other\"\n");
    assert_eq!(exit, 13, "{said}");
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
    // The key gone from every search once made: not found (11), never a second key made.
    let hidden = w.dir.join("hidden.toml");
    std::fs::write(&hidden, "[[rule]]\nfn = \"C_FindObjects\"\nhide_label = \"new\"\n").unwrap();
    let o =
        w.km_env(&["create", "--spec", "new", "--token", "ref", "--no-update-lock"], &[("P11_FAULT_PLAN", &hidden)]);
    assert_eq!(code(&o), 11, "{}", stderr(&o));
    assert!(stderr(&o).contains("vanished after creation"), "{}", stderr(&o));
}
