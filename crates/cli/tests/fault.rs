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
    // Named by its constant, which the `YubiKey` suites' latch reads (`YubikeyTurn::checked`).
    assert!(said.contains("C_Login: CKR_PIN_INCORRECT"), "{said}");
    assert_eq!(failed_login(&said).as_deref(), Some("CKR_PIN_INCORRECT"), "{said}");
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
    assert_eq!(w.code(&["create", "--spec", "k", "--token", "ref", "--update-lock"]), 0);
    let o = w.km_env(
        &["verify", "--spec", "k", "--token", "ref"],
        &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)],
    );
    assert_ne!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("p11-fault: use_label: no object labelled no-such-key"), "{}", stderr(&o));
    assert_eq!(fired(&trace), [] as [serde_json::Value; 0], "a rule that substituted nothing is traced as fired");
}

/// Unknown means try (review 2026-11-15 §4): an ECDH proof whose sealed derivation the module
/// refuses, every template of it (`derive_any`: as asked, with its length, without each policy
/// default) or will not MAC with once derived, proves with the extractable secret instead;
/// where that is refused too, both
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
    // A sealed secret the module derives but will not MAC with (tpm2-pkcs11 [run]): likewise.
    let (exit, said, fired) = run("mac", "[[rule]]\nfn = \"C_SignInit\"\nrv = \"CKR_KEY_FUNCTION_NOT_PERMITTED\"\n");
    assert_eq!((exit, fired), (0, 1), "{said}");
    let (exit, said, _) = run("both", &format!("[[rule]]\nfn = \"C_DeriveKey\"\n{refused}\n"));
    assert_eq!(exit, 16, "{said}");
    assert!(said.contains("C_DeriveKey (proof of possession)") && said.contains("(sealed: "), "{said}");
    let (exit, said, _) = run("other", "[[rule]]\nfn = \"C_DeriveKey\"\nof_label = \"d\"\nuse_label = \"d-other\"\n");
    assert_eq!(exit, 13, "{said}");
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
        let calls = |f: &str| {
            let text = std::fs::read_to_string(&trace).unwrap_or_default();
            text.lines().filter(|l| l.contains(&format!("\"fn\":\"{f}\""))).count()
        };
        (code(&o), stderr(&o), calls("C_DecryptInit"), calls("C_UnwrapKey"))
    };
    let refused = "rv = \"CKR_MECHANISM_PARAM_INVALID\"";
    let (exit, said, inits, _) = run("init", "r", &format!("[[rule]]\nfn = \"C_DecryptInit\"\ncall = 1\n{refused}\n"));
    assert_eq!((exit, inits), (16, 3), "{said}");
    let (exit, said, inits, _) = run("mid", "r", "[[rule]]\nfn = \"C_Decrypt\"\nrv = \"CKR_DEVICE_ERROR\"\n");
    assert_eq!((exit, inits), (16, 1), "{said}");
    let (exit, said, _, unwraps) =
        run("unwrap", "u", &format!("[[rule]]\nfn = \"C_UnwrapKey\"\ncall = 1\n{refused}\n"));
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
    // The key gone from every search once made: not found (11), never a second key made.
    let hidden = w.dir.join("hidden.toml");
    std::fs::write(&hidden, "[[rule]]\nfn = \"C_FindObjects\"\nhide_label = \"new\"\n").unwrap();
    let o =
        w.km_env(&["create", "--spec", "new", "--token", "ref", "--no-update-lock"], &[("P11_FAULT_PLAN", &hidden)]);
    assert_eq!(code(&o), 11, "{}", stderr(&o));
    assert!(stderr(&o).contains("vanished after creation"), "{}", stderr(&o));
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
    let create = ["create", "--token", "ref", "--update-lock"];
    let o = w.km_env(&create, &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)]);
    assert_eq!(o.status.code(), None, "the plan did not end the run: {}", stderr(&o));
    assert_eq!((on_token("k1"), on_token("k2")), (2, 0), "the first pair's key, both halves");
    let lock = w.lock();
    assert!(lock["realisations"]["k1"].get("ref").is_some(), "made before the kill, not recorded: {lock}");
    assert!(lock["realisations"].get("k2").is_none(), "{lock}");
    let o = w.km(&create);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
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
    let create = ["create", "--spec", "k", "--token", "ref", "--update-lock"];
    let o = w.km_env(&create, &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)]);
    assert_ne!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(fired(&trace).len(), 1, "the generation, once");
    assert!(stderr(&o).contains("removed 2 object(s) just created"), "{}", stderr(&o));
    assert_eq!(left(), 0, "the pair the module made is still under the locator");
    // Nothing left in the way: the next run creates it.
    let o = w.km(&create);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(left(), 2);
}

/// A curve refused by OID is generated once more by name only where the token's profile says
/// only its name generates it (ykcs11's edwards25519), or nothing is known of it (ISSUES.md
/// B18). `SoftHSM`'s profile says it generates edwards25519 by OID: its refusal is reported as
/// it was given, with no second generation on the token.
#[test]
fn a_refused_curve_is_tried_by_name_only_where_the_profile_says_so() {
    let refuse = "[[rule]]\nfn = \"C_GenerateKeyPair\"\nrv = \"CKR_DEVICE_ERROR\"\n";
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
    assert!(stderr(&o).contains("CKR_DEVICE_ERROR"), "{}", stderr(&o));
    let text = std::fs::read_to_string(&trace).unwrap();
    let generations = text.lines().filter(|l| l.contains("\"C_GenerateKeyPair\"")).count();
    assert_eq!(generations, 1, "{text}");
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
        [(&["verify", "--spec", "k", "--token", "ref"][..], 5), (&["check", "k", "--token", "ref"][..], 5)]
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
/// answer. Each `C_GetAttributeValue` of `verify`, `check` and `lock` fails in turn with
/// `CKR_DEVICE_ERROR` until the rule no longer fires, and every run exits 16: before, a policy
/// flag read so was left out (14, "changed since it was realised"; `lock` would record it so) and
/// a public key object's point read so was "no key material" (13) (review D7). A module that
/// refuses only the attribute (`CKR_ARGUMENTS_BAD`, as ykcs11 refuses `CKA_PUBLIC_KEY_INFO`)
/// still leaves an optional one out: there the run passes, and `lock` writes what a clean run does.
/// (A policy flag refused so is not what the token can show: `lock --update-lock` records that.)
#[test]
fn a_failed_attribute_read_is_never_an_answer() {
    const PUBLIC_KEY_INFO: u64 = 0x129;
    const ALLOWED_MECHANISMS: u64 = 0x4000_0600;
    let Some(w) = lying("fault-reads") else { return };
    let lock = w.dir.join("keys.lock");
    let before = std::fs::read(&lock).unwrap();
    let relock = |spec: &'static str| vec!["lock", "--spec", spec, "--token", "ref", "--update-lock"];
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
                ("verify", vec!["verify", "--spec", spec, "--token", "ref"]),
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
