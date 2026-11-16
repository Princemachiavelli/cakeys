//! camigrate against a module that fails or lies (`crates/p11-fault`, `docs/FAULT_SHIM.md`):
//! `SoftHSM` behind the shim as the source or the target of a move, kryoptic as the other side.
//! A move that cannot finish leaves the target as it was and the lock unchanged, and says why.
//!
//! Needs `P11_FAULT_MODULE` naming `SoftHSM` and `CAKEYS_KRYOPTIC_MODULE`, which the per-test
//! runner (nix/test-tokens.sh) sets; skipped without them.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::xref::{Env, Plant, Ref};
use common::*;
use cryptoki::object::{Attribute, CertificateType, ObjectClass};
use x509_cert::der::{Decode as _, Encode as _};

const CERT: &[u8] = include_bytes!("../../cli/tests/fixtures/adopt-cert.der");

/// `SoftHSM` behind the shim (`softhsm`) and kryoptic, each naming a transport key of its own,
/// with three keys realised where they are born: `ek` (P-256) on `softhsm`, `kk` (P-256) and
/// `ks` (AES) on kryoptic, each with a spec on the other token.
fn tokens(name: &str) -> Option<(Env, String)> {
    let real = suite_var("P11_FAULT_MODULE", "CAKEYS_FAULT_REQUIRE", name)?;
    let kryoptic = suite_var("CAKEYS_KRYOPTIC_MODULE", "CAKEYS_KRYOPTIC_REQUIRE", name)?;
    let dir = test_dir(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    let token = |name, module| Ref { name, module, token_label: "kmtest", env: &[], plant: Plant::Create, eddsa: true };
    let e = Env { dir, refs: vec![token("softhsm", fault_shim()), token("kryoptic", kryoptic)] };
    let (soft, kry) = (&e.refs[0], &e.refs[1]);
    let moves = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let transport = |r: &Ref| {
        format!("[objects.tk-{0}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n", r.name)
            + &Env::spec(
                &format!("tk-{}", r.name),
                &format!("tk-{}", r.name),
                "attributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = false }\n",
                &[r],
                &format!("tk-{}", r.name),
                ", binding = \"pop-unwrap\"",
            )
    };
    let key = |o: &str, ty: &str, born: &Ref, other: &Ref| {
        format!("[objects.{o}]\n{ty}\ncreateOn = \"{}\"\n\n", born.name)
            + &Env::spec(&format!("{o}-src"), o, moves, &[born], &format!("f-{o}"), "")
            + &Env::spec(&format!("{o}-dst"), o, moves, &[other], &format!("f-{o}"), "")
    };
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
    let body = transport(soft)
        + &transport(kry)
        + &key("ek", ec, soft, kry)
        + &key("kk", ec, kry, soft)
        + &key("ks", aes, kry, soft)
        + "[objects.crt]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\n"
        + &Env::spec("crt-src", "crt", "", &[kry], "f-crt", "")
        + &Env::spec("crt-dst", "crt", "", &[soft], "f-crt", "");
    // A certificate, planted on kryoptic: a public object, moved as it is.
    let cert = x509_cert::Certificate::from_der(CERT).unwrap();
    open_session(&kry.module, "kmtest", "1234")
        .create_object(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Subject(cert.tbs_certificate().subject().to_der().unwrap()),
            Attribute::Value(CERT.to_vec()),
            Attribute::Token(true),
            Attribute::Label(b"f-crt".to_vec()),
        ])
        .unwrap();
    e.config_with(&body, &|r| format!("transportWith = \"tk-{}\"\n", r.name));
    // The keys are made where they are born; the planted certificate is adopted.
    for (verb, spec, r) in [
        ("create", "tk-softhsm", soft),
        ("create", "tk-kryoptic", kry),
        ("create", "ek-src", soft),
        ("create", "kk-src", kry),
        ("create", "ks-src", kry),
        ("realise", "crt-src", kry),
    ] {
        let o = e.cakeys(r, &[verb, spec, "--token", r.name]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
    }
    Some((e, real))
}

/// Run camigrate under `plan` (no dry-run twin: the plan's calls are counted for this run), and
/// what it said, its exit, and how many rules fired.
fn faulted(e: &Env, name: &str, plan: &str, args: &[&str]) -> (i32, String, usize) {
    let (path, trace) = (e.dir.join(format!("{name}.toml")), e.dir.join(format!("{name}.jsonl")));
    std::fs::write(&path, plan).unwrap();
    let leak = |p: &std::path::Path| -> &'static str { Box::leak(p.to_str().unwrap().to_owned().into_boxed_str()) };
    let env: &'static [(&str, &str)] =
        Box::leak(Box::new([("P11_FAULT_PLAN", leak(&path)), ("P11_FAULT_TRACE", leak(&trace))]));
    let r = Ref { env, ..e.refs[0].clone() };
    let o = e.km_alone(&r, args);
    let text = std::fs::read_to_string(&trace).unwrap_or_default();
    let fired = text.lines().filter(|l| !l.contains("\"rule\":null")).count();
    (code(&o), stderr(&o), fired)
}

/// A move the module fails part-way: the source's wrap, the target's unwrap, the creation or
/// the proof after it. Each is refused with the step named, the target is left without the
/// object, and the lock is as it was; with no plan, the same moves then succeed.
#[test]
fn a_move_the_module_fails_is_refused_and_undone() {
    let Some((e, real)) = tokens("fault-moves") else { return };
    let fails =
        |function: &str, more: &str| format!("[[rule]]\nfn = \"{function}\"\n{more}rv = \"CKR_DEVICE_ERROR\"\n");
    let out: &[&str] = &["migrate", "ek", "--from", "softhsm", "--to", "kryoptic"];
    let into: &[&str] = &["migrate", "kk", "--from", "kryoptic", "--to", "softhsm"];
    let host: &[&str] = &["migrate", "ks", "--from", "kryoptic", "--to", "softhsm", "--allow-host-plaintext"];
    let cert: &[&str] = &["migrate", "crt", "--from", "kryoptic", "--to", "softhsm"];
    let wrong_type =
        "[[rule]]\nfn = \"C_GetAttributeValue\"\nattribute = \"CKA_CERTIFICATE_TYPE\"\nvalue = \"0100000000000000\"\n";
    // `C_Sign` is asked the length first: the second call of a signature is the one that signs,
    // and it fails after the real call, which ends the operation (docs/FAULT_SHIM.md).
    let cases: Vec<(&str, &[&str], String, i32, &str)> = vec![
        // The source (softhsm) wraps: its key-encryption key, the transport key it loads, each wrap.
        ("kek", out, fails("C_GenerateKey", ""), 15, "making the KEK"),
        ("transport", out, fails("C_CreateObject", ""), 15, "loading the transport key"),
        ("wrap-kek", out, fails("C_WrapKey", "call = 1\n"), 15, "wrapping the KEK"),
        ("wrap-key", out, fails("C_WrapKey", "call = 3\n"), 15, "wrapping the key"),
        // The target (softhsm) unwraps (after its transport key proved possession by unwrapping,
        // twice), then proves possession of what it unwrapped.
        ("unwrap-kek", into, fails("C_UnwrapKey", "call = 3\n"), 13, "unwrapping the KEK"),
        ("unwrap-key", into, fails("C_UnwrapKey", "call = 4\n"), 13, "unwrapping the key"),
        ("proof", into, fails("C_Sign", "call = 6\nwhen = \"after\"\n"), 16, "just imported for 'kk'"),
        // The host path into softhsm: the creation, then the commitment of what was created.
        ("create", host, fails("C_CreateObject", ""), 15, "creating the key"),
        ("commit", host, fails("C_Sign", "call = 2\nwhen = \"after\"\n"), 15, "just imported for 'ks'"),
        // A certificate created on softhsm, which then says it is of another type than X.509.
        ("cert-type", cert, wrong_type.to_owned(), 13, "just imported for 'crt'"),
    ];
    let lock = std::fs::read(e.dir.join("keys.lock")).unwrap();
    let on_target = |label: &str| {
        let module = if label == "f-ek" { &e.refs[1].module } else { &real };
        open_session(module, "kmtest", "1234").labelled(label).len()
    };
    for (name, args, plan, exit, why) in &cases {
        let (code, said, fired) = faulted(&e, name, plan, args);
        assert_eq!(code, *exit, "{name}: {said}");
        assert!(said.contains(why), "{name}: expected {why:?} in {said}");
        assert_eq!(fired, 1, "{name}: the rule fired {fired} times");
        assert_eq!(on_target(&format!("f-{}", args[1])), 0, "{name}: left objects on the target");
        assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), lock, "{name}: changed the lock");
    }
    // The undoing itself refused: what was imported is still there, and said to be.
    let kept = fails("C_Sign", "call = 6\nwhen = \"after\"\n") + &fails("C_DestroyObject", "");
    let (code, said, _) = faulted(&e, "kept", &kept, into);
    assert_eq!(code, 16, "{said}");
    assert!(said.contains("is still on the token"), "{said}");
    assert!(on_target("f-kk") > 0);
    assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), lock, "kept: changed the lock");
    // Nothing was the moves' own fault: with no plan, the two not left half-done go through.
    for args in [out, host, cert] {
        let o = e.km_alone(&e.refs[0], args);
        assert_eq!(common::code(&o), 0, "{args:?}: {}", stderr(&o));
    }
}
