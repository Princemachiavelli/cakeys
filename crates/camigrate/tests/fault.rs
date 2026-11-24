//! camigrate against a module that fails or lies (`crates/p11-fault`, `docs/FAULT_SHIM.md`):
//! `SoftHSM` behind the shim as the source or the target of a move, kryoptic as the other side.
//! A move that cannot finish leaves the target as it was and the lock unchanged, and says why.
//!
//! Needs `P11_FAULT_MODULE` naming `SoftHSM` and `CAKEYS_KRYOPTIC_MODULE`, which the per-test
//! runner (nix/test-tokens.sh) sets; skipped without them.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::xref::{Env, Ref};
use common::*;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass};
use std::fmt::Write as _;
use x509_cert::der::{Decode as _, Encode as _};

const CERT: &[u8] = include_bytes!("../../cli/tests/fixtures/adopt-cert.der");

/// `SoftHSM` behind the shim (`softhsm`) and kryoptic, each naming a transport key of its own,
/// with three keys realised where they are born: `ek` (P-256) on `softhsm`, `kk` (P-256) and
/// `ks` (AES) on kryoptic, each with a spec on the other token.
fn tokens(name: &str) -> Option<(Env, String)> {
    let real = suite_var("P11_FAULT_MODULE", "CAKEYS_FAULT_REQUIRE", name)?;
    let kryoptic = suite_var("CAKEYS_KRYOPTIC_MODULE", "CAKEYS_KRYOPTIC_REQUIRE", name)?;
    let e = Env::over(name, vec![created_ref("softhsm", fault_shim()), created_ref("kryoptic", kryoptic)]);
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
                ", origin = \"create\", binding = \"pop-unwrap\"",
            )
    };
    let key = |o: &str, ty: &str, born: &Ref, other: &Ref| {
        format!("[objects.{o}]\n{ty}\n\n")
            + &Env::spec(&format!("{o}-src"), o, moves, &[born], &format!("f-{o}"), ", origin = \"create\"")
            + &Env::spec(&format!("{o}-dst"), o, moves, &[other], &format!("f-{o}"), ", origin = \"import\"")
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
        + &Env::spec("crt-dst", "crt", "", &[soft], "f-crt", ", origin = \"import\"");
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
    // SoftHSM's SO, for `transport --trusted` (the runner initialises it with SO PIN 5678).
    let so_pin = e.dir.join("so-pin");
    std::fs::write(&so_pin, "5678\n").unwrap();
    e.config_with(&body, &|r| {
        let so =
            if r.name == "softhsm" { format!("soCredentialFile = \"{}\"\n", so_pin.display()) } else { String::new() };
        format!("migrate = {{ transportWith = \"tk-{}\" }}\n{so}", r.name)
    });
    // The keys are made where they are born; the planted certificate is adopted.
    for (verb, spec, r) in [
        ("create", "tk-softhsm", soft),
        ("create", "tk-kryoptic", kry),
        ("create", "ek-src", soft),
        ("create", "kk-src", kry),
        ("create", "ks-src", kry),
        ("lock", "crt-src", kry),
    ] {
        let o = e.cakeys(r, &[verb, "--spec", spec, "--token", r.name]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
    }
    Some((e, real))
}

/// Run camigrate under `plan` (no dry-run twin: the plan's calls are counted for this run), and
/// what it said, its exit, and how many rules fired.
fn faulted(e: &Env, name: &str, plan: &str, args: &[&str]) -> (i32, String, usize) {
    let (path, trace) = (e.dir.join(format!("{name}.toml")), e.dir.join(format!("{name}.jsonl")));
    std::fs::write(&path, plan).unwrap();
    let env = ref_env(&[("P11_FAULT_PLAN", path.to_str().unwrap()), ("P11_FAULT_TRACE", trace.to_str().unwrap())]);
    let r = Ref { env, ..e.refs[0].clone() };
    let o = e.km_alone(&r, args);
    let text = std::fs::read_to_string(&trace).unwrap_or_default();
    let fired = text.lines().filter(|l| !l.contains("\"rule\":null")).count();
    (code(&o), stderr(&o), fired)
}

/// The sessions run `name` of [`faulted`] opened on the shimmed token, each by its flags.
fn sessions(e: &Env, name: &str) -> Vec<u64> {
    let text = std::fs::read_to_string(e.dir.join(format!("{name}.jsonl"))).unwrap_or_default();
    text.lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|c| c["fn"] == "C_OpenSession")
        .map(|c| c["flags"].as_u64().unwrap_or_default())
        .collect()
}

/// Every token object on `module`'s token `kmtest`: its class, label, ID and key type, sorted
/// (an object's handle may differ from one session to the next).
fn objects(module: &str) -> Vec<String> {
    let s = open_session(module, "kmtest", "1234");
    let kinds = [AttributeType::Class, AttributeType::Label, AttributeType::Id, AttributeType::KeyType];
    let mut all: Vec<String> = s
        .find_objects(&[Attribute::Token(true)])
        .unwrap()
        .into_iter()
        .map(|h| format!("{:?}", s.get_attributes(h, &kinds).unwrap()))
        .collect();
    all.sort();
    all
}

/// A move the module fails part-way: the source's wrap, the target's unwrap, the creation or
/// the proof after it. Each is refused with the step named, the target is left without the
/// object, and the lock is as it was; with no plan, the same moves then succeed.
#[test]
fn a_move_the_module_fails_is_refused_and_undone() {
    let Some((e, real)) = tokens("fault-moves") else { return };
    let fails =
        |function: &str, more: &str| format!("[[rule]]\nfn = \"{function}\"\n{more}rv = \"CKR_DEVICE_ERROR\"\n");
    let bad =
        |function: &str, more: &str| format!("[[rule]]\nfn = \"{function}\"\n{more}rv = \"CKR_WRAPPED_KEY_INVALID\"\n");
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
        // `C_WrapKey` too is asked the length first: calls 1 and 2 wrap the KEK to the transport
        // key (OAEP), 3 is the first of the key's own wrap under the KEK (RFC 5649) [run].
        ("wrap-kek", out, fails("C_WrapKey", "call = 1\n"), 15, "wrapping the KEK"),
        ("wrap-key", out, fails("C_WrapKey", "call = 3\n"), 15, "wrapping the key"),
        // The target (softhsm) unwraps (after its transport key proved possession by unwrapping,
        // twice: calls 1 and 2), then proves possession of what it unwrapped. A module that fails
        // the unwrap is 16, said as what may be a damaged bundle; one that says the blob is bad,
        // 13 (review sealed.rs F2: every unwrap failure was 13, "tampered with").
        ("unwrap-kek", into, fails("C_UnwrapKey", "call = 3\n"), 16, "unwrapping the KEK"),
        ("unwrap-key", into, fails("C_UnwrapKey", "call = 4\n"), 16, "damaged or altered bundle"),
        ("unwrap-bad", into, bad("C_UnwrapKey", "call = 4\n"), 13, "the bundle was tampered with"),
        // Each of the transport key's two proofs signs an HMAC of the secret it unwrapped (calls 1
        // to 4, the length then the MAC); `kk`'s own proof is then calls 5 and 6 (ECDSA) [run].
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
    // Both tokens, the source's too: a key-encryption key or a loaded transport key the error
    // path left as a token object would show there (review fault.rs F1: only the target's label
    // was looked for). `real` is SoftHSM itself, past the shim.
    let tokens = || (objects(&real), objects(&e.refs[1].module));
    let before = tokens();
    for (name, args, plan, exit, why) in &cases {
        let (code, said, fired) = faulted(&e, name, plan, args);
        assert_eq!(code, *exit, "{name}: {said}");
        assert!(said.contains(why), "{name}: expected {why:?} in {said}");
        assert_eq!(fired, 1, "{name}: the rule fired {fired} times");
        // The shimmed token, source or target, is opened once per run (review lib.rs F5: a
        // target was opened read-only for the plan, then again read-write for the move).
        assert_eq!(sessions(&e, name).len(), 1, "{name}: sessions opened {:?}", sessions(&e, name));
        assert_eq!(on_target(&format!("f-{}", args[1])), 0, "{name}: left objects on the target");
        assert_eq!(tokens(), before, "{name}: left objects on a token");
        assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), lock, "{name}: changed the lock");
    }
    // The undoing itself refused: what was imported is still there, and said to be. (`call = 6`:
    // `kk`'s proof, as in "proof".)
    let kept = fails("C_Sign", "call = 6\nwhen = \"after\"\n") + &fails("C_DestroyObject", "");
    let (code, said, _) = faulted(&e, "kept", &kept, into);
    assert_eq!(code, 16, "{said}");
    assert!(said.contains("is still on the token"), "{said}");
    assert!(on_target("f-kk") > 0);
    assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), lock, "kept: changed the lock");
    // Nothing was the moves' own fault: with no plan, the three not left half-done go through,
    // and each lands where it was sent, recorded and verified (review fault.rs F2: exit 0
    // alone passed a move that recorded nothing).
    for args in [out, host, cert] {
        let o = e.km_alone(&e.refs[0], args);
        assert_eq!(common::code(&o), 0, "{args:?}: {}", stderr(&o));
        let (spec, to) = (format!("{}-dst", args[1]), args[5]);
        let o = e.cakeys(&e.refs[0], &["check", "--spec", &spec, "--token", to]);
        assert_eq!(common::code(&o), 0, "{spec} on {to}: {}", stderr(&o));
    }
}

/// An SO step that succeeded is said to have succeeded (token/mod.rs F2): the SO's
/// `C_Logout` after `transport --trusted` made the trusted copy fails, and the run says the copy
/// was made, never only the logout's error; the next run finds the copy and has nothing to do.
#[test]
fn an_so_step_that_was_done_is_said_to_be_done() {
    let Some((e, _real)) = tokens("fault-so-logout") else { return };
    let trust: &[&str] = &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--trust-on", "softhsm"];
    // The user's logout before the SO's login is the first; the SO's own, after the step, the second.
    let (code, said, fired) =
        faulted(&e, "so-logout", "[[rule]]\nfn = \"C_Logout\"\ncall = 2\nrv = \"CKR_DEVICE_ERROR\"\n", trust);
    assert_ne!(code, 0, "{said}");
    assert_eq!(fired, 1, "{said}");
    assert!(said.contains("marking the transport key trusted on 'softhsm' was done"), "{said}");
    let o = e.km_alone(&e.refs[0], trust);
    assert_eq!(common::code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("already trusts"), "{}", stderr(&o));
}

/// A run records each object as it lands (docs/REVIEW D2, camigrate lib.rs F4): an import of a
/// bundle carrying `kk` and `crt` into `softhsm`, killed at `crt`'s `C_CreateObject` (the second:
/// the first is `kk`'s public half), has recorded `kk`, so nothing it made sits on the target
/// unrecorded; the next run finds `kk` there, verifies it, and imports `crt`.
#[test]
fn an_import_killed_part_way_has_recorded_what_it_made() {
    let Some((e, real)) = tokens("fault-killed") else { return };
    let bundle = e.dir.join("killed.bundle.toml");
    let path = bundle.to_str().unwrap();
    let export = ["export", "kk", "crt", "--from", "kryoptic", "--to", "softhsm", "--out", path];
    let o = e.km_alone(&e.refs[1], &export);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let import: &[&str] = &["import", "--to", "softhsm", "--in", path];
    let plan = e.dir.join("killed.toml");
    std::fs::write(&plan, "[[rule]]\nfn = \"C_CreateObject\"\ncall = 2\nabort = true\n").unwrap();
    let env = ref_env(&[("P11_FAULT_PLAN", plan.to_str().unwrap())]);
    let o = e.km_alone(&Ref { env, ..e.refs[0].clone() }, import);
    assert_eq!(o.status.code(), None, "the plan did not end the run: {}", stderr(&o));
    let on_target = |label: &str| open_session(&real, "kmtest", "1234").labelled(label).len();
    assert_eq!((on_target("f-kk"), on_target("f-crt")), (2, 0), "kk and its public half, no certificate");
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    assert!(lock["realisations"]["kk-dst"].get("softhsm").is_some(), "made before the kill, not recorded: {lock}");
    assert!(lock["realisations"].get("crt-dst").is_none(), "{lock}");
    let o = e.km_alone(&e.refs[0], import);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("already realised and verifies"), "{}", stderr(&o));
    assert_eq!(on_target("f-crt"), 1);
}

/// A token's transport key never leaves, as if `noExport` (docs/CONFIG.md): named, a move is
/// refused (15) and says it is the transport key; without names, an export leaves it out without
/// a warning and a migrate moves everything else, where it stopped at it (15) before.
#[test]
fn a_transport_key_never_leaves() {
    let Some((e, real)) = tokens("transport-stays") else { return };
    let soft = &e.refs[0];
    let o = e.km_alone(soft, &["migrate", "tk-kryoptic", "--from", "kryoptic", "--to", "softhsm", "--dry-run"]);
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("the transport key of token 'kryoptic'"), "{}", stdout(&o));
    let out = e.dir.join("all.bundle.toml");
    let o = e.km_alone(soft, &["export", "--from", "kryoptic", "--to", "softhsm", "--out", out.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stderr(&o).contains("tk-kryoptic"), "{}", stderr(&o));
    assert!(!std::fs::read_to_string(&out).unwrap().contains("tk-kryoptic"));
    let o = e.km_alone(soft, &["migrate", "--from", "kryoptic", "--to", "softhsm", "--allow-host-plaintext"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let on_target = |label: &str| open_session(&real, "kmtest", "1234").labelled(label).len();
    assert_eq!(on_target("tk-kryoptic"), 0);
    assert!(["f-kk", "f-ks", "f-crt"].iter().all(|l| on_target(l) > 0), "the others did not move");
}

/// An export to a bundle opens its target token once (review lib.rs F5): with no public key of
/// the transport key in the lock, the plan's session reads it, where the export opened the token
/// a second time and logged in again (`CKR_USER_ALREADY_LOGGED_IN` in the coverage trace).
#[test]
fn an_export_opens_its_target_once() {
    let Some((e, _)) = tokens("export-opens-once") else { return };
    let lock = e.dir.join("keys.lock");
    let mut doc: toml::Table = toml::from_str(&std::fs::read_to_string(&lock).unwrap()).unwrap();
    let tk = doc["objects"].as_table_mut().and_then(|o| o.get_mut("tk-softhsm")).and_then(toml::Value::as_table_mut);
    assert!(tk.expect("the lock records tk-softhsm").remove("publicKey").is_some(), "no publicKey to forget");
    std::fs::write(&lock, toml::to_string(&doc).unwrap()).unwrap();
    let out = e.dir.join("once.bundle.toml");
    let args = ["export", "kk", "--from", "kryoptic", "--to", "softhsm", "--out", out.to_str().unwrap()];
    let (code, said, _) = faulted(&e, "export-once", "", &args);
    assert_eq!(code, 0, "{said}");
    assert!(said.contains("the lock records no public key for it yet"), "the token was not read: {said}");
    assert_eq!(sessions(&e, "export-once").len(), 1, "the export opened its target more than once");
}

/// Each object of a `migrate` moves on its own, as a bundle's keys import (review D8): the one
/// the module fails is undone and the run exits with its failure, the others still move and
/// the lock records them. Two certificates on kryoptic move into `SoftHSM`, which says the
/// first is of another type than X.509 once created (13); the second moves.
#[test]
fn a_failed_move_leaves_the_others_moving() {
    let name = "fault-migrate-rest";
    let Some(real) = suite_var("P11_FAULT_MODULE", "CAKEYS_FAULT_REQUIRE", name) else { return };
    let Some(kryoptic) = suite_var("CAKEYS_KRYOPTIC_MODULE", "CAKEYS_KRYOPTIC_REQUIRE", name) else { return };
    let e = Env::over(name, vec![created_ref("softhsm", fault_shim()), created_ref("kryoptic", kryoptic)]);
    let (soft, kry) = (&e.refs[0], &e.refs[1]);
    let mut body = String::new();
    let session = open_session(&kry.module, "kmtest", "1234");
    for (o, der) in [
        ("c1", &include_bytes!("../../cli/tests/fixtures/adopt-cert.der")[..]),
        ("c2", &include_bytes!("../../cli/tests/fixtures/adopt-cert-p384.der")[..]),
    ] {
        writeln!(body, "[objects.{o}]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n").unwrap();
        body += &Env::spec(&format!("{o}-src"), o, "", &[kry], &format!("f-{o}"), "");
        body += &Env::spec(&format!("{o}-dst"), o, "", &[soft], &format!("f-{o}"), ", origin = \"import\"");
        let cert = x509_cert::Certificate::from_der(der).unwrap();
        session
            .create_object(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Subject(cert.tbs_certificate().subject().to_der().unwrap()),
                Attribute::Value(der.to_vec()),
                Attribute::Token(true),
                Attribute::Label(format!("f-{o}").into_bytes()),
            ])
            .unwrap();
    }
    e.config_with(&body, &|_| String::new());
    for spec in ["c1-src", "c2-src"] {
        let o = e.cakeys(kry, &["lock", "--spec", spec, "--token", "kryoptic"]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
    }
    let lie = "[[rule]]\nfn = \"C_GetAttributeValue\"\nof_label = \"f-c1\"\nattribute = \"CKA_CERTIFICATE_TYPE\"\n\
               value = \"0100000000000000\"\n";
    let (code, said, _) = faulted(&e, "rest", lie, &["migrate", "--from", "kryoptic", "--to", "softhsm"]);
    assert_eq!(code, 13, "{said}");
    assert!(said.contains("just imported for 'c1'"), "{said}");
    let on_target = |label: &str| open_session(&real, "kmtest", "1234").labelled(label).len();
    assert_eq!((on_target("f-c1"), on_target("f-c2")), (0, 1), "{said}");
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    let realised = |spec: &str| lock["realisations"].get(spec).is_some_and(|r| r.get("softhsm").is_some());
    assert_eq!((realised("c1-dst"), realised("c2-dst")), (false, true), "{lock}");
}
