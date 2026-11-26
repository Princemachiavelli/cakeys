//! Tests camigrate against a module that fails or returns false answers (`crates/p11-fault`,
//! `docs/FAULT_SHIM.md`). `SoftHSM` runs behind the shim as the source or the target of a move,
//! and kryoptic is the other side. A move that cannot finish leaves the target as it was and the
//! lock unchanged, and it reports why.
//!
//! The tests need `P11_FAULT_MODULE` naming `SoftHSM`, and `CAKEYS_KRYOPTIC_MODULE`, which the
//! runner for each test (nix/test-tokens.sh) sets. The tests are skipped without them.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::state;
use common::xref::{Env, Ref};
use common::*;
use cryptoki::object::{Attribute, CertificateType, ObjectClass};
use std::fmt::Write as _;
use x509_cert::der::{Decode as _, Encode as _};

const CERT: &[u8] = include_bytes!("../../cli/tests/fixtures/adopt-cert.der");

/// Sets up `SoftHSM` behind the shim (`softhsm`) and kryoptic, each naming its own transport key,
/// with three keys realised where they are born: `ek` (P-256) on `softhsm`, and `kk` (P-256) and
/// `ks` (AES) on kryoptic. Each key also has a spec on the other token.
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
    // Plant a certificate on kryoptic. It is a public object, so it moves as it is.
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
    // SoftHSM's SO PIN, for `transport --trust-on` (the runner initialises the token with the SO
    // PIN 5678).
    let so_pin = e.dir.join("so-pin");
    std::fs::write(&so_pin, "5678\n").unwrap();
    e.config_with(&body, &|r| {
        let so =
            if r.name == "softhsm" { format!("soCredentialFile = \"{}\"\n", so_pin.display()) } else { String::new() };
        format!("migrate = {{ transportWith = \"tk-{}\" }}\n{so}", r.name)
    });
    // The keys are made where they are born, and the planted certificate is adopted.
    for (verb, spec, r) in [
        ("create", "tk-softhsm", soft),
        ("create", "tk-kryoptic", kry),
        ("create", "ek-src", soft),
        ("create", "kk-src", kry),
        ("create", "ks-src", kry),
        ("lock", "crt-src", kry),
    ] {
        let o = e.cakeys(r, &[verb, "--spec", spec, "--token", r.name]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    Some((e, real))
}

/// Runs camigrate under the fault plan `plan`, and returns its exit code, its standard error, and
/// the number of rules that fired. It runs no dry-run twin, because the plan's calls are counted
/// for this run.
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

/// Returns the flags of each session that the run `name` of [`faulted`] opened on the shimmed
/// token.
fn sessions(e: &Env, name: &str) -> Vec<u64> {
    let text = std::fs::read_to_string(e.dir.join(format!("{name}.jsonl"))).unwrap_or_default();
    text.lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|c| c["fn"] == "C_OpenSession")
        .map(|c| c["flags"].as_u64().unwrap_or_default())
        .collect()
}

/// Returns the current state of the lock and of both tokens (`state::snapshot`): `SoftHSM` itself,
/// read without the shim (`real`), and kryoptic.
fn now(e: &Env, real: &str) -> state::Snapshot {
    let softhsm = state::TokenView { module: real, ..e.refs[0].view() };
    state::snapshot(&[&e.dir.join("keys.lock")], &[softhsm, e.refs[1].view()])
}

/// Checks moves that the module fails part of the way through: the source's wrap, the target's
/// unwrap, the creation, or the proof after it. Each move is refused with the step named, the
/// target is left without the object, and the lock stays as it was. Without a fault plan, the
/// same moves then succeed.
#[test]
fn a_move_the_module_fails_is_refused_and_undone() {
    let Some((e, real)) = tokens("fault-moves") else { return };
    let fails =
        |function: &str, more: &str| format!("[[rule]]\nfn = \"{function}\"\n{more}rv = \"CKR_DEVICE_ERROR\"\n");
    let bad =
        |function: &str, more: &str| format!("[[rule]]\nfn = \"{function}\"\n{more}rv = \"CKR_WRAPPED_KEY_INVALID\"\n");
    let refuses = |function: &str| format!("[[rule]]\nfn = \"{function}\"\nrv = \"CKR_MECHANISM_INVALID\"\n");
    let out: &[&str] = &["migrate", "ek", "--from", "softhsm", "--to", "kryoptic"];
    let into: &[&str] = &["migrate", "kk", "--from", "kryoptic", "--to", "softhsm"];
    let host: &[&str] = &["migrate", "ks", "--from", "kryoptic", "--to", "softhsm", "--allow-host-plaintext"];
    let cert: &[&str] = &["migrate", "crt", "--from", "kryoptic", "--to", "softhsm"];
    let wrong_type =
        "[[rule]]\nfn = \"C_GetAttributeValue\"\nattribute = \"CKA_CERTIFICATE_TYPE\"\nvalue = \"0100000000000000\"\n";
    // `C_Sign` is first called for the length, so the second call of a signature is the one that
    // signs. That call fails after the real call, which ends the operation (docs/FAULT_SHIM.md).
    // A step that fails with a device error (`CKR_DEVICE_ERROR`) exits 16 and names the step. Only
    // the module's refusal of the step exits 15 (review 2026-11-24 L4a-1 found that device
    // failures also exited 15).
    let cases: Vec<(&str, &[&str], String, i32, &str)> = vec![
        // The source (softhsm) wraps. The faults hit its key-encryption key, the transport key
        // that it loads, and each wrap.
        ("kek", out, fails("C_GenerateKey", ""), 16, "making the KEK"),
        ("kek-refused", out, refuses("C_GenerateKey"), 15, "making the KEK"),
        ("transport", out, fails("C_CreateObject", ""), 16, "loading the transport key"),
        // `C_WrapKey` is also first called for the length. Calls 1 and 2 wrap the KEK to the
        // transport key (OAEP), and call 3 is the first call of the key's own wrap under the KEK
        // (RFC 5649) [run].
        ("wrap-kek", out, fails("C_WrapKey", "call = 1\n"), 16, "wrapping the KEK"),
        ("wrap-key", out, fails("C_WrapKey", "call = 3\n"), 16, "wrapping the key"),
        // The target (softhsm) unwraps, after its transport key proved possession by unwrapping
        // twice (calls 1 and 2), and then proves possession of what it unwrapped. When the module
        // fails the unwrap, the run exits 16 and says that the bundle may be damaged. When the
        // module says that the blob is invalid, the run exits 13 (review sealed.rs F2 found that
        // every unwrap failure was 13, "tampered with").
        ("unwrap-kek", into, fails("C_UnwrapKey", "call = 3\n"), 16, "unwrapping the KEK"),
        ("unwrap-key", into, fails("C_UnwrapKey", "call = 4\n"), 16, "damaged or altered bundle"),
        ("unwrap-bad", into, bad("C_UnwrapKey", "call = 4\n"), 13, "the bundle was tampered with"),
        // Each of the transport key's two proofs signs an HMAC of the secret that it unwrapped
        // (calls 1 to 4, first the length and then the MAC). `kk`'s own proof is then calls 5
        // and 6 (ECDSA) [run].
        ("proof", into, fails("C_Sign", "call = 6\nwhen = \"after\"\n"), 16, "just imported for 'kk'"),
        // The host path into softhsm: the creation, and then the commitment of what was created.
        ("create", host, fails("C_CreateObject", ""), 16, "creating the key"),
        ("create-refused", host, refuses("C_CreateObject"), 15, "creating the key"),
        ("commit", host, fails("C_Sign", "call = 2\nwhen = \"after\"\n"), 16, "just imported for 'ks'"),
        // A certificate is created on softhsm, and softhsm then reports a type other than X.509
        // for it.
        ("cert-type", cert, wrong_type.to_owned(), 13, "just imported for 'crt'"),
    ];
    let lock = std::fs::read(e.dir.join("keys.lock")).unwrap();
    let on_target = |label: &str| {
        let module = if label == "f-ek" { &e.refs[1].module } else { &real };
        open_session(module, "kmtest", "1234").labelled(label).len()
    };
    // Take a snapshot of both tokens, including the source, and of the lock. A key-encryption key
    // or a loaded transport key that the error path left as a token object would show there
    // (review fault.rs F1 found that only the target's label was checked).
    let before = now(&e, &real);
    for (name, args, plan, exit, why) in &cases {
        let (code, said, fired) = faulted(&e, name, plan, args);
        assert_eq!(code, *exit, "{name}: {said}");
        assert!(said.contains(why), "{name}: expected {why:?} in {said}");
        assert_eq!(fired, 1, "{name}: the rule fired {fired} times");
        // The shimmed token, as the source or the target, is opened once in each run (review
        // lib.rs F5 found that a target was opened read-only for the plan, and then again
        // read-write for the move).
        assert_eq!(sessions(&e, name).len(), 1, "{name}: sessions opened {:?}", sessions(&e, name));
        assert_eq!(on_target(&format!("f-{}", args[1])), 0, "{name}: left objects on the target");
        state::assert_unchanged(&before, &now(&e, &real), name);
    }
    // When the removal itself is refused, the imported object stays on the token, and the run
    // says so. (`call = 6` is `kk`'s proof, as in the "proof" case.)
    let kept = fails("C_Sign", "call = 6\nwhen = \"after\"\n") + &fails("C_DestroyObject", "");
    let (code, said, _) = faulted(&e, "kept", &kept, into);
    assert_eq!(code, 16, "{said}");
    assert!(said.contains("is still on the token"), "{said}");
    assert!(on_target("f-kk") > 0);
    assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), lock, "kept: changed the lock");
    // The failures came only from the fault plans. Without a plan, the three moves that were not
    // left half-done go through, and each lands where it was sent, recorded and verified (review
    // fault.rs F2 found that a check of exit 0 alone passed a move that recorded nothing).
    for args in [out, host, cert] {
        let o = e.km_alone(&e.refs[0], args);
        assert_eq!(common::code(&o), 22, "{args:?}: {}", stderr(&o));
        let (spec, to) = (format!("{}-dst", args[1]), args[5]);
        let o = e.cakeys(&e.refs[0], &["check", "--spec", &spec, "--token", to]);
        assert_eq!(common::code(&o), 0, "{spec} on {to}: {}", stderr(&o));
    }
}

/// Checks that a source that hands over another key than the one that was asked for is caught on
/// the host before anything is written (review 2026-11-24 D-5, and C-13 for the host move). The
/// fault is p11-fault's `wrap_label`: `C_WrapKey` wraps `f-kk` when it was asked for `f-ek`. No
/// key file is written, no key is made on the target, each run exits 10, and the lock and both
/// tokens stay as they were. Without the substitution, each run goes through.
#[test]
fn a_source_that_hands_over_another_key_writes_nothing() {
    let Some((e, real)) = tokens("fault-other-key") else { return };
    let (soft, kry) = (&e.refs[0], &e.refs[1]);
    // Put a second extractable P-256 key on the shimmed token, to hand over in place of `ek`.
    let o = e.km_alone(soft, &["migrate", "kk", "--from", "kryoptic", "--to", "softhsm"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let (out, pass, lock) = (e.dir.join("ek.p8"), e.dir.join("pass"), e.dir.join("keys.lock"));
    std::fs::write(&pass, "correct horse\n").unwrap();
    let (out_s, pass_s) = (out.to_str().unwrap(), pass.to_str().unwrap());
    let other = "[[rule]]\nfn = \"C_WrapKey\"\nof_label = \"f-ek\"\nwrap_label = \"f-kk\"\n";
    // Force the host path out of softhsm: its sealed methods are hidden, so RFC 5649 to the host
    // is the only method left.
    let host_only = "[[rule]]\nfn = \"C_GetMechanismList\"\n\
                     hide_mechanisms = [\"CKM_RSA_PKCS_OAEP\", \"CKM_RSA_AES_KEY_WRAP\", \"CKM_ECDH1_DERIVE\"]\n\n";
    let file: &[&str] = &[
        "export",
        "ek",
        "--from",
        "softhsm",
        "--to-key-file",
        "pkcs8",
        "--out",
        out_s,
        "--passphrase-file",
        pass_s,
        "--allow-host-plaintext",
    ];
    let host: &[&str] = &["migrate", "ek", "--from", "softhsm", "--to", "kryoptic", "--allow-host-plaintext"];
    // Read SoftHSM itself without the shim, as the other tests do.
    let softhsm = state::TokenView { module: &real, ..soft.view() };
    let views = [softhsm, kry.view()];
    let now = || state::snapshot(&[&lock, &out], &views);
    for (name, args, plan) in [("key-file", file, other.to_owned()), ("host", host, format!("{host_only}{other}"))] {
        let before = now();
        let (code, said, _) = faulted(&e, name, &plan, args);
        assert_eq!(code, 10, "{name}: {said}");
        state::assert_unchanged(&before, &now(), name);
    }
    for (name, args, plan, exit) in [("key-file-ok", file, "", 0), ("host-ok", host, host_only, 22)] {
        let (code, said, _) = faulted(&e, name, plan, args);
        assert_eq!(code, exit, "{name}: {said}");
    }
    assert!(out.exists(), "no key file without the substitution");
}

/// Checks that an SO step that succeeded is reported as succeeded (token/mod.rs F2). The SO's
/// `C_Logout` fails after `transport --trust-on` made the trusted copy, and the run says that the
/// copy was made, not only the logout's error. The next run finds the copy and has nothing to do.
#[test]
fn an_so_step_that_was_done_is_said_to_be_done() {
    let Some((e, _real)) = tokens("fault-so-logout") else { return };
    let trust: &[&str] = &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--trust-on", "softhsm"];
    // The user's logout before the SO's login is the first `C_Logout` call, and the SO's own
    // logout after the step is the second.
    let (code, said, fired) =
        faulted(&e, "so-logout", "[[rule]]\nfn = \"C_Logout\"\ncall = 2\nrv = \"CKR_DEVICE_ERROR\"\n", trust);
    assert_ne!(code, 0, "{said}");
    assert_eq!(fired, 1, "{said}");
    assert!(said.contains("marking the transport key trusted on 'softhsm' was done"), "{said}");
    let o = e.km_alone(&e.refs[0], trust);
    assert_eq!(common::code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("already trusts"), "{}", stderr(&o));
}

/// Checks that a run records each object as it lands (docs/REVIEW D2, camigrate lib.rs F4). An
/// import of a bundle that carries `kk` and `crt` into `softhsm` is killed at `crt`'s
/// `C_CreateObject` (the second call; the first call creates `kk`'s public half). By then, the run
/// has recorded `kk`, so nothing that it made is on the target without a record. The next run
/// finds `kk` there, verifies it, and imports `crt`.
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
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert!(stderr(&o).contains("already realised and verifies"), "{}", stderr(&o));
    assert_eq!(on_target("f-crt"), 1);
}

/// Checks that a token's transport key never leaves, as if its spec said `noExport`
/// (docs/CONFIG.md). When the key is named, a move is refused (15) and says that it is the
/// transport key. Without names, an export leaves the key out without a warning, and a migrate
/// moves everything else; before this change, the migrate stopped at the key (15).
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
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let on_target = |label: &str| open_session(&real, "kmtest", "1234").labelled(label).len();
    assert_eq!(on_target("tk-kryoptic"), 0);
    assert!(["f-kk", "f-ks", "f-crt"].iter().all(|l| on_target(l) > 0), "the others did not move");
}

/// Checks that an export to a bundle opens its target token once (review lib.rs F5). When the lock
/// has no public key for the transport key, the plan's session reads it. Before this change, the
/// export opened the token a second time and logged in again (`CKR_USER_ALREADY_LOGGED_IN` in the
/// coverage trace).
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

/// Checks that each object of a `migrate` moves on its own, in the same way as a bundle's keys
/// import (review D8). The object that the module fails is undone, and its row shows the failure's
/// code. The other objects still move, and the lock records them. Because the lock was written,
/// the run exits 22 (before review 2026-11-24 L5, it exited with the failure's code although the
/// lock had changed). Two certificates on kryoptic move into `SoftHSM`. `SoftHSM` reports the
/// first one as a type other than X.509 after it is created (13), and the second one moves.
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
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    let lie = "[[rule]]\nfn = \"C_GetAttributeValue\"\nof_label = \"f-c1\"\nattribute = \"CKA_CERTIFICATE_TYPE\"\n\
               value = \"0100000000000000\"\n";
    let (code, said, _) = faulted(&e, "rest", lie, &["migrate", "--from", "kryoptic", "--to", "softhsm"]);
    assert_eq!(code, 22, "{said}");
    assert!(said.contains("just imported for 'c1'"), "{said}");
    let on_target = |label: &str| open_session(&real, "kmtest", "1234").labelled(label).len();
    assert_eq!((on_target("f-c1"), on_target("f-c2")), (0, 1), "{said}");
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    let realised = |spec: &str| lock["realisations"].get(spec).is_some_and(|r| r.get("softhsm").is_some());
    assert_eq!((realised("c1-dst"), realised("c2-dst")), (false, true), "{lock}");
}

/// Checks that every entry path that would write to a write-protected target
/// (`CKF_WRITE_PROTECTED`) refuses it (15), in the dry run as in the run. Review 2026-11-24
/// L4a-3 found that the dry runs opened their target read-only and passed it. The entry paths are
/// a `migrate`, whose plan takes the target from the lock when the target does not open, an
/// `import` of a bundle, and an `import` of a key file. Nothing changes, and the injected fault
/// fires. Without the fault, each dry run passes.
#[test]
fn a_write_protected_target_is_refused_by_each_dry_run_as_by_its_run() {
    let Some((e, real)) = tokens("write-protected") else { return };
    let (soft, kry) = (&e.refs[0], &e.refs[1]);
    // Make the inputs of the imports first: a bundle of kk for softhsm, and kk as a key file.
    let (bundle, file, pass) = (e.dir.join("kk.bundle.toml"), e.dir.join("kk.p8"), e.dir.join("pass"));
    std::fs::write(&pass, "correct horse\n").unwrap();
    let (bundle, file, pass) = (bundle.to_str().unwrap(), file.to_str().unwrap(), pass.to_str().unwrap());
    let plaintext = ["--passphrase-file", pass, "--allow-host-plaintext"];
    for args in [
        &["export", "kk", "--from", "kryoptic", "--to", "softhsm", "--out", bundle][..],
        &[&["export", "kk", "--from", "kryoptic", "--to-key-file", "pkcs8", "--out", file][..], &plaintext].concat(),
    ] {
        let o = e.km_alone(kry, args);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
    }
    let protected = "[[rule]]\nfn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_WRITE_PROTECTED\"]\n";
    let lock = e.dir.join("keys.lock");
    let views = [state::TokenView { module: &real, ..soft.view() }, kry.view()];
    let now = || state::snapshot(&[&lock], &views);
    let runs: [Vec<&str>; 3] = [
        vec!["migrate", "kk", "--from", "kryoptic", "--to", "softhsm"],
        vec!["import", "--to", "softhsm", "--in", bundle],
        [&["import", "--to", "softhsm", "--in", file][..], &plaintext].concat(),
    ];
    for (i, run) in runs.iter().enumerate() {
        let dry = [&run[..], &["--dry-run"]].concat();
        for (j, args) in [&run[..], &dry[..]].into_iter().enumerate() {
            let before = now();
            let (code, said, fired) = faulted(&e, &format!("protected-{i}-{j}"), protected, args);
            assert_eq!(code, 15, "{args:?}: {said}");
            assert!(fired > 0, "{args:?}: the token was never asked its flags");
            state::assert_unchanged(&before, &now(), &format!("{args:?}"));
        }
        let (code, said, _) = faulted(&e, &format!("honest-{i}"), "", &dry);
        assert_eq!(code, 0, "{dry:?}: {said}");
    }
}
