//! The dry-run matrix (MIGRATE.md phase 1) across the reference tokens: the plan follows each
//! side's capabilities, and a transport file carries the locked identity. The source and target
//! realisations are recorded with `cakeys` (built beside camigrate, `common::sibling`), the
//! plans made with camigrate. A reference takes part when its suite's variables are set, as in
//! `cakeys`' tests/references.rs; skipped with fewer than two.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::xref::{Env, Ref, env};
use common::*;

/// `export --dry-run` (MIGRATE.md phase 1): the plan follows each side's capabilities. Between
/// the software references, the composed sealed method with the strongest OAEP hash both
/// implement; to tpm2-pkcs11 and through p11-kit (whose RPC drops AES key wrap) only through the
/// host, behind the flag; to a file behind the flag; a key made non-extractable never. Nothing
/// moves without --dry-run yet.
#[test]
fn export_plans_follow_each_sides_capabilities() {
    let Some(e) = env("export-plan") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping export-plan: needs the softhsm and kryoptic references");
        return;
    };
    let p256 = |o: &str| {
        format!("[objects.{o}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n")
    };
    let attrs = |x: bool| format!("attributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = {x} }}\n");
    let body = p256("movable")
        + &p256("fixed")
        + &p256("movable-k")
        + &Env::spec("movable", "movable", &attrs(true), &[soft], "xref-mv", ", autoCreate = true")
        + &Env::spec("fixed", "fixed", &attrs(false), &[soft], "xref-fx", ", autoCreate = true")
        + &Env::spec("movable-k", "movable-k", &attrs(true), &[kry], "xref-mvk", ", autoCreate = true");
    e.config(&body);
    for (spec, r) in [("movable", soft), ("fixed", soft), ("movable-k", kry)] {
        assert_eq!(code(&e.cakeys(r, &["realise", spec, "--token", r.name])), 0, "{spec}");
    }
    let plan = |r: &Ref, args: &[&str]| -> (i32, serde_json::Value) {
        let mut a = vec!["export"];
        a.extend_from_slice(args);
        a.extend(["--token", r.name, "--dry-run", "--json"]);
        let o = e.km(r, &a);
        (code(&o), serde_json::from_str(&stdout(&o)).unwrap_or_default())
    };
    let first = |v: &serde_json::Value| {
        let p = &v["plans"][0];
        (p["method"].as_str().map(str::to_owned), p["exposure"].as_str().map(str::to_owned), p["ready"].as_bool())
    };
    let some = |s: &str| Some(s.to_owned());

    let (c, v) = plan(soft, &["movable", "--target", "kryoptic"]);
    assert_eq!(c, 0, "{v}");
    assert_eq!(first(&v), (some("rsa-oaep-sha1+aes-kwp"), some("sealed"), Some(true)), "{v}");
    assert_eq!(v["capabilities"]["to"], "token");
    if named("kryoptic-der").is_some() {
        let (c, v) = plan(kry, &["movable-k", "--target", "kryoptic-der"]);
        assert_eq!((c, first(&v).0), (0, some("rsa-oaep-sha256+aes-kwp")), "{v}");
    }
    let (c, v) = plan(soft, &["fixed", "--target", "kryoptic"]);
    assert_eq!((c, first(&v).0), (15, None), "{v}");
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("not extractable"), "{v}");
    if named("tpm2").is_some() {
        let (c, v) = plan(soft, &["movable", "--target", "tpm2"]);
        assert_eq!((c, first(&v)), (15, (some("tpm2-ptool"), some("host"), Some(false))), "{v}");
        assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("--allow-host-plaintext"), "{v}");
        let (c, v) = plan(soft, &["movable", "--target", "tpm2", "--allow-host-plaintext"]);
        assert_eq!((c, first(&v).2), (0, Some(true)), "{v}");
        assert!(v["plans"][0]["notes"][0].as_str().unwrap().contains("residence"), "{v}");
    }
    if named("p11kit").is_some() {
        let (c, v) = plan(soft, &["movable", "--target", "p11kit"]);
        assert_eq!((c, first(&v)), (15, (some("host-pkcs8"), some("host"), Some(false))), "{v}");
    }
    let (c, v) = plan(soft, &["movable", "--to-file", "pkcs12", "--allow-host-plaintext"]);
    assert_eq!((c, first(&v)), (0, (some("pkcs12"), some("file"), Some(true))), "{v}");
    // Every object on the source: one plan each, 15 since one cannot move.
    let (c, v) = plan(soft, &["--target", "kryoptic"]);
    assert_eq!((c, v["plans"].as_array().map(Vec::len)), (15, Some(2)), "{v}");
    let o = e.km(soft, &["export", "movable", "--token", "softhsm", "--target", "kryoptic"]);
    assert_eq!(code(&o), 15);
    assert!(String::from_utf8_lossy(&o.stderr).contains("only --dry-run"));
}

/// `camigrate transport` (MIGRATE.md D3) writes the transport key's public half with its locked
/// identity; an export planned from that file alone wraps to it, and an edited file is refused.
#[test]
fn transport_files_carry_the_locked_identity() {
    let Some(e) = env("transport") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping transport: needs the softhsm and kryoptic references");
        return;
    };
    let body = "[objects.kek]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 3072\n\n\
                [objects.ec]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [objects.mv]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        .to_owned()
        + &Env::spec(
            "kek",
            "kek",
            "attributes = { CKA_UNWRAP = true, CKA_DECRYPT = true, CKA_EXTRACTABLE = false }\n",
            &[kry],
            "xref-kek",
            ", autoCreate = true, binding = \"pop-decrypt\"",
        )
        + &Env::spec("ec-k", "ec", "attributes = { CKA_SIGN = true }\n", &[kry], "xref-tec", ", autoCreate = true")
        + &Env::spec(
            "movable",
            "mv",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
            &[soft],
            "xref-tmv",
            ", autoCreate = true",
        );
    e.config(&body);
    assert_eq!(code(&e.cakeys(kry, &["realise", "kek", "--token", "kryoptic"])), 0);
    let file = e.dir.join("kryoptic.transport.toml");
    let path = file.to_str().unwrap();
    let o = e.km(kry, &["transport", "kek", "--token", "kryoptic", "--out", path]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("also decrypts"));
    let t: toml::Table = toml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let lock: toml::Table = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    assert_eq!(t["format"].as_str(), Some("cakeys-transport"));
    assert_eq!(t["provider"].as_str(), Some("kryoptic"));
    assert_eq!(t["rfc7093m4"], lock["objects"]["kek"]["ids"]["rfc7093m4"], "the locked identity");
    // Only an RSA private key can be a transport key.
    assert_eq!(code(&e.cakeys(kry, &["realise", "ec-k", "--token", "kryoptic"])), 0);
    assert_eq!(code(&e.km(kry, &["transport", "ec-k", "--token", "kryoptic"])), 17);
    // A source plans from the file alone.
    assert_eq!(code(&e.cakeys(soft, &["realise", "movable", "--token", "softhsm"])), 0);
    let o = e.km(soft, &["export", "mv", "--token", "softhsm", "--transport", path, "--dry-run", "--json"]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["capabilities"]["to"], "transport file");
    assert_eq!(v["plans"][0]["method"], "rsa-oaep-sha1+aes-kwp");
    // A file edited to name another identity is refused.
    let text = std::fs::read_to_string(&file).unwrap();
    let edited = text.replace(t["rfc7093m4"].as_str().unwrap(), "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    std::fs::write(&file, edited).unwrap();
    let o = e.km(soft, &["export", "mv", "--token", "softhsm", "--transport", path, "--dry-run"]);
    assert_eq!(code(&o), 17, "{}", String::from_utf8_lossy(&o.stderr));
}
