//! The move matrix across the reference tokens (MIGRATE.md D9): the plan follows each side's
//! capabilities, a transport file carries the locked identity, and a real `migrate` does exactly
//! what its `--dry-run` says. Realisations are recorded and checked with `cakeys` (built beside
//! camigrate, `common::sibling`), plans made and objects moved with camigrate. A reference takes
//! part when its suite's variables are set, as in `cakeys`' tests/references.rs; skipped with
//! fewer than two.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::xref::{Env, Plant, Ref, env};
use common::*;
use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;
use x509_cert::der::{Decode as _, Encode as _};

/// `export --dry-run` (MIGRATE.md phase 1): the plan follows each side's capabilities. Between
/// the software references, the composed sealed method with the strongest OAEP hash both
/// implement; to tpm2-pkcs11 and through p11-kit (whose RPC drops AES key wrap) only through the
/// host, behind the flag; to a file behind the flag; a key made non-extractable never. A sealed
/// plan needs a transport key realised on the target (MIGRATE.md D3), and without --dry-run the
/// export writes the bundle.
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
        + &Env::spec("movable-k", "movable-k", &attrs(true), &[kry], "xref-mvk", ", autoCreate = true")
        + &e.refs.iter().filter(|r| r.name.starts_with("kryoptic")).map(transport_key).collect::<String>();
    names_transport(&e, &body, |r| r.name.starts_with("kryoptic"));
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
    assert_eq!((c, first(&v)), (15, (some("rsa-oaep-sha1+aes-kwp"), some("sealed"), Some(false))), "{v}");
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("is not realised on 'kryoptic'"), "{v}");
    for r in e.refs.iter().filter(|r| r.name.starts_with("kryoptic")) {
        let o = e.cakeys(r, &["realise", &format!("tk-{}", r.name), "--token", r.name]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
    }
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
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let bundle: toml::Table = toml::from_str(&stdout(&o)).unwrap();
    assert_eq!(bundle["keys"][0]["method"].as_str(), Some("rsa-oaep-sha1+aes-kwp"));
    assert_eq!(bundle["transport"]["object"].as_str(), Some("tk-kryoptic"));
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

const CERT_RSA: &[u8] = include_bytes!("../../cli/tests/fixtures/adopt-cert.der");
const CERT_P384: &[u8] = include_bytes!("../../cli/tests/fixtures/adopt-cert-p384.der");
const CERT_ED25519: &[u8] = include_bytes!("../../cli/tests/fixtures/adopt-cert-ed25519.der");
const P384_PARAMS: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const ED25519_PARAMS: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// One public class of the matrix: its object (and keys.toml type), the attributes its specs
/// declare (the target's creation template: MIGRATE.md D6), the planting template of its
/// material, and whether tpm2-pkcs11 creates it from a value (its profile's public accept rows).
struct Public {
    name: &'static str,
    ty: &'static str,
    attributes: &'static str,
    material: fn() -> Vec<Attribute>,
    tpm2: bool,
}

/// A certificate's SPKI, from its DER.
fn spki(cert: &[u8]) -> Vec<u8> {
    x509_cert::Certificate::from_der(cert).unwrap().tbs_certificate().subject_public_key_info().to_der().unwrap()
}

/// A certificate's subject key as a public key object: an EC or Edwards point as a DER OCTET
/// STRING, beside the curve's parameters.
fn point_key(cert: &[u8], kt: KeyType, params: &[u8]) -> Vec<Attribute> {
    let spki = spki(cert);
    let info = x509_cert::spki::SubjectPublicKeyInfoRef::from_der(&spki).unwrap();
    let point = x509_cert::der::asn1::OctetStringRef::new(info.subject_public_key.as_bytes().unwrap()).unwrap();
    vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(kt),
        Attribute::EcParams(params.to_vec()),
        Attribute::EcPoint(point.to_der().unwrap()),
    ]
}

const PUBLIC: [Public; 5] = [
    Public {
        name: "pub-cert",
        ty: "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"",
        attributes: "",
        material: || {
            let cert = x509_cert::Certificate::from_der(CERT_RSA).unwrap();
            vec![
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Subject(cert.tbs_certificate().subject().to_der().unwrap()),
                Attribute::Value(CERT_RSA.to_vec()),
            ]
        },
        tpm2: true,
    },
    Public {
        name: "pub-data",
        ty: "class = \"CKO_DATA\"",
        attributes: "attributes = { CKA_PRIVATE = false }\n",
        material: || {
            let value = b"camigrate public data".to_vec();
            vec![Attribute::Class(ObjectClass::DATA), Attribute::Private(false), Attribute::Value(value)]
        },
        tpm2: false,
    },
    Public {
        name: "pub-rsa",
        ty: "class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048",
        attributes: "",
        material: || {
            let key = rsa::PublicKey::from_public_key_der(&spki(CERT_RSA)).unwrap();
            vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::RSA),
                Attribute::Modulus(key.n().to_be_bytes_trimmed_vartime().to_vec()),
                Attribute::PublicExponent(key.e().to_be_bytes_trimmed_vartime().to_vec()),
            ]
        },
        tpm2: true,
    },
    Public {
        name: "pub-p384",
        ty: "class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"",
        attributes: "",
        material: || point_key(CERT_P384, KeyType::EC, P384_PARAMS),
        tpm2: false,
    },
    Public {
        name: "pub-ed25519",
        ty: "class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"",
        attributes: "",
        material: || point_key(CERT_ED25519, KeyType::EC_EDWARDS, ED25519_PARAMS),
        tpm2: false,
    },
];

/// The dry-run property for the `public` rows (MIGRATE.md D9, phase 2): for every public class,
/// source and target reference, `migrate --dry-run`'s verdict is the outcome. A ready plan moves
/// the object, records it with its `origin`, and `cakeys verify` then accepts it on the target —
/// the lock camigrate wrote loads, and the identity survived the move. A blocked plan is 15, the
/// lock unchanged, the target locator empty.
#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn public_moves_do_what_the_plan_says() {
    let Some(e) = env("public-moves") else { return };
    // A source holds the class when it was planted there; kryoptic-der reads kryoptic's token.
    let holds = |r: &Ref, c: &Public| c.tpm2 || r.plant != Plant::Ptool;
    // Two references on one token through one module (kryoptic and kryoptic-der) cannot both be
    // opened in one process with their own settings: no move between them.
    let same_token = |a: &Ref, b: &Ref| a.module == b.module && a.token_label == b.token_label;
    let pairs: Vec<(&Public, &Ref, &Ref)> = PUBLIC
        .iter()
        .flat_map(|c| e.refs.iter().map(move |s| (c, s)))
        .filter(|(c, s)| holds(s, c))
        .flat_map(|(c, s)| e.refs.iter().filter(move |d| !same_token(s, d)).map(move |d| (c, s, d)))
        .collect();
    let target_label = |c: &Public, s: &Ref, d: &Ref| format!("cm-{}-{}-{}", c.name, s.name, d.name);
    let target_spec = |c: &Public, s: &Ref, d: &Ref| format!("{}-{}-{}", c.name, s.name, d.name);
    for r in e.refs(|r| r.plant != Plant::Shared) {
        let s = open_session(&r.module, r.token_label, "1234");
        let mut labels: Vec<String> = PUBLIC.iter().map(|c| format!("cm-{}", c.name)).collect();
        labels.extend(pairs.iter().map(|(c, s, d)| target_label(c, s, d)));
        s.clear(&labels.iter().map(String::as_str).collect::<Vec<_>>());
        for c in PUBLIC.iter().filter(|c| holds(r, c)) {
            let mut t = (c.material)();
            t.extend([Attribute::Token(true), Attribute::Label(format!("cm-{}", c.name).into_bytes())]);
            s.create_object(&t).unwrap_or_else(|err| panic!("planting {} on {}: {err}", c.name, r.name));
        }
    }
    let mut body = String::new();
    for c in &PUBLIC {
        body += &format!("[objects.{}]\n{}\n\n", c.name, c.ty);
        for r in e.refs.iter().filter(|r| holds(r, c)) {
            body += &Env::spec(
                &format!("{}-src-{}", c.name, r.name),
                c.name,
                c.attributes,
                &[r],
                &format!("cm-{}", c.name),
                "",
            );
        }
    }
    for (c, s, d) in &pairs {
        body += &Env::spec(&target_spec(c, s, d), c.name, c.attributes, &[d], &target_label(c, s, d), "");
    }
    e.config(&body);
    for c in &PUBLIC {
        for r in e.refs.iter().filter(|r| holds(r, c)) {
            let spec = format!("{}-src-{}", c.name, r.name);
            let o = e.cakeys(r, &["realise", &spec, "--token", r.name]);
            assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
        }
    }
    let lock_path = e.dir.join("keys.lock");
    let mut rows = Vec::new();
    for (c, s, d) in &pairs {
        let spec = target_spec(c, s, d);
        let args = ["migrate", c.name, "--from", s.name, "--to", d.name, "--spec", &spec];
        let o = e.km(s, &[&args[..], &["--dry-run", "--json"]].concat());
        let plan: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        let ready = plan["plans"][0]["ready"].as_bool().unwrap();
        assert_eq!(code(&o) == 0, ready, "{spec}: the dry run's exit and its plan disagree");
        let before = std::fs::read(&lock_path).unwrap();
        let o = e.km(s, &args);
        let row = format!("{spec}: plan {}, move exit {}", if ready { "ready" } else { "blocked" }, code(&o));
        if ready {
            assert_eq!(code(&o), 0, "{row}: {}", stderr(&o));
            let lock: toml::Value = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
            let origin = &lock["realisations"][spec.as_str()][d.name]["provenance"]["origin"];
            assert_eq!(origin["from"].as_str(), Some(s.name), "{row}");
            assert_eq!((origin["method"].as_str(), origin["exposure"].as_str()), (Some("public"), Some("public")));
            let v = e.cakeys(d, &["verify", &spec, "--token", d.name]);
            assert_eq!(code(&v), 0, "{row}: cakeys verify: {}", stderr(&v));
            // A re-run moves nothing and changes nothing.
            let again = std::fs::read(&lock_path).unwrap();
            assert_eq!(code(&e.km(s, &args)), 0, "{row}: the re-run");
            assert_eq!(std::fs::read(&lock_path).unwrap(), again, "{row}: the re-run changed the lock");
        } else {
            assert_eq!(code(&o), 15, "{row}: {}", stderr(&o));
            assert_eq!(std::fs::read(&lock_path).unwrap(), before, "{row}: a refused move changed the lock");
            let left = open_session(&d.module, d.token_label, "1234").labelled(&target_label(c, s, d));
            assert!(left.is_empty(), "{row}: a refused move left objects on the target");
        }
        rows.push(row);
    }
    eprintln!("public moves:\n  {}", rows.join("\n  "));
    assert!(rows.iter().any(|r| r.contains("ready")), "no public move was planned ready");
}

/// The locator guard is per class (`Token::occupied`): PKCS#11 puts a key, its public key and
/// its certificate under one label, so they move into one target label in either order. The
/// key's import and the public key object's share one public key object (whichever comes first
/// creates it, the other records it); a second object of a class already there is still 13,
/// leaving nothing.
#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn objects_sharing_a_locator_move_in_any_order() {
    let Some(e) = env("shared-locator") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping shared-locator: needs the softhsm and kryoptic references");
        return;
    };
    open_session(&kry.module, kry.token_label, "1234").clear(&["sl-a", "sl-b"]);
    let src = open_session(&soft.module, soft.token_label, "1234");
    src.clear(&["sl-k1", "sl-k2", "sl-crt1", "sl-crt2"]);
    for (label, der) in [("sl-crt1", CERT_RSA), ("sl-crt2", CERT_P384)] {
        let cert = x509_cert::Certificate::from_der(der).unwrap();
        src.create_object(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Subject(cert.tbs_certificate().subject().to_der().unwrap()),
            Attribute::Value(der.to_vec()),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
        ])
        .unwrap();
    }
    drop(src);
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let ec_pub = "class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let cert = "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"";
    let movable = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let mut body = transport_key(kry);
    for (n, target) in [("1", "sl-a"), ("2", "sl-b")] {
        let (k, kp, c) = (format!("k{n}"), format!("k{n}-pub"), format!("crt{n}"));
        body += &format!(
            "[objects.{k}]\n{ec}\ncreateOn = \"softhsm\"\n\n[objects.{kp}]\n{ec_pub}\n\n[objects.{c}]\n{cert}\n\n"
        );
        body += &Env::spec(&format!("{k}-soft"), &k, movable, &[soft], &format!("sl-k{n}"), ", autoCreate = true");
        body += &Env::spec(&format!("{kp}-soft"), &kp, "", &[soft], &format!("sl-k{n}"), "");
        body += &Env::spec(&format!("{c}-soft"), &c, "", &[soft], &format!("sl-crt{n}"), "");
        body += &Env::spec(&format!("{k}-kry"), &k, movable, &[kry], target, "");
        body += &Env::spec(&format!("{kp}-kry"), &kp, "", &[kry], target, "");
        body += &Env::spec(&format!("{c}-kry"), &c, "", &[kry], target, "");
    }
    // A second certificate for the first target label: a collision of its class.
    body += &Env::spec("crt2-kry-a", "crt2", "", &[kry], "sl-a", "");
    names_transport(&e, &body, |r| r.name == "kryoptic");
    assert_eq!(code(&e.cakeys(kry, &["realise", "tk-kryoptic", "--token", "kryoptic"])), 0);
    for spec in ["k1-soft", "k1-pub-soft", "crt1-soft", "k2-soft", "k2-pub-soft", "crt2-soft"] {
        let o = e.cakeys(soft, &["realise", spec, "--token", "softhsm"]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
    }
    let on_target = |label: &str| open_session(&kry.module, kry.token_label, "1234").labelled(label).len();
    let mv = |object: &str, spec: &str| {
        let o = e.km(soft, &["migrate", object, "--from", "softhsm", "--to", "kryoptic", "--spec", spec]);
        assert_eq!(code(&o), 0, "{object}: {}", stderr(&o));
        let v = e.cakeys(kry, &["verify", spec, "--token", "kryoptic"]);
        assert_eq!(code(&v), 0, "{spec}: {}", stderr(&v));
    };
    // The key first: its import creates the public half, which the public key object then is.
    mv("k1", "k1-kry");
    mv("k1-pub", "k1-pub-kry");
    mv("crt1", "crt1-kry");
    assert_eq!(on_target("sl-a"), 3, "a key, one public key object and a certificate");
    // The other order: the certificate and the public key object first, the key reusing it.
    mv("crt2", "crt2-kry");
    mv("k2-pub", "k2-pub-kry");
    mv("k2", "k2-kry");
    assert_eq!(on_target("sl-b"), 3, "a key, one public key object and a certificate");
    // A second certificate under 'sl-a' collides with the first: 13, nothing left.
    let o = e.km(soft, &["migrate", "crt2", "--from", "softhsm", "--to", "kryoptic", "--spec", "crt2-kry-a"]);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert_eq!(on_target("sl-a"), 3, "the refused certificate left an object");
}

/// The transport key of reference `r` (MIGRATE.md D3), as keys.toml text: an RSA key that only
/// unwraps and never leaves the token, proven by unwrapping (`pop-unwrap`). Its token names it
/// with [`names_transport`].
fn transport_key(r: &Ref) -> String {
    format!("[objects.tk-{0}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 3072\n\n", r.name)
        + &Env::spec(
            &format!("tk-{}", r.name),
            &format!("tk-{}", r.name),
            "attributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = false }\n",
            &[r],
            &format!("tk-{}", r.name),
            ", autoCreate = true, binding = \"pop-unwrap\"",
        )
}

/// keys.toml with `body`, each reference `holds` picks naming its [`transport_key`]
/// (`transportWith`).
fn names_transport(e: &Env, body: &str, holds: impl Fn(&Ref) -> bool) {
    e.config_with(body, &|r| if holds(r) { format!("transportWith = \"tk-{}\"\n", r.name) } else { String::new() });
}

/// One key class of the sealed matrix: its keys.toml type and the attributes its specs declare
/// (extractable, or it could never move: MIGRATE.md D1).
struct Key {
    name: &'static str,
    ty: &'static str,
    attributes: &'static str,
}

const KEYS: [Key; 5] = [
    Key {
        name: "k-p256",
        ty: "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
        attributes: "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
    },
    Key {
        name: "k-ed25519",
        ty: "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"",
        attributes: "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
    },
    Key {
        name: "k-rsa",
        ty: "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048",
        attributes: "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
    },
    Key {
        name: "k-aes",
        ty: "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32",
        attributes: "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
    },
    Key {
        name: "k-hmac",
        ty: "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32",
        attributes: "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
    },
];

/// The dry-run property for the sealed rows (MIGRATE.md D9, phase 3): for every key class,
/// source and target reference, `migrate --dry-run`'s verdict is the outcome. Each key is
/// generated on its source (`createOn`), each target holds a transport key. A ready move exits
/// 0, records its `origin`, and `cakeys verify` then accepts the key on the target — proving
/// possession, so the unwrapped key is the locked one; a blocked one is 15 with the lock
/// unchanged and nothing on the target.
#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn sealed_moves_do_what_the_plan_says() {
    let Some(e) = env("sealed-moves") else { return };
    // Sources make extractable keys: not tpm2-pkcs11 (its keys never leave the TPM), and not
    // Edwards keys through p11-kit (the RPC drops their generation); kryoptic-der reads kryoptic.
    let generates =
        |r: &Ref, k: &Key| matches!(r.plant, Plant::Create) && !(k.name == "k-ed25519" && r.name == "p11kit");
    let same_token = |a: &Ref, b: &Ref| a.module == b.module && a.token_label == b.token_label;
    let pairs: Vec<(&Key, &Ref, &Ref)> = KEYS
        .iter()
        .flat_map(|k| e.refs.iter().map(move |s| (k, s)))
        .filter(|(k, s)| generates(s, k))
        .flat_map(|(k, s)| e.refs.iter().filter(move |d| !same_token(s, d)).map(move |d| (k, s, d)))
        .collect();
    let object = |k: &Key, s: &Ref| format!("{}-{}", k.name, s.name);
    let target_label = |k: &Key, s: &Ref, d: &Ref| format!("cm-{}-{}-{}", k.name, s.name, d.name);
    let target_spec = |k: &Key, s: &Ref, d: &Ref| format!("{}-{}-{}", k.name, s.name, d.name);
    let unwraps = |d: &Ref| d.plant != Plant::Ptool;
    let mut body = e.refs.iter().filter(|d| unwraps(d)).map(transport_key).collect::<String>();
    for k in &KEYS {
        for s in e.refs.iter().filter(|s| generates(s, k)) {
            let o = object(k, s);
            body += &format!("[objects.{o}]\n{}\ncreateOn = \"{}\"\n\n", k.ty, s.name);
            body += &Env::spec(&format!("{o}-src"), &o, k.attributes, &[s], &format!("cm-{o}"), ", autoCreate = true");
        }
    }
    for (k, s, d) in &pairs {
        body += &Env::spec(&target_spec(k, s, d), &object(k, s), k.attributes, &[d], &target_label(k, s, d), "");
    }
    names_transport(&e, &body, unwraps);
    // p11-kit hides the module behind it, so its capabilities are a spec-compliant module's until
    // keys.toml names that module's provider (DESIGN §6.2): this one forwards `SoftHSM`, whose
    // unwrapped secret keys lose their length (`secret-unwraps = false`).
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    let provider = |p: &str| {
        let named = if p.is_empty() { String::new() } else { format!("provider = \"{p}\"\n") };
        std::fs::write(&config, text.replace("[tokens.p11kit]\n", &format!("[tokens.p11kit]\n{named}"))).unwrap();
    };
    provider("softhsm");
    for d in e.refs.iter().filter(|d| unwraps(d)) {
        let o = e.cakeys(d, &["realise", &format!("tk-{}", d.name), "--token", d.name]);
        assert_eq!(code(&o), 0, "transport key on {}: {}", d.name, stderr(&o));
    }
    for k in &KEYS {
        for s in e.refs.iter().filter(|s| generates(s, k)) {
            let spec = format!("{}-src", object(k, s));
            let o = e.cakeys(s, &["realise", &spec, "--token", s.name]);
            assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
        }
    }
    // Unnamed, the module behind p11-kit is planned as spec-compliant, with a warning; named, its
    // own claims decide: `SoftHSM`'s blocks a secret key, kryoptic's does not.
    let (kry, p11) = (e.refs.iter().find(|r| r.name == "kryoptic"), e.refs.iter().find(|r| r.name == "p11kit"));
    if let (Some(s), Some(d)) = (kry, p11) {
        let (spec, o) = (target_spec(&KEYS[3], s, d), object(&KEYS[3], s));
        for (named, ready, warned) in [("", true, true), ("softhsm", false, false), ("kryoptic", true, false)] {
            provider(named);
            let args = ["migrate", &o, "--from", s.name, "--to", d.name, "--spec", &spec, "--dry-run", "--json"];
            let out = e.km(s, &args);
            let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
            let row = format!("{spec} with provider '{named}'");
            assert_eq!(plan["plans"][0]["ready"].as_bool(), Some(ready), "{row}: {plan}");
            assert_eq!(stderr(&out).contains("planned as a spec-compliant module"), warned, "{row}: {}", stderr(&out));
        }
        provider("softhsm");
    }
    let lock_path = e.dir.join("keys.lock");
    let mut rows = Vec::new();
    for (k, s, d) in &pairs {
        let (spec, o) = (target_spec(k, s, d), object(k, s));
        let args = ["migrate", o.as_str(), "--from", s.name, "--to", d.name, "--spec", &spec];
        let out = e.km(s, &[&args[..], &["--dry-run", "--json"]].concat());
        let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
        let ready = plan["plans"][0]["ready"].as_bool().unwrap();
        assert_eq!(code(&out) == 0, ready, "{spec}: the dry run's exit and its plan disagree");
        let method = plan["plans"][0]["method"].as_str().unwrap_or("-").to_owned();
        let before = std::fs::read(&lock_path).unwrap();
        let out = e.km(s, &args);
        let row =
            format!("{spec}: {method}, plan {}, move exit {}", if ready { "ready" } else { "blocked" }, code(&out));
        if ready {
            assert_eq!(code(&out), 0, "{row}: {}", stderr(&out));
            let lock: toml::Value = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
            let origin = &lock["realisations"][spec.as_str()][d.name]["provenance"]["origin"];
            assert_eq!(origin["from"].as_str(), Some(s.name), "{row}");
            assert_eq!(origin["method"].as_str(), Some(method.as_str()), "{row}");
            let v = e.cakeys(d, &["verify", &spec, "--token", d.name]);
            assert_eq!(code(&v), 0, "{row}: cakeys verify: {}", stderr(&v));
        } else {
            assert_eq!(code(&out), 15, "{row}: {}", stderr(&out));
            assert_eq!(std::fs::read(&lock_path).unwrap(), before, "{row}: a refused move changed the lock");
            let left = open_session(&d.module, d.token_label, "1234").labelled(&target_label(k, s, d));
            assert!(left.is_empty(), "{row}: a refused move left objects on the target");
        }
        rows.push(row);
    }
    eprintln!("sealed moves:\n  {}", rows.join("\n  "));
    assert!(rows.iter().any(|r| r.contains("plan ready")), "no sealed move was planned ready");
}

/// A bundle crosses untrusted channels (MIGRATE.md D5, D6): `export --out` writes it and
/// `import --in` reads it, checked against the lock before the target is touched — another key's
/// IDs are 17 or 10 — and after: tampered bytes do not unwrap (13), and the blobs of another
/// key unwrap into material that is not the locked one (a private key fails its proof of possession,
/// 13; a secret key its commitment, 10). Neither leaves anything
/// on the target. A transport file for a key the lock does not pin is no channel at all.
#[test]
fn bundles_are_checked_against_the_lock() {
    let Some(e) = env("bundles") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping bundles: needs the softhsm and kryoptic references");
        return;
    };
    bundle_keys(&e, soft, kry);
    let export = |objects: &[&str]| export_bundle(&e, soft, objects);
    let (ek1, ek2) = (export(&["ek1"]), export(&["ek2"]));
    let text = std::fs::read_to_string(&ek1).unwrap();
    let lock_path = e.dir.join("keys.lock");
    let import = |path: &std::path::Path| e.km(kry, &["import", "--token", "kryoptic", "--in", path.to_str().unwrap()]);
    let empty = |label: &str| open_session(&kry.module, kry.token_label, "1234").labelled(label).is_empty();
    let refused = |text: String, want: i32, what: &str| {
        let path = e.dir.join("altered.bundle.toml");
        std::fs::write(&path, text).unwrap();
        let before = std::fs::read(&lock_path).unwrap();
        let o = import(&path);
        assert_eq!(code(&o), want, "{what}: {}", stderr(&o));
        assert!(empty("xb-ek1"), "{what}: left objects on the target");
        assert_eq!(std::fs::read(&lock_path).unwrap(), before, "{what}: changed the lock");
    };
    let b: toml::Value = toml::from_str(&text).unwrap();
    let key_blob = b["keys"][0]["wrapped"].as_str().unwrap();
    // Another key's IDs alone: the form check refuses them, the public key no longer theirs (17).
    let ids = b["keys"][0]["ids"]["rfc7093m4"].as_str().unwrap();
    let other: toml::Value = toml::from_str(&std::fs::read_to_string(&ek2).unwrap()).unwrap();
    let other_ids = other["keys"][0]["ids"]["rfc7093m4"].as_str().unwrap();
    refused(text.replace(ids, other_ids), 17, "the IDs of another key");
    // With its public key too: consistent, but not what the lock pins for 'ek1' (10), before the
    // target is touched.
    let public = b["keys"][0]["publicKey"].as_str().unwrap();
    let relabelled = text.replace(ids, other_ids).replace(public, other["keys"][0]["publicKey"].as_str().unwrap());
    refused(relabelled, 10, "another key's IDs and public key");
    // A flipped byte in the wrapped key: RFC 5649's integrity check refuses it.
    refused(text.replace(key_blob, &base64_flip(key_blob)), 13, "a tampered blob");
    // The other key's blobs (its KEK and its key), wrapped to the same transport key: unwrapped,
    // then refused by identity and removed again.
    let swap = |into: &toml::Value, from: &toml::Value| {
        let mut swapped = into.clone();
        swapped["kek"] = from["kek"].clone();
        swapped["keys"][0]["wrapped"] = from["keys"][0]["wrapped"].clone();
        toml::to_string(&swapped).unwrap()
    };
    // A private key's identity is its public key, which the bundle carries: the other key's
    // private half fails the proof of possession (13).
    refused(swap(&b, &other), 13, "another private key's blobs");
    // A secret key's identity is its commitment, computed from the unwrapped key: 10.
    let (sk1, sk2) = (export(&["sk1"]), export(&["sk2"]));
    let read = |p: &std::path::Path| -> toml::Value { toml::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() };
    let path = e.dir.join("swapped-secret.bundle.toml");
    std::fs::write(&path, swap(&read(&sk1), &read(&sk2))).unwrap();
    let o = import(&path);
    assert_eq!(code(&o), 10, "another secret key's blobs: {}", stderr(&o));
    assert!(empty("xb-sk1"), "left behind");
    // A transport file for a key the lock does not pin: the plan refuses to wrap to it.
    let rogue = e.dir.join("rogue.transport.toml");
    let file = e.km(kry, &["transport", "tk-kryoptic", "--token", "kryoptic", "--out", rogue.to_str().unwrap()]);
    assert_eq!(code(&file), 0, "{}", stderr(&file));
    let t = std::fs::read_to_string(&rogue).unwrap().replace("object = \"tk-kryoptic\"", "object = \"ek2\"");
    std::fs::write(&rogue, t).unwrap();
    let o = e.km(soft, &["export", "ek2", "--token", "softhsm", "--transport", rogue.to_str().unwrap(), "--dry-run"]);
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("is not the"), "{}", stdout(&o));
}

/// The keys the bundle tests move: P-256 `ek1`, `ek2` and AES `sk1`, `sk2`, each born on `SoftHSM`
/// (`createOn`) with a spec on kryoptic, whose transport key is realised; `nx`, a P-256 key made
/// non-extractable there, which cannot move; and `nox`, an extractable one its spec keeps there
/// (`noExport`).
fn bundle_keys(e: &Env, soft: &Ref, kry: &Ref) {
    // A certificate, planted on SoftHSM: a public object that travels in a bundle as it is.
    open_session(&kry.module, kry.token_label, "1234").clear(&["xb-crt"]);
    let src = open_session(&soft.module, soft.token_label, "1234");
    src.clear(&["xb-crt"]);
    let x509 = x509_cert::Certificate::from_der(CERT_RSA).unwrap();
    src.create_object(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
        Attribute::Subject(x509.tbs_certificate().subject().to_der().unwrap()),
        Attribute::Value(CERT_RSA.to_vec()),
        Attribute::Token(true),
        Attribute::Label(b"xb-crt".to_vec()),
    ])
    .unwrap();
    drop(src);
    let crt = "[objects.crt]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\n".to_owned()
        + &Env::spec("crt-soft", "crt", "", &[soft], "xb-crt", "")
        + &Env::spec("crt-kry", "crt", "", &[kry], "xb-crt", "");
    let key = |o: &str, ty: &str| {
        format!("[objects.{o}]\n{ty}\ncreateOn = \"softhsm\"\n\n")
            + &Env::spec(
                &format!("{o}-soft"),
                o,
                "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
                &[soft],
                &format!("xb-{o}"),
                ", autoCreate = true",
            )
            + &Env::spec(
                &format!("{o}-kry"),
                o,
                "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
                &[kry],
                &format!("xb-{o}"),
                "",
            )
    };
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
    let fixed = "[objects.nx]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n".to_owned()
        + &Env::spec(
            "nx-soft",
            "nx",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }\n",
            &[soft],
            "xb-nx",
            ", autoCreate = true",
        );
    let kept = "[objects.nox]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n".to_owned()
        + &Env::spec(
            "nox-soft",
            "nox",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\nnoExport = true\n",
            &[soft],
            "xb-nox",
            ", autoCreate = true",
        );
    let body = transport_key(kry)
        + &key("ek1", ec)
        + &key("ek2", ec)
        + &key("sk1", aes)
        + &key("sk2", aes)
        + &fixed
        + &kept
        + &crt;
    names_transport(e, &body, |r| r.name == "kryoptic");
    assert_eq!(code(&e.cakeys(kry, &["realise", "tk-kryoptic", "--token", "kryoptic"])), 0);
    for spec in ["ek1-soft", "ek2-soft", "sk1-soft", "sk2-soft", "nx-soft", "nox-soft", "crt-soft"] {
        assert_eq!(code(&e.cakeys(soft, &["realise", spec, "--token", "softhsm"])), 0, "{spec}");
    }
}

/// `export` of `objects` from `SoftHSM` to kryoptic, into a bundle file: its path.
fn export_bundle(e: &Env, soft: &Ref, objects: &[&str]) -> std::path::PathBuf {
    let path = e.dir.join(format!("{}.bundle.toml", objects.join("+")));
    let out = path.to_str().unwrap().to_owned();
    let args = [&["export"], objects, &["--token", "softhsm", "--target", "kryoptic", "--out", &out]].concat();
    let r = e.km(soft, &args);
    assert_eq!(code(&r), 0, "export {objects:?}: {}", stderr(&r));
    path
}

/// One bundle per export (MIGRATE.md D5): every key, one shared KEK. Each key imports on its
/// own: one that fails leaves nothing while the others are imported and recorded, and the run
/// exits with the failure. Named objects export all or nothing: one that cannot move writes no
/// bundle; without names, what cannot move is warned about and left out.
#[test]
fn bundles_carry_every_key_of_an_export() {
    let Some(e) = env("multi-bundles") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping multi-bundles: needs the softhsm and kryoptic references");
        return;
    };
    bundle_keys(&e, soft, kry);
    let export = |objects: &[&str]| export_bundle(&e, soft, objects);
    let lock_path = e.dir.join("keys.lock");
    let import = |path: &std::path::Path| e.km(kry, &["import", "--token", "kryoptic", "--in", path.to_str().unwrap()]);
    let empty = |label: &str| open_session(&kry.module, kry.token_label, "1234").labelled(label).is_empty();
    let read = |p: &std::path::Path| -> toml::Value { toml::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() };
    // One bundle per export: two keys, one shared KEK. A dry run checks both and imports nothing.
    let both = export(&["ek1", "sk1"]);
    let b = read(&both);
    assert_eq!(b["keys"].as_array().map(Vec::len), Some(2), "{b}");
    assert!(b.get("kek").is_some(), "{b}");
    let o = e.km(kry, &["import", "--token", "kryoptic", "--in", both.to_str().unwrap(), "--dry-run"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(empty("xb-ek1") && empty("xb-sk1"), "the dry run imported");
    // Each key on its own: with sk1's label altered (10), ek1 still imports and is recorded,
    // sk1 leaves nothing, and the run exits with sk1's failure.
    let mut altered = b.clone();
    altered["keys"][1]["commitmentLabel"] = toml::Value::String("another label".into());
    let path = e.dir.join("partial.bundle.toml");
    std::fs::write(&path, toml::to_string(&altered).unwrap()).unwrap();
    let o = import(&path);
    assert_eq!(code(&o), 10, "{}", stderr(&o));
    assert!(empty("xb-sk1"), "the failed key left objects");
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
    assert!(lock["realisations"]["ek1-kry"].get("kryoptic").is_some(), "the good key was not recorded");
    assert!(lock["realisations"].get("sk1-kry").is_none(), "the failed key was recorded");
    assert_eq!(code(&e.cakeys(kry, &["verify", "ek1-kry", "--token", "kryoptic"])), 0);
    // The whole bundle again: ek1 is already there and verifies, sk1 imports.
    let o = import(&both);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["verify", "sk1-kry", "--token", "kryoptic"])), 0);
    // Without names, every key that can move: the non-extractable one is warned about, left out.
    let out = e.dir.join("all.bundle.toml");
    let r = e.km(soft, &["export", "--token", "softhsm", "--target", "kryoptic", "--out", out.to_str().unwrap()]);
    assert_eq!(code(&r), 0, "{}", stderr(&r));
    assert!(stderr(&r).contains("nx: left out of the bundle: not extractable"), "{}", stderr(&r));
    assert!(!stderr(&r).contains("nox"), "noExport is left out quietly: {}", stderr(&r));
    let objects: Vec<String> =
        read(&out)["keys"].as_array().unwrap().iter().map(|k| k["object"].as_str().unwrap().to_owned()).collect();
    assert_eq!(objects, ["crt", "ek1", "ek2", "sk1", "sk2"]);
    // The certificate travels as its value; the import takes the keys first, then it.
    let all = read(&out);
    let crt = all["keys"].as_array().unwrap().iter().find(|k| k["object"].as_str() == Some("crt")).unwrap();
    assert_eq!((crt["method"].as_str(), crt.get("wrapped")), (Some("public"), None), "{crt}");
    let o = import(&out);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    for spec in ["crt-kry", "ek2-kry", "sk2-kry"] {
        assert_eq!(code(&e.cakeys(kry, &["verify", spec, "--token", "kryoptic"])), 0, "{spec}");
    }
    // Named, all or nothing: an object that cannot move fails the export, and no bundle is written.
    let out = e.dir.join("never.bundle.toml");
    let r = e.km(
        soft,
        &["export", "ek2", "nx", "--token", "softhsm", "--target", "kryoptic", "--out", out.to_str().unwrap()],
    );
    assert_eq!(code(&r), 15, "{}", stderr(&r));
    assert!(!out.exists(), "a failed export wrote a bundle");
    // noExport, named: refused, with the spec that keeps it.
    let r = e.km(soft, &["export", "nox", "--token", "softhsm", "--target", "kryoptic", "--dry-run"]);
    assert_eq!(code(&r), 15, "{}", stdout(&r));
    assert!(stdout(&r).contains("noExport in spec 'nox-soft'"), "{}", stdout(&r));
    let r = e.km(
        soft,
        &["export", "ek2", "nosuch", "--token", "softhsm", "--target", "kryoptic", "--out", out.to_str().unwrap()],
    );
    assert_eq!(code(&r), 14, "{}", stderr(&r));
    assert!(!out.exists(), "a failed export wrote a bundle");
}

/// A token names its transport key (`transportWith`, MIGRATE.md D3), and realising it records
/// its public key in the lock, held to the locked identity: a source then plans and exports to
/// that token from the lock alone, the target unreachable. Without the recorded key, a plan
/// from the lock is blocked; a `transportWith` that is no unwrap-only RSA key is invalid.
#[test]
fn exports_to_a_token_need_only_the_lock() {
    let Some(e) = env("lock-transport") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping lock-transport: needs the softhsm and kryoptic references");
        return;
    };
    let body = transport_key(kry)
        + "[objects.mv]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        + &Env::spec(
            "mv",
            "mv",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
            &[soft],
            "xl-mv",
            ", autoCreate = true",
        );
    // Named, not picked: without transportWith, the plan says how to name one.
    e.config(&body);
    assert_eq!(code(&e.cakeys(kry, &["realise", "tk-kryoptic", "--token", "kryoptic"])), 0);
    assert_eq!(code(&e.cakeys(soft, &["realise", "mv", "--token", "softhsm"])), 0);
    let o = e.km(soft, &["export", "mv", "--token", "softhsm", "--target", "kryoptic", "--dry-run"]);
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("transportWith"), "{}", stdout(&o));
    // Realised before transportWith named it: no public key yet, so with kryoptic unreachable the
    // plan is blocked; realising it again records the key.
    names_transport(&e, &body, |r| r.name == "kryoptic");
    let away = format!("kryoptic={}", e.dir.join("absent.so").display());
    let plan = |e: &Env| {
        e.km(soft, &["--module", &away, "export", "mv", "--token", "softhsm", "--target", "kryoptic", "--dry-run"])
    };
    let o = plan(&e);
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("records no public key"), "{}", stdout(&o));
    assert_eq!(code(&e.cakeys(kry, &["realise", "tk-kryoptic", "--token", "kryoptic"])), 0);
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    let tk = &lock["objects"]["tk-kryoptic"];
    let spki = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.decode(tk["publicKey"].as_str().unwrap()).unwrap()
    };
    assert_eq!(tk["ids"]["rfc7093m4"].as_str(), Some(cakeys_core::id::sri(&spki).as_str()));
    assert_eq!(code(&plan(&e)), 0);
    let out = e.dir.join("mv.bundle.toml");
    let o = e.km(
        soft,
        &[
            "--module",
            &away,
            "export",
            "mv",
            "--token",
            "softhsm",
            "--target",
            "kryoptic",
            "--out",
            out.to_str().unwrap(),
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(bundle["transport"]["rfc7093m4"].as_str(), tk["ids"]["rfc7093m4"].as_str());
    // A recorded public key that is not the locked identity's: the lock does not load (17).
    let lock_path = e.dir.join("keys.lock");
    let text = std::fs::read_to_string(&lock_path).unwrap();
    let flipped = base64_flip(tk["publicKey"].as_str().unwrap());
    std::fs::write(&lock_path, text.replace(tk["publicKey"].as_str().unwrap(), &flipped)).unwrap();
    assert_eq!(code(&plan(&e)), 17);
    std::fs::write(&lock_path, text).unwrap();
    // A transportWith naming a key that is no transport key is invalid.
    e.config_with(&body, &|r| if r.name == "kryoptic" { "transportWith = \"mv\"\n".into() } else { String::new() });
    assert_eq!(code(&e.km(soft, &["export", "mv", "--token", "softhsm", "--target", "kryoptic", "--dry-run"])), 17);
}

/// `text`, base64, with one byte of what it encodes flipped.
fn base64_flip(text: &str) -> String {
    use base64::Engine as _;
    let mut bytes = base64::engine::general_purpose::STANDARD.decode(text).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `enforced` (MIGRATE.md D2, phase 3b): a `CKA_WRAP_WITH_TRUSTED` key on `SoftHSM` moves only after
/// its SO trusted the target's transport key (`transport --trusted`, with `mgmKeyFile`), and
/// then by `CKM_RSA_AES_KEY_WRAP` under that trusted copy alone: each bundle entry carries its
/// own key-encryption key. kryoptic imports and verifies them. A wrap-with-trusted key on
/// kryoptic never moves: it cannot trust an RSA key (its profile's `trusted-wrap = false`).
#[test]
fn enforced_moves_wrap_only_under_the_trusted_transport_key() {
    let Some(e) = env("enforced") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping enforced: needs the softhsm and kryoptic references");
        return;
    };
    std::fs::write(e.dir.join("so-pin"), "5678\n").unwrap();
    let trusted = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true, CKA_WRAP_WITH_TRUSTED = true }\n";
    let key = |o: &str, ty: &str, born: &Ref, other: &Ref| {
        format!("[objects.{o}]\n{ty}\ncreateOn = \"{}\"\n\n", born.name)
            + &Env::spec(&format!("{o}-src"), o, trusted, &[born], &format!("xe-{o}"), ", autoCreate = true")
            + &Env::spec(&format!("{o}-dst"), o, trusted, &[other], &format!("xe-{o}"), "")
    };
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
    let body = transport_key(kry) + &key("ek", ec, soft, kry) + &key("sk", aes, soft, kry) + &key("kk", ec, kry, soft);
    let so_pin = e.dir.join("so-pin");
    e.config_with(&body, &|r| match r.name {
        "kryoptic" => "transportWith = \"tk-kryoptic\"\n".into(),
        "softhsm" => format!("mgmKeyFile = \"{}\"\n", so_pin.display()),
        _ => String::new(),
    });
    for (spec, r) in [("tk-kryoptic", kry), ("ek-src", soft), ("sk-src", soft), ("kk-src", kry)] {
        let o = e.cakeys(r, &["realise", spec, "--token", r.name]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
    }
    let plan = |o: &str, from: &Ref, to: &Ref| -> serde_json::Value {
        let out = e.km(from, &["migrate", o, "--from", from.name, "--to", to.name, "--dry-run", "--json"]);
        serde_json::from_str(&stdout(&out)).unwrap()
    };
    // Untrusted: blocked, naming the SO's step.
    let p = plan("ek", soft, kry);
    assert_eq!(p["plans"][0]["ready"].as_bool(), Some(false), "{p}");
    assert!(p["plans"][0]["reasons"][0].as_str().unwrap().contains("--trusted softhsm"), "{p}");
    // The SO trusts the transport key, from the public key the lock records; again, nothing to do.
    let trust = ["transport", "tk-kryoptic", "--token", "kryoptic", "--trusted", "softhsm"];
    let o = e.km(soft, &trust);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let o = e.km(soft, &trust);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("already trusts"), "{}", stderr(&o));
    for o in ["ek", "sk"] {
        let p = plan(o, soft, kry);
        assert_eq!(
            (p["plans"][0]["ready"].as_bool(), p["plans"][0]["exposure"].as_str()),
            (Some(true), Some("enforced")),
            "{p}"
        );
    }
    // One bundle: each enforced key with its own key-encryption key, none shared.
    let out = e.dir.join("enforced.bundle.toml");
    let exported = e.km(
        soft,
        &["export", "ek", "sk", "--token", "softhsm", "--target", "kryoptic", "--out", out.to_str().unwrap()],
    );
    assert_eq!(code(&exported), 0, "{}", stderr(&exported));
    let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(bundle.get("kek").is_none(), "{bundle}");
    for k in bundle["keys"].as_array().unwrap() {
        assert_eq!((k["exposure"].as_str(), k.get("kek").is_some()), (Some("enforced"), true), "{k}");
    }
    let o = e.km(kry, &["import", "--token", "kryoptic", "--in", out.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    for spec in ["ek-dst", "sk-dst"] {
        assert_eq!(code(&e.cakeys(kry, &["verify", spec, "--token", "kryoptic"])), 0, "{spec}");
    }
    // kryoptic cannot trust an RSA key: a wrap-with-trusted key there never leaves.
    let p = plan("kk", kry, soft);
    let reasons = p["plans"][0]["reasons"].to_string();
    assert!(p["plans"][0]["ready"] == false && reasons.contains("trusted-wrap = false"), "{p}");
}

/// The dry-run property for the `host` rows (MIGRATE.md D2, phase 4): with
/// `--allow-host-plaintext`, every move the plan sends through the host (`host-pkcs8`,
/// `host-raw`: a target that cannot unwrap the key, like `SoftHSM` for secret keys or p11-kit
/// without AES key wrap; `tpm2-ptool` into tpm2-pkcs11) moves, records its `origin` with the
/// `host` exposure, and `cakeys verify` accepts the key on the target.
#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn host_moves_do_what_the_plan_says() {
    let Some(e) = env("host-moves") else { return };
    let generates =
        |r: &Ref, k: &Key| matches!(r.plant, Plant::Create) && !(k.name == "k-ed25519" && r.name == "p11kit");
    let same_token = |a: &Ref, b: &Ref| a.module == b.module && a.token_label == b.token_label;
    let pairs: Vec<(&Key, &Ref, &Ref)> = KEYS
        .iter()
        .flat_map(|k| e.refs.iter().map(move |s| (k, s)))
        .filter(|(k, s)| generates(s, k))
        .flat_map(|(k, s)| e.refs.iter().filter(move |d| !same_token(s, d)).map(move |d| (k, s, d)))
        .collect();
    let object = |k: &Key, s: &Ref| format!("h{}-{}", k.name, s.name);
    let target_label = |k: &Key, s: &Ref, d: &Ref| format!("hm-{}-{}-{}", k.name, s.name, d.name);
    let target_spec = |k: &Key, s: &Ref, d: &Ref| format!("h{}-{}-{}", k.name, s.name, d.name);
    let mut body = String::new();
    for k in &KEYS {
        for s in e.refs.iter().filter(|s| generates(s, k)) {
            let o = object(k, s);
            body += &format!("[objects.{o}]\n{}\ncreateOn = \"{}\"\n\n", k.ty, s.name);
            body += &Env::spec(&format!("{o}-src"), &o, k.attributes, &[s], &format!("hm-{o}"), ", autoCreate = true");
        }
    }
    for (k, s, d) in &pairs {
        body += &Env::spec(&target_spec(k, s, d), &object(k, s), k.attributes, &[d], &target_label(k, s, d), "");
    }
    e.config(&body);
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, text.replace("[tokens.p11kit]\n", "[tokens.p11kit]\nprovider = \"softhsm\"\n")).unwrap();
    for k in &KEYS {
        for s in e.refs.iter().filter(|s| generates(s, k)) {
            let spec = format!("{}-src", object(k, s));
            let o = e.cakeys(s, &["realise", &spec, "--token", s.name]);
            assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
        }
    }
    let lock_path = e.dir.join("keys.lock");
    let mut rows = Vec::new();
    for (k, s, d) in &pairs {
        let (spec, o) = (target_spec(k, s, d), object(k, s));
        let args = ["migrate", o.as_str(), "--from", s.name, "--to", d.name, "--spec", &spec, "--allow-host-plaintext"];
        let out = e.km(s, &[&args[..], &["--dry-run", "--json"]].concat());
        let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
        let method = plan["plans"][0]["method"].as_str().unwrap_or("-").to_owned();
        let through_host = method.starts_with("host-") || method == "tpm2-ptool";
        if !through_host || plan["plans"][0]["ready"].as_bool() != Some(true) {
            continue;
        }
        let out = e.km(s, &args);
        let row = format!("{spec}: {method}, move exit {}", code(&out));
        assert_eq!(code(&out), 0, "{row}: {}", stderr(&out));
        let lock: toml::Value = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
        let origin = &lock["realisations"][spec.as_str()][d.name]["provenance"]["origin"];
        assert_eq!(
            (origin["method"].as_str(), origin["exposure"].as_str()),
            (Some(method.as_str()), Some("host")),
            "{row}"
        );
        let v = e.cakeys(d, &["verify", &spec, "--token", d.name]);
        assert_eq!(code(&v), 0, "{row}: cakeys verify: {}", stderr(&v));
        rows.push(row);
    }
    eprintln!("host moves:\n  {}", rows.join("\n  "));
    if e.refs.iter().any(|r| r.name == "softhsm") && e.refs.iter().any(|r| r.name == "kryoptic") {
        assert!(rows.iter().any(|r| r.contains("host-raw")), "no secret key moved through the host into SoftHSM");
    }
    if e.refs.iter().any(|r| r.name == "tpm2") {
        assert!(rows.iter().any(|r| r.contains("tpm2-ptool")), "no key moved into tpm2-pkcs11 through tpm2_ptool");
    }
}
