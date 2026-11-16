//! The move matrix across the reference tokens (docs/CAMIGRATE.md D9): the plan follows each side's
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

/// [`Env::spec`]'s `extra` for a pair `cakeys create` makes (a source, a transport key) and for
/// one a move lands on; without either, a pair is adopted.
const CREATE: &str = ", origin = \"create\"";
const IMPORT: &str = ", origin = \"import\"";

/// `export --dry-run` (docs/CAMIGRATE.md phase 1): the plan follows each side's capabilities. Between
/// the software references, the composed sealed method with the strongest OAEP hash both
/// implement; to tpm2-pkcs11 and through p11-kit (whose RPC drops AES key wrap) only through the
/// host, behind the flag; to a file behind the flag; a key made non-extractable never. A sealed
/// plan needs a transport key realised on the target (docs/CAMIGRATE.md D3), and without --dry-run the
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
        + &Env::spec("movable", "movable", &attrs(true), &[soft], "xref-mv", CREATE)
        + &Env::spec("fixed", "fixed", &attrs(false), &[soft], "xref-fx", CREATE)
        + &Env::spec("movable-k", "movable-k", &attrs(true), &[kry], "xref-mvk", CREATE)
        + &e.refs.iter().filter(|r| r.name.starts_with("kryoptic")).map(transport_key).collect::<String>();
    names_transport(&e, &body, |r| r.name.starts_with("kryoptic"));
    for (spec, r) in [("movable", soft), ("fixed", soft), ("movable-k", kry)] {
        assert_eq!(code(&e.cakeys(r, &["create", spec, "--token", r.name])), 0, "{spec}");
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
        let o = e.cakeys(r, &["create", &format!("tk-{}", r.name), "--token", r.name]);
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
        // Allowed, the host path is still no export's: a bundle carries sealed keys only.
        let (c, v) = plan(soft, &["movable", "--target", "tpm2", "--allow-host-plaintext"]);
        assert_eq!((c, first(&v).2), (15, Some(false)), "{v}");
        assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("move it with `camigrate migrate`"), "{v}");
        assert!(v["plans"][0]["notes"][0].as_str().unwrap().contains("residence"), "{v}");
    }
    if named("p11kit").is_some() {
        let (c, v) = plan(soft, &["movable", "--target", "p11kit"]);
        assert_eq!((c, first(&v)), (15, (some("host-pkcs8"), some("host"), Some(false))), "{v}");
    }
    let (c, v) = plan(soft, &["movable", "--to-file", "pkcs8", "--allow-host-plaintext"]);
    assert_eq!((c, first(&v)), (0, (some("pkcs8-pbes2"), some("file"), Some(true))), "{v}");
    // PKCS#12 carries the key with its certificate, and the lock pairs none with this key: said
    // in the plan, as the export itself would refuse it.
    let (c, v) = plan(soft, &["movable", "--to-file", "pkcs12", "--allow-host-plaintext"]);
    assert_eq!((c, first(&v)), (15, (some("pkcs12"), some("file"), Some(false))), "{v}");
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("pairs no certificate"), "{v}");
    // Every object on the source: one plan each. Without names the export takes what can move,
    // so its plan is 0 with the blocked one shown, as the export itself is.
    let (c, v) = plan(soft, &["--target", "kryoptic"]);
    assert_eq!((c, v["plans"].as_array().map(Vec::len)), (0, Some(2)), "{v}");
    assert_eq!(v["plans"].as_array().unwrap().iter().filter(|p| p["ready"] == false).count(), 1, "{v}");
    let o = e.km(soft, &["export", "movable", "--token", "softhsm", "--target", "kryoptic"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let bundle: toml::Table = toml::from_str(&stdout(&o)).unwrap();
    assert_eq!(bundle["keys"][0]["method"].as_str(), Some("rsa-oaep-sha1+aes-kwp"));
    assert_eq!(bundle["transport"]["object"].as_str(), Some("tk-kryoptic"));
}

/// `camigrate transport` (docs/CAMIGRATE.md D3) writes the transport key's public half with its locked
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
            ", origin = \"create\", binding = \"pop-decrypt\"",
        )
        + &Env::spec("ec-k", "ec", "attributes = { CKA_SIGN = true }\n", &[kry], "xref-tec", CREATE)
        + &Env::spec(
            "movable",
            "mv",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
            &[soft],
            "xref-tmv",
            CREATE,
        );
    e.config(&body);
    assert_eq!(code(&e.cakeys(kry, &["create", "kek", "--token", "kryoptic"])), 0);
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
    assert_eq!(code(&e.cakeys(kry, &["create", "ec-k", "--token", "kryoptic"])), 0);
    assert_eq!(code(&e.km(kry, &["transport", "ec-k", "--token", "kryoptic"])), 17);
    // A source plans from the file alone.
    assert_eq!(code(&e.cakeys(soft, &["create", "movable", "--token", "softhsm"])), 0);
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
/// declare (the target's creation template: docs/CAMIGRATE.md D6), the planting template of its
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

/// The dry-run property for the `public` rows (docs/CAMIGRATE.md D9, phase 2): for every public class,
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
        body += &Env::spec(&target_spec(c, s, d), c.name, c.attributes, &[d], &target_label(c, s, d), IMPORT);
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
        if ready {
            // The same verdict for `export`: a public object needs no transport key (neither
            // token names one here), so its bundle names none, and a dry-run import accepts it.
            let out = e.dir.join(format!("{spec}.bundle.toml"));
            let out = out.to_str().unwrap();
            let exported = e.km(s, &["export", c.name, "--token", s.name, "--target", d.name, "--out", out]);
            assert_eq!(code(&exported), 0, "{spec}: export: {}", stderr(&exported));
            let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(out).unwrap()).unwrap();
            assert!(bundle.get("transport").is_none() && bundle.get("kek").is_none(), "{spec}: {bundle}");
            let checked = e.km(d, &["import", "--token", d.name, "--in", out, "--spec", &spec, "--dry-run"]);
            assert_eq!(code(&checked), 0, "{spec}: import --dry-run: {}", stderr(&checked));
            assert_eq!(std::fs::read(&lock_path).unwrap(), before, "{spec}: an export or a dry run changed the lock");
        }
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
        body += &format!("[objects.{k}]\n{ec}\n\n[objects.{kp}]\n{ec_pub}\n\n[objects.{c}]\n{cert}\n\n");
        body += &Env::spec(&format!("{k}-soft"), &k, movable, &[soft], &format!("sl-k{n}"), CREATE);
        body += &Env::spec(&format!("{kp}-soft"), &kp, "", &[soft], &format!("sl-k{n}"), "");
        body += &Env::spec(&format!("{c}-soft"), &c, "", &[soft], &format!("sl-crt{n}"), "");
        body += &Env::spec(&format!("{k}-kry"), &k, movable, &[kry], target, IMPORT);
        body += &Env::spec(&format!("{kp}-kry"), &kp, "", &[kry], target, IMPORT);
        body += &Env::spec(&format!("{c}-kry"), &c, "", &[kry], target, IMPORT);
    }
    // A second certificate for the first target label: a collision of its class.
    body += &Env::spec("crt2-kry-a", "crt2", "", &[kry], "sl-a", IMPORT);
    names_transport(&e, &body, |r| r.name == "kryoptic");
    assert_eq!(code(&e.cakeys(kry, &["create", "tk-kryoptic", "--token", "kryoptic"])), 0);
    // The keys are made; their public halves and the planted certificates are adopted.
    for (verb, spec) in [
        ("create", "k1-soft"),
        ("realise", "k1-pub-soft"),
        ("realise", "crt1-soft"),
        ("create", "k2-soft"),
        ("realise", "k2-pub-soft"),
        ("realise", "crt2-soft"),
    ] {
        let o = e.cakeys(soft, &[verb, spec, "--token", "softhsm"]);
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

/// A private data object (`CKA_PRIVATE = true`, which `cakeys` identifies once its spec declares
/// it) holds a secret value: the public method would write it into a bundle and recreate it
/// under the target's default `CKA_PRIVATE`, so no move plans for it (15), whatever is allowed;
/// an export without names leaves it out with a warning. Nothing reaches the target.
#[test]
fn private_data_objects_never_move() {
    let Some(e) = env("private-data") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping private-data: needs the softhsm and kryoptic references");
        return;
    };
    let on_target = || open_session(&kry.module, kry.token_label, "1234").labelled("pd-secret").len();
    open_session(&kry.module, kry.token_label, "1234").clear(&["pd-secret"]);
    let src = open_session(&soft.module, soft.token_label, "1234");
    src.clear(&["pd-secret"]);
    src.create_object(&[
        Attribute::Class(ObjectClass::DATA),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(b"pd-secret".to_vec()),
        Attribute::Value(b"7c1f9e04b2a85d36 an application secret".to_vec()),
    ])
    .unwrap();
    drop(src);
    let private = "attributes = { CKA_PRIVATE = true }\n";
    e.config(
        &("[objects.pd]\nclass = \"CKO_DATA\"\n\n".to_owned()
            + &Env::spec("pd-soft", "pd", private, &[soft], "pd-secret", "")
            + &Env::spec("pd-kry", "pd", private, &[kry], "pd-secret", IMPORT)),
    );
    let o = e.cakeys(soft, &["realise", "pd-soft", "--token", "softhsm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let mv = ["migrate", "pd", "--from", "softhsm", "--to", "kryoptic", "--spec", "pd-kry"];
    let o = e.km(soft, &[&mv[..], &["--dry-run", "--json"]].concat());
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("private data object"), "{v}");
    let o = e.km(soft, &[&mv[..], &["--allow-host-plaintext"]].concat());
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert_eq!(on_target(), 0);
    // Without names an export takes what can move: here nothing, the private object said.
    let o = e.km(soft, &["export", "--token", "softhsm", "--target", "kryoptic"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("pd: left out of the bundle"), "{}", stderr(&o));
}

/// The transport key of reference `r` (docs/CAMIGRATE.md D3), as keys.toml text: an RSA key that only
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
            ", origin = \"create\", binding = \"pop-unwrap\"",
        )
}

/// keys.toml with `body`, each reference `holds` picks naming its [`transport_key`]
/// (`transportWith`).
fn names_transport(e: &Env, body: &str, holds: impl Fn(&Ref) -> bool) {
    e.config_with(body, &|r| if holds(r) { format!("transportWith = \"tk-{}\"\n", r.name) } else { String::new() });
}

/// One key class of the sealed matrix: its keys.toml type and the attributes its specs declare
/// (extractable, or it could never move: docs/CAMIGRATE.md D1).
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

/// The dry-run property for the sealed rows (docs/CAMIGRATE.md D9, phase 3): for every key class,
/// source and target reference, `migrate --dry-run`'s verdict is the outcome. Each key is
/// generated on its source (`origin = "create"`, its targets `import`), each target holds a transport key. A ready move exits
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
            body += &format!("[objects.{o}]\n{}\n\n", k.ty);
            body += &Env::spec(&format!("{o}-src"), &o, k.attributes, &[s], &format!("cm-{o}"), CREATE);
        }
    }
    for (k, s, d) in &pairs {
        body += &Env::spec(&target_spec(k, s, d), &object(k, s), k.attributes, &[d], &target_label(k, s, d), IMPORT);
    }
    names_transport(&e, &body, unwraps);
    // p11-kit hides the module behind it, so its capabilities are a spec-compliant module's until
    // keys.toml names that module's provider (docs/ARCHITECTURE.md, "Providers"): this one forwards `SoftHSM`, whose
    // unwrapped secret keys lose their length (`secret-unwraps = false`).
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    let provider = |p: &str| {
        let named = if p.is_empty() { String::new() } else { format!("provider = \"{p}\"\n") };
        std::fs::write(&config, text.replace("[tokens.p11kit]\n", &format!("[tokens.p11kit]\n{named}"))).unwrap();
    };
    provider("softhsm");
    for d in e.refs.iter().filter(|d| unwraps(d)) {
        let o = e.cakeys(d, &["create", &format!("tk-{}", d.name), "--token", d.name]);
        assert_eq!(code(&o), 0, "transport key on {}: {}", d.name, stderr(&o));
    }
    for k in &KEYS {
        for s in e.refs.iter().filter(|s| generates(s, k)) {
            let spec = format!("{}-src", object(k, s));
            let o = e.cakeys(s, &["create", &spec, "--token", s.name]);
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
            // An unwrapped private key's public half is made as a generated one: it verifies and
            // is public, whatever the token's own default for an object.
            if k.ty.contains("CKO_PRIVATE_KEY") && matches!(d.name, "softhsm" | "kryoptic") {
                assert_eq!(public_half(d, &target_label(k, s, d)), (true, false), "{row}");
            }
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

/// A bundle crosses untrusted channels (docs/CAMIGRATE.md D5, D6): `export --out` writes it and
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
    // A bundle sealed to another transport key than the one realised here (10), and one whose
    // key is another type than the lock's (14): each before the target is touched.
    let sealed_to = b["transport"]["rfc7093m4"].as_str().unwrap();
    refused(text.replace(sealed_to, ids), 10, "another transport key");
    refused(text.replace("curve = \"secp256r1\"", "curve = \"secp384r1\""), 14, "another type");
    another_type_in_one_place(&e, kry, &text);
    // Against a lock that pins nothing: a wrapped key's transport key has no realisation there,
    // and a certificate's import nothing to be checked against (14 both).
    let bare = e.dir.join("bare.lock");
    std::fs::write(&bare, "version = 1\n").unwrap();
    for (path, why) in [(&ek1, "has no realisation on 'kryoptic'"), (&export(&["crt"]), "the lock pins no IDs")] {
        let args = ["--lock", bare.to_str().unwrap(), "import", "--token", "kryoptic", "--in", path.to_str().unwrap()];
        let o = e.km(kry, &args);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains(why), "{}", stderr(&o));
    }
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

/// The bundle's key type is held to the lock and to keys.toml, each on its own: a bundle of
/// `ek1` as a P-384 key is refused (14) when the lock agrees with it and keys.toml does not, and
/// when keys.toml agrees and the lock does not.
fn another_type_in_one_place(e: &Env, kry: &Ref, bundle: &str) {
    let (was, now) = ("curve = \"secp256r1\"", "curve = \"secp384r1\"");
    let path = e.dir.join("p384.bundle.toml");
    std::fs::write(&path, bundle.replace(was, now)).unwrap();
    let import = |lock: &std::path::Path| {
        let args = ["--lock", lock.to_str().unwrap(), "import", "--token", "kryoptic", "--in", path.to_str().unwrap()];
        let o = e.km(kry, &args);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains("the bundle carries a"), "{}", stderr(&o));
        let left = open_session(&kry.module, kry.token_label, "1234").labelled("xb-ek1");
        assert_eq!(left.len(), 0, "a refused import left objects");
    };
    // The lock says P-384 too; keys.toml still says P-256.
    let mut lock: toml::Table = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    lock["objects"]["ek1"]["type"]["curve"] = toml::Value::String("secp384r1".into());
    let retyped = e.dir.join("p384.lock");
    std::fs::write(&retyped, toml::to_string(&lock).unwrap()).unwrap();
    import(&retyped);
    // keys.toml says P-384 too; the lock still says P-256.
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    let at = text.find("[objects.ek1]").unwrap();
    std::fs::write(&config, format!("{}{}", &text[..at], text[at..].replacen(was, now, 1))).unwrap();
    import(&e.dir.join("keys.lock"));
    std::fs::write(&config, text).unwrap();
}

/// The keys the bundle tests move: P-256 `ek1`, `ek2` and AES `sk1`, `sk2`, each born on `SoftHSM`
/// (`origin = "create"`) with an `import` spec on kryoptic, whose transport key is realised; `nx`, a P-256 key made
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
        + &Env::spec("crt-kry", "crt", "", &[kry], "xb-crt", IMPORT);
    let key = |o: &str, ty: &str| {
        format!("[objects.{o}]\n{ty}\n\n")
            + &Env::spec(
                &format!("{o}-soft"),
                o,
                "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
                &[soft],
                &format!("xb-{o}"),
                CREATE,
            )
            + &Env::spec(
                &format!("{o}-kry"),
                o,
                "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
                &[kry],
                &format!("xb-{o}"),
                IMPORT,
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
            CREATE,
        );
    let kept = "[objects.nox]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n".to_owned()
        + &Env::spec(
            "nox-soft",
            "nox",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\nnoExport = true\n",
            &[soft],
            "xb-nox",
            CREATE,
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
    assert_eq!(code(&e.cakeys(kry, &["create", "tk-kryoptic", "--token", "kryoptic"])), 0);
    for spec in ["ek1-soft", "ek2-soft", "sk1-soft", "sk2-soft", "nx-soft", "nox-soft"] {
        assert_eq!(code(&e.cakeys(soft, &["create", spec, "--token", "softhsm"])), 0, "{spec}");
    }
    // The planted certificate is adopted.
    assert_eq!(code(&e.cakeys(soft, &["realise", "crt-soft", "--token", "softhsm"])), 0);
}

/// `--transport-key` names the transport key and `--lock` the lock file, as `transportWith` and
/// the default path do: a plan with either is the plan without, and one naming a spec that is no
/// transport key there, or a lock that records nothing, is blocked.
fn named_transport_key_and_lock(e: &Env, soft: &Ref) {
    let plan = ["export", "ek1", "--token", "softhsm", "--target", "kryoptic", "--dry-run"];
    let with = |extra: &[&str]| code(&e.km(soft, &[&plan[..], extra].concat()));
    assert_eq!(with(&["--transport-key", "tk-kryoptic"]), 0);
    assert_eq!(with(&["--transport-key", "ek1-kry"]), 15);
    let copy = e.dir.join("copy.lock");
    std::fs::copy(e.dir.join("keys.lock"), &copy).unwrap();
    let locked = |lock: &std::path::Path| code(&e.km(soft, &[&["--lock", lock.to_str().unwrap()], &plan[..]].concat()));
    assert_eq!(locked(&copy), 0);
    assert_eq!(locked(&e.dir.join("absent.lock")), 14);
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

/// One bundle per export (docs/CAMIGRATE.md D5): every key, one shared KEK. Each key imports on its
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
    named_transport_key_and_lock(&e, soft);
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
    // Its public half is made as a generated one: it verifies and is public, undeclared.
    assert_eq!(public_half(kry, "xb-ek1"), (true, false));
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

/// What camigrate refuses around its plans, and the offline path the other tests only plan
/// (the coverage report's gaps): admin operations inside a Nix build (D8); a key file export
/// without its flags, with an empty passphrase, of several keys or of a key the lock pairs no
/// certificate with; a key file whose key the lock does not pin; and an export sealed to a
/// transport file, written, imported and verified.
#[test]
fn refusals_around_the_plans_and_the_offline_export() {
    let Some(e) = env("refusals") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping refusals: needs the softhsm and kryoptic references");
        return;
    };
    bundle_keys(&e, soft, kry);
    // The tokens are shared with the tests before this one, which import these keys too.
    open_session(&kry.module, kry.token_label, "1234").clear(&["xb-ek1", "xb-ek2", "xb-sk1", "xb-sk2"]);
    let path = |name: &str| e.dir.join(name).to_str().unwrap().to_owned();
    let refused = |o: &std::process::Output, want: i32, what: &str| {
        assert_eq!(code(o), want, "{what}: {}", stderr(o));
        assert!(stderr(o).contains(what) || stdout(o).contains(what), "{what}: {} {}", stdout(o), stderr(o));
    };
    let (pass, empty) = (path("pass"), path("empty"));
    std::fs::write(&pass, "correct horse\n").unwrap();
    std::fs::write(&empty, "\n").unwrap();
    let to_file = |format: &'static str, out: &str| -> Vec<String> {
        ["--token", "softhsm", "--to-file", format, "--out", out, "--passphrase-file", &pass, "--allow-host-plaintext"]
            .map(String::from)
            .to_vec()
    };
    let args = |head: &[&str], tail: &[String]| -> Vec<String> {
        head.iter().map(|a| (*a).to_owned()).chain(tail.iter().cloned()).collect()
    };
    let run = |r: &Ref, a: &[String]| e.km(r, &a.iter().map(String::as_str).collect::<Vec<_>>());

    // D8: an export, a key file's import and `transport --trusted` are admin operations, and a
    // move writes the lock: each is refused inside a Nix build, before any token is opened.
    let bundle = path("nix.bundle.toml");
    let admin: [(&[&str], &str); 4] = [
        (
            &["export", "ek1", "--token", "softhsm", "--target", "kryoptic", "--out", &bundle],
            "export is an admin operation",
        ),
        (
            &["import", "--token", "kryoptic", "--in", &bundle, "--passphrase-file", &pass, "--allow-host-plaintext"],
            "import of a key file is an admin operation",
        ),
        (
            &["transport", "tk-kryoptic", "--token", "kryoptic", "--trusted", "softhsm"],
            "transport --trusted is an admin",
        ),
        (&["migrate", "crt", "--from", "softhsm", "--to", "kryoptic"], "cannot write the lock"),
    ];
    for (a, what) in admin {
        refused(&e.km_in_nix_build(soft, a), 14, what);
    }
    assert!(!std::path::Path::new(&bundle).exists(), "a refused export wrote a bundle");

    // A key file: its flags and its passphrase are input, wrong before any plan.
    let o = e.km_alone(soft, &["export", "ek1", "--token", "softhsm", "--to-file", "pkcs8", "--allow-host-plaintext"]);
    refused(&o, 17, "needs --out and --passphrase-file");
    let out = path("ek1.pem");
    let flags = ["--to-file", "pkcs8", "--out", &out, "--passphrase-file", &empty, "--allow-host-plaintext"];
    refused(
        &e.km_alone(soft, &[&["export", "ek1", "--token", "softhsm"][..], &flags].concat()),
        17,
        "passphrase is empty",
    );
    // What a file can hold is in the plan: one key, and for PKCS#12 its paired certificate.
    refused(&run(soft, &args(&["export", "ek1", "ek2"], &to_file("pkcs8", &out))), 15, "a key file holds one key");
    refused(&run(soft, &args(&["export", "ek1"], &to_file("pkcs12", &out))), 15, "pairs no certificate");
    assert!(!std::path::Path::new(&out).exists(), "a refused export wrote a key file");
    // A key file names no object: a lock that does not pin its key has nowhere to put it.
    assert_eq!(code(&run(soft, &args(&["export", "ek1"], &to_file("pkcs8", &out)))), 0);
    let unpinned = path("unpinned.lock");
    let import = ["import", "--token", "kryoptic", "--in", &out, "--passphrase-file", &pass, "--allow-host-plaintext"];
    refused(
        &e.km(kry, &[&["--lock", &unpinned][..], &import].concat()),
        14,
        "pins no private key with this key's identity",
    );

    // Offline: the transport file on stdout is the one `--out` writes; an export sealed to it
    // needs no target, and the target imports and verifies the bundle.
    let transport = path("tk.transport.toml");
    let o = e.km(kry, &["transport", "tk-kryoptic", "--token", "kryoptic"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(code(&e.km(kry, &["transport", "tk-kryoptic", "--token", "kryoptic", "--out", &transport])), 0);
    assert_eq!(stdout(&o).trim_end(), std::fs::read_to_string(&transport).unwrap().trim_end());
    let sealed = path("sk2.bundle.toml");
    let o = e.km(soft, &["export", "sk2", "--token", "softhsm", "--transport", &transport, "--out", &sealed]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // A --spec that does not realise the bundle's object there is refused before the import.
    let o = e.km(kry, &["import", "--token", "kryoptic", "--in", &sealed, "--spec", "ek1-kry"]);
    refused(&o, 17, "--spec 'ek1-kry' selects nothing");
    let o = e.km(kry, &["import", "--token", "kryoptic", "--in", &sealed]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["verify", "sk2-kry", "--token", "kryoptic"])), 0);
    // A token the lock records nothing on has nothing to plan.
    if named("p11kit").is_some() {
        let o = e.km(soft, &["export", "--token", "p11kit", "--target", "kryoptic", "--dry-run"]);
        refused(&o, 14, "the lock records no realisation on token 'p11kit'");
    }
    transport_files_and_bundle_entries_are_checked(&e, soft, &transport);
}

/// A transport file is input: one of a provider this build does not link has no plan (15), one
/// naming an object whose key the lock does not pin blocks it (15), and one of a provider with
/// no committed profile is planned by that provider's own rules. A bundle entry whose object has
/// no spec on the importing token is reported, not imported, and fails the run (17). A
/// transport key whose spec has left keys.toml blocks the plan (15), as it would stop the export.
fn transport_files_and_bundle_entries_are_checked(e: &Env, soft: &Ref, transport: &str) {
    let text = std::fs::read_to_string(transport).unwrap();
    let plan = |name: &str, from: &str, to: &str| {
        let path = e.dir.join(name);
        assert!(text.contains(from), "{from}: {text}");
        std::fs::write(&path, text.replace(from, to)).unwrap();
        e.km(soft, &["export", "sk1", "--token", "softhsm", "--transport", path.to_str().unwrap(), "--dry-run"])
    };
    let provider = "provider = \"kryoptic\"";
    let o = plan("nope.transport.toml", provider, "provider = \"nope\"");
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("provider 'nope' is not in this build"), "{}", stderr(&o));
    let o = plan("other.transport.toml", "object = \"tk-kryoptic\"", "object = \"tk-other\"");
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("the lock pins no key for its object 'tk-other'"), "{}", stdout(&o));
    let o = plan("generic.transport.toml", provider, "provider = \"generic\"");
    assert_eq!(code(&o), 0, "{} {}", stdout(&o), stderr(&o));

    // The certificate has a spec on SoftHSM and on kryoptic, and none on the third token.
    let bundle = export_bundle(e, soft, &["crt"]);
    if let Some(der) = e.refs.iter().find(|r| r.name == "kryoptic-der") {
        let o = e.km(der, &["import", "--token", "kryoptic-der", "--in", bundle.to_str().unwrap()]);
        assert_eq!(code(&o), 17, "{}", stderr(&o));
        let said = stdout(&o) + &stderr(&o);
        assert!(
            said.contains("crt: not imported")
                && said.contains("keys.toml has no spec of object 'crt' on token 'kryoptic-der'"),
            "{said}"
        );
    }

    // The lock still names tk-kryoptic as kryoptic's transport key; keys.toml no longer has it.
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let attributes = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let kry = e.refs.iter().find(|r| r.name == "kryoptic").unwrap();
    let body = format!("[objects.ek1]\n{ec}\n\n")
        + &Env::spec("ek1-soft", "ek1", attributes, &[soft], "xb-ek1", CREATE)
        + &Env::spec("ek1-kry", "ek1", attributes, &[kry], "xb-ek1", IMPORT);
    e.config(&body);
    let out = e.dir.join("gone.bundle.toml");
    let export = ["export", "ek1", "--token", "softhsm", "--target", "kryoptic", "--transport-key", "tk-kryoptic"];
    let o = e.km(soft, &[&export[..], &["--out", out.to_str().unwrap()]].concat());
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("the transport key's spec 'tk-kryoptic' is gone from keys.toml"), "{}", stderr(&o));
    assert!(!out.exists(), "a refused export wrote a bundle");
}

/// A move lands only on a pair that says `origin = "import"`: a target pair that says the key is
/// adopted there is refused, by the dry run as by the run, and by name, before anything moves.
#[test]
fn a_move_lands_only_on_an_import_pair() {
    let Some(e) = env("import-only") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping import-only: needs the softhsm and kryoptic references");
        return;
    };
    let movable = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let body = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n".to_owned()
        + &Env::spec("k-soft", "k", movable, &[soft], "xi-k", CREATE)
        + &Env::spec("k-kry", "k", movable, &[kry], "xi-k", "");
    e.config(&body);
    assert_eq!(code(&e.cakeys(soft, &["create", "k-soft", "--token", "softhsm"])), 0);
    let mv = ["migrate", "k", "--from", "softhsm", "--to", "kryoptic", "--allow-host-plaintext"];
    for extra in [&["--dry-run"][..], &[], &["--spec", "k-kry", "--dry-run"], &["--spec", "k-kry"]] {
        let o = e.km(soft, &[&mv[..], extra].concat());
        let said = format!("{}{}", stdout(&o), stderr(&o));
        assert!(matches!(code(&o), 15 | 17), "{extra:?}: {said}");
        assert!(said.contains("a move lands only where keys.toml says origin = \"import\""), "{extra:?}: {said}");
    }
    assert!(open_session(&kry.module, kry.token_label, "1234").labelled("xi-k").is_empty(), "nothing moved");
}

/// A transport key is held to what the lock records of it (docs/CAMIGRATE.md D3): `transport`
/// refuses a key that is no RSA private key (17), one that may not unwrap and one that could
/// leave its token (14), and a plan naming such a key with `--transport-key` is blocked (15).
/// An export without names in which nothing can move writes no bundle (15).
#[test]
fn transport_keys_are_held_to_what_the_lock_records() {
    let Some(e) = env("transport-keys") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping transport-keys: needs the softhsm and kryoptic references");
        return;
    };
    let rsa = |name: &str, attributes: &str, binding: &str| {
        format!("[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n")
            + &Env::spec(name, name, attributes, &[kry], &format!("xt-{name}"), &format!("{CREATE}{binding}"))
    };
    let ec = |name: &str, extractable: bool| {
        format!("[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n")
            + &Env::spec(
                name,
                name,
                &format!("attributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = {extractable} }}\n"),
                &[soft],
                &format!("xt-{name}"),
                CREATE,
            )
    };
    let body = rsa("signs", "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }\n", "")
        + &rsa("leaves", "attributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = true }\n", ", binding = \"pop-unwrap\"")
        + &ec("stays", false)
        + &ec("moves", true);
    e.config(&body);
    for spec in ["signs", "leaves"] {
        assert_eq!(code(&e.cakeys(kry, &["create", spec, "--token", "kryoptic"])), 0, "{spec}");
    }
    for spec in ["stays", "moves"] {
        assert_eq!(code(&e.cakeys(soft, &["create", spec, "--token", "softhsm"])), 0, "{spec}");
    }
    let refused = |o: &std::process::Output, want: i32, what: &str| {
        assert_eq!(code(o), want, "{what}: {}", stderr(o));
        assert!(stderr(o).contains(what) || stdout(o).contains(what), "{what}: {} {}", stdout(o), stderr(o));
    };
    let transport = |r: &Ref, spec: &str, token: &str| e.km(r, &["transport", spec, "--token", token]);
    refused(&transport(soft, "moves", "softhsm"), 17, "a transport key is an RSA private key");
    refused(&transport(kry, "signs", "kryoptic"), 14, "a transport key must allow CKA_UNWRAP");
    refused(&transport(kry, "leaves", "kryoptic"), 14, "a transport key must never leave the token");
    let plan = ["export", "moves", "--token", "softhsm", "--target", "kryoptic", "--dry-run"];
    for key in ["signs", "leaves"] {
        let o = e.km(soft, &[&plan[..], &["--transport-key", key]].concat());
        refused(&o, 15, &format!("'{key}' on 'kryoptic' is no transport key"));
    }
    // Nothing moves: one key never leaves its token, the other has no transport key to go under.
    let out = e.dir.join("none.bundle.toml");
    let o = e.km(soft, &["export", "--token", "softhsm", "--target", "kryoptic", "--out", out.to_str().unwrap()]);
    refused(&o, 15, "nothing on 'softhsm' can go into a bundle");
    assert!(stderr(&o).contains("moves: left out of the bundle"), "{}", stderr(&o));
    assert!(!out.exists(), "an export of nothing wrote a bundle");
}

/// A token names its transport key (`transportWith`, docs/CAMIGRATE.md D3), and realising it records
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
            CREATE,
        );
    // Named, not picked: without transportWith, the plan says how to name one.
    e.config(&body);
    assert_eq!(code(&e.cakeys(kry, &["create", "tk-kryoptic", "--token", "kryoptic"])), 0);
    assert_eq!(code(&e.cakeys(soft, &["create", "mv", "--token", "softhsm"])), 0);
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
    // With kryoptic in reach, the export asks the token for the key the lock lacks and says so;
    // `transport --trusted` takes the key from the lock alone, and has none to take.
    let early = e.dir.join("early.bundle.toml");
    let o =
        e.km(soft, &["export", "mv", "--token", "softhsm", "--target", "kryoptic", "--out", early.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("the lock records no public key for it yet"), "{}", stderr(&o));
    let o = e.km(kry, &["transport", "tk-kryoptic", "--token", "kryoptic", "--trusted", "softhsm"]);
    assert_eq!(code(&o), 14, "{}", stderr(&o));
    assert!(stderr(&o).contains("records no public key for transport key"), "{}", stderr(&o));
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
    // The unreachable target's capabilities come only from an observation all its realisations
    // agree on: with none recorded, or two that differ, the plan fails as the open did.
    let mut lock: toml::Table = toml::from_str(&text).unwrap();
    let realisations = lock["realisations"].as_table().unwrap().clone();
    let observed = realisations["tk-kryoptic"]["kryoptic"]["observation"].as_str().unwrap().to_owned();
    let mut bare = realisations.clone();
    bare["tk-kryoptic"]["kryoptic"].as_table_mut().unwrap().remove("observation");
    lock.insert("realisations".into(), bare.into());
    lock["observations"].as_table_mut().unwrap().remove(&observed);
    std::fs::write(&lock_path, toml::to_string(&lock).unwrap()).unwrap();
    let o = plan(&e);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(!stderr(&o).contains("come from the lock"), "{}", stderr(&o));
    let mut lock: toml::Table = toml::from_str(&text).unwrap();
    let other = cakeys_core::id::sri(b"another observation");
    let copy = lock["observations"][&observed].clone();
    lock["observations"].as_table_mut().unwrap().insert(other.clone(), copy);
    let mut second = realisations["tk-kryoptic"].clone();
    second["kryoptic"].as_table_mut().unwrap().insert("observation".into(), other.into());
    lock["realisations"].as_table_mut().unwrap().insert("tk-again".into(), second);
    std::fs::write(&lock_path, toml::to_string(&lock).unwrap()).unwrap();
    let o = plan(&e);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("2 different observations"), "{}", stderr(&o));
    std::fs::write(&lock_path, text).unwrap();
    // A transportWith naming a key that is no transport key is invalid.
    e.config_with(&body, &|r| if r.name == "kryoptic" { "transportWith = \"mv\"\n".into() } else { String::new() });
    assert_eq!(code(&e.km(soft, &["export", "mv", "--token", "softhsm", "--target", "kryoptic", "--dry-run"])), 17);
}

/// The sealed path at OAEP SHA-256, which `SoftHSM` cannot do: between two kryoptic tokens, the
/// second one initialised in this test in a slot of its own. Both are reached through one
/// kryoptic configuration naming both slots, which every run here carries.
#[test]
fn sealed_moves_wrap_with_oaep_sha256_between_kryoptic_tokens() {
    let Some(mut e) = env("oaep-sha256") else { return };
    let Some(kry) = e.refs.iter().find(|r| r.name == "kryoptic") else {
        eprintln!("skipping oaep-sha256: needs the kryoptic reference");
        return;
    };
    let module = kry.module.clone();
    // Slot 2 before slot 1: the suites append to the last table, which stays the first token's.
    let conf = e.dir.join("kryoptic-two.conf");
    let first = std::fs::read_to_string(std::env::var("KRYOPTIC_CONF").unwrap()).unwrap();
    let db = e.dir.join("kryoptic-two.sql");
    std::fs::write(
        &conf,
        format!("[[slots]]\nslot = 2\ndbtype = \"sqlite\"\ndbargs = \"{}\"\n\n{first}", db.display()),
    )
    .unwrap();
    let conf: &'static str = Box::leak(conf.to_str().unwrap().to_owned().into_boxed_str());
    let tool = |args: &[&str]| {
        let o = std::process::Command::new("pkcs11-tool")
            .env("KRYOPTIC_CONF", conf)
            .args(["--module", &module])
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "pkcs11-tool {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr));
    };
    tool(&["--init-token", "--slot", "2", "--so-pin", "5678", "--label", "kmtest2"]);
    tool(&[
        "--token-label",
        "kmtest2",
        "--login",
        "--login-type",
        "so",
        "--so-pin",
        "5678",
        "--init-pin",
        "--pin",
        "1234",
    ]);
    let both: &'static [(&str, &str)] = Box::leak(Box::new([("KRYOPTIC_CONF", conf)]));
    e.refs.retain(|r| r.name == "kryoptic");
    e.refs[0].env = both;
    e.refs.push(Ref { name: "kryoptic2", token_label: "kmtest2", ..e.refs[0].clone() });
    let (kry, two) = (&e.refs[0], &e.refs[1]);
    let attributes = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let body = transport_key(two)
        + "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        + &Env::spec("k-one", "k", attributes, &[kry], "xo-k", CREATE)
        + &Env::spec("k-two", "k", attributes, &[two], "xo-k", IMPORT);
    names_transport(&e, &body, |r| r.name == "kryoptic2");
    for (spec, r) in [("tk-kryoptic2", two), ("k-one", kry)] {
        let o = e.cakeys(r, &["create", spec, "--token", r.name]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
    }
    let args = ["migrate", "k", "--from", "kryoptic", "--to", "kryoptic2"];
    let o = e.km(kry, &[&args[..], &["--dry-run", "--json"]].concat());
    let plan: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(plan["plans"][0]["method"].as_str(), Some("rsa-oaep-sha256+aes-kwp"), "{plan}");
    let o = e.km(kry, &args);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(two, &["verify", "k-two", "--token", "kryoptic2"])), 0);
}

/// A key whose target spec declares `CKA_ALWAYS_AUTHENTICATE` moves as its plan says: kryoptic
/// to `SoftHSM`, whose ECDSA signs in one part only, proves possession with the per-use PIN
/// (`pop-sign-pin`) after the single-part sign the patched cryptoki adds. Before it, the plan
/// said ready and the move then failed its proof (15). The plan and the proof ask one check
/// (`cakeys_pkcs11::token::proof_refusal`).
#[test]
fn per_use_pin_targets_move_as_planned() {
    let Some(e) = env("per-use-pin") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping per-use-pin: needs the softhsm and kryoptic references");
        return;
    };
    let body = transport_key(soft)
        + "[objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        + &Env::spec(
            "a-src",
            "a",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
            &[kry],
            "xp-a",
            CREATE,
        )
        + &Env::spec(
            "a-dst",
            "a",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true, CKA_ALWAYS_AUTHENTICATE = true }\n",
            &[soft],
            "xp-a",
            IMPORT,
        );
    names_transport(&e, &body, |r| r.name == "softhsm");
    for (spec, r) in [("tk-softhsm", soft), ("a-src", kry)] {
        let o = e.cakeys(r, &["create", spec, "--token", r.name]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
    }
    // The dry-run twin holds the move to the plan's verdict.
    let o = e.km(kry, &["migrate", "a", "--from", "kryoptic", "--to", "softhsm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    assert_eq!(lock["realisations"]["a-dst"]["softhsm"]["binding"].as_str(), Some("pop-sign-pin"), "{lock}");
    assert_eq!(code(&e.cakeys(soft, &["verify", "a-dst", "--token", "softhsm"])), 0);
}

/// `text`, base64, with one byte of what it encodes flipped.
fn base64_flip(text: &str) -> String {
    use base64::Engine as _;
    let mut bytes = base64::engine::general_purpose::STANDARD.decode(text).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// `enforced` (docs/CAMIGRATE.md D2, phase 3b): a `CKA_WRAP_WITH_TRUSTED` key on `SoftHSM` moves only after
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
    let key = |o: &str, ty: &str, born: &Ref, other: &Ref, public: &str| {
        format!("[objects.{o}]\n{ty}\n\n")
            + &Env::spec(&format!("{o}-src"), o, trusted, &[born], &format!("xe-{o}"), CREATE)
            + &Env::spec(&format!("{o}-dst"), o, &format!("{trusted}{public}"), &[other], &format!("xe-{o}"), IMPORT)
    };
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
    // On kryoptic, `ek`'s public half is declared not to verify: the import makes it so.
    let body = transport_key(kry)
        + &key("ek", ec, soft, kry, "publicAttributes = { CKA_VERIFY = false }\n")
        + &key("sk", aes, soft, kry, "")
        + &key("kk", ec, kry, soft, "");
    let so_pin = e.dir.join("so-pin");
    e.config_with(&body, &|r| match r.name {
        "kryoptic" => "transportWith = \"tk-kryoptic\"\n".into(),
        "softhsm" => format!("mgmKeyFile = \"{}\"\n", so_pin.display()),
        _ => String::new(),
    });
    for (spec, r) in [("tk-kryoptic", kry), ("ek-src", soft), ("sk-src", soft), ("kk-src", kry)] {
        let o = e.cakeys(r, &["create", spec, "--token", r.name]);
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
    // The trusted copy is the only trusted object there: the export has nothing to warn of.
    let narrow = e.dir.join("narrow.bundle.toml");
    let o =
        e.km(soft, &["export", "ek", "--token", "softhsm", "--target", "kryoptic", "--out", narrow.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stderr(&o).contains("are CKA_TRUSTED"), "{}", stderr(&o));
    // Another key the SO trusts: `enforced` is then only as narrow as that set, which both the
    // trust and the export say.
    plant_trusted_key(soft);
    let o = e.km(soft, &trust);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("already trusts"), "{}", stderr(&o));
    assert!(stderr(&o).contains("1 other object(s) on 'softhsm' are CKA_TRUSTED"), "{}", stderr(&o));
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
    assert!(stderr(&exported).contains("1 other object(s) on 'softhsm' are CKA_TRUSTED"), "{}", stderr(&exported));
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
    assert_eq!(public_half(kry, "xe-ek"), (false, false), "the public half as the target spec declares it");
    // kryoptic cannot trust an RSA key: a wrap-with-trusted key there never leaves.
    let p = plan("kk", kry, soft);
    let reasons = p["plans"][0]["reasons"].to_string();
    assert!(p["plans"][0]["ready"] == false && reasons.contains("trusted-wrap = false"), "{p}");
}

/// A side with no RFC 5649 of its own (AWS `CloudHSM`, whose profile subtracts the AES key wraps
/// it lists but refuses \[run\]) moves the composed method by `CKM_RSA_AES_KEY_WRAP`, in and out.
/// Offline, `SoftHSM` under a copy of its committed profile, added through `profileDirs` and named
/// by `provider`, that subtracts its
/// AES key wraps: into it, `migrate` unwraps both blobs in one call; out of it, each sealed key of
/// a bundle carries its own key-encryption key, which `import` takes. kryoptic and `SoftHSM`
/// verify what arrived.
#[test]
fn rsa_aes_key_wrap_stands_in_for_rfc_5649() {
    let Some(e) = env("rsa-aes") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping rsa-aes: needs the softhsm and kryoptic references");
        return;
    };
    let profiles = e.dir.join("profiles");
    std::fs::create_dir_all(&profiles).unwrap();
    let committed = std::fs::read_to_string(committed_profile("modules/softhsm/2.7.toml")).unwrap();
    let subtract = "[subtract]\nmechanisms = [\"CKM_AES_KEY_WRAP\", \"CKM_AES_KEY_WRAP_PAD\"]\n\n[match]\n";
    assert!(!committed.contains("[subtract]"), "the fixture adds softhsm/2.7's only subtraction");
    let renamed = committed.replacen("profile = \"softhsm/2.7\"", "profile = \"softhsm/2.7+no-aes-key-wrap\"", 1);
    std::fs::write(profiles.join("softhsm.toml"), renamed.replacen("[match]\n", subtract, 1)).unwrap();
    let extractable = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let key = |o: &str, born: &Ref, other: &Ref| {
        format!("[objects.{o}]\n{ec}\n\n")
            + &Env::spec(&format!("{o}-src"), o, extractable, &[born], &format!("ra-{o}"), CREATE)
            + &Env::spec(&format!("{o}-dst"), o, extractable, &[other], &format!("ra-{o}"), IMPORT)
    };
    let body = transport_key(kry) + &transport_key(soft) + &key("in", kry, soft) + &key("out", soft, kry);
    e.config_with(&body, &|r| match r.name {
        "softhsm" => {
            "transportWith = \"tk-softhsm\"\nprovider = \"softhsm\"\nmoduleProfile = \"softhsm/2.7+no-aes-key-wrap\"\n"
                .into()
        }
        "kryoptic" => "transportWith = \"tk-kryoptic\"\n".into(),
        _ => String::new(),
    });
    // profileDirs is a top-level key: ahead of every table.
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, format!("profileDirs = [\"{}\"]\n\n{text}", profiles.display())).unwrap();
    for (spec, r) in [("tk-kryoptic", kry), ("tk-softhsm", soft), ("in-src", kry), ("out-src", soft)] {
        let o = e.cakeys(r, &["create", spec, "--token", r.name]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
    }
    // Into the side without RFC 5649: the composed method, unwrapped by CKM_RSA_AES_KEY_WRAP.
    let o = e.km(kry, &["migrate", "in", "--from", "kryoptic", "--to", "softhsm", "--spec", "in-dst"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("rsa-oaep-sha1+aes-kwp"), "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(soft, &["verify", "in-dst", "--token", "softhsm"])), 0);
    // Out of it, through a file: the sealed key with its own KEK, no shared one.
    let out = e.dir.join("rsa-aes.bundle.toml");
    let exported =
        e.km(soft, &["export", "out", "--token", "softhsm", "--target", "kryoptic", "--out", out.to_str().unwrap()]);
    assert_eq!(code(&exported), 0, "{}", stderr(&exported));
    let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(bundle.get("kek").is_none(), "{bundle}");
    let k = &bundle["keys"][0];
    assert_eq!((k["exposure"].as_str(), k.get("kek").is_some()), (Some("sealed"), true), "{k}");
    let o = e.km(kry, &["import", "--token", "kryoptic", "--in", out.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["verify", "out-dst", "--token", "kryoptic"])), 0);
}

/// `CKA_VERIFY` and `CKA_PRIVATE` of the one public key object labelled `label` on `r`'s token.
fn public_half(r: &Ref, label: &str) -> (bool, bool) {
    use cryptoki::object::AttributeType;
    let session = open_session(&r.module, r.token_label, "1234");
    let found = session
        .find_objects(&[Attribute::Label(label.as_bytes().to_vec()), Attribute::Class(ObjectClass::PUBLIC_KEY)])
        .unwrap();
    let [public] = found.as_slice() else { panic!("{} public key objects labelled {label}", found.len()) };
    let attrs = session.get_attributes(*public, &[AttributeType::Verify, AttributeType::Private]).unwrap();
    match attrs.as_slice() {
        [Attribute::Verify(verify), Attribute::Private(private)] => (*verify, *private),
        other => panic!("{label}: {other:?}"),
    }
}

/// An RSA public key the SO of `soft`'s token (SO PIN 5678) marks `CKA_TRUSTED`, beside the
/// transport key's trusted copy.
fn plant_trusted_key(soft: &Ref) {
    use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
    let ctx = Pkcs11::new(&soft.module).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().label() == soft.token_label)
        .unwrap();
    let session = ctx.open_rw_session(slot).unwrap();
    session.login(cryptoki::session::UserType::So, Some(&cryptoki::types::AuthPin::new("5678".into()))).unwrap();
    let mut modulus = vec![0xc5; 256];
    modulus[255] = 0x01;
    session
        .create_object(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Modulus(modulus),
            Attribute::PublicExponent(vec![1, 0, 1]),
            Attribute::Token(true),
            Attribute::Wrap(true),
            Attribute::Trusted(true),
            Attribute::Label(b"xe-other-trusted".to_vec()),
        ])
        .unwrap();
    drop(session);
    ctx.finalize().unwrap();
}

/// The dry-run property for the `host` rows (docs/CAMIGRATE.md D2, phase 4): with
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
            body += &format!("[objects.{o}]\n{}\n\n", k.ty);
            body += &Env::spec(&format!("{o}-src"), &o, k.attributes, &[s], &format!("hm-{o}"), CREATE);
        }
    }
    for (k, s, d) in &pairs {
        body += &Env::spec(&target_spec(k, s, d), &object(k, s), k.attributes, &[d], &target_label(k, s, d), IMPORT);
    }
    e.config(&body);
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, text.replace("[tokens.p11kit]\n", "[tokens.p11kit]\nprovider = \"softhsm\"\n")).unwrap();
    for k in &KEYS {
        for s in e.refs.iter().filter(|s| generates(s, k)) {
            let spec = format!("{}-src", object(k, s));
            let o = e.cakeys(s, &["create", &spec, "--token", s.name]);
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
        // A re-run finds the key there, verifies it and changes nothing.
        let again = std::fs::read(&lock_path).unwrap();
        let out = e.km(s, &args);
        assert_eq!(code(&out), 0, "{row}: the re-run: {}", stderr(&out));
        assert_eq!(std::fs::read(&lock_path).unwrap(), again, "{row}: the re-run changed the lock");
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

/// The host path's guards (docs/CAMIGRATE.md D6), into `SoftHSM` behind p11-kit, where the plan
/// sends an EC key through the host: another key under the target locator is never imported
/// over (13); a public half of the key already there is reused, and when it is not what the
/// target spec's `publicAttributes` say, the private key just created is removed again (13);
/// a target session without login cannot tell the locator is free (16).
#[test]
fn host_moves_refuse_what_they_cannot_check() {
    let Some(e) = env("host-guards") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(fwd)) = (named("softhsm"), named("p11kit")) else {
        eprintln!("skipping host-guards: needs the softhsm and p11kit references");
        return;
    };
    let attributes = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let body = "[objects.hg]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n".to_owned()
        + &Env::spec("hg-src", "hg", attributes, &[soft], "hg-src", CREATE)
        + &Env::spec(
            "hg-dst",
            "hg",
            &format!("{attributes}publicAttributes = {{ CKA_VERIFY = true }}\n"),
            &[fwd],
            "hg-dst",
            IMPORT,
        )
        + &format!(
            "[tokens.p11kit-anon]\nmodule = \"{}\"\ntokenLabel = \"kmp11\"\nprovider = \"softhsm\"\n\n",
            fwd.module
        )
        + "[specs.hg-anon]\nobject = \"hg\"\nattributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n\
           tokens.p11kit-anon = { locator = { CKA_LABEL = \"hg-anon\" }, origin = \"import\" }\n\n";
    e.config_with(&body, &|r| if r.name == "p11kit" { "provider = \"softhsm\"\n".into() } else { String::new() });
    let o = e.cakeys(soft, &["create", "hg-src", "--token", "softhsm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let migrate = |spec: &str, to: &str| {
        e.km(soft, &["migrate", "hg", "--from", "softhsm", "--to", to, "--spec", spec, "--allow-host-plaintext"])
    };
    // A bundle carries sealed keys and public objects: the host path is migrate's, and the plan
    // of an export says so (it once said ready, and the export then refused).
    let export = ["export", "hg", "--token", "softhsm", "--target", "p11kit", "--allow-host-plaintext"];
    let plan = e.km(soft, &[&export[..], &["--dry-run"]].concat());
    assert_eq!(code(&plan), 15, "{}", stdout(&plan));
    assert!(stdout(&plan).contains("not host-pkcs8: move it with `camigrate migrate`"), "{}", stdout(&plan));
    let out = e.dir.join("hg.bundle.toml");
    assert_eq!(code(&e.km(soft, &[&export[..], &["--out", out.to_str().unwrap()]].concat())), 15);
    assert!(!out.exists());
    // The target token itself, reached directly (the forwarder serves this SoftHSM token).
    let direct = std::env::var("CAKEYS_TEST_MODULE").unwrap();
    let target = || open_session(&direct, "kmp11", "1234");
    let p256 = P256_PARAMS.to_vec();

    // Another key under the target locator.
    let t = target();
    t.generate_key_pair(
        &cryptoki::mechanism::Mechanism::EccKeyPairGen,
        &[Attribute::Token(true), Attribute::Label(b"hg-dst".to_vec()), Attribute::EcParams(p256.clone())],
        &[Attribute::Token(true), Attribute::Label(b"hg-dst".to_vec()), Attribute::Sign(true)],
    )
    .unwrap();
    drop(t);
    let o = migrate("hg-dst", "p11kit");
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("would collide with"), "{}", stderr(&o));

    // The key's own public half, but without CKA_VERIFY: reused, then refused, the import undone.
    let source = open_session(&soft.module, soft.token_label, "1234");
    let public = source
        .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::Label(b"hg-src".to_vec())])
        .unwrap()[0];
    let [Attribute::EcPoint(point)] =
        &source.get_attributes(public, &[cryptoki::object::AttributeType::EcPoint]).unwrap()[..]
    else {
        panic!("no CKA_EC_POINT")
    };
    drop(source);
    let t = target();
    t.clear(&["hg-dst"]);
    t.create_object(&[
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::EcParams(p256),
        Attribute::EcPoint(point.clone()),
        Attribute::Token(true),
        Attribute::Verify(false),
        Attribute::Label(b"hg-dst".to_vec()),
    ])
    .unwrap();
    drop(t);
    let o = migrate("hg-dst", "p11kit");
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert!(stderr(&o).contains("removed 1 object(s) just imported"), "{}", stderr(&o));
    let left =
        target().find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Label(b"hg-dst".to_vec())]);
    assert_eq!(left.unwrap().len(), 0, "the imported private key was left on the target");
    let lock = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    assert!(!lock.contains("[realisations.hg-dst"), "{lock}");

    // No login on the target: whether the locator is free cannot be known.
    let o = migrate("hg-anon", "p11kit-anon");
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("without login cannot tell a target locator is free"), "{}", stderr(&o));
}

/// The fixture P-256 key whose certificate is `FIXTURE_CERT`, planted on `soft` under `xf-k`: the
/// private key (extractable), its public key and the certificate. `kry`'s `xf-k` is emptied.
fn plant_fixture_key(soft: &Ref, kry: &Ref) {
    open_session(&kry.module, kry.token_label, "1234").clear(&["xf-k"]);
    let src = open_session(&soft.module, soft.token_label, "1234");
    src.clear(&["xf-k"]);
    let pem =
        std::fs::read_to_string(format!("{}/../cli/tests/fixtures/tpm-import-p256.pem", env!("CARGO_MANIFEST_DIR")))
            .unwrap();
    let der = x509_cert::der::pem::decode_vec(pem.as_bytes()).unwrap().1;
    let cakeys_core::plaintext::PrivateParts::Ec(scalar) =
        cakeys_core::plaintext::private_from_pkcs8(&der, cakeys_core::types::KeyType::Ec, Some("secp256r1")).unwrap()
    else {
        panic!("not an EC key")
    };
    let label = || Attribute::Label(b"xf-k".to_vec());
    src.create_object(&[
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::EcParams(P256_PARAMS.to_vec()),
        Attribute::Value(scalar.to_vec()),
        Attribute::Token(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(true),
        label(),
    ])
    .unwrap();
    let mut public = point_key(FIXTURE_CERT, KeyType::EC, P256_PARAMS);
    public.extend([Attribute::Token(true), Attribute::Verify(true), label()]);
    src.create_object(&public).unwrap();
    let cert = x509_cert::Certificate::from_der(FIXTURE_CERT).unwrap();
    src.create_object(&[
        Attribute::Class(ObjectClass::CERTIFICATE),
        Attribute::CertificateType(CertificateType::X_509),
        Attribute::Subject(cert.tbs_certificate().subject().to_der().unwrap()),
        Attribute::Value(FIXTURE_CERT.to_vec()),
        Attribute::Token(true),
        label(),
    ])
    .unwrap();
    drop(src);
}

const FIXTURE_CERT: &[u8] = include_bytes!("../../cli/tests/fixtures/tpm-import-p256-cert.der");
const P256_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// `import --dry-run` of the key file `p12` on kryoptic checks it against the lock and the
/// token and changes neither; a `--spec` that selects nothing is refused (17).
fn key_file_dry_run(e: &Env, kry: &Ref, p12: &std::path::Path, pass: &std::path::Path) {
    let before = std::fs::read(e.dir.join("keys.lock")).unwrap();
    let dry = |extra: &[&str]| {
        let (file, pass) = (p12.to_str().unwrap(), pass.to_str().unwrap());
        let args = ["import", "--token", "kryoptic", "--in", file, "--passphrase-file", pass];
        e.km(kry, &[&args[..], &["--allow-host-plaintext", "--dry-run"], extra].concat())
    };
    let o = dry(&[]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let said = stdout(&o);
    assert!(said.contains("fk by pkcs12 (file)") && said.contains("its certificate: ready"), "{said}");
    assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), before, "a dry run changed the lock");
    for spec in ["nosuch", "fk-soft"] {
        let o = dry(&["--spec", spec]);
        assert_eq!(code(&o), 17, "--spec {spec}: {}", stderr(&o));
    }
}

/// Key files (docs/CAMIGRATE.md D2 `file`, phase 4b): one private key leaves `SoftHSM` through the host
/// as encrypted PKCS#8 or as PKCS#12 with the certificate the lock pairs with it, mode 0600,
/// unreadable without the passphrase. kryoptic imports the PKCS#12 (key and certificate) after a
/// wrong passphrase was refused (17: bad input, not other material) and a `--dry-run` checked
/// it, both leaving nothing, records it as from a `file`, and verifies both; the PKCS#8 of the
/// same key is then already there. A `--spec` that selects nothing is refused (17).
#[test]
fn key_files_carry_one_key_and_its_certificate() {
    let Some(e) = env("key-files") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let (Some(soft), Some(kry)) = (named("softhsm"), named("kryoptic")) else {
        eprintln!("skipping key-files: needs the softhsm and kryoptic references");
        return;
    };
    plant_fixture_key(soft, kry);
    let key_attrs = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let body = "[objects.fk]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [objects.fc]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\n"
        .to_owned()
        + &Env::spec("fk-soft", "fk", key_attrs, &[soft], "xf-k", "")
        + &Env::spec("fc-soft", "fc", "", &[soft], "xf-k", "")
        + &Env::spec("fk-kry", "fk", key_attrs, &[kry], "xf-k", IMPORT)
        + &Env::spec("fc-kry", "fc", "", &[kry], "xf-k", IMPORT)
        // The key alone on the third token: the lock pairs no certificate with it there.
        + &named("kryoptic-der").map_or_else(String::new, |der| Env::spec("fk-der", "fk", key_attrs, &[der], "xf-k2", IMPORT));
    e.config(&body);
    for spec in ["fk-soft", "fc-soft"] {
        let o = e.cakeys(soft, &["realise", spec, "--token", "softhsm"]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
    }
    let pass = e.dir.join("pass");
    std::fs::write(&pass, "correct horse\n").unwrap();
    let wrong = e.dir.join("wrong");
    std::fs::write(&wrong, "battery staple\n").unwrap();
    let export = |format: &str| {
        let out = e.dir.join(format!("fk.{format}"));
        let o = e.km(
            soft,
            &[
                "export",
                "fk",
                "--token",
                "softhsm",
                "--to-file",
                format,
                "--out",
                out.to_str().unwrap(),
                "--passphrase-file",
                pass.to_str().unwrap(),
                "--allow-host-plaintext",
            ],
        );
        assert_eq!(code(&o), 0, "{format}: {}", stderr(&o));
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&out).unwrap().permissions()) & 0o777,
            0o600,
            "{format}"
        );
        out
    };
    let (p8, p12) = (export("pkcs8"), export("pkcs12"));
    assert!(std::fs::read_to_string(&p8).unwrap().starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
    let import = |file: &std::path::Path, pass: &std::path::Path| {
        e.km(
            kry,
            &[
                "import",
                "--token",
                "kryoptic",
                "--in",
                file.to_str().unwrap(),
                "--passphrase-file",
                pass.to_str().unwrap(),
                "--allow-host-plaintext",
            ],
        )
    };
    let untouched = |what: &str| {
        assert!(open_session(&kry.module, kry.token_label, "1234").labelled("xf-k").is_empty(), "{what} left objects");
    };
    let o = import(&p12, &wrong);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    untouched("a refused file");
    key_file_dry_run(&e, kry, &p12, &pass);
    untouched("a dry run");
    let o = import(&p12, &pass);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    let origin = &lock["realisations"]["fk-kry"]["kryoptic"]["provenance"]["origin"];
    assert_eq!(
        (origin["from"].as_str(), origin["method"].as_str(), origin["exposure"].as_str()),
        (Some("file"), Some("pkcs12"), Some("file"))
    );
    for spec in ["fk-kry", "fc-kry"] {
        assert_eq!(code(&e.cakeys(kry, &["verify", spec, "--token", "kryoptic"])), 0, "{spec}");
    }
    let o = import(&p8, &pass);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("already realised"), "{}", stderr(&o));
    // Where the lock pairs no certificate with the key, the PKCS#12's key is imported and its
    // certificate is not, said in the plan and in the run.
    if let Some(der) = named("kryoptic-der") {
        let (file, pass) = (p12.to_str().unwrap(), pass.to_str().unwrap());
        let args = ["import", "--token", "kryoptic-der", "--in", file, "--passphrase-file", pass];
        let o = e.km(der, &[&args[..], &["--allow-host-plaintext", "--dry-run"]].concat());
        assert!(stderr(&o).contains("the file's certificate would not be imported"), "{}", stderr(&o));
        let o = e.km(der, &[&args[..], &["--allow-host-plaintext"]].concat());
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert!(stderr(&o).contains("the file's certificate is not imported"), "{}", stderr(&o));
        assert_eq!(code(&e.cakeys(der, &["verify", "fk-der", "--token", "kryoptic-der"])), 0);
    }
}
