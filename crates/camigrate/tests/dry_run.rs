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
