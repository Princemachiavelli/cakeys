//! Tests the move matrix across the reference tokens (docs/CAMIGRATE.md D9). The plan follows
//! each side's capabilities, a transport file carries the locked identity, and a real `migrate`
//! does exactly what its `--dry-run` says. Realisations are recorded and checked with `cakeys`
//! (built next to camigrate, `common::sibling`), and plans are made and objects are moved with
//! camigrate. A reference takes part when its suite's variables are set, as in `cakeys`'
//! tests/references.rs. The tests are skipped with fewer than two references.
//!
//! Each test has its own token sets (nextest runs one process and one token set for each test:
//! nix/test-tokens.sh), so no test here clears what another test left. Plain `cargo test` with
//! tokens is not supported (ISSUES.md). A test clears only what it made itself (review
//! `dry_run.rs` F7 found that clearing labels that another test might have left suggested shared
//! tokens).

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use cakeys_core::config::ALLOW_NIX_STORE_KEYS;
use common::state;
use common::xref::{Env, Plant, Ref, env};
use common::*;
use cryptoki::object::{Attribute, CertificateType, KeyType, ObjectClass};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;
use x509_cert::der::{Decode as _, Encode as _};

/// The `extra` arguments of [`Env::spec`]: `CREATE` for a pair that `cakeys create` makes (a
/// source or a transport key), and `IMPORT` for a pair on which a move lands. A pair with neither
/// is adopted.
const CREATE: &str = ", origin = \"create\"";
const IMPORT: &str = ", origin = \"import\"";

/// Checks that the dry-run twin compares every token that a move names (review xref.rs F1).
/// `kryoptic-der` reads kryoptic's token through another configuration, and a move that names it
/// compares that token once. Before the fix, the twin compared no token there, so a dry run that
/// wrote to that target would have passed.
#[test]
fn the_dry_run_twin_compares_every_token_a_move_names() {
    let Some(e) = env("twin-tokens") else { return };
    if e.needs("twin-tokens", ["kryoptic-der"]).is_none() {
        return;
    }
    let names = |args: &[&str]| e.compared(args).iter().map(|r| r.name).collect::<Vec<_>>();
    assert_eq!(names(&["migrate", "x", "--from", "softhsm", "--to", "kryoptic-der"]), ["softhsm", "kryoptic"]);
    assert_eq!(names(&["migrate", "x", "--from", "kryoptic", "--to", "kryoptic-der"]), ["kryoptic"]);
    assert_eq!(names(&["export", "x", "--from", "kryoptic-der", "--to", "softhsm"]), ["softhsm", "kryoptic"]);
}

/// Checks that the plan of `export --dry-run` (docs/CAMIGRATE.md phase 1) follows each side's
/// capabilities. Between the software references, the plan uses the composed sealed method with
/// the strongest OAEP hash that both sides implement. To tpm2-pkcs11, and through p11-kit (whose
/// RPC drops AES key wrap), a key moves only through the host, and only with the flag. To a file,
/// a key moves only with the flag. A key that was made non-extractable never moves. A sealed plan
/// needs a transport key realised on the target (docs/CAMIGRATE.md D3), and without --dry-run,
/// the export writes the bundle.
#[test]
fn export_plans_follow_each_sides_capabilities() {
    let Some(e) = env("export-plan") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let Some([soft, kry]) = e.needs("export-plan", ["softhsm", "kryoptic"]) else { return };
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
        assert_eq!(code(&e.cakeys(r, &["create", "--spec", spec, "--token", r.name])), 22, "{spec}");
    }
    let plan = |r: &Ref, args: &[&str]| -> (i32, serde_json::Value) {
        let mut a = vec!["export"];
        a.extend_from_slice(args);
        a.extend(["--from", r.name, "--dry-run", "--json"]);
        let o = e.km(r, &a);
        (code(&o), serde_json::from_str(&stdout(&o)).unwrap_or_default())
    };
    let first = |v: &serde_json::Value| {
        let p = &v["plans"][0];
        (p["method"].as_str().map(str::to_owned), p["exposure"].as_str().map(str::to_owned), p["ready"].as_bool())
    };
    let some = |s: &str| Some(s.to_owned());

    let (c, v) = plan(soft, &["movable", "--to", "kryoptic"]);
    assert_eq!((c, first(&v)), (15, (some("rsa-oaep-sha1+aes-kwp"), some("sealed"), Some(false))), "{v}");
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("is not realised on 'kryoptic'"), "{v}");
    for r in e.refs.iter().filter(|r| r.name.starts_with("kryoptic")) {
        let o = e.cakeys(r, &["create", "--spec", &format!("tk-{}", r.name), "--token", r.name]);
        assert_eq!(code(&o), 22, "{}", stderr(&o));
    }
    let (c, v) = plan(soft, &["movable", "--to", "kryoptic"]);
    assert_eq!(c, 0, "{v}");
    assert_eq!(first(&v), (some("rsa-oaep-sha1+aes-kwp"), some("sealed"), Some(true)), "{v}");
    assert_eq!(v["capabilities"]["to"], "token");
    if named("kryoptic-der").is_some() {
        let (c, v) = plan(kry, &["movable-k", "--to", "kryoptic-der"]);
        assert_eq!((c, first(&v).0), (0, some("rsa-oaep-sha256+aes-kwp")), "{v}");
    }
    let (c, v) = plan(soft, &["fixed", "--to", "kryoptic"]);
    assert_eq!((c, first(&v).0), (15, None), "{v}");
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("not extractable"), "{v}");
    if named("tpm2").is_some() {
        let (c, v) = plan(soft, &["movable", "--to", "tpm2"]);
        assert_eq!((c, first(&v)), (15, (some("tpm2-ptool"), some("host"), Some(false))), "{v}");
        assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("--allow-host-plaintext"), "{v}");
        // Even with the flag, an export cannot use the host path, because a bundle carries only
        // sealed keys.
        let (c, v) = plan(soft, &["movable", "--to", "tpm2", "--allow-host-plaintext"]);
        assert_eq!((c, first(&v).2), (15, Some(false)), "{v}");
        assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("move it with `camigrate migrate`"), "{v}");
        // The plan's notes say why no sealed method carries the key (review plan.rs F2; this note
        // comes first), and then what the target changes about the key. The test looks the notes
        // up by content, not by position.
        let notes: Vec<&str> =
            v["plans"][0]["notes"].as_array().unwrap().iter().filter_map(serde_json::Value::as_str).collect();
        assert!(notes.iter().any(|n| n.starts_with("not sealed: ")), "{v}");
        assert!(notes.iter().any(|n| n.contains("residence")), "{v}");
    }
    if named("p11kit").is_some() {
        let (c, v) = plan(soft, &["movable", "--to", "p11kit"]);
        assert_eq!((c, first(&v)), (15, (some("host-pkcs8"), some("host"), Some(false))), "{v}");
    }
    let (c, v) = plan(soft, &["movable", "--to-key-file", "pkcs8", "--allow-host-plaintext"]);
    assert_eq!((c, first(&v)), (0, (some("pkcs8-pbes2"), some("file"), Some(true))), "{v}");
    // PKCS#12 carries the key with its certificate, and the lock pairs no certificate with this
    // key. The plan says so, because the export itself would refuse it.
    let (c, v) = plan(soft, &["movable", "--to-key-file", "pkcs12", "--allow-host-plaintext"]);
    assert_eq!((c, first(&v)), (15, (some("pkcs12"), some("file"), Some(false))), "{v}");
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("pairs no certificate"), "{v}");
    // Every object on the source gets one plan. Without names, the export takes what can move, so
    // its plan exits 0 and shows the blocked object, as the export itself does.
    let (c, v) = plan(soft, &["--to", "kryoptic"]);
    assert_eq!((c, v["plans"].as_array().map(Vec::len)), (0, Some(2)), "{v}");
    assert_eq!(v["plans"].as_array().unwrap().iter().filter(|p| p["ready"] == false).count(), 1, "{v}");
    let o = e.km(soft, &["export", "movable", "--from", "softhsm", "--to", "kryoptic"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let bundle: toml::Table = toml::from_str(&stdout(&o)).unwrap();
    assert_eq!(bundle["keys"][0]["method"].as_str(), Some("rsa-oaep-sha1+aes-kwp"));
    assert_eq!(bundle["transport"]["object"].as_str(), Some("tk-kryoptic"));
}

/// Checks that `camigrate transport` (docs/CAMIGRATE.md D3) writes the transport key's public half
/// with its locked identity, that an export planned from that file alone wraps to it, and that an
/// edited file is refused.
#[test]
fn transport_files_carry_the_locked_identity() {
    let Some(e) = env("transport") else { return };
    let Some([soft, kry]) = e.needs("transport", ["softhsm", "kryoptic"]) else { return };
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
    assert_eq!(code(&e.cakeys(kry, &["create", "--spec", "kek", "--token", "kryoptic"])), 22);
    let file = e.dir.join("kryoptic.transport.toml");
    let path = file.to_str().unwrap();
    let o = e.km(kry, &["transport", "--spec", "kek", "--token", "kryoptic", "--out", path]);
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("also decrypts"));
    let t: toml::Table = toml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let lock: toml::Table = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    assert_eq!(t["format"].as_str(), Some("cakeys-transport"));
    assert_eq!(t["provider"].as_str(), Some("kryoptic"));
    assert_eq!(t["rfc7093m4"], lock["objects"]["kek"]["ids"]["rfc7093m4"], "the locked identity");
    // Only an RSA private key can be a transport key.
    assert_eq!(code(&e.cakeys(kry, &["create", "--spec", "ec-k", "--token", "kryoptic"])), 22);
    assert_eq!(code(&e.km(kry, &["transport", "--spec", "ec-k", "--token", "kryoptic"])), 17);
    // A source plans from the file alone, and seals to the transport key that is named for --to,
    // the file's token. keys.toml names no transport key for kryoptic here, so --transport-spec
    // names it.
    assert_eq!(code(&e.cakeys(soft, &["create", "--spec", "movable", "--token", "softhsm"])), 22);
    let export =
        ["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--to-transport-file", path, "--dry-run", "--json"];
    let o = e.km(soft, &export);
    assert_eq!(code(&o), 15, "no transport key named for kryoptic: {}", stdout(&o));
    assert!(stdout(&o).contains("no transport key is named for 'kryoptic'"), "{}", stdout(&o));
    let o = e.km(soft, &[&export[..], &["--transport-spec", "kek"]].concat());
    assert_eq!(code(&o), 0, "{}", String::from_utf8_lossy(&o.stderr));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(v["capabilities"]["to"], "transport file");
    assert_eq!(v["plans"][0]["method"], "rsa-oaep-sha1+aes-kwp");
    // A file edited to name another identity is refused.
    let text = std::fs::read_to_string(&file).unwrap();
    let edited = text.replace(t["rfc7093m4"].as_str().unwrap(), "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    std::fs::write(&file, edited).unwrap();
    let o = e
        .km(soft, &["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--to-transport-file", path, "--dry-run"]);
    assert_eq!(code(&o), 17, "{}", String::from_utf8_lossy(&o.stderr));
}

const CERT_RSA: &[u8] = include_bytes!("../../cli/tests/fixtures/adopt-cert.der");
const CERT_P384: &[u8] = include_bytes!("../../cli/tests/fixtures/adopt-cert-p384.der");
const CERT_ED25519: &[u8] = include_bytes!("../../cli/tests/fixtures/adopt-cert-ed25519.der");

/// One public class of the matrix: its object (and keys.toml type), the attributes that its specs
/// declare (the target's creation template: docs/CAMIGRATE.md D6), the planting template of its
/// material, and whether tpm2-pkcs11 creates it from a value (its profile's public accept rows).
struct Public {
    name: &'static str,
    ty: &'static str,
    attributes: &'static str,
    material: fn() -> Vec<Attribute>,
    tpm2: bool,
}

/// Returns whether two references are on one token through one module (kryoptic and
/// kryoptic-der). Such references cannot both be opened in one process with their own settings,
/// so no move runs between them.
fn same_token(a: &Ref, b: &Ref) -> bool {
    a.module == b.module && a.token_label == b.token_label
}

/// Returns every (item, source, target) of a move matrix: each item on each source that `holds`
/// it, to each target on another token. Before review `dry_run.rs` F3, each matrix had its own
/// copy of this function.
fn matrix<'a, T>(items: &'a [T], refs: &'a [Ref], holds: impl Fn(&Ref, &T) -> bool) -> Vec<(&'a T, &'a Ref, &'a Ref)> {
    items
        .iter()
        .flat_map(|i| refs.iter().map(move |s| (i, s)))
        .filter(|(i, s)| holds(s, i))
        .flat_map(|(i, s)| refs.iter().filter(move |d| !same_token(s, d)).map(move |d| (i, s, d)))
        .collect()
}

/// Returns whether the source `r` makes an extractable key `k`. tpm2-pkcs11 does not, because its
/// keys never leave the TPM. p11-kit does not make Edwards keys, because its RPC drops their
/// generation. kryoptic-der does not, because it reads kryoptic's token.
fn generates(r: &Ref, k: &Key) -> bool {
    matches!(r.plant, Plant::Create) && !(k.name == "k-ed25519" && r.name == "p11kit")
}

/// Returns a certificate's SPKI from its DER (`common::spki` builds one from its parts).
fn cert_spki(cert: &[u8]) -> Vec<u8> {
    x509_cert::Certificate::from_der(cert).unwrap().tbs_certificate().subject_public_key_info().to_der().unwrap()
}

/// Returns a certificate's subject key as the attributes of a public key object: an EC or Edwards
/// point as a DER OCTET STRING, together with the curve's parameters.
fn point_key(cert: &[u8], kt: KeyType, params: &[u8]) -> Vec<Attribute> {
    let spki = cert_spki(cert);
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
            let key = rsa::PublicKey::from_public_key_der(&cert_spki(CERT_RSA)).unwrap();
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
        material: || point_key(CERT_P384, KeyType::EC, P384),
        tpm2: false,
    },
    Public {
        name: "pub-ed25519",
        ty: "class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"",
        attributes: "",
        material: || point_key(CERT_ED25519, KeyType::EC_EDWARDS, ED25519),
        tpm2: false,
    },
];

/// Checks the dry-run property for the `public` rows (docs/CAMIGRATE.md D9, phase 2). For every
/// public class, source reference and target reference, the verdict of `migrate --dry-run` is the
/// outcome. A ready plan moves the object and records it with its `origin`, and `cakeys check`
/// then accepts it on the target, which shows that the lock that camigrate wrote loads and that
/// the identity survived the move. A blocked plan exits 15, with the lock unchanged and the target
/// locator empty.
#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn public_moves_do_what_the_plan_says() {
    let Some(e) = env("public-moves") else { return };
    // A source holds the class when the class was planted there. kryoptic-der reads kryoptic's
    // token.
    let holds = |r: &Ref, c: &Public| c.tpm2 || r.plant != Plant::Ptool;
    let pairs = matrix(&PUBLIC, &e.refs, holds);
    let target_label = |c: &Public, s: &Ref, d: &Ref| format!("cm-{}-{}-{}", c.name, s.name, d.name);
    let target_spec = |c: &Public, s: &Ref, d: &Ref| format!("{}-{}-{}", c.name, s.name, d.name);
    for r in e.refs(|r| r.plant != Plant::Shared) {
        let s = open_session(&r.module, r.token_label, "1234");
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
            let o = e.cakeys(r, &["lock", "--spec", &spec, "--token", r.name]);
            assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
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
            // `export` gets the same verdict. A public object needs no transport key (neither
            // token names one here), so its bundle names none, and a dry-run import accepts it.
            let out = e.dir.join(format!("{spec}.bundle.toml"));
            let out = out.to_str().unwrap();
            let exported = e.km(s, &["export", c.name, "--from", s.name, "--to", d.name, "--out", out]);
            assert_eq!(code(&exported), 0, "{spec}: export: {}", stderr(&exported));
            let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(out).unwrap()).unwrap();
            assert!(bundle.get("transport").is_none() && bundle.get("kek").is_none(), "{spec}: {bundle}");
            let checked = e.km(d, &["import", "--to", d.name, "--in", out, "--spec", &spec, "--dry-run"]);
            assert_eq!(code(&checked), 0, "{spec}: import --dry-run: {}", stderr(&checked));
            assert_eq!(std::fs::read(&lock_path).unwrap(), before, "{spec}: an export or a dry run changed the lock");
        }
        let o = e.km(s, &args);
        let row = format!("{spec}: plan {}, move exit {}", if ready { "ready" } else { "blocked" }, code(&o));
        if ready {
            assert_eq!(code(&o), 22, "{row}: {}", stderr(&o));
            let lock: toml::Value = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
            let origin = &lock["realisations"][spec.as_str()][d.name]["provenance"]["origin"];
            assert_eq!(origin["from"].as_str(), Some(s.name), "{row}");
            assert_eq!((origin["method"].as_str(), origin["exposure"].as_str()), (Some("public"), Some("public")));
            let v = e.cakeys(d, &["check", "--spec", &spec, "--token", d.name]);
            assert_eq!(code(&v), 0, "{row}: cakeys check: {}", stderr(&v));
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

/// Checks that the locator guard decides by class (`Token::occupied`). PKCS#11 puts a key, its
/// public key and its certificate under one label, so they move into one target label in either
/// order. The key's import and the public key object's import share one public key object: the
/// first one creates it, and the other one records it. A second object of a class that is already
/// there is still refused (13), and it leaves nothing behind.
#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn objects_sharing_a_locator_move_in_any_order() {
    let Some(e) = env("shared-locator") else { return };
    let Some([soft, kry]) = e.needs("shared-locator", ["softhsm", "kryoptic"]) else { return };
    let src = open_session(&soft.module, soft.token_label, "1234");
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
    // A second certificate for the first target label is a collision within its class.
    body += &Env::spec("crt2-kry-a", "crt2", "", &[kry], "sl-a", IMPORT);
    names_transport(&e, &body, |r| r.name == "kryoptic");
    assert_eq!(code(&e.cakeys(kry, &["create", "--spec", "tk-kryoptic", "--token", "kryoptic"])), 22);
    // The keys are made, and their public halves and the planted certificates are adopted.
    for (verb, spec) in [
        ("create", "k1-soft"),
        ("lock", "k1-pub-soft"),
        ("lock", "crt1-soft"),
        ("create", "k2-soft"),
        ("lock", "k2-pub-soft"),
        ("lock", "crt2-soft"),
    ] {
        let o = e.cakeys(soft, &[verb, "--spec", spec, "--token", "softhsm"]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    let on_target = |label: &str| open_session(&kry.module, kry.token_label, "1234").labelled(label).len();
    let mv = |object: &str, spec: &str| {
        let o = e.km(soft, &["migrate", object, "--from", "softhsm", "--to", "kryoptic", "--spec", spec]);
        assert_eq!(code(&o), 22, "{object}: {}", stderr(&o));
        let v = e.cakeys(kry, &["check", "--spec", spec, "--token", "kryoptic"]);
        assert_eq!(code(&v), 0, "{spec}: {}", stderr(&v));
    };
    // A --spec that selects nothing (an unknown spec, or the pair of another object) is refused
    // (17) by the dry run as by the run, and the run exits as its dry run did (D9; review
    // 2026-11-23 C-2 found that the dry run reported ready). Nothing moves.
    for spec in ["nope", "k2-kry"] {
        let named = ["migrate", "k1", "--from", "softhsm", "--to", "kryoptic", "--spec", spec];
        for extra in [&["--dry-run"][..], &[]] {
            let o = e.km(soft, &[&named[..], extra].concat());
            assert_eq!(code(&o), 17, "{spec} {extra:?}: {}", stderr(&o));
            assert!(stderr(&o).contains(&format!("--spec '{spec}'")), "{spec} {extra:?}: {}", stderr(&o));
        }
    }
    assert_eq!(on_target("sl-a"), 0, "a refused --spec moved something");
    // Move the key first. Its import creates the public half, and the move of the public key
    // object then finds that public half and records it as the object.
    mv("k1", "k1-kry");
    mv("k1-pub", "k1-pub-kry");
    mv("crt1", "crt1-kry");
    assert_eq!(on_target("sl-a"), 3, "a key, one public key object and a certificate");
    // Move in the other order: the certificate and the public key object first, and then the key,
    // which reuses the public key object.
    mv("crt2", "crt2-kry");
    mv("k2-pub", "k2-pub-kry");
    mv("k2", "k2-kry");
    assert_eq!(on_target("sl-b"), 3, "a key, one public key object and a certificate");
    // A second certificate under 'sl-a' collides with the first one, so it is refused (13), and
    // nothing is left behind.
    let o = e.km(soft, &["migrate", "crt2", "--from", "softhsm", "--to", "kryoptic", "--spec", "crt2-kry-a"]);
    assert_eq!(code(&o), 13, "{}", stderr(&o));
    assert_eq!(on_target("sl-a"), 3, "the refused certificate left an object");
}

/// Checks that no move plans for a private data object (15), whatever flags are given. Such an
/// object (`CKA_PRIVATE = true`, which `cakeys` identifies once its spec declares it) holds a
/// secret value. The public method would write the value into a bundle and recreate the object
/// under the target's default `CKA_PRIVATE`. An export without names leaves the object out with a
/// warning. Nothing reaches the target.
#[test]
fn private_data_objects_never_move() {
    let Some(e) = env("private-data") else { return };
    let Some([soft, kry]) = e.needs("private-data", ["softhsm", "kryoptic"]) else { return };
    let on_target = || open_session(&kry.module, kry.token_label, "1234").labelled("pd-secret").len();
    let src = open_session(&soft.module, soft.token_label, "1234");
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
    let o = e.cakeys(soft, &["lock", "--spec", "pd-soft", "--token", "softhsm"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let mv = ["migrate", "pd", "--from", "softhsm", "--to", "kryoptic", "--spec", "pd-kry"];
    let o = e.km(soft, &[&mv[..], &["--dry-run", "--json"]].concat());
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("private data object"), "{v}");
    let o = e.km(soft, &[&mv[..], &["--allow-host-plaintext"]].concat());
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert_eq!(on_target(), 0);
    // Without names, an export takes what can move. Here nothing can move, and the export reports
    // the private object.
    let o = e.km(soft, &["export", "--from", "softhsm", "--to", "kryoptic"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("pd: left out of the bundle"), "{}", stderr(&o));
}

/// Checks that a dry run reads each object on the source as its run does, once the verdict lets
/// the plans proceed (review 2026-11-24 L4b-3 found that the dry runs planned from the lock
/// alone). It also checks that a run that the verdict refuses prints a row for each object
/// (L4b-1). A public data object with a second object under its label is refused with 12 by the
/// dry run and by the run. When it is named together with a private data object, for which no
/// move plans (15), the verdict refuses first: the dry run exits 15, as the run does, and not with
/// the 12 of the search. The run's rows say that the private object failed with 15 and that the
/// public object was ready and did not move. [`Env::km`] runs each dry run before its run and
/// requires the run to exit as the dry run did.
#[test]
fn the_dry_run_searches_the_source_once_the_verdict_lets_the_plans_go() {
    let Some(e) = env("source-search") else { return };
    let Some([soft, kry]) = e.needs("source-search", ["softhsm", "kryoptic"]) else { return };
    let plant = |label: &str, private: bool, value: &[u8]| {
        open_session(&soft.module, soft.token_label, "1234")
            .create_object(&[
                Attribute::Class(ObjectClass::DATA),
                Attribute::Token(true),
                Attribute::Private(private),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Value(value.to_vec()),
            ])
            .unwrap();
    };
    plant("ss-secret", true, b"an application secret");
    plant("ss-note", false, b"a public note");
    let (private, public) = ("attributes = { CKA_PRIVATE = true }\n", "attributes = { CKA_PRIVATE = false }\n");
    e.config(
        &("[objects.secret]\nclass = \"CKO_DATA\"\n\n[objects.note]\nclass = \"CKO_DATA\"\n\n".to_owned()
            + &Env::spec("secret-soft", "secret", private, &[soft], "ss-secret", "")
            + &Env::spec("secret-kry", "secret", private, &[kry], "ss-secret", IMPORT)
            + &Env::spec("note-soft", "note", public, &[soft], "ss-note", "")
            + &Env::spec("note-kry", "note", public, &[kry], "ss-note", IMPORT)),
    );
    for spec in ["secret-soft", "note-soft"] {
        let o = e.cakeys(soft, &["lock", "--spec", spec, "--token", "softhsm"]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    // Plant a second data object under the note's label, after the lock recorded the first one.
    plant("ss-note", false, b"another note");
    let migrate = |objects: &[&str]| {
        let mut args = vec!["migrate"];
        args.extend_from_slice(objects);
        args.extend(["--from", "softhsm", "--to", "kryoptic", "--allow-host-plaintext"]);
        e.km(soft, &args)
    };
    let o = migrate(&["note"]);
    assert_eq!(code(&o), 12, "{}", stderr(&o));
    let o = migrate(&["secret", "note"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    let mut rows: Vec<(String, String, u8)> =
        state::rows(&o).into_iter().map(|r| (r.object, r.outcome, r.exit)).collect();
    rows.sort();
    assert_eq!(rows, [("note".into(), "ready".into(), 0), ("secret".into(), "failed".into(), 15)], "{}", stderr(&o));
    assert_eq!(open_session(&kry.module, kry.token_label, "1234").labelled("ss-note").len(), 0);
}

/// Checks that a run whose lock cannot be saved after an object moved (21: the object is on its
/// token, and the lock does not record it) still prints its rows (review 2026-11-24 D-9 found that
/// the run returned before printing any row). The unrecorded object's row has 21 and its rule, and
/// the run moves nothing after that object, so the next object has no row. The save is made to
/// fail by a limit on the size of a written file (`RLIMIT_FSIZE`, with its signal ignored), set to
/// the lock's current size. The token's own files are smaller than that limit.
#[test]
#[expect(unsafe_code, reason = "pre_exec: the limit is set in the child, between fork and exec")]
fn a_lock_that_cannot_be_saved_mid_run_keeps_the_rows() {
    use std::os::unix::process::CommandExt as _;
    let Some(e) = env("lock-mid-run") else { return };
    let Some([soft, kry]) = e.needs("lock-mid-run", ["softhsm", "kryoptic"]) else { return };
    let src = open_session(&kry.module, kry.token_label, "1234");
    let mut body = String::new();
    for o in ["d1", "d2"] {
        src.create_object(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Label(format!("lm-{o}").into_bytes()),
            Attribute::Value(o.as_bytes().to_vec()),
        ])
        .unwrap();
        let public = "attributes = { CKA_PRIVATE = false }\n";
        body += &(format!("[objects.{o}]\nclass = \"CKO_DATA\"\n\n")
            + &Env::spec(&format!("{o}-kry"), o, public, &[kry], &format!("lm-{o}"), "")
            + &Env::spec(&format!("{o}-soft"), o, public, &[soft], &format!("lm-{o}"), IMPORT));
    }
    drop(src);
    e.config(&body);
    for spec in ["d1-kry", "d2-kry"] {
        assert_eq!(code(&e.cakeys(kry, &["lock", "--spec", spec, "--token", "kryoptic"])), 22, "{spec}");
    }
    let lock = e.dir.join("keys.lock");
    let limit = std::fs::metadata(&lock).unwrap().len();
    let mut run = Run::new(BIN, &e.dir.join("keys.toml"))
        .envs(kry.env.iter().copied())
        .command(&["migrate", "d1", "d2", "--from", "kryoptic", "--to", "softhsm"]);
    // SAFETY: The closure runs between fork and exec, and it makes only async-signal-safe calls
    // (signal and setrlimit).
    unsafe {
        run.pre_exec(move || {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            let l = libc::rlimit { rlim_cur: limit, rlim_max: limit };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &raw const l) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let o = run.output().unwrap();
    assert_eq!(code(&o), 21, "{}", stderr(&o));
    let rows = state::rows(&o);
    let row = |object: &str| rows.iter().find(|r| r.object == object);
    let d1 = row("d1").unwrap_or_else(|| panic!("no row for d1: {rows:?}"));
    assert_eq!((d1.exit, d1.rule.as_deref()), (21, Some("lock-writable")), "{d1:?}");
    assert!(row("d2").is_none(), "moved after the lock could not be saved: {rows:?}");
    let on_soft = |l: &str| open_session(&soft.module, soft.token_label, "1234").labelled(l).len();
    assert_eq!((on_soft("lm-d1"), on_soft("lm-d2")), (1, 0));
}

/// Checks that a move into a token for which keys.toml gives no user PIN is refused before any
/// plan, in a dry run and in a real run, and that nothing is written. The refusal is 16, by the
/// rule `needs-login`, because a session without a login cannot tell whether its locator is free.
#[test]
fn a_target_without_a_pin_is_refused_before_any_plan() {
    let Some(e) = env("needs-login") else { return };
    let Some([soft, kry]) = e.needs("needs-login", ["softhsm", "kryoptic"]) else { return };
    let public = "attributes = { CKA_PRIVATE = false }\n";
    e.config(
        &("[objects.nl]\nclass = \"CKO_DATA\"\n\n".to_owned()
            + &Env::spec("nl-soft", "nl", public, &[soft], "nl", "")
            + &Env::spec("nl-kry", "nl", public, &[kry], "nl", IMPORT)),
    );
    let path = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&path).unwrap();
    let (head, tail) = text.split_once("[tokens.kryoptic]").unwrap();
    let (section, rest) = tail.split_once("\n\n").unwrap();
    let section: Vec<&str> = section.lines().filter(|l| !l.starts_with("pinFile")).collect();
    std::fs::write(&path, format!("{head}[tokens.kryoptic]{}\n\n{rest}", section.join("\n"))).unwrap();
    let lock = e.dir.join("keys.lock");
    let before = state::snapshot(&[&lock], &[kry.view()]);
    for dry in [&["--dry-run"][..], &[]] {
        let o = e.km_alone(soft, &[&["migrate", "nl", "--from", "softhsm", "--to", "kryoptic"][..], dry].concat());
        assert_eq!(code(&o), 16, "{dry:?}: {}", stderr(&o));
        state::assert_unchanged(&before, &state::snapshot(&[&lock], &[kry.view()]), &format!("{dry:?}"));
    }
}

/// Checks that a key file's refusal is reported in its row, as a bundle entry's refusal is (review
/// 2026-11-24 D-9 found that `import --in` of a key file returned every refusal before printing a
/// row). In a dry run and in a real run, the run's exit code and the row's exit code are the
/// refusal's code, and the row names the rule.
#[test]
fn a_key_file_refusal_is_its_row() {
    let Some(e) = env("key-file-rows") else { return };
    let Some([soft, kry]) = e.needs("key-file-rows", ["softhsm", "kryoptic"]) else { return };
    bundle_keys(&e, soft, kry);
    let (out, pass) = (e.dir.join("ek1.pem"), e.dir.join("pass"));
    std::fs::write(&pass, "correct horse\n").unwrap();
    let (out, pass) = (out.to_str().unwrap(), pass.to_str().unwrap());
    let flags = ["--passphrase-file", pass, "--allow-host-plaintext"];
    let export = ["export", "ek1", "--from", "softhsm", "--to-key-file", "pkcs8", "--out", out];
    assert_eq!(code(&e.km(soft, &[&export[..], &flags].concat())), 0);
    // ek1 is born on softhsm, so none of its pairs there accepts an import.
    for dry in [&[][..], &["--dry-run"]] {
        let o = e.km_alone(soft, &[&["import", "--to", "softhsm", "--in", out][..], &flags, dry].concat());
        let rows = state::rows(&o);
        assert_eq!(rows.len(), 1, "{dry:?}: {}", stderr(&o));
        assert_eq!((code(&o), i32::from(rows[0].exit)), (17, 17), "{dry:?}: {rows:?}");
        assert_eq!(rows[0].object, "ek1", "{rows:?}");
    }
}

/// Returns the transport key of the reference `r` (docs/CAMIGRATE.md D3) as keys.toml text: an
/// RSA key that only unwraps and never leaves the token, and that proves possession by unwrapping
/// (`pop-unwrap`). Its token names it with [`names_transport`].
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

/// Writes keys.toml with `body`. Each reference that `holds` selects names its [`transport_key`]
/// (`transportWith`).
fn names_transport(e: &Env, body: &str, holds: impl Fn(&Ref) -> bool) {
    e.config_with(body, &|r| {
        if holds(r) { format!("migrate = {{ transportWith = \"tk-{}\" }}\n", r.name) } else { String::new() }
    });
}

/// One key class of the sealed matrix: its keys.toml type and the attributes that its specs
/// declare. The key is extractable, because otherwise it could never move (docs/CAMIGRATE.md D1).
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

/// Checks the dry-run property for the sealed rows (docs/CAMIGRATE.md D9, phase 3). For every key
/// class, source reference and target reference, the verdict of `migrate --dry-run` is the
/// outcome. Each key is generated on its source (`origin = "create"`, and `import` on its
/// targets), and each target holds a transport key. A ready move exits 0 and records its `origin`,
/// and `cakeys check` then accepts the key on the target. That check proves possession, so the
/// unwrapped key is the locked one. A blocked move exits 15, with the lock unchanged and nothing on
/// the target.
#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn sealed_moves_do_what_the_plan_says() {
    let Some(e) = env("sealed-moves") else { return };
    let pairs = matrix(&KEYS, &e.refs, generates);
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
    // p11-kit hides the module behind it, so its capabilities are those of a spec-compliant
    // module until keys.toml names that module's provider (docs/ARCHITECTURE.md, "Providers").
    // This p11-kit forwards `SoftHSM`, whose unwrapped secret keys lose their length
    // (`move.secret-unwrap` is no).
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    let provider = |p: &str| {
        let named = if p.is_empty() { String::new() } else { format!("provider = \"{p}\"\n") };
        std::fs::write(&config, text.replace("[tokens.p11kit]\n", &format!("[tokens.p11kit]\n{named}"))).unwrap();
    };
    provider("softhsm");
    for d in e.refs.iter().filter(|d| unwraps(d)) {
        let o = e.cakeys(d, &["create", "--spec", &format!("tk-{}", d.name), "--token", d.name]);
        assert_eq!(code(&o), 22, "transport key on {}: {}", d.name, stderr(&o));
    }
    for k in &KEYS {
        for s in e.refs.iter().filter(|s| generates(s, k)) {
            let spec = format!("{}-src", object(k, s));
            let o = e.cakeys(s, &["create", "--spec", &spec, "--token", s.name]);
            assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
        }
    }
    // When the module behind p11-kit is not named, it is planned as spec-compliant, with a
    // warning. When it is named, its own claims decide: `SoftHSM`'s claims block a secret key, and
    // kryoptic's claims do not.
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
            assert_eq!(code(&out), 22, "{row}: {}", stderr(&out));
            let lock: toml::Value = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
            let origin = &lock["realisations"][spec.as_str()][d.name]["provenance"]["origin"];
            assert_eq!(origin["from"].as_str(), Some(s.name), "{row}");
            assert_eq!(origin["method"].as_str(), Some(method.as_str()), "{row}");
            let v = e.cakeys(d, &["check", "--spec", &spec, "--token", d.name]);
            assert_eq!(code(&v), 0, "{row}: cakeys check: {}", stderr(&v));
            // An unwrapped private key's public half is made in the same way as a generated key's
            // public half: it verifies and is public, whatever the token's own default for an
            // object is.
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

/// Checks that a bundle can cross untrusted channels (docs/CAMIGRATE.md D5, D6). `export --out`
/// writes it, and `import --in` reads it and checks it against the lock before the target is
/// touched: another key's IDs are refused with 17 or 10. The import also checks it afterward:
/// tampered bytes do not unwrap (13, or 16 where the module says only that it failed:
/// [`tampered_unwrap`]), and the blobs of another key unwrap into material that is not the locked
/// key (a private key fails its proof of possession, 13, and a secret key fails its commitment,
/// 10). Neither case leaves anything on the target. A transport file for a key that the lock does
/// not pin is refused as a channel.
#[test]
fn bundles_are_checked_against_the_lock() {
    let Some(e) = env("bundles") else { return };
    let Some([soft, kry]) = e.needs("bundles", ["softhsm", "kryoptic"]) else { return };
    bundle_keys(&e, soft, kry);
    let export = |objects: &[&str]| export_bundle(&e, soft, objects);
    let (ek1, ek2) = (export(&["ek1"]), export(&["ek2"]));
    let text = std::fs::read_to_string(&ek1).unwrap();
    let lock_path = e.dir.join("keys.lock");
    let import = |path: &std::path::Path| e.km(kry, &["import", "--to", "kryoptic", "--in", path.to_str().unwrap()]);
    let empty = |label: &str| open_session(&kry.module, kry.token_label, "1234").labelled(label).is_empty();
    let refused = |text: String, want: i32, what: &str| {
        let path = e.dir.join("altered.bundle.toml");
        std::fs::write(&path, text).unwrap();
        let before = std::fs::read(&lock_path).unwrap();
        let o = import(&path);
        assert_eq!(code(&o), want, "{what}: {}", stderr(&o));
        assert!(empty("xb-ek1"), "{what}: left objects on the target");
        assert_eq!(std::fs::read(&lock_path).unwrap(), before, "{what}: changed the lock");
        stderr(&o)
    };
    let b: toml::Value = toml::from_str(&text).unwrap();
    let key_blob = b["keys"][0]["wrapped"].as_str().unwrap();
    // With only another key's IDs, the form check refuses them, because the public key no longer
    // matches them (17).
    let ids = b["keys"][0]["ids"]["rfc7093m4"].as_str().unwrap();
    let other: toml::Value = toml::from_str(&std::fs::read_to_string(&ek2).unwrap()).unwrap();
    let other_ids = other["keys"][0]["ids"]["rfc7093m4"].as_str().unwrap();
    refused(text.replace(ids, other_ids), 17, "the IDs of another key");
    // With the other key's public key too, the entry is consistent, but it is not what the lock
    // pins for 'ek1' (10). It is refused before the target is touched.
    let public = b["keys"][0]["publicKey"].as_str().unwrap();
    let relabelled = text.replace(ids, other_ids).replace(public, other["keys"][0]["publicKey"].as_str().unwrap());
    refused(relabelled, 10, "another key's IDs and public key");
    // A bundle sealed to another transport key than the one realised here (10), and a bundle
    // whose key is another type than the lock's (14), are each refused before the target is
    // touched.
    let sealed_to = b["transport"]["rfc7093m4"].as_str().unwrap();
    refused(text.replace(sealed_to, ids), 10, "another transport key");
    refused(text.replace("curve = \"secp256r1\"", "curve = \"secp384r1\""), 14, "another type");
    another_type_in_one_place(&e, kry, &text);
    // Against a lock that pins nothing, a wrapped key's transport key has no realisation, and a
    // certificate's import has nothing to be checked against (14 in both cases).
    let bare = e.dir.join("bare.lock");
    std::fs::write(&bare, "version = 1\n").unwrap();
    for (path, why) in [(&ek1, "is not realised on 'kryoptic'"), (&export(&["crt"]), "the lock pins no IDs")] {
        let args = ["--lock", bare.to_str().unwrap(), "import", "--to", "kryoptic", "--in", path.to_str().unwrap()];
        let o = e.km(kry, &args);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains(why), "{}", stderr(&o));
    }
    // RFC 5649's integrity check refuses a flipped byte in the wrapped key, and the run reports it
    // as precisely as the module's return value allows (review sealed.rs F2).
    let (want, said) = tampered_unwrap(kry);
    let o = refused(text.replace(key_blob, &base64_flip(key_blob)), want, "a tampered blob");
    assert!(said.iter().all(|s| o.contains(s)), "a tampered blob: expected {said:?} in {o}");
    // The other key's blobs (its KEK and its key), wrapped to the same transport key, are
    // unwrapped, then refused by identity and removed again.
    let swap = |into: &toml::Value, from: &toml::Value| {
        let mut swapped = into.clone();
        swapped["kek"] = from["kek"].clone();
        swapped["keys"][0]["wrapped"] = from["keys"][0]["wrapped"].clone();
        toml::to_string(&swapped).unwrap()
    };
    // A private key's identity is its public key, which the bundle carries, so the other key's
    // private half fails the proof of possession (13).
    refused(swap(&b, &other), 13, "another private key's blobs");
    // A secret key's identity is its commitment, which is computed from the unwrapped key, so the
    // import is refused with 10.
    let (sk1, sk2) = (export(&["sk1"]), export(&["sk2"]));
    let read = |p: &std::path::Path| -> toml::Value { toml::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() };
    let path = e.dir.join("swapped-secret.bundle.toml");
    std::fs::write(&path, swap(&read(&sk1), &read(&sk2))).unwrap();
    let o = import(&path);
    assert_eq!(code(&o), 10, "another secret key's blobs: {}", stderr(&o));
    assert!(empty("xb-sk1"), "left behind");
    // For a transport file of a key that the lock does not pin, the plan refuses to wrap to it.
    let rogue = e.dir.join("rogue.transport.toml");
    let file =
        e.km(kry, &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--out", rogue.to_str().unwrap()]);
    assert_eq!(code(&file), 0, "{}", stderr(&file));
    let t = std::fs::read_to_string(&rogue).unwrap().replace("object = \"tk-kryoptic\"", "object = \"ek2\"");
    std::fs::write(&rogue, t).unwrap();
    let o = e.km(
        soft,
        &[
            "export",
            "ek2",
            "--from",
            "softhsm",
            "--to",
            "kryoptic",
            "--to-transport-file",
            rogue.to_str().unwrap(),
            "--dry-run",
        ],
    );
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("is not the"), "{}", stdout(&o));
}

/// Returns the exit code and the message of an import into `r` for a tampered RFC 5649 blob. The
/// exit code is 13 with "tampered with" where the module says that the wrapped data is invalid. It
/// is 16 where the module says only that it failed, and the message then says that the bundle may
/// be damaged; kryoptic returns `CKR_DEVICE_ERROR` \[run\].
fn tampered_unwrap(r: &Ref) -> (i32, &'static [&'static str]) {
    if r.name.starts_with("kryoptic") {
        (16, &["CKR_DEVICE_ERROR", "damaged or altered bundle"])
    } else {
        (13, &["the bundle was tampered with"])
    }
}

/// Checks the bundle's key type against the lock and against keys.toml separately. A bundle of
/// `ek1` as a P-384 key is refused (14) when the lock agrees with it and keys.toml does not, and
/// also when keys.toml agrees and the lock does not.
fn another_type_in_one_place(e: &Env, kry: &Ref, bundle: &str) {
    let (was, now) = ("curve = \"secp256r1\"", "curve = \"secp384r1\"");
    let path = e.dir.join("p384.bundle.toml");
    std::fs::write(&path, bundle.replace(was, now)).unwrap();
    let import = |lock: &std::path::Path| {
        let args = ["--lock", lock.to_str().unwrap(), "import", "--to", "kryoptic", "--in", path.to_str().unwrap()];
        let o = e.km(kry, &args);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains("the bundle carries a"), "{}", stderr(&o));
        let left = open_session(&kry.module, kry.token_label, "1234").labelled("xb-ek1");
        assert_eq!(left.len(), 0, "a refused import left objects");
    };
    // The lock also says P-384, and keys.toml still says P-256.
    let mut lock: toml::Table = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    lock["objects"]["ek1"]["type"]["curve"] = toml::Value::String("secp384r1".into());
    let retyped = e.dir.join("p384.lock");
    std::fs::write(&retyped, toml::to_string(&lock).unwrap()).unwrap();
    import(&retyped);
    // keys.toml also says P-384, and the lock still says P-256.
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    let at = text.find("[objects.ek1]").unwrap();
    std::fs::write(&config, format!("{}{}", &text[..at], text[at..].replacen(was, now, 1))).unwrap();
    import(&e.dir.join("keys.lock"));
    std::fs::write(&config, text).unwrap();
}

/// Sets up the keys that the bundle tests move: the P-256 keys `ek1` and `ek2` and the AES keys
/// `sk1` and `sk2`, each born on `SoftHSM` (`origin = "create"`) with an `import` spec on kryoptic,
/// whose transport key is realised. It also sets up `nx`, a P-256 key made non-extractable on
/// `SoftHSM`, which cannot move, and `nox`, an extractable key that its spec keeps there
/// (`noExport`).
fn bundle_keys(e: &Env, soft: &Ref, kry: &Ref) {
    // Plant a certificate on SoftHSM. It is a public object, so it travels in a bundle as it is.
    let src = open_session(&soft.module, soft.token_label, "1234");
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
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\nmigrate = { noExport = true }\n",
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
    assert_eq!(code(&e.cakeys(kry, &["create", "--spec", "tk-kryoptic", "--token", "kryoptic"])), 22);
    for spec in ["ek1-soft", "ek2-soft", "sk1-soft", "sk2-soft", "nx-soft", "nox-soft"] {
        assert_eq!(code(&e.cakeys(soft, &["create", "--spec", spec, "--token", "softhsm"])), 22, "{spec}");
    }
    // The planted certificate is adopted.
    assert_eq!(code(&e.cakeys(soft, &["lock", "--spec", "crt-soft", "--token", "softhsm"])), 22);
}

/// Checks that `--transport-spec` names the transport key and `--lock` names the lock file, in the
/// same way as `transportWith` and the default path do. A plan with either flag is the same as the
/// plan without it. A plan that names a spec that is not a transport key there, or a new lock that
/// records nothing, is blocked. A lock file that does not exist is refused (17), because only
/// `--new-lock` reads a missing lock as empty.
fn named_transport_key_and_lock(e: &Env, soft: &Ref) {
    let plan = ["export", "ek1", "--from", "softhsm", "--to", "kryoptic", "--dry-run"];
    let with = |extra: &[&str]| code(&e.km(soft, &[&plan[..], extra].concat()));
    assert_eq!(with(&["--transport-spec", "tk-kryoptic"]), 0);
    assert_eq!(with(&["--transport-spec", "ek1-kry"]), 15);
    // `migrate` names its transport key in the same way (review 2026-11-23 D-23 found that no test
    // ran it).
    let mv = ["migrate", "ek1", "--from", "softhsm", "--to", "kryoptic", "--spec", "ek1-kry", "--dry-run"];
    let moved = |extra: &[&str]| code(&e.km(soft, &[&mv[..], extra].concat()));
    assert_eq!(moved(&["--transport-spec", "tk-kryoptic"]), 0);
    assert_eq!(moved(&["--transport-spec", "ek1-kry"]), 15);
    let copy = e.dir.join("copy.lock");
    std::fs::copy(e.dir.join("keys.lock"), &copy).unwrap();
    let locked = |lock: &std::path::Path| code(&e.km(soft, &[&["--lock", lock.to_str().unwrap()], &plan[..]].concat()));
    assert_eq!(locked(&copy), 0);
    let absent = e.dir.join("absent.lock");
    assert_eq!(locked(&absent), 17);
    let new = [&["--new-lock", "--lock", absent.to_str().unwrap()], &plan[..]].concat();
    assert_eq!(code(&e.km(soft, &new)), 14);
    assert!(!absent.exists(), "a dry run created the lock");
}

/// Checks the import of a bundle file's EC key under `binding = "token-asserted"` (sealed.rs F1).
/// The transport key is public, so anyone can seal a key of their own next to the lock's IDs and
/// `publicKey`, and on a target that keeps no point with the unwrapped key, only a proof ties the
/// two together. `import --in` refuses the key (14) before the target is touched, in a dry run or
/// a real run, and records nothing. The same kind of key under `pop-sign` imports. `migrate`, whose
/// bundle never leaves the process, still moves the asserted key.
#[test]
fn a_bundle_files_unproven_ec_key_is_refused() {
    let Some(e) = env("carried") else { return };
    let Some([soft, kry]) = e.needs("carried", ["softhsm", "kryoptic"]) else { return };
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let attributes = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let key = |o: &str, binding: &str| {
        format!("[objects.{o}]\n{ec}\n\n")
            + &Env::spec(&format!("{o}-soft"), o, attributes, &[soft], &format!("xc-{o}"), CREATE)
            + &Env::spec(&format!("{o}-kry"), o, attributes, &[kry], &format!("xc-{o}"), &format!("{IMPORT}{binding}"))
    };
    let body = transport_key(kry) + &key("ta", ", binding = \"token-asserted\"") + &key("tp", "");
    names_transport(&e, &body, |r| r.name == "kryoptic");
    assert_eq!(code(&e.cakeys(kry, &["create", "--spec", "tk-kryoptic", "--token", "kryoptic"])), 22);
    for spec in ["ta-soft", "tp-soft"] {
        assert_eq!(code(&e.cakeys(soft, &["create", "--spec", spec, "--token", "softhsm"])), 22, "{spec}");
    }
    let lock =
        || -> toml::Value { toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap() };
    let empty = |label: &str| open_session(&kry.module, kry.token_label, "1234").labelled(label).is_empty();
    let bundle = export_bundle(&e, soft, &["ta"]);
    for dry_run in [&["--dry-run"][..], &[]] {
        let o = e.km(kry, &[&["import", "--to", "kryoptic", "--in", bundle.to_str().unwrap()], dry_run].concat());
        assert_eq!(code(&o), 14, "{dry_run:?}: {}", stderr(&o));
        assert!(stderr(&o).contains("token-asserted\" proves nothing"), "{}", stderr(&o));
        assert!(empty("xc-ta"), "{dry_run:?}: the refused import touched the target");
    }
    assert!(lock()["realisations"].get("ta-kry").is_none(), "{}", lock());
    // With a proof, the same kind of key imports from a file.
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", export_bundle(&e, soft, &["tp"]).to_str().unwrap()]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    // Within one process, only the locked source can have made the bundle.
    let o = e.km(soft, &["migrate", "ta", "--from", "softhsm", "--to", "kryoptic", "--spec", "ta-kry"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["check", "--spec", "ta-kry", "--token", "kryoptic"])), 0);
}

/// Exports `objects` from `SoftHSM` to kryoptic into a bundle file, and returns the file's path.
fn export_bundle(e: &Env, soft: &Ref, objects: &[&str]) -> std::path::PathBuf {
    let path = e.dir.join(format!("{}.bundle.toml", objects.join("+")));
    let out = path.to_str().unwrap().to_owned();
    let args = [&["export"], objects, &["--from", "softhsm", "--to", "kryoptic", "--out", &out]].concat();
    let r = e.km(soft, &args);
    assert_eq!(code(&r), 0, "export {objects:?}: {}", stderr(&r));
    path
}

/// Checks that each export writes one bundle (docs/CAMIGRATE.md D5) with every key and one shared
/// KEK. Each key imports on its own: a key that fails leaves nothing, while the other keys are
/// imported and recorded. Because the run wrote the lock, it exits 22, and the failed key's row
/// shows the failure's code (review 2026-11-24 L5). Named objects export all or nothing: when one
/// of them cannot move, no bundle is written. Without names, the objects that cannot move are left
/// out with a warning.
#[test]
fn bundles_carry_every_key_of_an_export() {
    let Some(e) = env("multi-bundles") else { return };
    let Some([soft, kry]) = e.needs("multi-bundles", ["softhsm", "kryoptic"]) else { return };
    bundle_keys(&e, soft, kry);
    let export = |objects: &[&str]| export_bundle(&e, soft, objects);
    let lock_path = e.dir.join("keys.lock");
    named_transport_key_and_lock(&e, soft);
    let import = |path: &std::path::Path| e.km(kry, &["import", "--to", "kryoptic", "--in", path.to_str().unwrap()]);
    let empty = |label: &str| open_session(&kry.module, kry.token_label, "1234").labelled(label).is_empty();
    let read = |p: &std::path::Path| -> toml::Value { toml::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() };
    // One export writes one bundle with two keys and one shared KEK. A dry run checks both keys
    // and imports nothing.
    let both = export(&["ek1", "sk1"]);
    let b = read(&both);
    assert_eq!(b["keys"].as_array().map(Vec::len), Some(2), "{b}");
    assert!(b.get("kek").is_some(), "{b}");
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", both.to_str().unwrap(), "--dry-run"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(empty("xb-ek1") && empty("xb-sk1"), "the dry run imported");
    // Each key is imported on its own. With the commitment label of sk1 altered, ek1 still
    // imports and is recorded, sk1 fails with 10 and leaves nothing, and the run exits 22
    // because it wrote the lock for ek1. The row of sk1 shows its exit code 10.
    let mut altered = b.clone();
    altered["keys"][1]["commitmentLabel"] = toml::Value::String("another label".into());
    let path = e.dir.join("partial.bundle.toml");
    std::fs::write(&path, toml::to_string(&altered).unwrap()).unwrap();
    let o = import(&path);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let exits: Vec<_> = state::rows(&o).iter().map(|r| (r.object.clone(), r.exit)).collect();
    assert_eq!(exits, [("ek1".to_owned(), 0), ("sk1".to_owned(), 10)], "{}", stderr(&o));
    assert!(empty("xb-sk1"), "the failed key left objects");
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
    assert!(lock["realisations"]["ek1-kry"].get("kryoptic").is_some(), "the good key was not recorded");
    assert!(lock["realisations"].get("sk1-kry").is_none(), "the failed key was recorded");
    assert_eq!(code(&e.cakeys(kry, &["check", "--spec", "ek1-kry", "--token", "kryoptic"])), 0);
    // Its public half is made in the same way as a generated key's public half: it verifies and is
    // public, although the spec does not declare it.
    assert_eq!(public_half(kry, "xb-ek1"), (true, false));
    // Import the whole bundle again: ek1 is already there and verifies, and sk1 imports.
    let o = import(&both);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["check", "--spec", "sk1-kry", "--token", "kryoptic"])), 0);
    // Without names, the export takes every key that can move. The non-extractable key is left
    // out with a warning.
    let out = e.dir.join("all.bundle.toml");
    let r = e.km(soft, &["export", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()]);
    assert_eq!(code(&r), 0, "{}", stderr(&r));
    assert!(stderr(&r).contains("nx: left out of the bundle: not extractable"), "{}", stderr(&r));
    assert!(!stderr(&r).contains("nox"), "noExport is left out quietly: {}", stderr(&r));
    let objects: Vec<String> =
        read(&out)["keys"].as_array().unwrap().iter().map(|k| k["object"].as_str().unwrap().to_owned()).collect();
    assert_eq!(objects, ["crt", "ek1", "ek2", "sk1", "sk2"]);
    // The certificate travels as its value. The import takes the keys first, and then the
    // certificate.
    let all = read(&out);
    let crt = all["keys"].as_array().unwrap().iter().find(|k| k["object"].as_str() == Some("crt")).unwrap();
    assert_eq!((crt["method"].as_str(), crt.get("wrapped")), (Some("public"), None), "{crt}");
    let o = import(&out);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    for spec in ["crt-kry", "ek2-kry", "sk2-kry"] {
        assert_eq!(code(&e.cakeys(kry, &["check", "--spec", spec, "--token", "kryoptic"])), 0, "{spec}");
    }
    // Named objects export all or nothing: an object that cannot move fails the export, and no
    // bundle is written.
    let out = e.dir.join("never.bundle.toml");
    let r =
        e.km(soft, &["export", "ek2", "nx", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()]);
    assert_eq!(code(&r), 15, "{}", stderr(&r));
    assert!(!out.exists(), "a failed export wrote a bundle");
    // A named object with noExport is refused, and the message names the spec that keeps it.
    let r = e.km(soft, &["export", "nox", "--from", "softhsm", "--to", "kryoptic", "--dry-run"]);
    assert_eq!(code(&r), 15, "{}", stdout(&r));
    assert!(stdout(&r).contains("noExport in spec 'nox-soft'"), "{}", stdout(&r));
    let r = e.km(
        soft,
        &["export", "ek2", "nosuch", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()],
    );
    assert_eq!(code(&r), 14, "{}", stderr(&r));
    assert!(!out.exists(), "a failed export wrote a bundle");
}

/// Checks D8 and C-12: what a Nix build refuses, and what `ALLOW_NIX_STORE_KEYS` allows.
fn refused_in_a_nix_build(e: &Env, soft: &Ref, pass: &str, bundle: &str) {
    // A key file is told apart from a bundle by its content, so the refused import names a real
    // key file.
    let key_file = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/keyfiles/p256.pkcs8.pem");
    // D8: an export, a key file's import and `transport --trust-on` are admin operations, and a
    // move writes the lock. Each of them is refused inside a Nix build, before any token is
    // opened, with the single exit code for a refusal there (21, review 2026-11-23 C-12).
    let admin: [(&[&str], &str); 4] = [
        (&["export", "ek1", "--from", "softhsm", "--to", "kryoptic", "--out", bundle], "export is an admin operation"),
        (
            &["import", "--to", "kryoptic", "--in", key_file, "--passphrase-file", pass, "--allow-host-plaintext"],
            "import of a key file is an admin operation",
        ),
        (
            &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--trust-on", "softhsm"],
            "transport --trust-on is an admin",
        ),
        (&["migrate", "crt", "--from", "softhsm", "--to", "kryoptic"], "cannot write the lock"),
    ];
    for (a, what) in admin {
        let o = e.km_in_nix_build(soft, &[], a);
        assert_eq!(code(&o), 21, "{what}: {}", stderr(&o));
        assert!(stderr(&o).contains(what), "{what}: {}", stderr(&o));
    }
    assert!(!std::path::Path::new(bundle).exists(), "a refused export wrote a bundle");
    // A build that makes and uses throwaway keys says so with `ALLOW_NIX_STORE_KEYS`, and then
    // runs as it would outside a Nix build.
    let o = e.km_in_nix_build(soft, &[(ALLOW_NIX_STORE_KEYS, "1")], admin[0].0);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    std::fs::remove_file(bundle).unwrap();
}

/// Checks what camigrate refuses around its plans, and runs the offline path that the other tests
/// only plan (these were gaps in the coverage report). The refusals are: admin operations inside a
/// Nix build (D8); a key file export without its flags, with an empty passphrase, of several keys,
/// or of a key with which the lock pairs no certificate; and a key file whose key the lock does
/// not pin. The offline path is an export sealed to a transport file, which is written, imported
/// and verified.
#[test]
fn refusals_around_the_plans_and_the_offline_export() {
    let Some(e) = env("refusals") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let Some([soft, kry]) = e.needs("refusals", ["softhsm", "kryoptic"]) else { return };
    bundle_keys(&e, soft, kry);
    let path = |name: &str| e.dir.join(name).to_str().unwrap().to_owned();
    let (pass, empty) = (path("pass"), path("empty"));
    std::fs::write(&pass, "correct horse\n").unwrap();
    std::fs::write(&empty, "\n").unwrap();
    let to_file = |format: &'static str, out: &str| -> Vec<String> {
        [
            "--from",
            "softhsm",
            "--to-key-file",
            format,
            "--out",
            out,
            "--passphrase-file",
            &pass,
            "--allow-host-plaintext",
        ]
        .map(String::from)
        .to_vec()
    };
    let args = |head: &[&str], tail: &[String]| -> Vec<String> {
        head.iter().map(|a| (*a).to_owned()).chain(tail.iter().cloned()).collect()
    };
    let run = |r: &Ref, a: &[String]| e.km(r, &a.iter().map(String::as_str).collect::<Vec<_>>());

    refused_in_a_nix_build(&e, soft, &pass, &path("nix.bundle.toml"));

    // For a key file, the flags and the passphrase are input, and wrong input is refused before
    // any plan.
    let o =
        e.km_alone(soft, &["export", "ek1", "--from", "softhsm", "--to-key-file", "pkcs8", "--allow-host-plaintext"]);
    exits(&o, 17, "needs --out and --passphrase-file");
    let out = path("ek1.pem");
    let flags = ["--to-key-file", "pkcs8", "--out", &out, "--passphrase-file", &empty, "--allow-host-plaintext"];
    exits(
        &e.km_alone(soft, &[&["export", "ek1", "--from", "softhsm"][..], &flags].concat()),
        17,
        "passphrase is empty",
    );
    // The plan checks what a file can hold: one key, and for PKCS#12 also its paired certificate.
    exits(&run(soft, &args(&["export", "ek1", "ek2"], &to_file("pkcs8", &out))), 15, "a key file holds one key");
    exits(&run(soft, &args(&["export", "ek1"], &to_file("pkcs12", &out))), 15, "pairs no certificate");
    assert!(!std::path::Path::new(&out).exists(), "a refused export wrote a key file");
    // A key file names no object, so a lock that does not pin its key has no place to put it.
    assert_eq!(code(&run(soft, &args(&["export", "ek1"], &to_file("pkcs8", &out)))), 0);
    let unpinned = path("unpinned.lock");
    let import = ["import", "--to", "kryoptic", "--in", &out, "--passphrase-file", &pass, "--allow-host-plaintext"];
    exits(
        &e.km(kry, &[&["--new-lock", "--lock", &unpinned][..], &import].concat()),
        14,
        "pins no private key with this key's identity",
    );

    // The offline path: the transport file on stdout is the same as the one that `--out` writes,
    // an export sealed to it needs no target, and the target imports and verifies the bundle.
    let transport = path("tk.transport.toml");
    let o = e.km(kry, &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        code(&e.km(kry, &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--out", &transport])),
        0
    );
    assert_eq!(stdout(&o).trim_end(), std::fs::read_to_string(&transport).unwrap().trim_end());
    // The transport key can be named as cakeys' verbs name it, by its object, or not named at
    // all, in which case the token's transportWith applies.
    for args in [&["transport", "tk-kryoptic", "--token", "kryoptic"][..], &["transport", "--token", "kryoptic"]] {
        let same = e.km(kry, args);
        assert_eq!((code(&same), stdout(&same)), (0, stdout(&o)), "{args:?}: {}", stderr(&same));
    }
    exits(&e.km(kry, &["transport", "--token", "softhsm-nope"]), 17, "unknown token 'softhsm-nope'");
    exits(
        &e.km(kry, &["transport", "ek1", "--spec", "tk-kryoptic", "--token", "kryoptic"]),
        17,
        "realises 'tk-kryoptic'",
    );
    let sealed = path("sk2.bundle.toml");
    let o = e.km(
        soft,
        &[
            "export",
            "sk2",
            "--from",
            "softhsm",
            "--to",
            "kryoptic",
            "--to-transport-file",
            &transport,
            "--out",
            &sealed,
        ],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // A --spec that does not realise the bundle's object on that token is refused before the
    // import.
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", &sealed, "--spec", "ek1-kry"]);
    exits(&o, 17, "--spec 'ek1-kry' selects nothing");
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", &sealed]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["check", "--spec", "sk2-kry", "--token", "kryoptic"])), 0);
    // A token on which the lock records nothing has nothing to plan.
    if named("p11kit").is_some() {
        let o = e.km(soft, &["export", "--from", "p11kit", "--to", "kryoptic", "--dry-run"]);
        exits(&o, 14, "the lock records no realisation on token 'p11kit'");
    }
    the_transport_file_is_read_once(&e, soft, &transport);
    transport_files_and_bundle_entries_are_checked(&e, soft, &transport);
}

/// Checks that a transport file is read once (camigrate lib.rs F3), so that the plan checks the
/// same key against the lock as the key to which the export seals. The file is a FIFO whose first
/// read returns the pinned transport key's file, and whose later reads return a copy that names
/// another object. The bundle names the pinned key.
fn the_transport_file_is_read_once(e: &Env, soft: &Ref, transport: &str) {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    let pinned = std::fs::read_to_string(transport).unwrap();
    let rogue = pinned.replace("object = \"tk-kryoptic\"", "object = \"ek2\"");
    assert_ne!(pinned, rogue);
    let fifo = e.dir.join("once.transport.fifo");
    let _ = std::fs::remove_file(&fifo);
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
    let writer = {
        let fifo = fifo.clone();
        std::thread::spawn(move || {
            for (i, text) in [pinned, rogue].into_iter().enumerate() {
                // Do not write the second text while the first read is still open, because the
                // reader would take both texts as one. When no reader is left, a nonblocking open
                // for writing fails with ENXIO, and the loop waits for that.
                if i > 0 {
                    loop {
                        match std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(&fifo) {
                            Ok(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
                            Err(e) if e.raw_os_error() == Some(libc::ENXIO) => break,
                            Err(e) => panic!("{e}"),
                        }
                    }
                }
                let mut w = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
                w.write_all(text.as_bytes()).unwrap();
            }
        })
    };
    let out = e.dir.join("once.bundle.toml");
    let (fifo_arg, out_arg) = (fifo.to_str().unwrap(), out.to_str().unwrap());
    let o = e.km_alone(
        soft,
        &["export", "sk2", "--from", "softhsm", "--to", "kryoptic", "--to-transport-file", fifo_arg, "--out", out_arg],
    );
    // A run that read the file once leaves the writer waiting for a second reader. The test opens
    // the FIFO as that reader, so that the writer can finish.
    let reader = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(&fifo).unwrap();
    writer.join().unwrap();
    drop(reader);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(bundle["transport"]["object"].as_str(), Some("tk-kryoptic"), "sealed to a second read: {bundle}");
}

/// Checks that a transport file is treated as input. A file of a provider that this build does
/// not link has no plan (15). A file that names an object whose key the lock does not pin blocks
/// the plan (15). A file of a provider with no committed profile is planned by that provider's
/// own rules. A bundle entry whose object has no spec on the importing token is reported, not
/// imported, and fails the run (17). A transport key whose spec was removed from keys.toml blocks
/// the plan (15), as it would stop the export.
fn transport_files_and_bundle_entries_are_checked(e: &Env, soft: &Ref, transport: &str) {
    let text = std::fs::read_to_string(transport).unwrap();
    let plan = |name: &str, from: &str, to: &str| {
        let path = e.dir.join(name);
        assert!(text.contains(from), "{from}: {text}");
        std::fs::write(&path, text.replace(from, to)).unwrap();
        e.km(
            soft,
            &[
                "export",
                "sk1",
                "--from",
                "softhsm",
                "--to",
                "kryoptic",
                "--to-transport-file",
                path.to_str().unwrap(),
                "--dry-run",
            ],
        )
    };
    let provider = "provider = \"kryoptic\"";
    let o = plan("nope.transport.toml", provider, "provider = \"nope\"");
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("provider 'nope' is not in this build"), "{}", stderr(&o));
    let o = plan("other.transport.toml", "object = \"tk-kryoptic\"", "object = \"tk-other\"");
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("its object 'tk-other' is not the transport key of 'kryoptic'"), "{}", stdout(&o));
    let o = plan("generic.transport.toml", provider, "provider = \"generic\"");
    assert_eq!(code(&o), 0, "{} {}", stdout(&o), stderr(&o));
    a_transport_file_of_another_pinned_key_is_refused(e, soft, &text);

    // The certificate has a spec on SoftHSM and on kryoptic, and none on the third token. A bundle
    // made for that third token names the certificate (a public object needs no transport key
    // there).
    if let Some(der) = e.refs.iter().find(|r| r.name == "kryoptic-der") {
        let bundle = e.dir.join("crt-der.bundle.toml");
        let out = bundle.to_str().unwrap();
        let o = e.km(soft, &["export", "crt", "--from", "softhsm", "--to", "kryoptic-der", "--out", out]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        let o = e.km(der, &["import", "--to", "kryoptic-der", "--in", out]);
        assert_eq!(code(&o), 17, "{}", stderr(&o));
        let said = stdout(&o) + &stderr(&o);
        assert!(
            said.contains("crt: not imported")
                && said.contains("keys.toml has no spec of object 'crt' on token 'kryoptic-der'"),
            "{said}"
        );
    }

    // The lock still names tk-kryoptic as kryoptic's transport key, and keys.toml no longer has
    // it.
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let attributes = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let kry = e.refs.iter().find(|r| r.name == "kryoptic").unwrap();
    let body = format!("[objects.ek1]\n{ec}\n\n")
        + &Env::spec("ek1-soft", "ek1", attributes, &[soft], "xb-ek1", CREATE)
        + &Env::spec("ek1-kry", "ek1", attributes, &[kry], "xb-ek1", IMPORT);
    e.config(&body);
    let out = e.dir.join("gone.bundle.toml");
    let export = ["export", "ek1", "--from", "softhsm", "--to", "kryoptic", "--transport-spec", "tk-kryoptic"];
    let o = e.km(soft, &[&export[..], &["--out", out.to_str().unwrap()]].concat());
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("the transport key's spec 'tk-kryoptic' is gone from keys.toml"), "{}", stderr(&o));
    assert!(!out.exists(), "a refused export wrote a bundle");
}

/// Checks that the plan and the export refuse a transport file that was swapped in transit for
/// another key that the lock pins, with that key's real identity and public key (here the
/// certificate's RSA subject key). The file must name the transport key of the token that `--to`
/// names, which is the key that `transportWith` or `--transport-spec` names. Otherwise, whoever
/// holds the other key's private half could unwrap the bundle (review 2026-11-23 C-1). The case of
/// a dev token's genuine file in place of the prod token's file is tested by
/// `transport_files_are_bound_to_the_target_named` (review 2026-11-24 D-1).
fn a_transport_file_of_another_pinned_key_is_refused(e: &Env, soft: &Ref, text: &str) {
    use base64::Engine as _;
    let lock: toml::Table = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    let pinned = lock["objects"]["crt"]["ids"]["rfc7093m4"].as_str().unwrap();
    let cert = x509_cert::Certificate::from_der(CERT_RSA).unwrap();
    let spki =
        cakeys_core::id::spki_canonical(&cert.tbs_certificate().subject_public_key_info().to_der().unwrap()).unwrap();
    assert_eq!(cakeys_core::id::sri(&spki), pinned, "the lock pins the certificate's subject key");
    let mut swapped: toml::Table = toml::from_str(text).unwrap();
    swapped["object"] = "crt".into();
    swapped["rfc7093m4"] = pinned.into();
    swapped["spki"] = base64::engine::general_purpose::STANDARD.encode(&spki).into();
    let path = e.dir.join("swapped.transport.toml");
    std::fs::write(&path, toml::to_string(&swapped).unwrap()).unwrap();
    let export =
        ["export", "sk1", "--from", "softhsm", "--to", "kryoptic", "--to-transport-file", path.to_str().unwrap()];
    let o = e.km(soft, &[&export[..], &["--dry-run"]].concat());
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("its object 'crt' is not the transport key of 'kryoptic'"), "{}", stdout(&o));
    let out = e.dir.join("swapped.bundle.toml");
    let o = e.km(soft, &[&export[..], &["--out", out.to_str().unwrap()]].concat());
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(!out.exists(), "a bundle was sealed to another pinned key");
    // Naming another key with --transport-spec does not make it a transport key. Whether it is not
    // an unwrap-only RSA key or is not realised there, it is refused, and the message names it.
    let o = e.km(soft, &[&export[..], &["--dry-run", "--transport-spec", "crt-kry"]].concat());
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("'crt-kry'"), "{}", stdout(&o));
}

/// Checks that a move lands only on a pair that says `origin = "import"`. A target pair that says
/// that the key is adopted there is refused, by the dry run as by the run, with a message that
/// names it, before anything moves.
#[test]
fn a_move_lands_only_on_an_import_pair() {
    let Some(e) = env("import-only") else { return };
    let Some([soft, kry]) = e.needs("import-only", ["softhsm", "kryoptic"]) else { return };
    let movable = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let body = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n".to_owned()
        + &Env::spec("k-soft", "k", movable, &[soft], "xi-k", CREATE)
        + &Env::spec("k-kry", "k", movable, &[kry], "xi-k", "");
    e.config(&body);
    assert_eq!(code(&e.cakeys(soft, &["create", "--spec", "k-soft", "--token", "softhsm"])), 22);
    let mv = ["migrate", "k", "--from", "softhsm", "--to", "kryoptic", "--allow-host-plaintext"];
    // Without a name, the plan is blocked (15). Naming the adopted pair is wrong input (17). Each
    // run is checked for its own code (review dry_run.rs F5 found that either code was accepted for
    // all four runs).
    let runs =
        [(&["--dry-run"][..], 15), (&[], 15), (&["--spec", "k-kry", "--dry-run"], 17), (&["--spec", "k-kry"], 17)];
    for (extra, want) in runs {
        let o = e.km(soft, &[&mv[..], extra].concat());
        let said = format!("{}{}", stdout(&o), stderr(&o));
        assert_eq!(code(&o), want, "{extra:?}: {said}");
        assert!(said.contains("a move lands only where keys.toml says origin = \"import\""), "{extra:?}: {said}");
    }
    assert!(open_session(&kry.module, kry.token_label, "1234").labelled("xi-k").is_empty(), "nothing moved");
}

/// Checks a transport key against what the lock records about it (docs/CAMIGRATE.md D3).
/// `transport` refuses a key that is not an RSA private key (17), and a key that may not unwrap or
/// that could leave its token (14). A plan that names such a key with `--transport-spec` is
/// blocked (15). An export without names in which nothing can move writes no bundle (15).
#[test]
fn transport_keys_are_held_to_what_the_lock_records() {
    let Some(e) = env("transport-keys") else { return };
    let Some([soft, kry]) = e.needs("transport-keys", ["softhsm", "kryoptic"]) else { return };
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
        assert_eq!(code(&e.cakeys(kry, &["create", "--spec", spec, "--token", "kryoptic"])), 22, "{spec}");
    }
    for spec in ["stays", "moves"] {
        assert_eq!(code(&e.cakeys(soft, &["create", "--spec", spec, "--token", "softhsm"])), 22, "{spec}");
    }
    let transport = |r: &Ref, spec: &str, token: &str| e.km(r, &["transport", "--spec", spec, "--token", token]);
    exits(&transport(soft, "moves", "softhsm"), 17, "a transport key is an RSA private key");
    exits(&transport(kry, "signs", "kryoptic"), 14, "a transport key must allow CKA_UNWRAP");
    exits(&transport(kry, "leaves", "kryoptic"), 14, "a transport key must never leave the token");
    let plan = ["export", "moves", "--from", "softhsm", "--to", "kryoptic", "--dry-run"];
    for key in ["signs", "leaves"] {
        let o = e.km(soft, &[&plan[..], &["--transport-spec", key]].concat());
        exits(&o, 15, &format!("'{key}' on 'kryoptic' is no transport key"));
    }
    // Nothing moves: one key never leaves its token, and the other key has no transport key to be
    // wrapped under.
    let out = e.dir.join("none.bundle.toml");
    let o = e.km(soft, &["export", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()]);
    exits(&o, 15, "moves: left out of the bundle");
    assert!(!out.exists(), "an export of nothing wrote a bundle");
}

/// Sets up two targets with one transport key each (`kryoptic` and `kryoptic-der`,
/// `transportWith`), a second transport key on `kryoptic` that its `transportWith` does not name
/// (`tk-alt`), and `mv` on `SoftHSM`, which may move to `kryoptic`. The tests that use it check
/// that the transport key is bound to the target that the operator names (review 2026-11-24 D-1,
/// D-8, D-10).
fn two_targets(test: &str) -> Option<(Env, [Ref; 3])> {
    let e = env(test)?;
    let [soft, kry, der] = e.needs(test, ["softhsm", "kryoptic", "kryoptic-der"])?.map(Ref::clone);
    let so_pin = e.dir.join("so-pin");
    std::fs::write(&so_pin, "5678\n").unwrap();
    let movable = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let alt = "[objects.tk-alt]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n".to_owned()
        + &Env::spec(
            "tk-alt",
            "tk-alt",
            "attributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = false }\n",
            &[&kry],
            "tk-alt",
            ", origin = \"create\", binding = \"pop-unwrap\"",
        );
    let body = transport_key(&kry)
        + &transport_key(&der)
        + &alt
        + "[objects.mv]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        + &Env::spec("mv-soft", "mv", movable, &[&soft], "xbt-mv", CREATE)
        + &Env::spec("mv-kry", "mv", movable, &[&kry], "xbt-mv", IMPORT);
    e.config_with(&body, &|r| match r.name {
        "kryoptic" | "kryoptic-der" => format!("migrate = {{ transportWith = \"tk-{}\" }}\n", r.name),
        "softhsm" => format!("soCredentialFile = \"{}\"\n", so_pin.display()),
        _ => String::new(),
    });
    for (spec, r) in [("tk-kryoptic", &kry), ("tk-kryoptic-der", &der), ("tk-alt", &kry), ("mv-soft", &soft)] {
        let o = e.cakeys(r, &["create", "--spec", spec, "--token", r.name]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    Some((e, [soft, kry, der]))
}

/// Asserts that `o` exits with `want` and says `what` on standard output or standard error.
fn exits(o: &std::process::Output, want: i32, what: &str) {
    assert_eq!(code(o), want, "{what}: {} {}", stdout(o), stderr(o));
    assert!(stderr(o).contains(what) || stdout(o).contains(what), "{what}: {} {}", stdout(o), stderr(o));
}

/// Returns the path of a file in `e`'s directory, as an argument.
fn file_arg(e: &Env, name: &str) -> String {
    e.dir.join(name).to_str().unwrap().to_owned()
}

/// Reads and parses a TOML file.
fn read_toml(path: &str) -> toml::Table {
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Checks that an export to a transport file names its target (`--to`), and that the file must be
/// that token's file (docs/CAMIGRATE.md D3; review 2026-11-24 D-1). The genuine file of another
/// target, with its own key, identity and public key (`kryoptic-der`'s file, swapped in for
/// `kryoptic`'s), is refused with 17, in a dry run or a real run, and nothing is written. The
/// bundle names its target, and so does the export's last line. A bundle made for another target
/// is refused on the wrong target (14), in a dry run or a real run.
#[test]
fn transport_files_are_bound_to_the_target_named() {
    let Some((e, [soft, kry, der])) = two_targets("bound-file") else { return };
    let dev = file_arg(&e, "dev.transport.toml");
    assert_eq!(code(&e.km(&der, &["transport", "--token", "kryoptic-der", "--out", &dev])), 0);
    let out = file_arg(&e, "swapped.bundle.toml");
    let o = e.km_alone(&soft, &["export", "mv", "--from", "softhsm", "--to-transport-file", &dev, "--out", &out]);
    // This is a usage error from clap, because --to-transport-file requires --to.
    assert_eq!(code(&o), 2, "an export to a transport file names no target: {}", stderr(&o));
    assert!(!std::path::Path::new(&out).exists(), "sealed to the file's own target");
    let swapped = ["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--to-transport-file", &dev];
    for extra in [&["--dry-run"][..], &["--out", &out]] {
        exits(
            &e.km(&soft, &[&swapped[..], extra].concat()),
            17,
            "a transport file of 'kryoptic-der', not of 'kryoptic'",
        );
    }
    assert!(!std::path::Path::new(&out).exists(), "sealed to another target's transport key");
    let bundle = file_arg(&e, "dev.bundle.toml");
    let own = ["export", "mv", "--from", "softhsm", "--to", "kryoptic-der", "--to-transport-file", &dev];
    assert_eq!(code(&e.km(&soft, &own)), 0);
    let o = e.km(&soft, &[&own[..], &["--out", &bundle]].concat());
    exits(&o, 0, "for 'kryoptic-der'");
    let b = read_toml(&bundle);
    assert_eq!((b["version"].as_integer(), b["target"].as_str()), (Some(2), Some("kryoptic-der")), "{b}");
    assert_eq!(b["transport"]["object"].as_str(), Some("tk-kryoptic-der"), "{b}");
    for extra in [&["--dry-run"][..], &[]] {
        let o = e.km(&kry, &[&["import", "--to", "kryoptic", "--in", &bundle][..], extra].concat());
        exits(&o, 14, "the bundle is for 'kryoptic-der', not 'kryoptic'");
    }
}

/// Checks that an import requires a bundle's transport key to be the target's own transport key,
/// as every export does (`transportWith`, or `--transport-spec`; docs/CAMIGRATE.md D3; review
/// 2026-11-24 D-8). A bundle sealed to another key realised there (`tk-alt`, which is a transport
/// key but not the named one) is refused with 14 before the token is touched, in a dry run or a
/// real run. When the import names the key as the export named it, the bundle imports. A version-1
/// bundle, which names no target, is read with a warning.
#[test]
fn bundles_are_bound_to_the_targets_transport_key() {
    let Some((e, [soft, kry, _])) = two_targets("bound-bundle") else { return };
    let sealed_alt = file_arg(&e, "alt.bundle.toml");
    let to_alt = ["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--transport-spec", "tk-alt"];
    let o = e.km(&soft, &[&to_alt[..], &["--out", &sealed_alt]].concat());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    for extra in [&["--dry-run"][..], &[]] {
        let o = e.km(&kry, &[&["import", "--to", "kryoptic", "--in", &sealed_alt][..], extra].concat());
        exits(&o, 14, "sealed to 'tk-alt'");
    }
    assert!(open_session(&kry.module, kry.token_label, "1234").labelled("xbt-mv").is_empty(), "imported");
    let o = e.km(&kry, &["import", "--to", "kryoptic", "--in", &sealed_alt, "--transport-spec", "tk-alt"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let k = file_arg(&e, "k.bundle.toml");
    assert_eq!(code(&e.km(&soft, &["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--out", &k])), 0);
    let mut old = read_toml(&k);
    old.remove("target");
    old["version"] = 1.into();
    let v1 = file_arg(&e, "v1.bundle.toml");
    std::fs::write(&v1, toml::to_string(&old).unwrap()).unwrap();
    let o = e.km(&kry, &["import", "--to", "kryoptic", "--in", &v1, "--dry-run"]);
    exits(&o, 0, "a version-1 bundle names no target");
}

/// Checks that every path that takes a transport key from the lock applies the one rule to it
/// (docs/CAMIGRATE.md D3; review 2026-11-24 D-10, D-7). `transport --trust-on` refuses a 1024-bit
/// key that the lock records (17) and makes no trusted copy. A key that the lock does not record as
/// non-extractable is not a transport key, because an unknown value does not pass: the plan blocks
/// it (15), and `transport` refuses it (14).
#[test]
fn locked_transport_keys_are_held_to_one_rule() {
    let Some((e, [soft, kry, _])) = two_targets("bound-lock") else { return };
    let lock = read_toml(&file_arg(&e, "keys.lock"));
    let with = |r: &Ref, l: &str, args: &[&str]| e.km(r, &[&["--lock", &file_arg(&e, l)][..], args].concat());
    let mut unrecorded = lock.clone();
    let policy = unrecorded["realisations"]["tk-kryoptic"]["kryoptic"]["policy"].as_table_mut().unwrap();
    assert_eq!(policy.remove("CKA_EXTRACTABLE").and_then(|v| v.as_bool()), Some(false));
    std::fs::write(file_arg(&e, "unrecorded.lock"), toml::to_string(&unrecorded).unwrap()).unwrap();
    let o = with(&soft, "unrecorded.lock", &["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--dry-run"]);
    exits(&o, 15, "CKA_EXTRACTABLE");
    exits(&with(&kry, "unrecorded.lock", &["transport", "--token", "kryoptic"]), 14, "CKA_EXTRACTABLE");
    // Write a lock that records a 1024-bit transport key (a key that keys.toml declared without
    // modulusBits).
    let small = cakeys_core::id::rsa_spki(&[0xc5u8; 128], &[1, 0, 1]).unwrap();
    let mut smaller = lock.clone();
    let tk = smaller["objects"]["tk-kryoptic"].as_table_mut().unwrap();
    tk["publicKey"] = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&small).into()
    };
    tk["ids"]["rfc7093m4"] = cakeys_core::id::sri(&small).into();
    std::fs::write(file_arg(&e, "small.lock"), toml::to_string(&smaller).unwrap()).unwrap();
    let trust = ["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--trust-on", "softhsm"];
    exits(&with(&soft, "small.lock", &trust), 17, "at least 2048 bits");
    let copy = open_session(&soft.module, soft.token_label, "1234").labelled("cakeys-transport-kryoptic-tk-kryoptic");
    assert!(copy.is_empty(), "a 1024-bit key was made trusted");
}

/// Checks that an export without names takes what can move, and ends as its dry run did when
/// nothing can move (docs/CAMIGRATE.md D9; review 2026-11-24 D-6). A token that holds only its
/// own transport key, which never leaves, has nothing to export, and both the export and its dry
/// run say so (15). With a name, the key is refused as a key that never leaves (15).
#[test]
fn an_export_of_nothing_that_can_go_ends_as_its_plan() {
    let Some((e, [_, kry, der])) = two_targets("nothing-goes") else { return };
    let export = ["export", "--from", "kryoptic-der", "--to", "kryoptic"];
    exits(&e.km_alone(&der, &[&export[..], &["--dry-run"]].concat()), 15, "nothing on 'kryoptic-der' can go");
    let out = file_arg(&e, "nothing.bundle.toml");
    exits(&e.km(&der, &[&export[..], &["--out", &out]].concat()), 15, "nothing on 'kryoptic-der' can go");
    assert!(!std::path::Path::new(&out).exists(), "a bundle was written");
    let named = ["export", "tk-kryoptic-der", "--from", "kryoptic-der", "--to", "kryoptic", "--dry-run"];
    exits(&e.km_alone(&kry, &named), 15, "it never leaves 'kryoptic-der'");
}

/// Checks that an export to a key file without names, from a token where nothing can move, ends as
/// its plan does (17), and that nothing is written. A key file holds one key. The plan once said
/// ready although it had no plan (a sibling of review 2026-11-24 D-6).
#[test]
fn a_key_file_of_nothing_ends_as_its_plan() {
    let Some((e, [_, _, der])) = two_targets("no-key-file") else { return };
    let pass = file_arg(&e, "pass");
    std::fs::write(&pass, "correct horse\n").unwrap();
    let out = file_arg(&e, "nothing.p8");
    let export = ["export", "--from", "kryoptic-der", "--to-key-file", "pkcs8", "--allow-host-plaintext"];
    exits(&e.km_alone(&der, &[&export[..], &["--dry-run"]].concat()), 17, "a key file holds one key");
    let o = e.km(&der, &[&export[..], &["--out", &out, "--passphrase-file", &pass]].concat());
    exits(&o, 17, "a key file holds one key");
    assert!(!std::path::Path::new(&out).exists(), "a key file was written");
}

/// Checks that the plan checks where the module can place a key (`Provider::placement`) where a
/// move lands, as the import checks it before its write (review 2026-11-24 D-2). Into a PIV token
/// (a `SoftHSM` token bound to ykcs11, which places a key by `CKA_ID` alone, never under a label
/// and never in the attestation slot f9, `CKA_ID = "19"`), `migrate --dry-run` refuses as the run
/// does (17), and nothing reaches the token.
#[test]
fn placement_is_planned_where_a_move_lands() {
    let Some(e) = env("placement") else { return };
    let Some([soft]) = e.needs("placement", ["softhsm"]) else { return };
    let so = e.dir.join("so-pin");
    std::fs::write(&so, "5678\n").unwrap();
    let pair = |spec: &str, locator: &str| {
        format!(
            "[specs.{spec}]\nobject = \"pl\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.piv = {{ locator = {{ {locator} }}, origin = \"import\" }}\n\n"
        )
    };
    let body = format!(
        "[tokens.piv]\nmodule = \"{}\"\ntokenLabel = \"{}\"\nprovider = \"ykcs11\"\npinFile = \"{}\"\nsoCredentialFile = \"{}\"\n\n",
        soft.module,
        soft.token_label,
        e.dir.join("pin").display(),
        so.display()
    ) + "[objects.pl]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        + &Env::spec(
            "pl-src",
            "pl",
            "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n",
            &[soft],
            "pl-src",
            CREATE,
        )
        + &pair("pl-label", "CKA_LABEL = \"pl-label\"")
        + &pair("pl-f9", "CKA_ID = \"19\"");
    e.config(&body);
    assert_eq!(code(&e.cakeys(soft, &["create", "--spec", "pl-src", "--token", "softhsm"])), 22);
    let session = || open_session(&soft.module, soft.token_label, "1234");
    let before = session().find_objects(&[]).unwrap().len();
    for (spec, said) in [("pl-label", "ignores CKA_LABEL"), ("pl-f9", "\"19\" names none")] {
        let migrate = ["migrate", "pl", "--from", "softhsm", "--to", "piv", "--spec", spec, "--allow-host-plaintext"];
        exits(&e.km_alone(soft, &[&migrate[..], &["--dry-run"]].concat()), 17, said);
        // The twin check: the run refuses as its dry run did.
        exits(&e.km(soft, &migrate), 17, said);
        assert_eq!(session().find_objects(&[]).unwrap().len(), before, "{spec}: an object reached the token");
    }
}

/// Checks that the plan checks whether another key is under the target locator where a move lands,
/// as the import checks it before its write (docs/CAMIGRATE.md D6, If-None-Match; review
/// 2026-11-24 D-3). `migrate --dry-run` refuses (13) as the run does. The dry-run twin once
/// accepted this refusal after a ready plan.
#[test]
fn an_occupied_locator_is_planned() {
    let Some((e, [soft, kry, _])) = two_targets("occupied") else { return };
    let t = open_session(&kry.module, kry.token_label, "1234");
    t.generate_key_pair(
        &cryptoki::mechanism::Mechanism::EccKeyPairGen,
        &[Attribute::Token(true), Attribute::Label(b"xbt-mv".to_vec()), Attribute::EcParams(P256.to_vec())],
        &[Attribute::Token(true), Attribute::Label(b"xbt-mv".to_vec()), Attribute::Sign(true)],
    )
    .unwrap();
    drop(t);
    let migrate = ["migrate", "mv", "--from", "softhsm", "--to", "kryoptic"];
    exits(&e.km_alone(&soft, &[&migrate[..], &["--dry-run"]].concat()), 13, "would collide with");
    exits(&e.km(&soft, &migrate), 13, "would collide with");
    assert_eq!(open_session(&kry.module, kry.token_label, "1234").labelled("xbt-mv").len(), 2, "imported over it");
}

/// Checks that an export plans against the target that `--to` names, whether it reaches the token
/// or only its transport file (review 2026-11-24 D-4 found that a transport file's plan checked
/// none of the landing rules). A landing pair that opts into an attestation that kryoptic's
/// provider cannot make is refused by both plans and both exports (15), as by the import there and
/// by a move, and nothing is written.
#[test]
fn exports_plan_against_their_target_either_way() {
    let Some((e, [soft, kry, _])) = two_targets("landing-either") else { return };
    let prod = file_arg(&e, "prod.transport.toml");
    assert_eq!(code(&e.km(&kry, &["transport", "--token", "kryoptic", "--out", &prod])), 0);
    let toml = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&toml).unwrap();
    let plain = "tokens.kryoptic = { locator = { CKA_LABEL = \"xbt-mv\" }, origin = \"import\" }";
    assert!(text.contains(plain), "{text}");
    let attested = plain.replace("origin = \"import\" }", "origin = \"import\", attestation = true }");
    std::fs::write(&toml, text.replace(plain, &attested)).unwrap();
    let said = "attests nothing";
    let out = file_arg(&e, "attested.bundle.toml");
    let export = ["export", "mv", "--from", "softhsm", "--to", "kryoptic"];
    for extra in [&[][..], &["--to-transport-file", &prod]] {
        let args = [&export[..], extra].concat();
        exits(&e.km_alone(&soft, &[&args[..], &["--dry-run"]].concat()), 15, said);
        exits(&e.km(&soft, &[&args[..], &["--out", &out]].concat()), 15, said);
        assert!(!std::path::Path::new(&out).exists(), "{extra:?}: a bundle was written");
    }
    exits(&e.km(&soft, &["migrate", "mv", "--from", "softhsm", "--to", "kryoptic"]), 15, said);
}

/// Checks that a token names its transport key (`transportWith`, docs/CAMIGRATE.md D3), and that
/// realising the key records its public key in the lock, checked against the locked identity. A
/// source then plans and exports to that token from the lock alone, while the target is
/// unreachable. Without the recorded key, a plan from the lock is blocked. A `transportWith` that
/// names a key that is not an unwrap-only RSA key is invalid.
#[test]
fn exports_to_a_token_need_only_the_lock() {
    let Some(e) = env("lock-transport") else { return };
    let Some([soft, kry]) = e.needs("lock-transport", ["softhsm", "kryoptic"]) else { return };
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
    // The transport key must be named; it is never picked. Without transportWith, the plan says
    // how to name one.
    e.config(&body);
    assert_eq!(code(&e.cakeys(kry, &["create", "--spec", "tk-kryoptic", "--token", "kryoptic"])), 22);
    assert_eq!(code(&e.cakeys(soft, &["create", "--spec", "mv", "--token", "softhsm"])), 22);
    let o = e.km(soft, &["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--dry-run"]);
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("transportWith"), "{}", stdout(&o));
    // The key was realised before transportWith named it, so the lock has no public key yet, and
    // with kryoptic unreachable, the plan is blocked. Realising it again records the key.
    names_transport(&e, &body, |r| r.name == "kryoptic");
    let away = format!("kryoptic={}", e.dir.join("absent.so").display());
    let plan = |e: &Env| {
        e.km(soft, &["--module", &away, "export", "mv", "--from", "softhsm", "--to", "kryoptic", "--dry-run"])
    };
    let o = plan(&e);
    exits(&o, 15, "records no public key");
    // With kryoptic reachable, the export asks the token for the public key that the lock lacks,
    // and says so. `transport --trust-on` takes the key only from the lock, and it has none to
    // take.
    let early = e.dir.join("early.bundle.toml");
    let o = e.km(soft, &["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--out", early.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("the lock records no public key for it yet"), "{}", stderr(&o));
    let o = e.km(kry, &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--trust-on", "softhsm"]);
    exits(&o, 14, "records no public key for transport key");
    assert_eq!(code(&e.cakeys(kry, &["lock", "--spec", "tk-kryoptic", "--token", "kryoptic"])), 22);
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
        &["--module", &away, "export", "mv", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()],
    );
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(bundle["transport"]["rfc7093m4"].as_str(), tk["ids"]["rfc7093m4"].as_str());
    // When the recorded public key does not have the locked identity, the lock does not load (17).
    let lock_path = e.dir.join("keys.lock");
    let text = std::fs::read_to_string(&lock_path).unwrap();
    let flipped = base64_flip(tk["publicKey"].as_str().unwrap());
    std::fs::write(&lock_path, text.replace(tk["publicKey"].as_str().unwrap(), &flipped)).unwrap();
    assert_eq!(code(&plan(&e)), 17);
    // The unreachable target's capabilities come only from an observation on which all its
    // realisations agree. When none is recorded, or when two differ, the plan fails as the open
    // did.
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
    // A transportWith that names a key that is not a transport key is invalid.
    e.config_with(&body, &|r| {
        if r.name == "kryoptic" { "migrate = { transportWith = \"mv\" }\n".into() } else { String::new() }
    });
    assert_eq!(code(&e.km(soft, &["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--dry-run"])), 17);
}

/// Checks the sealed path with OAEP SHA-256, which `SoftHSM` cannot do. The move runs between two
/// kryoptic tokens, and this test initialises the second token in its own slot. Both tokens are
/// reached through one kryoptic configuration that names both slots, and every run here uses that
/// configuration.
#[test]
fn sealed_moves_wrap_with_oaep_sha256_between_kryoptic_tokens() {
    let Some(mut e) = env("oaep-sha256") else { return };
    let Some([kry]) = e.needs("oaep-sha256", ["kryoptic"]) else { return };
    let module = kry.module.clone();
    // Write slot 2 before slot 1, because the suites append to the last table, which must stay the
    // first token's table.
    let conf = e.dir.join("kryoptic-two.conf");
    let first = std::fs::read_to_string(std::env::var("KRYOPTIC_CONF").unwrap()).unwrap();
    let db = e.dir.join("kryoptic-two.sql");
    std::fs::write(
        &conf,
        format!("[[slots]]\nslot = 2\ndbtype = \"sqlite\"\ndbargs = \"{}\"\n\n{first}", db.display()),
    )
    .unwrap();
    let conf = conf.to_str().unwrap().to_owned();
    let tool = |args: &[&str]| {
        let o = std::process::Command::new("pkcs11-tool")
            .env("KRYOPTIC_CONF", &conf)
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
    let both = ref_env(&[("KRYOPTIC_CONF", &conf)]);
    e.refs.retain(|r| r.name == "kryoptic");
    e.refs[0].env = both;
    e.refs.push(Ref { name: "kryoptic2", token_label: "kmtest2", ..e.refs[0].clone() });
    let (kry, two) = (&e.refs[0], &e.refs[1]);
    // The twin compares the databases of this configuration, not the databases of the process's
    // configuration (review 2026-11-24 L3).
    assert!(two.view().db.contains(&db) && kry.view().db.contains(&db), "{:?}", two.view().db);
    let attributes = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let body = transport_key(two)
        + "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        + &Env::spec("k-one", "k", attributes, &[kry], "xo-k", CREATE)
        + &Env::spec("k-two", "k", attributes, &[two], "xo-k", IMPORT);
    names_transport(&e, &body, |r| r.name == "kryoptic2");
    for (spec, r) in [("tk-kryoptic2", two), ("k-one", kry)] {
        let o = e.cakeys(r, &["create", "--spec", spec, "--token", r.name]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    let args = ["migrate", "k", "--from", "kryoptic", "--to", "kryoptic2"];
    let o = e.km(kry, &[&args[..], &["--dry-run", "--json"]].concat());
    let plan: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    // The dry run's exit code is its plan's exit code (review dry_run.rs F6).
    assert_eq!((code(&o), plan["plans"][0]["ready"].as_bool()), (0, Some(true)), "{plan}");
    assert_eq!(plan["plans"][0]["method"].as_str(), Some("rsa-oaep-sha256+aes-kwp"), "{plan}");
    let o = e.km(kry, &args);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(two, &["check", "--spec", "k-two", "--token", "kryoptic2"])), 0);
}

/// Checks that a key whose target spec declares `CKA_ALWAYS_AUTHENTICATE` moves as its plan says.
/// The key moves from kryoptic to `SoftHSM`, whose ECDSA signs only in one part, and it proves
/// possession with the per-use PIN (`pop-sign-pin`) through the single-part sign that the patched
/// cryptoki adds. Previously, the plan said ready, and the move then failed its proof (15). The
/// plan and the proof use the same check (`cakeys_pkcs11::token::proof_refusal`).
#[test]
fn per_use_pin_targets_move_as_planned() {
    let Some(e) = env("per-use-pin") else { return };
    let Some([soft, kry]) = e.needs("per-use-pin", ["softhsm", "kryoptic"]) else { return };
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
        let o = e.cakeys(r, &["create", "--spec", spec, "--token", r.name]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    // The dry-run twin requires the move to match the plan's verdict.
    let o = e.km(kry, &["migrate", "a", "--from", "kryoptic", "--to", "softhsm"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    assert_eq!(lock["realisations"]["a-dst"]["softhsm"]["binding"].as_str(), Some("pop-sign-pin"), "{lock}");
    assert_eq!(code(&e.cakeys(soft, &["check", "--spec", "a-dst", "--token", "softhsm"])), 0);
}

/// Returns the base64 `text` with one byte of the encoded data flipped.
fn base64_flip(text: &str) -> String {
    use base64::Engine as _;
    let mut bytes = base64::engine::general_purpose::STANDARD.decode(text).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x01;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Checks `enforced` (docs/CAMIGRATE.md D2, phase 3b). A `CKA_WRAP_WITH_TRUSTED` key on `SoftHSM`
/// moves only after its SO trusted the target's transport key (`transport --trust-on`, with
/// `soCredentialFile`), and then only by `CKM_RSA_AES_KEY_WRAP` under that trusted copy. Each
/// bundle entry carries its own key-encryption key. kryoptic imports and verifies the keys. A
/// wrap-with-trusted key on kryoptic never moves, because kryoptic cannot trust an RSA key (its
/// profile's `move.trusted-wrap` row says no).
#[test]
fn enforced_moves_wrap_only_under_the_trusted_transport_key() {
    let Some(e) = env("enforced") else { return };
    let Some([soft, kry]) = e.needs("enforced", ["softhsm", "kryoptic"]) else { return };
    std::fs::write(e.dir.join("so-pin"), "5678\n").unwrap();
    let trusted = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true, CKA_WRAP_WITH_TRUSTED = true }\n";
    let key = |o: &str, ty: &str, born: &Ref, other: &Ref, public: &str| {
        format!("[objects.{o}]\n{ty}\n\n")
            + &Env::spec(&format!("{o}-src"), o, trusted, &[born], &format!("xe-{o}"), CREATE)
            + &Env::spec(&format!("{o}-dst"), o, &format!("{trusted}{public}"), &[other], &format!("xe-{o}"), IMPORT)
    };
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
    // On kryoptic, the spec declares `ek`'s public half with `CKA_VERIFY = false`, and the import
    // creates it that way.
    let body = transport_key(kry)
        + &key("ek", ec, soft, kry, "publicAttributes = { CKA_VERIFY = false }\n")
        + &key("sk", aes, soft, kry, "")
        + &key("kk", ec, kry, soft, "");
    let so_pin = e.dir.join("so-pin");
    e.config_with(&body, &|r| match r.name {
        "kryoptic" => "migrate = { transportWith = \"tk-kryoptic\" }\n".into(),
        "softhsm" => format!("soCredentialFile = \"{}\"\n", so_pin.display()),
        _ => String::new(),
    });
    for (spec, r) in [("tk-kryoptic", kry), ("ek-src", soft), ("sk-src", soft), ("kk-src", kry)] {
        let o = e.cakeys(r, &["create", "--spec", spec, "--token", r.name]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    // The dry run's exit code is its plan's exit code: 0 when ready, and 15 when blocked (review
    // dry_run.rs F6).
    let plan = |o: &str, from: &Ref, to: &Ref| -> serde_json::Value {
        let out = e.km(from, &["migrate", o, "--from", from.name, "--to", to.name, "--dry-run", "--json"]);
        let p: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
        let want = if p["plans"][0]["ready"].as_bool() == Some(true) { 0 } else { 15 };
        assert_eq!(code(&out), want, "{p}");
        p
    };
    // While the transport key is not trusted, the plan is blocked, and it names the SO's step.
    let p = plan("ek", soft, kry);
    assert_eq!(p["plans"][0]["ready"].as_bool(), Some(false), "{p}");
    assert!(p["plans"][0]["reasons"][0].as_str().unwrap().contains("--trust-on softhsm"), "{p}");
    // The SO trusts the transport key, from the public key the lock records; again, nothing to do.
    let trust = ["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--trust-on", "softhsm"];
    let o = e.km(soft, &trust);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // The trusted copy is the only trusted object there, so the export has nothing to warn about.
    let narrow = e.dir.join("narrow.bundle.toml");
    let o = e.km(soft, &["export", "ek", "--from", "softhsm", "--to", "kryoptic", "--out", narrow.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!stderr(&o).contains("are CKA_TRUSTED"), "{}", stderr(&o));
    // When the SO trusts another key, `enforced` is only as narrow as the set of trusted keys, and
    // both the trust step and the export say so.
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
    // One bundle holds each enforced key with its own key-encryption key, and no KEK is shared.
    let out = e.dir.join("enforced.bundle.toml");
    let exported =
        e.km(soft, &["export", "ek", "sk", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()]);
    assert_eq!(code(&exported), 0, "{}", stderr(&exported));
    assert!(stderr(&exported).contains("1 other object(s) on 'softhsm' are CKA_TRUSTED"), "{}", stderr(&exported));
    let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(bundle.get("kek").is_none(), "{bundle}");
    for k in bundle["keys"].as_array().unwrap() {
        assert_eq!((k["exposure"].as_str(), k.get("kek").is_some()), (Some("enforced"), true), "{k}");
    }
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", out.to_str().unwrap()]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    for spec in ["ek-dst", "sk-dst"] {
        assert_eq!(code(&e.cakeys(kry, &["check", "--spec", spec, "--token", "kryoptic"])), 0, "{spec}");
    }
    assert_eq!(public_half(kry, "xe-ek"), (false, false), "the public half as the target spec declares it");
    // kryoptic cannot trust an RSA key, so a wrap-with-trusted key there never leaves.
    let p = plan("kk", kry, soft);
    let reasons = p["plans"][0]["reasons"].to_string();
    assert!(p["plans"][0]["ready"] == false && reasons.contains("move.trusted-wrap row says no"), "{p}");
}

/// Checks that a side with no RFC 5649 key wrap of its own moves the composed method by
/// `CKM_RSA_AES_KEY_WRAP`, in both directions. AWS `CloudHSM` is such a side: its profile subtracts
/// the AES key wraps that it lists but refuses \[run\]. Offline, the test uses `SoftHSM` under a
/// copy of its committed profile that subtracts its AES key wraps, added through `profileDirs` and
/// named by `provider`. Into that side, `migrate` unwraps both blobs in one call. Out of that side,
/// each sealed key of a bundle carries its own key-encryption key, which `import` accepts. kryoptic
/// and `SoftHSM` verify what arrived.
#[test]
fn rsa_aes_key_wrap_stands_in_for_rfc_5649() {
    let Some(e) = env("rsa-aes") else { return };
    let Some([soft, kry]) = e.needs("rsa-aes", ["softhsm", "kryoptic"]) else { return };
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
            "migrate = { transportWith = \"tk-softhsm\" }\nprovider = \"softhsm\"\nmoduleProfile = \"softhsm/2.7+no-aes-key-wrap\"\n"
                .into()
        }
        "kryoptic" => "migrate = { transportWith = \"tk-kryoptic\" }\n".into(),
        _ => String::new(),
    });
    // profileDirs is a top-level key, so it must come before every table.
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, format!("profileDirs = [\"{}\"]\n\n{text}", profiles.display())).unwrap();
    for (spec, r) in [("tk-kryoptic", kry), ("tk-softhsm", soft), ("in-src", kry), ("out-src", soft)] {
        let o = e.cakeys(r, &["create", "--spec", spec, "--token", r.name]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    // Into the side without RFC 5649, the composed method is unwrapped by CKM_RSA_AES_KEY_WRAP.
    let o = e.km(kry, &["migrate", "in", "--from", "kryoptic", "--to", "softhsm", "--spec", "in-dst"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert!(stderr(&o).contains("rsa-oaep-sha1+aes-kwp"), "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(soft, &["check", "--spec", "in-dst", "--token", "softhsm"])), 0);
    // Out of that side, through a file, the sealed key carries its own KEK, and no KEK is shared.
    let out = e.dir.join("rsa-aes.bundle.toml");
    let exported =
        e.km(soft, &["export", "out", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()]);
    assert_eq!(code(&exported), 0, "{}", stderr(&exported));
    let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(bundle.get("kek").is_none(), "{bundle}");
    let k = &bundle["keys"][0];
    assert_eq!((k["exposure"].as_str(), k.get("kek").is_some()), (Some("sealed"), true), "{k}");
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", out.to_str().unwrap()]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["check", "--spec", "out-dst", "--token", "kryoptic"])), 0);
}

/// Returns `CKA_VERIFY` and `CKA_PRIVATE` of the one public key object with the label `label` on
/// `r`'s token.
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

/// Plants an RSA public key that the SO of `soft`'s token (SO PIN 5678) marks `CKA_TRUSTED`, next
/// to the transport key's trusted copy.
fn plant_trusted_key(soft: &Ref) {
    // Use the shared context (review dry_run.rs F2). A separate context's own initialize and
    // finalize calls unloaded the module while other holders still had sessions open.
    let session = open_so_session(&soft.module, soft.token_label, "5678");
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
}

/// Checks the dry-run property for the `host` rows (docs/CAMIGRATE.md D2, phase 4). With
/// `--allow-host-plaintext`, every move that the plan sends through the host moves, records its
/// `origin` with the `host` exposure, and `cakeys check` accepts the key on the target. Such moves
/// use `host-pkcs8` or `host-raw` (for a target that cannot unwrap the key, like `SoftHSM` for
/// secret keys or p11-kit without AES key wrap), or `tpm2-ptool` into tpm2-pkcs11. Every other row
/// also runs: the dry run's exit code is its plan's exit code, and a blocked move exits 15 with the
/// lock and the target unchanged. Each host method that the references allow moves at least one
/// key.
#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn host_moves_do_what_the_plan_says() {
    let Some(e) = env("host-moves") else { return };
    let pairs = matrix(&KEYS, &e.refs, generates);
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
            let o = e.cakeys(s, &["create", "--spec", &spec, "--token", s.name]);
            assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
        }
    }
    let lock_path = e.dir.join("keys.lock");
    let mut rows = Vec::new();
    for (k, s, d) in &pairs {
        let (spec, o) = (target_spec(k, s, d), object(k, s));
        let args = ["migrate", o.as_str(), "--from", s.name, "--to", d.name, "--spec", &spec, "--allow-host-plaintext"];
        let out = e.km(s, &[&args[..], &["--dry-run", "--json"]].concat());
        let plan: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
        let ready = plan["plans"][0]["ready"].as_bool().unwrap();
        assert_eq!(code(&out) == 0, ready, "{spec}: the dry run's exit and its plan disagree");
        let method = plan["plans"][0]["method"].as_str().unwrap_or("-").to_owned();
        let through_host = method.starts_with("host-") || method == "tpm2-ptool";
        let before = std::fs::read(&lock_path).unwrap();
        let out = e.km(s, &args);
        let row =
            format!("{spec}: {method}, plan {}, move exit {}", if ready { "ready" } else { "blocked" }, code(&out));
        rows.push(row.clone());
        // Every row runs, as the rows of the sealed matrix do (review dry_run.rs F1). A row that
        // the planner wrongly blocks, or sends another way, fails here instead of being dropped.
        if !ready {
            assert_eq!(code(&out), 15, "{row}: {}", stderr(&out));
            assert_eq!(std::fs::read(&lock_path).unwrap(), before, "{row}: a refused move changed the lock");
            let left = open_session(&d.module, d.token_label, "1234").labelled(&target_label(k, s, d));
            assert!(left.is_empty(), "{row}: a refused move left objects on the target");
            continue;
        }
        assert_eq!(code(&out), 22, "{row}: {}", stderr(&out));
        let lock: toml::Value = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
        let origin = &lock["realisations"][spec.as_str()][d.name]["provenance"]["origin"];
        assert_eq!(origin["method"].as_str(), Some(method.as_str()), "{row}");
        assert_eq!(origin["exposure"].as_str() == Some("host"), through_host, "{row}: {origin}");
        let v = e.cakeys(d, &["check", "--spec", &spec, "--token", d.name]);
        assert_eq!(code(&v), 0, "{row}: cakeys check: {}", stderr(&v));
        // A re-run finds the key there, verifies it, and changes nothing.
        let again = std::fs::read(&lock_path).unwrap();
        let out = e.km(s, &args);
        assert_eq!(code(&out), 0, "{row}: the re-run: {}", stderr(&out));
        assert_eq!(std::fs::read(&lock_path).unwrap(), again, "{row}: the re-run changed the lock");
    }
    eprintln!("host moves:\n  {}", rows.join("\n  "));
    if e.refs.iter().any(|r| r.name == "softhsm") && e.refs.iter().any(|r| r.name == "kryoptic") {
        assert!(
            rows.iter().any(|r| r.contains("host-raw, plan ready")),
            "no secret key moved through the host into SoftHSM"
        );
    }
    if e.refs.iter().any(|r| r.name == "p11kit") {
        assert!(
            rows.iter().any(|r| r.contains("host-pkcs8, plan ready")),
            "no private key moved through the host into p11-kit"
        );
    }
    if e.refs.iter().any(|r| r.name == "tpm2") {
        assert!(
            rows.iter().any(|r| r.contains("tpm2-ptool, plan ready")),
            "no key moved into tpm2-pkcs11 through tpm2_ptool"
        );
    }
}

/// Checks `tpm2_ptool import` under a locator that names a `CKA_ID`. The key lands under that ID,
/// so `cakeys check` finds it by label and ID together. (The tool stores the text that it is given
/// as the ID's bytes. It once received cakeys' hex as that text, so the key landed under `30 61`
/// for `0a`, and nothing found it.) An ID that the tool cannot take as text is refused (17) before
/// anything reaches the TPM.
#[test]
fn tpm2_ptool_imports_under_the_locator_id() {
    let Some(e) = env("ptool-id") else { return };
    let Some([soft, tpm]) = e.needs("ptool-id", ["softhsm", "tpm2"]) else { return };
    let attributes = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let target = |spec: &str, id: &str| {
        format!(
            "[specs.{spec}]\nobject = \"pid\"\n{attributes}\
             tokens.tpm2 = {{ locator = {{ CKA_LABEL = \"{spec}\", CKA_ID = \"{id}\" }}, origin = \"import\" }}\n\n"
        )
    };
    let body = "[objects.pid]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n".to_owned()
        + &Env::spec("pid-src", "pid", attributes, &[soft], "pid-src", CREATE)
        + &target("pid-tpm", "0a01")
        + &target("pid-bad", "ff");
    e.config(&body);
    let o = e.cakeys(soft, &["create", "--spec", "pid-src", "--token", "softhsm"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let migrate = |spec: &'static str| {
        ["migrate", "pid", "--from", "softhsm", "--to", "tpm2", "--spec", spec, "--allow-host-plaintext"]
    };
    let o = e.km(soft, &migrate("pid-tpm"));
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let v = e.cakeys(tpm, &["check", "--spec", "pid-tpm", "--token", "tpm2"]);
    assert_eq!(code(&v), 0, "the key is not under CKA_ID 0a01: {}", stderr(&v));
    // No text spells the byte ff, so the ID is refused before the tool runs, and nothing lands
    // under the label.
    let o = e.km_alone(soft, &migrate("pid-bad"));
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    assert!(stderr(&o).contains("takes CKA_ID as text"), "{}", stderr(&o));
    let lock = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    assert!(!lock.contains("pid-bad"), "{lock}");
    let list = std::process::Command::new("pkcs11-tool")
        .args(["--module", &tpm.module, "--token-label", tpm.token_label, "--login", "--pin", "1234", "--list-objects"])
        .output()
        .unwrap();
    assert!(list.status.success(), "{}", String::from_utf8_lossy(&list.stderr));
    assert!(!String::from_utf8_lossy(&list.stdout).contains("pid-bad"), "an object was left on the TPM under pid-bad");
}

/// Checks the reopen after `tpm2_ptool import`, which opens the token again to see the key
/// (camigrate host.rs F1). A reopen that fails leaves the key in the TPM without a record, and the
/// run says so and says how to resolve it. `cakeys lock`, as the message says, then records the
/// key. tpm2-pkcs11 runs behind p11-fault, which answers the reopen's `C_Login` itself, so nothing
/// reaches the TPM. The reopen's login is the last login of a run, and the test counts the logins
/// on a move of the same shape without a fault.
#[test]
fn a_failed_reopen_after_ptool_says_what_is_in_the_tpm() {
    let Some(e) = env("ptool-reopen") else { return };
    let Some([soft, tpm]) = e.needs("ptool-reopen", ["softhsm", "tpm2"]) else { return };
    let (soft, tpm) = (soft.clone(), tpm.clone());
    let shimmed = Ref { module: fault_shim(), ..tpm.clone() };
    let e = Env { dir: e.dir.clone(), refs: vec![soft.clone(), shimmed] };
    let attributes = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let body = "[objects.pr]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n".to_owned()
        + &Env::spec("pr-src", "pr", attributes, &[&soft], "pr-src", CREATE)
        + &Env::spec("pr-a", "pr", attributes, &[&tpm], "pr-a", IMPORT)
        + &Env::spec("pr-b", "pr", attributes, &[&tpm], "pr-b", IMPORT);
    e.config(&body);
    assert_eq!(code(&e.cakeys(&soft, &["create", "--spec", "pr-src", "--token", "softhsm"])), 22);
    let faulted = |name: &str, plan: &str, spec: &str| {
        let (path, trace) = (e.dir.join(format!("{name}.toml")), e.dir.join(format!("{name}.jsonl")));
        std::fs::write(&path, plan).unwrap();
        let _ = std::fs::remove_file(&trace);
        let env = ref_env(&[
            ("P11_FAULT_MODULE", &tpm.module),
            ("P11_FAULT_PLAN", &path.display().to_string()),
            ("P11_FAULT_TRACE", &trace.display().to_string()),
        ]);
        let args = ["migrate", "pr", "--from", "softhsm", "--to", "tpm2", "--spec", spec, "--allow-host-plaintext"];
        let o = e.km_alone(&Ref { env, ..soft.clone() }, &args);
        let logins =
            std::fs::read_to_string(&trace).unwrap_or_default().lines().filter(|l| l.contains("\"C_Login\"")).count();
        (o, logins)
    };
    // With a rule that never fires, the move goes through, and its logins are counted.
    let (o, logins) = faulted("count", "[[rule]]\nfn = \"C_Login\"\ncall = 999\nrv = \"CKR_DEVICE_ERROR\"\n", "pr-a");
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert!(logins >= 2, "the import and the reopen each log in: {logins}");
    let plan = format!("[[rule]]\nfn = \"C_Login\"\ncall = {logins}\nrv = \"CKR_DEVICE_ERROR\"\n");
    let (o, _) = faulted("reopen", &plan, "pr-b");
    assert_ne!(code(&o), 0, "{}", stderr(&o));
    assert!(
        stderr(&o).contains("tpm2_ptool imported the key, but the token could not be opened again"),
        "{}",
        stderr(&o)
    );
    assert!(stderr(&o).contains("cakeys lock --spec pr-b --token tpm2"), "{}", stderr(&o));
    let lock = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    assert!(!lock.contains("pr-b"), "{lock}");
    // As the note says, the key is recorded where it is, and it verifies (through the shim, with
    // no fault plan).
    let through = Ref { env: ref_env(&[("P11_FAULT_MODULE", &tpm.module)]), ..tpm.clone() };
    let o = e.cakeys(&through, &["lock", "--spec", "pr-b", "--token", "tpm2"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(&through, &["check", "--spec", "pr-b", "--token", "tpm2"])), 0);
}

/// Checks that the landing checks run on the pair that `--spec` picks. An object with two import
/// pairs on the target once skipped all of them (the plan looked for its one pair, found two, and
/// checked nothing), so an attestation that the target's provider cannot give for an imported key
/// (PIV) was not refused before the move wrote the key. kryoptic stands in for the device, with its
/// token named `piv` and bound to the `ykcs11` provider, and each pair in a PIV slot by `CKA_ID`.
/// (Under a label, the placement check refuses first: `placement_is_planned_where_a_move_lands`.)
/// Without `--spec`, the plan says that it cannot pick a pair.
#[test]
fn landing_checks_follow_the_spec_named() {
    let Some(e) = env("landing-spec") else { return };
    let Some([soft, kry]) = e.needs("landing-spec", ["softhsm", "kryoptic"]) else { return };
    let so = e.dir.join("so-pin");
    std::fs::write(&so, "5678\n").unwrap();
    let attributes = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let landing = |spec: &str, id: &str, extra: &str| {
        format!(
            "[specs.{spec}]\nobject = \"ls\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.piv = {{ locator = {{ CKA_ID = \"{id}\" }}, origin = \"import\"{extra} }}\n\n"
        )
    };
    let body = format!(
        "[tokens.piv]\nmodule = \"{}\"\ntokenLabel = \"{}\"\nprovider = \"ykcs11\"\npinFile = \"{}\"\nsoCredentialFile = \"{}\"\n\n",
        kry.module,
        kry.token_label,
        e.dir.join("pin").display(),
        so.display()
    ) + "[objects.ls]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n"
        + &Env::spec("ls-src", "ls", attributes, &[soft], "ls-src", CREATE)
        + &landing("ls-attested", "17", ", attestation = true")
        + &landing("ls-plain", "18", "");
    e.config(&body);
    let o = e.cakeys(soft, &["create", "--spec", "ls-src", "--token", "softhsm"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let plan = |spec: Option<&str>| {
        let mut args = vec!["migrate", "ls", "--from", "softhsm", "--to", "piv", "--allow-host-plaintext"];
        if let Some(s) = spec {
            args.extend(["--spec", s]);
        }
        args.extend(["--dry-run", "--json"]);
        let o = e.km_alone(soft, &args);
        let v: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap_or_default();
        (code(&o), v["plans"][0]["reasons"].to_string())
    };
    let (c, reasons) = plan(Some("ls-attested"));
    assert_eq!(c, 15, "{reasons}");
    assert!(reasons.contains("attests only keys the device generated"), "{reasons}");
    let (c, reasons) = plan(None);
    assert_eq!(c, 15, "{reasons}");
    assert!(reasons.contains("several specs"), "{reasons}");
    // The move itself refuses before anything reaches the target.
    let o = e.km_alone(
        soft,
        &["migrate", "ls", "--from", "softhsm", "--to", "piv", "--spec", "ls-attested", "--allow-host-plaintext"],
    );
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    let id = Attribute::Id(vec![0x17]);
    assert!(open_session(&kry.module, kry.token_label, "1234").find_objects(&[id]).unwrap().is_empty(), "imported");
}

/// Checks the host path's guards (docs/CAMIGRATE.md D6) into `SoftHSM` behind p11-kit, where the
/// plan sends an EC key through the host. A key is never imported over another key under the
/// target locator (13). A public half of the key that is already there is reused. When that public
/// half does not match the target spec's `publicAttributes`, the plan refuses it, in a dry run and
/// in a real run, before anything is created (13; the run once created the private key and then
/// removed it again). A target session without a login cannot tell whether the locator is free
/// (16).
#[test]
fn host_moves_refuse_what_they_cannot_check() {
    let Some(e) = env("host-guards") else { return };
    let Some([soft, fwd]) = e.needs("host-guards", ["softhsm", "p11kit"]) else { return };
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
    let o = e.cakeys(soft, &["create", "--spec", "hg-src", "--token", "softhsm"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let migrate = |spec: &str, to: &str| {
        e.km(soft, &["migrate", "hg", "--from", "softhsm", "--to", to, "--spec", spec, "--allow-host-plaintext"])
    };
    // A bundle carries only sealed keys and public objects, so the host path belongs to migrate,
    // and the plan of an export says so (it once said ready, and the export then refused).
    let export = ["export", "hg", "--from", "softhsm", "--to", "p11kit", "--allow-host-plaintext"];
    let plan = e.km(soft, &[&export[..], &["--dry-run"]].concat());
    assert_eq!(code(&plan), 15, "{}", stdout(&plan));
    assert!(stdout(&plan).contains("not host-pkcs8: move it with `camigrate migrate`"), "{}", stdout(&plan));
    let out = e.dir.join("hg.bundle.toml");
    assert_eq!(code(&e.km(soft, &[&export[..], &["--out", out.to_str().unwrap()]].concat())), 15);
    assert!(!out.exists());
    // Open the target token directly (the p11-kit forwarder serves this SoftHSM token).
    let direct = std::env::var("CAKEYS_TEST_MODULE").unwrap();
    let target = || open_session(&direct, "kmp11", "1234");
    let p256 = P256.to_vec();

    // Put another key under the target locator.
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
    // The message says how to record a key that an earlier run moved there but could not record
    // (review 2026-11-23 C-21).
    assert!(stderr(&o).contains("`cakeys lock --spec hg-dst --token p11kit` records it"), "{}", stderr(&o));

    // The key's own public half, but without CKA_VERIFY, is refused before the import.
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
    let left =
        target().find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Label(b"hg-dst".to_vec())]);
    assert_eq!(left.unwrap().len(), 0, "the imported private key was left on the target");
    let lock = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    assert!(!lock.contains("[realisations.hg-dst"), "{lock}");

    // Without a login on the target, the run cannot know whether the locator is free.
    let o = migrate("hg-anon", "p11kit-anon");
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("without login cannot tell a target locator is free"), "{}", stderr(&o));
}

/// Plants the fixture P-256 key whose certificate is `FIXTURE_CERT` on `soft` under `xf-k`: the
/// private key (extractable), its public key and the certificate.
fn plant_fixture_key(soft: &Ref) {
    let src = open_session(&soft.module, soft.token_label, "1234");
    let pem =
        std::fs::read_to_string(format!("{}/../cli/tests/fixtures/tpm-import-p256.pem", env!("CARGO_MANIFEST_DIR")))
            .unwrap();
    let der = x509_cert::der::pem::decode_vec(pem.as_bytes()).unwrap().1;
    let cakeys_core::plaintext::PrivateParts::Ec(scalar) = cakeys_core::plaintext::private_from_pkcs8(
        &der,
        cakeys_core::types::KeyType::Ec,
        Some(cakeys_core::id::Curve::P256),
    )
    .unwrap() else {
        panic!("not an EC key")
    };
    let label = || Attribute::Label(b"xf-k".to_vec());
    src.create_object(&[
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC),
        Attribute::EcParams(P256.to_vec()),
        Attribute::Value(scalar.to_vec()),
        Attribute::Token(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(true),
        label(),
    ])
    .unwrap();
    let mut public = point_key(FIXTURE_CERT, KeyType::EC, P256);
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

/// Checks that `import --dry-run` of the key file `p12` on kryoptic checks the file against the
/// lock and the token and changes neither, and that a `--spec` that selects nothing is refused
/// (17).
fn key_file_dry_run(e: &Env, kry: &Ref, p12: &std::path::Path, pass: &std::path::Path) {
    let before = std::fs::read(e.dir.join("keys.lock")).unwrap();
    let dry = |extra: &[&str]| {
        let (file, pass) = (p12.to_str().unwrap(), pass.to_str().unwrap());
        let args = ["import", "--to", "kryoptic", "--in", file, "--passphrase-file", pass];
        e.km(kry, &[&args[..], &["--allow-host-plaintext", "--dry-run"], extra].concat())
    };
    let o = dry(&[]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&o.stdout).unwrap();
    let row =
        |object: &str| rows.iter().find(|r| r["object"] == object).unwrap_or_else(|| panic!("{object}: {rows:?}"));
    assert_eq!(
        (row("fk")["method"].as_str(), row("fk")["outcome"].as_str()),
        (Some("pkcs12"), Some("ready")),
        "{rows:?}"
    );
    assert_eq!(row("fc")["outcome"].as_str(), Some("ready"), "{rows:?}");
    assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), before, "a dry run changed the lock");
    for spec in ["nosuch", "fk-soft"] {
        let o = dry(&["--spec", spec]);
        assert_eq!(code(&o), 17, "--spec {spec}: {}", stderr(&o));
    }
}

/// Checks key files (docs/CAMIGRATE.md D2 `file`, phase 4b). One private key leaves `SoftHSM`
/// through the host as encrypted PKCS#8, or as PKCS#12 with the certificate that the lock pairs
/// with it, with mode 0600, and unreadable without the passphrase. kryoptic refuses a wrong
/// passphrase (17: bad input, not other material), and a `--dry-run` checks the file; neither
/// leaves anything. kryoptic then imports the PKCS#12 (key and certificate), records it as from a
/// `file`, and verifies both. The PKCS#8 of the same key is then already there. A `--spec` that
/// selects nothing is refused (17).
#[test]
fn key_files_carry_one_key_and_its_certificate() {
    let Some(e) = env("key-files") else { return };
    let named = |n: &str| e.refs.iter().find(|r| r.name == n);
    let Some([soft, kry]) = e.needs("key-files", ["softhsm", "kryoptic"]) else { return };
    plant_fixture_key(soft);
    let key_attrs = "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n";
    let body = "[objects.fk]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [objects.fc]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\n"
        .to_owned()
        + &Env::spec("fk-soft", "fk", key_attrs, &[soft], "xf-k", "")
        + &Env::spec("fc-soft", "fc", "", &[soft], "xf-k", "")
        + &Env::spec("fk-kry", "fk", key_attrs, &[kry], "xf-k", IMPORT)
        + &Env::spec("fc-kry", "fc", "", &[kry], "xf-k", IMPORT)
        // The key alone goes on the third token, where the lock pairs no certificate with it.
        + &named("kryoptic-der").map_or_else(String::new, |der| Env::spec("fk-der", "fk", key_attrs, &[der], "xf-k2", IMPORT));
    e.config(&body);
    for spec in ["fk-soft", "fc-soft"] {
        let o = e.cakeys(soft, &["lock", "--spec", spec, "--token", "softhsm"]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
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
                "--from",
                "softhsm",
                "--to-key-file",
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
                "--to",
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
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    let origin = &lock["realisations"]["fk-kry"]["kryoptic"]["provenance"]["origin"];
    assert_eq!(
        (origin["from"].as_str(), origin["method"].as_str(), origin["exposure"].as_str()),
        (Some("file"), Some("pkcs12"), Some("file"))
    );
    for spec in ["fk-kry", "fc-kry"] {
        assert_eq!(code(&e.cakeys(kry, &["check", "--spec", spec, "--token", "kryoptic"])), 0, "{spec}");
    }
    let o = import(&p8, &pass);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("already realised"), "{}", stderr(&o));
    // Where the lock pairs no certificate with the key, the PKCS#12's key is imported and its
    // certificate is not, and both the plan and the run say so.
    if let Some(der) = named("kryoptic-der") {
        let (file, pass) = (p12.to_str().unwrap(), pass.to_str().unwrap());
        let args = ["import", "--to", "kryoptic-der", "--in", file, "--passphrase-file", pass];
        let o = e.km(der, &[&args[..], &["--allow-host-plaintext", "--dry-run"]].concat());
        assert!(stderr(&o).contains("the file's certificate would not be imported"), "{}", stderr(&o));
        let o = e.km(der, &[&args[..], &["--allow-host-plaintext"]].concat());
        assert_eq!(code(&o), 22, "{}", stderr(&o));
        assert!(stderr(&o).contains("the file's certificate is not imported"), "{}", stderr(&o));
        assert_eq!(code(&e.cakeys(der, &["check", "--spec", "fk-der", "--token", "kryoptic-der"])), 0);
    }
}

/// Checks that `--config` names the keys.toml, and with it the lock: the lock of `site.toml` is
/// `site.lock` next to it, unless `--lock` names another file. No token is needed, because a lock
/// that does not parse stops the run before any token opens, and the message names the file that
/// the run read.
#[test]
fn the_lock_follows_the_config_path() {
    let w = Workdir::new("config-path");
    let config = w.dir.join("site.toml");
    let pin = w.dir.join("pin");
    let token = |t: &str| format!("[tokens.{t}]\nmodule = \"/nonexistent/{t}.so\"\ntokenLabel = \"{t}\"\n");
    let tokens = format!("{}pinFile = \"{}\"\n\n{}", token("a"), pin.display(), token("b"));
    std::fs::write(&config, tokens + &format!("pinFile = \"{}\"\n", pin.display())).unwrap();
    std::fs::write(w.dir.join("site.lock"), "not a lock [").unwrap();
    std::fs::write(w.dir.join("keys.lock"), "not a lock either [").unwrap();
    let run = |more: &[&str]| {
        let at = ["--config", config.to_str().unwrap()];
        let args = [&at[..], more, &["migrate", "--from", "a", "--to", "b", "--dry-run"]].concat();
        tool(BIN).args(args).current_dir(&w.dir).output().unwrap()
    };
    let o = run(&[]);
    assert_ne!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("site.lock") && !stderr(&o).contains("keys.lock"), "{}", stderr(&o));
    let other = w.dir.join("other.lock");
    std::fs::write(&other, "also not a lock [").unwrap();
    let o = run(&["--lock", other.to_str().unwrap()]);
    assert_ne!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("other.lock") && !stderr(&o).contains("site.lock"), "{}", stderr(&o));
}
