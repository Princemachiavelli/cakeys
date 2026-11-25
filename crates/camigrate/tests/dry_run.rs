//! The move matrix across the reference tokens (docs/CAMIGRATE.md D9): the plan follows each side's
//! capabilities, a transport file carries the locked identity, and a real `migrate` does exactly
//! what its `--dry-run` says. Realisations are recorded and checked with `cakeys` (built beside
//! camigrate, `common::sibling`), plans made and objects moved with camigrate. A reference takes
//! part when its suite's variables are set, as in `cakeys`' tests/references.rs; skipped with
//! fewer than two.
//!
//! Each test has token sets of its own (nextest, one process and one token set per test:
//! nix/test-tokens.sh), so nothing here clears what another test left; plain `cargo test` with
//! tokens is unsupported (ISSUES.md). A test clears only what it made itself (review `dry_run.rs`
//! F7: clears of labels another test might have left suggested shared tokens).

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use cakeys_core::config::ALLOW_NIX_STORE_KEYS;
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
/// The dry-run twin compares every token a move names (review xref.rs F1): `kryoptic-der` reads
/// kryoptic's token through another configuration, and a move naming it compares that token,
/// once. It compared none, so a dry run writing to the target there would have passed.
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
        // Allowed, the host path is still no export's: a bundle carries sealed keys only.
        let (c, v) = plan(soft, &["movable", "--to", "tpm2", "--allow-host-plaintext"]);
        assert_eq!((c, first(&v).2), (15, Some(false)), "{v}");
        assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("move it with `camigrate migrate`"), "{v}");
        // Its notes: why no sealed way carries it (review plan.rs F2, said first), then what the
        // target changes about the key. Looked up, not by position.
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
    // PKCS#12 carries the key with its certificate, and the lock pairs none with this key: said
    // in the plan, as the export itself would refuse it.
    let (c, v) = plan(soft, &["movable", "--to-key-file", "pkcs12", "--allow-host-plaintext"]);
    assert_eq!((c, first(&v)), (15, (some("pkcs12"), some("file"), Some(false))), "{v}");
    assert!(v["plans"][0]["reasons"][0].as_str().unwrap().contains("pairs no certificate"), "{v}");
    // Every object on the source: one plan each. Without names the export takes what can move,
    // so its plan is 0 with the blocked one shown, as the export itself is.
    let (c, v) = plan(soft, &["--to", "kryoptic"]);
    assert_eq!((c, v["plans"].as_array().map(Vec::len)), (0, Some(2)), "{v}");
    assert_eq!(v["plans"].as_array().unwrap().iter().filter(|p| p["ready"] == false).count(), 1, "{v}");
    let o = e.km(soft, &["export", "movable", "--from", "softhsm", "--to", "kryoptic"]);
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
    // A source plans from the file alone, sealing to the transport key named for --to, the
    // file's token (keys.toml names none for kryoptic here, so --transport-spec does).
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

/// Two references on one token through one module (kryoptic and kryoptic-der) cannot both be
/// opened in one process with their own settings: no move between them.
fn same_token(a: &Ref, b: &Ref) -> bool {
    a.module == b.module && a.token_label == b.token_label
}

/// Every (item, source, target) of a move matrix: each item on each source that `holds` it,
/// to each target on another token. Each matrix had its own copy (review `dry_run.rs` F3).
fn matrix<'a, T>(items: &'a [T], refs: &'a [Ref], holds: impl Fn(&Ref, &T) -> bool) -> Vec<(&'a T, &'a Ref, &'a Ref)> {
    items
        .iter()
        .flat_map(|i| refs.iter().map(move |s| (i, s)))
        .filter(|(i, s)| holds(s, i))
        .flat_map(|(i, s)| refs.iter().filter(move |d| !same_token(s, d)).map(move |d| (i, s, d)))
        .collect()
}

/// Sources make extractable keys: not tpm2-pkcs11 (its keys never leave the TPM), and not
/// Edwards keys through p11-kit (the RPC drops their generation); kryoptic-der reads kryoptic.
fn generates(r: &Ref, k: &Key) -> bool {
    matches!(r.plant, Plant::Create) && !(k.name == "k-ed25519" && r.name == "p11kit")
}

/// A certificate's SPKI, from its DER (`common::spki` builds one from its parts).
fn cert_spki(cert: &[u8]) -> Vec<u8> {
    x509_cert::Certificate::from_der(cert).unwrap().tbs_certificate().subject_public_key_info().to_der().unwrap()
}

/// A certificate's subject key as a public key object: an EC or Edwards point as a DER OCTET
/// STRING, beside the curve's parameters.
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

/// The dry-run property for the `public` rows (docs/CAMIGRATE.md D9, phase 2): for every public class,
/// source and target reference, `migrate --dry-run`'s verdict is the outcome. A ready plan moves
/// the object, records it with its `origin`, and `cakeys check` then accepts it on the target —
/// the lock camigrate wrote loads, and the identity survived the move. A blocked plan is 15, the
/// lock unchanged, the target locator empty.
#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn public_moves_do_what_the_plan_says() {
    let Some(e) = env("public-moves") else { return };
    // A source holds the class when it was planted there; kryoptic-der reads kryoptic's token.
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
            // The same verdict for `export`: a public object needs no transport key (neither
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

/// The locator guard is per class (`Token::occupied`): PKCS#11 puts a key, its public key and
/// its certificate under one label, so they move into one target label in either order. The
/// key's import and the public key object's share one public key object (whichever comes first
/// creates it, the other records it); a second object of a class already there is still 13,
/// leaving nothing.
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
    // A second certificate for the first target label: a collision of its class.
    body += &Env::spec("crt2-kry-a", "crt2", "", &[kry], "sl-a", IMPORT);
    names_transport(&e, &body, |r| r.name == "kryoptic");
    assert_eq!(code(&e.cakeys(kry, &["create", "--spec", "tk-kryoptic", "--token", "kryoptic"])), 22);
    // The keys are made; their public halves and the planted certificates are adopted.
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
    // A --spec that selects nothing, unknown or another object's pair, is refused (17) by the dry
    // run as by the run, which exits as its dry run did (D9; review 2026-11-23 C-2: the dry run
    // said ready). Nothing moves.
    for spec in ["nope", "k2-kry"] {
        let named = ["migrate", "k1", "--from", "softhsm", "--to", "kryoptic", "--spec", spec];
        for extra in [&["--dry-run"][..], &[]] {
            let o = e.km(soft, &[&named[..], extra].concat());
            assert_eq!(code(&o), 17, "{spec} {extra:?}: {}", stderr(&o));
            assert!(stderr(&o).contains(&format!("--spec '{spec}'")), "{spec} {extra:?}: {}", stderr(&o));
        }
    }
    assert_eq!(on_target("sl-a"), 0, "a refused --spec moved something");
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
    // Without names an export takes what can move: here nothing, the private object said.
    let o = e.km(soft, &["export", "--from", "softhsm", "--to", "kryoptic"]);
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
    e.config_with(body, &|r| {
        if holds(r) { format!("migrate = {{ transportWith = \"tk-{}\" }}\n", r.name) } else { String::new() }
    });
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
/// 0, records its `origin`, and `cakeys check` then accepts the key on the target — proving
/// possession, so the unwrapped key is the locked one; a blocked one is 15 with the lock
/// unchanged and nothing on the target.
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
    // p11-kit hides the module behind it, so its capabilities are a spec-compliant module's until
    // keys.toml names that module's provider (docs/ARCHITECTURE.md, "Providers"): this one forwards `SoftHSM`, whose
    // unwrapped secret keys lose their length (`move.secret-unwrap` no).
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
            assert_eq!(code(&out), 22, "{row}: {}", stderr(&out));
            let lock: toml::Value = toml::from_str(&std::fs::read_to_string(&lock_path).unwrap()).unwrap();
            let origin = &lock["realisations"][spec.as_str()][d.name]["provenance"]["origin"];
            assert_eq!(origin["from"].as_str(), Some(s.name), "{row}");
            assert_eq!(origin["method"].as_str(), Some(method.as_str()), "{row}");
            let v = e.cakeys(d, &["check", "--spec", &spec, "--token", d.name]);
            assert_eq!(code(&v), 0, "{row}: cakeys check: {}", stderr(&v));
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
/// IDs are 17 or 10 — and after: tampered bytes do not unwrap (13, or 16 where the module says
/// only that it failed: [`tampered_unwrap`]), and the blobs of another key unwrap into material
/// that is not the locked one (a private key fails its proof of possession, 13; a secret key its
/// commitment, 10). Neither leaves anything on the target. A transport file for a key the lock
/// does not pin is no channel at all.
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
    for (path, why) in [(&ek1, "is not realised on 'kryoptic'"), (&export(&["crt"]), "the lock pins no IDs")] {
        let args = ["--lock", bare.to_str().unwrap(), "import", "--to", "kryoptic", "--in", path.to_str().unwrap()];
        let o = e.km(kry, &args);
        assert_eq!(code(&o), 14, "{}", stderr(&o));
        assert!(stderr(&o).contains(why), "{}", stderr(&o));
    }
    // A flipped byte in the wrapped key: RFC 5649's integrity check refuses it, and the run says
    // so as the module's return value allows (review sealed.rs F2).
    let (want, said) = tampered_unwrap(kry);
    let o = refused(text.replace(key_blob, &base64_flip(key_blob)), want, "a tampered blob");
    assert!(said.iter().all(|s| o.contains(s)), "a tampered blob: expected {said:?} in {o}");
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

/// What an import into `r` exits with for a tampered RFC 5649 blob, and what it says: 13 and
/// "tampered with" where the module says the wrapped data is invalid; 16 where it says only that
/// it failed, said as what may be a damaged bundle — kryoptic's `CKR_DEVICE_ERROR` \[run\].
fn tampered_unwrap(r: &Ref) -> (i32, &'static [&'static str]) {
    if r.name.starts_with("kryoptic") {
        (16, &["CKR_DEVICE_ERROR", "damaged or altered bundle"])
    } else {
        (13, &["the bundle was tampered with"])
    }
}

/// The bundle's key type is held to the lock and to keys.toml, each on its own: a bundle of
/// `ek1` as a P-384 key is refused (14) when the lock agrees with it and keys.toml does not, and
/// when keys.toml agrees and the lock does not.
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

/// `--transport-spec` names the transport key and `--lock` the lock file, as `transportWith` and
/// the default path do: a plan with either is the plan without, and one naming a spec that is no
/// transport key there, or a new lock that records nothing, is blocked. A lock that is not there
/// is refused (17): only `--new-lock` reads it as empty.
fn named_transport_key_and_lock(e: &Env, soft: &Ref) {
    let plan = ["export", "ek1", "--from", "softhsm", "--to", "kryoptic", "--dry-run"];
    let with = |extra: &[&str]| code(&e.km(soft, &[&plan[..], extra].concat()));
    assert_eq!(with(&["--transport-spec", "tk-kryoptic"]), 0);
    assert_eq!(with(&["--transport-spec", "ek1-kry"]), 15);
    // `migrate` names its transport key the same way (review 2026-11-23 D-23: no test ran it).
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

/// A bundle file's EC key under `binding = "token-asserted"` (sealed.rs F1): the transport key is
/// public, so anyone can seal a key of their own beside the lock's IDs and `publicKey`, and on a
/// target that keeps no point with the unwrapped key only a proof ties the two. `import --in`
/// refuses it (14) before the target is touched, dry run or not, and records nothing; the same
/// key under `pop-sign` imports, and `migrate`, whose bundle never leaves the process, still
/// moves the asserted one.
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
    // Proven, the same kind of key imports from a file.
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", export_bundle(&e, soft, &["tp"]).to_str().unwrap()]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    // In one process, nothing but the locked source made the bundle.
    let o = e.km(soft, &["migrate", "ta", "--from", "softhsm", "--to", "kryoptic", "--spec", "ta-kry"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["check", "--spec", "ta-kry", "--token", "kryoptic"])), 0);
}

/// `export` of `objects` from `SoftHSM` to kryoptic, into a bundle file: its path.
fn export_bundle(e: &Env, soft: &Ref, objects: &[&str]) -> std::path::PathBuf {
    let path = e.dir.join(format!("{}.bundle.toml", objects.join("+")));
    let out = path.to_str().unwrap().to_owned();
    let args = [&["export"], objects, &["--from", "softhsm", "--to", "kryoptic", "--out", &out]].concat();
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
    let Some([soft, kry]) = e.needs("multi-bundles", ["softhsm", "kryoptic"]) else { return };
    bundle_keys(&e, soft, kry);
    let export = |objects: &[&str]| export_bundle(&e, soft, objects);
    let lock_path = e.dir.join("keys.lock");
    named_transport_key_and_lock(&e, soft);
    let import = |path: &std::path::Path| e.km(kry, &["import", "--to", "kryoptic", "--in", path.to_str().unwrap()]);
    let empty = |label: &str| open_session(&kry.module, kry.token_label, "1234").labelled(label).is_empty();
    let read = |p: &std::path::Path| -> toml::Value { toml::from_str(&std::fs::read_to_string(p).unwrap()).unwrap() };
    // One bundle per export: two keys, one shared KEK. A dry run checks both and imports nothing.
    let both = export(&["ek1", "sk1"]);
    let b = read(&both);
    assert_eq!(b["keys"].as_array().map(Vec::len), Some(2), "{b}");
    assert!(b.get("kek").is_some(), "{b}");
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", both.to_str().unwrap(), "--dry-run"]);
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
    assert_eq!(code(&e.cakeys(kry, &["check", "--spec", "ek1-kry", "--token", "kryoptic"])), 0);
    // Its public half is made as a generated one: it verifies and is public, undeclared.
    assert_eq!(public_half(kry, "xb-ek1"), (true, false));
    // The whole bundle again: ek1 is already there and verifies, sk1 imports.
    let o = import(&both);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["check", "--spec", "sk1-kry", "--token", "kryoptic"])), 0);
    // Without names, every key that can move: the non-extractable one is warned about, left out.
    let out = e.dir.join("all.bundle.toml");
    let r = e.km(soft, &["export", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()]);
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
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    for spec in ["crt-kry", "ek2-kry", "sk2-kry"] {
        assert_eq!(code(&e.cakeys(kry, &["check", "--spec", spec, "--token", "kryoptic"])), 0, "{spec}");
    }
    // Named, all or nothing: an object that cannot move fails the export, and no bundle is written.
    let out = e.dir.join("never.bundle.toml");
    let r =
        e.km(soft, &["export", "ek2", "nx", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()]);
    assert_eq!(code(&r), 15, "{}", stderr(&r));
    assert!(!out.exists(), "a failed export wrote a bundle");
    // noExport, named: refused, with the spec that keeps it.
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

/// D8 and C-12: what a Nix build refuses, and what `ALLOW_NIX_STORE_KEYS` lets through.
fn refused_in_a_nix_build(e: &Env, soft: &Ref, pass: &str, bundle: &str) {
    // A key file is told from a bundle by what it holds, so the refused import names a real one.
    let key_file = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/keyfiles/p256.pkcs8.pem");
    // D8: an export, a key file's import and `transport --trust-on` are admin operations, and a
    // move writes the lock: each is refused inside a Nix build, before any token is opened, with
    // the one code of a refusal there (21, review 2026-11-23 C-12).
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
    // A build that makes and uses throwaway keys says so, and runs as outside one.
    let o = e.km_in_nix_build(soft, &[(ALLOW_NIX_STORE_KEYS, "1")], admin[0].0);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    std::fs::remove_file(bundle).unwrap();
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
    let Some([soft, kry]) = e.needs("refusals", ["softhsm", "kryoptic"]) else { return };
    bundle_keys(&e, soft, kry);
    let path = |name: &str| e.dir.join(name).to_str().unwrap().to_owned();
    let refused = |o: &std::process::Output, want: i32, what: &str| {
        assert_eq!(code(o), want, "{what}: {}", stderr(o));
        assert!(stderr(o).contains(what) || stdout(o).contains(what), "{what}: {} {}", stdout(o), stderr(o));
    };
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

    // A key file: its flags and its passphrase are input, wrong before any plan.
    let o =
        e.km_alone(soft, &["export", "ek1", "--from", "softhsm", "--to-key-file", "pkcs8", "--allow-host-plaintext"]);
    refused(&o, 17, "needs --out and --passphrase-file");
    let out = path("ek1.pem");
    let flags = ["--to-key-file", "pkcs8", "--out", &out, "--passphrase-file", &empty, "--allow-host-plaintext"];
    refused(
        &e.km_alone(soft, &[&["export", "ek1", "--from", "softhsm"][..], &flags].concat()),
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
    let import = ["import", "--to", "kryoptic", "--in", &out, "--passphrase-file", &pass, "--allow-host-plaintext"];
    refused(
        &e.km(kry, &[&["--new-lock", "--lock", &unpinned][..], &import].concat()),
        14,
        "pins no private key with this key's identity",
    );

    // Offline: the transport file on stdout is the one `--out` writes; an export sealed to it
    // needs no target, and the target imports and verifies the bundle.
    let transport = path("tk.transport.toml");
    let o = e.km(kry, &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        code(&e.km(kry, &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--out", &transport])),
        0
    );
    assert_eq!(stdout(&o).trim_end(), std::fs::read_to_string(&transport).unwrap().trim_end());
    // Named as cakeys' verbs name it, by its object, or not at all: the token's transportWith.
    for args in [&["transport", "tk-kryoptic", "--token", "kryoptic"][..], &["transport", "--token", "kryoptic"]] {
        let same = e.km(kry, args);
        assert_eq!((code(&same), stdout(&same)), (0, stdout(&o)), "{args:?}: {}", stderr(&same));
    }
    refused(&e.km(kry, &["transport", "--token", "softhsm-nope"]), 17, "unknown token 'softhsm-nope'");
    refused(
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
    // A --spec that does not realise the bundle's object there is refused before the import.
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", &sealed, "--spec", "ek1-kry"]);
    refused(&o, 17, "--spec 'ek1-kry' selects nothing");
    let o = e.km(kry, &["import", "--to", "kryoptic", "--in", &sealed]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(kry, &["check", "--spec", "sk2-kry", "--token", "kryoptic"])), 0);
    // A token the lock records nothing on has nothing to plan.
    if named("p11kit").is_some() {
        let o = e.km(soft, &["export", "--from", "p11kit", "--to", "kryoptic", "--dry-run"]);
        refused(&o, 14, "the lock records no realisation on token 'p11kit'");
    }
    the_transport_file_is_read_once(&e, soft, &transport);
    transport_files_and_bundle_entries_are_checked(&e, soft, &transport);
}

/// A transport file is read once (camigrate lib.rs F3): the plan checks against the lock the
/// very key the export seals to. Through a FIFO whose first read holds the pinned transport
/// key's file and any later read a copy naming another object, the bundle names the pinned one.
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
                // Not while the first read is still open: it would take both texts as one. With
                // no reader left, a nonblocking open for writing fails (ENXIO).
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
    // A run that read once leaves the writer waiting for a second reader: be it, and let it end.
    let reader = std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(&fifo).unwrap();
    writer.join().unwrap();
    drop(reader);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let bundle: toml::Value = toml::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert_eq!(bundle["transport"]["object"].as_str(), Some("tk-kryoptic"), "sealed to a second read: {bundle}");
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

    // The certificate has a spec on SoftHSM and on kryoptic, and none on the third token: a
    // bundle made for that token (a public object needs no transport key there) names it.
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

    // The lock still names tk-kryoptic as kryoptic's transport key; keys.toml no longer has it.
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

/// A transport file swapped in transit for another key the lock pins, with that key's real
/// identity and public key (here the certificate's RSA subject key), is refused by the plan and
/// by the export: the file must name the transport key of the token `--to` names, the one
/// `transportWith` or `--transport-spec` names, else whoever holds the other key's private half
/// unwraps the bundle (review 2026-11-23 C-1). A dev token's genuine file in prod's place is
/// `transport_files_are_bound_to_the_target_named`'s (review 2026-11-24 D-1).
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
    // Naming another key with --transport-spec does not make it one (no unwrap-only RSA key, or
    // none realised there: refused either way, naming it).
    let o = e.km(soft, &[&export[..], &["--dry-run", "--transport-spec", "crt-kry"]].concat());
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("'crt-kry'"), "{}", stdout(&o));
}

/// A move lands only on a pair that says `origin = "import"`: a target pair that says the key is
/// adopted there is refused, by the dry run as by the run, and by name, before anything moves.
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
    // Without a name the plan is blocked (15); naming the adopted pair is wrong input (17). Each
    // run its own code (review dry_run.rs F5: either was taken for all four).
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

/// A transport key is held to what the lock records of it (docs/CAMIGRATE.md D3): `transport`
/// refuses a key that is no RSA private key (17), one that may not unwrap and one that could
/// leave its token (14), and a plan naming such a key with `--transport-spec` is blocked (15).
/// An export without names in which nothing can move writes no bundle (15).
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
    let refused = |o: &std::process::Output, want: i32, what: &str| {
        assert_eq!(code(o), want, "{what}: {}", stderr(o));
        assert!(stderr(o).contains(what) || stdout(o).contains(what), "{what}: {} {}", stdout(o), stderr(o));
    };
    let transport = |r: &Ref, spec: &str, token: &str| e.km(r, &["transport", "--spec", spec, "--token", token]);
    refused(&transport(soft, "moves", "softhsm"), 17, "a transport key is an RSA private key");
    refused(&transport(kry, "signs", "kryoptic"), 14, "a transport key must allow CKA_UNWRAP");
    refused(&transport(kry, "leaves", "kryoptic"), 14, "a transport key must never leave the token");
    let plan = ["export", "moves", "--from", "softhsm", "--to", "kryoptic", "--dry-run"];
    for key in ["signs", "leaves"] {
        let o = e.km(soft, &[&plan[..], &["--transport-spec", key]].concat());
        refused(&o, 15, &format!("'{key}' on 'kryoptic' is no transport key"));
    }
    // Nothing moves: one key never leaves its token, the other has no transport key to go under.
    let out = e.dir.join("none.bundle.toml");
    let o = e.km(soft, &["export", "--from", "softhsm", "--to", "kryoptic", "--out", out.to_str().unwrap()]);
    refused(&o, 15, "nothing on 'softhsm' can go into a bundle");
    assert!(stderr(&o).contains("moves: left out of the bundle"), "{}", stderr(&o));
    assert!(!out.exists(), "an export of nothing wrote a bundle");
}

/// Two targets with a transport key each (`kryoptic` and `kryoptic-der`, `transportWith`), a
/// second transport key on `kryoptic` its `transportWith` does not name (`tk-alt`), and `mv`
/// on `SoftHSM`, which may move to `kryoptic`: the transport key bound to the target the operator
/// names (review 2026-11-24 D-1, D-8, D-10).
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

/// `refused`: exit `want`, saying `what` on stdout or stderr.
fn refused(o: &std::process::Output, want: i32, what: &str) {
    assert_eq!(code(o), want, "{what}: {} {}", stdout(o), stderr(o));
    assert!(stderr(o).contains(what) || stdout(o).contains(what), "{what}: {} {}", stdout(o), stderr(o));
}

/// A file in `e`'s directory, as an argument.
fn file_arg(e: &Env, name: &str) -> String {
    e.dir.join(name).to_str().unwrap().to_owned()
}

/// A TOML file, read.
fn read_toml(path: &str) -> toml::Table {
    toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// An export to a transport file names its target (`--to`), and the file must be that token's
/// (docs/CAMIGRATE.md D3; review 2026-11-24 D-1): another target's genuine file, its own key,
/// identity and public key (`kryoptic-der`'s, swapped in for `kryoptic`'s), is 17, dry or not,
/// and nothing is written. The bundle names its target, and so does the export's last line; a
/// bundle made for another target is refused there (14), dry or not.
#[test]
fn transport_files_are_bound_to_the_target_named() {
    let Some((e, [soft, kry, der])) = two_targets("bound-file") else { return };
    let dev = file_arg(&e, "dev.transport.toml");
    assert_eq!(code(&e.km(&der, &["transport", "--token", "kryoptic-der", "--out", &dev])), 0);
    let out = file_arg(&e, "swapped.bundle.toml");
    let o = e.km_alone(&soft, &["export", "mv", "--from", "softhsm", "--to-transport-file", &dev, "--out", &out]);
    assert_ne!(code(&o), 0, "an export to a transport file names no target: {}", stderr(&o));
    assert!(stderr(&o).contains("--to"), "{}", stderr(&o));
    assert!(!std::path::Path::new(&out).exists(), "sealed to the file's own target");
    let swapped = ["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--to-transport-file", &dev];
    for extra in [&["--dry-run"][..], &["--out", &out]] {
        refused(
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
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("for 'kryoptic-der'"), "{}", stderr(&o));
    let b = read_toml(&bundle);
    assert_eq!((b["version"].as_integer(), b["target"].as_str()), (Some(2), Some("kryoptic-der")), "{b}");
    assert_eq!(b["transport"]["object"].as_str(), Some("tk-kryoptic-der"), "{b}");
    for extra in [&["--dry-run"][..], &[]] {
        let o = e.km(&kry, &[&["import", "--to", "kryoptic", "--in", &bundle][..], extra].concat());
        refused(&o, 14, "the bundle is for 'kryoptic-der', not 'kryoptic'");
    }
}

/// An import holds a bundle's transport key to the target's own, as every export does
/// (`transportWith`, or `--transport-spec`; docs/CAMIGRATE.md D3; review 2026-11-24 D-8): one
/// sealed to another key realised there (`tk-alt`, a transport key, but not the one named) is 14
/// before the token is touched, dry or not; named as the export named it, it imports. A
/// version-1 bundle, which names no target, is read with a warning.
#[test]
fn bundles_are_bound_to_the_targets_transport_key() {
    let Some((e, [soft, kry, _])) = two_targets("bound-bundle") else { return };
    let sealed_alt = file_arg(&e, "alt.bundle.toml");
    let to_alt = ["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--transport-spec", "tk-alt"];
    let o = e.km(&soft, &[&to_alt[..], &["--out", &sealed_alt]].concat());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    for extra in [&["--dry-run"][..], &[]] {
        let o = e.km(&kry, &[&["import", "--to", "kryoptic", "--in", &sealed_alt][..], extra].concat());
        refused(&o, 14, "sealed to 'tk-alt'");
        assert!(stderr(&o).contains("'tk-kryoptic'"), "{}", stderr(&o));
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
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("a version-1 bundle names no target"), "{}", stderr(&o));
}

/// Every path that takes a transport key from the lock holds it to the one rule (docs/CAMIGRATE.md
/// D3; review 2026-11-24 D-10, D-7): `transport --trust-on` refuses a 1024-bit key the lock
/// records (17) and makes no trusted copy; a transport key the lock does not record as
/// non-extractable is none, since unknown is no verdict: the plan blocks it (15), `transport`
/// refuses it (14).
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
    refused(&o, 15, "CKA_EXTRACTABLE");
    refused(&with(&kry, "unrecorded.lock", &["transport", "--token", "kryoptic"]), 14, "CKA_EXTRACTABLE");
    // A lock recording a 1024-bit transport key (one keys.toml declared without modulusBits).
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
    refused(&with(&soft, "small.lock", &trust), 17, "at least 2048 bits");
    let copy = open_session(&soft.module, soft.token_label, "1234").labelled("cakeys-transport-kryoptic-tk-kryoptic");
    assert!(copy.is_empty(), "a 1024-bit key was made trusted");
}

/// An export without names takes what can go, and ends as its dry run did when nothing can
/// (docs/CAMIGRATE.md D9; review 2026-11-24 D-6): a token that holds only its own transport
/// key, which never leaves, has nothing to export, and both say so (15). With a name, the key
/// is refused as one that never leaves (15).
#[test]
fn an_export_of_nothing_that_can_go_ends_as_its_plan() {
    let Some((e, [_, kry, der])) = two_targets("nothing-goes") else { return };
    let export = ["export", "--from", "kryoptic-der", "--to", "kryoptic"];
    refused(&e.km_alone(&der, &[&export[..], &["--dry-run"]].concat()), 15, "nothing on 'kryoptic-der' can go");
    let out = file_arg(&e, "nothing.bundle.toml");
    refused(&e.km(&der, &[&export[..], &["--out", &out]].concat()), 15, "nothing on 'kryoptic-der' can go");
    assert!(!std::path::Path::new(&out).exists(), "a bundle was written");
    let named = ["export", "tk-kryoptic-der", "--from", "kryoptic-der", "--to", "kryoptic", "--dry-run"];
    refused(&e.km_alone(&kry, &named), 15, "it never leaves 'kryoptic-der'");
}

/// A key file holds one key: an export to one without names, from a token where nothing can go,
/// ends as its plan does (17), which once said ready over no plan (review 2026-11-24 D-6's
/// sibling), and nothing is written.
#[test]
fn a_key_file_of_nothing_ends_as_its_plan() {
    let Some((e, [_, _, der])) = two_targets("no-key-file") else { return };
    let pass = file_arg(&e, "pass");
    std::fs::write(&pass, "correct horse\n").unwrap();
    let out = file_arg(&e, "nothing.p8");
    let export = ["export", "--from", "kryoptic-der", "--to-key-file", "pkcs8", "--allow-host-plaintext"];
    refused(&e.km_alone(&der, &[&export[..], &["--dry-run"]].concat()), 17, "a key file holds one key");
    let o = e.km(&der, &[&export[..], &["--out", &out, "--passphrase-file", &pass]].concat());
    refused(&o, 17, "a key file holds one key");
    assert!(!std::path::Path::new(&out).exists(), "a key file was written");
}

/// Where the module can place a key (`Provider::placement`) is planned where a move lands, as
/// the import asks it before its write (review 2026-11-24 D-2): into a PIV token (a `SoftHSM`
/// token bound to ykcs11, which places a key by `CKA_ID` alone, never under a label nor in f9's
/// attestation slot, `CKA_ID = "19"`), `migrate --dry-run` refuses as the run does (17), and
/// nothing reaches the token.
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
        let o = e.km_alone(soft, &[&migrate[..], &["--dry-run"]].concat());
        assert_eq!(code(&o), 17, "{spec}, dry: {} {}", stdout(&o), stderr(&o));
        assert!(stdout(&o).contains(said), "{spec}, dry: {}", stdout(&o));
        // The twin: the run refuses as its dry run did.
        let o = e.km(soft, &migrate);
        assert_eq!(code(&o), 17, "{spec}: {}", stderr(&o));
        assert!(stderr(&o).contains(said), "{spec}: {}", stderr(&o));
        assert_eq!(session().find_objects(&[]).unwrap().len(), before, "{spec}: an object reached the token");
    }
}

/// A target locator another key sits under is planned where a move lands, as the import asks it
/// before its write (docs/CAMIGRATE.md D6, If-None-Match; review 2026-11-24 D-3): `migrate
/// --dry-run` refuses (13) as the run does, which the dry-run twin once admitted after a ready
/// plan.
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
    refused(&e.km_alone(&soft, &[&migrate[..], &["--dry-run"]].concat()), 13, "would collide with");
    refused(&e.km(&soft, &migrate), 13, "would collide with");
    assert_eq!(open_session(&kry.module, kry.token_label, "1234").labelled("xbt-mv").len(), 2, "imported over it");
}

/// An export plans against the target `--to` names, whether it reaches the token or only its
/// transport file (review 2026-11-24 D-4: a transport file's plan asked none of the landing
/// rules): a landing pair that opts into an attestation kryoptic's provider cannot make is
/// refused by both plans and both exports (15), as by the import there and by a move, and
/// nothing is written.
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
        refused(&e.km_alone(&soft, &[&args[..], &["--dry-run"]].concat()), 15, said);
        refused(&e.km(&soft, &[&args[..], &["--out", &out]].concat()), 15, said);
        assert!(!std::path::Path::new(&out).exists(), "{extra:?}: a bundle was written");
    }
    refused(&e.km(&soft, &["migrate", "mv", "--from", "softhsm", "--to", "kryoptic"]), 15, said);
}

/// A token names its transport key (`transportWith`, docs/CAMIGRATE.md D3), and realising it records
/// its public key in the lock, held to the locked identity: a source then plans and exports to
/// that token from the lock alone, the target unreachable. Without the recorded key, a plan
/// from the lock is blocked; a `transportWith` that is no unwrap-only RSA key is invalid.
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
    // Named, not picked: without transportWith, the plan says how to name one.
    e.config(&body);
    assert_eq!(code(&e.cakeys(kry, &["create", "--spec", "tk-kryoptic", "--token", "kryoptic"])), 22);
    assert_eq!(code(&e.cakeys(soft, &["create", "--spec", "mv", "--token", "softhsm"])), 22);
    let o = e.km(soft, &["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--dry-run"]);
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("transportWith"), "{}", stdout(&o));
    // Realised before transportWith named it: no public key yet, so with kryoptic unreachable the
    // plan is blocked; realising it again records the key.
    names_transport(&e, &body, |r| r.name == "kryoptic");
    let away = format!("kryoptic={}", e.dir.join("absent.so").display());
    let plan = |e: &Env| {
        e.km(soft, &["--module", &away, "export", "mv", "--from", "softhsm", "--to", "kryoptic", "--dry-run"])
    };
    let o = plan(&e);
    assert_eq!(code(&o), 15, "{}", stdout(&o));
    assert!(stdout(&o).contains("records no public key"), "{}", stdout(&o));
    // With kryoptic in reach, the export asks the token for the key the lock lacks and says so;
    // `transport --trust-on` takes the key from the lock alone, and has none to take.
    let early = e.dir.join("early.bundle.toml");
    let o = e.km(soft, &["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--out", early.to_str().unwrap()]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("the lock records no public key for it yet"), "{}", stderr(&o));
    let o = e.km(kry, &["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--trust-on", "softhsm"]);
    assert_eq!(code(&o), 14, "{}", stderr(&o));
    assert!(stderr(&o).contains("records no public key for transport key"), "{}", stderr(&o));
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
    e.config_with(&body, &|r| {
        if r.name == "kryoptic" { "migrate = { transportWith = \"mv\" }\n".into() } else { String::new() }
    });
    assert_eq!(code(&e.km(soft, &["export", "mv", "--from", "softhsm", "--to", "kryoptic", "--dry-run"])), 17);
}

/// The sealed path at OAEP SHA-256, which `SoftHSM` cannot do: between two kryoptic tokens, the
/// second one initialised in this test in a slot of its own. Both are reached through one
/// kryoptic configuration naming both slots, which every run here carries.
#[test]
fn sealed_moves_wrap_with_oaep_sha256_between_kryoptic_tokens() {
    let Some(mut e) = env("oaep-sha256") else { return };
    let Some([kry]) = e.needs("oaep-sha256", ["kryoptic"]) else { return };
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
    // The dry run's exit is its plan's (review dry_run.rs F6).
    assert_eq!((code(&o), plan["plans"][0]["ready"].as_bool()), (0, Some(true)), "{plan}");
    assert_eq!(plan["plans"][0]["method"].as_str(), Some("rsa-oaep-sha256+aes-kwp"), "{plan}");
    let o = e.km(kry, &args);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(two, &["check", "--spec", "k-two", "--token", "kryoptic2"])), 0);
}

/// A key whose target spec declares `CKA_ALWAYS_AUTHENTICATE` moves as its plan says: kryoptic
/// to `SoftHSM`, whose ECDSA signs in one part only, proves possession with the per-use PIN
/// (`pop-sign-pin`) after the single-part sign the patched cryptoki adds. Before it, the plan
/// said ready and the move then failed its proof (15). The plan and the proof ask one check
/// (`cakeys_pkcs11::token::proof_refusal`).
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
    // The dry-run twin holds the move to the plan's verdict.
    let o = e.km(kry, &["migrate", "a", "--from", "kryoptic", "--to", "softhsm"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    assert_eq!(lock["realisations"]["a-dst"]["softhsm"]["binding"].as_str(), Some("pop-sign-pin"), "{lock}");
    assert_eq!(code(&e.cakeys(soft, &["check", "--spec", "a-dst", "--token", "softhsm"])), 0);
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
/// its SO trusted the target's transport key (`transport --trust-on`, with `soCredentialFile`), and
/// then by `CKM_RSA_AES_KEY_WRAP` under that trusted copy alone: each bundle entry carries its
/// own key-encryption key. kryoptic imports and verifies them. A wrap-with-trusted key on
/// kryoptic never moves: it cannot trust an RSA key (its profile's `move.trusted-wrap` row says no).
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
    // On kryoptic, `ek`'s public half is declared not to verify: the import makes it so.
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
    // The dry run's exit is its plan's: 0 ready, 15 blocked (review dry_run.rs F6).
    let plan = |o: &str, from: &Ref, to: &Ref| -> serde_json::Value {
        let out = e.km(from, &["migrate", o, "--from", from.name, "--to", to.name, "--dry-run", "--json"]);
        let p: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
        let want = if p["plans"][0]["ready"].as_bool() == Some(true) { 0 } else { 15 };
        assert_eq!(code(&out), want, "{p}");
        p
    };
    // Untrusted: blocked, naming the SO's step.
    let p = plan("ek", soft, kry);
    assert_eq!(p["plans"][0]["ready"].as_bool(), Some(false), "{p}");
    assert!(p["plans"][0]["reasons"][0].as_str().unwrap().contains("--trust-on softhsm"), "{p}");
    // The SO trusts the transport key, from the public key the lock records; again, nothing to do.
    let trust = ["transport", "--spec", "tk-kryoptic", "--token", "kryoptic", "--trust-on", "softhsm"];
    let o = e.km(soft, &trust);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // The trusted copy is the only trusted object there: the export has nothing to warn of.
    let narrow = e.dir.join("narrow.bundle.toml");
    let o = e.km(soft, &["export", "ek", "--from", "softhsm", "--to", "kryoptic", "--out", narrow.to_str().unwrap()]);
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
    // kryoptic cannot trust an RSA key: a wrap-with-trusted key there never leaves.
    let p = plan("kk", kry, soft);
    let reasons = p["plans"][0]["reasons"].to_string();
    assert!(p["plans"][0]["ready"] == false && reasons.contains("move.trusted-wrap row says no"), "{p}");
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
    // profileDirs is a top-level key: ahead of every table.
    let config = e.dir.join("keys.toml");
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, format!("profileDirs = [\"{}\"]\n\n{text}", profiles.display())).unwrap();
    for (spec, r) in [("tk-kryoptic", kry), ("tk-softhsm", soft), ("in-src", kry), ("out-src", soft)] {
        let o = e.cakeys(r, &["create", "--spec", spec, "--token", r.name]);
        assert_eq!(code(&o), 22, "{spec}: {}", stderr(&o));
    }
    // Into the side without RFC 5649: the composed method, unwrapped by CKM_RSA_AES_KEY_WRAP.
    let o = e.km(kry, &["migrate", "in", "--from", "kryoptic", "--to", "softhsm", "--spec", "in-dst"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert!(stderr(&o).contains("rsa-oaep-sha1+aes-kwp"), "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(soft, &["check", "--spec", "in-dst", "--token", "softhsm"])), 0);
    // Out of it, through a file: the sealed key with its own KEK, no shared one.
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
    // On the shared context (review dry_run.rs F2): its own initialize and finalize pulled the
    // module from under any other holder's session.
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

/// The dry-run property for the `host` rows (docs/CAMIGRATE.md D2, phase 4): with
/// `--allow-host-plaintext`, every move the plan sends through the host (`host-pkcs8`,
/// `host-raw`: a target that cannot unwrap the key, like `SoftHSM` for secret keys or p11-kit
/// without AES key wrap; `tpm2-ptool` into tpm2-pkcs11) moves, records its `origin` with the
/// `host` exposure, and `cakeys check` accepts the key on the target. Every other row runs
/// too: the dry run's exit is its plan's, and a blocked move is 15 with the lock and target
/// unchanged. Each host method the references allow moves at least one key.
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
        // Every row runs, as the sealed matrix's do (review dry_run.rs F1): a row the planner
        // wrongly blocks, or sends another way, fails here instead of being dropped.
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
        // A re-run finds the key there, verifies it and changes nothing.
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

/// `tpm2_ptool import` under a locator that names a `CKA_ID`: the key lands under that ID (the
/// tool stores the text it is given as the ID's bytes, and once took cakeys' hex for that text,
/// so the key landed under `30 61` for `0a` and nothing found it), so `cakeys check` finds it by
/// label and ID together. An ID the tool cannot take as text is refused (17) before anything
/// reaches the TPM.
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
    // No text spells the byte ff: refused before the tool runs, so nothing lands under the label.
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

/// After `tpm2_ptool import`, the token is opened again to see the key (camigrate host.rs F1):
/// a reopen that fails leaves the key in the TPM, unrecorded, and the run says so and how to
/// resolve it; `cakeys lock`, as it says, records it. tpm2-pkcs11 sits behind p11-fault, which
/// answers the reopen's `C_Login` itself (nothing reaches the TPM): the last login of a run,
/// counted on an unfaulted move of the same shape.
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
    // A rule that never fires: the move goes through, and its logins are counted.
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
    // As the note says: recorded where it is, it verifies (through the shim, with no plan).
    let through = Ref { env: ref_env(&[("P11_FAULT_MODULE", &tpm.module)]), ..tpm.clone() };
    let o = e.cakeys(&through, &["lock", "--spec", "pr-b", "--token", "tpm2"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(code(&e.cakeys(&through, &["check", "--spec", "pr-b", "--token", "tpm2"])), 0);
}

/// The landing checks are made on the pair `--spec` picks: an object with two import pairs on
/// the target once skipped them all (the plan looked for its one pair, found two and asked
/// nothing), so an attestation the target's provider cannot give of an imported key (PIV) was
/// not refused before the move wrote the key. kryoptic stands in for the device, its token named
/// `piv` and bound to the `ykcs11` provider, each pair in a PIV slot by `CKA_ID` (under a label,
/// placement refuses first: `placement_is_planned_where_a_move_lands`). Without `--spec` the plan
/// says it cannot pick.
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

/// The host path's guards (docs/CAMIGRATE.md D6), into `SoftHSM` behind p11-kit, where the plan
/// sends an EC key through the host: another key under the target locator is never imported
/// over (13); a public half of the key already there is reused, and when it is not what the
/// target spec's `publicAttributes` say, the private key just created is removed again (13);
/// a target session without login cannot tell the locator is free (16).
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
    // A bundle carries sealed keys and public objects: the host path is migrate's, and the plan
    // of an export says so (it once said ready, and the export then refused).
    let export = ["export", "hg", "--from", "softhsm", "--to", "p11kit", "--allow-host-plaintext"];
    let plan = e.km(soft, &[&export[..], &["--dry-run"]].concat());
    assert_eq!(code(&plan), 15, "{}", stdout(&plan));
    assert!(stdout(&plan).contains("not host-pkcs8: move it with `camigrate migrate`"), "{}", stdout(&plan));
    let out = e.dir.join("hg.bundle.toml");
    assert_eq!(code(&e.km(soft, &[&export[..], &["--out", out.to_str().unwrap()]].concat())), 15);
    assert!(!out.exists());
    // The target token itself, reached directly (the forwarder serves this SoftHSM token).
    let direct = std::env::var("CAKEYS_TEST_MODULE").unwrap();
    let target = || open_session(&direct, "kmp11", "1234");
    let p256 = P256.to_vec();

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
    // With how to record a key an earlier run moved there but could not record (review
    // 2026-11-23 C-21).
    assert!(stderr(&o).contains("`cakeys lock --spec hg-dst --token p11kit` records it"), "{}", stderr(&o));

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

/// `import --dry-run` of the key file `p12` on kryoptic checks it against the lock and the
/// token and changes neither; a `--spec` that selects nothing is refused (17).
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
        // The key alone on the third token: the lock pairs no certificate with it there.
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
    // certificate is not, said in the plan and in the run.
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

/// `--config` names the keys.toml, and with it the lock: `site.toml`'s is `site.lock` beside it,
/// unless `--lock` names another. No token is needed: a lock that does not parse stops the run
/// before any token opens, naming the file it read.
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
