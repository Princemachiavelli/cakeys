//! Identity: each scheme's ID against an independent host oracle, the schemes a lock pins,
//! and data and public key objects.

use super::*;

#[test]
fn secret_commitments_match_host_hmac() {
    let Some(e) = env("secret_commitments") else { return };
    // Non-sensitive so the test can read CKA_VALUE and compute the oracle on the host.
    e.config(
        r#"
[objects.mac]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.mac-sign]
object = "mac"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = false, CKA_EXTRACTABLE = true }
tokens.ref = { locator = { CKA_LABEL = "oracle-commitment" }, origin = "create" }

[objects.mac2]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.mac2-nosign]
object = "mac2"
attributes = { CKA_SIGN = false, CKA_SENSITIVE = false, CKA_EXTRACTABLE = true }
tokens.ref = { locator = { CKA_LABEL = "oracle-wrap-rebind" }, origin = "create" }
"#,
    );
    for (spec, object, label, key_type, mode) in [
        ("mac-sign", "mac", "oracle-commitment", "CKK_GENERIC_SECRET", "commitment"),
        ("mac2-nosign", "mac2", "oracle-wrap-rebind", "CKK_GENERIC_SECRET", "wrap-rebind"),
    ] {
        assert_eq!(e.code(&["create", "--spec", spec, "--token", "ref", "--update-lock"]), 0);
        assert_eq!(e.lock()["realisations"][spec]["ref"]["mode"].as_str(), Some(mode));
        let s = e.session();
        let h = s.labelled(label)[0];
        let value = match &s.get_attributes(h, &[AttributeType::Value]).unwrap()[0] {
            Attribute::Value(v) => v.clone(),
            a => panic!("{a:?}"),
        };
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&value).unwrap();
        mac.update(format!("key-management/v1/commitment/{key_type}/256").as_bytes());
        assert_eq!(e.locked_id(object, "commitment"), sri(&mac.finalize().into_bytes()), "{mode}");
    }
}

#[test]
fn two_specs_same_material() {
    let Some(e) = env("two_specs") else { return };
    // One object, two specs with different policy: sign-capable (commitment) and sign-less
    // (wrap-rebind). Same material must give the same material CA-ID.
    e.config(
        r#"
[objects.shared]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.shared-sign]
object = "shared"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = true }
tokens.ref = { locator = { CKA_LABEL = "shared-a" }, origin = "create" }

[specs.shared-nosign]
object = "shared"
attributes = { CKA_SIGN = false, CKA_SENSITIVE = true, CKA_EXTRACTABLE = true }
tokens.ref = { locator = { CKA_LABEL = "shared-b" }, origin = "adopt" }
"#,
    );
    assert_eq!(e.code(&["create", "--spec", "shared-sign", "--token", "ref", "--update-lock"]), 0);
    // Absent is NotFound, never a silent create.
    assert_eq!(e.code(&["lock", "--spec", "shared-nosign", "--token", "ref", "--no-update-lock"]), 11);
    let s = e.session();
    let a = s.labelled("shared-a")[0];
    s.copy_object(a, &[Attribute::Label(b"shared-b".to_vec()), Attribute::Sign(false)]).unwrap();
    // The replica verifies against the identity locked through the first spec.
    assert_eq!(e.code(&["lock", "--spec", "shared-nosign", "--token", "ref", "--update-lock"]), 0);
    let lock = e.lock();
    assert_eq!(lock["realisations"]["shared-sign"]["ref"]["mode"].as_str(), Some("commitment"));
    assert_eq!(lock["realisations"]["shared-nosign"]["ref"]["mode"].as_str(), Some("wrap-rebind"));
    assert_ne!(
        lock["realisations"]["shared-sign"]["ref"]["specDigest"],
        lock["realisations"]["shared-nosign"]["ref"]["specDigest"]
    );
    assert_eq!(e.code(&["check", "shared", "--spec", "shared-nosign"]), 0);
}

#[test]
fn a_secret_key_without_a_reverifiable_identity_is_refused() {
    let Some(e) = env("no_identity") else { return };
    let spec = |sign: bool, extra: &str| {
        format!(
            r#"
[objects.locked]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.locked-down]
object = "locked"
attributes = {{ CKA_SIGN = {sign}, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false, CKA_DERIVE = true }}
tokens.ref = {{ locator = {{ CKA_LABEL = "locked" }}, origin = "create"{extra} }}
"#
        )
    };
    e.config(&spec(false, ""));
    let v = e.km(&["validate"]);
    assert_eq!(code(&v), 17);
    assert!(stderr(&v).contains("declare a usage bit"), "{}", stderr(&v));
    assert_eq!(e.code(&["lock", "--spec", "locked-down", "--token", "ref", "--no-update-lock"]), 17);
    assert_eq!(e.session().labelled("locked"), []);
    // The per-token opt-in to weaker modes is gone from the schema (docs/DESIGN.md §3.4): on a
    // spec that is otherwise valid, the old key is refused as unknown.
    e.config(&spec(true, ""));
    assert_eq!(e.code(&["validate"]), 0);
    e.config(&spec(true, r#", identity.allow = ["host-at-import"]"#));
    let v = e.km(&["validate"]);
    assert_eq!(code(&v), 17);
    assert!(stderr(&v).contains("identity"), "{}", stderr(&v));
}

/// A known AES-256 value, planted several times with different usage bits: the host knows the
/// material, the token holds it sensitive and (mostly) non-extractable.
const AES_VALUE: [u8; 32] = *b"key-management aes test vector!!";

fn aes_oracle(scheme: &str) -> String {
    aes_commitment(&AES_VALUE, scheme)
}

#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn aes_commitments_match_host_oracles() {
    let Some(e) = env("aes_commitments") else { return };
    // (spec, label, SIGN, ENCRYPT, WRAP, EXTRACTABLE, mode, schemes computed)
    // aes-all goes first: it links the schemes the single-purpose specs then each check.
    let cases: [(&str, &str, bool, bool, bool, bool, &str, &[&str]); 5] = [
        ("aes-all", "aes-all", true, true, true, false, "commitment", &["cmac", "kcv-ecb", "kw"]),
        ("aes-kek", "aes-kek", false, false, true, false, "commitment", &["kw"]),
        ("aes-mac", "aes-mac", true, false, false, false, "commitment", &["cmac"]),
        ("aes-enc", "aes-enc", false, true, false, false, "commitment", &["kcv-ecb"]),
        // No usable usage bit, but extractable: a session copy gets every AES commitment.
        ("aes-x", "aes-x", false, false, false, true, "wrap-rebind", &["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"]),
    ];
    let s = e.session();
    let mut body = String::from(
        "[objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [objects.kek-gen]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.kek-gen]\nobject = \"kek-gen\"\n\
         attributes = { CKA_WRAP = true, CKA_UNWRAP = true, CKA_SIGN = false, CKA_ENCRYPT = false, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n\
         tokens.ref = { locator = { CKA_LABEL = \"kek-gen\" }, origin = \"create\" }\n",
    );
    for (spec, label, sign, enc, wrap, x, _, _) in cases {
        s.create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::AES),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Value(AES_VALUE.to_vec()),
            Attribute::Sign(sign),
            Attribute::Encrypt(enc),
            Attribute::Decrypt(true),
            Attribute::Wrap(wrap),
            Attribute::Sensitive(true),
            Attribute::Extractable(x),
        ])
        .unwrap();
        body += &format!(
            "\n[specs.{spec}]\nobject = \"aes\"\n\
             attributes = {{ CKA_SIGN = {sign}, CKA_ENCRYPT = {enc}, CKA_WRAP = {wrap}, CKA_SENSITIVE = true, CKA_EXTRACTABLE = {x} }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"adopt\" }}\n"
        );
    }
    e.config(&body);

    // Each spec computes what its usage bits allow; later specs must agree with earlier ones.
    for (spec, _, _, _, _, _, mode, schemes) in cases {
        let o = e.km(&["lock", "--spec", spec, "--token", "ref", "--update-lock"]);
        assert_eq!(code(&o), 0, "{spec}");
        let r: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        let got: Vec<&str> = r["ids"].as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(got, schemes, "{spec}");
        assert_eq!(r["mode"].as_str(), Some(mode), "{spec}");
        // A commitment is a fingerprint: replayable by whatever saw it once (no fresh proof).
        assert_eq!(r["assurance"].as_str(), Some("fingerprint"), "{spec}");
    }
    // cmac/kcv-ecb/kw are unchanged by kcv-ecb-dec joining (it only adds an ID).
    for scheme in ["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"] {
        assert_eq!(e.locked_id("aes", scheme), aes_oracle(scheme), "{scheme}");
    }
    // The lock never holds the token output itself, only its hash.
    let lock_text = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    assert!(!lock_text.contains(&{
        use base64::Engine;
        let mut m = <cmac::Cmac<aes::Aes256> as KeyInit>::new_from_slice(&AES_VALUE).unwrap();
        m.update(b"key-management/v1/cmac/CKK_AES/256");
        base64::engine::general_purpose::STANDARD.encode(m.finalize().into_bytes())
    }));

    assert_eq!(e.code(&["check", "aes.id.kw", "--spec", "aes-kek"]), 0);
    // aes-kek may only wrap: no CMAC is computed for it.
    assert_eq!(e.code(&["check", "aes.id.cmac", "--spec", "aes-kek"]), 15);
    assert_eq!(e.code(&["check", "aes.id.commitment", "--spec", "aes-kek"]), 15);

    // A scheme the spec can never compute is refused before anything is created.
    assert_eq!(e.code(&["check", "kek-gen.id.cmac"]), 15);
    assert_eq!(s.labelled("kek-gen"), []);

    // A generated, non-extractable KEK: stable identity across runs, deletable by it.
    let r = ["lock", "--spec", "kek-gen", "--token", "ref", "--no-update-lock"];
    let first = e.km(&["create", "--spec", "kek-gen", "--token", "ref", "--no-update-lock"]);
    assert_eq!(code(&first), 18);
    assert_eq!(got_hash(&e.km(&r)), got_hash(&first));
    assert_eq!(e.code(&recording(&r)), 0);
    assert_eq!(e.locked_id("kek-gen", "kw"), got_hash(&first));
    assert_eq!(e.code(&["delete", "--spec", "kek-gen", "--token", "ref", "--update-lock"]), 0);
    assert_eq!(e.code(&["verify", "--spec", "kek-gen", "--token", "ref"]), 11);
}

#[test]
fn disjoint_schemes_never_link_material() {
    let Some(e) = env("disjoint") else { return };
    // Two *different* AES keys: one may only sign (cmac), the other only wrap (kw).
    let s = e.session();
    for (label, value, sign, wrap) in [("only-mac", [1u8; 32], true, false), ("only-kek", [2u8; 32], false, true)] {
        s.create_object(&[
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::AES),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Value(value.to_vec()),
            Attribute::Sign(sign),
            Attribute::Wrap(wrap),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
        ])
        .unwrap();
    }
    e.config(
        r#"
[objects.k]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.k-mac]
object = "k"
attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }
tokens.ref = { locator = { CKA_LABEL = "only-mac" }, origin = "adopt" }

[specs.k-kek]
object = "k"
attributes = { CKA_WRAP = true, CKA_EXTRACTABLE = false }
tokens.ref = { locator = { CKA_LABEL = "only-kek" }, origin = "adopt" }
"#,
    );
    assert_eq!(e.code(&["lock", "--spec", "k-mac", "--token", "ref", "--update-lock"]), 0);
    // No shared scheme: the lock must not start claiming the KEK is the same material.
    assert_eq!(e.code(&["lock", "--spec", "k-kek", "--token", "ref", "--update-lock"]), 14);
    assert!(e.lock()["objects"]["k"]["ids"].get("kw").is_none());
    assert!(e.lock()["realisations"].get("k-kek").is_none());
}

#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn curves_and_rsa_sizes_match_an_independent_der_oracle() {
    let Some(e) = env("curves") else { return };
    let kinds = [
        ("p256", "keyType = \"CKK_EC\"\ncurve = \"secp256r1\""),
        ("p384", "keyType = \"CKK_EC\"\ncurve = \"secp384r1\""),
        ("p521", "keyType = \"CKK_EC\"\ncurve = \"P-521\""),
        ("ed25519", "keyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\""),
        ("ed448", "keyType = \"CKK_EC_EDWARDS\"\ncurve = \"Ed448\""),
        ("secp256k1", "keyType = \"CKK_EC\"\ncurve = \"secp256k1\""),
        ("bp256", "keyType = \"CKK_EC\"\ncurve = \"brainpoolP256r1\""),
        ("bp384", "keyType = \"CKK_EC\"\ncurve = \"brainpoolP384r1\""),
        ("rsa3072", "keyType = \"CKK_RSA\"\nmodulusBits = 3072"),
        ("rsa4096", "keyType = \"CKK_RSA\"\nmodulusBits = 4096"),
    ];
    let mut body = String::new();
    for (k, ty) in kinds {
        // No Ed448 verifier on the host: possession cannot be proven, so it is an explicit opt-in.
        let binding = if k == "ed448" { ", binding = \"token-asserted\"" } else { "" };
        body += &format!(
            "[objects.{k}]\nclass = \"CKO_PRIVATE_KEY\"\n{ty}\n\n\
             [specs.{k}-gen]\nobject = \"{k}\"\n\
             attributes = {{ CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{k}\" }}, origin = \"create\"{binding} }}\n\n\
             [specs.{k}-pub]\nobject = \"{k}\"\n\
             tokens.ref-anon = {{ locator = {{ CKA_LABEL = \"{k}\" }}, origin = \"adopt\", publicOnly = true }}\n\n"
        );
    }
    e.config(&body);
    assert_eq!(e.code(&["validate"]), 0);
    let s = e.session();
    for (k, ty) in kinds {
        let spec = format!("{k}-gen");
        // A curve the reference lacks is refused as unsupported, and nothing is left behind.
        if REF.missing_curves.iter().any(|c| ty.ends_with(&format!("curve = \"{c}\""))) {
            let o = e.km(&["create", "--spec", &spec, "--token", "ref", "--update-lock"]);
            assert_eq!(code(&o), 15, "{k}: {}", stderr(&o));
            assert_eq!(s.labelled(k), [], "{k}");
            continue;
        }
        assert_eq!(e.code(&["create", "--spec", &spec, "--token", "ref", "--no-update-lock"]), 18, "{k}");
        let o = e.km(&["lock", "--spec", &spec, "--token", "ref", "--update-lock"]);
        assert_eq!(code(&o), 0, "{k}");
        assert_eq!(e.locked_id(k, "rfc7093m4"), sri(&oracle_spki(&s, k)), "{k}");
        let binding = if k == "ed448" { "token-asserted" } else { "pop-sign" };
        assert_eq!(e.lock()["realisations"][&spec]["ref"]["binding"].as_str(), Some(binding), "{k}");
        // A proven key is a proof; one only the token asserts is public bytes.
        let r: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        let assurance = if k == "ed448" { "public" } else { "proof" };
        assert_eq!(r["assurance"].as_str(), Some(assurance), "{k}");
        // A fresh challenge each run: repeat to catch encoding quirks (high-S, short r or s).
        for _ in 0..8 {
            assert_eq!(e.code(&["verify", "--spec", &spec, "--token", "ref"]), 0, "{k}");
        }
        // Same identity through the public key object, without login.
        let pubs = format!("{k}-pub");
        assert_eq!(e.code(&["lock", "--spec", &pubs, "--token", "ref-anon", "--update-lock"]), 0, "{k}");
        assert_eq!(e.lock()["realisations"][&pubs]["ref-anon"]["binding"].as_str(), Some("token-asserted"), "{k}");
    }
    // Without the opt-in, an Ed448 key is refused up front.
    e.config(&body.replace(", binding = \"token-asserted\"", ""));
    assert_eq!(e.code(&["validate"]), 17);
    e.config(&body);
    // The curve is part of the object type: a P-384 key does not satisfy a P-256 spec.
    let text = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    std::fs::write(
        e.dir.join("keys.toml"),
        text.replace(
            "[objects.p384]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"",
            "[objects.p384]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
        ),
    )
    .unwrap();
    assert_eq!(e.code(&["resolve", "--spec", "p384-gen", "--token", "ref"]), 13);
}

#[test]
#[expect(clippy::format_push_string, reason = "the fixture TOML bodies are appended as += format!(...)")]
fn hmac_key_types_commit_with_their_own_hash() {
    use cryptoki::object::KeyType as K;
    let Some(e) = env("hmac_types") else { return };
    if !cryptoki_hmac_types_fixed(std::env::var("CAKEYS_TEST_REQUIRE").is_ok()) {
        return;
    }
    // SoftHSM wants HMAC keys at least as long as the hash output.
    let material = *b"hmac key types test vector, long enough for every hash in the set";
    let types = [
        ("CKK_SHA_1_HMAC", K::SHA_1_HMAC, 20),
        ("CKK_SHA224_HMAC", K::SHA224_HMAC, 28),
        ("CKK_SHA256_HMAC", K::SHA256_HMAC, 32),
        ("CKK_SHA384_HMAC", K::SHA384_HMAC, 48),
        ("CKK_SHA512_HMAC", K::SHA512_HMAC, 64),
    ];
    let s = e.session();
    let mut body = String::new();
    for (name, kt, len) in types {
        let label = format!("hmac-{name}");
        plant_secret(&s, &label, kt, &material[..len], &[Attribute::Sign(true)]);
        body += &format!(
            "[objects.{name}]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"{name}\"\nvalueLen = {len}\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ CKA_SIGN = true, CKA_EXTRACTABLE = false }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"adopt\" }}\n\n"
        );
    }
    body += "[objects.gen384]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA384_HMAC\"\nvalueLen = 48\n\n\
             [specs.gen384]\nobject = \"gen384\"\nattributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }\n\
             tokens.ref = { locator = { CKA_LABEL = \"hmac-gen384\" }, origin = \"create\" }\n";
    e.config(&body);
    for (name, _, len) in types {
        assert_eq!(e.code(&["lock", "--spec", name, "--token", "ref", "--update-lock"]), 0, "{name}");
        let label = format!("key-management/v1/commitment/{name}/{}", len * 8);
        let value = &material[..len];
        let mac = |out: Vec<u8>| sri(&out);
        let want = match name {
            "CKK_SHA_1_HMAC" => mac({
                let mut m = <Hmac<sha1::Sha1> as KeyInit>::new_from_slice(value).unwrap();
                m.update(label.as_bytes());
                m.finalize().into_bytes().to_vec()
            }),
            "CKK_SHA224_HMAC" => mac({
                let mut m = <Hmac<sha2::Sha224> as KeyInit>::new_from_slice(value).unwrap();
                m.update(label.as_bytes());
                m.finalize().into_bytes().to_vec()
            }),
            "CKK_SHA256_HMAC" => mac({
                let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(value).unwrap();
                m.update(label.as_bytes());
                m.finalize().into_bytes().to_vec()
            }),
            "CKK_SHA384_HMAC" => mac({
                let mut m = <Hmac<sha2::Sha384> as KeyInit>::new_from_slice(value).unwrap();
                m.update(label.as_bytes());
                m.finalize().into_bytes().to_vec()
            }),
            _ => mac({
                let mut m = <Hmac<sha2::Sha512> as KeyInit>::new_from_slice(value).unwrap();
                m.update(label.as_bytes());
                m.finalize().into_bytes().to_vec()
            }),
        };
        assert_eq!(e.locked_id(name, "commitment"), want, "{name}");
    }
    // A hash-bound HMAC type generates with its own CKM_SHA384_KEY_GEN (PKCS#11 3.0): on a token
    // without it, refused up front with nothing created.
    if REF.hmac_key_gen {
        let o = e.km(&["create", "--spec", "gen384", "--token", "ref", "--update-lock"]);
        assert_eq!(code(&o), 0, "{}", stderr(&o));
        assert_eq!(s.labelled("hmac-gen384").len(), 1);
        assert_eq!(e.lock()["realisations"]["gen384"]["ref"]["mode"].as_str(), Some("commitment"));
    } else {
        let o = e.km(&["create", "--spec", "gen384", "--token", "ref", "--no-update-lock"]);
        assert_eq!(code(&o), 15, "{}", stderr(&o));
        assert!(stderr(&o).contains("CKM_SHA384_KEY_GEN"), "{}", stderr(&o));
        assert_eq!(s.labelled("hmac-gen384"), []);
    }
}

#[test]
fn aes_128_192_and_decrypt_only_match_host_oracles() {
    let Some(e) = env("aes_sizes") else { return };
    let s = e.session();
    let all = [Attribute::Sign(true), Attribute::Encrypt(true), Attribute::Decrypt(true), Attribute::Wrap(true)];
    let k128 = *b"aes-128 vector!!";
    let k192 = *b"aes-192 test vector 24B!";
    let k256 = *b"aes-256 decrypt-only vector 32B!";
    plant_secret(&s, "aes-128", cryptoki::object::KeyType::AES, &k128, &all);
    plant_secret(&s, "aes-192", cryptoki::object::KeyType::AES, &k192, &all);
    plant_secret(
        &s,
        "aes-dec",
        cryptoki::object::KeyType::AES,
        &k256,
        &[Attribute::Decrypt(true), Attribute::Encrypt(false), Attribute::Sign(false), Attribute::Wrap(false)],
    );
    let spec = |name: &str, len: usize, attrs: &str, label: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = {len}\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ {attrs}, CKA_EXTRACTABLE = false }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"adopt\" }}\n\n"
        )
    };
    let every = "CKA_SIGN = true, CKA_ENCRYPT = true, CKA_DECRYPT = true, CKA_WRAP = true";
    e.config(
        &(spec("a128", 16, every, "aes-128")
            + &spec("a192", 24, every, "aes-192")
            + &spec("adec", 32, "CKA_DECRYPT = true", "aes-dec")),
    );
    for (name, key, schemes) in [
        ("a128", &k128[..], &["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"][..]),
        ("a192", &k192[..], &["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"][..]),
        ("adec", &k256[..], &["kcv-ecb-dec"][..]),
    ] {
        let o = e.km(&["lock", "--spec", name, "--token", "ref", "--update-lock"]);
        assert_eq!(code(&o), 0, "{name}");
        let r: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        assert_eq!(r["ids"].as_object().unwrap().keys().collect::<Vec<_>>(), schemes, "{name}");
        for scheme in schemes {
            assert_eq!(e.locked_id(name, scheme), aes_commitment(key, scheme), "{name} {scheme}");
        }
    }
    // The decrypt-only key is now identifiable (before kcv-ecb-dec it needed an opt-in mode).
    assert_eq!(e.code(&["check", "adec"]), 0);
}

/// 24 bytes with DES's odd parity in each byte's low bit, as a token stores a Triple DES key.
fn des3_key(text: &[u8; 24]) -> [u8; 24] {
    text.map(|b| (b & 0xfe) | u8::from((b & 0xfe).count_ones() % 2 == 0))
}

/// Triple DES keys (`CKK_DES3`), as payment HSMs hold them: identified by the DES3 check values
/// (`kcv-ecb`, `kcv-ecb-dec`), each matching the host's `des` oracle; a generated key without
/// `valueLen` (the key type fixes 24 bytes, and the token keeps no `CKA_VALUE_LEN`); and a module
/// without Triple DES (kryoptic) refusing before anything is created (15).
#[test]
fn des3_check_values_match_host_oracles() {
    let Some(e) = env("des3") else { return };
    let key = des3_key(b"des3 check value vector!");
    // des3-gen is generated; the other keys are planted.
    let spec = |name: &str, object: &str, attrs: &str, label: &str| {
        let origin = if name == "des3-gen" { "create" } else { "adopt" };
        format!(
            "[specs.{name}]\nobject = \"{object}\"\nattributes = {{ {attrs} }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"{origin}\" }}\n\n"
        )
    };
    let fixed = "CKA_SENSITIVE = true, CKA_EXTRACTABLE = false";
    let mut body = String::from(
        "[objects.des3]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"\nvalueLen = 24\n\n\
         [objects.des3-gen]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"\n\n",
    );
    body += &spec("des3-gen", "des3-gen", &format!("CKA_ENCRYPT = true, {fixed}"), "des3-gen");
    // A DES3 key that may only sign: no DES3 commitment uses CKA_SIGN (CMAC is not named, OPEN.md).
    body += &spec("des3-mac", "des3", &format!("CKA_SIGN = true, {fixed}"), "des3-mac");
    e.config(&body);
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 17);
    assert!(
        stderr(&o).contains("no usage bit that commits a CKK_DES3 key: CKA_ENCRYPT, CKA_DECRYPT"),
        "{}",
        stderr(&o)
    );
    body = body.replace(&spec("des3-mac", "des3", &format!("CKA_SIGN = true, {fixed}"), "des3-mac"), "");

    if !REF.des3 {
        // No Triple DES on the module: refused from what the token lists, nothing created.
        e.config(&body);
        let o = e.km(&["create", "--spec", "des3-gen", "--token", "ref", "--no-update-lock"]);
        assert_eq!(code(&o), 15, "{}", stderr(&o));
        assert!(stderr(&o).contains("CKM_DES3_ECB"), "{}", stderr(&o));
        assert_eq!(e.session().labelled("des3-gen"), []);
        return;
    }

    // One value planted three times with different usage bits, and an AES key in its place once.
    let s = e.session();
    let des3 = cryptoki::object::KeyType::DES3;
    let enc_dec = [Attribute::Encrypt(true), Attribute::Decrypt(true), Attribute::Sign(false)];
    plant_secret(&s, "des3-both", des3, &key, &enc_dec);
    plant_secret(&s, "des3-dec", des3, &key, &[Attribute::Encrypt(false), Attribute::Decrypt(true)]);
    s.create_object(&[
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(des3),
        Attribute::Token(true),
        Attribute::Label(b"des3-x".to_vec()),
        Attribute::Value(key.to_vec()),
        Attribute::Encrypt(false),
        Attribute::Decrypt(false),
        Attribute::Sensitive(true),
        Attribute::Extractable(true),
    ])
    .unwrap();
    plant_secret(&s, "aes-in-place", cryptoki::object::KeyType::AES, &AES_VALUE, &[Attribute::Encrypt(true)]);
    body += &spec("des3-both", "des3", &format!("CKA_ENCRYPT = true, CKA_DECRYPT = true, {fixed}"), "des3-both");
    body += &spec("des3-dec", "des3", &format!("CKA_ENCRYPT = false, CKA_DECRYPT = true, {fixed}"), "des3-dec");
    // No usage bit a commitment uses, but extractable: a session copy computes both check values.
    body += &spec("des3-x", "des3", "CKA_ENCRYPT = false, CKA_DECRYPT = false, CKA_EXTRACTABLE = true", "des3-x");
    body += &spec("des3-aes", "des3", "CKA_ENCRYPT = true", "aes-in-place");
    e.config(&body);
    for (name, mode, schemes) in [
        ("des3-both", "commitment", &["kcv-ecb", "kcv-ecb-dec"][..]),
        ("des3-dec", "commitment", &["kcv-ecb-dec"][..]),
        ("des3-x", "wrap-rebind", &["kcv-ecb", "kcv-ecb-dec"][..]),
    ] {
        let o = e.km(&["lock", "--spec", name, "--token", "ref", "--update-lock"]);
        assert_eq!(code(&o), 0, "{name}: {}", stderr(&o));
        let r: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
        assert_eq!(r["ids"].as_object().unwrap().keys().collect::<Vec<_>>(), schemes, "{name}");
        assert_eq!(r["mode"].as_str(), Some(mode), "{name}");
        assert_eq!(r["assurance"].as_str(), Some("fingerprint"), "{name}");
    }
    for scheme in ["kcv-ecb", "kcv-ecb-dec"] {
        assert_eq!(e.locked_id("des3", scheme), des3_commitment(&key, scheme), "{scheme}");
    }
    assert_eq!(e.lock()["objects"]["des3"]["type"]["valueLen"].as_integer(), Some(24));
    assert_eq!(e.code(&["check", "des3.id.kcv-ecb-dec", "--spec", "des3-dec"]), 0);
    // Another key type under the locator is another object (13), whatever its length.
    assert_eq!(e.code(&["lock", "--spec", "des3-aes", "--token", "ref", "--update-lock"]), 13);

    // Generated with CKM_DES3_KEY_GEN: no valueLen in keys.toml or the template, a stable
    // identity across runs, and deletable by it.
    let r = ["lock", "--spec", "des3-gen", "--token", "ref", "--no-update-lock"];
    let first = e.km(&["create", "--spec", "des3-gen", "--token", "ref", "--no-update-lock"]);
    assert_eq!(code(&first), 18, "{}", stderr(&first));
    assert_eq!(got_hash(&e.km(&r)), got_hash(&first));
    assert_eq!(e.code(&recording(&r)), 0);
    assert_eq!(e.locked_id("des3-gen", "kcv-ecb"), got_hash(&first));
    assert_eq!(e.lock()["objects"]["des3-gen"]["type"]["valueLen"].as_integer(), Some(24));
    assert_eq!(e.code(&["check", "des3-gen"]), 0);
    assert_eq!(e.code(&["delete", "--spec", "des3-gen", "--token", "ref", "--update-lock"]), 0);
    assert_eq!(e.code(&["verify", "--spec", "des3-gen", "--token", "ref"]), 11);
}

#[test]
fn a_new_scheme_missing_from_the_lock_is_a_note_unless_requested() {
    let Some(e) = env("upgrade") else { return };
    let key = *b"upgrade rule aes test vector 32B";
    plant_secret(
        &e.session(),
        "upgrade-aes",
        cryptoki::object::KeyType::AES,
        &key,
        &[Attribute::Sign(true), Attribute::Encrypt(true)],
    );
    e.config(
        "[objects.u]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.u]\nobject = \"u\"\nattributes = { CKA_SIGN = true, CKA_ENCRYPT = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"upgrade-aes\" }, origin = \"adopt\" }\n",
    );
    // First use: nothing to compare, fails like a FOD.
    assert_eq!(e.code(&["verify", "--spec", "u", "--token", "ref"]), 18);
    assert_eq!(e.code(&["lock", "--spec", "u", "--token", "ref", "--update-lock"]), 0);
    // A lock written by a version that only knew cmac.
    e.write_lock_keeping_realisations(&format!(
        "version = 1\n[objects.u]\ncommitmentLabel = \"key-management/v1\"\n\
         [objects.u.type]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n[objects.u.ids]\ncmac = \"{}\"\n",
        aes_commitment(&key, "cmac")
    ));
    let mut old = e.lock();
    old["realisations"]["u"]["ref"]["schemes"] = toml::Value::Array(vec!["cmac".into()]);
    std::fs::write(e.dir.join("keys.lock"), toml::to_string(&old).unwrap()).unwrap();
    let v = e.km(&["verify", "--spec", "u", "--token", "ref"]);
    assert_eq!(code(&v), 0);
    assert!(stderr(&v).contains("kcv-ecb identity the lock does not record"));
    assert_eq!(e.code(&["check", "u"]), 0);
    assert_eq!(e.code(&["check", "u.id.cmac"]), 0);
    // Asking for the scheme explicitly requires it to be locked.
    assert_eq!(e.code(&["check", "u.id.kcv-ecb"]), 18);
    assert_eq!(e.code(&["lock", "--spec", "u", "--token", "ref", "--update-lock"]), 0);
    assert_eq!(e.code(&["check", "u.id.kcv-ecb"]), 0);
    // A wrong locked value still fails, whatever else matches.
    let text = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    let wrong = text.replace(&aes_commitment(&key, "kcv-ecb"), "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    std::fs::write(e.dir.join("keys.lock"), wrong).unwrap();
    assert_eq!(e.code(&["verify", "--spec", "u", "--token", "ref"]), 10);
}

#[test]
fn standalone_public_key_objects() {
    let Some(e) = env("public_keys") else { return };
    let der: &[u8] = include_bytes!("../fixtures/adopt-cert-p384.der");
    let cert = <x509_cert::Certificate as x509_cert::der::Decode>::from_der(der).unwrap();
    let point = cert.tbs_certificate().subject_public_key_info().subject_public_key.raw_bytes().to_vec();
    e.session()
        .create_object(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::EC),
            Attribute::Token(true),
            Attribute::Label(b"standalone-pub".to_vec()),
            Attribute::Verify(true),
            Attribute::EcParams(P384.to_vec()),
            Attribute::EcPoint(tlv(0x04, &point)),
        ])
        .unwrap();
    e.config(
        "[objects.anchor]\nclass = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"\n\n\
         [specs.anchor]\nobject = \"anchor\"\nattributes = { CKA_VERIFY = true }\n\
         tokens.ref-anon = { locator = { CKA_LABEL = \"standalone-pub\" }, origin = \"adopt\" }\n\
         tokens.ref = { locator = { CKA_LABEL = \"standalone-pub\" }, origin = \"adopt\" }\n",
    );
    let o = e.km(&["lock", "--spec", "anchor", "--token", "ref-anon", "--update-lock"]);
    assert_eq!(code(&o), 0);
    assert_eq!(e.locked_id("anchor", "rfc7093m4"), P384_PUBKEYHASH, "matches openssl over the certificate's key");
    assert!(
        stdout(&e.km(&["verify", "--spec", "anchor", "--token", "ref-anon"]))
            .ends_with("object=standalone-pub;type=public")
    );
    assert_eq!(e.code(&["check", "anchor.id.rfc7093m4", "--token", "ref-anon"]), 0);
    // Deletable by identity; then absent.
    assert_eq!(e.code(&["delete", "--spec", "anchor", "--token", "ref", "--update-lock"]), 0);
    assert_eq!(e.code(&["verify", "--spec", "anchor", "--token", "ref-anon"]), 11);
    // Public keys are adopted, not created.
    let o = e.km(&["create", "--spec", "anchor", "--token", "ref", "--no-update-lock"]);
    assert_eq!(code(&o), 17);
    assert!(stderr(&o).contains("origin = \"adopt\": it is found there, never created"), "{}", stderr(&o));
}

#[test]
fn data_objects_are_identified_by_their_public_value() {
    let Some(e) = env("data") else { return };
    let value = b"key-management data object payload\n".to_vec();
    let s = e.session();
    let data = |label: &str, private: bool| {
        vec![
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(true),
            Attribute::Private(private),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Application(b"key-management test".to_vec()),
            Attribute::Value(value.clone()),
        ]
    };
    s.create_object(&data("data-public", false)).unwrap();
    s.create_object(&data("data-private", true)).unwrap();
    e.config(
        "[objects.blob]\nclass = \"CKO_DATA\"\n\n\
         [specs.blob]\nobject = \"blob\"\nattributes = { CKA_PRIVATE = false }\n\
         tokens.ref-anon = { locator = { CKA_LABEL = \"data-public\" }, origin = \"adopt\" }\n\n\
         [objects.secret-blob]\nclass = \"CKO_DATA\"\n\n\
         [specs.secret-blob]\nobject = \"secret-blob\"\n\
         tokens.ref = { locator = { CKA_LABEL = \"data-private\" }, origin = \"adopt\" }\n",
    );
    assert_eq!(e.code(&["lock", "--spec", "blob", "--token", "ref-anon", "--update-lock"]), 0);
    // valuehash is SHA-256 of the content: the same SRI hash as a flat Nix fixed-output hash.
    assert_eq!(e.locked_id("blob", "valuehash"), sri(&value));
    assert!(
        stdout(&e.km(&["verify", "--spec", "blob", "--token", "ref-anon"])).ends_with("object=data-public;type=data")
    );
    assert_eq!(e.code(&["check", "blob.id.valuehash"]), 0);
    // A private value's hash would be an offline guessing oracle: refused, nothing recorded.
    let o = e.km(&["lock", "--spec", "secret-blob", "--token", "ref", "--update-lock"]);
    assert_eq!(code(&o), 15);
    assert!(stderr(&o).contains("CKA_PRIVATE"));
    let lock = std::fs::read_to_string(e.dir.join("keys.lock")).unwrap();
    assert!(!lock.contains("secret-blob"), "{lock}");
    // Data objects are adopted, not created.
    assert_eq!(e.code(&["create", "--spec", "blob", "--token", "ref-anon", "--no-update-lock"]), 17);
}

/// A private data object (`CKA_PRIVATE = true`: an API token, a wrapped blob, an application
/// secret), identified like a public one by `valuehash` once its spec declares `CKA_PRIVATE =
/// true`: the author's statement that the value is not guessable (DESIGN §3.1). Read under the
/// user login; without one the token shows no such object (11). The undeclared case stays
/// refused (`data_objects_are_identified_by_their_public_value`).
#[test]
fn private_data_objects_are_identified_when_declared() {
    let Some(e) = env("private_data") else { return };
    let value = b"0f4c1e9a7b3d52c86e1f0a9b4d7c3e25 an unguessable application secret".to_vec();
    let s = e.session();
    for (label, private) in [("data-secret", true), ("data-open", false)] {
        s.create_object(&[
            Attribute::Class(ObjectClass::DATA),
            Attribute::Token(true),
            Attribute::Private(private),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Application(b"key-management test".to_vec()),
            Attribute::Value(value.clone()),
        ])
        .unwrap();
    }
    e.config(
        "[objects.secret]\nclass = \"CKO_DATA\"\n\n\
         [specs.secret]\nobject = \"secret\"\nattributes = { CKA_PRIVATE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"data-secret\" }, origin = \"adopt\" }\n\
         tokens.ref-anon = { locator = { CKA_LABEL = \"data-secret\" }, origin = \"adopt\" }\n\n\
         [objects.open]\nclass = \"CKO_DATA\"\n\n\
         [specs.open-as-private]\nobject = \"open\"\nattributes = { CKA_PRIVATE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"data-open\" }, origin = \"adopt\" }\n",
    );
    let o = e.km(&["lock", "--spec", "secret", "--token", "ref", "--update-lock"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let r: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(r["assurance"].as_str(), Some("public"), "whoever holds the value passes");
    assert_eq!(e.locked_id("secret", "valuehash"), sri(&value));
    assert_eq!(e.lock()["realisations"]["secret"]["ref"]["policy"]["CKA_PRIVATE"].as_bool(), Some(true));
    assert!(stdout(&e.km(&["verify", "--spec", "secret", "--token", "ref"])).ends_with("object=data-secret;type=data"));
    assert_eq!(e.code(&["check", "secret.id.valuehash", "--token", "ref"]), 0);
    // Without a login the token shows no private object: absent.
    assert_eq!(e.code(&["verify", "--spec", "secret", "--token", "ref-anon"]), 11);
    // Declaring it private does not make a public object one: the declared policy is checked (13).
    let o = e.km(&["lock", "--spec", "open-as-private", "--token", "ref", "--no-update-lock"]);
    assert_eq!(code(&o), 13);
    assert!(stderr(&o).contains("CKA_PRIVATE is false"), "{}", stderr(&o));
}
