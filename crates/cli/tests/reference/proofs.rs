//! Proof of possession (`pop-*`) and the PIV attestation.

use super::*;

/// docs/DESIGN.md §3.6: a `CKA_ALWAYS_AUTHENTICATE` key proves possession under its
/// per-use policy (`C_SignInit → C_Login(CKU_CONTEXT_SPECIFIC) → C_Sign`), and the
/// lock records `pop-sign-pin` from the attribute the token reports, declared or not.
#[test]
fn always_authenticate_keys_prove_possession_with_a_per_use_pin() {
    let Some(e) = env("always-auth-pop") else { return };
    let s = e.session();
    let spec = |key: &str, label: &str, attributes: &str| {
        format!(
            "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\n{key}\n\n[specs.s]\nobject = \"o\"\n\
             attributes = {{ {attributes} }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"create\" }}\n"
        )
    };
    let rsa = "keyType = \"CKK_RSA\"\nmodulusBits = 2048";
    let declared = "CKA_SIGN = true, CKA_ALWAYS_AUTHENTICATE = true, CKA_DESTROYABLE = true";
    e.config(&spec(rsa, "always-auth-rsa", declared));
    let o = e.km(&["create", "--spec", "s", "--token", "ref"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let r = &e.lock()["realisations"]["s"]["ref"];
    assert_eq!(r["binding"].as_str(), Some("pop-sign-pin"), "{r}");
    assert_eq!(r["policy"]["CKA_ALWAYS_AUTHENTICATE"].as_bool(), Some(true), "{r}");
    let o = e.km(&["check", "--spec", "s", "--token", "ref"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));

    // The module enforces the policy: signing without the context-specific login fails, so the
    // proof above did log in rather than sign freely.
    let private = s
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Label(b"always-auth-rsa".to_vec())])
        .unwrap()[0];
    assert!(s.sign(&Mechanism::Sha256RsaPkcs, private, b"challenge").is_err(), "signed without re-authenticating");

    // Undeclared, the attribute the token reports still decides: same proof, same record.
    e.config(&spec(rsa, "always-auth-rsa", "CKA_SIGN = true"));
    let o = e.km(&["resolve", "--spec", "s", "--token", "ref"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let resolved: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(resolved["binding"].as_str(), Some("pop-sign-pin"), "{resolved}");

    // The signature after the login is single-part, which every signing mechanism offers:
    // hashed ECDSA (SoftHSM signs it in one part only), raw ECDSA over the host's digest where
    // the token lacks the hashed one, and EdDSA.
    let ec = "keyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let ed = "keyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"";
    for (key, label, hidden) in
        [(ec, "always-auth-ec", None), (ec, "always-auth-raw", Some("CKM_ECDSA_SHA256")), (ed, "always-auth-ed", None)]
    {
        std::fs::write(e.dir.join("keys.lock"), EMPTY_LOCK).unwrap();
        e.config(&spec(key, label, declared));
        let hidden = hidden.map(|m| e.hiding(m));
        let envs: Vec<(&str, &std::path::Path)> = hidden.iter().map(|(var, conf)| (*var, conf.as_path())).collect();
        let o = e.km_env(&["create", "--spec", "s", "--token", "ref"], &envs);
        assert_eq!(code(&o), 22, "{label}: {}", stderr(&o));
        assert_eq!(e.lock()["realisations"]["s"]["ref"]["binding"].as_str(), Some("pop-sign-pin"), "{label}");
        assert_eq!(code(&e.km_env(&["check", "--spec", "s", "--token", "ref"], &envs)), 0, "{label}");
    }
}

/// A recorded proof of possession cannot silently become a token assertion.
#[test]
fn binding_downgrade_is_refused() {
    let Some(e) = env("binding") else { return };
    let body = EC.replace("ec-lifecycle", "binding");
    e.config(&body);
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    let opted_out = body.replace("origin = \"create\" }", "origin = \"create\", binding = \"token-asserted\" }");
    assert_ne!(opted_out, body);
    e.config(&opted_out);
    assert_eq!(e.code(&["check", "--spec", "signing-soft", "--token", "ref"]), 14);
    assert_eq!(e.code(&["lock", "--spec", "signing-soft", "--token", "ref"]), 14);
    // Without CKA_SIGN and without the opt-in, the spec is invalid.
    e.config(&body.replace("CKA_SIGN = true", "CKA_SIGN = false"));
    assert_eq!(e.code(&["validate"]), 17);
}

/// P0-1: keys that cannot sign still prove possession. `pop-ecdh` derives the shared secret into
/// a non-extractable session key and MACs the challenge on both sides; `pop-decrypt` has the token
/// RSA-OAEP-decrypt the challenge; `pop-unwrap` has it unwrap a host secret into a non-extractable
/// session key and MAC with it (a transport key, docs/CAMIGRATE.md D3). A different private key under the
/// locator fails the proof.
#[test]
fn derive_and_decrypt_only_keys_prove_possession() {
    let Some(e) = env("pop-ecdh") else { return };
    // Shapes: each proof needs its capability declared, and applies to its key type only.
    let ec = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
              [specs.k]\nobject = \"k\"\nattributes = { CKA_DERIVE = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n";
    let rsa = "[objects.r]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n\
               [specs.r]\nobject = \"r\"\nattributes = { CKA_DECRYPT = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n";
    let unwrap = "[objects.u]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n\
                  [specs.u]\nobject = \"u\"\nattributes = { CKA_UNWRAP = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n";
    // Each invalid (17) for its own reason, so a refusal of the shared skeleton cannot pass.
    for (body, token, why) in [
        (ec, "binding = \"pop-decrypt\"", "by decrypting: it applies to RSA private keys only"),
        (ec.replace("CKA_DERIVE = true, ", "").as_str(), "binding = \"pop-ecdh\"", "needs CKA_DERIVE = true"),
        (rsa, "binding = \"pop-ecdh\"", "by deriving: it applies to EC private keys only"),
        (rsa.replace("CKA_DECRYPT = true, ", "").as_str(), "binding = \"pop-decrypt\"", "needs CKA_DECRYPT = true"),
        (ec, "binding = \"pop-unwrap\"", "by unwrapping: it applies to RSA private keys only"),
        (unwrap.replace("CKA_UNWRAP = true, ", "").as_str(), "binding = \"pop-unwrap\"", "needs CKA_UNWRAP = true"),
    ] {
        e.config(&format!("{body}tokens.ref = {{ locator = {{ CKA_LABEL = \"x\" }}, origin = \"adopt\", {token} }}\n"));
        let o = e.km(&["validate"]);
        assert!(code(&o) == 17 && stderr(&o).contains(why), "{token}: expected 17 and {why:?}: {}", stderr(&o));
    }
    // The default proof (pop-sign) still needs CKA_SIGN.
    e.config(&format!("{ec}tokens.ref = {{ locator = {{ CKA_LABEL = \"x\" }}, origin = \"adopt\" }}\n"));
    let o = e.km(&["validate"]);
    assert!(code(&o) == 17 && stderr(&o).contains("needs CKA_SIGN = true"), "{}", stderr(&o));

    // Derive-only EC key, proven by deriving: created, recorded as pop-ecdh, verifies.
    e.config(&format!(
        "{ec}tokens.ref = {{ locator = {{ CKA_LABEL = \"pop-ecdh\" }}, origin = \"create\", binding = \"pop-ecdh\" }}\n"
    ));
    assert_eq!(e.code(&["create", "--spec", "k", "--token", "ref"]), 22);
    let real = &e.lock()["realisations"]["k"]["ref"];
    assert_eq!(real["binding"].as_str(), Some("pop-ecdh"));
    assert_eq!(e.code(&["check", "--spec", "k", "--token", "ref"]), 0);
    assert!(e.lock()["objects"]["k"]["ids"].get("rfc7093m4").is_some(), "the object id was recorded");

    // Decrypt-only RSA key, proven by decrypting (OAEP-SHA256).
    e.config(&format!("{rsa}tokens.ref = {{ locator = {{ CKA_LABEL = \"pop-oaep\" }}, origin = \"create\", binding = \"pop-decrypt\" }}\n"));
    assert_eq!(e.code(&["create", "--spec", "r", "--token", "ref"]), 22);
    assert_eq!(e.lock()["realisations"]["r"]["ref"]["binding"].as_str(), Some("pop-decrypt"));
    assert_eq!(e.code(&["check", "--spec", "r", "--token", "ref"]), 0);

    // Unwrap-only RSA key, proven by unwrapping: no CKA_DECRYPT, nothing leaves the token.
    e.config(&format!(
        "{unwrap}tokens.ref = {{ locator = {{ CKA_LABEL = \"pop-unwrap\" }}, origin = \"create\", binding = \"pop-unwrap\" }}\n"
    ));
    let o = e.km(&["create", "--spec", "u", "--token", "ref"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(e.lock()["realisations"]["u"]["ref"]["binding"].as_str(), Some("pop-unwrap"));
    assert_eq!(e.code(&["check", "--spec", "u", "--token", "ref"]), 0);

    // Back to the EC spec for the conflict phase.
    e.config(&format!(
        "{ec}tokens.ref = {{ locator = {{ CKA_LABEL = \"pop-ecdh\" }}, origin = \"create\", binding = \"pop-ecdh\" }}\n"
    ));

    // A different private key under the EC locator fails the derivation proof, like H1. A fresh
    // session: one opened before the `lock` processes does not see objects they created
    // (common/mod.rs), but everything is visible to a session opened after them.
    let usage = [Attribute::Derive(true), Attribute::Sensitive(true), Attribute::Extractable(false)];
    swap_private_key(
        &e.session(),
        "pop-ecdh",
        &Mechanism::EccKeyPairGen,
        &[Attribute::EcParams(P256.to_vec())],
        &usage,
        &[],
    );
    assert_swapped_key_conflict(&e.km(&["check", "--spec", "k", "--token", "ref"]));
    assert_eq!(e.code(&["lock", "--spec", "k", "--token", "ref", "--dry-run"]), 13);
}

/// A proof the token cannot give is refused, never skipped: without the proof's mechanism the
/// token is unsupported (15) with the opt-out named, and a `CKA_ALWAYS_AUTHENTICATE` key under a
/// binding that has no per-use login is unavailable (16).
#[test]
fn proofs_the_token_cannot_give_are_refused() {
    let Some(e) = env("pop-refused") else { return };
    let ec = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
              [specs.k]\nobject = \"k\"\nattributes = { CKA_DERIVE = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n\
              tokens.ref = { locator = { CKA_LABEL = \"pop-refused-ec\" }, origin = \"create\", binding = \"pop-ecdh\" }\n\n";
    e.config(ec);
    assert_eq!(e.code(&["create", "k"]), 22);
    // The same token through a module configuration that hides the proof's mechanism.
    let (var, hidden) = e.hiding("CKM_ECDH1_DERIVE");
    let o = e.km_env(&["check", "k", "--token", "ref"], &[(var, hidden.as_path())]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    let said = stderr(&o);
    assert!(said.contains("CKM_ECDH1_DERIVE") && said.contains("token-asserted"), "{said}");
    // A key that wants its PIN per use, under a proof that has no point to give it. Declared, the
    // spec is invalid (attributes_are_validated_per_class); here the token reports it undeclared.
    // (An object of its own: the lock pins `k`'s material.)
    let s = e.session();
    let label = || Attribute::Label(b"pop-refused-always".to_vec());
    let p256 = P256.to_vec();
    s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[Attribute::Token(true), label(), Attribute::EcParams(p256)],
        &[Attribute::Token(true), label(), Attribute::Derive(true), Attribute::AlwaysAuthenticate(true)],
    )
    .unwrap();
    drop(s);
    let always = ec
        .replace("pop-refused-ec\" }", "pop-refused-always\" }")
        .replace("[objects.k]", "[objects.a]")
        .replace("[specs.k]\nobject = \"k\"", "[specs.a]\nobject = \"a\"")
        .replace(", CKA_SENSITIVE = true, CKA_EXTRACTABLE = false", "");
    e.config(&format!("{ec}{always}"));
    let o = e.km(&["lock", "a", "--token", "ref", "--dry-run"]);
    let said = stderr(&o);
    assert!(said.contains("CKA_ALWAYS_AUTHENTICATE") && said.contains("pop-sign"), "{said}");
    assert_eq!(code(&o), 16, "{said}");
}

/// A proof falls back where the token lacks its first choice, and still catches a swapped key
/// there: without the curve's hashed ECDSA, `pop-sign` signs a host digest with raw `CKM_ECDSA`;
/// without HMAC, `pop-ecdh` derives into an extractable secret the host compares; without OAEP,
/// `pop-decrypt` decrypts a PKCS #1 v1.5 challenge.
#[test]
fn proofs_fall_back_to_what_the_token_has() {
    let Some(e) = env("pop-fallback") else { return };
    let key = |name: &str, key: &str, usage: &str, binding: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\n{key}\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ {usage} = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"pop-fallback-{name}\" }}, origin = \"create\", binding = \"{binding}\" }}\n\n"
        )
    };
    let ec = |name: &str, usage: &str, binding: &str| {
        key(name, "keyType = \"CKK_EC\"\ncurve = \"secp256r1\"", usage, binding)
    };
    let rsa = key("r", "keyType = \"CKK_RSA\"\nmodulusBits = 2048", "CKA_DECRYPT", "pop-decrypt");
    e.config(&(ec("s", "CKA_SIGN", "pop-sign") + &ec("d", "CKA_DERIVE", "pop-ecdh") + &rsa));
    for (spec, mechanism) in [("s", "CKM_ECDSA_SHA256"), ("d", "CKM_SHA256_HMAC"), ("r", "CKM_RSA_PKCS_OAEP")] {
        let (var, conf) = e.hiding(mechanism);
        let create = ["create", "--spec", spec, "--token", "ref"];
        let o = e.km_env(&create, &[(var, conf.as_path())]);
        assert_eq!(code(&o), 22, "{mechanism} hidden: {}", stderr(&o));
        assert_eq!(code(&e.km_env(&["check", "--spec", spec, "--token", "ref"], &[(var, conf.as_path())])), 0);
    }
    // Another private key under the derive-only locator: the extractable path's comparison fails.
    let usage = [Attribute::Derive(true), Attribute::Sensitive(true), Attribute::Extractable(false)];
    let p256 = [Attribute::EcParams(P256.to_vec())];
    swap_private_key(&e.session(), "pop-fallback-d", &Mechanism::EccKeyPairGen, &p256, &usage, &[]);
    let (var, conf) = e.hiding("CKM_SHA256_HMAC");
    assert_swapped_key_conflict(&e.km_env(&["check", "--spec", "d", "--token", "ref"], &[(var, conf.as_path())]));
}

/// What a key cannot give its proof with: a `CKA_ALWAYS_AUTHENTICATE` key on a token with no PIN
/// configured is unavailable (16); a key whose `CKA_ALLOWED_MECHANISMS` leave out every mechanism
/// the proof could use is unsupported (15), those mechanisms named. A decrypt-only key pinned to
/// `CKM_RSA_PKCS` proves with PKCS #1 v1.5 instead of OAEP.
#[test]
fn proofs_the_key_will_not_give_are_refused() {
    let Some(e) = env("pop-key-refuses") else { return };
    let spec = |name: &str, key: &str, token: &str, usage: &str, binding: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\n{key}\n\n[specs.{name}]\nobject = \"{name}\"\n\
             attributes = {{ {usage} = true }}\n\
             tokens.{token} = {{ locator = {{ CKA_LABEL = \"pop-key-{name}\" }}, origin = \"create\", binding = \"{binding}\" }}\n\n"
        )
    };
    let ec = "keyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let rsa = "keyType = \"CKK_RSA\"\nmodulusBits = 2048";
    // Keys planted as a real deployment might hold them.
    let s = e.session();
    let label = |name: &str| Attribute::Label(format!("pop-key-{name}").into_bytes());
    let plant_ec = |name: &str, mechanism: &Mechanism, params: &[u8], private: &[Attribute]| {
        let public = [Attribute::Token(true), label(name), Attribute::EcParams(params.to_vec())];
        let private = [&[Attribute::Token(true), label(name)], private].concat();
        s.generate_key_pair(mechanism, &public, &private)
    };
    let p256 = P256;
    // Visible without login (CKA_PRIVATE = false), so `ref-anon` finds it, and wanting the PIN per
    // use: kryoptic makes it, SoftHSM refuses the combination (CKR_TEMPLATE_INCONSISTENT).
    let anon = [Attribute::Private(false), Attribute::Sign(true), Attribute::AlwaysAuthenticate(true)];
    let anon = plant_ec("anon", &Mechanism::EccKeyPairGen, p256, &anon).is_ok();
    let derive = [Attribute::Derive(true), Attribute::AllowedMechanisms(vec![MechanismType::ECDSA])];
    plant_ec("derive", &Mechanism::EccKeyPairGen, p256, &derive).unwrap();
    let plant_rsa = |name: &str, usage: Attribute| {
        let public = [
            Attribute::Token(true),
            label(name),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![1, 0, 1]),
        ];
        let private =
            [Attribute::Token(true), label(name), usage, Attribute::AllowedMechanisms(vec![MechanismType::RSA_PKCS])];
        s.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public, &private).unwrap();
    };
    plant_rsa("decrypt", Attribute::Decrypt(true));
    plant_rsa("unwrap", Attribute::Unwrap(true));
    drop(s);
    e.config(&format!(
        "{}{}{}{}",
        spec("anon", ec, "ref-anon", "CKA_SIGN", "pop-sign"),
        spec("derive", ec, "ref", "CKA_DERIVE", "pop-ecdh"),
        spec("decrypt", rsa, "ref", "CKA_DECRYPT", "pop-decrypt"),
        spec("unwrap", rsa, "ref", "CKA_UNWRAP", "pop-unwrap"),
    ));
    assert_eq!(anon, REF.provider == "kryoptic");
    if anon {
        let o = e.km(&["lock", "--spec", "anon", "--token", "ref-anon", "--dry-run"]);
        assert_eq!(code(&o), 16, "{}", stderr(&o));
        assert!(stderr(&o).contains("needs the user PIN per use"), "{}", stderr(&o));
    }
    for (name, mechanism) in [("derive", "CKM_ECDH1_DERIVE"), ("unwrap", "CKM_RSA_PKCS_OAEP")] {
        let o = e.km(&["lock", "--spec", name, "--token", "ref", "--dry-run"]);
        assert_eq!(code(&o), 15, "{name}: {}", stderr(&o));
        assert!(stderr(&o).contains(&format!("CKA_ALLOWED_MECHANISMS allows none of {mechanism}")), "{}", stderr(&o));
    }
    assert_eq!(e.code(&["lock", "--spec", "decrypt", "--token", "ref"]), 22);
    // The same on the extractable derive path (no HMAC for the sealed one).
    let (var, conf) = e.hiding("CKM_SHA256_HMAC");
    let o = e.km_env(&["lock", "--spec", "derive", "--token", "ref", "--dry-run"], &[(var, conf.as_path())]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("allows none of CKM_ECDH1_DERIVE"), "{}", stderr(&o));
}

/// A key bound to one RSA signature proves possession in it (Cloud KMS binds each key so
/// \[run\]): PSS, hashed by the token or over the host's digest, and PKCS #1 v1.5 over SHA-512,
/// hashed or raw over its `DigestInfo`. The host verifies each as the key is bound.
#[test]
fn a_key_bound_to_one_signature_proves_in_it() {
    use std::fmt::Write as _;
    let Some(e) = env("pop-key-bound") else { return };
    let s = e.session();
    let bound = [
        ("pss", vec![MechanismType::SHA256_RSA_PKCS_PSS]),
        ("pss-raw", vec![MechanismType::RSA_PKCS_PSS]),
        ("sha512", vec![MechanismType::SHA512_RSA_PKCS]),
        ("sha512-raw", vec![MechanismType::RSA_PKCS, MechanismType::SHA512_RSA_PKCS]),
    ];
    let mut config = String::new();
    for (name, allowed) in &bound {
        let label = Attribute::Label(format!("pop-bound-{name}").into_bytes());
        let public = [
            Attribute::Token(true),
            label.clone(),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![1, 0, 1]),
        ];
        let private =
            [Attribute::Token(true), label, Attribute::Sign(true), Attribute::AllowedMechanisms(allowed.clone())];
        s.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public, &private).unwrap();
        let _ = write!(
            config,
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"pop-bound-{name}\" }}, origin = \"adopt\", binding = \"pop-sign\" }}\n\n"
        );
    }
    drop(s);
    e.config(&config);
    for (name, _) in &bound {
        let o = e.km(&["lock", name, "--token", "ref"]);
        assert_eq!(code(&o), 22, "{name}: {}", stderr(&o));
        assert_eq!(e.code(&["check", name, "--token", "ref"]), 0, "{name}");
    }
}

/// ykcs11's slot 9a objects from the committed fixtures (crates/ykcs11/tests/fixtures/): the
/// public key planted, and its attestation and device certificates planted on request.
struct Piv<'a> {
    s: &'a TestSession,
    slot: Vec<u8>,
    device: Vec<u8>,
}

impl<'a> Piv<'a> {
    const SLOT_LABEL: &'static str = "X.509 Certificate for PIV Attestation 9a";
    const DEVICE_LABEL: &'static str = "X.509 Certificate for PIV Attestation";

    /// Plant slot 9a's public key (`CKA_ID` 01) and write keys.toml's spec `piv` adopting it on
    /// token `yk` (`provider = "ykcs11"`) with attestation.
    fn plant(e: &Suite, s: &'a TestSession) -> Piv<'a> {
        let fixture = |name: &str| {
            let pem =
                std::fs::read_to_string(format!("{}/../ykcs11/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR")));
            x509_cert::der::pem::decode_vec(pem.unwrap().as_bytes()).unwrap().1
        };
        let spki = fixture("slotpub.pem");
        let info = <x509_cert::spki::SubjectPublicKeyInfoOwned as x509_cert::der::Decode>::from_der(&spki).unwrap();
        let point = info.subject_public_key.raw_bytes().to_vec();
        s.create_object(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::KeyType(cryptoki::object::KeyType::EC),
            Attribute::EcParams(P256.to_vec()),
            Attribute::EcPoint(tlv(0x04, &point)),
            Attribute::Token(true),
            Attribute::Verify(true),
            Attribute::Id(vec![0x01]),
            Attribute::Label(b"Public key for PIV Authentication".to_vec()),
        ])
        .unwrap();
        e.write_config(&format!(
            "[tokens.yk]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nprovider = \"ykcs11\"\n\n\
             [objects.piv]\nclass = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.piv]\nobject = \"piv\"\ntokens.yk = {{ locator = {{ CKA_ID = \"01\" }}, origin = \"adopt\", attestation = true }}\n",
            e.module,
            e.dir.join("pin").display()
        ));
        Piv { s, slot: fixture("slot.pem"), device: fixture("f9.pem") }
    }

    fn cert(&self, der: &[u8], label: &str, id: u8) -> cryptoki::object::ObjectHandle {
        let mut t = cert_object(der, label.as_bytes(), Some(id));
        t.retain(|a| !matches!(a, Attribute::Token(_)));
        t.push(Attribute::Token(true));
        self.s.create_object(&t).unwrap()
    }

    /// Slot 9a's attestation certificate, under the key's `CKA_ID` and the slot-suffixed label.
    fn slot_cert(&self) -> cryptoki::object::ObjectHandle {
        self.cert(&self.slot, Self::SLOT_LABEL, 0x01)
    }

    /// The f9 device certificate, under the bare label.
    fn device_cert(&self) -> cryptoki::object::ObjectHandle {
        self.cert(&self.device, Self::DEVICE_LABEL, 0x19)
    }
}

/// The `YubiKey` provider's `piv-attestation` lookups, on this token named `provider = "ykcs11"`
/// with ykcs11's objects planted ([`Piv`]): slot 9a's public key (`CKA_ID` 01), its attestation
/// certificate under the same `CKA_ID` and the slot-suffixed label, and the f9 device
/// certificate under the bare label. The chain ends at a test root, never a pinned Yubico one:
/// refused (13). Without the slot or the device certificate there is no attestation (15); with
/// two of either, it is ambiguous (12). `check --at` holds the chain to that time.
#[test]
fn piv_attestations_are_found_by_slot_and_chain_to_yubico() {
    let Some(e) = env("piv-attest") else { return };
    let s = e.session();
    let piv = Piv::plant(&e, &s);
    let slot_cert = piv.slot_cert();
    let device_cert = piv.device_cert();
    let refused = |exit: i32, why: &str| {
        let o = e.km(&["lock", "--spec", "piv", "--token", "yk", "--dry-run"]);
        assert_eq!(code(&o), exit, "{}", stderr(&o));
        assert!(stderr(&o).contains(why), "expected {why:?} in {}", stderr(&o));
    };
    refused(13, "is signed by no pinned root and no intermediate given");
    let second = piv.slot_cert();
    refused(12, "2 attestation certificates share the key's CKA_ID");
    s.destroy_object(second).unwrap();
    s.destroy_object(slot_cert).unwrap();
    refused(15, "no attestation certificate for this key");
    piv.slot_cert();
    let second = piv.device_cert();
    refused(12, "2 objects carry the f9 device certificate label");
    s.destroy_object(second).unwrap();
    s.destroy_object(device_cert).unwrap();
    refused(15, "the device attestation certificate (slot f9) is not exposed");

    // `check --at` reaches the chain (ISSUES.md B8; review check.rs F1): before the device
    // certificate's notBefore (2026-11-12) the dates refuse first; with `--ignore-validity` the
    // chain goes on to its root, which no pinned one signed; and now, the same.
    let device_cert = piv.device_cert();
    let checked = |more: &[&str], why: &str| {
        let o = e.km(&[&["check", "piv", "--token", "yk"][..], more].concat());
        assert_eq!(code(&o), 13, "{more:?}: {}", stderr(&o));
        assert!(stderr(&o).contains(why), "{more:?}: expected {why:?} in {}", stderr(&o));
    };
    checked(&["--at", "2026-01-01T00:00:00Z"], "is not valid at 2026-01-01T00:00:00Z");
    checked(&["--ignore-validity"], "is signed by no pinned root and no intermediate given");
    checked(&[], "is signed by no pinned root and no intermediate given");
    s.destroy_object(device_cert).unwrap();

    // ykcs11 reports CKA_DERIVE false on every private key though it derives with any EC key:
    // the provider records what the key does. And it creates only in an SO session.
    let ec_params = P256.to_vec();
    let id = || Attribute::Id(vec![0x02]);
    s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[Attribute::Token(true), id(), Attribute::EcParams(ec_params)],
        &[Attribute::Token(true), id(), Attribute::Sign(true), Attribute::Derive(false)],
    )
    .unwrap();
    let key = |name: &str, id: &str, extra: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.yk = {{ locator = {{ CKA_ID = \"{id}\" }}{extra} }}\n\n"
        )
    };
    let config = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    e.write_config(&format!(
        "{config}\n{}{}",
        key("sig", "02", ", origin = \"adopt\""),
        key("new", "03", ", origin = \"create\"")
    ));
    let o = e.km(&["resolve", "--spec", "sig", "--token", "yk"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let resolved: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(resolved["policy"]["CKA_DERIVE"].as_bool(), Some(true), "{resolved}");
    let o = e.km(&["create", "--spec", "new", "--token", "yk", "--no-update-lock"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("needs a Security Officer session"), "{}", stderr(&o));
    // ykcs11 clears only a slot's certificate on delete and keeps the key: a delete is refused (15)
    // with the tool that does remove it, never reported as done.
    assert_eq!(e.code(&["lock", "--spec", "sig", "--token", "yk"]), 22);
    let o = e.km(&["delete", "--spec", "sig", "--token", "yk"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("ykman piv keys delete"), "{}", stderr(&o));
    // An admin credential the module refuses: the SO step is unavailable (16), never retried.
    std::fs::write(e.dir.join("bad-so"), "0000\n").unwrap();
    let text = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    let bad_so = format!("provider = \"ykcs11\"\nsoCredentialFile = \"{}\"\n", e.dir.join("bad-so").display());
    e.write_config(&text.replacen("provider = \"ykcs11\"\n", &bad_so, 1));
    let o = e.km(&["create", "--spec", "new", "--token", "yk", "--no-update-lock"]);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("C_Login (SO) with soCredentialFile/soCredentialEnv"), "{}", stderr(&o));
}
