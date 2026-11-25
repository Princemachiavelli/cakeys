//! Conflicts and drift: ambiguity, swapped and forged objects, policy and spec changes (H1, S3,
//! S4, S8) and downgrades.

use super::*;

#[test]
fn conflicts_and_ambiguity() {
    let Some(e) = env("conflicts") else { return };
    e.config(
        r#"
[objects.k]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.k-sign]
object = "k"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "conflict" }, origin = "create" }

[specs.k-nosign]
object = "k"
attributes = { CKA_SIGN = false }
tokens.ref = { locator = { CKA_LABEL = "conflict" }, origin = "adopt", binding = "token-asserted" }

[specs.k-dup]
object = "k"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "dup" }, origin = "adopt" }

[objects.g]
class = "CKO_SECRET_KEY"
keyType = "CKK_GENERIC_SECRET"
valueLen = 32

[specs.g-on-aes]
object = "g"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "typed" }, origin = "adopt" }
"#,
    );
    assert_eq!(e.code(&["create", "--spec", "k-sign", "--token", "ref"]), 22);
    // Same locator, different policy: the live object doesn't satisfy the spec.
    assert_eq!(e.code(&["lock", "--spec", "k-nosign", "--token", "ref", "--dry-run"]), 13);

    let s = e.session();
    let ec_params = P256.to_vec();
    for _ in 0..2 {
        let label = Attribute::Label(b"dup".to_vec());
        s.generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[Attribute::Token(true), label.clone(), Attribute::EcParams(ec_params.clone())],
            &[Attribute::Token(true), label, Attribute::Sign(true)],
        )
        .unwrap();
    }
    assert_eq!(e.code(&["resolve", "--spec", "k-dup", "--token", "ref"]), 12);

    // Same class, different key type under the locator: the object type must match.
    s.generate_key(
        &Mechanism::AesKeyGen,
        &[
            Attribute::Token(true),
            Attribute::Label(b"typed".to_vec()),
            Attribute::ValueLen(32.into()),
            Attribute::Sign(true),
            Attribute::Class(ObjectClass::SECRET_KEY),
        ],
    )
    .unwrap();
    assert_eq!(e.code(&["resolve", "--spec", "g-on-aes", "--token", "ref"]), 13);
}

#[test]
fn downgrade_is_an_error() {
    let Some(e) = env("downgrade") else { return };
    e.config(
        r#"
[objects.d]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.d-wrap]
object = "d"
attributes = { CKA_EXTRACTABLE = true }
tokens.ref = { locator = { CKA_LABEL = "downgrade" }, origin = "create" }
"#,
    );
    assert_eq!(e.code(&["create", "--spec", "d-wrap", "--token", "ref"]), 22);
    // Pretend the lock was recorded with a stronger mode than is now achievable: edited as TOML,
    // so a change of the writer's layout cannot leave it as it was (review drift.rs F1).
    let mut lock = e.lock();
    let mode = &mut lock["realisations"]["d-wrap"]["ref"]["mode"];
    assert_eq!(mode.as_str(), Some("wrap-rebind"), "the realisation's recorded mode");
    *mode = "commitment".into();
    e.write_lock(&lock);
    assert_eq!(e.code(&["check", "--spec", "d-wrap", "--token", "ref"]), 14);
}

/// A consumer that picks the private key by `CKA_ID` (OpenSSH) must get this one: with a login,
/// another private key under the same `CKA_ID` is ambiguous. The lock records the session kind.
#[test]
fn a_second_private_key_under_the_same_id_is_ambiguous() {
    let Some(e) = env("dup_id") else { return };
    let s = e.session();
    let ec_params = P256.to_vec();
    let generate = |label: &[u8]| {
        let common = [Attribute::Token(true), Attribute::Label(label.to_vec()), Attribute::Id(vec![0x77])];
        s.generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[&common[..], &[Attribute::EcParams(ec_params.clone())]].concat(),
            &[&common[..], &[Attribute::Sign(true)]].concat(),
        )
        .unwrap()
    };
    generate(b"dup-id-a");
    e.config(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"dup-id-a\" }, origin = \"adopt\" }\n\n\
         [specs.k-pub]\nobject = \"k\"\ntokens.ref-anon = { locator = { CKA_LABEL = \"dup-id-a\" }, origin = \"adopt\", publicOnly = true }\n",
    );
    assert_eq!(e.code(&["lock", "--spec", "k", "--token", "ref"]), 22);
    assert_eq!(e.code(&["lock", "--spec", "k-pub", "--token", "ref-anon"]), 22);
    let lock = e.lock();
    assert_eq!(lock["realisations"]["k"]["ref"]["observed"]["session"].as_str(), Some("user"));
    assert_eq!(lock["realisations"]["k-pub"]["ref-anon"]["observed"]["session"].as_str(), Some("public"));
    let uri = lock["realisations"]["k"]["ref"]["observed"]["uri"].as_str().unwrap();
    assert!(uri.contains(";serial="), "{uri}");
    generate(b"dup-id-b");
    let o = e.km(&["check", "--spec", "k", "--token", "ref"]);
    assert_eq!(code(&o), 12);
    assert!(stderr(&o).contains("share CKA_ID %77"), "{}", stderr(&o));
    // A public session cannot see the other private key: it passes, as the lock says it would.
    assert_eq!(e.code(&["check", "--spec", "k-pub", "--token", "ref-anon"]), 0);
}

/// The lock records every boolean attribute the object shows (declared or not) and its creation
/// facts: a later change on the token is reviewed, and a replaced object is refused outright.
#[test]
#[expect(clippy::many_single_char_names, reason = "the env/session/handle fixture bindings stay short")]
fn policy_drift_and_replaced_objects_are_refused() {
    let Some(e) = env("policy") else { return };
    e.config(
        "[objects.k]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true, CKA_SENSITIVE = false, CKA_EXTRACTABLE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"policy\" }, origin = \"create\" }\n",
    );
    let r = ["lock", "--spec", "k", "--token", "ref"];
    let verify = ["check", "--spec", "k", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "k", "--token", "ref"]), 22);
    let real = &e.lock()["realisations"]["k"]["ref"];
    assert_eq!(real["policy"]["CKA_SIGN"].as_bool(), Some(true));
    assert!(real["policy"].get("CKA_ENCRYPT").is_some(), "undeclared attributes are recorded too");
    assert_eq!(real["immutables"]["CKA_LOCAL"].as_bool(), Some(true));
    assert_eq!(real["immutables"]["CKA_KEY_GEN_MECHANISM"].as_str(), Some("CKM_AES_KEY_GEN"));

    // An undeclared attribute changed on the token: a change to review, then re-record.
    let s = e.session();
    let find = || {
        s.find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY), Attribute::Label(b"policy".to_vec())]).unwrap()[0]
    };
    let h = find();
    let encrypt = real["policy"]["CKA_ENCRYPT"].as_bool().unwrap();
    s.update_attributes(h, &[Attribute::Encrypt(!encrypt)]).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 14);
    assert!(stderr(&o).contains(&format!("CKA_ENCRYPT {encrypt} -> {}", !encrypt)), "{}", stderr(&o));
    assert_eq!(e.code(&r), 22);
    assert_eq!(e.code(&verify), 0);

    // The same material re-imported: the IDs match, but it is no longer CKA_LOCAL.
    let value = match s.get_attributes(h, &[AttributeType::Value]).unwrap().remove(0) {
        Attribute::Value(v) => v,
        a => panic!("{a:?}"),
    };
    s.destroy_object(h).unwrap();
    s.create_object(&[
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(cryptoki::object::KeyType::AES),
        Attribute::Token(true),
        Attribute::Label(b"policy".to_vec()),
        Attribute::Value(value),
        Attribute::Sign(true),
        Attribute::Encrypt(!encrypt),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ])
    .unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 14);
    assert!(stderr(&o).contains("was replaced") && stderr(&o).contains("CKA_LOCAL"), "{}", stderr(&o));
    assert_eq!(e.code(&r), 14, "also when updating");
}

/// P2-10: `CKA_ALLOWED_MECHANISMS` and `publicAttributes` are set when generating, checked on
/// the object (and on the public half), and a mechanism list the spec no longer names is a
/// conflict like any other attribute mismatch.
#[test]
fn allowed_mechanisms_and_public_attributes() {
    let Some(e) = env("attrs") else { return };
    let s = e.session();
    let spec = |mechs: &str, public: &str| {
        format!(
            "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.k]\nobject = \"k\"\n\
             attributes = {{ CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false, CKA_ALLOWED_MECHANISMS = [{mechs}] }}\n\
             publicAttributes = {{ {public} }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"attrs\" }}, origin = \"create\" }}\n"
        )
    };
    // A list without the proof's mechanism is an invalid spec (17); one the proof can use but
    // naming a mechanism the token does not offer is refused before anything is created (15).
    e.config(&spec("\"CKM_BOGUS\"", "CKA_VERIFY = false"));
    assert_eq!(e.code(&["create", "--spec", "k", "--token", "ref", "--no-update-lock"]), 17);
    e.config(&spec("\"CKM_ECDSA\", \"CKM_BOGUS\"", "CKA_VERIFY = false"));
    e.refused(&["create", "--spec", "k", "--token", "ref", "--no-update-lock"], 15, "templates");

    // Created with the restriction; the public half honors publicAttributes (the default
    // CKA_VERIFY = true is left out where they override it).
    e.config(&spec("\"CKM_ECDSA\", \"CKM_ECDSA_SHA256\"", "CKA_VERIFY = false"));
    assert_eq!(e.code(&["create", "--spec", "k", "--token", "ref"]), 22);
    let digest = e.lock()["realisations"]["k"]["ref"]["specDigest"].as_str().unwrap().to_owned();
    let policy = &e.lock()["realisations"]["k"]["ref"]["policy"]["CKA_ALLOWED_MECHANISMS"];
    assert_eq!(policy.as_array().map(std::vec::Vec::len), Some(2), "{policy}");
    assert_eq!(policy[0].as_str(), Some("CKM_ECDSA"), "{policy}");
    let public =
        s.find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::Label(b"attrs".to_vec())]).unwrap()[0];
    let Attribute::Verify(verify) = &s.get_attributes(public, &[AttributeType::Verify]).unwrap()[0] else {
        panic!("no CKA_VERIFY on the public half")
    };
    assert!(!*verify, "publicAttributes = {{ CKA_VERIFY = false }}");
    assert_eq!(e.code(&["check", "--spec", "k", "--token", "ref"]), 0);

    // The same set in another order is the same spec: same digest, no change to review.
    e.config(&spec("\"CKM_ECDSA_SHA256\", \"CKM_ECDSA\"", "CKA_VERIFY = false"));
    assert_eq!(e.code(&["check", "--spec", "k", "--token", "ref"]), 0);
    assert_eq!(e.lock()["realisations"]["k"]["ref"]["specDigest"].as_str(), Some(digest.as_str()));

    // A different set does not satisfy the object: a conflict naming the attribute.
    e.config(&spec("\"CKM_ECDSA_SHA256\"", "CKA_VERIFY = false"));
    let o = e.km(&["check", "--spec", "k", "--token", "ref"]);
    assert_eq!(code(&o), 13);
    assert!(stderr(&o).contains("CKA_ALLOWED_MECHANISMS"));
    e.config(&spec("\"CKM_ECDSA\", \"CKM_ECDSA_SHA256\"", "CKA_VERIFY = false"));

    // A changed public half is a conflict; without it publicAttributes cannot be checked (11).
    s.update_attributes(public, &[Attribute::Verify(true)]).unwrap();
    assert_eq!(e.code(&["check", "--spec", "k", "--token", "ref"]), 13);
    s.update_attributes(public, &[Attribute::Verify(false)]).unwrap();
    s.destroy_object(public).unwrap();
    assert_eq!(e.code(&["check", "--spec", "k", "--token", "ref"]), 11);
}

/// P2-10: `CKA_ALLOWED_MECHANISMS` joins the observed policy vector. It is read-only once set
/// (PKCS#11 3.2 §4), so it cannot drift on the token; a lock recorded before cakeys observed it
/// still verifies, with a note, and `lock` records it.
#[test]
fn an_undeclared_mechanism_list_is_observed_policy() {
    let Some(e) = env("attrs-drift") else { return };
    let s = e.session();
    let ec_params = P256.to_vec();
    let common = [
        Attribute::Token(true),
        Attribute::Label(b"attrs-drift".to_vec()),
        Attribute::AllowedMechanisms(vec![MechanismType::ECDSA, MechanismType::ECDSA_SHA256]),
    ];
    s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[&common[..], &[Attribute::EcParams(ec_params.clone())]].concat(),
        &[&common[..], &[Attribute::Sign(true), Attribute::Sensitive(true), Attribute::Extractable(false)]].concat(),
    )
    .unwrap();
    e.config(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n\
         tokens.ref = { locator = { CKA_LABEL = \"attrs-drift\" }, origin = \"adopt\" }\n",
    );
    assert_eq!(e.code(&["lock", "--spec", "k", "--token", "ref"]), 22);
    let policy = &e.lock()["realisations"]["k"]["ref"]["policy"];
    assert_eq!(policy.get("CKA_ALLOWED_MECHANISMS").map(|m| m.as_array().unwrap().len()), Some(2), "{policy}");

    // A lock that does not record the list (e.g. written by an older cakeys) still verifies.
    let mut lock = e.lock();
    let policy = lock["realisations"]["k"]["ref"]["policy"].as_table_mut().unwrap();
    assert!(policy.remove("CKA_ALLOWED_MECHANISMS").is_some());
    e.write_lock(&lock);
    let o = e.km(&["check", "--spec", "k", "--token", "ref"]);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("CKA_ALLOWED_MECHANISMS"), "{}", stderr(&o));
    assert_eq!(e.code(&["lock", "--spec", "k", "--token", "ref"]), 22);
    assert_eq!(e.code(&["check", "--spec", "k", "--token", "ref"]), 0);
}

/// H1 (docs/archive/REVIEW-2026-11-11.md): `SoftHSM` EC private keys expose no public key, so their
/// identity is read from the public key object under the same locator. Replace the private key,
/// keep the public object: a conflict (`assert_swapped_key_conflict`).
#[test]
fn h1_a_private_key_beside_an_unbound_public_object_is_a_conflict() {
    let Some(e) = env("gap_h1") else { return };
    e.config(EC.replace("ec-lifecycle", "gap-a").as_str());
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    assert_eq!(e.lock()["realisations"]["signing-soft"]["ref"]["binding"].as_str(), Some("pop-sign"));
    let usage = [Attribute::Sign(true), Attribute::Sensitive(true), Attribute::Extractable(false)];
    let p256 = [Attribute::EcParams(P256.to_vec())];
    swap_private_key(&e.session(), "gap-a", &Mechanism::EccKeyPairGen, &p256, &usage, &[]);
    // Different private key under the locator, same public object.
    assert_swapped_key_conflict(&e.km(&["check", "--spec", "signing-soft", "--token", "ref"]));
    // So is deleting: If-Match must not pass on the public object alone.
    assert_eq!(e.code(&["delete", "--spec", "signing-soft", "--token", "ref"]), 13);
}

/// The live object must be the declared type, and its public half must be one public key it
/// shows: another RSA size, another secret length or another certificate type is a conflict
/// (13); an EC key with no public key anywhere is not found (11) and one beside two public key
/// objects ambiguous (12); a public key object cakeys cannot read beside an RSA key is a
/// conflict (13), since a consumer selecting the public half by the locator could get it.
#[test]
fn the_live_object_must_be_what_the_spec_says() {
    let Some(e) = env("live-type") else { return };
    let s = e.session();
    let label = |name: &str| Attribute::Label(format!("live-{name}").into_bytes());
    let rsa_pair = |name: &str| {
        let public = [
            Attribute::Token(true),
            label(name),
            Attribute::ModulusBits(2048.into()),
            Attribute::PublicExponent(vec![1, 0, 1]),
            Attribute::Verify(true),
        ];
        s.generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &public,
            &[Attribute::Token(true), label(name), Attribute::Sign(true)],
        )
        .unwrap()
    };
    let p256 = P256;
    let pair = |mechanism: &Mechanism, name: &str, params: &[u8], usage: Attribute| {
        let public = [Attribute::Token(true), label(name), Attribute::EcParams(params.to_vec())];
        s.generate_key_pair(mechanism, &public, &[Attribute::Token(true), label(name), usage])
    };
    let ec_pair = |name: &str, params: &[u8]| pair(&Mechanism::EccKeyPairGen, name, params, Attribute::Sign(true));
    rsa_pair("rsa");
    let aes = [Attribute::Token(true), label("aes"), Attribute::ValueLen(32.into()), Attribute::Encrypt(true)];
    s.generate_key(&Mechanism::AesKeyGen, &aes).unwrap();
    let (public, _) = ec_pair("ec-alone", p256).unwrap();
    s.destroy_object(public).unwrap();
    ec_pair("ec-two", p256).unwrap();
    let (other, _) = ec_pair("ec-other", p256).unwrap();
    s.update_attributes(other, &[label("ec-two")]).unwrap();
    rsa_pair("rsa-odd");
    // A public key cakeys does not read, under the RSA key's locator: P-224 where the module
    // makes it (SoftHSM), else an X25519 key (kryoptic).
    let p224 = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x21];
    let x25519 = [0x06, 0x03, 0x2b, 0x65, 0x6e];
    let (odd, _) = ec_pair("odd", &p224)
        .or_else(|_| pair(&Mechanism::EccMontgomeryKeyPairGen, "odd", &x25519, Attribute::Derive(true)))
        .unwrap();
    s.update_attributes(odd, &[label("rsa-odd")]).unwrap();
    // An RSA pair beside a second public key of another pair, and one whose public half is
    // another pair's: what a spec declaring publicAttributes checks first.
    rsa_pair("pub-two");
    let (extra, _) = rsa_pair("pub-extra");
    s.update_attributes(extra, &[label("pub-two")]).unwrap();
    let (own, _) = rsa_pair("pub-swap");
    s.destroy_object(own).unwrap();
    let (foreign, _) = rsa_pair("pub-foreign");
    s.update_attributes(foreign, &[label("pub-swap")]).unwrap();
    drop(s);

    let spec = |name: &str, object: &str, usage: &str, label: &str| {
        format!(
            "[objects.{name}]\n{object}\n\n[specs.{name}]\nobject = \"{name}\"\nattributes = {{ {usage} = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"live-{label}\" }}, origin = \"adopt\" }}\n\n"
        )
    };
    let rsa = |bits: u32| format!("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = {bits}");
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    e.config(
        &[
            spec("big", &rsa(3072), "CKA_SIGN", "rsa"),
            spec("short", "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 16", "CKA_ENCRYPT", "aes"),
            spec("alone", ec, "CKA_SIGN", "ec-alone"),
            spec("two", ec, "CKA_SIGN", "ec-two"),
            spec("odd", &rsa(2048), "CKA_SIGN", "rsa-odd"),
            spec("pub-two", &rsa(2048), "CKA_SIGN", "pub-two")
                .replace("tokens.ref", "publicAttributes = { CKA_VERIFY = true }\ntokens.ref"),
            spec("pub-swap", &rsa(2048), "CKA_SIGN", "pub-swap")
                .replace("tokens.ref", "publicAttributes = { CKA_VERIFY = true }\ntokens.ref"),
            spec("pub-only", &rsa(2048), "CKA_SIGN", "rsa")
                .replace("attributes = { CKA_SIGN = true }", "publicAttributes = { CKA_VERIFY = true }")
                .replace(" }\n\n", ", publicOnly = true }\n\n"),
        ]
        .concat(),
    );
    let refused = |spec: &str, exit: i32, why: &str| {
        let o = e.km(&["lock", "--spec", spec, "--token", "ref", "--dry-run"]);
        assert_eq!(code(&o), exit, "{spec}: {}", stderr(&o));
        assert!(stderr(&o).contains(why), "{spec}: expected {why:?} in {}", stderr(&o));
    };
    refused("big", 13, "RSA modulus is Some(2048) bits, spec says 3072");
    refused("short", 13, "CKA_VALUE_LEN is");
    refused("two", 12, "several public key objects share the locator");
    refused("odd", 13, "exposes no key material");
    refused("pub-two", 12, "several public key objects share the locator");
    refused("pub-swap", 13, "the public key object under the locator holds another key");
    // Adopted publicOnly, the public key object itself carries the publicAttributes.
    assert_eq!(e.code(&["lock", "--spec", "pub-only", "--token", "ref", "--dry-run"]), 18);
    // kryoptic's EC private key carries its own CKA_PUBLIC_KEY_INFO; SoftHSM's carries no public key.
    if REF.provider == "softhsm" {
        refused("alone", 11, "no public key object, CKA_PUBLIC_KEY_INFO or certificate under the locator");
    } else {
        assert_eq!(e.code(&["lock", "--spec", "alone", "--token", "ref", "--dry-run"]), 18);
    }
}

/// H1b (report "Cakeys lock file design review"): `SoftHSM` lets a user set `CKA_PUBLIC_KEY_INFO` on a
/// private key without checking it. cakeys reads the key material first and only cross-checks the
/// asserted SPKI, so a different RSA private key carrying the old SPKI is a conflict.
#[test]
fn h1b_a_forged_public_key_info_is_a_conflict() {
    let Some(e) = env("gap_h1b") else { return };
    e.config(
        "[objects.r]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n\
         [specs.r]\nobject = \"r\"\nattributes = { CKA_SIGN = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"h1b\" }, origin = \"create\" }\n",
    );
    assert_eq!(e.code(&["create", "--spec", "r", "--token", "ref"]), 22);
    let s = e.session();
    let spki_a = oracle_spki(&s, "h1b");
    let rsa = [Attribute::ModulusBits(2048.into()), Attribute::PublicExponent(vec![1, 0, 1])];
    let forged = [Attribute::PublicKeyInfo(spki_a)];
    swap_private_key(&s, "h1b", &Mechanism::RsaPkcsKeyPairGen, &rsa, &[Attribute::Sign(true)], &forged);
    drop(s);
    let o = e.km(&["check", "--spec", "r", "--token", "ref"]);
    assert_eq!(code(&o), 13);
    assert!(stderr(&o).contains("disagrees with the key material"));
}

/// S3: a (spec, token) pair the lock has never recorded does not verify on object IDs alone.
#[test]
fn s3_an_unrecorded_token_is_a_precondition_failure() {
    let Some(e) = env("gap_s3") else { return };
    let pin = e.dir.join("pin");
    e.config(&format!(
        "[tokens.ref-b]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n\n{}\
         tokens.ref-b = {{ locator = {{ CKA_LABEL = \"s3\" }}, origin = \"adopt\" }}\n",
        e.module,
        pin.display(),
        EC.replace("ec-lifecycle", "s3")
    ));
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    let verify = ["check", "--spec", "signing-soft", "--token", "ref-b"];
    assert_eq!(e.code(&verify), 14);
    assert_eq!(e.code(&["lock", "--spec", "signing-soft", "--token", "ref-b"]), 22);
    assert_eq!(e.code(&verify), 0);
}

/// S4: turning publicOnly on is a change to keys.toml, also for a spec without attributes.
#[test]
fn s4_a_public_only_flip_is_a_spec_change() {
    let Some(e) = env("gap_s4") else { return };
    let body = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [specs.k]\nobject = \"k\"\ntokens.ref = { locator = { CKA_LABEL = \"s4\" }, origin = \"create\", binding = \"token-asserted\" }\n";
    e.config(body);
    assert_eq!(e.code(&["create", "--spec", "k", "--token", "ref"]), 22);
    e.config(&body.replace("origin = \"create\", binding = ", "origin = \"adopt\", publicOnly = true, binding = "));
    let verify = e.km(&["check", "--spec", "k", "--token", "ref"]);
    assert_eq!(code(&verify), 14);
    assert!(stderr(&verify).contains("publicOnly false -> true"));
}

/// S8: pointing a spec at another object, or another locator, is reported as a keys.toml change
/// (exit 14), not as an unexplained hash mismatch.
#[test]
fn s8_a_retargeted_spec_is_a_spec_change() {
    let Some(e) = env("gap_s8") else { return };
    let body = "[objects.a]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [objects.b]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                [specs.sa]\nobject = \"a\"\nattributes = { CKA_SIGN = true }\ntokens.ref = { locator = { CKA_LABEL = \"s8-a\" }, origin = \"create\" }\n\n\
                [specs.sb]\nobject = \"b\"\nattributes = { CKA_SIGN = true }\ntokens.ref = { locator = { CKA_LABEL = \"s8-b\" }, origin = \"create\" }\n";
    e.config(body);
    assert_eq!(e.code(&["create", "--token", "ref"]), 22);
    let lock = e.lock();
    assert_eq!(lock["realisations"]["sa"]["ref"]["object"].as_str(), Some("a"));
    assert_eq!(lock["realisations"]["sa"]["ref"]["locator"]["CKA_LABEL"].as_str(), Some("s8-a"));
    e.config(
        &body
            .replace("[specs.sa]\nobject = \"a\"", "[specs.sa]\nobject = \"b\"")
            .replace("\"s8-a\" }, origin = \"create\"", "\"s8-a\" }, origin = \"adopt\""),
    );
    let verify = e.km(&["check", "--spec", "sa", "--token", "ref"]);
    assert_eq!(code(&verify), 14);
    assert!(stderr(&verify).contains("object 'a' -> 'b'"));
    // The same object under another locator: also a change to review.
    e.config(&body.replace("CKA_LABEL = \"s8-a\"", "CKA_LABEL = \"s8-b\""));
    assert_eq!(e.code(&["check", "--spec", "sa", "--token", "ref"]), 14);
}
