//! Tests of what is refused before any token is asked: keys.toml's rules and the address grammar.

use super::*;

/// An object that cannot be adopted is invalid (17) at `validate`. An object that can be adopted
/// but never created (a publicOnly key, a certificate) is valid there, and a `create` that names
/// it refuses it (17).
#[test]
fn adoption_rules_are_validated() {
    let Some(e) = env("adoption_rules") else { return };
    let rsa = "keyType = \"CKK_RSA\"\nmodulusBits = 2048\nclass = \"CKO_PRIVATE_KEY\"";
    let cert = "certificateType = \"CKC_X_509\"\nclass = \"CKO_CERTIFICATE\"";
    for (body, why, valid) in [
        (rsa, "{ CKA_LABEL = \"x\" }, publicOnly = true", true),
        (rsa, "{ CKA_LABEL = \"x\" }, publicOnly = true }\nattributes = { CKA_SIGN = true", false),
        (cert, "{ CKA_LABEL = \"x\" }", true),
        (
            "keyType = \"CKK_AES\"\nvalueLen = 32\nclass = \"CKO_SECRET_KEY\"",
            "{ CKA_LABEL = \"x\" }, publicOnly = true",
            false,
        ),
    ] {
        e.config(&format!("[objects.o]\n{body}\n\n[specs.s]\nobject = \"o\"\ntokens.ref = {{ locator = {why} }}\n"));
        assert_eq!(e.code(&["validate"]), if valid { 0 } else { 17 }, "{body} / {why}");
        assert_eq!(e.code(&["create", "--spec", "s", "--token", "ref", "--no-update-lock"]), 17, "{body} / {why}");
    }
    assert!(e.session().labelled("x").is_empty(), "nothing was created");
}

/// P2-10: declared attribute names must fit the class (PKCS#11 3.2 §4), the extra booleans can be
/// set, and the refusals apply. `binding = "pop-sign-pin"` is recorded in the lock but never
/// configured, a `CKA_ALWAYS_AUTHENTICATE` key proves possession only by signing, and a key with
/// `CKA_TRUSTED = true` cannot be generated.
#[test]
fn attributes_are_validated_per_class() {
    let Some(e) = env("attr-class") else { return };
    // Each case is invalid (17) for its own reason. The configuration around each case is valid,
    // so a refusal of that configuration (a label, origin or locator rule) cannot be mistaken for
    // the refusal under test.
    for (object, attrs, why) in [
        (
            "certificateType = \"CKC_X_509\"\nclass = \"CKO_CERTIFICATE\"",
            "attributes = { CKA_SIGN = true }",
            "CKA_SIGN does not apply to CKO_CERTIFICATE",
        ),
        (
            "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
            "attributes = { CKA_SIGN = true, CKA_TRUSTED = true }",
            "CKA_TRUSTED does not apply to CKO_PRIVATE_KEY",
        ),
        (
            "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
            "attributes = { CKA_SIGN = true }\npublicAttributes = { CKA_ALWAYS_AUTHENTICATE = true }",
            "CKA_ALWAYS_AUTHENTICATE does not apply to CKO_PUBLIC_KEY",
        ),
        (
            "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32",
            "attributes = { CKA_ALWAYS_AUTHENTICATE = true }",
            "CKA_ALWAYS_AUTHENTICATE does not apply to CKO_SECRET_KEY",
        ),
        (
            "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
            "attributes = { CKA_SIGN = true, CKA_DERIVE = [\"CKM_ECDSA\"] }",
            "only CKA_ALLOWED_MECHANISMS takes a mechanism list",
        ),
    ] {
        e.config(&format!(
            "[objects.o]\n{object}\n\n[specs.s]\nobject = \"o\"\n{attrs}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"x\" }}, origin = \"adopt\" }}\n"
        ));
        let o = e.km(&["validate"]);
        assert!(code(&o) == 17 && stderr(&o).contains(why), "{attrs}: expected 17 and {why:?}: {}", stderr(&o));
    }

    // A CKA_ALWAYS_AUTHENTICATE key proves possession with a PIN for each use (pop-sign, the
    // default)...
    e.config(
        "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"o\"\nattributes = { CKA_SIGN = true, CKA_ALWAYS_AUTHENTICATE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"x\" }, origin = \"adopt\" }\n",
    );
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // ...but pop-sign-pin is what the lock records, never what keys.toml asks for.
    e.config(
        "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"o\"\nattributes = { CKA_SIGN = true, CKA_ALWAYS_AUTHENTICATE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"x\" }, origin = \"adopt\", binding = \"pop-sign-pin\" }\n",
    );
    assert_eq!(e.code(&["validate"]), 17);
    // Every signing key may declare it, including Edwards keys. A key whose proof is not a
    // signature (here `pop-ecdh`) may not, because only `pop-sign` proves possession with a
    // per-use login.
    e.config(
        "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"\n\n\
         [specs.s]\nobject = \"o\"\nattributes = { CKA_SIGN = true, CKA_ALWAYS_AUTHENTICATE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"x\" }, origin = \"adopt\" }\n",
    );
    assert_eq!(e.code(&["validate"]), 0);
    e.config(
        "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"o\"\nattributes = { CKA_DERIVE = true, CKA_ALWAYS_AUTHENTICATE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"x\" }, origin = \"adopt\", binding = \"pop-ecdh\" }\n",
    );
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 17);
    assert!(stderr(&o).contains("only \"pop-sign\" proves possession with it"), "{}", stderr(&o));

    // The token's security officer sets CKA_TRUSTED, and generation never sets it. Such a key is
    // therefore adopted (or imported), and it never has `origin = "create"`.
    let trusted = |origin: &str| {
        e.config(&format!(
            "[objects.o]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
             [specs.s]\nobject = \"o\"\nattributes = {{ CKA_WRAP = true, CKA_TRUSTED = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"trusted\" }}, origin = \"{origin}\" }}\n"
        ));
        e.km(&["validate"])
    };
    assert_eq!(code(&trusted("adopt")), 0, "adopted, a trusted key is only read");
    let o = trusted("create");
    assert_eq!(code(&o), 17);
    assert!(stderr(&o).contains("CKA_TRUSTED = true cannot be generated"), "{}", stderr(&o));

    // The extra booleans can be set: the key is created with them, and the policy records them.
    // binding = "token-asserted" replaces the proof of possession, which this key cannot perform.
    let s = e.session();
    e.config(
        "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"o\"\n\
         attributes = { CKA_SIGN = true, CKA_ALWAYS_AUTHENTICATE = true, CKA_DESTROYABLE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"always-auth\" }, origin = \"create\", binding = \"token-asserted\" }\n",
    );
    assert_eq!(e.code(&["create", "--spec", "s", "--token", "ref"]), 22);
    let policy = &e.lock()["realisations"]["s"]["ref"]["policy"];
    assert_eq!(policy["CKA_ALWAYS_AUTHENTICATE"].as_bool(), Some(true), "{policy}");
    let private = s
        .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Label(b"always-auth".to_vec())])
        .unwrap()[0];
    let Attribute::AlwaysAuthenticate(aa) =
        &s.get_attributes(private, &[AttributeType::AlwaysAuthenticate]).unwrap()[0]
    else {
        panic!("no CKA_ALWAYS_AUTHENTICATE on the private half")
    };
    assert!(*aa, "the template set CKA_ALWAYS_AUTHENTICATE");
    assert_eq!(e.code(&["check", "--spec", "s", "--token", "ref"]), 0);
}

#[test]
fn brainpool_p512_is_refused_clearly() {
    let Some(e) = env("bp512") else { return };
    e.config(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"brainpoolP512r1\"\n\n\
         [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\ntokens.ref = { locator = { CKA_LABEL = \"bp512\" }, origin = \"create\" }\n",
    );
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 15);
    assert!(stderr(&o).contains("no RustCrypto crate"));
}

/// `[tokens.<t>.options]` belong to the token's provider, which checks them when the token is
/// opened (and `validate` checks them when the provider is named). The reference providers take
/// no options, so any option is refused (17) instead of being silently ignored.
#[test]
fn provider_options_are_checked_by_the_provider() {
    let Some(e) = env("options") else { return };
    std::fs::write(
        e.dir.join("keys.toml"),
        format!(
            "[tokens.ref]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\noptions = {{ tcti = \"device:/dev/tpmrm0\" }}\n\n{}",
            e.module,
            EC.replace("ec-lifecycle", "options")
        ),
    )
    .unwrap();
    let o = e.km(&["resolve", "--spec", "signing-soft", "--token", "ref"]);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    let refused = format!("provider {} takes no options", REF.provider);
    assert!(stderr(&o).contains(&format!("tokens.ref.options.tcti: {refused}")));
    // With the provider named, `validate` checks them without opening the token.
    let named = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap().replacen(
        "tokenLabel",
        &format!("provider = \"{}\"\ntokenLabel", REF.provider),
        1,
    );
    std::fs::write(e.dir.join("keys.toml"), named).unwrap();
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    assert!(stderr(&o).contains(&refused));
}

/// Every verb takes the same address (docs/CAKEYS.md): the object first, narrowed by `--spec`
/// and `--token` when it is realised more than once. `--spec` alone names its object. Only
/// `check` accepts `.id.<scheme>`. A name that keys.toml lacks is refused with 17.
#[test]
fn every_verb_names_the_object_first() {
    let Some(e) = env("address") else { return };
    e.config(
        r#"
[objects.signer]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.signer-ref]
object = "signer"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "addr-k" }, origin = "create" }
"#,
    );
    assert_eq!(e.code(&["create", "signer"]), 22);
    for args in [
        &["resolve", "signer"][..],
        &["lock", "signer", "--token", "ref"],
        &["lock", "--spec", "signer-ref"],
        &["check", "signer"],
        &["check", "signer.id.rfc7093m4", "--spec", "signer-ref", "--token", "ref"],
    ] {
        let o = e.km(args);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
    }
    for args in [
        &["lock", "signer.id.rfc7093m4"][..],
        &["resolve"],
        &["check", "nope"],
        &["check", "--spec", "nope"],
        &["delete", "signer", "--spec", "nope"],
        &["lock", "signer", "--token", "nope"],
    ] {
        assert_eq!(e.code(args), 17, "{args:?}");
    }

    // When the object is realised twice (the same key under a second token name), the bare
    // object is ambiguous (12) for every verb, including `delete`, until `--spec` or `--token`
    // narrows it (review validate.rs F1).
    let text = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    e.write_config(&format!(
        "{text}\n[tokens.ref2]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n\n\
         [specs.signer-two]\nobject = \"signer\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.ref2 = {{ locator = {{ CKA_LABEL = \"addr-k\" }}, origin = \"adopt\" }}\n",
        e.module,
        e.dir.join("pin").display()
    ));
    let made = e.session().labelled("addr-k").len();
    assert!(made > 0);
    for verb in ["resolve", "lock", "check", "delete"] {
        let o = e.km(&[verb, "signer"]);
        assert_eq!(code(&o), 12, "{verb}: {}", stderr(&o));
    }
    assert_eq!(e.session().labelled("addr-k").len(), made, "an ambiguous delete removed something");
    assert_eq!(e.code(&["check", "signer", "--spec", "signer-ref"]), 0);
    assert_eq!(e.code(&["check", "signer", "--token", "ref"]), 0);

    // The delete also removes the key, so `check` finds nothing afterward (review validate.rs
    // F3).
    assert_eq!(e.code(&["delete", "signer", "--spec", "signer-ref"]), 22);
    assert_eq!(e.session().labelled("addr-k"), []);
    assert_eq!(e.code(&["check", "signer", "--spec", "signer-ref"]), 11);
}
