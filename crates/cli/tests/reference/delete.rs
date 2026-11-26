//! `delete` and `gc`: only what was identified is removed, from the token and from the lock.

use super::*;

#[test]
fn ec_lifecycle() {
    let Some(e) = env("ec_lifecycle") else { return };
    e.config(EC);
    let r = ["lock", "--spec", "signing-soft", "--token", "ref", "--dry-run"];
    let c = ["create", "--spec", "signing-soft", "--token", "ref", "--no-update-lock"];

    // Only `create` creates: `lock` and `check` find nothing, and name it.
    let absent = e.km(&r);
    assert_eq!(code(&absent), 11);
    assert!(stderr(&absent).contains("`cakeys create` makes it"), "{}", stderr(&absent));
    assert_eq!(e.code(&["check", "signing"]), 11);
    assert!(e.session().labelled("ec-lifecycle").is_empty(), "lock and check never create");
    // First use: creates, then fails like a FOD with a fake hash.
    let first = e.km(&c);
    assert_eq!(code(&first), 18);
    let got = got_hash(&first);
    // Re-running finds the same object: same hash, no duplicate (else exit 12, ambiguous).
    let again = e.km(&r);
    assert_eq!(code(&again), 18);
    assert_eq!(got_hash(&again), got);
    assert_eq!(e.code(&["resolve", "--spec", "signing-soft", "--token", "ref"]), 0);

    // Record it; now lock is a no-op success.
    assert_eq!(e.code(&recording(&r)), 22);
    assert_eq!(e.locked_id("signing", "rfc7093m4"), got);
    assert_eq!(e.code(&r), 0);

    let verify = e.km(&["check", "--spec", "signing-soft", "--token", "ref"]);
    assert_eq!(code(&verify), 0);
    let uri = stdout(&verify);
    assert!(
        uri.starts_with("pkcs11:token=kmtest;serial=") && uri.contains(";object=ec-lifecycle;type=private"),
        "{uri}"
    );
    let check = e.km(&["check", "signing.id.rfc7093m4"]);
    assert_eq!(code(&check), 0);
    // `pubkeyhash` is an input alias of rfc7093m4.
    assert_eq!(stdout(&e.km(&["check", "signing.id.pubkeyhash"])), stdout(&check));
    assert_eq!(stdout(&check), stdout(&verify));
    assert_eq!(e.code(&["check", "signing.id.commitment"]), 15);

    // The module and PIN only on request: the default output stays the locator.
    assert!(!stdout(&check).contains('?'), "{}", stdout(&check));

    // DELETE + If-Match.
    let del = ["delete", "--spec", "signing-soft", "--token", "ref"];
    e.refused(&[&del[..], &["--if-match", "sha256-AAAA"]].concat(), 14, "if-match");
    assert_eq!(e.code(&["check", "--spec", "signing-soft", "--token", "ref"]), 0);
    // The right one deletes (review delete.rs F1: only a wrong one was tested).
    let right = e.km(&[&del[..], &["--if-match", &got]].concat());
    assert_eq!(code(&right), 22, "{}", stderr(&right));
    assert_eq!(e.code(&del), 0, "delete of an absent object succeeds, and changes nothing");
    assert_eq!(e.code(&["check", "--spec", "signing-soft", "--token", "ref"]), 11);
    // Both halves gone from the token, not only unfound (review delete.rs F3).
    assert_eq!(e.session().labelled("ec-lifecycle"), []);
    assert!(e.lock().get("realisations").and_then(|r| r.get("signing-soft")).is_none());

    // Deleting something that never existed succeeds even with no expected identity anywhere,
    // and writes no lock.
    std::fs::remove_file(e.dir.join("keys.lock")).unwrap();
    assert_eq!(e.code(&["--new-lock", "delete", "--spec", "signing-soft", "--token", "ref"]), 0);
    assert!(!e.dir.join("keys.lock").exists());
    // ...but a present object with no expected identity is never deleted blindly, nor planned.
    let fresh = e.km(&[&["--new-lock"][..], &c].concat());
    assert_eq!(code(&fresh), 18);
    let unlocked = ["--new-lock", "delete", "--spec", "signing-soft", "--token", "ref"];
    e.refused(&unlocked, 14, "if-match");
    e.refused(&[&unlocked[..], &["--dry-run"]].concat(), 14, "if-match");
    assert_eq!(e.code(&["check", "--spec", "signing-soft", "--token", "ref"]), 17, "no lock");
    assert_eq!(e.code(&["--new-lock", "check", "--spec", "signing-soft", "--token", "ref"]), 18);
    // `--if-match` is the expected identity where no lock gives one.
    let o = e.km(&[&unlocked[..], &["--if-match", &got_hash(&fresh)]].concat());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(e.session().labelled("ec-lifecycle"), []);
    // Restore the original locked identity for the final check.
    std::fs::write(
        e.dir.join("keys.lock"),
        format!(
            "version = 1\n[objects.signing.type]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\
             [objects.signing.ids]\nrfc7093m4 = \"{got}\"\n"
        ),
    )
    .unwrap();

    // A re-created key is new material: the lock pins the old identity, so `create` is
    // refused up front (D1) and regeneration can never satisfy it.
    e.refused(&c, 14, "pinned-lost");
    assert_eq!(e.code(&r), 11);
    assert_eq!(e.code(&del), 0, "nothing was created, so absent is success again");
}

/// D3: `gc --dry-run` prints lock entries whose spec or token is gone from keys.toml, and `gc`
/// removes exactly what it printed. Live objects keep their ids.
#[test]
fn gc_prints_then_removes_stale_entries() {
    let Some(e) = env("gc") else { return };
    let object = "[objects.signing]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n";
    e.config(EC.replace("ec-lifecycle", "gc-key").as_str());
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    let id = e.locked_id("signing", "rfc7093m4");
    let key = || e.lock()["realisations"]["signing-soft"]["ref"]["observation"].as_str().unwrap().to_owned();

    // Nothing stale: prints nothing, and gc writes nothing.
    for args in [&["gc", "--dry-run"][..], &["gc"][..]] {
        let o = e.km(args);
        assert_eq!(code(&o), 0, "{args:?}");
        assert_eq!(stdout(&o), "");
    }
    assert!(e.lock()["realisations"]["signing-soft"]["ref"].is_table());
    assert_eq!(e.locked_id("signing", "rfc7093m4"), id);

    // The spec is gone: its realisation is stale, printed as the table name, and so is the
    // observation only it named; gc removes both but keeps the object's ids (the material may
    // live on elsewhere).
    e.config(object);
    let stale = format!("realisations.signing-soft.ref\nobservations.\"{}\"", key());
    let o = e.km(&["gc", "--dry-run"]);
    assert_eq!(code(&o), 0);
    assert_eq!(stdout(&o), stale);
    assert!(e.lock()["realisations"]["signing-soft"]["ref"].is_table(), "not removed by --dry-run");
    let o = e.km(&["gc"]);
    assert_eq!(code(&o), 22);
    assert_eq!(stdout(&o), stale);
    assert!(e.lock().get("realisations").and_then(|r| r.get("signing-soft")).is_none());
    assert_eq!(e.locked_id("signing", "rfc7093m4"), id);
    assert!(e.lock().get("observations").is_none());

    // Re-recorded, then the spec loses the token: the same realisation is stale again.
    let spec_body = "[specs.signing-soft]\nobject = \"signing\"\nattributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n";
    let spec_no_token = format!("{spec_body}tokens = {{}}\n");
    let spec_full =
        format!("{spec_body}tokens.ref = {{ locator = {{ CKA_LABEL = \"gc-key\" }}, origin = \"create\" }}\n");
    e.config(&format!("{object}\n{spec_full}"));
    assert_eq!(e.code(&["lock", "--spec", "signing-soft", "--token", "ref"]), 22);
    e.config(&format!("{object}\n{spec_no_token}"));
    let stale = format!("realisations.signing-soft.ref\nobservations.\"{}\"", key());
    assert_eq!(stdout(&e.km(&["gc", "--dry-run"])), stale);
    assert_eq!(e.code(&["gc"]), 22);
    assert!(e.lock().get("realisations").and_then(|r| r.get("signing-soft")).is_none());

    // The object too is gone from keys.toml: its record is collected.
    e.config("");
    assert_eq!(stdout(&e.km(&["gc", "--dry-run"])), "objects.signing");
    assert!(e.lock()["objects"]["signing"].is_table(), "not removed by --dry-run");
    assert_eq!(e.code(&["gc"]), 22);
    assert!(e.lock().get("objects").and_then(|o| o.get("signing")).is_none());
    assert_eq!(stdout(&e.km(&["gc", "--dry-run"])), "");
}

/// A public key object of another key under a private key's locator is a conflict (13) for
/// every verb that resolves: a consumer selecting the public half by the locator would get it.
/// `delete` still removes only what it identified — the private key, and its public half only
/// when that holds the same key — so the foreign object and, once the private key is gone, a lone
/// public key are left. A session without login cannot see the private key, so it never reports
/// it absent (16).
#[test]
fn a_foreign_public_key_conflicts_and_is_never_deleted() {
    let Some(e) = env("delete_identified") else { return };
    let s = e.session();
    e.config(
        r#"
[objects.k]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
modulusBits = 2048

[objects.other]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_RSA"
modulusBits = 2048

[specs.k]
object = "k"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "del-rsa" }, origin = "create" }
tokens.ref-anon = { locator = { CKA_LABEL = "del-rsa" }, origin = "adopt" }

[specs.other]
object = "other"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "del-other" }, origin = "create" }
"#,
    );
    for spec in ["k", "other"] {
        assert_eq!(e.code(&["create", "--spec", spec, "--token", "ref"]), 22);
    }
    let of_class = |class, label: &str| {
        s.find_objects(&[Attribute::Class(class), Attribute::Label(label.as_bytes().to_vec())]).unwrap()
    };
    let modulus = |h| s.get_attributes(h, &[AttributeType::Modulus]).unwrap();
    // Another key's public half, planted under the locator.
    let other = of_class(ObjectClass::PUBLIC_KEY, "del-other")[0];
    let mut planted = vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(cryptoki::object::KeyType::RSA),
        Attribute::Token(true),
        Attribute::Label(b"del-rsa".to_vec()),
    ];
    planted.extend(s.get_attributes(other, &[AttributeType::Modulus, AttributeType::PublicExponent]).unwrap());
    s.create_object(&planted).unwrap();
    assert_eq!(of_class(ObjectClass::PUBLIC_KEY, "del-rsa").len(), 2);
    for verb in ["check", "resolve"] {
        let o = e.km(&[verb, "--spec", "k", "--token", "ref"]);
        assert_eq!(code(&o), 13, "{verb}: {}", stderr(&o));
        assert!(stderr(&o).contains("holds another key"), "{verb}");
    }
    assert_eq!(e.code(&["check", "k", "--token", "ref"]), 13);

    let del = |token| e.km(&["delete", "--spec", "k", "--token", token]);
    // Nothing deleted unseen: the token as it was.
    e.refused(&["delete", "--spec", "k", "--token", "ref-anon"], 16, "needs-login");

    let o = del("ref");
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert!(stderr(&o).contains("left 1 public key object(s)"));
    assert_eq!(of_class(ObjectClass::PRIVATE_KEY, "del-rsa").len(), 0, "the identified private key is gone");
    let left = of_class(ObjectClass::PUBLIC_KEY, "del-rsa");
    assert_eq!(left.len(), 1);
    assert_eq!(modulus(left[0]), modulus(other), "the planted key is the one left");

    // Absent now: success, and the lone public key is still not identified, so it stays.
    assert_eq!(code(&del("ref")), 0);
    assert_eq!(of_class(ObjectClass::PUBLIC_KEY, "del-rsa").len(), 1);
}
