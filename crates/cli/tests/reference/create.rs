//! `create`: the one verb that makes keys, what it refuses before making anything, and what it
//! records.

use super::*;

#[test]
fn never_create_over_an_occupied_locator() {
    let Some(e) = env("occupied") else { return };
    let s = e.session();
    s.create_object(&cert_object(ADOPT_CERT, b"occupied", None)).unwrap();
    e.config(
        r#"
[objects.k]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.k]
object = "k"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "occupied" }, origin = "create" }
"#,
    );
    // Like a PIV slot holding a certificate: generating there would replace its key. The token
    // is as it was: no key made beside the certificate.
    e.refused(&["create", "--spec", "k", "--token", "ref", "--no-update-lock"], 13, "locator-free");
}

/// What `create` refuses once its token is open, `create --dry-run` refuses too, with the same
/// exit and naming the rule, and neither changes the lock or the token: another class under the
/// locator (`locator-free`, 13), a key there the lock does not pin (`unpinned-exists`, 19), a
/// pinned key the token lost (`pinned-lost`, 14), a token without login (`needs-login`, 16).
/// The dry run once planned without the token and passed, 0, each time (review 2026-11-24 C-4).
#[test]
fn a_dry_run_refuses_what_the_run_refuses_on_the_token() {
    let Some(e) = env("create-twins") else { return };
    let s = e.session();
    s.create_object(&cert_object(ADOPT_CERT, b"twin-occupied", None)).unwrap();
    let key = |name: &str, token: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.{token} = {{ locator = {{ CKA_LABEL = \"twin-{name}\" }}, origin = \"create\" }}\n\n"
        )
    };
    e.config(&(key("occupied", "ref") + &key("exists", "ref") + &key("lost", "ref") + &key("anon", "ref-anon")));
    // Made and not recorded: a first use (18).
    assert_eq!(e.code(&["create", "--spec", "exists", "--token", "ref", "--no-update-lock"]), 18);
    assert_eq!(e.code(&["create", "--spec", "lost", "--token", "ref"]), 22);
    for h in s.labelled("twin-lost") {
        s.destroy_object(h).unwrap();
    }
    for (spec, token, exit, rule) in [
        ("occupied", "ref", 13, "locator-free"),
        ("exists", "ref", 19, "unpinned-exists"),
        ("lost", "ref", 14, "pinned-lost"),
        ("anon", "ref-anon", 16, "needs-login"),
    ] {
        let args = ["create", "--spec", spec, "--token", token];
        let plan = e.refused(&[&args[..], &["--dry-run"]].concat(), exit, rule);
        assert_eq!(plan[0].more["action"].as_str(), Some("refuse"), "{spec}: {plan:?}");
        e.refused(&args, exit, rule);
    }
}

/// A session without login cannot see a private key: `create` on a pair whose key the lock pins,
/// through a token with no PIN configured, is refused for the login (`needs-login`, 16). It once
/// said the key was gone and creating it would make other material (14, D1), for a key that was
/// there.
#[test]
fn create_without_login_asks_for_a_pin() {
    let Some(e) = env("create-no-login") else { return };
    let spec = |token: &str| {
        format!(
            "[objects.nl]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.nl]\nobject = \"nl\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.{token} = {{ locator = {{ CKA_LABEL = \"create-nl\" }}, origin = \"create\" }}\n"
        )
    };
    e.config(&spec("ref"));
    assert_eq!(e.code(&["create", "--spec", "nl", "--token", "ref"]), 22);
    e.config(&spec("ref-anon"));
    e.refused(&["create", "--spec", "nl", "--token", "ref-anon", "--no-update-lock"], 16, "needs-login");
}

/// D1: when the lock already pins an object's material, `create` is refused before anything is
/// created — generated material could never match. The same material adopted (or already under the
/// locator) still realises through `lock`; `create` there makes nothing and verifies it as
/// `check` does, which wants the realisation recorded first (14).
#[test]
fn create_never_fights_a_locked_identity() {
    let Some(e) = env("d1") else { return };
    let second = "[specs.second-slot]\nobject = \"signing\"\nattributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }\n";
    e.config(EC.replace("ec-lifecycle", "d1-first").as_str());
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    let id = e.locked_id("signing", "rfc7093m4");

    // A second spec over the same object, an empty locator, now the one that creates it (the
    // first adopts what is there): `create` is refused up front (14), naming the pinned scheme —
    // also when the lock is written — and nothing is created.
    let first = EC.replace("ec-lifecycle", "d1-first").replace("origin = \"create\"", "origin = \"adopt\"");
    e.config(&format!(
        "{first}{second}tokens.ref = {{ locator = {{ CKA_LABEL = \"d1-second\" }}, origin = \"create\" }}\n"
    ));
    for args in [
        &["create", "--spec", "second-slot", "--token", "ref", "--no-update-lock"][..],
        &["create", "--spec", "second-slot", "--token", "ref"][..],
    ] {
        let rows = e.refused(args, 14, "pinned-lost");
        assert!(rows[0].error.as_deref().is_some_and(|e| e.contains("rfc7093m4")), "{rows:?}");
    }
    let s = e.session();

    // The same material under the locator still realises (like `two_specs_same_material`): the
    // second spec's `lock` records a second realisation of the one object. `create` never makes
    // a pinned key again: it verifies the one that is there as `check` does, which refuses a
    // realisation the lock does not record (14) until `lock` records it; then it passes.
    e.config(&format!(
        "{first}{second}tokens.ref = {{ locator = {{ CKA_LABEL = \"d1-first\" }}, origin = \"create\" }}\n"
    ));
    let o = e.km(&["create", "--spec", "second-slot", "--token", "ref", "--no-update-lock"]);
    assert_eq!(code(&o), 14, "{}", stderr(&o));
    assert!(stderr(&o).contains("the lock records no realisation of spec 'second-slot'"), "{}", stderr(&o));
    assert_eq!(s.labelled("d1-first").len(), 2, "the pair that was there, and no other");
    assert_eq!(e.code(&["lock", "--spec", "second-slot", "--token", "ref"]), 22);
    let lock = e.lock();
    assert!(lock["realisations"]["second-slot"]["ref"].is_table());
    assert_eq!(lock["realisations"]["second-slot"]["ref"]["object"].as_str(), Some("signing"));
    assert_eq!(e.locked_id("signing", "rfc7093m4"), id, "the object keeps its one identity");
    assert_eq!(e.code(&["create", "--spec", "second-slot", "--token", "ref"]), 0);
    assert_eq!(s.labelled("d1-first").len(), 2, "still no other");
}

/// `cakeys create` is the one verb that makes keys: every unpinned pair, once, with every guard
/// of a creation. A pinned key is verified as `check` verifies it, never made again: one that
/// matches is left alone (0), one that does not fails as `check` fails it (10), one its token
/// lost is refused (14). An unpinned key already there is never found (19).
#[test]
fn create_makes_keys_and_nothing_else_does() {
    let Some(e) = env("create") else { return };
    let s = e.session();
    let body = "[objects.ec]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
         [specs.ec]\nobject = \"ec\"\nattributes = { CKA_SIGN = true, CKA_DESTROYABLE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"create-ec\" }, origin = \"create\" }\n\n\
         [specs.aes]\nobject = \"aes\"\nattributes = { CKA_EXTRACTABLE = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"create-aes\" }, origin = \"create\" }\n\n\
         [objects.cert]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\n\
         [specs.cert]\nobject = \"cert\"\ntokens.ref = { locator = { CKA_LABEL = \"create-cert\" } }\n\n\
         [specs.ec-public]\nobject = \"ec\"\n\
         tokens.ref = { locator = { CKA_LABEL = \"create-ec-public\" }, publicOnly = true }\n";
    e.config(body);
    // The first-use flow finds nothing and makes nothing.
    assert_eq!(e.code(&["lock", "--spec", "ec", "--token", "ref"]), 11);
    assert_eq!(e.code(&["check", "ec", "--spec", "ec"]), 11);

    // A dry run of a plan that would make keys passes, and makes and writes nothing (review
    // create.rs F2: only a refused plan's dry run was shown to).
    let lock_before = std::fs::read(e.dir.join("keys.lock")).ok();
    let o = e.km(&["create", "--token", "ref", "--dry-run"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(std::fs::read(e.dir.join("keys.lock")).ok(), lock_before, "the dry run wrote the lock");
    assert_eq!((s.labelled("create-ec"), s.labelled("create-aes")), (vec![], vec![]), "the dry run made a key");

    // Every unpinned pair on the token, created and recorded; what is adopted, not made, skipped.
    let o = e.km(&["create", "--token", "ref"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let said = stderr(&o);
    assert!(said.contains("'cert' (spec 'cert') on token 'ref': origin = \"adopt\""), "{said}");
    assert!(said.contains("(spec 'ec-public') on token 'ref': origin = \"adopt\""), "{said}");
    let made: serde_json::Value = serde_json::from_str(&stdout(&o)).unwrap();
    assert_eq!(made.as_array().map(Vec::len), Some(2), "{made}");
    let lock = e.lock();
    for spec in ["ec", "aes"] {
        assert!(lock["realisations"][spec]["ref"].is_table(), "{spec}: {lock}");
    }
    assert_eq!(e.code(&["check", "--spec", "ec", "--token", "ref"]), 0);

    // Again: both are pinned now, so each is verified as `check` verifies it, and nothing is
    // created twice; named, the same. Each verified pair has its row (review 2026-11-24 C-1:
    // none had).
    for (args, specs) in [
        (&["create", "--token", "ref"][..], &["ec", "aes"][..]),
        (&["create", "--spec", "ec", "--token", "ref"], &["ec"]),
    ] {
        let o = e.km(args);
        assert_eq!(code(&o), 0, "{args:?}: {}", stderr(&o));
        let rows: Vec<serde_json::Value> = serde_json::from_str(&stdout(&o)).unwrap();
        let mut verified: Vec<(&str, &str)> =
            rows.iter().map(|r| (r["spec"].as_str().unwrap(), r["outcome"].as_str().unwrap())).collect();
        verified.sort_unstable();
        let mut want: Vec<(&str, &str)> = specs.iter().map(|s| (*s, "verified")).collect();
        want.sort_unstable();
        assert_eq!(verified, want, "{args:?}");
        assert!(stderr(&o).contains("already pins object 'ec'"), "{}", stderr(&o));
        assert!(stderr(&o).contains("'ec' (spec 'ec') on token 'ref' is already there and matches the lock"));
        assert_eq!(s.labelled("create-ec").len(), 2, "no second pair");
    }
    assert_eq!(e.code(&["create", "--dry-run"]), 0);
    let plan: serde_json::Value = serde_json::from_str(&stdout(&e.km(&["create", "--dry-run"]))).unwrap();
    let action = |spec: &str| plan.as_array().unwrap().iter().find(|p| p["spec"] == spec).unwrap()["action"].clone();
    assert_eq!((action("ec"), action("cert")), ("verify".into(), "skip".into()), "{plan}");

    // A pinned key that does not match the lock fails as `check` fails it (10), the run with it.
    let path = e.dir.join("keys.lock");
    let pinned = std::fs::read_to_string(&path).unwrap();
    let mut lock = e.lock();
    for (_, id) in lock["objects"]["aes"]["ids"].as_table_mut().unwrap().iter_mut() {
        *id = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".into();
    }
    std::fs::write(&path, toml::to_string(&lock).unwrap()).unwrap();
    for args in [&["create", "--token", "ref"][..], &["create", "--spec", "aes", "--token", "ref"]] {
        let o = e.km(args);
        assert_eq!(code(&o), 10, "{args:?}: {}", stderr(&o));
        assert_eq!(e.code(&["check", "aes"]), 10);
    }
    std::fs::write(&path, &pinned).unwrap();

    // A key the lock does not pin, already under its locator, is never found: 19, named or not.
    e.config(&format!(
        "{body}\n[objects.loose]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.loose]\nobject = \"loose\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.ref = {{ locator = {{ CKA_LABEL = \"create-loose\" }}, origin = \"create\" }}\n"
    ));
    // Made, and not recorded: a first use (18).
    assert_eq!(e.code(&["create", "--spec", "loose", "--token", "ref", "--no-update-lock"]), 18);
    for args in [&["create", "--token", "ref"][..], &["create", "--spec", "loose", "--token", "ref"]] {
        e.refused(args, 19, "unpinned-exists");
    }
    s.clear(&["create-loose"]);
    e.config(body);

    // A pinned key the token lost is refused, never regenerated (14), named or not.
    s.clear(&["create-ec"]);
    e.refused(&["create", "--spec", "ec", "--token", "ref"], 14, "pinned-lost");
    e.refused(&["create", "--token", "ref"], 14, "pinned-lost");
    // Named, a pair whose origin is not `create` is still not created (17).
    let o = e.km(&["create", "--spec", "cert", "--token", "ref"]);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    assert!(stderr(&o).contains("origin = \"adopt\": it is found there, never created"), "{}", stderr(&o));
    assert!(s.labelled("create-ec").is_empty(), "nothing regenerated");
}

/// `create` checks each pair it would make against the capability profiles before it opens a
/// token. Here keys.toml names the token a kryoptic one, whose profile cannot generate
/// secp256k1: the run is refused (15) and nothing is made; `--dry-run` says what each pair would
/// get, opening and writing nothing; `--skip-unsupported` makes the rest and warns.
#[test]
fn create_checks_the_profiles_before_it_makes_anything() {
    let Some(e) = env("create_gate") else { return };
    let key = |name: &str, curve: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"{curve}\"\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"gate-{name}\" }}, origin = \"create\" }}\n\n"
        )
    };
    let tokens = reference_tokens(&e.module, &e.dir).replacen(
        "tokenLabel = \"kmtest\"\n",
        "tokenLabel = \"kmtest\"\nprovider = \"kryoptic\"\n",
        1,
    );
    e.write_config(&(tokens + &key("p256", "secp256r1") + &key("k1", "secp256k1")));
    let lock = e.dir.join("keys.lock");
    // A session opened after each run sees what it made (common/mod.rs).
    let made = |label: &str| !e.session().labelled(label).is_empty();
    let nothing_made =
        || !made("gate-p256") && !made("gate-k1") && std::fs::read_to_string(&lock).unwrap() == EMPTY_LOCK;

    let plan = e.refused(&["create", "--dry-run"], 15, "capability");
    let row = |spec: &str| plan.iter().find(|p| p.spec == spec).unwrap();
    let action = |spec: &str| row(spec).more["action"].as_str().unwrap_or_default().to_owned();
    assert_eq!((action("p256"), action("k1")), ("create".into(), "refuse".into()), "{plan:?}");
    // The profile that decided, not the sentence around it (review create.rs F3).
    assert!(row("k1").error.as_deref().is_some_and(|e| e.contains("kryoptic/1.5")), "{plan:?}");
    assert_eq!(e.code(&["create", "--dry-run", "--skip-unsupported"]), 0);
    assert!(nothing_made(), "a dry run makes nothing");

    let o = e.km(&["create"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("--skip-unsupported"), "names the way past it: {}", stderr(&o));
    assert!(nothing_made(), "a refused run makes nothing");

    let o = e.km(&["create", "--skip-unsupported"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let warned = stderr(&o).lines().any(|l| l.starts_with("warning:") && l.contains("'k1' (spec 'k1')"));
    assert!(warned, "the skipped pair warned: {}", stderr(&o));
    assert!(made("gate-p256") && !made("gate-k1"));
    assert!(e.lock()["realisations"]["p256"]["ref"].is_table());
}

/// What a token answered is recorded with its observation (docs/LOCK.md): the proof a
/// realisation gave and the generation `create` made. Those answers decide before the profile
/// of the token's kind, so a recorded *no* refuses in `validate` and `create`'s gate as a
/// profile's does, before anything is made; `check` never reads them.
#[test]
fn a_tokens_own_answers_decide_before_its_profile() {
    let Some(e) = env("answers") else { return };
    let key = |name: &str, usage: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ {usage} = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"answers-{name}\" }}, origin = \"create\" }}\n\n"
        )
    };
    e.config(
        &(key("sign", "CKA_SIGN")
            + &key("derive", "CKA_DERIVE")
                .replace("origin = \"create\"", "origin = \"create\", binding = \"pop-ecdh\"")),
    );
    assert_eq!(e.code(&["create", "sign"]), 22);
    let observation = |lock: &toml::Value| {
        let k = lock["realisations"]["sign"]["ref"]["observation"].as_str().unwrap().to_owned();
        lock["observations"][&k].clone()
    };
    let answers = observation(&e.lock())["capabilities"].clone();
    assert_eq!(answers["prove.pop-sign.CKK_EC.secp256r1"]["answer"].as_str(), Some("yes"), "{answers}");
    assert_eq!(answers["generate.CKK_EC.secp256r1"]["answer"].as_str(), Some("yes"), "{answers}");
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // This token, as recorded, cannot prove a derive-only key: refused before anything is made.
    let path = e.dir.join("keys.lock");
    let mut lock = e.lock();
    let k = lock["realisations"]["sign"]["ref"]["observation"].as_str().unwrap().to_owned();
    let no = toml::toml! { answer = "no" evidence = "as recorded" };
    lock["observations"][&k]["capabilities"]
        .as_table_mut()
        .unwrap()
        .insert("prove.pop-ecdh.CKK_EC.secp256r1".into(), no.into());
    std::fs::write(&path, toml::to_string(&lock).unwrap()).unwrap();
    let o = e.km(&["validate"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("cannot prove possession by prove.pop-ecdh.CKK_EC.secp256r1"), "{}", stderr(&o));
    assert!(stderr(&o).contains("as recorded"), "{}", stderr(&o));
    // `create`'s gate too: the profile passed it (`validate` was 0), so the answer refused it.
    e.refused(&["create", "derive", "--dry-run"], 15, "capability");
    assert_eq!(e.code(&["check", "sign"]), 0, "check never reads the answers");
    assert!(e.session().labelled("answers-derive").is_empty(), "nothing was made");
}

/// `create` over tokens of one module (`ref` and `ref-anon` share it) opens each in turn; a pair
/// that fails — opening its token included — leaves what was created before it recorded, and the
/// run exits 22, the lock written (the failure's code is its row's); and a name that selects
/// nothing is refused (17), never an empty success.
#[test]
fn create_records_what_it_made_before_a_failure() {
    let Some(e) = env("create_failure") else { return };
    // Spec `a-<first>` on `ref` sorts before `b-second` on `second`.
    let body = |first: &str, second: &str| {
        format!(
            "[tokens.gone]\nmodule = \"/nonexistent/libgone.so\"\ntokenLabel = \"gone\"\n\n\
             [objects.{first}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [objects.second]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\n\
             [specs.a-{first}]\nobject = \"{first}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"create2-{first}\" }}, origin = \"create\" }}\n\n\
             [specs.b-second]\nobject = \"second\"\nattributes = {{ CKA_EXTRACTABLE = true }}\n\
             tokens.{second} = {{ locator = {{ CKA_LABEL = \"create2-second\" }}, origin = \"create\" }}\n"
        )
    };
    let recorded = |spec: &str| e.lock()["realisations"][spec]["ref"].is_table();
    // The rows say what the exit no longer does: the first created, the second failed with 16.
    let exits = |o: &Output| state::rows(o).iter().map(|r| (r.spec.clone(), r.exit)).collect::<Vec<_>>();

    // The second token cannot be opened at all: the first key is recorded anyway.
    e.config(&body("one", "gone"));
    let o = e.km(&["create"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert_eq!(exits(&o), [("a-one".to_owned(), 0), ("b-second".to_owned(), 16)], "{}", stderr(&o));
    assert!(recorded("a-one"), "{}", e.lock());

    // The second token is another token of the same module: it opens, refuses to create where a
    // session without login cannot see private objects (16), and the first key is recorded.
    e.config(&body("two", "ref-anon"));
    let o = e.km(&["create"]);
    let err = stderr(&o);
    assert!(!err.contains("already been initialized"), "{err}");
    assert_eq!(code(&o), 22, "{err}");
    assert_eq!(exits(&o), [("a-two".to_owned(), 0), ("b-second".to_owned(), 16)], "{err}");
    assert!(err.contains("cannot see private objects"), "{err}");
    assert!(recorded("a-two"), "{}", e.lock());

    // An address naming nothing keys.toml has is invalid, as for every verb.
    for (args, why) in [
        (&["create", "--token", "typo"][..], "unknown token 'typo'"),
        (&["create", "--spec", "a-two", "--token", "ref-anon"][..], "no spec places spec 'a-two' on token 'ref-anon'"),
        (&["create", "typo"][..], "unknown object 'typo'"),
        (&["create", "two", "--spec", "b-second"][..], "spec 'b-second' realises 'second', not 'two'"),
    ] {
        let o = e.km(args);
        assert!(code(&o) == 17 && stderr(&o).contains(why), "{args:?}: expected 17 and {why:?}: {}", stderr(&o));
    }
}
