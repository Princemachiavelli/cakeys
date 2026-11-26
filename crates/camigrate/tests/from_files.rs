//! Tests objects that are born in files (docs/FILE.md). `camigrate import --to <t>` without
//! `--in` creates each object for which a pair on the token says `origin = "file"`. It creates the
//! object from the file that the object's `migrate.file` names, as OpenSSL wrote it
//! (tests/fixtures/keyfiles/make.sh). The file is the object's first use, so every other token
//! and every later run must match it. The realisations are checked with `cakeys` (built next to
//! camigrate, `common::sibling`). The tests are skipped without the `SoftHSM` reference, and
//! kryoptic takes part when it is also set up.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::state;
use common::xref::{Env, Ref};
use common::*;
use std::path::PathBuf;

const FROM_FILE: &str = ", origin = \"file\"";

fn fixture(name: &str) -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keyfiles").join(name)
}

/// Returns the `SoftHSM` reference, and also kryoptic's reference when kryoptic is set up. These
/// tests need only `SoftHSM`. The cross-reference harness skips when it has fewer than two
/// references, so with that harness, a run with only `SoftHSM` (and `CAKEYS_TEST_REQUIRE`) passed
/// without running anything (review `from_files.rs` F2).
fn env(name: &str) -> Option<Env> {
    let soft = suite_var(SOFTHSM.module_var, SOFTHSM.require_var, name)?;
    let mut refs = vec![created_ref("softhsm", soft)];
    if let Some(kry) = required_var(KRYOPTIC.module_var, KRYOPTIC.require_var) {
        refs.push(created_ref("kryoptic", kry));
    }
    Some(Env::over(name, refs))
}

/// Compares every AES commitment that the lock records for the `kek` object with the host's own
/// commitment of the key in `aes256.key`. A comparison of the token's IDs only with other IDs from
/// the token would miss an error that every spelling of the file shares (review `from_files.rs`
/// F1).
fn assert_aes_ids_are_the_files(lock: &toml::Value, object: &str) {
    let key = std::fs::read(fixture("aes256.key")).unwrap();
    let ids = lock["objects"][object]["ids"].as_table().unwrap();
    let mut compared = 0;
    for (scheme, id) in ids {
        if ["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"].contains(&scheme.as_str()) {
            assert_eq!(id.as_str(), Some(aes_commitment(&key, scheme).as_str()), "{object} {scheme}");
            compared += 1;
        }
    }
    assert!(compared > 0, "{object}: no AES commitment recorded: {ids:?}");
}

/// Returns the keys.toml body for the objects that one server bundle, one secret key file and one
/// data file hold, each realised on every token in `refs`.
fn body(refs: &[&Ref], key_file: &str) -> String {
    let file = |name: &str| fixture(name).display().to_string();
    format!(
        "[objects.web]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\
         migrate = {{ file = \"{key}\" }}\n\n\
         [objects.web-cert]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\
         migrate = {{ file = \"{bundle}\" }}\n\n\
         [objects.kek]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\
         migrate = {{ file = \"{aes}\" }}\n\n\
         [objects.note]\nclass = \"CKO_DATA\"\nmigrate = {{ file = \"{note}\" }}\n\n",
        key = file(key_file),
        bundle = file("p256.bundle.pem"),
        aes = file("aes256.key"),
        note = file("note.bin"),
    ) + &Env::spec(
        "web",
        "web",
        "attributes = { CKA_SIGN = true, CKA_EXTRACTABLE = false }\n",
        refs,
        "ff-web",
        FROM_FILE,
    ) + &Env::spec("web-cert", "web-cert", "", refs, "ff-web", FROM_FILE)
        + &Env::spec(
            "kek",
            "kek",
            "attributes = { CKA_ENCRYPT = true, CKA_EXTRACTABLE = false }\n",
            refs,
            "ff-kek",
            FROM_FILE,
        )
        + &Env::spec("note", "note", "", refs, "ff-note", FROM_FILE)
}

/// Checks that a data object whose spec does not say that it is public is not treated as public
/// (review 2026-11-24 D-7; docs/archive/REVIEW-2026-11-24/phase1-design.md §9.2). Its value from
/// its file is a secret, so the value passes through this process only with
/// --allow-host-plaintext, in a dry run or a real run. Without the flag, the import is refused
/// (15), nothing is made, and no lock is written. The object is recorded as a raw value from a
/// file, not as a public object (it is made in the way that `templates::object` makes an
/// undeclared one).
#[test]
fn undeclared_data_objects_count_as_private() {
    let Some(e) = env("from-files-data") else { return };
    let soft = &e.refs[0];
    e.config(&body(&[soft], "p256.bundle.pem"));
    let lock = || std::fs::read(e.dir.join("keys.lock")).ok();
    let o = e.km(soft, &["import", "note", "--to", "softhsm"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(open_session(&soft.module, soft.token_label, "1234").labelled("ff-note").is_empty(), "made");
    assert_eq!(lock().as_deref(), Some(EMPTY_LOCK.as_bytes()), "a refused import wrote the lock");
    let o = e.km(soft, &["import", "note", "--to", "softhsm", "--allow-host-plaintext"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    let origin = &lock["realisations"]["note"]["softhsm"]["provenance"]["origin"];
    assert_eq!((origin["method"].as_str(), origin["exposure"].as_str()), (Some("raw"), Some("file")), "{origin}");
}

/// Checks that one server bundle (curve parameters, the key as SEC1, its certificate and the CA's
/// certificate), an AES key's bytes and a data file populate `SoftHSM`. The keys are imported only
/// with --allow-host-plaintext, and each object is recorded with its origin and with the identity
/// from its file. `cakeys check` then verifies each object, a re-run imports nothing, and a second
/// token (kryoptic, when it is set up) gets the same material. Another key under the same object
/// is refused (10) before anything is written.
#[test]
fn files_populate_tokens_with_their_material() {
    let Some(e) = env("from-files") else { return };
    let soft = &e.refs[0];
    let kry = e.refs.iter().find(|r| r.name == "kryoptic");
    let refs: Vec<&Ref> = [Some(soft), kry].into_iter().flatten().collect();
    e.config(&body(&refs, "p256.bundle.pem"));

    // A key from a file is plaintext in this process, so it is refused (15) without the flag,
    // nothing is made, and no lock is written (review `from_files.rs` F3 found that only the exit
    // code and the message were checked).
    let lock_bytes = || std::fs::read(e.dir.join("keys.lock")).ok();
    let o = e.km(soft, &["import", "web", "--to", "softhsm"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("--allow-host-plaintext"), "{}", stderr(&o));
    // A certificate read from a file next to a key is refused in the same way, because finding
    // the certificate decodes the key.
    let o = e.km(soft, &["import", "web-cert", "--to", "softhsm"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("holds a private key"), "{}", stderr(&o));
    assert!(
        open_session(&soft.module, soft.token_label, "1234").labelled("ff-web").is_empty(),
        "a refused key left objects"
    );
    assert_eq!(lock_bytes().as_deref(), Some(EMPTY_LOCK.as_bytes()), "a refused import wrote the lock");

    let o = e.km(soft, &["import", "--to", "softhsm", "--allow-host-plaintext"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    let spki = cakeys_core::id::spki_canonical(&std::fs::read(fixture("p256.pub.der")).unwrap()).unwrap();
    assert_eq!(lock["objects"]["web"]["ids"]["rfc7093m4"].as_str(), Some(cakeys_core::id::sri(&spki).as_str()));
    let cert = std::fs::read(fixture("p256.crt.der")).unwrap();
    assert_eq!(lock["objects"]["web-cert"]["ids"]["certhash"].as_str(), Some(cakeys_core::id::sri(&cert).as_str()));
    let note = std::fs::read(fixture("note.bin")).unwrap();
    assert_eq!(lock["objects"]["note"]["ids"]["valuehash"].as_str(), Some(cakeys_core::id::sri(&note).as_str()));
    assert_aes_ids_are_the_files(&lock, "kek");
    for (spec, method, exposure) in [
        ("web", "sec1", "file"),
        ("web-cert", "public", "public"),
        ("kek", "raw", "file"),
        // Its spec does not say that it is public, so it is not treated as public: it is a raw
        // value from a file.
        ("note", "raw", "file"),
    ] {
        let origin = &lock["realisations"][spec]["softhsm"]["provenance"]["origin"];
        assert_eq!(
            (origin["from"].as_str(), origin["method"].as_str(), origin["exposure"].as_str()),
            (Some("file"), Some(method), Some(exposure)),
            "{spec}"
        );
        assert_eq!(code(&e.cakeys(soft, &["check", "--spec", spec, "--token", "softhsm"])), 0, "{spec}");
    }

    // A re-run imports nothing and leaves the lock's bytes unchanged.
    let before = lock_bytes();
    let o = e.km(soft, &["import", "--to", "softhsm", "--allow-host-plaintext"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("already realised"), "{}", stderr(&o));
    assert_eq!(lock_bytes(), before, "a re-run changed the lock");

    // The same material goes on a second token, and it is checked against the lock that the first
    // import wrote.
    if let Some(kry) = kry {
        let o = e.km(kry, &["import", "--to", "kryoptic", "--allow-host-plaintext"]);
        assert_eq!(code(&o), 22, "{}", stderr(&o));
        for spec in ["web", "web-cert", "kek", "note"] {
            assert_eq!(code(&e.cakeys(kry, &["check", "--spec", spec, "--token", "kryoptic"])), 0, "{spec}");
        }
    }

    // Another key under the same object is refused (10) before anything is written, and the lock
    // stays as it was.
    let other = body(&refs, "ca.pkcs8.pem")
        + &Env::spec("web-2", "web", "attributes = { CKA_SIGN = true }\n", &[soft], "ff-web2", FROM_FILE);
    e.config(&other);
    let before = std::fs::read(e.dir.join("keys.lock")).unwrap();
    let o = e.km(soft, &["import", "web", "--to", "softhsm", "--spec", "web-2", "--allow-host-plaintext"]);
    assert_eq!(code(&o), 10, "{}", stderr(&o));
    assert!(
        open_session(&soft.module, soft.token_label, "1234").labelled("ff-web2").is_empty(),
        "another key left objects"
    );
    assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), before);
}

/// Checks one key in each format that a file may hold. Each format is used in turn as the object's
/// file, each under its own spec on `SoftHSM`. The first format is the key's first use, and every
/// later format must read as that key and be recorded with its format. A passphrase comes from
/// keys.toml or from `--passphrase-file`. A format that is not read is refused (17) with the
/// command that converts it, and nothing is made.
#[test]
fn every_file_format_imports_as_the_same_key() {
    let Some(e) = env("file-formats") else { return };
    let soft = &e.refs[0];
    let pass = e.dir.join("pass");
    std::fs::write(&pass, "pass phrase\n").unwrap();
    let pass_file = format!(", passphraseFile = \"{}\"", pass.display());
    // Returns keys.toml with the object `k` read from `file`, and one spec for each format up to
    // the `last`.
    let config = |last: usize, file: &str, extra: &str| {
        let mut body = format!(
            "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\
             migrate = {{ file = \"{}\"{extra} }}\n\n",
            fixture(file).display()
        );
        for i in 0..=last {
            body += &Env::spec(
                &format!("k{i}"),
                "k",
                "attributes = { CKA_SIGN = true }\n",
                &[soft],
                &format!("fmt-{i}"),
                FROM_FILE,
            );
        }
        e.config(&body);
    };
    let import = |i: usize, extra: &[&str]| {
        let spec = format!("k{i}");
        let args = ["import", "k", "--to", "softhsm", "--spec", &spec, "--allow-host-plaintext"];
        e.km(soft, &[&args[..], extra].concat())
    };

    config(0, "p256.legacy.p12", "");
    let o = import(0, &["--passphrase-file", pass.to_str().unwrap()]);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    assert!(stderr(&o).contains("openssl pkcs12 -in old.p12 -legacy"), "{}", stderr(&o));
    assert!(
        open_session(&soft.module, soft.token_label, "1234").labelled("fmt-0").is_empty(),
        "a refused file left objects"
    );

    let formats = [
        ("pkcs8", "p256.pkcs8.der", ""),
        ("sec1", "p256.sec1.der", ""),
        ("pkcs8-pbes2", "p256.enc.pem", pass_file.as_str()),
        ("pkcs12", "p256.p12", ""),
        ("sec1", "p256.bundle.pem", ""),
    ];
    for (i, (method, file, extra)) in formats.iter().enumerate() {
        config(i, file, extra);
        if *method == "pkcs12" {
            // The passphrase of this file is given only on the command line.
            let o = import(i, &[]);
            assert_eq!(code(&o), 17, "{}", stderr(&o));
            assert!(stderr(&o).contains("no passphrase is given"), "{}", stderr(&o));
        }
        let o = import(i, &["--passphrase-file", pass.to_str().unwrap()]);
        assert_eq!(code(&o), 22, "{file}: {}", stderr(&o));
        let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
        let origin = &lock["realisations"][format!("k{i}").as_str()]["softhsm"]["provenance"]["origin"];
        assert_eq!(origin["method"].as_str(), Some(*method), "{file}");
        assert_eq!(code(&e.cakeys(soft, &["check", "--spec", &format!("k{i}"), "--token", "softhsm"])), 0, "{file}");
    }
    // A passphrase from the environment gets the same check as a passphrase from a file. An empty
    // passphrase is refused (17) as empty, and it is never tried and reported as a passphrase that
    // the file "does not open under" (review 2026-11-23 C-14).
    let last = formats.len();
    config(last, "p256.enc.pem", ", passphraseEnv = \"CAKEYS_TEST_EMPTY_PASS\"");
    let vars: Vec<_> = soft.env.iter().copied().chain([("CAKEYS_TEST_EMPTY_PASS", "")]).collect();
    let empty = Ref { env: ref_env(&vars), ..soft.clone() };
    let spec = format!("k{last}");
    let o = e.km(&empty, &["import", "k", "--to", "softhsm", "--spec", &spec, "--allow-host-plaintext"]);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    assert!(stderr(&o).contains("env var CAKEYS_TEST_EMPTY_PASS: the passphrase is empty"), "{}", stderr(&o));
    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    let spki = cakeys_core::id::spki_canonical(&std::fs::read(fixture("p256.pub.der")).unwrap()).unwrap();
    assert_eq!(lock["objects"]["k"]["ids"]["rfc7093m4"].as_str(), Some(cakeys_core::id::sri(&spki).as_str()));
}

/// Checks one AES key's file as its bytes, as hex digits and as base64, in turn, each under its
/// own spec on `SoftHSM`. The bytes are the key's first use. The hex (recognised by its length)
/// and the base64 (recognised by its length, and then named by `migrate.encoding`) must import as
/// that key. A file whose encoding is named wrongly is refused (17), and nothing is made.
#[test]
fn every_spelling_of_a_secret_key_imports_as_the_same_key() {
    let Some(e) = env("key-spellings") else { return };
    let soft = &e.refs[0];
    // Returns keys.toml with the AES key `k` read from `file`, and one spec for each spelling up
    // to the `last`.
    let config = |last: usize, file: &str, extra: &str| {
        let mut body = format!(
            "[objects.k]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\
             migrate = {{ file = \"{}\"{extra} }}\n\n",
            fixture(file).display()
        );
        for i in 0..=last {
            body += &Env::spec(
                &format!("k{i}"),
                "k",
                "attributes = { CKA_ENCRYPT = true, CKA_EXTRACTABLE = false }\n",
                &[soft],
                &format!("spell-{i}"),
                FROM_FILE,
            );
        }
        e.config(&body);
    };
    let import = |i: usize| {
        let spec = format!("k{i}");
        e.km(soft, &["import", "k", "--to", "softhsm", "--spec", &spec, "--allow-host-plaintext"])
    };

    let spellings = [
        ("aes256.key", ""),
        ("aes256.hex", ""),
        ("aes256.b64", ""),
        ("aes256.b64", ", encoding = \"base64\""),
        ("aes256.hex", ", encoding = \"hex\""),
    ];
    for (i, (file, extra)) in spellings.iter().enumerate() {
        config(i, file, extra);
        let o = import(i);
        assert_eq!(code(&o), 22, "{file}{extra}: {}", stderr(&o));
        let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
        let origin = &lock["realisations"][format!("k{i}").as_str()]["softhsm"]["provenance"]["origin"];
        assert_eq!((origin["method"].as_str(), origin["exposure"].as_str()), (Some("raw"), Some("file")), "{file}");
        let check = ["check", "--spec", &format!("k{i}"), "--token", "softhsm"];
        assert_eq!(code(&e.cakeys(soft, &check)), 0, "{file}{extra}");
    }

    let lock: toml::Value = toml::from_str(&std::fs::read_to_string(e.dir.join("keys.lock")).unwrap()).unwrap();
    assert_aes_ids_are_the_files(&lock, "k");

    // Hex digits that are named as base64 spell 48 bytes, not the key's 32 bytes.
    let i = spellings.len();
    config(i, "aes256.hex", ", encoding = \"base64\"");
    let o = import(i);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    assert!(stderr(&o).contains("48 bytes of base64, and the key is 32"), "{}", stderr(&o));
    assert!(
        open_session(&soft.module, soft.token_label, "1234").labelled(&format!("spell-{i}")).is_empty(),
        "a refused file left objects"
    );

    // The file of another key does not hold the key that the lock pins. The import is refused
    // (10) by the host's own commitment, before anything is made (review 2026-11-24 D-5).
    let other = e.dir.join("other.key");
    std::fs::write(&other, [0x5a; 32]).unwrap();
    config(i, other.to_str().unwrap(), "");
    let before = state::snapshot(&[&e.dir.join("keys.lock")], &[soft.view()]);
    let o = import(i);
    assert_eq!(code(&o), 10, "{}", stderr(&o));
    state::assert_unchanged(&before, &state::snapshot(&[&e.dir.join("keys.lock")], &[soft.view()]), "another key");
}

/// Checks that a key-file import is refused (15) before the key is written when the spec asks for
/// an attestation that the provider gives only for keys that its device generated (PIV). A
/// `YubiKey` keeps what it imported, and before this check, a key that was written first and then
/// refused by the attestation stayed in its slot. (The only guard was in the move planner, which a
/// key-file import never runs.) `SoftHSM` stands in for the device here, with its token named
/// `piv` and bound to the `ykcs11` provider, and nothing may reach it. The dry run reports the
/// same refusal.
#[test]
fn an_import_the_provider_cannot_attest_is_refused_before_the_write() {
    let Some(e) = env("from-files-attest") else { return };
    let soft = &e.refs[0];
    let so = e.dir.join("so-pin");
    std::fs::write(&so, "5678\n").unwrap();
    let body = format!(
        "[tokens.piv]\nmodule = \"{module}\"\ntokenLabel = \"{label}\"\nprovider = \"ykcs11\"\n\
         pinFile = \"{pin}\"\nsoCredentialFile = \"{so}\"\n\n\
         [objects.pk]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\
         migrate = {{ file = \"{key}\" }}\n\n\
         [specs.pk]\nobject = \"pk\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.piv = {{ locator = {{ CKA_ID = \"18\" }}, origin = \"file\", attestation = true }}\n",
        module = soft.module,
        label = soft.token_label,
        pin = e.dir.join("pin").display(),
        so = so.display(),
        key = fixture("p256.pkcs8.pem").display(),
    );
    e.config(&body);
    for dry_run in [true, false] {
        let mut args = vec!["import", "pk", "--to", "piv", "--allow-host-plaintext"];
        if dry_run {
            args.push("--dry-run");
        }
        let o = e.km_alone(soft, &args);
        assert_eq!(code(&o), 15, "dry run {dry_run}: {}", stderr(&o));
        assert!(stderr(&o).contains("attests only keys the device generated"), "dry run {dry_run}: {}", stderr(&o));
    }
    // ykcs11 locates objects by CKA_ID alone (a CKA_LABEL is refused first, 17), so the test looks
    // for the key by its CKA_ID.
    let id = cryptoki::object::Attribute::Id(vec![0x18]);
    assert!(
        open_session(&soft.module, soft.token_label, "1234").find_objects(&[id]).unwrap().is_empty(),
        "the refused key reached the token"
    );
}

/// Checks that a file import that ends before its first object still prints a row for each
/// object, with the exit code of the refusal. Review 2026-11-24 L4b-1 found that the bundle's
/// import and `migrate` printed no row in that case, and the imports from files had the same early
/// returns. A `--spec` that selects nothing is refused (17) before the target opens. The table
/// holds both entry paths from files: the objects born in files (`import --to`), where each object
/// has a row, and a key file (`import --in`), where the key, which is the only object, has a row.
/// Each dry run is first checked in the same way ([`Env::km`]).
#[test]
fn a_file_import_that_ends_before_its_objects_prints_a_row_for_each() {
    let Some(e) = env("from-files-rows") else { return };
    let soft = &e.refs[0];
    e.config(&body(&[soft], "p256.bundle.pem"));
    let rows = |o: &std::process::Output| -> Vec<(String, String, u8)> {
        state::rows(o).into_iter().map(|r| (r.object, r.outcome, r.exit)).collect()
    };
    let failed = |objects: &[&str]| -> Vec<(String, String, u8)> {
        objects.iter().map(|o| ((*o).to_owned(), "failed".to_owned(), 17)).collect()
    };
    let key_file = fixture("p256.pkcs8.pem").display().to_string();
    let table: [(&str, &[&str], &[&str]); 2] = [
        ("objects born in files", &[], &["kek", "web", "note", "web-cert"]),
        ("a key file", &["--in", &key_file], &["web"]),
    ];
    // A key file's key must be the key that the lock pins, so the objects are first imported from
    // their own files.
    let o = e.km(soft, &["import", "--to", "softhsm", "--allow-host-plaintext"]);
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    for (what, input, objects) in table {
        let mut args = vec!["import", "--to", "softhsm", "--spec", "no-such-spec", "--allow-host-plaintext"];
        args.extend_from_slice(input);
        let o = e.km(soft, &args);
        assert_eq!(code(&o), 17, "{what}: {}", stderr(&o));
        assert_eq!(rows(&o), failed(objects), "{what}: {}", stderr(&o));
    }
}
