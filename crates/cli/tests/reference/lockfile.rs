//! The lock file: its invariants, provenance and observations, what it pins, and the sidecar
//! lock that serialises its writers.

use super::*;

#[test]
fn module_and_token_provenance_warn_but_do_not_fail() {
    let Some(e) = env("provenance") else { return };
    e.config(EC.replace("ec-lifecycle", "provenance").as_str());
    let r = ["lock", "--spec", "signing-soft", "--token", "ref", "--update-lock"];
    let verify = ["verify", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref", "--no-update-lock"]), 18);
    assert_eq!(e.code(&r), 0);

    let real = &e.lock()["realisations"]["signing-soft"]["ref"];
    let seen = e.observation("signing-soft", "ref");
    // The file actually loaded, symlinks resolved: provenance only.
    let loaded = std::fs::canonicalize(&e.module).unwrap();
    let loaded = loaded.to_str().unwrap();
    assert_eq!(seen["module"]["path"].as_str(), Some(loaded));
    assert_eq!(seen["module"]["manufacturer"].as_str(), Some(REF.manufacturer));
    assert_ne!(seen["module"]["version"].as_str().unwrap(), "");
    assert_eq!(seen["token"]["model"].as_str(), Some(REF.model));
    assert!(!real["observed"]["uri"].as_str().unwrap().contains("module-path"), "URI is a pure locator");
    assert!(!stderr(&e.km(&verify)).contains("warning"));

    let path = e.dir.join("keys.lock");
    let original = std::fs::read_to_string(&path).unwrap();
    let version = seen["module"]["version"].as_str().unwrap().to_owned();

    // A different module version: still verifies (identity is the CA-ID), with a warning. Not
    // 0.0: kryoptic reports that as its library version.
    std::fs::write(&path, original.replace(&format!("version = \"{version}\""), "version = \"99.99\"")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("warning:") && stderr(&o).contains("with module"), "{}", stderr(&o));

    // Same build identity, different file: a note only.
    std::fs::write(&path, original.replace(loaded, "/nix/store/old-softhsm/lib/libsofthsm2.so")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("note:") && !stderr(&o).contains("warning:"), "{}", stderr(&o));

    // The file's hash is recorded too; other content at the same path (replaced in place, as
    // outside the Nix store) is a warning.
    let hash = seen["module"]["hash"].as_str().unwrap().to_owned();
    assert_eq!(hash, sri(&std::fs::read(loaded).unwrap()));
    std::fs::write(&path, original.replace(&hash, "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("warning:") && stderr(&o).contains("of hash"), "{}", stderr(&o));

    // A different token: warning.
    std::fs::write(&path, original.replace(&format!("model = \"{}\"", REF.model), "model = \"Other\"")).unwrap();
    assert!(stderr(&e.km(&verify)).contains("realised on token Other"));

    // Re-binding with --update-lock records the current module and token.
    assert_eq!(e.code(&r), 0);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

    // The lock records the file the loader mapped, symlinks resolved, whatever named it: a
    // symlink given with --module, or a bare file name found by the library search.
    let module_path = |o: &Output| {
        assert_eq!(code(o), 0, "{}", stderr(o));
        e.observation("signing-soft", "ref")["module"]["path"].as_str().unwrap().to_owned()
    };
    let link = e.dir.join("module.so");
    std::os::unix::fs::symlink(&e.module, &link).unwrap();
    let via_link = format!("ref={}", link.display());
    assert_eq!(module_path(&e.km(&[&["--module", via_link.as_str()][..], &r[..]].concat())), loaded);
    let module = std::path::Path::new(&e.module);
    let bare = format!("ref={}", module.file_name().unwrap().to_str().unwrap());
    let search = [("LD_LIBRARY_PATH", module.parent().unwrap())];
    assert_eq!(module_path(&e.km_env(&[&["--module", bare.as_str()][..], &r[..]].concat(), &search)), loaded);
    // A per-machine `module = "$NAME"`: unset, it is invalid (17) unless --module replaces it
    // first, as lib.mkKeys does in a build sandbox that sets no such variable.
    let toml = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    e.write_config(&toml.replace(&format!("module = \"{}\"", e.module), "module = \"$CAKEYS_TEST_UNSET_MODULE\""));
    let o = e.km(&verify);
    assert_eq!(code(&o), 17);
    assert!(stderr(&o).contains("CAKEYS_TEST_UNSET_MODULE"), "{}", stderr(&o));
    assert_eq!(e.code(&[&["--module", via_link.as_str()][..], &verify[..]].concat()), 0);
    assert!(!stderr(&e.km(&verify)).contains("warning"));
}

/// The field classes are real: removing `observed`, `provenance` and the observation table
/// changes no verdict, while the compared fields and the version are required — and a
/// realisation must not name an observation the lock lacks.
#[test]
fn observed_and_provenance_never_change_a_verdict() {
    let Some(e) = env("classes") else { return };
    e.config(EC.replace("ec-lifecycle", "classes").as_str());
    let verify = ["verify", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref", "--update-lock"]), 0);
    let mut full = e.lock();
    full["realisations"]["signing-soft"]["ref"].as_table_mut().unwrap().insert(
        "provenance".into(),
        toml::from_str("origin = { from = \"elsewhere\", method = \"public\", exposure = \"public\" }").unwrap(),
    );
    let strip = |mut lock: toml::Value| {
        let real = lock["realisations"]["signing-soft"]["ref"].as_table_mut().unwrap();
        for field in ["observed", "observation", "provenance"] {
            assert!(real.remove(field).is_some(), "{field}");
        }
        assert!(lock.as_table_mut().unwrap().remove("observations").is_some());
        lock
    };
    let write = |lock: &toml::Value| std::fs::write(e.dir.join("keys.lock"), toml::to_string(lock).unwrap()).unwrap();
    write(&full);
    assert_eq!(e.code(&verify), 0);
    write(&strip(full.clone()));
    assert_eq!(e.code(&verify), 0);
    let mut dangling = full.clone();
    dangling.as_table_mut().unwrap().remove("observations");
    write(&dangling);
    assert_eq!(e.code(&verify), 17);
    // A wrong ID is still a mismatch, a missing record still a precondition failure.
    let mut wrong = strip(full.clone());
    wrong["objects"]["signing"]["ids"]["rfc7093m4"] = sri(b"other").into();
    write(&wrong);
    assert_eq!(e.code(&verify), 10);
    let mut unrecorded = full.clone();
    unrecorded["realisations"].as_table_mut().unwrap().clear();
    write(&unrecorded);
    assert_eq!(e.code(&verify), 14);
    // Required: the version, and every compared field.
    let mut versionless = full.clone();
    versionless.as_table_mut().unwrap().remove("version");
    write(&versionless);
    assert_eq!(e.code(&verify), 17);
    let mut objectless = full.clone();
    objectless["realisations"]["signing-soft"]["ref"].as_table_mut().unwrap().remove("object");
    write(&objectless);
    assert_eq!(e.code(&verify), 17);
}

/// A malformed or self-contradictory lock is invalid (exit 17), not a hash mismatch; the same
/// material is never recorded under two names; computing fewer schemes than recorded is refused.
#[test]
fn lock_invariants_are_checked() {
    let Some(e) = env("invariants") else { return };
    let body = EC.replace("ec-lifecycle", "invariants")
        + "\n[objects.twin]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
           [specs.twin]\nobject = \"twin\"\nattributes = { CKA_SIGN = true }\n\
           tokens.ref = { locator = { CKA_LABEL = \"invariants\" }, origin = \"adopt\" }\n";
    e.config(&body);
    let verify = ["verify", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref", "--update-lock"]), 0);
    let good = e.lock();
    assert_eq!(good["realisations"]["signing-soft"]["ref"]["schemes"].as_array().unwrap().len(), 1);
    // The same key under a second object name is refused when recording.
    assert_eq!(e.code(&["lock", "--spec", "twin", "--token", "ref", "--update-lock"]), 14);
    assert!(e.lock().get("objects").unwrap().get("twin").is_none());

    let write = |lock: &toml::Value| std::fs::write(e.dir.join("keys.lock"), toml::to_string(lock).unwrap()).unwrap();
    let edit = |f: &dyn Fn(&mut toml::Value)| {
        let mut lock = good.clone();
        f(&mut lock);
        write(&lock);
        e.code(&verify)
    };
    assert_eq!(edit(&|l| l["objects"]["signing"]["ids"]["rfc7093m4"] = "sha256-AAAA".into()), 17);
    assert_eq!(edit(&|l| l["realisations"]["signing-soft"]["ref"]["specDigest"] = "abc".into()), 17);
    let set = |l: &mut toml::Value, k: &str, v: toml::Value| {
        l["objects"]["signing"].as_table_mut().unwrap().insert(k.into(), v);
    };
    assert_eq!(edit(&|l| set(l, "commitmentLabel", "".into())), 17);
    assert_eq!(edit(&|l| set(l, "pairs", toml::Value::Array(vec!["signing".into()]))), 17);
    assert_eq!(edit(&|l| set(l, "pairs", toml::Value::Array(vec!["in-another-fragment".into()]))), 0);
    assert_eq!(
        edit(&|l| {
            l["realisations"]["signing-soft"]["ref"].as_table_mut().unwrap().remove("binding");
        }),
        17,
        "a private key realisation must record its binding"
    );
    assert_eq!(
        edit(&|l| {
            let s = l["objects"]["signing"].clone();
            l["objects"].as_table_mut().unwrap().insert("twin".into(), s);
        }),
        17,
        "same material twice"
    );
    assert_eq!(
        edit(&|l| l["realisations"]["signing-soft"]["ref"]["schemes"] = toml::Value::Array(vec!["certhash".into()])),
        17
    );
    // A scheme the realisation established but no longer computes: a downgrade.
    let valuehash = sri(b"recorded by an imaginary earlier version");
    assert_eq!(
        edit(&|l| {
            l["objects"]["signing"]["ids"].as_table_mut().unwrap().insert("valuehash".into(), valuehash.clone().into());
            l["realisations"]["signing-soft"]["ref"]["schemes"] =
                toml::Value::Array(vec!["rfc7093m4".into(), "valuehash".into()]);
        }),
        14
    );
    write(&good);
    assert_eq!(e.code(&verify), 0);
}

/// M3: `--update-lock` holds an advisory lock on `<lock>.lck` across its read-modify-write. While
/// the sidecar lock is held by someone else, a second updater waits and a reader proceeds.
#[test]
fn update_lock_waits_for_the_sidecar_lock() {
    let Some(e) = env("m3-flock") else { return };
    e.config(EC.replace("ec-lifecycle", "m3-flock").as_str());
    let r = ["lock", "--spec", "signing-soft", "--token", "ref", "--update-lock"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 0);

    // Hold the sidecar the same way cakeys does: an exclusive std file lock.
    let held =
        std::fs::File::options().write(true).create(true).truncate(false).open(e.dir.join("keys.lock.lck")).unwrap();
    held.lock().unwrap();
    let spawn = |args: &[&str]| {
        tool(env!("CARGO_BIN_EXE_cakeys")).arg("--config").arg(e.dir.join("keys.toml")).args(args).spawn().unwrap()
    };
    // A reader never takes it: verify finishes while it is held. However slow the build (a debug
    // build behind the fault shim takes over a second): one that waited would never finish.
    let mut reader = spawn(&["verify", "--spec", "signing-soft", "--token", "ref"]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(status) = reader.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() > deadline {
            let _ = reader.kill();
            panic!("verify waited for the sidecar lock");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success());
    // An updater waits, and says so before it blocks: its note is awaited, never a timer, which
    // a slow build (the fault shim's) outlasted with no lock taken at all (review lockfile.rs F1).
    let mut updater = tool(env!("CARGO_BIN_EXE_cakeys"))
        .arg("--config")
        .arg(e.dir.join("keys.toml"))
        .args(r)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let lines = std::io::BufRead::lines(std::io::BufReader::new(updater.stderr.take().unwrap()));
    let (said, heard) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in lines.map_while(Result::ok) {
            let _ = said.send(line);
        }
    });
    let waiting =
        format!("note: waiting for {}: another run is updating the lock", e.dir.join("keys.lock.lck").display());
    let mut before = Vec::new();
    loop {
        match heard.recv_timeout(std::time::Duration::from_secs(60)) {
            Ok(line) if line == waiting => break,
            Ok(line) => before.push(line),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout | std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("the updater never waited for the sidecar lock; it said {before:?}")
            }
        }
    }
    assert!(updater.try_wait().unwrap().is_none(), "the updater finished while the lock was held");
    drop(held);
    assert_eq!(updater.wait().unwrap().code(), Some(0));
    reader.join().unwrap();

    // The sidecar is the lock file's, however the run names it (review D2): an updater through a
    // symlink waits on the same `<lock>.lck`.
    let link = e.dir.join("linked.lock");
    std::os::unix::fs::symlink(e.dir.join("keys.lock"), &link).unwrap();
    let held =
        std::fs::File::options().write(true).create(true).truncate(false).open(e.dir.join("keys.lock.lck")).unwrap();
    held.lock().unwrap();
    let mut linked = tool(env!("CARGO_BIN_EXE_cakeys"))
        .arg("--config")
        .arg(e.dir.join("keys.toml"))
        .arg("--lock")
        .arg(&link)
        .args(r)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut said = String::new();
    let lines = std::io::BufRead::lines(std::io::BufReader::new(linked.stderr.take().unwrap()));
    let (tell, heard) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in lines.map_while(Result::ok) {
            let _ = tell.send(line);
        }
    });
    while let Ok(line) = heard.recv_timeout(std::time::Duration::from_secs(60)) {
        said += &line;
        if line == waiting {
            break;
        }
    }
    let finished = linked.try_wait().unwrap();
    drop(held);
    let _ = linked.wait();
    reader.join().unwrap();
    assert!(
        said.contains(&waiting) && finished.is_none(),
        "through a symlink, the updater took another sidecar: {said}"
    );
    assert!(!e.dir.join("linked.lock.lck").exists(), "a sidecar beside the symlink");
    assert_eq!(e.code(&["verify", "--spec", "signing-soft", "--token", "ref"]), 0);
}

/// `lock` and `delete` write the lock by default; `--no-update-lock` compares only (first use
/// is then 10 and nothing is written). Where the lock cannot be written — a Nix build sandbox, a
/// read-only lock, a read-only directory — a writing run is refused (21) before the token is
/// touched, naming `--no-update-lock`; `check` never writes and is unaffected.
#[test]
fn lock_is_written_by_default_and_refused_where_it_cannot_be() {
    use std::os::unix::fs::PermissionsExt;
    let Some(e) = env("lock-default") else { return };
    e.config(&EC.replace("ec-lifecycle", "lock-default"));
    let r = ["lock", "--spec", "signing-soft", "--token", "ref"];
    let compare = [&r[..], &["--no-update-lock"]].concat();
    let lock = e.dir.join("keys.lock");
    let refused = |o: &Output, why: &str| {
        let err = stderr(o);
        assert_eq!(code(o), 21, "{err}");
        assert!(err.contains(why) && err.contains("--no-update-lock"), "{err}");
    };

    // Compare only: first use is 10 and the lock is not created.
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref", "--no-update-lock"]), 18);
    assert_eq!(e.code(&compare), 18);
    assert!(!lock.exists());
    // Both spellings at once are a usage error.
    assert_eq!(e.code(&[&r[..], &["--update-lock", "--no-update-lock"]].concat()), 2);
    // The default records first use and succeeds.
    assert_eq!(e.code(&r), 0);
    assert!(e.lock()["realisations"]["signing-soft"]["ref"].is_table());

    // In a Nix build sandbox a writing run is refused up front, delete included; comparing and
    // `check` work there.
    let sandbox = [("NIX_BUILD_TOP", e.dir.as_path())];
    refused(&e.km_env(&r, &sandbox), "Nix build sandbox");
    refused(&e.km_env(&["delete", "--spec", "signing-soft", "--token", "ref"], &sandbox), "Nix build sandbox");
    assert_eq!(code(&e.km_env(&compare, &sandbox)), 0);
    assert_eq!(code(&e.km_env(&["check", "signing.id.rfc7093m4"], &sandbox)), 0);

    // A read-only lock (unless running as root, which access(2) lets write anyway).
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
    if std::fs::OpenOptions::new().append(true).open(&lock).is_err() {
        refused(&e.km(&r), "is not writable");
        assert_eq!(e.code(&compare), 0);
    }
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();

    // A read-only directory with no lock in it yet: the write would need a new file there.
    let ro = e.dir.join("ro");
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
    if std::fs::File::create(ro.join("probe")).is_err() {
        let elsewhere = ro.join("keys.lock");
        let elsewhere = elsewhere.to_str().unwrap();
        refused(&e.km(&[&["--lock", elsewhere][..], &r[..]].concat()), "directory");
        assert_eq!(e.code(&[&["--lock", elsewhere][..], &compare[..]].concat()), 18);
    }
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn commitment_label_comes_from_the_lock() {
    let Some(e) = env("label") else { return };
    let value = *b"commitment label test vector 32B";
    plant_secret(
        &e.session(),
        "label-mac",
        cryptoki::object::KeyType::GENERIC_SECRET,
        &value,
        &[Attribute::Sign(true)],
    );
    e.config(
        "[objects.m]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32\n\n\
         [specs.m]\nobject = \"m\"\nattributes = { CKA_SIGN = true }\n\
         tokens.ref = { locator = { CKA_LABEL = \"label-mac\" }, origin = \"adopt\" }\n",
    );
    let hmac = |label: &str| {
        let mut m = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(&value).unwrap();
        m.update(format!("{label}/commitment/CKK_GENERIC_SECRET/256").as_bytes());
        sri(&m.finalize().into_bytes())
    };
    let path = e.dir.join("keys.lock");
    let lock = |text: String| e.write_lock_keeping_realisations(&text.replace("{M_TYPE}", M_TYPE));
    let verify = ["verify", "--spec", "m", "--token", "ref"];

    // A new object gets the default label, and the lock records it.
    assert_eq!(e.code(&["lock", "--spec", "m", "--token", "ref", "--update-lock"]), 0);
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("version = 1"), "{text}");
    assert!(text.contains("commitmentLabel = \"key-management/v1\""), "{text}");
    assert_eq!(e.locked_id("m", "commitment"), hmac("key-management/v1"));

    // Another label in the lock is the one used (not the code default)...
    let custom = "example.org/keys/v1";
    lock(format!(
        "version = 1\n[objects.m]\ncommitmentLabel = \"{custom}\"\n{{M_TYPE}}[objects.m.ids]\ncommitment = \"{}\"\n",
        hmac(custom)
    ));
    assert_eq!(e.code(&verify), 0);
    // ...so a hash made with any other label does not match it.
    lock(format!(
        "version = 1\n[objects.m]\ncommitmentLabel = \"{custom}\"\n{{M_TYPE}}[objects.m.ids]\ncommitment = \"{}\"\n",
        hmac("key-management/v1")
    ));
    assert_eq!(e.code(&verify), 10);

    // Commitment IDs require the label; other lock versions are refused.
    lock(format!("version = 1\n{{M_TYPE}}[objects.m.ids]\ncommitment = \"{}\"\n", hmac("key-management/v1")));
    assert_eq!(e.code(&verify), 17);
    lock("version = 2\n".into());
    assert_eq!(e.code(&verify), 17);
}

const M_TYPE: &str = "[objects.m.type]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32\n";

#[test]
fn the_lock_pins_type_spec_provenance_and_schemes() {
    let Some(e) = env("pins") else { return };
    e.config(EC.replace("ec-lifecycle", "pins").as_str());
    let toml = e.dir.join("keys.toml");
    let path = e.dir.join("keys.lock");
    let config = std::fs::read_to_string(&toml).unwrap();
    let r = ["lock", "--spec", "signing-soft", "--token", "ref", "--update-lock"];
    let verify = ["verify", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 0);
    let locked = std::fs::read_to_string(&path).unwrap();
    let lock: toml::Value = toml::from_str(&locked).unwrap();
    assert_eq!(lock["objects"]["signing"]["type"]["curve"].as_str(), Some("secp256r1"));
    let seen = e.observation("signing-soft", "ref");
    assert_eq!(seen["provider"].as_str(), Some(REF.provider));
    assert!(seen["cakeysVersion"].as_str().is_some_and(|v| !v.is_empty()));

    // 1. A curve alias is the same object type: keys.toml and the lock canonicalize it, so
    //    nothing changed and nothing needs re-recording.
    std::fs::write(&toml, config.replace("curve = \"secp256r1\"", "curve = \"P-256\"")).unwrap();
    assert_eq!(e.code(&verify), 0);
    assert_eq!(e.code(&r), 0);
    std::fs::write(&toml, &config).unwrap();

    // 2. A changed spec (still satisfied by the token) needs the lock re-recorded.
    std::fs::write(&toml, config.replace("CKA_EXTRACTABLE = false }", "CKA_EXTRACTABLE = false, CKA_PRIVATE = true }"))
        .unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 14);
    assert!(stderr(&o).contains("spec 'signing-soft' changed in keys.toml"), "{}", stderr(&o));
    assert_eq!(e.code(&r), 0);
    assert_eq!(e.code(&verify), 0);
    std::fs::write(&toml, &config).unwrap();
    assert_eq!(e.code(&r), 0);
    let locked = std::fs::read_to_string(&path).unwrap();

    // 3. Provenance: another provider warns, another cakeys version is a note.
    std::fs::write(&path, locked.replace(&format!("provider = \"{}\"", REF.provider), "provider = \"other\"")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("warning:") && stderr(&o).contains("provider other"), "{}", stderr(&o));
    let version = seen["cakeysVersion"].as_str().unwrap();
    std::fs::write(&path, locked.replace(&format!("cakeysVersion = \"{version}\""), "cakeysVersion = \"0.0.0\""))
        .unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(
        stderr(&o).contains("note:") && stderr(&o).contains("cakeys 0.0.0") && !stderr(&o).contains("warning:"),
        "{}",
        stderr(&o)
    );

    // 4. A scheme this cakeys does not know is reported by name, not silently skipped.
    std::fs::write(
        &path,
        locked.replace(
            "[objects.signing.ids]\n",
            "[objects.signing.ids]\nfuturehash = \"sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\"\n",
        ),
    )
    .unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("futurehash") && stderr(&o).contains("does not know"), "{}", stderr(&o));

    // The alias is input-only: a lock recording `pubkeyhash` is refused with a rename hint.
    std::fs::write(&path, locked.replace("rfc7093m4 = ", "pubkeyhash = ")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 17);
    assert!(stderr(&o).contains("the lock uses 'rfc7093m4'"), "{}", stderr(&o));

    // IDs without a type are an incomplete lock.
    let lock_without_type = locked
        .lines()
        .filter(|l| {
            !["[objects.signing.type]", "class = \"CKO_PRIVATE_KEY\"", "keyType = \"CKK_EC\"", "curve = \"secp256r1\""]
                .contains(l)
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(&path, lock_without_type).unwrap();
    assert_eq!(e.code(&verify), 17);
}
