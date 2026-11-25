//! Tests of the lock file: its invariants, provenance and observations, what it pins, and the
//! sidecar lock that makes its writers run one after another.

use super::*;

#[test]
fn module_and_token_provenance_warn_but_do_not_fail() {
    let Some(e) = env("provenance") else { return };
    e.config(EC.replace("ec-lifecycle", "provenance").as_str());
    let r = ["lock", "--spec", "signing-soft", "--token", "ref"];
    let verify = ["check", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref", "--no-update-lock"]), 18);
    assert_eq!(e.code(&r), 22);

    let real = &e.lock()["realisations"]["signing-soft"]["ref"];
    let seen = e.observation("signing-soft", "ref");
    // The file that was actually loaded, with symlinks resolved. It is recorded as provenance
    // only.
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

    // A different module version still verifies (the identity is the CA-ID), with a warning.
    // The test does not use 0.0, because kryoptic reports that as its library version.
    std::fs::write(&path, original.replace(&format!("version = \"{version}\""), "version = \"99.99\"")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("warning:") && stderr(&o).contains("with module"), "{}", stderr(&o));

    // The same build identity in a different file causes only a note.
    std::fs::write(&path, original.replace(loaded, "/nix/store/old-softhsm/lib/libsofthsm2.so")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("note:") && !stderr(&o).contains("warning:"), "{}", stderr(&o));

    // The file's hash is recorded too. Other content at the same path (a file replaced in place,
    // as can happen outside the Nix store) causes a warning.
    let hash = seen["module"]["hash"].as_str().unwrap().to_owned();
    assert_eq!(hash, sri(&std::fs::read(loaded).unwrap()));
    std::fs::write(&path, original.replace(&hash, "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 0);
    assert!(stderr(&o).contains("warning:") && stderr(&o).contains("of hash"), "{}", stderr(&o));

    // A different token causes a warning.
    std::fs::write(&path, original.replace(&format!("model = \"{}\"", REF.model), "model = \"Other\"")).unwrap();
    assert!(stderr(&e.km(&verify)).contains("realised on token Other"));

    // A writing `lock` binds the realisation again and records the current module and token.
    assert_eq!(e.code(&r), 22);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

    // The lock records the file that the loader mapped, with symlinks resolved, whatever named
    // it: a symlink given with --module, or a bare file name that the library search found.
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
    // The loader's search variable: LD_LIBRARY_PATH on Linux, DYLD_LIBRARY_PATH on darwin.
    let dir = module.parent().unwrap();
    let search = [("LD_LIBRARY_PATH", dir), ("DYLD_LIBRARY_PATH", dir)];
    assert_eq!(module_path(&e.km_env(&[&["--module", bare.as_str()][..], &r[..]].concat(), &search)), loaded);
    // A per-machine `module = "$NAME"`: when the variable is unset, the module is unavailable
    // (16, because this host's environment does not provide it: review A-14), unless --module
    // replaces it first, as lib.mkKeys does in a build sandbox that sets no such variable.
    let toml = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    e.write_config(&toml.replace(&format!("module = \"{}\"", e.module), "module = \"$CAKEYS_TEST_UNSET_MODULE\""));
    let o = e.km(&verify);
    assert_eq!(code(&o), 16);
    assert!(stderr(&o).contains("CAKEYS_TEST_UNSET_MODULE"), "{}", stderr(&o));
    assert_eq!(e.code(&[&["--module", via_link.as_str()][..], &verify[..]].concat()), 0);
    assert!(!stderr(&e.km(&verify)).contains("warning"));
}

/// The field classes have an effect: removing `observed`, `provenance` and the observation table
/// changes no verdict, while the compared fields and the version are required. A realisation must
/// also not name an observation that the lock lacks.
#[test]
fn observed_and_provenance_never_change_a_verdict() {
    let Some(e) = env("classes") else { return };
    e.config(EC.replace("ec-lifecycle", "classes").as_str());
    let verify = ["check", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
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
    // A wrong ID is still a mismatch (10), and a missing record is still a precondition failure
    // (14).
    let mut wrong = strip(full.clone());
    wrong["objects"]["signing"]["ids"]["rfc7093m4"] = sri(b"other").into();
    write(&wrong);
    assert_eq!(e.code(&verify), 10);
    let mut unrecorded = full.clone();
    unrecorded["realisations"].as_table_mut().unwrap().clear();
    write(&unrecorded);
    assert_eq!(e.code(&verify), 14);
    // The version and every compared field are required.
    let mut versionless = full.clone();
    versionless.as_table_mut().unwrap().remove("version");
    write(&versionless);
    assert_eq!(e.code(&verify), 17);
    let mut objectless = full.clone();
    objectless["realisations"]["signing-soft"]["ref"].as_table_mut().unwrap().remove("object");
    write(&objectless);
    assert_eq!(e.code(&verify), 17);
}

/// A malformed or self-contradictory lock is invalid (exit 17), and not a hash mismatch. The same
/// material is never recorded under two names. A run that computes fewer schemes than the lock
/// records is refused.
#[test]
fn lock_invariants_are_checked() {
    let Some(e) = env("invariants") else { return };
    let body = EC.replace("ec-lifecycle", "invariants")
        + "\n[objects.twin]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
           [specs.twin]\nobject = \"twin\"\nattributes = { CKA_SIGN = true }\n\
           tokens.ref = { locator = { CKA_LABEL = \"invariants\" }, origin = \"adopt\" }\n";
    e.config(&body);
    let verify = ["check", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    let good = e.lock();
    assert_eq!(good["realisations"]["signing-soft"]["ref"]["schemes"].as_array().unwrap().len(), 1);
    // The same key under a second object name is refused when recording.
    assert_eq!(e.code(&["lock", "--spec", "twin", "--token", "ref"]), 14);
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
    // A scheme that the realisation established but no longer computes is a downgrade.
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

/// M3: a writing run holds an advisory lock on `<lock>.lck` during its read-modify-write. While
/// another process holds the sidecar lock, a second updater waits and a reader continues.
#[test]
fn update_lock_waits_for_the_sidecar_lock() {
    let Some(e) = env("m3-flock") else { return };
    e.config(EC.replace("ec-lifecycle", "m3-flock").as_str());
    let r = ["lock", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);

    // Hold the sidecar in the same way as cakeys does: with an exclusive std file lock.
    let held =
        std::fs::File::options().write(true).create(true).truncate(false).open(e.dir.join("keys.lock.lck")).unwrap();
    held.lock().unwrap();
    let spawn = |args: &[&str]| e.run().command(args).spawn().unwrap();
    // A reader never takes the sidecar lock, so `check` finishes while the lock is held. This
    // holds however slow the build is (a debug build behind the fault shim takes over a second),
    // because a reader that waited would never finish.
    let mut reader = spawn(&["check", "--spec", "signing-soft", "--token", "ref"]);
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
    drop(held);
    // An updater waits, and prints a note before it blocks. The test waits for that note, and
    // never for a timer, because a slow build (the fault shim's) once outlasted the timer without
    // taking any lock (review lockfile.rs F1).
    let (waited, code) = waits_for_the_sidecar(&e, &r);
    waited.unwrap_or_else(|said| panic!("the updater did not wait for the sidecar lock: {said}"));
    assert_eq!(code, Some(0));

    // The sidecar belongs to the lock file, however the run names the file (review D2), so an
    // updater that names the lock through a symlink waits on the same `<lock>.lck`.
    let link = e.dir.join("linked.lock");
    std::os::unix::fs::symlink(e.dir.join("keys.lock"), &link).unwrap();
    let (waited, _) = waits_for_the_sidecar(&e, &[&["--lock", link.to_str().unwrap()][..], &r[..]].concat());
    waited.unwrap_or_else(|said| panic!("through a symlink, the updater took another sidecar: {said}"));
    assert!(!e.dir.join("linked.lock.lck").exists(), "a sidecar beside the symlink");
    assert_eq!(e.code(&["check", "--spec", "signing-soft", "--token", "ref"]), 0);

    // `gc` writes the lock, so it holds the sidecar too (docs/CAKEYS.md; review delete.rs F4).
    let (waited, code) = waits_for_the_sidecar(&e, &["gc"]);
    waited.unwrap_or_else(|said| panic!("gc did not wait for the sidecar lock: {said}"));
    assert_eq!(code, Some(0));
}

/// Runs `args` while this test holds `keys.lock.lck` as cakeys does (with an exclusive file lock).
/// The first value is `Ok` when the run printed that it waits for the lock and was still running
/// then, and otherwise `Err` with what the run printed. In either case, the hold is released and
/// the run finishes, and the second value is the run's exit code.
fn waits_for_the_sidecar(e: &Suite, args: &[&str]) -> (Result<(), String>, Option<i32>) {
    use std::sync::mpsc::RecvTimeoutError;
    let sidecar = e.dir.join("keys.lock.lck");
    let held = std::fs::File::options().write(true).create(true).truncate(false).open(&sidecar).unwrap();
    held.lock().unwrap();
    let mut run = e.run().command(args).stderr(std::process::Stdio::piped()).spawn().unwrap();
    let lines = std::io::BufRead::lines(std::io::BufReader::new(run.stderr.take().unwrap()));
    let (tell, heard) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in lines.map_while(Result::ok) {
            let _ = tell.send(line);
        }
    });
    let waiting = format!("note: waiting for {}: another run is updating the lock", sidecar.display());
    let mut said = Vec::new();
    let heard_it = loop {
        match heard.recv_timeout(std::time::Duration::from_secs(60)) {
            Ok(line) if line == waiting => break true,
            Ok(line) => said.push(line),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break false,
        }
    };
    let running = run.try_wait().unwrap().is_none();
    drop(held);
    let status = run.wait().unwrap();
    reader.join().unwrap();
    let verdict = if heard_it && running {
        Ok(())
    } else {
        Err(format!("{said:?}, and it {}", if running { "never said it waits" } else { "had finished" }))
    };
    (verdict, status.code())
}

/// `lock` and `delete` write the lock by default, and a run that writes it exits 22, which means
/// that the run succeeded and that the lock is ready to review and commit. `--dry-run` only
/// compares (first use then exits 18, and nothing is written). Every verb refuses a lock that does
/// not exist (17), unless `--new-lock` starts one, so a mistyped `--lock` never makes a new, empty
/// lock. Where the lock cannot be written (a Nix build sandbox, a read-only lock, a read-only
/// directory), a writing run is refused (21) before the token is touched, and the message names
/// `--dry-run`. The verbs `check` and `resolve` never write, so they still work there (review
/// 2026-11-23 C-4, C-16). The test also runs `resolve` on a key that the lock does not record,
/// with no lock file present, and checks that it exits 0, creates no lock file and does not change
/// the token's objects (CAKEYS.md: "`resolve` and `check` are GETs and never write either").
#[test]
fn lock_is_written_by_default_and_refused_where_it_cannot_be() {
    use std::os::unix::fs::PermissionsExt;
    let Some(e) = env("lock-default") else { return };
    e.config(&EC.replace("ec-lifecycle", "lock-default"));
    let r = ["lock", "--spec", "signing-soft", "--token", "ref"];
    let compare = [&r[..], &["--dry-run"]].concat();
    let lock = e.dir.join("keys.lock");
    let refused = |o: &Output, why: &str| {
        let err = stderr(o);
        assert_eq!(code(o), 21, "{err}");
        assert!(err.contains(why) && err.contains("--dry-run"), "{err}");
    };

    // Without a lock, every verb refuses (17), names --new-lock, and creates nothing.
    std::fs::remove_file(&lock).unwrap();
    for args in [&r[..], &compare, &["check", "--spec", "signing-soft", "--token", "ref"], &["gc"]] {
        let o = e.km(args);
        assert!(code(&o) == 17 && stderr(&o).contains("--new-lock"), "{args:?}: {}", stderr(&o));
    }
    assert!(!lock.exists());
    // With --new-lock, a compare-only run reads the lock as empty: first use exits 18, and no
    // lock is created.
    assert_eq!(e.code(&["--new-lock", "create", "--spec", "signing-soft", "--token", "ref", "--no-update-lock"]), 18);
    assert_eq!(e.code(&[&["--new-lock"][..], &compare].concat()), 18);
    assert!(!lock.exists());
    // Resolve the key that the lock does not record. It must exit 0, create no lock file and
    // leave the token's objects unchanged.
    let resolve = ["resolve", "--spec", "signing-soft", "--token", "ref"];
    let before = state::snapshot(&[&lock], &[e.token_view()]);
    let o = e.km(&[&["--new-lock"][..], &resolve].concat());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    state::assert_unchanged(&before, &state::snapshot(&[&lock], &[e.token_view()]), "resolve");
    // `--update-lock` no longer exists (2), because writing is the default.
    assert_eq!(e.code(&[&r[..], &["--update-lock"]].concat()), 2);
    // A writing run records the first use, prints that it wrote the lock, and exits 22.
    let o = e.km(&[&["--new-lock"][..], &r[..]].concat());
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert!(stderr(&o).contains(&format!("updated {}", lock.display())), "{}", stderr(&o));
    assert!(e.lock()["realisations"]["signing-soft"]["ref"].is_table());
    // A second run changes nothing: it exits 0, and the lock is untouched.
    let before = std::fs::read(&lock).unwrap();
    assert_eq!(e.code(&r), 0);
    assert_eq!(std::fs::read(&lock).unwrap(), before);

    // In a Nix build sandbox, a writing run is refused before it starts, including a delete. A
    // comparison and `check` work there.
    let sandbox = [("NIX_BUILD_TOP", e.dir.as_path())];
    refused(&e.km_env(&r, &sandbox), "Nix build sandbox");
    refused(&e.km_env(&["delete", "--spec", "signing-soft", "--token", "ref"], &sandbox), "Nix build sandbox");
    assert_eq!(code(&e.km_env(&compare, &sandbox)), 0);
    assert_eq!(code(&e.km_env(&["check", "signing.id.rfc7093m4"], &sandbox)), 0);
    assert_eq!(code(&e.km_env(&resolve, &sandbox)), 0);

    // A read-only lock (unless the test runs as root, which access(2) lets write anyway).
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o444)).unwrap();
    if std::fs::OpenOptions::new().append(true).open(&lock).is_err() {
        refused(&e.km(&r), "is not writable");
        assert_eq!(e.code(&compare), 0);
        assert_eq!(e.code(&resolve), 0);
    } else {
        skip("lockfile", REF.require_var, "the read-only lock: this user writes a mode-444 file");
    }
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();

    // A read-only directory with no lock in it yet, where the write would need a new file.
    let ro = e.dir.join("ro");
    std::fs::create_dir_all(&ro).unwrap();
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
    if std::fs::File::create(ro.join("probe")).is_err() {
        let elsewhere = ro.join("keys.lock");
        let elsewhere = elsewhere.to_str().unwrap();
        assert_eq!(e.code(&[&["--lock", elsewhere][..], &r[..]].concat()), 17);
        refused(&e.km(&[&["--new-lock", "--lock", elsewhere][..], &r[..]].concat()), "directory");
        assert_eq!(e.code(&[&["--new-lock", "--lock", elsewhere][..], &compare[..]].concat()), 18);
    } else {
        skip("lockfile", REF.require_var, "the read-only directory: this user writes into a mode-555 one");
    }
    std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// `CAKEYS_CONFIG` and `CAKEYS_LOCK` stand in for `--config` and `--lock`, and the flags take
/// precedence over them. A lock that exists but cannot be read is an I/O failure (1), and never a
/// first use (review lockfile.rs F2: neither the variables nor exit 1 had a test).
#[test]
fn the_variables_name_the_files_and_an_unreadable_lock_is_an_io_failure() {
    use std::os::unix::fs::PermissionsExt;
    let Some(e) = env("lock-vars") else { return };
    e.config(&EC.replace("ec-lifecycle", "lock-vars"));
    let r = ["lock", "--spec", "signing-soft", "--token", "ref"];
    let verify = ["check", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref", "--no-update-lock"]), 18);
    let config = e.dir.join("keys.toml");
    let elsewhere = e.dir.join("elsewhere.lock");
    let beside = std::fs::read(e.dir.join("keys.lock")).unwrap();

    // The variables alone (through `tool`, not `Run`, because `Run` names the config with the
    // flag).
    let o = tool(BIN).env("CAKEYS_CONFIG", &config).env("CAKEYS_LOCK", &elsewhere).args(r).output().unwrap();
    assert_eq!(code(&o), 17, "no lock there yet: {}", stderr(&o));
    let o = tool(BIN)
        .env("CAKEYS_CONFIG", &config)
        .env("CAKEYS_LOCK", &elsewhere)
        .arg("--new-lock")
        .args(r)
        .output()
        .unwrap();
    assert_eq!(code(&o), 22, "{}", stderr(&o));
    assert!(elsewhere.is_file(), "no lock where CAKEYS_LOCK names it");
    assert_eq!(std::fs::read(e.dir.join("keys.lock")).unwrap(), beside, "the lock beside the config written");

    // The flags take precedence over variables that name nothing.
    let o = tool(BIN)
        .env("CAKEYS_CONFIG", e.dir.join("absent.toml"))
        .env("CAKEYS_LOCK", e.dir.join("absent.lock"))
        .arg("--config")
        .arg(&config)
        .arg("--lock")
        .arg(&elsewhere)
        .args(verify)
        .output()
        .unwrap();
    assert_eq!(code(&o), 0, "{}", stderr(&o));

    // A lock that this user cannot read (root reads it anyway).
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::File::open(&elsewhere).is_ok() {
        skip("lock-vars", REF.require_var, "the unreadable lock: this user reads a mode-000 file");
    } else {
        let o = e.km(&[&["--lock", elsewhere.to_str().unwrap()][..], &verify[..]].concat());
        assert_eq!(code(&o), 1, "{}", stderr(&o));
    }
    std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o644)).unwrap();
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
    let verify = ["check", "--spec", "m", "--token", "ref"];

    // A new object gets the default label, and the lock records it.
    assert_eq!(e.code(&["lock", "--spec", "m", "--token", "ref"]), 22);
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

    // Commitment IDs require the label, and other lock versions are refused.
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
    let r = ["lock", "--spec", "signing-soft", "--token", "ref"];
    let verify = ["check", "--spec", "signing-soft", "--token", "ref"];
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    let locked = std::fs::read_to_string(&path).unwrap();
    let lock: toml::Value = toml::from_str(&locked).unwrap();
    assert_eq!(lock["objects"]["signing"]["type"]["curve"].as_str(), Some("secp256r1"));
    let seen = e.observation("signing-soft", "ref");
    assert_eq!(seen["provider"].as_str(), Some(REF.provider));
    assert!(seen["cakeysVersion"].as_str().is_some_and(|v| !v.is_empty()));

    // 1. A curve alias is the same object type. keys.toml and the lock canonicalize it, so
    //    nothing changed, and nothing needs to be recorded again.
    std::fs::write(&toml, config.replace("curve = \"secp256r1\"", "curve = \"P-256\"")).unwrap();
    assert_eq!(e.code(&verify), 0);
    assert_eq!(e.code(&r), 0);
    std::fs::write(&toml, &config).unwrap();

    // 2. A changed spec (which the token still satisfies) needs the lock to be recorded again.
    std::fs::write(&toml, config.replace("CKA_EXTRACTABLE = false }", "CKA_EXTRACTABLE = false, CKA_PRIVATE = true }"))
        .unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 14);
    assert!(stderr(&o).contains("spec 'signing-soft' changed in keys.toml"), "{}", stderr(&o));
    assert_eq!(e.code(&r), 22);
    assert_eq!(e.code(&verify), 0);
    std::fs::write(&toml, &config).unwrap();
    assert_eq!(e.code(&r), 22);
    let locked = std::fs::read_to_string(&path).unwrap();

    // 3. Provenance: another provider causes a warning, and another cakeys version causes a
    //    note.
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

    // 4. A scheme that this cakeys does not know is reported by name, and not skipped without
    //    a message.
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

    // The alias is accepted only as input: a lock that records `pubkeyhash` is refused with a
    // hint to rename it.
    std::fs::write(&path, locked.replace("rfc7093m4 = ", "pubkeyhash = ")).unwrap();
    let o = e.km(&verify);
    assert_eq!(code(&o), 17);
    assert!(stderr(&o).contains("the lock uses 'rfc7093m4'"), "{}", stderr(&o));

    // A lock with IDs but without a type is incomplete.
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
