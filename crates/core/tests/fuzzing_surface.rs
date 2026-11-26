//! The entry points of the fuzz targets are never built into a product (review D8). Every
//! `mod fuzzing` in the workspace is built only for the tests, for the `fuzzing` feature and for
//! Kani, and only the fuzz crate (`fuzz/`, which is a separate workspace) enables that feature.
//! The `fuzzing` module of ykcs11, for example, trusts the root certificate of the test fixture,
//! which is a test key.

use std::path::{Path, PathBuf};

const GATE: &str = r#"#[cfg(any(test, feature = "fuzzing", kani))]"#;

fn files(dir: &Path, ext: &str, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, ext, out);
        } else if path.extension().is_some_and(|e| e == ext) {
            out.push(path);
        }
    }
}

fn crates() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
fn every_fuzzing_module_is_gated() {
    let mut rs = Vec::new();
    files(&crates(), "rs", &mut rs);
    let mut modules = 0;
    for path in rs {
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            // A `mod fuzzing` declaration, with any visibility.
            let t = line.trim_start();
            let after_pub = t.strip_prefix("pub").map(|r| r.split_once(' ').map_or(r, |(_, rest)| rest));
            if after_pub.unwrap_or(t).starts_with("mod fuzzing") {
                modules += 1;
                assert_eq!(
                    i.checked_sub(1).map(|p| lines[p].trim()),
                    Some(GATE),
                    "{}:{}: `mod fuzzing` without {GATE} on the line before it",
                    path.display(),
                    i + 1
                );
            }
        }
    }
    // The six modules: in core, caprobe, camigrate, tpm2-pkcs11 (two: the crate's and its
    // attestation module's), and ykcs11.
    assert_eq!(modules, 6, "the scan found the modules it guards");
}

#[test]
fn no_workspace_manifest_turns_fuzzing_on() {
    let mut tomls = Vec::new();
    files(&crates(), "toml", &mut tomls);
    tomls.push(crates().join("../Cargo.toml"));
    for path in tomls.iter().filter(|p| p.file_name().is_some_and(|n| n == "Cargo.toml")) {
        let manifest: toml::Table = std::fs::read_to_string(path).unwrap().parse().unwrap();
        let mut on = Vec::new();
        let mut walk = |v: &toml::Value, here: String| walk_features(v, &here, &mut on);
        for (k, v) in &manifest {
            walk(v, k.clone());
        }
        assert!(on.is_empty(), "{}: {on:?} turns the fuzzing entry points on", path.display());
    }
}

/// Collects into `on` the path of every array under `v` that names the feature `fuzzing` (or
/// `<crate>/fuzzing`). That covers every `features` list of a dependency and every feature list
/// of `[features]`. The definition `fuzzing = []` names no feature, so it is not collected.
fn walk_features(v: &toml::Value, here: &str, on: &mut Vec<String>) {
    match v {
        toml::Value::Array(items) => {
            if items.iter().any(|i| i.as_str().is_some_and(|s| s == "fuzzing" || s.ends_with("/fuzzing"))) {
                on.push(here.to_owned());
            }
        }
        toml::Value::Table(t) => {
            for (k, v) in t {
                walk_features(v, &format!("{here}.{k}"), on);
            }
        }
        _ => {}
    }
}
