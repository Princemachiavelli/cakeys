//! Each tool's `patched-cryptoki` feature names every part the patched binding makes possible
//! (review D3). The tests that link the patched binding see the workspace's unified features, so
//! one manifest missing a part would pass them and leave that tool, built alone, without it.

use std::path::Path;

#[test]
fn every_tool_turns_on_what_the_patched_binding_makes_possible() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let binding = ["cakeys-pkcs11/rv-value"];
    for (dir, own) in [("cli", &[][..]), ("caprobe", &["kwp"][..]), ("camigrate", &["kwp"][..])] {
        let path = crates.join(dir).join("Cargo.toml");
        let manifest: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let features = manifest["features"]["patched-cryptoki"]
            .as_array()
            .unwrap_or_else(|| panic!("{} has no `patched-cryptoki` feature", path.display()));
        let names: Vec<&str> = features.iter().filter_map(toml::Value::as_str).collect();
        for part in binding.iter().chain(own) {
            assert!(names.contains(part), "{}: `patched-cryptoki` lacks `{part}`: {names:?}", path.display());
        }
    }
}
