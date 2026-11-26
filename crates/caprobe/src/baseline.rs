//! The generator of the spec baseline (docs/CAPROBE.md D1). The file
//! profiles/baselines/pkcs11-3.2.toml is generated from the vendored OASIS headers and is never
//! edited by hand. This module is used only by tests. The first test regenerates the baseline
//! and compares it with the committed file on every run. After a header update,
//! `CAKEYS_UPDATE_BASELINE=1 cargo test -p caprobe` regenerates the committed file: it writes the
//! new text beside the file as `.new`, or over the file with `CAKEYS_ACCEPT=1`
//! (`cakeys_profile::regenerate`). The second test pins the frozen spellings and IDs.

use cakeys_profile::baseline::{CURVES, ClassMembers, TABLES};
use cakeys_profile::{Baseline, regenerate};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

/// The `CKP_*` names that are conformance profiles (from the PKCS #11 Profiles standard), not
/// parameter sets. Every other `CKP_` name in pkcs11t.h is a parameter set: the post-quantum sets
/// (ML-DSA, ML-KEM and SLH-DSA) and the PBKDF2 pseudo-random functions. A future header that adds
/// a conformance profile puts it in the wrong section, which changes the generated file. The
/// pinned test then fails, and the fix is to add the name to this list.
const CONFORMANCE: [&str; 7] = [
    "CKP_INVALID_ID",
    "CKP_BASELINE_PROVIDER",
    "CKP_EXTENDED_PROVIDER",
    "CKP_AUTHENTICATION_TOKEN",
    "CKP_PUBLIC_CERTIFICATES_TOKEN",
    "CKP_COMPLETE_PROVIDER",
    "CKP_HKDF_TLS_TOKEN",
];

/// The constant families by prefix, each with its table ([`TABLES`]). The `CKP_` prefix is not
/// listed, because its names are split between `parameter-sets` and `conformance-profiles`
/// ([`CONFORMANCE`]).
const FAMILIES: [(&str, &str); 16] = [
    ("CKM_", "mechanisms"),
    ("CKK_", "key-types"),
    ("CKA_", "attributes"),
    ("CKO_", "objects"),
    ("CKR_", "return-values"),
    ("CKF_", "flags"),
    ("CKU_", "user-types"),
    ("CKS_", "session-states"),
    ("CKC_", "certificate-types"),
    ("CKH_", "hardware-features"),
    ("CKG_", "generators"),
    ("CKD_", "kdfs"),
    ("CKZ_", "sources"),
    ("CKN_", "notifications"),
    ("CKT_", "trust-values"),
    ("CKV_", "validation-types"),
];

/// Returns the value of a constant from its text. The text is a hex literal (`0x00000211UL`), a
/// decimal literal (`2UL`), or an or-expression in parentheses over literals and names that were
/// defined earlier (`(CKF_ARRAY_ATTRIBUTE|0x00000211UL)`, as the array attributes use). A bare
/// name is an alias, and this function returns no value for it.
fn value(text: &str, defined: &BTreeMap<String, u64>) -> Option<u64> {
    let literal = |t: &str| {
        let t = t.strip_suffix("UL").unwrap_or(t);
        match t.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).ok(),
            None => t.parse().ok(),
        }
    };
    match text.strip_prefix('(').and_then(|t| t.strip_suffix(')')) {
        Some(expr) => expr
            .split('|')
            .map(str::trim)
            .try_fold(0, |acc, t| Some(acc | literal(t).or_else(|| defined.get(t).copied())?)),
        None => literal(text),
    }
}

/// Generates the baseline from the OASIS header files: `types` is the text of pkcs11t.h, and
/// `functions` is the text of pkcs11f.h. The generator takes the constants of every family in
/// [`FAMILIES`] and reads their values with [`value`]. It skips aliases
/// (`#define CKM_SHA3_256_KEY_DERIVE CKM_SHA3_256_KEY_DERIVATION`) and the `*_VENDOR_DEFINED`
/// range constants, so that every name maps to its own ID.
///
/// # Errors
///
/// Returns each family constant, as `NAME text`, whose value [`value`] cannot read and that is
/// not an alias of a constant defined before it (for example `(1UL << 31)`, `~0UL`, or a name
/// that is defined later). Such a constant is never skipped silently, because the pinned test
/// compares the committed file with this generator's own output, so a dropped row would be
/// missing from both.
fn from_headers(name: &str, types: &str, functions: &str) -> Result<Baseline, Vec<String>> {
    let mut b = Baseline {
        baseline: name.to_owned(),
        mechanisms: BTreeMap::new(),
        key_types: BTreeMap::new(),
        attributes: BTreeMap::new(),
        objects: BTreeMap::new(),
        functions: BTreeSet::new(),
        parameter_sets: BTreeMap::new(),
        conformance_profiles: BTreeMap::new(),
        return_values: BTreeMap::new(),
        flags: BTreeMap::new(),
        user_types: BTreeMap::new(),
        session_states: BTreeMap::new(),
        certificate_types: BTreeMap::new(),
        hardware_features: BTreeMap::new(),
        generators: BTreeMap::new(),
        kdfs: BTreeMap::new(),
        sources: BTreeMap::new(),
        notifications: BTreeMap::new(),
        trust_values: BTreeMap::new(),
        validation_types: BTreeMap::new(),
        curves: CURVES.iter().map(|s| (*s).to_owned()).collect(),
        class: BTreeMap::new(),
    };
    // Every constant that has been read so far, for the or-expressions that name one.
    let mut defined = BTreeMap::new();
    let mut unread = Vec::new();
    for line in types.lines() {
        let Some(rest) = line.trim_start().strip_prefix("#define ") else { continue };
        let mut fields = rest.split_whitespace();
        let (Some(name), Some(text)) = (fields.next(), fields.next()) else { continue };
        let table = if name.starts_with("CKP_") {
            Some(if CONFORMANCE.contains(&name) { "conformance-profiles" } else { "parameter-sets" })
        } else {
            FAMILIES.iter().find(|(prefix, _)| name.starts_with(prefix)).map(|(_, table)| *table)
        };
        let Some(id) = value(text, &defined) else {
            // An alias names a constant that was already read, and that constant keeps its own
            // row, so an alias is not an error.
            if table.is_some() && !defined.contains_key(text) {
                unread.push(format!("{name} {text}"));
            }
            continue;
        };
        defined.insert(name.to_owned(), id);
        if name.ends_with("VENDOR_DEFINED") {
            continue;
        }
        if let Some(map) = table.and_then(|t| b.table_mut(t)) {
            map.insert(name.to_owned(), id);
        }
    }
    for line in functions.lines() {
        let Some(rest) = line.trim().strip_prefix("CK_PKCS11_FUNCTION_INFO(") else { continue };
        let Some(name) = rest.strip_suffix(')') else { continue };
        if name.starts_with("C_") {
            b.functions.insert(name.to_owned());
        }
    }
    if !unread.is_empty() {
        return Err(unread);
    }
    b.class = curated_classes(&b);
    Ok(b)
}

/// Returns the curated classes (the taxonomy of [`from_headers`]), which are the classes that
/// `--class` can list.
fn curated_classes(b: &Baseline) -> BTreeMap<String, ClassMembers> {
    let mut classes = BTreeMap::new();
    let pq = |n: &str| n.starts_with("CKM_ML_") || n.starts_with("CKM_SLH_") || n.contains("XMSS") || n.contains("HSS");
    classes.insert(
        "pq".into(),
        ClassMembers {
            mechanisms: b.mechanisms.keys().filter(|n| pq(n)).cloned().collect(),
            parameter_sets: b
                .parameter_sets
                .keys()
                .filter(|n| n.starts_with("CKP_ML_") || n.starts_with("CKP_SLH_"))
                .cloned()
                .collect(),
        },
    );
    classes.insert(
        "hmac".into(),
        ClassMembers {
            mechanisms: b.mechanisms.keys().filter(|n| n.contains("_HMAC")).cloned().collect(),
            parameter_sets: vec![],
        },
    );
    classes.insert(
        "key-wrap".into(),
        ClassMembers {
            mechanisms: b.mechanisms.keys().filter(|n| n.contains("KEY_WRAP")).cloned().collect(),
            parameter_sets: vec![],
        },
    );
    classes
        .insert("oaep".into(), ClassMembers { mechanisms: vec!["CKM_RSA_PKCS_OAEP".into()], parameter_sets: vec![] });
    classes
}

/// Writes the baseline as TOML. The output is deterministic: the pinned test regenerates it, and
/// the committed file (`profiles/baselines/pkcs11-3.2.toml`) has the same content.
#[must_use]
fn to_toml(b: &Baseline) -> String {
    let mut s = String::new();
    let head = |s: &mut String, table: &str| {
        if !s.is_empty() {
            s.push('\n');
        }
        let _ = writeln!(s, "[{table}]");
    };
    let _ = writeln!(
        s,
        "# Generated by caprobe (crates/caprobe) from the OASIS PKCS #11 v3.2 headers\n\
             # vendored in profiles/baselines/headers/pkcs11-3.2/. Never edit by hand: regenerate\n\
             # with CAKEYS_UPDATE_BASELINE=1 cargo test -p caprobe — the pinned test\n\
             # regenerates and compares on every run."
    );
    let _ = writeln!(s, "baseline = \"{}\"", b.baseline);
    // The top-level keys come before every table, because TOML has no way to close a table.
    let _ = writeln!(s, "functions = [{}]", quoted(&b.functions));
    let _ = writeln!(s, "curves = [{}]", quoted(&b.curves));
    for table in TABLES {
        head(&mut s, table);
        for (n, id) in b.table(table).into_iter().flatten() {
            let _ = writeln!(s, "{n} = {id:#010x}");
        }
    }
    for (class, members) in &b.class {
        let _ = writeln!(s);
        let _ = writeln!(s, "[class.{class}]");
        if !members.mechanisms.is_empty() {
            let _ = writeln!(s, "mechanisms = [{}]", quoted(&members.mechanisms));
        }
        if !members.parameter_sets.is_empty() {
            let _ = writeln!(s, "parameter-sets = [{}]", quoted(&members.parameter_sets));
        }
    }
    s
}

/// Returns the body of a TOML array, such as `\"a\", \"b\"`, for the emitted arrays.
fn quoted<'a, I>(names: I) -> String
where
    I: IntoIterator,
    I::Item: AsRef<str> + 'a,
{
    names.into_iter().map(|n| format!("\"{}\"", n.as_ref())).collect::<Vec<_>>().join(", ")
}

const TYPES: &str = include_str!("../../../profiles/baselines/headers/pkcs11-3.2/pkcs11t.h");
const FUNCTIONS: &str = include_str!("../../../profiles/baselines/headers/pkcs11-3.2/pkcs11f.h");
const COMMITTED: &str = include_str!("../../../profiles/baselines/pkcs11-3.2.toml");

/// Returns the baseline that the vendored headers generate.
fn vendored() -> Baseline {
    from_headers("pkcs11-3.2", TYPES, FUNCTIONS)
        .unwrap_or_else(|unread| panic!("family constants the generator cannot read: {unread:?}"))
}

/// Returns the baseline text to compare `generated` with. Without `update`, this is the
/// committed text that is compiled in. When `update` names the committed file, this is
/// `generated` as the regenerating run wrote it, so the run compares with what it just wrote and
/// passes. The file is written as every golden file is ([`regenerate::write`]): over the file
/// only when the change is accepted (the bool in `update`), and otherwise beside it as `.new`.
/// Nothing is written when the file already parses to `generated`, because `nix fmt` formats the
/// file after it is written, so its text never equals the emitter's text.
fn committed_text(generated: &Baseline, update: Option<(&Path, bool)>) -> String {
    match update {
        Some((path, accept)) => {
            let text = to_toml(generated);
            let now = std::fs::read_to_string(path).ok().and_then(|t| Baseline::from_toml(&t).ok());
            if now.as_ref() != Some(generated) {
                let written = regenerate::write(path, &text, accept).expect("writing the regenerated baseline");
                eprintln!("{written}");
            }
            text
        }
        None => COMMITTED.to_owned(),
    }
}

#[test]
fn committed_baseline_is_generated_from_the_vendored_headers() {
    let generated = vendored();
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles/baselines/pkcs11-3.2.toml"));
    let update = std::env::var_os("CAKEYS_UPDATE_BASELINE").is_some().then_some((path, regenerate::accepted()));
    let committed = Baseline::from_toml(&committed_text(&generated, update)).expect("the committed baseline parses");
    assert_eq!(
        committed, generated,
        "profiles/baselines/pkcs11-3.2.toml is not what the vendored headers generate; regenerate with CAKEYS_UPDATE_BASELINE=1"
    );
}

/// With `CAKEYS_UPDATE_BASELINE=1`, the test compares with the file that it wrote, not with the
/// file that is compiled in, so the regenerating run passes (review baseline F2). The run
/// replaces the committed file only when the change is accepted, and a file that parses to the
/// same baseline is not changed (review 2026-11-24 C-8).
#[test]
fn a_regenerating_run_compares_with_what_it_wrote() {
    let mut generated = vendored();
    generated.baseline = "regenerated".to_owned();
    let dir = std::env::temp_dir().join(format!("caprobe-baseline-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (path, new) = (dir.join("baseline.toml"), dir.join("baseline.toml.new"));
    let read = |p: &Path| std::fs::read_to_string(p).ok();
    let text = committed_text(&generated, Some((&path, false)));
    assert_eq!(read(&path).as_deref(), Some(text.as_str()));
    assert_eq!(Baseline::from_toml(&text).unwrap(), generated);
    // The formatted file is the same baseline, so nothing is written.
    std::fs::write(&path, text.replace(", ", ",\n  ")).unwrap();
    committed_text(&generated, Some((&path, false)));
    assert_eq!(read(&new), None);
    // A different baseline that is not accepted leaves the committed file unchanged and writes
    // the regenerated text beside it.
    let formatted = read(&path);
    generated.baseline = "again".to_owned();
    let again = committed_text(&generated, Some((&path, false)));
    assert_eq!(read(&path), formatted);
    assert_eq!(read(&new).as_deref(), Some(again.as_str()));
    // An accepted baseline replaces the file and removes the `.new` file.
    committed_text(&generated, Some((&path, true)));
    assert_eq!(read(&path).as_deref(), Some(again.as_str()));
    assert_eq!(read(&new), None);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A family constant that is written in a form that the scanner cannot read makes the generator
/// fail and name the constant. An alias of a constant that was read before it is skipped (review
/// baseline F1).
#[test]
fn an_unreadable_family_constant_fails_the_generator() {
    let aliases = "#define CKM_A 0x00000001UL\n#define CKM_B CKM_A\n#define CK_NOT_A_FAMILY (1UL << 2)\n";
    let b = from_headers("t", aliases, "").unwrap();
    assert_eq!(b.mechanisms.keys().collect::<Vec<_>>(), ["CKM_A"]);
    let unread =
        format!("{aliases}#define CKM_SHIFTED (1UL<<31)\n#define CKA_LATER CKA_NOT_YET\n#define CKA_NOT_YET 2UL\n");
    assert_eq!(from_headers("t", &unread, "").unwrap_err(), ["CKM_SHIFTED (1UL<<31)", "CKA_LATER CKA_NOT_YET"]);
}

/// The loader reads back exactly what the generator writes. This tests the emitter that
/// `CAKEYS_UPDATE_BASELINE=1` runs on every test run, not only when the baseline is regenerated.
#[test]
fn the_emitted_baseline_parses_back_to_itself() {
    let generated = vendored();
    let text = to_toml(&generated);
    assert_eq!(Baseline::from_toml(&text).expect("the emitted baseline parses"), generated);
    assert!(text.starts_with("# Generated by caprobe"), "{}", &text[..60]);
}

#[test]
fn names_and_ids_are_pinned() {
    let b = Baseline::from_toml(COMMITTED).unwrap();
    // The mechanisms that the layers and profiles name, with their IDs from the specification.
    assert_eq!(b.mechanisms["CKM_AES_KEY_WRAP"], 0x2109);
    assert_eq!(b.mechanisms["CKM_AES_KEY_WRAP_PAD"], 0x210A);
    assert_eq!(b.mechanisms["CKM_AES_KEY_WRAP_KWP"], 0x210B);
    assert_eq!(b.mechanisms["CKM_EC_EDWARDS_KEY_PAIR_GEN"], 0x1055);
    assert_eq!(b.mechanisms["CKM_EDDSA"], 0x1057);
    assert_eq!(b.mechanisms["CKM_AES_CBC_ENCRYPT_DATA"], 0x1105);
    // The post-quantum mechanisms of PKCS #11 3.2: one mechanism for each algorithm, with the
    // parameter set chosen by CKA_PARAMETER_SET.
    assert_eq!(b.mechanisms["CKM_ML_DSA"], 0x1D);
    assert_eq!(b.mechanisms["CKM_ML_KEM"], 0x17);
    assert_eq!(b.mechanisms["CKM_SLH_DSA"], 0x2E);
    assert_eq!(b.parameter_sets["CKP_ML_DSA_65"], 0x2);
    assert_eq!(b.parameter_sets["CKP_ML_KEM_1024"], 0x3);
    assert_eq!(b.parameter_sets["CKP_SLH_DSA_SHA2_256F"], 0xB);
    // The key types that the cryptoki layer subtracts, with their real IDs (as the patched
    // cryptoki defines them).
    assert_eq!(b.key_types["CKK_SHA224_HMAC"], 0x2E);
    assert_eq!(b.key_types["CKK_SHA384_HMAC"], 0x2C);
    assert_eq!(b.key_types["CKK_SHA512_HMAC"], 0x2D);
    // The attributes and the 3.2 functions, and a check that the vendor-defined range constants
    // are left out.
    assert_eq!(b.attributes["CKA_VALUE_LEN"], 0x161);
    assert!(b.functions.contains("C_EncapsulateKey"));
    assert!(!b.mechanisms.contains_key("CKM_VENDOR_DEFINED"));
    // The array attributes, defined as or-expressions over CKF_ARRAY_ATTRIBUTE.
    assert_eq!(b.attributes["CKA_ALLOWED_MECHANISMS"], 0x4000_0600);
    assert_eq!(b.attributes["CKA_WRAP_TEMPLATE"], 0x4000_0211);
    // The other constant families, including the families with decimal values. Aliases are
    // left out.
    assert_eq!(b.return_values["CKR_OK"], 0);
    assert_eq!(b.return_values["CKR_KEY_NOT_WRAPPABLE"], 0x69);
    assert_eq!(b.flags["CKF_ARRAY_ATTRIBUTE"], 0x4000_0000);
    assert_eq!(b.flags["CKF_TOKEN_INITIALIZED"], 0x400);
    assert_eq!(b.user_types["CKU_CONTEXT_SPECIFIC"], 2);
    assert_eq!(b.session_states["CKS_RW_USER_FUNCTIONS"], 3);
    assert_eq!(b.certificate_types["CKC_X_509"], 0);
    assert_eq!(b.generators["CKG_MGF1_SHA256"], 2);
    assert_eq!(b.kdfs["CKD_SHA256_KDF"], 6);
    assert_eq!(b.sources["CKZ_DATA_SPECIFIED"], 1);
    assert_eq!(b.trust_values["CKT_TRUST_ANCHOR"], 2);
    assert!(!b.return_values.contains_key("CKR_VENDOR_DEFINED"));
    // Every table that the generator writes is a table that the loader names.
    assert!(TABLES.iter().all(|t| b.table(t).is_some_and(|m| !m.is_empty())), "an empty or unknown table");
    // The classes that the queries group by, and the curve names that keys.toml uses.
    assert!(b.class["pq"].mechanisms.iter().any(|m| m == "CKM_ML_DSA"));
    assert!(b.class["hmac"].mechanisms.iter().any(|m| m == "CKM_SHA512_HMAC"));
    assert!(b.class["key-wrap"].mechanisms.iter().any(|m| m == "CKM_AES_KEY_WRAP_KWP"));
    assert_eq!(b.class["oaep"].mechanisms, ["CKM_RSA_PKCS_OAEP"]);
    assert!(b.curves.contains("secp256r1") && b.curves.contains("edwards25519"));
}
