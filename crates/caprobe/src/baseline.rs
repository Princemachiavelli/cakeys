//! The spec baseline's generator (docs/CAPROBE.md D1): profiles/baselines/pkcs11-3.2.toml is
//! generated from the vendored OASIS headers, never edited. Test-only: the first test
//! regenerates and compares on every run (`CAKEYS_UPDATE_BASELINE=1 cargo test -p caprobe`
//! rewrites the committed file after a header bump); the second pins the frozen spellings and
//! IDs.

use cakeys_profile::Baseline;
use cakeys_profile::baseline::{CURVES, ClassMembers};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// The `CKP_*` names that are conformance profiles (the PKCS #11 Profiles standard), not
/// parameter sets. Everything else under `CKP_` in pkcs11t.h is a parameter set: the PQ sets
/// (ML-DSA/ML-KEM/SLH-DSA) and the PBKDF2 pseudo-random functions. A future header that adds a
/// conformance profile lands it in the wrong section and so changes the generated file: the
/// pinned test fails, forcing this list to grow.
const CONFORMANCE: [&str; 7] = [
    "CKP_INVALID_ID",
    "CKP_BASELINE_PROVIDER",
    "CKP_EXTENDED_PROVIDER",
    "CKP_AUTHENTICATION_TOKEN",
    "CKP_PUBLIC_CERTIFICATES_TOKEN",
    "CKP_COMPLETE_PROVIDER",
    "CKP_HKDF_TLS_TOKEN",
];

/// Generate the baseline from the OASIS header files: `types` is pkcs11t.h, `functions`
/// pkcs11f.h. Only `#define <PREFIX>_... 0x...` constants are taken: aliases
/// (`#define CKM_SHA3_256_KEY_DERIVE CKM_SHA3_256_KEY_DERIVATION`) and the
/// `*_VENDOR_DEFINED` range constants are skipped, so every name maps to its own ID.
#[must_use]
fn from_headers(name: &str, types: &str, functions: &str) -> Baseline {
    let mut b = Baseline {
        baseline: name.to_owned(),
        mechanisms: BTreeMap::new(),
        key_types: BTreeMap::new(),
        attributes: BTreeMap::new(),
        objects: BTreeMap::new(),
        functions: BTreeSet::new(),
        parameter_sets: BTreeMap::new(),
        conformance_profiles: BTreeMap::new(),
        curves: CURVES.iter().map(|s| (*s).to_owned()).collect(),
        class: BTreeMap::new(),
    };
    for line in types.lines() {
        let Some(rest) = line.trim_start().strip_prefix("#define ") else { continue };
        let mut fields = rest.split_whitespace();
        let (Some(name), Some(value)) = (fields.next(), fields.next()) else { continue };
        if name.ends_with("VENDOR_DEFINED") {
            continue;
        }
        let Some(hex) = value.strip_prefix("0x").map(|v| v.strip_suffix("UL").unwrap_or(v)) else {
            continue;
        };
        let Ok(id) = u64::from_str_radix(hex, 16) else { continue };
        let map = match name {
            n if n.starts_with("CKM_") => Some(&mut b.mechanisms),
            n if n.starts_with("CKK_") => Some(&mut b.key_types),
            n if n.starts_with("CKA_") => Some(&mut b.attributes),
            n if n.starts_with("CKO_") => Some(&mut b.objects),
            n if n.starts_with("CKP_") => {
                Some(if CONFORMANCE.contains(&name) { &mut b.conformance_profiles } else { &mut b.parameter_sets })
            }
            _ => None,
        };
        if let Some(map) = map {
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
    b.class = curated_classes(&b);
    b
}

/// The curated classes ([`from_headers`]'s taxonomy): what `--class` can list.
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

/// Emit the baseline as TOML, the deterministic form the pinned test regenerates and the
/// committed file (`profiles/baselines/pkcs11-3.2.toml`) mirrors.
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
    // Top-level keys precede every table (TOML has no table close).
    let _ = writeln!(s, "functions = [{}]", quoted(&b.functions));
    let _ = writeln!(s, "curves = [{}]", quoted(&b.curves));
    head(&mut s, "mechanisms");
    for (n, id) in &b.mechanisms {
        let _ = writeln!(s, "{n} = {id:#010x}");
    }
    head(&mut s, "key-types");
    for (n, id) in &b.key_types {
        let _ = writeln!(s, "{n} = {id:#010x}");
    }
    head(&mut s, "attributes");
    for (n, id) in &b.attributes {
        let _ = writeln!(s, "{n} = {id:#010x}");
    }
    head(&mut s, "objects");
    for (n, id) in &b.objects {
        let _ = writeln!(s, "{n} = {id:#010x}");
    }
    head(&mut s, "parameter-sets");
    for (n, id) in &b.parameter_sets {
        let _ = writeln!(s, "{n} = {id:#010x}");
    }
    head(&mut s, "conformance-profiles");
    for (n, id) in &b.conformance_profiles {
        let _ = writeln!(s, "{n} = {id:#010x}");
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

/// TOML array body: `\"a\", \"b\"` for the emitted arrays.
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

#[test]
fn committed_baseline_is_generated_from_the_vendored_headers() {
    let generated = from_headers("pkcs11-3.2", TYPES, FUNCTIONS);
    if std::env::var_os("CAKEYS_UPDATE_BASELINE").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles/baselines/pkcs11-3.2.toml");
        std::fs::write(path, to_toml(&generated)).expect("writing the regenerated baseline");
    }
    let committed = Baseline::from_toml(COMMITTED).expect("the committed baseline parses");
    assert_eq!(
        committed, generated,
        "profiles/baselines/pkcs11-3.2.toml is not what the vendored headers generate; regenerate with CAKEYS_UPDATE_BASELINE=1"
    );
}

#[test]
fn names_and_ids_are_pinned() {
    let b = Baseline::from_toml(COMMITTED).unwrap();
    // Mechanisms the layers and profiles name, with their spec IDs.
    assert_eq!(b.mechanisms["CKM_AES_KEY_WRAP"], 0x2109);
    assert_eq!(b.mechanisms["CKM_AES_KEY_WRAP_PAD"], 0x210A);
    assert_eq!(b.mechanisms["CKM_AES_KEY_WRAP_KWP"], 0x210B);
    assert_eq!(b.mechanisms["CKM_EC_EDWARDS_KEY_PAIR_GEN"], 0x1055);
    assert_eq!(b.mechanisms["CKM_EDDSA"], 0x1057);
    assert_eq!(b.mechanisms["CKM_AES_CBC_ENCRYPT_DATA"], 0x1105);
    // PKCS #11 3.2's PQ mechanisms: one mechanism per algorithm, parameter sets by CKA_PARAMETER_SET.
    assert_eq!(b.mechanisms["CKM_ML_DSA"], 0x1D);
    assert_eq!(b.mechanisms["CKM_ML_KEM"], 0x17);
    assert_eq!(b.mechanisms["CKM_SLH_DSA"], 0x2E);
    assert_eq!(b.parameter_sets["CKP_ML_DSA_65"], 0x2);
    assert_eq!(b.parameter_sets["CKP_ML_KEM_1024"], 0x3);
    assert_eq!(b.parameter_sets["CKP_SLH_DSA_SHA2_256F"], 0xB);
    // The key types the cryptoki layer subtracts, with their real (patched cryptoki) IDs.
    assert_eq!(b.key_types["CKK_SHA224_HMAC"], 0x2E);
    assert_eq!(b.key_types["CKK_SHA384_HMAC"], 0x2C);
    assert_eq!(b.key_types["CKK_SHA512_HMAC"], 0x2D);
    // Attributes, the 3.2 functions, and the vendor-defined range constants staying out.
    assert_eq!(b.attributes["CKA_VALUE_LEN"], 0x161);
    assert!(b.functions.contains("C_EncapsulateKey"));
    assert!(!b.mechanisms.contains_key("CKM_VENDOR_DEFINED"));
    // The classes the queries group by, and the curve vocabulary of keys.toml.
    assert!(b.class["pq"].mechanisms.iter().any(|m| m == "CKM_ML_DSA"));
    assert!(b.class["hmac"].mechanisms.iter().any(|m| m == "CKM_SHA512_HMAC"));
    assert!(b.class["key-wrap"].mechanisms.iter().any(|m| m == "CKM_AES_KEY_WRAP_KWP"));
    assert_eq!(b.class["oaep"].mechanisms, ["CKM_RSA_PKCS_OAEP"]);
    assert!(b.curves.contains("secp256r1") && b.curves.contains("edwards25519"));
}
