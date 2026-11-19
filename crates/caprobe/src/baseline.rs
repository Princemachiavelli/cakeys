//! The spec baseline's generator (docs/CAPROBE.md D1): profiles/baselines/pkcs11-3.2.toml is
//! generated from the vendored OASIS headers, never edited. Test-only: the first test
//! regenerates and compares on every run (`CAKEYS_UPDATE_BASELINE=1 cargo test -p caprobe`
//! rewrites the committed file after a header bump); the second pins the frozen spellings and
//! IDs.

use cakeys_profile::Baseline;
use cakeys_profile::baseline::{CURVES, ClassMembers, TABLES};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

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

/// The constant families by prefix, each with its table ([`TABLES`]). `CKP_` is split between
/// `parameter-sets` and `conformance-profiles` ([`CONFORMANCE`]), so it is not listed.
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

/// A constant's value: a hex (`0x00000211UL`) or decimal (`2UL`) literal, or an or-expression
/// in parentheses over literals and names defined earlier (`(CKF_ARRAY_ATTRIBUTE|0x00000211UL)`,
/// the array attributes). A bare name is an alias and has no value of its own here.
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

/// Generate the baseline from the OASIS header files: `types` is pkcs11t.h, `functions`
/// pkcs11f.h. Constants of every family in [`FAMILIES`] are taken, by [`value`]; aliases
/// (`#define CKM_SHA3_256_KEY_DERIVE CKM_SHA3_256_KEY_DERIVATION`) and the
/// `*_VENDOR_DEFINED` range constants are skipped, so every name maps to its own ID.
///
/// # Errors
///
/// The family constants whose value [`value`] cannot read and that are no alias of a constant
/// defined before them (`(1UL << 31)`, `~0UL`, a name defined later): each `NAME text`. Never
/// skipped silently: the pinned test compares the committed file with this generator's own
/// output, so a dropped row would be missing from both.
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
    // Every constant read so far, for the or-expressions that name one.
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
            // An alias names a constant already read, which keeps its own row.
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

/// The vendored headers' baseline.
fn vendored() -> Baseline {
    from_headers("pkcs11-3.2", TYPES, FUNCTIONS)
        .unwrap_or_else(|unread| panic!("family constants the generator cannot read: {unread:?}"))
}

/// The baseline text to compare `generated` with: the committed one compiled in, or, when
/// `update` names the committed file, `generated` written there, so the regenerating run
/// compares with what it just wrote and passes.
fn committed_text(generated: &Baseline, update: Option<&Path>) -> String {
    match update {
        Some(path) => {
            let text = to_toml(generated);
            std::fs::write(path, &text).expect("writing the regenerated baseline");
            text
        }
        None => COMMITTED.to_owned(),
    }
}

#[test]
fn committed_baseline_is_generated_from_the_vendored_headers() {
    let generated = vendored();
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles/baselines/pkcs11-3.2.toml"));
    let update = std::env::var_os("CAKEYS_UPDATE_BASELINE").is_some().then_some(path);
    let committed = Baseline::from_toml(&committed_text(&generated, update)).expect("the committed baseline parses");
    assert_eq!(
        committed, generated,
        "profiles/baselines/pkcs11-3.2.toml is not what the vendored headers generate; regenerate with CAKEYS_UPDATE_BASELINE=1"
    );
}

/// `CAKEYS_UPDATE_BASELINE=1` compares with the file it wrote, not the one compiled in: the
/// regenerating run passes (review baseline F2).
#[test]
fn a_regenerating_run_compares_with_what_it_wrote() {
    let mut generated = vendored();
    generated.baseline = "regenerated".to_owned();
    let path = std::env::temp_dir().join(format!("caprobe-baseline-{}.toml", std::process::id()));
    let text = committed_text(&generated, Some(&path));
    let written = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(written, text);
    assert_eq!(Baseline::from_toml(&text).unwrap(), generated);
}

/// A family constant written in a form the scanner cannot read fails the generator, naming
/// it; an alias of a constant read before it is skipped (review baseline F1).
#[test]
fn an_unreadable_family_constant_fails_the_generator() {
    let aliases = "#define CKM_A 0x00000001UL\n#define CKM_B CKM_A\n#define CK_NOT_A_FAMILY (1UL << 2)\n";
    let b = from_headers("t", aliases, "").unwrap();
    assert_eq!(b.mechanisms.keys().collect::<Vec<_>>(), ["CKM_A"]);
    let unread =
        format!("{aliases}#define CKM_SHIFTED (1UL<<31)\n#define CKA_LATER CKA_NOT_YET\n#define CKA_NOT_YET 2UL\n");
    assert_eq!(from_headers("t", &unread, "").unwrap_err(), ["CKM_SHIFTED (1UL<<31)", "CKA_LATER CKA_NOT_YET"]);
}

/// What the generator writes is what the loader reads back: the emitter that
/// `CAKEYS_UPDATE_BASELINE=1` runs is tested on every run, not only when regenerating.
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
    // The array attributes, defined as or-expressions over CKF_ARRAY_ATTRIBUTE.
    assert_eq!(b.attributes["CKA_ALLOWED_MECHANISMS"], 0x4000_0600);
    assert_eq!(b.attributes["CKA_WRAP_TEMPLATE"], 0x4000_0211);
    // The other constant families, decimal-valued ones included; aliases stay out.
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
    // Every table the generator writes is one the loader names.
    assert!(TABLES.iter().all(|t| b.table(t).is_some_and(|m| !m.is_empty())), "an empty or unknown table");
    // The classes the queries group by, and the curve vocabulary of keys.toml.
    assert!(b.class["pq"].mechanisms.iter().any(|m| m == "CKM_ML_DSA"));
    assert!(b.class["hmac"].mechanisms.iter().any(|m| m == "CKM_SHA512_HMAC"));
    assert!(b.class["key-wrap"].mechanisms.iter().any(|m| m == "CKM_AES_KEY_WRAP_KWP"));
    assert_eq!(b.class["oaep"].mechanisms, ["CKM_RSA_PKCS_OAEP"]);
    assert!(b.curves.contains("secp256r1") && b.curves.contains("edwards25519"));
}
