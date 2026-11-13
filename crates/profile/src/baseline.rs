//! The spec baseline (docs/PROVIDERS.md): the universe and taxonomy of one PKCS#11 revision,
//! generated from the OASIS header files vendored under profiles/baselines/headers/.
//!
//! A baseline never claims what any vendor supports. It names the spec's members — mechanisms,
//! key types, attributes, objects, functions, parameter sets — with their numeric IDs, groups
//! them into classes for by-class queries ("which PQ mechanisms?"), and validates the names a
//! profile or a query uses. The committed TOML is generated, never edited: the pinned test
//! regenerates it from the headers and compares (D1).

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

/// The curves cakeys names (crates/core/src/id.rs's vocabulary, not spec constants: pkcs11t.h
/// carries no curve names), so curve queries validate against the same spellings as keys.toml.
pub const CURVES: [&str; 8] = [
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "secp256k1",
    "brainpoolP256r1",
    "brainpoolP384r1",
    "edwards25519",
    "edwards448",
];

/// One member group of a baseline class.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct ClassMembers {
    #[serde(default)]
    pub mechanisms: Vec<String>,
    #[serde(default, rename = "parameter-sets")]
    pub parameter_sets: Vec<String>,
}

/// One spec revision's members, keyed by name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Baseline {
    /// The baseline's name, as profiles and queries cite it (e.g. "pkcs11-3.2").
    pub baseline: String,
    /// Mechanism types (`CKM_*`) and their IDs.
    pub mechanisms: BTreeMap<String, u64>,
    /// Key types (`CKK_*`) and their IDs.
    #[serde(rename = "key-types")]
    pub key_types: BTreeMap<String, u64>,
    /// Attribute types (`CKA_*`) and their IDs.
    pub attributes: BTreeMap<String, u64>,
    /// Object classes (`CKO_*`) and their IDs.
    pub objects: BTreeMap<String, u64>,
    /// Cryptoki functions (`C_*`).
    pub functions: BTreeSet<String>,
    /// Parameter sets (`CKP_*`, the PQ sets and the PBKDF2 functions) and their IDs.
    #[serde(rename = "parameter-sets")]
    pub parameter_sets: BTreeMap<String, u64>,
    /// Conformance profiles (`CKP_*`, the Profiles standard) and their IDs.
    #[serde(rename = "conformance-profiles")]
    pub conformance_profiles: BTreeMap<String, u64>,
    /// The curves cakeys names ([`CURVES`]).
    pub curves: BTreeSet<String>,
    /// Curated member groups for by-class queries: pq, hmac, key-wrap, oaep.
    pub class: BTreeMap<String, ClassMembers>,
}

impl Baseline {
    /// Generate the baseline from the OASIS header files: `types` is pkcs11t.h, `functions`
    /// pkcs11f.h. Only `#define <PREFIX>_... 0x...` constants are taken: aliases
    /// (`#define CKM_SHA3_256_KEY_DERIVE CKM_SHA3_256_KEY_DERIVATION`) and the
    /// `*_VENDOR_DEFINED` range constants are skipped, so every name maps to its own ID.
    #[must_use]
    pub fn from_headers(name: &str, types: &str, functions: &str) -> Baseline {
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
        b.class = b.curated_classes();
        b
    }

    /// The curated classes ([`Baseline::from_headers`]'s taxonomy): what `--class` can list.
    fn curated_classes(&self) -> BTreeMap<String, ClassMembers> {
        let mut classes = BTreeMap::new();
        let pq =
            |n: &str| n.starts_with("CKM_ML_") || n.starts_with("CKM_SLH_") || n.contains("XMSS") || n.contains("HSS");
        classes.insert(
            "pq".into(),
            ClassMembers {
                mechanisms: self.mechanisms.keys().filter(|n| pq(n)).cloned().collect(),
                parameter_sets: self
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
                mechanisms: self.mechanisms.keys().filter(|n| n.contains("_HMAC")).cloned().collect(),
                parameter_sets: vec![],
            },
        );
        classes.insert(
            "key-wrap".into(),
            ClassMembers {
                mechanisms: self.mechanisms.keys().filter(|n| n.contains("KEY_WRAP")).cloned().collect(),
                parameter_sets: vec![],
            },
        );
        classes.insert(
            "oaep".into(),
            ClassMembers { mechanisms: vec!["CKM_RSA_PKCS_OAEP".into()], parameter_sets: vec![] },
        );
        classes
    }

    /// Parse a committed baseline file.
    ///
    /// # Errors
    ///
    /// The message carries the TOML error with its line, for the loader to prefix with the
    /// file's path.
    pub fn from_toml(text: &str) -> Result<Baseline, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// Emit the baseline as TOML, the deterministic form the pinned test regenerates and the
    /// committed file (`profiles/baselines/pkcs11-3.2.toml`) mirrors.
    #[must_use]
    pub fn to_toml(&self) -> String {
        let mut s = String::new();
        let head = |s: &mut String, table: &str| {
            if !s.is_empty() {
                s.push('\n');
            }
            let _ = writeln!(s, "[{table}]");
        };
        let _ = writeln!(
            s,
            "# Generated by cakeys-profile (crates/profile) from the OASIS PKCS #11 v3.2 headers\n\
             # vendored in profiles/baselines/headers/pkcs11-3.2/. Never edit by hand: regenerate\n\
             # with CAKEYS_UPDATE_BASELINE=1 cargo test -p cakeys-profile — the pinned test\n\
             # regenerates and compares on every run."
        );
        let _ = writeln!(s, "baseline = \"{}\"", self.baseline);
        // Top-level keys precede every table (TOML has no table close).
        let _ = writeln!(s, "functions = [{}]", quoted(&self.functions));
        let _ = writeln!(s, "curves = [{}]", quoted(&self.curves));
        head(&mut s, "mechanisms");
        for (n, id) in &self.mechanisms {
            let _ = writeln!(s, "{n} = {id:#010x}");
        }
        head(&mut s, "key-types");
        for (n, id) in &self.key_types {
            let _ = writeln!(s, "{n} = {id:#010x}");
        }
        head(&mut s, "attributes");
        for (n, id) in &self.attributes {
            let _ = writeln!(s, "{n} = {id:#010x}");
        }
        head(&mut s, "objects");
        for (n, id) in &self.objects {
            let _ = writeln!(s, "{n} = {id:#010x}");
        }
        head(&mut s, "parameter-sets");
        for (n, id) in &self.parameter_sets {
            let _ = writeln!(s, "{n} = {id:#010x}");
        }
        head(&mut s, "conformance-profiles");
        for (n, id) in &self.conformance_profiles {
            let _ = writeln!(s, "{n} = {id:#010x}");
        }
        for (class, members) in &self.class {
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
}

/// TOML array body: `\"a\", \"b\"` for the emitted arrays.
fn quoted<'a, I>(names: I) -> String
where
    I: IntoIterator,
    I::Item: AsRef<str> + 'a,
{
    names.into_iter().map(|n| format!("\"{}\"", n.as_ref())).collect::<Vec<_>>().join(", ")
}
