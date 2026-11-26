//! The spec baseline (docs/CAPROBE.md) lists every member of one PKCS#11 revision and sorts the
//! members into classes. It is generated from the OASIS header files that are vendored under
//! profiles/baselines/headers/.
//!
//! A baseline never claims what any vendor supports. It names the members of the spec with
//! their numeric IDs: mechanisms, key types, attributes, objects, functions, parameter sets, and
//! the other constant families (return values, flags, user types, certificate types and more).
//! It groups the members into classes for queries by class ("which PQ mechanisms?"), and it
//! validates the names that a profile or a query uses. The committed TOML is generated and is
//! never edited by hand. caprobe generates it (crates/caprobe/src/emit.rs), and caprobe's pinned
//! test regenerates it from the headers and compares the result with the committed file (D1).

use std::collections::{BTreeMap, BTreeSet};

/// The curves that cakeys names (`cakeys_names::Curve`). These names are not spec constants,
/// because pkcs11t.h holds no curve names. Curve queries therefore validate against the same
/// spellings as keys.toml. The Montgomery curves (`CKK_EC_MONTGOMERY`, with the PKCS#11 3.0 names
/// `curve25519` and `curve448`) are probed and queried, but they cannot yet be keys.toml objects,
/// because core has no Montgomery key type.
pub const CURVES: [&str; 10] = cakeys_names::Curve::NAMES;

/// One member group of a baseline class.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassMembers {
    /// The member mechanisms, by `CKM_*` name.
    #[serde(default)]
    pub mechanisms: Vec<String>,
    /// The member parameter sets (PQ key types).
    #[serde(default, rename = "parameter-sets")]
    pub parameter_sets: Vec<String>,
}

/// One spec revision's members, keyed by name.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
    // The constant families below default to empty, so a test baseline that is written by hand
    // needs to name only what it uses. caprobe's pinned test requires each of them in the
    // committed file.
    /// Return values (`CKR_*`).
    #[serde(default, rename = "return-values")]
    pub return_values: BTreeMap<String, u64>,
    /// Flags (`CKF_*`). The token, slot, session, mechanism and other flag words all use this
    /// prefix.
    #[serde(default)]
    pub flags: BTreeMap<String, u64>,
    /// User types (`CKU_*`).
    #[serde(default, rename = "user-types")]
    pub user_types: BTreeMap<String, u64>,
    /// Session states (`CKS_*`).
    #[serde(default, rename = "session-states")]
    pub session_states: BTreeMap<String, u64>,
    /// Certificate types (`CKC_*`).
    #[serde(default, rename = "certificate-types")]
    pub certificate_types: BTreeMap<String, u64>,
    /// Hardware feature types (`CKH_*`).
    #[serde(default, rename = "hardware-features")]
    pub hardware_features: BTreeMap<String, u64>,
    /// Mask generation functions and IV generators (`CKG_*`, one prefix for both).
    #[serde(default)]
    pub generators: BTreeMap<String, u64>,
    /// Key derivation functions (`CKD_*`).
    #[serde(default)]
    pub kdfs: BTreeMap<String, u64>,
    /// Parameter sources (`CKZ_*`: the OAEP encoding parameter, the PBKDF2 salt).
    #[serde(default)]
    pub sources: BTreeMap<String, u64>,
    /// Notifications (`CKN_*`).
    #[serde(default)]
    pub notifications: BTreeMap<String, u64>,
    /// Trust values (`CKT_*`, for the 3.2 `CKA_TRUST_*` attributes).
    #[serde(default, rename = "trust-values")]
    pub trust_values: BTreeMap<String, u64>,
    /// Validation and validation-authority types (`CKV_*`).
    #[serde(default, rename = "validation-types")]
    pub validation_types: BTreeMap<String, u64>,
    /// The curves cakeys names ([`CURVES`]).
    pub curves: BTreeSet<String>,
    /// Member groups, chosen by hand, for queries by class: pq, hmac, key-wrap and oaep.
    pub class: BTreeMap<String, ClassMembers>,
}

/// The baseline's name-to-ID tables, by their TOML names, in the order the generator writes them.
pub const TABLES: [&str; 18] = [
    "mechanisms",
    "key-types",
    "attributes",
    "objects",
    "parameter-sets",
    "conformance-profiles",
    "return-values",
    "flags",
    "user-types",
    "session-states",
    "certificate-types",
    "hardware-features",
    "generators",
    "kdfs",
    "sources",
    "notifications",
    "trust-values",
    "validation-types",
];

macro_rules! tables {
    ($self:ident, $name:ident, $($ref:tt)+) => {
        match $name {
            "mechanisms" => Some($($ref)+ $self.mechanisms),
            "key-types" => Some($($ref)+ $self.key_types),
            "attributes" => Some($($ref)+ $self.attributes),
            "objects" => Some($($ref)+ $self.objects),
            "parameter-sets" => Some($($ref)+ $self.parameter_sets),
            "conformance-profiles" => Some($($ref)+ $self.conformance_profiles),
            "return-values" => Some($($ref)+ $self.return_values),
            "flags" => Some($($ref)+ $self.flags),
            "user-types" => Some($($ref)+ $self.user_types),
            "session-states" => Some($($ref)+ $self.session_states),
            "certificate-types" => Some($($ref)+ $self.certificate_types),
            "hardware-features" => Some($($ref)+ $self.hardware_features),
            "generators" => Some($($ref)+ $self.generators),
            "kdfs" => Some($($ref)+ $self.kdfs),
            "sources" => Some($($ref)+ $self.sources),
            "notifications" => Some($($ref)+ $self.notifications),
            "trust-values" => Some($($ref)+ $self.trust_values),
            "validation-types" => Some($($ref)+ $self.validation_types),
            _ => None,
        }
    };
}

impl Baseline {
    /// The name-to-ID table called `name` in the TOML (one of [`TABLES`]).
    #[must_use]
    pub fn table(&self, name: &str) -> Option<&BTreeMap<String, u64>> {
        tables!(self, name, &)
    }

    /// Returns the same table as [`Baseline::table`], but mutable, so that the generator can
    /// fill it.
    pub fn table_mut(&mut self, name: &str) -> Option<&mut BTreeMap<String, u64>> {
        tables!(self, name, &mut)
    }

    /// Parse a committed baseline file.
    ///
    /// # Errors
    ///
    /// Returns the TOML error, with its line, as a message. The loader prefixes the message with
    /// the file's path.
    pub fn from_toml(text: &str) -> Result<Baseline, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A misspelled key, at the top level or in a class, is refused instead of being read as an
    /// empty list (review baseline.rs F1), as in every profile section. The committed baseline
    /// loads.
    #[test]
    fn a_misspelt_baseline_key_is_refused() {
        let committed = crate::embedded::BASELINE_FILES[0].1;
        Baseline::from_toml(committed).unwrap();
        let class = committed.replacen("parameter-sets = [", "parameter_sets = [", 1);
        assert_ne!(class, committed, "the committed baseline has a class with parameter sets");
        let top = format!("key_types = {{}}\n{committed}");
        for text in [class, top] {
            let e = Baseline::from_toml(&text).unwrap_err();
            assert!(e.contains("unknown field"), "{e}");
        }
    }
}
