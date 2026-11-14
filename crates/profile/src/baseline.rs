//! The spec baseline (docs/CAPROBE.md): the universe and taxonomy of one PKCS#11 revision,
//! generated from the OASIS header files vendored under profiles/baselines/headers/.
//!
//! A baseline never claims what any vendor supports. It names the spec's members — mechanisms,
//! key types, attributes, objects, functions, parameter sets — with their numeric IDs, groups
//! them into classes for by-class queries ("which PQ mechanisms?"), and validates the names a
//! profile or a query uses. The committed TOML is generated, never edited: caprobe generates it
//! (crates/caprobe/src/emit.rs), and its pinned test regenerates it from the headers and
//! compares (D1).

use std::collections::{BTreeMap, BTreeSet};

/// The curves cakeys names (crates/core/src/id.rs's vocabulary, not spec constants: pkcs11t.h
/// carries no curve names), so curve queries validate against the same spellings as keys.toml.
/// The Montgomery curves (`CKK_EC_MONTGOMERY`, PKCS#11 3.0's `curve25519`/`curve448` names) are
/// probed and queried, not yet keys.toml objects: id.rs has no Montgomery key type.
pub const CURVES: [&str; 10] = [
    "secp256r1",
    "secp384r1",
    "secp521r1",
    "secp256k1",
    "brainpoolP256r1",
    "brainpoolP384r1",
    "edwards25519",
    "edwards448",
    "curve25519",
    "curve448",
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
    /// Parse a committed baseline file.
    ///
    /// # Errors
    ///
    /// The message carries the TOML error with its line, for the loader to prefix with the
    /// file's path.
    pub fn from_toml(text: &str) -> Result<Baseline, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }
}
