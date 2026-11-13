//! A capability profile (docs/PROVIDERS.md D2, D3): how one vendor SO version (`observed`
//! mode) or one layer between cakeys and the token (`delta` mode) deviates from what it
//! advertises. The rows committed today carry this repo's [run] evidence; the probe (phase 3)
//! regenerates them and fills the `advertise` lists.

use std::collections::BTreeMap;

/// Whether the profile is a module's observed set or a layer's subtraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// A module profile: deltas against the module's own advertisement, which the probe
    /// records in `advertise` (D2).
    Observed,
    /// A layer between cakeys and the token: open-world, it forwards everything except what
    /// it subtracts (p11-kit's RPC, the cryptoki binding, the hardware under the module).
    Delta,
}

/// D9: how a profile is matched to a module, advisory metadata until phase 2 wires detection
/// into the token open. The expressed module version and manufacturer come from `C_GetInfo`,
/// never a module digest; a module that hides its version (kryoptic reports 0.0) matches on
/// the manufacturer alone.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct MatchInfo {
    pub manufacturer: Option<String>,
    #[serde(rename = "module-version")]
    pub module_version: Option<String>,
}

/// What a profile subtracts: capabilities the module advertises but cannot use, or that a
/// layer does not carry.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Subtract {
    #[serde(default)]
    pub mechanisms: Vec<String>,
    #[serde(default, rename = "key-types")]
    pub key_types: Vec<String>,
    /// One note for the whole subtraction (each entry may still get its own under `notes`).
    #[serde(default)]
    pub note: Option<String>,
}

/// The RSA-OAEP hashes a module actually implements for wrapping (`wrap = { oaep = [...] }`):
/// `SoftHSM` lists `CKM_RSA_PKCS_OAEP` but implements `SHA-1` only.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Wrap {
    #[serde(default)]
    pub oaep: Vec<String>,
}

/// The per-module unwrap-template rules, as data (MIGRATE.md D6's provider hook): attributes
/// the module refuses in a template (`SoftHSM: CKA_VALUE_LEN`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Unwrap {
    #[serde(default)]
    pub refuse: Vec<String>,
}

/// What a module generates for one key type: the generatable items (curves for `CKK_EC` and
/// `CKK_EC_EDWARDS`, parameter sets for the PQ types) and the known-unusable ones; and the
/// inclusive RSA modulus range. What is in neither list answers unknown (D5's partial
/// profiles), never a guess.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct GenerateRow {
    #[serde(default)]
    pub can: Vec<String>,
    #[serde(default)]
    pub cannot: Vec<String>,
    #[serde(default, rename = "min-bits")]
    pub min_bits: Option<u32>,
    #[serde(default, rename = "max-bits")]
    pub max_bits: Option<u32>,
}

/// A layer's numeric restriction, intersected with every other layer's (D3): swtpm refuses
/// 4096-bit RSA generation, whatever tpm2-pkcs11's module profile says.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Restrict {
    /// What the restriction applies to; only "generate" exists today.
    pub operation: String,
    #[serde(rename = "key-type")]
    pub key_type: String,
    #[serde(default, rename = "min-bits")]
    pub min_bits: Option<u32>,
    #[serde(default, rename = "max-bits")]
    pub max_bits: Option<u32>,
    #[serde(default)]
    pub note: Option<String>,
}

/// One capability profile: `profile` names it ("family/version"), `mode` picks its semantics,
/// and the rest are its rows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// The profile's name, "family/version" (e.g. "softhsm/2.7"): what `--profile` selects.
    pub profile: String,
    pub mode: Mode,
    /// The advertisement list has not been recorded yet (the probe, phase 3): mechanism
    /// membership questions answer unknown rather than guessing.
    #[serde(default)]
    pub partial: bool,
    #[serde(default)]
    pub r#match: MatchInfo,
    /// What `C_GetMechanismList` returns; the drift baseline once the probe records it.
    #[serde(default)]
    pub advertise: Vec<String>,
    #[serde(default)]
    pub subtract: Subtract,
    /// Mechanisms usable although the module does not list them.
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub wrap: Wrap,
    /// What the module generates, per key type.
    #[serde(default)]
    pub generate: BTreeMap<String, GenerateRow>,
    #[serde(default)]
    pub unwrap: Unwrap,
    #[serde(default)]
    pub restrict: Vec<Restrict>,
    /// Freeform evidence, keyed by the name each note explains (shown in verdicts).
    #[serde(default)]
    pub notes: BTreeMap<String, String>,
}

impl Profile {
    /// Parse a profile file.
    ///
    /// # Errors
    ///
    /// The message carries the TOML error with its line, for the loader to prefix with the
    /// file's path.
    pub fn from_toml(text: &str) -> Result<Profile, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// The profile's family: `softhsm/2.7` -> `softhsm`, what a keys.toml `provider` names.
    #[must_use]
    pub fn family(&self) -> &str {
        self.profile.split('/').next().unwrap_or(&self.profile)
    }
}
