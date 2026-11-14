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

/// D9/D10: how a profile is matched to a token. A profile is observed on one module *and*
/// the hardware under it (`tpm2-pkcs11/1.10+swtpm`): the module's manufacturer and expressed
/// version come from `C_GetInfo` (never a module digest), the token's model and firmware from
/// `C_GetTokenInfo`. A module that hides its version (kryoptic reports 0.0) records no
/// `module-version`; its firmware is then the version evidence. Resolution prefers the profile
/// matching the most keys and flags anything short of all of them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct MatchInfo {
    pub manufacturer: Option<String>,
    #[serde(rename = "module-version")]
    pub module_version: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
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
/// `SoftHSM` lists `CKM_RSA_PKCS_OAEP` but implements `SHA-1` only. Absent: never probed, a
/// spec-compliant module is assumed; `[]`: probed, and no hash round-trips.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Wrap {
    #[serde(default)]
    pub oaep: Option<Vec<String>>,
}

/// What decryption a module actually implements with its private keys (`decrypt = { oaep =
/// [...] }`): the RSA-OAEP hashes (MGF1 of the same hash) that decrypt what the host encrypted
/// to the key, which `pop-decrypt` needs. Absent: never probed; `[]`: probed, none decrypts.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Decrypt {
    #[serde(default)]
    pub oaep: Option<Vec<String>>,
}

/// How a module derives with `CKM_ECDH1_DERIVE` (`derive = { sealed = ... }`): whether it
/// derives into a sealed secret (`CKA_SENSITIVE`, not `CKA_EXTRACTABLE`), which `pop-ecdh`
/// MACs with when it can. ykcs11 derives only into an extractable secret [src]. And what
/// `CKA_DERIVE` the base key reports although it derived (`key-attribute`): ykcs11 reports
/// false on every key, from a fixed table [src], so a spec asking `CKA_DERIVE = true` of it can
/// never be met while ECDH works. And whether it derives in a read-only session (`read-only`):
/// tpm2-pkcs11 keeps derived secrets as store rows, so it refuses there [run]. Absent: never
/// probed.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Derive {
    #[serde(default)]
    pub sealed: Option<bool>,
    #[serde(default, rename = "key-attribute")]
    pub key_attribute: Option<bool>,
    #[serde(default, rename = "read-only")]
    pub read_only: Option<bool>,
}

/// A finding a person made rather than the probe (`[manual.<key>]`): a fact the probe cannot
/// observe, or one it does not reach yet. Kept apart from the probe's rows so a reader always
/// knows which is which: the probe preserves the section across regenerations like
/// `[migration]`, and the diff never compares it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manual {
    /// What was found.
    pub finding: String,
    /// How: the command or source that shows it, with its date and an evidence tag (`[run]`,
    /// `[src]`, `[spec]`).
    pub evidence: String,
}

/// The per-module unwrap-template rules, as data (MIGRATE.md D6's provider hook): attributes
/// the module refuses in a template (`SoftHSM: CKA_VALUE_LEN`). Absent: never probed; `[]`:
/// probed, and the module refuses none.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Unwrap {
    #[serde(default)]
    pub refuse: Option<Vec<String>>,
}

/// What a module generates for one key type: the generatable items (curves for `CKK_EC` and
/// `CKK_EC_EDWARDS`, parameter sets for the PQ types) and the known-unusable ones; and for
/// RSA the modulus sizes. `min-bits`/`max-bits` are the inclusive range the module reports
/// (`C_GetMechanismInfo`, or a hand claim); `can-bits`/`cannot-bits` the sizes a probe
/// generated or saw refused. What none of them decides answers unknown (D5), never a guess.
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
    #[serde(default, rename = "can-bits")]
    pub can_bits: Vec<u32>,
    #[serde(default, rename = "cannot-bits")]
    pub cannot_bits: Vec<u32>,
    /// Curves in `can` that generate only when `CKA_EC_PARAMS` names them (PKCS#11 3.0's
    /// `PrintableString` form), never by OID: ykcs11's Edwards and Montgomery curves [src].
    #[serde(default, rename = "by-name")]
    pub by_name: Vec<String>,
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

/// How plaintext material gets into a token (the `host` paths), as data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlaintextKind {
    /// `C_CreateObject` with the key's attributes (any module that accepts it).
    CreateObject,
    /// `tpm2_ptool import`.
    Tpm2Ptool,
    /// ykcs11's `C_CreateObject` as SO into a PIV slot.
    PivImport,
}

/// One row of what a module's import paths take: a class, and optionally only some key types,
/// curves, or an inclusive RSA modulus range (empty: any).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct AcceptRow {
    pub class: String,
    #[serde(default, rename = "key-types")]
    pub key_types: Vec<String>,
    #[serde(default)]
    pub curves: Vec<String>,
    #[serde(default, rename = "min-bits")]
    pub min_bits: Option<u32>,
    #[serde(default, rename = "max-bits")]
    pub max_bits: Option<u32>,
}

/// How a module moves keys (MIGRATE.md D2/D10), as data. Absent fields mean a spec-compliant
/// PKCS#11 module: it wraps and unwraps with what it lists and imports public objects and
/// plaintext keys with `C_CreateObject`. The OAEP hashes come from `wrap.oaep`, the one row
/// the `--oaep` query shares.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Migration {
    /// Whether the module ever wraps a key out (`C_WrapKey`): ykcs11 and tpm2-pkcs11 never.
    #[serde(default)]
    pub exports: Option<bool>,
    /// Whether the module unwraps a key in (`C_UnwrapKey`).
    #[serde(default)]
    pub unwraps: Option<bool>,
    /// Whether a secret key it unwraps reports its length (`CKA_VALUE_LEN`), which the import's
    /// type check reads: `SoftHSM` leaves it 0 and refuses it in the template (default: yes).
    #[serde(default, rename = "secret-unwraps")]
    pub secret_unwraps: Option<bool>,
    /// How plaintext private and secret keys get in, if at all.
    #[serde(default, rename = "plaintext-import")]
    pub plaintext_import: Option<PlaintextKind>,
    /// What the plaintext import takes.
    #[serde(default, rename = "plaintext-accepts", alias = "plaintext_accepts")]
    pub plaintext_accepts: Vec<AcceptRow>,
    /// Public objects `C_CreateObject` takes; the spec-compliant classes when empty.
    #[serde(default, rename = "public-accepts")]
    pub public_accepts: Vec<AcceptRow>,
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
    /// A passthrough (p11-kit) that hides the module behind it: no claim of that module applies
    /// until keys.toml names its `provider`, so a plan through it warns. `notes."requires-provider"`
    /// says what the passthrough does carry.
    #[serde(default, rename = "requires-provider")]
    pub requires_provider: bool,
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
    pub decrypt: Decrypt,
    #[serde(default)]
    pub derive: Derive,
    /// How the module moves keys (MIGRATE.md), when it deviates from a spec-compliant module.
    #[serde(default)]
    pub migration: Option<Migration>,
    #[serde(default)]
    pub restrict: Vec<Restrict>,
    /// Freeform evidence, keyed by the name each note explains (shown in verdicts).
    #[serde(default)]
    pub notes: BTreeMap<String, String>,
    /// What people found by hand ([`Manual`]): never probe output.
    #[serde(default)]
    pub manual: BTreeMap<String, Manual>,
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
