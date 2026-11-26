//! The observation model: what a run saw of a token and its objects, and which source reported
//! each fact.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Facts about the object and the run at the time of the realisation. They are never compared.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Observed {
    /// The RFC 7512 URI of the object, derived from the token label, the serial number and the
    /// locator.
    pub uri: String,
    /// Whether the run was logged in (so that private objects and duplicate private-key IDs were
    /// visible) or not.
    pub session: Session,
}

/// The session a realisation was observed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Session {
    /// Logged in as the user.
    User,
    /// No login, so only public objects were visible.
    Public,
}

/// The history of one object on this token. It never affects a verdict, and recording the same
/// object again keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    /// Where the material came from, when it was imported (docs/CAMIGRATE.md D7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
}

/// How an imported object reached this token (docs/CAMIGRATE.md D7, "Frozen names and formats").
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    /// The source token.
    pub from: String,
    /// A method name of `migrate::Method`.
    pub method: String,
    /// How exposed the material was during the move.
    pub exposure: crate::migrate::Exposure,
    /// Set for a vendor method. Then `exposure` is the level that the vendor method declared, not
    /// a level that cakeys established.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub declared: bool,
}

/// What a realisation saw of its token and of the software that handled the token (review A3).
/// The lock stores each distinct value once in its `observations` table. A difference in the
/// module build, the token, the provider, or a mechanism that is gone causes a warning. A
/// difference in the module file, the cakeys version or the profile causes a note. `lock`
/// records the current values again. The provider, module and token are absent only in entries
/// that were recorded before cakeys wrote these fields.
///
/// This is the only lock table that accepts keys that this version of cakeys does not know. Such
/// keys never change a verdict, so a lock that a newer cakeys wrote still loads. The keys are
/// kept (`extra`) when the lock is rewritten. Only recording the realisation again, which refers
/// to a new entry, drops them.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    /// The provider that handled the module. Its fix-ups must not change the identity of an
    /// object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The cakeys version that recorded the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cakeys_version: Option<String>,
    /// The module capability profile that the token resolved to (docs/CAPROBE.md D8), when a
    /// committed profile exists for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// The usable mechanisms (the Nix library builds `functions.<token>` from them). A mechanism
    /// that the token no longer offers causes a warning.
    #[serde(default)]
    pub mechanisms: Vec<String>,
    /// The PKCS#11 module (`C_GetInfo`, plus the loaded file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<ModuleInfo>,
    /// The token that holds the objects (`C_GetTokenInfo`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenInfo>,
    /// The answers that this deployment's token gave about the operations of cakeys, with the
    /// same keys as the rows of a capability profile (`prove.pop-sign.CKK_EC.secp256r1`,
    /// docs/CAPROBE.md). They are the proofs and generations that `lock` and `create` have just
    /// performed. They are answers of this token, not of its kind of token, so they take
    /// precedence over a shipped profile. They are never a verdict of `check`. They are not part
    /// of the entry's key, and new answers are merged into them, not replaced, as runs record
    /// more.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities: BTreeMap<String, Answered>,
    /// The keys of a newer cakeys, as they were read.
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// The answer in an [`Answered`] (ISSUES.md Q28): yes or no. Any other word comes from a newer
/// cakeys. It is kept as it was read and answers nothing. The value is written as the word.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(from = "String", into = "String")]
pub enum Said {
    /// `yes`.
    Yes,
    /// `no`.
    No,
    /// Another word, as it was read.
    Other(String),
}

impl From<String> for Said {
    fn from(word: String) -> Self {
        match word.as_str() {
            "yes" => Said::Yes,
            "no" => Said::No,
            _ => Said::Other(word),
        }
    }
}

impl From<&str> for Said {
    fn from(word: &str) -> Self {
        Said::from(word.to_owned())
    }
}

impl From<Said> for String {
    fn from(said: Said) -> Self {
        match said {
            Said::Yes => "yes".into(),
            Said::No => "no".into(),
            Said::Other(word) => word,
        }
    }
}

/// One answer that a token gave (in the `capabilities` of an [`Observation`]). `answer` is `yes`
/// or `no`, `evidence` is what showed the answer, and `via` is how the operation succeeded. The
/// fields of a newer cakeys are kept.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Answered {
    /// `yes` or `no`. Any other word answers nothing.
    pub answer: Said,
    /// What showed the answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// How the operation succeeded, where there is more than one way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// The fields of a newer cakeys, as they were read.
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

impl Answered {
    /// Returns a plain yes, without evidence or a way.
    #[must_use]
    pub fn yes() -> Answered {
        Answered { answer: Said::Yes, evidence: None, via: None, extra: BTreeMap::new() }
    }
}

impl Observation {
    /// Returns the entry's key: the SRI SHA-256 of its RFC 8785 (JCS) form, as for
    /// `id::spec_digest`, without its `capabilities`. The capabilities are left out so that all
    /// the answers of the token accumulate under one entry.
    ///
    /// # Panics
    ///
    /// Panics if the entry cannot be canonicalized, which only `extra` could cause (with a float
    /// that is not finite). cakeys computes keys only for the entries that it builds, and those
    /// have no `extra`.
    #[must_use]
    pub fn digest(&self) -> String {
        let bare = Observation { capabilities: BTreeMap::new(), ..self.clone() };
        let doc = serde_json::to_value(&bare).expect("an observation is plain data");
        crate::id::sri(serde_jcs::to_string(&doc).expect("an observation of strings canonicalizes").as_bytes())
    }
}

/// What the lock knows about the module and the hardware of one token
/// ([`super::Lock::token_observation`]).
#[derive(Debug)]
pub enum TokenObservation<'a> {
    /// No realisation on the token names an observation.
    None,
    /// Every realisation on the token that names an observation names this one.
    One(&'a Observation),
    /// The realisations on the token were recorded with different observations, so it is not
    /// known which observation is current. The value holds the specs, grouped by the entry that
    /// they name.
    Several(Vec<Vec<String>>),
}

impl TokenObservation<'_> {
    /// Returns the message for [`TokenObservation::Several`]: what differs, and how to record the
    /// current observation.
    #[must_use]
    pub fn several(token: &str, groups: &[Vec<String>]) -> String {
        let groups: Vec<String> = groups.iter().map(|g| g.join(", ")).collect();
        format!(
            "the realisations on token '{token}' were recorded with {} different observations of \
             its module and token ({}); `lock` them to record the current one",
            groups.len(),
            groups.join("; ")
        )
    }
}

/// The module that realised an object (`C_GetInfo` plus the loaded file). It is provenance only.
/// On verify, a different build identity causes a warning, and so does a different `hash` at the
/// same `path` (the file was replaced in place, which a path outside the Nix store does not
/// show). A different `path` alone (a Nix rebuild) causes a note. The CA-IDs enforce the identity
/// of the object itself.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleInfo {
    /// The file that the dynamic loader mapped, with symlinks resolved, whatever named it in
    /// keys.toml or with `--module` (a file name without a directory, a profile symlink, or
    /// `$NAME`).
    pub path: String,
    /// The SRI SHA-256 of that file. It is absent when the file could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// `CK_INFO.libraryDescription`.
    pub description: String,
    /// `CK_INFO.manufacturerID`.
    pub manufacturer: String,
    /// `CK_INFO.libraryVersion`.
    pub version: String,
    /// `CK_INFO.cryptokiVersion`: the PKCS#11 version that the module implements.
    pub cryptoki: String,
}

impl ModuleInfo {
    /// Returns whether the two modules are equal in every field except the file (`path` and
    /// `hash`).
    #[must_use]
    pub fn same_build_identity(&self, other: &Self) -> bool {
        (&self.description, &self.manufacturer, &self.version, &self.cryptoki)
            == (&other.description, &other.manufacturer, &other.version, &other.cryptoki)
    }
}

/// The token on which a realisation was made (`C_GetTokenInfo`). It is provenance, like
/// [`ModuleInfo`], and a different token causes a warning.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenInfo {
    /// `CK_TOKEN_INFO.model`.
    pub model: String,
    /// `CK_TOKEN_INFO.serialNumber`.
    pub serial: String,
    /// `CK_TOKEN_INFO.firmwareVersion`.
    pub firmware: String,
}
