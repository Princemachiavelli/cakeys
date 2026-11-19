//! The observation model: what a run saw of a token and its objects, and who said it.

use super::{ModuleInfo, TokenInfo};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Facts about the object and the run at realisation time. Never compared.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Observed {
    /// RFC 7512 URI of the object (derived from the token label, serial and locator).
    pub uri: String,
    /// Logged in (private objects and duplicate private-key IDs were visible) or not.
    pub session: Session,
}

/// The session a realisation was observed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Session {
    /// Logged in as the user.
    User,
    /// No login: public objects only.
    Public,
}

/// One object's history on this token. Never a verdict; re-recording the same object keeps it.
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
    /// How exposed the material was on the way.
    pub exposure: crate::migrate::Exposure,
    /// A vendor method: `exposure` is the level it declared, not one cakeys established.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub declared: bool,
}

/// What a realisation saw of its token and what handled it (review A3), stored once per
/// distinct value in the lock's `observations`. Differences warn (module build, token,
/// provider, a mechanism gone) or note (module file, cakeys version, profile); `lock`
/// re-binds them. The provider, module and token are absent only in entries recorded before
/// cakeys wrote them.
///
/// The one lock table that takes keys this cakeys does not know: they never change a verdict,
/// so a lock a newer cakeys wrote still loads, and they are kept (`extra`) when the lock is
/// rewritten — only re-recording the realisation, which names a fresh entry, drops them.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    /// Provider that handled the module (fix-ups must not change identity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The cakeys version that recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cakeys_version: Option<String>,
    /// The module capability profile the token resolved to (docs/CAPROBE.md D8), when one is
    /// committed for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Usable mechanisms (feeds `functions.<token>` in the Nix library). One that has since gone
    /// from the token is a warning.
    #[serde(default)]
    pub mechanisms: Vec<String>,
    /// PKCS#11 module (`C_GetInfo`, plus the loaded file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<ModuleInfo>,
    /// Token that holds the objects (`C_GetTokenInfo`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<TokenInfo>,
    /// What this deployment's token answered about cakeys' operations, keyed as a capability
    /// profile's rows are (`prove.pop-sign.CKK_EC.secp256r1`, docs/CAPROBE.md): the proofs and
    /// generations `lock` and `create` just demonstrated, and what `caprobe probe --record`
    /// measured. Answers of this token, not of its kind, so they decide before a shipped
    /// profile does; never a verdict of `check`. Not part of the entry's key, and merged, not
    /// replaced, as runs record more.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities: BTreeMap<String, Answered>,
    /// Keys of a newer cakeys, as read.
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

/// What an [`Answered`] says (ISSUES.md Q28): yes or no; any other word, a newer cakeys's, is
/// kept as read and answers nothing. Written as the word.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(from = "String", into = "String")]
pub enum Said {
    /// `yes`.
    Yes,
    /// `no`.
    No,
    /// Another word, as read.
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

/// One answer a token gave (an [`Observation`]'s `capabilities`): `answer` is `yes` or `no`,
/// `evidence` what showed it, `via` how it succeeded. A newer cakeys' fields are kept.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Answered {
    /// `yes` or `no`; anything else answers nothing.
    pub answer: Said,
    /// What showed it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// How it succeeded, where there is more than one way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// Fields of a newer cakeys, as read.
    #[serde(flatten)]
    pub extra: BTreeMap<String, toml::Value>,
}

impl Answered {
    /// A plain yes.
    #[must_use]
    pub fn yes() -> Answered {
        Answered { answer: Said::Yes, evidence: None, via: None, extra: BTreeMap::new() }
    }
}

impl Observation {
    /// The entry's key: the SRI SHA-256 of its RFC 8785 (JCS) form, as `id::spec_digest`,
    /// without its `capabilities` — what the token answered accumulates under one entry.
    ///
    /// # Panics
    ///
    /// If the entry does not canonicalize, which only `extra` could cause (a float that is not
    /// finite); cakeys computes keys only for the entries it builds, which have none.
    #[must_use]
    pub fn digest(&self) -> String {
        let bare = Observation { capabilities: BTreeMap::new(), ..self.clone() };
        let doc = serde_json::to_value(&bare).expect("an observation is plain data");
        crate::id::sri(serde_jcs::to_string(&doc).expect("an observation of strings canonicalizes").as_bytes())
    }
}

/// What the lock knows of one token's module and hardware ([`super::Lock::token_observation`]).
#[derive(Debug)]
pub enum TokenObservation<'a> {
    /// No realisation on the token names an observation.
    None,
    /// Every realisation on the token that names one names this.
    One(&'a Observation),
    /// Its realisations were recorded with different observations, so which is current is not
    /// known: the specs, grouped by the entry they name.
    Several(Vec<Vec<String>>),
}

impl TokenObservation<'_> {
    /// The message for [`TokenObservation::Several`]: what differs and how to refresh it.
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
