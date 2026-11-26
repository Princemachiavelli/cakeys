//! A capability profile (docs/CAPROBE.md D2, D3) records how one vendor SO version (`observed`
//! mode) or one layer between cakeys and the token (`delta` mode) differs from what it
//! advertises. The rows that are committed today hold this repository's \[run\] evidence. The
//! probe (phase 3) regenerates them and fills the `advertise` lists.

use crate::capability::{Answer, By, Capability, DECRYPT_OAEP, Move, On, Row, Rows, UNWRAP_TEMPLATE, WRAP_OAEP};
use crate::names::KeyKind;
use std::collections::BTreeMap;

/// Whether the profile is a module's observed set or a layer's subtraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// A module profile. It holds deltas against the module's own advertised list, which the
    /// probe records in `advertise` (D2).
    Observed,
    /// A layer between cakeys and the token (p11-kit's RPC, the cryptoki binding, or the
    /// hardware under the module). A layer forwards everything except what it subtracts.
    Delta,
}

/// How a profile is matched to a token (D9, D10). A profile is observed on one module *and* the
/// hardware under it (`tpm2-pkcs11/1.10+swtpm`). The module's manufacturer and the version that
/// it reports come from `C_GetInfo` (never from a digest of the module file). The token's model
/// and firmware come from `C_GetTokenInfo`. A module that hides its version (kryoptic reports
/// 0.0) records no `module-version`, and its firmware is then the evidence of its version.
/// Resolution prefers the profile that matches the most keys, and it reports a warning for any
/// match that does not match all of them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatchInfo {
    /// The module's manufacturer, as `C_GetInfo` reports it.
    pub manufacturer: Option<String>,
    /// The module's version, as `C_GetInfo` reports it (`module-version`).
    #[serde(rename = "module-version")]
    pub module_version: Option<String>,
    /// The token's model, as `C_GetTokenInfo` reports it.
    pub model: Option<String>,
    /// The token's firmware version, as `C_GetTokenInfo` reports it.
    pub firmware: Option<String>,
}

/// What a profile subtracts: capabilities that the module advertises but cannot use, or that a
/// layer does not forward.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subtract {
    /// Mechanisms, by `CKM_*` name.
    #[serde(default)]
    pub mechanisms: Vec<String>,
    /// Key types, by `CKK_*` name (`key-types`).
    #[serde(default, rename = "key-types")]
    pub key_types: Vec<String>,
    /// One note for the whole subtraction. Each entry may still have its own note under `notes`.
    #[serde(default)]
    pub note: Option<String>,
}

/// A finding that a person made, not the probe (`[manual.<key>]`): a fact that the probe cannot
/// observe, or one that it does not test yet. These findings are kept apart from the probe's
/// rows, so that a reader always knows which is which. The probe keeps the section unchanged
/// when it regenerates the profile, as it does with `[migration]`, and the diff never compares
/// it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manual {
    /// What was found.
    pub finding: String,
    /// How it was found: the command or source that shows it, with its date and an evidence tag
    /// (`\[run\]`, `\[src\]`, `[spec]`).
    pub evidence: String,
}

/// Why an advertised mechanism has no measured row (`[untested]`, `docs/archive/CAPROBE_PROFILE_COVERAGE.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Why {
    /// The binding has no constant or parameter type for the mechanism, and the probe cannot
    /// build the call by hand. The cryptoki layer profile has the same note.
    Cryptoki,
    /// A mechanism ID that the baseline does not name. Its parameters are unknown, so the probe
    /// cannot make a meaningful call.
    Vendor,
    /// A test needs state or carries a risk that the probe's rules forbid (a scratch slot, or the
    /// real TPM).
    Hardware,
    /// A test needs a service that was not run for this profile.
    Cloud,
    /// The mechanism was decided to be out of scope, because the tools never use it
    /// (`spec-coverage/manual.toml`).
    Scope,
    /// No probe tries it yet.
    Unprobed,
    /// The probe tried it, and the module returned `CKR_OK`, but nothing outside the module could
    /// check the result (for example, a signature for which the host has no verifier). Such an
    /// entry is never yes (review 2026-11-24 E-4).
    Unverified,
    /// A capability (the entry's key has the form of a row's key) on which the module failed
    /// with a device failure ([`crate::DEVICE_FAILED_RV`]). That is not a real answer from the
    /// module, so the capability is unknown, and an unknown capability causes a refusal.
    Device,
    /// A capability that cakeys or its provider refused before the module was asked (because the
    /// host has no verifier, or because the provider refuses the template). This is not a real
    /// answer from the module either.
    Cakeys,
}

impl Why {
    /// The word that the `[untested]` table holds.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Why::Cryptoki => "cryptoki",
            Why::Vendor => "vendor",
            Why::Hardware => "hardware",
            Why::Cloud => "cloud",
            Why::Scope => "scope",
            Why::Unprobed => "unprobed",
            Why::Unverified => "unverified",
            Why::Device => "device",
            Why::Cakeys => "cakeys",
        }
    }

    /// Returns whether the entry is for a capability that the probe could not decide. The key of
    /// such an entry has the form of a row's key.
    #[must_use]
    pub fn undecided(self) -> bool {
        matches!(self, Why::Device | Why::Cakeys)
    }
}

/// One advertised mechanism that the probe did not try (`[untested]`). The probe writes these
/// entries and regenerates them with the profile. They are never claims.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Untested {
    /// Why it was not tried.
    pub why: Why,
    /// The reason, in words.
    #[serde(default)]
    pub note: Option<String>,
}

/// What `C_GetMechanismInfo` reports for one mechanism (`[mechanism-info."CKM_X"]`). This is a
/// claim that the probe records and checks against what it measured. It is never evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MechanismInfo {
    /// The smallest key size that the module reports (in bits or bytes, as the module counts).
    pub min: u64,
    /// The largest key size that the module reports.
    pub max: u64,
    /// The operations that the module flags for the mechanism.
    #[serde(default)]
    pub flags: Vec<String>,
}

/// The key sizes that a module reports for one key type (`[reported."CKK_RSA"]`): the inclusive
/// range that `C_GetMechanismInfo` gives, or a claim written by hand. What the module actually
/// did with a size is recorded in a [`Capability::Generate`] row.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reported {
    /// The smallest modulus that the module reports, in bits (`min-bits`).
    #[serde(default, rename = "min-bits")]
    pub min_bits: Option<u32>,
    /// The largest modulus that the module reports, in bits (`max-bits`).
    #[serde(default, rename = "max-bits")]
    pub max_bits: Option<u32>,
}

/// What a module generates for one key type, according to its rows ([`Profile::generation`]).
/// It holds the curves (or parameter sets) that generated and those that did not, the modulus
/// sizes that generated and those that did not, the curves that generate only by name, and the
/// range that the module reports. A question that none of these decides answers unknown (D5),
/// and never a guess.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenerateRow {
    /// The curves or parameter sets that the module generates.
    pub can: Vec<String>,
    /// The curves or parameter sets that the module does not generate, although it may list
    /// them.
    pub cannot: Vec<String>,
    /// The smallest RSA modulus that the module reports, in bits.
    pub min_bits: Option<u32>,
    /// The largest RSA modulus that the module reports, in bits.
    pub max_bits: Option<u32>,
    /// RSA modulus sizes that generated.
    pub can_bits: Vec<u32>,
    /// RSA modulus sizes that the module refused.
    pub cannot_bits: Vec<u32>,
    /// Secret-key lengths that generated, in bytes. `CKA_VALUE_LEN` gives the length of a key
    /// type with a length in bytes, never in the bits of an RSA modulus.
    pub can_bytes: Vec<u32>,
    /// Secret-key lengths that the module refused, in bytes.
    pub cannot_bytes: Vec<u32>,
    /// The curves in `can` that generate only when `CKA_EC_PARAMS` names them (the
    /// `PrintableString` form of PKCS#11 3.0), and never by OID. ykcs11's Edwards and Montgomery
    /// curves behave this way \[src\].
    pub by_name: Vec<String>,
}

/// A layer's numeric restriction, which applies together with every other layer's restriction
/// (D3). For example, swtpm refuses 4096-bit RSA generation, whatever tpm2-pkcs11's module
/// profile says.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restrict {
    /// The operation to which the restriction applies. Only "generate" exists today, and an
    /// operation from a newer cakeys restricts nothing here. The field is a plain string, because
    /// one value needs no enum (review 2026-11-23 A-13).
    pub operation: String,
    /// The key type it restricts (`key-type`).
    #[serde(rename = "key-type")]
    pub key_type: KeyKind,
    /// The smallest size allowed, in bits (`min-bits`).
    #[serde(default, rename = "min-bits")]
    pub min_bits: Option<u32>,
    /// The largest size allowed, in bits (`max-bits`).
    #[serde(default, rename = "max-bits")]
    pub max_bits: Option<u32>,
    /// The reason for the restriction, which verdicts show.
    #[serde(default)]
    pub note: Option<String>,
}

/// The way in which plaintext key material is imported into a token (the `host` paths), as
/// data.
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

impl PlaintextKind {
    /// The name that a profile writes in `plaintext-import` and in an `import.*` row's `via`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            PlaintextKind::CreateObject => "create-object",
            PlaintextKind::Tpm2Ptool => "tpm2-ptool",
            PlaintextKind::PivImport => "piv-import",
        }
    }
}

/// One row of what a module's import paths accept: a class, and optionally a limit to some key
/// types, some curves, or an inclusive RSA modulus range. An empty limit accepts any value.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptRow {
    /// The object class, by `CKO_*` name.
    pub class: String,
    /// The key types, by `CKK_*` name (`key-types`). An empty list accepts any key type.
    #[serde(default, rename = "key-types")]
    pub key_types: Vec<String>,
    /// The curves, by name. An empty list accepts any curve.
    #[serde(default)]
    pub curves: Vec<String>,
    /// The smallest RSA modulus, in bits (`min-bits`).
    #[serde(default, rename = "min-bits")]
    pub min_bits: Option<u32>,
    /// The largest RSA modulus, in bits (`max-bits`).
    #[serde(default, rename = "max-bits")]
    pub max_bits: Option<u32>,
}

/// What a module's import paths accept (docs/CAMIGRATE.md D2/D10), as data. These are claims
/// that this repository makes. Absent fields describe a spec-compliant PKCS#11 module, which
/// imports public objects and plaintext keys with `C_CreateObject`. Whether the module exports,
/// unwraps, keeps a secret key's length, and wraps to a trusted key is recorded in
/// [`Capability::Move`] rows. The OAEP hashes are recorded in `wrap.rsa-oaep.*` rows.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    /// The way in which plaintext private keys and secret keys are imported, if they can be.
    #[serde(default, rename = "plaintext-import")]
    pub plaintext_import: Option<PlaintextKind>,
    /// What the plaintext import accepts.
    #[serde(default, rename = "plaintext-accepts")]
    pub plaintext_accepts: Vec<AcceptRow>,
    /// The public objects that `C_CreateObject` accepts. When the list is empty, the module
    /// accepts the classes that the spec requires.
    #[serde(default, rename = "public-accepts")]
    pub public_accepts: Vec<AcceptRow>,
    /// The keys that the module accepts by no import path at all, neither sealed nor from the
    /// host, whatever its mechanisms suggest. For example, AWS `CloudHSM` holds Ed25519 as
    /// `CKK_EC` and refuses a `CKK_EC_EDWARDS` template \[run\].
    #[serde(default)]
    pub refuses: Vec<AcceptRow>,
}

/// One capability profile. `profile` names it ("family/version"), `mode` selects how its rows
/// are interpreted, and the other fields are its rows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// The profile's name, "family/version" (for example, "softhsm/2.7"). `--profile` selects a
    /// profile by this name.
    pub profile: String,
    /// A module's observed set, or a layer's subtraction.
    pub mode: Mode,
    /// True when the advertised list has not been recorded yet (the probe, phase 3). A question
    /// about whether the module has a mechanism then answers unknown instead of guessing.
    #[serde(default)]
    pub partial: bool,
    /// True for a passthrough (p11-kit) that hides the module behind it. No claim about that
    /// module applies until keys.toml names its `provider`, so a plan through the passthrough
    /// warns. `notes."requires-provider"` says what the passthrough does forward.
    #[serde(default, rename = "requires-provider")]
    pub requires_provider: bool,
    /// How the profile is matched to a token (`[match]`).
    #[serde(default)]
    pub r#match: MatchInfo,
    /// What `C_GetMechanismList` returns. Once the probe records it, drift detection compares
    /// against it.
    #[serde(default)]
    pub advertise: Vec<String>,
    /// The advertised mechanisms that the probe did not try, and why (`[untested]`). The answer
    /// for one of these is unknown, and never yes.
    #[serde(default)]
    pub untested: BTreeMap<String, Untested>,
    /// What the profile subtracts (`[subtract]`).
    #[serde(default)]
    pub subtract: Subtract,
    /// Mechanisms that are usable although the module does not list them.
    #[serde(default)]
    pub add: Vec<String>,
    /// Whether the module can perform each of cakeys' operations (`[capabilities]`). One row
    /// type covers generation, wrapping, decryption, unwrap templates, ECDH and moves.
    #[serde(default, deserialize_with = "crate::capability::deserialize")]
    pub capabilities: Rows,
    /// The key sizes that the module reports, per key type (`[reported."CKK_RSA"]`).
    #[serde(default)]
    pub reported: BTreeMap<String, Reported>,
    /// What `C_GetMechanismInfo` reports, for each mechanism for which the probe has rows
    /// (`[mechanism-info."CKM_X"]`). These are claims, and the diff never compares them.
    #[serde(default, rename = "mechanism-info")]
    pub mechanism_info: BTreeMap<String, MechanismInfo>,
    /// What the module and the token report about themselves, as `name -> value` (`[claims]`):
    /// token flags and limits, the interface version, the hardware features and the profile
    /// objects. These values are reported, never probed, and never compared.
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
    /// What the module's import paths accept (docs/CAMIGRATE.md), when the module differs from a
    /// spec-compliant module.
    #[serde(default)]
    pub migration: Option<Migration>,
    /// A layer's numeric restrictions (`[[restrict]]`).
    #[serde(default)]
    pub restrict: Vec<Restrict>,
    /// Free-form evidence, keyed by the name that each note explains. Verdicts show these notes.
    #[serde(default)]
    pub notes: BTreeMap<String, String>,
    /// What people found by hand ([`Manual`]). The probe never writes these entries.
    #[serde(default)]
    pub manual: BTreeMap<String, Manual>,
}

impl Profile {
    /// Returns a profile named `profile`, of `mode`, with no rows. A probe starts from this
    /// profile.
    #[must_use]
    pub fn new(profile: String, mode: Mode) -> Profile {
        Profile {
            profile,
            mode,
            partial: false,
            requires_provider: false,
            r#match: MatchInfo::default(),
            advertise: Vec::new(),
            untested: BTreeMap::new(),
            subtract: Subtract::default(),
            add: Vec::new(),
            capabilities: BTreeMap::new(),
            reported: BTreeMap::new(),
            mechanism_info: BTreeMap::new(),
            claims: BTreeMap::new(),
            migration: None,
            restrict: Vec::new(),
            notes: BTreeMap::new(),
            manual: BTreeMap::new(),
        }
    }

    /// Parses a profile file.
    ///
    /// # Errors
    ///
    /// Returns the TOML error, with its line, as a message. The loader prefixes the message with
    /// the file's path.
    pub fn from_toml(text: &str) -> Result<Profile, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// Returns what is wrong with the `[untested]` table, one line for each problem: an entry for
    /// a mechanism that the module does not advertise, an entry that a row measures, or an entry
    /// for a mechanism that the module was found to refuse. A profile that records `[untested]`
    /// at all is complete, because the probe writes the whole table. Every advertised name is
    /// then either measured or listed, so the rows and the operation probes decided every
    /// mechanism that the table does not list.
    #[must_use]
    pub fn untested_problems(&self) -> Vec<String> {
        let measured: std::collections::BTreeSet<String> =
            self.capabilities.iter().flat_map(|(c, r)| c.mechanisms(r.via.as_deref())).collect();
        let mut out = Vec::new();
        for (name, u) in &self.untested {
            // An entry for a capability: the probe tried it and could not decide (E-2).
            if let Ok(c) = Capability::parse(name) {
                if !u.why.undecided() {
                    out.push(format!(
                        "[untested] {name}: a capability's entry says device or cakeys, not {}",
                        u.why.name()
                    ));
                }
                if self.capabilities.contains_key(&c) {
                    out.push(format!("[untested] {name}: also a row"));
                }
                continue;
            }
            if u.why.undecided() {
                out.push(format!("[untested] {name}: {} names a capability, and this is none", u.why.name()));
            }
            if !self.advertise.iter().any(|a| a == name) {
                out.push(format!("[untested] {name}: the module does not advertise it"));
            }
            if self.subtract.mechanisms.iter().any(|a| a == name) {
                out.push(format!("[untested] {name}: also subtracted, so it was tried"));
            }
            if measured.contains(name) {
                out.push(format!("[untested] {name}: a capability row measures it"));
            }
        }
        out
    }

    /// Returns the profile's family, which a keys.toml `provider` names: `softhsm/2.7` becomes
    /// `softhsm`.
    #[must_use]
    pub fn family(&self) -> &str {
        self.profile.split_once('/').map_or(&self.profile, |(family, _)| family)
    }

    /// Returns the answer to `c`, if the profile has one. A capability that the probe could not
    /// decide ([`Self::unknown`]) answers no. A plan never treats an unknown as yes, so it
    /// refuses as it does for an unsupported capability (exit 15), and its evidence asks for a
    /// new probe run (phase1-design §9.1).
    #[must_use]
    pub fn answer(&self, c: &Capability) -> Option<bool> {
        if self.unknown(c).is_some() {
            return Some(false);
        }
        self.capabilities.get(c).map(|r| r.answer.yes())
    }

    /// Returns why `c` is unknown although the profile mentions it. That is the case for a
    /// legacy `no` that cites a device failure ([`Row::device_failed`]), and for an `[untested]`
    /// entry for the capability (the probe tried it and could not decide). Returns `None` for a
    /// row that answers, and when the profile does not mention `c` at all.
    #[must_use]
    pub fn unknown(&self, c: &Capability) -> Option<String> {
        const REPROBE: &str = "re-probe it (T2, profiles/LEDGER.toml)";
        if let Some(r) = self.capabilities.get(c) {
            let rv = r.device_failed()?;
            return Some(format!(
                "unknown, not the module's no: {rv} is the device failing (a legacy row: {}); {REPROBE}",
                r.evidence.as_deref().unwrap_or_default()
            ));
        }
        let u = self.untested.get(&c.to_string()).filter(|u| u.why.undecided())?;
        Some(format!(
            "unknown, not the module's no: the probe could not decide it ({}{}); {REPROBE}",
            u.why.name(),
            u.note.as_ref().map(|n| format!(": {n}")).unwrap_or_default()
        ))
    }

    /// Returns the evidence for the answer to `c`. That is the reason why it is unknown, if it
    /// is. Otherwise, it is the row's evidence with its provenance ([`Self::provenance`]), or,
    /// failing that, the note that an older profile kept for it under the key `note` (the curve,
    /// or `"<key type> at <bits>"`).
    #[must_use]
    pub fn evidence(&self, c: &Capability, note: &str) -> Option<String> {
        let shown = self.provenance(c);
        let with = |e: String| match shown {
            Some(p) => format!("{e} ({p})"),
            None => e,
        };
        self.unknown(c)
            .or_else(|| self.capabilities.get(c).and_then(|r| r.evidence.clone()).map(with))
            .or_else(|| self.notes.get(note).cloned().map(with))
            .or_else(|| shown.map(str::to_owned))
    }

    /// Returns a warning about weak provenance of `c`'s row, for a note next to its answer
    /// (phase1-design §2.4). A probed row without `by` is a legacy row, and a yes that only the
    /// module reports is unverified. Returns `None` for a row that the host checked or that the
    /// module refused, for a claim written by hand (`move.*`, or a layer's rows), and when there
    /// is no row.
    #[must_use]
    pub fn provenance(&self, c: &Capability) -> Option<&'static str> {
        let row = self.capabilities.get(c).filter(|_| c.probed() && self.mode == Mode::Observed)?;
        match row.by {
            None => Some("a legacy row: provenance unknown"),
            Some(By::Unverified) => Some("unverified: only the module says so"),
            Some(By::Host | By::Module) => None,
        }
    }

    /// Sets the row of `c`.
    pub fn set(&mut self, c: Capability, row: Row) {
        self.capabilities.insert(c, row);
    }

    /// Returns the members of `asked` whose row answers yes. Returns `None` when none of them has
    /// a row (they were never probed), and `Some([])` when every row that exists answers no.
    fn yes_of(&self, asked: &[&str], cap: impl Fn(String) -> Capability) -> Option<Vec<String>> {
        let rows: Vec<(&str, bool)> =
            asked.iter().filter_map(|a| self.answer(&cap((*a).to_owned())).map(|y| (*a, y))).collect();
        (!rows.is_empty()).then(|| rows.into_iter().filter(|(_, y)| *y).map(|(a, _)| a.to_owned()).collect())
    }

    /// Returns the OAEP hashes with which a wrap completes a round trip, or `None` if the wrap
    /// was never probed.
    #[must_use]
    pub fn wrap_oaep(&self) -> Option<Vec<String>> {
        self.yes_of(&WRAP_OAEP, Capability::WrapOaep)
    }

    /// Returns the OAEP hashes with which the module's private keys decrypt (`pop-decrypt`), or
    /// `None` if decryption was never probed.
    #[must_use]
    pub fn decrypt_oaep(&self) -> Option<Vec<String>> {
        self.yes_of(&DECRYPT_OAEP, Capability::DecryptOaep)
    }

    /// Returns the attributes that the module refuses in an unwrap template, or `None` if this
    /// was never probed.
    #[must_use]
    pub fn unwrap_refuse(&self) -> Option<Vec<String>> {
        let rows: Vec<(&str, bool)> = UNWRAP_TEMPLATE
            .iter()
            .filter_map(|a| self.answer(&Capability::UnwrapTemplate((*a).to_owned())).map(|y| (*a, y)))
            .collect();
        (!rows.is_empty()).then(|| rows.into_iter().filter(|(_, y)| !y).map(|(a, _)| a.to_owned()).collect())
    }

    /// Returns whether a way of moving keys works. `None` means that there is no claim, and the
    /// module is assumed to behave as the spec requires.
    #[must_use]
    pub fn moves(&self, m: Move) -> Option<bool> {
        self.answer(&Capability::Move(m))
    }

    /// Returns whether the module can unwrap any key into the token. The answer is yes when any
    /// probed `unwrap.<key type>` row answers yes, and no when all of them answer no. Without
    /// such rows, the `move.unwrap` claim decides. The result is `None` when neither exists.
    #[must_use]
    pub fn unwraps(&self) -> Option<bool> {
        self.any_of(|c| matches!(c, Capability::Unwrap { .. })).or_else(|| self.moves(Move::Unwrap))
    }

    /// Returns whether the module can create any public key object. The answer is yes when any
    /// probed `create.CKO_PUBLIC_KEY.*` row answers yes, and no when all of them answer no. The
    /// result is `None` when there is no such row.
    #[must_use]
    pub fn creates_public_keys(&self) -> Option<bool> {
        self.any_of(|c| matches!(c, Capability::Create { class, .. } if class == "CKO_PUBLIC_KEY"))
    }

    /// Returns whether any row that `matching` selects answers yes, or `None` when `matching`
    /// selects no row.
    fn any_of(&self, matching: impl Fn(&Capability) -> bool) -> Option<bool> {
        let mut rows = self.capabilities.iter().filter(|(c, _)| matching(c)).peekable();
        rows.peek()?;
        Some(rows.any(|(_, r)| r.answer.yes()))
    }

    /// Returns the key types for which the profile records anything about generation. These are
    /// the key types for which [`Self::generation`] returns `Some`.
    #[must_use]
    pub fn generation_key_types(&self) -> std::collections::BTreeSet<&str> {
        let rows = self.capabilities.keys().filter_map(|c| match c {
            Capability::Generate { key_type, on: On::Item(_) | On::Bits(_) | On::Bytes(_) } => Some(key_type.name()),
            _ => None,
        });
        let undecided = self.untested.iter().filter(|(_, u)| u.why.undecided()).filter_map(|(name, _)| {
            let kt = name.strip_prefix("generate.")?.split_once('.')?.0;
            Capability::parse(name).is_ok().then_some(kt)
        });
        rows.chain(undecided).chain(self.reported.keys().map(String::as_str)).collect()
    }

    /// Returns what the module generates for `key_type`, according to its rows and its reported
    /// range, or `None` when the profile records nothing about the key type. A secret key's
    /// lengths go into `can_bytes` and `cannot_bytes`, separate from the bits of an RSA modulus.
    #[must_use]
    pub fn generation(&self, key_type: &str) -> Option<GenerateRow> {
        let mut row = GenerateRow::default();
        let mut any = false;
        if let Some(r) = self.reported.get(key_type) {
            (row.min_bits, row.max_bits, any) = (r.min_bits, r.max_bits, true);
        }
        for (c, r) in &self.capabilities {
            let Capability::Generate { key_type: kt, on } = c else { continue };
            if kt != key_type {
                continue;
            }
            any = true;
            // A legacy row that cites a device failure is already a `no`, so it causes a refusal,
            // as an unknown answer does.
            match (on, r.answer) {
                (On::Item(i), Answer::Yes) => {
                    row.can.push(i.clone());
                    if r.via.as_deref() == Some("by-name") {
                        row.by_name.push(i.clone());
                    }
                }
                (On::Item(i), Answer::No) => row.cannot.push(i.clone()),
                (On::Bits(b), Answer::Yes) => row.can_bits.push(*b),
                (On::Bits(b), Answer::No) => row.cannot_bits.push(*b),
                // A secret key's length is in bytes, and it is kept separate from the bits of an
                // RSA modulus.
                (On::Bytes(b), Answer::Yes) => row.can_bytes.push(*b),
                (On::Bytes(b), Answer::No) => row.cannot_bytes.push(*b),
            }
        }
        // A size that the probe could not decide also causes a refusal, and interpolation does
        // not cross it. If an undecided size lies between two sizes that generated, there is no
        // evidence that the sizes between them work.
        for (name, _) in self.untested.iter().filter(|(_, u)| u.why.undecided()) {
            let Ok(Capability::Generate { key_type: kt, on }) = Capability::parse(name) else { continue };
            if kt != key_type {
                continue;
            }
            any = true;
            match on {
                On::Item(i) => row.cannot.push(i),
                On::Bits(b) => row.cannot_bits.push(b),
                On::Bytes(b) => row.cannot_bytes.push(b),
            }
        }
        any.then_some(row)
    }

    /// Records what the probe saw `key_type` generate. Each curve or size becomes a row, with
    /// `via = "by-name"` for the curves that generate only by name, and the reported range is
    /// stored separately. `notes` gives a row its evidence, keyed by the curve or by
    /// `"<key type> at <bits>"`. A size or curve that generated gets `by = "host"`, because the
    /// host found the key pair under the locator that it asked for. A refused size or curve gets
    /// `by = "module"`. The probe puts nothing else in `row`.
    pub fn set_generation(&mut self, key_type: &str, row: &GenerateRow) {
        let kind = KeyKind::from(key_type);
        let generate = |on| Capability::Generate { key_type: kind.clone(), on };
        let probed = |answer, via| Row {
            answer,
            by: Some(if answer == Answer::Yes { By::Host } else { By::Module }),
            evidence: None,
            via,
        };
        for i in &row.can {
            let via = row.by_name.contains(i).then(|| "by-name".to_owned());
            self.set(generate(On::Item(i.clone())), probed(Answer::Yes, via));
        }
        for i in &row.cannot {
            self.set(generate(On::Item(i.clone())), probed(Answer::No, None));
        }
        // Each size is written in the unit in which the row is read back (`On::size`). A size in
        // bits is never written for a key type whose rows are read back as bytes.
        for b in &row.can_bits {
            self.set(generate(On::size(&kind, *b)), probed(Answer::Yes, None));
        }
        for b in &row.cannot_bits {
            self.set(generate(On::size(&kind, *b)), probed(Answer::No, None));
        }
        // A secret key's length is in bytes, whatever the key type (`generate.CKK_AES.32`).
        for b in &row.can_bytes {
            self.set(generate(On::Bytes(*b)), probed(Answer::Yes, None));
        }
        for b in &row.cannot_bytes {
            self.set(generate(On::Bytes(*b)), probed(Answer::No, None));
        }
        if row.min_bits.is_some() || row.max_bits.is_some() {
            self.reported.insert(key_type.to_owned(), Reported { min_bits: row.min_bits, max_bits: row.max_bits });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(rows: &str) -> Profile {
        Profile::from_toml(&format!("profile = \"m/1\"\nmode = \"observed\"\n[capabilities]\n{rows}")).unwrap()
    }

    /// `generation` covers every row that a profile keeps, with each size in the unit that its
    /// key type uses. An AES length is in bytes, separate from the bits of an RSA modulus (review
    /// profile.rs F1).
    #[test]
    fn generation_speaks_for_the_rows_it_keeps() {
        let p = profile(
            "\"generate.CKK_AES.32\" = { answer = \"yes\" }\n\"generate.CKK_AES.8\" = { answer = \"no\" }\n\
             \"generate.CKK_EC.secp256r1\" = { answer = \"no\" }\n",
        );
        let aes = p.generation("CKK_AES").unwrap();
        assert_eq!((aes.can_bytes, aes.cannot_bytes), (vec![32], vec![8]));
        assert!(aes.can_bits.is_empty() && aes.cannot_bits.is_empty());
        assert_eq!(p.generation("CKK_EC").map(|r| r.cannot), Some(vec!["secp256r1".to_owned()]));
        assert_eq!(p.generation("CKK_DES3"), None);
        assert_eq!(p.generation_key_types().into_iter().collect::<Vec<_>>(), ["CKK_AES", "CKK_EC"]);
        // In every committed profile, `generation` and `generation_key_types` agree.
        for p in crate::Set::embedded().unwrap().all() {
            for kt in KeyKind::NAMES {
                assert_eq!(p.generation(kt).is_some(), p.generation_key_types().contains(kt), "{} {kt}", p.profile);
            }
        }
    }

    /// A note states the provenance of a row (phase1-design §2.4). A probed row without `by` is
    /// marked as legacy, and an unverified yes is marked as unverified. A row that the host
    /// checked or that the module refused, a claim written by hand, and a layer's row get no
    /// extra note.
    #[test]
    fn a_note_says_how_far_its_row_is_shown() {
        let p = profile(
            "\"generate.CKK_RSA.1024\" = { answer = \"no\", evidence = \"CKR_KEY_SIZE_RANGE\" }\n\
             \"generate.CKK_RSA.2048\" = { answer = \"no\", by = \"module\", evidence = \"CKR_KEY_SIZE_RANGE\" }\n\
             \"commit.cmac.CKK_AES.32\" = { answer = \"yes\", by = \"unverified\" }\n\
             \"commit.cmac.CKK_AES.16\" = { answer = \"yes\", by = \"host\" }\n\
             \"move.secret-unwrap\" = { answer = \"no\" }\n",
        );
        let rsa = |bits| Capability::Generate { key_type: KeyKind::Rsa, on: On::Bits(bits) };
        let cmac = |bytes| Capability::Commit { kind: "cmac".into(), key_type: KeyKind::Aes, bytes };
        assert_eq!(
            p.evidence(&rsa(1024), "").as_deref(),
            Some("CKR_KEY_SIZE_RANGE (a legacy row: provenance unknown)")
        );
        assert_eq!(p.evidence(&rsa(2048), "").as_deref(), Some("CKR_KEY_SIZE_RANGE"));
        assert_eq!(p.provenance(&cmac(32)), Some("unverified: only the module says so"));
        assert_eq!(p.provenance(&cmac(16)), None);
        assert_eq!(p.provenance(&Capability::Move(Move::SecretUnwrap)), None);
        let mut layer = p.clone();
        layer.mode = Mode::Delta;
        assert_eq!(layer.evidence(&rsa(1024), "").as_deref(), Some("CKR_KEY_SIZE_RANGE"));
    }

    /// A row's `by` is valid only with the answers that it can support. `by = "module"` goes with
    /// a no that does not cite a device failure, and `by = "unverified"` goes with a yes. Each
    /// invalid pair is refused when the profile loads, so it is never read.
    #[test]
    fn provenance_holds_only_with_its_answers() {
        let load = |row: &str| {
            Profile::from_toml(&format!(
                "profile = \"m/1\"\nmode = \"observed\"\n[capabilities]\n\"generate.CKK_RSA.2048\" = {row}\n"
            ))
        };
        for bad in [
            "{ answer = \"yes\", by = \"module\" }",
            "{ answer = \"no\", by = \"unverified\" }",
            "{ answer = \"no\", by = \"module\", evidence = \"generation refused: CKR_DEVICE_ERROR\" }",
            "{ answer = \"no\", by = \"module\", evidence = \"a: CKR_MECHANISM_INVALID; b: CKR_GENERAL_ERROR\" }",
            "{ answer = \"no\", by = \"device\" }",
        ] {
            assert!(load(bad).is_err(), "{bad}");
        }
        for good in [
            "{ answer = \"no\", by = \"module\", evidence = \"CKR_DEVICE_ERRORS_ARE_NOT_A_NAME\" }",
            "{ answer = \"no\", by = \"host\", evidence = \"another key\" }",
            "{ answer = \"yes\", by = \"unverified\" }",
            "{ answer = \"yes\", by = \"host\" }",
            "{ answer = \"no\", evidence = \"CKR_DEVICE_ERROR\" }",
        ] {
            load(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
    }

    /// A capability that the probe could not decide is unknown. It causes a refusal, as an
    /// unsupported capability does, and its evidence asks for a new probe run (phase1-design
    /// §2.4, §9.1). This applies to a legacy no that cites a device failure, and to an
    /// `[untested]` entry keyed by the capability. Neither one allows interpolation: a size
    /// between two sizes that generated is not yes when an undecided size lies between them.
    #[test]
    fn what_the_probe_could_not_decide_refuses_as_unknown() {
        let p = Profile::from_toml(
            "profile = \"m/1\"\nmode = \"observed\"\nadvertise = [\"CKM_X\"]\n[capabilities]\n\
             \"generate.CKK_RSA.1024\" = { answer = \"yes\", by = \"host\" }\n\
             \"generate.CKK_RSA.2048\" = { answer = \"yes\", by = \"host\" }\n\
             \"generate.CKK_RSA.3072\" = { answer = \"no\", evidence = \"generation refused: CKR_GENERAL_ERROR\" }\n\
             \"generate.CKK_RSA.4096\" = { answer = \"no\", evidence = \"generation refused: CKR_KEY_SIZE_RANGE\" }\n\
             \"import.CKK_EC.secp256r1\" = { answer = \"no\", evidence = \"CKR_DEVICE_ERROR\" }\n\
             [untested]\n\"generate.CKK_RSA.1536\" = { why = \"device\", note = \"CKR_HOST_MEMORY\" }\n\
             \"prove.pop-sign.CKK_EC_EDWARDS.edwards448\" = { why = \"cakeys\", note = \"no Ed448 verifier\" }\n",
        )
        .unwrap();
        assert_eq!(p.untested_problems(), Vec::<String>::new());
        let rsa = |bits| Capability::Generate { key_type: KeyKind::Rsa, on: On::Bits(bits) };
        for c in [
            rsa(3072),
            rsa(1536),
            Capability::parse("import.CKK_EC.secp256r1").unwrap(),
            Capability::parse("prove.pop-sign.CKK_EC_EDWARDS.edwards448").unwrap(),
        ] {
            assert_eq!(p.answer(&c), Some(false), "{c}");
            let why = p.evidence(&c, "").unwrap_or_default();
            assert!(
                why.starts_with("unknown, not the module's no") && why.contains("(T2, profiles/LEDGER.toml)"),
                "{c}: {why}"
            );
        }
        // The module's own no stays a no, and a yes stays a yes.
        assert_eq!(p.unknown(&rsa(4096)), None);
        assert_eq!(p.answer(&rsa(2048)), Some(true));
        assert_eq!(p.answer(&rsa(8192)), None);
        let g = p.generation("CKK_RSA").unwrap();
        assert!(g.cannot_bits.contains(&1536) && g.cannot_bits.contains(&3072), "{g:?}");
        // An undecided entry may only be keyed by a capability, and it must not also be a row.
        let wrong = |untested: &str| {
            let mut q = p.clone();
            q.untested = toml::from_str(untested).unwrap();
            q.untested_problems()
        };
        assert_eq!(wrong("\"generate.CKK_RSA.1536\" = { why = \"unprobed\" }").len(), 1);
        assert_eq!(wrong("\"generate.CKK_RSA.2048\" = { why = \"device\" }").len(), 1);
        assert_eq!(wrong("\"CKM_X\" = { why = \"cakeys\" }").len(), 1);
    }

    /// This test lists the committed rows that load as unknown. They are the legacy device
    /// failures of the hardware profiles, for which the probe cannot run again here
    /// (phase1-design §2.4), and no others. A new such row fails this test until it is added to
    /// the list. The cloud profiles have none.
    #[test]
    fn the_committed_device_failures_are_these() {
        let mut found: Vec<String> = Vec::new();
        for p in crate::Set::embedded().unwrap().all() {
            for c in p.capabilities.keys().filter(|c| p.unknown(c).is_some()) {
                found.push(format!("{} {c}", p.profile));
            }
        }
        let ykcs11 = [
            "import.CKK_EC.brainpoolP256r1",
            "import.CKK_EC.brainpoolP384r1",
            "import.CKK_EC.secp256k1",
            "import.CKK_EC.secp521r1",
            "import.CKK_EC_EDWARDS.edwards25519",
            "import.CKK_RSA.1024",
            "import.CKK_RSA.1536",
            "import.CKK_RSA.2048",
            "import.CKK_RSA.3072",
            "import.CKK_RSA.4096",
        ];
        // The software profiles were probed again with provenance (phase1-design §9.6), so they
        // have none. Their device failures are `[untested]` entries.
        let mut expected: Vec<String> = [
            "tpm2-pkcs11/1.10+amd-ftpm derive.ecdh.sealed",
            "tpm2-pkcs11/1.10+amd-ftpm generate.CKK_EC.secp521r1",
            "tpm2-pkcs11/1.10+amd-ftpm generate.CKK_RSA.1536",
            "tpm2-pkcs11/1.10+amd-ftpm prove.pop-sign.CKK_EC.secp384r1",
        ]
        .into_iter()
        .map(str::to_owned)
        .chain(ykcs11.iter().map(|c| format!("ykcs11/2.7 {c}")))
        .collect();
        expected.sort();
        found.sort();
        assert_eq!(found, expected);
    }

    /// Every row that `set_generation` writes is read back from its key as the same row, for any
    /// key type, because each size is in the unit that its key type uses (review profile.rs F2).
    #[test]
    fn written_generation_rows_read_back() {
        let row = GenerateRow {
            can: vec!["a".into()],
            cannot: vec!["b".into()],
            can_bits: vec![2048],
            cannot_bits: vec![1536],
            by_name: vec!["a".into()],
            ..GenerateRow::default()
        };
        for kt in ["CKK_RSA", "CKK_AES", "CKK_EC", "CKK_ML_DSA"] {
            let mut p = profile("");
            p.set_generation(kt, &row);
            assert_eq!(p.capabilities.len(), 4, "{kt}");
            for c in p.capabilities.keys() {
                assert_eq!(Capability::parse(&c.to_string()).as_ref(), Ok(c), "{kt}: {c}");
            }
        }
        let mut rsa = profile("");
        rsa.set_generation("CKK_RSA", &row);
        assert_eq!(rsa.generation("CKK_RSA"), Some(row));
        // For each secret key type, a secret key's lengths are written as rows in bytes (never
        // read as the bits of an RSA modulus), and they are read back as bytes.
        let secret = GenerateRow { can_bytes: vec![16, 32], cannot_bytes: vec![8], ..GenerateRow::default() };
        for kt in ["CKK_AES", "CKK_GENERIC_SECRET", "CKK_DES3", "CKK_SHA256_HMAC"] {
            let mut p = profile("");
            p.set_generation(kt, &secret);
            assert_eq!(p.capabilities.len(), 3, "{kt}");
            for c in p.capabilities.keys() {
                assert_eq!(Capability::parse(&c.to_string()).as_ref(), Ok(c), "{kt}: {c}");
            }
            assert_eq!(p.generation(kt), Some(secret.clone()), "{kt}");
        }
    }

    /// The family is the name before the first `/`, or the whole name without one.
    #[test]
    fn the_family_is_the_name_before_the_version() {
        let named = |n: &str| Profile { profile: n.into(), ..profile("") };
        assert_eq!(named("softhsm/2.7").family(), "softhsm");
        assert_eq!(named("aws-cloudhsm/5.18+hsm2m-fips").family(), "aws-cloudhsm");
        assert_eq!(named("swtpm").family(), "swtpm");
    }
}
