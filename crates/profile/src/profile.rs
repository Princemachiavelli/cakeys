//! A capability profile (docs/CAPROBE.md D2, D3): how one vendor SO version (`observed`
//! mode) or one layer between cakeys and the token (`delta` mode) deviates from what it
//! advertises. The rows committed today carry this repo's \[run\] evidence; the probe (phase 3)
//! regenerates them and fills the `advertise` lists.

use crate::capability::{Answer, By, Capability, DECRYPT_OAEP, Move, On, Row, Rows, UNWRAP_TEMPLATE, WRAP_OAEP};
use crate::names::KeyKind;
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
#[serde(deny_unknown_fields)]
pub struct MatchInfo {
    /// The module's manufacturer, as `C_GetInfo` reports it.
    pub manufacturer: Option<String>,
    /// The module's version, as `C_GetInfo` expresses it (`module-version`).
    #[serde(rename = "module-version")]
    pub module_version: Option<String>,
    /// The token's model, as `C_GetTokenInfo` reports it.
    pub model: Option<String>,
    /// The token's firmware version, as `C_GetTokenInfo` reports it.
    pub firmware: Option<String>,
}

/// What a profile subtracts: capabilities the module advertises but cannot use, or that a
/// layer does not carry.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subtract {
    /// Mechanisms, by `CKM_*` name.
    #[serde(default)]
    pub mechanisms: Vec<String>,
    /// Key types, by `CKK_*` name (`key-types`).
    #[serde(default, rename = "key-types")]
    pub key_types: Vec<String>,
    /// One note for the whole subtraction (each entry may still get its own under `notes`).
    #[serde(default)]
    pub note: Option<String>,
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
    /// How: the command or source that shows it, with its date and an evidence tag (`\[run\]`,
    /// `\[src\]`, `[spec]`).
    pub evidence: String,
}

/// Why an advertised mechanism has no measured row (`[untested]`, `docs/archive/CAPROBE_PROFILE_COVERAGE.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Why {
    /// The binding has no constant or parameter type for it, and the probe cannot build the call
    /// by hand; the cryptoki layer carries the same note.
    Cryptoki,
    /// A mechanism ID the baseline does not name: no known parameters, so no meaningful call.
    Vendor,
    /// Testing needs state or a risk the probe's rules forbid (a scratch slot, the real TPM).
    Hardware,
    /// Testing needs a service that was not run for this profile.
    Cloud,
    /// Decided out of scope: the tools never use it (`spec-coverage/manual.toml`).
    Scope,
    /// No probe tries it yet.
    Unprobed,
    /// Tried, and the module said `CKR_OK`, but nothing outside it could check the result (a
    /// signature the host has no verifier for): never yes (review 2026-11-24 E-4).
    Unverified,
    /// A capability (the key is a row's) the module failed on with a device failure
    /// ([`crate::DEVICE_FAILED_RV`]): no answer of the module's, so unknown, which refuses.
    Device,
    /// A capability cakeys or its provider refused before the module was asked (no verifier on
    /// the host, a template the provider refuses): no answer of the module's either.
    Cakeys,
}

impl Why {
    /// The word the table writes.
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

    /// Whether the entry is a capability's the probe could not decide (its key is a row's).
    #[must_use]
    pub fn undecided(self) -> bool {
        matches!(self, Why::Device | Why::Cakeys)
    }
}

/// One advertised mechanism the probe did not try (`[untested]`): probe output, regenerated
/// with the profile, never a claim.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Untested {
    /// Why it was not tried.
    pub why: Why,
    /// What to know of it: the reason in words.
    #[serde(default)]
    pub note: Option<String>,
}

/// What `C_GetMechanismInfo` reports for one mechanism (`[mechanism-info."CKM_X"]`): a claim the
/// probe records and checks against what it measured, never evidence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MechanismInfo {
    /// The smallest key size it reports (bits or bytes, as the module counts).
    pub min: u64,
    /// The largest.
    pub max: u64,
    /// The operations it flags.
    #[serde(default)]
    pub flags: Vec<String>,
}

/// The key sizes a module reports for one key type (`[reported."CKK_RSA"]`): the inclusive range
/// `C_GetMechanismInfo` gives, or a hand claim. What the module did with a size is a
/// [`Capability::Generate`] row.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reported {
    /// The smallest modulus it reports, in bits (`min-bits`).
    #[serde(default, rename = "min-bits")]
    pub min_bits: Option<u32>,
    /// The largest modulus it reports, in bits (`max-bits`).
    #[serde(default, rename = "max-bits")]
    pub max_bits: Option<u32>,
}

/// What a module generates for one key type, as its rows say ([`Profile::generation`]): the
/// curves (or parameter sets) that generated and that did not, the modulus sizes likewise, the
/// curves that generate only by name, and the range the module reports. What none of them
/// decides answers unknown (D5), never a guess.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GenerateRow {
    /// What it generates: curves, or parameter sets.
    pub can: Vec<String>,
    /// What it does not generate, although it may list them.
    pub cannot: Vec<String>,
    /// The smallest RSA modulus it reports, in bits.
    pub min_bits: Option<u32>,
    /// The largest RSA modulus it reports, in bits.
    pub max_bits: Option<u32>,
    /// RSA modulus sizes that generated.
    pub can_bits: Vec<u32>,
    /// RSA modulus sizes refused.
    pub cannot_bits: Vec<u32>,
    /// Secret-key lengths that generated, in bytes (`CKA_VALUE_LEN`: the unit the key types
    /// with a length read, never the bits of an RSA modulus).
    pub can_bytes: Vec<u32>,
    /// Secret-key lengths refused, in bytes.
    pub cannot_bytes: Vec<u32>,
    /// Curves in `can` that generate only when `CKA_EC_PARAMS` names them (PKCS#11 3.0's
    /// `PrintableString` form), never by OID: ykcs11's Edwards and Montgomery curves \[src\].
    pub by_name: Vec<String>,
}

/// A layer's numeric restriction, intersected with every other layer's (D3): swtpm refuses
/// 4096-bit RSA generation, whatever tpm2-pkcs11's module profile says.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restrict {
    /// What the restriction applies to; only "generate" exists today, and an operation of a
    /// newer cakeys restricts nothing here. A plain name: one value needs no enum (review
    /// 2026-11-23 A-13).
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
    /// Why, shown in verdicts.
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

impl PlaintextKind {
    /// The name a profile writes: `plaintext-import`, and an `import.*` row's `via`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            PlaintextKind::CreateObject => "create-object",
            PlaintextKind::Tpm2Ptool => "tpm2-ptool",
            PlaintextKind::PivImport => "piv-import",
        }
    }
}

/// One row of what a module's import paths take: a class, and optionally only some key types,
/// curves, or an inclusive RSA modulus range (empty: any).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptRow {
    /// The object class, by `CKO_*` name.
    pub class: String,
    /// The key types, by `CKK_*` name (`key-types`; empty: any).
    #[serde(default, rename = "key-types")]
    pub key_types: Vec<String>,
    /// The curves, by name (empty: any).
    #[serde(default)]
    pub curves: Vec<String>,
    /// The smallest RSA modulus, in bits (`min-bits`).
    #[serde(default, rename = "min-bits")]
    pub min_bits: Option<u32>,
    /// The largest RSA modulus, in bits (`max-bits`).
    #[serde(default, rename = "max-bits")]
    pub max_bits: Option<u32>,
}

/// What a module's import paths take (docs/CAMIGRATE.md D2/D10), as data: this repo's claims.
/// Absent fields mean a spec-compliant PKCS#11 module: it imports public objects and plaintext
/// keys with `C_CreateObject`. Whether it exports, unwraps, keeps a secret's length and wraps
/// toward a trusted key are [`Capability::Move`] rows; the OAEP hashes `wrap.rsa-oaep.*`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Migration {
    /// How plaintext private and secret keys get in, if at all.
    #[serde(default, rename = "plaintext-import")]
    pub plaintext_import: Option<PlaintextKind>,
    /// What the plaintext import takes.
    #[serde(default, rename = "plaintext-accepts")]
    pub plaintext_accepts: Vec<AcceptRow>,
    /// Public objects `C_CreateObject` takes; the spec-compliant classes when empty.
    #[serde(default, rename = "public-accepts")]
    pub public_accepts: Vec<AcceptRow>,
    /// Keys it takes in by no import at all, sealed or host, whatever its mechanisms say: AWS
    /// `CloudHSM` holds Ed25519 as `CKK_EC` and refuses a `CKK_EC_EDWARDS` template \[run\].
    #[serde(default)]
    pub refuses: Vec<AcceptRow>,
}

/// One capability profile: `profile` names it ("family/version"), `mode` picks its semantics,
/// and the rest are its rows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// The profile's name, "family/version" (e.g. "softhsm/2.7"): what `--profile` selects.
    pub profile: String,
    /// A module's observed set, or a layer's subtraction.
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
    /// How the profile is matched to a token (`[match]`).
    #[serde(default)]
    pub r#match: MatchInfo,
    /// What `C_GetMechanismList` returns; the drift baseline once the probe records it.
    #[serde(default)]
    pub advertise: Vec<String>,
    /// What it advertises that the probe did not try, and why (`[untested]`): an answer for
    /// one of these is unknown, never yes.
    #[serde(default)]
    pub untested: BTreeMap<String, Untested>,
    /// What it subtracts (`[subtract]`).
    #[serde(default)]
    pub subtract: Subtract,
    /// Mechanisms usable although the module does not list them.
    #[serde(default)]
    pub add: Vec<String>,
    /// What the module answers about cakeys' operations (`[capabilities]`): one row type for
    /// generation, wrapping, decryption, unwrap templates, ECDH and moves.
    #[serde(default, deserialize_with = "crate::capability::deserialize")]
    pub capabilities: Rows,
    /// The key sizes the module reports, per key type (`[reported."CKK_RSA"]`).
    #[serde(default)]
    pub reported: BTreeMap<String, Reported>,
    /// What `C_GetMechanismInfo` reports, per mechanism the probe has rows for
    /// (`[mechanism-info."CKM_X"]`): claims, never compared.
    #[serde(default, rename = "mechanism-info")]
    pub mechanism_info: BTreeMap<String, MechanismInfo>,
    /// What the module and token report of themselves, `name -> value` (`[claims]`): token
    /// flags and limits, the interface version, the hardware features and profiles objects.
    /// Reported, never probed, never compared.
    #[serde(default)]
    pub claims: BTreeMap<String, String>,
    /// What the module's import paths take (docs/CAMIGRATE.md), when it deviates from a
    /// spec-compliant module.
    #[serde(default)]
    pub migration: Option<Migration>,
    /// A layer's numeric restrictions (`[[restrict]]`).
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
    /// A profile named `profile` of `mode` with no rows: what a probe starts from.
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

    /// Parse a profile file.
    ///
    /// # Errors
    ///
    /// The message carries the TOML error with its line, for the loader to prefix with the
    /// file's path.
    pub fn from_toml(text: &str) -> Result<Profile, String> {
        toml::from_str(text).map_err(|e| e.to_string())
    }

    /// What is wrong with the `[untested]` table, one line each: an entry the module does not
    /// advertise, one a row measures, or one the module was found to refuse. A profile that
    /// records `[untested]` at all (the probe writes it whole) is closed by it: every advertised
    /// name is measured or listed, so what the table lacks, the rows and the operation probes
    /// decided.
    #[must_use]
    pub fn untested_problems(&self) -> Vec<String> {
        let measured: std::collections::BTreeSet<String> =
            self.capabilities.iter().flat_map(|(c, r)| c.mechanisms(r.via.as_deref())).collect();
        let mut out = Vec::new();
        for (name, u) in &self.untested {
            // A capability's entry: the probe tried it and could not decide (E-2).
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

    /// The profile's family: `softhsm/2.7` -> `softhsm`, what a keys.toml `provider` names.
    #[must_use]
    pub fn family(&self) -> &str {
        self.profile.split_once('/').map_or(&self.profile, |(family, _)| family)
    }

    /// The answer to `c`, if the profile has one. What the probe could not decide ([`Self::unknown`])
    /// answers no: unknown is never planned as yes, and refuses as an unsupported capability
    /// does (15), its evidence naming the re-probe (phase1-design §9.1).
    #[must_use]
    pub fn answer(&self, c: &Capability) -> Option<bool> {
        if self.unknown(c).is_some() {
            return Some(false);
        }
        self.capabilities.get(c).map(|r| r.answer.yes())
    }

    /// Why `c` is unknown although the profile speaks of it: a legacy `no` citing a device
    /// failure ([`Row::device_failed`]), or an `[untested]` entry of the capability's (the probe
    /// tried and could not decide). `None` for a row that answers, or no word at all.
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

    /// What shows the answer to `c`: why it is unknown, else its row's evidence, else the note an
    /// older profile kept for it under `note` (the curve, or `"<key type> at <bits>"`).
    #[must_use]
    pub fn evidence(&self, c: &Capability, note: &str) -> Option<String> {
        self.unknown(c)
            .or_else(|| self.capabilities.get(c).and_then(|r| r.evidence.clone()))
            .or_else(|| self.notes.get(note).cloned())
    }

    /// Set the row of `c`.
    pub fn set(&mut self, c: Capability, row: Row) {
        self.capabilities.insert(c, row);
    }

    /// Of `asked`, the ones whose row answers yes; `None` when none of them has a row (never
    /// probed), `Some([])` when every row there says no.
    fn yes_of(&self, asked: &[&str], cap: impl Fn(String) -> Capability) -> Option<Vec<String>> {
        let rows: Vec<(&str, bool)> =
            asked.iter().filter_map(|a| self.answer(&cap((*a).to_owned())).map(|y| (*a, y))).collect();
        (!rows.is_empty()).then(|| rows.into_iter().filter(|(_, y)| *y).map(|(a, _)| a.to_owned()).collect())
    }

    /// The OAEP hashes a wrap round-trips with; `None`: never probed.
    #[must_use]
    pub fn wrap_oaep(&self) -> Option<Vec<String>> {
        self.yes_of(&WRAP_OAEP, Capability::WrapOaep)
    }

    /// The OAEP hashes its private keys decrypt with (`pop-decrypt`); `None`: never probed.
    #[must_use]
    pub fn decrypt_oaep(&self) -> Option<Vec<String>> {
        self.yes_of(&DECRYPT_OAEP, Capability::DecryptOaep)
    }

    /// The attributes it refuses in an unwrap template; `None`: never probed.
    #[must_use]
    pub fn unwrap_refuse(&self) -> Option<Vec<String>> {
        let rows: Vec<(&str, bool)> = UNWRAP_TEMPLATE
            .iter()
            .filter_map(|a| self.answer(&Capability::UnwrapTemplate((*a).to_owned())).map(|y| (*a, y)))
            .collect();
        (!rows.is_empty()).then(|| rows.into_iter().filter(|(_, y)| !y).map(|(a, _)| a.to_owned()).collect())
    }

    /// Whether a way of moving keys works; `None`: no claim (a spec-compliant module's answer).
    #[must_use]
    pub fn moves(&self, m: Move) -> Option<bool> {
        self.answer(&Capability::Move(m))
    }

    /// Whether the module unwraps a key in at all: yes when any probed `unwrap.<key type>` row
    /// says so, no when they all say no, else its `move.unwrap` claim; `None`: neither.
    #[must_use]
    pub fn unwraps(&self) -> Option<bool> {
        self.any_of(|c| matches!(c, Capability::Unwrap { .. })).or_else(|| self.moves(Move::Unwrap))
    }

    /// Whether the module creates public key objects at all: yes when any probed
    /// `create.CKO_PUBLIC_KEY.*` row says so, no when they all say no; `None`: no such row.
    #[must_use]
    pub fn creates_public_keys(&self) -> Option<bool> {
        self.any_of(|c| matches!(c, Capability::Create { class, .. } if class == "CKO_PUBLIC_KEY"))
    }

    /// Whether any row `matching` picks says yes; `None` when it picks none.
    fn any_of(&self, matching: impl Fn(&Capability) -> bool) -> Option<bool> {
        let mut rows = self.capabilities.iter().filter(|(c, _)| matching(c)).peekable();
        rows.peek()?;
        Some(rows.any(|(_, r)| r.answer.yes()))
    }

    /// The key types the profile says anything about generating: those [`Self::generation`]
    /// answers `Some` for.
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

    /// What it generates of `key_type`, as its rows and reported range say; `None` when it
    /// says nothing about the key type. A secret key's lengths are the `can_bytes` and
    /// `cannot_bytes`, apart from an RSA modulus's bits.
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
            // A legacy row citing a device failure is a `no` already: it refuses, as unknown.
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
                // A secret key's length is in bytes, kept apart from an RSA modulus's bits.
                (On::Bytes(b), Answer::Yes) => row.can_bytes.push(*b),
                (On::Bytes(b), Answer::No) => row.cannot_bytes.push(*b),
            }
        }
        // What the probe could not decide refuses as well, and stops interpolation past it: an
        // undecided size between two that generated is no evidence the one between works.
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

    /// Record what the probe saw `key_type` generate: each curve or size as a row (`via =
    /// "by-name"` for the curves only their name generates), the reported range apart. `notes`
    /// gives a row its evidence, by the curve or by `"<key type> at <bits>"`. A size or curve
    /// that generated is the host's (the pair found under the locator it asked for), one
    /// refused the module's: the probe puts nothing else in `row`.
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
        // A size in the unit the row reads back in (`On::size`): never a bits row that a re-read
        // would take for bytes.
        for b in &row.can_bits {
            self.set(generate(On::size(&kind, *b)), probed(Answer::Yes, None));
        }
        for b in &row.cannot_bits {
            self.set(generate(On::size(&kind, *b)), probed(Answer::No, None));
        }
        // A secret key's length is bytes whatever the key type (`generate.CKK_AES.32`).
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

    /// `generation` speaks for every row a profile keeps, each size in the unit its key type
    /// reads: an AES length is bytes, apart from an RSA modulus's bits (review profile.rs F1).
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
        // Over every committed profile, the two agree.
        for p in crate::Set::embedded().unwrap().all() {
            for kt in KeyKind::NAMES {
                assert_eq!(p.generation(kt).is_some(), p.generation_key_types().contains(kt), "{} {kt}", p.profile);
            }
        }
    }

    /// A row's `by` holds only with the answers it can show: the module's is a no and never a
    /// device failure, an unverified one a yes. Each wrong pair is refused at load, never read.
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

    /// What the probe could not decide is unknown, which refuses as an unsupported capability
    /// does and names the re-probe (phase1-design §2.4, §9.1): a legacy no citing a device
    /// failure, and an `[untested]` entry keyed by the capability. Neither interpolates: a size
    /// between two that generated, across an undecided one, is not yes.
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
        // The module's own no, and a yes, are what they say.
        assert_eq!(p.unknown(&rsa(4096)), None);
        assert_eq!(p.answer(&rsa(2048)), Some(true));
        assert_eq!(p.answer(&rsa(8192)), None);
        let g = p.generation("CKK_RSA").unwrap();
        assert!(g.cannot_bits.contains(&1536) && g.cannot_bits.contains(&3072), "{g:?}");
        // An undecided entry is a capability's only, and never also a row.
        let wrong = |untested: &str| {
            let mut q = p.clone();
            q.untested = toml::from_str(untested).unwrap();
            q.untested_problems()
        };
        assert_eq!(wrong("\"generate.CKK_RSA.1536\" = { why = \"unprobed\" }").len(), 1);
        assert_eq!(wrong("\"generate.CKK_RSA.2048\" = { why = \"device\" }").len(), 1);
        assert_eq!(wrong("\"CKM_X\" = { why = \"cakeys\" }").len(), 1);
    }

    /// Which committed rows load as unknown: the legacy device failures of the hardware profiles
    /// the probe cannot re-run here (phase1-design §2.4), and no other. A new one fails here
    /// until it is listed, and the cloud profiles have none.
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
        // The software profiles, probed again with provenance (phase1-design §9.6), have none:
        // their device failures are `[untested]` entries.
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

    /// Every row `set_generation` writes reads back as itself from its key, for any key type:
    /// a size is in the unit its key type reads (review profile.rs F2).
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
        // A secret key's lengths are bytes rows (never read as an RSA modulus's bits), for each
        // secret key type, and read back as bytes.
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
