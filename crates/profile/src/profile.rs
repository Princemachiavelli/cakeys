//! A capability profile (docs/CAPROBE.md D2, D3): how one vendor SO version (`observed`
//! mode) or one layer between cakeys and the token (`delta` mode) deviates from what it
//! advertises. The rows committed today carry this repo's \[run\] evidence; the probe (phase 3)
//! regenerates them and fills the `advertise` lists.

use crate::capability::{Answer, Capability, DECRYPT_OAEP, Move, On, Row, Rows, UNWRAP_TEMPLATE, WRAP_OAEP};
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
    /// Curves in `can` that generate only when `CKA_EC_PARAMS` names them (PKCS#11 3.0's
    /// `PrintableString` form), never by OID: ykcs11's Edwards and Montgomery curves \[src\].
    pub by_name: Vec<String>,
}

/// A layer's numeric restriction, intersected with every other layer's (D3): swtpm refuses
/// 4096-bit RSA generation, whatever tpm2-pkcs11's module profile says.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Restrict {
    /// What the restriction applies to; only "generate" exists today.
    pub operation: String,
    /// The key type it restricts (`key-type`).
    #[serde(rename = "key-type")]
    pub key_type: String,
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
            subtract: Subtract::default(),
            add: Vec::new(),
            capabilities: BTreeMap::new(),
            reported: BTreeMap::new(),
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

    /// The profile's family: `softhsm/2.7` -> `softhsm`, what a keys.toml `provider` names.
    #[must_use]
    pub fn family(&self) -> &str {
        self.profile.split('/').next().unwrap_or(&self.profile)
    }

    /// The answer to `c`, if the profile has one.
    #[must_use]
    pub fn answer(&self, c: &Capability) -> Option<bool> {
        self.capabilities.get(c).map(|r| r.answer.yes())
    }

    /// What shows the answer to `c`: its row's evidence, else the note an older profile kept for
    /// it under `note` (the curve, or `"<key type> at <bits>"`).
    #[must_use]
    pub fn evidence(&self, c: &Capability, note: &str) -> Option<String> {
        self.capabilities.get(c).and_then(|r| r.evidence.clone()).or_else(|| self.notes.get(note).cloned())
    }

    /// Set the answer to `c`, with its evidence and how it succeeded.
    pub fn set(&mut self, c: Capability, answer: Answer, evidence: Option<String>, via: Option<String>) {
        self.capabilities.insert(c, Row { answer, evidence, via });
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

    /// The key types the profile says anything about generating.
    #[must_use]
    pub fn generation_key_types(&self) -> std::collections::BTreeSet<&str> {
        let rows = self.capabilities.keys().filter_map(|c| match c {
            Capability::Generate { key_type, .. } => Some(key_type.as_str()),
            _ => None,
        });
        rows.chain(self.reported.keys().map(String::as_str)).collect()
    }

    /// What it generates of `key_type`, as its rows and reported range say; `None` when it
    /// says nothing about the key type.
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
                // No secret-key generation row is written: a generation row reads sizes in bits.
                (On::Bytes(_), _) => {}
            }
        }
        any.then_some(row)
    }

    /// Record what the probe saw `key_type` generate: each curve or size as a row (`via =
    /// "by-name"` for the curves only their name generates), the reported range apart. `notes`
    /// gives a row its evidence, by the curve or by `"<key type> at <bits>"`.
    pub fn set_generation(&mut self, key_type: &str, row: &GenerateRow) {
        let generate = |on| Capability::Generate { key_type: key_type.to_owned(), on };
        for i in &row.can {
            let via = row.by_name.contains(i).then(|| "by-name".to_owned());
            self.set(generate(On::Item(i.clone())), Answer::Yes, None, via);
        }
        for i in &row.cannot {
            self.set(generate(On::Item(i.clone())), Answer::No, None, None);
        }
        for b in &row.can_bits {
            self.set(generate(On::Bits(*b)), Answer::Yes, None, None);
        }
        for b in &row.cannot_bits {
            self.set(generate(On::Bits(*b)), Answer::No, None, None);
        }
        if row.min_bits.is_some() || row.max_bits.is_some() {
            self.reported.insert(key_type.to_owned(), Reported { min_bits: row.min_bits, max_bits: row.max_bits });
        }
    }
}
