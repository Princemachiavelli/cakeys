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
    /// How the module moves keys (MIGRATE.md), when it deviates from a spec-compliant module.
    #[serde(default)]
    pub migration: Option<Migration>,
    #[serde(default)]
    pub restrict: Vec<Restrict>,
    /// Freeform evidence, keyed by the name each note explains (shown in verdicts).
    #[serde(default)]
    pub notes: BTreeMap<String, String>,
}

/// A TOML basic-string body for `s`: quotes, backslashes and control characters escaped.
/// Module-supplied text must land in the file as parseable TOML that reads back identically —
/// a fixed-width field a module pads with NULs (tpm2-pkcs11's token model, [run]) would
/// otherwise make the committed profile unparsable.
fn toml_str(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04X}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}

/// A TOML array `key = [...]` of escaped strings, laid out the way the repo's formatter (taplo,
/// treefmt.nix: 120 columns) lays it out, so a generated profile survives `nix fmt` byte for byte:
/// on one line when it fits, else one item per line with a trailing comma.
fn toml_array(key: &str, items: &[String]) -> String {
    let items: Vec<String> = items.iter().map(|x| format!("\"{}\"", toml_str(x))).collect();
    let line = format!("{key} = [{}]", items.join(", "));
    if line.chars().count() <= 120 {
        return line;
    }
    let mut out = format!("{key} = [\n");
    for x in &items {
        out.push_str("  ");
        out.push_str(x);
        out.push_str(",\n");
    }
    out.push(']');
    out
}

/// One `[[migration.*-accepts]]` entry for [`Profile::to_toml`], with its bits when it has
/// them.
fn accept_toml(s: &mut String, what: &str, row: &AcceptRow, bits: bool) {
    use std::fmt::Write as _;
    let _ = writeln!(s, "\n[[migration.{what}]]");
    let _ = write!(s, "class = \"{}\"", toml_str(&row.class));
    if !row.key_types.is_empty() {
        let _ = write!(s, "\n{}", toml_array("key-types", &row.key_types));
    }
    if !row.curves.is_empty() {
        let _ = write!(s, "\n{}", toml_array("curves", &row.curves));
    }
    if bits && let Some(b) = row.min_bits {
        let _ = write!(s, "\nmin-bits = {b}");
    }
    if bits && let Some(b) = row.max_bits {
        let _ = write!(s, "\nmax-bits = {b}");
    }
    let _ = writeln!(s);
}

/// A TOML integer-array body.
fn bits_list(items: &[u32]) -> String {
    items.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
}

/// The `[match]` section for [`Profile::to_toml`], when it has any key.
fn match_toml(m: &MatchInfo, s: &mut String) {
    use std::fmt::Write as _;
    if m.manufacturer.is_none() && m.module_version.is_none() && m.model.is_none() && m.firmware.is_none() {
        return;
    }
    let _ = writeln!(s, "\n[match]");
    if let Some(x) = &m.manufacturer {
        let _ = writeln!(s, "manufacturer = \"{}\"", toml_str(x));
    }
    if let Some(v) = &m.module_version {
        let _ = writeln!(s, "module-version = \"{}\"", toml_str(v));
    }
    if let Some(v) = &m.model {
        let _ = writeln!(s, "model = \"{}\"", toml_str(v));
    }
    if let Some(v) = &m.firmware {
        let _ = writeln!(s, "firmware = \"{}\"", toml_str(v));
    }
}

/// The wrap, unwrap and subtract sections for [`Profile::to_toml`]: the probed rows even when
/// empty (probed, none — distinct from never probed), the subtraction only when non-empty.
fn filters_toml(p: &Profile, s: &mut String) {
    use std::fmt::Write as _;
    if let Some(oaep) = &p.wrap.oaep {
        let _ = writeln!(s, "\n[wrap]\n{}", toml_array("oaep", oaep));
    }
    if let Some(refuse) = &p.unwrap.refuse {
        let _ = writeln!(s, "\n[unwrap]\n{}", toml_array("refuse", refuse));
    }
    if !p.subtract.mechanisms.is_empty() || !p.subtract.key_types.is_empty() {
        let _ = writeln!(s, "\n[subtract]");
        if !p.subtract.mechanisms.is_empty() {
            let _ = writeln!(s, "{}", toml_array("mechanisms", &p.subtract.mechanisms));
        }
        if !p.subtract.key_types.is_empty() {
            let _ = writeln!(s, "{}", toml_array("key-types", &p.subtract.key_types));
        }
        if let Some(n) = &p.subtract.note {
            let _ = writeln!(s, "note = \"{}\"", toml_str(n));
        }
    }
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

    /// Emit the profile as TOML, the committed format with only its non-empty sections: what
    /// the probe writes, `--out` prints, and the committed module profiles are regenerated
    /// from — never edited by hand (docs/PROVIDERS.md: the conformance test re-probes the
    /// reference tokens and compares on every build). The one section the probe does not
    /// generate, `[migration]`, carries this repo's claims (MIGRATE.md evidence) and the
    /// probe preserves it across regenerations.
    #[must_use]
    pub fn to_toml(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(
            s,
            "# Generated by `cakeys probe` (docs/PROVIDERS.md phase 3). Never edit: regenerate\n\
             # with `cakeys probe --token <t> --write --diff <profile> --out <this file>`; the\n\
             # conformance test re-probes and compares on every build. A profile is what the\n\
             # probe measured: this module on this token's hardware, together. Only [migration]\n\
             # is not probe output: it is this repo's claims, preserved across regenerations."
        );
        let _ = writeln!(s, "profile = \"{}\"", toml_str(&self.profile));
        let _ = writeln!(
            s,
            "mode = \"{}\"",
            match self.mode {
                Mode::Observed => "observed",
                Mode::Delta => "delta",
            }
        );
        if self.partial {
            let _ = writeln!(s, "partial = true");
        }
        if !self.advertise.is_empty() {
            let _ = writeln!(s, "{}", toml_array("advertise", &self.advertise));
        }
        match_toml(&self.r#match, &mut s);
        filters_toml(self, &mut s);
        for (kt, row) in &self.generate {
            let _ = writeln!(s, "\n[generate.\"{}\"]", toml_str(kt));
            if !row.can.is_empty() {
                let _ = writeln!(s, "{}", toml_array("can", &row.can));
            }
            if !row.cannot.is_empty() {
                let _ = writeln!(s, "{}", toml_array("cannot", &row.cannot));
            }
            if let Some(b) = row.min_bits {
                let _ = writeln!(s, "min-bits = {b}");
            }
            if let Some(b) = row.max_bits {
                let _ = writeln!(s, "max-bits = {b}");
            }
            if !row.can_bits.is_empty() {
                let _ = writeln!(s, "can-bits = [{}]", bits_list(&row.can_bits));
            }
            if !row.cannot_bits.is_empty() {
                let _ = writeln!(s, "cannot-bits = [{}]", bits_list(&row.cannot_bits));
            }
        }
        if let Some(m) = &self.migration {
            let _ = writeln!(s, "\n[migration]");
            if let Some(b) = m.exports {
                let _ = writeln!(s, "exports = {b}");
            }
            if let Some(b) = m.unwraps {
                let _ = writeln!(s, "unwraps = {b}");
            }
            if let Some(k) = m.plaintext_import {
                let _ = writeln!(
                    s,
                    "plaintext-import = \"{}\"",
                    match k {
                        PlaintextKind::CreateObject => "create-object",
                        PlaintextKind::Tpm2Ptool => "tpm2-ptool",
                        PlaintextKind::PivImport => "piv-import",
                    }
                );
            }
            for row in &m.public_accepts {
                accept_toml(&mut s, "public-accepts", row, false);
            }
            for row in &m.plaintext_accepts {
                accept_toml(&mut s, "plaintext-accepts", row, true);
            }
        }
        for r in &self.restrict {
            let _ = writeln!(s, "\n[[restrict]]");
            let _ = writeln!(s, "operation = \"{}\"", toml_str(&r.operation));
            let _ = writeln!(s, "key-type = \"{}\"", toml_str(&r.key_type));
            if let Some(b) = r.min_bits {
                let _ = writeln!(s, "min-bits = {b}");
            }
            if let Some(b) = r.max_bits {
                let _ = writeln!(s, "max-bits = {b}");
            }
            if let Some(n) = &r.note {
                let _ = writeln!(s, "note = \"{}\"", toml_str(n));
            }
        }
        if !self.notes.is_empty() {
            let _ = writeln!(s, "\n[notes]");
            for (k, v) in &self.notes {
                let _ = writeln!(s, "\"{}\" = \"{}\"", toml_str(k), toml_str(v));
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emitting_and_parsing_round_trips_module_supplied_text() {
        let mut profile = Profile::from_toml("profile = \"t\"\nmode = \"observed\"\n").unwrap();
        // Every character a module's fixed-width fields or error messages can carry: the NUL
        // padding of a C string, embedded quotes, a backslash, and a control byte — none of
        // which may corrupt the committed TOML (tpm2-pkcs11's NUL-padded token model once
        // made the embedded set unparsable [run]).
        let nasty = "SW\u{0}\u{0}\u{0}TPM \"model's\" \\ \u{1}firm\u{0}ware \u{7f}";
        profile.notes.insert("token".into(), nasty.to_owned());
        let text = profile.to_toml();
        let back = Profile::from_toml(&text).unwrap();
        assert_eq!(back.notes.get("token"), Some(&nasty.to_owned()));
        // And the emitter never writes a raw control byte, whatever the text.
        assert!(!text.bytes().any(|b| b < 0x20 && b != b'\n' && b != b'\t'));
    }

    #[test]
    fn arrays_are_laid_out_as_the_formatter_would() {
        // taplo at 120 columns (treefmt.nix): a generated profile must survive `nix fmt`
        // unchanged, or the conformance test's byte comparison fails after formatting.
        assert_eq!(toml_array("oaep", &["SHA-1".into()]), "oaep = [\"SHA-1\"]");
        let long: Vec<String> = (0..12).map(|i| format!("CKM_MECHANISM_{i:02}")).collect();
        let text = toml_array("advertise", &long);
        assert!(text.starts_with("advertise = [\n  \"CKM_MECHANISM_00\",\n"));
        assert!(text.ends_with("  \"CKM_MECHANISM_11\",\n]"));
        assert!(text.lines().all(|l| l.len() <= 120));
    }
}
