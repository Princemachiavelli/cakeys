//! The capability-profile emitter (docs/PROVIDERS.md): a profile as the committed TOML. Only
//! `caprobe` writes profiles; `cakeys` reads them (`cakeys_profile`).

use cakeys_profile::profile::{AcceptRow, GenerateRow, MatchInfo, Mode, PlaintextKind, Profile};
use std::collections::BTreeMap;

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

/// One `[[migration.*-accepts]]` entry for [`profile`], with its bits when it has
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

/// The `[match]` section for [`profile`], when it has any key.
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

/// The `[generate.<key type>]` sections for [`profile`], each with its non-empty rows.
fn generate_toml(generate: &BTreeMap<String, GenerateRow>, s: &mut String) {
    use std::fmt::Write as _;
    for (kt, row) in generate {
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
        if !row.by_name.is_empty() {
            let _ = writeln!(s, "{}", toml_array("by-name", &row.by_name));
        }
    }
}

/// The wrap, unwrap and subtract sections for [`profile`]: the probed rows even when
/// empty (probed, none — distinct from never probed), the subtraction only when non-empty.
fn filters_toml(p: &Profile, s: &mut String) {
    use std::fmt::Write as _;
    if let Some(oaep) = &p.wrap.oaep {
        let _ = writeln!(s, "\n[wrap]\n{}", toml_array("oaep", oaep));
    }
    if let Some(refuse) = &p.unwrap.refuse {
        let _ = writeln!(s, "\n[unwrap]\n{}", toml_array("refuse", refuse));
    }
    if let Some(oaep) = &p.decrypt.oaep {
        let _ = writeln!(s, "\n[decrypt]\n{}", toml_array("oaep", oaep));
    }
    let rows =
        [("sealed", p.derive.sealed), ("key-attribute", p.derive.key_attribute), ("read-only", p.derive.read_only)];
    if rows.iter().any(|(_, v)| v.is_some()) {
        let _ = writeln!(s, "\n[derive]");
        for (k, v) in rows {
            if let Some(v) = v {
                let _ = writeln!(s, "{k} = {v}");
            }
        }
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

/// Emit the profile as TOML, the committed format with only its non-empty sections: what
/// the probe writes, `--out` prints, and the committed module profiles are regenerated
/// from — never edited by hand (docs/PROVIDERS.md: the conformance test re-probes the
/// reference tokens and compares on every build). The two sections the probe does not
/// generate are preserved by it across regenerations: `[migration]`, this repo's claims
/// (MIGRATE.md evidence), and `[manual]`, what people found by hand.
#[must_use]
pub fn profile(p: &Profile) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# Generated by `caprobe probe` (docs/PROVIDERS.md phase 3). Never edit: regenerate\n\
             # with `caprobe probe --token <t> --write --diff <profile> --out <this file>`; the\n\
             # conformance test re-probes and compares on every build. A profile is what the\n\
             # probe measured: this module on this token's hardware, together. Only [migration]\n\
             # and [manual] are not probe output: this repo's claims and hand findings,\n\
             # preserved across regenerations."
    );
    let _ = writeln!(s, "profile = \"{}\"", toml_str(&p.profile));
    let _ = writeln!(
        s,
        "mode = \"{}\"",
        match p.mode {
            Mode::Observed => "observed",
            Mode::Delta => "delta",
        }
    );
    if p.partial {
        let _ = writeln!(s, "partial = true");
    }
    if !p.advertise.is_empty() {
        let _ = writeln!(s, "{}", toml_array("advertise", &p.advertise));
    }
    match_toml(&p.r#match, &mut s);
    filters_toml(p, &mut s);
    generate_toml(&p.generate, &mut s);
    if let Some(m) = &p.migration {
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
    for r in &p.restrict {
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
    if !p.notes.is_empty() {
        let _ = writeln!(s, "\n[notes]");
        for (k, v) in &p.notes {
            let _ = writeln!(s, "\"{}\" = \"{}\"", toml_str(k), toml_str(v));
        }
    }
    for (k, m) in &p.manual {
        let _ = writeln!(s, "\n[manual.\"{}\"]", toml_str(k));
        let _ = writeln!(s, "finding = \"{}\"", toml_str(&m.finding));
        let _ = writeln!(s, "evidence = \"{}\"", toml_str(&m.evidence));
    }
    s
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
        let text = super::profile(&profile);
        let back = Profile::from_toml(&text).unwrap();
        assert_eq!(back.notes.get("token"), Some(&nasty.to_owned()));
        // And the emitter never writes a raw control byte, whatever the text.
        assert!(!text.bytes().any(|b| b < 0x20 && b != b'\n' && b != b'\t'));
    }

    #[test]
    fn every_probed_and_hand_row_round_trips() {
        let text = "profile = \"t\"\nmode = \"observed\"\n\n[decrypt]\noaep = []\n\n[derive]\nsealed = false\nkey-attribute = false\nread-only = true\n\n\
                    [generate.\"CKK_EC_EDWARDS\"]\ncan = [\"edwards25519\"]\nby-name = [\"edwards25519\"]\n\n\
                    [manual.\"fips\"]\nfinding = \"approved mode \\\"on\\\"\"\nevidence = \"[run] ykman piv info\"\n";
        let profile = Profile::from_toml(text).unwrap();
        assert_eq!(profile.decrypt.oaep, Some(Vec::new()), "probed and empty, not absent");
        assert_eq!(profile.derive.sealed, Some(false));
        assert_eq!(profile.derive.key_attribute, Some(false));
        assert_eq!(profile.derive.read_only, Some(true));
        assert_eq!(profile.generate["CKK_EC_EDWARDS"].by_name, ["edwards25519"]);
        assert_eq!(profile.manual["fips"].evidence, "[run] ykman piv info");
        assert_eq!(Profile::from_toml(&super::profile(&profile)).unwrap(), profile);
        // A hand finding without its evidence is no finding.
        assert!(Profile::from_toml("profile = \"t\"\nmode = \"observed\"\n[manual.x]\nfinding = \"y\"\n").is_err());
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

    /// A probed-empty row (`oaep = []`) survives the emitter; an absent one stays absent.
    #[test]
    fn probed_empty_is_not_unprobed() {
        let none = Profile::from_toml("profile = \"m/1\"\nmode = \"observed\"\n[wrap]\noaep = []\n").unwrap();
        assert_eq!(Profile::from_toml(&super::profile(&none)).unwrap().wrap.oaep, Some(Vec::new()));
        let unprobed = Profile::from_toml("profile = \"m/1\"\nmode = \"observed\"\n").unwrap();
        assert_eq!(Profile::from_toml(&super::profile(&unprobed)).unwrap().wrap.oaep, None);
    }
}
