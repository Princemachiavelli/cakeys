//! The capability-profile emitter (docs/CAPROBE.md): a profile as the committed TOML. Only
//! `caprobe` writes profiles; `cakeys` reads them (`cakeys_profile`).

use cakeys_profile::profile::{AcceptRow, MatchInfo, Mode, Profile, Reported};
use cakeys_profile::{Capability, Row};
use std::collections::BTreeMap;

/// A TOML basic-string body for `s`: quotes, backslashes and control characters escaped.
/// Module-supplied text must land in the file as parseable TOML that reads back identically —
/// a fixed-width field a module pads with NULs (tpm2-pkcs11's token model, \[run\]) would
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

/// The `[capabilities]` section for [`profile`]: one inline row per capability, in its order.
fn capabilities_toml(rows: &BTreeMap<Capability, Row>, s: &mut String) {
    use std::fmt::Write as _;
    if rows.is_empty() {
        return;
    }
    let _ = writeln!(s, "\n[capabilities]");
    for (c, r) in rows {
        let _ = write!(s, "\"{}\" = {{ answer = \"{}\"", toml_str(&c.to_string()), r.answer.name());
        if let Some(v) = &r.via {
            let _ = write!(s, ", via = \"{}\"", toml_str(v));
        }
        if let Some(e) = &r.evidence {
            let _ = write!(s, ", evidence = \"{}\"", toml_str(e));
        }
        let _ = writeln!(s, " }}");
    }
}

/// The `[reported.<key type>]` sections for [`profile`]: the sizes the module reports.
fn reported_toml(reported: &BTreeMap<String, Reported>, s: &mut String) {
    use std::fmt::Write as _;
    for (kt, r) in reported {
        let _ = writeln!(s, "\n[reported.\"{}\"]", toml_str(kt));
        if let Some(b) = r.min_bits {
            let _ = writeln!(s, "min-bits = {b}");
        }
        if let Some(b) = r.max_bits {
            let _ = writeln!(s, "max-bits = {b}");
        }
    }
}

/// The subtract section for [`profile`], only when non-empty.
fn filters_toml(p: &Profile, s: &mut String) {
    use std::fmt::Write as _;
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
/// from — never edited by hand (docs/CAPROBE.md: the conformance test re-probes the
/// reference tokens and compares on every build). The two sections the probe does not
/// generate are preserved by it across regenerations: `[migration]`, this repo's claims
/// (docs/CAMIGRATE.md evidence), and `[manual]`, what people found by hand.
#[must_use]
pub(crate) fn profile(p: &Profile) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# Generated by `caprobe probe` (docs/CAPROBE.md). Never edit: regenerate\n\
             # with `caprobe probe --token <t> --write --diff <profile> --out <this file>`; the\n\
             # conformance test re-probes and compares on every build. A profile is what the\n\
             # probe measured: this module on this token's hardware, together. Only [migration],\n\
             # the move.* capabilities and [manual] are not probe output: this repo's claims and\n\
             # hand findings, preserved across regenerations."
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
    if p.requires_provider {
        let _ = writeln!(s, "requires-provider = true");
    }
    if p.partial {
        let _ = writeln!(s, "partial = true");
    }
    if !p.advertise.is_empty() {
        let _ = writeln!(s, "{}", toml_array("advertise", &p.advertise));
    }
    if !p.add.is_empty() {
        let _ = writeln!(s, "{}", toml_array("add", &p.add));
    }
    match_toml(&p.r#match, &mut s);
    filters_toml(p, &mut s);
    capabilities_toml(&p.capabilities, &mut s);
    reported_toml(&p.reported, &mut s);
    if let Some(m) = &p.migration {
        let _ = writeln!(s, "\n[migration]");
        if let Some(k) = m.plaintext_import {
            let _ = writeln!(s, "plaintext-import = \"{}\"", k.name());
        }
        for row in &m.public_accepts {
            accept_toml(&mut s, "public-accepts", row, false);
        }
        for row in &m.plaintext_accepts {
            accept_toml(&mut s, "plaintext-accepts", row, true);
        }
        for row in &m.refuses {
            accept_toml(&mut s, "refuses", row, true);
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
        let text = "profile = \"t\"\nmode = \"observed\"\n\n[capabilities]\n\
                    \"decrypt.rsa-oaep.SHA-1\" = { answer = \"no\", evidence = \"CKR_ARGUMENTS_BAD\" }\n\
                    \"derive.ecdh.sealed\" = { answer = \"no\" }\n\"derive.ecdh.read-only\" = { answer = \"yes\" }\n\
                    \"generate.CKK_EC_EDWARDS.edwards25519\" = { answer = \"yes\", via = \"by-name\" }\n\
                    \"generate.CKK_RSA.2048\" = { answer = \"yes\" }\n\"move.trusted-wrap\" = { answer = \"no\" }\n\n\
                    [reported.\"CKK_RSA\"]\nmin-bits = 1024\nmax-bits = 4096\n\n\
                    [manual.\"fips\"]\nfinding = \"approved mode \\\"on\\\"\"\nevidence = \"[run] ykman piv info\"\n";
        let profile = Profile::from_toml(text).unwrap();
        assert_eq!(profile.decrypt_oaep(), Some(Vec::new()), "probed and empty, not absent");
        assert_eq!(profile.answer(&Capability::DeriveSealed), Some(false));
        assert_eq!(profile.answer(&Capability::DeriveReadOnly), Some(true));
        let ed = profile.generation("CKK_EC_EDWARDS").unwrap();
        assert_eq!((ed.can, ed.by_name), (vec!["edwards25519".to_owned()], vec!["edwards25519".to_owned()]));
        let rsa = profile.generation("CKK_RSA").unwrap();
        assert_eq!((rsa.can_bits, rsa.min_bits, rsa.max_bits), (vec![2048], Some(1024), Some(4096)));
        assert_eq!(profile.moves(cakeys_profile::Move::TrustedWrap), Some(false));
        assert_eq!(profile.manual["fips"].evidence, "[run] ykman piv info");
        let emitted = super::profile(&profile);
        assert!(emitted.contains("\"decrypt.rsa-oaep.SHA-1\" = { answer = \"no\", evidence = \"CKR_ARGUMENTS_BAD\" }"));
        assert_eq!(Profile::from_toml(&emitted).unwrap(), profile);
        // A hand finding without its evidence is no finding; a row naming no capability, none.
        assert!(Profile::from_toml("profile = \"t\"\nmode = \"observed\"\n[manual.x]\nfinding = \"y\"\n").is_err());
        let unknown = "profile = \"t\"\nmode = \"observed\"\n[capabilities]\n\"wrap.SHA-1\" = { answer = \"yes\" }\n";
        assert!(Profile::from_toml(unknown).unwrap_err().contains("names no capability"));
    }

    /// A layer and a hand-kept module profile round-trip with every row they can carry: a
    /// layer's subtractions and note, the flags, each plaintext-import kind, and restrictions.
    #[test]
    fn layers_flags_and_restrictions_round_trip() {
        let layer = "profile = \"l/1\"\nmode = \"delta\"\nrequires-provider = true\n\n\
                     [subtract]\nmechanisms = [\"CKM_EDDSA\"]\nkey-types = [\"CKK_SHA512_HMAC\"]\nnote = \"dropped by the layer\"\n";
        let layer = Profile::from_toml(layer).unwrap();
        assert_eq!(Profile::from_toml(&super::profile(&layer)).unwrap(), layer);
        // A provider's stand-ins the probe found working: `add`, beside the advertisement.
        let added = Profile::from_toml(
            "profile = \"m/1\"\nmode = \"observed\"\nadvertise = [\"CKM_EC_KEY_PAIR_GEN\"]\n\
             add = [\"CKM_EC_EDWARDS_KEY_PAIR_GEN\", \"CKM_EDDSA\"]\n",
        )
        .unwrap();
        assert_eq!(Profile::from_toml(&super::profile(&added)).unwrap(), added);
        for kind in ["create-object", "tpm2-ptool", "piv-import"] {
            let text = format!(
                "profile = \"m/1\"\nmode = \"observed\"\npartial = true\n\n[migration]\nplaintext-import = \"{kind}\"\n\n\
                 [[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\nmin-bits = 2048\nmax-bits = 4096\nnote = \"by firmware\"\n"
            );
            let module = Profile::from_toml(&text).unwrap();
            assert_eq!(Profile::from_toml(&super::profile(&module)).unwrap(), module, "{kind}");
        }
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

    /// Probed with every answer no survives the emitter as that, not as never probed.
    #[test]
    fn probed_empty_is_not_unprobed() {
        let none = Profile::from_toml(
            "profile = \"m/1\"\nmode = \"observed\"\n[capabilities]\n\
             \"wrap.rsa-oaep.SHA-1\" = { answer = \"no\" }\n\"wrap.rsa-oaep.SHA-256\" = { answer = \"no\" }\n",
        )
        .unwrap();
        assert_eq!(Profile::from_toml(&super::profile(&none)).unwrap().wrap_oaep(), Some(Vec::new()));
        let unprobed = Profile::from_toml("profile = \"m/1\"\nmode = \"observed\"\n").unwrap();
        assert_eq!(Profile::from_toml(&super::profile(&unprobed)).unwrap().wrap_oaep(), None);
    }
}
