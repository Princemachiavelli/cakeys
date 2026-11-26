//! The capability-profile emitter (docs/CAPROBE.md) writes a profile as the committed TOML. Only
//! `caprobe` writes profiles, and `cakeys` reads them (`cakeys_profile`).

use cakeys_profile::profile::{AcceptRow, MatchInfo, Mode, Profile, Reported};
use cakeys_profile::{Capability, Row};
use std::collections::BTreeMap;

/// Returns the body of a TOML basic string for `s`, with quotes, backslashes and control
/// characters escaped. Text that a module supplies must reach the file as TOML that parses and
/// reads back identically. Without the escapes, a fixed-width field that a module pads with NUL
/// bytes (the token model of tpm2-pkcs11, \[run\]) would make the committed profile
/// unparsable.
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

/// Returns a TOML array `key = [...]` of escaped strings, laid out as the repository's formatter
/// (taplo in treefmt.nix, at 120 columns) lays it out, so that `nix fmt` leaves a generated
/// profile unchanged byte for byte. The array is on one line when it fits, and otherwise it has
/// one item on each line with a trailing comma.
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

/// Writes one `[[migration.*]]` row for [`profile`], with every field that the parser reads,
/// including the bit bounds (emit.rs F1: a `public-accepts` row lost its bounds).
fn accept_toml(s: &mut String, what: &str, row: &AcceptRow) {
    use std::fmt::Write as _;
    let _ = writeln!(s, "\n[[migration.{what}]]");
    let _ = write!(s, "class = \"{}\"", toml_str(&row.class));
    if !row.key_types.is_empty() {
        let _ = write!(s, "\n{}", toml_array("key-types", &row.key_types));
    }
    if !row.curves.is_empty() {
        let _ = write!(s, "\n{}", toml_array("curves", &row.curves));
    }
    if let Some(b) = row.min_bits {
        let _ = write!(s, "\nmin-bits = {b}");
    }
    if let Some(b) = row.max_bits {
        let _ = write!(s, "\nmax-bits = {b}");
    }
    let _ = writeln!(s);
}

/// Writes the `[match]` section for [`profile`], when the section has any key.
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

/// Writes the `[capabilities]` section for [`profile`]: one inline row for each capability, in
/// the order of the capabilities.
fn capabilities_toml(rows: &BTreeMap<Capability, Row>, s: &mut String) {
    use std::fmt::Write as _;
    if rows.is_empty() {
        return;
    }
    let _ = writeln!(s, "\n[capabilities]");
    for (c, r) in rows {
        let _ = write!(s, "\"{}\" = {{ answer = \"{}\"", toml_str(&c.to_string()), r.answer.name());
        if let Some(by) = r.by {
            let _ = write!(s, ", by = \"{}\"", by.name());
        }
        if let Some(v) = &r.via {
            let _ = write!(s, ", via = \"{}\"", toml_str(v));
        }
        if let Some(e) = &r.evidence {
            let _ = write!(s, ", evidence = \"{}\"", toml_str(e));
        }
        let _ = writeln!(s, " }}");
    }
}

/// Writes the `[reported.<key type>]` sections for [`profile`]: the key sizes that the module
/// reports.
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

/// Writes the subtract section for [`profile`], only when the section is not empty. A section
/// with only a note is not empty (emit.rs F1).
fn filters_toml(p: &Profile, s: &mut String) {
    use std::fmt::Write as _;
    if !p.subtract.mechanisms.is_empty() || !p.subtract.key_types.is_empty() || p.subtract.note.is_some() {
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

/// Returns the profile as TOML in the committed format, with only its non-empty sections. This
/// is the text that the probe writes, that `--out` prints, and that the committed module
/// profiles are regenerated as. profiles/LEDGER.toml says for each file whether a build
/// re-probes it and how it is regenerated. The header names the ledger and claims neither of
/// those things (review 2026-11-24 E-7). The emitter also writes the two sections that the
/// probe does not generate, so that they are kept across regenerations: `[migration]`, which
/// holds this repository's claims (the docs/CAMIGRATE.md evidence), and `[manual]`, which holds
/// what people found by hand.
#[must_use]
pub(crate) fn profile(p: &Profile) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# Generated by `caprobe probe` (docs/CAPROBE.md): what the probe measured, this module\n\
             # on this token's hardware together. Regenerate it with `caprobe regenerate`, not by hand.\n\
             # profiles/LEDGER.toml names the command and whether a build re-probes this file; if\n\
             # none does, the run it was last probed in and every hand edit since, which\n\
             # nix/ledger.py holds to the file and to the code on its path. Only [migration], the\n\
             # move.* capabilities and [manual] are not probe output: this repo's claims and hand\n\
             # findings, preserved across regenerations."
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
    untested_toml(p, &mut s);
    match_toml(&p.r#match, &mut s);
    filters_toml(p, &mut s);
    capabilities_toml(&p.capabilities, &mut s);
    reported_toml(&p.reported, &mut s);
    reported_claims_toml(p, &mut s);
    if let Some(m) = &p.migration {
        let _ = writeln!(s, "\n[migration]");
        if let Some(k) = m.plaintext_import {
            let _ = writeln!(s, "plaintext-import = \"{}\"", k.name());
        }
        for row in &m.public_accepts {
            accept_toml(&mut s, "public-accepts", row);
        }
        for row in &m.plaintext_accepts {
            accept_toml(&mut s, "plaintext-accepts", row);
        }
        for row in &m.refuses {
            accept_toml(&mut s, "refuses", row);
        }
    }
    for r in &p.restrict {
        let _ = writeln!(s, "\n[[restrict]]");
        let _ = writeln!(s, "operation = \"{}\"", toml_str(&r.operation));
        let _ = writeln!(s, "key-type = \"{}\"", toml_str(r.key_type.name()));
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

/// Writes `[untested]`: each advertised mechanism that the probe did not measure, and why.
fn untested_toml(p: &Profile, s: &mut String) {
    use std::fmt::Write as _;
    if p.untested.is_empty() {
        return;
    }
    let _ = writeln!(s, "\n[untested]");
    for (name, u) in &p.untested {
        let note = u.note.as_ref().map(|n| format!(", note = \"{}\"", toml_str(n))).unwrap_or_default();
        let _ = writeln!(s, "\"{}\" = {{ why = \"{}\"{note} }}", toml_str(name), u.why.name());
    }
}

/// Writes `[mechanism-info]` and `[claims]`: what the module reports about itself. These
/// sections are never compared.
fn reported_claims_toml(p: &Profile, s: &mut String) {
    use std::fmt::Write as _;
    if !p.mechanism_info.is_empty() {
        let _ = writeln!(s, "\n[mechanism-info]");
        for (name, i) in &p.mechanism_info {
            let flags: Vec<String> = i.flags.iter().map(|f| format!("\"{}\"", toml_str(f))).collect();
            let _ = writeln!(
                s,
                "\"{}\" = {{ min = {}, max = {}, flags = [{}] }}",
                toml_str(name),
                i.min,
                i.max,
                flags.join(", ")
            );
        }
    }
    if !p.claims.is_empty() {
        let _ = writeln!(s, "\n[claims]");
        for (k, v) in &p.claims {
            let _ = writeln!(s, "\"{}\" = \"{}\"", toml_str(k), toml_str(v));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every committed module profile is byte for byte what the emitter writes for it. This
    /// includes the profiles of hardware modules, which no test re-probes. The hand-written
    /// layers and hardware profiles have comments, so for them the test checks only that they
    /// parse to the same profile after they are emitted. A change to how rows are typed,
    /// ordered or written that would rewrite a profile fails here, not at the next
    /// regeneration.
    #[test]
    fn every_committed_profile_is_what_the_emitter_writes() {
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles"));
        for dir in ["layers", "hardware"] {
            for entry in std::fs::read_dir(root.join(dir)).unwrap() {
                let path = entry.unwrap().path();
                let read = Profile::from_toml(&std::fs::read_to_string(&path).unwrap()).unwrap();
                assert_eq!(Profile::from_toml(&super::profile(&read)).unwrap(), read, "{}", path.display());
            }
        }
        let mut files = Vec::new();
        for family in std::fs::read_dir(root.join("modules")).unwrap() {
            for entry in std::fs::read_dir(family.unwrap().path()).unwrap() {
                files.push(entry.unwrap().path());
            }
        }
        files.sort();
        assert!(files.len() >= 9, "{files:?}");
        let differ: Vec<String> = files
            .iter()
            .filter(|path| {
                let text = std::fs::read_to_string(path).unwrap();
                super::profile(&Profile::from_toml(&text).unwrap()) != text
            })
            .map(|path| path.display().to_string())
            .collect();
        assert_eq!(differ, [] as [String; 0]);
    }

    /// The header that every profile carries makes no claim about the file (review 2026-11-24
    /// E-7, E-8). It does not claim a re-probe, which only some profiles get, and it does not
    /// list regeneration flags, which belong to the command that it names
    /// (`caprobe regenerate`). The header names the ledger, which says both things for each
    /// file, and the ledger has an entry for every committed module profile.
    #[test]
    fn the_header_names_the_ledger_and_claims_nothing_else() {
        let text = super::profile(&Profile::from_toml("profile = \"m/1\"\nmode = \"observed\"\n").unwrap());
        let header: Vec<&str> = text.lines().take_while(|l| l.starts_with('#')).collect();
        let header = header.join("\n");
        assert!(header.contains("profiles/LEDGER.toml") && header.contains("`caprobe regenerate`"), "{header}");
        let claims =
            ["Never edit", "every build", "re-probes and compares", "conformance test", "--rsa-max-bits", "--out"];
        for claim in claims {
            assert!(!header.contains(claim), "the header says `{claim}`:\n{header}");
        }
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
        let ledger = std::fs::read_to_string(root.join("profiles/LEDGER.toml")).unwrap();
        for family in std::fs::read_dir(root.join("profiles/modules")).unwrap() {
            for entry in std::fs::read_dir(family.unwrap().path()).unwrap() {
                let path = entry.unwrap().path();
                let rel = path.strip_prefix(root).unwrap().display().to_string();
                assert!(ledger.contains(&format!("path = \"{rel}\"")), "profiles/LEDGER.toml has no entry for {rel}");
            }
        }
    }

    /// The closing check (`docs/archive/CAPROBE_PROFILE_COVERAGE.md`, Part 0). The `[untested]`
    /// table of a committed module profile names no mechanism that the module does not
    /// advertise, that a row measures, or that the module was found to refuse. The profiles
    /// that were regenerated for the coverage plan each have the table, because an advertised
    /// mechanism with neither a row nor an entry is a mechanism that no one recorded.
    /// docs/OPEN.md lists the profiles that the check does not yet cover.
    #[test]
    fn untested_entries_are_consistent_and_the_regenerated_profiles_have_them() {
        let root = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles/modules"));
        let mut have = Vec::new();
        for family in std::fs::read_dir(root).unwrap() {
            for entry in std::fs::read_dir(family.unwrap().path()).unwrap() {
                let path = entry.unwrap().path();
                let p = Profile::from_toml(&std::fs::read_to_string(&path).unwrap()).unwrap();
                assert_eq!(p.untested_problems(), Vec::<String>::new(), "{}", path.display());
                if !p.untested.is_empty() {
                    have.push(p.profile.clone());
                }
            }
        }
        for name in ["softhsm/2.7", "kryoptic/1.5", "tpm2-pkcs11/1.10+swtpm"] {
            assert!(have.iter().any(|h| h == name), "{name} records no [untested]: regenerate it; have {have:?}");
        }
    }

    #[test]
    fn emitting_and_parsing_round_trips_module_supplied_text() {
        let mut profile = Profile::from_toml("profile = \"t\"\nmode = \"observed\"\n").unwrap();
        // This text has every kind of character that a module's fixed-width fields or error
        // messages can carry: the NUL padding of a C string, embedded quotes, a backslash, and a
        // control byte. None of them may corrupt the committed TOML (the NUL-padded token model
        // of tpm2-pkcs11 once made the embedded set unparsable [run]).
        let nasty = "SW\u{0}\u{0}\u{0}TPM \"model's\" \\ \u{1}firm\u{0}ware \u{7f}";
        profile.notes.insert("token".into(), nasty.to_owned());
        let text = super::profile(&profile);
        let back = Profile::from_toml(&text).unwrap();
        assert_eq!(back.notes.get("token"), Some(&nasty.to_owned()));
        // The emitter never writes a raw control byte, whatever the text is.
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
        // A hand finding without its evidence is not a finding, and a row that names no
        // capability is not a row.
        assert!(Profile::from_toml("profile = \"t\"\nmode = \"observed\"\n[manual.x]\nfinding = \"y\"\n").is_err());
        let unknown = "profile = \"t\"\nmode = \"observed\"\n[capabilities]\n\"wrap.SHA-1\" = { answer = \"yes\" }\n";
        assert!(Profile::from_toml(unknown).unwrap_err().contains("names no capability"));
    }

    /// A layer and a hand-kept module profile round-trip with every row that they can carry: a
    /// layer's subtractions and note, the flags, each kind of plaintext import, and the
    /// restrictions.
    #[test]
    fn layers_flags_and_restrictions_round_trip() {
        let layer = "profile = \"l/1\"\nmode = \"delta\"\nrequires-provider = true\n\n\
                     [subtract]\nmechanisms = [\"CKM_EDDSA\"]\nkey-types = [\"CKK_SHA512_HMAC\"]\nnote = \"dropped by the layer\"\n";
        let layer = Profile::from_toml(layer).unwrap();
        assert_eq!(Profile::from_toml(&super::profile(&layer)).unwrap(), layer);
        // The `add` list holds a provider's stand-ins that the probe found working, beside the
        // advertisement.
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
        // The layout matches taplo at 120 columns (treefmt.nix). `nix fmt` must leave a
        // generated profile unchanged, or the byte comparison of the conformance test fails
        // after formatting.
        assert_eq!(toml_array("oaep", &["SHA-1".into()]), "oaep = [\"SHA-1\"]");
        let long: Vec<String> = (0..12).map(|i| format!("CKM_MECHANISM_{i:02}")).collect();
        let text = toml_array("advertise", &long);
        assert!(text.starts_with("advertise = [\n  \"CKM_MECHANISM_00\",\n"));
        assert!(text.ends_with("  \"CKM_MECHANISM_11\",\n]"));
        assert!(text.lines().all(|l| l.len() <= 120));
    }

    /// Every optional field that the parser reads passes the fuzz target's round trip when it is
    /// set alone, with no other field that would make the emitter write its section anyway. A
    /// field that the emitter writes only beside another field is lost (emit.rs F1: a
    /// `[subtract]` note alone, and the bits of a `public-accepts` row). A field that is added to
    /// the parser must be added to this test.
    #[test]
    fn every_optional_field_alone_round_trips() {
        let head = "profile = \"m/1\"\nmode = \"observed\"\n";
        let accepts = |table: &str| {
            [
                format!("[migration]\n[[migration.{table}]]\nclass = \"CKO_PRIVATE_KEY\"\n"),
                format!("[migration]\n[[migration.{table}]]\nclass = \"CKO_PRIVATE_KEY\"\nkey-types = [\"CKK_EC\"]\n"),
                format!("[migration]\n[[migration.{table}]]\nclass = \"CKO_PRIVATE_KEY\"\ncurves = [\"secp256r1\"]\n"),
                format!("[migration]\n[[migration.{table}]]\nclass = \"CKO_PRIVATE_KEY\"\nmin-bits = 2048\n"),
                format!("[migration]\n[[migration.{table}]]\nclass = \"CKO_PRIVATE_KEY\"\nmax-bits = 4096\n"),
            ]
        };
        let mut bodies: Vec<String> = [
            "partial = true\n",
            "requires-provider = true\n",
            "advertise = [\"CKM_EC_KEY_PAIR_GEN\"]\n",
            "add = [\"CKM_EDDSA\"]\n",
            "[match]\nmanufacturer = \"m\"\n",
            "[match]\nmodule-version = \"1.0\"\n",
            "[match]\nmodel = \"x\"\n",
            "[match]\nfirmware = \"2\"\n",
            "[subtract]\nmechanisms = [\"CKM_EDDSA\"]\n",
            "[subtract]\nkey-types = [\"CKK_EC\"]\n",
            "[subtract]\nnote = \"why\"\n",
            "[capabilities]\n\"derive.ecdh.sealed\" = { answer = \"no\" }\n",
            // The provenance fields (review 2026-11-24 E-2 to E-4).
            "[capabilities]\n\"derive.ecdh.sealed\" = { answer = \"no\", by = \"module\" }\n",
            "[untested]\n\"derive.ecdh.sealed\" = { why = \"device\", note = \"CKR_GENERAL_ERROR\" }\n",
            "[reported.\"CKK_RSA\"]\nmin-bits = 1024\n",
            "[reported.\"CKK_RSA\"]\nmax-bits = 4096\n",
            "[migration]\n",
            "[migration]\nplaintext-import = \"create-object\"\n",
            "[[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\n",
            "[[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\nmin-bits = 2048\n",
            "[[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\nmax-bits = 4096\n",
            "[[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\nnote = \"by firmware\"\n",
            "[notes]\ntoken = \"t\"\n",
            "[manual.x]\nfinding = \"y\"\nevidence = \"[run] z\"\n",
            // The fields that were added with the coverage plan (review 2026-11-23 D-20).
            "[untested]\n\"CKM_SHA256\" = { why = \"scope\" }\n",
            "[untested]\n\"CKM_SHA256\" = { why = \"scope\", note = \"on the host\" }\n",
            "[mechanism-info]\n\"CKM_AES_CBC\" = { min = 16, max = 32, flags = [] }\n",
            "[mechanism-info]\n\"CKM_AES_CBC\" = { min = 16, max = 32, flags = [\"encrypt\"] }\n",
            "[claims]\n\"interface\" = \"Cryptoki 3.2\"\n",
        ]
        .map(str::to_owned)
        .into();
        for table in ["public-accepts", "plaintext-accepts", "refuses"] {
            bodies.extend(accepts(table));
        }
        for body in bodies {
            let text = format!("{head}{body}");
            let parsed = Profile::from_toml(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
            assert_ne!(parsed, Profile::from_toml(head).unwrap(), "the field is not read:\n{text}");
            crate::fuzzing::profile_round_trip(&text);
        }
    }

    /// A profile in which every probed answer is no keeps that meaning after the emitter writes
    /// it, and does not turn into a profile that was never probed.
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
