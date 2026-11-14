//! The probe diff (docs/CAPROBE.md): what a generated profile observed against what
//! a claimed profile says, over the rows a probe can observe. Empty is conformance — the
//! shipped profile is what the module does; non-empty is drift, each line naming the row.

use cakeys_profile::{GenerateRow, Profile};
use std::collections::{BTreeMap, BTreeSet};

/// Compare the probe-observable rows of `generated` against `claimed`: one line per
/// difference, empty when the claimed profile is exactly what the probe observed.
///
/// Never compared: the profiles' names (the probe names by provider and expressed version, a
/// module that hides it names differently), `partial` (whether the probe has filled the rows
/// is not a claim), the notes and `[manual]` findings (human evidence), and the rows no probe
/// observes yet — the
/// migration rows and the layer subtractions (data until docs/CAMIGRATE.md phase 3
/// exercises them).
#[must_use]
pub fn diff(generated: &Profile, claimed: &Profile) -> Vec<String> {
    let mut out = read_only(generated, claimed);
    sets("subtract.mechanisms", &generated.subtract.mechanisms, &claimed.subtract.mechanisms, &mut out);
    probed("wrap.oaep", generated.wrap.oaep.as_deref(), claimed.wrap.oaep.as_deref(), &mut out);
    probed("unwrap.refuse", generated.unwrap.refuse.as_deref(), claimed.unwrap.refuse.as_deref(), &mut out);
    probed("decrypt.oaep", generated.decrypt.oaep.as_deref(), claimed.decrypt.oaep.as_deref(), &mut out);
    for (what, row) in [
        ("derive.sealed", (|p: &Profile| p.derive.sealed) as fn(&Profile) -> Option<bool>),
        ("derive.key-attribute", |p| p.derive.key_attribute),
        ("derive.read-only", |p| p.derive.read_only),
    ] {
        let shown = |p| row(p).map(|b| b.to_string());
        optional(what, shown(generated).as_ref(), shown(claimed).as_ref(), &mut out);
    }
    restrictions(generated, claimed, &mut out);
    for (kt, (g, c)) in rows(generated, claimed) {
        match (g, c) {
            (None, Some(_)) => out.push(format!("generate.{kt}: only claimed")),
            (Some(_), None) => out.push(format!("generate.{kt}: only observed")),
            (Some(g), Some(c)) => {
                sets(&format!("generate.{kt}.can"), &g.can, &c.can, &mut out);
                sets(&format!("generate.{kt}.cannot"), &g.cannot, &c.cannot, &mut out);
                let bits = |v: &[u32]| v.iter().map(u32::to_string).collect::<Vec<_>>();
                sets(&format!("generate.{kt}.can-bits"), &bits(&g.can_bits), &bits(&c.can_bits), &mut out);
                sets(&format!("generate.{kt}.cannot-bits"), &bits(&g.cannot_bits), &bits(&c.cannot_bits), &mut out);
                sets(&format!("generate.{kt}.by-name"), &g.by_name, &c.by_name, &mut out);
            }
            (None, None) => {}
        }
    }
    out.sort();
    out
}

/// The generate rows of both profiles, by key type.
fn rows<'a>(
    generated: &'a Profile,
    claimed: &'a Profile,
) -> BTreeMap<&'a str, (Option<&'a GenerateRow>, Option<&'a GenerateRow>)> {
    let mut rows: BTreeMap<&str, (Option<&GenerateRow>, Option<&GenerateRow>)> = BTreeMap::new();
    for (kt, row) in &generated.generate {
        rows.insert(kt, (Some(row), claimed.generate.get(kt)));
    }
    for (kt, row) in &claimed.generate {
        rows.entry(kt).or_insert((None, Some(row)));
    }
    rows
}

/// [`diff`] over the rows a read-only probe observes — the match keys, the advertisement and
/// the key sizes the module reports (`C_GetMechanismInfo`) — so a probe that wrote nothing (a
/// production token, SO-only hardware) can still conform. A `partial` claimed profile records
/// no advertisement, so it is not compared.
#[must_use]
pub fn read_only(generated: &Profile, claimed: &Profile) -> Vec<String> {
    let mut out = Vec::new();
    let (g, c) = (&generated.r#match, &claimed.r#match);
    optional("match.manufacturer", g.manufacturer.as_ref(), c.manufacturer.as_ref(), &mut out);
    optional("match.module-version", g.module_version.as_ref(), c.module_version.as_ref(), &mut out);
    optional("match.model", g.model.as_ref(), c.model.as_ref(), &mut out);
    optional("match.firmware", g.firmware.as_ref(), c.firmware.as_ref(), &mut out);
    if !claimed.partial {
        sets("advertise", &generated.advertise, &claimed.advertise, &mut out);
    }
    for (kt, (g, c)) in rows(generated, claimed) {
        numeric(&format!("generate.{kt}.min-bits"), g.and_then(|r| r.min_bits), c.and_then(|r| r.min_bits), &mut out);
        numeric(&format!("generate.{kt}.max-bits"), g.and_then(|r| r.max_bits), c.and_then(|r| r.max_bits), &mut out);
    }
    out.sort();
    out
}

/// One line per name in only one of the two lists, sorted.
fn sets(what: &str, generated: &[String], claimed: &[String], out: &mut Vec<String>) {
    let (generated, claimed): (BTreeSet<&String>, BTreeSet<&String>) =
        (generated.iter().collect(), claimed.iter().collect());
    for x in generated.difference(&claimed) {
        out.push(format!("{what}: only observed: {x}"));
    }
    for x in claimed.difference(&generated) {
        out.push(format!("{what}: only claimed: {x}"));
    }
}

/// Compare an optional row that both sides may omit.
fn optional(what: &str, generated: Option<&String>, claimed: Option<&String>, out: &mut Vec<String>) {
    match (generated, claimed) {
        (Some(g), Some(c)) if g != c => out.push(format!("{what}: observed \"{g}\", claimed \"{c}\"")),
        (Some(g), None) => out.push(format!("{what}: only observed: {g}")),
        (None, Some(c)) => out.push(format!("{what}: only claimed: {c}")),
        _ => {}
    }
}

/// A row the probe may not have run: absent is never probed, `[]` is probed and empty.
fn probed(what: &str, generated: Option<&[String]>, claimed: Option<&[String]>, out: &mut Vec<String>) {
    match (generated, claimed) {
        (Some(g), Some(c)) => sets(what, g, c, out),
        (Some(_), None) => out.push(format!("{what}: only observed (claimed: never probed)")),
        (None, Some(_)) => out.push(format!("{what}: only claimed (not probed this run)")),
        (None, None) => {}
    }
}

/// The numeric restrictions (a hardware layer's generation bounds), keyed by operation and key
/// type.
fn restrictions(generated: &Profile, claimed: &Profile, out: &mut Vec<String>) {
    let key = |p: &Profile| -> BTreeMap<(String, String), (Option<u32>, Option<u32>)> {
        p.restrict.iter().map(|r| ((r.operation.clone(), r.key_type.clone()), (r.min_bits, r.max_bits))).collect()
    };
    let (g, c) = (key(generated), key(claimed));
    for (k, gv) in &g {
        let what = format!("restrict.{}.{}", k.0, k.1);
        match c.get(k) {
            None => out.push(format!("{what}: only observed")),
            Some(cv) => {
                numeric(&format!("{what}.min-bits"), gv.0, cv.0, out);
                numeric(&format!("{what}.max-bits"), gv.1, cv.1, out);
            }
        }
    }
    for k in c.keys().filter(|k| !g.contains_key(*k)) {
        out.push(format!("restrict.{}.{}: only claimed", k.0, k.1));
    }
}

/// Compare an optional numeric row.
fn numeric(what: &str, generated: Option<u32>, claimed: Option<u32>, out: &mut Vec<String>) {
    match (generated, claimed) {
        (Some(g), Some(c)) if g != c => out.push(format!("{what}: observed {g}, claimed {c}")),
        (Some(g), None) => out.push(format!("{what}: only observed: {g}")),
        (None, Some(c)) => out.push(format!("{what}: only claimed: {c}")),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(name: &str, text: &str) -> Profile {
        Profile::from_toml(&format!("profile = \"{name}\"\nmode = \"observed\"\n{text}")).unwrap()
    }

    #[test]
    fn an_empty_diff_is_conformance() {
        let generated = profile(
            "softhsm/probe",
            "advertise = [\"CKM_AES_KEY_WRAP\"]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n\
             [wrap]\noaep = [\"SHA-1\"]\n[generate.\"CKK_EC\"]\ncan = [\"secp256r1\"]\nmin-bits = 1024\n",
        );
        // The claimed profile may carry more than a probe observes: notes, migration rows.
        let claimed = profile(
            "softhsm/2.7",
            "advertise = [\"CKM_AES_KEY_WRAP\"]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n\
             [wrap]\noaep = [\"SHA-1\"]\n[generate.\"CKK_EC\"]\ncan = [\"secp256r1\"]\nmin-bits = 1024\n\
             [migration]\nexports = false\n[notes]\nhuman = \"evidence\"\n\
             [manual.so]\nfinding = \"by hand\"\nevidence = \"[run]\"",
        );
        assert_eq!(diff(&generated, &claimed), Vec::<String>::new());
    }

    #[test]
    fn every_differing_row_is_a_named_line() {
        let generated = profile(
            "softhsm/probe",
            "advertise = [\"CKM_A\", \"CKM_G\"]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n\
             [generate.\"CKK_EC\"]\ncan = [\"secp256r1\", \"secp384r1\"]\nmax-bits = 4096\n",
        );
        let claimed = profile(
            "softhsm/2.7",
            "advertise = [\"CKM_A\", \"CKM_B\"]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n\
             [generate.\"CKK_EC\"]\ncan = [\"secp256r1\"]\nmax-bits = 3072\n[generate.\"CKK_RSA\"]\ncan = []\n",
        );
        let lines = diff(&generated, &claimed);
        assert!(lines.contains(&"advertise: only observed: CKM_G".to_owned()));
        assert!(lines.contains(&"advertise: only claimed: CKM_B".to_owned()));
        assert!(lines.contains(&"generate.CKK_EC.can: only observed: secp384r1".to_owned()));
        assert!(lines.contains(&"generate.CKK_EC.max-bits: observed 4096, claimed 3072".to_owned()));
        assert!(lines.contains(&"generate.CKK_RSA: only claimed".to_owned()));
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn a_read_only_probe_conforms_on_the_rows_it_observes() {
        // A read-only probe has no generate, wrap or unwrap rows: only match and advertise count.
        let generated = profile(
            "softhsm/probe",
            "advertise = [\"CKM_A\"]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n",
        );
        let claimed = profile(
            "softhsm/2.7",
            "advertise = [\"CKM_A\"]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n\
             [wrap]\noaep = [\"SHA-1\"]\n[generate.\"CKK_EC\"]\ncan = [\"secp256r1\"]\n",
        );
        assert_eq!(read_only(&generated, &claimed), Vec::<String>::new());
        assert_eq!(diff(&generated, &claimed).len(), 2);
        // A partial claimed profile records no advertisement: nothing to compare it with.
        let partial =
            profile("ykcs11/2.7", "partial = true\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n");
        assert_eq!(read_only(&generated, &partial), Vec::<String>::new());
    }
}
