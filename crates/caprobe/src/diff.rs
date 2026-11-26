//! The probe diff (docs/CAPROBE.md) compares what a generated profile observed with what a
//! claimed profile says, over the rows that a probe can observe. An empty diff means conformance:
//! the shipped profile describes what the module does. A non-empty diff means drift, and each
//! line names the row that differs.

use cakeys_profile::{Capability, KeyKind, Profile, Row};
use std::collections::{BTreeMap, BTreeSet};

/// Compares the rows of `generated` that a probe can observe with the same rows of `claimed`.
/// Returns one line for each difference, and an empty list when the claimed profile is exactly
/// what the probe observed.
///
/// These parts are never compared:
/// - the profiles' names, because the probe names a profile by provider and expressed version,
///   and a module that hides its version gets another name;
/// - `partial`, because whether the probe has filled the rows is not a claim;
/// - the notes, each row's evidence, and the `[manual]` findings, which are human evidence;
/// - what no probe observes: `[migration]` and the `move.*` capabilities, which are this
///   repository's claims.
///
/// Both subtractions, of mechanisms and of key types, are compared.
#[must_use]
pub(crate) fn diff(generated: &Profile, claimed: &Profile) -> Vec<String> {
    let mut out = read_only(generated, claimed);
    sets("subtract.mechanisms", &generated.subtract.mechanisms, &claimed.subtract.mechanisms, &mut out);
    sets("subtract.key-types", &generated.subtract.key_types, &claimed.subtract.key_types, &mut out);
    sets("add", &generated.add, &claimed.add, &mut out);
    restrictions(generated, claimed, &mut out);
    let names: BTreeSet<&String> = generated.untested.keys().chain(claimed.untested.keys()).collect();
    for name in names {
        match (generated.untested.get(name), claimed.untested.get(name)) {
            (Some(g), Some(c)) if g.why != c.why => {
                out.push(format!("untested.{name}: observed {}, claimed {}", g.why.name(), c.why.name()));
            }
            (Some(g), None) => out.push(format!("untested.{name}: only observed: {}", g.why.name())),
            (None, Some(c)) => out.push(format!("untested.{name}: only claimed: {}", c.why.name())),
            _ => {}
        }
    }
    let probed = |p: &Profile| -> BTreeMap<Capability, Row> {
        p.capabilities.iter().filter(|(c, _)| c.probed()).map(|(c, r)| (c.clone(), r.clone())).collect()
    };
    let (g, c) = (probed(generated), probed(claimed));
    let shown = |r: &Row| match &r.via {
        Some(via) => format!("{} ({via})", r.answer.name()),
        None => r.answer.name().to_owned(),
    };
    for cap in g.keys().chain(c.keys()).collect::<BTreeSet<_>>() {
        match (g.get(cap), c.get(cap)) {
            (Some(g), Some(c)) if shown(g) != shown(c) => {
                out.push(format!("{cap}: observed {}, claimed {}", shown(g), shown(c)));
            }
            (Some(g), None) => out.push(format!("{cap}: only observed: {}", shown(g))),
            (None, Some(c)) => out.push(format!("{cap}: only claimed: {}", shown(c))),
            _ => {}
        }
    }
    out.sort();
    out
}

/// Runs [`diff`] over only the rows that a read-only probe observes: the match keys, the
/// advertisement, and the key sizes that the module reports (`C_GetMechanismInfo`). A probe that
/// wrote nothing (on a production token, or on hardware that only the SO can write) can
/// therefore still conform. A `partial` claimed profile records no advertisement, so the
/// advertisement is not compared for it.
#[must_use]
pub(crate) fn read_only(generated: &Profile, claimed: &Profile) -> Vec<String> {
    let mut out = Vec::new();
    let (g, c) = (&generated.r#match, &claimed.r#match);
    optional("match.manufacturer", g.manufacturer.as_ref(), c.manufacturer.as_ref(), &mut out);
    optional("match.module-version", g.module_version.as_ref(), c.module_version.as_ref(), &mut out);
    optional("match.model", g.model.as_ref(), c.model.as_ref(), &mut out);
    optional("match.firmware", g.firmware.as_ref(), c.firmware.as_ref(), &mut out);
    if !claimed.partial {
        sets("advertise", &generated.advertise, &claimed.advertise, &mut out);
    }
    let key_types: BTreeSet<&String> = generated.reported.keys().chain(claimed.reported.keys()).collect();
    for kt in key_types {
        let (g, c) = (generated.reported.get(kt), claimed.reported.get(kt));
        numeric(&format!("reported.{kt}.min-bits"), g.and_then(|r| r.min_bits), c.and_then(|r| r.min_bits), &mut out);
        numeric(&format!("reported.{kt}.max-bits"), g.and_then(|r| r.max_bits), c.and_then(|r| r.max_bits), &mut out);
    }
    out.sort();
    out
}

/// Adds one line for each name that is in only one of the two lists, in sorted order.
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

/// Compares an optional row that both sides may omit.
fn optional(what: &str, generated: Option<&String>, claimed: Option<&String>, out: &mut Vec<String>) {
    match (generated, claimed) {
        (Some(g), Some(c)) if g != c => out.push(format!("{what}: observed \"{g}\", claimed \"{c}\"")),
        (Some(g), None) => out.push(format!("{what}: only observed: {g}")),
        (None, Some(c)) => out.push(format!("{what}: only claimed: {c}")),
        _ => {}
    }
}

/// Compares the numeric restrictions (the generation bounds of a hardware layer), keyed by
/// operation and key type. Two rows for the same pair on one side produce a line of their own,
/// and neither row is compared as if it were the only one.
fn restrictions(generated: &Profile, claimed: &Profile, out: &mut Vec<String>) {
    let mut key = |p: &Profile, side: &str| -> BTreeMap<(String, KeyKind), (Option<u32>, Option<u32>)> {
        let mut rows = BTreeMap::new();
        for r in &p.restrict {
            let k = (r.operation.clone(), r.key_type.clone());
            if rows.insert(k, (r.min_bits, r.max_bits)).is_some() {
                out.push(format!("restrict.{}.{}: {side} more than once", r.operation, r.key_type));
            }
        }
        rows
    };
    let (g, c) = (key(generated, "observed"), key(claimed, "claimed"));
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

/// Compares an optional numeric row.
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

    /// Returns `[capabilities]` rows, one on each line.
    fn caps(rows: &[(&str, &str)]) -> String {
        let rows: String = rows.iter().fold(String::new(), |s, (c, row)| s + &format!("\"{c}\" = {{ {row} }}\n"));
        format!("[capabilities]\n{rows}")
    }

    #[test]
    fn an_empty_diff_is_conformance() {
        let rows = caps(&[
            ("wrap.rsa-oaep.SHA-1", "answer = \"yes\""),
            ("generate.CKK_EC.secp256r1", "answer = \"yes\", evidence = \"generated\""),
        ]);
        let head =
            "advertise = [\"CKM_AES_KEY_WRAP\"]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n";
        let generated = profile("softhsm/probe", &format!("{head}{rows}[reported.\"CKK_RSA\"]\nmin-bits = 1024\n"));
        // The claimed profile may carry more than a probe observes: notes, claims, and
        // different evidence for a row.
        let claimed = profile(
            "softhsm/2.7",
            &format!(
                "{head}{}\"move.export\" = {{ answer = \"no\" }}\n[reported.\"CKK_RSA\"]\nmin-bits = 1024\n\
                 [migration]\nplaintext-import = \"create-object\"\n[notes]\nhuman = \"evidence\"\n\
                 [manual.so]\nfinding = \"by hand\"\nevidence = \"[run]\"",
                rows.replace("evidence = \"generated\"", "evidence = \"another run\"")
            ),
        );
        assert_eq!(diff(&generated, &claimed), Vec::<String>::new());
    }

    #[test]
    fn every_differing_row_is_a_named_line() {
        let head =
            |adv: &str| format!("advertise = [{adv}]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n");
        let generated = profile(
            "softhsm/probe",
            &format!(
                "{}{}[reported.\"CKK_RSA\"]\nmax-bits = 4096\n",
                head("\"CKM_A\", \"CKM_G\""),
                caps(&[
                    ("generate.CKK_EC.secp256r1", "answer = \"yes\""),
                    ("generate.CKK_EC.secp384r1", "answer = \"yes\""),
                    ("generate.CKK_EC_EDWARDS.edwards25519", "answer = \"yes\", via = \"by-name\""),
                ])
            ),
        );
        let claimed = profile(
            "softhsm/2.7",
            &format!(
                "{}{}[reported.\"CKK_RSA\"]\nmax-bits = 3072\n",
                head("\"CKM_A\", \"CKM_B\""),
                caps(&[
                    ("generate.CKK_EC.secp256r1", "answer = \"yes\""),
                    ("generate.CKK_EC_EDWARDS.edwards25519", "answer = \"yes\""),
                    ("generate.CKK_RSA.2048", "answer = \"no\""),
                ])
            ),
        );
        let lines = diff(&generated, &claimed);
        assert_eq!(
            lines,
            [
                "advertise: only claimed: CKM_B",
                "advertise: only observed: CKM_G",
                "generate.CKK_EC.secp384r1: only observed: yes",
                "generate.CKK_EC_EDWARDS.edwards25519: observed yes (by-name), claimed yes",
                "generate.CKK_RSA.2048: only claimed: no",
                "reported.CKK_RSA.max-bits: observed 4096, claimed 3072",
            ]
        );
    }

    /// Rows that only one side has, in each table that the diff compares: the capabilities, a
    /// size bound, and the restrictions.
    #[test]
    fn rows_only_one_side_has_are_named() {
        let head = "advertise = [\"CKM_A\"]\n[match]\nmanufacturer = \"M\"\nmodule-version = \"1\"\n";
        let generated = profile(
            "m/probe",
            &format!(
                "{head}{}[reported.\"CKK_RSA\"]\nmin-bits = 1024\n\
                 [[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\nmax-bits = 2048\n\
                 [[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_AES\"\nmax-bits = 256\n",
                caps(&[
                    ("wrap.rsa-oaep.SHA-1", "answer = \"yes\""),
                    ("unwrap.template.CKA_VALUE_LEN", "answer = \"no\""),
                    ("derive.ecdh.sealed", "answer = \"no\""),
                ])
            ),
        );
        let claimed = profile(
            "m/1",
            &format!(
                "{head}{}[reported.\"CKK_RSA\"]\nmax-bits = 4096\n\
                 [[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\nmax-bits = 3072\n\
                 [[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_DES3\"\nmin-bits = 112\n",
                caps(&[
                    ("unwrap.template.CKA_VALUE_LEN", "answer = \"yes\""),
                    ("derive.ecdh.read-only", "answer = \"yes\"")
                ])
            ),
        );
        let lines = diff(&generated, &claimed);
        for want in [
            "reported.CKK_RSA.min-bits: only observed: 1024",
            "reported.CKK_RSA.max-bits: only claimed: 4096",
            "wrap.rsa-oaep.SHA-1: only observed: yes",
            "unwrap.template.CKA_VALUE_LEN: observed no, claimed yes",
            "restrict.generate.CKK_RSA.max-bits: observed 2048, claimed 3072",
            "restrict.generate.CKK_AES: only observed",
            "restrict.generate.CKK_DES3: only claimed",
            "derive.ecdh.sealed: only observed: no",
            "derive.ecdh.read-only: only claimed: yes",
        ] {
            assert!(lines.iter().any(|l| l == want), "missing {want:?} in {lines:#?}");
        }
    }

    /// Key-type subtractions are compared in the same way as mechanism subtractions, and a
    /// restriction that is listed twice on one side is drift by itself (review diff F1, F2).
    #[test]
    fn key_type_subtractions_and_repeated_restrictions_are_named() {
        let rsa =
            |bits: u32| format!("[[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\nmax-bits = {bits}\n");
        let generated =
            profile("m/probe", &format!("[subtract]\nkey-types = [\"CKK_SHA224_HMAC\"]\n{}{}", rsa(2048), rsa(3072)));
        let claimed = profile("m/1", &format!("[subtract]\nkey-types = [\"CKK_DES3\"]\n{}", rsa(3072)));
        assert_eq!(
            diff(&generated, &claimed),
            [
                "restrict.generate.CKK_RSA: observed more than once",
                "subtract.key-types: only claimed: CKK_DES3",
                "subtract.key-types: only observed: CKK_SHA224_HMAC",
            ]
        );
    }

    #[test]
    fn a_read_only_probe_conforms_on_the_rows_it_observes() {
        // A read-only probe has no capability rows, so only the match keys and the
        // advertisement count.
        let generated = profile(
            "softhsm/probe",
            "advertise = [\"CKM_A\"]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n",
        );
        let claimed = profile(
            "softhsm/2.7",
            &format!(
                "advertise = [\"CKM_A\"]\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n{}",
                caps(&[("wrap.rsa-oaep.SHA-1", "answer = \"yes\""), ("generate.CKK_EC.secp256r1", "answer = \"yes\"")])
            ),
        );
        assert_eq!(read_only(&generated, &claimed), Vec::<String>::new());
        assert_eq!(diff(&generated, &claimed).len(), 2);
        // A partial claimed profile records no advertisement, so there is nothing to compare
        // the observed advertisement with.
        let partial =
            profile("ykcs11/2.7", "partial = true\n[match]\nmanufacturer = \"SoftHSM\"\nmodule-version = \"2.7\"\n");
        assert_eq!(read_only(&generated, &partial), Vec::<String>::new());
    }
}
