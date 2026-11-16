//! The effective capability of a stack (docs/CAPROBE.md D3): one module profile, the delta
//! layers between cakeys and it, and the baseline that names and groups everything. Every
//! verdict cites the profile that decided, so a "no" names the layer that subtracted and an
//! "unknown" says why it cannot say (D5's conservative answers).

use crate::baseline::Baseline;
use crate::capability::{Capability, On};
use crate::profile::Profile;

/// The capability of generating `key_type` on `on`.
fn generate(key_type: &str, on: On) -> Capability {
    Capability::Generate { key_type: key_type.to_owned(), on }
}

/// A query's answer: yes (with who said so), no (with who and why), or unknown (why it
/// cannot say). No and unknown are different exits (15 and 16), so a check can tell a hard
/// refusal from a question the profiles do not cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// It can.
    Yes {
        /// The profile that said so.
        by: String,
        /// Its note on the row, when it has one.
        note: Option<String>,
    },
    /// It cannot (15).
    No {
        /// The profile that said so: the layer that subtracted, or the module's.
        by: String,
        /// Why, when the profile says.
        note: Option<String>,
    },
    /// The profiles cannot say (16).
    Unknown {
        /// Why not.
        why: String,
    },
}

impl Verdict {
    fn yes(by: &str, note: Option<&String>) -> Verdict {
        Verdict::Yes { by: by.to_owned(), note: note.cloned() }
    }

    fn no(by: &str, note: Option<String>) -> Verdict {
        Verdict::No { by: by.to_owned(), note }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Yes { by, note } => {
                write!(f, "yes ({by})")?;
                if let Some(n) = note {
                    write!(f, ": {n}")?;
                }
                Ok(())
            }
            Verdict::No { by, note } => {
                write!(f, "no — {by}")?;
                if let Some(n) = note {
                    write!(f, ": {n}")?;
                }
                Ok(())
            }
            Verdict::Unknown { why } => write!(f, "unknown — {why}"),
        }
    }
}

/// One resolved stack: the baseline, the module profile if one was selected, and the delta
/// layers on top of it. `supports(x) = ⋀ layers`: any layer's subtraction decides no, else the
/// module's observed set does.
pub struct Effective<'a> {
    baseline: &'a Baseline,
    module: Option<&'a Profile>,
    layers: &'a [&'a Profile],
}

impl<'a> Effective<'a> {
    /// Compose a stack from its parts. The baseline comes from the loaded set, the module
    /// profile is optional (a layer-only or class-only query needs none), and the layers are
    /// applied in the order given.
    #[must_use]
    pub fn new(baseline: &'a Baseline, module: Option<&'a Profile>, layers: &'a [&'a Profile]) -> Effective<'a> {
        Effective { baseline, module, layers }
    }

    /// The baseline this stack resolves names against.
    #[must_use]
    pub fn baseline(&self) -> &Baseline {
        self.baseline
    }

    /// Whether a mechanism is usable. Layers subtract first (a dropped mechanism is no for
    /// every module behind them), then the module's deltas against its advertisement decide;
    /// a profile without an `advertise` list (the probe, phase 3) answers unknown.
    #[must_use]
    pub fn mechanism(&self, name: &str) -> Verdict {
        if !self.baseline.mechanisms.contains_key(name) {
            return Verdict::Unknown { why: format!("not a mechanism of baseline {}", self.baseline.baseline) };
        }
        for l in self.layers {
            if l.subtract.mechanisms.iter().any(|m| m == name) {
                return Verdict::no(&l.profile, l.notes.get(name).cloned().or(l.subtract.note.clone()));
            }
        }
        let Some(m) = self.module else {
            return Verdict::Unknown { why: "no module profile selected".into() };
        };
        if m.subtract.mechanisms.iter().any(|x| x == name) {
            return Verdict::no(&m.profile, m.notes.get(name).cloned());
        }
        if m.advertise.is_empty() {
            return Verdict::Unknown {
                why: format!(
                    "module profile {} records no advertisement for it (partial: the probe, \
                     docs/CAPROBE.md, records the list)",
                    m.profile
                ),
            };
        }
        if m.advertise.iter().any(|x| x == name) || m.add.iter().any(|x| x == name) {
            Verdict::yes(&m.profile, m.notes.get(name))
        } else {
            Verdict::no(&m.profile, m.notes.get(name).cloned().or_else(|| Some("not advertised".into())))
        }
    }

    /// Whether a module generates a key of `key_type`, optionally with one item (a curve, or a
    /// parameter set for the PQ types) and a modulus size. Layers subtract key types and
    /// intersect size bounds first, then the module's `generate` row decides: what is in
    /// neither its `can` nor its `cannot` answers unknown, never a guess.
    #[must_use]
    pub fn generate(&self, key_type: &str, item: Option<&str>, bits: Option<u32>) -> Verdict {
        if !self.baseline.key_types.contains_key(key_type) {
            return Verdict::Unknown { why: format!("not a key type of baseline {}", self.baseline.baseline) };
        }
        if let Some(item) = item
            && !self.baseline.curves.contains(item)
            && !self.baseline.parameter_sets.contains_key(item)
        {
            return Verdict::Unknown {
                why: format!("not a curve or parameter set of baseline {}", self.baseline.baseline),
            };
        }
        for l in self.layers {
            if l.subtract.key_types.iter().any(|k| k == key_type) {
                return Verdict::no(&l.profile, l.notes.get(key_type).cloned().or(l.subtract.note.clone()));
            }
            // A layer's `cannot` rows (the hardware under the module refusing a curve, D10);
            // its `can` rows mean nothing in delta mode, where the module decides the rest.
            if let Some(item) = item
                && l.generation(key_type).is_some_and(|row| row.cannot.iter().any(|c| c == item))
            {
                return Verdict::no(&l.profile, l.evidence(&generate(key_type, On::Item(item.to_owned())), item));
            }
            for r in &l.restrict {
                if r.operation == "generate"
                    && r.key_type == key_type
                    && let Some(bits) = bits
                    && (r.max_bits.is_some_and(|max| bits > max) || r.min_bits.is_some_and(|min| bits < min))
                {
                    return Verdict::no(&l.profile, r.note.clone());
                }
            }
        }
        let Some(m) = self.module else {
            return Verdict::Unknown { why: "no module profile selected".into() };
        };
        let Some(row) = m.generation(key_type) else {
            return Verdict::Unknown { why: format!("module profile {} records no {key_type} generation", m.profile) };
        };
        if let Some(bits) = bits {
            // What the probe saw decides; then the range the module reports; then, for a
            // probed row, only a size between two that generated is yes — the rest of what was
            // never tried is unknown.
            let size_note = || m.evidence(&generate(key_type, On::Bits(bits)), &format!("{key_type} at {bits}"));
            if row.cannot_bits.contains(&bits) {
                return Verdict::no(&m.profile, size_note());
            }
            if row.can_bits.contains(&bits) {
                return Verdict::yes(&m.profile, None);
            }
            if row.max_bits.is_some_and(|max| bits > max) || row.min_bits.is_some_and(|min| bits < min) {
                return Verdict::no(&m.profile, m.notes.get(key_type).cloned());
            }
            let tried = row.can_bits.iter().chain(&row.cannot_bits);
            if tried.clone().next().is_some() {
                let (lo, hi) = (row.can_bits.iter().min(), row.can_bits.iter().max());
                if lo.is_some_and(|lo| *lo < bits) && hi.is_some_and(|hi| bits < *hi) {
                    return Verdict::yes(&m.profile, None);
                }
                let tried: Vec<String> = tried.map(u32::to_string).collect();
                return Verdict::Unknown {
                    why: format!("module profile {} probed {} bits only", m.profile, tried.join(", ")),
                };
            }
        }
        if let Some(item) = item {
            if row.can.iter().any(|c| c == item) {
                return Verdict::yes(
                    &m.profile,
                    m.evidence(&generate(key_type, On::Item(item.to_owned())), item).as_ref(),
                );
            }
            if row.cannot.iter().any(|c| c == item) {
                return Verdict::no(&m.profile, m.evidence(&generate(key_type, On::Item(item.to_owned())), item));
            }
            return Verdict::Unknown {
                why: format!("module profile {} records neither can nor cannot for it (partial)", m.profile),
            };
        }
        Verdict::yes(&m.profile, m.notes.get(key_type))
    }

    /// Whether a curve is generatable, over every key type that has a row: any row's yes wins,
    /// else any row's no, else unknown (the curve names no key type of this profile).
    #[must_use]
    pub fn curve(&self, name: &str) -> Verdict {
        if !self.baseline.curves.contains(name) {
            return Verdict::Unknown { why: format!("not a curve of baseline {}", self.baseline.baseline) };
        }
        let Some(m) = self.module else {
            return Verdict::Unknown { why: "no module profile selected".into() };
        };
        let verdicts: Vec<Verdict> =
            m.generation_key_types().into_iter().map(|kt| self.generate(kt, Some(name), None)).collect();
        verdicts
            .iter()
            .find(|v| matches!(v, Verdict::Yes { .. }))
            .or_else(|| verdicts.iter().find(|v| matches!(v, Verdict::No { .. })))
            .cloned()
            .unwrap_or(Verdict::Unknown {
                why: format!("no generate row of module profile {} lists the curve", m.profile),
            })
    }

    /// Ask after a bare name: `CKM_*` a mechanism, `CKK_*` a key type, `CKP_*` a parameter set
    /// (mapped to its PQ key type), anything else a curve. `bits` asks for an RSA size.
    #[must_use]
    pub fn query(&self, name: &str, bits: Option<u32>) -> Verdict {
        if name.starts_with("CKM_") {
            self.mechanism(name)
        } else if name.starts_with("CKK_") {
            self.generate(name, None, bits)
        } else if let Some(kt) = parameter_set_key_type(name) {
            self.generate(kt, Some(name), None)
        } else {
            self.curve(name)
        }
    }

    /// The members of a baseline class with their verdicts, or [`None`] when the baseline
    /// defines no such class.
    #[must_use]
    pub fn class(&self, class: &str) -> Option<Vec<(String, Verdict)>> {
        let members = self.baseline.class.get(class)?;
        Some(
            members
                .mechanisms
                .iter()
                .map(|m| (m.clone(), self.mechanism(m)))
                .chain(members.parameter_sets.iter().map(|p| (p.clone(), self.query(p, None))))
                .collect(),
        )
    }

    /// The RSA-OAEP hashes usable for wrapping, with their verdicts; layers subtract none
    /// today (whether p11-kit forwards OAEP wrapping is [todo], docs/CAMIGRATE.md).
    #[must_use]
    pub fn oaep(&self) -> Vec<(String, Verdict)> {
        match self.module {
            None => vec![("OAEP".into(), Verdict::Unknown { why: "no module profile selected".into() })],
            Some(m) => match m.wrap_oaep().as_deref() {
                None => vec![(
                    "OAEP".into(),
                    Verdict::Unknown { why: format!("module profile {} records no OAEP probe", m.profile) },
                )],
                // Probed, and no hash round-trips.
                Some([]) => vec![("OAEP".into(), Verdict::no(&m.profile, m.notes.get("oaep").cloned()))],
                Some(hashes) => {
                    hashes.iter().map(|h| (h.clone(), Verdict::yes(&m.profile, m.notes.get("oaep")))).collect()
                }
            },
        }
    }
}

/// The PQ key type a `CKP_*` parameter set belongs to ([`Effective::query`]): the PBKDF2
/// pseudo-random functions name none.
fn parameter_set_key_type(name: &str) -> Option<&'static str> {
    Some(match name.strip_prefix("CKP_")? {
        n if n.starts_with("ML_DSA_") => "CKK_ML_DSA",
        n if n.starts_with("ML_KEM_") => "CKK_ML_KEM",
        n if n.starts_with("SLH_DSA_") => "CKK_SLH_DSA",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::Baseline;

    /// A tiny baseline for the algebra tests: the real committed one is exercised through
    /// [`crate::Set::embedded`] below.
    fn baseline() -> Baseline {
        let text = r#"
            baseline = "test"
            functions = []
            curves = ["secp256r1", "secp256k1"]
            [mechanisms]
            CKM_AES_KEY_WRAP = 0x2109
            CKM_SHA512_HMAC = 0x271
            CKM_ECDSA = 0x1041
            [key-types]
            CKK_AES = 0x1f
            CKK_EC = 0x3
            CKK_RSA = 0x0
            CKK_ML_DSA = 0x4a
            [attributes]
            CKA_VALUE_LEN = 0x161
            [objects]
            CKO_DATA = 0x0
            [parameter-sets]
            CKP_ML_DSA_65 = 0x2
            [conformance-profiles]
            CKP_BASELINE_PROVIDER = 0x1
            [class.pq]
            mechanisms = ["CKM_SHA512_HMAC"]
            parameter-sets = ["CKP_ML_DSA_65"]
        "#;
        Baseline::from_toml(text).unwrap()
    }

    fn profile(text: &str) -> Profile {
        Profile::from_toml(text).unwrap()
    }

    fn eff<'a>(b: &'a Baseline, m: Option<&'a Profile>, l: &'a [&'a Profile]) -> Effective<'a> {
        Effective::new(b, m, l)
    }

    #[test]
    fn layer_subtraction_decides_no_for_every_module() {
        let b = baseline();
        let p11 = profile(
            "profile = \"p11-kit/0.26\"\nmode = \"delta\"\n[subtract]\nmechanisms = [\"CKM_AES_KEY_WRAP\"]\nnote = \"the RPC drops it\"",
        );
        let softhsm = profile("profile = \"softhsm/2.7\"\nmode = \"observed\"\nadvertise = [\"CKM_AES_KEY_WRAP\"]");
        assert!(matches!(
            eff(&b, Some(&softhsm), &[&p11]).mechanism("CKM_AES_KEY_WRAP"),
            Verdict::No { by, .. } if by == "p11-kit/0.26"
        ));
        assert!(matches!(eff(&b, None, &[&p11]).mechanism("CKM_AES_KEY_WRAP"), Verdict::No { .. }));
    }

    #[test]
    fn a_partial_module_profile_answers_unknown_not_a_guess() {
        let b = baseline();
        let softhsm = profile("profile = \"softhsm/2.7\"\nmode = \"observed\"\npartial = true");
        assert!(matches!(
            eff(&b, Some(&softhsm), &[]).mechanism("CKM_SHA512_HMAC"),
            Verdict::Unknown { why, .. } if why.contains("partial")
        ));
    }

    #[test]
    fn a_subtracted_module_mechanism_is_no_with_its_note() {
        let b = baseline();
        let tpm2 = profile(
            "profile = \"tpm2-pkcs11/1.10\"\nmode = \"observed\"\n[subtract]\n\
             mechanisms = [\"CKM_SHA512_HMAC\"]\n[notes]\nCKM_SHA512_HMAC = \"C_GenerateKey fails\"",
        );
        assert!(matches!(
            eff(&b, Some(&tpm2), &[]).mechanism("CKM_SHA512_HMAC"),
            Verdict::No { note, .. } if note.as_deref() == Some("C_GenerateKey fails")
        ));
    }

    #[test]
    fn curves_decide_by_can_and_cannot_lists() {
        let b = baseline();
        let kryoptic = profile(
            "profile = \"kryoptic/1.5\"\nmode = \"observed\"\n[capabilities]\n\
             \"generate.CKK_EC.secp256r1\" = { answer = \"yes\" }\n\"generate.CKK_EC.secp256k1\" = { answer = \"no\" }",
        );
        assert!(matches!(eff(&b, Some(&kryoptic), &[]).curve("secp256r1"), Verdict::Yes { .. }));
        assert!(matches!(eff(&b, Some(&kryoptic), &[]).curve("secp256k1"), Verdict::No { .. }));
    }

    #[test]
    fn layer_restrictions_decide_before_the_module_row() {
        let b = baseline();
        let swtpm = profile(
            "profile = \"swtpm\"\nmode = \"delta\"\n[[restrict]]\noperation = \"generate\"\n\
             key-type = \"CKK_RSA\"\nmax-bits = 3072\nnote = \"refuses RSA-4096\"",
        );
        let module = profile("profile = \"x/1\"\nmode = \"observed\"\n[reported.\"CKK_RSA\"]\nmax-bits = 4096");
        let layers = [&swtpm];
        // A restriction names a bits bound: without bits it cannot decide, beyond it it can.
        assert!(matches!(eff(&b, Some(&module), &layers).query("CKK_RSA", None), Verdict::Yes { .. }));
        assert!(matches!(
            eff(&b, Some(&module), &layers).query("CKK_RSA", Some(4096)),
            Verdict::No { by, note, .. } if by == "swtpm" && note.as_deref() == Some("refuses RSA-4096")
        ));
        assert!(matches!(eff(&b, Some(&module), &layers).query("CKK_RSA", Some(2048)), Verdict::Yes { .. }));
    }

    #[test]
    fn parameter_sets_map_to_their_pq_key_type() {
        let b = baseline();
        let module = profile(
            "profile = \"vendor/1\"\nmode = \"observed\"\n[capabilities]\n\"generate.CKK_ML_DSA.CKP_ML_DSA_65\" = { answer = \"yes\" }",
        );
        assert!(matches!(
            eff(&b, Some(&module), &[]).query("CKP_ML_DSA_65", None),
            Verdict::Yes { by, .. } if by == "vendor/1"
        ));
        assert!(matches!(eff(&b, Some(&module), &[]).query("CKP_ML_DSA_44", None), Verdict::Unknown { .. }));
    }

    #[test]
    fn class_listing_tells_mechanisms_from_parameter_sets() {
        let b = baseline();
        let module = profile(
            "profile = \"vendor/1\"\nmode = \"observed\"\n[capabilities]\n\"generate.CKK_ML_DSA.CKP_ML_DSA_65\" = { answer = \"yes\" }",
        );
        let pq = eff(&b, Some(&module), &[]).class("pq").unwrap();
        assert_eq!(pq[0].0, "CKM_SHA512_HMAC");
        assert!(matches!(pq[0].1, Verdict::Unknown { .. })); // partial module: no advertise list
        assert_eq!(pq[1].0, "CKP_ML_DSA_65");
        assert!(matches!(pq[1].1, Verdict::Yes { .. }));
    }

    /// What the stack cannot answer is unknown, never a guess: no module profile, a name the
    /// baseline lacks, an RSA size outside what was probed; a layer's own `cannot` row is a no,
    /// and a size between two that generated is a yes.
    #[test]
    fn unknowns_layer_refusals_and_sizes_between_probes() {
        let b = baseline();
        let unknown =
            |v: Verdict, why: &str| assert!(matches!(&v, Verdict::Unknown { why: w } if w.contains(why)), "{v:?}");
        let bare = eff(&b, None, &[]);
        assert_eq!(bare.baseline().baseline, "test");
        unknown(bare.mechanism("CKM_AES_KEY_WRAP"), "no module profile selected");
        unknown(bare.generate("CKK_EC", Some("secp256r1"), None), "no module profile selected");
        unknown(bare.curve("secp256r1"), "no module profile selected");
        unknown(bare.curve("secp112r1"), "not a curve");
        unknown(bare.generate("CKK_NOPE", None, None), "not a key type");
        assert!(matches!(bare.oaep().as_slice(), [(_, Verdict::Unknown { .. })]));
        let hardware = profile(
            "profile = \"hw\"\nmode = \"delta\"\n[capabilities]\n\"generate.CKK_EC.secp256k1\" = { answer = \"no\" }\n[notes]\nsecp256k1 = \"no such curve in the chip\"\n",
        );
        let module = profile(
            "profile = \"m/1\"\nmode = \"observed\"\nadvertise = [\"CKM_AES_KEY_WRAP\"]\n\
             [capabilities]\n\"generate.CKK_EC.secp256r1\" = { answer = \"yes\" }\n\"generate.CKK_EC.secp256k1\" = { answer = \"yes\" }\n\
             \"generate.CKK_RSA.2048\" = { answer = \"yes\" }\n\"generate.CKK_RSA.4096\" = { answer = \"yes\" }\n",
        );
        let layers = [&hardware];
        let stack = eff(&b, Some(&module), &layers);
        let v = stack.generate("CKK_EC", Some("secp256k1"), None);
        assert!(matches!(&v, Verdict::No { by, note: Some(n) } if by == "hw" && n.contains("chip")), "{v:?}");
        assert!(matches!(stack.generate("CKK_EC", Some("secp256r1"), None), Verdict::Yes { .. }));
        assert!(matches!(stack.generate("CKK_RSA", None, Some(3072)), Verdict::Yes { .. }));
        unknown(stack.generate("CKK_RSA", None, Some(8192)), "probed 2048, 4096 bits only");
    }

    /// A mechanism is usable when the module advertises it or the profile adds it, and no
    /// other; a verdict prints its answer, who decided, and the note.
    #[test]
    fn advertised_or_added_mechanisms_are_yes_and_verdicts_print() {
        let b = baseline();
        let module = profile(
            "profile = \"m/1\"\nmode = \"observed\"\nadvertise = [\"CKM_AES_KEY_WRAP\"]\nadd = [\"CKM_SHA512_HMAC\"]\n\
             [notes]\nCKM_SHA512_HMAC = \"works unlisted\"\n",
        );
        let stack = eff(&b, Some(&module), &[]);
        assert_eq!(stack.mechanism("CKM_AES_KEY_WRAP").to_string(), "yes (m/1)");
        assert_eq!(stack.mechanism("CKM_SHA512_HMAC").to_string(), "yes (m/1): works unlisted");
        assert_eq!(stack.mechanism("CKM_ECDSA").to_string(), "no — m/1: not advertised");
        assert_eq!(stack.mechanism("CKM_NOPE").to_string(), "unknown — not a mechanism of baseline test");
        assert_eq!(Verdict::No { by: "layer".into(), note: None }.to_string(), "no — layer");
    }

    /// A layer subtracts the key types it names and no other, and a size bound, a layer's or
    /// the module's own, is inclusive at both ends.
    #[test]
    fn key_types_and_size_bounds_decide_exactly() {
        let b = baseline();
        let layer = profile(
            "profile = \"layer\"\nmode = \"delta\"\n[subtract]\nkey-types = [\"CKK_AES\"]\nnote = \"no AES here\"\n\
             [[restrict]]\noperation = \"generate\"\nkey-type = \"CKK_RSA\"\nmin-bits = 2048\nmax-bits = 4096\n\
             note = \"2048 to 4096\"\n",
        );
        let open = profile(
            "profile = \"m/1\"\nmode = \"observed\"\n[reported.\"CKK_RSA\"]\n[reported.\"CKK_EC\"]\n[reported.\"CKK_AES\"]\n",
        );
        let layers = [&layer];
        let stack = eff(&b, Some(&open), &layers);
        let said = |v: Verdict| v.to_string();
        assert_eq!(said(stack.generate("CKK_AES", None, None)), "no — layer: no AES here");
        assert_eq!(said(stack.generate("CKK_EC", None, None)), "yes (m/1)");
        for (bits, want) in [
            (1024, "no — layer: 2048 to 4096"),
            (2048, "yes (m/1)"),
            (4096, "yes (m/1)"),
            (8192, "no — layer: 2048 to 4096"),
        ] {
            assert_eq!(said(stack.generate("CKK_RSA", None, Some(bits))), want, "{bits} bits behind the layer");
        }
        // A restriction on another operation or key type bounds nothing here.
        assert_eq!(said(stack.generate("CKK_EC", None, Some(8192))), "yes (m/1)");

        let bounded = profile(
            "profile = \"m/2\"\nmode = \"observed\"\n[reported.\"CKK_RSA\"]\nmin-bits = 2048\nmax-bits = 4096\n\
             [notes]\nCKK_RSA = \"2048 to 4096 only\"\n",
        );
        let stack = eff(&b, Some(&bounded), &[]);
        for (bits, want) in [
            (1024, "no — m/2: 2048 to 4096 only"),
            (2048, "yes (m/2): 2048 to 4096 only"),
            (4096, "yes (m/2): 2048 to 4096 only"),
            (8192, "no — m/2: 2048 to 4096 only"),
        ] {
            assert_eq!(said(stack.generate("CKK_RSA", None, Some(bits))), want, "{bits} bits in the module's range");
        }
    }

    /// A parameter set belongs to the PQ key type its name says, and to none otherwise.
    #[test]
    fn parameter_sets_name_their_key_type() {
        for (name, want) in [
            ("CKP_ML_DSA_65", Some("CKK_ML_DSA")),
            ("CKP_ML_KEM_768", Some("CKK_ML_KEM")),
            ("CKP_SLH_DSA_SHA2_128S", Some("CKK_SLH_DSA")),
            ("CKP_PKCS5_PBKD2_HMAC_SHA1", None),
            ("ML_DSA_65", None),
        ] {
            assert_eq!(parameter_set_key_type(name), want, "{name}");
        }
    }
}
