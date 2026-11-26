//! The effective capability of a stack (docs/CAPROBE.md D3). A stack consists of one module
//! profile, the delta layers between cakeys and the module, and the baseline that names and
//! groups every member. Every verdict names the profile that decided it. A "no" therefore names
//! the layer that removed the capability, and an "unknown" says why the profiles cannot decide
//! (the conservative answers of D5).

use crate::baseline::Baseline;
use crate::capability::{Capability, On};
use crate::names::KeyKind;
use crate::profile::{Profile, Why};

/// Returns the capability row for the generation of `key_type` on `on`.
fn generate(key_type: &str, on: On) -> Capability {
    Capability::Generate { key_type: KeyKind::from(key_type), on }
}

/// The answer to a query: yes (with the profile that decided it), no (with the profile and the
/// reason), or unknown (with the reason why the profiles cannot decide). No and unknown cause
/// different exit codes (15 and 16), so a check can tell a definite refusal apart from a question
/// that the profiles do not cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The stack can do it.
    Yes {
        /// The profile that decided the answer.
        by: String,
        /// The profile's note on the row, when it has one.
        note: Option<String>,
    },
    /// The stack cannot do it (exit 15).
    No {
        /// The profile that decided the answer: the layer that removed the capability, or the
        /// module's profile.
        by: String,
        /// The reason, when the profile gives one.
        note: Option<String>,
    },
    /// The profiles cannot decide (exit 16).
    Unknown {
        /// The reason why the profiles cannot decide.
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
/// layers on top of the module. A capability is supported only if every layer allows it. A
/// subtraction in any layer decides no, and otherwise the module's observed set decides.
pub struct Effective<'a> {
    baseline: &'a Baseline,
    module: Option<&'a Profile>,
    layers: &'a [&'a Profile],
}

impl<'a> Effective<'a> {
    /// Composes a stack from its parts. The baseline comes from the loaded set. The module
    /// profile is optional, because a query about layers only or about a class needs no module
    /// profile. The layers are applied in the order given.
    #[must_use]
    pub fn new(baseline: &'a Baseline, module: Option<&'a Profile>, layers: &'a [&'a Profile]) -> Effective<'a> {
        Effective { baseline, module, layers }
    }

    /// The baseline this stack resolves names against.
    #[must_use]
    pub fn baseline(&self) -> &Baseline {
        self.baseline
    }

    /// Returns whether a mechanism is usable. The layers subtract first: a mechanism that a layer
    /// drops is no for every module behind that layer. Then the module's deltas against its
    /// advertised list decide. A profile without an `advertise` list (the probe records that list,
    /// phase 3) answers unknown, except for the mechanisms that its `add` list records as usable.
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
        // A mechanism that the profile records as usable (`add`) is yes, whether or not the
        // module advertises it, and also in a profile that records no advertised list.
        if m.add.iter().any(|x| x == name) {
            return Verdict::yes(&m.profile, m.notes.get(name));
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
        if m.advertise.iter().any(|x| x == name) {
            // A mechanism that is advertised but was never tried is not yes. A mechanism that the
            // tools never use (`scope`) is never asked about, so it keeps the answer that the
            // advertised list gives.
            if let Some(u) = m.untested.get(name).filter(|u| u.why != Why::Scope) {
                return Verdict::Unknown {
                    why: format!(
                        "module profile {} advertises it but did not test it ({}){}",
                        m.profile,
                        u.why.name(),
                        u.note.as_ref().map(|n| format!(": {n}")).unwrap_or_default()
                    ),
                };
            }
            Verdict::yes(&m.profile, m.notes.get(name))
        } else {
            Verdict::no(&m.profile, m.notes.get(name).cloned().or_else(|| Some("not advertised".into())))
        }
    }

    /// Returns the no that a layer gives to the generation of `key_type`, with `item` and a size
    /// in bits. A layer refuses when it subtracts the key type, when its hardware refuses the
    /// curve (D10), or when a `restrict` row bounds the size. A layer's `can` rows mean nothing
    /// in delta mode, because the module decides everything that the layers do not refuse.
    fn layers_refuse(&self, key_type: &str, item: Option<&str>, bits: Option<u32>) -> Option<Verdict> {
        for l in self.layers {
            if l.subtract.key_types.iter().any(|k| k == key_type) {
                return Some(Verdict::no(&l.profile, l.notes.get(key_type).cloned().or(l.subtract.note.clone())));
            }
            if let Some(item) = item
                && l.generation(key_type).is_some_and(|row| row.cannot.iter().any(|c| c == item))
            {
                return Some(Verdict::no(&l.profile, l.evidence(&generate(key_type, On::Item(item.to_owned())), item)));
            }
            for r in &l.restrict {
                if r.operation == "generate"
                    && r.key_type == key_type
                    && let Some(bits) = bits
                    && (r.max_bits.is_some_and(|max| bits > max) || r.min_bits.is_some_and(|min| bits < min))
                {
                    return Some(Verdict::no(&l.profile, r.note.clone()));
                }
            }
        }
        None
    }

    /// Returns whether a module generates a secret key of `key_type` that is `bytes` long, when
    /// the size is known (`CKA_VALUE_LEN`, from `valueLen` or from the length that the key type
    /// fixes). The order is the same as in [`Self::generate`]. First the layers subtract the key
    /// type and bound the size. Their `restrict` rows are in bits, so the length is multiplied by
    /// eight. Then the module's rows decide. A length that the probe tried is decided by its own
    /// row. A length between two lengths that generated is yes only for a key type whose length
    /// is free (a generic secret or an HMAC key). It is never yes for AES, whose only valid
    /// lengths are the three that AES defines. Any other length answers unknown, and the
    /// function never guesses.
    #[must_use]
    pub fn generate_secret(&self, key_type: &str, bytes: Option<u32>) -> Verdict {
        if !self.baseline.key_types.contains_key(key_type) {
            return Verdict::Unknown { why: format!("not a key type of baseline {}", self.baseline.baseline) };
        }
        if let Some(refused) = self.layers_refuse(key_type, None, bytes.map(|b| b.saturating_mul(8))) {
            return refused;
        }
        let Some(m) = self.module else {
            return Verdict::Unknown { why: "no module profile selected".into() };
        };
        let Some(row) = m.generation(key_type) else {
            return Verdict::Unknown { why: format!("module profile {} records no {key_type} generation", m.profile) };
        };
        if let Some(n) = bytes {
            let size_note = || m.evidence(&generate(key_type, On::Bytes(n)), &format!("{key_type} at {n} bytes"));
            let free = !matches!(KeyKind::from(key_type), KeyKind::Aes | KeyKind::Des3);
            let tried = tried(row.can_bytes.iter().copied(), row.cannot_bytes.iter().copied());
            match decide_size(&tried, n, free) {
                Size::No => return Verdict::no(&m.profile, size_note()),
                Size::Yes => return Verdict::yes(&m.profile, None),
                Size::Unknown if !tried.is_empty() => {
                    return Verdict::Unknown {
                        why: format!("module profile {} probed {} bytes only", m.profile, sizes(&tried)),
                    };
                }
                Size::Unknown => {}
            }
        }
        // The question is about the key type in general: yes when some length generated, and no
        // when every length that was tried was refused.
        if !row.can_bytes.is_empty() {
            return Verdict::yes(&m.profile, m.notes.get(key_type));
        }
        if !row.cannot_bytes.is_empty() {
            let tried: Vec<String> = row.cannot_bytes.iter().map(u32::to_string).collect();
            let why = m.notes.get(key_type).cloned().unwrap_or_else(|| format!("refused {} bytes", tried.join(", ")));
            return Verdict::no(&m.profile, Some(why));
        }
        Verdict::Unknown { why: format!("module profile {} records no {key_type} generation it can judge", m.profile) }
    }

    /// Returns whether a module computes the commitment `kind` (`hmac-sha256`, `cmac`, `kcv-ecb`
    /// and others) on a secret key of `key_type` that is `bytes` long, when the length is known.
    /// The module's `commit.*` row for that length decides. For a key type whose length is free,
    /// an untried length is yes when the nearest tried lengths on both sides worked, and any
    /// other length is unknown (so a length below a refused length is never yes). Without a
    /// length, a free key type is yes when any length worked. A profile without such rows
    /// answers unknown, because it knows only the advertised mechanism.
    #[must_use]
    pub fn commit(&self, kind: &str, key_type: &str, bytes: Option<u32>) -> Verdict {
        let Some(m) = self.module else {
            return Verdict::Unknown { why: "no module profile selected".into() };
        };
        let kt = KeyKind::from(key_type);
        let rows = commit_rows(m, kind, &kt);
        if rows.is_empty() {
            return Verdict::Unknown { why: format!("module profile {} records no {kind} commitment", m.profile) };
        }
        let row = |b: u32| Capability::Commit { kind: kind.to_owned(), key_type: kt.clone(), bytes: b };
        let free = !matches!(kt, KeyKind::Aes | KeyKind::Des3);
        let unknown = || Verdict::Unknown {
            why: format!("module profile {} probed {kind} at {} bytes only", m.profile, sizes(&rows)),
        };
        if let Some(n) = bytes {
            return match decide_size(&rows, n, free) {
                Size::Yes => Verdict::yes(&m.profile, m.provenance(&row(n)).map(str::to_owned).as_ref()),
                Size::No => Verdict::no(&m.profile, m.evidence(&row(n), &format!("{kind} on {key_type} at {n} bytes"))),
                Size::Unknown => unknown(),
            };
        }
        // The question is about the commitment in general: no when every length that was tried
        // was refused.
        if rows.iter().all(|(_, yes)| !yes) {
            return Verdict::no(&m.profile, m.evidence(&row(rows[0].0), &format!("{kind} on {key_type}")));
        }
        if free {
            return Verdict::yes(&m.profile, None);
        }
        unknown()
    }

    /// Returns whether the module profile measured the commitment `kind` on `key_type` at any
    /// length. A caller uses it to tell apart two kinds of unknown from [`Self::commit`]: an
    /// unknown for a length that the probe did not try, and an unknown for a commitment that the
    /// probe never measured. In the second case, the advertised mechanism decides.
    #[must_use]
    pub fn measured_commit(&self, kind: &str, key_type: &str) -> bool {
        self.module.is_some_and(|m| !commit_rows(m, kind, &KeyKind::from(key_type)).is_empty())
    }

    /// Returns whether a module generates a key of `key_type`, optionally with one item (a curve,
    /// or a parameter set for the PQ types) and a modulus size. First the layers subtract key
    /// types and apply their size bounds. Then the module's `generate` row decides. An item or
    /// size that is in neither its `can` list nor its `cannot` list answers unknown, and the
    /// function never guesses.
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
        if let Some(refused) = self.layers_refuse(key_type, item, bits) {
            return refused;
        }
        let Some(m) = self.module else {
            return Verdict::Unknown { why: "no module profile selected".into() };
        };
        let Some(row) = m.generation(key_type) else {
            return Verdict::Unknown { why: format!("module profile {} records no {key_type} generation", m.profile) };
        };
        if let Some(bits) = bits {
            // The sizes that the probe tried decide first, and then the range that the module
            // reports. For a probed row, an untried size is yes only when it lies between two
            // sizes that generated. Any other untried size is unknown.
            let size_note = || m.evidence(&generate(key_type, On::Bits(bits)), &format!("{key_type} at {bits}"));
            let outside = row.max_bits.is_some_and(|max| bits > max) || row.min_bits.is_some_and(|min| bits < min);
            let tried = tried(row.can_bits.iter().copied(), row.cannot_bits.iter().copied());
            // Outside the reported range, no size is interpolated, and only a size that the probe
            // tried can override the range.
            match decide_size(&tried, bits, !outside) {
                Size::No => return Verdict::no(&m.profile, size_note()),
                Size::Yes => return Verdict::yes(&m.profile, None),
                Size::Unknown if outside => return Verdict::no(&m.profile, m.notes.get(key_type).cloned()),
                Size::Unknown if !tried.is_empty() => {
                    return Verdict::Unknown {
                        why: format!("module profile {} probed {} bits only", m.profile, sizes(&tried)),
                    };
                }
                Size::Unknown => {}
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
        // The question is about the key type in general. It is yes when some curve or size
        // generated, or when the module reports that it generates the key type. It is no when
        // every curve or size that was tried was refused. Rows that all answer no never make it
        // yes.
        if !row.can.is_empty() || !row.can_bits.is_empty() || m.reported.contains_key(key_type) {
            return Verdict::yes(&m.profile, m.notes.get(key_type));
        }
        if !row.cannot.is_empty() || !row.cannot_bits.is_empty() {
            let tried: Vec<String> =
                row.cannot.iter().cloned().chain(row.cannot_bits.iter().map(u32::to_string)).collect();
            let why = m.notes.get(key_type).cloned().unwrap_or_else(|| format!("refused {}", tried.join(", ")));
            return Verdict::no(&m.profile, Some(why));
        }
        Verdict::Unknown { why: format!("module profile {} records no {key_type} generation it can judge", m.profile) }
    }

    /// Returns whether a curve can be generated, over every key type that has a generation row in
    /// the module's profile or in a layer. Any yes decides first, then any no. Otherwise the
    /// answer is unknown, because no key type of this stack lists the curve. A layer's `cannot`
    /// row decides no even without a module profile, as it does for [`Self::generate`].
    #[must_use]
    pub fn curve(&self, name: &str) -> Verdict {
        if !self.baseline.curves.contains(name) {
            return Verdict::Unknown { why: format!("not a curve of baseline {}", self.baseline.baseline) };
        }
        let key_types: std::collections::BTreeSet<&str> = self
            .module
            .into_iter()
            .chain(self.layers.iter().copied())
            .flat_map(Profile::generation_key_types)
            .collect();
        let verdicts: Vec<Verdict> = key_types.into_iter().map(|kt| self.generate(kt, Some(name), None)).collect();
        let unknown = match self.module {
            None => "no module profile selected".to_owned(),
            Some(m) => format!("no generate row of module profile {} lists the curve", m.profile),
        };
        verdicts
            .iter()
            .find(|v| matches!(v, Verdict::Yes { .. }))
            .or_else(|| verdicts.iter().find(|v| matches!(v, Verdict::No { .. })))
            .cloned()
            .unwrap_or(Verdict::Unknown { why: unknown })
    }

    /// Answers a query about a bare name. A `CKM_*` name is a mechanism, and a `CKK_*` name is a
    /// key type. A `CKP_*` name of a PQ parameter set is generated with its PQ key type. Any other
    /// name is a curve. `bits` asks about an RSA size.
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

    /// Returns the RSA-OAEP hashes that are usable for wrapping, with their verdicts. No layer
    /// subtracts any of them today (whether p11-kit forwards OAEP wrapping is [todo],
    /// docs/CAMIGRATE.md).
    #[must_use]
    pub fn oaep(&self) -> Vec<(String, Verdict)> {
        match self.module {
            None => vec![("OAEP".into(), Verdict::Unknown { why: "no module profile selected".into() })],
            Some(m) => match m.wrap_oaep().as_deref() {
                None => vec![(
                    "OAEP".into(),
                    Verdict::Unknown { why: format!("module profile {} records no OAEP probe", m.profile) },
                )],
                // The probe ran, and no hash completed a round trip.
                Some([]) => vec![("OAEP".into(), Verdict::no(&m.profile, m.notes.get("oaep").cloned()))],
                Some(hashes) => {
                    hashes.iter().map(|h| (h.clone(), Verdict::yes(&m.profile, m.notes.get("oaep")))).collect()
                }
            },
        }
    }
}

/// The verdict that the sizes a probe tried give for size `n`.
enum Size {
    /// `n` was tried and worked, or, for a free size, `n` lies between two sizes that worked.
    Yes,
    /// `n` was tried and refused. A size with both a working row and a refused row counts as
    /// refused.
    No,
    /// Any other case. An untried size never takes the no that the tried sizes gave (review
    /// 2026-11-24 A-9).
    Unknown,
}

/// The single rule that decides a size, in bits for [`Effective::generate`] and in bytes for
/// [`Effective::generate_secret`] and [`Effective::commit`]. A tried size is decided by its own
/// rows. An untried size is yes only when `free` is true and [`between_working`] holds, and it
/// is unknown otherwise.
fn decide_size(tried: &[(u32, bool)], n: u32, free: bool) -> Size {
    let at: Vec<bool> = tried.iter().filter(|(s, _)| *s == n).map(|(_, ok)| *ok).collect();
    if at.contains(&false) {
        Size::No
    } else if !at.is_empty() || (free && between_working(tried, n)) {
        Size::Yes
    } else {
        Size::Unknown
    }
}

/// Returns whether `n`, a size that the probe did not try, lies between the nearest tried sizes
/// on either side, and both of those sizes worked. If the nearest tried size on one side was
/// refused (for example, because a TPM has discrete sizes or a module has a minimum HMAC
/// length), or if no size was tried on one side, `n` stays unknown. A size with both a working
/// row and a refused row counts as refused. This is the single rule by which a size is
/// interpolated, in bits for [`Effective::generate`] and in bytes for
/// [`Effective::generate_secret`] and [`Effective::commit`] (review 2026-11-23 A-1).
fn between_working(tried: &[(u32, bool)], n: u32) -> bool {
    let worked = |size: u32| tried.iter().filter(|(s, _)| *s == size).all(|(_, ok)| *ok);
    let below = tried.iter().map(|(s, _)| *s).filter(|s| *s < n).max();
    let above = tried.iter().map(|(s, _)| *s).filter(|s| *s > n).min();
    below.zip(above).is_some_and(|(lo, hi)| worked(lo) && worked(hi))
}

/// Returns the lengths at which `m` measured the commitment `kind` on `kt`, each with whether it
/// worked.
fn commit_rows(m: &Profile, kind: &str, kt: &KeyKind) -> Vec<(u32, bool)> {
    m.capabilities
        .iter()
        .filter_map(|(c, r)| match c {
            Capability::Commit { kind: k, key_type: t, bytes: b } if k == kind && t == kt => Some((*b, r.answer.yes())),
            _ => None,
        })
        .collect()
}

/// Merges `can` and `cannot` into one list of tried sizes, each with whether it worked.
fn tried(can: impl IntoIterator<Item = u32>, cannot: impl IntoIterator<Item = u32>) -> Vec<(u32, bool)> {
    can.into_iter().map(|s| (s, true)).chain(cannot.into_iter().map(|s| (s, false))).collect()
}

/// Returns the tried sizes, sorted, as the message of an unknown verdict lists them.
fn sizes(tried: &[(u32, bool)]) -> String {
    let mut sizes: Vec<u32> = tried.iter().map(|(s, _)| *s).collect();
    sizes.sort_unstable();
    sizes.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
}

/// Returns the PQ key type to which a `CKP_*` parameter set belongs ([`Effective::query`]). The
/// PBKDF2 pseudo-random functions also use the `CKP_*` prefix, but they belong to no key type.
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

    /// A small baseline for the tests of the verdict rules. The tests in lib.rs exercise the
    /// real committed baseline through [`crate::Set::embedded`].
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
            CKK_GENERIC_SECRET = 0x10
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

    /// An advertised mechanism that the probe did not try is unknown, and never yes, unless the
    /// tools never use it (`scope`). The test also checks that an `[untested]` entry for a
    /// mechanism that the module does not advertise is reported as a problem.
    #[test]
    fn an_untested_mechanism_is_unknown_not_yes() {
        let b = baseline();
        let m = profile(
            "profile = \"m/1\"\nmode = \"observed\"\nadvertise = [\"CKM_AES_KEY_WRAP\", \"CKM_SHA512_HMAC\", \"CKM_X\"]\n\
             [untested]\n\"CKM_AES_KEY_WRAP\" = { why = \"cryptoki\", note = \"no name\" }\n\
             \"CKM_SHA512_HMAC\" = { why = \"scope\" }\n\"CKM_GONE\" = { why = \"vendor\" }\n",
        );
        let e = eff(&b, Some(&m), &[]);
        let Verdict::Unknown { why } = e.mechanism("CKM_AES_KEY_WRAP") else { panic!() };
        assert!(why.contains("did not test it (cryptoki): no name"), "{why}");
        assert!(matches!(e.mechanism("CKM_SHA512_HMAC"), Verdict::Yes { .. }));
        assert_eq!(m.untested_problems(), ["[untested] CKM_GONE: the module does not advertise it"]);
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

    /// A mechanism that a partial profile's `add` records as usable is yes, without an advertised
    /// list. Every other mechanism stays unknown (review effective.rs F3).
    #[test]
    fn a_partial_module_profile_answers_its_add() {
        let b = baseline();
        let partial = profile("profile = \"m/1\"\nmode = \"observed\"\npartial = true\nadd = [\"CKM_ECDSA\"]");
        assert!(matches!(eff(&b, Some(&partial), &[]).mechanism("CKM_ECDSA"), Verdict::Yes { by, .. } if by == "m/1"));
        assert!(matches!(eff(&b, Some(&partial), &[]).mechanism("CKM_SHA512_HMAC"), Verdict::Unknown { .. }));
        // A layer's subtraction still decides first.
        let layer = profile("profile = \"l\"\nmode = \"delta\"\n[subtract]\nmechanisms = [\"CKM_ECDSA\"]");
        assert!(matches!(eff(&b, Some(&partial), &[&layer]).mechanism("CKM_ECDSA"), Verdict::No { .. }));
    }

    /// A curve that a layer refuses is no even when no module profile is selected, as a
    /// generation that a layer refuses is (review effective.rs F4). A curve that no layer refuses
    /// stays unknown.
    #[test]
    fn a_layer_refuses_a_curve_without_a_module() {
        let b = baseline();
        let hw = profile(
            "profile = \"hw\"\nmode = \"delta\"\n[capabilities]\n\"generate.CKK_EC.secp256k1\" = { answer = \"no\" }\n",
        );
        let layers = [&hw];
        assert!(matches!(eff(&b, None, &layers).curve("secp256k1"), Verdict::No { by, .. } if by == "hw"));
        assert!(matches!(
            eff(&b, None, &layers).curve("secp256r1"),
            Verdict::Unknown { why } if why == "no module profile selected"
        ));
        assert!(matches!(eff(&b, None, &layers).generate("CKK_EC", Some("secp256k1"), None), Verdict::No { .. }));
        // With a module that generates it, the layer's no still wins.
        let module = profile(
            "profile = \"x/1\"\nmode = \"observed\"\n[capabilities]\n\"generate.CKK_EC.secp256k1\" = { answer = \"yes\" }\n",
        );
        assert!(matches!(eff(&b, Some(&module), &layers).curve("secp256k1"), Verdict::No { by, .. } if by == "hw"));
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
        // A restriction states a bound in bits. Without a size in bits, the restriction cannot
        // decide. With a size beyond the bound, it decides no.
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

    /// A question that the stack cannot answer is unknown, and never a guess. That covers a stack
    /// without a module profile, a name that the baseline lacks, and an RSA size outside the
    /// probed sizes. A layer's own `cannot` row is a no, and a size between two sizes that
    /// generated is a yes.
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

    /// A query about a key type without a curve or size is no when every row for that key type
    /// is a no. (Before the fix, any row at all made the answer yes.) A size between two sizes
    /// that generated is unknown when a refused size lies between them, because a TPM generates
    /// only its discrete sizes.
    #[test]
    fn refused_rows_never_add_up_to_yes() {
        let b = baseline();
        let tpm = profile(
            "profile = \"tpm/1\"\nmode = \"observed\"\n[capabilities]\n\
             \"generate.CKK_EC.secp256r1\" = { answer = \"no\" }\n\"generate.CKK_EC.secp256k1\" = { answer = \"no\" }\n\
             \"generate.CKK_RSA.1024\" = { answer = \"yes\" }\n\"generate.CKK_RSA.1536\" = { answer = \"no\" }\n\
             \"generate.CKK_RSA.2048\" = { answer = \"yes\" }\n\"generate.CKK_RSA.3072\" = { answer = \"yes\" }\n",
        );
        let stack = eff(&b, Some(&tpm), &[]);
        let v = stack.generate("CKK_EC", None, None);
        assert!(matches!(&v, Verdict::No { note: Some(n), .. } if n.contains("secp256k1, secp256r1")), "{v:?}");
        assert!(matches!(stack.generate("CKK_RSA", None, None), Verdict::Yes { .. }));
        assert!(matches!(stack.generate("CKK_AES", None, None), Verdict::Unknown { .. }));
        assert!(matches!(stack.generate("CKK_RSA", None, Some(2560)), Verdict::Yes { .. }));
        for bits in [1280, 1792] {
            let v = stack.generate("CKK_RSA", None, Some(bits));
            assert!(matches!(&v, Verdict::Unknown { why } if why.contains("1024, 1536, 2048, 3072")), "{bits}: {v:?}");
        }
    }

    /// A secret-key length that the probe did not try is yes only when it lies between the
    /// nearest two tried lengths and both of them worked. This holds for a commitment and for a
    /// generation. A length below a refused length, beyond the last tried length, or across a
    /// refused length is unknown, and never a guess. Before the fix, `SoftHSM`'s rows (16 bytes
    /// refused, 32 and 64 bytes computed) made 8 bytes a yes (review 2026-11-23 A-1).
    #[test]
    fn secret_lengths_interpolate_only_between_two_that_worked() {
        let b = baseline();
        let m = profile(
            "profile = \"m/1\"\nmode = \"observed\"\n[capabilities]\n\
             \"commit.hmac-sha256.CKK_GENERIC_SECRET.16\" = { answer = \"no\" }\n\
             \"commit.hmac-sha256.CKK_GENERIC_SECRET.32\" = { answer = \"yes\" }\n\
             \"commit.hmac-sha256.CKK_GENERIC_SECRET.64\" = { answer = \"yes\" }\n\
             \"commit.hmac-sha256.CKK_GENERIC_SECRET.128\" = { answer = \"no\" }\n\
             \"commit.hmac-sha256.CKK_GENERIC_SECRET.256\" = { answer = \"yes\" }\n\
             \"generate.CKK_GENERIC_SECRET.16\" = { answer = \"yes\" }\n\
             \"generate.CKK_GENERIC_SECRET.24\" = { answer = \"no\" }\n\
             \"generate.CKK_GENERIC_SECRET.32\" = { answer = \"yes\" }\n\
             \"generate.CKK_GENERIC_SECRET.64\" = { answer = \"yes\" }\n",
        );
        let stack = eff(&b, Some(&m), &[]);
        let commit = |n: Option<u32>| stack.commit("hmac-sha256", "CKK_GENERIC_SECRET", n);
        let unknown = |v: Verdict, n: Option<u32>| {
            assert!(
                matches!(&v, Verdict::Unknown { why } if why.ends_with("16, 32, 64, 128, 256 bytes only")),
                "{n:?}: {v:?}"
            );
        };
        for n in [8, 24, 96, 512] {
            unknown(commit(Some(n)), Some(n));
        }
        assert!(matches!(commit(Some(48)), Verdict::Yes { .. }));
        assert!(matches!(commit(Some(16)), Verdict::No { .. }));
        assert!(matches!(commit(None), Verdict::Yes { .. }), "the key type at all: some length worked");
        let generate = |n: u32| stack.generate_secret("CKK_GENERIC_SECRET", Some(n));
        for n in [8, 20, 128] {
            assert!(
                matches!(&generate(n), Verdict::Unknown { why } if why.ends_with("16, 24, 32, 64 bytes only")),
                "{n} bytes: {:?}",
                generate(n)
            );
        }
        assert!(matches!(generate(48), Verdict::Yes { .. }));
    }

    /// One rule decides a size for every query (review 2026-11-24 A-9). A length that the probe
    /// did not try is unknown, whatever the answers for the tried lengths were. It never takes
    /// the no that every tried length gave. A tried length is decided by its own row. The test
    /// covers generation in bits, generation in bytes and the commitments.
    #[test]
    fn an_untried_size_is_unknown_whatever_the_tried_ones_said() {
        type Ask<'a> = Box<dyn Fn(u32) -> Verdict + 'a>;
        let b = baseline();
        let m = profile(
            "profile = \"m/1\"\nmode = \"observed\"\n[capabilities]\n\
             \"commit.hmac-sha256.CKK_GENERIC_SECRET.16\" = { answer = \"no\" }\n\
             \"commit.hmac-sha256.CKK_GENERIC_SECRET.32\" = { answer = \"no\" }\n\
             \"commit.cmac.CKK_AES.16\" = { answer = \"no\" }\n\
             \"generate.CKK_GENERIC_SECRET.16\" = { answer = \"no\" }\n\
             \"generate.CKK_GENERIC_SECRET.32\" = { answer = \"no\" }\n\
             \"generate.CKK_RSA.1024\" = { answer = \"no\" }\n\
             \"generate.CKK_RSA.2048\" = { answer = \"no\" }\n",
        );
        let stack = eff(&b, Some(&m), &[]);
        let asked: [(&str, Ask); 3] = [
            ("commit", Box::new(|n| stack.commit("hmac-sha256", "CKK_GENERIC_SECRET", Some(n)))),
            ("generate_secret", Box::new(|n| stack.generate_secret("CKK_GENERIC_SECRET", Some(n)))),
            ("generate", Box::new(|n| stack.generate("CKK_RSA", None, Some(n * 64)))),
        ];
        for (what, ask) in &asked {
            for n in [8, 24, 48] {
                assert!(matches!(ask(n), Verdict::Unknown { .. }), "{what} at {n}: {:?}", ask(n));
            }
            assert!(matches!(ask(32), Verdict::No { .. }), "{what} at a refused size: {:?}", ask(32));
        }
        let aes = stack.commit("cmac", "CKK_AES", Some(32));
        assert!(matches!(aes, Verdict::Unknown { .. }), "{aes:?}");
        // For a query about the key type in general, the module answers no when every tried
        // length was refused.
        assert!(matches!(stack.commit("hmac-sha256", "CKK_GENERIC_SECRET", None), Verdict::No { .. }));
    }

    /// A mechanism is usable when the module advertises it or the profile adds it, and in no
    /// other case. A verdict prints its answer, the profile that decided it, and the note.
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

    /// A layer subtracts the key types that it names and no others. A size bound, whether it is
    /// a layer's or the module's own, includes both ends.
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

    /// A parameter set belongs to the PQ key type that its name gives, and to no key type
    /// otherwise.
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
