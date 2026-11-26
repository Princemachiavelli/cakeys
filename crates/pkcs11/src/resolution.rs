//! Profile resolution (docs/CAPROBE.md D9, phase 2). It decides which module profile and which
//! delta layers make up a token's effective capability. The binding layer is always present. A
//! forwarder is recognized from the module itself, and the configuration names the other layers.
//! The module profile follows the provider family. Among the family's profiles, the one with the
//! most matching match keys is chosen: first the version that `C_GetInfo` reports, and then the
//! token's model and firmware (D9/D10). A module digest is never used. When a family has only one
//! committed profile, that profile matches by manufacturer alone, and the match is flagged as
//! low-evidence (kryoptic reports version 0.0 \[run\]).

use crate::binding;
use cakeys_core::config::{ModuleInfo, Observation, Said, TokenCfg, TokenInfo};
use cakeys_profile::{Answer, Capability, Mode, Profile, Row, Set};
use std::collections::BTreeSet;

/// A token's resolved profiles, which [`crate::Token`] holds and every consumer reads.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    /// The module profile, when a profile is committed for the selected provider family.
    pub module: Option<Profile>,
    /// The delta layers, innermost first: the binding, any forwarder that the module names, and
    /// the extra layers of the configuration.
    pub layers: Vec<Profile>,
    /// What resolution noticed while it ran (for example, a low-evidence version match). `caps`
    /// prints these notes, so a resolved stack is never a guess that nobody is told about.
    pub notes: Vec<String>,
    /// The name and the note of a layer that hides the module behind it (`requires-provider`)
    /// when keys.toml names no provider for that module. A plan prints a warning with it.
    pub hidden: Option<String>,
}

impl Resolved {
    /// Returns the module profile's name, for `caps` and for messages.
    #[must_use]
    pub fn module_name(&self) -> Option<&str> {
        self.module.as_ref().map(|p| p.profile.as_str())
    }

    /// Places the answers of this deployment's token (`observed.capabilities`, which is the
    /// lock's record of what its runs demonstrated and what the probe measured) over the module
    /// profile. The token's own answer takes precedence over what a shipped profile says about
    /// its kind of token. When there is no module profile, the answers form a partial profile by
    /// themselves, which says nothing about mechanisms. A row that this version of cakeys cannot
    /// read is ignored. A recorded answer that agrees with the profile and does not say how
    /// (`via`) keeps the profile's `via`. So a lock that was written before cakeys recorded
    /// `via = "by-name"` still lets a curve that is generated only by name retry by name
    /// (ISSUES.md B18).
    pub fn with_answers(&mut self, token: &str, observed: &Observation) {
        let rows: Vec<(Capability, Row)> = observed
            .capabilities
            .iter()
            .filter_map(|(k, a)| {
                let answer = match a.answer {
                    Said::Yes => Answer::Yes,
                    Said::No => Answer::No,
                    Said::Other(_) => return None,
                };
                Some((
                    Capability::parse(k).ok()?,
                    Row { answer, by: None, evidence: a.evidence.clone(), via: a.via.clone() },
                ))
            })
            .collect();
        if rows.is_empty() {
            return;
        }
        let module = self.module.get_or_insert_with(|| Profile {
            partial: true,
            ..Profile::new(format!("{token} (as recorded)"), Mode::Observed)
        });
        self.notes.push(format!(
            "{} answer(s) recorded for token '{token}' decide before profile {}",
            rows.len(),
            module.profile
        ));
        for (capability, mut row) in rows {
            if row.via.is_none()
                && let Some(had) = module.capabilities.get(&capability).filter(|had| had.answer == row.answer)
            {
                row.via.clone_from(&had.via);
            }
            module.capabilities.insert(capability, row);
        }
    }

    /// Returns the names of the layers, in order.
    #[must_use]
    pub fn layer_names(&self) -> Vec<&str> {
        self.layers.iter().map(|p| p.profile.as_str()).collect()
    }

    /// Returns every mechanism that the stack subtracts from the module's advertised list.
    #[must_use]
    pub fn subtracted_mechanisms(&self) -> BTreeSet<&str> {
        self.module
            .iter()
            .chain(self.layers.iter())
            .flat_map(|p| p.subtract.mechanisms.iter().map(String::as_str))
            .collect()
    }

    /// Returns every mechanism that the stack adds although the module does not list it (a
    /// provider's substitute that the probe found to work, `Provider::stand_in`).
    #[must_use]
    pub fn added_mechanisms(&self) -> BTreeSet<&str> {
        self.module.iter().chain(self.layers.iter()).flat_map(|p| p.add.iter().map(String::as_str)).collect()
    }

    /// Returns every key type that the stack subtracts (the key types that an unpatched binding
    /// maps wrongly).
    #[must_use]
    pub fn subtracted_key_types(&self) -> BTreeSet<&str> {
        self.module
            .iter()
            .chain(self.layers.iter())
            .flat_map(|p| p.subtract.key_types.iter().map(String::as_str))
            .collect()
    }
}

/// Returns the `ModuleInfo` of a module that nobody has seen yet, which is the case for keys.toml's
/// provider alone (the static gate) or for a transport file. Such a module gives nothing from which
/// to detect a forwarder, but the binding layer still applies.
#[must_use]
pub fn moduleless_info() -> ModuleInfo {
    ModuleInfo {
        path: String::new(),
        hash: None,
        description: String::new(),
        manufacturer: String::new(),
        version: String::new(),
        cryptoki: String::new(),
    }
}

/// Resolves a token's profiles. `provider` is the name of the selected provider (or of the
/// explicitly configured one, which is a family and never a profile, docs/CONFIG.md). `token` is
/// what `C_GetTokenInfo` returned, when there is a token (its firmware matches a module that hides
/// its version).
///
/// # Errors
///
/// The parse error of [`Set::embedded`], or the message for a layer that the configuration names
/// but no profile set has. The token open maps both to exit code 17. A module version that no
/// profile records is never an error: the nearest profile is used instead, with a note.
pub fn resolve(
    cfg: &TokenCfg,
    module: &ModuleInfo,
    token: Option<&TokenInfo>,
    provider: &str,
) -> Result<Resolved, String> {
    let set = Set::active()?;
    let mut out = Resolved::default();
    // The binding layer is always present, because it sits between cakeys and every module.
    out.layers.push(binding::layer()?);
    out.add_forwarders(set, module);
    out.add_configured(set, cfg)?;
    out.hidden = hidden_module(cfg, &out.layers);
    out.module = out.module_profile(set, cfg, module, token, provider)?;
    Ok(out)
}

impl Resolved {
    /// Adds a forwarder that the module itself names (p11-kit's client, which `C_GetInfo`
    /// describes).
    fn add_forwarders(&mut self, set: &Set, module: &ModuleInfo) {
        for p in set.all() {
            if p.mode == Mode::Delta
                && p.profile != binding::NAME
                && p.r#match.manufacturer.as_deref() == Some(module.manufacturer.as_str())
                && !self.layers.iter().any(|l| l.profile == p.profile)
            {
                self.notes.push(format!(
                    "{} is in the path: {} (detected from C_GetInfo)",
                    p.profile,
                    p.r#match.manufacturer.as_deref().unwrap_or_default()
                ));
                self.layers.push(p.clone());
            }
        }
    }

    /// Adds the extra layers of the configuration, by name or family (the hardware under the
    /// module, or a forwarder that the module does not name). A layer that is named explicitly is
    /// applied, even when nothing detected it.
    fn add_configured(&mut self, set: &Set, cfg: &TokenCfg) -> Result<(), String> {
        for name in &cfg.profiles {
            if self.layers.iter().any(|l| l.profile == name.as_str() || l.family() == name.as_str()) {
                continue;
            }
            self.layers.push(set.find(name)?.clone());
        }
        Ok(())
    }

    /// Returns the module profile of the configured provider's family, or otherwise of the
    /// selected provider's family. A profile is observed on a module and the hardware under it
    /// (D9/D10), so the profile with the most matching match keys is chosen: first the reported
    /// version (`C_GetInfo`; a module that hides it as 0.0 records none), and then the token's
    /// model and firmware. A match on less than all of these keys gets a note, and the rows that
    /// the hardware decides are dropped when the hardware is not known to be the observed
    /// hardware. A `moduleProfile` that names one profile of the family selects only that
    /// profile.
    fn module_profile(
        &mut self,
        set: &Set,
        cfg: &TokenCfg,
        module: &ModuleInfo,
        token: Option<&TokenInfo>,
        provider: &str,
    ) -> Result<Option<Profile>, String> {
        let family = cfg.named_provider().unwrap_or(provider);
        let candidates = module_candidates(set, family, cfg.module_profile.as_deref())?;
        let Some((chosen, tied, unversioned)) = choose(&candidates, &self.layers, module, token) else {
            return Ok(None);
        };
        let mut p = chosen.clone();
        if unversioned {
            self.nearest_version(&mut p, family, &candidates, module);
        }
        if tied.len() > 1 && token.is_none() {
            self.hardware_unknown(&mut p, &tied);
        }
        let fit = Fit::of(&p, module, token);
        self.weak_match(&p, &fit, unversioned, module, token);
        if fit.model == Some(false) || fit.firmware == Some(false) {
            self.other_hardware(&mut p, token);
        } else if tied.len() > 1 && token.is_some() {
            self.tied_on_this_hardware(&p, &tied);
        }
        Ok(Some(p))
    }

    /// Adds a note for pairs whose match keys are all the same (a FIPS and a non-FIPS `CloudHSM`
    /// cluster, because PKCS#11 reports no mode, D12) when this token fits all of them equally.
    /// The first pair is used with all its rows, and the note says so, so that the stack is never
    /// a guess that nobody is told about.
    fn tied_on_this_hardware(&mut self, p: &Profile, tied: &[&Profile]) {
        self.notes.push(format!(
            "module profiles {} fit this module and token equally: using {}; name another in \
             tokens.<token>.moduleProfile",
            tied.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", "),
            p.profile
        ));
    }

    /// Handles a module version that no profile of the family records (typically after an
    /// update). The nearest profile's module rows are kept, and its measured rows answer unknown
    /// ([`clear_hardware_rows`]). This is never an error, because a missing profile must not stop
    /// the token from opening (P1).
    fn nearest_version(&mut self, p: &mut Profile, family: &str, candidates: &[&Profile], module: &ModuleInfo) {
        self.notes.push(format!(
            "no module profile for '{family}' ({}) records module version '{}': using the nearest, {}, \
             without its measured rows (unknown); profile this module with \
             `caprobe probe` (docs/CAPROBE.md)",
            candidates.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", "),
            module.version,
            p.profile
        ));
        clear_hardware_rows(p);
    }

    /// Handles pairs of one module on several kinds of hardware when there is no token to say
    /// which hardware applies. What the module lists is taken from one of the pairs. Its measured
    /// rows depend on the hardware, so they answer unknown, as they do for hardware on which no
    /// pair was observed.
    fn hardware_unknown(&mut self, p: &mut Profile, tied: &[&Profile]) {
        self.notes.push(format!(
            "module profiles {} fit equally and the hardware is not known here: using {}'s module \
             rows, its measured rows are not used (unknown); name the \
             hardware in tokens.<token>.profiles, or the pair in tokens.<token>.moduleProfile",
            tied.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", "),
            p.profile
        ));
        clear_hardware_rows(p);
    }

    /// Adds a note for a module profile that matched on less than the module's version: by the
    /// manufacturer alone, or by the token's firmware when the module hides its version. No note
    /// is added when no profile records the module's version, because [`Self::nearest_version`]
    /// has already added one.
    fn weak_match(
        &mut self,
        p: &Profile,
        fit: &Fit,
        unversioned: bool,
        module: &ModuleInfo,
        token: Option<&TokenInfo>,
    ) {
        match (&p.r#match.module_version, fit.firmware) {
            (Some(_), _) if unversioned => {}
            (Some(v), _) if fit.version == Some(false) => self.notes.push(format!(
                "module profile {} matched by manufacturer alone: the module reports version '{}' \
                 where the profile records '{v}'",
                p.profile, module.version
            )),
            (None, Some(true)) => self.notes.push(format!(
                "module profile {} matched by the token's firmware {}: the module reports version \
                 '{}', which says nothing (secondary evidence, D9)",
                p.profile,
                seen(p.r#match.firmware.as_ref()),
                module.version
            )),
            (None, _) => self.notes.push(format!(
                "module profile {} matched by manufacturer alone: the module hides its version and the \
                 token's firmware is {} where the profile records {}",
                p.profile,
                seen(token.map(|t| &t.firmware)),
                seen(p.r#match.firmware.as_ref())
            )),
            _ => {}
        }
    }

    /// Handles another kind of hardware under the same module. What the module advertises still
    /// holds, but its measured rows depend on the hardware, so they answer unknown and do not
    /// give the observed hardware's answer.
    fn other_hardware(&mut self, p: &mut Profile, token: Option<&TokenInfo>) {
        self.notes.push(format!(
            "module profile {} was observed on model {} firmware {}, this token is model {} \
             firmware {}: its measured rows are not used (unknown)",
            p.profile,
            seen(p.r#match.model.as_ref()),
            seen(p.r#match.firmware.as_ref()),
            seen(token.map(|t| &t.model)),
            seen(token.map(|t| &t.firmware))
        ));
        clear_hardware_rows(p);
    }
}

/// Returns the name of a passthrough layer and the reason why it hides the module behind it, for
/// a plan to warn with. Only a provider name other than the passthrough's own family (which is
/// the provider that an observation records) says what that module is.
fn hidden_module(cfg: &TokenCfg, layers: &[Profile]) -> Option<String> {
    let named = |l: &Profile| cfg.named_provider().is_some_and(|p| p != l.family() && p != l.profile);
    let l = layers.iter().find(|l| l.requires_provider && !named(l))?;
    let why = l.notes.get("requires-provider").map_or("it hides the module behind it", String::as_str);
    Some(format!("{}: {why}", l.profile))
}

/// Returns a match key in the form in which a note quotes it.
fn seen(x: Option<&String>) -> String {
    x.map_or_else(|| "unrecorded".to_owned(), |x| format!("'{x}'"))
}

/// Returns the observed module profiles of `family`, or only the profile that `pinned` names
/// (`moduleProfile`).
///
/// # Errors
///
/// An error when `pinned` names a profile that the set does not have.
fn module_candidates<'a>(set: &'a Set, family: &str, pinned: Option<&str>) -> Result<Vec<&'a Profile>, String> {
    if let Some(p) = pinned
        && !set.all().iter().any(|q| q.mode == Mode::Observed && q.profile == p)
    {
        return Err(format!("moduleProfile '{p}' is no module profile this build or a profileDirs entry has"));
    }
    Ok(set
        .all()
        .iter()
        .filter(|p| p.mode == Mode::Observed && p.family() == family && pinned.is_none_or(|n| p.profile == n))
        .collect())
}

/// Chooses the module profile among a family's `candidates`. Returns the chosen profile, the
/// profiles that fit equally well, and whether none of several candidates records the module's
/// version. The ranking uses first a configured hardware layer that names the pair
/// (`profiles = ["swtpm"]` -> `tpm2-pkcs11/1.10+swtpm`), and then the token's model and firmware.
/// A profile that records another module version is excluded when some profile records this
/// version. When no profile records this version, every candidate is eligible, and among equal
/// hardware the nearest recorded version is chosen ([`Nearness`]). Returns `None` for a family
/// with no profile.
fn choose<'a>(
    candidates: &[&'a Profile],
    layers: &[Profile],
    module: &ModuleInfo,
    token: Option<&TokenInfo>,
) -> Option<(&'a Profile, Vec<&'a Profile>, bool)> {
    let fit = |p: &Profile| Fit::of(p, module, token);
    let named_hardware = |p: &Profile| layers.iter().any(|l| p.profile.ends_with(&format!("+{}", l.profile)));
    match candidates {
        [] => None,
        [p] => Some((*p, vec![*p], false)),
        _ => {
            let eligible: Vec<&Profile> =
                candidates.iter().filter(|p| fit(p).version != Some(false)).copied().collect();
            let unversioned = eligible.is_empty();
            let eligible = if unversioned { candidates.to_vec() } else { eligible };
            let rank = |p: &Profile| {
                let near = if unversioned {
                    Nearness::of(p.r#match.module_version.as_deref(), &module.version)
                } else {
                    Nearness::Unknown
                };
                (named_hardware(p), fit(p).hardware_keys(), near)
            };
            let best = eligible.iter().map(|p| rank(p)).max()?;
            let tied: Vec<&Profile> = eligible.into_iter().filter(|p| rank(p) == best).collect();
            Some((tied[0], tied, unversioned))
        }
    }
}

/// How near a profile's recorded module version is to the module's version. The versions are
/// compared numerically for each dot-separated component (`1.10` is above `1.9`). The highest
/// recorded version at or below the module's version is the nearest. When there is none, the
/// lowest version above it is the nearest. A version that is not made of numbers (no recorded
/// version, or the empty version of a module that nobody has seen) is `Unknown`.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Nearness {
    Unknown,
    Above(std::cmp::Reverse<Vec<u64>>),
    AtOrBelow(Vec<u64>),
}

impl Nearness {
    fn of(recorded: Option<&str>, version: &str) -> Nearness {
        let parse = |v: &str| v.split('.').map(|c| c.parse::<u64>().ok()).collect::<Option<Vec<u64>>>();
        match (recorded.and_then(parse), parse(version)) {
            (Some(r), Some(v)) if r <= v => Nearness::AtOrBelow(r),
            (Some(r), Some(_)) => Nearness::Above(std::cmp::Reverse(r)),
            _ => Nearness::Unknown,
        }
    }
}

/// Drops the rows of a pair profile that depend on the hardware on which it was observed, and
/// the entries that the probe could not decide for those rows there ([`hardware_dependent`]). On
/// other or unknown hardware, those rows answer unknown, and only what the module advertises and
/// what is claimed of it (`move.*`) is kept (docs/CAPROBE.md, D10).
fn clear_hardware_rows(p: &mut Profile) {
    p.reported.clear();
    p.capabilities.retain(|c, _| !hardware_dependent(c));
    // What the probe could not decide on that hardware (`[untested]`, with the reason `device`
    // or `cakeys`) also belongs to that hardware, so on other hardware it is unknown, as the rows
    // are.
    p.untested.retain(|name, _| Capability::parse(name).map_or(true, |c| !hardware_dependent(&c)));
}

/// Returns whether a capability row's answer belongs to the hardware on which it was observed,
/// so that it is unknown on other hardware. Each kind is classified here without a wildcard, so
/// a kind that is added to `Capability` does not compile until it is classified (review
/// 2026-11-24 B-9: a `matches!` list carried 12 of 20 kinds, `prove.*` and `commit.*` among them,
/// over to hardware that was never measured).
///
/// Every measured kind depends on the hardware. Each such row is an operation that was run on a
/// key of that pair, and nothing in PKCS#11 says whether the module or the device refused it
/// (docs/CAPROBE.md, D10). A `move.*` row is not a measurement but this repository's claim
/// about the module ([`Capability::probed`]: it is kept across regenerations and never
/// compared), so it is kept.
fn hardware_dependent(c: &Capability) -> bool {
    match c {
        // What the module does, as it is claimed, and not as it was measured on one pair's
        // hardware.
        Capability::Move(_) => false,
        // The creation of keys and their movement in or out: generation, import, creation,
        // export, unwrap and deletion. The operations on a key: the proofs, the commitments, the
        // ciphers and derivations, the OAEP hashes, signing and encapsulation. The values to
        // which a key's attributes are set, and the values that are read back.
        Capability::Generate { .. }
        | Capability::Import { .. }
        | Capability::Create { .. }
        | Capability::Export { .. }
        | Capability::Unwrap { .. }
        | Capability::UnwrapTemplate(_)
        | Capability::Delete(_)
        | Capability::Prove { .. }
        | Capability::Commit { .. }
        | Capability::Crypt { .. }
        | Capability::Kdf { .. }
        | Capability::WrapOaep(_)
        | Capability::DecryptOaep(_)
        | Capability::DeriveSealed
        | Capability::DeriveReadOnly
        | Capability::DeriveEcdh { .. }
        | Capability::Sign { .. }
        | Capability::Encapsulate { .. }
        | Capability::Attr { .. } => true,
    }
}

/// How a module profile's match keys compare with a token. For each key, the field says whether
/// it matches (`None` means that the profile records no such key, or that there is no token to
/// compare with).
struct Fit {
    version: Option<bool>,
    model: Option<bool>,
    firmware: Option<bool>,
}

impl Fit {
    fn of(p: &Profile, module: &ModuleInfo, token: Option<&TokenInfo>) -> Fit {
        let m = &p.r#match;
        let key = |rec: Option<&String>, live: Option<&String>| rec.zip(live).map(|(r, l)| r == l);
        Fit {
            version: m.module_version.as_ref().map(|v| *v == module.version),
            model: key(m.model.as_ref(), token.map(|t| &t.model)),
            firmware: key(m.firmware.as_ref(), token.map(|t| &t.firmware)),
        }
    }

    /// Returns how many of the hardware keys match. This number breaks ties among the profiles
    /// of one version.
    fn hardware_keys(&self) -> usize {
        usize::from(self.model == Some(true)) + usize::from(self.firmware == Some(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(manufacturer: &str, version: &str) -> ModuleInfo {
        ModuleInfo {
            path: "/x.so".into(),
            hash: None,
            description: "d".into(),
            manufacturer: manufacturer.into(),
            version: version.into(),
            cryptoki: "3.2".into(),
        }
    }

    fn cfg(provider: Option<&str>, profiles: &[&str]) -> TokenCfg {
        TokenCfg {
            module: Some("/x.so".into()),
            provider: provider.map(Into::into),
            profiles: profiles.iter().map(|s| (*s).to_owned()).collect(),
            token_label: "t".into(),
            token_serial: None,
            module_profile: None,
            pin_file: None,
            pin_env: None,
            so_credential_file: None,
            so_credential_env: None,
            options: toml::Table::new(),
            probe: cakeys_core::config::ProbeCfg::default(),
            migrate: cakeys_core::config::TokenMigrateCfg::default(),
            nix: cakeys_core::config::NixCfg::default(),
        }
    }

    /// A lock that was written before cakeys recorded `via` holds a plain yes for a curve that,
    /// according to the profile, only its name generates. The answer keeps the profile's `via`,
    /// so the retry by name still runs (ISSUES.md B18). A recorded `via` is the token's own
    /// value, and a recorded no says nothing about how.
    #[test]
    fn a_recorded_answer_keeps_the_profiles_way_unless_it_names_one() {
        use cakeys_core::config::Answered;
        let row = Capability::Generate {
            key_type: "CKK_EC_EDWARDS".into(),
            on: cakeys_profile::On::Item("edwards25519".into()),
        };
        let after = |profile: Option<&str>, recorded: Answered| {
            let mut module = Profile::new("m".into(), Mode::Observed);
            module.capabilities.insert(
                row.clone(),
                Row { answer: Answer::Yes, by: None, evidence: None, via: profile.map(Into::into) },
            );
            let mut r = Resolved { module: Some(module), ..Resolved::default() };
            let mut observed = Observation::default();
            observed.capabilities.insert(row.to_string(), recorded);
            r.with_answers("t", &observed);
            r.module.unwrap().capabilities[&row].clone()
        };
        let by_name = Some("by-name".to_owned());
        assert_eq!(after(Some("by-name"), Answered::yes()).via, by_name);
        assert_eq!(after(None, Answered { via: by_name.clone(), ..Answered::yes() }).via, by_name);
        let no = after(Some("by-name"), Answered { answer: Said::No, ..Answered::yes() });
        assert_eq!((no.answer, no.via), (Answer::No, None));
    }

    #[test]
    fn every_stack_carries_the_binding_layer() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let r = resolve(&cfg(None, &[]), &module("Nobody", "1.0"), None, "generic").unwrap();
        assert!(r.module.is_none());
        assert_eq!(r.layer_names(), ["cryptoki/0.12"]);
    }

    #[test]
    fn the_module_profile_follows_the_provider_family() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let r = resolve(&cfg(None, &[]), &module("SoftHSM", "2.7"), None, "softhsm").unwrap();
        assert_eq!(r.module_name(), Some("softhsm/2.7"));
        assert_eq!(r.notes.len(), 0); // The reported version matches.
        // kryoptic hides its version (0.0), so the token's firmware is the secondary evidence.
        // In both cases, the match is flagged with a note.
        let firmware = |f: &str| TokenInfo { model: "v1".into(), serial: "s".into(), firmware: f.into() };
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), Some(&firmware("1.5")), "kryoptic").unwrap();
        assert_eq!(r.module_name(), Some("kryoptic/1.5"));
        assert_eq!(r.notes.len(), 1);
        assert!(r.notes[0].contains("by the token's firmware '1.5'"), "{:?}", r.notes);
        assert!(r.module.as_ref().unwrap().wrap_oaep().is_some());
        // Another firmware is flagged, and the hardware-dependent rows answer unknown.
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), Some(&firmware("1.6")), "kryoptic").unwrap();
        assert!(r.notes[0].contains("manufacturer alone"), "{:?}", r.notes);
        assert!(r.notes[1].contains("are not used"), "{:?}", r.notes);
        assert!(r.module.as_ref().unwrap().generation_key_types().is_empty());
        // The same applies to what the probe could not decide on that hardware (its
        // `[untested]` device entries).
        assert!(!r.module.as_ref().unwrap().untested.keys().any(|k| k.starts_with("generate.")));
        // With no token to compare with (a transport file), the match is flagged and the rows
        // are kept.
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), None, "kryoptic").unwrap();
        assert!(r.notes[0].contains("manufacturer alone"), "{:?}", r.notes);
        assert!(!r.module.as_ref().unwrap().generation_key_types().is_empty());
    }

    #[test]
    fn another_kind_of_hardware_keeps_the_advertisement_only() {
        cakeys_profile::Set::activate_embedded().unwrap();
        // A real TPM under the tpm2-pkcs11 that was observed on swtpm: what the module lists
        // still holds, but what it generates, wraps and unwraps depends on the TPM.
        let infineon = TokenInfo { model: "SLB9670".into(), serial: "s".into(), firmware: "7.85".into() };
        let r = resolve(&cfg(None, &[]), &module("tpm2-software.github.io", "1.10"), Some(&infineon), "tpm2-pkcs11")
            .unwrap();
        let m = r.module.as_ref().unwrap();
        assert!(m.profile.starts_with("tpm2-pkcs11/1.10+"), "{}", m.profile);
        assert!(!m.advertise.is_empty() && !m.subtract.mechanisms.is_empty());
        assert!(m.generation_key_types().is_empty() && m.wrap_oaep().is_none() && m.unwrap_refuse().is_none());
        assert!(m.decrypt_oaep().is_none());
        assert_eq!(r.notes.len(), 1, "{:?}", r.notes);
    }

    /// On other hardware, no measured row of any kind is kept, and neither is an entry that the
    /// probe left undecided (`[untested]`). The test walks every row of every committed profile
    /// by kind, and each measured row belongs to the hardware on which it was measured (review
    /// 2026-11-24 B-9: `prove.*` and `commit.*` rows carried a measured no over to hardware that
    /// was never measured, and that no became a refusal there). Every claim that this repository
    /// makes about the module (`move.*`, [`Capability::probed`]) belongs to the module and is
    /// kept. The kinds that the finding named are among the kinds walked, so the walk covers
    /// them.
    #[test]
    fn other_hardware_keeps_no_measured_row_of_any_kind() {
        let mut walked = BTreeSet::new();
        for (path, text) in cakeys_profile::embedded::PROFILE_FILES {
            let mut p = Profile::from_toml(text).unwrap_or_else(|e| panic!("{path}: {e}"));
            walked.extend(p.capabilities.keys().map(|c| c.to_string().split('.').next().unwrap_or("").to_owned()));
            let claims: Vec<String> = p.capabilities.keys().filter(|c| !c.probed()).map(ToString::to_string).collect();
            clear_hardware_rows(&mut p);
            let kept: Vec<String> = p.capabilities.keys().map(ToString::to_string).collect();
            assert_eq!(kept, claims, "{path}: the claims, and only they, stand");
            let undecided: Vec<&String> = p.untested.keys().filter(|k| Capability::parse(k).is_ok()).collect();
            assert!(undecided.is_empty(), "{path} keeps [untested] {undecided:?}");
            assert!(p.reported.is_empty(), "{path}");
        }
        for kind in ["generate", "prove", "commit", "move", "derive", "crypt", "delete", "attr"] {
            assert!(walked.contains(kind), "no committed row of {kind}: {walked:?}");
        }
    }

    /// The swtpm on which the pair was measured counts as that pair's hardware. tpm2-pkcs11 fills
    /// the token's model from the TPM's four vendor strings, swtpm's last two strings are NUL
    /// \[run\], and the probe writes the match key without the NULs. When the open read the model
    /// with the NULs, the model looked like another hardware's model, and the pair's measured rows
    /// (`delete.CKO_PRIVATE_KEY = no`) were never applied on the hardware that measured them.
    #[test]
    fn the_token_a_pair_was_measured_on_is_that_hardware() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let tpm2 = module("tpm2-software.github.io", "1.10");
        let sw = crate::token::token_info("SW   TPM\0\0\0\0\0\0\0\0", "0000000000000000", "36.37".into());
        let r = resolve(&cfg(None, &[]), &tpm2, Some(&sw), "tpm2-pkcs11").unwrap();
        assert!(r.notes.is_empty(), "{:?}", r.notes);
        let m = r.module.unwrap();
        assert_eq!(m.profile, "tpm2-pkcs11/1.10+swtpm");
        assert_eq!(m.answer(&Capability::Delete("CKO_PRIVATE_KEY".into())), Some(false));
    }

    #[test]
    fn pairs_of_one_module_resolve_by_their_hardware() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let tpm2 = module("tpm2-software.github.io", "1.10");
        let resolved = |cfg: &TokenCfg, token: Option<&TokenInfo>| {
            let r = resolve(cfg, &tpm2, token, "tpm2-pkcs11").unwrap();
            (r.module.unwrap(), r.notes)
        };
        // The token's model and firmware select the pair that was observed on that hardware,
        // with all its rows.
        let amd = TokenInfo { model: "AMD".into(), serial: "s".into(), firmware: "3.87".into() };
        let (m, notes) = resolved(&cfg(None, &[]), Some(&amd));
        assert_eq!(m.profile, "tpm2-pkcs11/1.10+amd-ftpm");
        assert!(!m.generation_key_types().is_empty() && notes.is_empty(), "{notes:?}");
        let sw = TokenInfo { model: "SW   TPM".into(), serial: "s".into(), firmware: "36.37".into() };
        assert_eq!(resolved(&cfg(None, &[]), Some(&sw)).0.profile, "tpm2-pkcs11/1.10+swtpm");
        // Without a token (validate by the provider alone), a configured hardware layer names
        // the pair.
        assert_eq!(resolved(&cfg(None, &["swtpm"]), None).0.profile, "tpm2-pkcs11/1.10+swtpm");
        // Without such a layer, the pairs tie: only the module rows are used, the hardware rows
        // are unknown, and a note says so.
        let (m, notes) = resolved(&cfg(None, &[]), None);
        assert!(m.generation_key_types().is_empty() && m.decrypt_oaep().is_none());
        assert!(notes.iter().any(|n| n.contains("fit equally")), "{notes:?}");
    }

    /// A module version that no profile of a family with several profiles records (after an
    /// update of the client library) opens with the nearest profile, with its hardware rows
    /// unknown and with a note. It is never an error. Pairs that tie on every key resolve to the
    /// first embedded pair, as with a recorded version.
    #[test]
    fn an_unrecorded_version_resolves_to_the_nearest_profile() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let amd = TokenInfo { model: "AMD".into(), serial: "s".into(), firmware: "3.87".into() };
        for (manufacturer, version, provider, token, expected) in [
            ("CloudHSM", "5.19", "aws-cloudhsm", None, "aws-cloudhsm/5.18+hsm2m-fips"),
            ("tpm2-software.github.io", "1.11", "tpm2-pkcs11", Some(&amd), "tpm2-pkcs11/1.10+amd-ftpm"),
            ("Google", "1.10", "kmsp11", None, "kmsp11/1.9+hsm-fips"),
        ] {
            let r = resolve(&cfg(None, &[]), &module(manufacturer, version), token, provider).unwrap();
            let m = r.module.as_ref().unwrap();
            assert_eq!(m.profile, expected, "{provider} {version}");
            assert!(
                m.generation_key_types().is_empty() && m.wrap_oaep().is_none() && m.decrypt_oaep().is_none(),
                "{provider}"
            );
            assert!(!m.advertise.is_empty(), "{provider}: the module rows stand");
            let note = format!("records module version '{version}': using the nearest, {expected}");
            assert!(r.notes.iter().any(|n| n.contains(&note) && n.contains("caprobe probe")), "{:?}", r.notes);
            assert!(!r.notes.iter().any(|n| n.contains("matched by manufacturer alone")), "{:?}", r.notes);
        }
    }

    #[test]
    fn the_nearest_version_is_the_highest_at_or_below_else_the_lowest_above() {
        let near = |r: &str, v: &str| Nearness::of(Some(r), v);
        assert!(near("1.9", "1.10") > near("1.8", "1.10"));
        assert!(near("1.10", "1.10") > near("1.9", "1.10"));
        assert!(near("1.9", "1.10") > near("1.11", "1.10"));
        assert!(near("1.11", "1.10") > near("2.0", "1.10"));
        assert_eq!(near("1.9", ""), Nearness::Unknown);
        assert_eq!(Nearness::of(None, "1.10"), Nearness::Unknown);
        assert_eq!(near("1.9-rc1", "1.10"), Nearness::Unknown);
    }

    #[test]
    fn a_forwarder_is_recognised_and_the_hidden_module_can_be_pinned() {
        cakeys_profile::Set::activate_embedded().unwrap();
        // Behind p11-kit, the module reports p11-kit, and the named provider still selects the
        // module profile.
        let r = resolve(&cfg(Some("softhsm"), &[]), &module("PKCS#11 Kit", "0.26"), None, "p11-kit").unwrap();
        assert_eq!(r.module_name(), Some("softhsm/2.7"));
        assert_eq!(r.layer_names(), ["cryptoki/0.12", "p11-kit/0.26"]);
        assert!(r.subtracted_mechanisms().contains("CKM_AES_KEY_WRAP"));
        assert_eq!(r.hidden, None);
    }

    /// Profiles that tie on every match key (a FIPS and a non-FIPS `CloudHSM` cluster, because
    /// PKCS#11 reports no mode, D12) resolve to the first embedded profile, which is the stricter
    /// one. A `moduleProfile` that names the other profile selects it, with or without a named
    /// provider. A name that no profile has is refused.
    #[test]
    fn a_module_profile_pin_takes_that_one() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let hsm = module("CloudHSM", "5.18");
        let tied = resolve(&cfg(None, &[]), &hsm, None, "aws-cloudhsm").unwrap();
        assert_eq!(tied.module_name(), Some("aws-cloudhsm/5.18+hsm2m-fips"));
        let pinned = |provider: Option<&str>, profile: &str| TokenCfg {
            module_profile: Some(profile.into()),
            ..cfg(provider, &[])
        };
        for provider in [Some("aws-cloudhsm"), None] {
            let r = resolve(&pinned(provider, "aws-cloudhsm/5.18+hsm2m-non-fips"), &hsm, None, "aws-cloudhsm").unwrap();
            assert_eq!(r.module_name(), Some("aws-cloudhsm/5.18+hsm2m-non-fips"), "{provider:?}");
        }
        let e = resolve(&pinned(None, "aws-cloudhsm/9.9"), &hsm, None, "aws-cloudhsm").unwrap_err();
        assert!(e.contains("moduleProfile 'aws-cloudhsm/9.9'"), "{e}");
    }

    /// With the token open, profiles that tie on every match key still resolve to the first
    /// profile with all its rows, and the run says that another profile fits as well
    /// (resolution.rs F1). A `NON_FIPS` cluster must not be judged by the FIPS profile without a
    /// message. A `moduleProfile` alone decides the profile, and hardware on which no pair was
    /// observed gets its own note.
    #[test]
    fn profiles_that_tie_on_the_token_are_said() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let ls2 = TokenInfo { model: "LS2".into(), serial: "s".into(), firmware: "10.23".into() };
        let kms = TokenInfo { model: "Cloud KMS Token".into(), serial: "s".into(), firmware: "0.0".into() };
        for (manufacturer, version, provider, token, chosen, other) in [
            (
                "CloudHSM",
                "5.18",
                "aws-cloudhsm",
                &ls2,
                "aws-cloudhsm/5.18+hsm2m-fips",
                "aws-cloudhsm/5.18+hsm2m-non-fips",
            ),
            ("Google", "1.9", "kmsp11", &kms, "kmsp11/1.9+hsm-fips", "kmsp11/1.9+hsm"),
        ] {
            let r = resolve(&cfg(None, &[]), &module(manufacturer, version), Some(token), provider).unwrap();
            let m = r.module.as_ref().unwrap();
            assert_eq!(m.profile, chosen);
            assert!(!m.generation_key_types().is_empty(), "{provider}: the hardware rows stand");
            let said: Vec<&String> =
                r.notes.iter().filter(|n| n.contains("fit this module and token equally")).collect();
            assert_eq!(said.len(), 1, "{:?}", r.notes);
            assert!(said[0].contains(chosen) && said[0].contains(other) && said[0].contains("moduleProfile"));
            let pinned = TokenCfg { module_profile: Some(other.into()), ..cfg(None, &[]) };
            let r = resolve(&pinned, &module(manufacturer, version), Some(token), provider).unwrap();
            assert_eq!((r.module_name(), r.notes.len()), (Some(other), 0), "{:?}", r.notes);
        }
        let infineon = TokenInfo { model: "SLB9670".into(), serial: "s".into(), firmware: "7.85".into() };
        let r = resolve(&cfg(None, &[]), &module("tpm2-software.github.io", "1.10"), Some(&infineon), "tpm2-pkcs11")
            .unwrap();
        assert!(!r.notes.iter().any(|n| n.contains("fit this module and token equally")), "{:?}", r.notes);
    }

    #[test]
    fn a_passthrough_hides_its_module_until_a_provider_is_named() {
        cakeys_profile::Set::activate_embedded().unwrap();
        // With no provider, or with the passthrough itself as the provider (which is what an
        // observation records), the module is hidden.
        let p11 = module("PKCS#11 Kit", "0.26");
        for named in [None, Some("p11-kit"), Some("p11-kit/0.26")] {
            let r = resolve(&cfg(named, &[]), &p11, None, "p11-kit").unwrap();
            assert!(r.hidden.as_deref().is_some_and(|h| h.starts_with("p11-kit/0.26: ")), "{named:?}: {:?}", r.hidden);
        }
        let r = resolve(&cfg(Some("kryoptic"), &[]), &p11, None, "p11-kit").unwrap();
        assert_eq!(r.hidden, None);
        // A module that is not a passthrough hides nothing.
        assert_eq!(resolve(&cfg(None, &[]), &module("SoftHSM", "2.7"), None, "softhsm").unwrap().hidden, None);
    }

    #[test]
    fn the_config_names_extra_layers() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let r =
            resolve(&cfg(None, &["swtpm"]), &module("tpm2-software.github.io", "1.10"), None, "tpm2-pkcs11").unwrap();
        assert_eq!(r.module_name(), Some("tpm2-pkcs11/1.10+swtpm"));
        assert_eq!(r.layer_names(), ["cryptoki/0.12", "swtpm"]);
        assert!(r.subtracted_mechanisms().contains("CKM_AES_KEY_GEN"));
        assert!(resolve(&cfg(None, &["no-such-layer"]), &module("SoftHSM", "2.7"), None, "softhsm").is_err());
    }
}
