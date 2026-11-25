//! Profile resolution (docs/CAPROBE.md D9, phase 2): which module profile and which delta
//! layers compose a token's effective capability. The binding layer is always there; a
//! forwarder is recognised from the module itself; the config names the rest; the module
//! profile follows the provider family, chosen by the most match keys — the version
//! `C_GetInfo` expresses, then the token's model and firmware (D9/D10) —
//! never a module digest; the one committed profile of a family matches by
//! manufacturer alone, flagged low-evidence (kryoptic reports 0.0 \[run\]).

use crate::binding;
use cakeys_core::config::{ModuleInfo, Observation, Said, TokenCfg, TokenInfo};
use cakeys_profile::{Answer, Capability, Mode, Profile, Row, Set};
use std::collections::BTreeSet;

/// A token's resolved profiles, what [`crate::Token`] carries and every consumer reads.
#[derive(Debug, Clone, Default)]
pub struct Resolved {
    /// The module profile, when one is committed for the selected provider family.
    pub module: Option<Profile>,
    /// The delta layers, innermost first: the binding, any forwarder the module names, the
    /// config's extras.
    pub layers: Vec<Profile>,
    /// What resolution noticed on the way (a low-evidence version match, ...): `caps` prints
    /// them, so a resolved stack is never a silent guess.
    pub notes: Vec<String>,
    /// A layer that hides the module behind it (`requires-provider`) while keys.toml names no
    /// provider for that module: the layer's name and its note. A plan warns with it.
    pub hidden: Option<String>,
}

impl Resolved {
    /// The module profile's name, for `caps` and messages.
    #[must_use]
    pub fn module_name(&self) -> Option<&str> {
        self.module.as_ref().map(|p| p.profile.as_str())
    }

    /// Put what this deployment's token answered (`observed.capabilities`, the lock's record of
    /// what its runs demonstrated and the probe measured) over the module profile: the token's
    /// own answer decides before what a shipped profile says of its kind. With no module
    /// profile, the answers stand alone (a partial profile: they say nothing of mechanisms). A
    /// row this cakeys cannot read answers nothing. A recorded answer that agrees with the
    /// profile and says nothing of how keeps the profile's `via`: a lock written before cakeys
    /// recorded `via = "by-name"` still lets a curve generated only by name retry by name
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

    /// The layers' names, in order.
    #[must_use]
    pub fn layer_names(&self) -> Vec<&str> {
        self.layers.iter().map(|p| p.profile.as_str()).collect()
    }

    /// Every mechanism the stack subtracts from a module's advertisement.
    #[must_use]
    pub fn subtracted_mechanisms(&self) -> BTreeSet<&str> {
        self.module
            .iter()
            .chain(self.layers.iter())
            .flat_map(|p| p.subtract.mechanisms.iter().map(String::as_str))
            .collect()
    }

    /// Every mechanism the stack adds although the module does not list it (a provider's
    /// stand-in the probe found working, `Provider::stand_in`).
    #[must_use]
    pub fn added_mechanisms(&self) -> BTreeSet<&str> {
        self.module.iter().chain(self.layers.iter()).flat_map(|p| p.add.iter().map(String::as_str)).collect()
    }

    /// Every key type the stack subtracts (an unpatched binding's broken ones).
    #[must_use]
    pub fn subtracted_key_types(&self) -> BTreeSet<&str> {
        self.module
            .iter()
            .chain(self.layers.iter())
            .flat_map(|p| p.subtract.key_types.iter().map(String::as_str))
            .collect()
    }
}

/// The `ModuleInfo` of a module nobody has seen yet — keys.toml's provider alone (the static
/// gate) or a transport file's — so nothing to detect a forwarder from; the binding layer still
/// applies.
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

/// Resolve a token's profiles: `provider` is the selected provider's name (or the explicitly
/// configured one: a family, never a profile, docs/CONFIG.md);
/// `token` is what `C_GetTokenInfo` gave, when there is a token (its firmware matches a module
/// that hides its version).
///
/// # Errors
///
/// [`Set::embedded`]'s parse error, or the message of a config-named layer no profile set has:
/// the token open maps both to 17. A module version no profile records is never an error: the
/// nearest profile stands in, with a note.
pub fn resolve(
    cfg: &TokenCfg,
    module: &ModuleInfo,
    token: Option<&TokenInfo>,
    provider: &str,
) -> Result<Resolved, String> {
    let set = Set::active()?;
    let mut out = Resolved::default();
    // The binding layer, always: the one between cakeys and every module.
    out.layers.push(binding::layer()?);
    out.add_forwarders(set, module);
    out.add_configured(set, cfg)?;
    out.hidden = hidden_module(cfg, &out.layers);
    out.module = out.module_profile(set, cfg, module, token, provider)?;
    Ok(out)
}

impl Resolved {
    /// A forwarder the module itself names (p11-kit's client: `C_GetInfo` describes it).
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

    /// The config's extras, by name or family (the hardware under the module, a forwarder the
    /// module does not name). Explicit means applied, even when nothing detected it.
    fn add_configured(&mut self, set: &Set, cfg: &TokenCfg) -> Result<(), String> {
        for name in &cfg.profiles {
            if self.layers.iter().any(|l| l.profile == name.as_str() || l.family() == name.as_str()) {
                continue;
            }
            self.layers.push(set.find(name)?.clone());
        }
        Ok(())
    }

    /// The module profile: of the configured provider's family, else the selected provider's
    /// family. A profile is observed on a module and the hardware under it (D9/D10), so it is
    /// chosen by the most match keys: the expressed version first (`C_GetInfo`; a module hiding
    /// it as 0.0 records none), then the token's model and firmware. Anything short of all of
    /// them is noted, and the rows the hardware decides are dropped where it is not known to be
    /// the observed one. A `moduleProfile` naming one profile of the family takes that one alone.
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

    /// Pairs whose match keys are all the same (a FIPS and a non-FIPS `CloudHSM` cluster: PKCS#11
    /// reports no mode, D12), and this token fits them alike: the first is used, rows intact, and
    /// said, so the stack is no silent guess.
    fn tied_on_this_hardware(&mut self, p: &Profile, tied: &[&Profile]) {
        self.notes.push(format!(
            "module profiles {} fit this module and token equally: using {}; name another in \
             tokens.<token>.moduleProfile",
            tied.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", "),
            p.profile
        ));
    }

    /// A module version no profile of the family records (an update, typically): the nearest
    /// profile's module rows stand, its hardware rows answer unknown. Never an error: a missing
    /// profile must not stop the token from opening (P1).
    fn nearest_version(&mut self, p: &mut Profile, family: &str, candidates: &[&Profile], module: &ModuleInfo) {
        self.notes.push(format!(
            "no module profile for '{family}' ({}) records module version '{}': using the nearest, {}, \
             without its generate, wrap, unwrap and decrypt rows (unknown); profile this module with \
             `caprobe probe` (docs/CAPROBE.md)",
            candidates.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", "),
            module.version,
            p.profile
        ));
        clear_hardware_rows(p);
    }

    /// Pairs of one module on several kinds of hardware, and no token to tell which: what the
    /// module lists is taken from one of them; what generates, wraps, unwraps and decrypts
    /// depends on the hardware — unknown, as for hardware no pair was observed on.
    fn hardware_unknown(&mut self, p: &mut Profile, tied: &[&Profile]) {
        self.notes.push(format!(
            "module profiles {} fit equally and the hardware is not known here: using {}'s module \
             rows, its generate, wrap, unwrap and decrypt rows are not used (unknown); name the \
             hardware in tokens.<token>.profiles, or the pair in tokens.<token>.moduleProfile",
            tied.iter().map(|p| p.profile.as_str()).collect::<Vec<_>>().join(", "),
            p.profile
        ));
        clear_hardware_rows(p);
    }

    /// A module profile matched on less than the module's version: by manufacturer alone, or by
    /// the token's firmware where the module hides its version. Not where no profile records
    /// the module's version: [`Self::nearest_version`] said so.
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

    /// Another kind of hardware under the same module: what the module advertises still holds,
    /// what generates, wraps and unwraps depends on the hardware — unknown, not the observed
    /// hardware's answer.
    fn other_hardware(&mut self, p: &mut Profile, token: Option<&TokenInfo>) {
        self.notes.push(format!(
            "module profile {} was observed on model {} firmware {}, this token is model {} \
             firmware {}: its generate, wrap and unwrap rows are not used (unknown)",
            p.profile,
            seen(p.r#match.model.as_ref()),
            seen(p.r#match.firmware.as_ref()),
            seen(token.map(|t| &t.model)),
            seen(token.map(|t| &t.firmware))
        ));
        clear_hardware_rows(p);
    }
}

/// A passthrough hides the module behind it: only a provider named past the passthrough's own
/// family (an observation records the detected one) says what that module is. The layer's name
/// and why, for a plan to warn with.
fn hidden_module(cfg: &TokenCfg, layers: &[Profile]) -> Option<String> {
    let named = |l: &Profile| cfg.named_provider().is_some_and(|p| p != l.family() && p != l.profile);
    let l = layers.iter().find(|l| l.requires_provider && !named(l))?;
    let why = l.notes.get("requires-provider").map_or("it hides the module behind it", String::as_str);
    Some(format!("{}: {why}", l.profile))
}

/// A match key as a note quotes it.
fn seen(x: Option<&String>) -> String {
    x.map_or_else(|| "unrecorded".to_owned(), |x| format!("'{x}'"))
}

/// The observed module profiles of `family`, or the one `pinned` names (`moduleProfile`).
///
/// # Errors
///
/// `pinned` names no profile the set has.
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

/// The module profile among a family's `candidates`, with the ones that fit it equally well,
/// and whether none of several records the module's version. Ranked by: a configured hardware
/// layer naming the pair (`profiles = ["swtpm"]` -> `tpm2-pkcs11/1.10+swtpm`), then the token's
/// model and firmware; a profile recording another module version is out while one records
/// this version. When none does, every candidate is in, and among equal hardware the nearest
/// recorded version wins ([`Nearness`]). `None` for a family with no profile.
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

/// How near a profile's recorded module version is to the module's, compared numerically per
/// dot-separated component (`1.10` is above `1.9`): the highest recorded version at or below
/// the module's is nearest, else the lowest above it. A version that is not numbers (none
/// recorded, or the empty one of a module nobody has seen) says nothing.
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

/// Drop a pair profile's rows that depend on the hardware it was observed on, and what the probe
/// could not decide of them there: what generates, wraps, unwraps, decrypts, imports and exports
/// there answers unknown on other or unknown hardware.
fn clear_hardware_rows(p: &mut Profile) {
    let hardware = |c: &Capability| {
        matches!(
            c,
            Capability::Generate { .. }
                | Capability::WrapOaep(_)
                | Capability::UnwrapTemplate(_)
                | Capability::DecryptOaep(_)
                | Capability::Import { .. }
                | Capability::Create { .. }
                | Capability::Export { .. }
                | Capability::Unwrap { .. }
        )
    };
    p.reported.clear();
    p.capabilities.retain(|c, _| !hardware(c));
    // What the probe could not decide there is that hardware's too (`[untested]`, why device or
    // cakeys): on other hardware, unknown as the rows are.
    p.untested.retain(|name, _| Capability::parse(name).map_or(true, |c| !hardware(&c)));
}

/// How a module profile's match keys meet a token: per key, whether it matches (`None`: the
/// profile records no such key, or there is no token to compare with).
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

    /// How many of the hardware keys match: the tie-breaker among one version's profiles.
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

    /// A lock written before cakeys recorded `via` holds a plain yes for a curve the profile
    /// says only its name generates: the answer keeps the profile's `via`, so the by-name retry
    /// still runs (ISSUES.md B18). A recorded `via` is the token's own, and a recorded no says
    /// nothing of how.
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
        assert_eq!(r.notes.len(), 0); // the expressed version matches
        // kryoptic hides its version (0.0): the token's firmware is the secondary evidence, and
        // either way the match is flagged, never silent.
        let firmware = |f: &str| TokenInfo { model: "v1".into(), serial: "s".into(), firmware: f.into() };
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), Some(&firmware("1.5")), "kryoptic").unwrap();
        assert_eq!(r.module_name(), Some("kryoptic/1.5"));
        assert_eq!(r.notes.len(), 1);
        assert!(r.notes[0].contains("by the token's firmware '1.5'"), "{:?}", r.notes);
        assert!(r.module.as_ref().unwrap().wrap_oaep().is_some());
        // Another firmware: flagged, and the hardware-dependent rows answer unknown.
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), Some(&firmware("1.6")), "kryoptic").unwrap();
        assert!(r.notes[0].contains("manufacturer alone"), "{:?}", r.notes);
        assert!(r.notes[1].contains("are not used"), "{:?}", r.notes);
        assert!(r.module.as_ref().unwrap().generation_key_types().is_empty());
        // And what the probe could not decide on that hardware (its `[untested]` device entries).
        assert!(!r.module.as_ref().unwrap().untested.keys().any(|k| k.starts_with("generate.")));
        // No token to compare with (a transport file): flagged, rows kept.
        let r = resolve(&cfg(None, &[]), &module("Kryoptic", "0.0"), None, "kryoptic").unwrap();
        assert!(r.notes[0].contains("manufacturer alone"), "{:?}", r.notes);
        assert!(!r.module.as_ref().unwrap().generation_key_types().is_empty());
    }

    #[test]
    fn another_kind_of_hardware_keeps_the_advertisement_only() {
        cakeys_profile::Set::activate_embedded().unwrap();
        // A real TPM under the tpm2-pkcs11 observed on swtpm: what the module lists holds, what
        // it generates, wraps and unwraps depends on the TPM.
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

    #[test]
    fn pairs_of_one_module_resolve_by_their_hardware() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let tpm2 = module("tpm2-software.github.io", "1.10");
        let resolved = |cfg: &TokenCfg, token: Option<&TokenInfo>| {
            let r = resolve(cfg, &tpm2, token, "tpm2-pkcs11").unwrap();
            (r.module.unwrap(), r.notes)
        };
        // The token's model and firmware pick the pair observed on that hardware, rows intact.
        let amd = TokenInfo { model: "AMD".into(), serial: "s".into(), firmware: "3.87".into() };
        let (m, notes) = resolved(&cfg(None, &[]), Some(&amd));
        assert_eq!(m.profile, "tpm2-pkcs11/1.10+amd-ftpm");
        assert!(!m.generation_key_types().is_empty() && notes.is_empty(), "{notes:?}");
        let sw = TokenInfo { model: "SW   TPM".into(), serial: "s".into(), firmware: "36.37".into() };
        assert_eq!(resolved(&cfg(None, &[]), Some(&sw)).0.profile, "tpm2-pkcs11/1.10+swtpm");
        // No token (validate by provider alone): a configured hardware layer names the pair ...
        assert_eq!(resolved(&cfg(None, &["swtpm"]), None).0.profile, "tpm2-pkcs11/1.10+swtpm");
        // ... else the pairs tie: module rows only, the hardware's unknown, and said so.
        let (m, notes) = resolved(&cfg(None, &[]), None);
        assert!(m.generation_key_types().is_empty() && m.decrypt_oaep().is_none());
        assert!(notes.iter().any(|n| n.contains("fit equally")), "{notes:?}");
    }

    /// A module version no profile of a family with several records (a client library update)
    /// opens with the nearest profile, its hardware rows unknown and a note: never an error.
    /// Pairs that tie on every key resolve to the first embedded, as with a recorded version.
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
        // Behind p11-kit the module says so; the provider pin still selects the module profile.
        let r = resolve(&cfg(Some("softhsm"), &[]), &module("PKCS#11 Kit", "0.26"), None, "p11-kit").unwrap();
        assert_eq!(r.module_name(), Some("softhsm/2.7"));
        assert_eq!(r.layer_names(), ["cryptoki/0.12", "p11-kit/0.26"]);
        assert!(r.subtracted_mechanisms().contains("CKM_AES_KEY_WRAP"));
        assert_eq!(r.hidden, None);
    }

    /// Profiles that tie on every match key (a FIPS and a non-FIPS `CloudHSM` cluster: PKCS#11
    /// reports no mode, D12) resolve to the first embedded, the stricter; `moduleProfile` naming
    /// the other takes it, with or without the provider named; a name no profile has is refused.
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

    /// With the token open, profiles that tie on every match key still resolve to the first,
    /// rows intact, and the run says that another fit as well (resolution.rs F1): a `NON_FIPS`
    /// cluster must not be judged by the FIPS profile without a word. A pin decides alone, and
    /// hardware no pair was observed on says so in its own note.
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
        // Unnamed, or named as the passthrough itself (what an observation records): hidden.
        let p11 = module("PKCS#11 Kit", "0.26");
        for named in [None, Some("p11-kit"), Some("p11-kit/0.26")] {
            let r = resolve(&cfg(named, &[]), &p11, None, "p11-kit").unwrap();
            assert!(r.hidden.as_deref().is_some_and(|h| h.starts_with("p11-kit/0.26: ")), "{named:?}: {:?}", r.hidden);
        }
        let r = resolve(&cfg(Some("kryoptic"), &[]), &p11, None, "p11-kit").unwrap();
        assert_eq!(r.hidden, None);
        // A module that is no passthrough hides nothing.
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
