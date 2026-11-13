//! The profile compiler (docs/PROVIDERS.md phase 3; the analysis in
//! `docs/PROVIDER_PROFILE.md`):
//! read-only probes record what a module shows through PKCS#11, and write probes — only on a
//! token keys.toml marks `scratch` — establish what it actually does. The output is a profile
//! in the committed format, diffable against what a shipped profile claims
//! (`cakeys_profile::diff`): that diff is the conformance check, and a probe of a new module
//! build against the old profile is the drift check.
//!
//! A probe records observations, never explanations (the analysis's firm line): what fails is
//! a `cannot` row or a `subtract` row carrying the `C_*` failure in its note, and what the
//! probe cannot reach is named in [`Probed::undetermined`], never guessed.

use crate::token::{Token, curve_of};
use cakeys_core::config::{ObjectCfg, TokenCfg};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cakeys_profile::baseline::CURVES;
use cakeys_profile::{GenerateRow, MatchInfo, Mode, Profile};
use cryptoki::error::RvError;
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use std::collections::BTreeMap;

/// The text of a module-supplied string with its C padding removed: PKCS#11's fixed-width
/// fields are C strings, and a module may NUL-pad them (tpm2-pkcs11's token model comes from
/// the TPM's four 4-byte vendor-string properties, so swtpm reports `SW` + NULs + `TPM`
/// [run]). The padding is layout, not content — a note records the text.
fn clean(s: &str) -> String {
    s.split('\0').filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" ")
}

/// The `CKR_*` name of a failure, for notes: cryptoki's `Display` is the spec's prose, which
/// changes with the binding and would make a regeneration differ with no behaviour change.
/// The name comes from `RvError`'s variant (`GeneralError` -> `CKR_GENERAL_ERROR`).
fn ckr(e: &cryptoki::error::Error) -> String {
    match e {
        cryptoki::error::Error::Pkcs11(RvError::VendorDefined(rv) | RvError::UnknownErrorCode(rv), _) => {
            format!("CKR {rv:#x}")
        }
        cryptoki::error::Error::Pkcs11(rv, _) => {
            let mut out = String::from("CKR");
            for c in format!("{rv:?}").chars() {
                if c.is_ascii_uppercase() {
                    out.push('_');
                }
                out.push(c.to_ascii_uppercase());
            }
            out
        }
        other => other.to_string(),
    }
}

/// What a probe found: the generated profile, and what it could not decide.
pub struct Probed {
    /// The observed capability profile of the module on this token's hardware, in the
    /// committed format. The probe measures the two together: telling the module's refusal from
    /// the hardware's is not observable through PKCS#11, so factoring one out is a hand step.
    pub profile: Profile,
    /// Why rows the probe would have liked are absent: an SO-only module's generation,
    /// facts the probe does not reach yet.
    pub undetermined: Vec<String>,
}

/// Probe `tok`. Read-only probes always run; `write` demands the write probes (generating,
/// wrapping, unwrapping, deleting), which run only on a token keys.toml marks `scratch` —
/// on any other token they are refused (17), never silently skipped.
///
/// # Errors
///
/// `Validation` (17) when `write` is set but the token is not marked scratch, has no PIN, or
/// its provider creates and destroys only as Security Officer (hardware: the probe stays
/// read-only); the scratch guard is the one thing the probe refuses rather than records.
pub fn probe(tok: &Token, cfg: &TokenCfg, write: bool) -> Result<Probed> {
    let mut profile = Profile {
        profile: format!("{}/{}", tok.provider.name(), tok.module.version),
        mode: Mode::Observed,
        partial: false,
        // Every match key there is: the module and the hardware it ran on. No serial — it
        // changes with every token re-initialisation, and a profile must regenerate identically.
        r#match: MatchInfo {
            manufacturer: Some(clean(&tok.module.manufacturer)),
            // A module reporting 0.0 hides its version (kryoptic [run]): the firmware is then
            // the version evidence.
            module_version: (tok.module.version != "0.0").then(|| clean(&tok.module.version)),
            model: Some(clean(&tok.token.model)),
            firmware: Some(clean(&tok.token.firmware)),
        },
        advertise: tok.advertised.clone(),
        subtract: cakeys_profile::profile::Subtract::default(),
        add: Vec::new(),
        wrap: cakeys_profile::profile::Wrap::default(),
        generate: BTreeMap::new(),
        unwrap: cakeys_profile::profile::Unwrap::default(),
        migration: None,
        restrict: Vec::new(),
        notes: BTreeMap::new(),
    };
    profile.notes.insert("cryptoki".into(), format!("the module reports Cryptoki {}", tok.module.cryptoki));
    // The RSA key sizes the module reports: read-only, a claim the write probes then test.
    if let Some((min, max)) = tok.rsa_bits {
        let row = profile.generate.entry("CKK_RSA".into()).or_default();
        row.min_bits = u32::try_from(min).ok();
        row.max_bits = u32::try_from(max).ok();
    }
    let mut undetermined = Vec::new();
    if !write {
        undetermined.push(
            "read-only probes only: pass --write against a token marked scratch in keys.toml to \
             generate, wrap and delete"
                .into(),
        );
        return Ok(Probed { profile, undetermined });
    }
    if tok.provider.manages_as_so() {
        // A module that creates only as SO (ykcs11, on hardware) is the destructive-on-hardware
        // case the scratch guard exists for: nothing written, ever.
        return Err(KmError::Validation(format!(
            "token '{}': its provider creates and destroys only in a Security Officer session, so \
             the write probe would put keys in device slots; probing it stays read-only",
            tok.name
        )));
    }
    if !cfg.scratch {
        return Err(KmError::Validation(format!(
            "token '{}' is not marked scratch in keys.toml: the write probes would create and \
             destroy objects on it (tokens.{}.scratch = true)",
            tok.name, tok.name
        )));
    }
    if !tok.logged_in {
        // Without a user login every token-object generation fails with
        // CKR_USER_NOT_LOGGED_IN, which the probes would record as the module's refusals.
        return Err(KmError::Validation(format!(
            "token '{}' has no PIN configured: the write probes need a user session",
            tok.name
        )));
    }
    write_probes(tok, &mut profile, &mut undetermined);
    Ok(Probed { profile, undetermined })
}

/// Everything the probes created, so every run cleans up after itself — and the leftover check
/// turns "delete really deletes" into a note.
struct Made<'a> {
    session: &'a Session,
    handles: Vec<ObjectHandle>,
    labels: Vec<String>,
    n: usize,
}

impl Made<'_> {
    fn label(&mut self) -> String {
        self.n += 1;
        format!("cakeys-probe-{:02}", self.n)
    }

    fn destroy_all(&self) {
        for h in &self.handles {
            // Deletion failures are observations here: the leftover check reports them.
            let _ = self.session.destroy_object(*h);
        }
    }

    /// Which probe labels are still on the token: what `C_DestroyObject` really deleted.
    fn leftovers(&self) -> Vec<String> {
        self.labels
            .iter()
            .filter(|l| {
                self.session
                    .find_objects(&[Attribute::Label(l.as_bytes().to_vec())])
                    .is_ok_and(|found| !found.is_empty())
            })
            .cloned()
            .collect()
    }

    /// Destroy what an earlier, interrupted run left (`cakeys-probe-NN`, its own labels on a
    /// scratch token), so this run's leftover check reports only this run. Returns the labels
    /// cleaned.
    fn clear_stale(&self) -> Vec<String> {
        let mut cleaned = Vec::new();
        let Ok(all) = self.session.find_objects(&[]) else { return cleaned };
        for h in all {
            let label = match self.session.get_attributes(h, &[cryptoki::object::AttributeType::Label]) {
                Ok(attrs) => match attrs.into_iter().next() {
                    Some(Attribute::Label(l)) => String::from_utf8_lossy(&l).into_owned(),
                    _ => continue,
                },
                Err(_) => continue,
            };
            if label.starts_with("cakeys-probe-") && self.session.destroy_object(h).is_ok() {
                cleaned.push(label);
            }
        }
        cleaned.sort();
        cleaned.dedup();
        cleaned
    }
}

/// The write probes: key pairs per curve and RSA size, the secret-key generation the module
/// advertises (a refusal is a `subtract` row), the OAEP hashes it actually implements
/// (wrap and unwrap back), and the unwrap-template rules. Every run cleans up after itself,
/// and the leftover check turns "delete really deletes" into a note.
fn write_probes(tok: &Token, profile: &mut Profile, undetermined: &mut Vec<String>) {
    let mut made = Made { session: tok.raw(), handles: Vec::new(), labels: Vec::new(), n: 0 };
    let stale = made.clear_stale();
    if !stale.is_empty() {
        // Not a profile row: an interrupted run is not something the module does.
        undetermined.push(format!("destroyed objects an interrupted probe left: {}", stale.join(", ")));
    }
    probe_curves(&mut made, profile);
    let transport = probe_rsa(&mut made, profile);
    let aes = probe_secrets(tok, &mut made, profile);
    match (transport, aes) {
        (Some(transport), Some(aes)) => probe_wrapping(&mut made, profile, transport, aes),
        _ => undetermined.push(
            "no wrap probes: the probes could not make both an RSA transport key and an AES key \
             on this token"
                .into(),
        ),
    }
    made.destroy_all();
    let leftovers = made.leftovers();
    if !leftovers.is_empty() {
        profile
            .notes
            .insert("destroy".into(), format!("C_DestroyObject leaves objects behind: {}", leftovers.join(", ")));
    }
}

/// Key pairs per curve: `can` or `cannot`, the refusal's `CKR_*` in a note.
fn probe_curves(made: &mut Made, profile: &mut Profile) {
    let session = made.session;
    for (kt, weierstrass) in [(Kt::Ec, true), (Kt::EcEdwards, false)] {
        let mech = if weierstrass { Mechanism::EccKeyPairGen } else { Mechanism::EccEdwardsKeyPairGen };
        let mut row = GenerateRow::default();
        for curve in CURVES.iter().filter(|c| c.starts_with("edwards") != weierstrass) {
            let mut obj = ObjectCfg::new(Class::PrivateKey, Some(kt));
            obj.curve = Some((*curve).to_owned());
            let Ok(params) = curve_of(&obj) else { continue };
            let label = made.label();
            let attempt = session.generate_key_pair(
                &mech,
                &[
                    Attribute::Token(true),
                    Attribute::Label(label.as_bytes().to_vec()),
                    Attribute::EcParams(params.params().to_vec()),
                    Attribute::Verify(true),
                    Attribute::Private(false),
                ],
                &[
                    Attribute::Token(true),
                    Attribute::Label(label.as_bytes().to_vec()),
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::Sensitive(true),
                ],
            );
            match attempt {
                // cryptoki's pair is (public, private) — the halves are the wrong way round for
                // how a reader expects it, so name them explicitly here.
                Ok((public, private)) => {
                    row.can.push((*curve).to_owned());
                    made.handles.extend([private, public]);
                    made.labels.push(label);
                }
                Err(e) => {
                    row.cannot.push((*curve).to_owned());
                    profile.notes.insert((*curve).to_owned(), format!("generation refused: {}", ckr(&e)));
                }
            }
        }
        profile.generate.insert(kt.name().to_owned(), row);
    }
}

/// Key pairs per RSA size: `can-bits` and `cannot-bits` beside the range the module reports.
/// Returns the 2048-bit pair, the wrap probes' transport key: wrapping is encryption, so its
/// public half wraps and its private half unwraps.
fn probe_rsa(made: &mut Made, profile: &mut Profile) -> Option<(ObjectHandle, ObjectHandle)> {
    let session = made.session;
    let mut row = profile.generate.remove("CKK_RSA").unwrap_or_default();
    let mut transport = None;
    for bits in [1024u32, 2048, 3072, 4096] {
        let label = made.label();
        let public = [
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::ModulusBits(u64::from(bits).into()),
            Attribute::PublicExponent(vec![1, 0, 1]),
            Attribute::Private(false),
        ];
        let plain = [
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Sensitive(true),
        ];
        // The 2048-bit pair is the wrap probes' transport key: the public half wraps
        // (CKA_ENCRYPT, CKA_WRAP), the private half unwraps (CKA_DECRYPT, CKA_UNWRAP) — each
        // attribute on the half the spec defines it for, since their defaults are the module's
        // choice. A module refusing the explicit rows gets the bare templates.
        let attempt = if bits == 2048 {
            let mut wraps = public.to_vec();
            wraps.extend([Attribute::Encrypt(true), Attribute::Wrap(true)]);
            let mut unwraps = plain.to_vec();
            unwraps.extend([Attribute::Decrypt(true), Attribute::Unwrap(true)]);
            session
                .generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &wraps, &unwraps)
                .or_else(|_| session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public, &plain))
        } else {
            session.generate_key_pair(&Mechanism::RsaPkcsKeyPairGen, &public, &plain)
        };
        match attempt {
            Ok((public, private)) => {
                if bits == 2048 {
                    transport = Some((public, private));
                }
                row.can_bits.push(bits);
                made.handles.extend([private, public]);
                made.labels.push(label);
            }
            Err(e) => {
                row.cannot_bits.push(bits);
                // One note per refused size: the last failure must not erase the others.
                profile.notes.insert(format!("CKK_RSA at {bits}"), format!("modulusBits = {bits}: {}", ckr(&e)));
            }
        }
    }
    profile.generate.insert("CKK_RSA".into(), row);
    transport
}

/// The secret-key generation the module advertises: success is implied by the advertise list,
/// a refusal is a `subtract` row (advertised but broken). Returns the first AES key, the wrap
/// probes' wrapped key.
fn probe_secrets(tok: &Token, made: &mut Made, profile: &mut Profile) -> Option<ObjectHandle> {
    let session = made.session;
    let mut aes = None;
    for (mech, name, key_type) in [
        (Mechanism::AesKeyGen, "CKM_AES_KEY_GEN", KeyType::AES),
        (Mechanism::GenericSecretKeyGen, "CKM_GENERIC_SECRET_KEY_GEN", KeyType::GENERIC_SECRET),
    ] {
        let name = name.to_owned();
        if !tok.advertised.contains(&name) {
            continue;
        }
        let label = made.label();
        let attempt = session.generate_key(
            &mech,
            &[
                Attribute::Token(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(key_type),
                Attribute::ValueLen(32.into()),
                Attribute::Extractable(true),
            ],
        );
        match attempt {
            Ok(h) => {
                if key_type == KeyType::AES && aes.is_none() {
                    aes = Some(h);
                }
                made.handles.push(h);
                made.labels.push(label);
            }
            Err(e) => {
                profile.subtract.mechanisms.push(name.clone());
                profile.notes.insert(name, format!("advertised but generation fails: {}", ckr(&e)));
            }
        }
    }
    aes
}

/// The OAEP hashes the module actually implements — wrap the fresh AES key to the fresh RSA
/// transport key (public half) and unwrap it back with the private half, only a round trip
/// counts — and the unwrap-template rule: a template carrying `CKA_VALUE_LEN`, refused with
/// `CKR_ATTRIBUTE_READ_ONLY` by `SoftHSM`.
fn probe_wrapping(made: &mut Made, profile: &mut Profile, transport: (ObjectHandle, ObjectHandle), aes: ObjectHandle) {
    let session = made.session;
    let (wraps, unwraps) = transport;
    // MGF1 of the same hash: the parameter set a transport wrap uses (`OaepHash`).
    let oaep_of = |hash, mgf| Mechanism::RsaPkcsOaep(PkcsOaepParams::new(hash, mgf, PkcsOaepSource::empty()));
    let mut round_trips = Vec::new();
    let mut failures = Vec::new();
    for (hash, mgf, name) in [
        (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, "SHA-1"),
        (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, "SHA-256"),
    ] {
        let mech = oaep_of(hash, mgf);
        // Wrapping is encryption: the public half wraps, the private half unwraps.
        let wrapped = match session.wrap_key(&mech, wraps, aes) {
            Ok(w) => w,
            Err(e) => {
                failures.push(format!("{name}: wrapping fails: {}", ckr(&e)));
                continue;
            }
        };
        let label = made.label();
        let template = [
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
        ];
        match session.unwrap_key(&mech, unwraps, &wrapped, &template) {
            Ok(h) => {
                round_trips.push((name, hash, mgf));
                made.handles.push(h);
                made.labels.push(label);
            }
            Err(e) => failures.push(format!("{name}: wraps but does not unwrap: {}", ckr(&e))),
        }
    }
    // One note under "oaep": what `--oaep` verdicts cite.
    if !failures.is_empty() {
        profile.notes.insert("oaep".into(), failures.join("; "));
    }
    // Probed: `[]` when no hash round-trips, distinct from never probed.
    profile.wrap.oaep = Some(round_trips.iter().map(|(name, ..)| (*name).to_owned()).collect());
    // The unwrap-template rule, with the first hash that round-trips; unprobed without one.
    let Some(&(_, hash, mgf)) = round_trips.first() else {
        return;
    };
    let mech = oaep_of(hash, mgf);
    let Ok(wrapped) = session.wrap_key(&mech, wraps, aes) else {
        return;
    };
    let label = made.label();
    let with_len = session.unwrap_key(
        &mech,
        unwraps,
        &wrapped,
        &[
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(32.into()),
        ],
    );
    match with_len {
        Ok(h) => {
            profile.unwrap.refuse = Some(Vec::new());
            made.handles.push(h);
            made.labels.push(label);
        }
        Err(cryptoki::error::Error::Pkcs11(RvError::AttributeReadOnly, _)) => {
            profile.unwrap.refuse = Some(vec!["CKA_VALUE_LEN".into()]);
            profile.notes.insert("CKA_VALUE_LEN".into(), "CKR_ATTRIBUTE_READ_ONLY in an unwrap template".into());
        }
        // Neither accepted nor the refusal the rule names: the row stays unprobed.
        Err(e) => {
            profile.notes.insert("unwrap-template".into(), format!("CKA_VALUE_LEN: {}", ckr(&e)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;
    use cryptoki::error::Error;

    #[test]
    fn notes_name_the_return_value_not_the_prose() {
        // Regeneration is byte-identical only while these spellings hold.
        let rv = |e| ckr(&Error::Pkcs11(e, Function::WrapKey));
        assert_eq!(rv(RvError::GeneralError), "CKR_GENERAL_ERROR");
        assert_eq!(rv(RvError::AttributeReadOnly), "CKR_ATTRIBUTE_READ_ONLY");
        assert_eq!(rv(RvError::CurveNotSupported), "CKR_CURVE_NOT_SUPPORTED");
        assert_eq!(rv(RvError::FunctionNotSupported), "CKR_FUNCTION_NOT_SUPPORTED");
        assert_eq!(rv(RvError::VendorDefined(0x8000_0001)), "CKR 0x80000001");
    }
}
