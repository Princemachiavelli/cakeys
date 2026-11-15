//! The profile compiler (docs/CAPROBE.md):
//! read-only probes record what a module shows through PKCS#11, and write probes — only on a
//! token keys.toml marks `scratch`, or in the one slot it names `scratchId` — establish what it
//! actually does. The output is a profile in the committed format, diffable against what a
//! shipped profile claims (`cakeys_profile::diff`): that diff is the conformance check, and a
//! probe of a new module build against the old profile is the drift check.
//!
//! A probe records observations, never explanations (the analysis's firm line): what fails is
//! a `cannot` row or a `subtract` row carrying the `C_*` failure in its note, and what the
//! probe cannot reach is named in [`Probed::undetermined`], never guessed.

use cakeys_core::config::TokenCfg;
use cakeys_core::id::Curve;
use cakeys_core::pop::{self, OaepHash, RsaPadding};
use cakeys_core::sig::{self, EcdsaHash, Encoding};
use cakeys_core::types::KeyType as Kt;
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::token::{self, Token, derive_any, is_policy_default, show, template_refusal};
use cakeys_pkcs11::{BoundKey, keygen_mechanism};
use cakeys_profile::baseline::CURVES;
use cakeys_profile::{GenerateRow, MatchInfo, Mode, Profile};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

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
fn ckr(e: &CkError) -> String {
    match e {
        CkError::Pkcs11(RvError::VendorDefined(rv) | RvError::UnknownErrorCode(rv), _) => {
            format!("CKR {rv:#x}")
        }
        CkError::Pkcs11(rv, _) => {
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
    /// Why rows the probe would have liked are absent: facts the probe does not reach yet, or
    /// could not reach on this token.
    pub undetermined: Vec<String>,
}

/// Where the write probes put what they generate.
enum Target {
    /// `cakeys-probe-NN` labels on a token keys.toml marks `scratch`: every run destroys what
    /// it made, and the leftover check turns "delete really deletes" into a note.
    Labels,
    /// The one slot `scratchId` names, on a token whose module generates only as Security
    /// Officer into device slots by `CKA_ID` (ykcs11): each generation replaces the slot's key
    /// in an SO session, nothing is destroyed (PIV cannot erase a key), and the last key
    /// generated stays.
    Slot(Vec<u8>),
}

/// Probe `tok`. Read-only probes always run; `write` demands the write probes (generating,
/// operating, wrapping, unwrapping, deleting), which run only on a token keys.toml marks
/// `scratch` — or, for a module that creates only as SO into device slots, in the one slot
/// `scratchId` names — and are refused (17) anywhere else, never silently skipped.
///
/// # Errors
///
/// `Validation` (17) when `write` is set but the token is not marked scratch, has no PIN, or
/// its provider creates only as Security Officer and no `scratchId` (with an admin credential)
/// names a slot holding nothing but the provider's own placeholder; the scratch guard is the
/// one thing the probe refuses rather than records. `Unavailable` when an SO login fails.
pub fn probe(tok: &Token, cfg: &TokenCfg, write: bool) -> Result<Probed> {
    let mut profile = Profile {
        profile: format!("{}/{}", tok.provider.name(), tok.module.version),
        mode: Mode::Observed,
        partial: false,
        requires_provider: false,
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
        decrypt: cakeys_profile::profile::Decrypt::default(),
        derive: cakeys_profile::profile::Derive::default(),
        migration: None,
        restrict: Vec::new(),
        notes: BTreeMap::new(),
        manual: BTreeMap::new(),
    };
    profile.notes.insert("cryptoki".into(), format!("the module reports Cryptoki {}", tok.module.cryptoki));
    // A mechanism listed more than once (libkmsp11 1.9: CKM_RSA_PKCS_KEY_PAIR_GEN 24 times
    // [run]) is advertised once; the repetition is a note.
    let mut counts = BTreeMap::<&str, usize>::new();
    for m in &tok.advertised {
        *counts.entry(m.as_str()).or_default() += 1;
    }
    let repeated: Vec<String> = counts.iter().filter(|(_, n)| **n > 1).map(|(m, n)| format!("{m} {n} times")).collect();
    if !repeated.is_empty() {
        profile.notes.insert("mechanism-list".into(), format!("C_GetMechanismList repeats {}", repeated.join(", ")));
        let mut seen = BTreeSet::new();
        profile.advertise.retain(|m| seen.insert(m.clone()));
    }
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
             generate, operate, wrap and delete"
                .into(),
        );
        return Ok(Probed { profile, undetermined });
    }
    let target = target(tok, cfg)?;
    if !tok.logged_in {
        // Without a user login every token-object generation fails with
        // CKR_USER_NOT_LOGGED_IN, which the probes would record as the module's refusals.
        return Err(KmError::Validation(format!(
            "token '{}' has no PIN configured: the write probes need a user session",
            tok.name
        )));
    }
    if let Target::Slot(id) = &target {
        check_slot(tok, id)?;
    }
    let mut made = Made {
        tok,
        session: tok.raw(),
        target,
        handles: Vec::new(),
        labels: Vec::new(),
        n: 0,
        ops: Ops::default(),
        undetermined,
        template_notes: BTreeMap::new(),
        bound_keys: tok.provider.bound_keys(),
        bound: None,
    };
    write_probes(&mut made, &mut profile)?;
    profile.notes.append(&mut made.template_notes);
    Ok(Probed { profile, undetermined: made.undetermined })
}

/// The scratch guard: where the write probes may write on this token, or why nowhere.
fn target(tok: &Token, cfg: &TokenCfg) -> Result<Target> {
    if tok.provider.manages_as_so() {
        let Some(id) = &cfg.scratch_id else {
            return Err(KmError::Validation(format!(
                "token '{}': its provider creates keys only in a Security Officer session, into \
                 device slots that may hold real keys: name the one slot the write probes may \
                 overwrite with tokens.{}.scratchId (a hex CKA_ID); `scratch` cannot mark the \
                 whole device",
                tok.name, tok.name
            )));
        };
        if !token::has_admin(cfg) {
            return Err(KmError::Validation(format!(
                "token '{}': the write probes generate as Security Officer: set tokens.{}.mgmKeyFile \
                 or mgmKeyEnv",
                tok.name, tok.name
            )));
        }
        // The config loader has already validated it.
        let id =
            cakeys_core::hex::decode(id).ok_or_else(|| KmError::Validation(format!("scratchId {id:?} is not hex")))?;
        return Ok(Target::Slot(id));
    }
    if cfg.scratch_id.is_some() {
        return Err(KmError::Validation(format!(
            "token '{}': scratchId names a slot for providers that create only as Security Officer \
             into device slots; provider {} creates as the user: mark the token scratch = true",
            tok.name,
            tok.provider.name()
        )));
    }
    if !cfg.scratch {
        return Err(KmError::Validation(format!(
            "token '{}' is not marked scratch in keys.toml: the write probes would create and \
             destroy objects on it (tokens.{}.scratch = true)",
            tok.name, tok.name
        )));
    }
    Ok(Target::Labels)
}

/// Refuse a scratch slot holding anything but the provider's own placeholder from an earlier
/// generation (`Provider::scratch_occupant`): `scratchId` is one hex string, and a typo must
/// never overwrite a real key.
fn check_slot(tok: &Token, id: &[u8]) -> Result<()> {
    let s = tok.raw();
    let find = |t: &[Attribute]| s.find_objects(t).map_err(|e| KmError::Unavailable(format!("C_FindObjects: {e}")));
    if find(&[Attribute::Id(id.to_vec())])?.is_empty() {
        return Ok(());
    }
    let mut certs = Vec::new();
    for h in find(&[Attribute::Class(ObjectClass::CERTIFICATE), Attribute::Id(id.to_vec())])? {
        // A certificate that cannot be read counts as one that is not the placeholder (its empty
        // value parses as no certificate): what the probe cannot see is never presumed scratch.
        let der = match s.get_attributes(h, &[AttributeType::Value]).map(|v| v.into_iter().next()) {
            Ok(Some(Attribute::Value(der))) => der,
            _ => Vec::new(),
        };
        certs.push(der);
    }
    if tok.provider.scratch_occupant(id, &certs) {
        return Ok(());
    }
    let shown = id.iter().fold(String::new(), |mut s, b| {
        let _ = std::fmt::Write::write_fmt(&mut s, format_args!("{b:02x}"));
        s
    });
    Err(KmError::Validation(format!(
        "token '{}': scratchId {shown} holds objects that are not {}'s own placeholder from an earlier \
         generation, so it may hold a real key: refusing to overwrite it; empty the slot or name \
         another",
        tok.name,
        tok.provider.name()
    )))
}

/// The message every operation probe signs, and the plaintext the decryption probes recover.
const MSG: &[u8] = b"cakeys probe: operations";

/// What the operation probes saw per advertised mechanism (D2: deltas only). A mechanism that
/// worked on some key is usable, the failures on other keys a note; one that failed on every
/// key it was tried with is a `subtract` row (advertised but unusable).
#[derive(Default)]
struct Ops {
    worked: BTreeSet<String>,
    failed: BTreeMap<String, Vec<String>>,
}

impl Ops {
    fn record(&mut self, mech: MechanismType, on: &str, outcome: std::result::Result<(), String>) {
        match outcome {
            Ok(()) => {
                self.worked.insert(mech.to_string());
            }
            Err(e) => self.failed.entry(mech.to_string()).or_default().push(format!("{on}: {e}")),
        }
    }

    fn finish(self, profile: &mut Profile) {
        for (mech, why) in self.failed {
            if !self.worked.contains(&mech) {
                profile.subtract.mechanisms.push(mech.clone());
            }
            let why = why.join("; ");
            profile
                .notes
                .entry(mech)
                .and_modify(|n| {
                    n.push_str("; ");
                    n.push_str(&why);
                })
                .or_insert(why);
        }
        profile.subtract.mechanisms.sort();
        profile.subtract.mechanisms.dedup();
    }
}

/// Everything the probes created, so every run cleans up after itself — and the leftover check
/// turns "delete really deletes" into a note — plus the operation outcomes and what could not
/// be decided.
struct Made<'a> {
    tok: &'a Token,
    session: &'a Session,
    target: Target,
    handles: Vec<ObjectHandle>,
    labels: Vec<String>,
    n: usize,
    ops: Ops,
    undetermined: Vec<String>,
    /// The policy defaults the module refused while it made the object without them
    /// (`template.<half>.<attribute>`): template errors, not what the module cannot do.
    template_notes: BTreeMap<String, String>,
    /// The keys the module binds to one purpose each ([`Provider::bound_keys`]); empty for a
    /// module whose keys are general purpose.
    ///
    /// [`Provider::bound_keys`]: cakeys_pkcs11::Provider::bound_keys
    bound_keys: Vec<BoundKey>,
    /// The mechanisms the key under the operation probes serves, when the module binds keys to
    /// them (Cloud KMS): nothing else is tried on it.
    bound: Option<Vec<String>>,
}

/// A generated pair, `(public, private)`, or the module's refusal.
type Pair = std::result::Result<(ObjectHandle, ObjectHandle), CkError>;

impl Made<'_> {
    fn label(&mut self) -> String {
        self.n += 1;
        format!("cakeys-probe-{:02}", self.n)
    }

    fn advertises(&self, m: MechanismType) -> bool {
        let m = m.to_string();
        self.tok.advertised.contains(&m) && self.bound.as_ref().is_none_or(|b| b.contains(&m))
    }

    /// Generate a key pair where the target says: the templates completed with a fresh probe
    /// label, or with the scratch slot's `CKA_ID` in a Security Officer session. The outer
    /// error is the SO login failing, which stops the probe; the inner one is the module's
    /// refusal, an observation.
    fn pair(&mut self, mech: &Mechanism, public: &[Attribute], private: &[Attribute]) -> Result<Pair> {
        let session = self.session;
        let locator = match &self.target {
            Target::Labels => None,
            Target::Slot(id) => Some(Attribute::Id(id.clone())),
        };
        let Some(id) = locator else {
            let label = self.label();
            let tag = |t: &[Attribute]| {
                [&[Attribute::Token(true), Attribute::Label(label.as_bytes().to_vec())][..], t].concat()
            };
            let mut made = session.generate_key_pair(mech, &tag(public), &tag(private));
            // A template refusal may be of one of the probe's own policy defaults, not of the key
            // (AWS CloudHSM refuses a public key that is not CKA_PRIVATE [run]): once more without
            // each, so the module's default decides, noted. The first refusal stands when none
            // of those helps.
            if let Err(e) = &made
                && template_refusal(e)
            {
                let halves = [("public", public), ("private", private)];
                'drop: for (i, (half, template)) in halves.iter().enumerate() {
                    for default in template.iter().filter(|a| is_policy_default(a)) {
                        let without: Vec<_> = template.iter().filter(|a| *a != default).cloned().collect();
                        let (pub_t, prv_t) = if i == 0 { (&without[..], private) } else { (public, &without[..]) };
                        if let Ok((public, private)) = session.generate_key_pair(mech, &tag(pub_t), &tag(prv_t)) {
                            let on = if i == 0 { public } else { private };
                            self.note_dropped(half, default, e, on);
                            made = Ok((public, private));
                            break 'drop;
                        }
                    }
                }
            }
            if let Ok((public, private)) = made {
                self.handles.extend([private, public]);
                self.labels.push(label);
            }
            return Ok(made);
        };
        let tag = |t: &[Attribute]| [&[Attribute::Token(true), id.clone()][..], t].concat();
        self.tok.as_so("the write probe", || Ok(session.generate_key_pair(mech, &tag(public), &tag(private))))
    }

    /// Note, once per attribute and half, a policy default the module refused while it made the
    /// object without it: the refusal, and what the object it made reports instead.
    fn note_dropped(&mut self, half: &str, default: &Attribute, refusal: &CkError, made: ObjectHandle) {
        let ty = default.attribute_type();
        let key = format!("template.{half}.{ty}");
        if self.template_notes.contains_key(&key) {
            return;
        }
        let read = match self.session.get_attributes(made, &[ty]).as_deref() {
            Ok([a]) => format!("reads {}", show(a)),
            Ok(_) => format!("reads no {ty}"),
            Err(e) => format!("{ty} unreadable: {}", ckr(e)),
        };
        self.template_notes.insert(
            key,
            format!("{} on a {half} object: {}; made without it, the object {read}", show(default), ckr(refusal)),
        );
    }

    /// Generate with the usage template — what the operation probes need — else the bare one a
    /// module may insist on. `Ok((pair, usable))`: `usable` when the usage template took.
    fn pair_for_use(
        &mut self,
        mech: &Mechanism,
        (public, private): (&[Attribute], &[Attribute]),
        (bare_public, bare_private): (&[Attribute], &[Attribute]),
    ) -> Result<(Pair, bool)> {
        match self.pair(mech, public, private)? {
            Ok(p) => Ok((Ok(p), true)),
            Err(_) => Ok((self.pair(mech, bare_public, bare_private)?, false)),
        }
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
    /// scratch token, and a purpose-bound module's keys under the bound labels), so this run's
    /// leftover check reports only this run. Returns the labels cleaned.
    fn clear_stale(&self) -> Vec<String> {
        let mut cleaned = Vec::new();
        let Ok(all) = self.session.find_objects(&[]) else { return cleaned };
        for h in all {
            let label = match self.session.get_attributes(h, &[AttributeType::Label]) {
                Ok(attrs) => match attrs.into_iter().next() {
                    Some(Attribute::Label(l)) => String::from_utf8_lossy(&l).into_owned(),
                    _ => continue,
                },
                Err(_) => continue,
            };
            let ours = label.starts_with("cakeys-probe-") || self.bound_keys.iter().any(|k| k.label == label);
            if ours && self.session.destroy_object(h).is_ok() {
                cleaned.push(label);
            }
        }
        cleaned.sort();
        cleaned.dedup();
        cleaned
    }
}

/// The write probes: key pairs per curve and RSA size, each operation the module advertises
/// on the first key of each kind, the secret-key generation it advertises (a refusal is a
/// `subtract` row), the OAEP hashes it actually implements for wrapping (wrap and unwrap back),
/// and the unwrap-template rules. On a scratch token every run cleans up after itself, and the
/// leftover check turns "delete really deletes" into a note.
fn write_probes(made: &mut Made, profile: &mut Profile) -> Result<()> {
    let labels = matches!(made.target, Target::Labels);
    if labels {
        let stale = made.clear_stale();
        if !stale.is_empty() {
            // Not a profile row: an interrupted run is not something the module does.
            made.undetermined.push(format!("destroyed objects an interrupted probe left: {}", stale.join(", ")));
        }
    }
    let bound = !made.bound_keys.is_empty();
    let transport = if bound {
        probe_bound(made, profile);
        made.undetermined.push(
            "no secret-key or wrap probes beyond generation: the module's keys serve only their \
             binding's mechanisms"
                .into(),
        );
        None
    } else {
        probe_curves(made, profile)?;
        probe_rsa(made, profile)?
    };
    if labels {
        if !bound {
            let aes = probe_secrets(made, profile);
            match (transport, aes) {
                (Some(transport), Some(aes)) => probe_wrapping(made, profile, transport, aes),
                _ => made.undetermined.push(
                    "no wrap probes: the probes could not make both an RSA transport key and an AES \
                     key on this token"
                        .into(),
                ),
            }
        }
        made.destroy_all();
        let leftovers = made.leftovers();
        if !leftovers.is_empty() {
            profile
                .notes
                .insert("destroy".into(), format!("C_DestroyObject leaves objects behind: {}", leftovers.join(", ")));
        }
    } else {
        made.undetermined.push(
            "in a scratch slot: no secret-key, wrap or delete probes (each needs a second object, \
             or erasing the slot's key)"
                .into(),
        );
    }
    std::mem::take(&mut made.ops).finish(profile);
    Ok(())
}

/// A module that binds every key to one purpose at creation ([`BoundKey`], Google Cloud KMS):
/// one key per binding, generated from the provider's exact template (no public template), and
/// probed with only the mechanisms its binding serves. The curves and sizes no binding covers
/// are tried without one ([`probe_unbound`]), so their `cannot` rows are observations too.
fn probe_bound(made: &mut Made, profile: &mut Profile) {
    let session = made.session;
    profile.notes.insert(
        "purpose-bound".into(),
        format!(
            "each key is bound to one purpose at creation ({} keys): one key per binding, each \
             probed with its own mechanisms",
            made.tok.provider.name()
        ),
    );
    let mut ec = GenerateRow::default();
    let mut rsa = profile.generate.remove("CKK_RSA").unwrap_or_default();
    let mut oaep: Option<Vec<String>> = None;
    for key in std::mem::take(&mut made.bound_keys) {
        let Some((mech, pair)) = keygen_mechanism(key.keygen) else {
            profile.notes.insert(key.name.clone(), format!("no generation probe: {} takes parameters", key.keygen));
            continue;
        };
        let generated = if pair {
            session.generate_key_pair(&mech, &[], &key.template).map(|(p, s)| (Some(p), s))
        } else {
            session.generate_key(&mech, &key.template).map(|s| (None, s))
        };
        let bits = key.on.parse::<u32>().ok();
        let (public, private) = match generated {
            Ok(keys) => keys,
            Err(e) => {
                profile.notes.insert(key.name.clone(), format!("generation refused: {}", ckr(&e)));
                match (key.kind.as_str(), bits) {
                    ("CKK_EC", _) if !ec.cannot.contains(&key.on) => ec.cannot.push(key.on.clone()),
                    ("CKK_RSA", Some(b)) if !rsa.cannot_bits.contains(&b) => rsa.cannot_bits.push(b),
                    _ => {}
                }
                continue;
            }
        };
        made.handles.extend(public);
        made.handles.push(private);
        made.labels.push(key.label.clone());
        match (key.kind.as_str(), bits) {
            ("CKK_EC", _) if !ec.can.contains(&key.on) => ec.can.push(key.on.clone()),
            ("CKK_RSA", Some(b)) if !rsa.can_bits.contains(&b) => rsa.can_bits.push(b),
            _ => {}
        }
        let Some(public) = public else { continue };
        made.bound = Some(key.mechanisms.iter().map(ToString::to_string).collect());
        // ECDSA's host check needs the curve; an RSA key is named by its binding, so the notes
        // of one size's several keys stay apart.
        let on = if key.kind == "CKK_EC" { key.on.clone() } else { key.name.clone() };
        operate(made, profile, &key.kind, &on, public, private);
        made.bound = None;
        // Each OAEP key decrypts with its own hash: the row is what any of them did.
        if let Some(works) = profile.decrypt.oaep.take() {
            let row = oaep.get_or_insert_with(Vec::new);
            for h in works {
                if !row.contains(&h) {
                    row.push(h);
                }
            }
        }
    }
    profile.decrypt.oaep = oaep;
    // A size that generated under one binding and not another can: the refusal stays a note.
    rsa.cannot_bits.retain(|b| !rsa.can_bits.contains(b));
    ec.cannot.retain(|c| !ec.can.contains(c));
    probe_unbound(made, profile, &mut ec, &mut rsa);
    rsa.can_bits.sort_unstable();
    rsa.cannot_bits.sort_unstable();
    profile.generate.insert("CKK_EC".into(), ec);
    profile.generate.insert("CKK_RSA".into(), rsa);
}

/// What no binding covers, tried with the label alone: libkmsp11 answers before any Cloud KMS
/// call (`CKR_TEMPLATE_INCOMPLETE`), so nothing is created; anything that does generate is
/// destroyed with the rest.
fn probe_unbound(made: &mut Made, profile: &mut Profile, ec: &mut GenerateRow, rsa: &mut GenerateRow) {
    let session = made.session;
    let bare = [Attribute::Label(b"cakeys-probe-unbound".to_vec())];
    let unbound = |made: &mut Made, mech: &Mechanism| match session.generate_key_pair(mech, &[], &bare) {
        Ok((public, private)) => {
            made.handles.extend([private, public]);
            "generated without a binding".to_owned()
        }
        Err(e) => ckr(&e),
    };
    let ec_refusal = unbound(made, &Mechanism::EccKeyPairGen);
    for name in CURVES.iter().filter(|n| Curve::from_cfg(Kt::Ec, n).is_some()) {
        let name = (*name).to_owned();
        if !ec.can.contains(&name) && !ec.cannot.contains(&name) {
            profile.notes.insert(name.clone(), format!("no binding for it; without one: {ec_refusal}"));
            ec.cannot.push(name);
        }
    }
    let edwards: Vec<String> =
        CURVES.iter().filter(|n| Curve::from_cfg(Kt::EcEdwards, n).is_some()).map(|n| (*n).to_owned()).collect();
    let montgomery: Vec<String> = MONTGOMERY.iter().map(|m| m.0.to_owned()).collect();
    for (kt, mech, names) in [
        ("CKK_EC_EDWARDS", Mechanism::EccEdwardsKeyPairGen, edwards),
        ("CKK_EC_MONTGOMERY", Mechanism::EccMontgomeryKeyPairGen, montgomery),
    ] {
        let refusal = unbound(made, &mech);
        for name in &names {
            profile.notes.insert(name.clone(), format!("no binding for it; without one: {refusal}"));
        }
        profile.generate.insert(kt.into(), GenerateRow { cannot: names, ..GenerateRow::default() });
    }
    let rsa_refusal = unbound(made, &Mechanism::RsaPkcsKeyPairGen);
    if !rsa.can_bits.contains(&1024) && !rsa.cannot_bits.contains(&1024) {
        rsa.cannot_bits.push(1024);
        profile.notes.insert("CKK_RSA at 1024".into(), format!("no binding for it; without one: {rsa_refusal}"));
    }
}

/// One curve to generate: its name, `CKA_EC_PARAMS` as the OID, and as the `PrintableString`
/// name where PKCS#11 3.0 allows it.
type CurveForm = (&'static str, &'static [u8], Option<&'static [u8]>);

/// The Montgomery curves (`CKK_EC_MONTGOMERY`): RFC 8410's OIDs, PKCS#11 3.0's names. Not
/// keys.toml objects yet (no Montgomery key type in id.rs), so they live here.
const MONTGOMERY: [CurveForm; 2] = [
    ("curve25519", &[0x06, 0x03, 0x2b, 0x65, 0x6e], Some(b"\x13\x0acurve25519")),
    ("curve448", &[0x06, 0x03, 0x2b, 0x65, 0x6f], Some(b"\x13\x08curve448")),
];

/// Key pairs per curve: `can` or `cannot`, the refusal's `CKR_*` in a note, and `by-name` for
/// a curve that generates only when named. The first key of each kind gets the operation
/// probes, right away — in a scratch slot the next generation replaces it.
fn probe_curves(made: &mut Made, profile: &mut Profile) -> Result<()> {
    let forms = |kt: Kt| -> Vec<CurveForm> {
        CURVES
            .iter()
            .filter_map(|name| Curve::from_cfg(kt, name).map(|c| (*name, c.params(), c.params_by_name())))
            .collect()
    };
    let families = [
        ("CKK_EC", Mechanism::EccKeyPairGen, forms(Kt::Ec)),
        ("CKK_EC_EDWARDS", Mechanism::EccEdwardsKeyPairGen, forms(Kt::EcEdwards)),
        ("CKK_EC_MONTGOMERY", Mechanism::EccMontgomeryKeyPairGen, MONTGOMERY.to_vec()),
    ];
    for (kt, mech, curves) in families {
        let mut row = GenerateRow::default();
        // A generation mechanism the module does not list is its answer, not a refusal to
        // explain (AWS CloudHSM lists no Edwards one, and makes Ed25519 its own way [run]).
        let keygen = mech.mechanism_type();
        if !made.tok.advertised.contains(&keygen.to_string()) {
            for (curve, ..) in curves {
                row.cannot.push(curve.to_owned());
                profile.notes.insert(curve.to_owned(), format!("not advertised: {keygen}"));
            }
            profile.generate.insert(kt.to_owned(), row);
            continue;
        }
        let mut probed_ops = false;
        for (curve, oid, name) in curves {
            // The usage each kind's operation probes need: signing, deriving, or both.
            let usage: &[Attribute] = match kt {
                "CKK_EC" => &[Attribute::Sign(true), Attribute::Derive(true)],
                "CKK_EC_EDWARDS" => &[Attribute::Sign(true)],
                _ => &[Attribute::Derive(true)],
            };
            let mut outcome = None;
            for params in std::iter::once(oid).chain(name) {
                let public = [Attribute::EcParams(params.to_vec()), Attribute::Verify(true), Attribute::Private(false)];
                let private = [Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Sensitive(true)];
                let with_usage = [&private[..], usage].concat();
                // A Montgomery public key verifies nothing: no CKA_VERIFY on its usage template.
                let use_public = if kt == "CKK_EC_MONTGOMERY" { &public[..1] } else { &public[..] };
                let (made_pair, usable) = made.pair_for_use(&mech, (use_public, &with_usage), (&public, &private))?;
                let by_name = !std::ptr::eq(params, oid);
                outcome = Some((made_pair, usable, by_name));
                if matches!(outcome, Some((Ok(_), ..))) {
                    break;
                }
            }
            match outcome {
                Some((Ok((public, private)), usable, by_name)) => {
                    row.can.push(curve.to_owned());
                    if by_name {
                        row.by_name.push(curve.to_owned());
                    }
                    if !probed_ops {
                        probed_ops = true;
                        if usable {
                            operate(made, profile, kt, curve, public, private);
                        } else {
                            made.undetermined.push(format!(
                                "no operation probes on {kt} keys: the module refused the usage attributes \
                                 when generating on {curve}"
                            ));
                        }
                    }
                }
                Some((Err(e), ..)) => {
                    row.cannot.push(curve.to_owned());
                    profile.notes.insert(curve.to_owned(), format!("generation refused: {}", ckr(&e)));
                }
                None => {}
            }
        }
        profile.generate.insert(kt.to_owned(), row);
    }
    Ok(())
}

/// Key pairs per RSA size: `can-bits` and `cannot-bits` beside the range the module reports.
/// The 2048-bit pair gets the operation probes, and on a scratch token it is the wrap probes'
/// transport key: wrapping is encryption, so its public half wraps and its private half
/// unwraps. In a scratch slot the next size replaces it, so there it is no transport key.
fn probe_rsa(made: &mut Made, profile: &mut Profile) -> Result<Option<(ObjectHandle, ObjectHandle)>> {
    let mut row = profile.generate.remove("CKK_RSA").unwrap_or_default();
    let mut transport = None;
    for bits in [1024u32, 2048, 3072, 4096] {
        let public = [
            Attribute::ModulusBits(u64::from(bits).into()),
            Attribute::PublicExponent(vec![1, 0, 1]),
            Attribute::Private(false),
        ];
        let plain = [Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Sensitive(true)];
        // The 2048-bit pair carries every usage the operation and wrap probes need, each
        // attribute on the half the spec defines it for, since their defaults are the module's
        // choice. A module refusing the explicit rows gets the bare templates.
        let attempt = if bits == 2048 {
            let mut public_use = public.to_vec();
            public_use.extend([Attribute::Encrypt(true), Attribute::Wrap(true), Attribute::Verify(true)]);
            let mut private_use = plain.to_vec();
            private_use.extend([Attribute::Decrypt(true), Attribute::Unwrap(true), Attribute::Sign(true)]);
            made.pair_for_use(&Mechanism::RsaPkcsKeyPairGen, (&public_use, &private_use), (&public, &plain))?
        } else {
            (made.pair(&Mechanism::RsaPkcsKeyPairGen, &public, &plain)?, false)
        };
        match attempt {
            (Ok((public, private)), usable) => {
                if bits == 2048 {
                    if usable {
                        operate(made, profile, "CKK_RSA", "RSA-2048", public, private);
                    } else {
                        made.undetermined.push(
                            "no operation probes on CKK_RSA keys: the module refused the usage attributes".into(),
                        );
                    }
                    if matches!(made.target, Target::Labels) {
                        transport = Some((public, private));
                    }
                }
                row.can_bits.push(bits);
            }
            (Err(e), _) => {
                row.cannot_bits.push(bits);
                // One note per refused size: the last failure must not erase the others.
                profile.notes.insert(format!("CKK_RSA at {bits}"), format!("modulusBits = {bits}: {}", ckr(&e)));
            }
        }
    }
    profile.generate.insert("CKK_RSA".into(), row);
    Ok(transport)
}

/// The operation probes on one fresh key pair of kind `kt`: every advertised mechanism that
/// applies to it, verified on the host wherever cakeys can (`sig`, `pop`) — signing, ECDH
/// derivation and decryption.
fn operate(made: &mut Made, profile: &mut Profile, kt: &str, on: &str, public: ObjectHandle, private: ObjectHandle) {
    if kt == "CKK_EC_MONTGOMERY" {
        // No Montgomery SPKI or host X25519 in cakeys yet.
        made.undetermined.push(format!("no operation probes on {on}: ECDH with {kt} keys is not probed yet"));
        return;
    }
    let spki = match made.tok.material_spki(public) {
        Ok(Some(spki)) => spki,
        Ok(None) => {
            made.undetermined.push(format!("no operation probes on {on}: its public key carries no material"));
            return;
        }
        Err(e) => {
            made.undetermined.push(format!("no operation probes on {on}: {e}"));
            return;
        }
    };
    match kt {
        "CKK_EC" => {
            let curve = Curve::from_cfg(Kt::Ec, on);
            ec_ops(made, private, &spki, on, curve.and_then(EcdsaHash::for_curve));
            if made.advertises(MechanismType::ECDH1_DERIVE) {
                derive(made, profile, private, &spki, on);
            }
        }
        "CKK_EC_EDWARDS" => {
            if made.advertises(MechanismType::EDDSA) {
                let mech = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
                let outcome = sign(made.session, &mech, private, MSG, |s| sig::ed25519(&spki, MSG, s));
                made.ops.record(MechanismType::EDDSA, on, outcome);
            }
        }
        "CKK_RSA" => rsa_ops(made, profile, private, &spki, on),
        _ => made.undetermined.push(format!("no operation probes on {on}: ECDH with {kt} keys is not probed yet")),
    }
}

/// Sign `data` with `mech`; `check` verifies the signature on the host where it can (`None`:
/// no host verifier for this one, the call succeeding is the observation).
fn sign(
    s: &Session,
    mech: &Mechanism,
    key: ObjectHandle,
    data: &[u8],
    check: impl FnOnce(&[u8]) -> sig::Verdict,
) -> std::result::Result<(), String> {
    let signature = s.sign(mech, key, data).map_err(|e| ckr(&e))?;
    match check(&signature) {
        Some(Err(e)) => Err(format!("the signature does not verify ({e})")),
        _ => Ok(()),
    }
}

/// ECDSA, raw and with each hash the module advertises; verified for the hashes `sig` has.
fn ec_ops(made: &mut Made, private: ObjectHandle, spki: &[u8], on: &str, hash: Option<EcdsaHash>) {
    let verify =
        |h: Option<EcdsaHash>| move |s: &[u8]| h.and_then(|h| sig::ecdsa(spki, MSG, s, Encoding::Raw, Some(h)));
    // Raw ECDSA signs the curve's digest of the message.
    let digest = hash.map_or_else(|| Sha256::digest(MSG).to_vec(), |h| h.digest(MSG));
    let raw = (Mechanism::Ecdsa, digest, hash.or(Some(EcdsaHash::Sha256)));
    let hashed = [
        (Mechanism::EcdsaSha1, MSG.to_vec(), None),
        (Mechanism::EcdsaSha224, MSG.to_vec(), None),
        (Mechanism::EcdsaSha256, MSG.to_vec(), Some(EcdsaHash::Sha256)),
        (Mechanism::EcdsaSha384, MSG.to_vec(), Some(EcdsaHash::Sha384)),
        (Mechanism::EcdsaSha512, MSG.to_vec(), Some(EcdsaHash::Sha512)),
    ];
    for (mech, data, h) in std::iter::once(raw).chain(hashed) {
        let mt = mech.mechanism_type();
        if made.advertises(mt) {
            let outcome = sign(made.session, &mech, private, &data, verify(h));
            made.ops.record(mt, on, outcome);
        }
    }
}

/// `CKM_ECDH1_DERIVE` against a host ephemeral key, as `pop-ecdh` does it: into a sealed
/// secret first, authenticated by an HMAC when the module has one; else into an extractable secret, read and
/// compared. `derive.sealed` records which, a refused sealed derivation the note.
fn derive(made: &mut Made, profile: &mut Profile, private: ObjectHandle, spki: &[u8], on: &str) {
    let s = made.session;
    let ch = match pop::ecdh_challenge(spki, MSG) {
        Ok(ch) => ch,
        Err(e) => {
            made.undetermined.push(format!("no ECDH probe on {on}: {e}"));
            return;
        }
    };
    let mech = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &ch.peer));
    let base = [
        Attribute::Token(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
    ];
    // A derived secret the module will not destroy stays behind (tpm2-pkcs11 persists it):
    // a note, since `pop-ecdh` derives one per proof.
    let destroy = |h, path: &str, profile: &mut Profile| {
        if let Err(e) = s.destroy_object(h) {
            profile.notes.insert(
                "derive.destroy".into(),
                format!("{on}: the {path} derived secret cannot be destroyed: {}", ckr(&e)),
            );
        }
    };
    // The sealed path decides when it MACs right (or the module has no HMAC to MAC with: then
    // `pop-ecdh` takes the extractable path anyway) or MACs wrong; it falls back to the
    // extractable path, with why, when the module refuses it or cannot MAC with it.
    let mut sealed =
        [&base[..], &[Attribute::Sensitive(true), Attribute::Extractable(false), Attribute::Sign(true)]].concat();
    let mut open = [&base[..], &[Attribute::Sensitive(false), Attribute::Extractable(true)]].concat();
    let len = ch.secret.len();
    let sealed_path = match derive_any(s, &mech, private, &sealed, len) {
        Ok((h, used, changed)) => {
            // The sealed path is the one that MACs on the token (what `derive.sealed` tells
            // pop-ecdh); what the secret reports, when not what was asked, is a note (AWS
            // CloudHSM: sensitive, but extractable [run]).
            let reads =
                s.get_attributes(h, &[AttributeType::Sensitive, AttributeType::Extractable]).unwrap_or_default();
            if !(reads.contains(&Attribute::Sensitive(true)) && reads.contains(&Attribute::Extractable(false))) {
                profile.notes.insert(
                    "derive.secret".into(),
                    format!(
                        "{on}: the derived secret reports {}",
                        reads.iter().map(show).collect::<Vec<_>>().join(", ")
                    ),
                );
            }
            let mac = made.advertises(MechanismType::SHA256_HMAC).then(|| s.sign(&Mechanism::Sha256Hmac, h, MSG));
            destroy(h, "sealed", profile);
            if let Some((changed, first)) = changed {
                profile.notes.insert(
                    "derive.template".into(),
                    format!("{on}: the template as asked is refused ({}); derived with {changed}", ckr(&first)),
                );
            }
            sealed = used;
            match mac {
                None => Ok(Ok(())),
                Some(Ok(tag)) if pop::ct_eq(&ch.mac, &tag) => Ok(Ok(())),
                Some(Ok(_)) => Ok(Err("the derived secret is not the shared secret".to_owned())),
                Some(Err(e)) => Err(format!("derives into a sealed secret, but HMAC with it fails: {}", ckr(&e))),
            }
        }
        Err(e) => Err(format!("a sealed (non-extractable) derived secret is refused: {}", ckr(&e))),
    };
    let outcome = match sealed_path {
        Ok(outcome) => {
            if outcome.is_ok() {
                profile.derive.sealed.get_or_insert(true);
            }
            outcome
        }
        Err(why) => match derive_any(s, &mech, private, &open, len) {
            Ok((h, used, changed)) => {
                if let Some((changed, first)) = changed {
                    profile.notes.insert(
                        "derive.template".into(),
                        format!("{on}: the template as asked is refused ({}); derived with {changed}", ckr(&first)),
                    );
                }
                open = used;
                let value = s.get_attributes(h, &[AttributeType::Value]).ok().and_then(|v| v.into_iter().next());
                destroy(h, "extractable", profile);
                match value {
                    Some(Attribute::Value(v)) if pop::ct_eq(&ch.secret, &v) => {
                        profile.derive.sealed = Some(false);
                        profile.notes.insert("derive.sealed".into(), why);
                        Ok(())
                    }
                    Some(Attribute::Value(_)) => Err("the derived secret is not the shared secret".to_owned()),
                    _ => Err(format!("{why}; the extractable derived secret's CKA_VALUE is unreadable")),
                }
            }
            Err(e) => Err(format!("{why}; extractable: {}", ckr(&e))),
        },
    };
    if outcome.is_ok() {
        let template = if profile.derive.sealed == Some(true) { &sealed } else { &open };
        derived_once(made, profile, &mech, private, template, on);
    }
    made.ops.record(MechanismType::ECDH1_DERIVE, on, outcome);
}

/// After a derivation took with `template`: whether it derives the same way in a read-only
/// session, where the read-only verbs prove possession (`verify`, `check`), and what the key
/// that derived says of itself (a spec asking `CKA_DERIVE = true` is checked against this, not
/// against what the key does).
fn derived_once(
    made: &mut Made,
    profile: &mut Profile,
    mech: &Mechanism,
    private: ObjectHandle,
    template: &[Attribute],
    on: &str,
) {
    match made.tok.extra_session(token::Access::Read).map(|ro| (ro.derive_key(mech, private, template), ro)) {
        Ok((Ok(h), ro)) => {
            let _ = ro.destroy_object(h);
            profile.derive.read_only.get_or_insert(true);
        }
        Ok((Err(e), _)) => {
            profile.derive.read_only = Some(false);
            profile.notes.insert("derive.read-only".into(), format!("{on}: in a read-only session: {}", ckr(&e)));
        }
        Err(e) => made.undetermined.push(format!("no read-only ECDH probe on {on}: {e}")),
    }
    if let Ok(attrs) = made.session.get_attributes(private, &[AttributeType::Derive])
        && let Some(Attribute::Derive(reported)) = attrs.into_iter().next()
    {
        profile.derive.key_attribute.get_or_insert(reported);
        if !reported {
            profile.notes.insert(
                "derive.key-attribute".into(),
                format!("{on}: derives although the key reports CKA_DERIVE = false"),
            );
        }
    }
}

/// PKCS#1 v1.5's `DigestInfo` prefix for SHA-256 (RFC 8017 §9.2): what raw `CKM_RSA_PKCS`
/// signs in front of the digest.
const SHA256_DIGEST_INFO: [u8; 19] =
    [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20];

/// RSA signing (PKCS#1 v1.5 raw and hashed, PSS raw and hashed, raw X.509) and decryption
/// (PKCS#1 v1.5, OAEP per hash: `decrypt.oaep`), on a 2048-bit key.
fn rsa_ops(made: &mut Made, profile: &mut Profile, private: ObjectHandle, spki: &[u8], on: &str) {
    let pkcs1 = |s: &[u8]| sig::rsa_pkcs1v15::<Sha256>(spki, MSG, s);
    let none = |_: &[u8]| None;
    let pss = |hash, mgf, len: usize| PkcsPssParams { hash_alg: hash, mgf, s_len: (len as u64).into() };
    let digest_info = [&SHA256_DIGEST_INFO[..], Sha256::digest(MSG).as_slice()].concat();
    // Raw RSA signs one modulus-sized block; a leading zero keeps it below any modulus.
    let block = [&[0u8][..], &[0x5a; 255]].concat();
    let sha256 = Sha256::digest(MSG).to_vec();
    let signs: [(Mechanism, Vec<u8>, bool); 11] = [
        (Mechanism::RsaPkcs, digest_info, true),
        (Mechanism::Sha1RsaPkcs, MSG.to_vec(), false),
        (Mechanism::Sha224RsaPkcs, MSG.to_vec(), false),
        (Mechanism::Sha256RsaPkcs, MSG.to_vec(), true),
        (Mechanism::Sha384RsaPkcs, MSG.to_vec(), false),
        (Mechanism::Sha512RsaPkcs, MSG.to_vec(), false),
        (Mechanism::RsaPkcsPss(pss(MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32)), sha256, false),
        (Mechanism::Sha1RsaPkcsPss(pss(MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, 20)), MSG.to_vec(), false),
        (Mechanism::Sha256RsaPkcsPss(pss(MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32)), MSG.to_vec(), false),
        (Mechanism::Sha384RsaPkcsPss(pss(MechanismType::SHA384, PkcsMgfType::MGF1_SHA384, 48)), MSG.to_vec(), false),
        (Mechanism::Sha512RsaPkcsPss(pss(MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, 64)), MSG.to_vec(), false),
    ];
    for (mech, data, verified) in signs {
        let mt = mech.mechanism_type();
        if made.advertises(mt) {
            let outcome = if verified {
                sign(made.session, &mech, private, &data, pkcs1)
            } else {
                sign(made.session, &mech, private, &data, none)
            };
            made.ops.record(mt, on, outcome);
        }
    }
    if made.advertises(MechanismType::RSA_X_509) {
        let outcome = sign(made.session, &Mechanism::RsaX509, private, &block, none);
        made.ops.record(MechanismType::RSA_X_509, on, outcome);
    }
    // Decryption: the host encrypts a fresh secret to the key, the token must recover it.
    let decrypts = |made: &mut Made, mech: &Mechanism, padding| -> std::result::Result<(), String> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| e.to_string())?;
        let cipher = pop::rsa_encrypt(spki, padding, &secret).map_err(|e| e.to_string())?;
        let plain = made.session.decrypt(mech, private, &cipher).map_err(|e| ckr(&e))?;
        if pop::ct_eq(&secret, &plain) { Ok(()) } else { Err("decrypts to something else".to_owned()) }
    };
    if made.advertises(MechanismType::RSA_PKCS) {
        let outcome = decrypts(made, &Mechanism::RsaPkcs, RsaPadding::Pkcs1v15);
        made.ops.record(MechanismType::RSA_PKCS, &format!("{on} decrypt"), outcome);
    }
    if made.advertises(MechanismType::RSA_PKCS_OAEP) {
        let mut works = Vec::new();
        for (hash, mgf, name, padding) in [
            (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, "SHA-1", RsaPadding::Oaep(OaepHash::Sha1)),
            (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, "SHA-256", RsaPadding::Oaep(OaepHash::Sha256)),
            (MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, "SHA-512", RsaPadding::OaepSha512),
        ] {
            let mech = Mechanism::RsaPkcsOaep(PkcsOaepParams::new(hash, mgf, PkcsOaepSource::empty()));
            let outcome = decrypts(made, &mech, padding);
            if outcome.is_ok() {
                works.push(name.to_owned());
            }
            made.ops.record(MechanismType::RSA_PKCS_OAEP, &format!("{on} decrypt {name}"), outcome);
        }
        // Probed: `[]` when no hash decrypts, distinct from never probed.
        profile.decrypt.oaep = Some(works);
    }
}

/// The secret-key generation the module advertises: success is implied by the advertise list,
/// a refusal is a `subtract` row (advertised but broken). Returns the first AES key, the wrap
/// probes' wrapped key.
fn probe_secrets(made: &mut Made, profile: &mut Profile) -> Option<ObjectHandle> {
    let session = made.session;
    let mut aes = None;
    for (mech, name, key_type) in [
        (Mechanism::AesKeyGen, "CKM_AES_KEY_GEN", KeyType::AES),
        (Mechanism::GenericSecretKeyGen, "CKM_GENERIC_SECRET_KEY_GEN", KeyType::GENERIC_SECRET),
    ] {
        let name = name.to_owned();
        if !made.tok.advertised.contains(&name) {
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
        Err(CkError::Pkcs11(RvError::AttributeReadOnly, _)) => {
            profile.unwrap.refuse = Some(vec!["CKA_VALUE_LEN".into()]);
            profile.notes.insert("CKA_VALUE_LEN".into(), "CKR_ATTRIBUTE_READ_ONLY in an unwrap template".into());
        }
        // Neither accepted nor the refusal the rule names: the row stays unprobed.
        Err(e) => {
            profile.notes.insert("unwrap-template".into(), format!("CKA_VALUE_LEN: {}", ckr(&e)));
        }
    }
}

/// What the `probe` verb asks beyond the probing itself.
pub struct Request<'a> {
    /// Also run the write probes ([`probe`]).
    pub write: bool,
    /// Name the generated profile; default: `claimed`'s name, else `<provider>/<version>`.
    pub name: Option<&'a str>,
    /// The committed profile the result is diffed against, if any.
    pub claimed: Option<&'a Profile>,
    /// The result is written to a file or judged against `claimed`, not only printed.
    pub kept: bool,
}

/// The `probe` verb: probe `tok` and name the result. What the probe could not decide is
/// noted.
///
/// Regeneration is the diff-and-write flow: the profile takes the claimed profile's name (a
/// module that hides its version — kryoptic reports 0.0 — still regenerates its committed
/// profile, whose name is the repo's, D9).
///
/// # Errors
///
/// `Validation` (17) when the result would be kept but this build's cryptoki is unpatched;
/// [`probe`]'s own refusals.
pub fn generate(tok: &Token, cfg: &TokenCfg, req: &Request, notes: &mut cakeys_pkcs11::ops::Notes) -> Result<Profile> {
    // cryptoki drops from C_GetMechanismList every mechanism it cannot name, so through
    // an unpatched binding the advertisement is short (kryoptic's CKM_AES_KEY_WRAP_KWP
    // [run]): such a build may print a probe, never write or judge a committed one.
    if !cakeys_pkcs11::binding::patched() {
        if req.kept {
            return Err(KmError::Validation(
                "this build's cryptoki lacks the Nix patches and drops the mechanisms it \
                 cannot name from C_GetMechanismList: probe with the Nix-built cakeys to \
                 write or diff a profile"
                    .into(),
            ));
        }
        notes.note("probe: this build's cryptoki is unpatched: the advertise list may be short");
    }
    let mut probed = probe(tok, cfg, req.write)?;
    for why in &probed.undetermined {
        notes.note(format_args!("probe: {why}"));
    }
    if let Some(n) = req.name {
        n.clone_into(&mut probed.profile.profile);
    } else if let Some(claimed) = req.claimed {
        probed.profile.profile.clone_from(&claimed.profile);
    }
    Ok(probed.profile)
}

/// The rows in which a generated profile differs from the committed `claimed`; none means it
/// conforms. A read-only probe observes only the match keys, the advertisement and the
/// reported key sizes, so only those can conform or drift.
#[must_use]
pub fn drift(generated: &Profile, claimed: &Profile, write: bool) -> Vec<String> {
    if write { crate::diff::diff(generated, claimed) } else { crate::diff::read_only(generated, claimed) }
}

/// Keep, in a generated `profile` about to replace the file with content `existing` (named
/// `shown` in messages), the two sections the probe does not generate: the file's [migration]
/// claims (docs/CAMIGRATE.md evidence, never probe-observable) and its [manual] findings (made by
/// hand, each with its evidence).
///
/// # Errors
///
/// `Validation` (17) for a file that does not parse (regenerating it would silently drop
/// those sections), and for any existing file from a read-only probe (it would drop every
/// write-probe row).
pub fn keep_claims(profile: &mut Profile, existing: &str, shown: &str, write: bool) -> Result<()> {
    if !write {
        return Err(KmError::Validation(format!(
            "{shown}: a read-only probe would overwrite its generate, wrap and unwrap rows; pass --write"
        )));
    }
    let old = Profile::from_toml(existing)
        .map_err(|e| KmError::Validation(format!("{shown}: not a profile, refusing to overwrite: {e}")))?;
    profile.migration = old.migration;
    profile.manual = old.manual;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;

    /// Only the probe's policy defaults are dropped, and only for a template refusal: a type or
    /// usage attribute stays, and a mechanism refusal is the module's answer.
    #[test]
    fn only_policy_defaults_are_dropped_and_only_for_template_refusals() {
        let refusal = |rv| CkError::Pkcs11(rv, Function::GenerateKeyPair);
        assert!(template_refusal(&refusal(RvError::AttributeValueInvalid)));
        assert!(template_refusal(&refusal(RvError::TemplateInconsistent)));
        assert!(!template_refusal(&refusal(RvError::MechanismInvalid)));
        assert!(!template_refusal(&refusal(RvError::FunctionFailed)));
        assert!(is_policy_default(&Attribute::Private(false)));
        assert!(is_policy_default(&Attribute::Extractable(false)));
        assert!(!is_policy_default(&Attribute::Sign(true)));
        assert!(!is_policy_default(&Attribute::KeyType(KeyType::EC)));
        assert_eq!(show(&Attribute::Private(false)), "CKA_PRIVATE = false");
    }

    #[test]
    fn notes_name_the_return_value_not_the_prose() {
        // Regeneration is byte-identical only while these spellings hold.
        let rv = |e| ckr(&CkError::Pkcs11(e, Function::WrapKey));
        assert_eq!(rv(RvError::GeneralError), "CKR_GENERAL_ERROR");
        assert_eq!(rv(RvError::AttributeReadOnly), "CKR_ATTRIBUTE_READ_ONLY");
        assert_eq!(rv(RvError::CurveNotSupported), "CKR_CURVE_NOT_SUPPORTED");
        assert_eq!(rv(RvError::FunctionNotSupported), "CKR_FUNCTION_NOT_SUPPORTED");
        assert_eq!(rv(RvError::VendorDefined(0x8000_0001)), "CKR 0x80000001");
    }

    #[test]
    fn a_mechanism_is_subtracted_only_when_it_failed_everywhere() {
        let mut ops = Ops::default();
        ops.record(MechanismType::ECDSA_SHA1, "secp256r1", Err("CKR_MECHANISM_INVALID".into()));
        ops.record(MechanismType::ECDSA, "secp256r1", Ok(()));
        ops.record(MechanismType::RSA_PKCS_OAEP, "RSA-2048 decrypt SHA-1", Ok(()));
        ops.record(MechanismType::RSA_PKCS_OAEP, "RSA-2048 decrypt SHA-256", Err("CKR_ARGUMENTS_BAD".into()));
        let mut profile = Profile::from_toml("profile = \"t\"\nmode = \"observed\"\n").unwrap();
        ops.finish(&mut profile);
        assert_eq!(profile.subtract.mechanisms, ["CKM_ECDSA_SHA1"]);
        assert_eq!(profile.notes["CKM_ECDSA_SHA1"], "secp256r1: CKR_MECHANISM_INVALID");
        // Worked with one hash: usable, the other hash's failure a note only.
        assert_eq!(profile.notes["CKM_RSA_PKCS_OAEP"], "RSA-2048 decrypt SHA-256: CKR_ARGUMENTS_BAD");
        assert!(!profile.notes.contains_key("CKM_ECDSA"));
    }
}
