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
//!
//! What the verbs do, the probe does with the provider's templates (`Provider::template`):
//! generation through `Token::create`, and the imports, creations and sealed round trips of
//! [`moves`]. The templates this file builds itself vary what the module is asked, to measure
//! it (a bare pair, a derive without a default, a wrap probe's keys), and are sent as they are.

use cakeys_core::config::{AttrValue, Binding, Locator, ObjectCfg, SpecCfg, TokenCfg};
use cakeys_core::id::Curve;
use cakeys_core::pop::{self, OaepHash, RsaPadding};
use cakeys_core::sig::{self, Encoding, HashAlg};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Msg, Result};
use cakeys_pkcs11::token::{self, Token, derive_any, is_policy_default, show, template_refusal};
use cakeys_pkcs11::{BoundKey, Declared, Half, Template, keygen_mechanism};
use cakeys_profile::capability::{DECRYPT_OAEP, UNWRAP_TEMPLATE, WRAP_OAEP};
use cakeys_profile::{Answer, Capability, GenerateRow, KeyKind, MatchInfo, Mode, On, Profile};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

mod moves;

/// The text of a module-supplied string with its C padding removed: PKCS#11's fixed-width
/// fields are C strings, and a module may NUL-pad them (tpm2-pkcs11's token model comes from
/// the TPM's four 4-byte vendor-string properties, so swtpm reports `SW` + NULs + `TPM`
/// \[run\]). The padding is layout, not content — a note records the text.
fn clean(s: &str) -> String {
    s.split('\0').filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" ")
}

/// The `CKR_*` name of a failure, for notes: cryptoki's `Display` is the spec's prose, which
/// changes with the binding and would make a regeneration differ with no behaviour change.
/// The verbs' own naming (`token::rv_name`), so a note and a refusal spell it alike.
fn ckr(e: &CkError) -> String {
    token::rv_name(e)
}

/// A failed module call as an operation's outcome: its `CKR_*` name ([`ckr`]), and the value
/// code matches on.
fn ck_refusal(e: &CkError) -> Msg {
    Msg::from(ckr(e)).with_rv(token::rv_of(e))
}

/// [`ck_refusal`] after what was being done.
fn ck_said(what: &str, e: &CkError) -> Msg {
    Msg::from(format!("{what}: {}", ckr(e))).with_rv(token::rv_of(e))
}

/// What a probe found: the generated profile, and what it could not decide.
pub(crate) struct Probed {
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
/// operating, wrapping, unwrapping, deleting), up to its largest RSA size, which run only on a
/// token keys.toml marks `scratch` — or, for a module that creates only as SO into device
/// slots, in the one slot `scratchId` names — and are refused (17) anywhere else, never
/// silently skipped.
///
/// # Errors
///
/// `Validation` (17) when `write` is set but the token is not marked scratch, has no PIN, or
/// its provider creates only as Security Officer and no `scratchId` (with an admin credential)
/// names a slot holding nothing but the provider's own placeholder; the scratch guard is the
/// one thing the probe refuses rather than records. `Unavailable` when an SO login fails.
pub(crate) fn probe(tok: &Token, cfg: &TokenCfg, write: Option<u32>) -> Result<Probed> {
    let profile = Profile {
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
        advertise: tok.advertised(),
        ..Profile::new(format!("{}/{}", tok.provider.name(), tok.module.version), Mode::Observed)
    };
    let mut profile = Draft::new(profile);
    profile.note("cryptoki".into(), format!("the module reports Cryptoki {}", tok.module.cryptoki));
    // A mechanism listed more than once (libkmsp11 1.9: CKM_RSA_PKCS_KEY_PAIR_GEN 24 times
    // [run]) is advertised once; the repetition is a note.
    let mut counts = BTreeMap::<&str, usize>::new();
    let advertised = tok.advertised();
    for m in &advertised {
        *counts.entry(m.as_str()).or_default() += 1;
    }
    let repeated: Vec<String> = counts.iter().filter(|(_, n)| **n > 1).map(|(m, n)| format!("{m} {n} times")).collect();
    if !repeated.is_empty() {
        profile.note("mechanism-list".into(), format!("C_GetMechanismList repeats {}", repeated.join(", ")));
        let mut seen = BTreeSet::new();
        profile.out.advertise.retain(|m| seen.insert(m.clone()));
    }
    // The RSA key sizes the module reports: read-only, a claim the write probes then test.
    if let Some((min, max)) = tok.rsa_bits {
        let row = profile.generate.entry(KeyKind::Rsa).or_default();
        row.min_bits = u32::try_from(min).ok();
        row.max_bits = u32::try_from(max).ok();
    }
    let mut undetermined = Vec::new();
    let Some(rsa_max_bits) = write else {
        undetermined.push(
            "read-only probes only: pass --write against a token marked scratch in keys.toml to \
             generate, operate, wrap and delete"
                .into(),
        );
        return Ok(Probed { profile: profile.finish(), undetermined });
    };
    let target = target(tok, cfg)?;
    if !tok.logged_in {
        // Without a user login every token-object generation fails with
        // CKR_USER_NOT_LOGGED_IN, which the probes would record as the module's refusals.
        return Err(KmError::Validation(
            format!("token '{}' has no PIN configured: the write probes need a user session", tok.name).into(),
        ));
    }
    if let Target::Slot(id) = &target {
        check_slot(tok, id)?;
    }
    let mut made = Made {
        tok,
        session: tok.raw(),
        scratch: Scratch { target, handles: Vec::new(), labels: Vec::new(), n: 0 },
        ops: Ops::default(),
        undetermined,
        template_notes: BTreeMap::new(),
        bound_keys: tok.provider.bound_keys(),
        bound: None,
        rsa_sizes: RSA_SIZES.iter().copied().filter(|b| *b <= rsa_max_bits).collect(),
    };
    write_probes(&mut made, &mut profile)?;
    profile.out.notes.append(&mut made.template_notes);
    Ok(Probed { profile: profile.finish(), undetermined: made.undetermined })
}

/// The scratch guard: where the write probes may write on this token, or why nowhere.
fn target(tok: &Token, cfg: &TokenCfg) -> Result<Target> {
    if tok.provider.manages_as_so() {
        let Some(id) = &cfg.probe.scratch_id else {
            return Err(KmError::Validation(
                format!(
                    "token '{}': its provider creates keys only in a Security Officer session, into \
                 device slots that may hold real keys: name the one slot the write probes may \
                 overwrite with tokens.{}.probe.scratchId (a hex CKA_ID); `scratch` cannot mark the \
                 whole device",
                    tok.name, tok.name
                )
                .into(),
            ));
        };
        if !token::has_admin(cfg) {
            return Err(KmError::Validation(
                format!(
                    "token '{}': the write probes generate as Security Officer: set tokens.{}.soCredentialFile \
                 or soCredentialEnv",
                    tok.name, tok.name
                )
                .into(),
            ));
        }
        // The config loader has already validated it.
        let id = cakeys_core::hex::decode(id)
            .ok_or_else(|| KmError::Validation(format!("probe.scratchId {id:?} is not hex").into()))?;
        return Ok(Target::Slot(id));
    }
    if cfg.probe.scratch_id.is_some() {
        return Err(KmError::Validation(
            format!(
                "token '{}': probe.scratchId names a slot for providers that create only as Security Officer \
             into device slots; provider {} creates as the user: mark the token probe.scratch = true",
                tok.name,
                tok.provider.name()
            )
            .into(),
        ));
    }
    if !cfg.probe.scratch {
        return Err(KmError::Validation(
            format!(
                "token '{}' is not marked scratch in keys.toml: the write probes would create and \
             destroy objects on it (tokens.{}.probe.scratch = true)",
                tok.name, tok.name
            )
            .into(),
        ));
    }
    Ok(Target::Labels)
}

/// Refuse a scratch slot holding anything but the provider's own placeholder from an earlier
/// generation (`Provider::scratch_occupant`): `scratchId` is one hex string, and a typo must
/// never overwrite a real key.
fn check_slot(tok: &Token, id: &[u8]) -> Result<()> {
    let s = tok.raw();
    let find =
        |t: &[Attribute]| s.find_objects(t).map_err(|e| KmError::Unavailable(format!("C_FindObjects: {e}").into()));
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
    let shown = cakeys_core::hex::encode(id);
    Err(KmError::Validation(
        format!(
            "token '{}': probe.scratchId {shown} holds objects that are not {}'s own placeholder from an earlier \
         generation, so it may hold a real key: refusing to overwrite it; empty the slot or name \
         another",
            tok.name,
            tok.provider.name()
        )
        .into(),
    ))
}

/// What the probes record as they run: the profile, and the working rows that become its
/// capabilities when they are done ([`Draft::finish`]). Everything else of the profile is
/// reached through it.
pub(crate) struct Draft {
    /// The profile as far as it is measured: what the probes set and note goes here.
    out: Profile,
    /// What each key type generated, by curve and by size, and the range the module reports.
    generate: BTreeMap<KeyKind, GenerateRow>,
    /// The OAEP hashes a wrap round-tripped with, of the ones tried; `None`: not probed.
    wrap_oaep: Option<Vec<String>>,
    /// The OAEP hashes the private key decrypted with, of the ones tried; `None`: not probed.
    decrypt_oaep: Option<Vec<String>>,
    /// The attributes an unwrap template refused, of the ones tried; `None`: not probed.
    unwrap_refused: Option<Vec<String>>,
    /// How ECDH derived.
    derive: Derived,
    /// What shows a generation row's answer: the refusal, or why nothing was tried.
    evidence: BTreeMap<Capability, String>,
}

/// How ECDH derived: into a sealed secret, and in a read-only session. (A base key that
/// derived while reporting `CKA_DERIVE = false` is a note: the provider repairs the read.)
#[derive(Default)]
struct Derived {
    sealed: Option<bool>,
    read_only: Option<bool>,
}

impl Draft {
    fn new(profile: Profile) -> Draft {
        Draft {
            out: profile,
            generate: BTreeMap::new(),
            wrap_oaep: None,
            decrypt_oaep: None,
            unwrap_refused: None,
            derive: Derived::default(),
            evidence: BTreeMap::new(),
        }
    }

    /// Set the answer to `c` ([`Profile::set`]).
    fn set(&mut self, c: Capability, answer: Answer, evidence: Option<String>, via: Option<String>) {
        self.out.set(c, answer, evidence, via);
    }

    /// Note `text` under `key`, over any note there.
    fn note(&mut self, key: String, text: String) {
        self.out.notes.insert(key, text);
    }

    /// Record why generating `key_type` on `on` answers as it does.
    fn generation_evidence(&mut self, key_type: &KeyKind, on: On, why: String) {
        self.evidence.insert(Capability::Generate { key_type: key_type.clone(), on }, why);
    }

    /// The profile with what the probes recorded as its rows: each OAEP hash tried, each
    /// template attribute tried, the ECDH answers, each curve and size generated or refused.
    fn finish(self) -> Profile {
        let mut p = self.out;
        let mut oaep = |worked: Option<Vec<String>>, tried: &[&str], cap: fn(String) -> Capability| {
            for h in tried.iter().filter(|_| worked.is_some()) {
                let yes = worked.iter().flatten().any(|w| w == h);
                p.set(cap((*h).to_owned()), Answer::of(yes), None, None);
            }
        };
        oaep(self.wrap_oaep, &WRAP_OAEP, Capability::WrapOaep);
        oaep(self.decrypt_oaep, &DECRYPT_OAEP, Capability::DecryptOaep);
        if let Some(refused) = self.unwrap_refused {
            for a in UNWRAP_TEMPLATE {
                let yes = !refused.iter().any(|r| r == a);
                p.set(Capability::UnwrapTemplate(a.to_owned()), Answer::of(yes), None, None);
            }
        }
        if let Some(b) = self.derive.sealed {
            p.set(Capability::DeriveSealed, Answer::of(b), None, None);
        }
        if let Some(b) = self.derive.read_only {
            p.set(Capability::DeriveReadOnly, Answer::of(b), None, None);
        }
        for (kt, row) in &self.generate {
            p.set_generation(kt.name(), row);
        }
        for (c, why) in self.evidence {
            if let Some(row) = p.capabilities.get_mut(&c) {
                row.evidence = Some(why);
            }
        }
        // What the probe noted of a row it wrote is that row's evidence.
        for (note, c) in [
            ("derive.sealed", Capability::DeriveSealed),
            ("derive.read-only", Capability::DeriveReadOnly),
            ("CKA_VALUE_LEN", Capability::UnwrapTemplate("CKA_VALUE_LEN".into())),
        ] {
            if let Some(row) = p.capabilities.get_mut(&c)
                && let Some(why) = p.notes.remove(note)
            {
                row.evidence = Some(why);
            }
        }
        p
    }
}

/// The message every operation probe signs, and the plaintext the decryption probes recover.
const MSG: &[u8] = b"cakeys probe: operations";

/// What the operation probes saw per mechanism (D2: deltas only). An advertised mechanism that
/// worked on some key is usable, the failures on other keys a note; one that failed on every
/// key it was tried with is a `subtract` row (advertised but unusable). One the module does not
/// list but runs is an `add` row; one it neither lists nor runs is what its list said. A
/// failure because an earlier one left its operation active (tpm2-pkcs11 \[run\]) says nothing
/// of the mechanism: undetermined.
#[derive(Default)]
struct Ops {
    worked: BTreeSet<String>,
    failed: BTreeMap<String, Vec<String>>,
    /// The mechanisms tried though the module does not list them.
    unlisted: BTreeSet<String>,
    /// The outcomes `CKR_OPERATION_ACTIVE` decided nothing of.
    busy: Vec<String>,
}

impl Ops {
    fn record(&mut self, mech: MechanismType, on: &str, outcome: std::result::Result<(), Msg>) {
        match outcome {
            Ok(()) => {
                self.worked.insert(mech.to_string());
            }
            Err(e) if token::rv_is(e.rv(), RvError::OperationActive) => {
                self.busy.push(format!("{mech} on {on}: an earlier operation left the session busy ({e})"));
            }
            Err(e) => self.failed.entry(mech.to_string()).or_default().push(format!("{on}: {e}")),
        }
    }

    /// The rows and notes of what was seen; returns what could not be decided.
    fn finish(self, profile: &mut Draft) -> Vec<String> {
        for mech in self.worked.iter().filter(|m| self.unlisted.contains(*m)) {
            profile.out.add.push(mech.clone());
            profile.note(mech.clone(), "not listed; works".into());
        }
        for (mech, why) in self.failed {
            if self.unlisted.contains(&mech) {
                if self.worked.contains(&mech) {
                    let note = profile.out.notes.entry(mech).or_default();
                    note.push_str("; ");
                    note.push_str(&why.join("; "));
                }
                continue;
            }
            if !self.worked.contains(&mech) {
                profile.out.subtract.mechanisms.push(mech.clone());
            }
            let why = why.join("; ");
            profile
                .out
                .notes
                .entry(mech)
                .and_modify(|n| {
                    n.push_str("; ");
                    n.push_str(&why);
                })
                .or_insert(why);
        }
        profile.out.subtract.mechanisms.sort();
        profile.out.subtract.mechanisms.dedup();
        self.busy
    }
}

/// Everything the probes created, so every run cleans up after itself — and the leftover check
/// turns "delete really deletes" into a note — plus the operation outcomes and what could not
/// be decided.
struct Made<'a> {
    tok: &'a Token,
    session: &'a Session,
    /// What the write probes made, and where they may.
    scratch: Scratch,
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
    /// The RSA sizes generated: [`RSA_SIZES`] up to the request's largest.
    rsa_sizes: Vec<u32>,
}

/// The objects the write probes make on their target: where they may write ([`Target`]), what
/// they made and under which labels, for the cleanup and the leftover check.
struct Scratch {
    target: Target,
    handles: Vec<ObjectHandle>,
    labels: Vec<String>,
    /// The last `cakeys-probe-NN` label handed out.
    n: usize,
}

impl Scratch {
    fn label(&mut self) -> String {
        self.n += 1;
        format!("cakeys-probe-{:02}", self.n)
    }

    /// Track `handles`, made under `label`, for the cleanup and the leftover check.
    fn track(&mut self, handles: &[ObjectHandle], label: &str) {
        self.handles.extend_from_slice(handles);
        if !self.labels.iter().any(|l| l == label) {
            self.labels.push(label.to_owned());
        }
    }

    fn destroy_all(&self, session: &Session) {
        for h in &self.handles {
            // Deletion failures are observations here: the leftover check reports them.
            let _ = session.destroy_object(*h);
        }
    }

    /// Which probe labels are still on the token: what `C_DestroyObject` really deleted.
    fn leftovers(&self, session: &Session) -> Vec<String> {
        self.labels
            .iter()
            .filter(|l| {
                session.find_objects(&[Attribute::Label(l.as_bytes().to_vec())]).is_ok_and(|found| !found.is_empty())
            })
            .cloned()
            .collect()
    }

    /// Destroy what an earlier, interrupted run left (`cakeys-probe-NN`, its own labels on a
    /// scratch token, and a purpose-bound module's keys under the bound labels), so this run's
    /// leftover check reports only this run. Returns the labels cleaned.
    fn clear_stale(session: &Session, bound_keys: &[BoundKey]) -> Vec<String> {
        let mut cleaned = Vec::new();
        let Ok(all) = session.find_objects(&[]) else { return cleaned };
        for h in all {
            let label = match session.get_attributes(h, &[AttributeType::Label]) {
                Ok(attrs) => match attrs.into_iter().next() {
                    Some(Attribute::Label(l)) => String::from_utf8_lossy(&l).into_owned(),
                    _ => continue,
                },
                Err(_) => continue,
            };
            let ours = label.starts_with("cakeys-probe-") || bound_keys.iter().any(|k| k.label == label);
            if ours && session.destroy_object(h).is_ok() {
                cleaned.push(label);
            }
        }
        cleaned.sort();
        cleaned.dedup();
        cleaned
    }
}

/// The RSA key sizes the write probes generate, in bits, whatever the module reports (a claim,
/// `[reported."CKK_RSA"]`): the sizes in use from 512 to 16384. The gate answers yes for a size
/// between two that generated, so these cover the range.
pub(crate) const RSA_SIZES: [u32; 10] = [512, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384];

/// A generated pair, `(public, private)`, or the module's refusal.
type Pair = std::result::Result<(ObjectHandle, ObjectHandle), CkError>;

/// A pair `Token::create` made, `(public, private, its note)`, or the module's refusal.
type Created = std::result::Result<(ObjectHandle, ObjectHandle, Option<token::CreateNote>), KmError>;

/// A probe spec: `CKA_SENSITIVE` and the usage bits `private` and `public` name, true.
fn spec(private: &[&str], public: &[&str]) -> SpecCfg {
    let attrs = |names: &[&str]| names.iter().map(|n| ((*n).to_owned(), AttrValue::Bool(true))).collect();
    SpecCfg {
        object: "probe".into(),
        attributes: attrs(&[&["CKA_SENSITIVE"], private].concat()),
        public_attributes: attrs(public),
        migrate: cakeys_core::config::SpecMigrateCfg::default(),
        tokens: BTreeMap::new(),
    }
}

/// A refusal `Token::create` reported, as the evidence of a generation row: the `CKR_*` of the
/// module call that failed, as the probe has always named it, else what was said.
fn refused(tok: &Token, e: &KmError) -> String {
    e.rv().map_or_else(|| evidence(tok, e), token::rv_value_name)
}

impl Made<'_> {
    fn advertises(&self, m: MechanismType) -> bool {
        self.tok.lists(m) && self.bound.as_ref().is_none_or(|b| b.contains(&m.to_string()))
    }

    /// Whether the operation probes try `m` on the key at hand: any mechanism, listed or not —
    /// what the module lists is a claim, not a bound — but on a key bound to some (Cloud KMS),
    /// only those.
    fn tries(&self, m: MechanismType) -> bool {
        self.bound.as_ref().is_none_or(|b| b.contains(&m.to_string()))
    }

    /// Record what `m` did on `on`, and whether the module lists it.
    fn record(&mut self, m: MechanismType, on: &str, outcome: std::result::Result<(), Msg>) {
        if !self.tok.lists(m) {
            self.ops.unlisted.insert(m.to_string());
        }
        self.ops.record(m, on, outcome);
    }

    /// Generate a key pair where the target says: the templates completed with a fresh probe
    /// label, or with the scratch slot's `CKA_ID` in a Security Officer session. The outer
    /// error is the SO login failing, which stops the probe; the inner one is the module's
    /// refusal, an observation.
    fn pair(&mut self, mech: &Mechanism, public: &[Attribute], private: &[Attribute]) -> Result<Pair> {
        let session = self.session;
        let locator = match &self.scratch.target {
            Target::Labels => None,
            Target::Slot(id) => Some(Attribute::Id(id.clone())),
        };
        let Some(id) = locator else {
            let label = self.scratch.label();
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
                self.scratch.track(&[private, public], &label);
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

    /// Generate `object` where the target says, as `spec` declares it, through the verbs' own
    /// create operation (`Token::create`: the provider's, as Security Officer where the module
    /// creates only so). The pair and `create`'s note, or the module's refusal as the inner
    /// error; an SO login failing is the outer one, and stops the probe.
    fn create(&mut self, object: &ObjectCfg, spec: &SpecCfg) -> Result<Created> {
        let (loc, label) = match &self.scratch.target {
            Target::Labels => {
                let label = self.scratch.label();
                (Locator { label: Some(label.clone()), id: None }, Some(label))
            }
            Target::Slot(id) => (Locator { label: None, id: Some(cakeys_core::hex::encode(id)) }, None),
        };
        let note = match self.tok.create(object, spec, &loc, None) {
            Ok(note) => note,
            Err(KmError::Unavailable(m)) if m.contains(token::SO_LOGIN) => return Err(KmError::Unavailable(m)),
            Err(e) => return Ok(Err(e)),
        };
        let one = |class| self.tok.find(class, &loc).map(|found| found.first().copied());
        let (Some(public), Some(private)) = (one(ObjectClass::PUBLIC_KEY)?, one(ObjectClass::PRIVATE_KEY)?) else {
            return Ok(Err(KmError::NotFound("the key pair it made is not under its locator".into())));
        };
        if let Some(label) = label {
            self.scratch.track(&[private, public], &label);
        }
        Ok(Ok((public, private, note)))
    }

    /// [`Self::create`] with the usage the operation probes need, else bare, as a module may
    /// insist. `Ok((created, usable))`: `usable` when the usage took.
    fn create_for_use(&mut self, object: &ObjectCfg, usage: &SpecCfg, bare: &SpecCfg) -> Result<(Created, bool)> {
        match self.create(object, usage)? {
            Ok(made) => Ok((Ok(made), true)),
            Err(_) => Ok((self.create(object, bare)?, false)),
        }
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
}

/// The write probes: key pairs per curve and RSA size, each operation the module advertises
/// on the first key of each kind, the secret-key generation it advertises (a refusal is a
/// `subtract` row), the OAEP hashes it actually implements for wrapping (wrap and unwrap back),
/// and the unwrap-template rules. On a scratch token every run cleans up after itself, and the
/// leftover check turns "delete really deletes" into a note.
fn write_probes(made: &mut Made, profile: &mut Draft) -> Result<()> {
    let labels = matches!(made.scratch.target, Target::Labels);
    if labels {
        let stale = Scratch::clear_stale(made.session, &made.bound_keys);
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
                (Some(transport), Some(aes)) => {
                    probe_wrapping(made, profile, transport, aes);
                    probe_key_wraps(made, profile, transport, aes);
                }
                _ => made.undetermined.push(
                    "no wrap probes: the probes could not make both an RSA transport key and an AES \
                     key on this token"
                        .into(),
                ),
            }
            // After the wrap probes: a secret key's sealed export takes an OAEP hash they found.
            moves::probe_moves(made, profile, transport)?;
        }
        destroy_all(made, profile);
    } else {
        if !bound {
            moves::probe_moves(made, profile, None)?;
        }
        made.undetermined.push(
            "in a scratch slot: no secret-key, wrap, export or delete probes (each needs a second \
             object, or erasing the slot's key)"
                .into(),
        );
    }
    let busy = std::mem::take(&mut made.ops).finish(profile);
    made.undetermined.extend(busy);
    profile.out.add.sort();
    profile.out.add.dedup();
    Ok(())
}

/// Destroy everything the probes made on a scratch token, and record what `C_DestroyObject`
/// really removed: a `delete.<class>` row per class the probes made, and a note naming the
/// labels still there.
fn destroy_all(made: &Made, profile: &mut Draft) {
    // Per class, how many objects sit under the probe's labels.
    let count = |made: &Made| {
        let mut by_class = BTreeMap::<String, usize>::new();
        for label in &made.scratch.labels {
            let found = made.session.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap_or_default();
            for h in found {
                if let Ok([Attribute::Class(c)]) = made.session.get_attributes(h, &[AttributeType::Class]).as_deref() {
                    *by_class.entry(c.to_string()).or_default() += 1;
                }
            }
        }
        by_class
    };
    let before = count(made);
    made.scratch.destroy_all(made.session);
    let after = count(made);
    for (class, n) in before {
        let left = after.get(&class).copied().unwrap_or_default();
        let why = (left > 0).then(|| format!("C_DestroyObject leaves {left} of {n} behind"));
        profile.set(Capability::Delete(class), Answer::of(left == 0), why, None);
    }
    let leftovers = made.scratch.leftovers(made.session);
    if !leftovers.is_empty() {
        profile.note("destroy".into(), format!("C_DestroyObject leaves objects behind: {}", leftovers.join(", ")));
    }
}

/// A module that binds every key to one purpose at creation ([`BoundKey`], Google Cloud KMS):
/// one key per binding, generated from the provider's exact template (no public template), and
/// probed with only the mechanisms its binding serves. The curves and sizes no binding covers
/// are tried without one ([`probe_unbound`]), so their `cannot` rows are observations too.
fn probe_bound(made: &mut Made, profile: &mut Draft) {
    let session = made.session;
    profile.note(
        "purpose-bound".into(),
        format!(
            "each key is bound to one purpose at creation ({} keys): one key per binding, each \
             probed with its own mechanisms",
            made.tok.provider.name()
        ),
    );
    let mut ec = GenerateRow::default();
    let mut rsa = profile.generate.remove(&KeyKind::Rsa).unwrap_or_default();
    let mut oaep: Option<Vec<String>> = None;
    for key in std::mem::take(&mut made.bound_keys) {
        let Some((mech, pair)) = keygen_mechanism(key.keygen) else {
            profile.note(key.name.clone(), format!("no generation probe: {} takes parameters", key.keygen));
            continue;
        };
        let generated = if pair {
            session.generate_key_pair(&mech, &[], &key.template).map(|(p, s)| (Some(p), s))
        } else {
            session.generate_key(&mech, &key.template).map(|s| (None, s))
        };
        let (public, private) = match generated {
            Ok(keys) => keys,
            Err(e) => {
                profile.note(key.name.clone(), format!("generation refused: {}", ckr(&e)));
                match (&key.kind, &key.on) {
                    (KeyKind::Ec, On::Item(curve)) if !ec.cannot.contains(curve) => ec.cannot.push(curve.clone()),
                    (KeyKind::Rsa, On::Bits(b)) if !rsa.cannot_bits.contains(b) => rsa.cannot_bits.push(*b),
                    _ => {}
                }
                continue;
            }
        };
        made.scratch.handles.extend(public);
        made.scratch.track(&[private], &key.label);
        match (&key.kind, &key.on) {
            (KeyKind::Ec, On::Item(curve)) if !ec.can.contains(curve) => ec.can.push(curve.clone()),
            (KeyKind::Rsa, On::Bits(b)) if !rsa.can_bits.contains(b) => rsa.can_bits.push(*b),
            _ => {}
        }
        let Some(public) = public else { continue };
        made.bound = Some(key.mechanisms.iter().map(ToString::to_string).collect());
        // ECDSA's host check needs the curve; an RSA key is named by its binding, so the notes
        // of one size's several keys stay apart.
        let on = match (&key.kind, &key.on) {
            (KeyKind::Ec, On::Item(curve)) => curve.clone(),
            _ => key.name.clone(),
        };
        operate(made, profile, &key.kind, &on, public, private);
        made.bound = None;
        // Each OAEP key decrypts with its own hash: the row is what any of them did.
        if let Some(works) = profile.decrypt_oaep.take() {
            let row = oaep.get_or_insert_with(Vec::new);
            for h in works {
                if !row.contains(&h) {
                    row.push(h);
                }
            }
        }
    }
    profile.decrypt_oaep = oaep;
    // A size that generated under one binding and not another can: the refusal stays a note.
    rsa.cannot_bits.retain(|b| !rsa.can_bits.contains(b));
    ec.cannot.retain(|c| !ec.can.contains(c));
    probe_unbound(made, profile, &mut ec, &mut rsa);
    rsa.can_bits.sort_unstable();
    rsa.cannot_bits.sort_unstable();
    profile.generate.insert(KeyKind::Ec, ec);
    profile.generate.insert(KeyKind::Rsa, rsa);
}

/// What no binding covers, tried with the label alone: libkmsp11 answers before any Cloud KMS
/// call (`CKR_TEMPLATE_INCOMPLETE`), so nothing is created; anything that does generate is
/// destroyed with the rest. A module that generates here is not purely purpose-bound, and the
/// bare template names no curve or size, so nobody knows which it made: no row is written for
/// that key type, and the run says so in its undetermined list.
fn probe_unbound(made: &mut Made, profile: &mut Draft, ec: &mut GenerateRow, rsa: &mut GenerateRow) {
    let session = made.session;
    let bare = [Attribute::Label(b"cakeys-probe-unbound".to_vec())];
    // The refusal, or None when the module generated.
    let unbound = |made: &mut Made, mech: &Mechanism, kt: &KeyKind| match session.generate_key_pair(mech, &[], &bare) {
        Ok((public, private)) => {
            made.scratch.handles.extend([private, public]);
            made.undetermined.push(format!(
                "no {kt} row for what no binding covers: generated without a binding, so not purely \
                 purpose-bound, and which curve or size it made is unknown"
            ));
            None
        }
        Err(e) => Some(ckr(&e)),
    };
    if let Some(ec_refusal) = unbound(made, &Mechanism::EccKeyPairGen, &KeyKind::Ec) {
        for name in Curve::ALL.iter().filter(|c| !c.edwards()).map(|c| c.name()) {
            let name = name.to_owned();
            if !ec.can.contains(&name) && !ec.cannot.contains(&name) {
                profile.note(name.clone(), format!("no binding for it; without one: {ec_refusal}"));
                ec.cannot.push(name);
            }
        }
    }
    let edwards: Vec<String> = Curve::ALL.iter().filter(|c| c.edwards()).map(|c| c.name().to_owned()).collect();
    let montgomery: Vec<String> = MONTGOMERY.iter().map(|m| m.0.to_owned()).collect();
    for (kt, mech, names) in [
        (KeyKind::EcEdwards, Mechanism::EccEdwardsKeyPairGen, edwards),
        (KeyKind::EcMontgomery, Mechanism::EccMontgomeryKeyPairGen, montgomery),
    ] {
        let Some(refusal) = unbound(made, &mech, &kt) else { continue };
        for name in &names {
            profile.note(name.clone(), format!("no binding for it; without one: {refusal}"));
        }
        profile.generate.insert(kt, GenerateRow { cannot: names, ..GenerateRow::default() });
    }
    let Some(rsa_refusal) = unbound(made, &Mechanism::RsaPkcsKeyPairGen, &KeyKind::Rsa) else { return };
    for bits in made.rsa_sizes.clone() {
        if !rsa.can_bits.contains(&bits) && !rsa.cannot_bits.contains(&bits) {
            rsa.cannot_bits.push(bits);
            let why = format!("no binding for it; without one: {rsa_refusal}");
            profile.generation_evidence(&KeyKind::Rsa, On::Bits(bits), why);
        }
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
fn probe_curves(made: &mut Made, profile: &mut Draft) -> Result<()> {
    // The curves cakeys has a key type for (core's), Weierstrass or Edwards.
    let forms = |edwards: bool| -> Vec<CurveForm> {
        Curve::ALL
            .iter()
            .filter(|c| c.edwards() == edwards)
            .map(|c| (c.name(), c.params(), c.params_by_name()))
            .collect()
    };
    let families = [
        (KeyKind::Ec, Mechanism::EccKeyPairGen, forms(false)),
        (KeyKind::EcEdwards, Mechanism::EccEdwardsKeyPairGen, forms(true)),
        (KeyKind::EcMontgomery, Mechanism::EccMontgomeryKeyPairGen, MONTGOMERY.to_vec()),
    ];
    for (kt, mech, curves) in families {
        let mut row = GenerateRow::default();
        // A generation mechanism the module does not list is tried all the same: the list is a
        // claim, and the module's answer the row. Where the provider stands in for it (AWS
        // CloudHSM lists no Edwards one, and makes Ed25519 with CKM_EC_KEY_PAIR_GEN [run]) the
        // stand-in is what is tried. Either way it is in `add` if a curve generates.
        let keygen = mech.mechanism_type();
        let listed = made.tok.lists(keygen);
        let stood_in = !listed && made.tok.provider.stand_ins().contains(&keygen);
        if !matches!(kt, KeyKind::EcMontgomery) {
            create_curves(made, profile, &kt, &curves, &mut row)?;
            record_stand_in(profile, stood_in, keygen, made.tok.runnable(mech).mechanism_type(), &row);
            record_unlisted(profile, !listed && !stood_in, keygen, &row);
            profile.generate.insert(kt, row);
            continue;
        }
        // Montgomery keys from here: no keys.toml object, so the probe's own templates.
        let mech = made.tok.runnable(mech);
        let mut probed_ops = false;
        for (curve, oid, name) in curves {
            let mut outcome = None;
            for params in std::iter::once(oid).chain(name) {
                let public = [Attribute::EcParams(params.to_vec()), Attribute::Verify(true), Attribute::Private(false)];
                let private = [Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Sensitive(true)];
                // The usage its operation probes need: deriving.
                let with_usage = [&private[..], &[Attribute::Derive(true)]].concat();
                // A Montgomery public key verifies nothing: no CKA_VERIFY on its usage template.
                let use_public = &public[..1];
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
                            operate(made, profile, &kt, curve, public, private);
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
                    profile.note(curve.to_owned(), format!("generation refused: {}", ckr(&e)));
                }
                None => {}
            }
        }
        record_stand_in(profile, stood_in, keygen, mech.mechanism_type(), &row);
        record_unlisted(profile, !listed && !stood_in, keygen, &row);
        profile.generate.insert(kt, row);
    }
    Ok(())
}

/// A generation mechanism the module does not list, which no provider stands in for: in `add`
/// when a curve generated with it all the same.
fn record_unlisted(profile: &mut Draft, unlisted: bool, keygen: MechanismType, row: &GenerateRow) {
    if unlisted && !row.can.is_empty() {
        profile.out.add.push(keygen.to_string());
        profile.note(keygen.to_string(), "not listed; generates".into());
    }
}

/// Key pairs of a key type cakeys manages (`CKK_EC`, `CKK_EC_EDWARDS`) per curve, generated
/// as the verbs generate them (`Token::create`): `can`, or `cannot` with the refusal as the
/// row's evidence, and `by-name` for a curve the module takes only by name. The first key with
/// its usage gets the operation probes, right away — in a scratch slot the next replaces it.
fn create_curves(
    made: &mut Made,
    profile: &mut Draft,
    kt: &KeyKind,
    curves: &[CurveForm],
    row: &mut GenerateRow,
) -> Result<()> {
    let (key_type, usage) = match kt {
        KeyKind::Ec => (Kt::Ec, spec(&["CKA_SIGN", "CKA_DERIVE"], &[])),
        _ => (Kt::EcEdwards, spec(&["CKA_SIGN"], &[])),
    };
    let mut probed_ops = false;
    for (curve, ..) in curves {
        let object = ObjectCfg {
            curve: Some((*curve).to_owned()),
            ..ObjectCfg::new(cakeys_core::types::ObjectClass::PrivateKey, Some(key_type))
        };
        match made.create_for_use(&object, &usage, &spec(&[], &[]))? {
            (Ok((public, private, note)), usable) => {
                row.can.push((*curve).to_owned());
                if note.as_ref().is_some_and(|n| n.by_name.is_some()) {
                    row.by_name.push((*curve).to_owned());
                }
                // The public CKA_PRIVATE = false default the module refused (AWS CloudHSM).
                if note.as_ref().is_some_and(|n| n.public_made_private) {
                    let said = token::PUBLIC_MADE_PRIVATE.to_owned();
                    made.template_notes.entry("template.public.CKA_PRIVATE".into()).or_insert(said);
                }
                // The first key with its usage gets the operation probes (and its proofs); each
                // later one its proofs.
                if !probed_ops {
                    probed_ops = true;
                    if usable {
                        operate(made, profile, kt, curve, public, private);
                    } else {
                        made.undetermined.push(format!(
                            "no operation probes on {kt} keys: the module refused the usage attributes when \
                             generating on {curve}"
                        ));
                    }
                } else if usable {
                    prove_key(made, profile, kt, curve, public, private);
                }
            }
            (Err(e), _) => {
                row.cannot.push((*curve).to_owned());
                let why = format!("generation refused: {}", refused(made.tok, &e));
                profile.generation_evidence(kt, On::Item((*curve).to_owned()), why);
            }
        }
    }
    Ok(())
}

/// A generation mechanism the module does not list but the provider stands in for (`ran`): in
/// `add` when a curve generated through it, a note either way.
fn record_stand_in(profile: &mut Draft, stood_in: bool, keygen: MechanismType, ran: MechanismType, row: &GenerateRow) {
    if !stood_in {
        return;
    }
    if row.can.is_empty() {
        profile.note(keygen.to_string(), "not listed; the provider's stand-in generates nothing".into());
    } else {
        profile.out.add.push(keygen.to_string());
        profile.note(keygen.to_string(), format!("not listed; generates through the provider's stand-in, {ran}"));
    }
}

/// Key pairs per RSA size ([`RSA_SIZES`] up to the request's largest, whatever the module
/// reports): `can-bits` and `cannot-bits` beside the range it reports, and each size's proofs
/// of possession. The 2048-bit pair gets the operation probes, and on a scratch token it is the
/// wrap probes' transport key: wrapping is encryption, so its public half wraps and its private
/// half unwraps. In a scratch slot the next size replaces it, so there it is no transport key.
fn probe_rsa(made: &mut Made, profile: &mut Draft) -> Result<Option<(ObjectHandle, ObjectHandle)>> {
    let mut row = profile.generate.remove(&KeyKind::Rsa).unwrap_or_default();
    let mut transport = None;
    for bits in made.rsa_sizes.clone() {
        // Generated as the verbs generate it, with every usage the proofs, the operation and
        // the wrap probes need, each attribute on the half the spec defines it for, since their
        // defaults are the module's choice. A module refusing them gets the bare spec.
        let object = ObjectCfg {
            modulus_bits: Some(bits.into()),
            ..ObjectCfg::new(cakeys_core::types::ObjectClass::PrivateKey, Some(Kt::Rsa))
        };
        let usage = spec(&["CKA_DECRYPT", "CKA_UNWRAP", "CKA_SIGN"], &["CKA_ENCRYPT", "CKA_WRAP", "CKA_VERIFY"]);
        let on = format!("RSA-{bits}");
        match made.create_for_use(&object, &usage, &spec(&[], &[]))? {
            (Ok((public, private, _)), usable) => {
                match (bits == 2048, usable) {
                    (true, true) => operate(made, profile, &KeyKind::Rsa, &on, public, private),
                    (false, true) => prove_key(made, profile, &KeyKind::Rsa, &on, public, private),
                    (_, false) => made.undetermined.push(format!(
                        "no operation probes or proofs on {on}: the module refused the usage attributes"
                    )),
                }
                if bits == 2048 && matches!(made.scratch.target, Target::Labels) {
                    transport = Some((public, private));
                }
                row.can_bits.push(bits);
            }
            (Err(e), _) => {
                row.cannot_bits.push(bits);
                let why = format!("modulusBits = {bits}: {}", refused(made.tok, &e));
                profile.generation_evidence(&KeyKind::Rsa, On::Bits(bits), why);
            }
        }
    }
    profile.generate.insert(KeyKind::Rsa, row);
    Ok(transport)
}

/// The operation probes on one fresh key pair of kind `kt`: every advertised mechanism that
/// applies to it, verified on the host wherever cakeys can (`sig`, `pop`) — signing, ECDH
/// derivation and decryption.
fn operate(made: &mut Made, profile: &mut Draft, kt: &KeyKind, on: &str, public: ObjectHandle, private: ObjectHandle) {
    if matches!(kt, KeyKind::EcMontgomery) {
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
    // First, as the verbs prove right after generating: a module that leaves an operation
    // active after a failed one (tpm2-pkcs11, on a hash the TPM lacks [run]) would otherwise
    // refuse the proof's own C_*Init with CKR_OPERATION_ACTIVE.
    prove(made, profile, kt, on, private, &spki);
    match kt {
        KeyKind::Ec => {
            let curve = Curve::from_cfg(Kt::Ec, on);
            ec_ops(made, private, &spki, on, curve.and_then(HashAlg::for_curve));
            if made.tries(MechanismType::ECDH1_DERIVE) {
                derive(made, profile, private, &spki, on);
            }
        }
        KeyKind::EcEdwards => {
            let pure = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
            let listed = made.advertises(MechanismType::EDDSA);
            if !listed && made.tok.provider.stand_ins().contains(&MechanismType::EDDSA) {
                // Not listed, but the provider signs pure EdDSA its own way (AWS CloudHSM's
                // vendor mechanism [run]): `add` when the host verifies what it signs.
                let mech = made.tok.runnable(pure);
                let vendor = *mech.mechanism_type();
                let name = MechanismType::EDDSA.to_string();
                match sign(made.session, &mech, private, MSG, |s| sig::ed25519(&spki, MSG, s)) {
                    Ok(()) => {
                        profile.out.add.push(name.clone());
                        profile.note(name, format!("not listed; signs through the provider's stand-in, {vendor:#x}"));
                    }
                    Err(e) => {
                        profile.note(name, format!("not listed; the provider's stand-in ({vendor:#x}) on {on}: {e}"));
                    }
                }
            } else if made.tries(MechanismType::EDDSA) {
                let outcome = sign(made.session, &pure, private, MSG, |s| sig::ed25519(&spki, MSG, s));
                made.record(MechanismType::EDDSA, on, outcome);
            }
        }
        KeyKind::Rsa => rsa_ops(made, profile, private, &spki, on),
        _ => made.undetermined.push(format!("no operation probes on {on}: none are written for {kt} keys")),
    }
}

/// [`prove`] on a key pair the operation probes do not take: its public half's SPKI first.
fn prove_key(
    made: &mut Made,
    profile: &mut Draft,
    kt: &KeyKind,
    on: &str,
    public: ObjectHandle,
    private: ObjectHandle,
) {
    match made.tok.material_spki(public) {
        Ok(Some(spki)) => prove(made, profile, kt, on, private, &spki),
        Ok(None) => made.undetermined.push(format!("no proofs on {on}: its public key carries no material")),
        Err(e) => made.undetermined.push(format!("no proofs on {on}: {e}")),
    }
}

/// The proofs of possession the verbs give with a private key of `kt` on `on`
/// (`Token::prove_binding`, their own code), each a `prove.*` row with the refusal as its
/// evidence. The probe's token has no module profile, so each proof tries what it can. A proof
/// refused because an earlier operation left the session busy says nothing of the key:
/// undetermined, never a row (tpm2-pkcs11 leaves a failed one active \[run\]).
fn prove(made: &mut Made, profile: &mut Draft, kt: &KeyKind, on: &str, private: ObjectHandle, spki: &[u8]) {
    let (key_type, bindings): (Kt, &[Binding]) = match kt {
        KeyKind::Ec => (Kt::Ec, &[Binding::PopSign, Binding::PopEcdh]),
        KeyKind::EcEdwards => (Kt::EcEdwards, &[Binding::PopSign]),
        KeyKind::Rsa => (Kt::Rsa, &[Binding::PopSign, Binding::PopDecrypt, Binding::PopUnwrap]),
        _ => return,
    };
    let mut object = ObjectCfg::new(cakeys_core::types::ObjectClass::PrivateKey, Some(key_type));
    let size = on.strip_prefix("RSA-").and_then(|b| b.parse::<u32>().ok());
    // A purpose-bound RSA key is named by its binding (several share a size, each proving
    // differently): the row keeps that name, the proof takes the size the key reports.
    match (key_type, size) {
        (_, Some(bits)) => object.modulus_bits = Some(bits.into()),
        (Kt::Rsa, None) => {
            if let Ok([Attribute::Modulus(n)]) =
                made.session.get_attributes(private, &[AttributeType::Modulus]).as_deref()
            {
                object.modulus_bits = u32::try_from(n.len() * 8).ok().map(Into::into);
            }
        }
        (_, None) => object.curve = Some(on.to_owned()),
    }
    let on = size.map_or_else(|| On::Item(on.to_owned()), On::Bits);
    for binding in bindings {
        let outcome = made.tok.prove_binding(private, &object, spki, *binding);
        let cap = Capability::Prove { binding: binding.name().into(), key_type: kt.clone(), on: on.clone() };
        match outcome {
            Err(e) if token::rv_is(e.rv(), RvError::OperationActive) => {
                made.undetermined.push(format!("no {cap} row: {}", evidence(made.tok, &e)));
            }
            outcome => {
                profile.set(cap, Answer::of(outcome.is_ok()), outcome.err().map(|e| evidence(made.tok, &e)), None);
            }
        }
    }
}

/// A refusal as a row's evidence, the same under any keys.toml and any binding: the token's
/// keys.toml name taken out, and the binding's prose for a `C_*` failure (it changes with the
/// binding) cut at the function that failed.
fn evidence(tok: &Token, e: &KmError) -> String {
    let said = e
        .to_string()
        .replace(&format!(" on token '{}'", tok.name), "")
        .replace(&format!("token '{}': ", tok.name), "")
        .replace(&format!("token '{}'", tok.name), "the token")
        .replace(&format!("'{}'", tok.name), "the token");
    // Cryptoki's prose runs from its marker to the end of the parenthesis it sits in, if any
    // (its own parentheses aside).
    let Some((before, prose)) = said.split_once(": PKCS11 error:") else {
        return said;
    };
    let open = before.matches('(').count() > before.matches(')').count();
    let mut depth = 0usize;
    let close = prose.char_indices().find_map(|(i, c)| match c {
        '(' => {
            depth += 1;
            None
        }
        ')' if depth == 0 => Some(i),
        ')' => {
            depth -= 1;
            None
        }
        _ => None,
    });
    match close.filter(|_| open) {
        Some(i) => format!("{before}{}", &prose[i..]),
        None => before.to_owned(),
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
) -> std::result::Result<(), Msg> {
    let signature = s.sign(mech, key, data).map_err(|e| ck_refusal(&e))?;
    match check(&signature) {
        Some(Err(e)) => Err(format!("the signature does not verify ({e})").into()),
        _ => Ok(()),
    }
}

/// ECDSA, raw and with each hash the module advertises; verified for the hashes `sig` has.
fn ec_ops(made: &mut Made, private: ObjectHandle, spki: &[u8], on: &str, hash: Option<HashAlg>) {
    let verify = |h: Option<HashAlg>| move |s: &[u8]| h.and_then(|h| sig::ecdsa(spki, MSG, s, Encoding::Raw, Some(h)));
    // Raw ECDSA signs the curve's digest of the message.
    let digest = hash.map_or_else(|| Sha256::digest(MSG).to_vec(), |h| h.digest(MSG));
    let raw = (Mechanism::Ecdsa, digest, hash.or(Some(HashAlg::Sha256)));
    let hashed = [
        (Mechanism::EcdsaSha1, MSG.to_vec(), None),
        (Mechanism::EcdsaSha224, MSG.to_vec(), None),
        (Mechanism::EcdsaSha256, MSG.to_vec(), Some(HashAlg::Sha256)),
        (Mechanism::EcdsaSha384, MSG.to_vec(), Some(HashAlg::Sha384)),
        (Mechanism::EcdsaSha512, MSG.to_vec(), Some(HashAlg::Sha512)),
    ];
    for (mech, data, h) in std::iter::once(raw).chain(hashed) {
        let mt = mech.mechanism_type();
        if made.tries(mt) {
            let outcome = sign(made.session, &mech, private, &data, verify(h));
            made.record(mt, on, outcome);
        }
    }
}

/// `CKM_ECDH1_DERIVE` against a host ephemeral key, as `pop-ecdh` does it: into a sealed
/// secret first, authenticated by an HMAC when the module has one; else into an extractable secret, read and
/// compared. `derive.sealed` records which, a refused sealed derivation the note.
fn derive(made: &mut Made, profile: &mut Draft, private: ObjectHandle, spki: &[u8], on: &str) {
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
    let destroy = |h, path: &str, profile: &mut Draft| {
        if let Err(e) = s.destroy_object(h) {
            profile.note(
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
            let reported = reads.iter().map(show).collect::<Vec<_>>().join(", ");
            let is_sealed =
                reads.contains(&Attribute::Sensitive(true)) && reads.contains(&Attribute::Extractable(false));
            if !is_sealed {
                profile.note("derive.secret".into(), format!("{on}: the derived secret reports {reported}"));
            }
            let mac = made.advertises(MechanismType::SHA256_HMAC).then(|| s.sign(&Mechanism::Sha256Hmac, h, MSG));
            // With no HMAC to MAC with, the secret itself says whether it is sealed: a template
            // that took only without its sealing attributes made an extractable one (ykcs11).
            let mac = match mac {
                None if !is_sealed => Some(Err(None)),
                other => other.map(|m| m.map_err(Some)),
            };
            destroy(h, "sealed", profile);
            if let Some((changed, first)) = changed {
                profile.note(
                    "derive.template".into(),
                    format!("{on}: the template as asked is refused ({}); derived with {changed}", ckr(&first)),
                );
            }
            sealed = used;
            match mac {
                None => Ok(Ok(())),
                Some(Ok(tag)) if pop::ct_eq(&ch.mac, &tag) => Ok(Ok(())),
                Some(Ok(_)) => Ok(Err(Msg::from("the derived secret is not the shared secret"))),
                Some(Err(Some(e))) => Err(ck_said("derives into a sealed secret, but HMAC with it fails", &e)),
                Some(Err(None)) => {
                    Err(format!("derives only into a secret that is not sealed: it reports {reported}").into())
                }
            }
        }
        Err(e) => Err(ck_said("a sealed (non-extractable) derived secret is refused", &e)),
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
                    profile.note(
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
                        profile.note("derive.sealed".into(), why.into_text());
                        Ok(())
                    }
                    Some(Attribute::Value(_)) => Err(Msg::from("the derived secret is not the shared secret")),
                    _ => Err(Msg::from(format!("{why}; the extractable derived secret's CKA_VALUE is unreadable"))
                        .with_rv(why.rv())),
                }
            }
            Err(e) => Err(Msg::from(format!("{why}; extractable: {}", ckr(&e))).with_rv(token::rv_of(&e).or(why.rv()))),
        },
    };
    if outcome.is_ok() {
        let template = if profile.derive.sealed == Some(true) { &sealed } else { &open };
        derived_once(made, profile, &mech, private, template, on);
    }
    made.record(MechanismType::ECDH1_DERIVE, on, outcome);
}

/// After a derivation took with `template`: whether it derives the same way in a read-only
/// session, where the read-only verbs prove possession (`verify`, `check`), and what the key
/// that derived says of itself (a spec asking `CKA_DERIVE = true` is checked against this, not
/// against what the key does).
fn derived_once(
    made: &mut Made,
    profile: &mut Draft,
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
            profile.note("derive.read-only".into(), format!("{on}: in a read-only session: {}", ckr(&e)));
        }
        Err(e) => made.undetermined.push(format!("no read-only ECDH probe on {on}: {e}")),
    }
    if let Ok(attrs) = made.session.get_attributes(private, &[AttributeType::Derive])
        && let Some(Attribute::Derive(false)) = attrs.into_iter().next()
    {
        profile
            .note("derive.key-attribute".into(), format!("{on}: derives although the key reports CKA_DERIVE = false"));
    }
}

/// RSA signing (PKCS#1 v1.5 raw and hashed, PSS raw and hashed, raw X.509) and decryption
/// (PKCS#1 v1.5, OAEP per hash: `decrypt.oaep`), on a 2048-bit key.
fn rsa_ops(made: &mut Made, profile: &mut Draft, private: ObjectHandle, spki: &[u8], on: &str) {
    let pkcs1 = |s: &[u8]| sig::rsa_pkcs1v15::<Sha256>(spki, MSG, s);
    let none = |_: &[u8]| None;
    let pss = |hash, mgf, len: usize| PkcsPssParams { hash_alg: hash, mgf, s_len: (len as u64).into() };
    // What raw `CKM_RSA_PKCS` signs: the digest behind its `DigestInfo` prefix.
    let digest_info = [token::digest_info(HashAlg::Sha256), Sha256::digest(MSG).as_slice()].concat();
    // Raw RSA signs one block the modulus' size, the key's whatever it is (an existing key
    // under the probes may be larger than the 2048 bits generated); a leading zero keeps it
    // below the modulus.
    let block = pop::rsa_modulus_len(spki).map(|n| [vec![0u8], vec![0x5a; n.saturating_sub(1)]].concat());
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
        if made.tries(mt) {
            let outcome = if verified {
                sign(made.session, &mech, private, &data, pkcs1)
            } else {
                sign(made.session, &mech, private, &data, none)
            };
            made.record(mt, on, outcome);
        }
    }
    if made.tries(MechanismType::RSA_X_509) {
        let outcome = match &block {
            Ok(block) => sign(made.session, &Mechanism::RsaX509, private, block, none),
            Err(e) => Err(e.to_string().into()),
        };
        made.record(MechanismType::RSA_X_509, on, outcome);
    }
    // Decryption: the host encrypts a fresh secret to the key, the token must recover it.
    let decrypts = |made: &mut Made, mech: &Mechanism, padding| -> std::result::Result<(), Msg> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| e.to_string())?;
        let cipher = pop::rsa_encrypt(spki, padding, &secret).map_err(|e| e.to_string())?;
        let plain = made.session.decrypt(mech, private, &cipher).map_err(|e| ck_refusal(&e))?;
        if pop::ct_eq(&secret, &plain) { Ok(()) } else { Err("decrypts to something else".into()) }
    };
    if made.tries(MechanismType::RSA_PKCS) {
        let outcome = decrypts(made, &Mechanism::RsaPkcs, RsaPadding::Pkcs1v15);
        made.record(MechanismType::RSA_PKCS, &format!("{on} decrypt"), outcome);
    }
    if made.tries(MechanismType::RSA_PKCS_OAEP) {
        let mut works = Vec::new();
        // The hashes a decryption proof tries (`token::OAEP`), each on its own.
        for padding in token::OAEP {
            let Some((params, name)) = token::oaep_params(padding) else { continue };
            let outcome = decrypts(made, &Mechanism::RsaPkcsOaep(params), padding);
            if outcome.is_ok() {
                works.push(name.to_owned());
            }
            made.record(MechanismType::RSA_PKCS_OAEP, &format!("{on} decrypt {name}"), outcome);
        }
        // Probed: `[]` when no hash decrypts, distinct from never probed.
        profile.decrypt_oaep = Some(works);
    }
}

/// The secret-key generation the module advertises: success is implied by the advertise list,
/// a refusal is a `subtract` row (advertised but broken). Returns the first AES key, the wrap
/// probes' wrapped key.
fn probe_secrets(made: &mut Made, profile: &mut Draft) -> Option<ObjectHandle> {
    let session = made.session;
    let mut aes = None;
    for (mech, name, key_type, kt) in [
        (Mechanism::AesKeyGen, "CKM_AES_KEY_GEN", KeyType::AES, Kt::Aes),
        (Mechanism::GenericSecretKeyGen, "CKM_GENERIC_SECRET_KEY_GEN", KeyType::GENERIC_SECRET, Kt::GenericSecret),
    ] {
        let name = name.to_owned();
        if !made.tok.lists(mech.mechanism_type()) {
            continue;
        }
        let label = made.scratch.label();
        let template = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(key_type),
            Attribute::ValueLen(32.into()),
            Attribute::Extractable(true),
        ];
        let template = match secret_template(made.tok, kt, &label, template) {
            Ok(t) => t,
            Err(e) => {
                // The provider's refusal, not the module's: nothing to subtract.
                made.undetermined.push(format!("no {name} probe: its template: {}", refused(made.tok, &e)));
                continue;
            }
        };
        match session.generate_key(&mech, &template) {
            Ok(h) => {
                if key_type == KeyType::AES && aes.is_none() {
                    aes = Some(h);
                }
                made.scratch.track(&[h], &label);
            }
            Err(e) => {
                profile.out.subtract.mechanisms.push(name.clone());
                profile.note(name, format!("advertised but generation fails: {}", ckr(&e)));
            }
        }
    }
    aes
}

/// `template`, the probe's generation of a 32-byte `key_type` secret key under `label`, as the
/// provider adjusts a generation's (`Provider::template`): declared as keys.toml would declare
/// such a key, so the probe measures what the verbs would send.
///
/// # Errors
///
/// The provider's refusal.
fn secret_template(tok: &Token, key_type: Kt, label: &str, template: Vec<Attribute>) -> Result<Vec<Attribute>> {
    let object = ObjectCfg { value_len: Some(32u32.into()), ..ObjectCfg::new(Class::SecretKey, Some(key_type)) };
    let locator = Locator { label: Some(label.to_owned()), id: None };
    let declared = Declared { object: &object, spec: &spec(&[], &[]), locator: &locator };
    tok.provider.adjusted(&Template::Generate(declared, Half::Key), template)
}

/// The OAEP hashes the module actually implements — wrap the fresh AES key to the fresh RSA
/// transport key (public half) and unwrap it back with the private half, only a round trip
/// counts — and the unwrap-template rule: a template carrying `CKA_VALUE_LEN`, refused with
/// `CKR_ATTRIBUTE_READ_ONLY` by `SoftHSM`.
fn probe_wrapping(made: &mut Made, profile: &mut Draft, transport: (ObjectHandle, ObjectHandle), aes: ObjectHandle) {
    let session = made.session;
    let (wraps, unwraps) = transport;
    // MGF1 of the same hash: the parameter sets a transport wrap uses (`OaepHash`).
    let oaep_of = |hash| {
        let (params, name) = token::oaep_of(hash);
        (Mechanism::RsaPkcsOaep(params), name)
    };
    let mut round_trips = Vec::new();
    let mut failures = Vec::new();
    for hash in [OaepHash::Sha1, OaepHash::Sha256] {
        let (mech, name) = oaep_of(hash);
        // Wrapping is encryption: the public half wraps, the private half unwraps.
        let wrapped = match session.wrap_key(&mech, wraps, aes) {
            Ok(w) => w,
            Err(e) => {
                failures.push(format!("{name}: wrapping fails: {}", ckr(&e)));
                continue;
            }
        };
        let label = made.scratch.label();
        let template = [
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
        ];
        match session.unwrap_key(&mech, unwraps, &wrapped, &template) {
            Ok(h) => {
                round_trips.push((name, hash));
                made.scratch.track(&[h], &label);
            }
            Err(e) => failures.push(format!("{name}: wraps but does not unwrap: {}", ckr(&e))),
        }
    }
    // One note under "oaep": what `--oaep` verdicts cite.
    if !failures.is_empty() {
        profile.note("oaep".into(), failures.join("; "));
    }
    // Probed: `[]` when no hash round-trips, distinct from never probed.
    profile.wrap_oaep = Some(round_trips.iter().map(|(name, ..)| (*name).to_owned()).collect());
    // The unwrap-template rule, with the first hash that round-trips; unprobed without one.
    let Some((mech, _)) = round_trips.first().map(|(_, hash)| oaep_of(*hash)) else {
        return;
    };
    let Ok(wrapped) = session.wrap_key(&mech, wraps, aes) else {
        return;
    };
    let label = made.scratch.label();
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
            profile.unwrap_refused = Some(Vec::new());
            made.scratch.track(&[h], &label);
        }
        Err(CkError::Pkcs11(RvError::AttributeReadOnly, _)) => {
            profile.unwrap_refused = Some(vec!["CKA_VALUE_LEN".into()]);
            profile.note("CKA_VALUE_LEN".into(), "CKR_ATTRIBUTE_READ_ONLY in an unwrap template".into());
        }
        // Neither accepted nor the refusal the rule names: the row stays unprobed.
        Err(e) => {
            profile.note("unwrap-template".into(), format!("CKA_VALUE_LEN: {}", ckr(&e)));
        }
    }
}

/// The key wraps the module advertises, each round-tripped: the AES key wrapped and unwrapped
/// back, under a fresh AES key-encryption key (`CKM_AES_KEY_WRAP`, `_PAD`, and `_KWP` where this
/// build names it) or under the RSA transport key (`CKM_RSA_AES_KEY_WRAP`, either OAEP hash). A
/// mechanism the module refuses as such (`CKR_MECHANISM_INVALID`, `CKR_FUNCTION_NOT_SUPPORTED`)
/// is a `subtract` row: AWS `CloudHSM` lists `CKM_AES_KEY_WRAP` and `_PAD` with
/// `CKF_WRAP | CKF_UNWRAP` and refuses both \[run\]. Any other refusal is a note, never a
/// subtraction: it may be the probe's template or key, not the mechanism.
fn probe_key_wraps(made: &mut Made, profile: &mut Draft, transport: (ObjectHandle, ObjectHandle), aes: ObjectHandle) {
    let session = made.session;
    let label = made.scratch.label();
    let template = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Wrap(true),
        Attribute::Unwrap(true),
    ];
    let kek = secret_template(made.tok, Kt::Aes, &label, template)
        .map_err(|e| refused(made.tok, &e))
        .and_then(|t| session.generate_key(&Mechanism::AesKeyGen, &t).map_err(|e| ckr(&e)));
    let kek = match kek {
        Ok(h) => {
            made.scratch.track(&[h], &label);
            Some(h)
        }
        Err(e) => {
            made.undetermined.push(format!("no AES key wrap probes: a wrapping AES key: {e}"));
            None
        }
    };
    // Each wrap's variants (CKM_RSA_AES_KEY_WRAP's by OAEP hash), its wrapping and unwrapping key.
    let mut wraps: Vec<(&str, Vec<KeyWrap>, ObjectHandle, ObjectHandle)> = Vec::new();
    if let Some(kek) = kek {
        wraps.push(("CKM_AES_KEY_WRAP", vec![KeyWrap::Aes(Mechanism::AesKeyWrap)], kek, kek));
        wraps.push(("CKM_AES_KEY_WRAP_PAD", vec![KeyWrap::Aes(Mechanism::AesKeyWrapPad)], kek, kek));
        #[cfg(feature = "kwp")]
        wraps.push(("CKM_AES_KEY_WRAP_KWP", vec![KeyWrap::Aes(Mechanism::AesKeyWrapKwp)], kek, kek));
    }
    if cfg!(feature = "kwp") {
        let hashes = [
            KeyWrap::RsaAes(MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
            KeyWrap::RsaAes(MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
        ];
        wraps.push(("CKM_RSA_AES_KEY_WRAP", hashes.into(), transport.0, transport.1));
    }
    for (name, variants, wraps_with, unwraps_with) in wraps {
        if !made.tok.advertised().iter().any(|a| a == name) {
            continue;
        }
        let mut refusals = Vec::new();
        let mut round_trip = false;
        for variant in variants {
            let oaep;
            let mech = match variant {
                KeyWrap::Aes(m) => m,
                KeyWrap::RsaAes(hash, mgf) => {
                    oaep = PkcsOaepParams::new(hash, mgf, PkcsOaepSource::empty());
                    match rsa_aes_key_wrap(&oaep) {
                        Some(m) => m,
                        None => continue,
                    }
                }
            };
            let mech = &mech;
            let wrapped = match session.wrap_key(mech, wraps_with, aes) {
                Ok(w) => w,
                Err(e) => {
                    refusals.push(("C_WrapKey", e));
                    continue;
                }
            };
            let label = made.scratch.label();
            let template = [
                Attribute::Token(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
            ];
            match session.unwrap_key(mech, unwraps_with, &wrapped, &template) {
                Ok(h) => {
                    made.scratch.track(&[h], &label);
                    round_trip = true;
                }
                Err(e) => refusals.push(("C_UnwrapKey", e)),
            }
        }
        if round_trip {
            continue;
        }
        let refused_as_such = refusals
            .iter()
            .any(|(_, e)| matches!(e, CkError::Pkcs11(RvError::MechanismInvalid | RvError::FunctionNotSupported, _)));
        let what: Vec<String> = refusals.iter().map(|(f, e)| format!("{f}: {}", ckr(e))).collect();
        if refused_as_such {
            profile.out.subtract.mechanisms.push(name.to_owned());
            profile.note(name.to_owned(), format!("advertised but refused: {}", what.join("; ")));
        } else {
            profile.note(name.to_owned(), format!("no round trip, not a mechanism refusal: {}", what.join("; ")));
        }
    }
    profile.out.subtract.mechanisms.sort();
    profile.out.subtract.mechanisms.dedup();
}

/// One key wrap [`probe_key_wraps`] tries: an AES key wrap, or `CKM_RSA_AES_KEY_WRAP` with
/// RSA-OAEP of this hash (MGF1 of the same).
enum KeyWrap {
    Aes(Mechanism<'static>),
    RsaAes(MechanismType, PkcsMgfType),
}

/// `CKM_RSA_AES_KEY_WRAP` with an AES-256 key and `oaep`: only the patched cryptoki names it
/// (the `kwp` feature).
#[cfg(feature = "kwp")]
#[allow(clippy::unnecessary_wraps, reason = "the unpatched build's twin has nothing to return")]
fn rsa_aes_key_wrap<'a>(oaep: &'a PkcsOaepParams<'a>) -> Option<Mechanism<'a>> {
    Some(Mechanism::RsaAesKeyWrap(cryptoki::mechanism::rsa::RsaAesKeyWrapParams::new(256.into(), oaep)))
}

#[cfg(not(feature = "kwp"))]
fn rsa_aes_key_wrap<'a>(_: &'a PkcsOaepParams<'a>) -> Option<Mechanism<'a>> {
    None
}

/// What the `probe` verb asks beyond the probing itself.
pub(crate) struct Request<'a> {
    /// Also run the write probes ([`probe`]).
    pub write: bool,
    /// Name the generated profile; default: `claimed`'s name, else `<provider>/<version>`.
    pub name: Option<&'a str>,
    /// The committed profile the result is diffed against, if any.
    pub claimed: Option<&'a Profile>,
    /// The result is written to a file or judged against `claimed`, not only printed.
    pub kept: bool,
    /// The largest of [`RSA_SIZES`] the write probes generate.
    pub rsa_max_bits: u32,
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
pub(crate) fn generate(
    tok: &Token,
    cfg: &TokenCfg,
    req: &Request,
    notes: &mut cakeys_pkcs11::ops::Notes,
) -> Result<Profile> {
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
    let mut probed = probe(tok, cfg, req.write.then_some(req.rsa_max_bits))?;
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
pub(crate) fn drift(generated: &Profile, claimed: &Profile, write: bool) -> Vec<String> {
    if write { crate::diff::diff(generated, claimed) } else { crate::diff::read_only(generated, claimed) }
}

/// Keep, in a generated `profile` about to replace the file with content `existing` (named
/// `shown` in messages), what the probe does not generate: the file's `[migration]` and
/// `move.*` claims (docs/CAMIGRATE.md evidence, never probe-observable) and its `[manual]`
/// findings (made by hand, each with its evidence).
///
/// # Errors
///
/// `Validation` (17) for a file that does not parse (regenerating it would silently drop
/// those sections), and for any existing file from a read-only probe (it would drop every
/// write-probe row).
pub(crate) fn keep_claims(profile: &mut Profile, existing: &str, shown: &str, write: bool) -> Result<()> {
    if !write {
        return Err(KmError::Validation(
            format!("{shown}: a read-only probe would overwrite its generate, wrap and unwrap rows; pass --write")
                .into(),
        ));
    }
    let old = Profile::from_toml(existing)
        .map_err(|e| KmError::Validation(format!("{shown}: not a profile, refusing to overwrite: {e}").into()))?;
    profile.migration = old.migration;
    profile.manual = old.manual;
    profile.capabilities.extend(old.capabilities.into_iter().filter(|(c, _)| !c.probed()));
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
        let mut profile = Draft::new(Profile::from_toml("profile = \"t\"\nmode = \"observed\"\n").unwrap());
        ops.finish(&mut profile);
        assert_eq!(profile.out.subtract.mechanisms, ["CKM_ECDSA_SHA1"]);
        assert_eq!(profile.out.notes["CKM_ECDSA_SHA1"], "secp256r1: CKR_MECHANISM_INVALID");
        // Worked with one hash: usable, the other hash's failure a note only.
        assert_eq!(profile.out.notes["CKM_RSA_PKCS_OAEP"], "RSA-2048 decrypt SHA-256: CKR_ARGUMENTS_BAD");
        assert!(!profile.out.notes.contains_key("CKM_ECDSA"));
    }
}
