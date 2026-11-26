//! The profile compiler (docs/CAPROBE.md). The read-only probes record what a module reports
//! through PKCS#11. The write probes establish what the module actually does, and they run only
//! on a token that keys.toml marks `scratch`, or in the one slot that keys.toml names with
//! `scratchId`. The output is a profile in the committed format, which can be compared with what
//! a shipped profile claims (`cakeys_profile::diff`). That comparison is the conformance check,
//! and the comparison of a probe of a new module build with the old profile is the drift check.
//!
//! A probe records observations and never explanations (a firm rule of the analysis). A failure
//! becomes a `cannot` row or a `subtract` row whose note holds the failed `C_*` call. What the
//! probe cannot reach is listed in [`Probed::undetermined`] and never guessed.
//!
//! When the probe does what a verb does, it uses the provider's templates (`Provider::template`):
//! it generates keys through `Token::create`, and [`moves`] runs the imports, the creations and
//! the sealed round trips. The templates that this file builds itself vary the request to the
//! module in order to measure the module (a bare key pair, a derive without a default, the keys
//! of a wrap probe), and the probe sends them without the provider's adjustment.

use cakeys_core::config::{AttrValue, Binding, Locator, Object, ObjectCfg, SpecCfg, TokenCfg};
use cakeys_core::id::Curve;
use cakeys_core::migrate::OaepHash;
use cakeys_core::pop::{self, RsaPadding};
use cakeys_core::sig::{self, Encoding, HashAlg};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Msg, Result};
use cakeys_pkcs11::token::{self, Token, derive_any, is_policy_default, show, template_refusal, unpadded};
use cakeys_pkcs11::{BoundKey, Declared, Half, Template, keygen_mechanism};
use cakeys_profile::capability::{DECRYPT_OAEP, UNWRAP_TEMPLATE};
use cakeys_profile::{Answer, By, Capability, GenerateRow, KeyKind, MatchInfo, Mode, On, Profile, Row, Untested, Why};
use cryptoki::error::{Error as CkError, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource, PkcsPssParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use std::collections::{BTreeMap, BTreeSet};

mod asymmetric;
mod bound;
mod checked;
mod extras;
mod moves;
mod scratch;
mod secrets;
mod wraps;

pub(crate) use asymmetric::RSA_SIZES;
use asymmetric::{montgomery, operate, probe_curves, probe_rsa};
use bound::probe_bound;
use checked::Checked;
use scratch::{Scratch, write_probes};
use wraps::{probe_key_wraps, probe_wrapping, rsa_aes_key_wrap};

/// Returns the name of a generated profile when neither `--name` nor `--diff` gives one:
/// `<provider>/<version>`, with the version cleaned by [`unpadded`] in the same way as the match
/// key's version.
fn default_name(provider: &str, version: &str) -> String {
    format!("{provider}/{}", unpadded(version))
}

/// Returns the `CKR_*` name of a failure, for notes. cryptoki's `Display` prints the
/// specification's prose, which changes with the binding and would make a regenerated profile
/// differ when the module's behavior did not change. The function uses the verbs' own naming
/// (`token::rv_name`), so a note and a refusal spell the name in the same way.
fn ckr(e: &CkError) -> String {
    token::rv_name(e)
}

/// Converts a failed module call into an operation's outcome: a message with the `CKR_*` name
/// ([`ckr`]), and the return value, which code matches on.
fn ck_refusal(e: &CkError) -> Msg {
    Msg::from(ckr(e)).with_rv(token::rv_of(e))
}

/// Like [`ck_refusal`], but the message starts with `what`, the step that failed.
fn ck_said(what: &str, e: &CkError) -> Msg {
    Msg::from(format!("{what}: {}", ckr(e))).with_rv(token::rv_of(e))
}

/// Returns whether `e` is a failed SO login (`Token::as_so`). Such a failure stops the probe and
/// never becomes a row.
fn so_login(e: &KmError) -> bool {
    matches!(e, KmError::Unavailable(m) if m.contains(token::SO_LOGIN))
}

/// What a probe found: the generated profile, and what it could not decide.
pub(crate) struct Probed {
    /// The observed capability profile of the module on this token's hardware, in the
    /// committed format. The probe measures the module and the hardware together, because
    /// PKCS#11 does not show whether the module or the hardware refused. Separating the two is a
    /// manual step.
    pub profile: Profile,
    /// The reasons why rows that the probe wanted to write are missing: facts that the probe
    /// does not reach yet, or that it could not reach on this token.
    pub undetermined: Vec<String>,
}

/// Where the write probes put what they generate.
enum Target {
    /// Objects under `cakeys-probe-NN` labels on a token that keys.toml marks `scratch`. Every
    /// run destroys what it made, and the leftover check records whether `C_DestroyObject`
    /// really removed the objects.
    Labels,
    /// The one slot that `scratchId` names, on a token whose module generates keys only as
    /// Security Officer, into device slots that it selects by `CKA_ID` (ykcs11). Each generation
    /// replaces the slot's key in an SO session. The probe destroys nothing, because PIV cannot
    /// erase a key, so the last key generated stays in the slot.
    Slot(Vec<u8>),
}

/// Probes `tok`. The read-only probes always run. When `write` is set, the write probes also run
/// (generating, operating, wrapping, unwrapping and deleting), with RSA sizes up to `write`
/// bits. The write probes run only on a token that keys.toml marks `scratch` or, for a module
/// that creates keys only as SO into device slots, in the one slot that `scratchId` names.
/// Anywhere else the probe refuses them with exit 17, and it never skips them silently.
///
/// # Errors
///
/// Returns `Validation` (exit 17) when `write` is set and the token is not marked scratch, or
/// has no PIN, or its provider creates keys only as Security Officer and no `scratchId` (with an
/// admin credential) names a slot that is empty or holds the probe's own mark certificate
/// ([`check_slot`]). The scratch guard is the only condition that the probe refuses instead of
/// recording. Returns `Unavailable` when an SO login fails.
pub(crate) fn probe(tok: &Token, cfg: &TokenCfg, write: Option<u32>) -> Result<Probed> {
    let advertised = tok.advertised();
    let profile = Profile {
        // The profile records every match key: the module and the hardware that it ran on. It
        // records no serial number, because the serial number changes each time the token is
        // initialized again, and a regenerated profile must be identical.
        r#match: MatchInfo {
            manufacturer: Some(unpadded(&tok.module.manufacturer)),
            // A module that reports the version 0.0 hides its version (kryoptic [run]). The
            // firmware version is then the only evidence of the version.
            module_version: (tok.module.version != "0.0").then(|| unpadded(&tok.module.version)),
            model: Some(unpadded(&tok.token.model)),
            firmware: Some(unpadded(&tok.token.firmware)),
        },
        advertise: advertised.clone(),
        ..Profile::new(default_name(tok.provider.name(), &tok.module.version), Mode::Observed)
    };
    let mut profile = Draft::new(profile);
    profile.note("cryptoki".into(), format!("the module reports Cryptoki {}", tok.module.cryptoki));
    // A mechanism that the module lists more than once (libkmsp11 1.9 lists
    // CKM_RSA_PKCS_KEY_PAIR_GEN 24 times [run]) is advertised once, and the repetition becomes a
    // note.
    let mut counts = BTreeMap::<&str, usize>::new();
    for m in &advertised {
        *counts.entry(m.as_str()).or_default() += 1;
    }
    let repeated: Vec<String> = counts.iter().filter(|(_, n)| **n > 1).map(|(m, n)| format!("{m} {n} times")).collect();
    if !repeated.is_empty() {
        profile.note("mechanism-list".into(), format!("C_GetMechanismList repeats {}", repeated.join(", ")));
        let mut seen = BTreeSet::new();
        profile.out.advertise.retain(|m| seen.insert(m.clone()));
    }
    // What the module and the token report about themselves is recorded as a claim and never
    // compared with anything.
    extras::record_claims(tok, &mut profile);
    // The RSA key sizes that the module reports come from a read-only query. They are a claim
    // that the write probes then test.
    if let Some((min, max)) = tok.rsa_bits {
        let row = profile.generate.entry(KeyKind::Rsa).or_default();
        row.min_bits = u32::try_from(min).ok();
        row.max_bits = u32::try_from(max).ok();
    }
    let mut undetermined = Vec::new();
    let Some(rsa_max_bits) = write else {
        undetermined.push(
            "read-only probes only: pass --write-probes against a token marked scratch in keys.toml to \
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

/// The scratch guard. Returns where the write probes may write on this token, or an error that
/// says why they may write nowhere.
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

/// Refuses a scratch slot that the probe did not leave. An empty slot passes. A slot that holds
/// objects passes only when all of these conditions hold:
/// - it holds at least one of the probe's mark certificates ([`moves::slot_mark`]), which every
///   slot run writes at its end;
/// - every key in it is a key that a mark names or one of the probe's test keys (a module can
///   keep every key it was given under one `CKA_ID`);
/// - every other certificate in it is the probe's test certificate (`moves::CERTIFICATE`) or what
///   the module keeps beside any key (`Provider::scratch_companion`: ykcs11's attestation
///   certificate);
/// - if the probe cannot read the public key of some key in it, it can read the public key of at
///   least one other key in it.
///
/// `scratchId` is one hex string, and a typo must never make the probe overwrite a real key. A
/// module's own placeholder certificate is therefore not a mark, because every key that the
/// module generates has one, including a real key that `cakeys create` made (review 2026-11-23
/// D-1). A mark issued for another key than the one in the slot is not accepted either. A key
/// that was put into a probed slot without a certificate leaves the slot in that state (review
/// 2026-11-24 E-6).
fn check_slot(tok: &Token, id: &[u8]) -> Result<()> {
    let s = tok.raw();
    let find =
        |t: &[Attribute]| s.find_objects(t).map_err(|e| KmError::Unavailable(format!("C_FindObjects: {e}").into()));
    if find(&[Attribute::Id(id.to_vec())])?.is_empty() {
        return Ok(());
    }
    let mut certs = Vec::new();
    for h in find(&[Attribute::Class(ObjectClass::CERTIFICATE), Attribute::Id(id.to_vec())])? {
        // A certificate whose value cannot be read counts as neither the probe's mark nor a
        // companion, because its empty value is not a certificate. The probe never assumes that
        // an object that it cannot read is scratch.
        let der = match s.get_attributes(h, &[AttributeType::Value]).map(|v| v.into_iter().next()) {
            Ok(Some(Attribute::Value(der))) => der,
            _ => Vec::new(),
        };
        certs.push(der);
    }
    // The slot's keys, identified by their public keys. A key whose public key cannot be read
    // (for example, a private key whose module keeps the EC point only on the public key object)
    // is accepted when another key in the slot has a readable public key. When no key's public
    // key is readable, the slot is refused.
    let (mut keys, mut unread) = (Vec::new(), 0);
    for class in [ObjectClass::PUBLIC_KEY, ObjectClass::PRIVATE_KEY] {
        for h in find(&[Attribute::Class(class), Attribute::Id(id.to_vec())])? {
            match tok.material_spki(h) {
                Ok(Some(spki)) => keys.push(spki),
                _ => unread += 1,
            }
        }
    }
    let mark_of = |c: &Vec<u8>| cakeys_core::id::cert_spki(c).ok().filter(|k| moves::slot_mark(k).as_ref() == Some(c));
    let marks: Vec<Vec<u8>> = certs.iter().filter_map(mark_of).collect();
    // The other certificates that may be in the slot beside the mark: the device's companion
    // certificate, and the test certificate that the create probe writes (in a module that keeps
    // every certificate it was given under one `CKA_ID`).
    let (others, tested) =
        (certs.iter().filter(|c| mark_of(c).is_none() && c.as_slice() != moves::CERTIFICATE), moves::test_keys());
    if !marks.is_empty()
        && others.into_iter().all(|c| tok.provider.scratch_companion(id, c))
        && keys.iter().all(|k| marks.contains(k) || tested.contains(k))
        && (unread == 0 || !keys.is_empty())
    {
        return Ok(());
    }
    let shown = cakeys_core::hex::encode(id);
    Err(KmError::Validation(
        format!(
            "token '{}': probe.scratchId {shown} holds objects caprobe did not leave there (a slot it probed \
             holds its own certificate, CN=cakeys-probe, over the key beside it), so it may hold a real key: \
             refusing to overwrite it; empty the slot or name another",
            tok.name
        )
        .into(),
    ))
}

/// What the probes record while they run: the profile, and the working rows that become the
/// profile's capabilities when the probes are done ([`Draft::finish`]). The probes reach the rest
/// of the profile through this struct.
pub(crate) struct Draft {
    /// The profile as far as the probes have measured it. The probes write their rows and notes
    /// here.
    out: Profile,
    /// For each key type, the curves and sizes that generated or were refused, and the size
    /// range that the module reports.
    generate: BTreeMap<KeyKind, GenerateRow>,
    /// The OAEP hashes, of the ones tried, with which a wrap completed a round trip. `None` means
    /// that this was not probed.
    wrap_oaep: Option<Vec<String>>,
    /// The OAEP hashes, of the ones tried, with which the private key decrypted. `None` means
    /// that this was not probed.
    decrypt_oaep: Option<Vec<String>>,
    /// The attributes, of the ones tried, that the module refused in an unwrap template. `None`
    /// means that this was not probed.
    unwrap_refused: Option<Vec<String>>,
    /// The results of the ECDH probes.
    derive: Derived,
    /// The evidence for each generation row's answer: the refusal, or the reason why nothing was
    /// tried.
    evidence: BTreeMap<Capability, String>,
    /// The mechanisms that the operation probes tried. It is `None` for a read-only probe, which
    /// tries no mechanism and therefore records no `[untested]` table.
    tried: Option<BTreeSet<String>>,
    /// Whether the probes wrote into one scratch slot (on a device that makes keys only as
    /// Security Officer). When they did, [`untested_why`] gives that restriction as the reason
    /// why a mechanism was not tried.
    slot: bool,
    /// The capabilities that the probes tried and could not decide ([`Refusal`]). Each one
    /// becomes an `[untested]` entry, except that a `None` value (a busy session) produces no
    /// entry. None of them becomes a row unless another try answered yes.
    undecided: BTreeMap<Capability, Option<Untested>>,
    /// The capabilities whose `yes` only the module reports, with no check by the host
    /// (`by = "unverified"`).
    unverified: BTreeSet<Capability>,
    /// The capabilities whose `no` is the host's finding (`by = "host"`).
    host_no: BTreeSet<Capability>,
    /// The listed mechanisms that worked only where the host could not check the result (review
    /// 2026-11-24 E-4). They become `[untested]` entries and never a yes.
    unchecked: BTreeSet<String>,
}

/// The class of a failed step, which decides what the failure says about the capability that
/// the step tested. Every site that writes a row from a failure uses this one classifier (review
/// 2026-11-24 E-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// The module refused with a `CKR_*` value of its own. The row is the module's no
    /// (`by = "module"`).
    Module,
    /// An earlier operation left the session busy (`CKR_OPERATION_ACTIVE`). The failure says
    /// nothing about this capability.
    Busy,
    /// The device, the token or the session failed (`DEVICE_FAILED_RV`). The failure is not an
    /// answer from the module.
    Device,
    /// cakeys or its provider refused before the module was asked (no `CKR_*` value).
    Cakeys,
}

impl Refusal {
    /// Returns the class of a failure that carries the return value `rv` (`KmError::rv`,
    /// `Msg::rv`, `token::rv_of`).
    pub(super) fn of(rv: Option<u64>) -> Refusal {
        match rv {
            None => Refusal::Cakeys,
            Some(_) if token::rv_is(rv, RvError::OperationActive) => Refusal::Busy,
            Some(v) if token::device_failed_rv(v) => Refusal::Device,
            Some(_) => Refusal::Module,
        }
    }
}

/// The results of the ECDH probes: whether ECDH derived into a sealed secret, and whether it
/// derived in a read-only session. A base key that derived while it reported
/// `CKA_DERIVE = false` becomes a note, because the provider corrects that attribute when cakeys
/// reads it.
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
            tried: None,
            slot: false,
            undecided: BTreeMap::new(),
            unverified: BTreeSet::new(),
            host_no: BTreeSet::new(),
            unchecked: BTreeSet::new(),
        }
    }

    /// Records that `c` worked, as `checked` showed.
    fn yes(&mut self, c: Capability, checked: Checked, via: Option<String>) {
        self.out.set(c, Row { answer: Answer::Yes, by: Some(checked.by()), evidence: None, via });
    }

    /// Records a no by the host's finding: the module answered, and the host found the answer
    /// wrong (another key or another value).
    fn wrong(&mut self, c: Capability, why: String) {
        self.out.set(c, Row { answer: Answer::No, by: Some(By::Host), evidence: Some(why), via: None });
    }

    /// Records that the input for `c` failed with the return value `rv`, and `evidence`
    /// describes the failure. The row is the module's no only when the module refused
    /// ([`Refusal::Module`]). A device failure, or a refusal before the module was asked, becomes
    /// an `[untested]` entry, and a busy session produces nothing. Every outcome except the
    /// module's no also adds a line to the run's `undetermined` list. A refusal answers only for
    /// the input that produced it: a site never passes the refusal of one capability for another
    /// capability (review 2026-11-24 E-5).
    fn refused(&mut self, undetermined: &mut Vec<String>, c: Capability, rv: Option<u64>, evidence: String) {
        match Refusal::of(rv) {
            Refusal::Module => {
                self.out.set(c, Row { answer: Answer::No, by: Some(By::Module), evidence: Some(evidence), via: None });
            }
            class => {
                undetermined.push(format!("no {c} row: {evidence}{}", undecided_why(class)));
                self.undecide(c, class, evidence);
            }
        }
    }

    /// Marks `c` so that the row that [`Self::finish`] writes for it from the fields is a no by
    /// the host's finding.
    fn found_wrong(&mut self, c: Capability) {
        self.host_no.insert(c);
    }

    /// Records `c` as tried and undecided, with the failure class `class` (any class except the
    /// module's own refusal).
    fn undecide(&mut self, c: Capability, class: Refusal, evidence: String) {
        let why = match class {
            Refusal::Device => Some(Why::Device),
            Refusal::Cakeys => Some(Why::Cakeys),
            Refusal::Busy | Refusal::Module => None,
        };
        let entry = why.map(|why| Untested { why, note: Some(evidence) });
        self.undecided.entry(c).or_insert(entry);
    }

    /// Records a generation of `key_type` at `on` that failed with `rv`. The module's own refusal
    /// becomes a `cannot` entry of `row`. Any other failure is handled as [`Self::refused`]
    /// describes, and it never becomes a `cannot` entry.
    fn generation_refused(
        &mut self,
        undetermined: &mut Vec<String>,
        row: &mut GenerateRow,
        (key_type, on): (&KeyKind, On),
        rv: Option<u64>,
        evidence: String,
    ) {
        let c = Capability::Generate { key_type: key_type.clone(), on: on.clone() };
        match Refusal::of(rv) {
            Refusal::Module => {
                match &on {
                    On::Item(i) => row.cannot.push(i.clone()),
                    On::Bits(b) if matches!(key_type, KeyKind::Rsa) => row.cannot_bits.push(*b),
                    On::Bits(b) | On::Bytes(b) => row.cannot_bytes.push(*b),
                }
                self.evidence.insert(c, evidence);
            }
            class => {
                undetermined.push(format!("no {c} row: {evidence}{}", undecided_why(class)));
                self.undecide(c, class, evidence);
            }
        }
    }

    /// Records the note `text` under `key`, and replaces any note that is already there.
    fn note(&mut self, key: String, text: String) {
        self.out.notes.insert(key, text);
    }

    /// Returns the profile with what the probes recorded as its rows: each OAEP hash tried, each
    /// template attribute tried, the ECDH answers, and each curve and size that generated or was
    /// refused.
    fn finish(self) -> Profile {
        let mut p = self.out;
        // A yes is checked by the host unless the probe marked it as unverified. A no is the
        // module's own refusal unless the probe marked it as the host's finding. Any other
        // failure is in `undecided`, and the loop below writes no row for it.
        let (unverified, host_no) = (self.unverified, self.host_no);
        let mut set = |c: Capability, yes: bool| {
            let by = match (yes, unverified.contains(&c), host_no.contains(&c)) {
                (true, true, _) => By::Unverified,
                (true, false, _) | (false, _, true) => By::Host,
                (false, _, false) => By::Module,
            };
            p.set(c, Row { answer: Answer::of(yes), by: Some(by), evidence: None, via: None });
        };
        let mut oaep = |worked: Option<Vec<String>>, tried: &[&str], cap: fn(String) -> Capability| {
            for h in tried.iter().filter(|_| worked.is_some()) {
                set(cap((*h).to_owned()), worked.iter().flatten().any(|w| w == h));
            }
        };
        // `wrap.rsa-oaep.*` rows are written where they are probed (`wraps::probe_wrapping`).
        oaep(self.decrypt_oaep, &DECRYPT_OAEP, Capability::DecryptOaep);
        if let Some(refused) = self.unwrap_refused {
            for a in UNWRAP_TEMPLATE {
                set(Capability::UnwrapTemplate(a.to_owned()), !refused.iter().any(|r| r == a));
            }
        }
        if let Some(b) = self.derive.sealed {
            set(Capability::DeriveSealed, b);
        }
        if let Some(b) = self.derive.read_only {
            set(Capability::DeriveReadOnly, b);
        }
        for (kt, row) in &self.generate {
            p.set_generation(kt.name(), row);
        }
        // A capability that was tried and not decided gets no row, unless another try answered
        // yes (for example, a size that generated under one binding). It gets an `[untested]`
        // entry that names the reason.
        for (c, entry) in self.undecided {
            if p.capabilities.get(&c).is_some_and(|r| r.answer.yes()) {
                continue;
            }
            p.capabilities.remove(&c);
            if let Some(entry) = entry {
                p.untested.insert(c.to_string(), entry);
            }
        }
        for (c, why) in self.evidence {
            if let Some(row) = p.capabilities.get_mut(&c) {
                row.evidence = Some(why);
            }
        }
        // A note that the probe made about a row that it wrote becomes that row's evidence.
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
        if let Some(tried) = self.tried {
            let measured: BTreeSet<String> =
                p.capabilities.iter().flat_map(|(c, r)| c.mechanisms(r.via.as_deref())).collect();
            for m in &p.advertise {
                if tried.contains(m) || measured.contains(m) || p.subtract.mechanisms.contains(m) || p.add.contains(m) {
                    continue;
                }
                let (why, note) = untested_why(m, self.slot);
                p.untested.insert(m.clone(), Untested { why, note: Some(note.into()) });
            }
            // A mechanism that was tried and worked only where the host had no check is unknown,
            // and never a yes (E-4).
            for m in p.advertise.iter().filter(|m| self.unchecked.contains(*m) && !measured.contains(*m)) {
                let note = "signs, but the host has no verifier for its signatures: only the module says it works";
                p.untested.insert(m.clone(), Untested { why: Why::Unverified, note: Some(note.into()) });
            }
        }
        p
    }
}

/// Returns, of the return values of several failures, the one that classifies them together:
/// the first value that is not the module's own refusal, or else the first value. The result is
/// the module's no only when the module refused every way.
fn worst(rvs: &[Option<u64>]) -> Option<u64> {
    rvs.iter().copied().find(|rv| Refusal::of(*rv) != Refusal::Module).or_else(|| rvs.first().copied()).flatten()
}

/// Returns the text that the run's undetermined line adds for a failure of the class `class`.
fn undecided_why(class: Refusal) -> &'static str {
    match class {
        Refusal::Device => " (the device failed: no answer of the module's)",
        Refusal::Cakeys => " (never asked of the module)",
        Refusal::Busy => " (an earlier operation left the session busy)",
        Refusal::Module => "",
    }
}

/// The mechanisms in the baseline that are only digests. The tools compute hashes on the host, so
/// they never ask a module to compute a digest (`spec-coverage/manual.toml`).
const DIGESTS: [&str; 18] = [
    "CKM_MD2",
    "CKM_MD5",
    "CKM_RIPEMD128",
    "CKM_RIPEMD160",
    "CKM_SHA_1",
    "CKM_SHA224",
    "CKM_SHA256",
    "CKM_SHA384",
    "CKM_SHA512",
    "CKM_SHA512_224",
    "CKM_SHA512_256",
    "CKM_SHA512_T",
    "CKM_SHA3_224",
    "CKM_SHA3_256",
    "CKM_SHA3_384",
    "CKM_SHA3_512",
    "CKM_SHAKE_128",
    "CKM_SHAKE_256",
];

/// The mechanisms for which the pinned cryptoki has no name and for which the probe builds no
/// call by hand. The cryptoki layer (`profiles/layers/cryptoki.toml`) has the same entries.
pub(crate) const CRYPTOKI_LACKS: [&str; 2] = ["CKM_XEDDSA", "CKM_AES_CFB128"];

/// Returns the reason why no probe tried an advertised mechanism, and the note text for that
/// reason.
fn untested_why(mechanism: &str, slot: bool) -> (Why, &'static str) {
    if mechanism.starts_with("unknown ") {
        (Why::Vendor, "a vendor mechanism the baseline does not name: no known parameters or semantics to call it with")
    } else if DIGESTS.contains(&mechanism) {
        (Why::Scope, "the tools hash on the host, so a module's digest is never asked of it")
    } else if CRYPTOKI_LACKS.contains(&mechanism) {
        (Why::Cryptoki, "the pinned cryptoki has no name or parameter type for it; see profiles/layers/cryptoki.toml")
    } else if slot {
        (
            Why::Hardware,
            "the probes write into one scratch slot of a device that makes keys only as Security Officer: no secret-key, wrap or derive probe runs there",
        )
    } else {
        (
            Why::Unprobed,
            "advertised, and its limits reported by C_GetMechanismInfo (see [mechanism-info]), but no probe exercised it on this token",
        )
    }
}

/// The message every operation probe signs, and the plaintext the decryption probes recover.
const MSG: &[u8] = b"cakeys probe: operations";

/// What the operation probes saw for each mechanism (D2: the profile records only the
/// differences from the module's list). An advertised mechanism that worked on some key is
/// usable, and its failures on other keys become a note. An advertised mechanism that failed on
/// every key that it was tried with becomes a `subtract` row (advertised but unusable). A
/// mechanism that the module does not list but runs becomes an `add` row. A mechanism that the
/// module neither lists nor runs needs no row, because the module's list already says that. A
/// failure that happened because an earlier operation was still active (tpm2-pkcs11 \[run\])
/// says nothing about the mechanism, so it is undetermined.
#[derive(Default)]
struct Ops {
    worked: BTreeSet<String>,
    /// The signing mechanisms whose signature the host verified at least once.
    checked: BTreeSet<String>,
    /// The signing mechanisms that signed where the host has no verifier (SHA-1, raw X.509). An
    /// unlisted mechanism that is in this set and not in `checked` does not become an `add` row
    /// (review 2026-11-23 D-2).
    unchecked: BTreeSet<String>,
    failed: BTreeMap<String, Vec<String>>,
    /// The mechanisms that the probes tried although the module does not list them.
    unlisted: BTreeSet<String>,
    /// The outcomes that decided nothing about the mechanism: failures with
    /// `CKR_OPERATION_ACTIVE`, and device failures.
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
            // A device failure says nothing about the mechanism, so it never becomes a `subtract`
            // row (E-2).
            Err(e) if Refusal::of(e.rv()) == Refusal::Device => {
                self.busy.push(format!("{mech} on {on}: the device failed ({e}): no answer of the module's"));
            }
            Err(e) => self.failed.entry(mech.to_string()).or_default().push(format!("{on}: {e}")),
        }
    }

    /// Like [`Self::record`], for a signature. `Ok(checked)` says whether the host verified the
    /// signature.
    fn record_signed(&mut self, mech: MechanismType, on: &str, outcome: std::result::Result<bool, Msg>) {
        if let Ok(checked) = &outcome {
            let seen = if *checked { &mut self.checked } else { &mut self.unchecked };
            seen.insert(mech.to_string());
        }
        self.record(mech, on, outcome.map(|_| ()));
    }

    /// Writes the rows and the notes of what the probes saw, and returns the outcomes that could
    /// not be decided.
    fn finish(self, profile: &mut Draft) -> Vec<String> {
        // A listed mechanism that signed only where the host could not check the signature is
        // not a yes (E-4).
        for mech in self.worked.iter().filter(|m| self.unchecked.contains(*m) && !self.checked.contains(*m)) {
            if !self.unlisted.contains(mech) {
                profile.unchecked.insert(mech.clone());
            }
        }
        for mech in self.worked.iter().filter(|m| self.unlisted.contains(*m)) {
            // A signature that the host could not verify does not show that the mechanism works.
            if self.unchecked.contains(mech) && !self.checked.contains(mech) {
                profile.note(
                    mech.clone(),
                    "not listed; signs, but the host cannot verify its signatures, so it is not added".into(),
                );
                continue;
            }
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

/// The state of the write probes: everything that the probes created, so that every run can clean
/// up after itself and the leftover check can record whether deletion really removes objects,
/// and also the operation outcomes and what could not be decided.
struct Made<'a> {
    tok: &'a Token,
    session: &'a Session,
    /// What the write probes made, and where they may write.
    scratch: Scratch,
    ops: Ops,
    undetermined: Vec<String>,
    /// The policy defaults that the module refused although it then made the object without them
    /// (`template.<half>.<attribute>`). These notes describe template errors, not something that
    /// the module cannot do.
    template_notes: BTreeMap<String, String>,
    /// The keys that the module binds to one purpose each ([`Provider::bound_keys`]). It is empty
    /// for a module whose keys serve every purpose.
    ///
    /// [`Provider::bound_keys`]: cakeys_pkcs11::Provider::bound_keys
    bound_keys: Vec<BoundKey>,
    /// The mechanisms that the key under test in the operation probes serves, when the module
    /// binds keys to mechanisms (Cloud KMS). The probes try no other mechanism on that key.
    bound: Option<Vec<String>>,
    /// The RSA sizes to generate: the sizes in [`RSA_SIZES`] up to the largest size that the run
    /// requested.
    rsa_sizes: Vec<u32>,
}

/// A generated key pair, `(public, private)`, or the module's refusal.
type Pair = std::result::Result<(ObjectHandle, ObjectHandle), CkError>;

/// The outcome of [`Made::create`], which calls `Token::create`.
enum Created {
    /// The key pair `(public, private)` that was found under its locator, and the note that
    /// `create` returned.
    Made(ObjectHandle, ObjectHandle, Option<token::CreateNote>),
    /// The module answered the generation with a `CKR_*` value. It becomes a `cannot` row when
    /// it is the module's own refusal, and no row otherwise ([`Draft::generation_refused`]
    /// classifies it).
    Refused(KmError),
    /// The module reported that it generated the key pair, but the pair is not under its
    /// locator. That is neither a yes nor a no, so the probe writes no row and adds a note.
    Lost(KmError),
    /// The module was never asked, because cakeys or the provider refused first (no `CKR_*`
    /// value: for example, a template that the provider refuses, or a host encoding error). That
    /// says nothing about the module, so the probe writes no row and adds a note, as the caller
    /// of `create_secret` does (review 2026-11-23 D-4).
    Undecided(KmError),
}

/// Returns a probe spec that sets `CKA_SENSITIVE` and the usage attributes that `private` and
/// `public` name to true.
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

/// Returns the evidence text of a generation row for a refusal that `Token::create` reported: the
/// `CKR_*` name of the module call that failed, in the form that the probe has always used, or
/// else the error's message as [`evidence`] cleans it.
fn refused(tok: &Token, e: &KmError) -> String {
    e.rv().map_or_else(|| evidence(tok, e), token::rv_value_name)
}

impl Made<'_> {
    fn advertises(&self, m: MechanismType) -> bool {
        self.tok.lists(m) && self.bound.as_ref().is_none_or(|b| b.contains(&m.to_string()))
    }

    /// Returns whether the operation probes try `m` on the current key. They try any mechanism,
    /// whether or not the module lists it, because the module's list is a claim and not a limit.
    /// On a key that the module binds to some mechanisms (Cloud KMS), they try only those
    /// mechanisms.
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

    /// Like [`Self::record`], for a signature. The outcome is the result of [`sign`], which says
    /// whether the host verified the signature.
    ///
    /// [`sign`]: asymmetric::sign
    fn record_signed(&mut self, m: MechanismType, on: &str, outcome: std::result::Result<bool, Msg>) {
        if !self.tok.lists(m) {
            self.ops.unlisted.insert(m.to_string());
        }
        self.ops.record_signed(m, on, outcome);
    }

    /// Generates a key pair where the target says. The function completes the templates with a
    /// new probe label, or with the scratch slot's `CKA_ID` in a Security Officer session. The
    /// outer error is a failed SO login, which stops the probe. The inner error is the module's
    /// refusal, which is an observation.
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
            // A template refusal may be caused by one of the probe's own policy defaults and not
            // by the key (AWS CloudHSM refuses a public key that is not CKA_PRIVATE [run]). The
            // probe therefore tries again once without each default, so that the module's
            // default applies, and it records a note. When none of those tries succeeds, the
            // first refusal is the result.
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

    /// Records a note, once for each attribute and half, for a policy default that the module
    /// refused although it then made the object without that default. The note holds the refusal
    /// and what the object reports instead. `half` is the half of the key pair whose template
    /// held the default, `public` or `private` (`C_GenerateKeyPair` takes a template for each
    /// half), and `made` is that half's object. `half` is also part of the note's name in the
    /// profile (`template.<half>.<attribute>`).
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

    /// Generates `object` where the target says, as `spec` declares it, through the verbs' own
    /// create operation (`Token::create`, which uses the provider's templates, and a Security
    /// Officer session where the module creates keys only as SO). Returns the key pair and the
    /// note of `create`, or the module's refusal as the inner error. The outer error is a failed
    /// SO login, which stops the probe.
    fn create(&mut self, object: &ObjectCfg, spec: &SpecCfg) -> Result<Created> {
        // The probe does not ask the module for a type that cakeys cannot parse (a curve that no
        // crate encodes). That case is undecided, like any refusal without a `CKR_*` value.
        let object = match Object::new(object) {
            Ok(o) => o,
            Err(e) => return Ok(Created::Undecided(e)),
        };
        let (loc, label) = match &self.scratch.target {
            Target::Labels => {
                let label = self.scratch.label();
                (Locator { label: Some(label.clone()), id: None }, Some(label))
            }
            Target::Slot(id) => (Locator { label: None, id: Some(cakeys_core::hex::encode(id)) }, None),
        };
        let note = match self.tok.create(object, spec, &loc, None) {
            Ok(note) => note,
            Err(e) if so_login(&e) => return Err(e),
            Err(e) if e.rv().is_none() => return Ok(Created::Undecided(e)),
            Err(e) => return Ok(Created::Refused(e)),
        };
        // The module made the object, so its label is tracked for the cleanup and the leftover
        // check from here on, whatever the lookups below find (probe.rs F3).
        if let Some(label) = &label {
            self.scratch.track(&[], label);
        }
        let one = |class| self.tok.find(class, &loc).map(|found| found.first().copied());
        let (public, private) = (one(ObjectClass::PUBLIC_KEY)?, one(ObjectClass::PRIVATE_KEY)?);
        if let Some(label) = &label {
            self.scratch.track(&[public, private].into_iter().flatten().collect::<Vec<_>>(), label);
        }
        Ok(match (public, private) {
            (Some(public), Some(private)) => Created::Made(public, private, note),
            _ => Created::Lost(KmError::NotFound("the pair it reported made is not under its locator".into())),
        })
    }

    /// Like [`Self::create`], for a secret key. The function generates `object` under a new probe
    /// label through the verbs' own create operation, and returns the key that it finds under
    /// that label. The inner error is the module's refusal when it carries a `CKR_*` value
    /// ([`KmError::rv`]). An inner error without one means that the probe could not ask (a
    /// provider's refusal, or a cryptoki without the HMAC key types), which says nothing about
    /// the module. The outer error is a failed SO login, which stops the probe.
    fn create_secret(
        &mut self,
        object: &ObjectCfg,
        spec: &SpecCfg,
    ) -> Result<std::result::Result<ObjectHandle, KmError>> {
        let object = match Object::new(object) {
            Ok(o) => o,
            Err(e) => return Ok(Err(e)),
        };
        let label = self.scratch.label();
        let loc = Locator { label: Some(label.clone()), id: None };
        match self.tok.create(object, spec, &loc, None) {
            Ok(_) => {}
            Err(e) if so_login(&e) => return Err(e),
            Err(e) => return Ok(Err(e)),
        }
        // The module made the key, so its label is tracked for the cleanup from here on, whatever
        // the lookup finds.
        self.scratch.track(&[], &label);
        let found = self.tok.find(ObjectClass::SECRET_KEY, &loc)?;
        Ok(match found.first().copied() {
            Some(h) => {
                self.scratch.track(&[h], &label);
                Ok(h)
            }
            None => Err(KmError::NotFound("the key it reported made is not under its locator".into())),
        })
    }

    /// Calls [`Self::create`] with the usage attributes that the operation probes need and, if
    /// that fails, with the bare spec, because a module may accept only the bare spec. Returns
    /// `Ok((created, usable))`, where `usable` is true when the module accepted the usage
    /// attributes.
    fn create_for_use(&mut self, object: &ObjectCfg, usage: &SpecCfg, bare: &SpecCfg) -> Result<(Created, bool)> {
        match self.create(object, usage)? {
            Created::Refused(_) | Created::Undecided(_) => Ok((self.create(object, bare)?, false)),
            made => Ok((made, true)),
        }
    }

    /// Generates a key pair with the usage template that the operation probes need and, if that
    /// fails, with the bare template, because a module may accept only the bare template. Returns
    /// `Ok((pair, usable))`, where `usable` is true when the module accepted the usage template.
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

/// Returns a refusal as a row's evidence, in a form that is the same under any keys.toml and any
/// binding. The function removes the token's keys.toml name. It replaces the binding's prose for
/// a `C_*` failure, which changes with the binding, with the return value's `CKR_*` name when the
/// error carries one. It also removes a provider's hint, because the hint is advice to the user
/// of the verbs, and a reworded hint would change committed profiles (review 2026-11-23 D-18).
fn evidence(tok: &Token, e: &KmError) -> String {
    evidence_text(&tok.name, &e.to_string(), e.rv())
}

/// Returns `said` without the provider hint that the token crate appends
/// (` (hint for <provider>: ...)`, `Token::unsupported_for`). The function removes the hint up
/// to and including its closing parenthesis.
fn without_hint(said: &str) -> String {
    let Some(start) = said.find(" (hint for ") else {
        return said.to_owned();
    };
    let mut depth = 0usize;
    let end = said[start + 1..].char_indices().find_map(|(i, c)| match c {
        '(' => {
            depth += 1;
            None
        }
        ')' if depth == 1 => Some(start + 1 + i + 1),
        ')' => {
            depth -= 1;
            None
        }
        _ => None,
    });
    end.map_or_else(|| said[..start].to_owned(), |end| format!("{}{}", &said[..start], &said[end..]))
}

/// Computes [`evidence`] for the message `said`, on the token that keys.toml names `token`, with
/// the return value `rv`. Only the token crate's own forms of the name (`token 'N'`) are
/// removed. A quoted word that happens to equal the name (an object named like the token) stays.
fn evidence_text(token: &str, said: &str, rv: Option<u64>) -> String {
    let said = without_hint(said);
    let said = said
        .replace(&format!(" on token '{token}'"), "")
        .replace(&format!("token '{token}': "), "")
        .replace(&format!("token '{token}'"), "the token");
    // cryptoki's prose runs from its marker to the closing parenthesis of the parentheses that
    // contain it, if there are any. Parentheses inside the prose itself do not count.
    let Some((before, prose)) = said.split_once(": PKCS11 error:") else {
        return said;
    };
    // When the return value is known and the message does not name it yet, the text
    // `<what>: Function::X` becomes `<what>: CKR_Y: Function::X`, which is the form that the
    // token crate writes itself.
    let before = match rv.map(token::rv_value_name).filter(|name| !before.contains(name.as_str())) {
        Some(name) => match before.rsplit_once(": ").filter(|(_, f)| f.starts_with("Function::")) {
            Some((what, function)) => format!("{what}: {name}: {function}"),
            None => format!("{before}: {name}"),
        },
        None => before.to_owned(),
    };
    let before = before.as_str();
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

/// The AES key lengths, in bytes, at which the write probes generate keys: the three lengths that
/// AES defines (16, 24 and 32), and lengths that it does not define, which a module should
/// refuse. The gate answers only for a length that was tried, because AES has no valid length
/// between two lengths that generated.
pub(crate) const AES_SIZES: [u32; 6] = [8, 16, 24, 32, 48, 64];

/// The lengths, in bytes, at which the write probes generate a secret key whose length is free
/// (a generic secret or an HMAC key). The gate answers yes for a length between two lengths that
/// generated, so these lengths cover the range that a module may accept.
pub(crate) const SECRET_SIZES: [u32; 8] = [1, 16, 32, 64, 128, 256, 512, 1024];

/// Returns the lengths, in bytes, at which the write probes generate a secret key of the type
/// `kt`, each with the `valueLen` that the template carries. The `valueLen` is `None` for Triple
/// DES, because its type fixes the length at 24 bytes and PKCS#11 gives it no `CKA_VALUE_LEN`.
fn secret_sizes(kt: Kt) -> Vec<(Option<u32>, u32)> {
    match kt {
        Kt::Aes => AES_SIZES.iter().map(|n| (Some(*n), *n)).collect(),
        Kt::Des3 => kt.fixed_value_len().and_then(|n| u32::try_from(n).ok()).map(|n| (None, n)).into_iter().collect(),
        _ => SECRET_SIZES.iter().map(|n| (Some(*n), *n)).collect(),
    }
}

/// Generates every secret key type that cakeys manages, in the way that the verbs make one
/// (`Token::create`, with the mechanism that [`token::secret_key_gen`] names), at each length of
/// [`secret_sizes`]. Each length gets a `generate.<key type>.<bytes>` row, yes or no. When a
/// module generates no length at all, the mechanism is advertised but broken, and it gets a
/// `subtract` row. A mechanism that the module does not list is not tried. Returns the first
/// 32-byte AES key, which the wrap probes use as the key to wrap.
fn probe_secrets(made: &mut Made, profile: &mut Draft) -> Result<Option<ObjectHandle>> {
    let mut aes = None;
    // The keys are extractable, because the wrap probes need the AES key to be extractable.
    let usage = spec(&["CKA_EXTRACTABLE"], &[]);
    for kt in Kt::ALL.iter().copied().filter(|k| !k.is_asymmetric()) {
        let kind = KeyKind::from(kt.name());
        let mech = token::secret_key_gen(kt).mechanism_type();
        if !made.tok.lists(mech) {
            continue;
        }
        let mut row = profile.generate.remove(&kind).unwrap_or_default();
        let mut first_refusal = None;
        for (value_len, bytes) in secret_sizes(kt) {
            let object =
                ObjectCfg { value_len: value_len.map(Into::into), ..ObjectCfg::new(Class::SecretKey, Some(kt)) };
            match made.create_secret(&object, &usage)? {
                Ok(h) => {
                    row.can_bytes.push(bytes);
                    if kt == Kt::Aes && bytes == 32 && aes.is_none() {
                        aes = Some(h);
                    }
                }
                Err(e) if e.rv().is_some() => {
                    let said = refused(made.tok, &e);
                    if Refusal::of(e.rv()) == Refusal::Module {
                        first_refusal.get_or_insert_with(|| said.clone());
                    }
                    let why = format!("valueLen = {bytes}: {said}");
                    profile.generation_refused(
                        &mut made.undetermined,
                        &mut row,
                        (&kind, On::Bytes(bytes)),
                        e.rv(),
                        why,
                    );
                }
                // The probe could not ask the module: the provider or this build refused.
                Err(e) => made
                    .undetermined
                    .push(format!("no generate.{kt}.{bytes} row: its template: {}", evidence(made.tok, &e))),
            }
        }
        if row.can_bytes.is_empty()
            && let Some(why) = first_refusal
        {
            profile.out.subtract.mechanisms.push(mech.to_string());
            profile.note(mech.to_string(), format!("advertised but generation fails: {why}"));
        }
        profile.generate.insert(kind, row);
    }
    Ok(aes)
}

/// Returns `template`, the probe's template for generating a 32-byte secret key of the type
/// `key_type` under `label`, as the provider adjusts a generation template
/// (`Provider::template`). The key is declared as keys.toml would declare such a key, so the probe
/// measures what the verbs would send.
///
/// # Errors
///
/// Returns the provider's refusal.
fn secret_template(tok: &Token, key_type: Kt, label: &str, template: Vec<Attribute>) -> Result<Vec<Attribute>> {
    let object = ObjectCfg { value_len: Some(32u32.into()), ..ObjectCfg::new(Class::SecretKey, Some(key_type)) };
    let locator = Locator { label: Some(label.to_owned()), id: None };
    let declared = Declared { object: Object::new(&object)?, spec: &spec(&[], &[]), locator: &locator };
    tok.provider.adjusted(&Template::Generate(declared, Half::Key), template)
}

/// The options of the `probe` verb beyond the probing itself.
pub(crate) struct Request<'a> {
    /// Also run the write probes ([`probe`]).
    pub write: bool,
    /// The name of the generated profile. The default is the name of `claimed`, or else
    /// `<provider>/<version>`.
    pub name: Option<&'a str>,
    /// The committed profile that the result is compared with, if any.
    pub claimed: Option<&'a Profile>,
    /// Whether the result is written to a file or compared with `claimed`, and not only printed.
    pub kept: bool,
    /// The largest size in [`RSA_SIZES`] that the write probes generate.
    pub rsa_max_bits: u32,
}

/// Returns what this build lacks to write or to compare a profile, each item with the reason
/// (review D3). The probe writes what it observes, so each missing item changes rows and not only
/// messages:
/// - a cryptoki without the Nix patches drops from the result of `C_GetMechanismList` every
///   standard mechanism that it cannot name, so the advertised list is too short (kryoptic's
///   `CKM_AES_KEY_WRAP_KWP` \[run\]);
/// - a build without the `kwp` feature does not probe the key wraps that only the patched binding
///   names.
///
/// A failure's `CK_RV` is no longer in this list, because every build carries it (review
/// 2026-11-23 B-6).
fn build_lacks(patched: bool, kwp: bool) -> Vec<&'static str> {
    let mut lacks = Vec::new();
    if !patched {
        lacks.push("its cryptoki lacks the Nix patches and drops the mechanisms it cannot name");
    }
    if !kwp {
        lacks.push("it is built without `kwp`, so the RFC 5649 and RSA-AES key wraps go unprobed");
    }
    lacks
}

/// Runs the `probe` verb: probes `tok` and names the result. The function adds a note for each
/// item that the probe could not decide.
///
/// A regeneration is the compare-and-write flow, so the generated profile takes the name of the
/// claimed profile. A module that hides its version (kryoptic reports 0.0) therefore still
/// regenerates its committed profile, whose name the repository chose (D9).
///
/// # Errors
///
/// Returns `Validation` (exit 17) when the result would be kept but this build lacks a patch or a
/// feature that [`build_lacks`] names. Also returns the errors of [`probe`].
pub(crate) fn generate(
    tok: &Token,
    cfg: &TokenCfg,
    req: &Request,
    notes: &mut cakeys_pkcs11::ops::Notes,
) -> Result<Profile> {
    let lacks = build_lacks(cakeys_pkcs11::binding::patched(), cfg!(feature = "kwp"));
    if !lacks.is_empty() {
        if req.kept {
            return Err(KmError::Validation(
                format!(
                    "this build cannot write or diff a profile: {}; probe with the Nix-built caprobe \
                     (the `patched-cryptoki` feature)",
                    lacks.join("; ")
                )
                .into(),
            ));
        }
        for why in lacks {
            notes.note(format_args!("probe: {why}: the rows may not be what the module does"));
        }
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

/// Returns the rows in which a generated profile differs from the committed profile `claimed`.
/// An empty result means that the module conforms. A read-only probe observes only the match
/// keys, the advertised mechanisms and the reported key sizes, so only those are compared.
#[must_use]
pub(crate) fn drift(generated: &Profile, claimed: &Profile, write: bool) -> Vec<String> {
    if write { crate::diff::diff(generated, claimed) } else { crate::diff::read_only(generated, claimed) }
}

/// Copies into the generated `profile` what the probe does not generate, from the file that
/// `profile` is about to replace. `existing` is that file's content, and `shown` is its name in
/// messages. The function keeps the file's `[migration]` section and `move.*` claims (evidence
/// from docs/CAMIGRATE.md, which a probe cannot observe) and its `[manual]` findings (made by
/// hand, each with its evidence). It keeps them only from the same profile: the file must hold
/// the family that was just probed, and the name that was just generated unless `renamed` is
/// true (`--name` was given).
///
/// # Errors
///
/// Returns `Validation` (exit 17) for a file that does not parse, because regenerating it would
/// silently drop those sections. Returns it for any existing file when the probe was read-only,
/// because the result would drop every write-probe row. Returns it for a file that holds another
/// family's profile, or another profile of this family when `renamed` is false, because the
/// file's claims are not this module's (a wrong `--out`).
pub(crate) fn keep_claims(
    profile: &mut Profile,
    existing: &str,
    shown: &str,
    write: bool,
    renamed: bool,
) -> Result<()> {
    if !write {
        return Err(KmError::Validation(
            format!(
                "{shown}: a read-only probe would overwrite its generate, wrap and unwrap rows; pass --write-probes"
            )
            .into(),
        ));
    }
    let old = Profile::from_toml(existing)
        .map_err(|e| KmError::Validation(format!("{shown}: not a profile, refusing to overwrite: {e}").into()))?;
    let (was, now) = (&old.profile, &profile.profile);
    if old.family() != profile.family() {
        return Err(KmError::Validation(
            format!("{shown} holds '{was}', not a profile of the probed '{now}': its claims are another module's")
                .into(),
        ));
    }
    if was != now && !renamed {
        return Err(KmError::Validation(
            format!("{shown} holds '{was}', the probe generated '{now}': pass --name to say which it is").into(),
        ));
    }
    profile.migration = old.migration;
    profile.manual = old.manual;
    profile.capabilities.extend(old.capabilities.into_iter().filter(|(c, _)| !c.probed()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::asymmetric::{montgomery_templates, operates_on};
    use super::scratch::delete_rows;
    use super::*;
    use cryptoki::context::Function;

    /// The Montgomery fallback template is never stricter than the first try (review 2026-11-23
    /// D-11): the first try also names every attribute that the fallback names, with the same
    /// value. A fallback that added `CKA_VERIFY` or `CKA_PRIVATE = false` to the public key would
    /// fail on modules that accept the first try, and cakeys would then record a curve that it
    /// can generate as refused.
    #[test]
    fn a_montgomery_fallback_is_never_stricter_than_the_first_try() {
        let (public, with_usage, private) = montgomery_templates(montgomery()[0].1);
        let first: Vec<_> = public.iter().chain(&with_usage).collect();
        let fallback: Vec<_> = public.iter().chain(&private).collect();
        for attr in &fallback {
            assert!(
                first.iter().any(|f| f == attr),
                "the fallback names {:?}, which the first try does not",
                attr.attribute_type()
            );
        }
        assert!(!fallback.iter().any(|a| a.attribute_type() == AttributeType::Derive), "the fallback names no usage");
        assert!(with_usage.contains(&Attribute::Derive(true)), "the first try asks for deriving");
    }

    /// The probes generate every secret key type that cakeys manages at one or more lengths, and
    /// only Triple DES without a `valueLen`, because its type fixes the length at 24 bytes. AES is
    /// generated at the three lengths that it defines and at other lengths, and the types with a
    /// free length are generated across the range that a module may accept.
    #[test]
    fn every_secret_key_type_has_lengths_to_generate_at() {
        for kt in Kt::ALL.iter().copied().filter(|k| !k.is_asymmetric()) {
            let sizes = secret_sizes(kt);
            assert!(!sizes.is_empty(), "{kt}");
            assert!(sizes.iter().all(|(len, bytes)| len.is_none_or(|l| l == *bytes)), "{kt}");
            assert_eq!(sizes.iter().all(|(len, _)| len.is_none()), kt == Kt::Des3, "{kt}");
        }
        assert_eq!(secret_sizes(Kt::Des3), [(None, 24)]);
        let aes: Vec<u32> = secret_sizes(Kt::Aes).into_iter().map(|(_, n)| n).collect();
        assert!([16, 24, 32].iter().all(|n| aes.contains(n)) && aes.iter().any(|n| ![16, 24, 32].contains(n)));
        assert!(secret_sizes(Kt::Sha256Hmac).len() > 3);
    }

    /// A probe writes or compares a profile only in a build with the patched binding and the
    /// `kwp` feature (review D3). `build_lacks` names each missing item, and any one missing item
    /// makes `generate` refuse.
    #[test]
    fn a_kept_profile_needs_every_patch_and_feature() {
        assert_eq!(build_lacks(true, true), Vec::<&str>::new());
        for (patched, kwp, named) in [(false, true, "lacks the Nix patches"), (true, false, "without `kwp`")] {
            let lacks = build_lacks(patched, kwp);
            assert!(lacks.len() == 1 && lacks[0].contains(named), "{lacks:?}");
        }
        assert_eq!(build_lacks(false, false).len(), 2);
    }

    /// The patched binding is linked only together with the features that use it (each tool's
    /// `patched-cryptoki` feature), so the probe of the Nix build may write a profile.
    #[test]
    fn the_patched_binding_comes_with_its_features() {
        let (patched, kwp) = (cakeys_pkcs11::binding::patched(), cfg!(feature = "kwp"));
        assert!(
            !patched || build_lacks(patched, kwp).is_empty(),
            "the patched cryptoki is linked without caprobe's `patched-cryptoki` feature: {:?}",
            build_lacks(patched, kwp)
        );
    }

    /// The probe drops only its own policy defaults, and only after a template refusal. A type or
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
        // A regenerated profile is identical byte for byte only while these spellings stay the
        // same.
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
        // OAEP worked with one hash, so the mechanism is usable, and the other hash's failure is
        // only a note.
        assert_eq!(profile.out.notes["CKM_RSA_PKCS_OAEP"], "RSA-2048 decrypt SHA-256: CKR_ARGUMENTS_BAD");
        assert!(!profile.out.notes.contains_key("CKM_ECDSA"));
    }

    /// An unlisted mechanism becomes an `add` row only when the host verified one of its
    /// signatures. A mechanism that signed only where the host has no verifier (SHA-1 here)
    /// becomes a note. A mechanism whose signature the host verified once is added, even if it
    /// also signed where the host could not check (review 2026-11-23 D-2: before the fix, any
    /// returned bytes produced an `add` row).
    #[test]
    fn only_a_verified_signature_adds_a_mechanism() {
        let mut ops = Ops::default();
        for m in [MechanismType::ECDSA_SHA224, MechanismType::SHA1_RSA_PKCS, MechanismType::SHA224_RSA_PKCS] {
            ops.unlisted.insert(m.to_string());
        }
        ops.record_signed(MechanismType::ECDSA_SHA224, "secp256r1", Ok(true));
        ops.record_signed(MechanismType::SHA1_RSA_PKCS, "RSA-2048", Ok(false));
        ops.record_signed(MechanismType::SHA224_RSA_PKCS, "RSA-2048", Ok(false));
        ops.record_signed(MechanismType::SHA224_RSA_PKCS, "RSA-3072", Ok(true));
        let mut profile = Draft::new(Profile::from_toml("profile = \"t\"\nmode = \"observed\"\n").unwrap());
        ops.finish(&mut profile);
        assert_eq!(profile.out.add, ["CKM_ECDSA_SHA224", "CKM_SHA224_RSA_PKCS"]);
        assert!(profile.out.notes["CKM_SHA1_RSA_PKCS"].contains("cannot verify its signatures"));
        assert_eq!(profile.out.subtract.mechanisms, [] as [String; 0]);
    }

    /// One classifier decides every failure (review 2026-11-24 E-2). A failure is the module's no
    /// only when its return value is the module's own refusal. A device failure, a busy session
    /// and a refusal before the module was asked write no row. A device failure and a refusal
    /// before the module was asked each write an `[untested]` entry that names the reason. The
    /// test covers every function that turns a failure into a row, and every device-failure
    /// value.
    #[test]
    fn only_the_modules_own_refusal_is_its_no() {
        let module_rv = 0x70; // CKR_MECHANISM_INVALID
        let busy = 0x90; // CKR_OPERATION_ACTIVE
        let device: Vec<u64> = (0..0x1000)
            .filter(|v| cakeys_profile::DEVICE_FAILED_RV.contains(&token::rv_value_name(*v).as_str()))
            .collect();
        assert_eq!(device.len(), cakeys_profile::DEVICE_FAILED_RV.len());
        let cases = device
            .iter()
            .map(|v| (Some(*v), Some(Why::Device)))
            .chain([(None, Some(Why::Cakeys)), (Some(busy), None)])
            .collect::<Vec<_>>();
        let cap = || Capability::WrapOaep("SHA-1".into());
        let generate = || Capability::Generate { key_type: KeyKind::Rsa, on: On::Bits(1536) };
        for (rv, why) in cases {
            let mut draft = Draft::new(Profile::new("t/1".into(), Mode::Observed));
            let mut undetermined = Vec::new();
            draft.refused(&mut undetermined, cap(), rv, format!("refused: {rv:?}"));
            let mut row = GenerateRow::default();
            draft.generation_refused(&mut undetermined, &mut row, (&KeyKind::Rsa, On::Bits(1536)), rv, "g".into());
            assert_eq!(row, GenerateRow::default(), "{rv:?}: a cannot from no refusal of the module's");
            draft.generate.insert(KeyKind::Rsa, row);
            let p = draft.finish();
            for c in [cap(), generate()] {
                assert!(!p.capabilities.contains_key(&c), "{rv:?}: {c} written as a row");
                assert_eq!(p.untested.get(&c.to_string()).map(|u| u.why), why, "{rv:?}: {c}");
            }
            assert_eq!(undetermined.len(), 2, "{rv:?}: {undetermined:?}");
            assert_eq!(p.untested_problems(), Vec::<String>::new());
        }
        // The module's own refusal is a no by the module.
        let mut draft = Draft::new(Profile::new("t/1".into(), Mode::Observed));
        let mut undetermined = Vec::new();
        draft.refused(&mut undetermined, cap(), Some(module_rv), "CKR_MECHANISM_INVALID".into());
        let mut row = GenerateRow::default();
        draft.generation_refused(
            &mut undetermined,
            &mut row,
            (&KeyKind::Rsa, On::Bits(1536)),
            Some(module_rv),
            "g".into(),
        );
        draft.generate.insert(KeyKind::Rsa, row);
        let p = draft.finish();
        for c in [cap(), generate()] {
            let r = &p.capabilities[&c];
            assert_eq!((r.answer, r.by), (Answer::No, Some(By::Module)), "{c}");
        }
        assert!(undetermined.is_empty() && p.untested.is_empty());
        // Of the failures of several ways, one failure that is not the module's own refusal
        // prevents a no by the module.
        assert_eq!(worst(&[Some(module_rv), Some(device[0]), Some(module_rv)]), Some(device[0]));
        assert_eq!(worst(&[Some(module_rv), None]), None);
        assert_eq!(worst(&[Some(module_rv), Some(0x91)]), Some(module_rv));
        // A yes from another try overrides an undecided result (for example, a size that was
        // tried under two bindings).
        let mut draft = Draft::new(Profile::new("t/1".into(), Mode::Observed));
        draft.refused(&mut Vec::new(), cap(), Some(device[0]), "device".into());
        draft.yes(cap(), Checked::same(&1, &1).unwrap(), None);
        let p = draft.finish();
        assert!(p.capabilities[&cap()].answer.yes() && !p.untested.contains_key(&cap().to_string()));
    }

    /// A listed mechanism that worked only where the host has no verifier becomes an
    /// `[untested]` entry with the reason `unverified`, and never a yes. A mechanism whose
    /// signature the host verified once counts as measured (review 2026-11-24 E-4).
    #[test]
    fn an_unchecked_signature_is_no_yes() {
        let mut ops = Ops::default();
        ops.record_signed(MechanismType::SHA1_RSA_PKCS, "RSA-2048", Ok(false));
        ops.record_signed(MechanismType::SHA256_RSA_PKCS, "RSA-2048", Ok(true));
        ops.record(MechanismType::ECDSA, "secp256r1", Err(Msg::from("CKR_DEVICE_ERROR").with_rv(Some(0x30))));
        let mut out = Profile::new("t/1".into(), Mode::Observed);
        out.advertise = ["CKM_SHA1_RSA_PKCS", "CKM_SHA256_RSA_PKCS", "CKM_ECDSA"].map(str::to_owned).into();
        let mut draft = Draft::new(out);
        draft.tried = Some(["CKM_SHA1_RSA_PKCS", "CKM_SHA256_RSA_PKCS", "CKM_ECDSA"].map(str::to_owned).into());
        let busy = ops.finish(&mut draft);
        // A device failure does not produce a `subtract` row, only an undetermined line.
        assert!(busy.iter().any(|b| b.contains("the device failed")), "{busy:?}");
        let p = draft.finish();
        assert!(p.subtract.mechanisms.is_empty(), "{:?}", p.subtract.mechanisms);
        assert_eq!(p.untested.get("CKM_SHA1_RSA_PKCS").map(|u| u.why), Some(Why::Unverified));
        assert!(!p.untested.contains_key("CKM_SHA256_RSA_PKCS"));
        assert_eq!(p.untested_problems(), Vec::<String>::new());
    }

    /// A provider's hint, including its own parentheses, is never part of the evidence, and the
    /// text after the hint stays.
    #[test]
    fn evidence_leaves_out_a_provider_hint() {
        let said = "unsupported: refused (CKR_X) (hint for kmsp11: a key (the CryptoKey) stays 30 days); retry";
        assert_eq!(without_hint(said), "unsupported: refused (CKR_X); retry");
        assert_eq!(without_hint("no hint (here)"), "no hint (here)");
    }

    /// Evidence keeps the module's return value and drops cryptoki's prose and the token's
    /// keys.toml name. It drops the name only in the token crate's own forms, so a quoted word
    /// that equals the name stays (review probe F6).
    #[test]
    fn evidence_names_the_return_value_not_the_prose() {
        let mech_invalid = 0x70; // CKR_MECHANISM_INVALID
        for (said, rv, want) in [
            // The token crate's own message already names the value, so the evidence names it
            // once, not twice.
            (
                "unavailable: C_Sign on token 'probe': CKR_MECHANISM_INVALID: Function::SignInit: PKCS11 error: The mechanism is invalid.",
                Some(mech_invalid),
                "unavailable: C_Sign: CKR_MECHANISM_INVALID: Function::SignInit",
            ),
            (
                "unavailable: C_Sign on token 'probe': Function::SignInit: PKCS11 error: The mechanism is invalid.",
                Some(mech_invalid),
                "unavailable: C_Sign: CKR_MECHANISM_INVALID: Function::SignInit",
            ),
            (
                "unavailable: C_Sign on token 'probe': Function::SignInit: PKCS11 error: The mechanism is invalid.",
                None,
                "unavailable: C_Sign: Function::SignInit",
            ),
            (
                "unsupported: token 'probe' refused it (C_UnwrapKey: Function::UnwrapKey: PKCS11 error: Some (prose).); retry",
                Some(mech_invalid),
                "unsupported: the token refused it (C_UnwrapKey: CKR_MECHANISM_INVALID: Function::UnwrapKey); retry",
            ),
            ("no object 'probe' on token 'probe'", None, "no object 'probe'"),
            ("token 'probe': CKR_GENERAL_ERROR", None, "CKR_GENERAL_ERROR"),
        ] {
            assert_eq!(evidence_text("probe", said, rv), want, "{said}");
        }
    }

    /// When a count fails, before or after the objects are destroyed, the probe writes no
    /// `delete` row, because an error does not show that the objects were deleted (review probe
    /// F5).
    #[test]
    fn a_failed_count_writes_no_delete_row() {
        let counts = |n: usize| Ok(BTreeMap::from([("CKO_PRIVATE_KEY".to_owned(), n)]));
        assert_eq!(
            delete_rows(true, counts(2), Ok(BTreeMap::new())).unwrap(),
            [("CKO_PRIVATE_KEY".into(), true, None)]
        );
        let left = delete_rows(true, counts(2), counts(1)).unwrap();
        assert_eq!(left, [("CKO_PRIVATE_KEY".into(), false, Some("C_DestroyObject leaves 1 of 2 behind".into()))]);
        assert_eq!(
            delete_rows(true, counts(2), Err("C_FindObjects: CKR_DEVICE_ERROR".into())).unwrap_err(),
            "C_FindObjects: CKR_DEVICE_ERROR"
        );
        assert!(delete_rows(true, Err("before".into()), Ok(BTreeMap::new())).is_err());
        // When objects were made but none were counted, the function returns an error instead of
        // staying silent (D-14). When nothing was made, it returns no row and no error.
        assert!(delete_rows(true, Ok(BTreeMap::new()), Ok(BTreeMap::new())).unwrap_err().contains("nothing found"));
        assert_eq!(delete_rows(false, Ok(BTreeMap::new()), Ok(BTreeMap::new())).unwrap(), []);
    }

    /// The default profile name spells a NUL-padded module version in the same way as the match
    /// key does (review probe F10).
    #[test]
    fn the_default_name_cleans_the_version() {
        assert_eq!(default_name("softhsm", "2.7\0\0"), "softhsm/2.7");
    }

    /// The RSA operation probes run on the 2048-bit key, or on the next larger usable size when
    /// the module refuses the 2048-bit key or that key is unusable. They never run twice and
    /// never on a smaller key (review probe F10).
    #[test]
    fn rsa_operations_run_on_the_first_usable_key_from_2048() {
        let run = |made: &[(u32, bool)]| {
            let mut operated = None;
            for (bits, usable) in made {
                if operates_on(*bits, *usable, operated.is_some()) {
                    operated = Some(*bits);
                }
            }
            operated
        };
        assert_eq!(run(&[(1024, true), (2048, true), (3072, true)]), Some(2048));
        assert_eq!(run(&[(1024, true), (3072, true), (4096, true)]), Some(3072), "2048 refused");
        assert_eq!(run(&[(2048, false), (3072, true)]), Some(3072), "2048 unusable");
        assert_eq!(run(&[(1024, true), (1536, true)]), None);
    }

    /// `--out` keeps an existing file's claims only when the file holds the profile that was just
    /// probed. A file of another family is refused, another profile of the same family needs
    /// `--name`, and the same profile keeps its `move.*` row (review probe F4).
    #[test]
    fn claims_are_kept_only_from_the_same_profile() {
        let file = |name: &str| {
            format!(
                "profile = \"{name}\"\nmode = \"observed\"\n[capabilities]\n\"move.secret-unwrap\" = {{ answer = \"no\" }}\n"
            )
        };
        let probed = || Profile::from_toml("profile = \"kryoptic/1.5\"\nmode = \"observed\"\n").unwrap();
        let keep = |existing: &str, renamed: bool| {
            let mut p = probed();
            keep_claims(&mut p, existing, "the file", true, renamed).map(|()| p)
        };
        for (existing, renamed, why) in
            [(file("softhsm/2.7"), true, "another module's"), (file("kryoptic/1.4"), false, "pass --name")]
        {
            let e = keep(&existing, renamed).unwrap_err();
            assert!(e.exit_code() == 17 && e.to_string().contains(why), "{e}");
        }
        for (existing, renamed) in [(file("kryoptic/1.5"), false), (file("kryoptic/1.4"), true)] {
            let p = keep(&existing, renamed).unwrap();
            assert_eq!(p.profile, "kryoptic/1.5");
            assert!(p.capabilities.keys().any(|c| c.to_string() == "move.secret-unwrap"), "{:?}", p.capabilities);
        }
    }
}
