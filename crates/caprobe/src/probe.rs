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

use cakeys_core::config::{AttrValue, Binding, Locator, Object, ObjectCfg, SpecCfg, TokenCfg};
use cakeys_core::id::Curve;
use cakeys_core::migrate::OaepHash;
use cakeys_core::pop::{self, RsaPadding};
use cakeys_core::sig::{self, Encoding, HashAlg};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Msg, Result};
use cakeys_pkcs11::token::{self, Token, derive_any, is_policy_default, show, template_refusal};
use cakeys_pkcs11::{BoundKey, Declared, Half, Template, keygen_mechanism};
use cakeys_profile::capability::{DECRYPT_OAEP, UNWRAP_TEMPLATE, WRAP_OAEP};
use cakeys_profile::{Answer, Capability, GenerateRow, KeyKind, MatchInfo, Mode, On, Profile, Untested, Why};
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
mod extras;
mod moves;
mod scratch;
mod secrets;
mod wraps;

pub(crate) use asymmetric::RSA_SIZES;
use asymmetric::{MONTGOMERY, operate, probe_curves, probe_rsa};
use bound::probe_bound;
use scratch::{Scratch, write_probes};
use wraps::{probe_key_wraps, probe_wrapping, rsa_aes_key_wrap};

/// The text of a module-supplied string with its C padding removed: PKCS#11's fixed-width
/// fields are C strings, and a module may NUL-pad them (tpm2-pkcs11's token model comes from
/// the TPM's four 4-byte vendor-string properties, so swtpm reports `SW` + NULs + `TPM`
/// \[run\]). The padding is layout, not content — a note records the text.
fn clean(s: &str) -> String {
    s.split('\0').filter(|part| !part.is_empty()).collect::<Vec<_>>().join(" ")
}

/// A generated profile's name without `--name` or `--diff`: `<provider>/<version>`, the
/// version [`clean`] as the match key's is.
fn default_name(provider: &str, version: &str) -> String {
    format!("{provider}/{}", clean(version))
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

/// Whether `e` is an SO login failing (`Token::as_so`): it stops the probe, never a row.
fn so_login(e: &KmError) -> bool {
    matches!(e, KmError::Unavailable(m) if m.contains(token::SO_LOGIN))
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
/// names a slot that is empty or holds the probe's own certificate ([`check_slot`]); the scratch
/// guard is the one thing the probe refuses rather than records. `Unavailable` when an SO login fails.
pub(crate) fn probe(tok: &Token, cfg: &TokenCfg, write: Option<u32>) -> Result<Probed> {
    let advertised = tok.advertised();
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
        advertise: advertised.clone(),
        ..Profile::new(default_name(tok.provider.name(), &tok.module.version), Mode::Observed)
    };
    let mut profile = Draft::new(profile);
    profile.note("cryptoki".into(), format!("the module reports Cryptoki {}", tok.module.cryptoki));
    // A mechanism listed more than once (libkmsp11 1.9: CKM_RSA_PKCS_KEY_PAIR_GEN 24 times
    // [run]) is advertised once; the repetition is a note.
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
    // What the module and token report of themselves: claims, never compared.
    extras::record_claims(tok, &mut profile);
    // The RSA key sizes the module reports: read-only, a claim the write probes then test.
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

/// Refuse a scratch slot the probe did not leave: one holding anything, unless it holds the
/// probe's own certificate ([`moves::SLOT_MARKER`], written at the end of every slot run) and
/// beside it only what the module keeps beside any key (`Provider::scratch_companion`: ykcs11's
/// attestation certificate). `scratchId` is one hex string, and a typo must never overwrite a
/// real key: a module's own placeholder certificate is no mark, since every key it generates
/// carries one, a real key `cakeys create` made included (review 2026-11-23 D-1).
fn check_slot(tok: &Token, id: &[u8]) -> Result<()> {
    let s = tok.raw();
    let find =
        |t: &[Attribute]| s.find_objects(t).map_err(|e| KmError::Unavailable(format!("C_FindObjects: {e}").into()));
    if find(&[Attribute::Id(id.to_vec())])?.is_empty() {
        return Ok(());
    }
    let mut certs = Vec::new();
    for h in find(&[Attribute::Class(ObjectClass::CERTIFICATE), Attribute::Id(id.to_vec())])? {
        // A certificate that cannot be read counts as neither the probe's mark nor a companion
        // (its empty value is no certificate): what the probe cannot see is never presumed scratch.
        let der = match s.get_attributes(h, &[AttributeType::Value]).map(|v| v.into_iter().next()) {
            Ok(Some(Attribute::Value(der))) => der,
            _ => Vec::new(),
        };
        certs.push(der);
    }
    let marker = |c: &Vec<u8>| c.as_slice() == moves::SLOT_MARKER;
    if certs.iter().any(marker) && certs.iter().filter(|c| !marker(c)).all(|c| tok.provider.scratch_companion(id, c)) {
        return Ok(());
    }
    let shown = cakeys_core::hex::encode(id);
    Err(KmError::Validation(
        format!(
            "token '{}': probe.scratchId {shown} holds objects caprobe did not leave there (a slot it probed \
             holds its own certificate, CN=cakeys-probe), so it may hold a real key: refusing to overwrite it; \
             empty the slot or name another",
            tok.name
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
    /// The mechanisms the operation probes tried; `None` for a read-only probe, which tries
    /// none and so records no `[untested]` table.
    tried: Option<BTreeSet<String>>,
    /// Whether the probes wrote into one scratch slot (a device that makes keys only as
    /// Security Officer): what an untried mechanism is then put down to.
    slot: bool,
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
            tried: None,
            slot: false,
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
        }
        p
    }
}

/// The mechanisms the baseline names that are digests alone: the tools hash on the host, so a
/// module's digest is never asked of it (`spec-coverage/manual.toml`).
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

/// Mechanisms the pinned cryptoki has no name for and the probe builds no call to by hand: the
/// cryptoki layer (`profiles/layers/cryptoki.toml`) carries the same entries.
pub(crate) const CRYPTOKI_LACKS: [&str; 2] = ["CKM_XEDDSA", "CKM_AES_CFB128"];

/// Why an advertised mechanism no probe tried was not tried, and the words for it.
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

/// What the operation probes saw per mechanism (D2: deltas only). An advertised mechanism that
/// worked on some key is usable, the failures on other keys a note; one that failed on every
/// key it was tried with is a `subtract` row (advertised but unusable). One the module does not
/// list but runs is an `add` row; one it neither lists nor runs is what its list said. A
/// failure because an earlier one left its operation active (tpm2-pkcs11 \[run\]) says nothing
/// of the mechanism: undetermined.
#[derive(Default)]
struct Ops {
    worked: BTreeSet<String>,
    /// The signing mechanisms whose signature the host verified at least once, and those that
    /// signed only where the host has no verifier (SHA-1, raw X.509): an unlisted one of the
    /// latter alone is no `add` row (review 2026-11-23 D-2).
    checked: BTreeSet<String>,
    unchecked: BTreeSet<String>,
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

    /// [`Self::record`] for a signature, `Ok(checked)`: whether the host verified it.
    fn record_signed(&mut self, mech: MechanismType, on: &str, outcome: std::result::Result<bool, Msg>) {
        if let Ok(checked) = &outcome {
            let seen = if *checked { &mut self.checked } else { &mut self.unchecked };
            seen.insert(mech.to_string());
        }
        self.record(mech, on, outcome.map(|_| ()));
    }

    /// The rows and notes of what was seen; returns what could not be decided.
    fn finish(self, profile: &mut Draft) -> Vec<String> {
        for mech in self.worked.iter().filter(|m| self.unlisted.contains(*m)) {
            // A signature only the module stands behind is not a mechanism the host saw work.
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

/// A generated pair, `(public, private)`, or the module's refusal.
type Pair = std::result::Result<(ObjectHandle, ObjectHandle), CkError>;

/// What [`Made::create`] got from `Token::create`.
enum Created {
    /// The pair `(public, private)` under its locator, and `create`'s note.
    Made(ObjectHandle, ObjectHandle, Option<token::CreateNote>),
    /// The module refused the generation (its `CKR_*`): a `cannot` row.
    Refused(KmError),
    /// The module said it generated, but the pair is not under its locator: neither a yes nor
    /// a no, so no row, and a note.
    Lost(KmError),
    /// The module was never asked: cakeys or the provider refused first (no `CKR_*`: a
    /// template the provider refuses, a host encoding error). It says nothing of the module, so
    /// no row and a note, as `create_secret`'s caller does (review 2026-11-23 D-4).
    Undecided(KmError),
}

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

    /// [`Self::record`] for a signature ([`sign`]'s outcome: whether the host verified it).
    ///
    /// [`sign`]: asymmetric::sign
    fn record_signed(&mut self, m: MechanismType, on: &str, outcome: std::result::Result<bool, Msg>) {
        if !self.tok.lists(m) {
            self.ops.unlisted.insert(m.to_string());
        }
        self.ops.record_signed(m, on, outcome);
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
    /// object without it: the refusal, and what the object it made reports instead. `half` is
    /// the key pair's half whose template held the default, `public` or `private`
    /// (`C_GenerateKeyPair` takes a template for each), and `made` that half's object; it names
    /// the note in the profile (`template.<half>.<attribute>`).
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
        // A type cakeys cannot parse (a curve no crate encodes) is not asked of the module: the
        // probe could not ask, as for any refusal without a `CKR_*`.
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
        // Made: its label is the cleanup's and the leftover check's from here on, whatever the
        // lookups below find (probe.rs F3).
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

    /// [`Self::create`] for a secret key: `object` generated under a fresh probe label, through
    /// the verbs' own create operation, and the key found under it. The inner error is the
    /// module's refusal when it carries a `CKR_*` ([`KmError::rv`]); without one the probe could
    /// not ask (a provider's refusal, a cryptoki without the HMAC key types), which says nothing
    /// of the module. An SO login failing is the outer one, and stops the probe.
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
        // Made: its label is the cleanup's from here on, whatever the lookup finds.
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

    /// [`Self::create`] with the usage the operation probes need, else bare, as a module may
    /// insist. `Ok((created, usable))`: `usable` when the usage took.
    fn create_for_use(&mut self, object: &ObjectCfg, usage: &SpecCfg, bare: &SpecCfg) -> Result<(Created, bool)> {
        match self.create(object, usage)? {
            Created::Refused(_) | Created::Undecided(_) => Ok((self.create(object, bare)?, false)),
            made => Ok((made, true)),
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

/// A refusal as a row's evidence, the same under any keys.toml and any binding: the token's
/// keys.toml name taken out, the binding's prose for a `C_*` failure (it changes with the
/// binding) replaced by the return value's `CKR_*` name, when the error carries it, and a
/// provider's hint left out: it is advice to the verbs' user, and a reworded hint would change
/// committed profiles (review 2026-11-23 D-18).
fn evidence(tok: &Token, e: &KmError) -> String {
    evidence_text(&tok.name, &e.to_string(), e.rv())
}

/// `said` without the provider hint the token crate appends (` (hint for <provider>: ...)`,
/// `Token::unsupported_for`), up to its closing parenthesis.
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

/// [`evidence`] of the message `said`, on the token keys.toml names `token`, with the return
/// value `rv`. Only the token crate's own forms of the name (`token 'N'`) are taken out: a
/// quoted word that happens to equal it (an object named like the token) stays.
fn evidence_text(token: &str, said: &str, rv: Option<u64>) -> String {
    let said = without_hint(said);
    let said = said
        .replace(&format!(" on token '{token}'"), "")
        .replace(&format!("token '{token}': "), "")
        .replace(&format!("token '{token}'"), "the token");
    // Cryptoki's prose runs from its marker to the end of the parenthesis it sits in, if any
    // (its own parentheses aside).
    let Some((before, prose)) = said.split_once(": PKCS11 error:") else {
        return said;
    };
    // `<what>: Function::X`, as `<what>: CKR_Y: Function::X` where the value is known (the
    // form the token crate writes itself), unless the message names it already.
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

/// The AES key lengths the write probes generate, in bytes: the three it defines (16, 24, 32) and
/// lengths it does not, which a module should refuse. The gate answers only for a length tried:
/// AES has no length between two that generated.
pub(crate) const AES_SIZES: [u32; 6] = [8, 16, 24, 32, 48, 64];

/// The lengths of a secret key whose length is free (a generic secret, an HMAC key), in bytes.
/// The gate answers yes for a length between two that generated, so these cover the range a
/// module may take.
pub(crate) const SECRET_SIZES: [u32; 8] = [1, 16, 32, 64, 128, 256, 512, 1024];

/// The lengths, in bytes, the write probes generate a secret key of type `kt` at: each with the
/// `valueLen` the template carries (`None` for Triple DES, whose type fixes the 24 bytes and
/// which PKCS#11 gives no `CKA_VALUE_LEN`).
fn secret_sizes(kt: Kt) -> Vec<(Option<u32>, u32)> {
    match kt {
        Kt::Aes => AES_SIZES.iter().map(|n| (Some(*n), *n)).collect(),
        Kt::Des3 => kt.fixed_value_len().and_then(|n| u32::try_from(n).ok()).map(|n| (None, n)).into_iter().collect(),
        _ => SECRET_SIZES.iter().map(|n| (Some(*n), *n)).collect(),
    }
}

/// The generation of every secret key type cakeys manages, as the verbs make one (`Token::create`,
/// the mechanism [`token::secret_key_gen`] names) at each length of [`secret_sizes`]: a
/// `generate.<key type>.<bytes>` row per length, yes or no. A module that generates no length at
/// all has the mechanism advertised but broken, a `subtract` row. A mechanism the module does not
/// list is not tried. Returns the first 32-byte AES key, the wrap probes' wrapped key.
fn probe_secrets(made: &mut Made, profile: &mut Draft) -> Result<Option<ObjectHandle>> {
    let mut aes = None;
    // Extractable, as the wrap probes need the AES key to be.
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
                    row.cannot_bytes.push(bytes);
                    let said = refused(made.tok, &e);
                    first_refusal.get_or_insert_with(|| said.clone());
                    profile.generation_evidence(&kind, On::Bytes(bytes), format!("valueLen = {bytes}: {said}"));
                }
                // The probe could not ask: the provider's or this build's refusal, not the module's.
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
    let declared = Declared { object: Object::new(&object)?, spec: &spec(&[], &[]), locator: &locator };
    tok.provider.adjusted(&Template::Generate(declared, Half::Key), template)
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

/// What this build lacks to write or judge a profile, each with why (review D3). The probe
/// writes what it observes, so each of these changes rows rather than only messages:
/// - an unpatched cryptoki drops from `C_GetMechanismList` every mechanism it cannot name, so the
///   advertisement is short (kryoptic's `CKM_AES_KEY_WRAP_KWP` \[run\]);
/// - without `kwp` the key wraps only the patched binding names go unprobed.
///
/// A failure's `CK_RV` is no longer among them: every build carries it (review 2026-11-23 B-6).
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
/// findings (made by hand, each with its evidence). Only the same profile's: the file must hold
/// the family just probed, and the name just generated unless `renamed` (`--name` given).
///
/// # Errors
///
/// `Validation` (17) for a file that does not parse (regenerating it would silently drop
/// those sections), for any existing file from a read-only probe (it would drop every
/// write-probe row), and for a file holding another family's profile, or another profile of
/// this family without `renamed`: its claims are not this module's (a wrong `--out`).
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
    /// D-11): every attribute it names, the first try names too, with the same value. A fallback
    /// that added `CKA_VERIFY` or `CKA_PRIVATE = false` to the public key would fail on modules
    /// that accept the first try, and cakeys would then record a curve it can generate as refused.
    #[test]
    fn a_montgomery_fallback_is_never_stricter_than_the_first_try() {
        let (public, with_usage, private) = montgomery_templates(MONTGOMERY[0].1);
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

    /// Every secret key type cakeys manages is generated at some length, and only Triple DES
    /// without a `valueLen` (its type fixes the 24 bytes): AES at the three lengths it defines and
    /// beyond them, the free-length types across the range a module may take.
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

    /// A probe writes or diffs a profile only from a build with the patched binding and `kwp`
    /// (review D3): each one missing is named, and any one refuses (`generate`).
    #[test]
    fn a_kept_profile_needs_every_patch_and_feature() {
        assert_eq!(build_lacks(true, true), Vec::<&str>::new());
        for (patched, kwp, named) in [(false, true, "lacks the Nix patches"), (true, false, "without `kwp`")] {
            let lacks = build_lacks(patched, kwp);
            assert!(lacks.len() == 1 && lacks[0].contains(named), "{lacks:?}");
        }
        assert_eq!(build_lacks(false, false).len(), 2);
    }

    /// The patched binding is linked with what uses it (each tool's `patched-cryptoki`): the
    /// Nix build's probe is one that may write a profile.
    #[test]
    fn the_patched_binding_comes_with_its_features() {
        let (patched, kwp) = (cakeys_pkcs11::binding::patched(), cfg!(feature = "kwp"));
        assert!(
            !patched || build_lacks(patched, kwp).is_empty(),
            "the patched cryptoki is linked without caprobe's `patched-cryptoki` feature: {:?}",
            build_lacks(patched, kwp)
        );
    }

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

    /// An unlisted mechanism is an `add` row only on a signature the host verified: one that
    /// signed only where the host has no verifier (SHA-1 here) is a note, and one that verified
    /// once is added whatever else it signed unchecked (review 2026-11-23 D-2: any returned bytes
    /// were an `add`).
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

    /// A provider's hint is never evidence, its own parentheses included; the text after it stays.
    #[test]
    fn evidence_leaves_out_a_provider_hint() {
        let said = "unsupported: refused (CKR_X) (hint for kmsp11: a key (the CryptoKey) stays 30 days); retry";
        assert_eq!(without_hint(said), "unsupported: refused (CKR_X); retry");
        assert_eq!(without_hint("no hint (here)"), "no hint (here)");
    }

    /// Evidence keeps the module's return value and drops cryptoki's prose and the token's
    /// keys.toml name, but only the token crate's forms of it: a quoted word that equals the
    /// name stays (review probe F6).
    #[test]
    fn evidence_names_the_return_value_not_the_prose() {
        let mech_invalid = 0x70; // CKR_MECHANISM_INVALID
        for (said, rv, want) in [
            // The token crate's own message names the value already: once, not twice.
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

    /// A count that failed, before or after the destroys, writes no `delete` row: an error is
    /// not "deleted" (review probe F5).
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
        // Objects made but none counted: said, not silent (D-14); nothing made, nothing to say.
        assert!(delete_rows(true, Ok(BTreeMap::new()), Ok(BTreeMap::new())).unwrap_err().contains("nothing found"));
        assert_eq!(delete_rows(false, Ok(BTreeMap::new()), Ok(BTreeMap::new())).unwrap(), []);
    }

    /// A NUL-padded module version names the default profile as it spells the match key
    /// (review probe F10).
    #[test]
    fn the_default_name_cleans_the_version() {
        assert_eq!(default_name("softhsm", "2.7\0\0"), "softhsm/2.7");
    }

    /// The RSA operation probes run on the 2048-bit key, or the next usable size up when that
    /// one is refused or unusable; never twice, never on a smaller key (review probe F10).
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

    /// `--out` keeps an existing file's claims only when it holds the profile just probed:
    /// another family's file is refused, another profile of the family needs `--name`, and the
    /// same profile keeps its `move.*` row (review probe F4).
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
