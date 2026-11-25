//! PKCS#11 token layer over `cryptoki`. Transparent: PKCS#11 names in, PKCS#11 calls out.
//! Module-specific behaviour goes through the selected [`Provider`].

use crate::provider::{
    AttestCtx, AttestationCap, Attested, Checked, Create, Declared, Destroy, Generation, Half, Provider, SessionKey,
    Template, Topic, keygen_mechanism,
};
use crate::registry::Registry;
use crate::templates;
use cakeys_core::Msg;
use cakeys_core::attrs;
use cakeys_core::config::{AttrValue, Binding, Locator, Mode, Object, ObjectCfg, SpecCfg, TokenCfg};
pub use cakeys_core::config::{Immutables, ModuleInfo, TokenInfo};
use cakeys_core::id::{self, BlockCipher, Commit, Curve, HmacHash, Scheme};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, Rv, RvError};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroize::Zeroizing;

mod generate;
mod host;
mod identity;
mod library;
mod login;
mod measure;
mod policy;
mod possession;
mod public;
mod rv;
mod types;
mod uri;

pub use generate::{BY_NAME, CreateNote, PUBLIC_MADE_PRIVATE, with_public_default_dropped};
pub use host::accepts_public_keys;
pub use identity::commit_mechanism;
use library::{Library, Logins, library, module_info};
pub use login::has_admin;
use login::{Pin, PinState, read_pin, session};
pub use policy::bool_attr;
pub use possession::{
    Derived, OAEP, ProofSide, derive_any, digest_info, is_policy_default, oaep_of, oaep_params, proof_refusal, show,
    template_refusal,
};
pub use public::{public_key_attrs, public_object_attrs};
pub use rv::{SO_LOGIN, device_failed_rv, read_attribute, rv_is, rv_name, rv_of, rv_value, rv_value_name};
use rv::{ck, if_readable};
use types::managed_class;
pub use types::{class_of, hmac_key_gen, key_type_of, secret_key_gen};
use uri::pct_all;
pub use uri::{PinRef, locator_attrs, pin_ref, provider_pem, with_query};

/// The session a verb opens (M1, docs/archive/REVIEW-2026-11-11.md): read-only for the verbs that only
/// read — a write-protected token (`CKF_WRITE_PROTECTED`) refuses read-write sessions, and the
/// session objects reading needs (a key-wrap copy, an ECDH secret) are allowed in read-only
/// ones — read-write only to create or destroy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// A read-only session: the verbs that only read.
    Read,
    /// A read-write session, to create or destroy objects.
    Write,
    /// Reads, and makes session objects (a key-wrap copy, a KEK): read-write where the token
    /// allows it, since AWS `CloudHSM` refuses even a session object in a read-only session
    /// (`CKR_SESSION_READ_ONLY` \[run\]); read-only on a write-protected token.
    Scratch,
}

/// An open token: its module and the session cakeys works in, with the provider that handles
/// the module and the mechanisms it may rely on.
pub struct Token {
    /// The token's name in keys.toml.
    pub name: String,
    /// The label the token reports (`CK_TOKEN_INFO.label`).
    pub(crate) label: String,
    /// What the module reports of itself, and the file loaded.
    pub module: ModuleInfo,
    /// What the token reports of itself.
    pub token: TokenInfo,
    /// Usable mechanisms: advertised ones, minus what the resolved capability profiles
    /// subtract (the module's advertised-but-broken rows and every layer's), else minus
    /// what the provider's override drops.
    pub mechanisms: Vec<MechanismType>,
    /// What `C_GetMechanismList` returned, as the module returned it: what
    /// [`Token::unprofiled`] filters anew, and [`Token::advertised`] names.
    listed: Vec<MechanismType>,
    /// The RSA key-pair generation's key-size range as `C_GetMechanismInfo` reports it, when
    /// the module advertises `CKM_RSA_PKCS_KEY_PAIR_GEN`: the probe's reported bounds.
    pub rsa_bits: Option<(u64, u64)>,
    /// The provider handling the module.
    pub provider: Arc<dyn Provider>,
    /// The resolved capability profiles (docs/CAPROBE.md): the module profile and the
    /// delta layers between cakeys and it, with the notes resolution noticed on the way.
    pub profiles: crate::resolution::Resolved,
    session: Session,
    /// The slot holding the token, for a second session ([`Token::extra_session`]).
    slot: cryptoki::slot::Slot,
    /// Logged in as the user: private objects are visible. Otherwise a public session.
    pub logged_in: bool,
    /// The token's config, for provider hooks that need more than the module (the native TPM
    /// attestation path's `options`: `tcti`, `tpm2Store` and `akHandle`).
    pub cfg: TokenCfg,
    /// The PIN counters at open, checked before every login (M2).
    pins: PinState,
    /// An SO login of this token was refused: the counters read at open no longer say what is
    /// left, so the credential is not tried again (review 2026-11-23 B-11).
    so_refused: std::sync::atomic::AtomicBool,
    /// A step runs in the SO session now ([`Token::as_so`]): a nested one runs as it is.
    in_so: std::sync::atomic::AtomicBool,
    /// The user credential, already read for login, kept for what needs it again: the
    /// context-specific login of a `CKA_ALWAYS_AUTHENTICATE` proof, the TPM attestation path
    /// (it unseals the token's wrapping key with it) and logging the user back in after an SO
    /// step (`soCredentialFile`/`soCredentialEnv`). Zeroized on drop.
    pin: Option<Zeroizing<String>>,
    /// When an attestation chain's certificates must be valid, as the open named it
    /// ([`crate::ChainTime`]).
    chain_time: crate::ChainTime,
    /// Last: fields drop in declaration order, so the session is closed before the module is
    /// finalized.
    library: Arc<Library>,
}

/// The mechanisms a token may rely on: what the module lists, less what the resolved stack
/// subtracts (the module profile's advertised-but-broken rows and every layer's), plus what it
/// adds although the module does not list it (a provider's stand-in the probe found working,
/// `Provider::stand_in`). Every layer subtracts, the binding's included where no module profile
/// is resolved (token/mod.rs F7), and by the one spelling of a mechanism's name
/// ([`policy::mechanism_namer`]): one cryptoki does not name is named by the baseline.
fn usable_mechanisms(
    advertised: &[MechanismType],
    profiles: &crate::resolution::Resolved,
) -> Result<Vec<MechanismType>> {
    let subtracted = profiles.subtracted_mechanisms();
    let mut usable: Vec<MechanismType> = if subtracted.is_empty() {
        advertised.to_vec()
    } else {
        let name = policy::mechanism_namer();
        advertised.iter().copied().filter(|m| !subtracted.contains(name(*m).as_str())).collect()
    };
    let added = profiles.added_mechanisms();
    if added.is_empty() {
        return Ok(usable);
    }
    let baseline =
        cakeys_profile::Set::active().and_then(|s| s.baseline()).map_err(|e| KmError::Validation(e.into()))?;
    for name in added {
        let id = baseline.mechanisms.get(name).and_then(|id| MechanismType::try_from(*id).ok());
        if let Some(m) = id.filter(|m| !usable.contains(m)) {
            usable.push(m);
        }
    }
    Ok(usable)
}

/// The `CKM_*` names of `mechanisms`, sorted: the form the lock, a profile and `caps` list them in.
fn sorted_names(mechanisms: &[MechanismType]) -> Vec<String> {
    let mut names: Vec<String> = mechanisms.iter().map(ToString::to_string).collect();
    names.sort();
    names
}

/// A session object cakeys made for one step (a derived secret, a key-encryption key, a
/// wrap-rebind copy), destroyed when this is dropped, whatever the step returned. A destroy
/// that fails is not an error: the object goes with its session.
pub struct SessionObject<'a> {
    session: &'a Session,
    handle: ObjectHandle,
}

impl<'a> SessionObject<'a> {
    /// `handle`, an object of `session`, to destroy on drop.
    #[must_use]
    pub fn new(session: &'a Session, handle: ObjectHandle) -> SessionObject<'a> {
        SessionObject { session, handle }
    }

    /// The object's handle.
    #[must_use]
    pub fn handle(&self) -> ObjectHandle {
        self.handle
    }
}

impl Drop for SessionObject<'_> {
    fn drop(&mut self) {
        let _ = self.session.destroy_object(self.handle);
    }
}

/// What [`Token::occupied`] found under a locator.
#[derive(Debug, Default)]
pub struct Occupied {
    /// Objects a creation there would collide with.
    pub colliding: usize,
    /// A public key object holding the key's public key, to reuse rather than create.
    pub public_half: Option<ObjectHandle>,
}

impl Token {
    /// Put what the lock recorded of this token (`observed`) over its module profile, as the
    /// static gate does ([`crate::gate::stack`]): the answers its own runs demonstrated decide
    /// before what a shipped profile says of its kind (ISSUES.md B18). Only an observation of
    /// the module and token this open found: answers recorded on another module or token say
    /// nothing of this one.
    pub fn with_answers(&mut self, observed: &cakeys_core::config::Observation) {
        if observed.module.as_ref() == Some(&self.module) && observed.token.as_ref() == Some(&self.token) {
            self.profiles.with_answers(&self.name, observed);
        }
    }

    /// Open the token named `name`: load the module, find the slot whose token label matches,
    /// read its capabilities, and log in as the user when a PIN is configured.
    ///
    /// Tokens of one module open at once share its library, which the first open initializes
    /// and dropping the last of them (or a failed open, when it was the only one) finalizes.
    ///
    /// # Errors
    ///
    /// `Validation` for a token with no module, an unknown provider, options its provider
    /// refuses, or an admin credential on a provider that creates as the user; `Ambiguous`
    /// when several slots carry the label; `Unavailable` when no slot does, the module
    /// cannot be loaded, any `C_*` call fails, or the PIN (env var or file) cannot be read.
    pub fn open(
        name: &str,
        cfg: &TokenCfg,
        module_override: Option<&str>,
        registry: &Registry,
        access: Access,
        chain_time: crate::ChainTime,
    ) -> Result<Token> {
        let module = match module_override {
            Some(m) => Some(m.to_owned()),
            None => cfg.module_path(name, &|var| std::env::var(var).ok())?,
        }
        .ok_or_else(|| {
            KmError::Validation(format!("token '{name}' has no module (set module, or pass --module)").into())
        })?;
        // From here every return releases the library (finalized with its last token), a failed
        // open too.
        let module_guard = library(&module)?;
        let ctx = &module_guard.0;
        let module = module_info(ctx, module)?;
        let provider = registry.select(cfg.named_provider(), &module)?;
        provider.check_options(name, &cfg.options)?;
        let FoundSlot { slot, token, pins, write_protected } =
            find_slot(ctx, &cfg.token_label, cfg.token_serial.as_deref(), &module.path)?;
        // The capability profiles (docs/CAPROBE.md): the module profile follows the
        // provider (D9), the binding layer is always in the stack, a forwarder the module
        // names and the config's extras with it. What the stack subtracts filters the
        // advertisement; a token with no resolved profile keeps the provider's own filter.
        let profiles = crate::resolution::resolve(cfg, &module, Some(&token), provider.name())
            .map_err(|e| KmError::Validation(e.into()))?;
        let advertised = ctx.get_mechanism_list(slot).map_err(ck("C_GetMechanismList"))?;
        let rsa_bits = advertised
            .contains(&MechanismType::RSA_PKCS_KEY_PAIR_GEN)
            .then(|| ctx.get_mechanism_info(slot, MechanismType::RSA_PKCS_KEY_PAIR_GEN).ok())
            .flatten()
            .map(|i| (i.min_key_size() as u64, i.max_key_size() as u64));
        let mechanisms = usable_mechanisms(&advertised, &profiles)?;
        let (session, pin) = session(ctx, &module_guard.2, slot, name, cfg, access, write_protected, pins)?;
        Ok(Token {
            name: name.to_owned(),
            label: cfg.token_label.clone(),
            module,
            token,
            mechanisms,
            listed: advertised,
            rsa_bits,
            profiles,
            session,
            slot,
            logged_in: pin.is_some(),
            cfg: cfg.clone(),
            pins,
            so_refused: std::sync::atomic::AtomicBool::new(false),
            in_so: std::sync::atomic::AtomicBool::new(false),
            pin,
            provider,
            chain_time,
            library: module_guard,
        })
    }

    /// An `Unsupported` error carrying the return value `msg` carries, and no advice.
    pub fn unsupported(&self, msg: impl Into<Msg>) -> KmError {
        KmError::Unsupported(msg.into())
    }

    /// [`Self::unsupported`], with the provider's advice on `about` if it has any.
    pub fn unsupported_for(&self, about: Topic, msg: impl Into<Msg>) -> KmError {
        self.provider.hinted(about, KmError::Unsupported(msg.into()))
    }

    /// A warning for the run when the user PIN counters at open reported a failed login
    /// (`CKF_USER_PIN_COUNT_LOW`) and cakeys logged in: retries remain, so it is no refusal.
    #[must_use]
    pub fn pin_warning(&self) -> Option<String> {
        (self.logged_in && self.pins.user.count_low).then(|| {
            format!(
                "token '{}': a user PIN login failed since the last success (CKF_USER_PIN_COUNT_LOW); check \
                 the PIN source before a wrong one spends more retries",
                self.name
            )
        })
    }

    /// The session itself, for raw `C_*` calls: caprobe's probes, which exercise what the
    /// module does beyond what the verbs ask of it (the verbs go through the methods above).
    #[must_use]
    pub fn raw(&self) -> &Session {
        &self.session
    }

    /// A second session on the token, for a step the module refuses in the verb's own: a
    /// read-only verb's proof by deriving on tpm2-pkcs11, which keeps derived secrets as store
    /// rows and so derives only in a read-write session \[run\]. Login state belongs to the
    /// token, shared by every session of the process, and object handles are valid in all of
    /// them (PKCS#11 base §5.6), so it needs no login and finds the same key.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the module refuses another session (`C_OpenSession`).
    pub fn extra_session(&self, access: Access) -> Result<Session> {
        let ctx = &self.library.0;
        match access {
            Access::Read => ctx.open_ro_session(self.slot).map_err(ck("C_OpenSession (read-only)")),
            Access::Scratch if ctx.get_token_info(self.slot).is_ok_and(|i| i.write_protected()) => {
                ctx.open_ro_session(self.slot).map_err(ck("C_OpenSession (read-only)"))
            }
            Access::Write | Access::Scratch => ctx.open_rw_session(self.slot).map_err(ck("C_OpenSession")),
        }
    }

    /// Whether the token may be relied on for mechanism `m` (provider-filtered).
    pub fn has(&self, m: MechanismType) -> bool {
        self.mechanisms.contains(&m)
    }

    /// The mechanism to run for `m`: `m` itself where the module lists it, else the provider's
    /// stand-in for it (`Provider::stand_in`: AWS `CloudHSM`'s Ed25519), else `m`.
    #[must_use]
    pub fn runnable<'a>(&self, m: Mechanism<'a>) -> Mechanism<'a> {
        if self.listed.contains(&m.mechanism_type()) { m } else { self.provider.stand_in(&m).unwrap_or(m) }
    }

    /// The session key `key`'s template ([`templates::session`]), as the provider adjusts it.
    ///
    /// # Errors
    ///
    /// The provider's refusal.
    pub fn session_template(&self, key: SessionKey) -> Result<Vec<Attribute>> {
        self.provider.adjusted_session(templates::session(key))
    }

    /// The key type of `h` as a spec-compliant module would report it: `CKA_KEY_TYPE`, repaired
    /// by the provider from `CKA_EC_PARAMS` (`Provider::key_type`). `None`: the object has none.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the module refuses `C_GetAttributeValue`.
    pub fn key_type(&self, h: ObjectHandle) -> Result<Option<KeyType>> {
        self.key_type_by(|t| self.attr(h, t))
    }

    /// [`Self::key_type`] where it can be read ([`if_readable`]).
    fn key_type_if_readable(&self, h: ObjectHandle) -> Result<Option<KeyType>> {
        self.key_type_by(|t| self.attr_if_readable(h, t))
    }

    fn key_type_by(&self, read: impl Fn(AttributeType) -> Result<Option<Attribute>>) -> Result<Option<KeyType>> {
        let Some(Attribute::KeyType(kt)) = read(AttributeType::KeyType)? else { return Ok(None) };
        let params = match kt {
            KeyType::EC => match read(AttributeType::EcParams)? {
                Some(Attribute::EcParams(p)) => Some(p),
                _ => None,
            },
            _ => None,
        };
        Ok(Some(self.provider.key_type(kt, params.as_deref())))
    }

    /// The provider's attestation capability for `object`'s class, when the spec opted in:
    /// `None` when this module attests nothing (or not this class).
    pub fn attestation_cap(&self, object: &ObjectCfg) -> Option<AttestationCap> {
        self.provider.attestation().filter(|cap| cap.classes.contains(&object.class))
    }

    /// Compute the attestation commitment for `key` (§3.7 of docs/DESIGN.md) through the
    /// provider: the module-exposed attestation certificate (PIV) or the native `TPM2_Certify`
    /// path (tpm2-pkcs11), verified on the host. `spki` is the material SPKI the attestation
    /// must name (`None` for secret keys), and `commitments` what a secret key's must be bound
    /// to instead; `provision` lets the provider create the device state it attests with (only
    /// `lock` sets it).
    ///
    /// # Errors
    ///
    /// Whatever the provider's attestation path cannot establish: `Unsupported` when the
    /// provider attests no class like this, `Unavailable` when the token has none to give
    /// (an imported key, a session that could not attest), `Conflict` when it names other
    /// material than `spki` or `commitments`.
    pub fn attest(
        &self,
        key: ObjectHandle,
        object: &ObjectCfg,
        spki: Option<&[u8]>,
        commitments: &[crate::provider::Commitment],
        provision: bool,
    ) -> Result<Attested> {
        let has_mechanism = |m: MechanismType| self.library.0.get_mechanism_info(self.slot, m).is_ok();
        let ctx = AttestCtx {
            session: &self.session,
            cfg: &self.cfg,
            module_version: &self.module.version,
            has_mechanism: &has_mechanism,
            token_name: &self.name,
            key,
            object,
            spki,
            commitments,
            pin: self.pin.as_ref().map(|p| p.as_str()),
            provision,
            chain_time: self.chain_time,
        };
        let cap = self
            .provider
            .attestation()
            .ok_or_else(|| KmError::Unsupported(format!("{} exposes no attestation", self.provider.name()).into()))?;
        (cap.attest)(&ctx)
    }

    /// Every object of `class` under the locator.
    ///
    /// # Errors
    ///
    /// `Validation` when the locator names neither `CKA_LABEL` nor `CKA_ID` or its `CKA_ID`
    /// is not hex; `Unavailable` when `C_FindObjects` fails.
    pub fn find(&self, class: ObjectClass, loc: &Locator) -> Result<Vec<ObjectHandle>> {
        let mut template = vec![Attribute::Class(class)];
        template.extend(locator_attrs(loc)?);
        self.session.find_objects(&template).map_err(ck("C_FindObjects"))
    }

    /// Every object under the locator, whatever its class (If-None-Match before generating: a key
    /// made now belongs with nothing already there).
    ///
    /// # Errors
    ///
    /// `Validation` for a locator naming neither `CKA_LABEL` nor `CKA_ID` (or a non-hex
    /// `CKA_ID`); `Unavailable` when `C_FindObjects` fails.
    pub fn find_any(&self, loc: &Locator) -> Result<Vec<ObjectHandle>> {
        self.session.find_objects(&locator_attrs(loc)?).map_err(ck("C_FindObjects"))
    }

    /// The objects the SO marked `CKA_TRUSTED` on this token (docs/CAMIGRATE.md D2, `enforced`): the
    /// public key object holding `spki` (the transport key's trusted copy), and how many others
    /// there are — an `enforced` move is only as narrow as the token's whole trusted set.
    ///
    /// # Errors
    ///
    /// `Unavailable` when `C_FindObjects` fails.
    pub fn trusted(&self, spki: &[u8]) -> Result<(Option<ObjectHandle>, usize)> {
        let found = self.session.find_objects(&[Attribute::Trusted(true)]).map_err(ck("C_FindObjects"))?;
        let mut copy = None;
        let mut others = 0;
        for h in found {
            if copy.is_none() && self.held_spki(h)?.as_deref() == Some(spki) {
                copy = Some(h);
            } else {
                others += 1;
            }
        }
        Ok((copy, others))
    }

    /// Create the trusted copy of a transport key on this token (`camigrate transport
    /// --trust-on`): an RSA public token object of `modulus` and `exponent`, labelled `label`,
    /// that may wrap, marked `CKA_TRUSTED` — which only the SO can set, and only at creation.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::as_so`] refuses; `Unsupported` when the module will not create it
    /// trusted.
    pub fn create_trusted_copy(&self, modulus: Vec<u8>, exponent: Vec<u8>, label: &str) -> Result<ObjectHandle> {
        let template = self.provider.adjusted(
            &Template::TrustedCopy,
            vec![
                Attribute::Class(ObjectClass::PUBLIC_KEY),
                Attribute::KeyType(KeyType::RSA),
                Attribute::Token(true),
                Attribute::Private(false),
                Attribute::Modulus(modulus),
                Attribute::PublicExponent(exponent),
                Attribute::Wrap(true),
                Attribute::Encrypt(false),
                Attribute::Verify(false),
                Attribute::Trusted(true),
                Attribute::Label(label.as_bytes().to_vec()),
            ],
        )?;
        self.as_so("marking the transport key trusted", || {
            self.session
                .create_object(&template)
                .map_err(|e| self.unsupported_for(Topic::Create, trusted_copy_refused(&self.name, &e)))
        })
    }

    /// If-None-Match before importing `object` under `loc`, per class: PKCS#11's convention puts a
    /// key, its public key and its certificate under one `CKA_ID` (and often one `CKA_LABEL`), so
    /// only what the creation would collide with counts — an object of its class, and for a
    /// private key any public key object that does not hold `spki`. A public key object that
    /// holds `spki` (`None`: not known yet, so none does) is no collision but the public half
    /// to reuse; for a public key object it is the object itself, already there.
    ///
    /// # Errors
    ///
    /// `Validation` for a locator naming neither `CKA_LABEL` nor `CKA_ID` (or a non-hex
    /// `CKA_ID`); `Unavailable` when `C_FindObjects` fails.
    pub fn occupied(&self, object: &ObjectCfg, loc: &Locator, spki: Option<&[u8]>) -> Result<Occupied> {
        let class = class_of(object);
        let mut out = Occupied::default();
        if class != ObjectClass::PUBLIC_KEY {
            out.colliding = self.find(class, loc)?.len();
        }
        if matches!(class, ObjectClass::PRIVATE_KEY | ObjectClass::PUBLIC_KEY) {
            for p in self.find(ObjectClass::PUBLIC_KEY, loc)? {
                match spki {
                    Some(s) if out.public_half.is_none() && self.held_spki(p)?.as_deref() == Some(s) => {
                        out.public_half = Some(p);
                    }
                    _ => out.colliding += 1,
                }
            }
        }
        Ok(out)
    }

    /// Exactly-one lookup of the object named by the locator: the key (private or secret) or
    /// certificate, or the public key object when adopting public-only.
    ///
    /// # Errors
    ///
    /// `Ambiguous` when several objects match the locator; whatever `find` refuses.
    pub fn find_key(&self, object: &ObjectCfg, loc: &Locator, public_only: bool) -> Result<Option<ObjectHandle>> {
        let class = if public_only { ObjectClass::PUBLIC_KEY } else { class_of(object) };
        let found = self.find(class, loc)?;
        match found.len() {
            0 => Ok(None),
            1 => Ok(Some(found[0])),
            n => Err(KmError::Ambiguous(format!("{n} objects match locator {loc} on token '{}'", self.name).into())),
        }
    }

    /// Consumers that select a key by `CKA_ID` (OpenSSH takes the first private key with the
    /// certificate's or public key's ID) must find exactly this one: refuse when another private
    /// key shares `h`'s `CKA_ID`. Only a logged-in session can see private keys; a public session
    /// checks nothing (the lock records which it was).
    ///
    /// # Errors
    ///
    /// `Ambiguous` (12) when another private key on the token shares the `CKA_ID`.
    pub fn check_unique_private_id(&self, h: ObjectHandle) -> Result<()> {
        if !self.logged_in {
            return Ok(());
        }
        let id = match self.attr(h, AttributeType::Id)? {
            Some(Attribute::Id(id)) if !id.is_empty() => id,
            _ => return Ok(()),
        };
        let keys = self
            .session
            .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(id.clone())])
            .map_err(ck("C_FindObjects"))?;
        if keys.len() > 1 {
            return Err(KmError::Ambiguous(
                format!(
                    "{} private keys on token '{}' share CKA_ID {}; a consumer selecting by ID may use another key",
                    keys.len(),
                    self.name,
                    pct_all(&id)
                )
                .into(),
            ));
        }
        Ok(())
    }

    /// The `CKA_ID` of the key `loc` finds, if it has a non-empty one (`None` too when nothing
    /// is found: call it on an object a check has just verified).
    ///
    /// # Errors
    ///
    /// As [`Token::find_key`], or when the module cannot read the attribute.
    pub fn key_id(&self, object: &ObjectCfg, loc: &Locator, public_only: bool) -> Result<Option<Vec<u8>>> {
        let Some(h) = self.find_key(object, loc, public_only)? else { return Ok(None) };
        Ok(match self.attr(h, AttributeType::Id)? {
            Some(Attribute::Id(id)) if !id.is_empty() => Some(id),
            _ => None,
        })
    }

    fn attr(&self, h: ObjectHandle, t: AttributeType) -> Result<Option<Attribute>> {
        Ok(self.session.get_attributes(h, &[t]).map_err(ck("C_GetAttributeValue"))?.into_iter().next())
    }

    /// `h`'s attribute `t` where it can be read ([`if_readable`]).
    fn attr_if_readable(&self, h: ObjectHandle, t: AttributeType) -> Result<Option<Attribute>> {
        if_readable(self.session.get_attributes(h, &[t]).map(|a| a.into_iter().next()))
    }
}

/// Why `token` would not create the trusted copy of a transport key: the module's refusal `e`,
/// its return value kept for code to match on (Q3).
fn trusted_copy_refused(token: &str, e: &CkError) -> Msg {
    Msg::from(format!("token '{token}' will not create a CKA_TRUSTED RSA public key: {e}")).with_rv(rv_of(e))
}

/// The one slot whose token is labelled `label`, with what `C_GetTokenInfo` says of it.
struct FoundSlot {
    slot: cryptoki::slot::Slot,
    token: TokenInfo,
    pins: PinState,
    write_protected: bool,
}

/// [`FoundSlot`] for `label`, and `serial` when given, among the module's slots with a token.
///
/// # Errors
///
/// `Ambiguous` when several match, naming their serials; `Unavailable` when none does or a
/// `C_*` call fails.
fn find_slot(ctx: &Pkcs11, label: &str, serial: Option<&str>, module_path: &str) -> Result<FoundSlot> {
    let mut found: Vec<FoundSlot> = Vec::new();
    for slot in ctx.get_slots_with_token().map_err(ck("C_GetSlotList"))? {
        let info = ctx.get_token_info(slot).map_err(ck("C_GetTokenInfo"))?;
        if info.label() != label || serial.is_some_and(|s| info.serial_number().trim() != s) {
            continue;
        }
        found.push(FoundSlot {
            slot,
            token: TokenInfo {
                model: info.model().trim().to_owned(),
                serial: info.serial_number().trim().to_owned(),
                firmware: info.firmware_version().to_string(),
            },
            pins: PinState {
                user: Pin {
                    locked: info.user_pin_locked(),
                    final_try: info.user_pin_final_try(),
                    count_low: info.user_pin_count_low(),
                },
                so: Pin {
                    locked: info.so_pin_locked(),
                    final_try: info.so_pin_final_try(),
                    count_low: info.so_pin_count_low(),
                },
            },
            write_protected: info.write_protected(),
        });
    }
    let named = match serial {
        Some(s) => format!("token '{label}' with serial '{s}'"),
        None => format!("token '{label}'"),
    };
    match found.len() {
        0 => Err(KmError::Unavailable(format!("{named} not present in {module_path}").into())),
        1 => Ok(found.remove(0)),
        _ => Err(KmError::Ambiguous(
            format!(
                "several tokens labelled '{label}' (serials {}); name one with tokenSerial",
                found.iter().map(|f| format!("'{}'", f.token.serial)).collect::<Vec<_>>().join(", ")
            )
            .into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;

    /// Every layer's subtraction applies, the binding layer's too when no module profile is
    /// resolved (token/mod.rs F7): a generic module loses what the binding cannot do, as a
    /// profiled one does.
    #[test]
    fn the_binding_layer_subtracts_without_a_module_profile() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let mut layer = cakeys_profile::Profile::new("binding".into(), cakeys_profile::Mode::Delta);
        layer.subtract.mechanisms = vec!["CKM_SHA_1".into(), "CKM_SHA256".into()];
        let profiles = crate::resolution::Resolved { layers: vec![layer], ..Default::default() };
        let advertised = [MechanismType::AES_KEY_WRAP, MechanismType::SHA256, MechanismType::SHA1];
        assert_eq!(usable_mechanisms(&advertised, &profiles).unwrap(), [MechanismType::AES_KEY_WRAP]);
        let none = crate::resolution::Resolved::default();
        assert_eq!(usable_mechanisms(&advertised, &none).unwrap(), advertised);
    }

    /// The module's refusal of a trusted copy keeps its return value (token/mod.rs F4), which
    /// `Token::unsupported` carries past a provider's hint.
    #[test]
    fn a_refused_trusted_copy_keeps_its_return_value() {
        let e = CkError::Pkcs11(RvError::VendorDefined(0x8000_0001), Function::CreateObject);
        let m = trusted_copy_refused("hsm", &e);
        assert_eq!(m.rv(), Some(0x8000_0001));
        assert!(m.contains("token 'hsm' will not create a CKA_TRUSTED RSA public key"), "{m}");
    }
}
