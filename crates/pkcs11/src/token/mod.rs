//! The PKCS#11 token layer over `cryptoki`. The layer is transparent: it takes PKCS#11 names as
//! input and makes the PKCS#11 calls with them. Behaviour that is specific to one module goes
//! through the selected [`Provider`].

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
use cakeys_core::{Check, KmError, Reason, Result};
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
pub use library::unpadded;
use library::{Library, Logins, library, module_info};
pub use login::has_admin;
use login::{Pin, PinState, read_pin, session};
pub use policy::bool_attr;
pub use possession::{
    Derived, OAEP, ProofSide, derive_any, digest_info, is_policy_default, oaep_of, oaep_params, proof_refusal, show,
    template_refusal,
};
pub use public::{public_key_attrs, public_object_attrs};
pub use rv::{
    SO_LOGIN, device_failed, device_failed_rv, read_attribute, refused_unless_device, rv_is, rv_name, rv_of, rv_value,
    rv_value_name,
};
use rv::{ck, if_readable};
use types::managed_class;
pub use types::{class_of, hmac_key_gen, key_type_of, secret_key_gen};
use uri::pct_all;
pub use uri::{PinRef, locator_attrs, pin_ref, provider_pem, with_query};

/// The kind of session that a verb opens (M1, docs/archive/REVIEW-2026-11-11.md). The verbs that
/// only read open a read-only session, because a write-protected token (`CKF_WRITE_PROTECTED`)
/// refuses read-write sessions, and because the session objects that a read needs (a key-wrap
/// copy, an ECDH secret) are allowed in a read-only session. A verb opens a read-write session
/// only to create or destroy objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// A read-only session, for the verbs that only read.
    Read,
    /// A read-write session, to create or destroy objects.
    Write,
    /// A session that reads and also makes session objects (a key-wrap copy, a KEK). It is
    /// read-write where the token allows it, because AWS `CloudHSM` refuses even a session object
    /// in a read-only session (`CKR_SESSION_READ_ONLY` \[run\]). It is read-only on a
    /// write-protected token.
    Scratch,
    /// The dry run of a write (`create --dry-run`, `delete --dry-run`, and camigrate's dry run
    /// into a token). The session is read-only, so the dry run writes nothing. The dry run opens
    /// only a token that [`Access::Write`] would open, so it refuses a write-protected token as
    /// the real run does (exit 15; review 2026-11-24 L4a-3: the dry runs once opened with
    /// [`Access::Read`] and passed such a token).
    DryWrite,
}

/// An open token: its module and the session that cakeys works in, with the provider that
/// handles the module and the mechanisms that cakeys may rely on.
pub struct Token {
    /// The token's name in keys.toml.
    pub name: String,
    /// The label that the token reports (`CK_TOKEN_INFO.label`).
    pub(crate) label: String,
    /// What the module reports about itself, and the file that was loaded.
    pub module: ModuleInfo,
    /// What the token reports about itself.
    pub token: TokenInfo,
    /// The usable mechanisms (`usable_mechanisms`): the mechanisms that the module advertises,
    /// minus the mechanisms that the resolved capability profiles subtract (the module profile's
    /// rows for mechanisms that are advertised but broken, and the subtractions of every layer),
    /// or else minus the mechanisms that the provider's override drops.
    pub mechanisms: Vec<MechanismType>,
    /// The list that `C_GetMechanismList` returned, unchanged. [`Token::unprofiled`] filters it
    /// again, and [`Token::advertised`] returns its names.
    listed: Vec<MechanismType>,
    /// The range of key sizes for RSA key-pair generation, as `C_GetMechanismInfo` reports it,
    /// when the module advertises `CKM_RSA_PKCS_KEY_PAIR_GEN`. The probe reports these bounds.
    pub rsa_bits: Option<(u64, u64)>,
    /// The provider that handles the module.
    pub provider: Arc<dyn Provider>,
    /// The resolved capability profiles (docs/CAPROBE.md): the module profile and the delta
    /// layers between cakeys and the module profile, with the notes that the resolution
    /// collected.
    pub profiles: crate::resolution::Resolved,
    session: Session,
    /// The slot that holds the token, for a second session ([`Token::extra_session`]).
    slot: cryptoki::slot::Slot,
    /// Whether the session is logged in as the user, so that private objects are visible. When
    /// it is `false`, the session is a public session.
    pub logged_in: bool,
    /// The token's configuration, for provider hooks that need more than the module, such as
    /// the `options` of the native TPM attestation path (`tcti`, `tpm2Store` and `akHandle`).
    pub cfg: TokenCfg,
    /// The PIN counters as they were when the token was opened. They are checked before every
    /// login (M2).
    pins: PinState,
    /// Whether an SO login on this token was refused. After a refusal, the counters read at the
    /// open no longer show how many retries are left, so the credential is not tried again
    /// (review 2026-11-23 B-11).
    so_refused: std::sync::atomic::AtomicBool,
    /// Whether a step runs in the SO session now ([`Token::as_so`]). A nested step then runs in
    /// the same SO session, without another login.
    in_so: std::sync::atomic::AtomicBool,
    /// The user credential, which was already read for the login. It is kept for the steps that
    /// need it again: the context-specific login of a `CKA_ALWAYS_AUTHENTICATE` proof, the TPM
    /// attestation path (which unseals the token's wrapping key with it), and the user's login
    /// again after an SO step (`soCredentialFile` or `soCredentialEnv`). It is zeroized on drop.
    pin: Option<Zeroizing<String>>,
    /// The time at which the certificates of an attestation chain must be valid, as the caller
    /// of the open specified it ([`crate::ChainTime`]).
    chain_time: crate::ChainTime,
    /// This field is last because fields are dropped in declaration order, so the session is
    /// closed before the module is finalized.
    library: Arc<Library>,
}

/// Returns the mechanisms that a token may be relied on for. These are the mechanisms that the
/// module lists, minus the mechanisms that the resolved profile stack subtracts (the module
/// profile's rows for mechanisms that are advertised but broken, and the subtractions of every
/// layer). The stack can also add a mechanism that the module does not list: a provider's
/// stand-in that the probe found working (`Provider::stand_in`). Every layer subtracts, including
/// the binding layer when no module profile is resolved (token/mod.rs F7). A subtraction matches a
/// mechanism by its one canonical name ([`policy::mechanism_namer`]), and a mechanism that
/// cryptoki does not name gets its name from the baseline.
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

/// Returns the `CKM_*` names of `mechanisms`, sorted, which is the form in which the lock, a
/// profile and `caps` list them.
fn sorted_names(mechanisms: &[MechanismType]) -> Vec<String> {
    let mut names: Vec<String> = mechanisms.iter().map(ToString::to_string).collect();
    names.sort();
    names
}

/// A session object that cakeys made for one step (a derived secret, a key-encryption key, or a
/// wrap-rebind copy). The object is destroyed when this value is dropped, whatever the step
/// returned. A failed destroy is not an error, because the module destroys a session object when
/// its session closes.
pub struct SessionObject<'a> {
    session: &'a Session,
    handle: ObjectHandle,
}

impl<'a> SessionObject<'a> {
    /// Wraps `handle`, an object of `session`, so that the object is destroyed on drop.
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
    /// The number of objects that a creation there would collide with.
    pub colliding: usize,
    /// A public key object that holds the key's public key. The import reuses it instead of
    /// creating another one.
    pub public_half: Option<ObjectHandle>,
}

impl Token {
    /// Places what the lock recorded about this token (`observed`) above its module profile, as
    /// the static gate does ([`crate::gate::stack`]). The answers that this token's own runs
    /// demonstrated take precedence over what a shipped profile says about this kind of module
    /// (ISSUES.md B18). The function applies only an observation of the same module and token
    /// that this open found, because answers recorded on another module or token say nothing
    /// about this one.
    pub fn with_answers(&mut self, observed: &cakeys_core::config::Observation) {
        if observed.module.as_ref() == Some(&self.module) && observed.token.as_ref() == Some(&self.token) {
            self.profiles.with_answers(&self.name, observed);
        }
    }

    /// Opens the token named `name`. It loads the module, finds the slot whose token label
    /// matches, reads the token's capabilities, and logs in as the user when a PIN is configured.
    ///
    /// Tokens of one module that are open at the same time share the module's library. The first
    /// open initializes the library, and the drop of the last token (or a failed open, when it
    /// was the only one) finalizes it.
    ///
    /// # Errors
    ///
    /// - `Validation` for a token with no module, an unknown provider, options that the provider
    ///   refuses, or an admin credential on a provider that creates objects as the user.
    /// - `Ambiguous` when several slots carry the label.
    /// - `Unavailable` when no slot carries the label, when the module cannot be loaded, when any
    ///   `C_*` call fails, or when the PIN (from an environment variable or a file) cannot be
    ///   read.
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
        // From here on, every return releases the library, including the return of a failed
        // open. The library is finalized with its last token.
        let module_guard = library(&module)?;
        let ctx = &module_guard.0;
        let module = module_info(ctx, module)?;
        let provider = registry.select(cfg.named_provider(), &module)?;
        provider.check_options(name, &cfg.options)?;
        let FoundSlot { slot, token, pins, write_protected } =
            find_slot(ctx, &cfg.token_label, cfg.token_serial.as_deref(), &module.path)?;
        // Resolve the capability profiles (docs/CAPROBE.md). The module profile follows the
        // provider (D9). The binding layer is always in the stack, together with a forwarder that
        // the module names and the extra profiles of the configuration. The mechanisms that the
        // stack subtracts are removed from the advertised list, and a token with no resolved
        // profile keeps the provider's own filter.
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

    /// Returns an `Unsupported` error with `msg`, which keeps the return value that `msg`
    /// carries, and with no advice from the provider.
    pub fn unsupported(&self, msg: impl Into<Msg>) -> KmError {
        KmError::Unsupported(msg.into())
    }

    /// Works as [`Self::unsupported`], and adds the provider's advice on `about` if the provider
    /// has any.
    pub fn unsupported_for(&self, about: Topic, msg: impl Into<Msg>) -> KmError {
        self.provider.hinted(about, KmError::Unsupported(msg.into()))
    }

    /// Turns the module's failed call `e` into the error of [`Self::unsupported_for`], which
    /// carries the call's return value. A failure of the device, the token or the session becomes
    /// `Unavailable` instead ([`refused_unless_device`]).
    pub fn refused_for(&self, about: Topic, e: &CkError, msg: impl Into<Msg>) -> KmError {
        refused_unless_device(msg.into().with_rv(rv_of(e)), |m| self.unsupported_for(about, m))
    }

    /// Returns a warning for the run when the user PIN counters at the open reported a failed
    /// login (`CKF_USER_PIN_COUNT_LOW`) and cakeys logged in. It is only a warning and not a
    /// refusal, because retries remain.
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

    /// Returns the session itself, for raw `C_*` calls. caprobe's probes use it to test what the
    /// module does beyond what the verbs ask of it. The verbs use the methods above instead.
    #[must_use]
    pub fn raw(&self) -> &Session {
        &self.session
    }

    /// Opens a second session on the token, for a step that the module refuses in the verb's own
    /// session. An example is a proof by derivation for a read-only verb on tpm2-pkcs11, which
    /// stores derived secrets as rows in its store and therefore derives only in a read-write
    /// session \[run\]. The login state belongs to the token and is shared by every session of
    /// the process, and object handles are valid in all of these sessions (PKCS#11 base §5.6).
    /// The second session therefore needs no login, and it finds the same key.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the module refuses another session (`C_OpenSession`).
    pub fn extra_session(&self, access: Access) -> Result<Session> {
        let ctx = &self.library.0;
        match access {
            Access::Read | Access::DryWrite => ctx.open_ro_session(self.slot).map_err(ck("C_OpenSession (read-only)")),
            Access::Scratch if ctx.get_token_info(self.slot).is_ok_and(|i| i.write_protected()) => {
                ctx.open_ro_session(self.slot).map_err(ck("C_OpenSession (read-only)"))
            }
            Access::Write | Access::Scratch => ctx.open_rw_session(self.slot).map_err(ck("C_OpenSession")),
        }
    }

    /// Returns whether the token may be relied on for mechanism `m`, after the filtering of
    /// `mechanisms`.
    pub fn has(&self, m: MechanismType) -> bool {
        self.mechanisms.contains(&m)
    }

    /// Returns the mechanism to run for `m`. This is `m` itself when the module lists it.
    /// Otherwise, it is the provider's stand-in for `m` (`Provider::stand_in`, for example AWS
    /// `CloudHSM`'s Ed25519), or `m` when the provider has no stand-in.
    #[must_use]
    pub fn runnable<'a>(&self, m: Mechanism<'a>) -> Mechanism<'a> {
        if self.listed.contains(&m.mechanism_type()) { m } else { self.provider.stand_in(&m).unwrap_or(m) }
    }

    /// Returns the template of the session key `key` ([`templates::session`]), as the provider
    /// adjusts it.
    ///
    /// # Errors
    ///
    /// The provider's refusal.
    pub fn session_template(&self, key: SessionKey) -> Result<Vec<Attribute>> {
        self.provider.adjusted_session(templates::session(key))
    }

    /// Returns the key type of `h` as a module that follows the specification would report it.
    /// The value is `CKA_KEY_TYPE`, which the provider corrects from `CKA_EC_PARAMS`
    /// (`Provider::key_type`). Returns `None` when the object has no key type.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the module refuses `C_GetAttributeValue`.
    pub fn key_type(&self, h: ObjectHandle) -> Result<Option<KeyType>> {
        self.key_type_by(|t| self.attr(h, t))
    }

    /// Works as [`Self::key_type`], but returns `None` when the module refuses to read an
    /// attribute ([`if_readable`]).
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

    /// Returns the provider's attestation capability for the class of `object`, for a spec that
    /// opted in. Returns `None` when this module attests nothing, or nothing of this class.
    pub fn attestation_cap(&self, object: &ObjectCfg) -> Option<AttestationCap> {
        self.provider.attestation().filter(|cap| cap.classes.contains(&object.class))
    }

    /// Computes the attestation for `key` through the provider (§3.7 of docs/DESIGN.md). The
    /// provider uses the attestation certificate that the module exposes (PIV) or the native
    /// `TPM2_Certify` path (tpm2-pkcs11), and the host verifies the result. `spki` is the material
    /// SPKI that the attestation must name (`None` for a secret key). `commitments` holds what a
    /// secret key's attestation must be bound to instead. `provision` allows the provider to
    /// create the device state that it attests with, and only `lock` sets it.
    ///
    /// # Errors
    ///
    /// Every failure of the provider's attestation path: `Unsupported` when the provider attests
    /// no class like this one, `Unavailable` when the token has no attestation to give (for an
    /// imported key, or for a session that could not attest), and `Conflict` when the attestation
    /// names material other than `spki` or `commitments`.
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

    /// Returns every object of `class` under the locator.
    ///
    /// # Errors
    ///
    /// `Validation` when the locator names neither `CKA_LABEL` nor `CKA_ID`, or when its `CKA_ID`
    /// is not hex. `Unavailable` when `C_FindObjects` fails.
    pub fn find(&self, class: ObjectClass, loc: &Locator) -> Result<Vec<ObjectHandle>> {
        let mut template = vec![Attribute::Class(class)];
        template.extend(locator_attrs(loc)?);
        self.session.find_objects(&template).map_err(ck("C_FindObjects"))
    }

    /// Returns every object under the locator, whatever its class. This is the If-None-Match
    /// check before a generation, because a key that is generated now must not share its locator
    /// with any object that is already there.
    ///
    /// # Errors
    ///
    /// `Validation` for a locator that names neither `CKA_LABEL` nor `CKA_ID`, or that has a
    /// `CKA_ID` that is not hex. `Unavailable` when `C_FindObjects` fails.
    pub fn find_any(&self, loc: &Locator) -> Result<Vec<ObjectHandle>> {
        self.session.find_objects(&locator_attrs(loc)?).map_err(ck("C_FindObjects"))
    }

    /// Looks up the objects that the SO marked `CKA_TRUSTED` on this token (docs/CAMIGRATE.md D2,
    /// `enforced`). Returns the public key object that holds `spki` (the trusted copy of the
    /// transport key) and the number of other trusted objects. The number matters because an
    /// `enforced` move allows a wrap with any trusted key on the token, so the move is only as
    /// restricted as the token's whole set of trusted objects.
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

    /// Creates the trusted copy of a transport key on this token (`camigrate transport
    /// --trust-on`). The copy is an RSA public token object with `modulus`, `exponent` and the
    /// label `label`. It may wrap, and it is marked `CKA_TRUSTED`, which only the SO can set, and
    /// only at creation.
    ///
    /// # Errors
    ///
    /// Every refusal of [`Self::as_so`]. `Unsupported` when the module does not create the object
    /// with `CKA_TRUSTED`.
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
                .map_err(|e| self.refused_for(Topic::Create, &e, trusted_copy_refused(&self.name, &e)))
        })
    }

    /// The If-None-Match check before an import of `object` under `loc`, which depends on the
    /// class. The PKCS#11 convention puts a key, its public key and its certificate under one
    /// `CKA_ID` (and often under one `CKA_LABEL`). So only the objects that the creation would
    /// collide with count: an object of the same class and, for a private key, any public key
    /// object that does not hold `spki`. A public key object that holds `spki` is not a
    /// collision. It is the public half, which the import reuses; for the import of a public key
    /// object, it is the object itself, which is already there. When `spki` is `None` (not known
    /// yet), no public key object counts as holding it.
    ///
    /// # Errors
    ///
    /// `Validation` for a locator that names neither `CKA_LABEL` nor `CKA_ID`, or that has a
    /// `CKA_ID` that is not hex. `Unavailable` when `C_FindObjects` fails.
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

    /// Looks up the one object that the locator names: the key (private or secret) or the
    /// certificate, or the public key object when the object is adopted with `publicOnly`.
    /// Returns `None` when no object matches.
    ///
    /// # Errors
    ///
    /// `Ambiguous` when several objects match the locator. Every error of `find`.
    pub fn find_key(&self, object: &ObjectCfg, loc: &Locator, public_only: bool) -> Result<Option<ObjectHandle>> {
        let class = if public_only { ObjectClass::PUBLIC_KEY } else { class_of(object) };
        let found = self.find(class, loc)?;
        match found.len() {
            0 => Ok(None),
            1 => Ok(Some(found[0])),
            n => Err(KmError::Ambiguous(Reason::check(
                Check::LocatorUnique,
                format!("{n} objects match locator {loc} on token '{}'", self.name),
            ))),
        }
    }

    /// Refuses when another private key shares the `CKA_ID` of `h`. A consumer that selects a key
    /// by `CKA_ID` must find exactly this key; for example, OpenSSH takes the first private key
    /// with the ID of the certificate or of the public key. Only a logged-in session can see
    /// private keys, so a public session checks nothing, and the lock records which kind of
    /// session it was.
    ///
    /// # Errors
    ///
    /// `Ambiguous` (exit 12) when another private key on the token shares the `CKA_ID`.
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
            return Err(KmError::Ambiguous(Reason::check(
                Check::CkaIdUnique,
                format!(
                    "{} private keys on token '{}' share CKA_ID {}; a consumer selecting by ID may use another key",
                    keys.len(),
                    self.name,
                    pct_all(&id)
                ),
            )));
        }
        Ok(())
    }

    /// Returns the `CKA_ID` of the key that `loc` finds, if the key has a non-empty one. It also
    /// returns `None` when nothing is found, so call it only on an object that a check has just
    /// verified.
    ///
    /// # Errors
    ///
    /// The errors of [`Token::find_key`], and an error when the module cannot read the attribute.
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

    /// Returns the attribute `t` of `h`, or `None` when the module refuses to read it
    /// ([`if_readable`]).
    fn attr_if_readable(&self, h: ObjectHandle, t: AttributeType) -> Result<Option<Attribute>> {
        if_readable(self.session.get_attributes(h, &[t]).map(|a| a.into_iter().next()))
    }
}

/// Returns the message for the refusal `e` of `token` to create the trusted copy of a transport
/// key. The message keeps the return value of `e`, so that code can match on it (Q3).
fn trusted_copy_refused(token: &str, e: &CkError) -> Msg {
    Msg::from(format!("token '{token}' will not create a CKA_TRUSTED RSA public key: {e}")).with_rv(rv_of(e))
}

/// The one slot whose token carries the requested label, with what `C_GetTokenInfo` reports
/// about the token.
struct FoundSlot {
    slot: cryptoki::slot::Slot,
    token: TokenInfo,
    pins: PinState,
    write_protected: bool,
}

/// Returns the token as `C_GetTokenInfo` describes it, with its fixed-width fields converted to
/// text ([`unpadded`]). The lock records this value, and a module profile's match keys are
/// compared with it.
pub(crate) fn token_info(model: &str, serial: &str, firmware: String) -> TokenInfo {
    TokenInfo { model: unpadded(model), serial: unpadded(serial), firmware }
}

/// Finds the [`FoundSlot`] whose token has the label `label` and, when `serial` is given, that
/// serial number, among the module's slots that hold a token.
///
/// # Errors
///
/// `Ambiguous` when several tokens match; the message names their serial numbers. `Unavailable`
/// when no token matches or when a `C_*` call fails.
fn find_slot(ctx: &Pkcs11, label: &str, serial: Option<&str>, module_path: &str) -> Result<FoundSlot> {
    let mut found: Vec<FoundSlot> = Vec::new();
    for slot in ctx.get_slots_with_token().map_err(ck("C_GetSlotList"))? {
        let info = ctx.get_token_info(slot).map_err(ck("C_GetTokenInfo"))?;
        if info.label() != label || serial.is_some_and(|s| unpadded(info.serial_number()) != s) {
            continue;
        }
        found.push(FoundSlot {
            slot,
            token: token_info(info.model(), info.serial_number(), info.firmware_version().to_string()),
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
        _ => Err(KmError::Ambiguous(Reason::check(
            Check::TokenUnique,
            format!(
                "several tokens labelled '{label}' (serials {}); name one with tokenSerial",
                found.iter().map(|f| format!("'{}'", f.token.serial)).collect::<Vec<_>>().join(", ")
            ),
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;

    /// The subtraction of every layer applies, including the binding layer's when no module
    /// profile is resolved (token/mod.rs F7). A generic module therefore loses the mechanisms
    /// that the binding cannot use, as a module with a profile does.
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

    /// The module's refusal of a trusted copy keeps its return value (token/mod.rs F4), and the
    /// `Unsupported` error that `Token::unsupported` builds still carries that value after the
    /// provider adds its hint.
    #[test]
    fn a_refused_trusted_copy_keeps_its_return_value() {
        let e = CkError::Pkcs11(RvError::VendorDefined(0x8000_0001), Function::CreateObject);
        let m = trusted_copy_refused("hsm", &e);
        assert_eq!(m.rv(), Some(0x8000_0001));
        assert!(m.contains("token 'hsm' will not create a CKA_TRUSTED RSA public key"), "{m}");
    }
}
