//! PKCS#11 token layer over `cryptoki`. Transparent: PKCS#11 names in, PKCS#11 calls out.
//! Module-specific behaviour goes through the selected [`Provider`].

use crate::provider::{
    AttestCtx, AttestationCap, Attested, Create, Destroy, Generation, Provider, Registry, keygen_mechanism,
};
use cakeys_core::attrs;
use cakeys_core::config::{AttrValue, Binding, Locator, Mode, ObjectCfg, SpecCfg, TokenCfg};
pub use cakeys_core::config::{Immutables, ModuleInfo, TokenInfo};
use cakeys_core::id::{self, BlockCipher, Commit, Curve, HmacHash, Scheme};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as CkError, RvError};
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
mod policy;
mod possession;
mod uri;

pub use generate::{BY_NAME, with_public_default_dropped};
pub use identity::commit_mechanism;
pub use policy::bool_attr;
pub use possession::{Derived, ProofSide, derive_any, is_policy_default, proof_refusal, show, template_refusal};
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

/// The PIN counters `C_GetTokenInfo` reports (M2): a login on the final try or a locked PIN is
/// refused before it is attempted, so a wrong PIN file never spends the last retry (PIV allows
/// few).
#[derive(Debug, Clone, Copy, Default)]
struct PinState {
    user: Pin,
    so: Pin,
}

/// One PIN's counters.
#[derive(Debug, Clone, Copy, Default)]
struct Pin {
    locked: bool,
    final_try: bool,
    /// A login failed since the last success, but retries remain: a warning, never a refusal.
    count_low: bool,
}

impl Pin {
    /// Refuse a login as `who` (user or SO) the counters say must not be tried.
    fn guard(self, token: &str, who: &str) -> Result<()> {
        let Pin { locked, final_try, .. } = self;
        if locked {
            return Err(KmError::Unavailable(format!(
                "token '{token}': the {who} PIN is locked (CKF_{}_PIN_LOCKED); unlock it with the vendor's tools",
                who.to_uppercase()
            )));
        }
        if final_try {
            return Err(KmError::Unavailable(format!(
                "token '{token}': one {who} PIN try is left before it locks (CKF_{}_PIN_FINAL_TRY); cakeys will \
                 not spend it on a PIN file that may be wrong — log in once by hand with the right PIN to reset \
                 the counter",
                who.to_uppercase()
            )));
        }
        Ok(())
    }
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
    /// Their names, sorted: what the lock records and `caps` prints.
    mechanism_names: Vec<String>,
    /// What `C_GetMechanismList` returned, sorted: the drift baseline the probe records as
    /// a profile's `advertise` list (D2).
    pub advertised: Vec<String>,
    /// The same list, as the module returned it: what [`Token::unprofiled`] filters anew.
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
    /// The user credential, already read for login, kept for what needs it again: the
    /// context-specific login of a `CKA_ALWAYS_AUTHENTICATE` proof, the TPM attestation path
    /// (it unseals the token's wrapping key with it) and logging the user back in after an SO
    /// step (`soCredentialFile`/`soCredentialEnv`). Zeroized on drop.
    pin: Option<Zeroizing<String>>,
    /// Last: fields drop in declaration order, so the session is closed before the module is
    /// finalized.
    library: Arc<Library>,
}

/// An initialized module library, shared by every `Token` of the module open at once, and
/// finalized when the last of them is dropped (cryptoki 0.12 never finalizes): a module library
/// may stay loaded after its last handle is gone (`SoftHSM` does), and another of its tokens
/// opened later in the process would then fail `C_Initialize` with
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
///
/// Finalized, the module stays mapped until the process exits: a module's own threads may still
/// be winding down when `C_Finalize` returns, and unloading under them crashes the process after
/// its work is done (libkmsp11's gRPC threads \[run\], about one run in twenty, exit 139 in place of
/// the run's own code). Opening the module again maps the same library and initializes it anew.
struct Library(Pkcs11);

impl Drop for Library {
    fn drop(&mut self) {
        let _ = self.0.clone().finalize();
        std::mem::forget(self.0.clone());
    }
}

/// The libraries this process initialized, by module path: a token of a module another open
/// token already initialized (the two sides of a move between tokens of one module) shares its
/// library rather than initializing it a second time.
static LIBRARIES: std::sync::Mutex<BTreeMap<String, std::sync::Weak<Library>>> = std::sync::Mutex::new(BTreeMap::new());

/// The initialized library of `module`: the one an open token holds, else newly loaded and
/// initialized.
fn library(module: &str) -> Result<Arc<Library>> {
    let mut open = LIBRARIES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(library) = open.get(module).and_then(std::sync::Weak::upgrade) {
        return Ok(library);
    }
    let ctx = Pkcs11::new(module).map_err(ck(&format!("loading {module}")))?;
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).map_err(ck("C_Initialize"))?;
    let library = Arc::new(Library(ctx));
    open.insert(module.to_owned(), Arc::downgrade(&library));
    Ok(library)
}

/// The mechanisms a token may rely on: what the module lists, less what the resolved stack
/// subtracts (the module profile's advertised-but-broken rows and every layer's), plus what it
/// adds although the module does not list it (a provider's stand-in the probe found working,
/// `Provider::stand_in`). With no module profile and only the binding layer, the list itself.
fn usable_mechanisms(
    advertised: &[MechanismType],
    profiles: &crate::resolution::Resolved,
) -> Result<Vec<MechanismType>> {
    if profiles.module.is_none() && profiles.layers.len() <= 1 {
        return Ok(advertised.to_vec());
    }
    let subtracted = profiles.subtracted_mechanisms();
    let mut usable: Vec<MechanismType> =
        advertised.iter().copied().filter(|m| !subtracted.contains(m.to_string().as_str())).collect();
    let baseline = cakeys_profile::Set::active().and_then(|s| s.baseline()).map_err(KmError::Validation)?;
    for name in profiles.added_mechanisms() {
        let id = baseline.mechanisms.get(name).and_then(|id| MechanismType::try_from(*id).ok());
        if let Some(m) = id.filter(|m| !usable.contains(m)) {
            usable.push(m);
        }
    }
    Ok(usable)
}

/// The `CKR_*` name of a module's failure: cryptoki's `Display` is the spec's prose, which
/// changes with the binding, so a message (and a profile row's evidence) names the return value
/// by its constant. From `RvError`'s variant (`GeneralError` -> `CKR_GENERAL_ERROR`).
#[must_use]
pub fn rv_name(e: &CkError) -> String {
    match e {
        CkError::Pkcs11(RvError::VendorDefined(rv) | RvError::UnknownErrorCode(rv), _) => format!("CKR {rv:#x}"),
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

fn ck(context: &str) -> impl FnOnce(CkError) -> KmError + '_ {
    move |e| KmError::Unavailable(format!("{context}: {e}"))
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
    ) -> Result<Token> {
        let module = match module_override {
            Some(m) => Some(m.to_owned()),
            None => cfg.module_path(name, &|var| std::env::var(var).ok())?,
        }
        .ok_or_else(|| KmError::Validation(format!("token '{name}' has no module (set module, or pass --module)")))?;
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
        let profiles =
            crate::resolution::resolve(cfg, &module, Some(&token), provider.name()).map_err(KmError::Validation)?;
        let advertised = ctx.get_mechanism_list(slot).map_err(ck("C_GetMechanismList"))?;
        let mut advertised_names: Vec<String> = advertised.iter().map(std::string::ToString::to_string).collect();
        advertised_names.sort();
        let rsa_bits = advertised
            .contains(&MechanismType::RSA_PKCS_KEY_PAIR_GEN)
            .then(|| ctx.get_mechanism_info(slot, MechanismType::RSA_PKCS_KEY_PAIR_GEN).ok())
            .flatten()
            .map(|i| (i.min_key_size() as u64, i.max_key_size() as u64));
        let mechanisms = usable_mechanisms(&advertised, &profiles)?;
        let mut mechanism_names: Vec<String> = mechanisms.iter().map(std::string::ToString::to_string).collect();
        mechanism_names.sort();
        let (session, pin) = session(ctx, slot, name, cfg, access, write_protected, pins)?;
        Ok(Token {
            name: name.to_owned(),
            label: cfg.token_label.clone(),
            module,
            token,
            mechanisms,
            mechanism_names,
            listed: advertised,
            advertised: advertised_names,
            rsa_bits,
            profiles,
            session,
            slot,
            logged_in: pin.is_some(),
            cfg: cfg.clone(),
            pins,
            pin,
            provider,
            library: module_guard,
        })
    }

    /// The token as a probe measures it: no module profile decides anything here — not its
    /// rows, nor what it subtracts from or adds to the mechanism list — so every operation asks
    /// the module itself, and an answer the profile would have given is tried instead. The
    /// layers between cakeys and the module stay: they are not the module.
    ///
    /// # Errors
    ///
    /// `Validation` when the active profile set has no baseline.
    pub fn unprofiled(mut self) -> Result<Token> {
        self.profiles.module = None;
        self.mechanisms = usable_mechanisms(&self.listed, &self.profiles)?;
        self.mechanism_names = self.mechanisms.iter().map(std::string::ToString::to_string).collect();
        self.mechanism_names.sort();
        Ok(self)
    }

    /// An `Unsupported` error carrying the provider's advice, if it has any.
    pub fn unsupported(&self, msg: String) -> KmError {
        match self.provider.hint() {
            Some(h) => KmError::Unsupported(format!("{msg} (hint for {}: {h})", self.provider.name())),
            None => KmError::Unsupported(msg),
        }
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
        let listed = self.advertised.iter().any(|a| *a == m.mechanism_type().to_string());
        if listed { m } else { self.provider.stand_in(&m).unwrap_or(m) }
    }

    /// The key type of `h` as a spec-compliant module would report it: `CKA_KEY_TYPE`, repaired
    /// by the provider from `CKA_EC_PARAMS` (`Provider::key_type`). `None`: the object has none.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the module refuses `C_GetAttributeValue`.
    pub fn key_type(&self, h: ObjectHandle) -> Result<Option<KeyType>> {
        let Some(Attribute::KeyType(kt)) = self.attr(h, AttributeType::KeyType)? else { return Ok(None) };
        let params = match kt {
            KeyType::EC => match self.attr(h, AttributeType::EcParams)? {
                Some(Attribute::EcParams(p)) => Some(p),
                _ => None,
            },
            _ => None,
        };
        Ok(Some(self.provider.key_type(kt, params.as_deref())))
    }

    /// The usable mechanisms, by `CKM_*` name.
    pub fn mechanism_names(&self) -> &[String] {
        &self.mechanism_names
    }

    /// The provider's attestation capability for `object`'s class, when the spec opted in:
    /// `None` when this module attests nothing (or not this class).
    pub fn attestation_cap(&self, object: &ObjectCfg) -> Option<AttestationCap> {
        self.provider.attestation().filter(|cap| cap.classes.contains(&object.class))
    }

    /// Compute the attestation commitment for `key` (§3.7 of docs/DESIGN.md) through the
    /// provider: the module-exposed attestation certificate (PIV) or the native `TPM2_Certify`
    /// path (tpm2-pkcs11), verified on the host. `spki` is the material SPKI the attestation
    /// must name (`None` for secret keys); `provision` lets the provider create the device
    /// state it attests with (only `lock` sets it).
    ///
    /// # Errors
    ///
    /// Whatever the provider's attestation path cannot establish: `Unsupported` when the
    /// provider attests no class like this, `Unavailable` when the token has none to give
    /// (an imported key, a session that could not attest), `Conflict` when it names other
    /// material than `spki`.
    pub fn attest(
        &self,
        key: ObjectHandle,
        object: &ObjectCfg,
        spki: Option<&[u8]>,
        provision: bool,
    ) -> Result<Attested> {
        let ctx = AttestCtx {
            session: &self.session,
            cfg: &self.cfg,
            module_version: &self.module.version,
            token_name: &self.name,
            key,
            object,
            spki,
            pin: self.pin.as_ref().map(|p| p.as_str()),
            provision,
        };
        self.provider.attest(&ctx)
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
            if copy.is_none() && self.held_spki(h).as_deref() == Some(spki) {
                copy = Some(h);
            } else {
                others += 1;
            }
        }
        Ok((copy, others))
    }

    /// Create the trusted copy of a transport key on this token (`camigrate transport
    /// --trusted`): an RSA public token object of `modulus` and `exponent`, labelled `label`,
    /// that may wrap, marked `CKA_TRUSTED` — which only the SO can set, and only at creation.
    ///
    /// # Errors
    ///
    /// Whatever [`Self::as_so`] refuses; `Unsupported` when the module will not create it
    /// trusted.
    pub fn create_trusted_copy(&self, modulus: Vec<u8>, exponent: Vec<u8>, label: &str) -> Result<ObjectHandle> {
        let template = [
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
        ];
        self.as_so("marking the transport key trusted", || {
            self.session.create_object(&template).map_err(|e| {
                self.unsupported(format!("token '{}' will not create a CKA_TRUSTED RSA public key: {e}", self.name))
            })
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
                    Some(s) if out.public_half.is_none() && self.held_spki(p).as_deref() == Some(s) => {
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
            n => Err(KmError::Ambiguous(format!("{n} objects match locator {loc} on token '{}'", self.name))),
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
            return Err(KmError::Ambiguous(format!(
                "{} private keys on token '{}' share CKA_ID {}; a consumer selecting by ID may use another key",
                keys.len(),
                self.name,
                pct_all(&id)
            )));
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

    /// Run `step` in a Security Officer session (`soCredentialFile`/`soCredentialEnv`), for modules that
    /// create and destroy objects only as SO, then return to the user session. Login state is
    /// per token, so the user is logged out first. The admin credential is read here, never at
    /// open, and zeroized when the step ends.
    ///
    /// # Errors
    ///
    /// `Unsupported` without an admin credential configured; `Unavailable` when the SO login,
    /// the logout or the return to the user session fails, or the PIN counters refuse a login;
    /// else whatever `step` returns.
    pub fn as_so<T>(&self, what: &str, step: impl FnOnce() -> Result<T>) -> Result<T> {
        let so = read_mgm(&self.cfg)?.ok_or_else(|| {
            self.unsupported(format!(
                "{what} on '{}' needs a Security Officer session: set tokens.{}.soCredentialFile or soCredentialEnv",
                self.name, self.name
            ))
        })?;
        self.pins.so.guard(&self.name, "SO")?;
        if self.logged_in {
            self.session.logout().map_err(ck("C_Logout"))?;
        }
        let out = match self.session.login(UserType::So, Some(&AuthPin::new(so.as_str().to_owned().into()))) {
            Ok(()) => {
                let out = step();
                let logout = self.session.logout().map_err(ck("C_Logout (SO)"));
                out.and_then(|v| logout.map(|()| v))
            }
            Err(e) => Err(KmError::Unavailable(format!(
                "C_Login (SO) with soCredentialFile/soCredentialEnv: {e}; it must hold the module's admin \
                 credential (the SO PIN; ykcs11: the PIV management key in hex, or the PIN on a \
                 device whose management key is PIN-protected)"
            ))),
        };
        drop(so);
        if self.logged_in {
            let pin =
                self.pin.as_deref().ok_or_else(|| KmError::Unavailable("no user PIN to log back in with".into()))?;
            match self.session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
                Err(e) => return Err(KmError::Unavailable(format!("C_Login (back to the user): {e}"))),
            }
        }
        out
    }
}

/// What a module says about itself (`C_GetInfo`), and the file the loader mapped for `module` with
/// its hash: the lock's module provenance.
fn module_info(ctx: &Pkcs11, module: String) -> Result<ModuleInfo> {
    let lib = ctx.get_library_info().map_err(ck("C_GetInfo"))?;
    let path = loaded_path(&module).unwrap_or(module);
    Ok(ModuleInfo {
        hash: std::fs::read(&path).ok().map(|bytes| id::sri(&bytes)),
        path,
        description: lib.library_description().trim().to_owned(),
        manufacturer: lib.manufacturer_id().trim().to_owned(),
        version: lib.library_version().to_string(),
        cryptoki: lib.cryptoki_version().to_string(),
    })
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
        0 => Err(KmError::Unavailable(format!("{named} not present in {module_path}"))),
        1 => Ok(found.remove(0)),
        _ => Err(KmError::Ambiguous(format!(
            "several tokens labelled '{label}' (serials {}); name one with tokenSerial",
            found.iter().map(|f| format!("'{}'", f.token.serial)).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// The file the dynamic loader mapped for `module`, symlinks resolved — what the lock records as
/// provenance, whatever named it: a bare file name (the loader's library search), a
/// `/run/current-system` symlink or a store path. Asked of the loader itself (`dladdr` on the
/// module's `C_GetFunctionList`), so it is the file whose code runs. `None` if it cannot tell.
#[expect(unsafe_code, reason = "dlopen(RTLD_NOLOAD)/dlsym/dladdr only look up the loaded module")]
fn loaded_path(module: &str) -> Option<String> {
    let name = std::ffi::CString::new(module).ok()?;
    // SAFETY: a valid NUL-terminated name; RTLD_NOLOAD returns the library `Pkcs11::new` already
    // loaded (adding a reference, released below) and never loads or initializes anything.
    let handle = unsafe { libc::dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    if handle.is_null() {
        return None;
    }
    // SAFETY: `handle` is a live handle and the symbol name NUL-terminated; the address is only
    // looked up, never called.
    let symbol = unsafe { libc::dlsym(handle, c"C_GetFunctionList".as_ptr()) };
    // SAFETY: an all-zero `Dl_info` is valid (null pointers); `dladdr` fills it for `symbol`.
    let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
    // SAFETY: as above; `dli_fname` is a NUL-terminated string owned by the loader, copied out
    // before the handle is released (and the module stays loaded through cryptoki's handle).
    let file = (!symbol.is_null() && unsafe { libc::dladdr(symbol, &raw mut info) } != 0 && !info.dli_fname.is_null())
        .then(|| unsafe { std::ffi::CStr::from_ptr(info.dli_fname) }.to_string_lossy().into_owned());
    // SAFETY: releases only the reference taken above.
    unsafe { libc::dlclose(handle) };
    std::fs::canonicalize(file?).ok()?.into_os_string().into_string().ok()
}

/// Open the session `access` asks for (M1) and log in as the user when a PIN is configured —
/// unless the counters say the login must not be tried (M2).
fn session(
    ctx: &Pkcs11,
    slot: cryptoki::slot::Slot,
    name: &str,
    cfg: &TokenCfg,
    access: Access,
    write_protected: bool,
    pins: PinState,
) -> Result<(Session, Option<Zeroizing<String>>)> {
    let session = match access {
        Access::Read => ctx.open_ro_session(slot).map_err(ck("C_OpenSession (read-only)"))?,
        Access::Write if write_protected => {
            return Err(KmError::Unsupported(format!(
                "token '{name}' is write-protected (CKF_WRITE_PROTECTED): it can be read, never created on or \
                 deleted from"
            )));
        }
        Access::Scratch if write_protected => ctx.open_ro_session(slot).map_err(ck("C_OpenSession (read-only)"))?,
        Access::Write | Access::Scratch => ctx.open_rw_session(slot).map_err(ck("C_OpenSession"))?,
    };
    let pin = read_pin(cfg)?;
    if let Some(pin) = pin.as_deref() {
        pins.user.guard(name, "user")?;
        match session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(e) => return Err(KmError::Unavailable(format!("C_Login: {e}"))),
        }
    }
    Ok((session, pin))
}

/// The user PIN (`pinEnv`, else `pinFile`).
fn read_pin(cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    read_secret("PIN", cfg.pin_env.as_deref(), cfg.pin_file.as_deref())
}

/// Whether keys.toml gives the token an admin (Security Officer) credential, which [`Token::as_so`]
/// reads.
#[must_use]
pub fn has_admin(cfg: &TokenCfg) -> bool {
    cfg.so_credential_file.is_some() || cfg.so_credential_env.is_some()
}

/// The admin credential (`soCredentialEnv`, else `soCredentialFile`), read only for an SO step. The format
/// is the module's: ykcs11 takes the PIV management key in hex, or the PIN on devices whose
/// management key is PIN-protected.
fn read_mgm(cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    read_secret("management-key", cfg.so_credential_env.as_deref(), cfg.so_credential_file.as_deref())
}

/// A credential from the environment variable `var`, else the file `path` (its trailing newline
/// dropped); neither configured is `None`, a configured one that cannot be read `Unavailable`.
fn read_secret(what: &str, var: Option<&str>, path: Option<&std::path::Path>) -> Result<Option<Zeroizing<String>>> {
    if let Some(var) = var {
        return std::env::var(var)
            .map(|s| Some(Zeroizing::new(s)))
            .map_err(|_| KmError::Unavailable(format!("{what} env var {var} not set")));
    }
    let Some(path) = path else { return Ok(None) };
    std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map(|s| Some(Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_owned())))
        .map_err(|e| KmError::Unavailable(format!("{what} file {}: {e}", path.display())))
}

/// The `cryptoki` class of a configured object.
#[must_use]
pub fn class_of(object: &ObjectCfg) -> ObjectClass {
    match object.class {
        Class::PrivateKey => ObjectClass::PRIVATE_KEY,
        Class::SecretKey => ObjectClass::SECRET_KEY,
        Class::PublicKey => ObjectClass::PUBLIC_KEY,
        Class::Certificate => ObjectClass::CERTIFICATE,
        Class::Data => ObjectClass::DATA,
    }
}

/// The configured class a token reports, if cakeys manages it.
fn managed_class(class: ObjectClass) -> Option<Class> {
    Class::ALL.iter().copied().find(|c| class_of(&ObjectCfg::new(*c, None)) == class)
}

/// The configured curve, after load-time canonicalization.
///
/// # Errors
///
/// Whatever `ObjectCfg::curve` rejects: `Validation` when the object names no curve,
/// `Unsupported` for one without a `RustCrypto` crate.
pub fn curve_of(object: &ObjectCfg) -> Result<Curve> {
    object.curve()
}

/// The `cryptoki` key type of a configured key (`ObjectCfg::checked_key_type`).
///
/// # Errors
///
/// Whatever `checked_key_type` rejects: `Unsupported` for a class/key-type pairing cakeys
/// does not manage (and `Validation` when an EC or Edwards key names no curve).
pub fn key_type_of(object: &ObjectCfg) -> Result<KeyType> {
    Ok(match object.checked_key_type()? {
        Kt::Ec => KeyType::EC,
        Kt::EcEdwards => KeyType::EC_EDWARDS,
        Kt::Rsa => KeyType::RSA,
        Kt::GenericSecret => KeyType::GENERIC_SECRET,
        Kt::Aes => KeyType::AES,
        Kt::Des3 => KeyType::DES3,
        Kt::Sha1Hmac => KeyType::SHA_1_HMAC,
        kt @ Kt::Sha224Hmac => hmac_key_type(kt, KeyType::SHA224_HMAC, 0x2e)?,
        Kt::Sha256Hmac => KeyType::SHA256_HMAC,
        kt @ Kt::Sha384Hmac => hmac_key_type(kt, KeyType::SHA384_HMAC, 0x2c)?,
        kt @ Kt::Sha512Hmac => hmac_key_type(kt, KeyType::SHA512_HMAC, 0x2d)?,
    })
}

/// The generation of a hash-bound HMAC key type: PKCS#11 3.0's `CKM_SHA*_KEY_GEN` for the type
/// (`CKM_GENERIC_SECRET_KEY_GEN` makes `CKK_GENERIC_SECRET` keys only; `SoftHSM` and kryoptic
/// refuse it for an HMAC type). `None` for any other key type. By core's key type: cryptoki's
/// constants for these types collide without the Nix build's patch.
#[must_use]
pub fn hmac_key_gen(kt: Kt) -> Option<Mechanism<'static>> {
    Some(match kt {
        Kt::Sha1Hmac => Mechanism::Sha1KeyGen,
        Kt::Sha224Hmac => Mechanism::Sha224KeyGen,
        Kt::Sha256Hmac => Mechanism::Sha256KeyGen,
        Kt::Sha384Hmac => Mechanism::Sha384KeyGen,
        Kt::Sha512Hmac => Mechanism::Sha512KeyGen,
        _ => return None,
    })
}

/// cryptoki 0.12.1 (and main) gives `SHA224/384/512_HMAC` the value of `CKK_SHA256_HMAC` (0x2b), so such
/// keys could be neither created nor told apart. The Nix build patches it
/// (nix/patches/cryptoki-hmac-key-types.patch); refuse rather than misidentify without the patch.
/// Named by core's key type `name`: cryptoki's own names the type it collides with.
fn hmac_key_type(name: Kt, kt: KeyType, raw: std::os::raw::c_ulong) -> Result<KeyType> {
    if std::os::raw::c_ulong::from(kt) == raw {
        Ok(kt)
    } else {
        Err(KmError::Unsupported(format!(
            "{name}: this build's cryptoki maps it to CKK_SHA256_HMAC; build with \
             nix/patches/cryptoki-hmac-key-types.patch applied"
        )))
    }
}
