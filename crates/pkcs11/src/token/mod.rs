//! PKCS#11 token layer over `cryptoki`. Transparent: PKCS#11 names in, PKCS#11 calls out.
//! Module-specific behaviour goes through the selected [`Provider`].

use crate::provider::{
    AttestCtx, AttestationCap, Attested, Create, Declared, Destroy, Generation, Half, Provider, Registry, SessionKey,
    Template, keygen_mechanism,
};
use crate::templates;
use cakeys_core::Msg;
use cakeys_core::attrs;
use cakeys_core::config::{AttrValue, Binding, Locator, Mode, ObjectCfg, SpecCfg, TokenCfg};
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
mod policy;
mod possession;
mod public;
mod uri;

pub use generate::{BY_NAME, CreateNote, PUBLIC_MADE_PRIVATE, with_public_default_dropped};
pub use host::accepts_public_keys;
pub use identity::commit_mechanism;
pub use policy::bool_attr;
pub use possession::{
    Derived, OAEP, ProofSide, derive_any, digest_info, is_policy_default, oaep_of, oaep_params, proof_refusal, show,
    template_refusal,
};
pub use public::{public_key_attrs, public_object_attrs};
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
            return Err(KmError::Unavailable(
                format!(
                    "token '{token}': the {who} PIN is locked (CKF_{}_PIN_LOCKED); unlock it with the vendor's tools",
                    who.to_uppercase()
                )
                .into(),
            ));
        }
        if final_try {
            return Err(KmError::Unavailable(
                format!(
                    "token '{token}': one {who} PIN try is left before it locks (CKF_{}_PIN_FINAL_TRY); cakeys will \
                 not spend it on a PIN file that may be wrong — log in once by hand with the right PIN to reset \
                 the counter",
                    who.to_uppercase()
                )
                .into(),
            ));
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
///
/// The second field is its key in [`LIBRARIES`].
struct Library(Pkcs11, String);

impl Drop for Library {
    /// Finalized under the registry lock, its entry then removed: until it is, another thread's
    /// [`library`] for the module waits ([`settled`]) rather than initializing it again before
    /// this `C_Finalize` (refused, `CKR_CRYPTOKI_ALREADY_INITIALIZED`) or having it torn down
    /// by this one (token/mod.rs F5). No `Library` is dropped while the lock is held (`library`
    /// only upgrades, waits and inserts), so this cannot deadlock.
    fn drop(&mut self) {
        let mut open = LIBRARIES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = self.0.clone().finalize();
        std::mem::forget(self.0.clone());
        if open.get(&self.1).is_some_and(|w| w.strong_count() == 0) {
            open.remove(&self.1);
        }
        FINALIZED.notify_all();
    }
}

/// The registry of initialized libraries: by key, the library a token holds.
type Libraries<T> = BTreeMap<String, std::sync::Weak<T>>;

/// The libraries this process initialized, by module path: a token of a module another open
/// token already initialized (the two sides of a move between tokens of one module) shares its
/// library rather than initializing it a second time.
static LIBRARIES: std::sync::Mutex<Libraries<Library>> = std::sync::Mutex::new(BTreeMap::new());

/// Signalled when a library's entry leaves [`LIBRARIES`], finalized.
static FINALIZED: std::sync::Condvar = std::sync::Condvar::new();

/// The library under `key` that a token still holds; `None` when there is none. One whose last
/// holder is finalizing it is waited for (`finalized` signals its removal): its module can be
/// initialized again only after that.
fn settled<'a, T>(
    mut open: std::sync::MutexGuard<'a, Libraries<T>>,
    finalized: &std::sync::Condvar,
    key: &str,
) -> (std::sync::MutexGuard<'a, Libraries<T>>, Option<Arc<T>>) {
    loop {
        match open.get(key).map(std::sync::Weak::upgrade) {
            Some(Some(live)) => return (open, Some(live)),
            Some(None) => open = finalized.wait(open).unwrap_or_else(std::sync::PoisonError::into_inner),
            None => return (open, None),
        }
    }
}

/// The initialized library of `module`: the one an open token holds, else newly loaded and
/// initialized.
fn library(module: &str) -> Result<Arc<Library>> {
    // By the file a path names, as the loader maps it: two spellings of one module (relative
    // and absolute, a symlink) are one library, which a second `C_Initialize` would refuse. A
    // bare name is the loader's own search, and stays as written.
    let key = module
        .contains('/')
        .then(|| std::fs::canonicalize(module).ok()?.into_os_string().into_string().ok())
        .flatten()
        .unwrap_or_else(|| module.to_owned());
    let open = LIBRARIES.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (open, found) = settled(open, &FINALIZED, &key);
    if let Some(library) = found {
        return Ok(library);
    }
    let ctx = Pkcs11::new(module).map_err(ck(&format!("loading {module}")))?;
    // Loaded, by the file the loader mapped: a bare name and a path to that file are one library
    // too (token/mod.rs F3). Found open, `ctx` goes uninitialized: only its loader reference.
    let key = loaded_path(module).unwrap_or(key);
    let (mut open, found) = settled(open, &FINALIZED, &key);
    if let Some(library) = found {
        return Ok(library);
    }
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).map_err(ck("C_Initialize"))?;
    let library = Arc::new(Library(ctx, key.clone()));
    open.insert(key, Arc::downgrade(&library));
    Ok(library)
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

/// The `CKR_*` name of a module's failure: cryptoki's `Display` is the spec's prose, which
/// changes with the binding, so a message (and a profile row's evidence) names the return value
/// by its constant: cryptoki's name for it with `rv-value`, else one derived from the variant;
/// `CKR 0x…` for a vendor-defined value or one cryptoki has no variant for.
#[must_use]
pub fn rv_name(e: &CkError) -> String {
    match e {
        CkError::Pkcs11(rv, _) => rv_error_name(*rv),
        other => other.to_string(),
    }
}

/// The `CKR_*` constant an `RvError` stands for: cryptoki's own name for it (`RvError::name`,
/// upstream/rust-cryptoki/0003, with `rv-value`), else one derived from the variant
/// (`GeneralError` -> `CKR_GENERAL_ERROR`), which `names_agree` holds equal; `CKR 0x…` for a
/// vendor-defined value or one cryptoki has no variant for.
fn rv_error_name(rv: RvError) -> String {
    match rv {
        RvError::VendorDefined(v) | RvError::UnknownErrorCode(v) => format!("CKR {v:#x}"),
        #[cfg(feature = "rv-value")]
        rv => rv.name().map_or_else(|| derived_name(rv), str::to_owned),
        #[cfg(not(feature = "rv-value"))]
        rv => derived_name(rv),
    }
}

/// The return value behind cryptoki's `RvError`: `CK_RV::from` (upstream/rust-cryptoki/0003,
/// with `rv-value`). Without it, only the value a vendor-defined or unknown error carries.
#[must_use]
pub fn rv_value(rv: RvError) -> Option<cryptoki_sys::CK_RV> {
    match rv {
        RvError::VendorDefined(v) | RvError::UnknownErrorCode(v) => Some(v),
        #[cfg(feature = "rv-value")]
        rv => Some(rv.into()),
        #[cfg(not(feature = "rv-value"))]
        _ => None,
    }
}

/// A name from `RvError`'s variant (`GeneralError` -> `CKR_GENERAL_ERROR`): every variant is
/// named after its constant.
fn derived_name(rv: RvError) -> String {
    let mut out = String::from("CKR");
    for c in format!("{rv:?}").chars() {
        if c.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(c.to_ascii_uppercase());
    }
    out
}

/// The return value of a failed module call, for [`KmError::with_rv`]: what code matches on
/// (ISSUES.md Q3), where the message names it for people.
#[must_use]
pub fn rv_of(e: &CkError) -> Option<u64> {
    match e {
        CkError::Pkcs11(rv, _) => rv_value(*rv),
        _ => None,
    }
}

/// Whether the return value an error carries (`KmError::rv`, `Msg::rv`) is `want`.
#[must_use]
pub fn rv_is(rv: Option<u64>, want: RvError) -> bool {
    rv.is_some_and(|v| Rv::from(v) == Rv::Error(want))
}

/// The `CKR_*` name of a return value an error carries; `CKR 0x…` for one with no name.
#[must_use]
pub fn rv_value_name(v: u64) -> String {
    match Rv::from(v) {
        Rv::Ok => "CKR_OK".to_owned(),
        Rv::Error(rv) => rv_error_name(rv),
    }
}

/// What an SO login that fails says first: a module step that needs the Security Officer
/// cannot run, and the probe stops there instead of recording a row.
pub const SO_LOGIN: &str = "C_Login (SO)";

fn ck(context: &str) -> impl FnOnce(CkError) -> KmError + '_ {
    move |e| KmError::Unavailable(format!("{context}: {e}").into()).with_rv(rv_of(&e))
}

/// Whether `e` says the device, the token or the session failed, rather than anything of the
/// object or attribute asked for. Matched on cryptoki's error, not on [`rv_of`], which a build
/// without `rv-value` leaves empty.
fn device_failed(e: &CkError) -> bool {
    matches!(
        e,
        CkError::Pkcs11(
            RvError::DeviceError
                | RvError::DeviceMemory
                | RvError::DeviceRemoved
                | RvError::HostMemory
                | RvError::GeneralError
                | RvError::TokenNotPresent
                | RvError::TokenNotRecognized
                | RvError::SessionClosed
                | RvError::SessionHandleInvalid
                | RvError::CryptokiNotInitialized
                | RvError::FunctionCanceled,
            _
        )
    )
}

/// An optional attribute read: `None` where the object lacks the attribute or the module
/// refuses to read it (ykcs11 refuses `CKA_PUBLIC_KEY_INFO` with `CKR_ARGUMENTS_BAD`, a build
/// may not name a mechanism). A failure of the device, token or session ([`device_failed`]) is
/// still unavailable (16), never read as the attribute's absence: a policy flag left out read
/// as a changed key (14), a public key object's point as another key (13) (review D7).
fn if_readable<T>(read: std::result::Result<Option<T>, CkError>) -> Result<Option<T>> {
    match read {
        Ok(v) => Ok(v),
        Err(e) if device_failed(&e) => Err(ck("C_GetAttributeValue")(e)),
        Err(_) => Ok(None),
    }
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
        let (session, pin) = session(ctx, slot, name, cfg, access, write_protected, pins)?;
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
            pin,
            provider,
            chain_time,
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
        // What the provider runs its own way although the module does not list it: the
        // verbs have it through the profile's `add` the probe records, so the probe's proofs
        // try it too (AWS CloudHSM's Ed25519 [run]).
        for m in self.provider.stand_ins() {
            if !self.mechanisms.contains(&m) {
                self.mechanisms.push(m);
            }
        }
        Ok(self)
    }

    /// An `Unsupported` error carrying the provider's advice, if it has any, and the return
    /// value `msg` carries.
    pub fn unsupported(&self, msg: impl Into<Msg>) -> KmError {
        let msg = msg.into();
        let rv = msg.rv();
        match self.provider.hint() {
            Some(h) => KmError::Unsupported(format!("{msg} (hint for {}: {h})", self.provider.name()).into()),
            None => KmError::Unsupported(msg),
        }
        .with_rv(rv)
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
        self.provider.adjusted(&Template::Session(key), templates::session(key))
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

    /// The usable mechanisms, by `CKM_*` name.
    pub fn mechanism_names(&self) -> Vec<String> {
        sorted_names(&self.mechanisms)
    }

    /// What `C_GetMechanismList` returned, by name, sorted, repetitions kept: the drift baseline
    /// the probe records as a profile's `advertise` list (D2).
    #[must_use]
    pub fn advertised(&self) -> Vec<String> {
        sorted_names(&self.listed)
    }

    /// Whether `C_GetMechanismList` listed `m`, whatever the profiles subtract.
    #[must_use]
    pub fn lists(&self, m: MechanismType) -> bool {
        self.listed.contains(&m)
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
            chain_time: self.chain_time,
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
            if copy.is_none() && self.held_spki(h)?.as_deref() == Some(spki) {
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
            self.session.create_object(&template).map_err(|e| self.unsupported(trusted_copy_refused(&self.name, &e)))
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
        let so = read_so_credential(&self.cfg)?.ok_or_else(|| {
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
                so_outcome(what, &self.name, out, logout)
            }
            Err(e) => Err(KmError::Unavailable(
                format!(
                    "{SO_LOGIN} with soCredentialFile/soCredentialEnv: {rv}; it must hold the module's admin \
                 credential (the SO PIN; ykcs11: the PIV management key in hex, or the PIN on a \
                 device whose management key is PIN-protected)",
                    rv = rv_name(&e)
                )
                .into(),
            )
            .with_rv(rv_of(&e))),
        };
        drop(so);
        if !self.logged_in {
            return out;
        }
        let back = match self.pin.as_deref() {
            None => Err(KmError::Unavailable("no user PIN to log back in with".into())),
            Some(pin) => match self.session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
                Err(e) => Err(KmError::Unavailable(format!("C_Login (back to the user): {}", rv_name(&e)).into())
                    .with_rv(rv_of(&e))),
            },
        };
        so_outcome(what, &self.name, out, back)
    }
}

/// What [`Token::as_so`] answers once the session is put back (`after`: the SO logout, then the
/// user's login): the step's own result first. A step that failed is reported as it failed,
/// never as the session trouble after it; a step that succeeded and a session that could not be
/// restored is an error that says the step was done, so a caller never takes a key it made (or
/// a trusted copy) for one that was not.
fn so_outcome<T>(what: &str, token: &str, step: Result<T>, after: Result<()>) -> Result<T> {
    match (step, after) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => {
            let rv = e.rv();
            Err(KmError::Unavailable(
                format!(
                    "{what} on '{token}' was done, but the session could not be restored afterwards ({e}): \
                     what it made or changed is on the token"
                )
                .into(),
            )
            .with_rv(rv))
        }
    }
}

/// Why `token` would not create the trusted copy of a transport key: the module's refusal `e`,
/// its return value kept for code to match on (Q3).
fn trusted_copy_refused(token: &str, e: &CkError) -> Msg {
    Msg::from(format!("token '{token}' will not create a CKA_TRUSTED RSA public key: {e}")).with_rv(rv_of(e))
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
            return Err(KmError::Unsupported(
                format!(
                    "token '{name}' is write-protected (CKF_WRITE_PROTECTED): it can be read, never created on or \
                 deleted from"
                )
                .into(),
            ));
        }
        Access::Scratch if write_protected => ctx.open_ro_session(slot).map_err(ck("C_OpenSession (read-only)"))?,
        Access::Write | Access::Scratch => ctx.open_rw_session(slot).map_err(ck("C_OpenSession"))?,
    };
    let pin = read_pin(cfg)?;
    if let Some(pin) = pin.as_deref() {
        pins.user.guard(name, "user")?;
        match session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
            Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(e) => return Err(KmError::Unavailable(format!("C_Login: {}", rv_name(&e)).into()).with_rv(rv_of(&e))),
        }
    }
    Ok((session, pin))
}

/// The user PIN (`pinEnv`, else `pinFile`).
fn read_pin(cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    cakeys_core::secret::read("PIN", cfg.pin_env.as_deref(), cfg.pin_file.as_deref())
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
fn read_so_credential(cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    cakeys_core::secret::read("SO credential", cfg.so_credential_env.as_deref(), cfg.so_credential_file.as_deref())
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
        Err(KmError::Unsupported(
            format!(
                "{name}: this build's cryptoki maps it to CKK_SHA256_HMAC; build with \
             nix/patches/cryptoki-hmac-key-types.patch applied"
            )
            .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;

    /// `as_so` reports the step first (token/mod.rs F2): a step that succeeded is never dropped
    /// for a failed logout or re-login without saying it was done, and a step that failed is
    /// never hidden behind the session trouble after it.
    #[test]
    fn the_so_step_is_reported_before_the_session_trouble() {
        let trouble = || Err(KmError::Unavailable("C_Logout (SO): CKR_DEVICE_ERROR".into()));
        assert_eq!(so_outcome("generating a key", "piv", Ok(7), Ok(())).unwrap(), 7);
        let done = so_outcome("generating a key", "piv", Ok(7), trouble()).unwrap_err();
        assert!(
            matches!(&done, KmError::Unavailable(m) if m.contains("generating a key on 'piv' was done")
                && m.contains("CKR_DEVICE_ERROR")),
            "{done}"
        );
        let failed =
            so_outcome::<()>("generating a key", "piv", Err(KmError::Unsupported("refused".into())), trouble());
        assert!(matches!(failed, Err(KmError::Unsupported(m)) if *m == *"refused"));
    }

    /// A lookup that finds a library whose last holder is finalizing it waits until its entry is
    /// gone (token/mod.rs F5): the module is initialized anew only after that `C_Finalize`. A
    /// library still held is shared; none is none.
    #[test]
    fn a_library_being_finalized_is_waited_for() {
        let open = Arc::new(std::sync::Mutex::new(Libraries::<u8>::new()));
        let finalized = Arc::new(std::sync::Condvar::new());
        let held = Arc::new(7);
        let dying = Arc::new(8);
        open.lock().unwrap().insert("held".into(), Arc::downgrade(&held));
        open.lock().unwrap().insert("dying".into(), Arc::downgrade(&dying));
        assert_eq!(settled(open.lock().unwrap(), &finalized, "held").1.as_deref(), Some(&7));
        assert!(settled(open.lock().unwrap(), &finalized, "none").1.is_none());
        // The last holder is gone, its finalize not done: the lookup waits for the removal.
        drop(dying);
        let removed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let lookup = {
            let (open, finalized, removed) = (Arc::clone(&open), Arc::clone(&finalized), Arc::clone(&removed));
            std::thread::spawn(move || {
                let (_open, found) = settled(open.lock().unwrap(), &finalized, "dying");
                (found.is_none(), removed.load(std::sync::atomic::Ordering::SeqCst))
            })
        };
        std::thread::sleep(std::time::Duration::from_millis(50));
        {
            let mut libraries = open.lock().unwrap();
            removed.store(true, std::sync::atomic::Ordering::SeqCst);
            libraries.remove("dying");
            finalized.notify_all();
        }
        assert_eq!(lookup.join().unwrap(), (true, true), "returned before the finalize was done");
    }

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
    /// `Token::unsupported` carries past a provider's hint. A vendor value: one every build
    /// carries, `rv-value` or not.
    #[test]
    fn a_refused_trusted_copy_keeps_its_return_value() {
        let e = CkError::Pkcs11(RvError::VendorDefined(0x8000_0001), Function::CreateObject);
        let m = trusted_copy_refused("hsm", &e);
        assert_eq!(m.rv(), Some(0x8000_0001));
        assert!(m.contains("token 'hsm' will not create a CKA_TRUSTED RSA public key"), "{m}");
    }

    /// Every return value cryptoki has a variant for converts back to itself, and cryptoki's
    /// name for it is the one derived from the variant: a build with `rv-value` and one without
    /// name every module failure alike, so no committed profile's `CKR_*` changes.
    #[cfg(feature = "rv-value")]
    #[test]
    fn names_agree() {
        for v in 1..0x1000 {
            let Rv::Error(rv) = Rv::from(v) else { continue };
            assert_eq!(rv_value(rv), Some(v), "{v:#x}");
            if let Some(name) = rv.name() {
                assert_eq!(name, derived_name(rv), "{v:#x}");
                assert_eq!(rv_value_name(v), name);
            }
        }
    }

    #[test]
    fn values_without_a_variant_go_by_their_value() {
        let vendor = CkError::Pkcs11(RvError::VendorDefined(0x8000_0001), Function::Initialize);
        assert_eq!(rv_name(&vendor), "CKR 0x80000001");
        // A value no constant has.
        assert_eq!(rv_value_name(0x20f), "CKR 0x20f");
        // CKR_TOKEN_NOT_INITIALIZED (PKCS#11 3.2): a variant only the patch adds.
        let expected = if cfg!(feature = "rv-value") { "CKR_TOKEN_NOT_INITIALIZED" } else { "CKR 0x208" };
        assert_eq!(rv_value_name(0x208), expected);
        assert_eq!(rv_value_name(0x30), "CKR_DEVICE_ERROR");
        assert_eq!(rv_value_name(0), "CKR_OK");
    }
}
