//! PKCS#11 token layer over `cryptoki`. Transparent: PKCS#11 names in, PKCS#11 calls out.
//! Module-specific behaviour goes through the selected [`Provider`].

use crate::provider::{AttestCtx, AttestationCap, Attested, Provider, Registry};
use cakeys_core::attrs;
use cakeys_core::config::{AttrValue, Binding, Locator, Mode, ObjectCfg, SpecCfg, TokenCfg};
pub use cakeys_core::config::{Immutables, ModuleInfo, TokenInfo};
use cakeys_core::id::{self, Commit, Curve, HmacHash, Scheme};
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
mod identity;
mod policy;
mod possession;
mod uri;

pub use identity::commit_mechanism;
pub use policy::bool_attr;
use uri::{locator_attrs, pct_all};

/// The session a verb opens (M1, docs/REVIEW-2026-11-11.md): read-only for the verbs that only
/// read — a write-protected token (`CKF_WRITE_PROTECTED`) refuses read-write sessions, and the
/// session objects reading needs (a key-wrap copy, an ECDH secret) are allowed in read-only
/// ones — read-write only to create or destroy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
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
}

impl Pin {
    /// Refuse a login as `who` (user or SO) the counters say must not be tried.
    fn guard(self, token: &str, who: &str) -> Result<()> {
        let Pin { locked, final_try } = self;
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

pub struct Token {
    pub name: String,
    pub label: String,
    pub module: ModuleInfo,
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
    /// The RSA key-pair generation's key-size range as `C_GetMechanismInfo` reports it, when
    /// the module advertises `CKM_RSA_PKCS_KEY_PAIR_GEN`: the probe's reported bounds.
    pub rsa_bits: Option<(u64, u64)>,
    pub provider: Arc<dyn Provider>,
    /// The resolved capability profiles (docs/PROVIDERS.md): the module profile and the
    /// delta layers between cakeys and it, with the notes resolution noticed on the way.
    pub profiles: crate::resolution::Resolved,
    session: Session,
    /// Logged in as the user: private objects are visible. Otherwise a public session.
    pub logged_in: bool,
    /// The token's config, for provider hooks that need more than the module (the native TPM
    /// attestation path's `options`: `tcti`, `tpm2Store` and `akHandle`).
    pub cfg: TokenCfg,
    /// The PIN counters at open, checked before every login (M2).
    pins: PinState,
    /// The user credential, already read for login, kept only when the provider can attest
    /// (the TPM attestation path unseals the token's wrapping key with it) or an SO step must
    /// log the user back in afterwards (`mgmKeyFile`/`mgmKeyEnv`). Zeroized on drop.
    pin: Option<Zeroizing<String>>,
}

fn ck(context: &str) -> impl FnOnce(CkError) -> KmError + '_ {
    move |e| KmError::Unavailable(format!("{context}: {e}"))
}

impl Token {
    /// Open the token named `name`: load the module, find the slot whose token label matches,
    /// read its capabilities, and log in as the user when a PIN is configured.
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
        let module = module_override
            .map(str::to_owned)
            .or_else(|| cfg.module.clone())
            .ok_or_else(|| KmError::Validation(format!("token '{name}' has no module")))?;
        let ctx = Pkcs11::new(&module).map_err(ck(&format!("loading {module}")))?;
        ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).map_err(ck("C_Initialize"))?;
        let lib = ctx.get_library_info().map_err(ck("C_GetInfo"))?;
        let module = ModuleInfo {
            path: module,
            description: lib.library_description().trim().to_owned(),
            manufacturer: lib.manufacturer_id().trim().to_owned(),
            version: lib.library_version().to_string(),
            cryptoki: lib.cryptoki_version().to_string(),
        };
        let provider = registry.select(cfg.provider.as_deref(), &module)?;
        provider.check_options(name, &cfg.options)?;
        if has_admin(cfg) && !provider.manages_as_so() {
            return Err(KmError::Validation(format!(
                "token '{name}': mgmKeyFile/mgmKeyEnv is only for modules that create keys as \
                 Security Officer (ykcs11); provider {} creates them as the user",
                provider.name()
            )));
        }
        let mut slot = None;
        for s in ctx.get_slots_with_token().map_err(ck("C_GetSlotList"))? {
            let info = ctx.get_token_info(s).map_err(ck("C_GetTokenInfo"))?;
            if info.label() == cfg.token_label {
                if slot.is_some() {
                    return Err(KmError::Ambiguous(format!("several tokens labelled '{}'", cfg.token_label)));
                }
                slot = Some((
                    s,
                    TokenInfo {
                        model: info.model().trim().to_owned(),
                        serial: info.serial_number().trim().to_owned(),
                        firmware: info.firmware_version().to_string(),
                    },
                    PinState {
                        user: Pin { locked: info.user_pin_locked(), final_try: info.user_pin_final_try() },
                        so: Pin { locked: info.so_pin_locked(), final_try: info.so_pin_final_try() },
                    },
                    info.write_protected(),
                ));
            }
        }
        let (slot, token, pins, write_protected) = slot.ok_or_else(|| {
            KmError::Unavailable(format!("token '{}' not present in {}", cfg.token_label, module.path))
        })?;
        // The capability profiles (docs/PROVIDERS.md phase 2): the module profile follows the
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
        let stack_decides = profiles.module.is_some() || profiles.layers.len() > 1;
        let mechanisms = if stack_decides {
            advertised
                .into_iter()
                .filter(|m| !profiles.subtracted_mechanisms().contains(m.to_string().as_str()))
                .collect()
        } else {
            provider.mechanisms(advertised)
        };
        let mut mechanism_names: Vec<String> = mechanisms.iter().map(std::string::ToString::to_string).collect();
        mechanism_names.sort();
        let (session, pin) = session(&ctx, slot, name, cfg, access, write_protected, pins)?;
        Ok(Token {
            name: name.to_owned(),
            label: cfg.token_label.clone(),
            module,
            token,
            mechanisms,
            mechanism_names,
            advertised: advertised_names,
            rsa_bits,
            profiles,
            session,
            logged_in: pin.is_some(),
            cfg: cfg.clone(),
            pins,
            pin: pin.filter(|_| provider.attestation().is_some() || has_admin(cfg)),
            provider,
        })
    }

    /// An `Unsupported` error carrying the provider's advice, if it has any.
    pub fn unsupported(&self, msg: String) -> KmError {
        match self.provider.hint() {
            Some(h) => KmError::Unsupported(format!("{msg} (hint for {}: {h})", self.provider.name())),
            None => KmError::Unsupported(msg),
        }
    }

    /// The session itself, for the probe's raw `C_*` calls (crate-internal: the normal verbs
    /// go through the methods above).
    pub(crate) fn raw(&self) -> &Session {
        &self.session
    }

    pub fn has(&self, m: MechanismType) -> bool {
        self.mechanisms.contains(&m)
    }

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
    /// state it attests with (only `realise` sets it).
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

    /// Every object under the locator, whatever its class (If-None-Match before creating).
    ///
    /// # Errors
    ///
    /// `Validation` for a locator naming neither `CKA_LABEL` nor `CKA_ID` (or a non-hex
    /// `CKA_ID`); `Unavailable` when `C_FindObjects` fails.
    pub fn find_any(&self, loc: &Locator) -> Result<Vec<ObjectHandle>> {
        self.session.find_objects(&locator_attrs(loc)?).map_err(ck("C_FindObjects"))
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

    fn attr(&self, h: ObjectHandle, t: AttributeType) -> Result<Option<Attribute>> {
        Ok(self.session.get_attributes(h, &[t]).map_err(ck("C_GetAttributeValue"))?.into_iter().next())
    }

    /// Run `step` in a Security Officer session (`mgmKeyFile`/`mgmKeyEnv`), for modules that
    /// create and destroy objects only as SO, then return to the user session. Login state is
    /// per token, so the user is logged out first. The admin credential is read here, never at
    /// open, and zeroized when the step ends.
    fn as_so<T>(&self, what: &str, step: impl FnOnce() -> Result<T>) -> Result<T> {
        let so = read_mgm(&self.cfg)?.ok_or_else(|| {
            self.unsupported(format!(
                "{what} on '{}' needs a Security Officer session: set tokens.{}.mgmKeyFile or mgmKeyEnv",
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
                "C_Login (SO) with mgmKeyFile/mgmKeyEnv: {e}; it must hold the module's admin \
                 credential (ykcs11: the PIV management key in hex, or the PIN on a device whose \
                 management key is PIN-protected)"
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
        Access::Write => ctx.open_rw_session(slot).map_err(ck("C_OpenSession"))?,
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

fn read_pin(cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    if let Some(var) = &cfg.pin_env {
        return std::env::var(var)
            .map(|s| Some(Zeroizing::new(s)))
            .map_err(|_| KmError::Unavailable(format!("PIN env var {var} not set")));
    }
    if let Some(path) = &cfg.pin_file {
        return std::fs::read_to_string(path)
            .map(Zeroizing::new)
            .map(|s| Some(Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_owned())))
            .map_err(|e| KmError::Unavailable(format!("PIN file {}: {e}", path.display())));
    }
    Ok(None)
}

fn has_admin(cfg: &TokenCfg) -> bool {
    cfg.mgm_key_file.is_some() || cfg.mgm_key_env.is_some()
}

/// The admin credential (`mgmKeyEnv`, else `mgmKeyFile`), read only for an SO step. The format
/// is the module's: ykcs11 takes the PIV management key in hex, or the PIN on devices whose
/// management key is PIN-protected.
fn read_mgm(cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    if let Some(var) = &cfg.mgm_key_env {
        return std::env::var(var)
            .map(|s| Some(Zeroizing::new(s)))
            .map_err(|_| KmError::Unavailable(format!("management-key env var {var} not set")));
    }
    if let Some(path) = &cfg.mgm_key_file {
        return std::fs::read_to_string(path)
            .map(Zeroizing::new)
            .map(|s| Some(Zeroizing::new(s.trim_end_matches(['\n', '\r']).to_owned())))
            .map_err(|e| KmError::Unavailable(format!("management-key file {}: {e}", path.display())));
    }
    Ok(None)
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
        Kt::Sha1Hmac => KeyType::SHA_1_HMAC,
        Kt::Sha224Hmac => hmac_key_type(KeyType::SHA224_HMAC, 0x2e)?,
        Kt::Sha256Hmac => KeyType::SHA256_HMAC,
        Kt::Sha384Hmac => hmac_key_type(KeyType::SHA384_HMAC, 0x2c)?,
        Kt::Sha512Hmac => hmac_key_type(KeyType::SHA512_HMAC, 0x2d)?,
    })
}

/// cryptoki 0.12.1 (and main) gives `SHA224/384/512_HMAC` the value of `CKK_SHA256_HMAC` (0x2b), so such
/// keys could be neither created nor told apart. The Nix build patches it
/// (nix/patches/cryptoki-hmac-key-types.patch); refuse rather than misidentify without the patch.
fn hmac_key_type(kt: KeyType, raw: std::os::raw::c_ulong) -> Result<KeyType> {
    if std::os::raw::c_ulong::from(kt) == raw {
        Ok(kt)
    } else {
        Err(KmError::Unsupported(format!(
            "{kt}: this build's cryptoki maps it to CKK_SHA256_HMAC; build with \
             nix/patches/cryptoki-hmac-key-types.patch applied"
        )))
    }
}
