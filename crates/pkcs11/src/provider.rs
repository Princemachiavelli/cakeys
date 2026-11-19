//! Module-specific behaviour: repairs and operations ([`Provider`]); a provider crate
//! overrides only what its module gets wrong. Every fix-up must return exactly what a
//! spec-compliant module would, so identities stay portable across modules and versions.

use crate::Token;
use cakeys_core::config::{Binding, Locator, ModuleInfo, ObjectCfg, Options, SpecCfg, TokenCfg};
use cakeys_core::id::Scheme;
use cakeys_core::plan::Target;
use cakeys_core::types::ObjectClass;
use cakeys_core::{KmError, Result};
pub use cakeys_profile::PlaintextKind;
use cakeys_profile::Set;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectHandle};
use cryptoki::session::Session;
use std::borrow::Cow;
use std::sync::Arc;

/// A key bound to one purpose at creation ([`Provider::bound_keys`]).
pub struct BoundKey {
    /// The module's name for the binding (a Cloud KMS algorithm), for notes.
    pub name: String,
    /// `CKA_LABEL`, part of `template`.
    pub label: String,
    /// The PKCS#11 key type it makes: `CKK_EC`, `CKK_RSA`, `CKK_AES`, ...
    pub kind: cakeys_profile::KeyKind,
    /// Its curve name, or its size (bits for RSA, as [`cakeys_profile::On::parse`] reads it).
    pub on: cakeys_profile::On,
    /// The generation mechanism (parameterless).
    pub keygen: MechanismType,
    /// The whole template: the private or secret half's; no public template is passed.
    pub template: Vec<Attribute>,
    /// The mechanisms a key with this binding serves; nothing else is tried on it.
    pub mechanisms: Vec<MechanismType>,
}

/// A key the module generates from its own template ([`Provider::generation`]): `keygen`
/// (parameterless) with `template` alone, the private or secret half's; a pair passes no public
/// template.
pub struct Generation {
    /// The parameterless generation mechanism.
    pub keygen: MechanismType,
    /// The whole template: the private or secret half's.
    pub template: Vec<Attribute>,
}

/// The parameterless generation mechanism `keygen` names, and whether it makes a key pair:
/// what a module-chosen generation ([`Generation`], [`BoundKey`]) runs. `None` for any other.
#[must_use]
pub fn keygen_mechanism(keygen: MechanismType) -> Option<(Mechanism<'static>, bool)> {
    Some(match keygen {
        MechanismType::ECC_KEY_PAIR_GEN => (Mechanism::EccKeyPairGen, true),
        MechanismType::RSA_PKCS_KEY_PAIR_GEN => (Mechanism::RsaPkcsKeyPairGen, true),
        MechanismType::AES_KEY_GEN => (Mechanism::AesKeyGen, false),
        MechanismType::GENERIC_SECRET_KEY_GEN => (Mechanism::GenericSecretKeyGen, false),
        _ => return None,
    })
}

/// What one family of PKCS#11 modules needs beyond the standard, at three kinds of seam and
/// nothing else (docs/archive/REVIEW-2026-11-15.md §4 named the first two):
///
/// - *repairs*, where a module's answer is made what a spec-compliant module's would be: one
///   for an attribute read ([`Self::repair`]), one for a mechanism ([`Self::stand_in`]);
/// - *templates*, where cakeys' own template for a call is made one the module takes: one for
///   every template cakeys builds, named by what it is for ([`Self::template`]);
/// - *operations*, which a provider may replace whole, the default being plain PKCS#11 through
///   a public [`Token`] method an override can wrap: [`Self::create`], [`Self::destroy`],
///   [`Self::import_plaintext`] and [`Self::attest`].
///
/// Beside them: how to recognise the module, its settings and advice, and the facts a caller
/// must know before it acts ([`Self::manages_as_so`], [`Self::generation`]). Two hooks only the
/// probe reads: [`Self::bound_keys`] lists what it generates on a module whose keys are bound to
/// one purpose, and [`Self::scratch_occupant`] guards its scratch slot. A provider that seems to
/// need a new hook overrides an operation in its own crate instead.
///
/// The in-tree providers are crates of this workspace (`cakeys-ykcs11`, `cakeys-tpm2-pkcs11`,
/// `cakeys-kmsp11`, `cakeys-aws-cloudhsm`); a crate outside it adds its own to a [`Registry`]
/// (the `custom-provider` example). A module with no fix-ups needs none: its capability
/// profile names it ([`Data`]).
pub trait Provider: Send + Sync {
    /// Name for `provider = "<name>"` in keys.toml and in messages.
    fn name(&self) -> &'static str;

    /// Whether this provider recognises the loaded module (from `C_GetInfo`), for auto-detection.
    fn matches(&self, module: &ModuleInfo) -> bool;

    /// Advice appended when the module cannot do something the spec asks for.
    fn hint(&self) -> Option<&'static str> {
        None
    }

    /// Check `token`'s `[tokens.<t>.options]` when it is opened: a provider with settings parses
    /// them (`cakeys_core::config::parse_options`, unknown names refused); the default takes none,
    /// so any option is refused (17) rather than silently ignored.
    ///
    /// # Errors
    ///
    /// `Validation` for any option on a provider that takes none; a provider with settings
    /// adds whatever its own parsing refuses.
    fn check_options(&self, token: &str, options: &Options) -> Result<()> {
        match options.keys().next() {
            None => Ok(()),
            Some(k) => Err(KmError::Validation(
                format!("tokens.{token}.options.{k}: provider {} takes no options", self.name()).into(),
            )),
        }
    }

    /// Whether the module creates and destroys token objects only in a Security Officer session
    /// (ykcs11: the PIV management key). Then `tokens.<t>.soCredentialFile`/`soCredentialEnv`
    /// is used for exactly those steps ([`Token::managing`]); elsewhere it is refused, since an
    /// SO there cannot do what the user does. A fact, not an operation: camigrate's imports and
    /// the probe's scratch guard read it too.
    fn manages_as_so(&self) -> bool {
        false
    }

    // ── Repairs ──────────────────────────────────────────────────────────────────────────

    /// Repair what the module reported for one attribute read ([`Report`]) to what a
    /// spec-compliant module would report, returning the same variant. The policy check, the
    /// identities and the lock all see the result, so identities stay portable across modules
    /// and versions; the profile keeps the raw observation. The default changes nothing.
    fn repair<'a>(&self, report: Report<'a>) -> Report<'a> {
        report
    }

    /// The mechanism this module runs for the standard `m` it does not list, parameterless:
    /// AWS `CloudHSM` generates Ed25519 with `CKM_EC_KEY_PAIR_GEN` and signs with a vendor
    /// mechanism \[run\]. Used only where the module does not list `m` ([`Token::runnable`]), and
    /// relied on only where a profile's `add` row records that it works (`caprobe` measures
    /// what it covers, `stand_ins`). `None`: no stand-in.
    fn stand_in(&self, _m: &Mechanism) -> Option<Mechanism<'static>> {
        None
    }

    // ── Templates ────────────────────────────────────────────────────────────────────────

    /// Adjust `attrs`, cakeys' template for the call `req` names, to one this module takes:
    /// a vendor attribute set, a default it refuses removed. Every template the verbs build for
    /// `C_GenerateKey(Pair)`, `C_CreateObject`, `C_UnwrapKey` and `C_DeriveKey` passes through
    /// here, and the probe's generations, imports, creations and sealed round trips ask it with
    /// the same purposes (its own templates still differ in places); `C_FindObjects` search
    /// templates and the probe's measurement variations do not. Secret material (`CKA_VALUE`, a
    /// private key's components) is never in `attrs`: cakeys adds it afterwards. Runs before
    /// cakeys' own fallbacks, which then work on the result (a public `CKA_PRIVATE = false`
    /// dropped where refused, a curve by name, `C_DeriveKey`'s policy defaults). A module that
    /// generates only from its own template replaces it whole instead ([`Self::generation`]).
    /// The default changes nothing.
    ///
    /// Each template is asked about before anything is created: the proof's and the
    /// commitments' session keys, which run once the object exists, by the capability check
    /// before it (`ops::check_import` for camigrate's imports). A plan asks too, with no token
    /// (`gate::check`, camigrate's `--dry-run` and the plan of every move): the same templates
    /// ([`crate::templates`]), less a public object's value and a public key's material, which
    /// it has not read. So a refusal should follow from the request (`req`: the object, its
    /// spec and locator, the purpose), not from material; one that does is made only at the run,
    /// still before anything is created.
    ///
    /// # Errors
    ///
    /// The provider's refusal of the call, `Unsupported` (15) for an object the module cannot
    /// take.
    fn template(&self, _req: &Template<'_>, _attrs: &mut Attributes) -> Result<()> {
        Ok(())
    }

    // ── Operations ───────────────────────────────────────────────────────────────────────

    /// The module's own generation of `object` as `spec` declares it under `loc`, to be proven
    /// by `binding` (private keys): `None` for cakeys' own templates, the default. The static
    /// half of [`Self::create`], read before any token is opened (the capability gate). A module
    /// that takes only its own template (Google Cloud KMS) chooses it here, and refuses here,
    /// before anything is created, what would become a key cakeys could not then identify or
    /// prove: a key it destroys again is not always gone (Cloud KMS keeps the label for good).
    ///
    /// # Errors
    ///
    /// `Unsupported` (15) for an object the module cannot make as declared; `Validation` (17)
    /// for a locator it cannot place a key under.
    fn generation(
        &self,
        _object: &ObjectCfg,
        _spec: &SpecCfg,
        _loc: &Locator,
        _binding: Option<Binding>,
    ) -> Result<Option<Generation>> {
        Ok(None)
    }

    /// Create `req`'s object on `tok`. The default is [`Token::create_declared`]: the module's
    /// own template where [`Self::generation`] chooses one, else cakeys' templates, in an SO
    /// session where [`Self::manages_as_so`]. An override refuses what the module would place
    /// elsewhere than asked (ykcs11 places by `CKA_ID`), before anything is created.
    ///
    /// # Errors
    ///
    /// As [`Token::create_declared`], plus the override's refusals.
    fn create(&self, tok: &Token, req: &Create<'_>) -> Result<Option<crate::token::CreateNote>> {
        tok.create_declared(req)
    }

    /// Destroy `req`'s handles, identified by the caller, on `tok`. The default is
    /// [`Token::destroy_plain`]: `C_DestroyObject` each, in an SO session where
    /// [`Self::manages_as_so`]. An override refuses (15) where the module's
    /// `C_DestroyObject` reports success but leaves the key (ykcs11), naming how to remove it.
    ///
    /// # Errors
    ///
    /// As [`Token::destroy_plain`], plus the override's refusals.
    fn destroy(&self, tok: &Token, req: &Destroy<'_>) -> Result<usize> {
        tok.destroy_plain(req)
    }

    /// Import plaintext key material the module's own way, outside PKCS#11 (docs/CAMIGRATE.md
    /// `tpm2-ptool`: tpm2-pkcs11 creates keys from values only through `tpm2_ptool import`):
    /// `ctx.key` is a private key's PKCS#8 `PrivateKeyInfo` or a secret key's value. The caller
    /// opens the token again afterwards to see the key. The default refuses.
    ///
    /// # Errors
    ///
    /// `Unsupported` (this default, or a key type the tool cannot take); whatever the tool
    /// reports.
    fn import_plaintext(&self, _ctx: &ImportCtx<'_>) -> Result<()> {
        Err(KmError::Unsupported(format!("{} imports no plaintext outside PKCS#11", self.name()).into()))
    }

    /// How plaintext keys get into this module, as a profile's `plaintext-import` and an
    /// `import.*` row's `via` name it: `C_CreateObject` by default (as SO where the provider
    /// manages as SO), or the provider's own [`Self::import_plaintext`].
    fn plaintext_import(&self) -> PlaintextKind {
        PlaintextKind::CreateObject
    }

    /// The attestation commitment this provider can compute (§3.7 of docs/DESIGN.md), if any:
    /// the scheme it records and the object classes it can attest.
    /// `None` (the default): this module exposes no attestation, so a spec opting into one is
    /// refused (15) before anything is created.
    fn attestation(&self) -> Option<AttestationCap> {
        None
    }

    /// Compute the attestation commitment for `key` on its token (called only when the spec
    /// opted in and [`Provider::attestation`] covers the class). Returns the canonical scheme
    /// digest plus the anchor it was verified to. A missing attestation is an error naming the
    /// reason (e.g. an imported key, or a session that could not attest), never a pass; an
    /// attestation that names other material than `ctx.spki` is a conflict (13).
    ///
    /// # Errors
    ///
    /// Whatever the module's attestation path cannot establish: `Unsupported` (this default:
    /// the provider advertises none), `Unavailable` when the token has none to give, `Conflict`
    /// when it names other material than `ctx.spki`.
    fn attest(&self, _ctx: &AttestCtx<'_>) -> Result<Attested> {
        // Unreachable in practice: the caller checks `attestation()` first. Kept as an error so
        // a provider advertising a capability must actually implement it.
        Err(KmError::Unsupported(format!("{} exposes no attestation", self.name()).into()))
    }

    // ── Read only by the probe ───────────────────────────────────────────────────────────

    /// The keys a module binds to one purpose when it creates them (Google Cloud KMS: one
    /// algorithm per key), each with the exact template it is generated from: the write probe
    /// generates these instead of its own templates. Empty for a module whose keys are general
    /// purpose, the default.
    fn bound_keys(&self) -> Vec<BoundKey> {
        Vec::new()
    }

    /// Whether the certificates `certs` (DER) found under the probe's scratch `CKA_ID` (`id`)
    /// show a slot holding only what this module itself wrote when it generated the slot's key —
    /// the only occupant the write probe may replace (`tokens.<t>.probe.scratchId`). Anything
    /// else may be a real key, so the probe refuses it. The default recognises none.
    fn scratch_occupant(&self, _id: &[u8], _certs: &[Vec<u8>]) -> bool {
        false
    }
}

/// One attribute read as the module reported it, for [`Provider::repair`]: the repair returns
/// the same variant with what a spec-compliant module would have reported.
pub enum Report<'a> {
    /// `CKA_EC_POINT`, which tpm2-pkcs11 and AWS `CloudHSM` encode their own way.
    EcPoint(Cow<'a, [u8]>),
    /// `CKA_KEY_TYPE`, with the object's `CKA_EC_PARAMS` where it has them: AWS `CloudHSM`
    /// reports an Ed25519 key as `CKK_EC` \[run\].
    KeyType {
        /// What the module reported.
        reported: KeyType,
        /// The object's `CKA_EC_PARAMS`, where it has them.
        ec_params: Option<&'a [u8]>,
    },
    /// A boolean policy attribute (`CKA_SIGN`, `CKA_DERIVE`, ...): ykcs11's fixed table says
    /// `CKA_DERIVE` false on keys its `C_DeriveKey` derives with. The profile keeps the raw
    /// observation (`derive.key-attribute`).
    PolicyFlag {
        /// The attribute read.
        attr: AttributeType,
        /// What the module reported.
        reported: bool,
        /// Reads the object's key type when it is a private key.
        private_key_type: &'a dyn Fn() -> Option<KeyType>,
    },
}

/// The repaired reads ([`Provider::repair`]): a repair that answers with another variant than
/// it was asked changes nothing.
impl dyn Provider + '_ {
    /// `CKA_EC_POINT` as `raw` reads, repaired.
    #[must_use]
    pub fn ec_point<'a>(&self, raw: &'a [u8]) -> Cow<'a, [u8]> {
        match self.repair(Report::EcPoint(Cow::Borrowed(raw))) {
            Report::EcPoint(point) => point,
            _ => Cow::Borrowed(raw),
        }
    }

    /// `CKA_KEY_TYPE` as `reported`, repaired from the object's `ec_params`.
    #[must_use]
    pub fn key_type(&self, reported: KeyType, ec_params: Option<&[u8]>) -> KeyType {
        match self.repair(Report::KeyType { reported, ec_params }) {
            Report::KeyType { reported: repaired, .. } => repaired,
            _ => reported,
        }
    }

    /// The policy flag `attr` as `reported`, repaired.
    #[must_use]
    pub fn policy_flag(
        &self,
        attr: AttributeType,
        reported: bool,
        private_key_type: &dyn Fn() -> Option<KeyType>,
    ) -> bool {
        match self.repair(Report::PolicyFlag { attr, reported, private_key_type }) {
            Report::PolicyFlag { reported: repaired, .. } => repaired,
            _ => reported,
        }
    }

    /// The standard mechanisms [`Provider::stand_in`] covers: of those cakeys runs through
    /// [`Token::runnable`], in the form it asks for them, each the provider answers. What
    /// `caprobe` probes although the module does not list it.
    #[must_use]
    pub fn stand_ins(&self) -> Vec<MechanismType> {
        let asked = [
            Mechanism::EccKeyPairGen,
            Mechanism::EccEdwardsKeyPairGen,
            Mechanism::EccMontgomeryKeyPairGen,
            Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
        ];
        asked.iter().filter(|m| self.stand_in(m).is_some()).map(Mechanism::mechanism_type).collect()
    }

    /// `template`, cakeys' template for `req`, as the provider adjusts it ([`Provider::template`]).
    ///
    /// # Errors
    ///
    /// The provider's refusal.
    pub fn adjusted(&self, req: &Template<'_>, template: Vec<Attribute>) -> Result<Vec<Attribute>> {
        let mut attrs = Attributes(template);
        self.template(req, &mut attrs)?;
        Ok(attrs.0)
    }
}

/// What a template cakeys builds is for ([`Provider::template`]).
pub enum Template<'a> {
    /// A key generated from cakeys' templates (`create`): one `half` of `on`.
    Generate(Declared<'a>, Half),
    /// A key imported (camigrate, and the probe's `import.*` rows): created from plaintext, or
    /// unwrapped from a bundle; for the unwrap, the attributes the module's profile refuses in one
    /// (`unwrap.refuse`) already left out.
    Import(Declared<'a>, Via),
    /// The public key object made beside an imported private key, from its public key.
    PublicHalf(Declared<'a>),
    /// A certificate, data object or public key object created from its value.
    Object(Declared<'a>),
    /// The trusted copy of a transport key, made as SO (`camigrate transport --trusted`).
    TrustedCopy,
    /// A session object cakeys makes for one step and destroys after it.
    Session(SessionKey),
}

/// The object a template makes: `object` as `spec` declares it, under `locator`.
#[derive(Clone, Copy)]
pub struct Declared<'a> {
    /// The object's type.
    pub object: &'a ObjectCfg,
    /// The spec it is made by (the probe's own, for its scratch objects).
    pub spec: &'a SpecCfg,
    /// Where it goes on the token.
    pub locator: &'a Locator,
}

impl<'a> From<&Target<'a>> for Declared<'a> {
    fn from(t: &Target<'a>) -> Self {
        Declared { object: t.object, spec: t.spec, locator: &t.on_token.locator }
    }
}

/// Which template of a generation ([`Template::Generate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Half {
    /// A key pair's public template.
    Public,
    /// The key itself: a pair's private template, or a secret key's.
    Key,
}

/// How a key is imported ([`Template::Import`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// `C_CreateObject` from the host's plaintext (`host`).
    CreateObject,
    /// `C_UnwrapKey` from a bundle or a transport (`sealed`).
    Unwrap,
}

/// A session object cakeys makes for one step ([`Template::Session`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKey {
    /// The secret a proof of possession unwraps (`pop-unwrap`) or derives (`pop-ecdh`) and MACs
    /// with, `sealed`; or, not sealed, the readable secret a `pop-ecdh` derives where the module
    /// refuses the sealed one.
    ProofSecret {
        /// The proof.
        binding: Binding,
        /// Sensitive and not extractable; else readable.
        sealed: bool,
    },
    /// wrap-rebind's AES key, which wraps the key under commitment for its copy.
    RebindKek,
    /// wrap-rebind's copy of the key under commitment, unwrapped with the uses it commits by.
    RebindCopy,
    /// The `kw` commitment's fixed key, which the key under commitment wraps.
    KwInput,
    /// The AES key the host draws and creates on the token to take a key out (`host` export).
    HostKek,
    /// A sealed export's transport public key, loaded on the source.
    TransportKey,
    /// A sealed export's AES key, generated on the source and wrapped to the transport key.
    ExportKek,
    /// A sealed import's AES key, unwrapped on the target with the transport key.
    ImportKek,
}

/// A template a provider adjusts ([`Provider::template`]): at most one attribute of each type,
/// as PKCS#11 requires of one.
pub struct Attributes(Vec<Attribute>);

impl Attributes {
    /// The attribute of type `t`, if the template has one.
    #[must_use]
    pub fn get(&self, t: AttributeType) -> Option<&Attribute> {
        self.0.iter().find(|a| a.attribute_type() == t)
    }

    /// Set `a`, replacing the template's attribute of its type where it has one.
    pub fn set(&mut self, a: Attribute) {
        match self.0.iter_mut().find(|b| b.attribute_type() == a.attribute_type()) {
            Some(b) => *b = a,
            None => self.0.push(a),
        }
    }

    /// Remove the attribute of type `t`, returning it.
    pub fn remove(&mut self, t: AttributeType) -> Option<Attribute> {
        let i = self.0.iter().position(|a| a.attribute_type() == t)?;
        Some(self.0.remove(i))
    }

    /// The template's attributes, in order.
    pub fn iter(&self) -> impl Iterator<Item = &Attribute> {
        self.0.iter()
    }
}

/// What [`Provider::create`] makes: `object` as `spec` declares it, under `locator`, to be
/// proven by `binding` (private keys).
pub struct Create<'a> {
    /// The object's type.
    pub object: &'a ObjectCfg,
    /// The spec it is created by.
    pub spec: &'a SpecCfg,
    /// Where it goes on the token.
    pub locator: &'a Locator,
    /// How a private key will be proven, which a module-chosen template must allow.
    pub binding: Option<Binding>,
}

/// What [`Provider::destroy`] removes: exactly `handles`, as `object` under `locator`.
pub struct Destroy<'a> {
    /// The objects' type.
    pub object: &'a ObjectCfg,
    /// Where they are on the token.
    pub locator: &'a Locator,
    /// The objects the caller identified; never empty.
    pub handles: &'a [ObjectHandle],
}

/// What a provider can attest (§3.7 of docs/DESIGN.md), from [`Provider::attestation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationCap {
    /// Scheme the commitment records (an attestation scheme: `Scheme::is_attestation`; its
    /// lock-record kind is `Scheme::attestation_kind`).
    pub scheme: Scheme,
    /// Object classes the attestation covers.
    pub classes: &'static [ObjectClass],
    /// Whether it covers a key imported onto the device, not only one the device made: false for
    /// PIV, whose attestation is of keys generated on the `YubiKey`. An import such an attestation
    /// cannot cover is refused before the key is written (15), where the device may keep it.
    pub imported: bool,
}

/// What [`Provider::import_plaintext`] gets: the token as keys.toml describes it, the key's type
/// and locator, and the plaintext. Never `Debug`: it would print the key and the PIN.
pub struct ImportCtx<'a> {
    /// The token, as keys.toml describes it.
    pub cfg: &'a TokenCfg,
    /// The token's name in keys.toml.
    pub token_name: &'a str,
    /// The user PIN, when the token has one.
    pub pin: Option<&'a str>,
    /// The key's type.
    pub object: &'a ObjectCfg,
    /// Where the key goes on the token.
    pub locator: &'a Locator,
    /// The plaintext key, as the source handed it over (PKCS#8 for a private key).
    pub key: &'a [u8],
}

/// Everything an attestation may need beyond the PKCS#11 module: the session (to find the
/// certificate objects a module exposes), the config (the native TPM path's TCTI and store) and
/// the PIN (the TPM path unseals the token's wrapping key with it), plus the material SPKI the
/// attestation must name (`None` exactly for secret keys, which have none).
///
/// `provision` is true only under `lock`: a provider that keeps device state to attest with
/// (the TPM Attestation Key) may create it then, never on a read (`resolve`, `verify`).
pub struct AttestCtx<'a> {
    /// An open session on the token, for the objects the module exposes (attestation
    /// certificates).
    pub session: &'a Session,
    /// The token, as keys.toml describes it (the native TPM path's TCTI and store).
    pub cfg: &'a TokenCfg,
    /// The module's version as `C_GetInfo` reports it ("1.10").
    pub module_version: &'a str,
    /// Whether the module has a mechanism (`C_GetMechanismInfo` answers): how a provider finds
    /// the vendor mechanisms its module has (tpm2-pkcs11's `CKM_TPM2_*`), which cryptoki 0.12.1
    /// leaves out of the list `C_GetMechanismList` returns because it has no name for them (main
    /// keeps them, 6cc2278; this works with either).
    pub has_mechanism: &'a dyn Fn(MechanismType) -> bool,
    /// The token's name in keys.toml.
    pub token_name: &'a str,
    /// The key to attest.
    pub key: ObjectHandle,
    /// The key's type.
    pub object: &'a ObjectCfg,
    /// The material SPKI the attestation must name: `None` exactly for secret keys.
    pub spki: Option<&'a [u8]>,
    /// The user PIN, when the token has one (the TPM path unseals the token's wrapping key
    /// with it).
    pub pin: Option<&'a str>,
    /// True only under `lock`: the provider may create the device state it attests with (the
    /// TPM Attestation Key), never on a read.
    pub provision: bool,
    /// When the attestation's certificates must be valid, and whether a fault in their dates refuses.
    pub chain_time: ChainTime,
}

/// When the certificates of an attestation chain must be valid (ISSUES.md B8). `check` holds
/// every link to its validity period, at the system clock's time unless told another
/// (`--at`, `--ignore-validity`); every other verb (`lock`, `create`, `verify`, camigrate) judges
/// the dates by the clock too but only warns ([`ChainTime::Warn`]): `check` is what enforces. There is
/// no default: every token open names one ([`crate::Token::open`]), so no reader of
/// attestations skips the dates by forgetting to ask (review D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainTime {
    /// The dates are not checked.
    Unchecked,
    /// Valid at this time: seconds since the Unix epoch, UTC.
    At(u64),
    /// Judged at this time, but a chain whose only fault is its dates is accepted with a warning
    /// ([`Attested::warning`]).
    Warn(u64),
    /// Asked for now, and the system clock reads before the Unix epoch: there is no time to judge
    /// the dates by. [`ChainTime::verify`] refuses, naming the clock, or with `warn` (a verb
    /// other than `check`) verifies the chain without its dates and warns so.
    NoClock {
        /// Whether a chain is accepted, with a warning, rather than refused.
        warn: bool,
    },
}

/// What [`ChainTime::NoClock`] says.
const NO_CLOCK: &str = "the system clock reads before 1970, so the attestation chain's dates cannot be judged: set \
     the clock, or `check --at <time>` judges them at another time (`--ignore-validity` skips them)";

impl ChainTime {
    /// Now, by the system clock. Never `SOURCE_DATE_EPOCH`: Nix's stdenv sets it to 1980 in
    /// every build, where every chain would be not yet valid.
    #[must_use]
    pub fn now() -> Self {
        Self::by_clock(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH), false)
    }

    /// Now, by the system clock, warning only: what every verb but `check` judges dates with.
    #[must_use]
    pub fn warn_now() -> Self {
        Self::by_clock(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH), true)
    }

    /// The time the clock's reading `since` the epoch gives, refusing (or with `warn`, warning)
    /// for a clock before it: never the epoch itself, where every chain is "not yet valid" and
    /// nothing names the clock (provider.rs F2).
    fn by_clock(since: std::result::Result<std::time::Duration, std::time::SystemTimeError>, warn: bool) -> Self {
        match (since, warn) {
            (Ok(d), false) => ChainTime::At(d.as_secs()),
            (Ok(d), true) => ChainTime::Warn(d.as_secs()),
            (Err(_), warn) => ChainTime::NoClock { warn },
        }
    }

    /// Verify a chain by `verify`, given the time to hold its dates to (`None`: unchecked). Under
    /// [`ChainTime::Warn`], a chain that fails only at that time (it verifies without the dates)
    /// is accepted, with the dated failure as the warning; any other failure is the undated one.
    /// [`ChainTime::NoClock`] has no time: refused, or (warning) verified without the dates.
    ///
    /// # Errors
    ///
    /// Whatever `verify` returns, as above; `Unavailable` for [`ChainTime::NoClock`] that refuses.
    pub fn verify<T>(self, verify: impl Fn(Option<u64>) -> Result<T>) -> Result<(T, Option<String>)> {
        match self {
            ChainTime::Unchecked => verify(None).map(|v| (v, None)),
            ChainTime::At(t) => verify(Some(t)).map(|v| (v, None)),
            ChainTime::Warn(t) => match verify(Some(t)) {
                Ok(v) => Ok((v, None)),
                Err(dated) => verify(None).map(|v| (v, Some(dated.to_string()))),
            },
            ChainTime::NoClock { warn: false } => Err(KmError::Unavailable(NO_CLOCK.into())),
            ChainTime::NoClock { warn: true } => verify(None).map(|v| (v, Some(NO_CLOCK.to_owned()))),
        }
    }

    /// An RFC 3339 time in UTC, `YYYY-MM-DDTHH:MM:SSZ` (`check --at`).
    ///
    /// # Errors
    ///
    /// `Validation` (17) for anything else.
    pub fn parse(s: &str) -> Result<Self> {
        let t: der::DateTime = s.parse().map_err(|e| {
            KmError::Validation(format!("--at {s}: not an RFC 3339 time in UTC (YYYY-MM-DDTHH:MM:SSZ): {e}").into())
        })?;
        Ok(ChainTime::At(t.unix_duration().as_secs()))
    }
}

impl AttestCtx<'_> {
    /// The material SPKI, required for asymmetric classes: an attestation that could not be
    /// cross-checked against the key `rfc7093m4` names would be provenance for unknown material.
    ///
    /// # Errors
    ///
    /// `Unsupported` when an asymmetric class has no SPKI to check against.
    pub fn required_spki(&self) -> Result<Option<&[u8]>> {
        match (self.object.class, self.spki) {
            (c, None) if c.is_asymmetric() => Err(KmError::Unsupported(
                format!("attesting a {} needs its material SPKI to cross-check against", self.object.class).into(),
            )),
            (_, spki) => Ok(spki),
        }
    }
}

/// A computed attestation commitment (§3.7 of docs/DESIGN.md): the scheme digest plus the
/// anchor the attestation was verified against — recorded in the lock as the realisation's
/// `attestation = { kind, root, id }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// The attestation scheme.
    pub scheme: Scheme,
    /// The per-device attestation ID.
    pub id: String,
    /// SRI digest of the anchor the attestation was verified to.
    pub root: String,
    /// Why the chain would fail `check` though it verified: its dates, under
    /// [`ChainTime::Warn`].
    pub warning: Option<String>,
}

/// Plain PKCS#11, used when no registered provider recognises the module.
pub struct Generic;

impl Provider for Generic {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        true
    }
}

/// A module that needs no code of its own (docs/CAPROBE.md: no Rust for a module without
/// fix-ups): recognised by the `[match] manufacturer` of its module profiles, named by their
/// family, every hook the default. `softhsm` and `kryoptic` are these (aws-cloudhsm has a crate
/// of its own).
pub struct Data(&'static str);

impl Provider for Data {
    fn name(&self) -> &'static str {
        self.0
    }

    /// Never asked: the registry detects data providers from the profiles, not one by one.
    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }
}

/// Registered providers. The CLI builds one from the provider crates it links; a downstream
/// binary adds its own with [`Registry::with`] (see the `custom-provider` example). A module
/// profile's family is a provider too ([`Data`]), with no code: the registry falls back to the
/// profiles when no code provider is named or claims a module.
#[derive(Clone, Default)]
pub struct Registry {
    providers: Vec<Arc<dyn Provider>>,
}

impl Registry {
    /// An empty registry: no provider beyond [`Generic`] and the profiles' [`Data`] ones.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Extend the registry with another provider, builder-style: the registry it returns is
    /// the one to use (the `#[must_use]` is load-bearing — the input is consumed).
    #[must_use]
    pub fn with(mut self, p: impl Provider + 'static) -> Self {
        self.providers.push(Arc::new(p));
        self
    }

    /// The names of the code providers registered, in registration order.
    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Whether `name` is a provider this registry can select explicitly.
    ///
    /// # Errors
    ///
    /// As [`Self::named`].
    pub fn knows(&self, name: &str) -> Result<bool> {
        Ok(self.named(name)?.is_some())
    }

    /// The provider registered as `name` (or [`Generic`]), else the module profile family of
    /// that name ([`Data`]), without loading any module.
    ///
    /// # Errors
    ///
    /// `Validation` (17) when no profile set is active: never taken for "no such provider"
    /// (ISSUES.md Q24).
    pub fn named(&self, name: &str) -> Result<Option<Arc<dyn Provider>>> {
        let set = Set::active().map_err(|e| KmError::Validation(e.into()))?;
        Ok(self.named_in(set, name))
    }

    fn named_in(&self, set: &'static Set, name: &str) -> Option<Arc<dyn Provider>> {
        if name == Generic.name() {
            return Some(Arc::new(Generic));
        }
        if let Some(p) = self.providers.iter().find(|p| p.name() == name) {
            return Some(Arc::clone(p));
        }
        let family = set.module_family_names().into_iter().find(|f| *f == name)?;
        Some(Arc::new(Data(family)))
    }

    /// The explicitly configured provider; else the first registered one that recognises the
    /// module; else the module profile family whose `[match] manufacturer` it reports
    /// ([`Data`]); else [`Generic`].
    ///
    /// # Errors
    ///
    /// `Validation` when `explicit` names neither a provider nor a profile family, or when the
    /// module's manufacturer is claimed by the profiles of several families and none is named.
    pub fn select(&self, explicit: Option<&str>, module: &ModuleInfo) -> Result<Arc<dyn Provider>> {
        self.select_in(Set::active().map_err(|e| KmError::Validation(e.into()))?, explicit, module)
    }

    fn select_in(&self, set: &'static Set, explicit: Option<&str>, module: &ModuleInfo) -> Result<Arc<dyn Provider>> {
        if let Some(name) = explicit {
            return self.named_in(set, name).ok_or_else(|| {
                KmError::Validation(
                    format!(
                        "unknown provider '{name}' (registered: generic, {}; profile families: {})",
                        self.names().join(", "),
                        set.module_family_names().join(", ")
                    )
                    .into(),
                )
            });
        }
        if let Some(p) = self.providers.iter().find(|p| p.matches(module)) {
            return Ok(Arc::clone(p));
        }
        let manufacturer = module.manufacturer.trim_end_matches([' ', '\0']);
        match set.module_families(manufacturer)[..] {
            [] => Ok(Arc::new(Generic)),
            [family] => Ok(Arc::new(Data(family))),
            ref families => Err(KmError::Validation(
                format!(
                    "the module's manufacturer '{manufacturer}' is claimed by the profiles of several families \
                 ({}): name one in `provider`",
                    families.join(", ")
                )
                .into(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    /// Every verb but `check` warns about a chain's dates, `check` refuses it, `--ignore-validity`
    /// skips them; a chain wrong for any other reason is refused under each (review D5).
    #[test]
    fn a_chain_out_of_its_dates_warns_where_check_refuses() {
        use super::ChainTime::{At, Unchecked, Warn};
        let dated = |at: Option<u64>| match at {
            Some(t) if t > 100 => Err(KmError::Conflict("'slot' is not valid at 101".into())),
            _ => Ok("attested"),
        };
        assert_eq!(Warn(50).verify(dated).unwrap(), ("attested", None));
        let (v, warning) = Warn(101).verify(dated).unwrap();
        assert_eq!((v, warning.as_deref()), ("attested", Some("conflict: 'slot' is not valid at 101")));
        assert_eq!(At(101).verify(dated).unwrap_err().exit_code(), 13);
        assert_eq!(Unchecked.verify(dated).unwrap(), ("attested", None));
        let unpinned = |_: Option<u64>| -> Result<&str> { Err(KmError::Conflict("signed by no pinned root".into())) };
        for when in [Warn(101), At(101), Unchecked] {
            assert!(when.verify(unpinned).unwrap_err().to_string().contains("no pinned root"), "{when:?}");
        }
    }

    /// A system clock before 1970 is no time to judge dates by (provider.rs F2): `check` refuses
    /// naming the clock, every other verb verifies without the dates and warns so; never the
    /// epoch, where every chain is "not yet valid" and nothing says why.
    #[test]
    fn a_clock_before_the_epoch_is_named() {
        use std::time::{Duration, UNIX_EPOCH};
        let before = UNIX_EPOCH.duration_since(UNIX_EPOCH + Duration::from_secs(1));
        assert_eq!(ChainTime::by_clock(before.clone(), false), ChainTime::NoClock { warn: false });
        assert_eq!(ChainTime::by_clock(before, true), ChainTime::NoClock { warn: true });
        assert_eq!(ChainTime::by_clock(Ok(Duration::from_secs(7)), false), ChainTime::At(7));
        assert_eq!(ChainTime::by_clock(Ok(Duration::from_secs(7)), true), ChainTime::Warn(7));
        let dated = |at: Option<u64>| at.map_or(Ok("attested"), |_| Err(KmError::Conflict("not valid at 0".into())));
        let e = ChainTime::NoClock { warn: false }.verify(dated).unwrap_err();
        assert!(matches!(&e, KmError::Unavailable(m) if m.contains("system clock reads before 1970")), "{e}");
        let (v, warning) = ChainTime::NoClock { warn: true }.verify(dated).unwrap();
        assert_eq!(v, "attested");
        assert!(warning.is_some_and(|w| w.contains("system clock")));
    }

    use super::*;

    struct Acme;
    impl Provider for Acme {
        fn name(&self) -> &'static str {
            "acme"
        }
        fn matches(&self, m: &ModuleInfo) -> bool {
            m.manufacturer == "Acme"
        }
    }

    /// A code provider for a manufacturer the profiles also name (`SoftHSM`'s).
    struct Mine;
    impl Provider for Mine {
        fn name(&self) -> &'static str {
            "mine"
        }
        fn matches(&self, m: &ModuleInfo) -> bool {
            m.manufacturer == "SoftHSM"
        }
    }

    /// A provider's template keeps one attribute per type: setting replaces in place.
    #[test]
    fn attributes_hold_one_of_each_type() {
        struct Vendor;
        impl Provider for Vendor {
            fn name(&self) -> &'static str {
                "vendor"
            }
            fn matches(&self, _: &ModuleInfo) -> bool {
                false
            }
            fn template(&self, _: &Template<'_>, attrs: &mut Attributes) -> Result<()> {
                attrs.set(Attribute::Sensitive(false));
                attrs.set(Attribute::Label(b"v".to_vec()));
                assert_eq!(attrs.remove(AttributeType::Token), Some(Attribute::Token(false)));
                assert_eq!(attrs.remove(AttributeType::Token), None);
                assert_eq!(attrs.get(AttributeType::Sensitive), Some(&Attribute::Sensitive(false)));
                Ok(())
            }
        }
        let p: &dyn Provider = &Vendor;
        let t = vec![Attribute::Token(false), Attribute::Sensitive(true), Attribute::Wrap(true)];
        let req = Template::Session(SessionKey::RebindKek);
        assert_eq!(
            p.adjusted(&req, t.clone()).unwrap(),
            [Attribute::Sensitive(false), Attribute::Wrap(true), Attribute::Label(b"v".to_vec())]
        );
        let generic: &dyn Provider = &Generic;
        assert_eq!(generic.adjusted(&req, t.clone()).unwrap(), t, "the default changes nothing");
    }

    fn module(manufacturer: &str) -> ModuleInfo {
        ModuleInfo {
            path: "/x.so".into(),
            hash: None,
            description: "d".into(),
            manufacturer: manufacturer.into(),
            version: "1.0".into(),
            cryptoki: "2.40".into(),
        }
    }

    #[test]
    fn selection_explicit_then_detected_then_generic() {
        Set::activate_embedded().unwrap();
        let r = Registry::new().with(Acme);
        assert_eq!(r.select(None, &module("Acme")).unwrap().name(), "acme");
        assert_eq!(r.select(None, &module("Other")).unwrap().name(), "generic");
        assert_eq!(r.select(Some("generic"), &module("Acme")).unwrap().name(), "generic");
        assert_eq!(r.select(Some("acme"), &module("Other")).unwrap().name(), "acme");
        assert!(matches!(r.select(Some("nope"), &module("Acme")), Err(KmError::Validation(_))));
        assert!(r.knows("acme").unwrap() && r.knows("generic").unwrap() && !r.knows("nope").unwrap());
    }

    /// A module no code claims is named by its profiles' family; code providers come first, a
    /// family is selectable by name, and two families claiming one manufacturer are refused.
    #[test]
    fn profiles_name_the_modules_code_does_not_claim() {
        let set: &'static Set = Box::leak(Box::new(Set::embedded().unwrap()));
        let r = Registry::new().with(Acme);
        assert_eq!(r.select_in(set, None, &module("SoftHSM")).unwrap().name(), "softhsm");
        assert_eq!(r.select_in(set, None, &module("Kryoptic")).unwrap().name(), "kryoptic");
        assert_eq!(r.select_in(set, None, &module("CloudHSM")).unwrap().name(), "aws-cloudhsm");
        // A layer's manufacturer (p11-kit's) names no module.
        assert_eq!(r.select_in(set, None, &module("PKCS#11 Kit")).unwrap().name(), "generic");
        assert_eq!(r.select_in(set, Some("softhsm"), &module("PKCS#11 Kit")).unwrap().name(), "softhsm");
        assert_eq!(r.select_in(set, Some("aws-cloudhsm"), &module("Other")).unwrap().name(), "aws-cloudhsm");
        // A provider is a family: one module profile's name is none (keys.toml's moduleProfile).
        let pair = Some("aws-cloudhsm/5.18+hsm2m-non-fips");
        assert!(r.select_in(set, pair, &module("CloudHSM")).is_err());
        let e = r.select_in(set, Some("nope"), &module("x")).err().unwrap();
        assert!(e.to_string().contains("profile families: aws-cloudhsm"), "{e}");
        // Code before data: a provider claiming SoftHSM's manufacturer wins.
        assert_eq!(Registry::new().with(Mine).select_in(set, None, &module("SoftHSM")).unwrap().name(), "mine");
        let dir = std::env::temp_dir().join(format!("cakeys-provider-twins-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("t.toml"),
            "profile = \"twin/1\"\nmode = \"observed\"\n[match]\nmanufacturer = \"SoftHSM\"\n",
        )
        .unwrap();
        let twins: &'static Set = Box::leak(Box::new(Set::embedded().unwrap().adding_dir(&dir).unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
        let e = r.select_in(twins, None, &module("SoftHSM")).err().unwrap();
        assert!(e.to_string().contains("several families (softhsm, twin)"), "{e}");
        assert_eq!(r.select_in(twins, Some("twin"), &module("SoftHSM")).unwrap().name(), "twin");
    }
}
