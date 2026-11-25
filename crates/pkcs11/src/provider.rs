//! Module-specific behaviour: repairs and operations ([`Provider`]); a provider crate
//! overrides only what its module gets wrong. Every fix-up must return exactly what a
//! spec-compliant module would, so identities stay portable across modules and versions.

use crate::Token;
use crate::chain_time::ChainTime;
use cakeys_core::config::{Binding, Locator, ModuleInfo, Object, ObjectCfg, Options, SpecCfg, TokenCfg};
use cakeys_core::id::Scheme;
use cakeys_core::plan::Target;
use cakeys_core::types::ObjectClass;
use cakeys_core::{KmError, Result};
pub use cakeys_profile::PlaintextKind;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectHandle};
use cryptoki::session::Session;
use std::borrow::Cow;

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

/// What an `Unsupported` refusal is about ([`Provider::hint`], `Token::unsupported_for`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topic {
    /// Generating a key on the token.
    Generate,
    /// Creating an object from a value (`C_CreateObject`): an import, a copy, a public object.
    Create,
    /// A mechanism the operation needs and the token does not offer or refuses.
    Mechanism,
}

/// What one family of PKCS#11 modules needs beyond the standard, at three kinds of seam and
/// nothing else (docs/archive/REVIEW-2026-11-15.md §4 named the first two):
///
/// - *repairs*, where a module's answer is made what a spec-compliant module's would be: one
///   for each attribute read that needs one ([`Self::ec_point`], [`Self::key_type`],
///   [`Self::policy_flag`]), one for a mechanism ([`Self::stand_in`]);
/// - *templates*, where cakeys' own template for a call is made one the module takes: one for
///   every template cakeys builds, named by what it is for ([`Self::template`]);
/// - *operations*, which a provider may replace whole, the default being plain PKCS#11 through
///   a public [`Token`] method an override can wrap: [`Self::create`] and [`Self::destroy`]; and
///   the two a provider names with what they are, so the pair cannot disagree:
///   [`Self::plaintext_import`] (its tool) and [`Self::attestation`] (its computation).
///
/// Beside them: how to recognise the module, its settings and advice, and the facts a caller
/// must know before it acts ([`Self::manages_as_so`], [`Self::generation`]). Two hooks only the
/// probe reads: [`Self::bound_keys`] lists what it generates on a module whose keys are bound to
/// one purpose, and [`Self::scratch_companion`] guards its scratch slot. A provider that seems to
/// need a new hook overrides an operation in its own crate instead.
///
/// The in-tree providers are crates of this workspace (`cakeys-ykcs11`, `cakeys-tpm2-pkcs11`,
/// `cakeys-kmsp11`, `cakeys-aws-cloudhsm`); a crate outside it adds its own to a [`Registry`](crate::Registry)
/// (the `custom-provider` example). A module with no fix-ups needs none: its capability
/// profile names it ([`Data`]).
pub trait Provider: Send + Sync {
    /// Name for `provider = "<name>"` in keys.toml and in messages.
    fn name(&self) -> &'static str;

    /// Whether this provider recognises the loaded module (from `C_GetInfo`), for auto-detection.
    fn matches(&self, module: &ModuleInfo) -> bool;

    /// Advice appended when the module cannot do what `about` names: only where it applies, so a
    /// refused proof mechanism never carries advice about generating keys (review 2026-11-23 B-9).
    fn hint(&self, about: Topic) -> Option<&'static str> {
        let _ = about;
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

    // Each repairs what the module reported for one attribute read to what a spec-compliant
    // module would report. The policy check, the identities and the lock all see the result, so
    // identities stay portable across modules and versions; the profile keeps the raw
    // observation. The defaults change nothing. One typed hook per read, so no repair can answer
    // for another (review 2026-11-23 B-22).

    /// `CKA_EC_POINT` as `raw` reads, which tpm2-pkcs11 and AWS `CloudHSM` encode their own way.
    fn ec_point<'a>(&self, raw: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(raw)
    }

    /// `CKA_KEY_TYPE` as `reported`, with the object's `CKA_EC_PARAMS` where it has them: AWS
    /// `CloudHSM` reports an Ed25519 key as `CKK_EC` \[run\].
    fn key_type(&self, reported: KeyType, ec_params: Option<&[u8]>) -> KeyType {
        let _ = ec_params;
        reported
    }

    /// The (attribute, private key type) pairs [`Self::policy_flag`] repairs: asked of no other
    /// read, so a repair cannot widen a permission it does not declare (review 2026-11-24 B-3).
    /// The default repairs none.
    fn repairs(&self) -> &'static [(AttributeType, KeyType)] {
        &[]
    }

    /// A boolean policy attribute `attr` (`CKA_SIGN`, `CKA_DERIVE`, ...) of a private key of
    /// type `private_key_type`, as `reported`; asked only of the pairs [`Self::repairs`]
    /// declares, and the closure always reads that type. ykcs11's fixed table says `CKA_DERIVE`
    /// false on keys its `C_DeriveKey` derives with (the profile keeps the raw observation,
    /// `derive.key-attribute`).
    fn policy_flag(&self, attr: AttributeType, reported: bool, private_key_type: &dyn Fn() -> Option<KeyType>) -> bool {
        let _ = (attr, private_key_type);
        reported
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
    /// a vendor attribute set, a default it refuses removed. A security attribute ([`SECURITY`]:
    /// where the object lives, who sees it, whether it leaves, its locator, what may change it)
    /// is checked on return: changed, added or removed, the template is refused (17), unless the
    /// change tightens it (review 2026-11-24 B-3). Every template the verbs build for
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
        _object: Object<'_>,
        _spec: &SpecCfg,
        _loc: &Locator,
        _binding: Option<Binding>,
    ) -> Result<Option<Generation>> {
        Ok(None)
    }

    /// Whether a key may be made under `loc` on this module, generated or imported: a module
    /// that places keys into fixed slots by their locator (ykcs11's PIV slots) refuses one it
    /// cannot place. Static, so asked before anything is created, by core and never by an
    /// override: the static rules ([`crate::ops::static_rules`]) ask it for every pair a write
    /// puts on the token (the capability gate, `create`, every import's
    /// [`crate::ops::check_import`]), and [`Token::create`] before it calls [`Self::create`]
    /// (review 2026-11-24 B-2: only ykcs11's `create` override asked it there). The default
    /// places a key anywhere.
    ///
    /// # Errors
    ///
    /// `Validation` (17) naming why the locator places no key.
    fn placement(&self, _loc: &Locator) -> Result<()> {
        Ok(())
    }

    /// Whether this module removes an object of `class` under `loc` when asked: a module whose
    /// `C_DestroyObject` reports success and keeps it refuses (15), naming how it is removed
    /// (ykcs11 keeps a PIV slot's key). Static, so asked before anything is destroyed and before
    /// any SO session, by core and never by an override: by `delete`'s plan and by every destroy
    /// of the token's ([`Token::destroy_handles`]). The default removes anything.
    ///
    /// # Errors
    ///
    /// `Unsupported` (15) naming why the object would stay.
    fn deletion(&self, _class: cakeys_core::types::ObjectClass, _loc: &Locator) -> Result<()> {
        Ok(())
    }

    /// Create `req`'s object on `tok`. [`Token::create`] calls it, and only it can: it asks
    /// [`Self::placement`] first and enters the SO session where [`Self::manages_as_so`] says the
    /// module needs one, then hands over a [`Checked`] request no other crate can build, so an
    /// override can skip neither (review 2026-11-24 B-2). The default is
    /// [`Token::create_declared`]: the module's own template where [`Self::generation`] chooses
    /// one, else cakeys' templates.
    ///
    /// # Errors
    ///
    /// As [`Token::create_declared`], plus the override's refusals.
    fn create(&self, tok: &Token, req: &Checked<Create<'_>>) -> Result<Option<crate::token::CreateNote>> {
        tok.create_declared(req)
    }

    /// Destroy `req`'s handles, identified by the caller, on `tok`. The token's destroys call it
    /// once [`Self::deletion`] allows them, in the SO session where [`Self::manages_as_so`] says
    /// the module needs one, with a [`Checked`] request. The default is
    /// [`Token::destroy_plain`]: `C_DestroyObject` each. The count it returns is a claim: what a
    /// delete destroyed is looked for again after it.
    ///
    /// # Errors
    ///
    /// As [`Token::destroy_plain`], plus the override's refusals.
    fn destroy(&self, tok: &Token, req: &Checked<Destroy<'_>>) -> Result<usize> {
        tok.destroy_plain(req)
    }

    /// How plaintext keys get into this module ([`PlaintextVia`]): `C_CreateObject` by default
    /// (as SO where the provider manages as SO), or the provider's own tool, which comes with
    /// the kind it is named by, so the two cannot disagree (review 2026-11-23 B-27).
    fn plaintext_import(&self) -> PlaintextVia {
        PlaintextVia::CreateObject(PlaintextKind::CreateObject)
    }

    /// The attestation commitment this provider can compute (§3.7 of docs/DESIGN.md), if any:
    /// the scheme it records, the object classes it can attest, and the computation itself.
    /// `None` (the default): this module exposes no attestation, so a spec opting into one is
    /// refused (15) before anything is created.
    fn attestation(&self) -> Option<AttestationCap> {
        None
    }

    // ── Read only by the probe ───────────────────────────────────────────────────────────

    /// The keys a module binds to one purpose when it creates them (Google Cloud KMS: one
    /// algorithm per key), each with the exact template it is generated from: the write probe
    /// generates these instead of its own templates. Empty for a module whose keys are general
    /// purpose, the default.
    fn bound_keys(&self) -> Vec<BoundKey> {
        Vec::new()
    }

    /// Whether `cert` (DER), found under the probe's scratch `CKA_ID` (`id`,
    /// `tokens.<t>.probe.scratchId`) beside the probe's own certificate, is one the module keeps
    /// beside any key in a slot (ykcs11: the device's attestation of the slot), which says nothing
    /// of whose key it is. Only the probe's certificate marks a slot as the probe's; a
    /// certificate the module writes for every key it generates is no companion, since a real
    /// key has it too (review 2026-11-23 D-1). The default recognises none.
    fn scratch_companion(&self, _id: &[u8], _cert: &[u8]) -> bool {
        false
    }
}

impl dyn Provider + '_ {
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

    /// `e` with the provider's advice on `about` where it is an `Unsupported` refusal and the
    /// provider has any ([`Provider::hint`]); any other error as it is.
    #[must_use]
    pub fn hinted(&self, about: Topic, e: KmError) -> KmError {
        match (e, self.hint(about)) {
            (KmError::Unsupported(m), Some(h)) => {
                let (rv, rule) = (m.rv(), m.rule());
                let e = KmError::Unsupported(format!("{m} (hint for {}: {h})", self.name()).into()).with_rv(rv);
                match rule {
                    Some(r) => e.with_rule(r),
                    None => e,
                }
            }
            (e, _) => e,
        }
    }

    /// `template`, cakeys' template for `req`, as the provider adjusts it ([`Provider::template`]),
    /// its security attributes ([`SECURITY`]) as cakeys built them or tightened (review
    /// 2026-11-24 B-3: a provider could make a sealed session key extractable, or move a key off
    /// its locator, and nothing read it back).
    ///
    /// # Errors
    ///
    /// The provider's refusal; `Validation` (17) when it changed, added or removed a security
    /// attribute other than to tighten it.
    pub fn adjusted(&self, req: &Template<'_>, template: Vec<Attribute>) -> Result<Vec<Attribute>> {
        let built = template.clone();
        let mut attrs = Attributes(template);
        self.template(req, &mut attrs)?;
        for (t, name, tightened) in SECURITY {
            let (before, after) = (built.iter().find(|a| a.attribute_type() == t), attrs.get(t));
            if before == after || tightened.is_some_and(|(made, v)| after == Some(&made(v))) {
                continue;
            }
            let show = |a: Option<&Attribute>| a.map_or_else(|| "absent".to_owned(), |a| format!("{a:?}"));
            return Err(KmError::Validation(
                format!(
                    "provider '{}' changed {name} in cakeys' template for {}, from {} to {}: a provider adjusts \
                     no security attribute but to tighten it",
                    self.name(),
                    req.purpose(),
                    show(before),
                    show(after)
                )
                .into(),
            ));
        }
        Ok(attrs.0)
    }

    /// The session template `t` as the provider adjusts it ([`Self::adjusted`]), asked as the
    /// session key it was built for, so the two cannot disagree.
    ///
    /// # Errors
    ///
    /// As [`Self::adjusted`].
    pub fn adjusted_session(&self, t: crate::templates::SessionTemplate) -> Result<Vec<Attribute>> {
        self.adjusted(&Template::Session(t.key()), t.into())
    }
}

/// The value that tightens a security attribute ([`SECURITY`]), as its constructor and the
/// value: `None` where no change does.
pub type Tightening = Option<(fn(bool) -> Attribute, bool)>;

/// The attributes a provider's template hook may not change ([`Provider::template`]), each with
/// the value that tightens it where one does: a restriction set true, a permission set false
/// (phase1-design.md §3.2.2). The others (where the object lives, its locator, what may change,
/// copy or destroy it) are kept as built.
pub const SECURITY: [(AttributeType, &str, Tightening); 11] = [
    (AttributeType::Token, "CKA_TOKEN", None),
    (AttributeType::Private, "CKA_PRIVATE", Some((Attribute::Private, true))),
    (AttributeType::Sensitive, "CKA_SENSITIVE", Some((Attribute::Sensitive, true))),
    (AttributeType::Extractable, "CKA_EXTRACTABLE", Some((Attribute::Extractable, false))),
    (AttributeType::WrapWithTrusted, "CKA_WRAP_WITH_TRUSTED", Some((Attribute::WrapWithTrusted, true))),
    (AttributeType::Trusted, "CKA_TRUSTED", Some((Attribute::Trusted, false))),
    (AttributeType::Id, "CKA_ID", None),
    (AttributeType::Label, "CKA_LABEL", None),
    (AttributeType::Modifiable, "CKA_MODIFIABLE", None),
    (AttributeType::Copyable, "CKA_COPYABLE", None),
    (AttributeType::Destroyable, "CKA_DESTROYABLE", None),
];

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
    /// The trusted copy of a transport key, made as SO (`camigrate transport --trust-on`).
    TrustedCopy,
    /// A session object cakeys makes for one step and destroys after it.
    Session(SessionKey),
}

impl Template<'_> {
    /// What the template is for, as a refusal names it.
    #[must_use]
    pub fn purpose(&self) -> String {
        match self {
            Template::Generate(on, half) => format!("generating {half:?} under {}", on.locator),
            Template::Import(on, via) => format!("importing ({via:?}) under {}", on.locator),
            Template::PublicHalf(on) => format!("the public half under {}", on.locator),
            Template::Object(on) => format!("the object under {}", on.locator),
            Template::TrustedCopy => "a transport key's trusted copy".to_owned(),
            Template::Session(key) => format!("the session key {key:?}"),
        }
    }
}

/// The object a template makes: `object` as `spec` declares it, under `locator`.
#[derive(Clone, Copy)]
pub struct Declared<'a> {
    /// The object, parsed.
    pub object: Object<'a>,
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

/// A request the token checked before it asks the provider ([`Provider::create`],
/// [`Provider::destroy`]): only this crate makes one, after the rules core asks first (where a
/// key may go) and in the session the module writes in, so an override that receives it was
/// called through them. It reads as the request it holds.
pub struct Checked<T>(T);

impl<T> Checked<T> {
    /// `req`, once the token has checked it.
    pub(crate) fn new(req: T) -> Checked<T> {
        Checked(req)
    }
}

impl<T> std::ops::Deref for Checked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

/// What [`Provider::create`] makes: `object` as `spec` declares it, under `locator`, to be
/// proven by `binding` (private keys).
pub struct Create<'a> {
    /// The object, parsed.
    pub object: Object<'a>,
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

/// What a provider can attest (§3.7 of docs/DESIGN.md), from [`Provider::attestation`], and how.
#[derive(Debug, Clone, Copy)]
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
    /// Compute the attestation commitment for `ctx.key` on its token (called only when the
    /// spec opted in and `classes` covers it): the canonical scheme digest plus the anchor it
    /// was verified to. A missing attestation is an error naming the reason (an imported key, a
    /// session that could not attest), never a pass: `Unavailable` when the token has none to
    /// give, `Conflict` (13) when it names other material than `ctx.spki`.
    pub attest: fn(&AttestCtx<'_>) -> Result<Attested>,
}

/// How plaintext keys get into a module ([`Provider::plaintext_import`]), each with the kind a
/// profile's `plaintext-import` and an `import.*` row's `via` name it by.
#[derive(Debug, Clone, Copy)]
pub enum PlaintextVia {
    /// `C_CreateObject` with the key's attributes: `create-object`, or `piv-import` (ykcs11, as
    /// SO into a PIV slot).
    CreateObject(PlaintextKind),
    /// The provider's own tool, outside PKCS#11 (docs/CAMIGRATE.md `tpm2-ptool`: tpm2-pkcs11
    /// creates keys from values only through `tpm2_ptool import`): `ctx.key` is a private key's
    /// PKCS#8 `PrivateKeyInfo` or a secret key's value. The caller opens the token again
    /// afterwards to see the key. Errors: `Unsupported` for a key type the tool cannot take,
    /// else whatever the tool reports.
    Tool(PlaintextKind, fn(&ImportCtx<'_>) -> Result<()>),
}

impl PlaintextVia {
    /// The kind it is named by.
    #[must_use]
    pub fn kind(self) -> PlaintextKind {
        match self {
            PlaintextVia::CreateObject(k) | PlaintextVia::Tool(k, _) => k,
        }
    }
}

/// What a [`PlaintextVia::Tool`] gets: the token as keys.toml describes it, the key's type
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
/// (the TPM Attestation Key) may create it then, never on a read (`resolve`, `check`).
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
    /// The commitments this run computed of the key through PKCS#11: for a secret key, what the
    /// attestation must be bound to in place of an SPKI, the device computing one of them with
    /// the object it attests (review 2026-11-23 B-1). Empty for any other class.
    pub commitments: &'a [Commitment],
    /// The user PIN, when the token has one (the TPM path unseals the token's wrapping key
    /// with it).
    pub pin: Option<&'a str>,
    /// True only under `lock`: the provider may create the device state it attests with (the
    /// TPM Attestation Key), never on a read.
    pub provision: bool,
    /// When the attestation's certificates must be valid, and whether a fault in their dates refuses.
    pub chain_time: ChainTime,
}

/// One commitment the run computed of the key under attestation ([`AttestCtx::commitments`]):
/// what the token operated on and the ID its output gave, as the lock records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// Which commitment.
    pub commit: cakeys_core::id::Commit,
    /// The bytes the token operated on (`Commit::input`, under the run's commitment label).
    pub input: Vec<u8>,
    /// Its ID: the SRI digest of the token's output.
    pub id: String,
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
    /// What the attestation does not establish though it verified, said on every run that
    /// computes it: tpm2-pkcs11's `akLabel` signer, whose public area only the module reports
    /// (review 2026-11-23 B-2).
    pub caveat: Option<String>,
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
pub struct Data(pub(crate) &'static str);

impl Provider for Data {
    fn name(&self) -> &'static str {
        self.0
    }

    /// Never asked: the registry detects data providers from the profiles, not one by one.
    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            // No security attribute changed ([`SECURITY`]): a vendor's own, a use and a subject.
            fn template(&self, _: &Template<'_>, attrs: &mut Attributes) -> Result<()> {
                attrs.set(Attribute::Wrap(false));
                attrs.set(Attribute::Subject(b"v".to_vec()));
                assert_eq!(attrs.remove(AttributeType::Unwrap), Some(Attribute::Unwrap(true)));
                assert_eq!(attrs.remove(AttributeType::Unwrap), None);
                assert_eq!(attrs.get(AttributeType::Wrap), Some(&Attribute::Wrap(false)));
                Ok(())
            }
        }
        let p: &dyn Provider = &Vendor;
        let t = vec![Attribute::Token(false), Attribute::Wrap(true), Attribute::Unwrap(true)];
        let req = Template::Session(SessionKey::RebindKek);
        assert_eq!(
            p.adjusted(&req, t.clone()).unwrap(),
            [Attribute::Token(false), Attribute::Wrap(false), Attribute::Subject(b"v".to_vec())]
        );
        let generic: &dyn Provider = &Generic;
        assert_eq!(generic.adjusted(&req, t.clone()).unwrap(), t, "the default changes nothing");
    }

    /// A provider sets `0` on every template it is asked.
    struct Sets(Attribute);

    impl Provider for Sets {
        fn name(&self) -> &'static str {
            "sets"
        }
        fn matches(&self, _: &ModuleInfo) -> bool {
            false
        }
        fn template(&self, _: &Template<'_>, attrs: &mut Attributes) -> Result<()> {
            attrs.set(self.0.clone());
            Ok(())
        }
    }

    /// A provider removes `0` from every template it is asked.
    struct Removes(AttributeType);

    impl Provider for Removes {
        fn name(&self) -> &'static str {
            "removes"
        }
        fn matches(&self, _: &ModuleInfo) -> bool {
            false
        }
        fn template(&self, _: &Template<'_>, attrs: &mut Attributes) -> Result<()> {
            attrs.remove(self.0);
            Ok(())
        }
    }

    /// Every session template cakeys builds (`templates::session`).
    fn session_keys() -> [SessionKey; 9] {
        let proof = |sealed| SessionKey::ProofSecret { binding: Binding::PopEcdh, sealed };
        [
            proof(true),
            proof(false),
            SessionKey::RebindKek,
            SessionKey::RebindCopy,
            SessionKey::KwInput,
            SessionKey::HostKek,
            SessionKey::TransportKey,
            SessionKey::ExportKek,
            SessionKey::ImportKek,
        ]
    }

    /// What a provider's template hook may do (review 2026-11-24 B-3, phase1-design.md §3.2.2):
    /// on every session template, a security attribute set to a value it does not have, or
    /// removed, is refused (17) naming it, unless the change tightens it (a restriction set
    /// true, a permission false); any other attribute is the provider's. Each template keeps
    /// the security attributes it was built with.
    #[test]
    fn a_provider_changes_no_security_attribute_but_to_tighten_it() {
        // The design's list, written out here so the test does not read the table it checks.
        let names = [
            (AttributeType::Token, "CKA_TOKEN"),
            (AttributeType::Private, "CKA_PRIVATE"),
            (AttributeType::Sensitive, "CKA_SENSITIVE"),
            (AttributeType::Extractable, "CKA_EXTRACTABLE"),
            (AttributeType::WrapWithTrusted, "CKA_WRAP_WITH_TRUSTED"),
            (AttributeType::Trusted, "CKA_TRUSTED"),
            (AttributeType::Id, "CKA_ID"),
            (AttributeType::Label, "CKA_LABEL"),
            (AttributeType::Modifiable, "CKA_MODIFIABLE"),
            (AttributeType::Copyable, "CKA_COPYABLE"),
            (AttributeType::Destroyable, "CKA_DESTROYABLE"),
        ];
        let name = |t: AttributeType| names.iter().find(|n| n.0 == t).map(|n| n.1);
        let loosened = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
            Attribute::WrapWithTrusted(false),
            Attribute::Trusted(true),
            Attribute::Id(b"x".to_vec()),
            Attribute::Label(b"x".to_vec()),
            Attribute::Modifiable(true),
            Attribute::Copyable(true),
            Attribute::Destroyable(false),
        ];
        let tightened = [
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::WrapWithTrusted(true),
            Attribute::Trusted(false),
        ];
        for key in session_keys() {
            let t: Vec<Attribute> = crate::templates::session(key).into();
            let req = Template::Session(key);
            let adjusted = |p: &dyn Provider| p.adjusted(&req, t.clone());
            for a in &loosened {
                let got = adjusted(&Sets(a.clone()));
                if t.contains(a) {
                    assert_eq!(got.unwrap(), t, "{key:?}: {a:?} is what it was built with");
                } else {
                    let e = got.unwrap_err();
                    assert_eq!(e.exit_code(), 17, "{key:?}: {a:?}: {e}");
                    assert!(e.to_string().contains(name(a.attribute_type()).unwrap()), "{e}");
                }
            }
            for a in &tightened {
                assert!(adjusted(&Sets(a.clone())).is_ok(), "{key:?}: tightening {a:?}");
            }
            for present in t.iter().map(Attribute::attribute_type) {
                let security = name(present).is_some();
                assert_eq!(adjusted(&Removes(present)).is_err(), security, "{key:?}: removing {present:?}");
            }
            assert!(adjusted(&Sets(Attribute::Subject(b"s".to_vec()))).is_ok(), "{key:?}: not a security attribute");
        }
    }
}
