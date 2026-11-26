//! Module-specific behavior: repairs and operations ([`Provider`]). A provider crate overrides
//! only what its module gets wrong. Every fix-up must return exactly what a spec-compliant module
//! would return, so that identities stay portable across modules and versions.

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

/// A key that is bound to one purpose when it is created ([`Provider::bound_keys`]).
pub struct BoundKey {
    /// The module's name for the binding (a Cloud KMS algorithm), for use in notes.
    pub name: String,
    /// The `CKA_LABEL`, which is also part of `template`.
    pub label: String,
    /// The PKCS#11 key type that the generation makes: `CKK_EC`, `CKK_RSA`, `CKK_AES`, and so on.
    pub kind: cakeys_profile::KeyKind,
    /// The key's curve name, or its size (in bits for RSA, as [`cakeys_profile::On::parse`]
    /// reads it).
    pub on: cakeys_profile::On,
    /// The generation mechanism, which takes no parameters.
    pub keygen: MechanismType,
    /// The complete template of the private or secret key. No public template is passed.
    pub template: Vec<Attribute>,
    /// The mechanisms that a key with this binding serves. No other mechanism is tried on it.
    pub mechanisms: Vec<MechanismType>,
}

/// A key that the module generates from its own template ([`Provider::generation`]). The module
/// runs `keygen`, which takes no parameters, with `template` alone, which is the template of the
/// private or secret key. A key pair passes no public template.
pub struct Generation {
    /// The generation mechanism, which takes no parameters.
    pub keygen: MechanismType,
    /// The complete template of the private or secret key.
    pub template: Vec<Attribute>,
}

/// Returns the parameterless generation mechanism that `keygen` names, and whether it makes a
/// key pair. A generation that the module chooses ([`Generation`], [`BoundKey`]) runs this
/// mechanism. Returns `None` for any other name.
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

/// The subject of an `Unsupported` refusal ([`Provider::hint`], `Token::unsupported_for`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Topic {
    /// The generation of a key on the token.
    Generate,
    /// The creation of an object from a value (`C_CreateObject`): an import, a copy, or a public
    /// object.
    Create,
    /// A mechanism that the operation needs and that the token does not offer or refuses.
    Mechanism,
}

/// What one family of PKCS#11 modules needs beyond the standard. A provider can change behavior
/// at three kinds of extension point and nowhere else (docs/archive/REVIEW-2026-11-15.md §4 named
/// the first two):
///
/// - *Repairs* change a module's answer into the answer that a spec-compliant module would give.
///   There is one repair for each attribute read that needs one ([`Self::ec_point`],
///   [`Self::key_type`], [`Self::policy_flag`]), and one for a mechanism ([`Self::stand_in`]).
/// - *Templates* change cakeys' own template for a call into a template that the module
///   accepts. There is one hook for every template that cakeys builds, and the hook's argument
///   names what the template is for ([`Self::template`]).
/// - *Operations* can be replaced completely by a provider. The default is plain PKCS#11 through
///   a public [`Token`] method that an override can wrap: [`Self::create`] and [`Self::destroy`].
///   Two more operations return the operation together with its kind, so that the two cannot
///   disagree: [`Self::plaintext_import`] (the provider's tool) and [`Self::attestation`] (its
///   computation).
///
/// The trait also says how to recognize the module, what its settings and advice are, and the
/// facts that a caller must know before it acts ([`Self::manages_as_so`], [`Self::generation`]).
/// Only the probe reads two hooks: [`Self::bound_keys`] lists what the probe generates on a
/// module whose keys are bound to one purpose, and [`Self::scratch_companion`] protects the
/// probe's scratch slot. A provider that seems to need a new hook overrides an operation in its
/// own crate instead.
///
/// The contract suite (crates/cli-common/tests/provider_contract.rs, review 2026-11-24 K-1 to K-7)
/// defines what every provider must satisfy, whatever its module. Each method is a `Hook` there,
/// with the test that checks it for every registered provider, and a method that is added here
/// fails that suite until it has a test.
///
/// The in-tree providers are crates of this workspace (`cakeys-ykcs11`, `cakeys-tpm2-pkcs11`,
/// `cakeys-kmsp11`, `cakeys-aws-cloudhsm`). A crate outside the workspace adds its own provider
/// to a [`Registry`](crate::Registry) (see the `custom-provider` example). A module with no
/// fix-ups needs no provider crate, because its capability profile names it ([`Data`]).
pub trait Provider: Send + Sync {
    /// The name for `provider = "<name>"` in keys.toml and in messages.
    fn name(&self) -> &'static str;

    /// Returns whether this provider recognizes the loaded module (from `C_GetInfo`), for
    /// auto-detection.
    fn matches(&self, module: &ModuleInfo) -> bool;

    /// Returns advice that is appended when the module cannot do what `about` names. Advice is
    /// given only where it applies, so a refused proof mechanism never carries advice about the
    /// generation of keys (review 2026-11-23 B-9).
    fn hint(&self, about: Topic) -> Option<&'static str> {
        let _ = about;
        None
    }

    /// Checks the `[tokens.<t>.options]` of `token` when the token is opened. A provider with
    /// settings parses them (`cakeys_core::config::parse_options`, which refuses unknown names).
    /// The default takes no options, so it refuses any option (exit 17) instead of ignoring it
    /// without a message.
    ///
    /// # Errors
    ///
    /// `Validation` for any option on a provider that takes none. A provider with settings adds
    /// the errors of its own parsing.
    fn check_options(&self, token: &str, options: &Options) -> Result<()> {
        match options.keys().next() {
            None => Ok(()),
            Some(k) => Err(KmError::Validation(
                format!("tokens.{token}.options.{k}: provider {} takes no options", self.name()).into(),
            )),
        }
    }

    /// Returns whether the module creates and destroys token objects only in a Security Officer
    /// session (for ykcs11, with the PIV management key). In that case,
    /// `tokens.<t>.soCredentialFile` or `soCredentialEnv` is used for exactly those steps
    /// ([`Token::managing`]). In other places, the SO credential is refused, because an SO there
    /// cannot do what the user does. This is a fact and not an operation, and camigrate's imports
    /// and the probe's scratch guard also read it.
    fn manages_as_so(&self) -> bool {
        false
    }

    // ── Repairs ──────────────────────────────────────────────────────────────────────────

    // Each repair changes what the module reported for one attribute read into what a
    // spec-compliant module would report. The policy check, the identities and the lock all see
    // the result, so identities stay portable across modules and versions. The profile keeps the
    // raw observation. The defaults change nothing. There is one typed hook for each read, so
    // that no repair can answer for another (review 2026-11-23 B-22).

    /// Returns `CKA_EC_POINT` in the standard encoding from the value `raw` that was read.
    /// tpm2-pkcs11 and AWS `CloudHSM` encode it in their own way.
    fn ec_point<'a>(&self, raw: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(raw)
    }

    /// Returns the corrected `CKA_KEY_TYPE` for the value `reported`, given the object's
    /// `CKA_EC_PARAMS` when it has them. AWS `CloudHSM` reports an Ed25519 key as `CKK_EC`
    /// \[run\].
    fn key_type(&self, reported: KeyType, ec_params: Option<&[u8]>) -> KeyType {
        let _ = ec_params;
        reported
    }

    /// Returns the (attribute, private key type) pairs that [`Self::policy_flag`] repairs.
    /// [`Self::policy_flag`] is called for no other read, so a repair cannot widen a permission
    /// that it does not declare (review 2026-11-24 B-3). The default repairs none.
    fn repairs(&self) -> &'static [(AttributeType, KeyType)] {
        &[]
    }

    /// Returns the corrected value of the boolean policy attribute `attr` (`CKA_SIGN`,
    /// `CKA_DERIVE`, and so on) of a private key of type `private_key_type`, for the value
    /// `reported`. It is called only for the pairs that [`Self::repairs`] declares, and the
    /// closure always reads that type. ykcs11's fixed table reports `CKA_DERIVE` as false on keys
    /// with which its `C_DeriveKey` derives (the profile keeps the raw observation,
    /// `derive.key-attribute`).
    fn policy_flag(&self, attr: AttributeType, reported: bool, private_key_type: &dyn Fn() -> Option<KeyType>) -> bool {
        let _ = (attr, private_key_type);
        reported
    }

    /// Returns the parameterless mechanism that this module runs in place of the standard
    /// mechanism `m`, which it does not list. AWS `CloudHSM` generates Ed25519 keys with
    /// `CKM_EC_KEY_PAIR_GEN` and signs with a vendor mechanism \[run\]. The substitute is used
    /// only when the module does not list `m` ([`Token::runnable`]), and it is relied on only when
    /// a profile's `add` row records that it works (`caprobe` measures what it covers,
    /// `stand_ins`). `None` means that there is no substitute.
    fn stand_in(&self, _m: &Mechanism) -> Option<Mechanism<'static>> {
        None
    }

    // ── Templates ────────────────────────────────────────────────────────────────────────

    /// Adjusts `attrs`, which is cakeys' template for the call that `req` names, into a template
    /// that this module accepts: for example, it sets a vendor attribute or removes a default
    /// that the module refuses. The security attributes ([`SECURITY`]: where the object lives,
    /// who can see it, whether it can leave, its locator, and what may change it) are checked
    /// when the hook returns. When the hook changed, added or removed one of them, the template is
    /// refused (exit 17), unless the change makes the template stricter (review 2026-11-24 B-3).
    /// Every template that the verbs build for `C_GenerateKey(Pair)`, `C_CreateObject`,
    /// `C_UnwrapKey` and `C_DeriveKey` passes through this hook. The probe's generations,
    /// imports, creations and sealed round trips also call it with the same purposes, although
    /// the probe's own templates still differ in places. `C_FindObjects` search templates and the
    /// probe's measurement variations do not pass through it. Secret material (`CKA_VALUE`, or a
    /// private key's components) is never in `attrs`, because cakeys adds it afterwards. The hook
    /// runs before cakeys' own fallbacks, which then work on the result (dropping a public
    /// `CKA_PRIVATE = false` that the module refuses, naming a curve by name, and the policy
    /// defaults of `C_DeriveKey`). A module that generates only from its own template replaces
    /// the template completely instead ([`Self::generation`]). The default changes nothing.
    ///
    /// Each template is checked before anything is created. The session keys of the proof and of
    /// the commitments, which are used once the object exists, are checked by the capability
    /// check before the creation (`ops::check_import` for camigrate's imports). A plan also
    /// checks the templates without a token (`gate::check`, camigrate's `--dry-run`, and the plan
    /// of every move). It uses the same templates ([`crate::templates`]), except for a public
    /// object's value and a public key's material, which the plan has not read. So a refusal
    /// should depend on the request (`req`: the object, its spec and locator, and the purpose),
    /// and not on material. A refusal that does depend on material happens only at the run, but
    /// still before anything is created.
    ///
    /// # Errors
    ///
    /// The provider's refusal of the call, which is `Unsupported` (exit 15) for an object that the
    /// module cannot accept.
    fn template(&self, _req: &Template<'_>, _attrs: &mut Attributes) -> Result<()> {
        Ok(())
    }

    // ── Operations ───────────────────────────────────────────────────────────────────────

    /// Returns the module's own generation of `object`, as `spec` declares it under `loc`, which
    /// `binding` will prove (for private keys). The default returns `None`, which means that
    /// cakeys' own templates are used. This is the static half of [`Self::create`], and it is
    /// read before any token is opened (by the capability gate). A module that accepts only its
    /// own template (Google Cloud KMS) chooses that template here. It also refuses here, before
    /// anything is created, a key that cakeys could not identify or prove afterwards, because a
    /// key that it destroys again is not always gone (Cloud KMS keeps the label permanently).
    ///
    /// # Errors
    ///
    /// `Unsupported` (exit 15) for an object that the module cannot make as declared.
    /// `Validation` (exit 17) for a locator under which it cannot place a key.
    fn generation(
        &self,
        _object: Object<'_>,
        _spec: &SpecCfg,
        _loc: &Locator,
        _binding: Option<Binding>,
    ) -> Result<Option<Generation>> {
        Ok(None)
    }

    /// Checks whether a key may be made under `loc` on this module, whether it is generated or
    /// imported. A module that places keys into fixed slots by their locator (ykcs11's PIV
    /// slots) refuses a key that it cannot place. The check is static, so it runs before anything
    /// is created. The core code calls it, and an override never does. The static rules
    /// ([`crate::ops::static_rules`]) call it for every pair that a write puts on the token (the
    /// capability gate, `create`, and [`crate::ops::check_import`] for every import), and
    /// [`Token::create`] calls it before it calls [`Self::create`] (review 2026-11-24 B-2: before
    /// this, only ykcs11's `create` override called it there). The default places a key anywhere.
    ///
    /// # Errors
    ///
    /// `Validation` (exit 17), which says why no key can be placed under the locator.
    fn placement(&self, _loc: &Locator) -> Result<()> {
        Ok(())
    }

    /// Checks whether this module removes an object of `class` under `loc` when asked. A module
    /// whose `C_DestroyObject` reports success but keeps the object refuses (exit 15), and the
    /// error says how the object can be removed (ykcs11 keeps a PIV slot's key). The check is
    /// static, so it runs before anything is destroyed and before any SO session. The core code
    /// calls it, and an override never does: `delete`'s plan calls it, and so does every destroy
    /// of the token ([`Token::destroy_handles`]). The default removes anything.
    ///
    /// # Errors
    ///
    /// `Unsupported` (exit 15), which says why the object would stay.
    fn deletion(&self, _class: cakeys_core::types::ObjectClass, _loc: &Locator) -> Result<()> {
        Ok(())
    }

    /// Creates the object of `req` on `tok`. Only [`Token::create`] can call this method. It
    /// first calls [`Self::placement`] and enters the SO session when [`Self::manages_as_so`]
    /// says that the module needs one. Then it passes a [`Checked`] request that no other crate
    /// can build, so an override can skip neither step (review 2026-11-24 B-2). The default is
    /// [`Token::create_declared`], which uses the module's own template when
    /// [`Self::generation`] chooses one, and cakeys' templates otherwise.
    ///
    /// # Errors
    ///
    /// The same errors as [`Token::create_declared`], and the refusals of the override.
    fn create(&self, tok: &Token, req: &Checked<Create<'_>>) -> Result<Option<crate::token::CreateNote>> {
        tok.create_declared(req)
    }

    /// Destroys the handles of `req`, which the caller identified, on `tok`. The token's destroys
    /// call this method after [`Self::deletion`] allows them, in the SO session when
    /// [`Self::manages_as_so`] says that the module needs one, and with a [`Checked`] request. The
    /// default is [`Token::destroy_plain`], which calls `C_DestroyObject` on each handle. The
    /// count that it returns is only what the provider reports, so the objects that a delete
    /// destroyed are looked up again afterwards.
    ///
    /// # Errors
    ///
    /// The same errors as [`Token::destroy_plain`], and the refusals of the override.
    fn destroy(&self, tok: &Token, req: &Checked<Destroy<'_>>) -> Result<usize> {
        tok.destroy_plain(req)
    }

    /// Returns how plaintext keys get into this module ([`PlaintextVia`]). The default is
    /// `C_CreateObject` (as the SO when the provider manages objects as the SO). Otherwise, it is
    /// the provider's own tool, which comes together with the kind by which it is named, so that
    /// the two cannot disagree (review 2026-11-23 B-27).
    fn plaintext_import(&self) -> PlaintextVia {
        PlaintextVia::CreateObject(PlaintextKind::CreateObject)
    }

    /// Returns the attestation commitment that this provider can compute (§3.7 of
    /// docs/DESIGN.md), if there is one: the scheme that it records, the object classes that it
    /// can attest, and the computation itself. The default is `None`, which means that this
    /// module exposes no attestation, so a spec that opts into one is refused (exit 15) before
    /// anything is created.
    fn attestation(&self) -> Option<AttestationCap> {
        None
    }

    // ── Read only by the probe ───────────────────────────────────────────────────────────

    /// Returns the keys that a module binds to one purpose when it creates them (Google Cloud
    /// KMS has one algorithm per key), each with the exact template from which it is generated.
    /// The write probe generates these keys instead of its own templates. The default is empty,
    /// for a module whose keys are general purpose.
    fn bound_keys(&self) -> Vec<BoundKey> {
        Vec::new()
    }

    /// Returns whether `cert` (DER), which was found under the probe's scratch `CKA_ID` (`id`,
    /// `tokens.<t>.probe.scratchId`) next to the probe's own certificate, is a certificate that
    /// the module keeps next to any key in a slot (for ykcs11, the device's attestation of the
    /// slot). Such a certificate says nothing about whose key is in the slot. Only the probe's
    /// certificate marks a slot as the probe's slot. A certificate that the module writes for
    /// every key that it generates is not a companion, because a real key has it too (review
    /// 2026-11-23 D-1). The default recognizes no certificate.
    fn scratch_companion(&self, _id: &[u8], _cert: &[u8]) -> bool {
        false
    }
}

impl dyn Provider + '_ {
    /// Returns the standard mechanisms that [`Provider::stand_in`] covers. These are the
    /// mechanisms that cakeys runs through [`Token::runnable`], in the form in which it asks for
    /// them, for which the provider returns a substitute. `caprobe` probes them although the
    /// module does not list them.
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

    /// Returns `e` with the provider's advice on `about` when `e` is an `Unsupported` refusal and
    /// the provider has advice ([`Provider::hint`]). Any other error is returned unchanged.
    #[must_use]
    pub fn hinted(&self, about: Topic, e: KmError) -> KmError {
        match (e, self.hint(about)) {
            (KmError::Unsupported(m), Some(h)) => {
                let text = format!("{m} (hint for {}: {h})", self.name());
                KmError::Unsupported(m.with_text(text))
            }
            (e, _) => e,
        }
    }

    /// Returns `template`, which is cakeys' template for `req`, as the provider adjusts it
    /// ([`Provider::template`]). The security attributes ([`SECURITY`]) must stay as cakeys
    /// built them, or be made stricter (review 2026-11-24 B-3: a provider could make a sealed
    /// session key extractable, or move a key away from its locator, and no code read the
    /// template back).
    ///
    /// # Errors
    ///
    /// The provider's refusal. `Validation` (exit 17) when the provider changed, added or removed
    /// a security attribute in a way that does not make it stricter.
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

    /// Returns the session template `t` as the provider adjusts it (`adjusted`). The provider is
    /// asked about the session key for which the template was built, so that the two cannot
    /// disagree.
    ///
    /// # Errors
    ///
    /// The same errors as `adjusted`.
    pub fn adjusted_session(&self, t: crate::templates::SessionTemplate) -> Result<Vec<Attribute>> {
        self.adjusted(&Template::Session(t.key()), t.into())
    }
}

/// The value that makes a security attribute stricter ([`SECURITY`]), as the attribute's
/// constructor and the value. `None` when no change makes it stricter.
pub type Tightening = Option<(fn(bool) -> Attribute, bool)>;

/// The attributes that a provider's template hook may not change ([`Provider::template`]), each
/// with the value that makes it stricter, when such a value exists: a restriction set to true,
/// or a permission set to false (phase1-design.md §3.2.2). The other attributes (where the object
/// lives, its locator, and what may change, copy or destroy it) must stay as they were built.
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

/// The purpose of a template that cakeys builds ([`Provider::template`]).
pub enum Template<'a> {
    /// A key that is generated from cakeys' templates (`create`): one `half` of `on`.
    Generate(Declared<'a>, Half),
    /// A key that is imported (by camigrate, and by the probe's `import.*` rows): created from
    /// plaintext, or unwrapped from a bundle. For the unwrap, the attributes that the module's
    /// profile refuses in an unwrap template (`unwrap.refuse`) are already left out.
    Import(Declared<'a>, Via),
    /// The public key object that is made next to an imported private key, from its public
    /// key.
    PublicHalf(Declared<'a>),
    /// A certificate, a data object or a public key object that is created from its value.
    Object(Declared<'a>),
    /// The trusted copy of a transport key, which is made as the SO (`camigrate transport
    /// --trust-on`).
    TrustedCopy,
    /// A session object that cakeys makes for one step and destroys after that step.
    Session(SessionKey),
}

impl Template<'_> {
    /// Returns the purpose of the template, in the form in which a refusal names it.
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

/// The object that a template makes: `object`, as `spec` declares it, under `locator`.
#[derive(Clone, Copy)]
pub struct Declared<'a> {
    /// The object, parsed.
    pub object: Object<'a>,
    /// The spec by which the object is made (the probe's own spec, for its scratch objects).
    pub spec: &'a SpecCfg,
    /// Where it goes on the token.
    pub locator: &'a Locator,
}

impl<'a> From<&Target<'a>> for Declared<'a> {
    fn from(t: &Target<'a>) -> Self {
        Declared { object: t.object, spec: t.spec, locator: &t.on_token.locator }
    }
}

/// The template of a generation that is meant ([`Template::Generate`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Half {
    /// A key pair's public template.
    Public,
    /// The key itself: a key pair's private template, or a secret key's template.
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

/// A session object that cakeys makes for one step ([`Template::Session`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKey {
    /// The secret that a proof of possession unwraps (`pop-unwrap`) or derives (`pop-ecdh`) and
    /// computes a MAC with, when `sealed` is true. When `sealed` is false, it is the readable
    /// secret that a `pop-ecdh` derives when the module refuses the sealed one.
    ProofSecret {
        /// The proof that uses the secret.
        binding: Binding,
        /// When true, the secret is sensitive and not extractable. Otherwise, it is readable.
        sealed: bool,
    },
    /// The AES key of wrap-rebind, which wraps the key under commitment to make its copy.
    RebindKek,
    /// The wrap-rebind copy of the key under commitment, which is unwrapped with the uses that
    /// its commitments need.
    RebindCopy,
    /// The `kw` commitment's fixed key, which the key under commitment wraps.
    KwInput,
    /// The AES key that the host draws and creates on the token to take a key out (`host`
    /// export).
    HostKek,
    /// The transport public key of a sealed export, which is loaded on the source.
    TransportKey,
    /// The AES key of a sealed export, which is generated on the source and wrapped to the
    /// transport key.
    ExportKek,
    /// The AES key of a sealed import, which is unwrapped on the target with the transport key.
    ImportKek,
}

/// A template that a provider adjusts ([`Provider::template`]). It holds at most one attribute
/// of each type, as PKCS#11 requires of a template.
pub struct Attributes(Vec<Attribute>);

impl Attributes {
    /// Returns the attribute of type `t`, if the template has one.
    #[must_use]
    pub fn get(&self, t: AttributeType) -> Option<&Attribute> {
        self.0.iter().find(|a| a.attribute_type() == t)
    }

    /// Sets `a`, and replaces the template's attribute of the same type when there is one.
    pub fn set(&mut self, a: Attribute) {
        match self.0.iter_mut().find(|b| b.attribute_type() == a.attribute_type()) {
            Some(b) => *b = a,
            None => self.0.push(a),
        }
    }

    /// Removes the attribute of type `t` and returns it.
    pub fn remove(&mut self, t: AttributeType) -> Option<Attribute> {
        let i = self.0.iter().position(|a| a.attribute_type() == t)?;
        Some(self.0.remove(i))
    }

    /// Returns the template's attributes, in order.
    pub fn iter(&self) -> impl Iterator<Item = &Attribute> {
        self.0.iter()
    }
}

/// A request that the token checked before it calls the provider ([`Provider::create`],
/// [`Provider::destroy`]). Only this crate makes one, after the rules that the core code checks
/// first (where a key may go), and inside the session in which the module writes. So an override
/// that receives a `Checked` request was called through those steps. It dereferences to the
/// request that it holds.
pub struct Checked<T>(T);

impl<T> Checked<T> {
    /// The request `req`, after the token has checked it.
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

/// What [`Provider::create`] makes: `object`, as `spec` declares it, under `locator`, which
/// `binding` will prove (for private keys).
pub struct Create<'a> {
    /// The object, parsed.
    pub object: Object<'a>,
    /// The spec by which the object is created.
    pub spec: &'a SpecCfg,
    /// Where it goes on the token.
    pub locator: &'a Locator,
    /// How a private key will be proven. A template that the module chooses must allow this
    /// proof.
    pub binding: Option<Binding>,
}

/// What [`Provider::destroy`] removes: exactly `handles`, as objects of the type `object` under
/// `locator`.
pub struct Destroy<'a> {
    /// The objects' type.
    pub object: &'a ObjectCfg,
    /// Where the objects are on the token.
    pub locator: &'a Locator,
    /// The objects that the caller identified. The list is never empty.
    pub handles: &'a [ObjectHandle],
}

/// What a provider can attest (§3.7 of docs/DESIGN.md), and how, as [`Provider::attestation`]
/// returns it.
#[derive(Debug, Clone, Copy)]
pub struct AttestationCap {
    /// The scheme that the commitment records. It is an attestation scheme
    /// (`Scheme::is_attestation`), and its kind in the lock record is
    /// `Scheme::attestation_kind`.
    pub scheme: Scheme,
    /// The object classes that the attestation covers.
    pub classes: &'static [ObjectClass],
    /// Whether the attestation covers a key that was imported onto the device, and not only a
    /// key that the device made. This is false for PIV, whose attestation covers only keys that
    /// were generated on the `YubiKey`. An import that such an attestation cannot cover is refused
    /// (exit 15) before the key is written, because the device may keep the key.
    pub imported: bool,
    /// Computes the attestation commitment for `ctx.key` on its token: the canonical scheme
    /// digest and the anchor against which it was verified. It is called only when the spec
    /// opted in and `classes` covers the key. A missing attestation is an error that names the
    /// reason (an imported key, or a session that could not attest), and it never passes. The
    /// error is `Unavailable` when the token has no attestation to give, and `Conflict` (exit 13)
    /// when the attestation names other material than `ctx.spki`.
    pub attest: fn(&AttestCtx<'_>) -> Result<Attested>,
}

/// How plaintext keys get into a module ([`Provider::plaintext_import`]). Each way comes with the
/// kind by which a profile's `plaintext-import` and an `import.*` row's `via` name it.
#[derive(Debug, Clone, Copy)]
pub enum PlaintextVia {
    /// `C_CreateObject` with the key's attributes: `create-object`, or `piv-import` (ykcs11, as
    /// the SO into a PIV slot).
    CreateObject(PlaintextKind),
    /// The provider's own tool, outside PKCS#11 (docs/CAMIGRATE.md `tpm2-ptool`: tpm2-pkcs11
    /// creates keys from values only through `tpm2_ptool import`). `ctx.key` is a private key's
    /// PKCS#8 `PrivateKeyInfo` or a secret key's value. The caller opens the token again
    /// afterwards to see the key. The tool returns `Unsupported` for a key type that it cannot
    /// accept, and otherwise whatever error the tool reports.
    Tool(PlaintextKind, fn(&ImportCtx<'_>) -> Result<()>),
}

impl PlaintextVia {
    /// Returns the kind by which this way is named.
    #[must_use]
    pub fn kind(self) -> PlaintextKind {
        match self {
            PlaintextVia::CreateObject(k) | PlaintextVia::Tool(k, _) => k,
        }
    }
}

/// What a [`PlaintextVia::Tool`] receives: the token as keys.toml describes it, the key's type
/// and locator, and the plaintext. It must never implement `Debug`, because `Debug` would print
/// the key and the PIN.
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

/// Everything that an attestation may need beyond the PKCS#11 module. That is the session (to
/// find the certificate objects that a module exposes), the configuration (the TCTI and the store
/// of the native TPM path), the PIN (with which the TPM path unseals the token's wrapping key),
/// and the material SPKI that the attestation must name (`None` exactly for secret keys, which
/// have no SPKI).
///
/// `provision` is true only under `lock`. A provider that keeps device state with which it
/// attests (the TPM Attestation Key) may create that state then, and never on a read (`resolve`,
/// `check`).
pub struct AttestCtx<'a> {
    /// An open session on the token, for the objects that the module exposes (attestation
    /// certificates).
    pub session: &'a Session,
    /// The token, as keys.toml describes it (the TCTI and the store of the native TPM path).
    pub cfg: &'a TokenCfg,
    /// The module's version, as `C_GetInfo` reports it ("1.10").
    pub module_version: &'a str,
    /// Returns whether the module has a mechanism (whether `C_GetMechanismInfo` answers). A
    /// provider uses it to find the vendor mechanisms of its module (tpm2-pkcs11's
    /// `CKM_TPM2_*`). cryptoki 0.12.1 leaves these mechanisms out of the list that
    /// `C_GetMechanismList` returns, because it has no name for them. cryptoki's main branch
    /// keeps them (6cc2278), and this function works with either version.
    pub has_mechanism: &'a dyn Fn(MechanismType) -> bool,
    /// The token's name in keys.toml.
    pub token_name: &'a str,
    /// The key to attest.
    pub key: ObjectHandle,
    /// The key's type.
    pub object: &'a ObjectCfg,
    /// The material SPKI that the attestation must name. It is `None` exactly for secret keys.
    pub spki: Option<&'a [u8]>,
    /// The commitments of the key that this run computed through PKCS#11. For a secret key, the
    /// attestation must be bound to these commitments instead of an SPKI, because the device
    /// computes one of them with the object that it attests (review 2026-11-23 B-1). The list is
    /// empty for any other class.
    pub commitments: &'a [Commitment],
    /// The user PIN, when the token has one (the TPM path unseals the token's wrapping key with
    /// it).
    pub pin: Option<&'a str>,
    /// True only under `lock`. Then the provider may create the device state with which it
    /// attests (the TPM Attestation Key). It never does so on a read.
    pub provision: bool,
    /// The time at which the attestation's certificates must be valid, and whether a fault in
    /// their dates refuses the attestation.
    pub chain_time: ChainTime,
}

/// One commitment of the key under attestation that the run computed
/// ([`AttestCtx::commitments`]): the input on which the token operated and the ID of its output,
/// as the lock records them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The kind of commitment.
    pub commit: cakeys_core::id::Commit,
    /// The bytes on which the token operated (`Commit::input`, with the run's commitment label).
    pub input: Vec<u8>,
    /// The commitment's ID, which is the SRI digest of the token's output.
    pub id: String,
}

impl AttestCtx<'_> {
    /// Returns the material SPKI, which is required for asymmetric classes. An attestation that
    /// could not be cross-checked against the key that `rfc7093m4` names would be provenance for
    /// unknown material.
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

/// A computed attestation commitment (§3.7 of docs/DESIGN.md): the scheme digest and the anchor
/// against which the attestation was verified. The lock records it as the realisation's
/// `attestation = { kind, root, id }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attested {
    /// The attestation scheme.
    pub scheme: Scheme,
    /// The per-device attestation ID.
    pub id: String,
    /// The SRI digest of the anchor against which the attestation was verified.
    pub root: String,
    /// The reason why the chain would fail `check` although it was verified: its dates, under
    /// [`ChainTime::Warn`].
    pub warning: Option<String>,
    /// What the attestation does not establish although it was verified. Every run that computes
    /// the attestation prints it. An example is tpm2-pkcs11's `akLabel` signer, whose public area
    /// only the module reports (review 2026-11-23 B-2).
    pub caveat: Option<String>,
}

/// Plain PKCS#11, which is used when no registered provider recognizes the module.
pub struct Generic;

impl Provider for Generic {
    fn name(&self) -> &'static str {
        "generic"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        true
    }
}

/// A provider for a module that needs no code of its own (docs/CAPROBE.md: no Rust code for a
/// module without fix-ups). It is recognized by the `[match] manufacturer` of its module
/// profiles, it is named by their family, and every hook has the default behavior. `softhsm` and
/// `kryoptic` are such providers (aws-cloudhsm has a crate of its own).
pub struct Data(pub(crate) &'static str);

impl Provider for Data {
    fn name(&self) -> &'static str {
        self.0
    }

    /// This method is never called, because the registry detects data providers from the
    /// profiles and not one at a time.
    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider's template keeps one attribute of each type, so `set` replaces an attribute in
    /// place.
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
            // No security attribute ([`SECURITY`]) is changed: a vendor's own attribute, a use and
            // a subject.
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

    /// A provider that sets `0` on every template that it is asked about.
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

    /// A provider that removes `0` from every template that it is asked about.
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

    /// Returns every session template that cakeys builds (`templates::session`).
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

    /// Tests what a provider's template hook may do (review 2026-11-24 B-3, phase1-design.md
    /// §3.2.2). On every session template, a security attribute that is set to a value that it
    /// does not have, or that is removed, is refused (exit 17) with its name, unless the change
    /// makes it stricter (a restriction set to true, or a permission set to false). The provider
    /// may change any other attribute. Each template keeps the security attributes with which it
    /// was built.
    #[test]
    fn a_provider_changes_no_security_attribute_but_to_tighten_it() {
        // The design's list is written out here, so that the test does not read the table that
        // it checks.
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
