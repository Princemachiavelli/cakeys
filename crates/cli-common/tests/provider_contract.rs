//! The provider contract (review 2026-11-24, phase1-design.md §3.3): what every provider this
//! build registers holds, whatever its module — the code providers of [`default_registry`],
//! `generic`, and each module profile family's data provider. Each is named on the `SoftHSM`
//! reference token, so its overrides run without its hardware; p11-fault supplies the module's
//! lies (K-5, Linux). One test per case of the design's table (K-1 to K-7), and [`Hook`], the
//! table of every `Provider` method with the case that holds it: a hook added to the trait fails
//! here until it has one. The `SoftHSM` tests skip without `CAKEYS_TEST_MODULE`, K-5 without
//! `P11_FAULT_MODULE` (nix/test-tokens.sh routes both).

#[path = "../../test-skip.rs"]
mod test_skip;

use cakeys_cli_common::default_registry;
use cakeys_core::KmError;
use cakeys_core::config::{Binding, Config, Locator, Lock, ModuleInfo, Object, Options, SpecCfg};
use cakeys_core::types::ObjectClass as Class;
use cakeys_pkcs11::ops::{self, LockWrite, Notes, Rule, Target};
use cakeys_pkcs11::provider::{AttestationCap, PlaintextVia, SECURITY};
use cakeys_pkcs11::token::{Access, CreateNote};
use cakeys_pkcs11::{
    Attributes, BoundKey, CODE_FAMILIES, ChainTime, Checked, Create, Declared, Destroy, Generation, Half, Provider,
    Registry, SessionKey, Template, Token, Topic, Via, keygen_mechanism, templates,
};
use cakeys_profile::Set;
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass};
use std::borrow::Cow;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Every `Provider` method (`crates/pkcs11/src/provider.rs`), each with the test of this file
/// that holds it ([`Hook::case`]): `k7_every_hook_has_a_case` reads the trait and fails on a
/// method missing here, and the `match` fails to compile until a new one has its case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Hook {
    Name,
    Matches,
    Hint,
    CheckOptions,
    ManagesAsSo,
    EcPoint,
    KeyType,
    Repairs,
    PolicyFlag,
    StandIn,
    Template,
    Generation,
    Placement,
    Deletion,
    Create,
    Destroy,
    PlaintextImport,
    Attestation,
    BoundKeys,
    ScratchCompanion,
}

impl Hook {
    const ALL: [Hook; 20] = [
        Hook::Name,
        Hook::Matches,
        Hook::Hint,
        Hook::CheckOptions,
        Hook::ManagesAsSo,
        Hook::EcPoint,
        Hook::KeyType,
        Hook::Repairs,
        Hook::PolicyFlag,
        Hook::StandIn,
        Hook::Template,
        Hook::Generation,
        Hook::Placement,
        Hook::Deletion,
        Hook::Create,
        Hook::Destroy,
        Hook::PlaintextImport,
        Hook::Attestation,
        Hook::BoundKeys,
        Hook::ScratchCompanion,
    ];

    /// The trait method's name.
    fn method(self) -> &'static str {
        match self {
            Hook::Name => "name",
            Hook::Matches => "matches",
            Hook::Hint => "hint",
            Hook::CheckOptions => "check_options",
            Hook::ManagesAsSo => "manages_as_so",
            Hook::EcPoint => "ec_point",
            Hook::KeyType => "key_type",
            Hook::Repairs => "repairs",
            Hook::PolicyFlag => "policy_flag",
            Hook::StandIn => "stand_in",
            Hook::Template => "template",
            Hook::Generation => "generation",
            Hook::Placement => "placement",
            Hook::Deletion => "deletion",
            Hook::Create => "create",
            Hook::Destroy => "destroy",
            Hook::PlaintextImport => "plaintext_import",
            Hook::Attestation => "attestation",
            Hook::BoundKeys => "bound_keys",
            Hook::ScratchCompanion => "scratch_companion",
        }
    }

    /// The test of this file that holds it, for every registered provider.
    fn case(self) -> &'static str {
        match self {
            // Each is its own name, and only its own code claims its family (B-7, B-10).
            Hook::Name | Hook::Matches => "k4_a_code_family_is_its_codes_alone",
            // Each opens the token, in the session it manages in, through its own options check.
            Hook::CheckOptions | Hook::ManagesAsSo => "k2_session_keys_read_back_as_built",
            // Repairs of a read: declared, idempotent, and nothing to a compliant answer (B-3).
            Hook::EcPoint | Hook::KeyType | Hook::Repairs | Hook::PolicyFlag | Hook::StandIn => {
                "k3_repairs_are_declared_and_idempotent"
            }
            // Templates, and a module's own: no security attribute changed (B-3, B-8).
            Hook::Template | Hook::Generation | Hook::BoundKeys => "k2_templates_keep_their_security_attributes",
            // Placement before creation, on every path that creates (B-1, B-2).
            Hook::Placement | Hook::Create | Hook::PlaintextImport => "k1_placement_comes_before_create_on_every_path",
            // A destroy the module claimed and did not do is found (B-13).
            Hook::Destroy => "k5_a_destroy_the_module_did_not_do_keeps_the_lock",
            // A profile's no refuses before the provider is asked to destroy (B-13).
            Hook::Deletion => "k6_a_profile_no_refuses_the_delete_before_any_destroy",
            // Advice and facts change no outcome.
            Hook::Hint | Hook::Attestation | Hook::ScratchCompanion => "what_a_provider_only_says_changes_no_outcome",
        }
    }
}

/// Every provider this build registers, by name: the code ones, `generic`, and each profile
/// family's (a code family's is its code).
fn providers() -> Vec<Arc<dyn Provider>> {
    let set = Set::activate_embedded().unwrap();
    let registry = default_registry();
    let mut names: Vec<&str> = registry.names();
    names.push("generic");
    names.extend(set.module_family_names().into_iter().filter(|f| !CODE_FAMILIES.contains(f)));
    names.dedup();
    names.into_iter().map(|n| registry.named(n).unwrap().unwrap_or_else(|| panic!("{n}: not named"))).collect()
}

/// A provider as `inner` is, every hook passed through, recording which hooks are asked, in
/// order; with `refuse_placement`, its placement refuses (17) whatever `inner` says.
#[derive(Clone)]
struct Spy {
    inner: Arc<dyn Provider>,
    asked: Arc<Mutex<Vec<Hook>>>,
    refuse_placement: bool,
}

impl Spy {
    fn new(inner: &Arc<dyn Provider>, refuse_placement: bool) -> Spy {
        Spy { inner: Arc::clone(inner), asked: Arc::default(), refuse_placement }
    }

    fn saw(&self, h: Hook) {
        self.asked.lock().unwrap().push(h);
    }

    fn asked(&self) -> Vec<Hook> {
        self.asked.lock().unwrap().clone()
    }
}

/// The name a case gives `p` on the token: its own, but `generic`'s, which a registry never
/// looks up (it is always [`cakeys_pkcs11::Generic`]), so a spy of it could not be selected.
fn spied(p: &dyn Provider) -> &'static str {
    match p.name() {
        "generic" => "generic-spied",
        name => name,
    }
}

impl Provider for Spy {
    fn name(&self) -> &'static str {
        spied(self.inner.as_ref())
    }
    fn matches(&self, module: &ModuleInfo) -> bool {
        self.saw(Hook::Matches);
        self.inner.matches(module)
    }
    fn hint(&self, about: Topic) -> Option<&'static str> {
        self.saw(Hook::Hint);
        self.inner.hint(about)
    }
    fn check_options(&self, token: &str, options: &Options) -> cakeys_core::Result<()> {
        self.saw(Hook::CheckOptions);
        self.inner.check_options(token, options)
    }
    fn manages_as_so(&self) -> bool {
        self.saw(Hook::ManagesAsSo);
        self.inner.manages_as_so()
    }
    fn ec_point<'a>(&self, raw: &'a [u8]) -> Cow<'a, [u8]> {
        self.saw(Hook::EcPoint);
        self.inner.ec_point(raw)
    }
    fn key_type(&self, reported: KeyType, ec_params: Option<&[u8]>) -> KeyType {
        self.saw(Hook::KeyType);
        self.inner.key_type(reported, ec_params)
    }
    fn repairs(&self) -> &'static [(AttributeType, KeyType)] {
        self.saw(Hook::Repairs);
        self.inner.repairs()
    }
    fn policy_flag(&self, attr: AttributeType, reported: bool, private_key_type: &dyn Fn() -> Option<KeyType>) -> bool {
        self.saw(Hook::PolicyFlag);
        self.inner.policy_flag(attr, reported, private_key_type)
    }
    fn stand_in(&self, m: &Mechanism) -> Option<Mechanism<'static>> {
        self.saw(Hook::StandIn);
        self.inner.stand_in(m)
    }
    fn template(&self, req: &Template<'_>, attrs: &mut Attributes) -> cakeys_core::Result<()> {
        self.saw(Hook::Template);
        self.inner.template(req, attrs)
    }
    fn generation(
        &self,
        object: Object<'_>,
        spec: &SpecCfg,
        loc: &Locator,
        binding: Option<Binding>,
    ) -> cakeys_core::Result<Option<Generation>> {
        self.saw(Hook::Generation);
        self.inner.generation(object, spec, loc, binding)
    }
    fn placement(&self, loc: &Locator) -> cakeys_core::Result<()> {
        self.saw(Hook::Placement);
        if self.refuse_placement {
            return Err(KmError::Validation("the spy places no key".into()));
        }
        self.inner.placement(loc)
    }
    fn deletion(&self, class: Class, loc: &Locator) -> cakeys_core::Result<()> {
        self.saw(Hook::Deletion);
        self.inner.deletion(class, loc)
    }
    fn create(&self, tok: &Token, req: &Checked<Create<'_>>) -> cakeys_core::Result<Option<CreateNote>> {
        self.saw(Hook::Create);
        self.inner.create(tok, req)
    }
    fn destroy(&self, tok: &Token, req: &Checked<Destroy<'_>>) -> cakeys_core::Result<usize> {
        self.saw(Hook::Destroy);
        self.inner.destroy(tok, req)
    }
    fn plaintext_import(&self) -> PlaintextVia {
        self.saw(Hook::PlaintextImport);
        self.inner.plaintext_import()
    }
    fn attestation(&self) -> Option<AttestationCap> {
        self.saw(Hook::Attestation);
        self.inner.attestation()
    }
    fn bound_keys(&self) -> Vec<BoundKey> {
        self.saw(Hook::BoundKeys);
        self.inner.bound_keys()
    }
    fn scratch_companion(&self, id: &[u8], cert: &[u8]) -> bool {
        self.saw(Hook::ScratchCompanion);
        self.inner.scratch_companion(id, cert)
    }
}

/// A provider named `name` that does as [`cakeys_pkcs11::Generic`] does: what makes and clears
/// a case's key under a provider's name, by plain PKCS#11, whatever that provider would do.
struct Plain(&'static str);

impl Provider for Plain {
    fn name(&self) -> &'static str {
        self.0
    }
    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }
}

// ── The reference token ──────────────────────────────────────────────────────────────────────

/// Held by each test while it uses the token: login is the process's.
static TOKEN: Mutex<()> = Mutex::new(());

/// The `SoftHSM` module, and the [`TOKEN`] guard; `None` (skipped) without it.
fn softhsm(test: &str) -> Option<(String, std::sync::MutexGuard<'static, ()>)> {
    let Ok(module) = std::env::var("CAKEYS_TEST_MODULE") else {
        test_skip::skip(test, "CAKEYS_TEST_REQUIRE", "CAKEYS_TEST_MODULE is not set");
        return None;
    };
    Some((module, TOKEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner)))
}

/// keys.toml for token `t` (the harness's `kmtest` through `module`, its provider `provider`)
/// and an EC key of spec `s` under `label` on it.
fn config(test: &str, module: &str, provider: &str, label: &str) -> Config {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("cakeys-contract-{test}"));
    std::fs::create_dir_all(&dir).unwrap();
    let (pin, so) = (dir.join("pin"), dir.join("so-pin"));
    std::fs::write(&pin, "1234\n").unwrap();
    std::fs::write(&so, "5678\n").unwrap();
    toml::from_str(&format!(
        "[tokens.t]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nsoCredentialFile = \"{}\"\n\
         provider = \"{provider}\"\n\n\
         [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"k\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.t = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"create\" }}\n",
        pin.display(),
        so.display()
    ))
    .unwrap()
}

/// A label of the case's own for `provider`: Cloud KMS's `CryptoKey` ID rule, which every
/// module takes (kmsp11's `generation` refuses another).
fn label(case: &str, provider: &str) -> String {
    format!("contract-{case}-{provider}")
}

fn open(cfg: &Config, registry: &Registry) -> Token {
    Token::open("t", &cfg.tokens["t"], None, registry, Access::Write, ChainTime::Unchecked).unwrap()
}

/// The token under `provider`'s name, opened as [`Plain`].
fn plain(cfg: &Config, provider: &'static str) -> Token {
    open(cfg, &Registry::new().with(Plain(provider)))
}

fn new_lock() -> Lock {
    Lock { version: cakeys_core::config::LOCK_VERSION, ..Lock::default() }
}

/// What a refused path reported: its exit code and the rule it named.
fn refused<T>(what: &str, r: cakeys_core::Result<T>) -> (u8, Option<Rule>) {
    match r {
        Ok(_) => panic!("{what}: not refused"),
        Err(e) => (e.exit_code(), e.rule()),
    }
}

// ── K-1 ──────────────────────────────────────────────────────────────────────────────────────

/// K-1 (B-1, B-2): every path that puts a key on the token asks placement before the provider
/// creates anything: the static gate, `create`, an import's check and `Token::create` all refuse
/// (17, naming the rule) when placement does, whatever else the provider overrides, and its
/// `create` is never asked. With the provider's own placement, `create` is asked after it.
#[test]
fn k1_placement_comes_before_create_on_every_path() {
    let Some((module, _token)) = softhsm("k1_placement_comes_before_create_on_every_path") else { return };
    let want = (17, Some(Rule::Placement));
    for p in providers() {
        let name = spied(p.as_ref());
        let cfg = config("k1", &module, name, &label("k1", name));
        let t = Target::new(&cfg, "s", "t").unwrap();
        let lock = new_lock();
        let spy = Spy::new(&p, true);
        let registry = Registry::new().with(spy.clone());

        let stack = cakeys_pkcs11::gate::stack("t", &cfg.tokens["t"], &lock).unwrap();
        let v =
            cakeys_pkcs11::gate::check(&t, ops::plan_mode(&t).unwrap(), &stack, &registry, ops::Verb::Create).unwrap();
        let rules: Vec<(u8, Rule)> = v.refusals.iter().map(|r| (r.error.exit_code(), r.rule)).collect();
        assert!(rules.contains(&(17, Rule::Placement)), "{name}: the gate refused {rules:?}");

        let tok = open(&cfg, &registry);
        plain(&cfg, name).destroy(&t.object, &t.on_token.locator).unwrap();
        let mut notes = Notes::default();
        assert_eq!(
            refused("create", ops::create(&t, &tok, &mut new_lock(), LockWrite::Record, &mut notes)),
            want,
            "{name}"
        );
        assert_eq!(refused("an import's check", ops::check_import(&t, &tok)), want, "{name}");
        assert_eq!(refused("Token::create", tok.create(t.object, t.spec, &t.on_token.locator, None)), want, "{name}");
        assert!(
            !spy.asked().contains(&Hook::Create),
            "{name}: create asked after placement refused: {:?}",
            spy.asked()
        );
        assert!(tok.find_any(&t.on_token.locator).unwrap().is_empty(), "{name}: a key was made");
        drop(tok);

        // The provider's own placement, then its create (which may refuse on this module).
        let spy = Spy::new(&p, false);
        let tok = open(&cfg, &Registry::new().with(spy.clone()));
        let made = tok.create(t.object, t.spec, &t.on_token.locator, None);
        let asked = spy.asked();
        match asked.iter().position(|h| *h == Hook::Create) {
            Some(at) => assert!(asked[..at].contains(&Hook::Placement), "{name}: create before placement: {asked:?}"),
            None => assert!(made.is_err(), "{name}: made without its create: {asked:?}"),
        }
        drop(tok);
        plain(&cfg, name).destroy(&t.object, &t.on_token.locator).unwrap();
    }
}

// ── K-2 ──────────────────────────────────────────────────────────────────────────────────────

/// The objects every template is asked for: an EC, an Edwards and an RSA key pair, an AES key,
/// a certificate and a data object, each under a label of its own on token `t`.
const OBJECTS: &str = "[tokens.t]\nmodule = \"/none\"\ntokenLabel = \"kmtest\"\n\n\
    [objects.ec]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\
    [objects.ed]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"\n\
    [objects.rsa]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\
    [objects.aes]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32\n\
    [objects.cert]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n\
    [objects.data]\nclass = \"CKO_DATA\"\n\n\
    [specs.ec]\nobject = \"ec\"\nattributes = { CKA_SIGN = true }\ntokens.t = { locator = { CKA_LABEL = \"contract-ec\" }, origin = \"create\" }\n\
    [specs.ed]\nobject = \"ed\"\nattributes = { CKA_SIGN = true }\ntokens.t = { locator = { CKA_LABEL = \"contract-ed\" }, origin = \"create\" }\n\
    [specs.rsa]\nobject = \"rsa\"\nattributes = { CKA_DECRYPT = true }\ntokens.t = { locator = { CKA_LABEL = \"contract-rsa\" }, origin = \"create\" }\n\
    [specs.aes]\nobject = \"aes\"\nattributes = { CKA_WRAP = true, CKA_UNWRAP = true }\ntokens.t = { locator = { CKA_LABEL = \"contract-aes\" }, origin = \"create\" }\n\
    [specs.cert]\nobject = \"cert\"\ntokens.t = { locator = { CKA_LABEL = \"contract-cert\" }, origin = \"import\" }\n\
    [specs.data]\nobject = \"data\"\ntokens.t = { locator = { CKA_LABEL = \"contract-data\" }, origin = \"import\" }\n";

/// secp256r1's `CKA_EC_PARAMS`.
const P256: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// Every template cakeys builds for `on`, with what it is for.
fn templates_of(on: Declared<'_>) -> Vec<(Template<'_>, Vec<Attribute>)> {
    let none = |_: &str, m: &str| -> cakeys_core::Result<cryptoki::mechanism::MechanismType> {
        Err(KmError::Validation(format!("no mechanism {m} here").into()))
    };
    let policy = templates::policy(&on.spec.attributes, &none).unwrap();
    let public = templates::policy(&on.spec.public_attributes, &none).unwrap();
    let mut out = Vec::new();
    match on.object.class {
        Class::PrivateKey | Class::SecretKey => {
            out.push((Template::Generate(on, Half::Key), templates::generation_key(on, policy.clone()).unwrap()));
            let params = (on.object.class == Class::PrivateKey && on.object.curve.is_some()).then_some(&P256[..]);
            if let Some(t) = templates::generation_public(on, public.clone(), params).unwrap() {
                out.push((Template::Generate(on, Half::Public), t));
            }
            for via in [Via::CreateObject, Via::Unwrap] {
                out.push((Template::Import(on, via), templates::import_key(on, policy.clone()).unwrap()));
            }
            if on.object.class == Class::PrivateKey {
                out.push((Template::PublicHalf(on), templates::public_half(on, public, None).unwrap()));
            }
        }
        _ => out.push((Template::Object(on), templates::object(on, policy, None).unwrap())),
    }
    out
}

/// What [`Token::create_trusted_copy`] builds, less the key's material.
fn trusted_copy() -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Wrap(true),
        Attribute::Encrypt(false),
        Attribute::Verify(false),
        Attribute::Trusted(true),
        Attribute::Label(b"contract-trusted".to_vec()),
    ]
}

/// Every session key cakeys makes.
const SESSION_KEYS: [SessionKey; 9] = [
    SessionKey::ProofSecret { binding: Binding::PopEcdh, sealed: true },
    SessionKey::ProofSecret { binding: Binding::PopEcdh, sealed: false },
    SessionKey::RebindKek,
    SessionKey::RebindCopy,
    SessionKey::KwInput,
    SessionKey::HostKek,
    SessionKey::TransportKey,
    SessionKey::ExportKek,
    SessionKey::ImportKek,
];

/// The security attributes of `attrs` ([`SECURITY`]), as they are set.
fn security(attrs: &[Attribute]) -> Vec<Option<&Attribute>> {
    SECURITY.iter().map(|(t, _, _)| attrs.iter().find(|a| a.attribute_type() == *t)).collect()
}

/// K-2 (B-3, B-8): every template a provider is asked about — each `Template` variant, every
/// session key and wrap-rebind's copy — comes back from it with the security attributes it was
/// built with (not even tightened: no in-tree provider needs to), or is refused by the provider
/// itself, never by the check of what it changed. A module's own generation template
/// (`generation`, kmsp11) and the probe's bound keys set no security attribute but the locator,
/// and name a generation mechanism cakeys runs.
#[test]
fn k2_templates_keep_their_security_attributes() {
    let cfg: Config = toml::from_str(OBJECTS).unwrap();
    for p in providers() {
        let name = p.name();
        let mut asked = 0;
        let check = |req: &Template<'_>, built: Vec<Attribute>| match p.adjusted(req, built.clone()) {
            Ok(after) => assert_eq!(security(&after), security(&built), "{name}: {}", req.purpose()),
            Err(e) => assert!(!e.to_string().contains("adjusts no security attribute"), "{name}: {e}"),
        };
        for spec in ["ec", "ed", "rsa", "aes", "cert", "data"] {
            let t = Target::new(&cfg, spec, "t").unwrap();
            for (req, built) in templates_of(Declared::from(&t)) {
                check(&req, built);
                asked += 1;
            }
            if matches!(t.object.class, Class::PrivateKey | Class::SecretKey) {
                let copy = templates::rebind_copy(t.object, &[]).unwrap();
                check(&Template::Session(copy.key()), copy.attributes().to_vec());
                // A module's own generation: the locator and nothing else of the security set.
                let loc = &t.on_token.locator;
                assert!(loc.id.is_none(), "the samples are located by label");
                let locator: Vec<Attribute> =
                    loc.label.iter().map(|l| Attribute::Label(l.as_bytes().to_vec())).collect();
                match p.generation(t.object, t.spec, &t.on_token.locator, None) {
                    Ok(Some(g)) => {
                        assert!(keygen_mechanism(g.keygen).is_some(), "{name}: {spec}: {:?}", g.keygen);
                        assert_eq!(security(&g.template), security(&locator), "{name}: {spec}: its own template");
                    }
                    Ok(None) => {}
                    Err(e) => assert!(matches!(e.exit_code(), 15 | 17), "{name}: {spec}: {e}"),
                }
            }
        }
        check(&Template::TrustedCopy, trusted_copy());
        for key in SESSION_KEYS {
            let t = templates::session(key);
            let built = t.attributes().to_vec();
            match p.adjusted_session(t) {
                Ok(after) => assert_eq!(security(&after), security(&built), "{name}: {key:?}"),
                Err(e) => assert!(!e.to_string().contains("adjusts no security attribute"), "{name}: {e}"),
            }
        }
        assert!(asked >= 20, "{name}: {asked} templates");
        for b in p.bound_keys() {
            assert!(keygen_mechanism(b.keygen).is_some(), "{name}: {}: {:?}", b.name, b.keygen);
            let label = [Attribute::Label(b.label.as_bytes().to_vec())];
            assert_eq!(security(&b.template), security(&label), "{name}: {}: its template", b.name);
        }
    }
}

/// K-2's token half (B-8): each session key, made on the token from the template the provider
/// gave back, reads back as cakeys built it: `CKA_TOKEN`, `CKA_SENSITIVE` and `CKA_EXTRACTABLE`
/// as `SessionTemplate::sealing` says, so neither the provider nor what cakeys adds after it
/// unseals a key the host may not read. Opening the token runs each provider's `check_options`
/// and the session it manages in.
#[test]
fn k2_session_keys_read_back_as_built() {
    let Some((module, _token)) = softhsm("k2_session_keys_read_back_as_built") else { return };
    let reads = [AttributeType::Token, AttributeType::Sensitive, AttributeType::Extractable];
    let objects: Config = toml::from_str(OBJECTS).unwrap();
    let aes = Target::new(&objects, "aes", "t").unwrap().object;
    for p in providers() {
        let name = spied(p.as_ref());
        let cfg = config("k2", &module, name, &label("k2", name));
        let spy = Spy::new(&p, false);
        let tok = open(&cfg, &Registry::new().with(spy.clone()));
        assert!(spy.asked().contains(&Hook::CheckOptions), "{name}: opened without its options checked");
        let copy = templates::rebind_copy(aes, &[]).unwrap();
        let built = SESSION_KEYS.iter().map(|k| templates::session(*k)).chain([copy]);
        for t in built {
            let (key, sealing) = (t.key(), t.sealing());
            let mut attrs = tok.provider.adjusted_session(t).unwrap();
            let has = |ty: AttributeType| attrs.iter().any(|a| a.attribute_type() == ty);
            let h = if attrs.contains(&Attribute::Class(ObjectClass::PUBLIC_KEY)) {
                let mut modulus = vec![0xc5; 256];
                modulus[255] = 1;
                attrs.extend([Attribute::Modulus(modulus), Attribute::PublicExponent(vec![1, 0, 1])]);
                tok.raw().create_object(&attrs)
            } else {
                if !has(AttributeType::ValueLen) {
                    attrs.push(Attribute::ValueLen(32.into()));
                }
                let generic = attrs.contains(&Attribute::KeyType(KeyType::GENERIC_SECRET));
                let m = if generic { Mechanism::GenericSecretKeyGen } else { Mechanism::AesKeyGen };
                tok.raw().generate_key(&m, &attrs)
            }
            .unwrap_or_else(|e| panic!("{name}: {key:?}: {e}"));
            for (ty, want) in reads.iter().zip(sealing) {
                let Some(want) = want else { continue };
                let read = tok.raw().get_attributes(h, &[*ty]).unwrap();
                let got = read.iter().find_map(|a| match a {
                    Attribute::Token(b) | Attribute::Sensitive(b) | Attribute::Extractable(b) => Some(*b),
                    _ => None,
                });
                assert_eq!(got, Some(want), "{name}: {key:?}: {ty:?}");
            }
            tok.raw().destroy_object(h).unwrap();
        }
    }
}

// ── K-3 ──────────────────────────────────────────────────────────────────────────────────────

/// The boolean attributes a policy reads ([`Provider::policy_flag`]).
const FLAGS: [AttributeType; 22] = [
    AttributeType::Sign,
    AttributeType::SignRecover,
    AttributeType::Verify,
    AttributeType::VerifyRecover,
    AttributeType::Encrypt,
    AttributeType::Decrypt,
    AttributeType::Wrap,
    AttributeType::Unwrap,
    AttributeType::Derive,
    AttributeType::Sensitive,
    AttributeType::Extractable,
    AttributeType::AlwaysSensitive,
    AttributeType::NeverExtractable,
    AttributeType::Private,
    AttributeType::Token,
    AttributeType::Modifiable,
    AttributeType::Copyable,
    AttributeType::Destroyable,
    AttributeType::Local,
    AttributeType::Trusted,
    AttributeType::WrapWithTrusted,
    AttributeType::AlwaysAuthenticate,
];

/// The key types a repair is asked about.
const KEY_TYPES: [KeyType; 7] = [
    KeyType::EC,
    KeyType::EC_EDWARDS,
    KeyType::EC_MONTGOMERY,
    KeyType::RSA,
    KeyType::AES,
    KeyType::GENERIC_SECRET,
    KeyType::DES3,
];

/// K-3 (B-3): a repair of a read is declared, idempotent, and changes nothing a spec-compliant
/// module reports. `policy_flag` differs from the reported value only for a pair `repairs`
/// declares (core asks no other, so an undeclared one would never apply), and repairing twice
/// is repairing once; `ec_point` and `key_type` leave a compliant answer as it is and are
/// idempotent on the encodings the modules use; a stand-in has no stand-in of its own.
#[test]
fn k3_repairs_are_declared_and_idempotent() {
    let point = |n: usize| std::iter::once(0x04).chain((1..n).map(|i| u8::try_from(i).unwrap())).collect::<Vec<u8>>();
    let der = |raw: &[u8]| -> Vec<u8> {
        let mut v = vec![0x04];
        if raw.len() >= 0x80 {
            v.push(0x81);
        }
        v.push(u8::try_from(raw.len()).unwrap());
        v.extend_from_slice(raw);
        v
    };
    // Compliant: a DER OCTET STRING of the point (P-256, P-521's long form, Ed25519).
    let compliant = [der(&point(65)), der(&point(133)), der(&[7; 32])];
    // What modules report instead: the bare point, P-521's short form (tpm2-pkcs11), an Ed25519
    // SPKI (AWS CloudHSM).
    let mut short = vec![0x04, 0x85];
    short.extend(point(133));
    let mut spki = vec![0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
    spki.extend([7; 32]);
    let reported = [point(65), point(133), short, spki, vec![], vec![0x04]];
    let ed25519 = [0x06, 0x03, 0x2b, 0x65, 0x70];
    let types: [(KeyType, Option<&[u8]>); 5] = [
        (KeyType::EC, Some(&P256)),
        (KeyType::EC_EDWARDS, Some(&ed25519)),
        (KeyType::RSA, None),
        (KeyType::AES, None),
        (KeyType::GENERIC_SECRET, None),
    ];
    let asked = [
        Mechanism::EccKeyPairGen,
        Mechanism::EccEdwardsKeyPairGen,
        Mechanism::EccMontgomeryKeyPairGen,
        Mechanism::RsaPkcsKeyPairGen,
        Mechanism::AesKeyGen,
        Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
        Mechanism::Ecdsa,
        Mechanism::RsaPkcs,
    ];
    for p in providers() {
        let name = p.name();
        let repairs = p.repairs();
        for attr in FLAGS {
            for kt in KEY_TYPES {
                for r in [false, true] {
                    let once = p.policy_flag(attr, r, &|| Some(kt));
                    assert!(
                        once == r || repairs.contains(&(attr, kt)),
                        "{name}: {attr:?} of {kt:?}: undeclared repair"
                    );
                    assert_eq!(p.policy_flag(attr, once, &|| Some(kt)), once, "{name}: {attr:?} of {kt:?}: twice");
                }
            }
        }
        for c in &compliant {
            assert_eq!(p.ec_point(c).as_ref(), c.as_slice(), "{name}: a compliant point");
        }
        for raw in compliant.iter().chain(&reported) {
            let once = p.ec_point(raw).into_owned();
            assert_eq!(p.ec_point(&once).as_ref(), once.as_slice(), "{name}: {raw:02x?} repaired twice");
        }
        for (kt, params) in types {
            assert_eq!(p.key_type(kt, params), kt, "{name}: a compliant {kt:?}");
        }
        for (kt, params) in [(KeyType::EC, Some(&ed25519[..])), (KeyType::EC, Some(&P256[..])), (KeyType::EC, None)] {
            let once = p.key_type(kt, params);
            assert_eq!(p.key_type(once, params), once, "{name}: {kt:?} repaired twice");
        }
        for m in &asked {
            if let Some(s) = p.stand_in(m) {
                assert_ne!(s.mechanism_type(), m.mechanism_type(), "{name}: {m:?} stands in for itself");
                assert!(p.stand_in(&s).is_none(), "{name}: {m:?}'s stand-in has one");
            }
        }
    }
}

// ── K-4 ──────────────────────────────────────────────────────────────────────────────────────

/// K-4 (B-7, B-10): a code family is its code's alone. A registry without the code refuses
/// (17) every family of `CODE_FAMILIES`; this build's registry names each one it links as
/// itself and refuses the others; a module of Yubico's that is no `YubiKey` (a `YubiHSM`) is no
/// family's, so `generic`; and every provider is the one its name selects.
#[test]
fn k4_a_code_family_is_its_codes_alone() {
    Set::activate_embedded().unwrap();
    let (bare, built) = (Registry::new(), default_registry());
    for family in CODE_FAMILIES {
        assert!(matches!(bare.named(family), Err(KmError::Validation(_))), "{family}: named without its code");
        match built.named(family) {
            Ok(Some(p)) => assert!(p.name() == family && built.names().contains(&family), "{family}"),
            other => assert!(!built.names().contains(&family) && other.is_err(), "{family}: {:?}", other.err()),
        }
    }
    let yubihsm = ModuleInfo {
        path: "/yubihsm_pkcs11.so".into(),
        hash: None,
        description: "YubiHSM PKCS#11 Library".into(),
        manufacturer: "Yubico (www.yubico.com)".into(),
        version: "2.6".into(),
        cryptoki: "2.40".into(),
    };
    assert_eq!(built.select(None, &yubihsm).unwrap().name(), "generic", "a YubiHSM");
    let all = providers();
    for p in &all {
        assert_eq!(built.named(p.name()).unwrap().map(|q| q.name()), Some(p.name()));
        // `generic` is what no other claims, so it claims any module.
        assert!(p.name() == "generic" || !p.matches(&yubihsm), "{}: claims a YubiHSM", p.name());
    }
    let mut names: Vec<&str> = all.iter().map(|p| p.name()).collect();
    let n = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), n, "two providers of one name: {names:?}");
}

// ── K-5, K-6 ─────────────────────────────────────────────────────────────────────────────────

/// K-5 (B-13): a module whose `C_DestroyObject` answers `CKR_OK` and destroys nothing
/// (p11-fault, every destroy) has `delete` end 16 (`delete-kept`) with the lock as it was, under
/// every provider that does not refuse the delete first; one that does refuses before its
/// `destroy` is asked. The key is made by plain PKCS#11 under the provider's name.
#[test]
fn k5_a_destroy_the_module_did_not_do_keeps_the_lock() {
    let Some((_module, _token)) = softhsm("k5_a_destroy_the_module_did_not_do_keeps_the_lock") else { return };
    let (Ok(_), Ok(plan)) = (std::env::var("P11_FAULT_MODULE"), std::env::var("P11_FAULT_PLAN")) else {
        test_skip::skip(
            "k5_a_destroy_the_module_did_not_do_keeps_the_lock",
            "CAKEYS_FAULT_REQUIRE",
            "P11_FAULT_MODULE and P11_FAULT_PLAN are not set (nix/test-tokens.sh sets them for this suite)",
        );
        return;
    };
    // Written before the shim is loaded, which reads it once.
    std::fs::write(&plan, "[[rule]]\nfn = \"C_DestroyObject\"\nrv = \"CKR_OK\"\n").unwrap();
    let shim = fault_shim();
    let mut kept = 0;
    for p in providers() {
        let name = spied(p.as_ref());
        let cfg = config("k5", &shim, name, &label("k5", name));
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = new_lock();
        let mut notes = Notes::default();
        ops::create(&t, &plain(&cfg, name), &mut lock, LockWrite::Record, &mut notes).unwrap();
        let recorded = toml::to_string(&lock).unwrap();
        let spy = Spy::new(&p, false);
        let tok = open(&cfg, &Registry::new().with(spy.clone()));
        let e = ops::delete(&t, &tok, &mut lock, None, false, &mut notes).err();
        let said = e.as_ref().map(ToString::to_string).unwrap_or_default();
        match e.map(|e| (e.exit_code(), e.rule())) {
            Some((16, Some(Rule::DeleteKept))) => kept += 1,
            Some((15 | 17, _)) => assert!(!spy.asked().contains(&Hook::Destroy), "{name}: refused after destroying"),
            other => panic!("{name}: {other:?}: {said}"),
        }
        assert_eq!(toml::to_string(&lock).unwrap(), recorded, "{name}: the lock is as it was");
        assert_eq!(tok.find_any(&t.on_token.locator).unwrap().len(), 2, "{name}: the key pair is there");
    }
    assert!(kept > 0, "no provider reached the destroy");
}

/// p11-fault, built beside this test binary as a dependency.
fn fault_shim() -> String {
    let exe = std::env::current_exe().unwrap();
    let path = exe.with_file_name(format!("libp11_fault{}", std::env::consts::DLL_SUFFIX));
    assert!(path.exists(), "{} is not built", path.display());
    path.to_str().unwrap().to_owned()
}

/// K-6 (B-13): a module profile that answers `delete.CKO_PRIVATE_KEY = no` (tpm2-pkcs11's on
/// swtpm, as committed) refuses the delete (15) under every provider, before its `destroy` is
/// asked, and the key and the lock stay.
#[test]
fn k6_a_profile_no_refuses_the_delete_before_any_destroy() {
    let Some((module, _token)) = softhsm("k6_a_profile_no_refuses_the_delete_before_any_destroy") else { return };
    let swtpm = Set::activate_embedded().unwrap().find("tpm2-pkcs11/1.10+swtpm").unwrap().clone();
    let row = cakeys_profile::Capability::Delete("CKO_PRIVATE_KEY".into());
    assert_eq!(swtpm.answer(&row), Some(false), "the committed row");
    for p in providers() {
        let name = spied(p.as_ref());
        let cfg = config("k6", &module, name, &label("k6", name));
        let t = Target::new(&cfg, "s", "t").unwrap();
        let mut lock = new_lock();
        let mut notes = Notes::default();
        let maker = plain(&cfg, name);
        maker.destroy(&t.object, &t.on_token.locator).unwrap();
        ops::create(&t, &maker, &mut lock, LockWrite::Record, &mut notes).unwrap();
        let recorded = toml::to_string(&lock).unwrap();
        let spy = Spy::new(&p, false);
        let mut tok = open(&cfg, &Registry::new().with(spy.clone()));
        tok.profiles.module = Some(swtpm.clone());
        for dry in [true, false] {
            let e = ops::delete(&t, &tok, &mut lock, None, dry, &mut notes).err();
            assert_eq!(e.map(|e| e.exit_code()), Some(15), "{name}: dry {dry}");
        }
        assert!(!spy.asked().contains(&Hook::Destroy), "{name}: destroy asked: {:?}", spy.asked());
        assert_eq!(toml::to_string(&lock).unwrap(), recorded, "{name}: the lock is as it was");
        assert_eq!(tok.find_any(&t.on_token.locator).unwrap().len(), 2, "{name}: the key pair is there");
        drop(tok);
        maker.destroy(&t.object, &t.on_token.locator).unwrap();
    }
}

// ── K-7, and the rest ────────────────────────────────────────────────────────────────────────

/// K-7: every `Provider` method is in [`Hook`], and each hook's case is a test of this file.
#[test]
fn k7_every_hook_has_a_case() {
    let source = |path: &str| {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    };
    let provider = source("../pkcs11/src/provider.rs");
    let body = provider.split("\npub trait Provider").nth(1).expect("the trait").split("\n}\n").next().unwrap();
    let methods: Vec<&str> =
        body.lines().filter_map(|l| l.strip_prefix("    fn ")).map(|l| l.split(['(', '<']).next().unwrap()).collect();
    let hooks: Vec<&str> = Hook::ALL.iter().map(|h| h.method()).collect();
    assert_eq!(methods, hooks, "the trait's methods, in order, and this file's hooks");
    let own = source("tests/provider_contract.rs");
    for h in Hook::ALL {
        let test = format!("#[test]\nfn {}()", h.case());
        assert!(own.contains(&test), "{h:?}: no test {}", h.case());
    }
}

/// What a provider only says — its hint, its attestation, a scratch companion — changes no
/// outcome: a hinted refusal keeps its kind, code and rule; an attestation names the classes it
/// attests; and bytes that are no certificate are no companion.
#[test]
fn what_a_provider_only_says_changes_no_outcome() {
    for p in providers() {
        let name = p.name();
        for about in [Topic::Generate, Topic::Create, Topic::Mechanism] {
            let e = KmError::Unsupported("refused".into()).with_rule(Rule::Placement);
            let hinted = p.hinted(about, e);
            assert_eq!((hinted.exit_code(), hinted.rule()), (15, Some(Rule::Placement)), "{name}: {about:?}");
            assert!(hinted.to_string().starts_with("unsupported: refused"), "{name}: {hinted}");
            let other = p.hinted(about, KmError::Validation("v".into()));
            assert_eq!(other.to_string(), KmError::Validation("v".into()).to_string(), "{name}");
        }
        if let Some(a) = p.attestation() {
            assert!(!a.classes.is_empty(), "{name}: attests nothing");
        }
        assert!(!p.scratch_companion(b"\x01", b"not a certificate"), "{name}");
    }
}
