//! `Provider::template` on a real module (`SoftHSM`): the templates cakeys builds for a
//! generation, a proof of possession, the host's session key and a transport key's trusted copy
//! each pass through the provider, what it sets reaches the token, and its refusal comes before
//! anything is made, a proof's included. Skipped without `CAKEYS_TEST_MODULE`.
//!
//! The import templates (`Import`, `PublicHalf`, `Object`) are asked by camigrate and the probe
//! alone, never by this crate: caprobe's `tests/template_hook.rs` holds the probe's to the
//! provider. camigrate has no entry point a test can give a registry, so its own asks are held
//! only by its runs with the default providers.

use cakeys_core::config::{AttrValue, Binding, Locator, Lock, Object, ObjectCfg, SpecCfg, TokenCfg};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::ops;
use cakeys_pkcs11::token::{Access, ModuleInfo};
use cakeys_pkcs11::{Attributes, ChainTime, Half, Provider, Registry, SessionKey, Template, Token};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// What the provider sets on every key it generates: readable back, and no default's.
const SUBJECT: &[u8] = b"0\x0e1\x0c0\n\x06\x03U\x04\x03\x0c\x03tmp";

/// What the provider sets as the trusted copy's `CKA_ID`: readable back, and no default's.
const TRUSTED_ID: &[u8] = b"stamped";

/// The label whose key the provider refuses to generate.
const REFUSED: &str = "tmpl-refused";

/// What a template is for, as the providers here record it.
fn kind(req: &Template<'_>) -> String {
    match req {
        Template::Generate(_, half) => format!("generate {half:?}"),
        Template::Session(key) => format!("session {key:?}"),
        Template::Import(_, via) => format!("import {via:?}"),
        Template::PublicHalf(_) => "public half".into(),
        Template::Object(_) => "object".into(),
        Template::TrustedCopy => "trusted copy".into(),
    }
}

/// A provider that records what each template is for, stamps generated private keys with
/// [`SUBJECT`] (a secret key has no `CKA_SUBJECT`: `SoftHSM` refuses one) and a trusted copy
/// with [`TRUSTED_ID`], and refuses a key under [`REFUSED`].
struct Stamp(Arc<Mutex<Vec<String>>>);

impl Provider for Stamp {
    fn name(&self) -> &'static str {
        "stamp"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }

    fn template(&self, req: &Template<'_>, attrs: &mut Attributes) -> Result<()> {
        match req {
            Template::Generate(on, _) if on.locator.label.as_deref() == Some(REFUSED) => {
                return Err(KmError::Unsupported("stamp refuses this key".into()));
            }
            Template::Generate(on, Half::Key) if on.object.class == Class::PrivateKey => {
                attrs.set(Attribute::Subject(SUBJECT.to_vec()));
            }
            Template::TrustedCopy => attrs.set(Attribute::Id(TRUSTED_ID.to_vec())),
            _ => {}
        }
        self.0.lock().unwrap().push(kind(req));
        Ok(())
    }
}

fn spec(attributes: &[(&str, bool)]) -> SpecCfg {
    SpecCfg {
        object: "k".into(),
        attributes: attributes.iter().map(|(n, v)| ((*n).to_owned(), AttrValue::Bool(*v))).collect(),
        public_attributes: BTreeMap::new(),
        migrate: cakeys_core::config::SpecMigrateCfg::default(),
        tokens: BTreeMap::new(),
    }
}

fn at(label: &str) -> Locator {
    Locator { label: Some(label.into()), id: None }
}

/// The `SoftHSM` reference token as keys.toml's `[tokens.softhsm]` says it, its provider
/// `provider`, and PIN files for it, the user's and the SO's (the harness's 5678); `None`
/// without the module.
fn token(provider: &str) -> Option<String> {
    let Ok(module) = std::env::var("CAKEYS_TEST_MODULE") else {
        // As every token suite (`common::suite_var`): required where the harness says so.
        assert!(std::env::var("CAKEYS_TEST_REQUIRE").is_err(), "CAKEYS_TEST_MODULE is required");
        eprintln!("skipping templates: CAKEYS_TEST_MODULE is not set");
        return None;
    };
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("cakeys-pkcs11-templates-{provider}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    std::fs::write(dir.join("so-pin"), "5678\n").unwrap();
    Some(format!(
        "module = \"{module}\"\nprovider = \"{provider}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n\
         soCredentialFile = \"{}\"\n",
        dir.join("pin").display(),
        dir.join("so-pin").display()
    ))
}

/// A provider that refuses every proof's session secret, and records what each template it is
/// asked is for.
struct NoProof(Arc<Mutex<Vec<String>>>);

impl Provider for NoProof {
    fn name(&self) -> &'static str {
        "no-proof"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }

    fn template(&self, req: &Template<'_>, _: &mut Attributes) -> Result<()> {
        self.0.lock().unwrap().push(kind(req));
        match req {
            Template::Session(SessionKey::ProofSecret { .. }) => Err(KmError::Unsupported("no-proof refuses".into())),
            _ => Ok(()),
        }
    }
}

/// The proof of possession runs once the key exists; its template is asked before the key is
/// generated, so a provider refusing it leaves nothing behind (a key on a module that cannot
/// delete one would stay).
#[test]
fn a_refused_proof_template_creates_nothing() {
    cakeys_profile::Set::activate_embedded().unwrap();
    let Some(token) = token("no-proof") else { return };
    let cfg: cakeys_core::config::Config = toml::from_str(&format!(
        "[tokens.softhsm]\n{token}\n\
         [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"k\"\nattributes = {{ CKA_DERIVE = true }}\n\
         tokens.softhsm = {{ locator = {{ CKA_LABEL = \"tmpl-proof\" }}, origin = \"create\", binding = \"pop-ecdh\" }}\n"
    ))
    .unwrap();
    let t = ops::Target::new(&cfg, "s", "softhsm").unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let registry = Registry::new().with(NoProof(Arc::clone(&asked)));
    let tok =
        Token::open("softhsm", &cfg.tokens["softhsm"], None, &registry, Access::Write, ChainTime::Unchecked).unwrap();
    tok.destroy(&t.object, &t.on_token.locator).unwrap();
    let mut lock = Lock { version: cakeys_core::config::LOCK_VERSION, ..Lock::default() };
    let mut notes = ops::Notes::default();
    asked.lock().unwrap().clear();
    let e = ops::create(&t, &tok, &mut lock, ops::LockWrite::Record, &mut notes).unwrap_err();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("no-proof refuses")), "{e}");
    // Not generated and removed again (SoftHSM could): never generated. A generation asks its
    // templates right before it generates, so a key made before the refusal shows as a second
    // pair of them; the check asks them once, then the proof's, refused, the last asked (review
    // templates.rs F2: an empty note list stood in for this).
    let asked = asked.lock().unwrap().clone();
    let refused = format!("session {:?}", SessionKey::ProofSecret { binding: Binding::PopEcdh, sealed: true });
    let generations = asked.iter().filter(|a| a.starts_with("generate")).count();
    assert_eq!(generations, 2, "the generation's templates, asked by the check alone: {asked:?}");
    assert_eq!(asked.last(), Some(&refused), "asked after the refusal: {asked:?}");
    assert_eq!(tok.find_any(&t.on_token.locator).unwrap().len(), 0);
}

#[test]
fn templates_pass_through_the_provider() {
    cakeys_profile::Set::activate_embedded().unwrap();
    let Some(table) = token("stamp") else { return };
    let cfg: TokenCfg = toml::from_str(&table).unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let registry = Registry::new().with(Stamp(Arc::clone(&asked)));
    let tok = Token::open("softhsm", &cfg, None, &registry, Access::Write, ChainTime::Unchecked).unwrap();
    let taken = || std::mem::take(&mut *asked.lock().unwrap());

    // A key pair: both templates asked, the key stamped.
    let ec = ObjectCfg { curve: Some("secp256r1".into()), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::Ec)) };
    let loc = at("tmpl-ec");
    tok.destroy(&ec, &loc).unwrap();
    tok.create(Object::new(&ec).unwrap(), &spec(&[("CKA_SIGN", true), ("CKA_DERIVE", true)]), &loc, None).unwrap();
    let mut generated = taken();
    generated.sort();
    assert_eq!(generated, ["generate Key", "generate Public"]);
    let [h] = tok.find(ObjectClass::PRIVATE_KEY, &loc).unwrap()[..] else { panic!("one private key") };
    let subject = tok.raw().get_attributes(h, &[AttributeType::Subject]).unwrap();
    assert_eq!(subject, [Attribute::Subject(SUBJECT.to_vec())]);

    // A proof's session secret.
    let spki = tok.spki(h, &loc).unwrap();
    tok.prove_binding(h, Object::new(&ec).unwrap(), &spki, Binding::PopEcdh).unwrap();
    assert!(
        taken().contains(&format!("session {:?}", SessionKey::ProofSecret { binding: Binding::PopEcdh, sealed: true })),
        "the sealed secret's template"
    );
    tok.destroy(&ec, &loc).unwrap();

    // The host's session key, taking a secret key out.
    let aes = ObjectCfg { value_len: Some(32), ..ObjectCfg::new(Class::SecretKey, Some(Kt::Aes)) };
    let loc = at("tmpl-aes");
    tok.destroy(&aes, &loc).unwrap();
    tok.create(Object::new(&aes).unwrap(), &spec(&[("CKA_EXTRACTABLE", true), ("CKA_SENSITIVE", false)]), &loc, None)
        .unwrap();
    let [h] = tok.find(ObjectClass::SECRET_KEY, &loc).unwrap()[..] else { panic!("one secret key") };
    taken();
    assert_eq!(tok.extract(h, &Mechanism::AesKeyWrapPad).unwrap().len(), 32);
    assert_eq!(taken(), [format!("session {:?}", SessionKey::HostKek)]);
    tok.destroy(&aes, &loc).unwrap();

    // A transport key's trusted copy, made as SO: its template asked, what the provider set on
    // the object (review templates.rs F3: no template but a generation's and a session's was
    // ever asked here).
    let mut modulus = vec![0xc5; 256];
    modulus[255] = 0x01;
    let h = tok.create_trusted_copy(modulus, vec![1, 0, 1], "tmpl-trusted").unwrap();
    assert_eq!(taken(), ["trusted copy"]);
    let id = tok.raw().get_attributes(h, &[AttributeType::Id, AttributeType::Trusted]).unwrap();
    assert_eq!(id, [Attribute::Id(TRUSTED_ID.to_vec()), Attribute::Trusted(true)]);
    // Taken off again as SO, with any an earlier run left (review 2026-11-23 B-25): the token's
    // trusted set, which `Token::trusted` counts for camigrate, stays as the test found it.
    let label = [Attribute::Label(b"tmpl-trusted".to_vec())];
    let left = || tok.raw().find_objects(&label).unwrap();
    tok.as_so("removing the trusted copies", || {
        for h in left() {
            tok.raw().destroy_object(h).map_err(|e| KmError::Unavailable(e.to_string().into()))?;
        }
        Ok(())
    })
    .unwrap();
    assert!(left().is_empty(), "a trusted copy left on the token");

    // Refused: the provider's error, and nothing under the locator.
    let loc = at(REFUSED);
    let e = tok.create(Object::new(&ec).unwrap(), &spec(&[("CKA_SIGN", true)]), &loc, None).unwrap_err();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("stamp refuses")), "{e}");
    assert_eq!(tok.find_any(&loc).unwrap().len(), 0, "made under the refused locator");
}
