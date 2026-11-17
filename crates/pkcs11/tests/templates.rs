//! `Provider::template` on a real module (`SoftHSM`): the templates cakeys builds for a
//! generation, a proof of possession and the host's session key each pass through the provider,
//! what it sets reaches the token, and its refusal comes before anything is made, a proof's
//! included. Skipped without `CAKEYS_TEST_MODULE`.

use cakeys_core::config::{AttrValue, Binding, Locator, Lock, ObjectCfg, SpecCfg, TokenCfg};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::ops;
use cakeys_pkcs11::token::{Access, ModuleInfo};
use cakeys_pkcs11::{Attributes, Half, Provider, Registry, SessionKey, Template, Token};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// What the provider sets on every key it generates: readable back, and no default's.
const SUBJECT: &[u8] = b"0\x0e1\x0c0\n\x06\x03U\x04\x03\x0c\x03tmp";

/// The label whose key the provider refuses to generate.
const REFUSED: &str = "tmpl-refused";

/// A provider that records what each template is for, stamps generated private keys with
/// [`SUBJECT`] (a secret key has no `CKA_SUBJECT`: `SoftHSM` refuses one),
/// and refuses a key under [`REFUSED`].
struct Stamp(Arc<Mutex<Vec<String>>>);

impl Provider for Stamp {
    fn name(&self) -> &'static str {
        "stamp"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }

    fn template(&self, req: &Template<'_>, attrs: &mut Attributes) -> Result<()> {
        let asked = match req {
            Template::Generate(on, half) => {
                if on.locator.label.as_deref() == Some(REFUSED) {
                    return Err(KmError::Unsupported("stamp refuses this key".into()));
                }
                if *half == Half::Key && on.object.class == Class::PrivateKey {
                    attrs.set(Attribute::Subject(SUBJECT.to_vec()));
                }
                format!("generate {half:?}")
            }
            Template::Session(key) => format!("session {key:?}"),
            Template::Import(_, via) => format!("import {via:?}"),
            Template::PublicHalf(_) => "public half".into(),
            Template::Object(_) => "object".into(),
            Template::TrustedCopy => "trusted copy".into(),
        };
        self.0.lock().unwrap().push(asked);
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
/// `provider`, and a PIN file for it; `None` without the module.
fn token(provider: &str) -> Option<String> {
    let Ok(module) = std::env::var("CAKEYS_TEST_MODULE") else {
        eprintln!("skipping templates: CAKEYS_TEST_MODULE is not set");
        return None;
    };
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("cakeys-pkcs11-templates-{provider}"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    Some(format!(
        "module = \"{module}\"\nprovider = \"{provider}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n",
        dir.join("pin").display()
    ))
}

/// A provider that refuses every proof's session secret.
struct NoProof;

impl Provider for NoProof {
    fn name(&self) -> &'static str {
        "no-proof"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }

    fn template(&self, req: &Template<'_>, _: &mut Attributes) -> Result<()> {
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
    let Some(token) = token("no-proof") else { return };
    let cfg: cakeys_core::config::Config = toml::from_str(&format!(
        "[tokens.softhsm]\n{token}\n\
         [objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"k\"\nattributes = {{ CKA_DERIVE = true }}\n\
         tokens.softhsm = {{ locator = {{ CKA_LABEL = \"tmpl-proof\" }}, origin = \"create\", binding = \"pop-ecdh\" }}\n"
    ))
    .unwrap();
    let t = ops::Target::new(&cfg, "s", "softhsm").unwrap();
    let registry = Registry::new().with(NoProof);
    let tok = Token::open("softhsm", &cfg.tokens["softhsm"], None, &registry, Access::Write).unwrap();
    tok.destroy(t.object, &t.on_token.locator).unwrap();
    let mut lock = Lock { version: cakeys_core::config::LOCK_VERSION, ..Lock::default() };
    let mut notes = ops::Notes::default();
    let e = ops::create(&t, &tok, &mut lock, ops::LockWrite::Record, &mut notes).unwrap_err();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("no-proof refuses")), "{e}");
    // Not generated and removed again (SoftHSM could): never generated.
    assert_eq!(notes.lines(), [] as [String; 0], "a key was generated");
    assert_eq!(tok.find_any(&t.on_token.locator).unwrap().len(), 0);
}

#[test]
fn templates_pass_through_the_provider() {
    let Some(table) = token("stamp") else { return };
    let cfg: TokenCfg = toml::from_str(&table).unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let registry = Registry::new().with(Stamp(Arc::clone(&asked)));
    let tok = Token::open("softhsm", &cfg, None, &registry, Access::Write).unwrap();
    let taken = || std::mem::take(&mut *asked.lock().unwrap());

    // A key pair: both templates asked, the key stamped.
    let ec = ObjectCfg { curve: Some("secp256r1".into()), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::Ec)) };
    let loc = at("tmpl-ec");
    tok.destroy(&ec, &loc).unwrap();
    tok.create(&ec, &spec(&[("CKA_SIGN", true), ("CKA_DERIVE", true)]), &loc, None).unwrap();
    let mut generated = taken();
    generated.sort();
    assert_eq!(generated, ["generate Key", "generate Public"]);
    let [h] = tok.find(ObjectClass::PRIVATE_KEY, &loc).unwrap()[..] else { panic!("one private key") };
    let subject = tok.raw().get_attributes(h, &[AttributeType::Subject]).unwrap();
    assert_eq!(subject, [Attribute::Subject(SUBJECT.to_vec())]);

    // A proof's session secret.
    let spki = tok.spki(h, &loc).unwrap();
    tok.prove_binding(h, &ec, &spki, Binding::PopEcdh).unwrap();
    assert!(
        taken().contains(&format!("session {:?}", SessionKey::ProofSecret { binding: Binding::PopEcdh, sealed: true })),
        "the sealed secret's template"
    );
    tok.destroy(&ec, &loc).unwrap();

    // The host's session key, taking a secret key out.
    let aes = ObjectCfg { value_len: Some(32), ..ObjectCfg::new(Class::SecretKey, Some(Kt::Aes)) };
    let loc = at("tmpl-aes");
    tok.destroy(&aes, &loc).unwrap();
    tok.create(&aes, &spec(&[("CKA_EXTRACTABLE", true), ("CKA_SENSITIVE", false)]), &loc, None).unwrap();
    let [h] = tok.find(ObjectClass::SECRET_KEY, &loc).unwrap()[..] else { panic!("one secret key") };
    taken();
    assert_eq!(tok.extract(h, &Mechanism::AesKeyWrapPad).unwrap().len(), 32);
    assert_eq!(taken(), [format!("session {:?}", SessionKey::HostKek)]);
    tok.destroy(&aes, &loc).unwrap();

    // Refused: the provider's error, and nothing under the locator.
    let loc = at(REFUSED);
    let e = tok.create(&ec, &spec(&[("CKA_SIGN", true)]), &loc, None).unwrap_err();
    assert!(matches!(&e, KmError::Unsupported(m) if m.contains("stamp refuses")), "{e}");
    assert_eq!(tok.find_any(&loc).unwrap().len(), 0, "made under the refused locator");
}
