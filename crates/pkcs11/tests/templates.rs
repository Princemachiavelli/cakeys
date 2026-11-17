//! `Provider::template` on a real module (`SoftHSM`): the templates cakeys builds for a
//! generation, a proof of possession and the host's session key each pass through the provider,
//! what it sets reaches the token, and its refusal comes before anything is made. Skipped
//! without `CAKEYS_TEST_MODULE`.

use cakeys_core::config::{AttrValue, Binding, Locator, ObjectCfg, SpecCfg, TokenCfg};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result};
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

#[test]
fn templates_pass_through_the_provider() {
    let Ok(module) = std::env::var("CAKEYS_TEST_MODULE") else {
        eprintln!("skipping templates: CAKEYS_TEST_MODULE is not set");
        return;
    };
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cakeys-pkcs11-templates");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    let cfg: TokenCfg = toml::from_str(&format!(
        "module = \"{module}\"\nprovider = \"stamp\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n",
        dir.join("pin").display()
    ))
    .unwrap();
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
