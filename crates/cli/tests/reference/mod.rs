//! The reference-token suite: end-to-end tests of the CLI against one software PKCS#11 token
//! (token `ref`, plus `ref-anon`, the same token without a PIN). Each reference binary
//! (`tests/softhsm.rs`) includes it.
//!
//! A verb's own tests are in its file (`check`, `create`, `delete` with `gc`, `validate`); what
//! `lock` and `check` share is by concern (`identity`, `proofs`, `adoption`, `drift`,
//! `lockfile`, `tokens`). This file holds the harness and the fixtures several of them use.

#![expect(clippy::type_complexity, reason = "table-driven cases")]

use cryptoki::context::Pkcs11;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::Session;
use cryptoki::types::AuthPin;
use hmac::{Hmac, KeyInit, Mac};
use std::process::{Command, Output};

use crate::REF;
use crate::common::*;

mod adoption;
mod check;
mod create;
mod delete;
mod drift;
mod identity;
mod lockfile;
mod proofs;
mod tokens;
mod validate;

/// The reference's suite for test `name` (its tokens: [`reference_tokens`]), or `None` (skipped).
pub(crate) fn env(name: &str) -> Option<Suite> {
    let module = suite_var(REF.module_var, REF.require_var, name)?;
    // Through p11-fault, the variable names the module behind it, and the token loads the shim.
    let module = if REF.through_fault_shim { fault_shim() } else { module };
    Some(Suite::new(name, module, reference_tokens))
}

impl Suite {
    /// Replace the lock with a hand-written one, keeping the realisations already recorded and the
    /// observations they name (the part under test is `objects`).
    fn write_lock_keeping_realisations(&self, text: &str) {
        let mut lock: toml::Table = toml::from_str(text).unwrap();
        let now = self.lock();
        // The realisations name entries of the observation table: they go together.
        for table in ["realisations", "observations"] {
            if let Some(t) = now.get(table) {
                lock.insert(table.into(), t.clone());
            }
        }
        std::fs::write(self.dir.join("keys.lock"), toml::to_string(&lock).unwrap()).unwrap();
    }
}

const EC: &str = r#"
[objects.signing]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.signing-soft]
object = "signing"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
tokens.ref = { locator = { CKA_LABEL = "ec-lifecycle" }, origin = "create" }
"#;

const ADOPT_CERT: &[u8] = include_bytes!("../fixtures/adopt-cert.der");

/// openssl-computed hashes of the EC and Edwards fixture certificates (see
/// `adoption::ADOPT_CERTHASH`).
const P384_CERTHASH: &str = "sha256-N9KvOrT63A5pe2lyZhomsSGisv5jxm7uGH0BBaDvT8w=";
const P384_PUBKEYHASH: &str = "sha256-vOGGK+vjgXw92IhWaKP7ud6cGe6qS9UCctpXq6zZmZo=";
const ED25519_CERTHASH: &str = "sha256-vLKP3eF+jeIMpcIz0K9c8oiCVsbvDve+uBUYho+aOmU=";
const ED25519_PUBKEYHASH: &str = "sha256-LmLQD9g76Y3XJI3Wu72BFxjm/HLImLgqJazAeCNi4lY=";

/// Plant a secret key with a known value (the host oracle knows it).
fn plant_secret(s: &Session, label: &str, kt: cryptoki::object::KeyType, value: &[u8], attrs: &[Attribute]) {
    let mut t = vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(kt),
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Value(value.to_vec()),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    t.extend_from_slice(attrs);
    s.create_object(&t).unwrap();
}

/// A private key swapped under its locator is a conflict (13), reached by one of two routes: where
/// the private key exposes no public key (`SoftHSM` EC and Edwards keys), the proof of possession
/// fails; where it carries its own `CKA_PUBLIC_KEY_INFO` (kryoptic), the cross-check against the
/// locked material refuses it before any proof runs.
fn assert_swapped_key_conflict(o: &Output) {
    let err = stderr(o);
    assert_eq!(code(o), 13, "{err}");
    assert!(err.contains("proof of possession failed") || err.contains("disagrees with the key material"), "{err}");
}

impl Suite {
    /// This test's copy of the module configuration with `mechanism` hidden, for [`Workdir::km_env`].
    fn hiding(&self, mechanism: &str) -> (&'static str, std::path::PathBuf) {
        let conf = std::fs::read_to_string(std::env::var(REF.conf_var).unwrap()).unwrap();
        let hidden = self.dir.join(format!("no-{mechanism}.conf"));
        std::fs::write(&hidden, (REF.hide_mechanism)(&conf, mechanism)).unwrap();
        (REF.conf_var, hidden)
    }
}
