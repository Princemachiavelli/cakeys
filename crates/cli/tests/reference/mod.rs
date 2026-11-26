//! The reference-token suite: end-to-end tests of the CLI against one software PKCS#11 token
//! (the token `ref`, plus `ref-anon`, which is the same token without a PIN). Each reference
//! binary (such as `tests/softhsm.rs`) includes it.
//!
//! The tests of a single verb are in that verb's file (`check`, `create`, `delete` with `gc`,
//! `validate`). The tests of what `lock` and `check` share are grouped by concern (`identity`,
//! `proofs`, `adoption`, `drift`, `lockfile`, `tokens`). The tests of the rows that every
//! per-object verb prints are in `rows`. This file holds the harness and the fixtures that
//! several of those files use.

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
mod rows;
mod tokens;
mod validate;

/// Returns the reference suite for test `name` (with the tokens of [`reference_tokens`]), or
/// `None` when the test is skipped.
pub(crate) fn env(name: &str) -> Option<Suite> {
    let module = suite_var(REF.module_var, REF.require_var, name)?;
    // Through p11-fault, the variable names the module behind the shim, and the token loads the
    // shim.
    let module = if REF.through_fault_shim { fault_shim() } else { module };
    Some(Suite::new(name, module, reference_tokens))
}

impl Suite {
    /// Replaces the lock with one written by hand, but keeps the realisations that are already
    /// recorded and the observations that they name. The part under test is `objects`.
    fn write_lock_keeping_realisations(&self, text: &str) {
        let mut lock: toml::Table = toml::from_str(text).unwrap();
        let now = self.lock();
        // The realisations name entries of the observation table, so the two tables are kept
        // together.
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

/// Hashes of the EC and Edwards fixture certificates, computed with openssl (see
/// `adoption::ADOPT_CERTHASH`).
const P384_CERTHASH: &str = "sha256-N9KvOrT63A5pe2lyZhomsSGisv5jxm7uGH0BBaDvT8w=";
const P384_PUBKEYHASH: &str = "sha256-vOGGK+vjgXw92IhWaKP7ud6cGe6qS9UCctpXq6zZmZo=";
const ED25519_CERTHASH: &str = "sha256-vLKP3eF+jeIMpcIz0K9c8oiCVsbvDve+uBUYho+aOmU=";
const ED25519_PUBKEYHASH: &str = "sha256-LmLQD9g76Y3XJI3Wu72BFxjm/HLImLgqJazAeCNi4lY=";

/// Plants a secret key with a known value, so that the host oracle knows the value.
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

/// Asserts that a private key that was swapped under its locator is a conflict (13). The conflict
/// is found in one of two ways. When the private key exposes no public key (`SoftHSM` EC and
/// Edwards keys), the proof of possession fails. When the private key holds its own
/// `CKA_PUBLIC_KEY_INFO` (kryoptic), the cross-check against the locked material refuses it before
/// any proof runs.
fn assert_swapped_key_conflict(o: &Output) {
    let err = stderr(o);
    assert_eq!(code(o), 13, "{err}");
    assert!(err.contains("proof of possession failed") || err.contains("disagrees with the key material"), "{err}");
}

impl Suite {
    /// Writes this test's copy of the module configuration with `mechanism` hidden, and returns
    /// the variable name and the file path for [`Workdir::km_env`].
    fn hiding(&self, mechanism: &str) -> (&'static str, std::path::PathBuf) {
        let conf = std::fs::read_to_string(std::env::var(REF.conf_var).unwrap()).unwrap();
        let hidden = self.dir.join(format!("no-{mechanism}.conf"));
        std::fs::write(&hidden, (REF.hide_mechanism)(&conf, mechanism)).unwrap();
        (REF.conf_var, hidden)
    }
}
