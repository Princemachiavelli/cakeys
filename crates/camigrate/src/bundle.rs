//! The export bundle (MIGRATE.md D5, "Frozen names and formats"): the objects one export moves
//! from a source to a target — keys wrapped to the target's transport key, public objects as
//! their bytes — with what the import checks
//! before it touches the target — per key its type, IDs and commitment label as the source's
//! lock pins them and the public key of a private key; for all, the source and the transport
//! key's identity. One file per (source, target) export; the composed method's key-encryption
//! key is shared by its keys. Never plaintext: the wrapped blobs are authenticated by RFC 5649
//! (or OAEP) and each identity recomputed on the target, so a bundle may cross untrusted
//! channels. Inside a wrapped private key is the PKCS#8 `C_WrapKey` emits; PKCS#12 or a CMS key
//! package would need the plaintext key on the host to build.

use base64::Engine as _;
use cakeys_core::config::ObjectCfg;
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::{KmError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The `format` of a bundle.
pub const BUNDLE_FORMAT: &str = "cakeys-export";
/// The `version` this camigrate writes and reads.
pub const BUNDLE_VERSION: u32 = 1;

/// One export: the keys, and what they share.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Bundle {
    pub format: String,
    pub version: u32,
    /// The AES key-encryption key under RSA-OAEP to the transport key (base64), shared by every
    /// key of a composed method; absent when none is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek: Option<String>,
    pub source: Source,
    pub transport: TransportRef,
    /// One entry per object, each object once.
    pub keys: Vec<Entry>,
}

/// One exported object: a key, wrapped, or a public object, as it is.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Entry {
    /// The object's name, as in the source's keys.toml and lock.
    pub object: String,
    /// The method's frozen name (`rsa-oaep-sha1+aes-kwp`, ...).
    pub method: String,
    pub exposure: Exposure,
    /// Secret keys: the label their commitments were computed with, as in the lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment_label: Option<String>,
    /// Private keys: the canonical SPKI DER (base64), which the target creates beside the key and
    /// whose hash must be the object's `rfc7093m4`. An addition to D5's format: a target module
    /// that keeps no public point with an unwrapped EC key (`SoftHSM`) could not compute the
    /// identity otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// A key (base64): under the bundle's KEK (RFC 5649), or under RSA-OAEP directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped: Option<String>,
    /// A public object (base64, method `public`): a certificate's DER, a public key's canonical
    /// SPKI, a data object's value. The import recomputes its identity from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The object's type, as in the lock.
    #[serde(rename = "type")]
    pub object_type: ObjectCfg,
    /// The object's IDs, as in the source's lock: the import must reproduce them.
    pub ids: BTreeMap<String, String>,
}

/// Where the material came from: provenance, as the source realisation records it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub token: String,
    pub provider: String,
}

/// The transport key the material is wrapped to: its object and locked identity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransportRef {
    pub object: String,
    pub rfc7093m4: String,
}

impl Bundle {
    /// Read a bundle, checking its form: the format and version, at least one key and each object
    /// once, sealed methods this camigrate knows with the KEK exactly when a composed one needs it
    /// (one OAEP hash for it), base64 blobs, SRI IDs, and public keys whose hash is the
    /// `rfc7093m4` they claim. That the IDs are the lock's is the import's check.
    ///
    /// # Errors
    ///
    /// `Validation` (17) for anything malformed or inconsistent.
    pub fn parse(text: &str, path: &std::path::Path) -> Result<Bundle> {
        let invalid = |msg: String| KmError::Validation(format!("{}: {msg}", path.display()));
        let mut b: Bundle = toml::from_str(text).map_err(|e| invalid(e.to_string()))?;
        if b.format != BUNDLE_FORMAT || b.version != BUNDLE_VERSION {
            return Err(invalid(format!("not a {BUNDLE_FORMAT} version {BUNDLE_VERSION} file")));
        }
        if b.keys.is_empty() {
            return Err(invalid("carries no keys".into()));
        }
        let mut seen = BTreeSet::new();
        let mut kek_hashes = BTreeSet::new();
        for e in &mut b.keys {
            let invalid = |msg: String| invalid(format!("key '{}': {msg}", e.object));
            if !seen.insert(e.object.clone()) {
                return Err(invalid("listed twice".into()));
            }
            e.object_type.canonicalize();
            let method = e.method().map_err(invalid)?;
            match method {
                Method::RsaOaepAesKwp(h) => {
                    kek_hashes.insert(h);
                }
                Method::RsaOaep(_) | Method::Public => {}
                _ => return Err(invalid(format!("method {} does not travel in a bundle", e.method))),
            }
            match (method == Method::Public, &e.wrapped, &e.value) {
                (false, Some(_), None) => {
                    e.wrapped_key().map_err(invalid)?;
                }
                (true, None, Some(_)) => {
                    e.public_value().map_err(invalid)?;
                }
                (false, ..) => return Err(invalid(format!("method {} needs a wrapped key and no value", e.method))),
                (true, ..) => return Err(invalid("a public object needs a value and no wrapped key".into())),
            }
            if let Some(v) = e.ids.values().find(|v| !cakeys_core::id::is_sri(v)) {
                return Err(invalid(format!("\"{v}\" is not a sha256 SRI digest")));
            }
            if let Some(spki) = e.public_spki().map_err(invalid)? {
                let id = cakeys_core::id::sri(&spki);
                if e.ids.get("rfc7093m4") != Some(&id) {
                    return Err(invalid(format!("publicKey is not the key rfc7093m4 names (its identity is {id})")));
                }
            }
        }
        match (kek_hashes.len(), &b.kek) {
            (0, Some(_)) => return Err(invalid("a kek, but no key of a composed method uses it".into())),
            (0, None) | (1, Some(_)) => {}
            (1, None) => return Err(invalid("keys of a composed method, but no kek".into())),
            _ => return Err(invalid("composed methods of several OAEP hashes share one kek".into())),
        }
        b.wrapped_kek().map_err(invalid)?;
        if !cakeys_core::id::is_sri(&b.transport.rfc7093m4) {
            return Err(invalid(format!("\"{}\" is not a sha256 SRI digest", b.transport.rfc7093m4)));
        }
        Ok(b)
    }

    /// The bundle's text.
    #[must_use]
    pub fn to_toml(&self) -> String {
        toml::to_string(self).unwrap_or_default()
    }

    /// The wrapped KEK's bytes.
    ///
    /// # Errors
    ///
    /// A message for malformed base64.
    pub fn wrapped_kek(&self) -> std::result::Result<Option<Vec<u8>>, String> {
        self.kek.as_deref().map(|k| decode("kek", k)).transpose()
    }
}

impl Entry {
    /// The method the entry names.
    ///
    /// # Errors
    ///
    /// A message for a name this camigrate does not know.
    pub fn method(&self) -> std::result::Result<Method, String> {
        Method::from_name(&self.method).ok_or_else(|| format!("unknown method '{}'", self.method))
    }

    /// The wrapped key's bytes.
    ///
    /// # Errors
    ///
    /// A message for malformed base64, or a public object's entry.
    pub fn wrapped_key(&self) -> std::result::Result<Vec<u8>, String> {
        decode("wrapped", self.wrapped.as_deref().ok_or("no wrapped key")?)
    }

    /// A public object's bytes.
    ///
    /// # Errors
    ///
    /// A message for malformed base64, or a key's entry.
    pub fn public_value(&self) -> std::result::Result<Vec<u8>, String> {
        decode("value", self.value.as_deref().ok_or("no value")?)
    }

    /// The private key's canonical SPKI DER.
    ///
    /// # Errors
    ///
    /// A message for malformed base64, or a public key cakeys cannot canonicalize.
    pub fn public_spki(&self) -> std::result::Result<Option<Vec<u8>>, String> {
        let Some(k) = &self.public_key else { return Ok(None) };
        let der = decode("publicKey", k)?;
        cakeys_core::id::spki_canonical(&der).map(Some).map_err(|e| format!("publicKey: {e}"))
    }
}

/// Standard base64.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode(what: &str, text: &str) -> std::result::Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD.decode(text).map_err(|e| format!("{what}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::types::{KeyType, ObjectClass};

    fn aes(object: &str, method: &str) -> Entry {
        let mut ty = ObjectCfg::new(ObjectClass::SecretKey, Some(KeyType::Aes));
        ty.value_len = Some(32);
        Entry {
            object: object.into(),
            method: method.into(),
            exposure: Exposure::Sealed,
            commitment_label: Some("key-management/v1".into()),
            public_key: None,
            wrapped: Some(encode(b"key")),
            value: None,
            object_type: ty,
            ids: [("cmac".to_owned(), cakeys_core::id::sri(object.as_bytes()))].into(),
        }
    }

    pub(crate) fn sample() -> Bundle {
        Bundle {
            format: BUNDLE_FORMAT.into(),
            version: BUNDLE_VERSION,
            kek: Some(encode(b"kek")),
            source: Source { token: "softhsm".into(), provider: "softhsm".into() },
            transport: TransportRef { object: "import-kek".into(), rfc7093m4: cakeys_core::id::sri(b"t") },
            keys: vec![aes("backup-kek", "rsa-oaep-sha1+aes-kwp"), aes("db-kek", "rsa-oaep-sha1+aes-kwp")],
        }
    }

    /// The frozen field names (MIGRATE.md, "Frozen names and formats"): a bundle written once
    /// must keep meaning the same.
    #[test]
    fn the_format_is_pinned_and_round_trips() {
        let b = sample();
        let text = b.to_toml();
        let path = std::path::Path::new("b.toml");
        assert_eq!(Bundle::parse(&text, path).unwrap(), b);
        let table: toml::Table = toml::from_str(&text).unwrap();
        let keys: Vec<&str> = table.keys().map(String::as_str).collect();
        assert_eq!(keys, ["format", "kek", "keys", "source", "transport", "version"]);
        let entry = table["keys"].as_array().unwrap()[0].as_table().unwrap();
        assert_eq!(
            entry.keys().map(String::as_str).collect::<Vec<_>>(),
            ["commitmentLabel", "exposure", "ids", "method", "object", "type", "wrapped"]
        );
    }

    /// The fuzz target's seed (fuzz/, nix/fuzz.nix) is a well-formed bundle.
    #[test]
    fn the_fuzz_seed_parses() {
        let text = include_str!("../tests/fixtures/sample.bundle.toml");
        Bundle::parse(text, std::path::Path::new("sample.bundle.toml")).unwrap();
    }

    /// What the form check refuses (17): another format, no keys or one twice, a composed method
    /// without the KEK or a KEK nothing uses, composed methods of two hashes under one KEK, a
    /// method that cannot travel in a bundle, a key without its wrapped bytes or a public object
    /// without its value, bad base64, a public key `rfc7093m4` does not name.
    #[test]
    fn malformed_bundles_are_refused() {
        let path = std::path::Path::new("b.toml");
        let refused = |b: Bundle, what: &str| {
            let e = Bundle::parse(&b.to_toml(), path).unwrap_err();
            assert!(e.exit_code() == 17 && e.to_string().contains(what), "{what}: {e}");
        };
        let direct = || vec![aes("backup-kek", "rsa-oaep-sha1")];
        refused(Bundle { format: "cakeys-transport".into(), ..sample() }, "not a cakeys-export");
        refused(Bundle { keys: vec![], ..sample() }, "carries no keys");
        refused(Bundle { keys: vec![aes("k", "rsa-oaep-sha1+aes-kwp"); 2], ..sample() }, "listed twice");
        refused(Bundle { kek: None, ..sample() }, "but no kek");
        refused(Bundle { keys: direct(), ..sample() }, "no key of a composed method uses it");
        Bundle::parse(&Bundle { kek: None, keys: direct(), ..sample() }.to_toml(), path).unwrap();
        let two = vec![aes("a", "rsa-oaep-sha1+aes-kwp"), aes("b", "rsa-oaep-sha256+aes-kwp")];
        refused(Bundle { keys: two, ..sample() }, "several OAEP hashes");
        refused(Bundle { keys: vec![aes("k", "host-pkcs8")], ..sample() }, "does not travel in a bundle");
        let cert = Entry {
            method: "public".into(),
            exposure: Exposure::Public,
            wrapped: None,
            value: Some(encode(b"der")),
            ..aes("c", "public")
        };
        Bundle::parse(
            &Bundle { keys: vec![aes("k", "rsa-oaep-sha1+aes-kwp"), cert.clone()], ..sample() }.to_toml(),
            path,
        )
        .unwrap();
        refused(Bundle { keys: vec![Entry { value: None, ..cert.clone() }], kek: None, ..sample() }, "needs a value");
        refused(
            Bundle { keys: vec![Entry { wrapped: Some(encode(b"k")), ..cert }], kek: None, ..sample() },
            "needs a value",
        );
        refused(
            Bundle { keys: vec![Entry { wrapped: None, ..aes("k", "rsa-oaep-sha1+aes-kwp") }], ..sample() },
            "needs a wrapped key",
        );
        refused(Bundle { keys: vec![aes("k", "rsa-aes")], ..sample() }, "unknown method");
        refused(Bundle { kek: Some("!".into()), ..sample() }, "kek");
        let n = [0xc5u8; 256];
        let spki = cakeys_core::id::rsa_spki(&n, &[1, 0, 1]).unwrap();
        let spoofed = Entry { public_key: Some(encode(&spki)), ..aes("k", "rsa-oaep-sha1+aes-kwp") };
        refused(Bundle { keys: vec![spoofed], ..sample() }, "is not the key rfc7093m4 names");
    }

    proptest::proptest! {
        /// Any text is read or refused as invalid (17), never a panic.
        #[test]
        fn any_text_parses_or_is_invalid(text in "\\PC*") {
            if let Err(e) = Bundle::parse(&text, std::path::Path::new("b.toml")) {
                proptest::prop_assert_eq!(e.exit_code(), 17);
            }
        }

        /// A bundle with any object names, label and blobs round-trips.
        #[test]
        fn bundles_round_trip(
            objects in proptest::collection::btree_set("[a-z][a-z0-9-]{0,20}", 1..4),
            label in "[ -~]{1,40}",
            kek: Vec<u8>,
            key: Vec<u8>,
        ) {
            let keys = objects
                .iter()
                .map(|o| Entry { commitment_label: Some(label.clone()), wrapped: Some(encode(&key)), ..aes(o, "rsa-oaep-sha1+aes-kwp") })
                .collect();
            let b = Bundle { kek: Some(encode(&kek)), keys, ..sample() };
            let back = Bundle::parse(&b.to_toml(), std::path::Path::new("b.toml")).unwrap();
            proptest::prop_assert_eq!(back, b);
        }
    }
}
