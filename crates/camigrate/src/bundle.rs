//! The export bundle (MIGRATE.md D5, "Frozen names and formats"): one object's material, wrapped
//! to a target's transport key, with what the import checks before it touches the target — the
//! object's type, IDs and commitment label as the source's lock pins them, the public key of a
//! private key, the source, and the transport key's identity. Never plaintext: the wrapped blobs
//! are authenticated by RFC 5649 and the identity recomputed on the target, so a bundle may
//! cross untrusted channels.

use base64::Engine as _;
use cakeys_core::config::ObjectCfg;
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::{KmError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The `format` of a bundle.
pub const BUNDLE_FORMAT: &str = "cakeys-export";
/// The `version` this camigrate writes and reads.
pub const BUNDLE_VERSION: u32 = 1;

/// One exported object.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Bundle {
    pub format: String,
    pub version: u32,
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
    /// The object's type, as in the lock.
    #[serde(rename = "type")]
    pub object_type: ObjectCfg,
    /// The object's IDs, as in the source's lock: the import must reproduce them.
    pub ids: BTreeMap<String, String>,
    pub source: Source,
    pub transport: TransportRef,
    pub wrapped: Wrapped,
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

/// The wrapped blobs, base64.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Wrapped {
    /// The AES KEK under RSA-OAEP to the transport key (the composed methods only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kek: Option<String>,
    /// The key: under the KEK (RFC 5649), or under RSA-OAEP directly.
    pub key: String,
}

impl Bundle {
    /// Read a bundle, checking its form: the format and version, a sealed method this camigrate
    /// knows with the blobs it needs, base64 blobs, SRI IDs, and a public key whose hash is the
    /// `rfc7093m4` it claims. That the IDs are the lock's is the import's check.
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
        b.object_type.canonicalize();
        let method = b.method().map_err(invalid)?;
        let composed = matches!(method, Method::RsaOaepAesKwp(_));
        if !composed && !matches!(method, Method::RsaOaep(_)) {
            return Err(invalid(format!("method {} carries no wrapped material", b.method)));
        }
        if composed != b.wrapped.kek.is_some() {
            let kek = if composed { "needs a" } else { "takes no" };
            return Err(invalid(format!("method {} {kek} wrapped KEK", b.method)));
        }
        b.wrapped_key().map_err(invalid)?;
        b.wrapped_kek().map_err(invalid)?;
        let digests = b.ids.values().chain([&b.transport.rfc7093m4]);
        if let Some(v) = digests.into_iter().find(|v| !cakeys_core::id::is_sri(v)) {
            return Err(invalid(format!("\"{v}\" is not a sha256 SRI digest")));
        }
        if let Some(spki) = b.public_spki().map_err(invalid)? {
            let id = cakeys_core::id::sri(&spki);
            if b.ids.get("rfc7093m4") != Some(&id) {
                return Err(invalid(format!("publicKey is not the key rfc7093m4 names (its identity is {id})")));
            }
        }
        Ok(b)
    }

    /// The bundle's text.
    #[must_use]
    pub fn to_toml(&self) -> String {
        toml::to_string(self).unwrap_or_default()
    }

    /// The method the bundle names.
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
    /// A message for malformed base64.
    pub fn wrapped_key(&self) -> std::result::Result<Vec<u8>, String> {
        decode("wrapped.key", &self.wrapped.key)
    }

    /// The wrapped KEK's bytes, for a composed method.
    ///
    /// # Errors
    ///
    /// A message for malformed base64.
    pub fn wrapped_kek(&self) -> std::result::Result<Option<Vec<u8>>, String> {
        self.wrapped.kek.as_deref().map(|k| decode("wrapped.kek", k)).transpose()
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

    pub(crate) fn sample() -> Bundle {
        let mut ty = ObjectCfg::new(ObjectClass::SecretKey, Some(KeyType::Aes));
        ty.value_len = Some(32);
        Bundle {
            format: BUNDLE_FORMAT.into(),
            version: BUNDLE_VERSION,
            object: "backup-kek".into(),
            method: "rsa-oaep-sha1+aes-kwp".into(),
            exposure: Exposure::Sealed,
            commitment_label: Some("key-management/v1".into()),
            public_key: None,
            object_type: ty,
            ids: [("cmac".to_owned(), cakeys_core::id::sri(b"k"))].into(),
            source: Source { token: "softhsm".into(), provider: "softhsm".into() },
            transport: TransportRef { object: "import-kek".into(), rfc7093m4: cakeys_core::id::sri(b"t") },
            wrapped: Wrapped { kek: Some(encode(b"kek")), key: encode(b"key") },
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
        assert_eq!(
            keys,
            [
                "commitmentLabel",
                "exposure",
                "format",
                "ids",
                "method",
                "object",
                "source",
                "transport",
                "type",
                "version",
                "wrapped"
            ]
        );
        assert_eq!(table["wrapped"].as_table().unwrap().keys().collect::<Vec<_>>(), ["kek", "key"]);
    }

    /// The fuzz target's seed (fuzz/, nix/fuzz.nix) is a well-formed bundle.
    #[test]
    fn the_fuzz_seed_parses() {
        let text = include_str!("../tests/fixtures/sample.bundle.toml");
        Bundle::parse(text, std::path::Path::new("sample.bundle.toml")).unwrap();
    }

    /// What the form check refuses (17): another format, a method without its KEK or with one it
    /// does not take, a method that wraps nothing, bad base64, a public key `rfc7093m4` does not
    /// name.
    #[test]
    fn malformed_bundles_are_refused() {
        let path = std::path::Path::new("b.toml");
        let refused = |b: Bundle, what: &str| {
            let e = Bundle::parse(&b.to_toml(), path).unwrap_err();
            assert!(e.exit_code() == 17 && e.to_string().contains(what), "{what}: {e}");
        };
        refused(Bundle { format: "cakeys-transport".into(), ..sample() }, "not a cakeys-export");
        refused(Bundle { wrapped: Wrapped { kek: None, key: encode(b"k") }, ..sample() }, "needs a wrapped KEK");
        refused(Bundle { method: "rsa-oaep-sha1".into(), ..sample() }, "takes no wrapped KEK");
        refused(Bundle { method: "public".into(), ..sample() }, "carries no wrapped material");
        refused(Bundle { method: "rsa-aes".into(), ..sample() }, "unknown method");
        refused(Bundle { wrapped: Wrapped { kek: Some("!".into()), key: encode(b"k") }, ..sample() }, "wrapped.kek");
        let n = [0xc5u8; 256];
        let spki = cakeys_core::id::rsa_spki(&n, &[1, 0, 1]).unwrap();
        refused(Bundle { public_key: Some(encode(&spki)), ..sample() }, "is not the key rfc7093m4 names");
    }

    proptest::proptest! {
        /// Any text is read or refused as invalid (17), never a panic.
        #[test]
        fn any_text_parses_or_is_invalid(text in "\\PC*") {
            if let Err(e) = Bundle::parse(&text, std::path::Path::new("b.toml")) {
                proptest::prop_assert_eq!(e.exit_code(), 17);
            }
        }

        /// A bundle with any object name, label and blobs round-trips.
        #[test]
        fn bundles_round_trip(object in "[a-z][a-z0-9-]{0,20}", label in "[ -~]{1,40}", kek: Vec<u8>, key: Vec<u8>) {
            let b = Bundle {
                object,
                commitment_label: Some(label),
                wrapped: Wrapped { kek: Some(encode(&kek)), key: encode(&key) },
                ..sample()
            };
            let back = Bundle::parse(&b.to_toml(), std::path::Path::new("b.toml")).unwrap();
            proptest::prop_assert_eq!(back, b);
        }
    }
}
