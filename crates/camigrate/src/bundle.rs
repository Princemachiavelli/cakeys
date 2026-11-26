//! The export bundle (docs/CAMIGRATE.md D5, "Frozen names and formats"). A bundle holds the
//! objects that one export moves from a source to a target: keys wrapped to the target's transport
//! key, and public objects as their bytes. It also holds what the import checks before it touches
//! the target. For each key, that is its type, its IDs and its commitment label as the source's
//! lock pins them, and the public key of a private key. For the whole bundle, it is the source and
//! the identity of the transport key. There is one file for each (source, target) export, and the
//! keys of the composed method share one key-encryption key.
//!
//! A bundle never holds plaintext, but the wrap authenticates nothing. The transport key is
//! public, so anyone can seal a key of their own to it. RFC 5649's integrity check holds only
//! under a KEK, and anyone can make a KEK; OAEP has no integrity check. A bundle may cross
//! untrusted channels because the target checks it: the target recomputes each identity, proves
//! its binding, and refuses a key from a file that nothing proves (an EC key under
//! `token-asserted`, `sealed::check_carried`). A wrapped private key holds the PKCS#8 that
//! `C_WrapKey` emits. PKCS#12 or a CMS key package would need the plaintext key on the host to
//! build.

use base64::Engine as _;
use cakeys_core::config::{Config, ObjectCfg};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass;
use cakeys_core::{KmError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::trust::Claimed;

/// The `format` of a bundle.
pub(crate) const BUNDLE_FORMAT: &str = "cakeys-export";
/// The `version` that this camigrate writes. Version 2 names its `target`. camigrate still reads
/// version 1, which names no target, and checks such a bundle only against the importing token's
/// transport key (review 2026-11-24 D-1).
pub(crate) const BUNDLE_VERSION: u32 = 2;
/// The version that came before `target` was added.
const BUNDLE_VERSION_UNTARGETED: u32 = 1;

/// One export: the objects, and what they share.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Bundle {
    /// [`BUNDLE_FORMAT`], checked on read.
    pub(crate) format: String,
    /// [`BUNDLE_VERSION`], checked on read.
    pub(crate) version: u32,
    /// The AES key-encryption key, wrapped with RSA-OAEP to the transport key (base64). Every key
    /// of a composed method that has no KEK of its own shares it. It is absent when no key shares
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kek: Option<String>,
    /// The source token and its provider.
    pub(crate) source: Source,
    /// The token that the bundle was made for (version 2), as the export named it. An import on
    /// any other token is refused. Version 1 has no target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) target: Option<String>,
    /// The transport key to which the wrapped keys are sealed. It is absent exactly when the
    /// bundle carries only public objects, which need no transport key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) transport: Option<TransportRef>,
    /// One entry for each object. Each object appears once.
    pub(crate) keys: Vec<Entry>,
}

/// One exported object: a wrapped key, or a public object as it is.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Entry {
    /// The object's name, as in the source's keys.toml and lock.
    pub(crate) object: String,
    /// The method's frozen name (`rsa-oaep-sha1+aes-kwp`, ...).
    pub(crate) method: String,
    /// The exposure the method gave the key.
    pub(crate) exposure: Exposure,
    /// For a secret key: the label with which its commitments were computed, as in the lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) commitment_label: Option<String>,
    /// For a private key: the canonical SPKI DER (base64). The target creates the public key from
    /// it next to the key, and its hash must be the object's `rfc7093m4`. This field is an
    /// addition to D5's format, because a target module that keeps no public point with an
    /// unwrapped EC key (`SoftHSM`) could not compute the identity otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) public_key: Option<String>,
    /// A key's own key-encryption key, wrapped with RSA-OAEP (base64). It is the first part of the
    /// output of `CKM_RSA_AES_KEY_WRAP`, and it is used instead of the bundle's shared KEK. Every
    /// `enforced` composed key has one, and so does a `sealed` composed key from a source with no
    /// RFC 5649 key wrap of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kek: Option<String>,
    /// A wrapped key (base64): wrapped under its KEK (RFC 5649), or wrapped under RSA-OAEP
    /// directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) wrapped: Option<String>,
    /// A public object's bytes (base64, method `public`): a certificate's DER, a public key's
    /// canonical SPKI, or a data object's value. The import recomputes the object's identity from
    /// these bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) value: Option<String>,
    /// The object's type, as in the lock.
    #[serde(rename = "type")]
    pub(crate) object_type: ObjectCfg,
    /// The object's IDs, as in the source's lock. The import must reproduce them.
    pub(crate) ids: BTreeMap<String, String>,
}

/// Where the material came from. This is provenance, as the source realisation records it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    /// The source token's name in keys.toml.
    pub(crate) token: String,
    /// The provider that handled the source token.
    pub(crate) provider: String,
}

/// The transport key to which the material is wrapped: its object and its locked identity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportRef {
    /// The transport key's object name.
    pub(crate) object: String,
    /// Its locked identity: the SPKI's `rfc7093m4`.
    pub(crate) rfc7093m4: String,
}

impl Bundle {
    /// Returns whether the file content `bytes` is a bundle, that is, TOML whose `format` is
    /// [`BUNDLE_FORMAT`]. `import --in` reads any other file as a key file (review 2026-11-23
    /// C-6).
    #[must_use]
    pub(crate) fn is_bundle(bytes: &[u8]) -> bool {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| text.parse::<toml::Table>().ok())
            .is_some_and(|t| t.get("format").and_then(toml::Value::as_str) == Some(BUNDLE_FORMAT))
    }

    /// Reads a bundle and checks its form. The format and the version must be known: version 2
    /// names its target, and version 1 names none. The bundle must hold at least one key, and each
    /// object only once. Each method must be one that this camigrate knows and that travels in a
    /// bundle. The shared KEK must be present exactly when a composed method needs it, and all the
    /// keys under it must use one OAEP hash. A transport key must be present exactly when a key is
    /// wrapped. Each exposure must be one that its method can have. The blobs must be valid
    /// base64, and the IDs must be SRI digests. A commitment label may appear only on a secret
    /// key, and a public key only on a private key, where its hash must be the `rfc7093m4` that the
    /// entry claims. The import later checks that the IDs are the lock's, that the bundle's target
    /// is the importing token, and that its transport key is that target's (`trust::BoundBundle`).
    /// Until then, the content of the bundle is only claimed.
    ///
    /// # Errors
    ///
    /// `Validation` (17) for anything malformed or inconsistent.
    pub(crate) fn parse(text: &str, path: &std::path::Path) -> Result<Claimed<Bundle>> {
        Self::read(text, path).map(Claimed::new)
    }

    /// The form check of [`Self::parse`].
    fn read(text: &str, path: &std::path::Path) -> Result<Bundle> {
        let invalid = |msg: String| KmError::Validation(format!("{}: {msg}", path.display()).into());
        let mut b: Bundle = toml::from_str(text).map_err(|e| invalid(e.to_string()))?;
        if b.format != BUNDLE_FORMAT || !(BUNDLE_VERSION_UNTARGETED..=BUNDLE_VERSION).contains(&b.version) {
            return Err(invalid(format!("not a {BUNDLE_FORMAT} version {BUNDLE_VERSION} (or 1) file")));
        }
        match (b.version, &b.target) {
            (BUNDLE_VERSION_UNTARGETED, Some(_)) => return Err(invalid("a version 1 bundle names no target".into())),
            (BUNDLE_VERSION, None) => {
                return Err(invalid(format!("a version {BUNDLE_VERSION} bundle names its target")));
            }
            _ => {}
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
            // Each class has its own fields: a commitment label only on a secret key, which has
            // commitments, and a public key only on the private key whose half it is.
            let class = e.object_type.class;
            if e.commitment_label.is_some() && class != ObjectClass::SecretKey {
                return Err(invalid(format!("a {class} carries no commitmentLabel")));
            }
            if e.public_key.is_some() && class != ObjectClass::PrivateKey {
                return Err(invalid(format!("a {class} carries no publicKey")));
            }
            let method = e.method().map_err(invalid)?;
            if e.kek.is_some() && !matches!(method, Method::RsaOaepAesKwp(_)) {
                return Err(invalid(format!("method {} takes no kek of its own", e.method)));
            }
            e.wrapped_kek().map_err(invalid)?;
            match method {
                Method::RsaOaepAesKwp(h) if e.kek.is_none() => {
                    kek_hashes.insert(h);
                }
                Method::RsaOaepAesKwp(_) | Method::RsaOaep(_) | Method::Public => {}
                _ => return Err(invalid(format!("method {} does not travel in a bundle", e.method))),
            }
            // The entry's exposure must be one that its method can have, because an import
            // records the exposure. Whether a key is `sealed` or `enforced` is the source's claim,
            // because only the source knows what its token would have refused. The exception is an
            // enforced composed key: it was wrapped by `CKM_RSA_AES_KEY_WRAP`, so it must have its
            // own KEK. A sealed composed key may also have its own KEK, because a source with no
            // RFC 5649 key wrap of its own (AWS CloudHSM) wraps each key in that way.
            let exposure_fits = match (&method, e.exposure) {
                (Method::Public, Exposure::Public)
                | (Method::RsaOaep(_), Exposure::Sealed | Exposure::Enforced)
                | (Method::RsaOaepAesKwp(_), Exposure::Sealed) => true,
                (Method::RsaOaepAesKwp(_), Exposure::Enforced) => e.kek.is_some(),
                _ => false,
            };
            if !exposure_fits {
                return Err(invalid(format!("method {} does not move a key {}", e.method, e.exposure)));
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
                if e.ids.get(cakeys_core::id::Scheme::Rfc7093m4.name()) != Some(&id) {
                    return Err(invalid(format!("publicKey is not the key rfc7093m4 names (its identity is {id})")));
                }
            }
        }
        match (kek_hashes.len(), &b.kek) {
            (0, Some(_)) => return Err(invalid("a kek, but no key of a composed method shares it".into())),
            (0, None) | (1, Some(_)) => {}
            (1, None) => return Err(invalid("keys of a composed method, but no kek".into())),
            _ => return Err(invalid("composed methods of several OAEP hashes share one kek".into())),
        }
        b.wrapped_kek().map_err(invalid)?;
        let wraps = b.keys.iter().any(|e| e.wrapped.is_some());
        match &b.transport {
            Some(t) if !cakeys_core::id::is_sri(&t.rfc7093m4) => {
                return Err(invalid(format!("\"{}\" is not a sha256 SRI digest", t.rfc7093m4)));
            }
            None if wraps => return Err(invalid("wrapped keys, but no transport key they are wrapped to".into())),
            _ => {}
        }
        Ok(b)
    }

    /// Checks the bundle's source against keys.toml. An import records `source.token` as the
    /// origin of the key (`Origin::from`), so it must be a token that keys.toml names. It must
    /// never be a name that a bundle file invented, such as `file`, which would read as the import
    /// of a key file, or a token that does not exist.
    ///
    /// # Errors
    ///
    /// `Validation` (17) for a source token that `cfg` does not name.
    pub(crate) fn check_source(&self, cfg: &Config) -> Result<()> {
        if cfg.tokens.contains_key(&self.source.token) {
            return Ok(());
        }
        Err(KmError::Validation(
            format!(
                "the bundle names its source '{}' (provider {}), a token keys.toml does not have: the lock would \
                 record the key as from it",
                self.source.token, self.source.provider
            )
            .into(),
        ))
    }

    /// Returns the bundle's text.
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) when the bundle does not serialize, so that an empty file is never
    /// written in its place.
    pub(crate) fn to_toml(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| KmError::Unavailable(format!("serializing the bundle: {e}").into()))
    }

    /// Returns the bytes of the shared wrapped KEK, if there is one.
    ///
    /// # Errors
    ///
    /// A message for malformed base64.
    pub(crate) fn wrapped_kek(&self) -> std::result::Result<Option<Vec<u8>>, String> {
        self.kek.as_deref().map(|k| decode("kek", k)).transpose()
    }
}

impl Entry {
    /// Returns the method that the entry names.
    ///
    /// # Errors
    ///
    /// A message for a name that this camigrate does not know.
    pub(crate) fn method(&self) -> std::result::Result<Method, String> {
        Method::from_name(&self.method).ok_or_else(|| format!("unknown method '{}'", self.method))
    }

    /// Returns the wrapped key's bytes.
    ///
    /// # Errors
    ///
    /// A message for malformed base64, or for the entry of a public object.
    pub(crate) fn wrapped_key(&self) -> std::result::Result<Vec<u8>, String> {
        decode("wrapped", self.wrapped.as_deref().ok_or("no wrapped key")?)
    }

    /// Returns the key's own wrapped KEK, if it has one.
    ///
    /// # Errors
    ///
    /// A message for malformed base64.
    pub(crate) fn wrapped_kek(&self) -> std::result::Result<Option<Vec<u8>>, String> {
        self.kek.as_deref().map(|k| decode("kek", k)).transpose()
    }

    /// Returns a public object's bytes.
    ///
    /// # Errors
    ///
    /// A message for malformed base64, or for the entry of a key.
    pub(crate) fn public_value(&self) -> std::result::Result<Vec<u8>, String> {
        decode("value", self.value.as_deref().ok_or("no value")?)
    }

    /// Returns the private key's canonical SPKI DER, or `None` when the entry has no public key.
    ///
    /// # Errors
    ///
    /// A message for malformed base64, or for a public key that cakeys cannot canonicalize.
    pub(crate) fn public_spki(&self) -> std::result::Result<Option<Vec<u8>>, String> {
        let Some(k) = &self.public_key else { return Ok(None) };
        let der = decode("publicKey", k)?;
        cakeys_core::id::spki_canonical(&der).map(Some).map_err(|e| format!("publicKey: {e}"))
    }
}

/// Encodes `bytes` as standard base64.
#[must_use]
pub(crate) fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode(what: &str, text: &str) -> std::result::Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD.decode(text).map_err(|e| format!("{what}: {e}"))
}

#[cfg(test)]
pub(crate) mod tests {
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
            kek: None,
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
            target: Some("kryoptic".into()),
            transport: Some(TransportRef { object: "import-kek".into(), rfc7093m4: cakeys_core::id::sri(b"t") }),
            keys: vec![aes("backup-kek", "rsa-oaep-sha1+aes-kwp"), aes("db-kek", "rsa-oaep-sha1+aes-kwp")],
        }
    }

    /// Checks the frozen field names (docs/CAMIGRATE.md, "Frozen names and formats"), so that a
    /// bundle that was written once keeps the same meaning.
    #[test]
    fn the_format_is_pinned_and_round_trips() {
        let b = sample();
        let text = b.to_toml().unwrap();
        let path = std::path::Path::new("b.toml");
        assert_eq!(Bundle::read(&text, path).unwrap(), b);
        let table: toml::Table = toml::from_str(&text).unwrap();
        let keys: Vec<&str> = table.keys().map(String::as_str).collect();
        assert_eq!(keys, ["format", "kek", "keys", "source", "target", "transport", "version"]);
        assert_eq!(table["version"].as_integer(), Some(2));
        let entry = table["keys"].as_array().unwrap()[0].as_table().unwrap();
        assert_eq!(
            entry.keys().map(String::as_str).collect::<Vec<_>>(),
            ["commitmentLabel", "exposure", "ids", "method", "object", "type", "wrapped"]
        );
    }

    /// Checks that the fuzz target's seeds (fuzz/, nix/fuzz.nix) are well-formed bundles of this
    /// version and of version 1, which names no target and is still read.
    #[test]
    fn the_fuzz_seed_parses() {
        let path = std::path::Path::new("sample.bundle.toml");
        let b = Bundle::read(include_str!("../tests/fixtures/sample.bundle.toml"), path).unwrap();
        assert_eq!((b.version, b.target.as_deref()), (2, Some("kryoptic")));
        let old = Bundle::read(include_str!("../tests/fixtures/sample-v1.bundle.toml"), path).unwrap();
        assert_eq!((old.version, old.target), (1, None));
        assert_eq!(
            Bundle { version: 2, target: b.target.clone(), ..old },
            b,
            "the versions differ in the target alone"
        );
    }

    /// Checks what the form check refuses (17): another format; no keys, or one object twice; a
    /// composed method without the KEK, or a KEK that no key uses; composed methods of two hashes
    /// under one KEK; a method that cannot travel in a bundle; a key without its wrapped bytes, or
    /// a public object without its value; wrapped keys without a transport key; an exposure that
    /// the method cannot have; bad base64; a public key that `rfc7093m4` does not name; and a field
    /// of another class.
    #[test]
    fn malformed_bundles_are_refused() {
        let path = std::path::Path::new("b.toml");
        let refused = |b: Bundle, what: &str| {
            let e = Bundle::read(&b.to_toml().unwrap(), path).unwrap_err();
            assert!(e.exit_code() == 17 && e.to_string().contains(what), "{what}: {e}");
        };
        let direct = || vec![aes("backup-kek", "rsa-oaep-sha1")];
        refused(Bundle { format: "cakeys-transport".into(), ..sample() }, "not a cakeys-export");
        // Version 2 names its target, and version 1 names none. No other version reads.
        refused(Bundle { target: None, ..sample() }, "a version 2 bundle names its target");
        refused(Bundle { version: 1, ..sample() }, "a version 1 bundle names no target");
        Bundle::read(&Bundle { version: 1, target: None, ..sample() }.to_toml().unwrap(), path).unwrap();
        for version in [0, 3] {
            refused(Bundle { version, ..sample() }, "not a cakeys-export version 2 (or 1) file");
        }
        refused(Bundle { keys: vec![], ..sample() }, "carries no keys");
        refused(Bundle { keys: vec![aes("k", "rsa-oaep-sha1+aes-kwp"); 2], ..sample() }, "listed twice");
        refused(Bundle { kek: None, ..sample() }, "but no kek");
        refused(Bundle { keys: direct(), ..sample() }, "no key of a composed method shares it");
        // An enforced key carries its own KEK, so it needs no shared KEK. Only a composed key may
        // have its own KEK.
        let own =
            Entry { kek: Some(encode(b"own")), exposure: Exposure::Enforced, ..aes("e", "rsa-oaep-sha1+aes-kwp") };
        Bundle::read(&Bundle { kek: None, keys: vec![own.clone()], ..sample() }.to_toml().unwrap(), path).unwrap();
        refused(
            Bundle { kek: None, keys: vec![Entry { method: "rsa-oaep-sha1".into(), ..own }], ..sample() },
            "takes no kek of its own",
        );
        Bundle::read(&Bundle { kek: None, keys: direct(), ..sample() }.to_toml().unwrap(), path).unwrap();
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
        Bundle::read(
            &Bundle { keys: vec![aes("k", "rsa-oaep-sha1+aes-kwp"), cert.clone()], ..sample() }.to_toml().unwrap(),
            path,
        )
        .unwrap();
        refused(Bundle { keys: vec![Entry { value: None, ..cert.clone() }], kek: None, ..sample() }, "needs a value");
        refused(
            Bundle { keys: vec![Entry { wrapped: Some(encode(b"k")), ..cert.clone() }], kek: None, ..sample() },
            "needs a value",
        );
        refused(
            Bundle { keys: vec![Entry { wrapped: None, ..aes("k", "rsa-oaep-sha1+aes-kwp") }], ..sample() },
            "needs a wrapped key",
        );
        refused(Bundle { keys: vec![aes("k", "rsa-aes")], ..sample() }, "unknown method");
        // A transport key is present exactly when a key is wrapped, so a bundle of public objects
        // alone names none.
        Bundle::read(
            &Bundle { keys: vec![cert.clone()], kek: None, transport: None, ..sample() }.to_toml().unwrap(),
            path,
        )
        .unwrap();
        refused(Bundle { transport: None, ..sample() }, "no transport key");
        // An exposure that its method cannot have is refused, because an import would record it.
        let claims = |e: Entry, exposure| Bundle { keys: vec![Entry { exposure, ..e }], ..sample() };
        refused(claims(aes("k", "rsa-oaep-sha1+aes-kwp"), Exposure::Enforced), "does not move a key enforced");
        refused(claims(aes("k", "rsa-oaep-sha1+aes-kwp"), Exposure::Host), "does not move a key host");
        refused(claims(aes("k", "rsa-oaep-sha1+aes-kwp"), Exposure::Public), "does not move a key public");
        refused(Bundle { kek: None, ..claims(cert.clone(), Exposure::Sealed) }, "does not move a key sealed");
        refused(Bundle { kek: Some("!".into()), ..sample() }, "kek");
        // A sealed composed key with its own KEK (a source without RFC 5649) parses.
        let own = Entry { kek: Some(encode(b"own kek")), ..aes("k", "rsa-oaep-sha1+aes-kwp") };
        Bundle::read(&Bundle { keys: vec![own], kek: None, ..sample() }.to_toml().unwrap(), path).unwrap();
        let n = [0xc5u8; 256];
        let spki = cakeys_core::id::rsa_spki(&n, &[1, 0, 1]).unwrap();
        let private = Entry {
            object_type: ObjectCfg::new(ObjectClass::PrivateKey, Some(KeyType::Rsa)),
            commitment_label: None,
            ..aes("k", "rsa-oaep-sha1+aes-kwp")
        };
        let spoofed = Entry { public_key: Some(encode(&spki)), ..private.clone() };
        refused(Bundle { keys: vec![spoofed], ..sample() }, "is not the key rfc7093m4 names");
        // Each class has its own fields: a public key only on a private key, and a commitment
        // label only on a secret key.
        let half = Entry { public_key: Some(encode(&spki)), ..aes("k", "rsa-oaep-sha1+aes-kwp") };
        refused(Bundle { keys: vec![half], ..sample() }, "a CKO_SECRET_KEY carries no publicKey");
        let labelled = Entry { commitment_label: Some("key-management/v1".into()), ..private };
        refused(Bundle { keys: vec![labelled], ..sample() }, "a CKO_PRIVATE_KEY carries no commitmentLabel");
    }

    /// Checks that a bundle's source must be a token that keys.toml names, because the lock
    /// records it as the origin of the keys. Any other source is refused (17), and the error names
    /// it.
    #[test]
    fn the_source_must_be_a_token_keys_toml_names() {
        let cfg = cakeys_core::config::parse_config_with(
            "[tokens.softhsm]\ntokenLabel = \"s\"\n",
            std::path::Path::new("keys.toml"),
            &|_| None,
        )
        .unwrap();
        sample().check_source(&cfg).unwrap();
        for token in ["file", "elsewhere"] {
            let b = Bundle { source: Source { token: token.into(), provider: "softhsm".into() }, ..sample() };
            let e = b.check_source(&cfg).unwrap_err();
            assert!(e.exit_code() == 17 && e.to_string().contains(&format!("'{token}'")), "{e}");
        }
    }

    /// Checks that the accessors return the bytes that the bundle carries, and that a transport
    /// key's identity must be an SRI digest.
    #[test]
    fn entries_hand_back_their_bytes() {
        let key = Entry { kek: Some(encode(b"own kek")), ..aes("k", "rsa-oaep-sha1+aes-kwp") };
        assert_eq!(key.wrapped_key().unwrap(), b"key");
        assert_eq!(key.wrapped_kek().unwrap().as_deref(), Some(&b"own kek"[..]));
        assert_eq!(aes("k", "rsa-oaep-sha1").wrapped_kek().unwrap(), None);
        assert!(key.public_value().is_err());
        let cert = Entry { wrapped: None, value: Some(encode(b"der")), ..aes("c", "public") };
        assert_eq!(cert.public_value().unwrap(), b"der");
        assert!(cert.wrapped_key().is_err());
        assert_eq!(sample().wrapped_kek().unwrap().as_deref(), Some(&b"kek"[..]));
        let unpinned = TransportRef { object: "import-kek".into(), rfc7093m4: "sha256-short".into() };
        let e = Bundle::read(
            &Bundle { transport: Some(unpinned), ..sample() }.to_toml().unwrap(),
            std::path::Path::new("b"),
        );
        assert!(e.unwrap_err().to_string().contains("is not a sha256 SRI digest"));
    }

    proptest::proptest! {
        /// Any text is read or refused as invalid (17), and it never causes a panic.
        #[test]
        fn any_text_parses_or_is_invalid(text in "\\PC*") {
            if let Err(e) = Bundle::read(&text, std::path::Path::new("b.toml")) {
                proptest::prop_assert_eq!(e.exit_code(), 17);
            }
        }

        /// A bundle with any object names, label and blobs reads back as the same bundle after it
        /// is written.
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
            let back = Bundle::read(&b.to_toml().unwrap(), std::path::Path::new("b.toml")).unwrap();
            proptest::prop_assert_eq!(back, b);
        }
    }
}
