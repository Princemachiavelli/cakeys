//! The export bundle (docs/CAMIGRATE.md D5, "Frozen names and formats"): the objects one export moves
//! from a source to a target — keys wrapped to the target's transport key, public objects as
//! their bytes — with what the import checks
//! before it touches the target — per key its type, IDs and commitment label as the source's
//! lock pins them and the public key of a private key; for all, the source and the transport
//! key's identity. One file per (source, target) export; the composed method's key-encryption
//! key is shared by its keys. Never plaintext, but the wrap authenticates nothing: the
//! transport key is public, so anyone can seal a key of their own to it, and RFC 5649's
//! integrity check holds only under a KEK anyone can make (OAEP has none). What a bundle may
//! cross untrusted channels on is the target: it recomputes each identity and proves its
//! binding, and refuses a key nothing proves (an EC key under `token-asserted`) from a file
//! (`sealed::check_carried`). Inside a wrapped private key is the PKCS#8 `C_WrapKey` emits;
//! PKCS#12 or a CMS key package would need the plaintext key on the host to build.

use base64::Engine as _;
use cakeys_core::config::{Config, ObjectCfg};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass;
use cakeys_core::{KmError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The `format` of a bundle.
pub(crate) const BUNDLE_FORMAT: &str = "cakeys-export";
/// The `version` this camigrate writes and reads.
pub(crate) const BUNDLE_VERSION: u32 = 1;

/// One export: the keys, and what they share.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Bundle {
    /// [`BUNDLE_FORMAT`], checked on read.
    pub(crate) format: String,
    /// [`BUNDLE_VERSION`], checked on read.
    pub(crate) version: u32,
    /// The AES key-encryption key under RSA-OAEP to the transport key (base64), shared by every
    /// key of a composed method; absent when none is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kek: Option<String>,
    /// The source token and its provider.
    pub(crate) source: Source,
    /// The transport key the wrapped keys are sealed to; absent exactly when the bundle carries
    /// public objects only, which need none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) transport: Option<TransportRef>,
    /// One entry per object, each object once.
    pub(crate) keys: Vec<Entry>,
}

/// One exported object: a key, wrapped, or a public object, as it is.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Entry {
    /// The object's name, as in the source's keys.toml and lock.
    pub(crate) object: String,
    /// The method's frozen name (`rsa-oaep-sha1+aes-kwp`, ...).
    pub(crate) method: String,
    /// The exposure the method gave the key.
    pub(crate) exposure: Exposure,
    /// Secret keys: the label their commitments were computed with, as in the lock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) commitment_label: Option<String>,
    /// Private keys: the canonical SPKI DER (base64), which the target creates beside the key and
    /// whose hash must be the object's `rfc7093m4`. An addition to D5's format: a target module
    /// that keeps no public point with an unwrapped EC key (`SoftHSM`) could not compute the
    /// identity otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) public_key: Option<String>,
    /// A key's own key-encryption key under RSA-OAEP (base64): the first part of
    /// `CKM_RSA_AES_KEY_WRAP`'s output, used instead of the bundle's shared one. Every `enforced`
    /// composed key has one, and a `sealed` one from a source with no RFC 5649 of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) kek: Option<String>,
    /// A key (base64): under its KEK (RFC 5649), or under RSA-OAEP directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) wrapped: Option<String>,
    /// A public object (base64, method `public`): a certificate's DER, a public key's canonical
    /// SPKI, a data object's value. The import recomputes its identity from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) value: Option<String>,
    /// The object's type, as in the lock.
    #[serde(rename = "type")]
    pub(crate) object_type: ObjectCfg,
    /// The object's IDs, as in the source's lock: the import must reproduce them.
    pub(crate) ids: BTreeMap<String, String>,
}

/// Where the material came from: provenance, as the source realisation records it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Source {
    /// The source token's name in keys.toml.
    pub(crate) token: String,
    /// The provider that handled it.
    pub(crate) provider: String,
}

/// The transport key the material is wrapped to: its object and locked identity.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportRef {
    /// The transport key's object name.
    pub(crate) object: String,
    /// Its locked identity: the SPKI's `rfc7093m4`.
    pub(crate) rfc7093m4: String,
}

impl Bundle {
    /// Whether the file `bytes` is a bundle (TOML whose `format` is [`BUNDLE_FORMAT`]), told by
    /// what it holds: anything else `import --in` reads as a key file (review 2026-11-23 C-6).
    #[must_use]
    pub(crate) fn is_bundle(bytes: &[u8]) -> bool {
        std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| text.parse::<toml::Table>().ok())
            .is_some_and(|t| t.get("format").and_then(toml::Value::as_str) == Some(BUNDLE_FORMAT))
    }

    /// Read a bundle, checking its form: the format and version, at least one key and each object
    /// once, sealed methods this camigrate knows with the KEK exactly when a composed one needs it
    /// (one OAEP hash for it), a transport key exactly when a key is wrapped, each exposure one
    /// its method can have, base64 blobs, SRI IDs, a commitment label only on a secret key, and
    /// a public key only on a private key, whose hash is the `rfc7093m4` it claims. That the IDs
    /// are the lock's is the import's check.
    ///
    /// # Errors
    ///
    /// `Validation` (17) for anything malformed or inconsistent.
    pub(crate) fn parse(text: &str, path: &std::path::Path) -> Result<Bundle> {
        let invalid = |msg: String| KmError::Validation(format!("{}: {msg}", path.display()).into());
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
            // Each class's own fields: a commitment label only where commitments are (secret
            // keys), a public key only beside the private key it is the half of.
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
            // What the entry says of its exposure must be what its method can be: an import
            // records it. `sealed` against `enforced` is the source's word (only the source
            // knows what its token would have refused), except that an enforced composed key
            // came out by CKM_RSA_AES_KEY_WRAP, so with its own KEK. A sealed one may too: a
            // source with no RFC 5649 of its own (AWS CloudHSM) wraps each key that way.
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

    /// The bundle's source against keys.toml: an import records `source.token` as where the key
    /// came from (`Origin::from`), so it must be a token keys.toml names, never a name a bundle
    /// file made up (`file`, which reads as a key file's import, or a token that does not exist).
    ///
    /// # Errors
    ///
    /// `Validation` (17) for a source token `cfg` does not name.
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

    /// The bundle's text.
    ///
    /// # Errors
    ///
    /// `Unavailable` when it does not serialize: never an empty file in its place.
    pub(crate) fn to_toml(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| KmError::Unavailable(format!("serializing the bundle: {e}").into()))
    }

    /// The wrapped KEK's bytes.
    ///
    /// # Errors
    ///
    /// A message for malformed base64.
    pub(crate) fn wrapped_kek(&self) -> std::result::Result<Option<Vec<u8>>, String> {
        self.kek.as_deref().map(|k| decode("kek", k)).transpose()
    }
}

impl Entry {
    /// The method the entry names.
    ///
    /// # Errors
    ///
    /// A message for a name this camigrate does not know.
    pub(crate) fn method(&self) -> std::result::Result<Method, String> {
        Method::from_name(&self.method).ok_or_else(|| format!("unknown method '{}'", self.method))
    }

    /// The wrapped key's bytes.
    ///
    /// # Errors
    ///
    /// A message for malformed base64, or a public object's entry.
    pub(crate) fn wrapped_key(&self) -> std::result::Result<Vec<u8>, String> {
        decode("wrapped", self.wrapped.as_deref().ok_or("no wrapped key")?)
    }

    /// An `enforced` key's own wrapped KEK.
    ///
    /// # Errors
    ///
    /// A message for malformed base64.
    pub(crate) fn wrapped_kek(&self) -> std::result::Result<Option<Vec<u8>>, String> {
        self.kek.as_deref().map(|k| decode("kek", k)).transpose()
    }

    /// A public object's bytes.
    ///
    /// # Errors
    ///
    /// A message for malformed base64, or a key's entry.
    pub(crate) fn public_value(&self) -> std::result::Result<Vec<u8>, String> {
        decode("value", self.value.as_deref().ok_or("no value")?)
    }

    /// The private key's canonical SPKI DER.
    ///
    /// # Errors
    ///
    /// A message for malformed base64, or a public key cakeys cannot canonicalize.
    pub(crate) fn public_spki(&self) -> std::result::Result<Option<Vec<u8>>, String> {
        let Some(k) = &self.public_key else { return Ok(None) };
        let der = decode("publicKey", k)?;
        cakeys_core::id::spki_canonical(&der).map(Some).map_err(|e| format!("publicKey: {e}"))
    }
}

/// Standard base64.
#[must_use]
pub(crate) fn encode(bytes: &[u8]) -> String {
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
            transport: Some(TransportRef { object: "import-kek".into(), rfc7093m4: cakeys_core::id::sri(b"t") }),
            keys: vec![aes("backup-kek", "rsa-oaep-sha1+aes-kwp"), aes("db-kek", "rsa-oaep-sha1+aes-kwp")],
        }
    }

    /// The frozen field names (docs/CAMIGRATE.md, "Frozen names and formats"): a bundle written once
    /// must keep meaning the same.
    #[test]
    fn the_format_is_pinned_and_round_trips() {
        let b = sample();
        let text = b.to_toml().unwrap();
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
    /// without its value, wrapped keys without a transport key, an exposure the method cannot
    /// have, bad base64, a public key `rfc7093m4` does not name, a field of another class.
    #[test]
    fn malformed_bundles_are_refused() {
        let path = std::path::Path::new("b.toml");
        let refused = |b: Bundle, what: &str| {
            let e = Bundle::parse(&b.to_toml().unwrap(), path).unwrap_err();
            assert!(e.exit_code() == 17 && e.to_string().contains(what), "{what}: {e}");
        };
        let direct = || vec![aes("backup-kek", "rsa-oaep-sha1")];
        refused(Bundle { format: "cakeys-transport".into(), ..sample() }, "not a cakeys-export");
        refused(Bundle { keys: vec![], ..sample() }, "carries no keys");
        refused(Bundle { keys: vec![aes("k", "rsa-oaep-sha1+aes-kwp"); 2], ..sample() }, "listed twice");
        refused(Bundle { kek: None, ..sample() }, "but no kek");
        refused(Bundle { keys: direct(), ..sample() }, "no key of a composed method shares it");
        // An enforced key carries its own KEK: no shared one needed, and only a composed key has one.
        let own =
            Entry { kek: Some(encode(b"own")), exposure: Exposure::Enforced, ..aes("e", "rsa-oaep-sha1+aes-kwp") };
        Bundle::parse(&Bundle { kek: None, keys: vec![own.clone()], ..sample() }.to_toml().unwrap(), path).unwrap();
        refused(
            Bundle { kek: None, keys: vec![Entry { method: "rsa-oaep-sha1".into(), ..own }], ..sample() },
            "takes no kek of its own",
        );
        Bundle::parse(&Bundle { kek: None, keys: direct(), ..sample() }.to_toml().unwrap(), path).unwrap();
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
        // A transport key exactly when a key is wrapped: public objects alone name none.
        Bundle::parse(
            &Bundle { keys: vec![cert.clone()], kek: None, transport: None, ..sample() }.to_toml().unwrap(),
            path,
        )
        .unwrap();
        refused(Bundle { transport: None, ..sample() }, "no transport key");
        // An exposure its method cannot have: an import would record it.
        let claims = |e: Entry, exposure| Bundle { keys: vec![Entry { exposure, ..e }], ..sample() };
        refused(claims(aes("k", "rsa-oaep-sha1+aes-kwp"), Exposure::Enforced), "does not move a key enforced");
        refused(claims(aes("k", "rsa-oaep-sha1+aes-kwp"), Exposure::Host), "does not move a key host");
        refused(claims(aes("k", "rsa-oaep-sha1+aes-kwp"), Exposure::Public), "does not move a key public");
        refused(Bundle { kek: None, ..claims(cert.clone(), Exposure::Sealed) }, "does not move a key sealed");
        refused(Bundle { kek: Some("!".into()), ..sample() }, "kek");
        // A sealed composed key with its own KEK (a source without RFC 5649) parses.
        let own = Entry { kek: Some(encode(b"own kek")), ..aes("k", "rsa-oaep-sha1+aes-kwp") };
        Bundle::parse(&Bundle { keys: vec![own], kek: None, ..sample() }.to_toml().unwrap(), path).unwrap();
        let n = [0xc5u8; 256];
        let spki = cakeys_core::id::rsa_spki(&n, &[1, 0, 1]).unwrap();
        let private = Entry {
            object_type: ObjectCfg::new(ObjectClass::PrivateKey, Some(KeyType::Rsa)),
            commitment_label: None,
            ..aes("k", "rsa-oaep-sha1+aes-kwp")
        };
        let spoofed = Entry { public_key: Some(encode(&spki)), ..private.clone() };
        refused(Bundle { keys: vec![spoofed], ..sample() }, "is not the key rfc7093m4 names");
        // Each class's own fields: a public key only beside a private key, a commitment label
        // only on a secret key.
        let half = Entry { public_key: Some(encode(&spki)), ..aes("k", "rsa-oaep-sha1+aes-kwp") };
        refused(Bundle { keys: vec![half], ..sample() }, "a CKO_SECRET_KEY carries no publicKey");
        let labelled = Entry { commitment_label: Some("key-management/v1".into()), ..private };
        refused(Bundle { keys: vec![labelled], ..sample() }, "a CKO_PRIVATE_KEY carries no commitmentLabel");
    }

    /// A bundle's source goes into the lock as where its keys came from: it must be a token
    /// keys.toml names (17 otherwise, saying which).
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

    /// The accessors hand back the bytes the bundle carries, and a transport key's identity
    /// must be an SRI digest.
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
        let e = Bundle::parse(
            &Bundle { transport: Some(unpinned), ..sample() }.to_toml().unwrap(),
            std::path::Path::new("b"),
        );
        assert!(e.unwrap_err().to_string().contains("is not a sha256 SRI digest"));
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
            let back = Bundle::parse(&b.to_toml().unwrap(), std::path::Path::new("b.toml")).unwrap();
            proptest::prop_assert_eq!(back, b);
        }
    }
}
