//! The transport file (docs/CAMIGRATE.md D3): a target's transport key, as a source needs it to wrap to
//! that target without reaching it.

use cakeys_core::{KmError, Result};
use serde::{Deserialize, Serialize};

/// The transport file (`camigrate transport`, docs/CAMIGRATE.md D3): what a source needs to wrap to a
/// target's transport key without reaching the target: the public key, its locked identity,
/// and the target's provider and mechanisms for planning.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Transport {
    pub format: String,
    pub version: u32,
    pub token: String,
    pub provider: String,
    pub object: String,
    pub rfc7093m4: String,
    /// Base64 of the canonical SPKI DER.
    pub spki: String,
    pub mechanisms: Vec<String>,
}

pub(crate) const TRANSPORT_FORMAT: &str = "cakeys-transport";
pub(crate) const TRANSPORT_VERSION: u32 = 1;

impl Transport {
    /// The transport file for `object`'s public key on `token`.
    ///
    /// # Errors
    ///
    /// `Validation` when `spki` is not a public key cakeys can canonicalize.
    pub(crate) fn new(
        token: &str,
        provider: &str,
        object: &str,
        spki: &[u8],
        mechanisms: &[String],
    ) -> Result<Transport> {
        use base64::Engine;
        let spki = cakeys_core::id::spki_canonical(spki)?;
        crate::sealed::check_transport_size(&spki)?;
        Ok(Transport {
            format: TRANSPORT_FORMAT.into(),
            version: TRANSPORT_VERSION,
            token: token.into(),
            provider: provider.into(),
            object: object.into(),
            rfc7093m4: cakeys_core::id::sri(&spki),
            spki: base64::engine::general_purpose::STANDARD.encode(&spki),
            mechanisms: mechanisms.to_vec(),
        })
    }

    /// Read a transport file, checking that its identity is the hash of its public key: a file
    /// edited to wrap to another key fails here, and against the lock (`tokens::pinned`).
    ///
    /// # Errors
    ///
    /// `Validation` for another format or version, malformed base64, a key smaller than a
    /// transport key may be, or an identity that is not the public key's.
    pub(crate) fn parse(text: &str, path: &std::path::Path) -> Result<Transport> {
        let t: Transport =
            toml::from_str(text).map_err(|e| KmError::Validation(format!("{}: {e}", path.display()).into()))?;
        if t.format != TRANSPORT_FORMAT || t.version != TRANSPORT_VERSION {
            return Err(KmError::Validation(
                format!("{}: not a {TRANSPORT_FORMAT} version {TRANSPORT_VERSION} file", path.display()).into(),
            ));
        }
        let spki = t.spki()?;
        // Refused on read, as `new` and `key` refuse it: a dry run says so too, not only the export.
        crate::sealed::check_transport_size(&spki)
            .map_err(|e| KmError::Validation(format!("{}: {}", path.display(), msg_of(e)).into()))?;
        let computed = cakeys_core::id::sri(&spki);
        if computed != t.rfc7093m4 {
            return Err(KmError::Validation(
                format!(
                    "{}: rfc7093m4 {} is not the identity of its public key ({computed})",
                    path.display(),
                    t.rfc7093m4
                )
                .into(),
            ));
        }
        Ok(t)
    }

    /// The file's text.
    ///
    /// # Errors
    ///
    /// `Unavailable` when it does not serialize: never an empty file in its place.
    pub(crate) fn to_toml(&self) -> Result<String> {
        toml::to_string(self).map_err(|e| KmError::Unavailable(format!("serializing the transport file: {e}").into()))
    }

    /// The canonical SPKI DER.
    ///
    /// # Errors
    ///
    /// `Validation` for malformed base64 or a public key cakeys cannot canonicalize.
    pub(crate) fn spki(&self) -> Result<Vec<u8>> {
        use base64::Engine;
        let der = base64::engine::general_purpose::STANDARD
            .decode(&self.spki)
            .map_err(|e| KmError::Validation(format!("transport key: {e}").into()))?;
        cakeys_core::id::spki_canonical(&der)
    }

    /// The key to seal to, as an export takes it.
    ///
    /// # Errors
    ///
    /// As [`Self::spki`].
    pub(crate) fn key(&self) -> Result<crate::sealed::TransportKey> {
        let spki = self.spki()?;
        crate::sealed::check_transport_size(&spki)?;
        Ok(crate::sealed::TransportKey { object: self.object.clone(), rfc7093m4: self.rfc7093m4.clone(), spki })
    }
}

/// The text of an error's message, without its class.
fn msg_of(e: KmError) -> String {
    e.into_msg().map_or_else(String::new, cakeys_core::Msg::into_text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    /// A transport file round-trips, and one edited to name another key's identity is refused.
    #[test]
    fn transport_files_check_their_identity() {
        // Any RSA public key will do: an all-0xc5 2048-bit modulus.
        let n = [0xc5u8; 256];
        let spki = cakeys_core::id::rsa_spki(&n, &[1, 0, 1]).unwrap();
        let t = Transport::new("kryoptic", "kryoptic", "import-kek", &spki, &["CKM_RSA_PKCS_OAEP".into()]).unwrap();
        let text = t.to_toml().unwrap();
        let path = std::path::Path::new("t.toml");
        assert_eq!(Transport::parse(&text, path).unwrap(), t);
        let other = text.replace(&t.rfc7093m4, &cakeys_core::id::sri(b"another key"));
        assert!(Transport::parse(&other, path).unwrap_err().to_string().contains("is not the identity"));
        let old = text.replace("version = 1", "version = 2");
        assert_eq!(Transport::parse(&old, path).unwrap_err().exit_code(), 17);
        // A transport key is at least 2048 bits: a smaller one makes no transport file.
        let small = cakeys_core::id::rsa_spki(&[0xc5u8; 128], &[1, 0, 1]).unwrap();
        let e = Transport::new("kryoptic", "kryoptic", "import-kek", &small, &[]).unwrap_err();
        assert!(e.to_string().contains("at least 2048 bits; this one has 1024"), "{e}");
        // Nor does a file edited to hold one read, its identity made to match (review
        // transport.rs F1): the dry run refuses it as the export would.
        let edited = Transport {
            spki: base64::engine::general_purpose::STANDARD.encode(&small),
            rfc7093m4: cakeys_core::id::sri(&cakeys_core::id::spki_canonical(&small).unwrap()),
            ..t
        };
        let e = Transport::parse(&edited.to_toml().unwrap(), path).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("this one has 1024"), "{e}");
    }
}
