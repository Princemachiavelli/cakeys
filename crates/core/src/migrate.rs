//! The vocabulary for moving keys (docs/CAMIGRATE.md): the method names and exposure levels that
//! a lock's `provenance.origin` records. These names are frozen, and the tests below pin them. A
//! token's capabilities for moving keys and the planner that chooses between them belong to
//! camigrate (README.md, "Three tools"), so a `cakeys` build contains none of that code (review
//! 2026-11-23 A-6).

use serde::{Deserialize, Serialize};

/// The RSA-OAEP hash, with MGF1 of the same hash, as a transport wrap and an OAEP proof use it. It
/// is defined here, next to the frozen method names that contain it (`rsa-oaep-sha256`), and not
/// in the proof module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OaepHash {
    /// SHA-1, with MGF1-SHA-1.
    Sha1,
    /// SHA-256, with MGF1-SHA-256.
    Sha256,
}

/// How much of the material is exposed during a move (docs/CAMIGRATE.md D2), with the strongest
/// protection first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    /// Nothing secret moves.
    Public,
    /// Sealed, and the source token accepts no other wrapping key (`CKA_WRAP_WITH_TRUSTED`).
    Enforced,
    /// The material leaves the source only when it is wrapped under a key on the target.
    Sealed,
    /// The material is in plaintext in the memory of cakeys and is zeroized afterwards. It is
    /// never written to disk.
    Host,
    /// A passphrase-protected file.
    File,
}

impl Exposure {
    /// Returns the name that a bundle and the lock write.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Exposure::Public => "public",
            Exposure::Enforced => "enforced",
            Exposure::Sealed => "sealed",
            Exposure::Host => "host",
            Exposure::File => "file",
        }
    }
}

impl std::fmt::Display for Exposure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// How an object moves. The names are frozen like scheme names (docs/CAMIGRATE.md, "Frozen names
/// and formats"), because a bundle or a lock's `provenance.origin` that was written with a name
/// must keep its meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    /// Only public material moves, and nothing secret.
    Public,
    /// A new AES KEK is wrapped with RSA-OAEP to the transport key, and the key is wrapped under
    /// the KEK (RFC 5649).
    RsaOaepAesKwp(OaepHash),
    /// The key is wrapped with RSA-OAEP directly to the transport key (for small secret keys).
    RsaOaep(OaepHash),
    /// Through the host, into a PKCS#11 target with `C_CreateObject`.
    HostPkcs8,
    /// Through the host as a raw secret value, into a PKCS#11 target with `C_CreateObject`.
    HostRaw,
    /// Through the host, then `tpm2_ptool import`.
    Tpm2Ptool,
    /// Through the host, then ykcs11 `C_CreateObject` as SO.
    PivImport,
    /// A duplication blob built on the host for the target TPM's parent key.
    TpmDuplicate,
    /// Through the host, written as a PKCS#8 `EncryptedPrivateKeyInfo` (PBES2).
    Pkcs8Pbes2,
    /// Through the host, written as PKCS#12 beside the key's certificate.
    Pkcs12,
    /// From a file that holds an unencrypted PKCS#8 `PrivateKeyInfo`, as PEM or DER
    /// (docs/FILE.md).
    Pkcs8,
    /// From a file that holds a PKCS#1 `RSAPrivateKey`, as PEM or DER.
    Pkcs1,
    /// From a file that holds a SEC1 `ECPrivateKey`, as PEM or DER.
    Sec1,
    /// From a file that holds the raw value of a secret key or of a private data object.
    Raw,
    /// A provider's own method (docs/CAMIGRATE.md D10).
    Vendor {
        /// The provider that declares the method.
        provider: String,
        /// The method's name within that provider.
        name: String,
    },
}

impl Method {
    /// Returns the frozen name, as a bundle and the lock write it.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Method::Vendor { provider, name } => format!("vendor:{provider}/{name}"),
            builtin => builtin.builtin_name().unwrap_or_default().to_owned(),
        }
    }

    /// Returns the frozen name of a built-in method, from one table for all of them. Returns
    /// `None` for a vendor method.
    fn builtin_name(&self) -> Option<&'static str> {
        Some(match self {
            Method::Public => "public",
            Method::RsaOaepAesKwp(OaepHash::Sha1) => "rsa-oaep-sha1+aes-kwp",
            Method::RsaOaepAesKwp(OaepHash::Sha256) => "rsa-oaep-sha256+aes-kwp",
            Method::RsaOaep(OaepHash::Sha1) => "rsa-oaep-sha1",
            Method::RsaOaep(OaepHash::Sha256) => "rsa-oaep-sha256",
            Method::HostPkcs8 => "host-pkcs8",
            Method::HostRaw => "host-raw",
            Method::Tpm2Ptool => "tpm2-ptool",
            Method::PivImport => "piv-import",
            Method::TpmDuplicate => "tpm-duplicate",
            Method::Pkcs8Pbes2 => "pkcs8-pbes2",
            Method::Pkcs12 => "pkcs12",
            Method::Pkcs8 => "pkcs8",
            Method::Pkcs1 => "pkcs1",
            Method::Sec1 => "sec1",
            Method::Raw => "raw",
            Method::Vendor { .. } => return None,
        })
    }

    /// Returns the method that a frozen name denotes, or `None` for a name that this version of
    /// cakeys does not know. A vendor method is `vendor:<provider>/<name>`, and each part is a name
    /// with the same grammar as the names in keys.toml (`[A-Za-z0-9][A-Za-z0-9_-]*`). The name is
    /// frozen into locks, so it must stay one word.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Method> {
        if let Some(rest) = name.strip_prefix("vendor:") {
            let (provider, name) = rest.split_once('/')?;
            return (crate::config::is_name(provider) && crate::config::is_name(name))
                .then(|| Method::Vendor { provider: provider.into(), name: name.into() });
        }
        Method::BUILTIN.iter().find(|m| m.builtin_name() == Some(name)).cloned()
    }

    /// Every built-in method, for the name lookups and for the test that pins the names.
    pub const BUILTIN: [Method; 16] = [
        Method::Public,
        Method::RsaOaepAesKwp(OaepHash::Sha256),
        Method::RsaOaepAesKwp(OaepHash::Sha1),
        Method::RsaOaep(OaepHash::Sha256),
        Method::RsaOaep(OaepHash::Sha1),
        Method::HostPkcs8,
        Method::HostRaw,
        Method::Tpm2Ptool,
        Method::PivImport,
        Method::TpmDuplicate,
        Method::Pkcs8Pbes2,
        Method::Pkcs12,
        Method::Pkcs8,
        Method::Pkcs1,
        Method::Sec1,
        Method::Raw,
    ];
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_names_are_pinned_and_round_trip() {
        let names: Vec<String> = Method::BUILTIN.iter().map(Method::name).collect();
        assert_eq!(
            names,
            [
                "public",
                "rsa-oaep-sha256+aes-kwp",
                "rsa-oaep-sha1+aes-kwp",
                "rsa-oaep-sha256",
                "rsa-oaep-sha1",
                "host-pkcs8",
                "host-raw",
                "tpm2-ptool",
                "piv-import",
                "tpm-duplicate",
                "pkcs8-pbes2",
                "pkcs12",
                "pkcs8",
                "pkcs1",
                "sec1",
                "raw",
            ]
        );
        for m in &Method::BUILTIN {
            assert_eq!(Method::from_name(&m.name()).as_ref(), Some(m));
        }
        let vendor = Method::Vendor { provider: "luna".into(), name: "clone".into() };
        assert_eq!(Method::from_name("vendor:luna/clone"), Some(vendor));
        assert_eq!(Method::from_name("vendor:luna"), None);
        assert_eq!(Method::from_name("rsa-aes"), None);
        let levels: Vec<&str> =
            [Exposure::Public, Exposure::Enforced, Exposure::Sealed, Exposure::Host, Exposure::File]
                .map(Exposure::name)
                .to_vec();
        assert_eq!(levels, ["public", "enforced", "sealed", "host", "file"]);
    }

    /// A vendor method needs both of its parts, and methods and exposure levels print as their
    /// names.
    #[test]
    fn names_print_and_half_named_vendor_methods_are_unknown() {
        assert_eq!(Method::from_name("vendor:/clone"), None);
        assert_eq!(Method::from_name("vendor:luna/"), None);
        // Each part is one name, with the grammar of the names in keys.toml: no second `/`, no
        // space and no dot.
        for name in ["vendor:luna/a/b", "vendor:luna/a b", "vendor:lu.na/clone", "vendor:luna/-clone"] {
            assert_eq!(Method::from_name(name), None, "{name}");
        }
        assert!(Method::from_name("vendor:aws-cloudhsm/key_clone-2").is_some());
        assert_eq!(Method::RsaOaep(OaepHash::Sha256).to_string(), "rsa-oaep-sha256");
        assert_eq!(Method::Vendor { provider: "luna".into(), name: "clone".into() }.to_string(), "vendor:luna/clone");
        assert_eq!(Exposure::Sealed.to_string(), "sealed");
    }
}
