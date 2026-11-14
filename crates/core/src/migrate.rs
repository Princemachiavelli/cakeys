//! The vocabulary of moving keys (MIGRATE.md): the method names and exposure levels a lock's
//! `provenance.origin` records (frozen, pinned below), and the capabilities a provider declares
//! for its token ([`Side`], the `Provider::migration` hook, D10). The planner that decides
//! between them is camigrate's (docs/SCOPE.md, "Three tools"), so a `cakeys` build carries
//! none of it.

use crate::config::ObjectCfg;
use crate::pop::OaepHash;
use crate::types::{KeyType, ObjectClass};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// How much of the material is exposed on the way (MIGRATE.md D2), strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    /// Nothing secret moves.
    Public,
    /// Sealed, and the source token accepts no other wrapping key (`CKA_WRAP_WITH_TRUSTED`).
    Enforced,
    /// Leaves the source only wrapped under a key on the target.
    Sealed,
    /// In plaintext in cakeys' memory, zeroized after; never on disk.
    Host,
    /// A passphrase-protected file.
    File,
}

impl Exposure {
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

/// How an object moves. The names are frozen like scheme names (MIGRATE.md, "Frozen names and
/// formats"): a bundle or a lock's `provenance.origin` written with one must keep meaning it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Method {
    Public,
    /// A fresh AES KEK under RSA-OAEP to the transport key, the key under the KEK (RFC 5649).
    RsaOaepAesKwp(OaepHash),
    /// The key under RSA-OAEP to the transport key directly (small secret keys).
    RsaOaep(OaepHash),
    /// Through the host, into a PKCS#11 target with `C_CreateObject`.
    HostPkcs8,
    HostRaw,
    /// Through the host, then `tpm2_ptool import`.
    Tpm2Ptool,
    /// Through the host, then ykcs11 `C_CreateObject` as SO.
    PivImport,
    /// A duplication blob built on the host for the target TPM's parent key.
    TpmDuplicate,
    Pkcs8Pbes2,
    Pkcs12,
    /// A provider's own method (MIGRATE.md D10).
    Vendor {
        provider: String,
        name: String,
    },
}

impl Method {
    /// The frozen name, as a bundle and the lock write it.
    #[must_use]
    pub fn name(&self) -> String {
        let oaep = |h: &OaepHash| match h {
            OaepHash::Sha1 => "rsa-oaep-sha1",
            OaepHash::Sha256 => "rsa-oaep-sha256",
        };
        match self {
            Method::Public => "public".into(),
            Method::RsaOaepAesKwp(h) => format!("{}+aes-kwp", oaep(h)),
            Method::RsaOaep(h) => oaep(h).into(),
            Method::HostPkcs8 => "host-pkcs8".into(),
            Method::HostRaw => "host-raw".into(),
            Method::Tpm2Ptool => "tpm2-ptool".into(),
            Method::PivImport => "piv-import".into(),
            Method::TpmDuplicate => "tpm-duplicate".into(),
            Method::Pkcs8Pbes2 => "pkcs8-pbes2".into(),
            Method::Pkcs12 => "pkcs12".into(),
            Method::Vendor { provider, name } => format!("vendor:{provider}/{name}"),
        }
    }

    /// The method a frozen name denotes; `None` for a name this cakeys does not know.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Method> {
        if let Some(rest) = name.strip_prefix("vendor:") {
            let (provider, name) = rest.split_once('/')?;
            return (!provider.is_empty() && !name.is_empty())
                .then(|| Method::Vendor { provider: provider.into(), name: name.into() });
        }
        Method::BUILTIN.iter().find(|m| m.name() == name).cloned()
    }

    /// Every built-in method, for name lookups and the pinning test.
    pub const BUILTIN: [Method; 12] = [
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
    ];
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name())
    }
}

/// Which objects a capability covers: a class, and optionally only some key types, curves or
/// RSA sizes (empty: any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accept {
    pub class: ObjectClass,
    pub key_types: Vec<KeyType>,
    pub curves: Vec<&'static str>,
    /// Inclusive RSA modulus range in bits.
    pub modulus_bits: Option<(u32, u32)>,
}

impl Accept {
    #[must_use]
    pub fn class(class: ObjectClass) -> Accept {
        Accept { class, key_types: vec![], curves: vec![], modulus_bits: None }
    }

    #[must_use]
    pub fn key(class: ObjectClass, key_types: &[KeyType]) -> Accept {
        Accept { key_types: key_types.to_vec(), ..Accept::class(class) }
    }

    #[must_use]
    pub fn covers(&self, ty: &ObjectCfg) -> bool {
        self.class == ty.class
            && (self.key_types.is_empty() || ty.key_type.is_some_and(|k| self.key_types.contains(&k)))
            && (self.curves.is_empty() || ty.curve.as_deref().is_some_and(|c| self.curves.contains(&c)))
            && match (self.modulus_bits, ty.modulus_bits) {
                (Some((lo, hi)), Some(bits)) => (u64::from(lo)..=u64::from(hi)).contains(&bits),
                (Some(_), None) => false,
                (None, _) => true,
            }
    }
}

/// How plaintext material gets into a token (the `host` paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaintextImport {
    /// `C_CreateObject` with the key's attributes (any PKCS#11 module that accepts it).
    CreateObject,
    /// `tpm2_ptool import`, for the listed objects.
    Tpm2Ptool(Vec<Accept>),
    /// ykcs11 `C_CreateObject` as SO into a PIV slot, for the listed objects.
    PivImport(Vec<Accept>),
}

/// A provider's own method (MIGRATE.md D10): its name, the exposure it declares, what it moves,
/// and the target providers it works with (empty: any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorMethod {
    pub provider: String,
    pub name: String,
    pub exposure: Exposure,
    pub objects: Vec<Accept>,
    pub targets: Vec<String>,
}

/// One token's capabilities for moving keys, as its provider describes them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(clippy::struct_excessive_bools, reason = "independent capability claims of a module profile")]
pub struct Side {
    pub token: String,
    pub provider: String,
    /// The usable mechanisms (provider-filtered), by `CKM_*` name.
    pub mechanisms: BTreeSet<String>,
    /// Whether the module ever wraps a key out (`C_WrapKey`).
    pub exports: bool,
    /// Whether the module unwraps a key in (`C_UnwrapKey`).
    pub unwraps: bool,
    /// Whether a secret key it unwraps reports its length (`CKA_VALUE_LEN`), which the import's
    /// type check reads: `SoftHSM` leaves it 0.
    pub secret_unwraps: bool,
    /// Whether a `CKA_WRAP_WITH_TRUSTED` key can leave toward a transport key the SO marked
    /// `CKA_TRUSTED` (`enforced`).
    pub trusted_wrap: bool,
    /// The OAEP hashes the module implements for wrapping, not only lists.
    pub oaep: Vec<OaepHash>,
    /// Public objects it accepts from their value or DER.
    pub public_import: Vec<Accept>,
    /// How plaintext private and secret keys get in, if at all.
    pub plaintext_import: Option<PlaintextImport>,
    /// Provider methods this side offers as a source (MIGRATE.md D10).
    pub vendor: Vec<VendorMethod>,
}

impl Side {
    /// A spec-compliant PKCS#11 module: wraps and unwraps with what it lists, imports public
    /// objects and plaintext keys with `C_CreateObject`.
    #[must_use]
    pub fn pkcs11(token: &str, provider: &str, mechanisms: impl IntoIterator<Item = String>) -> Side {
        Side {
            token: token.into(),
            provider: provider.into(),
            mechanisms: mechanisms.into_iter().collect(),
            exports: true,
            unwraps: true,
            secret_unwraps: true,
            trusted_wrap: true,
            oaep: vec![OaepHash::Sha1, OaepHash::Sha256],
            public_import: [ObjectClass::Certificate, ObjectClass::PublicKey, ObjectClass::Data]
                .into_iter()
                .map(Accept::class)
                .collect(),
            plaintext_import: Some(PlaintextImport::CreateObject),
            vendor: vec![],
        }
    }

    /// Whether the token offers `mechanism` (a `CKM_*` name).
    #[must_use]
    pub fn has(&self, mechanism: &str) -> bool {
        self.mechanisms.contains(mechanism)
    }

    /// RFC 5649, under either PKCS#11 name (the same format, MIGRATE.md spike).
    #[must_use]
    pub fn kwp(&self) -> bool {
        self.has("CKM_AES_KEY_WRAP_KWP") || self.has("CKM_AES_KEY_WRAP_PAD")
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
}
