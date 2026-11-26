//! The PKCS#11 object classes and key types that cakeys manages. They are parsed once, when
//! keys.toml or the lock is loaded. They serialize as their PKCS#11 names (`CKO_*`, `CKK_*`), so
//! spec digests and lock files stay unchanged. A name that cakeys does not know is invalid at
//! load (17).

use serde::{Deserialize, Serialize};

macro_rules! pkcs11_names {
    ($(#[$doc:meta])* $ty:ident($what:literal) { $($variant:ident = $name:literal),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
        pub enum $ty {
            $(#[doc = concat!("`", $name, "`.")] #[serde(rename = $name)] $variant,)*
        }

        impl $ty {
            /// Every value, in declaration order.
            pub const ALL: &[$ty] = &[$($ty::$variant),*];

            /// Returns the PKCS#11 name, as keys.toml and the lock write it.
            pub fn name(self) -> &'static str {
                match self {
                    $($ty::$variant => $name,)*
                }
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.name())
            }
        }

        impl std::str::FromStr for $ty {
            type Err = String;

            fn from_str(s: &str) -> Result<Self, String> {
                $ty::ALL.iter().copied().find(|v| v.name() == s).ok_or_else(|| format!(concat!("unknown ", $what, ": {}"), s))
            }
        }
    };
}

pkcs11_names! {
    /// The object classes (PKCS#11 3.2 §4).
    ObjectClass("object class") {
        Data = "CKO_DATA",
        Certificate = "CKO_CERTIFICATE",
        PublicKey = "CKO_PUBLIC_KEY",
        PrivateKey = "CKO_PRIVATE_KEY",
        SecretKey = "CKO_SECRET_KEY",
    }
}

pkcs11_names! {
    /// The key types (PKCS#11 3.2 §6).
    KeyType("key type") {
        Rsa = "CKK_RSA",
        Ec = "CKK_EC",
        EcEdwards = "CKK_EC_EDWARDS",
        GenericSecret = "CKK_GENERIC_SECRET",
        Aes = "CKK_AES",
        Sha1Hmac = "CKK_SHA_1_HMAC",
        Sha224Hmac = "CKK_SHA224_HMAC",
        Sha256Hmac = "CKK_SHA256_HMAC",
        Sha384Hmac = "CKK_SHA384_HMAC",
        Sha512Hmac = "CKK_SHA512_HMAC",
        Des3 = "CKK_DES3",
    }
}

impl ObjectClass {
    /// Returns whether the class is a private, public or secret key, which are the classes with
    /// key attributes.
    #[must_use]
    pub fn is_key(self) -> bool {
        matches!(self, ObjectClass::PrivateKey | ObjectClass::PublicKey | ObjectClass::SecretKey)
    }

    /// Returns whether the class is one of the two halves of a key pair.
    #[must_use]
    pub fn is_asymmetric(self) -> bool {
        matches!(self, ObjectClass::PrivateKey | ObjectClass::PublicKey)
    }
}

impl KeyType {
    /// Returns whether the key type is a type of the halves of a key pair. The other key types
    /// are secret keys.
    #[must_use]
    pub fn is_asymmetric(self) -> bool {
        matches!(self, KeyType::Rsa | KeyType::Ec | KeyType::EcEdwards)
    }

    /// Returns whether the key type is one of the HMAC key types that are bound to one hash
    /// (`CKK_SHA*_HMAC`), which PKCS#11 cannot generate.
    #[must_use]
    pub fn is_hash_bound_hmac(self) -> bool {
        matches!(
            self,
            KeyType::Sha1Hmac | KeyType::Sha224Hmac | KeyType::Sha256Hmac | KeyType::Sha384Hmac | KeyType::Sha512Hmac
        )
    }

    /// Returns the length in bytes that a key type fixes. A `CKK_DES3` key is three-key Triple
    /// DES with 24 bytes (including the parity bits), and PKCS#11 gives it no `CKA_VALUE_LEN`
    /// (`SoftHSM` stores none). For such a type, keys.toml's `valueLen` is that length or absent.
    #[must_use]
    pub fn fixed_value_len(self) -> Option<u64> {
        match self {
            KeyType::Des3 => Some(24),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names are the serialized form, which spec digests and locks depend on.
    #[test]
    fn names_round_trip_through_serde() {
        for c in ObjectClass::ALL {
            assert_eq!(serde_json::to_value(c).unwrap(), c.name());
            assert_eq!(c.name().parse::<ObjectClass>(), Ok(*c));
        }
        for k in KeyType::ALL {
            assert_eq!(serde_json::to_value(k).unwrap(), k.name());
            assert_eq!(k.name().parse::<KeyType>(), Ok(*k));
        }
        // cakeys does not manage two-key Triple DES or single DES (docs/OPEN.md).
        assert_eq!("CKK_DES2".parse::<KeyType>(), Err("unknown key type: CKK_DES2".to_owned()));
        assert!("CKK_DES".parse::<KeyType>().is_err());
        // The error names the PKCS#11 concept, and never the Rust type.
        assert_eq!("CKO_X".parse::<ObjectClass>(), Err("unknown object class: CKO_X".to_owned()));
    }

    #[test]
    fn only_des3_fixes_its_length() {
        let fixed: Vec<_> = KeyType::ALL.iter().filter_map(|k| Some((*k, k.fixed_value_len()?))).collect();
        assert_eq!(fixed, [(KeyType::Des3, 24)]);
    }
}
