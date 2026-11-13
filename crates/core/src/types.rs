//! The PKCS#11 object classes and key types cakeys manages, parsed once when keys.toml or the
//! lock is loaded. They serialize as their PKCS#11 names (`CKO_*`, `CKK_*`), so spec digests and
//! lock files are unchanged; a name cakeys does not know is invalid at load (17).

use serde::{Deserialize, Serialize};

macro_rules! pkcs11_names {
    ($(#[$doc:meta])* $ty:ident { $($variant:ident = $name:literal),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
        pub enum $ty {
            $(#[serde(rename = $name)] $variant,)*
        }

        impl $ty {
            pub const ALL: &[$ty] = &[$($ty::$variant),*];

            /// The PKCS#11 name, as keys.toml and the lock write it.
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
                $ty::ALL.iter().copied().find(|v| v.name() == s).ok_or_else(|| format!("unknown {}: {s}", stringify!($ty)))
            }
        }
    };
}

pkcs11_names! {
    /// Object classes (PKCS#11 3.2 §4).
    ObjectClass {
        Data = "CKO_DATA",
        Certificate = "CKO_CERTIFICATE",
        PublicKey = "CKO_PUBLIC_KEY",
        PrivateKey = "CKO_PRIVATE_KEY",
        SecretKey = "CKO_SECRET_KEY",
    }
}

pkcs11_names! {
    /// Key types (PKCS#11 3.2 §6).
    KeyType {
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
    }
}

impl ObjectClass {
    /// Private, public and secret keys: the classes with key attributes.
    pub fn is_key(self) -> bool {
        matches!(self, ObjectClass::PrivateKey | ObjectClass::PublicKey | ObjectClass::SecretKey)
    }

    /// The two halves of a key pair.
    pub fn is_asymmetric(self) -> bool {
        matches!(self, ObjectClass::PrivateKey | ObjectClass::PublicKey)
    }
}

impl KeyType {
    /// The halves of a key pair have these types; the rest are secret keys.
    pub fn is_asymmetric(self) -> bool {
        matches!(self, KeyType::Rsa | KeyType::Ec | KeyType::EcEdwards)
    }

    /// The HMAC key types bound to one hash (`CKK_SHA*_HMAC`), which PKCS#11 cannot generate.
    pub fn is_hash_bound_hmac(self) -> bool {
        matches!(
            self,
            KeyType::Sha1Hmac | KeyType::Sha224Hmac | KeyType::Sha256Hmac | KeyType::Sha384Hmac | KeyType::Sha512Hmac
        )
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
        assert!("CKK_DES3".parse::<KeyType>().is_err());
    }
}
