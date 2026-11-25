//! The names a profile row carries, as types (ISSUES.md Q28): the ones this cakeys knows as
//! variants, any other (a newer cakeys's) kept as read, so a profile still loads and writes
//! back unchanged. Each compares, hashes and orders by its name, as the text it replaced did:
//! rows keep their order, and a known name read as text is the known value.

/// A name this cakeys does not know, as read: only `From` makes one, after the known names did
/// not match, so an `Other` never holds a known name and a pattern on a variant sees every value
/// of it (review names.rs F1).
#[derive(Debug, Clone)]
pub struct Unknown(String);

impl Unknown {
    /// The name, as read.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! named {
    ($(#[$doc:meta])* $ty:ident { $($variant:ident = $name:literal),* $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone)]
        pub enum $ty {
            $(#[doc = concat!("`", $name, "`.")] $variant,)*
            /// A name this cakeys does not know, as read.
            Other(Unknown),
        }

        impl $ty {
            /// Every name this cakeys knows, one per variant.
            pub const NAMES: &[&str] = &[$($name),*];

            /// The name, as profiles write it.
            #[must_use]
            pub fn name(&self) -> &str {
                match self {
                    $($ty::$variant => $name,)*
                    $ty::Other(name) => &name.0,
                }
            }
        }

        impl From<&str> for $ty {
            fn from(name: &str) -> Self {
                match name {
                    $($name => $ty::$variant,)*
                    other => $ty::Other(Unknown(other.to_owned())),
                }
            }
        }

        impl From<String> for $ty {
            fn from(name: String) -> Self {
                Self::from(name.as_str())
            }
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.name())
            }
        }

        impl PartialEq for $ty {
            fn eq(&self, other: &Self) -> bool {
                self.name() == other.name()
            }
        }

        impl Eq for $ty {}

        impl PartialEq<str> for $ty {
            fn eq(&self, other: &str) -> bool {
                self.name() == other
            }
        }

        impl PartialEq<&str> for $ty {
            fn eq(&self, other: &&str) -> bool {
                self.name() == *other
            }
        }

        impl std::hash::Hash for $ty {
            fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
                self.name().hash(state);
            }
        }

        impl PartialOrd for $ty {
            fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for $ty {
            fn cmp(&self, other: &Self) -> std::cmp::Ordering {
                self.name().cmp(other.name())
            }
        }

        impl<'de> serde::Deserialize<'de> for $ty {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                String::deserialize(d).map(Self::from)
            }
        }
    };
}

named! {
    /// A key type a row names (`CKK_*`): every one the profiles measure, the Montgomery curves'
    /// included, which keys.toml does not take (`cakeys_core::types::KeyType`).
    KeyKind {
        Rsa = "CKK_RSA",
        Ec = "CKK_EC",
        EcEdwards = "CKK_EC_EDWARDS",
        EcMontgomery = "CKK_EC_MONTGOMERY",
        GenericSecret = "CKK_GENERIC_SECRET",
        Aes = "CKK_AES",
        Sha1Hmac = "CKK_SHA_1_HMAC",
        Sha224Hmac = "CKK_SHA224_HMAC",
        Sha256Hmac = "CKK_SHA256_HMAC",
        Sha384Hmac = "CKK_SHA384_HMAC",
        Sha512Hmac = "CKK_SHA512_HMAC",
        Des3 = "CKK_DES3",
        Des2 = "CKK_DES2",
        Hkdf = "CKK_HKDF",
        MlDsa = "CKK_ML_DSA",
        MlKem = "CKK_ML_KEM",
        SlhDsa = "CKK_SLH_DSA",
    }
}

named! {
    /// A proof of possession a `prove.*` row names, by its `binding` (`cakeys_core::config::Binding`).
    Proof {
        PopSign = "pop-sign",
        PopSignPin = "pop-sign-pin",
        PopEcdh = "pop-ecdh",
        PopDecrypt = "pop-decrypt",
        PopUnwrap = "pop-unwrap",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A known name read as text is the known value, an unknown one is kept as read, and both
    /// order by their names, as the strings they replace did.
    #[test]
    fn names_are_values_and_order_as_text() {
        assert!(matches!(KeyKind::from("CKK_EC"), KeyKind::Ec));
        // Every way to a value goes through the known names: a known one is never `Other`.
        for name in KeyKind::NAMES {
            assert!(!matches!(KeyKind::from(*name), KeyKind::Other(_)), "{name}");
            assert!(!matches!(KeyKind::from((*name).to_owned()), KeyKind::Other(_)), "{name}");
            let read: KeyKind = toml::from_str::<toml::Table>(&format!("k = \"{name}\""))
                .unwrap()
                .remove("k")
                .unwrap()
                .try_into()
                .unwrap();
            assert!(!matches!(read, KeyKind::Other(_)), "{name}");
        }
        assert!(matches!(KeyKind::from("CKK_FUTURE"), KeyKind::Other(u) if u.as_str() == "CKK_FUTURE"));
        assert_eq!(KeyKind::from("CKK_FUTURE").name(), "CKK_FUTURE");
        let mut kinds: Vec<KeyKind> =
            ["CKK_RSA", "CKK_EC_EDWARDS", "CKK_AES", "CKK_FUTURE", "CKK_EC"].map(KeyKind::from).into();
        kinds.sort();
        let names: Vec<&str> = kinds.iter().map(KeyKind::name).collect();
        assert_eq!(names, ["CKK_AES", "CKK_EC", "CKK_EC_EDWARDS", "CKK_FUTURE", "CKK_RSA"]);
        assert_eq!(Proof::from("pop-ecdh").to_string(), "pop-ecdh");
    }
}
