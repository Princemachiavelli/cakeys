//! The names that a profile row holds, represented as types (ISSUES.md Q28). Each name that this
//! version of cakeys knows is an enum variant. Any other name, such as a name from a newer
//! cakeys, is kept as it was read, so the profile still loads and is written back unchanged. Each
//! type compares, hashes and orders by its name, as the strings that it replaced did. As a
//! result, rows keep their order, and a known name that is read as text becomes the known
//! variant.

/// A name that this version of cakeys does not know, kept as it was read. Only the `From`
/// implementations create one, and only after none of the known names matched. As a result, an
/// `Other` never holds a known name, and a pattern that matches a variant matches every value
/// with that variant's name (review names.rs F1).
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
    /// A key type that a row names (`CKK_*`). The enum includes every key type that the profiles
    /// measure. That includes the key type of the Montgomery curves, which keys.toml does not
    /// accept (`cakeys_core::types::KeyType`).
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
    /// A proof of possession that a `prove.*` row names, by its `binding`
    /// (`cakeys_core::config::Binding`). The known variants are the proofs of the names table
    /// (`cakeys_names::Proof`), and the test `proofs_are_the_names_tables` keeps the two lists
    /// equal. Any other proof name is kept as it was read.
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

    /// A known name that is read as text becomes the known variant, and an unknown name is kept
    /// as it was read. Both kinds of value order by their names, as the strings that they replace
    /// did.
    #[test]
    fn names_are_values_and_order_as_text() {
        assert!(matches!(KeyKind::from("CKK_EC"), KeyKind::Ec));
        // Every conversion into a value checks the known names first, so a known name never
        // becomes `Other`.
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

    /// The proofs that a row knows are the proofs of the names table, in the same order. A proof
    /// that is added to only one of the two lists fails this test until the other list has it
    /// too. As a result, a `prove.*` row that core asks about is never read as an unknown name
    /// from another version of cakeys.
    #[test]
    fn proofs_are_the_names_tables() {
        assert_eq!(Proof::NAMES, cakeys_names::Proof::NAMES.as_slice());
    }
}
