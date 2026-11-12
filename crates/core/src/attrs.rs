//! Which boolean attributes each object class carries (PKCS#11 3.2 §4): one table for what a spec
//! may declare and what the observed policy vector records. The two sets differ in two places:
//! `CKA_TOKEN` is observed but never declared (every managed object is a token object), and a
//! secret key's `CKA_SIGN_RECOVER`/`CKA_VERIFY_RECOVER` may be declared but are not observed.

use crate::types::ObjectClass;

/// How cakeys uses a boolean attribute of a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Use {
    /// Declarable in a spec and recorded in the observed policy vector.
    Both,
    /// Recorded in the policy vector only.
    Observed,
    /// Declarable only.
    Declared,
}

/// Booleans every class carries (§4.2, §4.4).
const COMMON: &[(&str, Use)] = &[
    ("CKA_TOKEN", Use::Observed),
    ("CKA_PRIVATE", Use::Both),
    ("CKA_MODIFIABLE", Use::Both),
    ("CKA_COPYABLE", Use::Both),
    ("CKA_DESTROYABLE", Use::Both),
];

/// Usage and policy booleans of each class beyond the common ones.
fn of_class(class: ObjectClass) -> &'static [(&'static str, Use)] {
    use Use::*;
    match class {
        ObjectClass::PrivateKey => &[
            ("CKA_DERIVE", Both),
            ("CKA_SENSITIVE", Both),
            ("CKA_DECRYPT", Both),
            ("CKA_SIGN", Both),
            ("CKA_SIGN_RECOVER", Both),
            ("CKA_UNWRAP", Both),
            ("CKA_EXTRACTABLE", Both),
            ("CKA_WRAP_WITH_TRUSTED", Both),
            ("CKA_ALWAYS_AUTHENTICATE", Both),
        ],
        ObjectClass::PublicKey => &[
            ("CKA_DERIVE", Both),
            ("CKA_ENCRYPT", Both),
            ("CKA_VERIFY", Both),
            ("CKA_VERIFY_RECOVER", Both),
            ("CKA_WRAP", Both),
            ("CKA_TRUSTED", Both),
        ],
        ObjectClass::SecretKey => &[
            ("CKA_DERIVE", Both),
            ("CKA_SENSITIVE", Both),
            ("CKA_ENCRYPT", Both),
            ("CKA_DECRYPT", Both),
            ("CKA_SIGN", Both),
            ("CKA_SIGN_RECOVER", Declared),
            ("CKA_VERIFY", Both),
            ("CKA_VERIFY_RECOVER", Declared),
            ("CKA_WRAP", Both),
            ("CKA_UNWRAP", Both),
            ("CKA_EXTRACTABLE", Both),
            ("CKA_WRAP_WITH_TRUSTED", Both),
            ("CKA_TRUSTED", Both),
        ],
        ObjectClass::Certificate => &[("CKA_TRUSTED", Both)],
        ObjectClass::Data => &[],
    }
}

/// `CKA_ALLOWED_MECHANISMS`: the one non-boolean policy attribute, on key objects only.
pub const ALLOWED_MECHANISMS: &str = "CKA_ALLOWED_MECHANISMS";

fn bools(class: ObjectClass, want: fn(Use) -> bool) -> impl Iterator<Item = &'static str> + use<> {
    COMMON.iter().chain(of_class(class)).filter(move |(_, u)| want(*u)).map(|(n, _)| *n)
}

/// The booleans of `class` the observed policy vector records.
pub fn observed(class: ObjectClass) -> impl Iterator<Item = &'static str> + use<> {
    bools(class, |u| u != Use::Declared)
}

/// Whether a spec may declare the boolean `name` on a `class` object.
pub fn declarable(class: ObjectClass, name: &str) -> bool {
    bools(class, |u| u != Use::Observed).any(|n| n == name)
}

/// Whether `name` is a boolean some class may declare.
pub fn is_declarable_bool(name: &str) -> bool {
    ObjectClass::ALL.iter().any(|c| declarable(*c, name))
}

/// Whether a `class` object may carry `CKA_ALLOWED_MECHANISMS`.
pub fn has_allowed_mechanisms(class: ObjectClass) -> bool {
    class.is_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The observed vector is part of every recorded realisation: a change here changes locks.
    #[test]
    fn observed_vectors_are_pinned() {
        let v = |c| observed(c).collect::<Vec<_>>().join(" ");
        let common = "CKA_TOKEN CKA_PRIVATE CKA_MODIFIABLE CKA_COPYABLE CKA_DESTROYABLE";
        assert_eq!(
            v(ObjectClass::PrivateKey),
            format!("{common} CKA_DERIVE CKA_SENSITIVE CKA_DECRYPT CKA_SIGN CKA_SIGN_RECOVER CKA_UNWRAP CKA_EXTRACTABLE CKA_WRAP_WITH_TRUSTED CKA_ALWAYS_AUTHENTICATE")
        );
        assert_eq!(v(ObjectClass::PublicKey), format!("{common} CKA_DERIVE CKA_ENCRYPT CKA_VERIFY CKA_VERIFY_RECOVER CKA_WRAP CKA_TRUSTED"));
        assert_eq!(
            v(ObjectClass::SecretKey),
            format!("{common} CKA_DERIVE CKA_SENSITIVE CKA_ENCRYPT CKA_DECRYPT CKA_SIGN CKA_VERIFY CKA_WRAP CKA_UNWRAP CKA_EXTRACTABLE CKA_WRAP_WITH_TRUSTED CKA_TRUSTED")
        );
        assert_eq!(v(ObjectClass::Certificate), format!("{common} CKA_TRUSTED"));
        assert_eq!(v(ObjectClass::Data), common);
    }

    #[test]
    fn declarable_differs_from_observed_only_where_documented() {
        assert!(!is_declarable_bool("CKA_TOKEN"));
        assert!(declarable(ObjectClass::SecretKey, "CKA_SIGN_RECOVER"));
        assert!(!observed(ObjectClass::SecretKey).any(|n| n == "CKA_SIGN_RECOVER"));
        assert!(declarable(ObjectClass::Data, "CKA_PRIVATE"));
        assert!(!declarable(ObjectClass::Certificate, "CKA_SIGN"));
        assert!(!is_declarable_bool("CKA_LOCAL"), "immutables are never declared");
    }
}
