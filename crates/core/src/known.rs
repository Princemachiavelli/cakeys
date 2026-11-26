//! What is known about a security attribute, and the reason when it is not known. An attribute
//! that nobody declared, recorded or read is never a verdict, and every question about such an
//! attribute states how an unknown value counts (review 2026-11-24 D-7, B-4;
//! docs/archive/REVIEW-2026-11-24/phase1-design.md §2.2). An unknown restriction restricts, and an
//! unknown permission does not permit. There is no `Default`, no `From<Option<T>>` and no
//! `unwrap_or`: an `Option` becomes a [`Known`] only together with the reason why it may be absent
//! ([`Known::or`]).

/// A value, or the reason why it is not known.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known<T> {
    /// The value is known, and it is this one.
    Is(T),
    /// The value is not known, for this reason.
    Unknown(Why),
}

/// The reason why a value is not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The spec does not declare the value.
    Undeclared,
    /// The lock has no record of the value.
    Unrecorded,
    /// The module did not report the value.
    Unread,
}

impl<T> Known<T> {
    /// Returns `value`, or an unknown value with the reason `why` when `value` is absent.
    pub fn or(value: Option<T>, why: Why) -> Known<T> {
        match value {
            Some(v) => Known::Is(v),
            None => Known::Unknown(why),
        }
    }

    /// Returns the first of `self` and `then` that is known. When neither is known, it returns the
    /// reason of `self`.
    pub fn or_else(self, then: impl FnOnce() -> Known<T>) -> Known<T> {
        match self {
            Known::Is(v) => Known::Is(v),
            Known::Unknown(why) => match then() {
                Known::Is(v) => Known::Is(v),
                Known::Unknown(_) => Known::Unknown(why),
            },
        }
    }
}

impl Known<bool> {
    /// Returns whether a restriction holds. Only a known `false` removes the restriction.
    #[must_use]
    pub fn restricts(&self) -> bool {
        !matches!(self, Known::Is(false))
    }

    /// Returns whether a permission is granted. Only a known `true` grants it.
    #[must_use]
    pub fn permits(&self) -> bool {
        matches!(self, Known::Is(true))
    }
}

impl std::fmt::Display for Known<bool> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Known::Is(b) => write!(f, "{b}"),
            Known::Unknown(Why::Undeclared) => f.write_str("not declared"),
            Known::Unknown(Why::Unrecorded) => f.write_str("not recorded"),
            Known::Unknown(Why::Unread) => f.write_str("not reported"),
        }
    }
}

/// An attribute whose value `true` restricts what can be done with the object. An unknown value
/// restricts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restriction {
    /// `CKA_PRIVATE`: the object is visible only after a login.
    Private,
    /// `CKA_SENSITIVE`: the object's value never leaves the token in plaintext.
    Sensitive,
    /// `CKA_WRAP_WITH_TRUSTED`: the object can be wrapped only by a trusted key.
    WrapWithTrusted,
    /// `CKA_NEVER_EXTRACTABLE`: the object was never extractable.
    NeverExtractable,
    /// `CKA_ALWAYS_SENSITIVE`: the object was always sensitive.
    AlwaysSensitive,
}

impl Restriction {
    /// Its attribute's name.
    #[must_use]
    pub fn attr(self) -> &'static str {
        match self {
            Restriction::Private => "CKA_PRIVATE",
            Restriction::Sensitive => "CKA_SENSITIVE",
            Restriction::WrapWithTrusted => "CKA_WRAP_WITH_TRUSTED",
            Restriction::NeverExtractable => "CKA_NEVER_EXTRACTABLE",
            Restriction::AlwaysSensitive => "CKA_ALWAYS_SENSITIVE",
        }
    }
}

/// An attribute whose value `true` permits something. An unknown value does not permit it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// `CKA_EXTRACTABLE`: the object may be wrapped and exported from the token.
    Extractable,
    /// `CKA_UNWRAP`: the key may unwrap other keys.
    Unwrap,
    /// `CKA_DECRYPT`: the key may decrypt.
    Decrypt,
    /// `CKA_DERIVE`: the key may derive other keys.
    Derive,
    /// `CKA_TRUSTED`: the key may wrap objects that only a trusted key may wrap.
    Trusted,
    /// `CKA_SIGN`: the key may sign.
    Sign,
}

impl Permission {
    /// Its attribute's name.
    #[must_use]
    pub fn attr(self) -> &'static str {
        match self {
            Permission::Extractable => "CKA_EXTRACTABLE",
            Permission::Unwrap => "CKA_UNWRAP",
            Permission::Decrypt => "CKA_DECRYPT",
            Permission::Derive => "CKA_DERIVE",
            Permission::Trusted => "CKA_TRUSTED",
            Permission::Sign => "CKA_SIGN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unknown value counts in the safe direction for each kind of attribute: it restricts,
    /// and it does not permit.
    #[test]
    fn unknown_restricts_and_never_permits() {
        let unknown = Known::Unknown(Why::Undeclared);
        assert_eq!(
            [Known::Is(true), Known::Is(false), unknown].map(|k| (k.restricts(), k.permits())),
            [(true, true), (false, false), (true, false)]
        );
        assert_eq!(Known::or(None, Why::Unrecorded).or_else(|| Known::Is(false)), Known::Is(false));
        assert_eq!(Known::or(Some(true), Why::Unrecorded).or_else(|| Known::Is(false)), Known::Is(true));
        assert_eq!(
            Known::<bool>::or(None, Why::Unrecorded).or_else(|| Known::Unknown(Why::Undeclared)),
            Known::Unknown(Why::Unrecorded)
        );
    }
}
