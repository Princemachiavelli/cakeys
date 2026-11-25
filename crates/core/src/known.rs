//! What is known of a security attribute, and why not when it is not: an attribute nobody
//! declared, recorded or read is never a verdict, and every question about one says which way
//! unknown falls (review 2026-11-24 D-7, B-4; docs/archive/REVIEW-2026-11-24/phase1-design.md
//! §2.2). A restriction unknown restricts; a permission unknown does not permit. There is no
//! `Default`, no `From<Option<T>>` and no `unwrap_or`: an `Option` becomes a [`Known`] only with
//! the reason it may be absent ([`Known::or`]).

/// A value, or why it is not known.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known<T> {
    /// It is this.
    Is(T),
    /// It is not known, for this reason.
    Unknown(Why),
}

/// Why a value is not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The spec does not declare it.
    Undeclared,
    /// The lock has no record of it.
    Unrecorded,
    /// The module did not report it.
    Unread,
}

impl<T> Known<T> {
    /// `value`, or unknown for `why` where it is absent.
    pub fn or(value: Option<T>, why: Why) -> Known<T> {
        match value {
            Some(v) => Known::Is(v),
            None => Known::Unknown(why),
        }
    }

    /// The first of `self` and `then` that is known; `self`'s reason when neither is.
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
    /// Whether a restriction holds: only a known `false` lifts it.
    #[must_use]
    pub fn restricts(&self) -> bool {
        !matches!(self, Known::Is(false))
    }

    /// Whether a permission is granted: only a known `true` grants it.
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

/// An attribute whose `true` restricts what can be done with the object: unknown restricts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Restriction {
    /// `CKA_PRIVATE`: seen only after a login.
    Private,
    /// `CKA_SENSITIVE`: its value never leaves in plaintext.
    Sensitive,
    /// `CKA_WRAP_WITH_TRUSTED`: wrapped only by a trusted key.
    WrapWithTrusted,
    /// `CKA_NEVER_EXTRACTABLE`: never was extractable.
    NeverExtractable,
    /// `CKA_ALWAYS_SENSITIVE`: always was sensitive.
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

/// An attribute whose `true` permits something: unknown does not permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// `CKA_EXTRACTABLE`: it may be wrapped out.
    Extractable,
    /// `CKA_UNWRAP`: it unwraps.
    Unwrap,
    /// `CKA_DECRYPT`: it decrypts.
    Decrypt,
    /// `CKA_DERIVE`: it derives.
    Derive,
    /// `CKA_TRUSTED`: it may wrap what only a trusted key may.
    Trusted,
    /// `CKA_SIGN`: it signs.
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

    /// Unknown falls the safe way for each kind: it restricts, and it does not permit.
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
