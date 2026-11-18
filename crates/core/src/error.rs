//! Error classes with HTTP-like semantics and stable exit codes (docs/CAKEYS.md).

use std::fmt;

/// What a [`KmError`] says, and the PKCS#11 return value behind it when a module call failed
/// (`CK_RV`, a `CK_ULONG`: 64 bits on every platform this builds for). It displays as its text
/// alone: the value is for code to match on (ISSUES.md Q3), never part of a message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Msg {
    text: String,
    rv: Option<u64>,
}

impl Msg {
    /// The return value of the module call that failed, if a module call did.
    #[must_use]
    pub fn rv(&self) -> Option<u64> {
        self.rv
    }

    /// The text, owned.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }

    /// The same text, carrying the return value of the module call that failed.
    #[must_use]
    pub fn with_rv(mut self, rv: Option<u64>) -> Self {
        self.rv = rv;
        self
    }
}

impl std::ops::Deref for Msg {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl From<String> for Msg {
    fn from(text: String) -> Self {
        Msg { text, rv: None }
    }
}

impl From<&str> for Msg {
    fn from(text: &str) -> Self {
        text.to_owned().into()
    }
}

impl PartialEq<str> for Msg {
    fn eq(&self, other: &str) -> bool {
        self.text == other
    }
}

impl PartialEq<&str> for Msg {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

/// Every failure cakeys reports, each with a stable exit code (docs/CAKEYS.md, "Exit codes").
#[derive(Debug, thiserror::Error)]
pub enum KmError {
    /// Nothing under the locator (11).
    #[error("not found: {0}")]
    NotFound(Msg),
    /// Several objects match (12).
    #[error("ambiguous: {0}")]
    Ambiguous(Msg),
    /// The object is not what the spec says: wrong type or policy, a failed proof of possession,
    /// a foreign public key under the locator (13).
    #[error("conflict: {0}")]
    Conflict(Msg),
    /// The realisation moved since it was recorded: a spec or policy change, a downgrade, a
    /// replaced object (14).
    #[error("precondition failed: {0}")]
    PreconditionFailed(Msg),
    /// The token holds other material than the lock pins (10).
    #[error("hash mismatch in identity of {what}:\n  specified: {expected}\n     got:    {got}")]
    HashMismatch {
        /// What was identified.
        what: String,
        /// The ID the lock pins.
        expected: String,
        /// The ID computed from the token.
        got: String,
    },
    /// First use: the lock pins nothing to compare with yet, like a fixed-output derivation
    /// with a fake hash (18; HTTP's 428 Precondition Required). Not 10: a mismatch against a
    /// pinned ID is a security event, this the state before `lock` records the `got:` ID.
    #[error(
        "first use of {what}: the lock pins no identity for it yet; review, then `lock` records it\n     got:    {got}"
    )]
    FirstUse {
        /// What was identified.
        what: String,
        /// The ID computed from the token.
        got: String,
    },
    /// `create` found its object already under the locator: nothing was made (19).
    #[error("already exists: {0}")]
    Exists(Msg),
    /// `check --token`: an object on the token failed its check; each failure is listed with its
    /// own code (20).
    #[error("objects failed: {0}")]
    ObjectsFailed(Msg),
    /// The token cannot do what the spec needs (15).
    #[error("unsupported: {0}")]
    Unsupported(Msg),
    /// The token cannot be used now: absent, its PIN locked, its module not loadable (16).
    #[error("unavailable: {0}")]
    Unavailable(Msg),
    /// Invalid config, lock, spec or token options (17).
    #[error("invalid spec: {0}")]
    Validation(Msg),
    /// Reading or writing a file failed (exit 1, like any other failure outside the verbs).
    #[error("{0}")]
    Io(Msg),
}

impl KmError {
    /// The process exit code this error ends a run with.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            KmError::HashMismatch { .. } => 10,
            KmError::NotFound(_) => 11,
            KmError::Ambiguous(_) => 12,
            KmError::Conflict(_) => 13,
            KmError::PreconditionFailed(_) => 14,
            KmError::Unsupported(_) => 15,
            KmError::Unavailable(_) => 16,
            KmError::Validation(_) => 17,
            KmError::FirstUse { .. } => 18,
            KmError::Exists(_) => 19,
            KmError::ObjectsFailed(_) => 20,
            KmError::Io(_) => 1,
        }
    }
}

/// A result whose error is a [`KmError`].
pub type Result<T, E = KmError> = std::result::Result<T, E>;

impl KmError {
    /// An I/O error, with what was being done: `.map_err(KmError::io(format!("reading {p}")))`.
    pub fn io(what: impl std::fmt::Display) -> impl FnOnce(std::io::Error) -> KmError {
        move |e| KmError::Io(format!("{what}: {e}").into())
    }

    /// What it says, when it is one of the variants that say something in their own words.
    fn msg_mut(&mut self) -> Option<&mut Msg> {
        match self {
            KmError::NotFound(m)
            | KmError::Ambiguous(m)
            | KmError::Conflict(m)
            | KmError::PreconditionFailed(m)
            | KmError::Exists(m)
            | KmError::ObjectsFailed(m)
            | KmError::Unsupported(m)
            | KmError::Unavailable(m)
            | KmError::Validation(m)
            | KmError::Io(m) => Some(m),
            KmError::HashMismatch { .. } | KmError::FirstUse { .. } => None,
        }
    }

    /// The PKCS#11 return value of the module call that failed, where the token layer set it.
    #[must_use]
    pub fn rv(&self) -> Option<u64> {
        match self {
            KmError::HashMismatch { .. } | KmError::FirstUse { .. } => None,
            KmError::NotFound(m)
            | KmError::Ambiguous(m)
            | KmError::Conflict(m)
            | KmError::PreconditionFailed(m)
            | KmError::Exists(m)
            | KmError::ObjectsFailed(m)
            | KmError::Unsupported(m)
            | KmError::Unavailable(m)
            | KmError::Validation(m)
            | KmError::Io(m) => m.rv,
        }
    }

    /// The same error, carrying the return value of the module call that failed.
    #[must_use]
    pub fn with_rv(mut self, rv: Option<u64>) -> Self {
        if let Some(m) = self.msg_mut() {
            m.rv = rv;
        }
        self
    }

    /// The message of a variant that has one, return value included.
    #[must_use]
    pub fn into_msg(self) -> Option<Msg> {
        match self {
            KmError::NotFound(m)
            | KmError::Ambiguous(m)
            | KmError::Conflict(m)
            | KmError::PreconditionFailed(m)
            | KmError::Exists(m)
            | KmError::ObjectsFailed(m)
            | KmError::Unsupported(m)
            | KmError::Unavailable(m)
            | KmError::Validation(m)
            | KmError::Io(m) => Some(m),
            KmError::HashMismatch { .. } | KmError::FirstUse { .. } => None,
        }
    }
}
