//! Error classes with HTTP-like semantics and stable exit codes (docs/CAKEYS.md).

/// Every failure cakeys reports, each with a stable exit code (docs/CAKEYS.md, "Exit codes").
#[derive(Debug, thiserror::Error)]
pub enum KmError {
    /// Nothing under the locator (11).
    #[error("not found: {0}")]
    NotFound(String),
    /// Several objects match (12).
    #[error("ambiguous: {0}")]
    Ambiguous(String),
    /// The object is not what the spec says: wrong type or policy, a failed proof of possession,
    /// a foreign public key under the locator (13).
    #[error("conflict: {0}")]
    Conflict(String),
    /// The realisation moved since it was recorded: a spec or policy change, a downgrade, a
    /// replaced object (14).
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
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
    /// The token cannot do what the spec needs (15).
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The token cannot be used now: absent, its PIN locked, its module not loadable (16).
    #[error("unavailable: {0}")]
    Unavailable(String),
    /// Invalid config, lock, spec or token options (17).
    #[error("invalid spec: {0}")]
    Validation(String),
    /// Reading or writing a file failed (exit 1, like any other failure outside the verbs).
    #[error("{0}")]
    Io(String),
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
            KmError::Io(_) => 1,
        }
    }
}

/// A result whose error is a [`KmError`].
pub type Result<T, E = KmError> = std::result::Result<T, E>;

impl KmError {
    /// An I/O error, with what was being done: `.map_err(KmError::io(format!("reading {p}")))`.
    pub fn io(what: impl std::fmt::Display) -> impl FnOnce(std::io::Error) -> KmError {
        move |e| KmError::Io(format!("{what}: {e}"))
    }
}
