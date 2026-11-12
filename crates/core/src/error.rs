//! Error classes with HTTP-like semantics and stable exit codes (see PLAN.md, "Token verbs").

#[derive(Debug, thiserror::Error)]
pub enum KmError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("ambiguous: {0}")]
    Ambiguous(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
    #[error("hash mismatch in identity of {what}:\n  specified: {expected}\n     got:    {got}")]
    HashMismatch {
        what: String,
        expected: String,
        got: String,
    },
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("unavailable: {0}")]
    Unavailable(String),
    #[error("invalid spec: {0}")]
    Validation(String),
    /// Reading or writing a file failed (exit 1, like any other failure outside the verbs).
    #[error("{0}")]
    Io(String),
}

impl KmError {
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

pub type Result<T, E = KmError> = std::result::Result<T, E>;

impl KmError {
    /// An I/O error, with what was being done: `.map_err(KmError::io(format!("reading {p}")))`.
    pub fn io(what: impl std::fmt::Display) -> impl FnOnce(std::io::Error) -> KmError {
        move |e| KmError::Io(format!("{what}: {e}"))
    }
}
