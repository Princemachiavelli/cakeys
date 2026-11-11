//! key-mgmnt PKCS#11 backend: the token layer over `cryptoki`, the idempotent verbs, and the
//! [`Provider`] trait through which a crate adds module-specific behaviour (quirks, auto-detection).

pub mod ops;
pub mod provider;
pub mod token;

pub use provider::{Generic, Provider, Registry};
pub use token::Token;
