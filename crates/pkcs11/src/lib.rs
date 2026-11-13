//! cakeys PKCS#11 backend: the token layer over `cryptoki`, the idempotent verbs, and the
//! [`Provider`] trait through which a crate adds module-specific behaviour (quirks, auto-detection).
//! What a module *can do* is data — the capability profiles of docs/PROVIDERS.md — resolved
//! per token in [`resolution`] with the binding layer of [`binding`] always in the stack.

pub mod binding;
pub mod gate;
pub mod migrate;
pub mod ops;
pub mod probe;
pub mod provider;
pub mod providers;
pub mod resolution;
pub mod token;

pub use provider::{Generic, Provider, Registry};
pub use resolution::Resolved;
pub use token::Token;
