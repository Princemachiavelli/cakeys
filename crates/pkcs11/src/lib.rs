//! The PKCS#11 backend of cakeys. It contains the token layer over `cryptoki`, the idempotent
//! verbs, and the [`Provider`] trait, through which a crate adds module-specific behavior (quirks
//! and auto-detection). What a module *can do* is data: the capability profiles of
//! docs/CAPROBE.md. [`resolution`] resolves them for each token, and the binding layer of
//! [`binding`] is always in the stack.

pub mod binding;
pub mod chain_time;
pub mod gate;
pub mod ops;
pub mod provider;
pub mod providers;
pub mod registry;
pub mod resolution;
pub mod templates;
pub mod token;

pub use chain_time::ChainTime;
pub use provider::{
    Attributes, BoundKey, Checked, Create, Declared, Destroy, Generation, Generic, Half, Provider, SessionKey,
    Template, Topic, Via, keygen_mechanism,
};
pub use registry::{CODE_FAMILIES, Registry};
pub use resolution::Resolved;
pub use token::Token;
