//! cakeys core: `keys.toml`/`keys.lock`, error kinds and content-addressed identity (CA-IDs).
//! Touches no token; backends build on it.

pub mod attrs;
pub mod config;
pub mod error;
pub mod id;
pub mod migrate;
pub mod plan;
pub mod pop;
pub mod reconcile;
pub mod sig;
pub mod types;

pub use error::{KmError, Result};
