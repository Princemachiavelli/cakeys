//! cakeys core: `keys.toml`/`keys.lock`, error kinds and content-addressed identity (CA-IDs).
//! Touches no token; backends build on it.

pub mod config;
pub mod error;
pub mod id;
pub mod pop;

pub use error::{KmError, Result};
