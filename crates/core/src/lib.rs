//! cakeys core: `keys.toml`/`keys.lock`, error kinds and content-addressed identity (CA-IDs).
//! Touches no token; backends build on it.

pub mod attrs;
pub mod chain;
pub mod config;
pub mod error;
#[cfg(any(test, feature = "fuzzing", kani))]
pub mod fuzzing;
pub mod hex;
pub mod id;
pub mod migrate;
pub mod plaintext;
pub mod plan;
pub mod pop;
pub mod reconcile;
pub mod secret;
pub mod sig;
// The one way a test skips, every crate's (review 2026-11-24 C-11).
#[cfg(test)]
#[path = "../../test-skip.rs"]
mod test_skip;
pub mod types;

pub use error::{EXIT_CODES, KmError, LOCK_WRITTEN, Msg, Result};
