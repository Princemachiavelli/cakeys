//! The cakeys core: `keys.toml` and `keys.lock`, the error kinds, and the content-addressed
//! identity (CA-IDs). This crate never accesses a token, and the backends build on it.

pub mod attrs;
pub mod chain;
pub mod check;
pub mod config;
pub mod error;
#[cfg(any(test, feature = "fuzzing", kani))]
pub mod fuzzing;
pub mod hex;
pub mod id;
pub mod known;
pub mod migrate;
pub mod plaintext;
pub mod plan;
pub mod pop;
pub mod reconcile;
pub mod secret;
pub mod sig;
pub mod testing;
// The only way in which a test skips, shared by every crate (review 2026-11-24 C-11).
#[cfg(test)]
#[path = "../../test-skip.rs"]
mod test_skip;
pub mod types;

pub use check::{Check, Rule};
pub use error::{EXIT_CODES, KmError, LOCK_WRITTEN, Msg, Reason, Result};
