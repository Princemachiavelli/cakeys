//! Helpers for the tests of every crate: what a refusal must name.

use crate::{Check, KmError};

/// What [`assert_fires`] reads the refusal from: an error, or a result that should be one.
pub trait Refused {
    /// The error, or what was returned instead of one.
    ///
    /// # Errors
    ///
    /// The `Debug` text of a value that is not an error.
    fn refusal(&self) -> Result<&KmError, String>;
}

impl Refused for KmError {
    fn refusal(&self) -> Result<&KmError, String> {
        Ok(self)
    }
}

impl<T: std::fmt::Debug> Refused for crate::Result<T> {
    fn refusal(&self) -> Result<&KmError, String> {
        match self {
            Ok(v) => Err(format!("{v:?}")),
            Err(e) => Ok(e),
        }
    }
}

/// Assert that `result` is a refusal by `check`: an error whose [`KmError::check`] is `check`.
/// The liar lint (crates/cli/tests/liar_lint.rs) accepts a unit test as the one that fires a
/// check when the test's body calls this function with that check.
///
/// # Panics
///
/// When `result` is no error, or an error that names another check or none.
#[track_caller]
pub fn assert_fires(result: &impl Refused, check: Check) {
    match result.refusal() {
        Ok(e) => assert_eq!(e.check(), Some(check), "the refusal names another check: {e}"),
        Err(passed) => panic!("no refusal by {check}: the call returned {passed}"),
    }
}
