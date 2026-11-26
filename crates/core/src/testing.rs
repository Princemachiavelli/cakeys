//! Helpers for the tests of every crate. They assert which check a refusal names.

use crate::{Check, KmError};

/// The value from which [`assert_fires`] reads the refusal: an error, or a result that should be
/// an error.
pub trait Refused {
    /// Returns the error, or the value that was returned instead of an error.
    ///
    /// # Errors
    ///
    /// Returns the `Debug` text of a value that is not an error.
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

/// Asserts that `result` is a refusal by `check`: an error whose [`KmError::check`] is `check`.
/// The lint in `crates/cli/tests/liar_lint.rs` accepts a unit test as the test that fires a check
/// when the test's body calls this function with that check.
///
/// # Panics
///
/// Panics when `result` is not an error, or when it is an error that names a different check or
/// no check.
#[track_caller]
pub fn assert_fires(result: &impl Refused, check: Check) {
    match result.refusal() {
        Ok(e) => assert_eq!(e.check(), Some(check), "the refusal names another check: {e}"),
        Err(passed) => panic!("no refusal by {check}: the call returned {passed}"),
    }
}
