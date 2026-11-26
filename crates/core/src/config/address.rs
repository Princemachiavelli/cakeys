//! The resolution of a verb's address (`[<object>] [--spec] [--token]`, docs/CAKEYS.md) against
//! keys.toml (review 2026-11-23 A-7).

use super::Config;
use crate::Check;
use crate::error::{KmError, Reason, Result};

impl Config {
    /// Returns the (spec, token) pairs that a verb's address selects (`[<object>] [--spec]
    /// [--token]`, docs/CAKEYS.md). A part that is left out selects every value of that part. An
    /// empty result is not an error.
    ///
    /// # Errors
    ///
    /// Returns `Validation` (17) when a part names something that keys.toml does not have, or
    /// when `--spec` realises a different object than the named object.
    pub fn select(&self, object: Option<&str>, spec: Option<&str>, token: Option<&str>) -> Result<Vec<(&str, &str)>> {
        if let Some(o) = object
            && !self.objects.contains_key(o)
        {
            return Err(KmError::Validation(format!("unknown object '{o}'").into()));
        }
        if let Some(s) = spec {
            let Some(cfg) = self.specs.get(s) else {
                return Err(KmError::Validation(format!("unknown spec '{s}'").into()));
            };
            if let Some(o) = object.filter(|o| *o != cfg.object) {
                return Err(KmError::Validation(format!("spec '{s}' realises '{}', not '{o}'", cfg.object).into()));
            }
        }
        if let Some(t) = token
            && !self.tokens.contains_key(t)
        {
            return Err(KmError::Validation(format!("unknown token '{t}'").into()));
        }
        Ok(self
            .specs
            .iter()
            .filter(|(n, s)| spec.is_none_or(|w| w == n.as_str()) && object.is_none_or(|o| o == s.object))
            .flat_map(|(n, s)| s.tokens.keys().map(move |t| (n.as_str(), t.as_str())))
            .filter(|(_, t)| token.is_none_or(|w| w == *t))
            .collect())
    }

    /// Returns the one (spec, token) pair that a verb's address names. The address names an
    /// object or a `--spec`, and the other parts narrow the selection when the object is realised
    /// more than once.
    ///
    /// # Errors
    ///
    /// Returns `Validation` (17) when neither an object nor `--spec` is given, in the cases of
    /// [`Self::select`], or when no pair matches. Returns `Ambiguous` (12) when several pairs
    /// match, so that `--spec` or `--token` must narrow the selection.
    pub fn address(&self, object: Option<&str>, spec: Option<&str>, token: Option<&str>) -> Result<(String, String)> {
        if object.is_none() && spec.is_none() {
            return Err(KmError::Validation("name an object, or a spec with --spec".into()));
        }
        let pairs = self.select(object, spec, token)?;
        let what = object.map_or_else(|| format!("spec '{}'", spec.unwrap_or_default()), |o| format!("object '{o}'"));
        match pairs.as_slice() {
            [(s, t)] => Ok(((*s).to_owned(), (*t).to_owned())),
            [] => Err(KmError::Validation(
                format!(
                    "no spec places {what}{}{}",
                    spec.filter(|_| object.is_some()).map_or_else(String::new, |s| format!(" through spec '{s}'")),
                    token.map_or_else(String::new, |t| format!(" on token '{t}'"))
                )
                .into(),
            )),
            _ => Err(KmError::Ambiguous(Reason::check(
                Check::AddressUnique,
                format!("{what} has several (spec, token) pairs {pairs:?}; pass --spec/--token"),
            ))),
        }
    }
}
