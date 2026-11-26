//! What checked a probe's `yes` (the `by` field in the profile; docs/archive/REVIEW-2026-11-24
//! phase2-3-design §3.1): the host, with a check of its own, or nothing outside the module. Only
//! this file makes a [`Checked`] value. The host's checks make it (a comparison with what the
//! host knows, or a verification that the host ran), or [`Checked::unverified`] makes it. No
//! probe family can therefore record that the host checked something that it did not check
//! (review 2026-11-24 E-3, E-4). The test `checked_is_made_only_here` keeps the constructor in
//! this file.

use cakeys_profile::By;

/// What checked a `yes` ([`super::Draft::yes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Checked {
    by: By,
}

impl Checked {
    /// Compares on the host what the module gave (`got`) with what the host knows (`want`): a
    /// value read back, a key's public key, a check value or a count. Returns a host check when
    /// they are equal, and `None` when they differ.
    pub(crate) fn same<T: PartialEq + ?Sized>(got: &T, want: &T) -> Option<Checked> {
        (got == want).then_some(Checked { by: By::Host })
    }

    /// Converts the result of a check that the host ran (a signature or a proof of possession
    /// that it verified, or a value that it computed again) into a host check.
    ///
    /// # Errors
    ///
    /// Returns the error of `check` when the check did not pass.
    pub(crate) fn verified<E>(check: Result<(), E>) -> Result<Checked, E> {
        check.map(|()| Checked { by: By::Host })
    }

    /// Records that nothing outside the module checked the result, for example when only the
    /// module's own round trip or its own commitment shows it.
    pub(crate) const fn unverified() -> Checked {
        Checked { by: By::Unverified }
    }

    /// Returns who checked the result, as the profile records it.
    pub(crate) const fn by(self) -> By {
        self.by
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only this file uses the constructor. Every other source file of the crate makes a
    /// [`Checked`] with one of the functions above, and never with the struct literal
    /// (phase2-3-design §3.1, 2: "`Checked` cannot be faked").
    #[test]
    fn checked_is_made_only_here() {
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = vec![src];
        let mut offenders = Vec::new();
        while let Some(path) = files.pop() {
            if path.is_dir() {
                files.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
            } else if path.extension().is_some_and(|e| e == "rs") && !path.ends_with("probe/checked.rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                if text.contains("Checked {") {
                    offenders.push(path.display().to_string());
                }
            }
        }
        assert!(offenders.is_empty(), "a Checked made outside checked.rs: {offenders:?}");
        assert_eq!(Checked::same(&1, &1).map(Checked::by), Some(By::Host));
        assert_eq!(Checked::same(&1, &2), None);
        assert_eq!(Checked::verified(Err::<(), _>("no")), Err("no"));
        assert_eq!(Checked::unverified().by(), By::Unverified);
    }
}
