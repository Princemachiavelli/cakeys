//! What checked a probe's `yes` (`by` in the profile, docs/archive/REVIEW-2026-11-24
//! phase2-3-design §3.1): the host, by a check of its own, or nothing outside the module. A
//! [`Checked`] is made only here, by the host's checks themselves (a comparison with what the
//! host knows, a verification it ran) or as [`Checked::unverified`], so no probe family says the
//! host checked what it did not (review 2026-11-24 E-3, E-4). `checked_is_made_only_here` keeps
//! its constructor in this file.

use cakeys_profile::By;

/// What checked a `yes` ([`super::Draft::yes`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Checked {
    by: By,
}

impl Checked {
    /// What the module gave (`got`), compared on the host with what the host knows (`want`): a
    /// value read back, a key's public key, a check value, a count. `None` when they differ.
    pub(crate) fn same<T: PartialEq + ?Sized>(got: &T, want: &T) -> Option<Checked> {
        (got == want).then_some(Checked { by: By::Host })
    }

    /// A check the host ran: a signature or proof of possession it verified, a value it
    /// computed again. Its error when it did not pass.
    ///
    /// # Errors
    ///
    /// `check`'s own.
    pub(crate) fn verified<E>(check: Result<(), E>) -> Result<Checked, E> {
        check.map(|()| Checked { by: By::Host })
    }

    /// Nothing outside the module checked it: its own round trip, its own commitment.
    pub(crate) const fn unverified() -> Checked {
        Checked { by: By::Unverified }
    }

    /// Who checked it, as the profile says it.
    pub(crate) const fn by(self) -> By {
        self.by
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constructor is this file's: every other source of the crate makes a [`Checked`] by
    /// one of the functions above, never by the literal (phase2-3-design §3.1, 2: "`Checked`
    /// cannot be faked").
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
