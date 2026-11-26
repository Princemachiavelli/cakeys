//! The time at which the certificates of an attestation chain must be valid. This is the policy
//! that `attest` and `check` apply to the certificates' dates. It does not belong to a provider,
//! because every attesting provider uses it (review 2026-11-23 B-5).

use cakeys_core::{KmError, Result};

/// The time at which the certificates of an attestation chain must be valid (ISSUES.md B8).
/// `check` requires every certificate in the chain to be within its validity period at the
/// system clock's time, unless an option gives another time (`--at`) or turns the check off
/// (`--ignore-validity`). Every other verb (`lock`, `create`, `resolve`, camigrate) also checks
/// the dates against the clock, but only warns ([`ChainTime::Warn`]), so only `check` enforces
/// them. There is no default value: every token open names one ([`crate::Token::open`]), so no
/// code that reads attestations skips the dates because it forgot to ask (review D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainTime {
    /// The dates are not checked.
    Unchecked,
    /// The chain must be valid at this time, in seconds since the Unix epoch, UTC.
    At(u64),
    /// The dates are checked at this time, but a chain whose only fault is its dates is accepted
    /// with a warning ([`warning`](crate::provider::Attested::warning)).
    Warn(u64),
    /// The current time was requested, but the system clock reads a time before the Unix epoch,
    /// so there is no time against which to check the dates. [`ChainTime::verify`] refuses with
    /// an error that names the clock. With `warn` (a verb other than `check`), it verifies the
    /// chain without its dates and gives a warning that says so.
    NoClock {
        /// Whether a chain is accepted with a warning instead of being refused.
        warn: bool,
    },
}

/// The message for [`ChainTime::NoClock`].
const NO_CLOCK: &str = "the system clock reads before 1970, so the attestation chain's dates cannot be judged: set \
     the clock, or `check --at <time>` judges them at another time (`--ignore-validity` skips them)";

impl ChainTime {
    /// Returns the current time from the system clock. It never uses `SOURCE_DATE_EPOCH`,
    /// because Nix's stdenv sets that variable to 1980 in every build, and at that time every
    /// chain would be not yet valid.
    #[must_use]
    pub fn now() -> Self {
        Self::by_clock(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH), false)
    }

    /// Returns the current time from the system clock, with warnings only. Every verb except
    /// `check` checks dates with this value.
    #[must_use]
    pub fn warn_now() -> Self {
        Self::by_clock(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH), true)
    }

    /// Returns the time that the clock's reading `since` the epoch gives. For a clock that reads
    /// before the epoch, it returns [`ChainTime::NoClock`], which refuses (or, with `warn`,
    /// warns). It never returns the epoch itself, because at that time every chain is "not yet
    /// valid" and no message names the clock (provider.rs F2).
    fn by_clock(since: std::result::Result<std::time::Duration, std::time::SystemTimeError>, warn: bool) -> Self {
        match (since, warn) {
            (Ok(d), false) => ChainTime::At(d.as_secs()),
            (Ok(d), true) => ChainTime::Warn(d.as_secs()),
            (Err(_), warn) => ChainTime::NoClock { warn },
        }
    }

    /// Verifies a chain with `verify`, which receives the time at which the dates must be valid
    /// (`None` means that the dates are not checked). Under [`ChainTime::Warn`], a chain that
    /// fails only at that time (it verifies without the dates) is accepted, and the failure with
    /// the dates becomes the warning. Any other failure is reported as the failure without the
    /// dates. [`ChainTime::NoClock`] has no time, so it refuses, or, with `warn`, it verifies the
    /// chain without the dates.
    ///
    /// # Errors
    ///
    /// Whatever `verify` returns, as described above. `Unavailable` for a
    /// [`ChainTime::NoClock`] that refuses.
    pub fn verify<T>(self, verify: impl Fn(Option<u64>) -> Result<T>) -> Result<(T, Option<String>)> {
        match self {
            ChainTime::Unchecked => verify(None).map(|v| (v, None)),
            ChainTime::At(t) => verify(Some(t)).map(|v| (v, None)),
            ChainTime::Warn(t) => match verify(Some(t)) {
                Ok(v) => Ok((v, None)),
                Err(dated) => verify(None).map(|v| (v, Some(dated.to_string()))),
            },
            ChainTime::NoClock { warn: false } => Err(KmError::Unavailable(NO_CLOCK.into())),
            ChainTime::NoClock { warn: true } => verify(None).map(|v| (v, Some(NO_CLOCK.to_owned()))),
        }
    }

    /// Parses an RFC 3339 time in UTC, `YYYY-MM-DDTHH:MM:SSZ` (`check --at`).
    ///
    /// # Errors
    ///
    /// `Validation` (exit 17) for any other text.
    pub fn parse(s: &str) -> Result<Self> {
        let t: der::DateTime = s.parse().map_err(|e| {
            KmError::Validation(format!("--at {s}: not an RFC 3339 time in UTC (YYYY-MM-DDTHH:MM:SSZ): {e}").into())
        })?;
        Ok(ChainTime::At(t.unix_duration().as_secs()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::{Check, Reason};

    /// Every verb except `check` warns about a chain's dates, `check` refuses the chain, and
    /// `--ignore-validity` skips the dates. A chain that is wrong for any other reason is refused
    /// in every case (review D5).
    #[test]
    fn a_chain_out_of_its_dates_warns_where_check_refuses() {
        use super::ChainTime::{At, Unchecked, Warn};
        let dated = |at: Option<u64>| match at {
            Some(t) if t > 100 => {
                Err(KmError::Conflict(Reason::check(Check::ChainValidity, "'slot' is not valid at 101")))
            }
            _ => Ok("attested"),
        };
        assert_eq!(Warn(50).verify(dated).unwrap(), ("attested", None));
        let (v, warning) = Warn(101).verify(dated).unwrap();
        assert_eq!((v, warning.as_deref()), ("attested", Some("conflict: 'slot' is not valid at 101")));
        assert_eq!(At(101).verify(dated).unwrap_err().exit_code(), 13);
        assert_eq!(Unchecked.verify(dated).unwrap(), ("attested", None));
        let unpinned = |_: Option<u64>| -> Result<&str> {
            Err(KmError::Conflict(Reason::check(Check::ChainAnchor, "signed by no pinned root")))
        };
        for when in [Warn(101), At(101), Unchecked] {
            assert!(when.verify(unpinned).unwrap_err().to_string().contains("no pinned root"), "{when:?}");
        }
    }

    /// A system clock that reads before 1970 gives no time against which to check dates
    /// (provider.rs F2). `check` refuses with an error that names the clock, and every other verb
    /// verifies without the dates and gives a warning that says so. The epoch is never used,
    /// because at that time every chain is "not yet valid" and no message says why.
    #[test]
    fn a_clock_before_the_epoch_is_named() {
        use std::time::{Duration, UNIX_EPOCH};
        let before = UNIX_EPOCH.duration_since(UNIX_EPOCH + Duration::from_secs(1));
        assert_eq!(ChainTime::by_clock(before.clone(), false), ChainTime::NoClock { warn: false });
        assert_eq!(ChainTime::by_clock(before, true), ChainTime::NoClock { warn: true });
        assert_eq!(ChainTime::by_clock(Ok(Duration::from_secs(7)), false), ChainTime::At(7));
        assert_eq!(ChainTime::by_clock(Ok(Duration::from_secs(7)), true), ChainTime::Warn(7));
        let dated = |at: Option<u64>| {
            at.map_or(Ok("attested"), |_| Err(KmError::Conflict(Reason::check(Check::ChainValidity, "not valid at 0"))))
        };
        let e = ChainTime::NoClock { warn: false }.verify(dated).unwrap_err();
        assert!(matches!(&e, KmError::Unavailable(m) if m.contains("system clock reads before 1970")), "{e}");
        let (v, warning) = ChainTime::NoClock { warn: true }.verify(dated).unwrap();
        assert_eq!(v, "attested");
        assert!(warning.is_some_and(|w| w.contains("system clock")));
    }
}
