//! When an attestation chain's certificates are judged valid: the policy `attest` and `check`
//! apply to their dates. Not a provider's: every attesting provider asks it (review 2026-11-23
//! B-5).

use cakeys_core::{KmError, Result};

/// When the certificates of an attestation chain must be valid (ISSUES.md B8). `check` holds
/// every link to its validity period, at the system clock's time unless told another
/// (`--at`, `--ignore-validity`); every other verb (`lock`, `create`, `resolve`, camigrate) judges
/// the dates by the clock too but only warns ([`ChainTime::Warn`]): `check` is what enforces. There is
/// no default: every token open names one ([`crate::Token::open`]), so no reader of
/// attestations skips the dates by forgetting to ask (review D5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainTime {
    /// The dates are not checked.
    Unchecked,
    /// Valid at this time: seconds since the Unix epoch, UTC.
    At(u64),
    /// Judged at this time, but a chain whose only fault is its dates is accepted with a warning
    /// ([`warning`](crate::provider::Attested::warning)).
    Warn(u64),
    /// Asked for now, and the system clock reads before the Unix epoch: there is no time to judge
    /// the dates by. [`ChainTime::verify`] refuses, naming the clock, or with `warn` (a verb
    /// other than `check`) verifies the chain without its dates and warns so.
    NoClock {
        /// Whether a chain is accepted, with a warning, rather than refused.
        warn: bool,
    },
}

/// What [`ChainTime::NoClock`] says.
const NO_CLOCK: &str = "the system clock reads before 1970, so the attestation chain's dates cannot be judged: set \
     the clock, or `check --at <time>` judges them at another time (`--ignore-validity` skips them)";

impl ChainTime {
    /// Now, by the system clock. Never `SOURCE_DATE_EPOCH`: Nix's stdenv sets it to 1980 in
    /// every build, where every chain would be not yet valid.
    #[must_use]
    pub fn now() -> Self {
        Self::by_clock(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH), false)
    }

    /// Now, by the system clock, warning only: what every verb but `check` judges dates with.
    #[must_use]
    pub fn warn_now() -> Self {
        Self::by_clock(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH), true)
    }

    /// The time the clock's reading `since` the epoch gives, refusing (or with `warn`, warning)
    /// for a clock before it: never the epoch itself, where every chain is "not yet valid" and
    /// nothing names the clock (provider.rs F2).
    fn by_clock(since: std::result::Result<std::time::Duration, std::time::SystemTimeError>, warn: bool) -> Self {
        match (since, warn) {
            (Ok(d), false) => ChainTime::At(d.as_secs()),
            (Ok(d), true) => ChainTime::Warn(d.as_secs()),
            (Err(_), warn) => ChainTime::NoClock { warn },
        }
    }

    /// Verify a chain by `verify`, given the time to hold its dates to (`None`: unchecked). Under
    /// [`ChainTime::Warn`], a chain that fails only at that time (it verifies without the dates)
    /// is accepted, with the dated failure as the warning; any other failure is the undated one.
    /// [`ChainTime::NoClock`] has no time: refused, or (warning) verified without the dates.
    ///
    /// # Errors
    ///
    /// Whatever `verify` returns, as above; `Unavailable` for [`ChainTime::NoClock`] that refuses.
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

    /// An RFC 3339 time in UTC, `YYYY-MM-DDTHH:MM:SSZ` (`check --at`).
    ///
    /// # Errors
    ///
    /// `Validation` (17) for anything else.
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

    /// Every verb but `check` warns about a chain's dates, `check` refuses it, `--ignore-validity`
    /// skips them; a chain wrong for any other reason is refused under each (review D5).
    #[test]
    fn a_chain_out_of_its_dates_warns_where_check_refuses() {
        use super::ChainTime::{At, Unchecked, Warn};
        let dated = |at: Option<u64>| match at {
            Some(t) if t > 100 => Err(KmError::Conflict("'slot' is not valid at 101".into())),
            _ => Ok("attested"),
        };
        assert_eq!(Warn(50).verify(dated).unwrap(), ("attested", None));
        let (v, warning) = Warn(101).verify(dated).unwrap();
        assert_eq!((v, warning.as_deref()), ("attested", Some("conflict: 'slot' is not valid at 101")));
        assert_eq!(At(101).verify(dated).unwrap_err().exit_code(), 13);
        assert_eq!(Unchecked.verify(dated).unwrap(), ("attested", None));
        let unpinned = |_: Option<u64>| -> Result<&str> { Err(KmError::Conflict("signed by no pinned root".into())) };
        for when in [Warn(101), At(101), Unchecked] {
            assert!(when.verify(unpinned).unwrap_err().to_string().contains("no pinned root"), "{when:?}");
        }
    }

    /// A system clock before 1970 is no time to judge dates by (provider.rs F2): `check` refuses
    /// naming the clock, every other verb verifies without the dates and warns so; never the
    /// epoch, where every chain is "not yet valid" and nothing says why.
    #[test]
    fn a_clock_before_the_epoch_is_named() {
        use std::time::{Duration, UNIX_EPOCH};
        let before = UNIX_EPOCH.duration_since(UNIX_EPOCH + Duration::from_secs(1));
        assert_eq!(ChainTime::by_clock(before.clone(), false), ChainTime::NoClock { warn: false });
        assert_eq!(ChainTime::by_clock(before, true), ChainTime::NoClock { warn: true });
        assert_eq!(ChainTime::by_clock(Ok(Duration::from_secs(7)), false), ChainTime::At(7));
        assert_eq!(ChainTime::by_clock(Ok(Duration::from_secs(7)), true), ChainTime::Warn(7));
        let dated = |at: Option<u64>| at.map_or(Ok("attested"), |_| Err(KmError::Conflict("not valid at 0".into())));
        let e = ChainTime::NoClock { warn: false }.verify(dated).unwrap_err();
        assert!(matches!(&e, KmError::Unavailable(m) if m.contains("system clock reads before 1970")), "{e}");
        let (v, warning) = ChainTime::NoClock { warn: true }.verify(dated).unwrap();
        assert_eq!(v, "attested");
        assert!(warning.is_some_and(|w| w.contains("system clock")));
    }
}
