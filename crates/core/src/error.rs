//! The error classes, with meanings similar to HTTP status codes and with exit codes that do not
//! change (docs/CAKEYS.md).

use crate::check::{Check, Rule};
use std::fmt;

/// The message of a [`KmError`], with the PKCS#11 return value that caused it when a module call
/// failed (`CK_RV`, a `CK_ULONG`: 64 bits on every platform for which this crate builds), the
/// plan's rule that refused if one did ([`Rule`]), and the check that refused if one did
/// ([`Check`]). It displays only its text. The return value, the rule and the check are for code
/// to match on (ISSUES.md Q3), and they are never part of a message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Msg {
    text: String,
    rv: Option<u64>,
    rule: Option<Rule>,
    check: Option<Check>,
}

impl Msg {
    /// Returns the return value of the module call that failed, if a module call failed.
    #[must_use]
    pub fn rv(&self) -> Option<u64> {
        self.rv
    }

    /// Returns the text as an owned `String`.
    #[must_use]
    pub fn into_text(self) -> String {
        self.text
    }

    /// Returns a message with another text in place of this one, and with the same return value,
    /// rule and check. It is for a message that is rebuilt around the original message.
    #[must_use]
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = text.into();
        self
    }

    /// Returns the same text with the return value of the module call that failed.
    #[must_use]
    pub fn with_rv(mut self, rv: Option<u64>) -> Self {
        self.rv = rv;
        self
    }

    /// Returns the plan's rule that refused, if one did.
    #[must_use]
    pub fn rule(&self) -> Option<Rule> {
        self.rule
    }

    /// Returns the check that refused, if one did.
    #[must_use]
    pub fn check(&self) -> Option<Check> {
        self.check
    }

    /// Returns the same text, with `check` as the check that refused. A refusal with exit 11, 15
    /// or 16 names its check this way. The three variants that take a [`Reason`] name their
    /// check when they are created.
    #[must_use]
    pub fn with_check(mut self, check: Check) -> Self {
        self.check = Some(check);
        self
    }
}

impl std::ops::Deref for Msg {
    type Target = str;
    fn deref(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl From<String> for Msg {
    fn from(text: String) -> Self {
        Msg { text, rv: None, rule: None, check: None }
    }
}

impl From<&str> for Msg {
    fn from(text: &str) -> Self {
        text.to_owned().into()
    }
}

impl PartialEq<str> for Msg {
    fn eq(&self, other: &str) -> bool {
        self.text == other
    }
}

impl PartialEq<&str> for Msg {
    fn eq(&self, other: &&str) -> bool {
        self.text == *other
    }
}

/// The reason why a [`KmError::Conflict`], [`KmError::Ambiguous`] or
/// [`KmError::PreconditionFailed`] was returned. It holds the message and either the check or the
/// plan's rule that refused, or the statement that the input is malformed (a structure that does
/// not parse). The only constructors are [`Reason::check`], [`Reason::rule`] and
/// [`Reason::malformed`], and there is no `From<String>`, so every place that creates one of
/// these three errors must say which check refused. The JSON rows print that name
/// ([`KmError::check`]), and a malformed input names none. `Reason::malformed` is allowed only in
/// the modules that parse a structure (`malformed_only_in_parsers` in
/// crates/core/tests/checks.rs). A `Reason` dereferences to its [`Msg`], so `m.contains(…)` reads
/// its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason(Msg);

impl Reason {
    /// Returns a refusal by `check` with the message `text`.
    #[must_use]
    pub fn check(check: Check, text: impl Into<String>) -> Reason {
        Reason(Msg::from(text.into()).with_check(check))
    }

    /// Returns a refusal by the plan's rule `rule` with the message `text`.
    #[must_use]
    pub fn rule(rule: Rule, text: impl Into<String>) -> Reason {
        Reason(Msg { rule: Some(rule), ..Msg::from(text.into()) })
    }

    /// Returns a refusal of an input that does not parse as the expected structure, with the
    /// message `text`. It names no check.
    #[must_use]
    pub fn malformed(text: impl Into<String>) -> Reason {
        Reason(Msg::from(text.into()))
    }
}

impl std::ops::Deref for Reason {
    type Target = Msg;
    fn deref(&self) -> &Msg {
        &self.0
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl PartialEq<str> for Reason {
    fn eq(&self, other: &str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<&str> for Reason {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

/// Every failure that cakeys reports, each with an exit code that does not change (docs/CAKEYS.md,
/// "Exit codes").
#[derive(Debug, Clone, thiserror::Error)]
pub enum KmError {
    /// No object is under the locator (11).
    #[error("not found: {0}")]
    NotFound(Msg),
    /// Several objects match (12).
    #[error("ambiguous: {0}")]
    Ambiguous(Reason),
    /// The object is not what the spec declares: a wrong type or policy, a failed proof of
    /// possession, or the public key of another key under the locator (13).
    #[error("conflict: {0}")]
    Conflict(Reason),
    /// The realisation changed since it was recorded: a change of the spec or the policy, a
    /// downgrade, or a replaced object (14).
    #[error("precondition failed: {0}")]
    PreconditionFailed(Reason),
    /// The token holds other material than the lock pins (10).
    #[error("hash mismatch in identity of {what}:\n  specified: {expected}\n     got:    {got}")]
    HashMismatch {
        /// The object that was identified.
        what: String,
        /// The ID that the lock pins.
        expected: String,
        /// The ID computed from the token.
        got: String,
        /// The check that compared the two IDs: [`Check::IdentityMaterial`] for the material,
        /// [`Check::LockAttestationId`] for an attestation's ID.
        check: Check,
    },
    /// First use: the lock pins no ID to compare with yet (18; similar to HTTP's 428 Precondition
    /// Required). It reports the computed ID, as a Nix fixed-output derivation with a fake hash
    /// reports the hash that it got. It is not exit 10, because a mismatch against a pinned ID is
    /// a security event, and this is only the state before `lock` records the `got:` ID.
    #[error(
        "first use of {what}: the lock pins no identity for it yet; review, then `lock` records it\n     got:    {got}"
    )]
    FirstUse {
        /// The object that was identified.
        what: String,
        /// The ID computed from the token.
        got: String,
    },
    /// `create` found its object already under the locator, so it created nothing (19).
    #[error("already exists: {0}")]
    Exists(Msg),
    /// `check --token`: an object on the token failed its check. The output lists each failure
    /// with its own code (20).
    #[error("objects failed: {0}")]
    ObjectsFailed(Msg),
    /// The token cannot do what the spec needs (15).
    #[error("unsupported: {0}")]
    Unsupported(Msg),
    /// The token cannot be used now: it is absent, its PIN is locked, or its module cannot be
    /// loaded (16).
    #[error("unavailable: {0}")]
    Unavailable(Msg),
    /// An invalid configuration, lock, spec or token options (17). The message says which one is
    /// invalid: every error in keys.toml or keys.lock starts with the file's name.
    #[error("invalid: {0}")]
    Validation(Msg),
    /// The lock cannot be written (21). Either a run that writes the lock was refused before it
    /// touched any token (a read-only lock or directory, or a Nix build sandbox), or a save failed
    /// partway through, and the token may then hold an object that the lock does not record.
    #[error("lock cannot be written: {0}")]
    LockUnwritable(Msg),
    /// Reading or writing a file failed (exit 1, as for any other failure outside the verbs).
    #[error("{0}")]
    Io(Msg),
}

impl KmError {
    /// Returns the process exit code with which this error ends a run.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            KmError::HashMismatch { .. } => 10,
            KmError::NotFound(_) => 11,
            KmError::Ambiguous(_) => 12,
            KmError::Conflict(_) => 13,
            KmError::PreconditionFailed(_) => 14,
            KmError::Unsupported(_) => 15,
            KmError::Unavailable(_) => 16,
            KmError::Validation(_) => 17,
            KmError::FirstUse { .. } => 18,
            KmError::Exists(_) => 19,
            KmError::ObjectsFailed(_) => 20,
            KmError::LockUnwritable(_) => 21,
            KmError::Io(_) => 1,
        }
    }

    /// Returns one error of every variant, with the variant's name. The exit-code tests check the
    /// docs and the tables against this list. The match below has no wildcard, so a new variant
    /// does not compile until it is also listed here (review 2026-11-23 A-16: the tests used to
    /// read this file as text).
    #[doc(hidden)]
    #[must_use]
    pub fn every_variant() -> Vec<(&'static str, KmError)> {
        let s = String::new;
        let all = vec![
            (
                "HashMismatch",
                KmError::HashMismatch { what: s(), expected: s(), got: s(), check: Check::IdentityMaterial },
            ),
            ("FirstUse", KmError::FirstUse { what: s(), got: s() }),
            ("NotFound", KmError::NotFound("".into())),
            ("Ambiguous", KmError::Ambiguous(Reason::check(Check::LocatorUnique, ""))),
            ("Conflict", KmError::Conflict(Reason::check(Check::ObjectType, ""))),
            ("PreconditionFailed", KmError::PreconditionFailed(Reason::check(Check::LockSpec, ""))),
            ("Unsupported", KmError::Unsupported("".into())),
            ("Unavailable", KmError::Unavailable("".into())),
            ("Validation", KmError::Validation("".into())),
            ("Exists", KmError::Exists("".into())),
            ("ObjectsFailed", KmError::ObjectsFailed("".into())),
            ("LockUnwritable", KmError::LockUnwritable("".into())),
            ("Io", KmError::Io("".into())),
        ];
        for (_, e) in &all {
            match e {
                KmError::HashMismatch { .. }
                | KmError::FirstUse { .. }
                | KmError::NotFound(_)
                | KmError::Ambiguous(_)
                | KmError::Conflict(_)
                | KmError::PreconditionFailed(_)
                | KmError::Unsupported(_)
                | KmError::Unavailable(_)
                | KmError::Validation(_)
                | KmError::Exists(_)
                | KmError::ObjectsFailed(_)
                | KmError::LockUnwritable(_)
                | KmError::Io(_) => {}
            }
        }
        all
    }
}

/// The exit code of a run that wrote the lock, which means that it created the lock
/// (`--new-lock`) or changed it. The code is not 0, so that a consumer notices every change to
/// the lock and reviews and commits it (review 2026-11-23 C-16). A run that fails after it wrote
/// the lock also exits with this code, and the failed pair's row holds the failure's code;
/// otherwise the failure's code would hide the written lock (review 2026-11-24 L5).
pub const LOCK_WRITTEN: u8 = 22;

/// Every exit code of the three tools, in order, with its meaning. This is the one table that
/// every `--help` prints (review 2026-11-23 C-10), and the table "Exit codes" in docs/CAKEYS.md
/// lists the same codes (`the_exit_code_table_lists_every_code`).
pub const EXIT_CODES: [(u8, &str); 16] = [
    (0, "ok"),
    (1, "I/O or other failure"),
    (2, "command-line usage"),
    (10, "hash mismatch: the token holds other material than the lock pins"),
    (11, "not found under the locator"),
    (12, "ambiguous: several objects match"),
    (13, "conflict: the object is not what the spec says"),
    (14, "precondition failed: the realisation moved"),
    (15, "unsupported: the token cannot do what the spec needs"),
    (16, "unavailable: the token, or a PIN or passphrase source, cannot be used now"),
    (17, "invalid config, lock, spec or options"),
    (18, "first use: the lock pins nothing to compare with yet"),
    (19, "already exists: create found a key the lock does not pin under the locator"),
    (20, "objects failed: check --token lists each failure with its own code"),
    (21, "the lock cannot be written (read-only, or inside a Nix build)"),
    (LOCK_WRITTEN, "the lock was written: review and commit it, and retry any failed row"),
];

/// A result whose error is a [`KmError`].
pub type Result<T, E = KmError> = std::result::Result<T, E>;

/// Evaluates to `Some` with the [`Msg`] of a variant that has its own message text, and to `None`
/// for the two variants that format their own fields. This macro is the only list of those
/// variants. It matches `$e` by reference, by mutable reference or by value, as `$e` is given. A
/// [`Reason`]'s message is its [`Msg`].
macro_rules! said {
    ($e:expr) => {
        match $e {
            KmError::Ambiguous(Reason(m)) | KmError::Conflict(Reason(m)) | KmError::PreconditionFailed(Reason(m)) => {
                Some(m)
            }
            KmError::NotFound(m)
            | KmError::Exists(m)
            | KmError::ObjectsFailed(m)
            | KmError::LockUnwritable(m)
            | KmError::Unsupported(m)
            | KmError::Unavailable(m)
            | KmError::Validation(m)
            | KmError::Io(m) => Some(m),
            KmError::HashMismatch { .. } | KmError::FirstUse { .. } => None,
        }
    };
}

impl KmError {
    /// Returns a function that makes an I/O error with a description of the operation that
    /// failed: `.map_err(KmError::io(format!("reading {p}")))`.
    pub fn io(what: impl std::fmt::Display) -> impl FnOnce(std::io::Error) -> KmError {
        move |e| KmError::Io(format!("{what}: {e}").into())
    }

    /// Returns the message, when the error is one of the variants with their own message text.
    #[must_use]
    pub fn msg(&self) -> Option<&Msg> {
        said!(self)
    }

    fn msg_mut(&mut self) -> Option<&mut Msg> {
        said!(self)
    }

    /// Returns the same error with `what` in front of its message (`"<what>: <message>"`). This is
    /// the one way to say where an error arose, whatever its kind. The two variants that format
    /// their own fields are returned unchanged.
    #[must_use]
    pub fn prefixed(mut self, what: impl std::fmt::Display) -> Self {
        if let Some(m) = self.msg_mut() {
            m.text = format!("{what}: {}", m.text);
        }
        self
    }

    /// Returns the same error with `text` as its message, and keeps its kind, return value, rule
    /// and check. It is for a refusal that is reported again with other words. The two variants
    /// that format their own fields are returned unchanged.
    #[must_use]
    pub fn with_text(mut self, text: impl Into<String>) -> Self {
        if let Some(m) = self.msg_mut() {
            m.text = text.into();
        }
        self
    }

    /// Returns the PKCS#11 return value of the module call that failed, where the token layer set
    /// it.
    #[must_use]
    pub fn rv(&self) -> Option<u64> {
        self.msg().and_then(Msg::rv)
    }

    /// Returns the same error with the return value of the module call that failed.
    #[must_use]
    pub fn with_rv(mut self, rv: Option<u64>) -> Self {
        if let Some(m) = self.msg_mut() {
            m.rv = rv;
        }
        self
    }

    /// Returns the plan's rule that refused, if one did ([`Rule`]).
    #[must_use]
    pub fn rule(&self) -> Option<Rule> {
        self.msg().and_then(Msg::rule)
    }

    /// Returns the same error, with the rule that refused. The two variants that format their own
    /// fields name no rule, because no rule refuses with them.
    #[must_use]
    pub fn with_rule(mut self, rule: Rule) -> Self {
        if let Some(m) = self.msg_mut() {
            m.rule = Some(rule);
        }
        self
    }

    /// Returns the check that refused, if one did ([`Check`]). A [`KmError::HashMismatch`] names
    /// the check that compared its IDs, and a [`KmError::FirstUse`] names none, because nothing
    /// was compared.
    #[must_use]
    pub fn check(&self) -> Option<Check> {
        match self {
            KmError::HashMismatch { check, .. } => Some(*check),
            _ => self.msg().and_then(Msg::check),
        }
    }

    /// Returns the same error with `check` as the check that refused, in place of the check that
    /// it named. A [`KmError::FirstUse`] names no check and is returned unchanged.
    #[must_use]
    pub fn with_check(mut self, check: Check) -> Self {
        if let KmError::HashMismatch { check: c, .. } = &mut self {
            *c = check;
        } else if let Some(m) = self.msg_mut() {
            m.check = Some(check);
        }
        self
    }

    /// Returns the message of a variant that has one, including the return value.
    #[must_use]
    pub fn into_msg(self) -> Option<Msg> {
        said!(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every variant with its own message text keeps a return value through `with_rv`, `rv`, `msg`
    /// and `into_msg`. The two variants that format their own fields keep none.
    #[test]
    fn every_message_carries_its_return_value() {
        let m = || Msg::from("said");
        let r = || Reason::check(Check::ObjectType, "said");
        let said = [
            KmError::NotFound(m()),
            KmError::Ambiguous(r()),
            KmError::Conflict(r()),
            KmError::PreconditionFailed(r()),
            KmError::Exists(m()),
            KmError::ObjectsFailed(m()),
            KmError::Unsupported(m()),
            KmError::Unavailable(m()),
            KmError::Validation(m()),
            KmError::LockUnwritable(m()),
            KmError::Io(m()),
        ];
        for e in said {
            let code = e.exit_code();
            let e = e.with_rv(Some(0x30)).with_rule(Rule::Placement).prefixed("where");
            assert_eq!(e.exit_code(), code, "prefixing keeps the kind");
            assert_eq!((e.rv(), e.msg().map(|m| &**m)), (Some(0x30), Some("where: said")), "{code}");
            assert_eq!(e.rule(), Some(Rule::Placement), "{code}");
            assert_eq!(e.into_msg().and_then(|m| m.rv()), Some(0x30), "{code}");
        }
        let fields = [
            KmError::HashMismatch {
                what: "w".into(),
                expected: "e".into(),
                got: "g".into(),
                check: Check::IdentityMaterial,
            },
            KmError::FirstUse { what: "w".into(), got: "g".into() },
        ];
        for e in fields {
            let e = e.with_rv(Some(0x30)).with_rule(Rule::Placement).prefixed("where");
            assert!(!e.to_string().contains("where"));
            assert_eq!((e.rv(), e.rule(), e.msg().is_none()), (None, None, true));
            assert!(e.into_msg().is_none());
        }
    }

    /// Exit 17 covers keys.toml, keys.lock, token options and addresses. Its prefix names none of
    /// them, and the message says which one is invalid (review error.rs F2).
    #[test]
    fn an_invalid_lock_is_not_called_a_spec() {
        let e = KmError::Validation("keys.lock: object 'a' is not in the lock".into());
        assert_eq!(e.to_string(), "invalid: keys.lock: object 'a' is not in the lock");
    }
}
