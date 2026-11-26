//! The row every per-object verb prints, one per (spec, token) pair, whether the pair passed or
//! failed (review 2026-11-24 C-1: a passing `lock` row had no `outcome` or `exit`, a `delete`
//! row no `exit`, and `create` printed no row for a failure), and what a dry run's row and its
//! run's must agree on (docs/archive/REVIEW-2026-11-24/phase1-design.md §1.4).

use cakeys_core::{KmError, Rule};
use serde::{Deserialize, Serialize};

/// One pair's row. The process exit follows from the rows: 0 (22 when the lock was written),
/// the one failure's code, or 20 for several ([`refused`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    /// The object the spec realises.
    pub object: String,
    /// The spec.
    pub spec: String,
    /// The token.
    pub token: String,
    /// What happened, in the verb's word (`created`, `verified`, `locked`, `compared`,
    /// `deleted`, `would-delete`, `absent`; a `create --dry-run` row's `create`, `verify`,
    /// `skip`, `refuse`), or `failed`.
    pub outcome: String,
    /// The exit code the pair alone ends a run with: 0, a write recorded included (the run's 22
    /// says the lock was written), or its failure's.
    pub exit: u8,
    /// The rule that refused it (`cakeys_core::Rule::name`), where one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Whether the failure is the device's: its PKCS#11 return value says the device, the token
    /// or the session failed ([`cakeys_pkcs11::token::device_failed_rv`]), which no dry run can
    /// foresee.
    pub device: bool,
    /// Why it failed, as the run says it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The rules a dry run could not decide: its run may differ from it by these alone.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deferred: Vec<DeferredRow>,
    /// The verb's own fields, beside these: the realisation `lock` recorded or `create` made, as
    /// `resolve` prints it; a `create --dry-run` row's `action`, `reasons` and `refusals`.
    #[serde(flatten)]
    pub more: serde_json::Map<String, serde_json::Value>,
}

/// A rule a dry run deferred, in its row (`cakeys_pkcs11::ops::Deferred`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredRow {
    /// The rule's name.
    pub rule: String,
    /// Why only the run decides it.
    pub why: String,
}

impl Outcome {
    /// The pair (`object`, `spec`, `token`) passed, with `outcome`.
    #[must_use]
    pub fn passed(object: &str, spec: &str, token: &str, outcome: &str) -> Outcome {
        Outcome {
            object: object.to_owned(),
            spec: spec.to_owned(),
            token: token.to_owned(),
            outcome: outcome.to_owned(),
            exit: 0,
            rule: None,
            device: false,
            error: None,
            deferred: Vec::new(),
            more: serde_json::Map::new(),
        }
    }

    /// The pair (`object`, `spec`, `token`) failed with `e`: its exit code, the rule that
    /// refused it, whether the device failed, and the message (with its causes).
    #[must_use]
    pub fn failed(object: &str, spec: &str, token: &str, e: &anyhow::Error) -> Outcome {
        let km = e.downcast_ref::<KmError>();
        Outcome {
            outcome: "failed".to_owned(),
            error: Some(format!("{e:#}")),
            ..Outcome::passed(object, spec, token, "failed").refused_by(km)
        }
    }

    /// The same row, its exit, rule and device bit `e`'s (none: 1, as `main` maps an error that
    /// is no `KmError`).
    #[must_use]
    pub fn refused_by(self, e: Option<&KmError>) -> Outcome {
        Outcome {
            exit: e.map_or(1, KmError::exit_code),
            rule: e.and_then(KmError::rule).map(Rule::name).map(str::to_owned),
            device: e.and_then(KmError::rv).is_some_and(cakeys_pkcs11::token::device_failed_rv),
            ..self
        }
    }

    /// The same row, `more`'s fields beside its own (an object's: a [`cakeys_core::reconcile::Resolved`]).
    /// Its `object`, `spec` and `token` are the row's already, and are not repeated.
    ///
    /// # Errors
    ///
    /// `more` that does not serialize as an object.
    pub fn with(mut self, more: &impl Serialize) -> anyhow::Result<Outcome> {
        let serde_json::Value::Object(mut fields) = serde_json::to_value(more)? else {
            anyhow::bail!("a row's fields serialize as an object");
        };
        for own in ["object", "spec", "token"] {
            fields.remove(own);
        }
        self.more.extend(fields);
        Ok(self)
    }

    /// Whether `real` is what its dry run's row `dry` said it would be (§1.4): the same exit and
    /// rule; or a rule the dry run named as deferred; or a failure of the device, which no dry
    /// run foresees. A dry run admits a difference only by naming the rule.
    #[must_use]
    pub fn twin(dry: &Outcome, real: &Outcome) -> bool {
        (real.exit == dry.exit && real.rule == dry.rule)
            || real.rule.as_ref().is_some_and(|r| dry.deferred.iter().any(|d| &d.rule == r))
            || real.device
    }
}

/// The error a run whose pairs were refused by `errors` ends with: the one refusal's own, or
/// several as `ObjectsFailed` (20), each said first on stderr led by its exit code, as `check
/// --token` lists its failures. `what` names them (`"pairs refused"`). `None` when there is none.
#[must_use]
pub fn refused(mut errors: Vec<KmError>, what: &str) -> Option<KmError> {
    match errors.len() {
        0 => None,
        1 => errors.pop(),
        n => {
            for e in &errors {
                eprintln!("exit {}: {e}", e.exit_code());
            }
            Some(KmError::ObjectsFailed(format!("{n} {what}, each listed above with its exit code").into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::Reason;

    fn row(outcome: &str, exit: u8, rule: Option<&str>, device: bool, deferred: &[&str]) -> Outcome {
        Outcome {
            exit,
            rule: rule.map(str::to_owned),
            device,
            deferred: deferred
                .iter()
                .map(|r| DeferredRow { rule: (*r).to_owned(), why: "only the run".into() })
                .collect(),
            ..Outcome::passed("o", "s", "t", outcome)
        }
    }

    /// The twin oracle on rows the design names (§1.4, T-1): a run refused by a rule its dry run
    /// passed fails it; by a rule the dry run deferred, or by the device, passes; a dry run
    /// refused by one rule and its run by another fails, the exit the same or not.
    #[test]
    fn the_twin_oracle_admits_only_a_deferred_rule_or_the_device() {
        let ready = row("create", 0, None, false, &[]);
        let deferring = row("create", 0, None, false, &["templates"]);
        let locator = row("failed", 13, Some("locator-free"), false, &[]);
        let templates = row("failed", 15, Some("templates"), false, &[]);
        let capability = row("failed", 15, Some("capability"), false, &[]);
        let device = row("failed", 16, None, true, &[]);
        assert!(!Outcome::twin(&ready, &locator), "dry ready, run refused by a rule the dry run passed");
        assert!(Outcome::twin(&deferring, &templates), "a rule the dry run deferred");
        assert!(!Outcome::twin(&deferring, &capability), "a rule it did not defer");
        assert!(Outcome::twin(&ready, &device), "the device");
        assert!(!Outcome::twin(&row("refuse", 15, Some("templates"), false, &[]), &capability), "X, then Y");
        assert!(!Outcome::twin(&row("refuse", 13, Some("locator-free"), false, &[]), &templates), "X, then Y");
        assert!(Outcome::twin(&row("refuse", 13, Some("locator-free"), false, &[]), &locator), "the same refusal");
        assert!(Outcome::twin(&ready, &row("created", 0, None, false, &[])), "both pass");
    }

    /// A failure's row carries its code, its rule and whether the device failed; a row's fields
    /// and the verb's own round-trip through the one type.
    #[test]
    fn a_failure_row_says_its_code_rule_and_device() {
        let refusal = KmError::Conflict(Reason::rule(Rule::LocatorFree, "taken"));
        let r = Outcome::failed("o", "s", "t", &anyhow::Error::from(refusal));
        assert_eq!(
            (r.exit, r.rule.as_deref(), r.device, r.outcome.as_str()),
            (13, Some("locator-free"), false, "failed")
        );
        let device = KmError::Unavailable("C_Sign".into()).with_rv(Some(0x30)); // CKR_DEVICE_ERROR
        assert!(Outcome::failed("o", "s", "t", &anyhow::Error::from(device)).device);
        let wrong_pin = KmError::Unavailable("C_Login".into()).with_rv(Some(0xa0)); // CKR_PIN_INCORRECT
        assert!(!Outcome::failed("o", "s", "t", &anyhow::Error::from(wrong_pin)).device);
        let row = Outcome::passed("o", "s", "t", "locked")
            .with(&serde_json::json!({"object": "o", "uri": "pkcs11:object=o", "ids": {}}))
            .unwrap();
        let text = serde_json::to_string(&row).unwrap();
        assert_eq!(text.matches("\"object\"").count(), 1, "{text}");
        assert_eq!(serde_json::from_str::<Outcome>(&text).unwrap(), row);
    }

    /// One refusal ends a run with its own code; several with 20.
    #[test]
    fn a_run_ends_with_the_one_refusal_or_20() {
        assert!(refused(Vec::new(), "pairs refused").is_none());
        let one = refused(vec![KmError::Conflict("taken".into())], "pairs refused").unwrap();
        assert_eq!(one.exit_code(), 13);
        let two = vec![KmError::Conflict("taken".into()), KmError::Unsupported("no".into())];
        let several = refused(two, "pairs refused").unwrap();
        assert!(several.exit_code() == 20 && several.to_string().contains("2 pairs refused"), "{several}");
    }
}
