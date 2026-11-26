//! The row that every per-object verb prints, one for each (spec, token) pair, whether the pair
//! passed or failed (review 2026-11-24 C-1: before, a passing `lock` row had no `outcome` or
//! `exit`, a `delete` row had no `exit`, and `create` printed no row for a failure). This module
//! also defines what the row of a dry run and the row of its real run must agree on
//! (docs/archive/REVIEW-2026-11-24/phase1-design.md §1.4).

use cakeys_core::{Check, KmError, Rule};
use serde::{Deserialize, Serialize};

/// The row of one pair. The process exit code follows from the rows. It is 22 if the lock was
/// written, even if a pair failed after the write, and in that case the failed pair's row holds
/// the failure's code. Otherwise, it is 0, the code of the one failure, or 20 for several
/// failures ([`refused`]).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    /// The object that the spec realises.
    pub object: String,
    /// The spec.
    pub spec: String,
    /// The token.
    pub token: String,
    /// What happened, in the verb's word (`created`, `verified`, `locked`, `compared`,
    /// `deleted`, `would-delete`, `absent`, and for a `create --dry-run` row `create`, `verify`,
    /// `skip`, `refuse`), or `failed`.
    pub outcome: String,
    /// The exit code with which the pair alone would end a run: 0, also when the pair recorded a
    /// write (the run's 22 says that the lock was written), or the code of its failure.
    pub exit: u8,
    /// The rule that refused the pair (`cakeys_core::Rule::name`), if a rule did. Otherwise, the
    /// check that refused the pair (`cakeys_core::Check::name`, a dotted name such as
    /// `identity.material`), if a check did. docs/CAKEYS.md lists both under "Rules and checks".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Whether the device caused the failure: the PKCS#11 return value means that the device, the
    /// token or the session failed ([`cakeys_pkcs11::token::device_failed_rv`]), which no dry run
    /// can predict.
    pub device: bool,
    /// The reason for the failure, as the run reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The rules that a dry run could not decide. The real run may differ from the dry run only
    /// in these rules.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deferred: Vec<DeferredRow>,
    /// The verb's own fields, next to these: the realisation that `lock` recorded or `create`
    /// made, as `resolve` prints it, or the `action`, `reasons` and `refusals` of a
    /// `create --dry-run` row.
    #[serde(flatten)]
    pub more: serde_json::Map<String, serde_json::Value>,
}

/// A rule that a dry run deferred, in the dry run's row (`cakeys_pkcs11::ops::Deferred`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredRow {
    /// The rule's name.
    pub rule: String,
    /// The reason why only the real run can decide the rule.
    pub why: String,
}

impl Outcome {
    /// Returns the row of a pair (`object`, `spec`, `token`) that passed, with `outcome`.
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

    /// Returns the row of a pair (`object`, `spec`, `token`) that failed with `e`: its exit code,
    /// the rule that refused it, whether the device failed, and the message (with its causes).
    #[must_use]
    pub fn failed(object: &str, spec: &str, token: &str, e: &anyhow::Error) -> Outcome {
        let km = e.downcast_ref::<KmError>();
        Outcome {
            outcome: "failed".to_owned(),
            error: Some(format!("{e:#}")),
            ..Outcome::passed(object, spec, token, "failed").refused_by(km)
        }
    }

    /// Returns the same row with the exit code, the rule and the device flag of `e`. Without `e`,
    /// the exit code is 1, as `main` maps an error that is not a `KmError`.
    #[must_use]
    pub fn refused_by(self, e: Option<&KmError>) -> Outcome {
        Outcome {
            exit: e.map_or(1, KmError::exit_code),
            rule: e.and_then(|e| e.rule().map(Rule::name).or_else(|| e.check().map(Check::name))).map(str::to_owned),
            device: e.and_then(KmError::rv).is_some_and(cakeys_pkcs11::token::device_failed_rv),
            ..self
        }
    }

    /// Returns the same row with the fields of `more` next to its own fields (for an object, a
    /// [`cakeys_core::reconcile::Resolved`]). The `object`, `spec` and `token` of `more` are
    /// already in the row, so they are not repeated.
    ///
    /// # Errors
    ///
    /// Returns an error when `more` does not serialize as an object.
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

    /// Returns whether `real` matches what its dry run's row `dry` predicted (§1.4): the same exit
    /// code and rule, or a rule that the dry run named as deferred, or a failure of the device,
    /// which no dry run can predict. A dry run allows a difference only by naming the rule.
    #[must_use]
    pub fn twin(dry: &Outcome, real: &Outcome) -> bool {
        (real.exit == dry.exit && real.rule == dry.rule)
            || real.rule.as_ref().is_some_and(|r| dry.deferred.iter().any(|d| &d.rule == r))
            || real.device
    }
}

/// Returns the error with which a run ends when `errors` refused its pairs: the error of the one
/// refusal, or `ObjectsFailed` (20) for several refusals. For several refusals, each one is first
/// printed on stderr after its exit code, as `check --token` lists its failures. `what` names the
/// refusals (`"pairs refused"`). Returns `None` when there are no refusals.
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
    use cakeys_core::{Check, Reason};

    /// A refusal by a check names the check in its row's `rule`, as a refusal by a plan's rule
    /// names the rule (docs/CAKEYS.md, "Rules and checks"). A mismatch of the material is
    /// `identity.material`, and a failed proof is `pop.sign`. A refusal by a check that a plan's
    /// rule returns names the rule. A first use compared nothing, and a malformed input is not a
    /// refusal by a check, so neither names a rule or a check.
    #[test]
    fn a_refusal_row_names_its_check() {
        let rule = |e: KmError| Outcome::failed("o", "s", "t", &anyhow::Error::from(e)).rule;
        let mismatch = KmError::HashMismatch {
            what: "o".into(),
            expected: "sha256-a".into(),
            got: "sha256-b".into(),
            check: Check::IdentityMaterial,
        };
        assert_eq!(rule(mismatch).as_deref(), Some("identity.material"));
        let proof = || KmError::Conflict(Reason::check(Check::PopSign, "the signature does not verify"));
        assert_eq!(rule(proof()).as_deref(), Some("pop.sign"));
        assert_eq!(rule(proof().with_rule(Rule::Capability)).as_deref(), Some("capability"));
        assert_eq!(rule(KmError::FirstUse { what: "o".into(), got: "sha256-b".into() }), None);
        assert_eq!(rule(KmError::Conflict(Reason::malformed("no DER"))), None);
    }

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

    /// `Outcome::twin` on the rows that the design names (§1.4, T-1). A run that a rule refused
    /// after its dry run passed that rule fails the comparison. A run that a deferred rule or the
    /// device refused passes it. A dry run refused by one rule and a real run refused by another
    /// rule fail it, whether the exit codes are the same or not.
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

    /// A failure's row contains its exit code, its rule and whether the device failed. A row's
    /// fields and the verb's own fields round-trip through the one type.
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

    /// One refusal ends a run with its own exit code, and several refusals end it with 20.
    #[test]
    fn a_run_ends_with_the_one_refusal_or_20() {
        assert!(refused(Vec::new(), "pairs refused").is_none());
        let taken = || KmError::Conflict(Reason::rule(Rule::LocatorFree, "taken"));
        let one = refused(vec![taken()], "pairs refused").unwrap();
        assert_eq!(one.exit_code(), 13);
        let two = vec![taken(), KmError::Unsupported("no".into())];
        let several = refused(two, "pairs refused").unwrap();
        assert!(several.exit_code() == 20 && several.to_string().contains("2 pairs refused"), "{several}");
    }
}
