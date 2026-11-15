//! The fault plan (`docs/FAULT_SHIM.md`): TOML naming functions, the n-th call, and what to do
//! there. Read once per process; calls are counted per function from the process's first.

use crate::forward::Fn;
use crate::names;
use cryptoki_sys::CK_RV;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// The rules, in file order, and the calls counted so far.
pub struct Plan {
    rules: Vec<Rule>,
    counts: Vec<AtomicU64>,
}

/// One rule: which calls it matches, and the return value it makes them give.
#[derive(Debug, PartialEq, Eq)]
pub struct Rule {
    pub function: Fn,
    /// Only the n-th call of the process (from 1); every call when `None`.
    pub call: Option<u64>,
    pub rv: CK_RV,
    pub when: When,
}

/// Whether a rule answers instead of the real module, or after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum When {
    /// The real function is not called: as if the module had refused outright.
    #[default]
    Before,
    /// The real function is called, its effect happens, and the caller sees this value.
    After,
}

/// One call: the function, and which of its calls in this process it is.
#[derive(Debug, Clone, Copy)]
pub struct Call {
    pub function: Fn,
    pub n: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileText {
    #[serde(default)]
    rule: Vec<RuleText>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleText {
    #[serde(rename = "fn")]
    function: String,
    call: Option<u64>,
    rv: Option<Value>,
    #[serde(default)]
    when: When,
}

/// A value written by name (`"CKR_DEVICE_ERROR"`) or as a number (`0x30`).
#[derive(Deserialize)]
#[serde(untagged)]
enum Value {
    Name(String),
    Number(u64),
}

impl Default for Plan {
    /// No rules: the shim forwards everything unchanged.
    fn default() -> Plan {
        Plan::new(Vec::new())
    }
}

impl Plan {
    fn new(rules: Vec<Rule>) -> Plan {
        Plan { rules, counts: Fn::ALL.iter().map(|_| AtomicU64::new(0)).collect() }
    }

    /// Parse a plan.
    ///
    /// # Errors
    ///
    /// The TOML error, or the first rule that names an unknown function, field or return value,
    /// counts calls from 0, or does nothing: a plan that tests nothing is refused, never run.
    pub fn parse(text: &str) -> Result<Plan, String> {
        let file: FileText = toml::from_str(text).map_err(|e| e.to_string())?;
        let rules = file.rule.into_iter().enumerate().map(|(i, r)| rule(i + 1, r)).collect::<Result<_, _>>()?;
        Ok(Plan::new(rules))
    }

    /// The rules, in file order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Count a call of `function`: the first is 1.
    #[must_use]
    pub fn count(&self, function: Fn) -> Call {
        Call { function, n: self.counts[function as usize].fetch_add(1, Ordering::Relaxed) + 1 }
    }

    /// What `call` returns instead of reaching the real module, and the rule (from 1) that says
    /// so; `None` to forward it.
    #[must_use]
    pub fn before(&self, call: &Call) -> Option<(CK_RV, usize)> {
        self.first(call, When::Before)
    }

    /// What `call` returns in place of the real module's answer, and the rule (from 1); `None`
    /// to return the real one.
    #[must_use]
    pub fn after(&self, call: &Call) -> Option<(CK_RV, usize)> {
        self.first(call, When::After)
    }

    fn first(&self, call: &Call, when: When) -> Option<(CK_RV, usize)> {
        self.rules
            .iter()
            .enumerate()
            .find(|(_, r)| r.when == when && r.function == call.function && r.call.is_none_or(|n| n == call.n))
            .map(|(i, r)| (r.rv, i + 1))
    }
}

fn rule(index: usize, r: RuleText) -> Result<Rule, String> {
    let at = |why: String| format!("rule {index} ({}): {why}", r.function);
    let function = Fn::ALL.iter().copied().find(|f| f.name() == r.function).ok_or_else(|| {
        at(if r.function == "C_GetFunctionList" {
            "the entry point itself cannot be faulted".into()
        } else {
            "no such PKCS#11 2.40 function".into()
        })
    })?;
    if r.call == Some(0) {
        return Err(at("calls are counted from 1".into()));
    }
    let rv = match r.rv {
        Some(Value::Name(name)) => names::rv(&name).ok_or_else(|| at(format!("unknown return value {name}")))?,
        Some(Value::Number(n)) => n,
        None => return Err(at("nothing to do: give rv".into())),
    };
    Ok(Rule { function, call: r.call, rv, when: r.when })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki_sys::{CKR_DEVICE_ERROR, CKR_PIN_INCORRECT};

    #[test]
    fn rules_match_their_function_and_call() {
        let plan = Plan::parse(
            "[[rule]]\nfn = \"C_FindObjects\"\ncall = 2\nrv = \"CKR_DEVICE_ERROR\"\n\n\
             [[rule]]\nfn = \"C_Login\"\nwhen = \"after\"\nrv = 0xa0\n",
        )
        .unwrap();
        assert_eq!(plan.rules().len(), 2);
        let first = plan.count(Fn::C_FindObjects);
        let second = plan.count(Fn::C_FindObjects);
        assert_eq!((first.n, second.n), (1, 2));
        assert_eq!(plan.before(&first), None);
        assert_eq!(plan.before(&second), Some((CKR_DEVICE_ERROR, 1)));
        assert_eq!(plan.after(&second), None);
        let login = plan.count(Fn::C_Login);
        assert_eq!(plan.before(&login), None);
        assert_eq!(plan.after(&login), Some((CKR_PIN_INCORRECT, 2)));
        // Counted per function.
        assert_eq!(plan.count(Fn::C_Login).n, 2);
        assert_eq!(Plan::default().before(&first), None);
    }

    #[test]
    fn a_plan_that_would_test_nothing_is_refused() {
        for (text, why) in [
            ("[[rule]]\nfn = \"C_FindObject\"\nrv = \"CKR_OK\"\n", "no such PKCS#11 2.40 function"),
            ("[[rule]]\nfn = \"C_GetFunctionList\"\nrv = \"CKR_OK\"\n", "cannot be faulted"),
            ("[[rule]]\nfn = \"C_Login\"\nrv = \"CKR_PIN_WRONG\"\n", "unknown return value CKR_PIN_WRONG"),
            ("[[rule]]\nfn = \"C_Login\"\n", "nothing to do"),
            ("[[rule]]\nfn = \"C_Login\"\ncall = 0\nrv = \"CKR_OK\"\n", "counted from 1"),
            ("[[rule]]\nfn = \"C_Login\"\nrv = \"CKR_OK\"\nwhen = \"later\"\n", "unknown variant"),
            ("[[rule]]\nfn = \"C_Login\"\nrv = \"CKR_OK\"\ntypo = 1\n", "unknown field"),
            ("[[rules]]\nfn = \"C_Login\"\n", "unknown field"),
        ] {
            let Err(e) = Plan::parse(text) else { panic!("accepted: {text}") };
            assert!(e.contains(why), "expected {why:?} in {e:?}");
        }
    }
}
