//! The fault plan (`docs/FAULT_SHIM.md`): TOML naming functions, the n-th call, and what to do
//! there. Read once per process; calls are counted per function from the process's first.

use crate::forward::Fn;
use crate::names;
use cryptoki_sys::{CK_ATTRIBUTE_TYPE, CK_FLAGS, CK_RV};
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// The rules, in file order, and the calls counted so far.
pub struct Plan {
    rules: Vec<Rule>,
    counts: Vec<AtomicU64>,
}

/// One rule: which calls it matches, and what it does to them.
#[derive(Debug, PartialEq, Eq)]
pub struct Rule {
    pub function: Fn,
    /// Only the n-th call of the process (from 1); every call when `None`.
    pub call: Option<u64>,
    /// Only calls on an object with this `CKA_LABEL` (attribute and key rules).
    pub of_label: Option<Vec<u8>>,
    pub action: Action,
}

/// What a rule does to the calls it matches.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// The call returns this value: instead of reaching the real module, or after it.
    Rv { rv: CK_RV, when: When },
    /// `C_GetTokenInfo`, `C_GetSlotInfo`: flags set and cleared in what the real module reports.
    Flags { set: CK_FLAGS, clear: CK_FLAGS },
    /// `C_GetAttributeValue`: one attribute is not what the real module holds.
    Attribute { attribute: CK_ATTRIBUTE_TYPE, change: AttributeChange },
    /// `C_FindObjects`: the objects with this label are found too, where anything is found.
    AddLabel(Vec<u8>),
    /// A function taking a key: the object with this label (and the key's class) is used
    /// instead of the one the caller names.
    UseLabel(Vec<u8>),
}

/// What an attribute rule reports for its attribute.
#[derive(Debug, PartialEq, Eq)]
pub enum AttributeChange {
    /// The object has no such attribute (`CKR_ATTRIBUTE_TYPE_INVALID`).
    Drop,
    /// This value.
    Value(Vec<u8>),
    /// The attribute of the object with this label (of the same class, where one is).
    FromLabel(Vec<u8>),
    /// A length of `CK_UNAVAILABLE_INFORMATION` under `CKR_OK`: malformed.
    Unavailable,
    /// Only the first bytes of the real value.
    Truncate(usize),
}

/// Whether a return-value rule answers instead of the real module, or after it.
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
    of_label: Option<String>,
    rv: Option<Value>,
    when: Option<When>,
    #[serde(default)]
    set_flags: Vec<Value>,
    #[serde(default)]
    clear_flags: Vec<Value>,
    attribute: Option<Value>,
    #[serde(default)]
    drop: bool,
    /// Hex.
    value: Option<String>,
    from_label: Option<String>,
    /// `"unavailable"`.
    length: Option<String>,
    truncate: Option<usize>,
    add_label: Option<String>,
    use_label: Option<String>,
}

/// A value written by name (`"CKR_DEVICE_ERROR"`) or as a number (`0x30`).
#[derive(Deserialize)]
#[serde(untagged)]
enum Value {
    Name(String),
    Number(u64),
}

impl Value {
    fn resolve(self, what: &str, by_name: fn(&str) -> Option<u64>) -> Result<u64, String> {
        match self {
            Value::Name(name) => by_name(&name).ok_or_else(|| format!("unknown {what} {name}")),
            Value::Number(n) => Ok(n),
        }
    }
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
    /// The TOML error, or the first rule that names an unknown function, field or value,
    /// counts calls from 0, does nothing, does two things, or does what its function cannot: a
    /// plan that tests nothing is refused, never run.
    pub fn parse(text: &str) -> Result<Plan, String> {
        let file: FileText = toml::from_str(text).map_err(|e| e.to_string())?;
        let rules = file
            .rule
            .into_iter()
            .enumerate()
            .map(|(i, r)| {
                let name = r.function.clone();
                rule(r).map_err(|why| format!("rule {} ({name}): {why}", i + 1))
            })
            .collect::<Result<_, _>>()?;
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

    /// The rules for `call`'s function and number, each with its number in the plan (from 1).
    pub fn matching(&self, call: &Call) -> impl Iterator<Item = (usize, &Rule)> {
        let call = *call;
        self.rules
            .iter()
            .enumerate()
            .filter(move |(_, r)| r.function == call.function && r.call.is_none_or(|n| n == call.n))
            .map(|(i, r)| (i + 1, r))
    }

    /// What `call` returns instead of reaching the real module, and the rule (from 1) that says
    /// so; `None` to forward it.
    #[must_use]
    pub fn before(&self, call: &Call) -> Option<(CK_RV, usize)> {
        self.rv(call, When::Before)
    }

    /// What `call` returns in place of the real module's answer, and the rule (from 1); `None`
    /// to return the real one.
    #[must_use]
    pub fn after(&self, call: &Call) -> Option<(CK_RV, usize)> {
        self.rv(call, When::After)
    }

    fn rv(&self, call: &Call, at: When) -> Option<(CK_RV, usize)> {
        self.matching(call).find_map(|(i, r)| match r.action {
            Action::Rv { rv, when } if when == at => Some((rv, i)),
            _ => None,
        })
    }
}

/// The functions whose third argument is the key they use: what `use_label` substitutes.
pub const KEY_FUNCTIONS: [Fn; 7] = [
    Fn::C_EncryptInit,
    Fn::C_DecryptInit,
    Fn::C_SignInit,
    Fn::C_VerifyInit,
    Fn::C_WrapKey,
    Fn::C_UnwrapKey,
    Fn::C_DeriveKey,
];

fn rule(r: RuleText) -> Result<Rule, String> {
    let function = Fn::ALL.iter().copied().find(|f| f.name() == r.function).ok_or_else(|| {
        if r.function == "C_GetFunctionList" {
            "the entry point itself cannot be faulted".to_owned()
        } else {
            "no such PKCS#11 2.40 function".to_owned()
        }
    })?;
    if r.call == Some(0) {
        return Err("calls are counted from 1".into());
    }
    let only = |functions: &[Fn], what: &str| {
        if functions.contains(&function) {
            Ok(())
        } else {
            let names: Vec<&str> = functions.iter().map(|f| f.name()).collect();
            Err(format!("{what} is for {}", names.join(", ")))
        }
    };
    let flags = |values: Vec<Value>| -> Result<CK_FLAGS, String> {
        values.into_iter().try_fold(0, |all, v| Ok(all | v.resolve("slot or token flag", names::flag)?))
    };
    let mut actions = Vec::new();
    if let Some(rv) = r.rv {
        actions.push(Action::Rv { rv: rv.resolve("return value", names::rv)?, when: r.when.unwrap_or_default() });
    } else if r.when.is_some() {
        return Err("when goes with rv".into());
    }
    if !r.set_flags.is_empty() || !r.clear_flags.is_empty() {
        only(&[Fn::C_GetTokenInfo, Fn::C_GetSlotInfo], "set_flags/clear_flags")?;
        actions.push(Action::Flags { set: flags(r.set_flags)?, clear: flags(r.clear_flags)? });
    }
    let mut changes = Vec::new();
    if r.drop {
        changes.push(AttributeChange::Drop);
    }
    if let Some(hex) = &r.value {
        changes.push(AttributeChange::Value(unhex(hex).ok_or("value is hex")?));
    }
    if let Some(label) = r.from_label {
        changes.push(AttributeChange::FromLabel(label.into_bytes()));
    }
    match r.length.as_deref() {
        Some("unavailable") => changes.push(AttributeChange::Unavailable),
        Some(other) => return Err(format!("length = \"{other}\": only \"unavailable\"")),
        None => {}
    }
    if let Some(n) = r.truncate {
        changes.push(AttributeChange::Truncate(n));
    }
    match (r.attribute, changes.len()) {
        (Some(attribute), 1) => {
            only(&[Fn::C_GetAttributeValue], "attribute")?;
            let attribute = attribute.resolve("attribute", names::attribute)?;
            actions.push(Action::Attribute { attribute, change: changes.remove(0) });
        }
        (None, 0) => {}
        (Some(_), _) => return Err("an attribute rule gives one of drop, value, from_label, length, truncate".into()),
        (None, _) => return Err("drop, value, from_label, length and truncate go with attribute".into()),
    }
    if let Some(label) = r.add_label {
        only(&[Fn::C_FindObjects], "add_label")?;
        actions.push(Action::AddLabel(label.into_bytes()));
    }
    if let Some(label) = r.use_label {
        only(&KEY_FUNCTIONS, "use_label")?;
        actions.push(Action::UseLabel(label.into_bytes()));
    }
    let action = match actions.len() {
        1 => actions.remove(0),
        0 => {
            return Err("nothing to do: give rv, set_flags, clear_flags, attribute, add_label or use_label".into());
        }
        _ => return Err("one thing per rule".into()),
    };
    if r.of_label.is_some() && !matches!(action, Action::Attribute { .. } | Action::UseLabel(_)) {
        return Err("of_label goes with attribute or use_label".into());
    }
    Ok(Rule { function, call: r.call, of_label: r.of_label.map(String::into_bytes), action })
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return None;
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki_sys::{
        CKA_EC_POINT, CKF_USER_PIN_FINAL_TRY, CKF_WRITE_PROTECTED, CKR_DEVICE_ERROR, CKR_PIN_INCORRECT,
    };

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
    fn each_action_parses_to_what_it_does() {
        let plan = Plan::parse(
            "[[rule]]\nfn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_WRITE_PROTECTED\", \"CKF_USER_PIN_FINAL_TRY\"]\nclear_flags = [1]\n\n\
             [[rule]]\nfn = \"C_GetAttributeValue\"\nof_label = \"k\"\nattribute = \"CKA_EC_POINT\"\nvalue = \"0401\"\n\n\
             [[rule]]\nfn = \"C_GetAttributeValue\"\nattribute = 0x181\nfrom_label = \"other\"\n\n\
             [[rule]]\nfn = \"C_GetAttributeValue\"\nattribute = \"CKA_EC_POINT\"\ntruncate = 3\n\n\
             [[rule]]\nfn = \"C_FindObjects\"\ncall = 1\nadd_label = \"decoy\"\n\n\
             [[rule]]\nfn = \"C_DecryptInit\"\nof_label = \"shown\"\nuse_label = \"used\"\n",
        )
        .unwrap();
        let actions: Vec<&Action> = plan.rules().iter().map(|r| &r.action).collect();
        let point = |change| Action::Attribute { attribute: CKA_EC_POINT, change };
        assert_eq!(*actions[0], Action::Flags { set: CKF_WRITE_PROTECTED | CKF_USER_PIN_FINAL_TRY, clear: 1 });
        assert_eq!(*actions[1], point(AttributeChange::Value(vec![4, 1])));
        assert_eq!(*actions[2], point(AttributeChange::FromLabel(b"other".to_vec())));
        assert_eq!(*actions[3], point(AttributeChange::Truncate(3)));
        assert_eq!(*actions[4], Action::AddLabel(b"decoy".to_vec()));
        assert_eq!(*actions[5], Action::UseLabel(b"used".to_vec()));
        assert_eq!(plan.rules()[1].of_label.as_deref(), Some(&b"k"[..]));
        // An attribute or flag rule is no return value.
        let call = plan.count(Fn::C_GetTokenInfo);
        assert_eq!((plan.before(&call), plan.after(&call)), (None, None));
        assert_eq!(plan.matching(&call).map(|(i, _)| i).collect::<Vec<_>>(), [1]);
    }

    #[test]
    fn a_plan_that_would_test_nothing_is_refused() {
        for (text, why) in [
            ("[[rule]]\nfn = \"C_FindObject\"\nrv = \"CKR_OK\"\n", "no such PKCS#11 2.40 function"),
            ("[[rule]]\nfn = \"C_GetFunctionList\"\nrv = \"CKR_OK\"\n", "cannot be faulted"),
            ("[[rule]]\nfn = \"C_Login\"\nrv = \"CKR_PIN_WRONG\"\n", "unknown return value CKR_PIN_WRONG"),
            ("[[rule]]\nfn = \"C_Login\"\n", "nothing to do"),
            ("[[rule]]\nfn = \"C_Login\"\nwhen = \"after\"\n", "when goes with rv"),
            ("[[rule]]\nfn = \"C_Login\"\ncall = 0\nrv = \"CKR_OK\"\n", "counted from 1"),
            ("[[rule]]\nfn = \"C_Login\"\nrv = \"CKR_OK\"\nwhen = \"later\"\n", "unknown variant"),
            ("[[rule]]\nfn = \"C_Login\"\nrv = \"CKR_OK\"\ntypo = 1\n", "unknown field"),
            ("[[rules]]\nfn = \"C_Login\"\n", "unknown field"),
            (
                "[[rule]]\nfn = \"C_Login\"\nset_flags = [\"CKF_WRITE_PROTECTED\"]\n",
                "is for C_GetTokenInfo, C_GetSlotInfo",
            ),
            ("[[rule]]\nfn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_RW_SESSION\"]\n", "unknown slot or token flag"),
            ("[[rule]]\nfn = \"C_GetAttributeValue\"\nattribute = \"CKA_NOPE\"\ndrop = true\n", "unknown attribute"),
            ("[[rule]]\nfn = \"C_GetAttributeValue\"\nattribute = \"CKA_ID\"\n", "gives one of"),
            (
                "[[rule]]\nfn = \"C_GetAttributeValue\"\nattribute = \"CKA_ID\"\ndrop = true\ntruncate = 1\n",
                "gives one of",
            ),
            ("[[rule]]\nfn = \"C_GetAttributeValue\"\ndrop = true\n", "go with attribute"),
            ("[[rule]]\nfn = \"C_GetAttributeValue\"\nattribute = \"CKA_ID\"\nvalue = \"0g\"\n", "value is hex"),
            (
                "[[rule]]\nfn = \"C_GetAttributeValue\"\nattribute = \"CKA_ID\"\nlength = \"long\"\n",
                "only \"unavailable\"",
            ),
            ("[[rule]]\nfn = \"C_Sign\"\nuse_label = \"x\"\n", "use_label is for C_EncryptInit"),
            ("[[rule]]\nfn = \"C_FindObjectsInit\"\nadd_label = \"x\"\n", "add_label is for C_FindObjects"),
            ("[[rule]]\nfn = \"C_FindObjects\"\nadd_label = \"x\"\nrv = 0\n", "one thing per rule"),
            ("[[rule]]\nfn = \"C_FindObjects\"\nadd_label = \"x\"\nof_label = \"y\"\n", "of_label goes with"),
        ] {
            let Err(e) = Plan::parse(text) else { panic!("accepted: {text}") };
            assert!(e.contains(why), "expected {why:?} in {e:?}");
        }
    }
}
