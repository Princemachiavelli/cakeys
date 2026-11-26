//! The fault plan (`docs/FAULT_SHIM.md`) is TOML that names functions, the n-th call, and what to
//! do at that call. The shim reads it once per process. Calls are counted for each function, for
//! each rule, and over all functions from the process's first call.

use crate::forward::Fn;
use crate::trace::Detail;
use crate::{Fatal, names};
use cryptoki_sys::{
    CK_ATTRIBUTE_TYPE, CK_FLAGS, CK_KEY_TYPE, CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RV,
};
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// The rules, in file order, and the calls counted so far.
pub struct Plan {
    rules: Vec<Rule>,
    /// The number of calls of each function.
    counts: Vec<AtomicU64>,
    /// For each rule, the number of calls that met its other matchers (what `nth` and `from`
    /// count).
    met: Vec<AtomicU64>,
    /// The number of calls of all functions together.
    seq: AtomicU64,
}

/// One rule: the calls that it matches, and what it does to them.
#[derive(Debug, PartialEq, Eq)]
pub struct Rule {
    /// The function whose calls the rule matches, or every function when `None` (`fn = "*"`).
    pub(crate) function: Option<Fn>,
    /// Matches only the n-th call of the function in the process (counted from 1), or every call
    /// when `None`.
    pub call: Option<u64>,
    /// Matches only the n-th call that meets the rule's other matchers (counted from 1).
    pub nth: Option<u64>,
    /// Matches only the n-th call that meets the rule's other matchers and the calls after it.
    pub from: Option<u64>,
    /// Matches only the process's n-th call of any function (the trace's `seq`) and the calls
    /// after it.
    pub from_seq: Option<u64>,
    /// Matches only calls on an object with this `CKA_LABEL`. The object is the key that a
    /// `use_label` rule replaces, the key that is wrapped under `wrap_label`, and otherwise any
    /// object that the call names.
    pub of_label: Option<Vec<u8>>,
    /// Matches only calls with this mechanism.
    pub mechanism: Option<CK_MECHANISM_TYPE>,
    /// Matches only calls whose input template names this class.
    pub class: Option<CK_OBJECT_CLASS>,
    /// Matches only calls whose input template names this key type.
    pub key_type: Option<CK_KEY_TYPE>,
    /// What the rule does to the calls that it matches.
    pub(crate) action: Action,
}

impl Rule {
    /// Returns the objects of a call (in argument order) that the rule's `of_label` looks at:
    /// the key that is used (the first object) for `use_label` and for an attribute rule, the
    /// key that is wrapped (the second object) for `wrap_label`, and every object for the other
    /// rules.
    fn looks_at<'a>(&self, objects: &'a [CK_OBJECT_HANDLE]) -> &'a [CK_OBJECT_HANDLE] {
        match self.action {
            Action::UseLabel(_) | Action::Attribute { .. } => &objects[..objects.len().min(1)],
            Action::WrapLabel(_) => objects.get(1..).unwrap_or_default(),
            _ => objects,
        }
    }
}

/// What a rule does to the calls it matches.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// The call returns this value, either instead of reaching the real module or after it.
    Rv {
        /// The value returned (`CKR_*`).
        rv: CK_RV,
        /// Whether the value replaces the real call or follows it.
        when: When,
    },
    /// For `C_GetTokenInfo` and `C_GetSlotInfo`: flags that are set and cleared in what the
    /// real module reports.
    Flags {
        /// Flags set.
        set: CK_FLAGS,
        /// Flags cleared.
        clear: CK_FLAGS,
    },
    /// For `C_GetAttributeValue`: one attribute is reported differently from what the real
    /// module holds.
    Attribute {
        /// The attribute (`CKA_*`).
        attribute: CK_ATTRIBUTE_TYPE,
        /// What is reported for it.
        change: AttributeChange,
    },
    /// For `C_FindObjects`: the objects with this label are also found, in any search that finds
    /// something.
    AddLabel(Vec<u8>),
    /// For a function that takes a key: the object with this label (and the class of that key)
    /// is used instead of the key that the caller names.
    UseLabel(Vec<u8>),
    /// For `C_WrapKey`: the object with this label (and the class of the caller's key) is
    /// wrapped instead of the key that the caller names, so the blob holds a different key from
    /// the one that the caller sees.
    WrapLabel(Vec<u8>),
    /// For `C_FindObjects`: the objects with this label are not found.
    HideLabel(Vec<u8>),
    /// For `C_FindObjects`: each found object with the label `of` is replaced by the object of
    /// the same class with the label `by`.
    ReplaceLabel {
        /// The label of the objects replaced.
        of: Vec<u8>,
        /// The label of the objects that are found instead.
        by: Vec<u8>,
    },
    /// For a function that returns bytes: the last byte that it returns is changed.
    Corrupt,
    /// For a function that returns bytes: the function returns what it returned this many
    /// calls before (1 means the latest earlier output), when there was such an output and it
    /// fits the caller's buffer.
    ReplayOutput(usize),
    /// For `C_WrapKey`: the returned blob is transcoded, and every `C_UnwrapKey` undoes the
    /// transcoding, so the blob round-trips through the module but is not the blob that the
    /// module made.
    Transcode,
    /// For `C_GetMechanismList`: these mechanisms are not listed.
    HideMechanisms(Vec<CK_MECHANISM_TYPE>),
    /// The process ends at the call, before the call reaches the module
    /// (`std::process::abort`). This simulates a crash, a kill or an out-of-memory failure
    /// between two writes of a run.
    Abort,
}

/// What an attribute rule reports for its attribute.
#[derive(Debug, PartialEq, Eq)]
pub enum AttributeChange {
    /// The object has no such attribute (`CKR_ATTRIBUTE_TYPE_INVALID`).
    Drop,
    /// This value.
    Value(Vec<u8>),
    /// The attribute of the object with this label (of the same class, where such an object
    /// exists).
    FromLabel(Vec<u8>),
    /// A length of `CK_UNAVAILABLE_INFORMATION` with `CKR_OK`, which is a malformed answer.
    Unavailable,
    /// Only the first bytes of the real value.
    Truncate(usize),
}

/// Whether a return-value rule answers instead of the real module, or after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum When {
    /// The real function is not called, as if the module had refused the call outright.
    #[default]
    Before,
    /// The real function is called and has its effect, and the caller sees this value.
    After,
}

/// One call: the function, the call's number among the function's calls in this process, and
/// the rules that the call meets.
#[derive(Debug, Clone)]
pub struct Call {
    /// The function called.
    pub(crate) function: Fn,
    /// The call's number among the function's calls in this process (counted from 1).
    pub(crate) n: u64,
    /// The call's number among all calls of the process, of any function (counted from 1).
    pub(crate) seq: u64,
    /// The rules that the call meets (indices into the plan), chosen once, before the call
    /// reaches the module.
    rules: Vec<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileText {
    #[serde(default)]
    rule: Vec<RuleText>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(clippy::struct_excessive_bools, reason = "the plan's TOML: each flag a rule may give")]
struct RuleText {
    #[serde(rename = "fn")]
    function: String,
    call: Option<u64>,
    nth: Option<u64>,
    from: Option<u64>,
    from_seq: Option<u64>,
    of_label: Option<String>,
    mechanism: Option<Value>,
    class: Option<Value>,
    key_type: Option<Value>,
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
    wrap_label: Option<String>,
    hide_label: Option<String>,
    replace_label: Option<String>,
    #[serde(default)]
    corrupt: bool,
    replay_output: Option<usize>,
    #[serde(default)]
    transcode: bool,
    #[serde(default)]
    hide_mechanisms: Vec<Value>,
    #[serde(default)]
    abort: bool,
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
    /// Returns a plan with no rules, under which the shim forwards everything unchanged.
    fn default() -> Plan {
        Plan::new(Vec::new())
    }
}

impl Plan {
    fn new(rules: Vec<Rule>) -> Plan {
        let zeros = |n: usize| (0..n).map(|_| AtomicU64::new(0)).collect();
        Plan { counts: zeros(Fn::ALL.len()), met: zeros(rules.len()), rules, seq: AtomicU64::new(0) }
    }

    /// Parses a plan.
    ///
    /// # Errors
    ///
    /// Returns the TOML error, or the error of the first rule that names an unknown function,
    /// field or value, counts calls from 0, does nothing, does two things, or does something
    /// that its function cannot do. A plan that tests nothing is refused and never run.
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

    /// Returns the rules, in file order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Counts a call of `function` (the first call is 1), with no rule chosen for it yet.
    #[must_use]
    pub(crate) fn counted(&self, function: Fn) -> Call {
        let n = self.counts[function as usize].fetch_add(1, Ordering::Relaxed) + 1;
        Call { function, n, seq: self.seq.fetch_add(1, Ordering::Relaxed) + 1, rules: Vec::new() }
    }

    /// Counts a call of `function` and chooses its rules without any knowledge of its
    /// arguments, so a rule with a matcher on the arguments never meets the call.
    #[must_use]
    pub fn count(&self, function: Fn) -> Call {
        let mut call = self.counted(function);
        let _ = self.select(&mut call, &Detail::default(), |_, _| Ok(false));
        call
    }

    /// Chooses the rules that `call` meets, by what was read from its arguments before the call
    /// (`about`). A rule is chosen when all of its matchers hold, and `is_of(label, objects)`
    /// says whether one of `objects` has the label `label`. `nth` and `from` count only the
    /// calls that met every other matcher.
    ///
    /// # Errors
    ///
    /// Returns the error of `is_of` when a label could not be resolved. The rules after that
    /// rule are not chosen.
    pub(crate) fn select(
        &self,
        call: &mut Call,
        about: &Detail,
        is_of: impl std::ops::Fn(&[u8], &[CK_OBJECT_HANDLE]) -> Result<bool, Fatal>,
    ) -> Result<(), Fatal> {
        for (i, r) in self.rules.iter().enumerate() {
            let met = r.function.is_none_or(|f| f == call.function)
                && r.call.is_none_or(|n| n == call.n)
                && r.from_seq.is_none_or(|n| call.seq >= n)
                && r.mechanism.is_none_or(|m| about.mechanism == Some(m))
                && r.class.is_none_or(|c| about.classes.contains(&c))
                && r.key_type.is_none_or(|k| about.key_types.contains(&k));
            if !met {
                continue;
            }
            if let Some(label) = &r.of_label
                && !is_of(label, r.looks_at(&about.objects))?
            {
                continue;
            }
            if r.nth.is_some() || r.from.is_some() {
                let k = self.met[i].fetch_add(1, Ordering::Relaxed) + 1;
                if r.nth.is_some_and(|n| n != k) || r.from.is_some_and(|n| k < n) {
                    continue;
                }
            }
            call.rules.push(i);
        }
        Ok(())
    }

    /// Returns the rules that `call` meets, each with its number in the plan (counted from 1).
    pub fn matching<'a>(&'a self, call: &'a Call) -> impl Iterator<Item = (usize, &'a Rule)> {
        call.rules.iter().map(|&i| (i + 1, &self.rules[i]))
    }

    /// Returns the number of the `transcode` rule (counted from 1), if the plan has one. Every
    /// `C_UnwrapKey` undoes the transcoding.
    #[must_use]
    pub(crate) fn transcoder(&self) -> Option<usize> {
        self.rules.iter().position(|r| r.action == Action::Transcode).map(|i| i + 1)
    }

    /// Returns whether a `replay_output` rule names `function`, in which case the function's
    /// outputs are kept.
    #[must_use]
    pub(crate) fn replays(&self, function: Fn) -> bool {
        self.rules.iter().any(|r| r.function == Some(function) && matches!(r.action, Action::ReplayOutput(_)))
    }

    /// Returns what `call` returns instead of reaching the real module, and the number of the
    /// rule (counted from 1) that says so. Returns `None` when the call is forwarded.
    #[must_use]
    pub fn before(&self, call: &Call) -> Option<(CK_RV, usize)> {
        self.rv(call, When::Before)
    }

    /// Returns what `call` returns in place of the real module's answer, and the number of the
    /// rule (counted from 1). Returns `None` when the real answer is returned.
    #[must_use]
    pub fn after(&self, call: &Call) -> Option<(CK_RV, usize)> {
        self.rv(call, When::After)
    }

    /// Returns the number of the rule (counted from 1) that ends the process at `call`, if
    /// any.
    #[must_use]
    pub fn aborts(&self, call: &Call) -> Option<usize> {
        self.matching(call).find_map(|(i, r)| (r.action == Action::Abort).then_some(i))
    }

    fn rv(&self, call: &Call, at: When) -> Option<(CK_RV, usize)> {
        self.matching(call).find_map(|(i, r)| match r.action {
            Action::Rv { rv, when } if when == at => Some((rv, i)),
            _ => None,
        })
    }
}

/// Returns the functions whose forwarder runs one of `hooks` (in the table of forward.rs). The
/// hooks `substitute_key`, `wrap_key` and `unwrap_key` belong to the functions whose third
/// argument is the key that they use (the key that `use_label` substitutes). The hooks
/// `corrupt_output` and `wrap_key` belong to the functions that return bytes through a buffer and
/// its length (the bytes that `corrupt` and `replay_output` change).
fn hooked(hooks: &[&str]) -> Vec<Fn> {
    Fn::ALL.iter().copied().filter(|f| f.hook().is_some_and(|h| hooks.contains(&h))).collect()
}

/// Returns what an attribute rule says about its attribute: `drop`, `value`, `from_label`,
/// `length` and `truncate`, each taken out of `r`.
fn attribute_changes(r: &mut RuleText) -> Result<Vec<AttributeChange>, String> {
    let mut changes = Vec::new();
    if r.drop {
        changes.push(AttributeChange::Drop);
    }
    if let Some(hex) = &r.value {
        changes.push(AttributeChange::Value(unhex(hex).ok_or("value is hex")?));
    }
    if let Some(label) = r.from_label.take() {
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
    Ok(changes)
}

/// The `mechanism`, `class` and `key_type` that a rule matches.
type Arguments = (Option<CK_MECHANISM_TYPE>, Option<CK_OBJECT_CLASS>, Option<CK_KEY_TYPE>);

/// Returns what a rule does to the bytes that a function returns (its `corrupt`,
/// `replay_output` and `transcode`), checked by `only` against the functions that return bytes.
/// `narrowed` is true when the rule gives a matcher besides its function.
fn output_actions(
    (corrupt, replay, transcode): (bool, Option<usize>, bool),
    narrowed: bool,
    only: impl std::ops::Fn(&[Fn], &str) -> Result<(), String>,
) -> Result<Vec<Action>, String> {
    let mut actions = Vec::new();
    if corrupt {
        only(&hooked(&["corrupt_output", "wrap_key"]), "corrupt")?;
        actions.push(Action::Corrupt);
    }
    if let Some(k) = replay {
        only(&hooked(&["corrupt_output", "wrap_key"]), "replay_output")?;
        if k == 0 {
            return Err("replay_output = 0: the latest earlier output is 1".into());
        }
        actions.push(Action::ReplayOutput(k));
    }
    if transcode {
        only(&[Fn::C_WrapKey], "transcode")?;
        if narrowed {
            return Err("transcode takes no matcher: every C_UnwrapKey undoes it".into());
        }
        actions.push(Action::Transcode);
    }
    Ok(actions)
}

/// Checks whether `function` is one of `functions`. If it is not, the error says that `what` is
/// only for those functions.
fn only(function: Option<Fn>, functions: &[Fn], what: &str) -> Result<(), String> {
    if function.is_some_and(|f| functions.contains(&f)) {
        Ok(())
    } else {
        let names: Vec<&str> = functions.iter().map(|f| f.name()).collect();
        Err(format!("{what} is for {}", names.join(", ")))
    }
}

/// Checks a rule's matchers besides its function: the counts and `of_label`. Then returns the
/// `mechanism`, `class` and `key_type` that the rule gives (taken out of `r`).
fn matchers(function: Option<Fn>, r: &mut RuleText) -> Result<Arguments, String> {
    for (name, n) in [("call", r.call), ("nth", r.nth), ("from", r.from), ("from_seq", r.from_seq)] {
        if n == Some(0) {
            return Err(format!("{name} = 0: calls are counted from 1"));
        }
    }
    if [r.call, r.nth, r.from].iter().flatten().count() > 1 {
        return Err("one of call, nth and from: each counts its calls another way".into());
    }
    let any_argument = r.of_label.is_some() || r.mechanism.is_some() || r.class.is_some() || r.key_type.is_some();
    if function.is_none() && (r.call.is_some() || any_argument) {
        return Err("fn = \"*\" matches every function: by from_seq, nth or from, never by call or an argument".into());
    }
    // A matcher on the arguments is allowed only where the function's arguments are read before
    // the call (in the table of forward.rs). On another function, the matcher would never match,
    // and the rule would never fire.
    let reading = |kinds: &[&str], what: &str| {
        let functions: Vec<Fn> =
            Fn::ALL.iter().copied().filter(|f| f.reads().iter().any(|k| kinds.contains(k))).collect();
        only(function, &functions, what)
    };
    if r.of_label.is_some() {
        reading(&["object"], "of_label")?;
    }
    let matcher = |value: Option<Value>, kinds: &[&str], what: &str, by_name: fn(&str) -> Option<u64>| {
        value.map(|v| reading(kinds, what).and_then(|()| v.resolve(what, by_name))).transpose()
    };
    Ok((
        matcher(r.mechanism.take(), &["mechanism", "mechanism_type"], "mechanism", names::mechanism)?,
        matcher(r.class.take(), &["template"], "class", names::class)?,
        matcher(r.key_type.take(), &["template"], "key_type", names::key_type)?,
    ))
}

fn rule(mut r: RuleText) -> Result<Rule, String> {
    let function = if r.function == "*" {
        None
    } else {
        Some(Fn::ALL.iter().copied().find(|f| f.name() == r.function).ok_or_else(|| {
            if r.function == "C_GetFunctionList" {
                "the entry point itself cannot be faulted".to_owned()
            } else {
                "no such PKCS#11 2.40 function".to_owned()
            }
        })?)
    };
    // The `of_label` of a `replace_label` rule names the objects that the rule replaces, not
    // the objects that the call names, because a search names no object.
    let replace = r.replace_label.take().map(|by| (r.of_label.take(), by));
    let (mechanism, class, key_type) = matchers(function, &mut r)?;
    let only = |functions: &[Fn], what: &str| only(function, functions, what);
    // The flag must belong to the structure that the rule's function returns. The flag words of
    // the slot and of the token reuse bit values, so a slot flag on `C_GetTokenInfo` would set
    // a different flag (plan.rs F1).
    let (word, by_name): (_, fn(&str) -> Option<CK_FLAGS>) = if function == Some(Fn::C_GetSlotInfo) {
        ("slot flag", names::slot_flag)
    } else {
        ("token flag", names::token_flag)
    };
    let flags = |values: Vec<Value>| -> Result<CK_FLAGS, String> {
        values.into_iter().try_fold(0, |all, v| Ok(all | v.resolve(word, by_name)?))
    };
    let mut changes = attribute_changes(&mut r)?;
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
        only(&hooked(&["substitute_key", "wrap_key", "unwrap_key"]), "use_label")?;
        actions.push(Action::UseLabel(label.into_bytes()));
    }
    if let Some(label) = r.wrap_label {
        only(&[Fn::C_WrapKey], "wrap_label")?;
        actions.push(Action::WrapLabel(label.into_bytes()));
    }
    if let Some(label) = r.hide_label {
        only(&[Fn::C_FindObjects], "hide_label")?;
        actions.push(Action::HideLabel(label.into_bytes()));
    }
    if let Some((of, by)) = replace {
        only(&[Fn::C_FindObjects], "replace_label")?;
        let of = of.ok_or("replace_label goes with of_label, the label of the objects it replaces")?;
        actions.push(Action::ReplaceLabel { of: of.into_bytes(), by: by.into_bytes() });
    }
    let narrowed = [r.call, r.nth, r.from, r.from_seq, mechanism, class, key_type].iter().any(Option::is_some);
    let output = (r.corrupt, r.replay_output, r.transcode);
    actions.extend(output_actions(output, narrowed || r.of_label.is_some(), only)?);
    if !r.hide_mechanisms.is_empty() {
        only(&[Fn::C_GetMechanismList], "hide_mechanisms")?;
        let hidden = r.hide_mechanisms.into_iter().map(|m| m.resolve("mechanism", names::mechanism));
        actions.push(Action::HideMechanisms(hidden.collect::<Result<_, _>>()?));
    }
    if r.abort {
        actions.push(Action::Abort);
    }
    let action = match actions.len() {
        1 => actions.remove(0),
        0 => {
            return Err("nothing to do: give rv, set_flags, clear_flags, attribute, add_label, hide_label, \
                        replace_label, use_label, wrap_label, corrupt, replay_output, transcode, \
                        hide_mechanisms or abort"
                .into());
        }
        _ => return Err("one thing per rule".into()),
    };
    if function.is_none() && !matches!(action, Action::Rv { .. } | Action::Abort) {
        return Err("fn = \"*\" gives rv or abort".into());
    }
    Ok(Rule {
        function,
        call: r.call,
        nth: r.nth,
        from: r.from,
        from_seq: r.from_seq,
        of_label: r.of_label.map(String::into_bytes),
        mechanism,
        class,
        key_type,
        action,
    })
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
        CK_ATTRIBUTE, CKA_EC_POINT, CKA_KEY_TYPE, CKF_USER_PIN_FINAL_TRY, CKF_WRITE_PROTECTED, CKK_AES, CKM_ECDSA,
        CKM_SHA256_RSA_PKCS, CKR_DEVICE_ERROR, CKR_PIN_INCORRECT,
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
        // Calls are counted for each function.
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
             [[rule]]\nfn = \"C_DecryptInit\"\nof_label = \"shown\"\nuse_label = \"used\"\n\n\
             [[rule]]\nfn = \"C_WrapKey\"\nof_label = \"shown\"\nwrap_label = \"wrapped\"\n\n\
             [[rule]]\nfn = \"C_WrapKey\"\nuse_label = \"used\"\n\n\
             [[rule]]\nfn = \"C_DestroyObject\"\nof_label = \"k\"\nrv = \"CKR_OK\"\n\n\
             [[rule]]\nfn = \"*\"\nfrom_seq = 40\nrv = \"CKR_DEVICE_REMOVED\"\n\n\
             [[rule]]\nfn = \"C_SignInit\"\nmechanism = \"CKM_ECDSA\"\nnth = 2\nrv = \"CKR_DEVICE_ERROR\"\n\n\
             [[rule]]\nfn = \"C_GenerateKey\"\nclass = \"CKO_SECRET_KEY\"\nkey_type = \"CKK_AES\"\nfrom = 3\nabort = true\n\n\
             [[rule]]\nfn = \"C_FindObjects\"\nof_label = \"k\"\nreplace_label = \"k-other\"\n\n\
             [[rule]]\nfn = \"C_WrapKey\"\ncorrupt = true\n\n\
             [[rule]]\nfn = \"C_Sign\"\nreplay_output = 2\n\n\
             [[rule]]\nfn = \"C_WrapKey\"\ntranscode = true\n",
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
        assert_eq!(*actions[6], Action::WrapLabel(b"wrapped".to_vec()));
        assert_eq!(*actions[7], Action::UseLabel(b"used".to_vec()));
        assert_eq!(plan.rules()[1].of_label.as_deref(), Some(&b"k"[..]));
        assert_eq!(plan.rules()[6].of_label.as_deref(), Some(&b"shown"[..]));
        assert_eq!(*actions[12], Action::ReplaceLabel { of: b"k".to_vec(), by: b"k-other".to_vec() });
        // The rule's label names what it replaces, not the calls that it meets, because a
        // search names no object.
        assert_eq!(plan.rules()[12].of_label, None);
        assert_eq!(*actions[13], Action::Corrupt);
        assert_eq!(*actions[14], Action::ReplayOutput(2));
        assert_eq!(*actions[15], Action::Transcode);
        assert_eq!((plan.transcoder(), plan.replays(Fn::C_Sign), plan.replays(Fn::C_WrapKey)), (Some(16), true, false));
        // An attribute rule or a flag rule does not change the return value.
        let call = plan.count(Fn::C_GetTokenInfo);
        assert_eq!((plan.before(&call), plan.after(&call)), (None, None));
        assert_eq!(plan.matching(&call).map(|(i, _)| i).collect::<Vec<_>>(), [1]);
        // A slot rule uses the slot's own flag names.
        let slot =
            Plan::parse("[[rule]]\nfn = \"C_GetSlotInfo\"\nclear_flags = [\"CKF_TOKEN_PRESENT\", \"CKF_HW_SLOT\"]\n");
        assert_eq!(slot.unwrap().rules()[0].action, Action::Flags { set: 0, clear: 1 | 4 });
    }

    /// `nth` and `from` count only the calls that meet the rule's other matchers (its function,
    /// mechanism, label and template), not every call of its function. `fn = "*"` with
    /// `from_seq` meets the calls of every function from the process's n-th call on, and no
    /// call before it.
    #[test]
    fn nth_counts_only_matching_calls() {
        let plan = Plan::parse(
            "[[rule]]\nfn = \"C_SignInit\"\nmechanism = \"CKM_ECDSA\"\nnth = 2\nrv = \"CKR_DEVICE_ERROR\"\n\n\
             [[rule]]\nfn = \"C_DestroyObject\"\nof_label = \"k\"\nfrom = 2\nrv = \"CKR_OK\"\n\n\
             [[rule]]\nfn = \"C_GenerateKey\"\nkey_type = \"CKK_AES\"\nnth = 1\nabort = true\n\n\
             [[rule]]\nfn = \"*\"\nfrom_seq = 12\nrv = \"CKR_DEVICE_REMOVED\"\n",
        )
        .unwrap();
        // Object 7 has the label `k`, and no other object has it.
        let k = |_: &[u8], objects: &[CK_OBJECT_HANDLE]| Ok(objects.contains(&7));
        let rules = |function, about: &Detail| {
            let mut call = plan.counted(function);
            plan.select(&mut call, about, k).unwrap();
            (call.seq, plan.matching(&call).map(|(i, _)| i).collect::<Vec<_>>())
        };
        let mechanism = |m| {
            let mut d = Detail::default();
            d.mechanism_type(m);
            d
        };
        let object = |o| {
            let mut d = Detail::default();
            d.object(o);
            d
        };
        let mut aes = CKK_AES.to_ne_bytes();
        let template = |value: &mut [u8; 8]| {
            let entry = CK_ATTRIBUTE { type_: CKA_KEY_TYPE, pValue: value.as_mut_ptr().cast(), ulValueLen: 8 };
            let mut d = Detail::default();
            // SAFETY: one entry of ours, its value 8 bytes.
            unsafe { d.template(&raw const entry, 1) };
            d
        };
        let (rsa, ecdsa) = (mechanism(CKM_SHA256_RSA_PKCS), mechanism(CKM_ECDSA));
        let calls = [
            (Fn::C_SignInit, &rsa, vec![]),
            (Fn::C_SignInit, &ecdsa, vec![]),
            (Fn::C_SignInit, &rsa, vec![]),
            (Fn::C_SignInit, &ecdsa, vec![1]),
            (Fn::C_SignInit, &ecdsa, vec![]),
            (Fn::C_DestroyObject, &object(8), vec![]),
            (Fn::C_DestroyObject, &object(7), vec![]),
            (Fn::C_DestroyObject, &object(8), vec![]),
            (Fn::C_DestroyObject, &object(7), vec![2]),
            (Fn::C_GenerateKey, &Detail::default(), vec![]),
            (Fn::C_GenerateKey, &template(&mut aes), vec![3]),
            (Fn::C_Login, &Detail::default(), vec![4]),
            (Fn::C_DestroyObject, &object(7), vec![2, 4]),
        ];
        for (seq, (function, about, want)) in (1..).zip(calls) {
            assert_eq!(rules(function, about), (seq, want), "call {seq}, {}", function.name());
        }
    }

    /// `abort` ends the process only at its call. It takes no return value, and a rule does
    /// only one thing.
    #[test]
    fn abort_ends_the_process_at_its_call() {
        let plan = Plan::parse("[[rule]]\nfn = \"C_UnwrapKey\"\ncall = 2\nabort = true\n").unwrap();
        let (first, second) = (plan.count(Fn::C_UnwrapKey), plan.count(Fn::C_UnwrapKey));
        assert_eq!((plan.aborts(&first), plan.aborts(&second)), (None, Some(1)));
        assert_eq!((plan.before(&second), plan.after(&second)), (None, None));
        let two = Plan::parse("[[rule]]\nfn = \"C_UnwrapKey\"\nabort = true\nrv = \"CKR_DEVICE_ERROR\"\n");
        assert_eq!(two.err().as_deref(), Some("rule 1 (C_UnwrapKey): one thing per rule"));
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
            ("[[rule]]\nfn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_RW_SESSION\"]\n", "unknown token flag"),
            // Each flag word has its own names (plan.rs F1). A slot flag on the token's word
            // would set the token flag with the same value (CKF_HW_SLOT has the value 4 of
            // CKF_LOGIN_REQUIRED), and the reverse.
            ("[[rule]]\nfn = \"C_GetTokenInfo\"\nset_flags = [\"CKF_HW_SLOT\"]\n", "unknown token flag CKF_HW_SLOT"),
            ("[[rule]]\nfn = \"C_GetTokenInfo\"\nclear_flags = [\"CKF_TOKEN_PRESENT\"]\n", "unknown token flag"),
            ("[[rule]]\nfn = \"C_GetSlotInfo\"\nset_flags = [\"CKF_LOGIN_REQUIRED\"]\n", "unknown slot flag"),
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
            // Only C_WrapKey has a wrapped key, as its fourth argument.
            ("[[rule]]\nfn = \"C_UnwrapKey\"\nwrap_label = \"x\"\n", "wrap_label is for C_WrapKey"),
            ("[[rule]]\nfn = \"C_WrapKey\"\nwrap_label = \"x\"\nuse_label = \"y\"\n", "one thing per rule"),
            ("[[rule]]\nfn = \"C_FindObjectsInit\"\nadd_label = \"x\"\n", "add_label is for C_FindObjects"),
            ("[[rule]]\nfn = \"C_FindObjects\"\nadd_label = \"x\"\nrv = 0\n", "one thing per rule"),
            ("[[rule]]\nfn = \"C_FindObjects\"\nadd_label = \"x\"\nof_label = \"y\"\n", "of_label is for C_CopyObject"),
            ("[[rule]]\nfn = \"C_Login\"\nof_label = \"y\"\nrv = 0\n", "of_label is for"),
            // Each count starts from 1, and a rule counts its calls in only one way.
            ("[[rule]]\nfn = \"C_Login\"\nnth = 0\nrv = 0\n", "nth = 0: calls are counted from 1"),
            ("[[rule]]\nfn = \"C_Login\"\nfrom = 0\nrv = 0\n", "from = 0: calls are counted from 1"),
            ("[[rule]]\nfn = \"C_Login\"\nfrom_seq = 0\nrv = 0\n", "from_seq = 0: calls are counted from 1"),
            ("[[rule]]\nfn = \"C_Login\"\ncall = 1\nnth = 1\nrv = 0\n", "one of call, nth and from"),
            ("[[rule]]\nfn = \"C_Login\"\nnth = 1\nfrom = 1\nrv = 0\n", "one of call, nth and from"),
            // A rule for every function may give a return value or an abort, counted over the
            // process's calls.
            ("[[rule]]\nfn = \"*\"\ncall = 3\nrv = 0\n", "fn = \"*\" matches every function"),
            ("[[rule]]\nfn = \"*\"\nof_label = \"k\"\nrv = 0\n", "fn = \"*\" matches every function"),
            ("[[rule]]\nfn = \"*\"\nhide_label = \"k\"\n", "hide_label is for C_FindObjects"),
            // A matcher is allowed only where the function's arguments carry its value before
            // the call.
            ("[[rule]]\nfn = \"C_Login\"\nmechanism = \"CKM_ECDSA\"\nrv = 0\n", "mechanism is for C_GetMechanismInfo"),
            ("[[rule]]\nfn = \"C_SignInit\"\nmechanism = \"CKM_NOPE\"\nrv = 0\n", "unknown mechanism CKM_NOPE"),
            ("[[rule]]\nfn = \"C_GetAttributeValue\"\nclass = \"CKO_DATA\"\nrv = 0\n", "class is for C_CreateObject"),
            ("[[rule]]\nfn = \"C_FindObjectsInit\"\nclass = \"CKO_NOPE\"\nrv = 0\n", "unknown class CKO_NOPE"),
            ("[[rule]]\nfn = \"C_SignInit\"\nkey_type = \"CKK_EC\"\nrv = 0\n", "key_type is for C_CreateObject"),
            ("[[rule]]\nfn = \"C_GenerateKey\"\nkey_type = \"CKK_NOPE\"\nrv = 0\n", "unknown key_type CKK_NOPE"),
            ("[[rule]]\nfn = \"C_FindObjectsInit\"\nhide_label = \"x\"\n", "hide_label is for C_FindObjects"),
            (
                "[[rule]]\nfn = \"C_Verify\"\ncorrupt = true\n",
                "corrupt is for C_Encrypt, C_Decrypt, C_Sign, C_SignFinal, C_WrapKey",
            ),
            // A replacement names what it replaces, and a replay names an earlier output. Every
            // unwrap undoes a transcoded blob, so no matcher may select the wraps that the rule
            // transcodes.
            ("[[rule]]\nfn = \"C_FindObjects\"\nreplace_label = \"x\"\n", "replace_label goes with of_label"),
            (
                "[[rule]]\nfn = \"C_SignInit\"\nof_label = \"k\"\nreplace_label = \"x\"\n",
                "replace_label is for C_FindObjects",
            ),
            ("[[rule]]\nfn = \"C_Sign\"\nreplay_output = 0\n", "replay_output = 0: the latest earlier output is 1"),
            ("[[rule]]\nfn = \"C_FindObjects\"\nreplay_output = 1\n", "replay_output is for C_Encrypt"),
            ("[[rule]]\nfn = \"C_Sign\"\ntranscode = true\n", "transcode is for C_WrapKey"),
            ("[[rule]]\nfn = \"C_WrapKey\"\ncall = 2\ntranscode = true\n", "transcode takes no matcher"),
            ("[[rule]]\nfn = \"C_WrapKey\"\ncorrupt = true\ntranscode = true\n", "one thing per rule"),
            ("[[rule]]\nfn = \"C_GetMechanismList\"\nhide_mechanisms = [\"CKM_NOPE\"]\n", "unknown mechanism CKM_NOPE"),
            (
                "[[rule]]\nfn = \"C_GetMechanismInfo\"\nhide_mechanisms = [\"CKM_ECDSA\"]\n",
                "hide_mechanisms is for C_GetMechanismList",
            ),
        ] {
            let Err(e) = Plan::parse(text) else { panic!("accepted: {text}") };
            assert!(e.contains(why), "expected {why:?} in {e:?}");
        }
    }
}
