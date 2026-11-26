//! What the plan's rules do besides changing a return value: the few functions whose arguments
//! or outputs a rule changes. Each function forwards the call to the real module itself and
//! returns what the caller sees, with the number of the rule (counted from 1) that changed it, if
//! a rule did.
//!
//! Rules name objects by `CKA_LABEL`. The shim resolves a label through its own session on the
//! caller's slot, so a search that the caller has open is never disturbed.

use crate::plan::{Action, AttributeChange, Call};
use crate::{Fatal, Shim};
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_BYTE, CK_MECHANISM, CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE,
    CK_RV, CK_SESSION_HANDLE, CK_SESSION_INFO, CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CKA_CLASS, CKA_LABEL,
    CKF_RW_SESSION, CKF_SERIAL_SESSION, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_OK,
    CKR_SESSION_READ_WRITE_SO_EXISTS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::os::raw::c_void;
use std::sync::{Mutex, PoisonError};

/// What a hooked call returns: the value for the caller, and the rule that changed something.
pub(crate) type Outcome = Result<(CK_RV, Option<usize>), Fatal>;

/// `CK_UNAVAILABLE_INFORMATION`, which is the length of an attribute that cannot be given.
const UNAVAILABLE: CK_ULONG = CK_ULONG::MAX;

/// Returns the real module's function `$name`, or the reason why the call cannot be
/// forwarded.
macro_rules! real {
    ($shim:expr, $name:ident) => {
        $shim.real.$name.ok_or_else(|| Fatal(format!("{} has no function", stringify!($name))))?
    };
}

/// `C_GetTokenInfo`: returns the real answer with a rule's flags set and cleared.
pub(crate) unsafe fn token_info(shim: &Shim, call: &Call, slot: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) -> Outcome {
    // SAFETY: the caller's arguments, forwarded unchanged.
    let rv = unsafe { real!(shim, C_GetTokenInfo)(slot, info) };
    if rv != CKR_OK || info.is_null() {
        return Ok((rv, None));
    }
    // SAFETY: not null, and the real module just filled it.
    Ok((rv, flags(shim, call, unsafe { &mut (*info).flags })))
}

/// `C_GetSlotInfo`: returns the real answer with a rule's flags set and cleared.
pub(crate) unsafe fn slot_info(shim: &Shim, call: &Call, slot: CK_SLOT_ID, info: *mut CK_SLOT_INFO) -> Outcome {
    // SAFETY: the caller's arguments, forwarded unchanged.
    let rv = unsafe { real!(shim, C_GetSlotInfo)(slot, info) };
    if rv != CKR_OK || info.is_null() {
        return Ok((rv, None));
    }
    // SAFETY: not null, and the real module just filled it.
    Ok((rv, flags(shim, call, unsafe { &mut (*info).flags })))
}

fn flags(shim: &Shim, call: &Call, flags: &mut CK_ULONG) -> Option<usize> {
    let mut fired = None;
    for (i, rule) in shim.plan.matching(call) {
        if let Action::Flags { set, clear } = rule.action {
            *flags = (*flags | set) & !clear;
            fired.get_or_insert(i);
        }
    }
    fired
}

/// `C_FindObjects`: the objects of a `hide_label` rule are not found, and the objects of a
/// `replace_label` rule are replaced by other objects. When the real search found something and
/// there is room, the objects of an `add_label` rule are also found. (They are not added when the
/// search found nothing, because a client reads until a call returns no object, and it would
/// never stop.)
pub(crate) unsafe fn find_objects(
    shim: &Shim,
    call: &Call,
    session: CK_SESSION_HANDLE,
    out: *mut CK_OBJECT_HANDLE,
    max: CK_ULONG,
    count: *mut CK_ULONG,
) -> Outcome {
    // SAFETY: the caller's arguments, forwarded unchanged.
    let rv = unsafe { real!(shim, C_FindObjects)(session, out, max, count) };
    if rv != CKR_OK || out.is_null() || count.is_null() {
        return Ok((rv, None));
    }
    let room = usize::try_from(max).unwrap_or(0);
    // SAFETY: `count` is not null and the real module wrote it. `out` holds `max` handles, of
    // which the first `*count` are set. A count above `max` from the module is not trusted.
    let set = usize::try_from(unsafe { *count }).unwrap_or(0).min(room);
    let mut found = unsafe { std::slice::from_raw_parts(out, set).to_vec() };
    // What the search returned in earlier batches, which is tracked only when a rule adds to the
    // search or replaces objects in it.
    let adds = shim.plan.rules().iter().any(|r| matches!(r.action, Action::AddLabel(_) | Action::ReplaceLabel { .. }));
    let earlier = if adds { shim.searches.returned(session) } else { BTreeSet::new() };
    let mut fired = None;
    for (i, rule) in shim.plan.matching(call) {
        match &rule.action {
            Action::HideLabel(label) => {
                // SAFETY: real-module calls on the caller's session.
                let hidden = unsafe { named(shim, session, label, None)? };
                let before = found.len();
                found.retain(|h| !hidden.contains(h));
                if found.len() != before {
                    fired.get_or_insert(i);
                }
            }
            Action::ReplaceLabel { of, by } => {
                // SAFETY: real-module calls on the caller's session and the handles it found.
                unsafe {
                    for h in named(shim, session, of, None)? {
                        let Some(at) = found.iter().position(|f| *f == h) else { continue };
                        // A label with no object is an error in the plan, as for `use_label`.
                        let other = named(shim, session, by, class_of(shim, session, h))?.first().copied();
                        let other = other.ok_or_else(|| {
                            let by = String::from_utf8_lossy(by);
                            Fatal(format!("replace_label: no object labelled {by} of the class of the one replaced"))
                        })?;
                        // The replacement is found once per search, as an added object is.
                        if found.contains(&other) || earlier.contains(&other) {
                            found.remove(at);
                        } else {
                            found[at] = other;
                        }
                        fired.get_or_insert(i);
                    }
                }
            }
            Action::AddLabel(label) if !found.is_empty() => {
                // SAFETY: real-module calls on the caller's session.
                for h in unsafe { named(shim, session, label, None)? } {
                    if found.len() < room && !found.contains(&h) && !earlier.contains(&h) {
                        found.push(h);
                        fired.get_or_insert(i);
                    }
                }
            }
            _ => {}
        }
    }
    if fired.is_some() {
        // SAFETY: `found` holds at most `max` handles, which `out` has room for.
        unsafe {
            std::ptr::copy_nonoverlapping(found.as_ptr(), out, found.len());
            *count = found.len() as CK_ULONG;
        }
    }
    if adds {
        shim.searches.add(session, &found);
    }
    Ok((rv, fired))
}

/// What the open search of each caller session has returned so far. This is kept while a plan
/// adds objects to searches (`add_label`), so that an added object is found once per search: it
/// is not found again in a later batch, and it is not added when an earlier batch already
/// returned it. PKCS#11 lets a module return a search's matches over several batches, and a
/// client that reads until a batch comes back empty would otherwise see the object twice. The
/// record is cleared when the session starts or ends a search.
#[derive(Default)]
pub(crate) struct Searches(Mutex<BTreeMap<CK_SESSION_HANDLE, BTreeSet<CK_OBJECT_HANDLE>>>);

impl Searches {
    fn held(&self) -> std::sync::MutexGuard<'_, BTreeMap<CK_SESSION_HANDLE, BTreeSet<CK_OBJECT_HANDLE>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn returned(&self, session: CK_SESSION_HANDLE) -> BTreeSet<CK_OBJECT_HANDLE> {
        self.held().get(&session).cloned().unwrap_or_default()
    }

    fn add(&self, session: CK_SESSION_HANDLE, handles: &[CK_OBJECT_HANDLE]) {
        self.held().entry(session).or_default().extend(handles);
    }

    fn end(&self, session: CK_SESSION_HANDLE) {
        self.held().remove(&session);
    }
}

/// `C_FindObjectsInit`: starts a new search on the session, which has returned nothing yet.
pub(crate) unsafe fn find_objects_init(
    shim: &Shim,
    _call: &Call,
    session: CK_SESSION_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> Outcome {
    shim.searches.end(session);
    // SAFETY: the caller's arguments, forwarded unchanged.
    Ok((unsafe { real!(shim, C_FindObjectsInit)(session, template, count) }, None))
}

/// `C_FindObjectsFinal`: ends the session's search.
pub(crate) unsafe fn find_objects_final(shim: &Shim, _call: &Call, session: CK_SESSION_HANDLE) -> Outcome {
    shim.searches.end(session);
    // SAFETY: the caller's argument, forwarded unchanged.
    Ok((unsafe { real!(shim, C_FindObjectsFinal)(session) }, None))
}

/// `C_GetMechanismList`: returns the real list without the mechanisms of a `hide_mechanisms`
/// rule.
pub(crate) unsafe fn mechanism_list(
    shim: &Shim,
    call: &Call,
    slot: CK_SLOT_ID,
    list: *mut CK_MECHANISM_TYPE,
    count: *mut CK_ULONG,
) -> Outcome {
    // This reads the caller's room before the real module overwrites `count` with the length.
    // SAFETY: `count` is read only when it is not null.
    let room = if count.is_null() { 0 } else { usize::try_from(unsafe { *count }).unwrap_or(0) };
    // SAFETY: the caller's arguments, forwarded unchanged.
    let rv = unsafe { real!(shim, C_GetMechanismList)(slot, list, count) };
    if rv != CKR_OK || list.is_null() || count.is_null() {
        // A length query returns the real module's length, which a shorter list may not fill.
        return Ok((rv, None));
    }
    // SAFETY: `count` is not null, and the real module wrote it and that many mechanisms. `list`
    // holds `room` entries. A count above `room` from the module is not trusted.
    let written = usize::try_from(unsafe { *count }).unwrap_or(0).min(room);
    let mut listed = unsafe { std::slice::from_raw_parts(list, written).to_vec() };
    let mut fired = None;
    for (i, rule) in shim.plan.matching(call) {
        if let Action::HideMechanisms(hidden) = &rule.action {
            let before = listed.len();
            listed.retain(|m| !hidden.contains(m));
            if listed.len() != before {
                fired.get_or_insert(i);
            }
        }
    }
    if fired.is_some() {
        // SAFETY: no more mechanisms than the real module wrote there.
        unsafe {
            std::ptr::copy_nonoverlapping(listed.as_ptr(), list, listed.len());
            *count = listed.len() as CK_ULONG;
        }
    }
    Ok((rv, fired))
}

/// The value that `transcode` XORs into every byte of a wrapped key, and that `C_UnwrapKey`
/// removes again.
const PAD: u8 = 0x5a;

/// Forwards a function that returns bytes into the caller's buffer `out` of `*len` bytes, with
/// `real`, and changes what it returned where a rule says so ([`change_output`]).
///
/// # Safety
///
/// `len` is null or readable and writable, and `out` is null or `*len` writable bytes, as the
/// function's contract requires. `real` makes the real call with them.
pub(crate) unsafe fn corrupt_output(
    shim: &Shim,
    call: &Call,
    out: *mut u8,
    len: *mut CK_ULONG,
    real: impl FnOnce() -> CK_RV,
) -> (CK_RV, Option<usize>) {
    // SAFETY: the caller's arguments, under its contract.
    unsafe {
        let room = room(len);
        let rv = real();
        (rv, change_output(shim, call, out, len, room, rv))
    }
}

/// Returns the caller's room behind `len`. It must be read before the real module overwrites it
/// with the length that the module wrote.
///
/// # Safety
///
/// `len` is null or readable.
unsafe fn room(len: *const CK_ULONG) -> usize {
    // SAFETY: `len` is read only when it is not null.
    if len.is_null() { 0 } else { usize::try_from(unsafe { *len }).unwrap_or(0) }
}

/// Changes what a call that returned `rv` wrote into the caller's buffer `out` (of `room` bytes,
/// with `*len` bytes written), by the rules that `call` meets, in plan order. `corrupt` changes
/// the last byte. `replay_output` puts back what the function returned that many calls before,
/// when there was such a call and its output fits the room. `transcode` XORs every byte with
/// [`PAD`]. Returns the first rule that changed the output, if one did. A length query (no
/// buffer) is left unchanged, and so is a length that the caller's buffer cannot hold, because a
/// count above the given room from the module is not trusted, as in `find_objects`. What the
/// module really returned is kept for a later replay when a rule names the function.
///
/// # Safety
///
/// As [`corrupt_output`], once the real call has returned `rv`.
unsafe fn change_output(
    shim: &Shim,
    call: &Call,
    out: *mut u8,
    len: *mut CK_ULONG,
    room: usize,
    rv: CK_RV,
) -> Option<usize> {
    if rv != CKR_OK || out.is_null() || len.is_null() {
        return None;
    }
    // SAFETY: not null; the real module wrote the length there.
    let n = usize::try_from(unsafe { *len }).unwrap_or(0);
    if n == 0 || n > room {
        return None;
    }
    // SAFETY: the first `n` bytes of the caller's buffer, which the module filled.
    let real = unsafe { std::slice::from_raw_parts(out, n) }.to_vec();
    let mut output = real.clone();
    let mut fired = None;
    for (i, rule) in shim.plan.matching(call) {
        let changed = match rule.action {
            Action::Corrupt => {
                output[n - 1] ^= 0x01;
                true
            }
            Action::ReplayOutput(k) => match shim.outputs.earlier(call.function, k) {
                Some(earlier) if earlier.len() <= room => {
                    output = earlier;
                    true
                }
                _ => false,
            },
            Action::Transcode => {
                for b in &mut output {
                    *b ^= PAD;
                }
                true
            }
            _ => false,
        };
        if changed {
            fired.get_or_insert(i);
        }
    }
    if shim.plan.replays(call.function) {
        shim.outputs.keep(call.function, real);
    }
    if fired.is_some() {
        // SAFETY: `output` holds at most `room` bytes, which the caller's buffer has.
        unsafe {
            std::ptr::copy_nonoverlapping(output.as_ptr(), out, output.len());
            *len = output.len() as CK_ULONG;
        }
    }
    fired
}

/// What the functions that a `replay_output` rule names have returned, in order, for each
/// function.
#[derive(Default)]
pub(crate) struct Outputs(Mutex<BTreeMap<usize, Vec<Vec<u8>>>>);

impl Outputs {
    fn held(&self) -> std::sync::MutexGuard<'_, BTreeMap<usize, Vec<Vec<u8>>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns what `function` returned `k` calls ago (1 means the latest call), if it has
    /// returned that many times.
    fn earlier(&self, function: crate::Fn, k: usize) -> Option<Vec<u8>> {
        let held = self.held();
        let kept = held.get(&(function as usize))?;
        kept.len().checked_sub(k).map(|at| kept[at].clone())
    }

    fn keep(&self, function: crate::Fn, output: Vec<u8>) {
        self.held().entry(function as usize).or_default().push(output);
    }
}

/// Returns the key that a function that takes a key uses: the caller's key, or the object that a
/// `use_label` rule names (of the class of the caller's key).
pub(crate) unsafe fn substitute_key(
    shim: &Shim,
    call: &Call,
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
) -> Result<(CK_OBJECT_HANDLE, Option<usize>), Fatal> {
    let used = |action: &Action| match action {
        Action::UseLabel(label) => Some(label.clone()),
        _ => None,
    };
    // SAFETY: the caller's session and handle.
    unsafe { substitute(shim, call, session, key, "use_label", used) }
}

/// `C_WrapKey`: uses the wrapping key that a `use_label` rule names, and wraps the key that a
/// `wrap_label` rule names, each of the class of the caller's key, in place of the caller's keys.
/// A `wrap_label` rule's `of_label` names the key that is wrapped, and the blob then holds a
/// different key from the one that the caller sees.
#[expect(clippy::too_many_arguments, reason = "C_WrapKey's arguments, after the shim and the call")]
pub(crate) unsafe fn wrap_key(
    shim: &Shim,
    call: &Call,
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    wrapped: CK_OBJECT_HANDLE,
    out: *mut CK_BYTE,
    len: *mut CK_ULONG,
) -> Outcome {
    let other = |action: &Action| match action {
        Action::WrapLabel(label) => Some(label.clone()),
        _ => None,
    };
    // SAFETY: real-module calls on the caller's session and handles.
    let ((key, used), (wrapped, swapped)) = unsafe {
        (substitute_key(shim, call, session, key)?, substitute(shim, call, session, wrapped, "wrap_label", other)?)
    };
    // SAFETY: the caller's arguments, with the handles the rules name in place of the caller's;
    // then the blob it returned, as `corrupt_output` reads it.
    unsafe {
        let room = room(len);
        let rv = real!(shim, C_WrapKey)(session, mechanism, key, wrapped, out, len);
        Ok((rv, used.or(swapped).or(change_output(shim, call, out, len, room, rv))))
    }
}

/// `C_UnwrapKey`: uses the key that a `use_label` rule names in place of the unwrapping key.
/// When the plan transcodes what `C_WrapKey` returns, the transcoding is first undone on a copy
/// of the caller's blob, and the caller's blob is left as it was.
#[expect(clippy::too_many_arguments, reason = "C_UnwrapKey's arguments, after the shim and the call")]
pub(crate) unsafe fn unwrap_key(
    shim: &Shim,
    call: &Call,
    session: CK_SESSION_HANDLE,
    mechanism: *mut CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
    blob: *mut CK_BYTE,
    blob_len: CK_ULONG,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
    unwrapped: *mut CK_OBJECT_HANDLE,
) -> Outcome {
    // SAFETY: real-module calls on the caller's session and handle.
    let (key, used) = unsafe { substitute_key(shim, call, session, key)? };
    let undone = shim.plan.transcoder().filter(|_| !blob.is_null()).map(|i| {
        // SAFETY: the caller's blob of `blob_len` bytes, as `C_UnwrapKey` requires.
        let blob = unsafe { std::slice::from_raw_parts(blob, usize::try_from(blob_len).unwrap_or(0)) };
        (blob.iter().map(|b| b ^ PAD).collect::<Vec<u8>>(), i)
    });
    let (mut copy, transcoded) = undone.map_or((None, None), |(copy, i)| (Some(copy), Some(i)));
    let blob = copy.as_mut().map_or(blob, Vec::as_mut_ptr);
    // SAFETY: the caller's arguments, with the key a rule names and the blob undone in place of
    // the caller's; the copy lives past the call.
    let rv = unsafe { real!(shim, C_UnwrapKey)(session, mechanism, key, blob, blob_len, template, count, unwrapped) };
    Ok((rv, used.or(transcoded)))
}

/// Returns the handle that a function uses in place of the caller's `handle`: the caller's
/// handle, or the object of the same class that the first matching rule names. `label_of`
/// returns the label of a rule's action, and `what` is the kind of rule, for the message.
unsafe fn substitute(
    shim: &Shim,
    call: &Call,
    session: CK_SESSION_HANDLE,
    handle: CK_OBJECT_HANDLE,
    what: &str,
    label_of: impl Fn(&Action) -> Option<Vec<u8>>,
) -> Result<(CK_OBJECT_HANDLE, Option<usize>), Fatal> {
    for (i, rule) in shim.plan.matching(call) {
        let Some(label) = label_of(&rule.action) else { continue };
        // SAFETY: real-module calls on the caller's session and handles.
        unsafe {
            // A label with no object is an error in the plan, as for `from_label`. If the caller's
            // own key were used under a rule that the trace reports as fired, a test would pass
            // for the wrong reason (hooks.rs F1).
            let class = class_of(shim, session, handle);
            let other = named(shim, session, &label, class)?.first().copied().ok_or_else(|| {
                Fatal(format!("{what}: no object labelled {} of the key's class", String::from_utf8_lossy(&label)))
            })?;
            return Ok((other, Some(i)));
        }
    }
    Ok((handle, None))
}

/// `C_GetAttributeValue`: the shim answers the attributes that a rule names, and the real module
/// answers the other attributes, in the caller's template.
pub(crate) unsafe fn attribute_value(
    shim: &Shim,
    call: &Call,
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    template: *mut CK_ATTRIBUTE,
    count: CK_ULONG,
) -> Outcome {
    let get = real!(shim, C_GetAttributeValue);
    let mut rules = Vec::new();
    for (i, rule) in shim.plan.matching(call) {
        if let Action::Attribute { attribute, change } = &rule.action {
            rules.push((i, *attribute, change));
        }
    }
    let n = usize::try_from(count).unwrap_or(0);
    if rules.is_empty() || template.is_null() || n == 0 {
        // SAFETY: the caller's arguments, forwarded unchanged.
        return Ok((unsafe { get(session, object, template, count) }, None));
    }
    // SAFETY: the caller's template of `count` entries, as PKCS#11 requires of it.
    let entries = unsafe { std::slice::from_raw_parts_mut(template, n) };
    let rule_for = |ty: CK_ATTRIBUTE_TYPE| rules.iter().find(|(_, attribute, _)| *attribute == ty);
    // The real module answers the entries that no rule names, through a template that holds
    // only those entries.
    let (mut rest, mut at) = (Vec::new(), Vec::new());
    for (i, e) in entries.iter().enumerate() {
        if rule_for(e.type_).is_none() {
            rest.push(*e);
            at.push(i);
        }
    }
    if rest.len() == n {
        // SAFETY: the caller's arguments, forwarded unchanged.
        return Ok((unsafe { get(session, object, template, count) }, None));
    }
    let mut rv = if rest.is_empty() {
        CKR_OK
    } else {
        // SAFETY: a template of the caller's own entries (their buffers and lengths).
        unsafe { get(session, object, rest.as_mut_ptr(), rest.len() as CK_ULONG) }
    };
    for (e, i) in rest.iter().zip(at) {
        entries[i].ulValueLen = e.ulValueLen;
    }
    let mut fired = None;
    for e in entries.iter_mut() {
        let Some((i, _, change)) = rule_for(e.type_) else { continue };
        fired.get_or_insert(*i);
        // SAFETY: real-module calls on the caller's session and handles.
        let value = unsafe {
            match change {
                AttributeChange::Drop => Err(CKR_ATTRIBUTE_TYPE_INVALID),
                AttributeChange::Unavailable => Err(CKR_OK),
                AttributeChange::Value(v) => Ok(v.clone()),
                AttributeChange::FromLabel(label) => {
                    let class = class_of(shim, session, object);
                    let mut others = named(shim, session, label, class)?;
                    if others.is_empty() {
                        others = named(shim, session, label, None)?;
                    }
                    let other = others.first().ok_or_else(|| {
                        Fatal(format!("from_label: no object labelled {}", String::from_utf8_lossy(label)))
                    })?;
                    value_of(shim, session, *other, e.type_)
                }
                AttributeChange::Truncate(keep) => value_of(shim, session, object, e.type_).map(|mut v| {
                    v.truncate(*keep);
                    v
                }),
            }
        };
        let status = match value {
            // SAFETY: the caller's entry: its buffer holds the `ulValueLen` bytes it came with.
            Ok(v) => unsafe { serve(e, &v) },
            Err(status) => {
                e.ulValueLen = UNAVAILABLE;
                status
            }
        };
        if rv == CKR_OK {
            rv = status;
        }
    }
    Ok((rv, fired))
}

/// Answers the caller's entry with `value`: its length, and its bytes where the caller gave a
/// buffer that holds them. When the buffer is too small, the answer is `CKR_BUFFER_TOO_SMALL`
/// with an unavailable length.
///
/// # Safety
///
/// `entry.pValue` is null or points to `entry.ulValueLen` writable bytes.
unsafe fn serve(entry: &mut CK_ATTRIBUTE, value: &[u8]) -> CK_RV {
    let len = value.len() as CK_ULONG;
    if entry.pValue.is_null() {
        entry.ulValueLen = len;
        return CKR_OK;
    }
    if entry.ulValueLen < len {
        entry.ulValueLen = UNAVAILABLE;
        return CKR_BUFFER_TOO_SMALL;
    }
    // SAFETY: the buffer holds at least `len` bytes (checked above), and `value` is ours.
    unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), entry.pValue.cast::<u8>(), value.len()) };
    entry.ulValueLen = len;
    CKR_OK
}

/// Returns the real value of `attribute` on `object`, or the real module's refusal.
unsafe fn value_of(
    shim: &Shim,
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    attribute: CK_ATTRIBUTE_TYPE,
) -> Result<Vec<u8>, CK_RV> {
    let Some(get) = shim.real.C_GetAttributeValue else { return Err(CKR_ATTRIBUTE_TYPE_INVALID) };
    let mut entry = CK_ATTRIBUTE { type_: attribute, pValue: std::ptr::null_mut(), ulValueLen: 0 };
    // SAFETY: a one-entry template of ours: first for the length, then with a buffer of it.
    unsafe {
        let rv = get(session, object, &raw mut entry, 1);
        if rv != CKR_OK || entry.ulValueLen == UNAVAILABLE {
            return Err(if rv == CKR_OK { CKR_ATTRIBUTE_TYPE_INVALID } else { rv });
        }
        let mut value = vec![0u8; usize::try_from(entry.ulValueLen).unwrap_or(0)];
        entry.pValue = value.as_mut_ptr().cast::<c_void>();
        let rv = get(session, object, &raw mut entry, 1);
        if rv != CKR_OK {
            return Err(rv);
        }
        value.truncate(usize::try_from(entry.ulValueLen).unwrap_or(0));
        Ok(value)
    }
}

/// Returns the `CKA_CLASS` of `object`, if the real module gives it.
///
/// # Safety
///
/// As `value_of`: a real-module call on the caller's session and handle.
pub(crate) unsafe fn class_of(
    shim: &Shim,
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
) -> Option<CK_OBJECT_CLASS> {
    // SAFETY: as `value_of`.
    let value = unsafe { value_of(shim, session, object, CKA_CLASS) }.ok()?;
    Some(CK_OBJECT_CLASS::from_ne_bytes(value.try_into().ok()?))
}

/// Returns whether one of `objects` has the label `label` on the token that `session` is open
/// on (for an `of_label` matcher). It returns false when the call names no session.
///
/// # Safety
///
/// As `named`.
pub(crate) unsafe fn is_of(
    shim: &Shim,
    session: Option<CK_SESSION_HANDLE>,
    objects: &[CK_OBJECT_HANDLE],
    label: &[u8],
) -> Result<bool, Fatal> {
    let Some(session) = session.filter(|_| !objects.is_empty()) else { return Ok(false) };
    // SAFETY: as `named`.
    let named = unsafe { named(shim, session, label, None)? };
    Ok(objects.iter().any(|o| named.contains(o)))
}

/// Returns the objects with the label `label` (of `class`, when it is given) on the token that
/// `session` is open on, found through the shim's own session. Returns no objects when the
/// caller's session is not a valid session.
unsafe fn named(
    shim: &Shim,
    session: CK_SESSION_HANDLE,
    label: &[u8],
    class: Option<CK_OBJECT_CLASS>,
) -> Result<Vec<CK_OBJECT_HANDLE>, Fatal> {
    let failed = |what: &str, rv: CK_RV| Fatal(format!("resolving a label: {what} returned {rv:#x}"));
    let mut class = class;
    let mut template = vec![CK_ATTRIBUTE {
        type_: CKA_LABEL,
        pValue: label.as_ptr().cast_mut().cast(),
        ulValueLen: label.len() as CK_ULONG,
    }];
    if let Some(class) = &mut class {
        template.push(CK_ATTRIBUTE {
            type_: CKA_CLASS,
            pValue: std::ptr::from_mut(class).cast(),
            ulValueLen: size_of::<CK_OBJECT_CLASS>() as CK_ULONG,
        });
    }
    // SAFETY: real-module calls with arguments of ours, on a session opened and closed here.
    unsafe {
        let mut info = std::mem::zeroed::<CK_SESSION_INFO>();
        if real!(shim, C_GetSessionInfo)(session, &raw mut info) != CKR_OK {
            return Ok(Vec::new());
        }
        let mut own = 0;
        let open = real!(shim, C_OpenSession);
        let mut rv = open(info.slotID, CKF_SERIAL_SESSION, std::ptr::null_mut(), None, &raw mut own);
        // A read-only session is refused while the caller holds an SO session (PKCS #11,
        // C_OpenSession), and a read-write session reads the same objects (review 2026-11-23
        // B-17).
        if rv == CKR_SESSION_READ_WRITE_SO_EXISTS {
            rv = open(info.slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, std::ptr::null_mut(), None, &raw mut own);
        }
        if rv != CKR_OK {
            return Err(failed("C_OpenSession", rv));
        }
        let mut found = Vec::new();
        let mut what = "C_FindObjectsInit";
        let mut overrun = None;
        let mut rv = real!(shim, C_FindObjectsInit)(own, template.as_mut_ptr(), template.len() as CK_ULONG);
        if rv == CKR_OK {
            what = "C_FindObjects";
            loop {
                let mut batch = [0 as CK_OBJECT_HANDLE; 16];
                let mut n = 0;
                rv = real!(shim, C_FindObjects)(own, batch.as_mut_ptr(), batch.len() as CK_ULONG, &raw mut n);
                if rv != CKR_OK || n == 0 {
                    break;
                }
                // A count beyond the batch is the module's fault. It is reported by name, and it
                // never causes a panic that the guard would turn into a bare CKR_GENERAL_ERROR
                // (review 2026-11-23 B-16).
                let Some(got) = usize::try_from(n).ok().and_then(|n| batch.get(..n)) else {
                    overrun = Some(n);
                    break;
                };
                found.extend_from_slice(got);
            }
            real!(shim, C_FindObjectsFinal)(own);
        }
        real!(shim, C_CloseSession)(own);
        if let Some(n) = overrun {
            return Err(Fatal(format!("resolving a label: C_FindObjects returned {n} handles into room for 16")));
        }
        if rv == CKR_OK { Ok(found) } else { Err(failed(what, rv)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Fn, fake};
    use cryptoki_sys::{CK_FLAGS, CK_NOTIFY, CKR_DEVICE_ERROR};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    /// The caller's session, the shim's own session (opened to resolve a label), and the one
    /// object with the label that the rules name.
    const CALLER: CK_SESSION_HANDLE = 1;
    const OWN: CK_SESSION_HANDLE = 99;
    const LABELLED: CK_OBJECT_HANDLE = 7;

    thread_local! {
        /// The batches that the caller's search returns, in turn, and then no more batches.
        static BATCHES: RefCell<VecDeque<Vec<CK_OBJECT_HANDLE>>> = const { RefCell::new(VecDeque::new()) };
        /// What the shim's own search still has to return.
        static OWN_LEFT: RefCell<Vec<CK_OBJECT_HANDLE>> = const { RefCell::new(Vec::new()) };
        /// The value that `C_FindObjectsInit` on the shim's own session returns.
        static OWN_INIT: Cell<CK_RV> = const { Cell::new(CKR_OK) };
        /// Whether the caller holds an SO session, in which case a read-only session is
        /// refused.
        static SO_HELD: Cell<bool> = const { Cell::new(false) };
        /// A count that `C_FindObjects` reports on the shim's own session instead of the length
        /// of its batch.
        static OWN_COUNT: Cell<CK_ULONG> = const { Cell::new(0) };
        /// The objects under each label, when a test names them. The shim's own search then
        /// finds the objects of the label in its template. When this is empty, the search
        /// finds [`LABELLED`] for any label.
        static LABELS: RefCell<Vec<(&'static [u8], Vec<CK_OBJECT_HANDLE>)>> = const { RefCell::new(Vec::new()) };
        /// The wrapping key and the wrapped key that the last `C_WrapKey` received.
        static WRAPPED: Cell<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE)> = const { Cell::new((0, 0)) };
        /// The blob that the last `C_UnwrapKey` received.
        static UNWRAPPED: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    }

    unsafe extern "C" fn get_session_info(_: CK_SESSION_HANDLE, info: *mut CK_SESSION_INFO) -> CK_RV {
        // SAFETY: the shim's own `CK_SESSION_INFO`.
        unsafe { (*info).slotID = 0 };
        CKR_OK
    }

    unsafe extern "C" fn open_session(
        _: CK_SLOT_ID,
        flags: CK_FLAGS,
        _: *mut c_void,
        _: CK_NOTIFY,
        out: *mut CK_SESSION_HANDLE,
    ) -> CK_RV {
        if SO_HELD.get() && flags & CKF_RW_SESSION == 0 {
            return CKR_SESSION_READ_WRITE_SO_EXISTS;
        }
        // SAFETY: the shim's own handle.
        unsafe { *out = OWN };
        CKR_OK
    }

    unsafe extern "C" fn session_ok(_: CK_SESSION_HANDLE) -> CK_RV {
        CKR_OK
    }

    unsafe extern "C" fn find_init(session: CK_SESSION_HANDLE, template: *mut CK_ATTRIBUTE, n: CK_ULONG) -> CK_RV {
        if session != OWN {
            return CKR_OK;
        }
        let rv = OWN_INIT.get();
        if rv == CKR_OK {
            // SAFETY: the shim's own template of `n` entries, each value as long as it says.
            let label = unsafe { std::slice::from_raw_parts(template, usize::try_from(n).unwrap()) }
                .iter()
                .find(|e| e.type_ == CKA_LABEL)
                .map(|e| unsafe {
                    std::slice::from_raw_parts(e.pValue.cast::<u8>(), usize::try_from(e.ulValueLen).unwrap()).to_vec()
                });
            let found = LABELS.with_borrow(|labels| {
                if labels.is_empty() {
                    return vec![LABELLED];
                }
                labels.iter().find(|(l, _)| Some(*l) == label.as_deref()).map(|(_, h)| h.clone()).unwrap_or_default()
            });
            OWN_LEFT.set(found);
        }
        rv
    }

    unsafe extern "C" fn wrap(
        _: CK_SESSION_HANDLE,
        _: *mut CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
        wrapped: CK_OBJECT_HANDLE,
        out: *mut CK_BYTE,
        len: *mut CK_ULONG,
    ) -> CK_RV {
        WRAPPED.set((key, wrapped));
        // SAFETY: the caller's length, and its buffer of that many bytes where it gave one.
        unsafe {
            if !out.is_null() && *len >= 4 {
                std::ptr::copy_nonoverlapping([1u8, 2, 3, 4].as_ptr(), out, 4);
            }
            *len = 4;
        }
        CKR_OK
    }

    unsafe extern "C" fn unwrap(
        _: CK_SESSION_HANDLE,
        _: *mut CK_MECHANISM,
        _: CK_OBJECT_HANDLE,
        blob: *mut CK_BYTE,
        len: CK_ULONG,
        _: *mut CK_ATTRIBUTE,
        _: CK_ULONG,
        _: *mut CK_OBJECT_HANDLE,
    ) -> CK_RV {
        // SAFETY: the caller's blob of `len` bytes.
        UNWRAPPED.set(unsafe { std::slice::from_raw_parts(blob, usize::try_from(len).unwrap()) }.to_vec());
        CKR_OK
    }

    unsafe extern "C" fn find(
        session: CK_SESSION_HANDLE,
        out: *mut CK_OBJECT_HANDLE,
        max: CK_ULONG,
        count: *mut CK_ULONG,
    ) -> CK_RV {
        if session == OWN && OWN_COUNT.get() > 0 {
            // SAFETY: the shim's own count.
            unsafe { *count = OWN_COUNT.get() };
            return CKR_OK;
        }
        let batch = if session == OWN {
            OWN_LEFT.take()
        } else {
            BATCHES.with_borrow_mut(VecDeque::pop_front).unwrap_or_default()
        };
        assert!(batch.len() <= usize::try_from(max).unwrap(), "a batch the test's caller has no room for");
        // SAFETY: `out` holds `max` handles, at least the batch.
        unsafe {
            std::ptr::copy_nonoverlapping(batch.as_ptr(), out, batch.len());
            *count = batch.len() as CK_ULONG;
        }
        CKR_OK
    }

    /// Returns a module that holds the one labeled object, and whose searches by the caller
    /// return [`BATCHES`].
    fn module() -> cryptoki_sys::CK_FUNCTION_LIST {
        let mut m = crate::empty_table();
        m.C_GetSessionInfo = Some(get_session_info);
        m.C_OpenSession = Some(open_session);
        m.C_CloseSession = Some(session_ok);
        m.C_FindObjectsInit = Some(find_init);
        m.C_FindObjects = Some(find);
        m.C_FindObjectsFinal = Some(session_ok);
        m
    }

    /// Runs one whole search by the caller, reading three handles at a time until a batch comes
    /// back empty, and returns each batch that the caller got.
    fn search(shim: &Shim, batches: &[&[CK_OBJECT_HANDLE]]) -> Vec<Vec<CK_OBJECT_HANDLE>> {
        BATCHES.set(batches.iter().map(|b| b.to_vec()).collect());
        let mut got = Vec::new();
        // SAFETY: a search of the fake module, into buffers of ours.
        unsafe {
            let init = shim.plan.count(Fn::C_FindObjectsInit);
            assert_eq!(find_objects_init(shim, &init, CALLER, std::ptr::null_mut(), 0).unwrap().0, CKR_OK);
            loop {
                let (mut out, mut n) = ([0; 3], 0);
                let call = shim.plan.count(Fn::C_FindObjects);
                assert_eq!(find_objects(shim, &call, CALLER, out.as_mut_ptr(), 3, &raw mut n).unwrap().0, CKR_OK);
                if n == 0 {
                    break;
                }
                got.push(out[..usize::try_from(n).unwrap()].to_vec());
            }
            let fin = shim.plan.count(Fn::C_FindObjectsFinal);
            assert_eq!(find_objects_final(shim, &fin, CALLER).unwrap().0, CKR_OK);
        }
        got
    }

    /// `add_label` adds its object once per search. A search that the module returns over
    /// several batches gets the object in the first batch that finds anything, not in each
    /// batch, and the next search gets it again.
    #[test]
    fn an_added_object_is_found_once_per_search() {
        let shim = fake(&module(), "[[rule]]\nfn = \"C_FindObjects\"\nadd_label = \"decoy\"\n", None);
        assert_eq!(search(&shim, &[&[1, 2], &[3]]), [vec![1, 2, LABELLED], vec![3]]);
        assert_eq!(search(&shim, &[&[4]]), [vec![4, LABELLED]]);
        // The object is not added when an earlier batch of the search already returned it.
        assert_eq!(search(&shim, &[&[LABELLED], &[5]]), [vec![LABELLED], vec![5]]);
    }

    /// A label that cannot be resolved names the call that failed: the start of the search, not
    /// its batches.
    #[test]
    fn a_failed_search_start_is_named_as_such() {
        let shim = fake(&module(), "[[rule]]\nfn = \"C_FindObjects\"\nhide_label = \"decoy\"\n", None);
        OWN_INIT.set(CKR_DEVICE_ERROR);
        BATCHES.set(VecDeque::from([vec![1]]));
        let (mut out, mut n) = ([0; 3], 0);
        let call = shim.plan.count(Fn::C_FindObjects);
        // SAFETY: a search of the fake module, into buffers of ours.
        let fatal = unsafe { find_objects(&shim, &call, CALLER, out.as_mut_ptr(), 3, &raw mut n) }.unwrap_err();
        OWN_INIT.set(CKR_OK);
        assert!(fatal.0.contains("C_FindObjectsInit returned 0x30"), "{}", fatal.0);
    }

    /// A module that reports more handles than the shim's batch holds produces a fault that
    /// names the count, never a panic that the guard answers as a bare `CKR_GENERAL_ERROR`
    /// (review 2026-11-23 B-16).
    #[test]
    fn a_count_past_the_batch_is_named() {
        let shim = fake(&module(), "[[rule]]\nfn = \"C_FindObjects\"\nhide_label = \"decoy\"\n", None);
        OWN_COUNT.set(17);
        BATCHES.set(VecDeque::from([vec![1]]));
        let (mut out, mut n) = ([0; 3], 0);
        let call = shim.plan.count(Fn::C_FindObjects);
        // SAFETY: a search of the fake module, into buffers of ours.
        let fatal = unsafe { find_objects(&shim, &call, CALLER, out.as_mut_ptr(), 3, &raw mut n) }.unwrap_err();
        OWN_COUNT.set(0);
        assert!(fatal.0.contains("C_FindObjects returned 17 handles into room for 16"), "{}", fatal.0);
    }

    /// A label resolves while the caller holds an SO session, when the module refuses the shim a
    /// read-only session: the shim reads through a read-write session (review 2026-11-23 B-17).
    #[test]
    fn a_label_resolves_beside_an_so_session() {
        let shim = fake(&module(), "[[rule]]\nfn = \"C_FindObjects\"\nadd_label = \"decoy\"\n", None);
        SO_HELD.set(true);
        let got = search(&shim, &[&[1]]);
        SO_HELD.set(false);
        assert_eq!(got, [vec![1, LABELLED]]);
    }

    /// `wrap_label` wraps the object that its label names in place of the wrapped key, when
    /// `of_label` names the wrapped key. It does not do so when `of_label` names the wrapping key
    /// or another wrapped key. A label that names nothing is an error in the plan, and the shim
    /// never wraps the caller's key under a rule that it reports as fired.
    #[test]
    fn a_wrap_label_wraps_another_key() {
        let mut m = module();
        m.C_WrapKey = Some(wrap);
        LABELS.set(vec![(b"shown", vec![10]), (b"other", vec![11])]);
        let wrap_of = |shim: &Shim, key, wrapped| {
            let mut about = crate::trace::Detail::default();
            about.session(CALLER);
            about.object(key);
            about.object(wrapped);
            let (call, chosen) = shim.select(Fn::C_WrapKey, &about);
            chosen?;
            let mut len = 0;
            // SAFETY: the fake module's function, which reads no pointer.
            let out = unsafe {
                wrap_key(shim, &call, CALLER, std::ptr::null_mut(), key, wrapped, std::ptr::null_mut(), &raw mut len)
            };
            out.map(|(rv, fired)| (rv, fired, WRAPPED.get()))
        };
        let shim = fake(&m, "[[rule]]\nfn = \"C_WrapKey\"\nof_label = \"shown\"\nwrap_label = \"other\"\n", None);
        assert_eq!(wrap_of(&shim, 5, 10).unwrap(), (CKR_OK, Some(1), (5, 11)));
        assert_eq!(wrap_of(&shim, 10, 12).unwrap(), (CKR_OK, None, (10, 12)));
        let shim = fake(&m, "[[rule]]\nfn = \"C_WrapKey\"\nwrap_label = \"none\"\n", None);
        let fatal = wrap_of(&shim, 5, 10).unwrap_err();
        LABELS.set(Vec::new());
        assert!(fatal.0.contains("wrap_label: no object labelled none"), "{}", fatal.0);
    }

    /// `transcode` changes what `C_WrapKey` returns (never its length query), and every
    /// `C_UnwrapKey` undoes the change on a copy of the caller's blob. The blob round-trips
    /// through the module, but it is not the blob that the module made. Without such a rule,
    /// both calls pass unchanged.
    #[test]
    fn transcode_round_trips() {
        use std::ptr::null_mut as null;
        let mut m = module();
        m.C_WrapKey = Some(wrap);
        m.C_UnwrapKey = Some(unwrap);
        for (plan, fired) in [("[[rule]]\nfn = \"C_WrapKey\"\ntranscode = true\n", Some(1)), ("", None)] {
            let shim = fake(&m, plan, None);
            let (mut blob, mut len) = ([0u8; 8], 0);
            // SAFETY: the fake module's functions, into buffers of ours.
            unsafe {
                let call = shim.plan.count(Fn::C_WrapKey);
                let asked = wrap_key(&shim, &call, CALLER, null(), 5, 6, null(), &raw mut len).unwrap();
                assert_eq!((asked, len), ((CKR_OK, None), 4), "{plan}: the length query");
                len = 8;
                let wrapped = wrap_key(&shim, &call, CALLER, null(), 5, 6, blob.as_mut_ptr(), &raw mut len).unwrap();
                let pad = if fired.is_some() { PAD } else { 0 };
                assert_eq!((wrapped, &blob[..4]), ((CKR_OK, fired), &[1 ^ pad, 2 ^ pad, 3 ^ pad, 4 ^ pad][..]));
                let call = shim.plan.count(Fn::C_UnwrapKey);
                let unwrapped = unwrap_key(&shim, &call, CALLER, null(), 5, blob.as_mut_ptr(), 4, null(), 0, null());
                assert_eq!(unwrapped.unwrap(), (CKR_OK, fired), "{plan}");
            }
            assert_eq!(UNWRAPPED.take(), [1, 2, 3, 4], "{plan}: what the module unwrapped");
            assert_eq!(blob[0], 1 ^ if fired.is_some() { PAD } else { 0 }, "{plan}: the caller's blob");
        }
    }

    /// `replay_output` returns what the function returned that many calls before. It does not do
    /// so when no call came before, or when the earlier output does not fit the caller's buffer.
    /// The shim keeps what the module really returned, never what was replayed.
    #[test]
    fn an_output_is_replayed_from_an_earlier_call() {
        let shim = fake(&crate::empty_table(), "[[rule]]\nfn = \"C_Sign\"\nreplay_output = 1\n", None);
        let sign = |wrote: &[u8], room: usize| {
            let (mut out, mut len) = ([0u8; 4], room as CK_ULONG);
            let (at, call) = (&raw mut len, shim.plan.count(Fn::C_Sign));
            // SAFETY: a buffer of four bytes, of which the caller offers `room`.
            let (_, fired) = unsafe {
                corrupt_output(&shim, &call, out.as_mut_ptr(), at, || {
                    std::ptr::copy_nonoverlapping(wrote.as_ptr(), out.as_mut_ptr(), wrote.len());
                    *at = wrote.len() as CK_ULONG;
                    CKR_OK
                })
            };
            (fired, out[..usize::try_from(len).unwrap()].to_vec())
        };
        assert_eq!(sign(&[1, 2, 3], 4), (None, vec![1, 2, 3]));
        assert_eq!(sign(&[4, 5, 6], 4), (Some(1), vec![1, 2, 3]));
        assert_eq!(sign(&[7, 8], 2), (None, vec![7, 8]), "[4, 5, 6] does not fit");
        assert_eq!(sign(&[9], 4), (Some(1), vec![7, 8]));
    }

    /// `replace_label` finds another object (with the label `by`, of the class of the replaced
    /// object) in place of each object with the label `of`, once per search. When nothing has the
    /// label `by`, the call fails.
    #[test]
    fn a_found_object_is_replaced() {
        LABELS.set(vec![(b"shown", vec![7]), (b"other", vec![8])]);
        let shim = fake(
            &module(),
            "[[rule]]\nfn = \"C_FindObjects\"\nof_label = \"shown\"\nreplace_label = \"other\"\n",
            None,
        );
        assert_eq!(search(&shim, &[&[5, 7]]), [[5, 8]]);
        assert_eq!(search(&shim, &[&[8], &[7]]), [[8]], "found once");
        let shim =
            fake(&module(), "[[rule]]\nfn = \"C_FindObjects\"\nof_label = \"shown\"\nreplace_label = \"none\"\n", None);
        BATCHES.set([vec![7]].into());
        let (mut out, mut n) = ([0; 3], 0);
        let call = shim.plan.count(Fn::C_FindObjects);
        // SAFETY: a search of the fake module, into buffers of ours.
        let fatal = unsafe { find_objects(&shim, &call, CALLER, out.as_mut_ptr(), 3, &raw mut n) }.unwrap_err();
        LABELS.set(Vec::new());
        assert!(fatal.0.contains("replace_label: no object labelled none"), "{}", fatal.0);
    }

    /// `corrupt` changes the last byte that the module returned, inside the caller's buffer. A
    /// byte count above the caller's room from the module is not trusted, and nothing past the
    /// buffer is touched.
    #[test]
    fn corruption_stays_inside_the_callers_buffer() {
        let shim = fake(&crate::empty_table(), "[[rule]]\nfn = \"C_Sign\"\ncorrupt = true\n", None);
        for (wrote, fired, buffer) in [(3, Some(1), [0, 0, 1, 0, 0, 0, 0, 0]), (8, None, [0; 8])] {
            let mut out = [0u8; 8];
            let mut len: CK_ULONG = 4;
            let at = &raw mut len;
            let call = shim.plan.count(Fn::C_Sign);
            // SAFETY: a buffer of eight bytes, of which the caller offers four.
            let (rv, rule) = unsafe {
                corrupt_output(&shim, &call, out.as_mut_ptr(), at, || {
                    *at = wrote;
                    CKR_OK
                })
            };
            assert_eq!((rv, rule, out), (CKR_OK, fired, buffer), "a module that wrote {wrote}");
        }
    }

    /// An attribute that a rule names is served as PKCS#11 serves any attribute: only the length
    /// without a buffer, the bytes into a buffer that holds them, and a refusal for a buffer
    /// that is too small.
    #[test]
    fn a_value_is_served_into_the_callers_entry() {
        let entry = |buffer: Option<&mut [u8]>| CK_ATTRIBUTE {
            type_: CKA_LABEL,
            ulValueLen: buffer.as_ref().map_or(0, |b| b.len() as CK_ULONG),
            pValue: buffer.map_or(std::ptr::null_mut(), |b| b.as_mut_ptr().cast()),
        };
        let mut length_only = entry(None);
        // SAFETY: a null buffer.
        assert_eq!(unsafe { serve(&mut length_only, b"abc") }, CKR_OK);
        assert_eq!(length_only.ulValueLen, 3);
        let mut buffer = [0u8; 4];
        let mut fits = entry(Some(&mut buffer));
        // SAFETY: a buffer of the four bytes the entry says.
        assert_eq!(unsafe { serve(&mut fits, b"abc") }, CKR_OK);
        assert_eq!((fits.ulValueLen, &buffer[..3]), (3, &b"abc"[..]));
        let mut small = [0u8; 2];
        let mut short = entry(Some(&mut small));
        // SAFETY: a buffer of the two bytes the entry says.
        assert_eq!(unsafe { serve(&mut short, b"abc") }, CKR_BUFFER_TOO_SMALL);
        assert_eq!((short.ulValueLen, small), (UNAVAILABLE, [0, 0]));
    }
}
