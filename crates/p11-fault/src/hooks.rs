//! What the plan's rules do beyond a return value: the few functions whose arguments or
//! outputs a rule changes. Each forwards to the real module itself and returns what the caller
//! sees, with the rule (from 1) that changed it, if one did.
//!
//! Objects are named by `CKA_LABEL` and resolved through a session of the shim's own on the
//! caller's slot, so a search the caller has open is never disturbed.

use crate::plan::{Action, AttributeChange, Call};
use crate::{Fatal, Shim};
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_ATTRIBUTE_TYPE, CK_MECHANISM_TYPE, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE,
    CK_SESSION_INFO, CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CKA_CLASS, CKA_LABEL, CKF_RW_SESSION,
    CKF_SERIAL_SESSION, CKR_ATTRIBUTE_TYPE_INVALID, CKR_BUFFER_TOO_SMALL, CKR_OK, CKR_SESSION_READ_WRITE_SO_EXISTS,
};
use std::collections::{BTreeMap, BTreeSet};
use std::os::raw::c_void;
use std::sync::{Mutex, PoisonError};

/// What a hooked call returns: the caller's value, and the rule that changed something.
pub(crate) type Outcome = Result<(CK_RV, Option<usize>), Fatal>;

/// `CK_UNAVAILABLE_INFORMATION`: the length of an attribute that cannot be given.
const UNAVAILABLE: CK_ULONG = CK_ULONG::MAX;

/// The real module's function `$name`, or why the call cannot be forwarded.
macro_rules! real {
    ($shim:expr, $name:ident) => {
        $shim.real.$name.ok_or_else(|| Fatal(format!("{} has no function", stringify!($name))))?
    };
}

/// `C_GetTokenInfo`: the real answer with a rule's flags set and cleared.
pub(crate) unsafe fn token_info(shim: &Shim, call: &Call, slot: CK_SLOT_ID, info: *mut CK_TOKEN_INFO) -> Outcome {
    // SAFETY: the caller's arguments, forwarded unchanged.
    let rv = unsafe { real!(shim, C_GetTokenInfo)(slot, info) };
    if rv != CKR_OK || info.is_null() {
        return Ok((rv, None));
    }
    // SAFETY: not null, and the real module just filled it.
    Ok((rv, flags(shim, call, unsafe { &mut (*info).flags })))
}

/// `C_GetSlotInfo`: the real answer with a rule's flags set and cleared.
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

/// `C_FindObjects`: the objects of a `hide_label` rule are not found; and where the real search
/// found something and there is room, those of an `add_label` rule are found too. (Not where it
/// found nothing: a client reads until a call returns no object, and would never stop.)
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
    // SAFETY: `count` is not null and the real module wrote it; `out` holds `max` handles, of
    // which the first `*count` are set. A module that reports more than `max` is not believed.
    let set = usize::try_from(unsafe { *count }).unwrap_or(0).min(room);
    let mut found = unsafe { std::slice::from_raw_parts(out, set).to_vec() };
    // What the search returned in earlier batches, where a rule adds to it.
    let adds = shim.plan.rules().iter().any(|r| matches!(r.action, Action::AddLabel(_)));
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

/// What each caller session's open search has returned so far, kept while a plan adds objects
/// to searches (`add_label`): an added object is found once per search, never again in a later
/// batch, nor when an earlier batch already returned it. PKCS#11 lets a module return a search's
/// matches over several batches, and a client that reads until a batch comes back empty would
/// otherwise see the object twice. Forgotten when the session starts or ends a search.
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

/// `C_FindObjectsInit`: a new search on the session, which has returned nothing yet.
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

/// `C_FindObjectsFinal`: the session's search is over.
pub(crate) unsafe fn find_objects_final(shim: &Shim, _call: &Call, session: CK_SESSION_HANDLE) -> Outcome {
    shim.searches.end(session);
    // SAFETY: the caller's argument, forwarded unchanged.
    Ok((unsafe { real!(shim, C_FindObjectsFinal)(session) }, None))
}

/// `C_GetMechanismList`: the mechanisms of a `hide_mechanisms` rule are not listed.
pub(crate) unsafe fn mechanism_list(
    shim: &Shim,
    call: &Call,
    slot: CK_SLOT_ID,
    list: *mut CK_MECHANISM_TYPE,
    count: *mut CK_ULONG,
) -> Outcome {
    // The caller's room, before the real module overwrites `count` with the length.
    // SAFETY: read only when not null.
    let room = if count.is_null() { 0 } else { usize::try_from(unsafe { *count }).unwrap_or(0) };
    // SAFETY: the caller's arguments, forwarded unchanged.
    let rv = unsafe { real!(shim, C_GetMechanismList)(slot, list, count) };
    if rv != CKR_OK || list.is_null() || count.is_null() {
        // The length alone: the real module's, which a shorter list may fall short of.
        return Ok((rv, None));
    }
    // SAFETY: `count` is not null and the real module wrote it and that many mechanisms; `list`
    // holds `room`. A module that reports more than `room` is not believed.
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

/// A function returning bytes into the caller's buffer `out` of `*len` bytes, forwarded by
/// `real`: under a `corrupt` rule, the last of the bytes it returned is another. The length
/// query (no buffer) is left alone, and so is a length the caller's buffer cannot hold: a module
/// that reports more than the room it was given is not believed, as in `find_objects`.
///
/// # Safety
///
/// `len` is null or readable and writable, and `out` null or `*len` writable bytes, as the
/// function's contract requires; `real` makes the real call with them.
pub(crate) unsafe fn corrupt_output(
    shim: &Shim,
    call: &Call,
    out: *mut u8,
    len: *mut CK_ULONG,
    real: impl FnOnce() -> CK_RV,
) -> (CK_RV, Option<usize>) {
    // The caller's room, before the real module overwrites `len` with the length it wrote.
    // SAFETY: read only when not null.
    let room = if len.is_null() { 0 } else { usize::try_from(unsafe { *len }).unwrap_or(0) };
    let rv = real();
    if rv != CKR_OK || out.is_null() || len.is_null() {
        return (rv, None);
    }
    let Some((i, _)) = shim.plan.matching(call).find(|(_, rule)| rule.action == Action::Corrupt) else {
        return (rv, None);
    };
    // SAFETY: not null; the real module wrote the length there.
    let n = usize::try_from(unsafe { *len }).unwrap_or(0);
    if n == 0 || n > room {
        return (rv, None);
    }
    // SAFETY: `n - 1` is inside the caller's buffer of `room` bytes, which the module filled.
    unsafe { *out.add(n - 1) ^= 0x01 };
    (rv, Some(i))
}

/// The key a key-taking function uses: the caller's, or the object a `use_label` rule names
/// (of the caller's key's class).
pub(crate) unsafe fn substitute_key(
    shim: &Shim,
    call: &Call,
    session: CK_SESSION_HANDLE,
    key: CK_OBJECT_HANDLE,
) -> Result<(CK_OBJECT_HANDLE, Option<usize>), Fatal> {
    for (i, rule) in shim.plan.matching(call) {
        let Action::UseLabel(label) = &rule.action else { continue };
        // SAFETY: real-module calls on the caller's session and handles.
        unsafe {
            if !is_of(shim, session, key, rule.of_label.as_deref())? {
                continue;
            }
            // Nothing under the label is the plan's mistake, as for `from_label`: the caller's own
            // key run under a rule the trace says fired would pass a test for the wrong reason
            // (hooks.rs F1).
            let class = class_of(shim, session, key);
            let other = named(shim, session, label, class)?.first().copied().ok_or_else(|| {
                Fatal(format!("use_label: no object labelled {} of the key's class", String::from_utf8_lossy(label)))
            })?;
            return Ok((other, Some(i)));
        }
    }
    Ok((key, None))
}

/// `C_GetAttributeValue`: the attributes a rule names are answered by the shim, the others by
/// the real module, in the caller's template.
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
        if let Action::Attribute { attribute, change } = &rule.action
            // SAFETY: real-module calls on the caller's session and handle.
            && unsafe { is_of(shim, session, object, rule.of_label.as_deref())? }
        {
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
    // The real module answers the entries no rule names, through a template of only those.
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

/// Answer the caller's entry with `value`: its length, and its bytes where the caller gave a
/// buffer that holds them (`CKR_BUFFER_TOO_SMALL` and an unavailable length where it does not).
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

/// The real value of `attribute` on `object`, or the real module's refusal.
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

/// `CKA_CLASS` of `object`, if the real module gives it.
unsafe fn class_of(shim: &Shim, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> Option<CK_OBJECT_CLASS> {
    // SAFETY: as `value_of`.
    let value = unsafe { value_of(shim, session, object, CKA_CLASS) }.ok()?;
    Some(CK_OBJECT_CLASS::from_ne_bytes(value.try_into().ok()?))
}

/// Whether a rule for objects labelled `label` applies to `object`: every object without one.
unsafe fn is_of(
    shim: &Shim,
    session: CK_SESSION_HANDLE,
    object: CK_OBJECT_HANDLE,
    label: Option<&[u8]>,
) -> Result<bool, Fatal> {
    match label {
        None => Ok(true),
        // SAFETY: as `named`.
        Some(label) => Ok(unsafe { named(shim, session, label, None)? }.contains(&object)),
    }
}

/// The objects labelled `label` (of `class`, when given) on the token `session` is open on,
/// found through a session of the shim's own. None when the caller's session is no session.
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
        // A read-only session is refused while the caller holds an SO one (PKCS #11, C_OpenSession):
        // a read-write one reads the same objects (review 2026-11-23 B-17).
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
                // A count past the batch is the module's fault, named, never a panic the guard
                // turns into a bare CKR_GENERAL_ERROR (review 2026-11-23 B-16).
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

    /// The caller's session, the shim's own (opened to resolve a label), and the one object
    /// labelled as the rules say.
    const CALLER: CK_SESSION_HANDLE = 1;
    const OWN: CK_SESSION_HANDLE = 99;
    const LABELLED: CK_OBJECT_HANDLE = 7;

    thread_local! {
        /// The batches the caller's search returns, in turn; then none.
        static BATCHES: RefCell<VecDeque<Vec<CK_OBJECT_HANDLE>>> = const { RefCell::new(VecDeque::new()) };
        /// What the shim's own search has still to return.
        static OWN_LEFT: RefCell<Vec<CK_OBJECT_HANDLE>> = const { RefCell::new(Vec::new()) };
        /// What `C_FindObjectsInit` on the shim's own session returns.
        static OWN_INIT: Cell<CK_RV> = const { Cell::new(CKR_OK) };
        /// The caller holds an SO session: a read-only one is refused.
        static SO_HELD: Cell<bool> = const { Cell::new(false) };
        /// A count `C_FindObjects` reports on the shim's own session instead of its batch.
        static OWN_COUNT: Cell<CK_ULONG> = const { Cell::new(0) };
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

    unsafe extern "C" fn find_init(session: CK_SESSION_HANDLE, _: *mut CK_ATTRIBUTE, _: CK_ULONG) -> CK_RV {
        if session != OWN {
            return CKR_OK;
        }
        let rv = OWN_INIT.get();
        if rv == CKR_OK {
            OWN_LEFT.set(vec![LABELLED]);
        }
        rv
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

    /// A module holding the one labelled object, whose caller searches return [`BATCHES`].
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

    /// One whole search by the caller, read until a batch comes back empty, three at a time:
    /// each batch it got.
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

    /// `add_label` adds its object once per search: a search the module returns over several
    /// batches gets it in the first that finds anything, not in each; the next search, again.
    #[test]
    fn an_added_object_is_found_once_per_search() {
        let shim = fake(&module(), "[[rule]]\nfn = \"C_FindObjects\"\nadd_label = \"decoy\"\n", None);
        assert_eq!(search(&shim, &[&[1, 2], &[3]]), [vec![1, 2, LABELLED], vec![3]]);
        assert_eq!(search(&shim, &[&[4]]), [vec![4, LABELLED]]);
        // Nor beside the object itself, when an earlier batch of the search returned it.
        assert_eq!(search(&shim, &[&[LABELLED], &[5]]), [vec![LABELLED], vec![5]]);
    }

    /// A label that cannot be resolved names the call that failed: the search's start, not its
    /// batches.
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

    /// A module reporting more handles than the shim's batch holds is a fault named by its count,
    /// never a panic the guard answers as a bare `CKR_GENERAL_ERROR` (review 2026-11-23 B-16).
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

    /// A label resolves while the caller holds an SO session, where the module refuses the shim
    /// a read-only one: it reads through a read-write one (review 2026-11-23 B-17).
    #[test]
    fn a_label_resolves_beside_an_so_session() {
        let shim = fake(&module(), "[[rule]]\nfn = \"C_FindObjects\"\nadd_label = \"decoy\"\n", None);
        SO_HELD.set(true);
        let got = search(&shim, &[&[1]]);
        SO_HELD.set(false);
        assert_eq!(got, [vec![1, LABELLED]]);
    }

    /// `corrupt` changes the last byte the module returned, inside the caller's buffer; a module
    /// that reports more bytes than the caller had room for is not believed, and nothing past
    /// the buffer is touched.
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

    /// A ruled attribute is served as PKCS#11 serves any: the length alone without a buffer, the
    /// bytes into one that holds them, and a too-small buffer refused.
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
