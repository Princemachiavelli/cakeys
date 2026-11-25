//! The scratch slot: the write probes' objects, their cleanup and the stale check
//! (docs/CAPROBE.md).

use super::{
    Answer, Attribute, AttributeType, BTreeMap, BoundKey, Capability, Draft, Made, ObjectHandle, Result, Session,
    Target, ckr, extras, moves, probe_bound, probe_curves, probe_key_wraps, probe_rsa, probe_secrets, probe_wrapping,
    secrets,
};

/// The objects the write probes make on their target: where they may write ([`Target`]), what
/// they made and under which labels, for the cleanup and the leftover check.
pub(super) struct Scratch {
    pub(super) target: Target,
    pub(super) handles: Vec<ObjectHandle>,
    pub(super) labels: Vec<String>,
    /// The last `cakeys-probe-NN` label handed out.
    pub(super) n: usize,
}

impl Scratch {
    pub(super) fn label(&mut self) -> String {
        self.n += 1;
        format!("cakeys-probe-{:02}", self.n)
    }

    /// Track `handles`, made under `label`, for the cleanup and the leftover check.
    pub(super) fn track(&mut self, handles: &[ObjectHandle], label: &str) {
        self.handles.extend_from_slice(handles);
        if !self.labels.iter().any(|l| l == label) {
            self.labels.push(label.to_owned());
        }
    }

    pub(super) fn destroy_all(&self, session: &Session) {
        for h in &self.handles {
            // Deletion failures are observations here: the leftover check reports them.
            let _ = session.destroy_object(*h);
        }
    }

    /// After a probe failed: destroy what the run made, by handle, then anything still under its
    /// labels (a pair whose lookup failed is tracked by label alone). Not measured: a run that
    /// writes no profile records no `delete` row.
    pub(super) fn destroy_after_failure(&self, session: &Session) {
        self.destroy_all(session);
        for l in &self.labels {
            for h in session.find_objects(&[Attribute::Label(l.as_bytes().to_vec())]).unwrap_or_default() {
                let _ = session.destroy_object(h);
            }
        }
    }

    /// Which probe labels are still on the token: what `C_DestroyObject` really deleted.
    ///
    /// # Errors
    ///
    /// The failed lookup: a label it could not look up is not gone.
    pub(super) fn leftovers(&self, session: &Session) -> std::result::Result<Vec<String>, String> {
        let mut left = Vec::new();
        for l in &self.labels {
            let found = session
                .find_objects(&[Attribute::Label(l.as_bytes().to_vec())])
                .map_err(|e| format!("finding {l}: C_FindObjects: {}", ckr(&e)))?;
            if !found.is_empty() {
                left.push(l.clone());
            }
        }
        Ok(left)
    }

    /// Destroy what an earlier, interrupted run left (`cakeys-probe-NN`, its own labels on a
    /// scratch token, and a purpose-bound module's keys under the bound labels), so this run's
    /// leftover check reports only this run. Returns the labels cleaned.
    pub(super) fn clear_stale(session: &Session, bound_keys: &[BoundKey]) -> Vec<String> {
        let mut cleaned = Vec::new();
        let Ok(all) = session.find_objects(&[]) else { return cleaned };
        for h in all {
            let label = match session.get_attributes(h, &[AttributeType::Label]) {
                Ok(attrs) => match attrs.into_iter().next() {
                    Some(Attribute::Label(l)) => String::from_utf8_lossy(&l).into_owned(),
                    _ => continue,
                },
                Err(_) => continue,
            };
            let ours = label.starts_with("cakeys-probe-") || bound_keys.iter().any(|k| k.label == label);
            if ours && session.destroy_object(h).is_ok() {
                cleaned.push(label);
            }
        }
        cleaned.sort();
        cleaned.dedup();
        cleaned
    }
}

/// The write probes: key pairs per curve and RSA size, each operation the module advertises
/// on the first key of each kind, the secret-key generation it advertises (a refusal is a
/// `subtract` row), the OAEP hashes it actually implements for wrapping (wrap and unwrap back),
/// and the unwrap-template rules. On a scratch token every run cleans up after itself, a run a
/// probe's error ends included (only a crash is left to the next run's stale check), and the
/// leftover check turns "delete really deletes" into a note.
pub(super) fn write_probes(made: &mut Made, profile: &mut Draft) -> Result<()> {
    let labels = matches!(made.scratch.target, Target::Labels);
    if labels {
        let stale = Scratch::clear_stale(made.session, &made.bound_keys);
        if !stale.is_empty() {
            // Not a profile row: an interrupted run is not something the module does.
            made.undetermined.push(format!("destroyed objects an interrupted probe left: {}", stale.join(", ")));
        }
    }
    let probed = probe_writes(made, profile, labels);
    if labels {
        match probed {
            Ok(()) => destroy_all(made, profile),
            // What the probes made before the error goes too (review D7): it was left for the
            // next run's stale check, on a token keys.toml lends as scratch.
            Err(_) => made.scratch.destroy_after_failure(made.session),
        }
    }
    probed?;
    extras::check_reported_ranges(profile);
    let ops = std::mem::take(&mut made.ops);
    profile.tried = Some(ops.worked.iter().chain(ops.failed.keys()).chain(ops.unlisted.iter()).cloned().collect());
    profile.slot = matches!(made.scratch.target, Target::Slot(_));
    let busy = ops.finish(profile);
    made.undetermined.extend(busy);
    profile.out.add.sort();
    profile.out.add.dedup();
    Ok(())
}

/// [`write_probes`] but its cleanup.
pub(super) fn probe_writes(made: &mut Made, profile: &mut Draft, labels: bool) -> Result<()> {
    let bound = !made.bound_keys.is_empty();
    let transport = if bound {
        probe_bound(made, profile);
        made.undetermined.push(
            "no import, wrap, derive, commitment or attribute probes: the module's keys are made \
             from its own templates and serve only their binding's mechanisms (a bound AES key's \
             modes are probed)"
                .into(),
        );
        None
    } else {
        probe_curves(made, profile)?;
        probe_rsa(made, profile)?
    };
    if labels {
        if !bound {
            let aes = probe_secrets(made, profile)?;
            match (transport, aes) {
                (Some(transport), Some(aes)) => {
                    probe_wrapping(made, profile, transport, aes);
                    probe_key_wraps(made, profile, transport, aes);
                }
                _ => made.undetermined.push(
                    "no wrap probes: the probes could not make both an RSA transport key and an AES \
                     key on this token"
                        .into(),
                ),
            }
            // After the wrap probes: a secret key's sealed export takes an OAEP hash they found.
            moves::probe_moves(made, profile, transport)?;
            // The secret keys' operations (docs/archive/CAPROBE_PROFILE_COVERAGE.md): commitments,
            // symmetric modes and derivations, then the attributes and key types beyond cakeys'.
            secrets::probe_commits(made, profile)?;
            secrets::probe_modes(made, profile)?;
            secrets::probe_kdfs(made, profile);
            extras::probe_extras(made, profile);
        }
    } else {
        if !bound {
            moves::probe_moves(made, profile, None)?;
        }
        made.undetermined.push(
            "in a scratch slot: no secret-key, wrap, export or delete probes (each needs a second \
             object, or erasing the slot's key)"
                .into(),
        );
    }
    Ok(())
}

/// Destroy everything the probes made on a scratch token, and record what `C_DestroyObject`
/// really removed: a `delete.<class>` row per class the probes made, and a note naming the
/// labels still there.
/// A lookup that fails says nothing about what is there: no `delete` row is written from it
/// (the strongest yes from an error), only an undetermined line.
pub(super) fn destroy_all(made: &mut Made, profile: &mut Draft) {
    let before = count_by_class(made);
    made.scratch.destroy_all(made.session);
    let after = count_by_class(made);
    match delete_rows(!made.scratch.labels.is_empty(), before, after) {
        Ok(rows) => {
            for (class, deleted, why) in rows {
                profile.set(Capability::Delete(class), Answer::of(deleted), why, None);
            }
        }
        Err(why) => made.undetermined.push(format!("no delete rows: {why}")),
    }
    match made.scratch.leftovers(made.session) {
        Ok(left) if left.is_empty() => {}
        Ok(left) => {
            profile.note("destroy".into(), format!("C_DestroyObject leaves objects behind: {}", left.join(", ")));
        }
        Err(why) => made.undetermined.push(format!("no leftover check: {why}")),
    }
}

/// The `delete.<class>` rows from the per-class counts before and after the destroys: whether
/// each class is gone, and why not.
///
/// # Errors
///
/// Either count's failure: rows from a count that was not made would say "deleted". A count
/// before that finds nothing although the probes `made` objects (the fTPM run): no row could be
/// written, and the run says so rather than nothing (review 2026-11-23 D-14).
pub(super) fn delete_rows(
    made: bool,
    before: std::result::Result<BTreeMap<String, usize>, String>,
    after: std::result::Result<BTreeMap<String, usize>, String>,
) -> std::result::Result<Vec<(String, bool, Option<String>)>, String> {
    let (before, after) = (before?, after?);
    if made && before.is_empty() {
        return Err("nothing found under the probe's labels to count".into());
    }
    Ok(before
        .into_iter()
        .map(|(class, n)| {
            let left = after.get(&class).copied().unwrap_or_default();
            let why = (left > 0).then(|| format!("C_DestroyObject leaves {left} of {n} behind"));
            (class, left == 0, why)
        })
        .collect())
}

/// Per class, how many objects sit under the probe's labels.
///
/// # Errors
///
/// What failed to look them up: a count it could not make is not zero.
pub(super) fn count_by_class(made: &Made) -> std::result::Result<BTreeMap<String, usize>, String> {
    let mut by_class = BTreeMap::<String, usize>::new();
    for label in &made.scratch.labels {
        let found = made
            .session
            .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])
            .map_err(|e| format!("finding {label}: C_FindObjects: {}", ckr(&e)))?;
        for h in found {
            match made.session.get_attributes(h, &[AttributeType::Class]).as_deref() {
                Ok([Attribute::Class(c)]) => *by_class.entry(c.to_string()).or_default() += 1,
                Ok(_) => return Err(format!("an object under {label} reports no CKA_CLASS")),
                Err(e) => return Err(format!("reading the class of {label}: C_GetAttributeValue: {}", ckr(e))),
            }
        }
    }
    Ok(by_class)
}
