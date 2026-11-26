//! The write probes and their scratch objects (docs/CAPROBE.md): the tracking of what the probes
//! make, the cleanup, the leftover check, and the removal of objects that an interrupted run
//! left.

use super::{
    Attribute, AttributeType, BTreeMap, BoundKey, Capability, Checked, Draft, Made, ObjectHandle, Result, Session,
    Target, ckr, extras, moves, probe_bound, probe_curves, probe_key_wraps, probe_rsa, probe_secrets, probe_wrapping,
    secrets,
};

/// The objects that the write probes make on their target: where the probes may write
/// ([`Target`]), and what they made and under which labels, for the cleanup and the leftover
/// check.
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
            // A failed deletion is an observation here, which the leftover check reports.
            let _ = session.destroy_object(*h);
        }
    }

    /// Runs after a probe failed. The function destroys what the run made, first by handle and
    /// then by finding anything that is still under the run's labels (a key pair whose lookup
    /// failed is tracked only by its label). Nothing is measured, because a run that writes no
    /// profile records no `delete` row.
    pub(super) fn destroy_after_failure(&self, session: &Session) {
        self.destroy_all(session);
        for l in &self.labels {
            for h in session.find_objects(&[Attribute::Label(l.as_bytes().to_vec())]).unwrap_or_default() {
                let _ = session.destroy_object(h);
            }
        }
    }

    /// Returns the probe labels that are still on the token, which shows what `C_DestroyObject`
    /// really deleted.
    ///
    /// # Errors
    ///
    /// Returns the failed lookup, because a label that could not be looked up is not known to be
    /// gone.
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

    /// Destroys what an earlier, interrupted run left: the objects under the probe's own
    /// `cakeys-probe-NN` labels on a scratch token, and a purpose-bound module's keys under the
    /// bound labels. This run's leftover check then reports only this run's objects. Returns the
    /// labels that were cleaned.
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

/// Runs the write probes: key pairs on each curve and at each RSA size, the operations on the
/// first key of each kind, the secret-key generation that the module advertises (an advertised
/// mechanism that generates nothing becomes a `subtract` row), the OAEP hashes that the module
/// actually implements for wrapping (a wrap, and then an unwrap of the result), and the rules of
/// the unwrap template. On a scratch token, every run cleans up after itself, including a run
/// that a probe's error ends. Only a crash leaves objects for the next run's stale check. The
/// leftover check records in a note whether `C_DestroyObject` really removed the objects.
pub(super) fn write_probes(made: &mut Made, profile: &mut Draft) -> Result<()> {
    let labels = matches!(made.scratch.target, Target::Labels);
    if labels {
        let stale = Scratch::clear_stale(made.session, &made.bound_keys);
        if !stale.is_empty() {
            // This is not a profile row, because an interrupted run is not something that the
            // module does.
            made.undetermined.push(format!("destroyed objects an interrupted probe left: {}", stale.join(", ")));
        }
    }
    let probed = probe_writes(made, profile, labels);
    if labels {
        match probed {
            Ok(()) => destroy_all(made, profile),
            // The probe also destroys what the probes made before the error (review D7). Before
            // that fix, those objects stayed for the next run's stale check, on a token that
            // keys.toml offers as scratch.
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

/// Runs [`write_probes`] without its cleanup.
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
            // The move probes run after the wrap probes, because a secret key's sealed export uses
            // an OAEP hash that the wrap probes found.
            moves::probe_moves(made, profile, transport)?;
            // The secret keys' operations (docs/archive/CAPROBE_PROFILE_COVERAGE.md): commitments,
            // symmetric modes and derivations, and then the attributes and the key types that
            // cakeys does not manage.
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

/// Destroys everything that the probes made on a scratch token, and records what
/// `C_DestroyObject` really removed: a `delete.<class>` row for each class that the probes made,
/// and a note that names the labels that are still there. A failed lookup says nothing about what
/// is there, so the probe writes no `delete` row from it, only an undetermined line. A row
/// written from a failed lookup would report a yes (deleted) that only an error produced.
pub(super) fn destroy_all(made: &mut Made, profile: &mut Draft) {
    let before = count_by_class(made);
    made.scratch.destroy_all(made.session);
    let after = count_by_class(made);
    match delete_rows(!made.scratch.labels.is_empty(), before, after) {
        Ok(rows) => {
            // The host counted what is left after `C_DestroyObject`, so the row is the host's
            // finding whether it is yes or no.
            for (class, deleted, why) in rows {
                if let Some(checked) = Checked::same(&deleted, &true) {
                    profile.yes(Capability::Delete(class), checked, None);
                } else {
                    profile.wrong(
                        Capability::Delete(class),
                        why.unwrap_or_else(|| "still there after C_DestroyObject".into()),
                    );
                }
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

/// Returns the `delete.<class>` rows from the counts per class before and after the objects are
/// destroyed: whether each class is gone, and why not.
///
/// # Errors
///
/// Returns the failure of either count, because rows from a count that failed would say
/// "deleted". Also returns an error when the count before the destroys finds nothing although the
/// probes made objects (`made` is true; the fTPM run). No row can be written then, and the run
/// says so instead of saying nothing (review 2026-11-23 D-14).
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

/// Returns, for each class, the number of objects under the probe's labels.
///
/// # Errors
///
/// Returns the failure of a lookup, because a count that could not be made is not zero.
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
