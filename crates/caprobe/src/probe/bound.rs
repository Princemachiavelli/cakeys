//! The bound probes (docs/CAPROBE.md). They probe the keys whose complete template the provider
//! chooses (`bound_keys`), and an unbound pass probes the curves and sizes that no such key
//! covers.

use super::{
    Attribute, Capability, Curve, Draft, GenerateRow, KeyKind, Made, Mechanism, On, Refusal, ckr, keygen_mechanism,
    montgomery, operate, secrets, token,
};

/// Probes a module that binds every key to one purpose when it creates the key ([`BoundKey`],
/// Google Cloud KMS). The function generates one key for each binding from the provider's exact
/// template (with no public template), and it probes that key only with the mechanisms that its
/// binding serves. The curves and sizes that no binding covers are tried without a binding
/// ([`probe_unbound`]). A refusal of that template names no curve or size, so it answers for
/// none of them (review 2026-11-24 E-5).
///
/// [`BoundKey`]: super::BoundKey
pub(super) fn probe_bound(made: &mut Made, profile: &mut Draft) {
    let session = made.session;
    profile.note(
        "purpose-bound".into(),
        format!(
            "each key is bound to one purpose at creation ({} keys): one key per binding, each \
             probed with its own mechanisms",
            made.tok.provider.name()
        ),
    );
    let mut ec = GenerateRow::default();
    let mut rsa = profile.generate.remove(&KeyKind::Rsa).unwrap_or_default();
    let mut aes = GenerateRow::default();
    let mut oaep: Option<Vec<String>> = None;
    for key in std::mem::take(&mut made.bound_keys) {
        let Some((mech, pair)) = keygen_mechanism(key.keygen) else {
            profile.note(key.name.clone(), format!("no generation probe: {} takes parameters", key.keygen));
            continue;
        };
        let generated = if pair {
            session.generate_key_pair(&mech, &[], &key.template).map(|(p, s)| (Some(p), s))
        } else {
            session.generate_key(&mech, &key.template).map(|s| (None, s))
        };
        let (public, private) = match generated {
            Ok(keys) => keys,
            Err(e) => {
                let why = format!("generation refused: {}", ckr(&e));
                profile.note(key.name.clone(), why.clone());
                // The binding's own template names its curve or size, so its refusal answers for
                // that curve or size.
                let row = match (&key.kind, &key.on) {
                    (KeyKind::Ec, On::Item(_)) => &mut ec,
                    (KeyKind::Rsa, On::Bits(_)) => &mut rsa,
                    (KeyKind::Aes, On::Bytes(_)) => &mut aes,
                    _ => continue,
                };
                let at = (&key.kind, key.on.clone());
                profile.generation_refused(&mut made.undetermined, row, at, token::rv_of(&e), why);
                continue;
            }
        };
        made.scratch.handles.extend(public);
        made.scratch.track(&[private], &key.label);
        match (&key.kind, &key.on) {
            (KeyKind::Ec, On::Item(curve)) if !ec.can.contains(curve) => ec.can.push(curve.clone()),
            (KeyKind::Rsa, On::Bits(b)) if !rsa.can_bits.contains(b) => rsa.can_bits.push(*b),
            (KeyKind::Aes, On::Bytes(n)) if !aes.can_bytes.contains(n) => aes.can_bytes.push(*n),
            _ => {}
        }
        // A bound secret key: the probe tests its modes with the mechanisms that its binding
        // serves.
        if let (None, KeyKind::Aes, On::Bytes(n)) = (&public, &key.kind, &key.on) {
            secrets::probe_bound_aes(made, profile, &key.mechanisms, *n, private);
            continue;
        }
        let Some(public) = public else { continue };
        made.bound = Some(key.mechanisms.iter().map(ToString::to_string).collect());
        // The host's ECDSA check needs the curve. An RSA key is named by its binding, so that
        // the notes of several keys of one size stay separate.
        let on = match (&key.kind, &key.on) {
            (KeyKind::Ec, On::Item(curve)) => curve.clone(),
            _ => key.name.clone(),
        };
        operate(made, profile, &key.kind, &on, public, private);
        made.bound = None;
        // Each OAEP key decrypts with its own hash, so the row holds every hash with which any
        // of these keys decrypted.
        if let Some(works) = profile.decrypt_oaep.take() {
            let row = oaep.get_or_insert_with(Vec::new);
            for h in works {
                if !row.contains(&h) {
                    row.push(h);
                }
            }
        }
    }
    profile.decrypt_oaep = oaep;
    // A size that generated under one binding but not under another counts as `can`, and the
    // refusal stays a note.
    rsa.cannot_bits.retain(|b| !rsa.can_bits.contains(b));
    rsa.cannot_bits.dedup();
    ec.cannot.retain(|c| !ec.can.contains(c));
    ec.cannot.dedup();
    probe_unbound(made, profile, &mut ec, &mut rsa);
    rsa.can_bits.sort_unstable();
    rsa.cannot_bits.sort_unstable();
    aes.can_bytes.sort_unstable();
    aes.cannot_bytes.sort_unstable();
    aes.cannot_bytes.retain(|n| !aes.can_bytes.contains(n));
    if !aes.can_bytes.is_empty() || !aes.cannot_bytes.is_empty() {
        profile.generate.insert(KeyKind::Aes, aes);
    }
    profile.generate.insert(KeyKind::Ec, ec);
    profile.generate.insert(KeyKind::Rsa, rsa);
}

/// Tries the curves and sizes that no binding covers, with a template that holds only a label.
/// libkmsp11 answers before it makes any Cloud KMS call (`CKR_TEMPLATE_INCOMPLETE`), so nothing
/// is created, and anything that does generate is destroyed with the other probe objects. A
/// module that generates here is not purely purpose-bound, and the bare template names no curve
/// or size, so the probe cannot know which one the module made. The probe then writes no row for
/// that key type, and the run says so in its undetermined list. A refusal of that template writes
/// no row either, because it names no curve or size and so answers for none of them (review
/// 2026-11-24 E-5). Each of those curves and sizes gets an `[untested]` entry with the reason
/// `cakeys`, because cakeys' table of bindings limits what was tried.
pub(super) fn probe_unbound(made: &mut Made, profile: &mut Draft, ec: &mut GenerateRow, rsa: &mut GenerateRow) {
    let session = made.session;
    let bare = [Attribute::Label(b"cakeys-probe-unbound".to_vec())];
    // The refusal, or None when the module generated.
    let unbound = |made: &mut Made, mech: &Mechanism, kt: &KeyKind| match session.generate_key_pair(mech, &[], &bare) {
        Ok((public, private)) => {
            // The keys are also tracked by label, so that the delete rows and the leftover check
            // count them.
            made.scratch.track(&[private, public], "cakeys-probe-unbound");
            made.undetermined.push(format!(
                "no {kt} row for what no binding covers: generated without a binding, so not purely \
                 purpose-bound, and which curve or size it made is unknown"
            ));
            None
        }
        Err(e) => Some(ckr(&e)),
    };
    let unbound_why = |refusal: &str| format!("no binding for it; a template naming none is refused: {refusal}");
    let undecided = |profile: &mut Draft, kt: &KeyKind, on: On, refusal: &str| {
        let c = Capability::Generate { key_type: kt.clone(), on };
        profile.undecide(c, Refusal::Cakeys, unbound_why(refusal));
    };
    if let Some(ec_refusal) = unbound(made, &Mechanism::EccKeyPairGen, &KeyKind::Ec) {
        for name in Curve::ALL.iter().filter(|c| !c.edwards()).map(|c| c.name()) {
            let name = name.to_owned();
            if !ec.can.contains(&name) && !ec.cannot.contains(&name) {
                undecided(profile, &KeyKind::Ec, On::Item(name), &ec_refusal);
            }
        }
    }
    let edwards: Vec<String> = Curve::ALL.iter().filter(|c| c.edwards()).map(|c| c.name().to_owned()).collect();
    let montgomery: Vec<String> = montgomery().into_iter().map(|m| m.0.to_owned()).collect();
    for (kt, mech, names) in [
        (KeyKind::EcEdwards, Mechanism::EccEdwardsKeyPairGen, edwards),
        (KeyKind::EcMontgomery, Mechanism::EccMontgomeryKeyPairGen, montgomery),
    ] {
        let Some(refusal) = unbound(made, &mech, &kt) else { continue };
        for name in names {
            undecided(profile, &kt, On::Item(name), &refusal);
        }
    }
    let Some(rsa_refusal) = unbound(made, &Mechanism::RsaPkcsKeyPairGen, &KeyKind::Rsa) else { return };
    for bits in made.rsa_sizes.clone() {
        if !rsa.can_bits.contains(&bits) && !rsa.cannot_bits.contains(&bits) {
            undecided(profile, &KeyKind::Rsa, On::Bits(bits), &rsa_refusal);
        }
    }
}
