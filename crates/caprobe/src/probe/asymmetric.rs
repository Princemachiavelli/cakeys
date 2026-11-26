//! The asymmetric probes: the EC and Edwards curves, Montgomery pairs, RSA, and the
//! operations and derivations each key's usage allows (docs/CAPROBE.md).

use super::{
    Attribute, AttributeType, Binding, Capability, Checked, CkError, Created, Curve, Digest, Draft, EcKdf,
    Ecdh1DeriveParams, EddsaParams, EddsaSignatureScheme, Encoding, GenerateRow, HashAlg, KeyKind, KeyType, KmError,
    Kt, MSG, Made, Mechanism, MechanismType, Msg, Object, ObjectCfg, ObjectClass, ObjectHandle, On, PkcsMgfType,
    PkcsPssParams, Refusal, Result, RsaPadding, Session, Sha224, Sha256, Sha384, Sha512, Target, ck_refusal, ck_said,
    ckr, derive_any, evidence, extras, pop, refused, show, sig, spec, token,
};

/// The RSA key sizes the write probes generate, in bits, whatever the module reports (a claim,
/// `[reported."CKK_RSA"]`): the sizes in use from 512 to 16384. The gate answers yes for a size
/// between two that generated, so these cover the range.
pub(crate) const RSA_SIZES: [u32; 10] = [512, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384];

/// One curve to generate: its name, `CKA_EC_PARAMS` as the OID, and as the `PrintableString`
/// name where PKCS#11 3.0 allows it.
pub(super) type CurveForm = (&'static str, &'static [u8], Option<&'static [u8]>);

/// The Montgomery curves (`CKK_EC_MONTGOMERY`) of the names table (`cakeys_names::Curve`), with
/// RFC 8410's OIDs and PKCS#11 3.0's names. Not keys.toml objects yet (no Montgomery key type
/// in core), so the probe takes them from the table, not from core's curves.
pub(super) fn montgomery() -> Vec<CurveForm> {
    cakeys_names::Curve::ALL
        .into_iter()
        .filter(|c| c.family() == cakeys_names::Family::Montgomery)
        .map(|c| (c.name(), c.params(), c.params_by_name()))
        .collect()
}

/// The templates a Montgomery pair is tried on, as (public, with usage, private). A Montgomery
/// public key verifies nothing, so it names only the curve. The usage its operation probes need
/// is deriving; the fallback (public, private) names no usage at all, so it is never stricter
/// than the first try (review 2026-11-23 D-11).
pub(super) fn montgomery_templates(params: &[u8]) -> (Vec<Attribute>, Vec<Attribute>, Vec<Attribute>) {
    let public = vec![Attribute::EcParams(params.to_vec())];
    let private = vec![Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Sensitive(true)];
    let with_usage = [&private[..], &[Attribute::Derive(true)]].concat();
    (public, with_usage, private)
}

/// Key pairs per curve: `can` or `cannot`, the refusal's `CKR_*` in a note, and `by-name` for
/// a curve that generates only when named. The first key of each kind gets the operation
/// probes, right away — in a scratch slot the next generation replaces it.
pub(super) fn probe_curves(made: &mut Made, profile: &mut Draft) -> Result<()> {
    // The curves cakeys has a key type for (core's), Weierstrass or Edwards.
    let forms = |edwards: bool| -> Vec<CurveForm> {
        Curve::ALL
            .iter()
            .filter(|c| c.edwards() == edwards)
            .map(|c| (c.name(), c.params(), c.params_by_name()))
            .collect()
    };
    let families = [
        (KeyKind::Ec, Mechanism::EccKeyPairGen, forms(false)),
        (KeyKind::EcEdwards, Mechanism::EccEdwardsKeyPairGen, forms(true)),
        (KeyKind::EcMontgomery, Mechanism::EccMontgomeryKeyPairGen, montgomery()),
    ];
    for (kt, mech, curves) in families {
        let mut row = GenerateRow::default();
        // A generation mechanism the module does not list is tried all the same: the list is a
        // claim, and the module's answer the row. Where the provider stands in for it (AWS
        // CloudHSM lists no Edwards one, and makes Ed25519 with CKM_EC_KEY_PAIR_GEN [run]) the
        // stand-in is what is tried. Either way it is in `add` if a curve generates.
        let keygen = mech.mechanism_type();
        let listed = made.tok.lists(keygen);
        let stood_in = !listed && made.tok.provider.stand_ins().contains(&keygen);
        if !matches!(kt, KeyKind::EcMontgomery) {
            create_curves(made, profile, &kt, &curves, &mut row)?;
            record_stand_in(profile, stood_in, keygen, made.tok.runnable(mech).mechanism_type(), &row);
            record_unlisted(profile, !listed && !stood_in, keygen, &row);
            profile.generate.insert(kt, row);
            continue;
        }
        // Montgomery keys from here: no keys.toml object, so the probe's own templates.
        let mech = made.tok.runnable(mech);
        let mut probed_ops = false;
        for (curve, oid, name) in curves {
            let mut outcome = None;
            // The OID first, then the curve name (`by_name` from the second on).
            for (i, params) in std::iter::once(oid).chain(name).enumerate() {
                let (public, with_usage, private) = montgomery_templates(params);
                let (made_pair, usable) = made.pair_for_use(&mech, (&public, &with_usage), (&public, &private))?;
                let by_name = i > 0;
                outcome = Some((made_pair, usable, by_name));
                if matches!(outcome, Some((Ok(_), ..))) {
                    break;
                }
            }
            match outcome {
                Some((Ok((public, private)), usable, by_name)) => {
                    row.can.push(curve.to_owned());
                    if by_name {
                        row.by_name.push(curve.to_owned());
                    }
                    if !probed_ops {
                        probed_ops = true;
                        if usable {
                            operate(made, profile, &kt, curve, public, private);
                        } else {
                            made.undetermined.push(format!(
                                "no operation probes on {kt} keys: the module refused the usage attributes \
                                 when generating on {curve}"
                            ));
                        }
                    }
                }
                Some((Err(e), ..)) => profile.generation_refused(
                    &mut made.undetermined,
                    &mut row,
                    (&kt, On::Item(curve.to_owned())),
                    token::rv_of(&e),
                    format!("generation refused: {}", ckr(&e)),
                ),
                None => {}
            }
        }
        record_stand_in(profile, stood_in, keygen, mech.mechanism_type(), &row);
        record_unlisted(profile, !listed && !stood_in, keygen, &row);
        profile.generate.insert(kt, row);
    }
    Ok(())
}

/// A generation mechanism the module does not list, which no provider stands in for: in `add`
/// when a curve generated with it all the same.
pub(super) fn record_unlisted(profile: &mut Draft, unlisted: bool, keygen: MechanismType, row: &GenerateRow) {
    if unlisted && !row.can.is_empty() {
        profile.out.add.push(keygen.to_string());
        profile.note(keygen.to_string(), "not listed; generates".into());
    }
}

/// Key pairs of a key type cakeys manages (`CKK_EC`, `CKK_EC_EDWARDS`) per curve, generated
/// as the verbs generate them (`Token::create`): `can`, or `cannot` with the refusal as the
/// row's evidence, and `by-name` for a curve the module takes only by name. The first key with
/// its usage gets the operation probes, right away — in a scratch slot the next replaces it.
pub(super) fn create_curves(
    made: &mut Made,
    profile: &mut Draft,
    kt: &KeyKind,
    curves: &[CurveForm],
    row: &mut GenerateRow,
) -> Result<()> {
    let (key_type, usage) = match kt {
        KeyKind::Ec => (Kt::Ec, spec(&["CKA_SIGN", "CKA_DERIVE"], &[])),
        _ => (Kt::EcEdwards, spec(&["CKA_SIGN"], &[])),
    };
    let mut probed_ops = false;
    for (curve, ..) in curves {
        let object = ObjectCfg {
            curve: Some((*curve).to_owned()),
            ..ObjectCfg::new(cakeys_core::types::ObjectClass::PrivateKey, Some(key_type))
        };
        match made.create_for_use(&object, &usage, &spec(&[], &[]))? {
            (Created::Made(public, private, note), usable) => {
                row.can.push((*curve).to_owned());
                if note.as_ref().is_some_and(|n| n.by_name.is_some()) {
                    row.by_name.push((*curve).to_owned());
                }
                // The public CKA_PRIVATE = false default the module refused (AWS CloudHSM).
                if note.as_ref().is_some_and(|n| n.public_made_private) {
                    let said = token::PUBLIC_MADE_PRIVATE.to_owned();
                    made.template_notes.entry("template.public.CKA_PRIVATE".into()).or_insert(said);
                }
                // The first key with its usage gets the operation probes (and its proofs); each
                // later one its proofs.
                if !probed_ops {
                    probed_ops = true;
                    if usable {
                        operate(made, profile, kt, curve, public, private);
                    } else {
                        made.undetermined.push(format!(
                            "no operation probes on {kt} keys: the module refused the usage attributes when \
                             generating on {curve}"
                        ));
                    }
                } else if usable {
                    prove_key(made, profile, kt, curve, public, private);
                }
            }
            (Created::Refused(e), _) => {
                let why = format!("generation refused: {}", refused(made.tok, &e));
                profile.generation_refused(
                    &mut made.undetermined,
                    row,
                    (kt, On::Item((*curve).to_owned())),
                    e.rv(),
                    why,
                );
            }
            (Created::Lost(e), _) => {
                made.undetermined.push(format!("no generate row for {kt} on {curve}: the module generated, but {e}"));
            }
            (Created::Undecided(e), _) => {
                made.undetermined.push(format!("no generate row for {kt} on {curve}: never asked of the module: {e}"));
            }
        }
    }
    Ok(())
}

/// A generation mechanism the module does not list but the provider stands in for (`ran`): in
/// `add` when a curve generated through it, a note either way.
pub(super) fn record_stand_in(
    profile: &mut Draft,
    stood_in: bool,
    keygen: MechanismType,
    ran: MechanismType,
    row: &GenerateRow,
) {
    if !stood_in {
        return;
    }
    if row.can.is_empty() {
        profile.note(keygen.to_string(), "not listed; the provider's stand-in generates nothing".into());
    } else {
        profile.out.add.push(keygen.to_string());
        profile.note(keygen.to_string(), format!("not listed; generates through the provider's stand-in, {ran}"));
    }
}

/// Key pairs per RSA size ([`RSA_SIZES`] up to the request's largest, whatever the module
/// reports): `can-bits` and `cannot-bits` beside the range it reports, and each size's proofs
/// of possession. The 2048-bit pair gets the operation probes, and on a scratch token it is the
/// wrap probes' transport key: wrapping is encryption, so its public half wraps and its private
/// half unwraps. In a scratch slot the next size replaces it, so there it is no transport key.
pub(super) fn probe_rsa(made: &mut Made, profile: &mut Draft) -> Result<Option<(ObjectHandle, ObjectHandle)>> {
    let mut row = profile.generate.remove(&KeyKind::Rsa).unwrap_or_default();
    let mut transport = None;
    let mut operated = false;
    for bits in made.rsa_sizes.clone() {
        // Generated as the verbs generate it, with every usage the proofs, the operation and
        // the wrap probes need, each attribute on the half the spec defines it for, since their
        // defaults are the module's choice. A module refusing them gets the bare spec.
        let object = ObjectCfg {
            modulus_bits: Some(bits.into()),
            ..ObjectCfg::new(cakeys_core::types::ObjectClass::PrivateKey, Some(Kt::Rsa))
        };
        let usage = spec(&["CKA_DECRYPT", "CKA_UNWRAP", "CKA_SIGN"], &["CKA_ENCRYPT", "CKA_WRAP", "CKA_VERIFY"]);
        let on = format!("RSA-{bits}");
        match made.create_for_use(&object, &usage, &spec(&[], &[]))? {
            (Created::Made(public, private, _), usable) => {
                match (operates_on(bits, usable, operated), usable) {
                    (true, _) => {
                        operated = true;
                        operate(made, profile, &KeyKind::Rsa, &on, public, private);
                        if matches!(made.scratch.target, Target::Labels) {
                            transport = Some((public, private));
                        }
                    }
                    (false, true) => prove_key(made, profile, &KeyKind::Rsa, &on, public, private),
                    (false, false) => made.undetermined.push(format!(
                        "no operation probes or proofs on {on}: the module refused the usage attributes"
                    )),
                }
                row.can_bits.push(bits);
            }
            (Created::Refused(e), _) => {
                let why = format!("modulusBits = {bits}: {}", refused(made.tok, &e));
                profile.generation_refused(
                    &mut made.undetermined,
                    &mut row,
                    (&KeyKind::Rsa, On::Bits(bits)),
                    e.rv(),
                    why,
                );
            }
            (Created::Lost(e), _) => {
                made.undetermined.push(format!("no generate row for {on}: the module generated, but {e}"));
            }
            (Created::Undecided(e), _) => {
                made.undetermined.push(format!("no generate row for {on}: never asked of the module: {e}"));
            }
        }
    }
    if !operated {
        let why = if made.rsa_sizes.iter().any(|b| *b >= 2048) {
            "the module made none of them usable"
        } else {
            "--rsa-max-bits asks for none"
        };
        made.undetermined.push(format!(
            "no RSA operation, wrap or move probes: they run on an RSA key of 2048 bits or more, and {why}"
        ));
    }
    profile.generate.insert(KeyKind::Rsa, row);
    Ok(transport)
}

/// Whether the RSA operation probes run on the `bits` key just made (`usable` for them), once
/// `operated` tells whether they ran: on the 2048-bit key, or the next size up the module makes
/// usable when it will not make that one so (the operation key is also the wrap probes'
/// transport key). A smaller key only proves possession.
pub(super) fn operates_on(bits: u32, usable: bool, operated: bool) -> bool {
    usable && !operated && bits >= 2048
}

/// The operation probes on one fresh key pair of kind `kt`: every advertised mechanism that
/// applies to it, verified on the host wherever cakeys can (`sig`, `pop`) — signing, ECDH
/// derivation and decryption.
pub(super) fn operate(
    made: &mut Made,
    profile: &mut Draft,
    kt: &KeyKind,
    on: &str,
    public: ObjectHandle,
    private: ObjectHandle,
) {
    if matches!(kt, KeyKind::EcMontgomery) {
        // No Montgomery SPKI or host X25519 in cakeys: ECDH between two pairs on the token.
        match montgomery().into_iter().find(|m| m.0 == on) {
            Some((_, oid, name)) => {
                let forms: Vec<&[u8]> = std::iter::once(oid).chain(name).collect();
                extras::montgomery_ecdh(made, profile, on, &forms, (public, private));
            }
            None => made.undetermined.push(format!("no operation probes on {on}: unknown curve")),
        }
        return;
    }
    let spki = match made.tok.material_spki(public) {
        Ok(Some(spki)) => spki,
        Ok(None) => {
            made.undetermined.push(format!("no operation probes on {on}: its public key carries no material"));
            return;
        }
        Err(e) => {
            made.undetermined.push(format!("no operation probes on {on}: {e}"));
            return;
        }
    };
    // First, as the verbs prove right after generating: a module that leaves an operation
    // active after a failed one (tpm2-pkcs11, on a hash the TPM lacks [run]) would otherwise
    // refuse the proof's own C_*Init with CKR_OPERATION_ACTIVE.
    prove(made, profile, kt, on, private, &spki);
    match kt {
        KeyKind::Ec => {
            let curve = Curve::from_cfg(Kt::Ec, on);
            ec_ops(made, private, &spki, on, curve.and_then(HashAlg::for_curve));
            if made.tries(MechanismType::ECDH1_DERIVE) {
                derive(made, profile, private, &spki, on);
            }
        }
        KeyKind::EcEdwards => {
            let pure = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
            let listed = made.advertises(MechanismType::EDDSA);
            if !listed && made.tok.provider.stand_ins().contains(&MechanismType::EDDSA) {
                // Not listed, but the provider signs pure EdDSA its own way (AWS CloudHSM's
                // vendor mechanism [run]): `add` when the host verifies what it signs.
                let mech = made.tok.runnable(pure);
                let vendor = *mech.mechanism_type();
                let name = MechanismType::EDDSA.to_string();
                match sign(made.session, &mech, private, MSG, |s| sig::ed25519(&spki, MSG, s)) {
                    Ok(true) => {
                        profile.out.add.push(name.clone());
                        profile.note(name, format!("not listed; signs through the provider's stand-in, {vendor:#x}"));
                    }
                    Ok(false) => profile.note(
                        name,
                        format!("not listed; the provider's stand-in ({vendor:#x}) signs what the host cannot verify"),
                    ),
                    Err(e) => {
                        profile.note(name, format!("not listed; the provider's stand-in ({vendor:#x}) on {on}: {e}"));
                    }
                }
            } else if made.tries(MechanismType::EDDSA) {
                let outcome = sign(made.session, &pure, private, MSG, |s| sig::ed25519(&spki, MSG, s));
                made.record_signed(MechanismType::EDDSA, on, outcome);
            }
        }
        KeyKind::Rsa => rsa_ops(made, profile, private, &spki, on),
        _ => made.undetermined.push(format!("no operation probes on {on}: none are written for {kt} keys")),
    }
}

/// [`prove`] on a key pair the operation probes do not take: its public half's SPKI first.
pub(super) fn prove_key(
    made: &mut Made,
    profile: &mut Draft,
    kt: &KeyKind,
    on: &str,
    public: ObjectHandle,
    private: ObjectHandle,
) {
    match made.tok.material_spki(public) {
        Ok(Some(spki)) => prove(made, profile, kt, on, private, &spki),
        Ok(None) => made.undetermined.push(format!("no proofs on {on}: its public key carries no material")),
        Err(e) => made.undetermined.push(format!("no proofs on {on}: {e}")),
    }
}

/// The proofs of possession the verbs give with a private key of `kt` on `on`
/// (`Token::prove_binding`, their own code), each a `prove.*` row with the refusal as its
/// evidence. The probe's token has no module profile, so each proof tries what it can. A proof
/// refused because an earlier operation left the session busy says nothing of the key:
/// undetermined, never a row (tpm2-pkcs11 leaves a failed one active \[run\]).
pub(super) fn prove(made: &mut Made, profile: &mut Draft, kt: &KeyKind, on: &str, private: ObjectHandle, spki: &[u8]) {
    let (key_type, bindings): (Kt, &[Binding]) = match kt {
        KeyKind::Ec => (Kt::Ec, &[Binding::PopSign, Binding::PopEcdh]),
        KeyKind::EcEdwards => (Kt::EcEdwards, &[Binding::PopSign]),
        KeyKind::Rsa => (Kt::Rsa, &[Binding::PopSign, Binding::PopDecrypt, Binding::PopUnwrap]),
        _ => return,
    };
    // A key the host does not compute with has an identity but no proof here: the refusal is
    // cakeys', and says nothing of the module (as the import rows of a size the host reads not).
    if key_type == Kt::Rsa && !cakeys_core::pop::rsa_computes_with(spki) {
        made.undetermined.push(format!("no proofs on {on}: the host computes with no RSA key of that size"));
        return;
    }
    let mut object = ObjectCfg::new(cakeys_core::types::ObjectClass::PrivateKey, Some(key_type));
    let size = on.strip_prefix("RSA-").and_then(|b| b.parse::<u32>().ok());
    // A purpose-bound RSA key is named by its binding (several share a size, each proving
    // differently): the row keeps that name, the proof takes the size the key reports.
    match (key_type, size) {
        (_, Some(bits)) => object.modulus_bits = Some(bits.into()),
        (Kt::Rsa, None) => {
            if let Ok([Attribute::Modulus(n)]) =
                made.session.get_attributes(private, &[AttributeType::Modulus]).as_deref()
            {
                object.modulus_bits = Some(cakeys_core::id::modulus_bits(n));
            }
        }
        (_, None) => object.curve = Some(on.to_owned()),
    }
    let on = size.map_or_else(|| On::Item(on.to_owned()), On::Bits);
    for binding in bindings {
        let outcome = Object::new(&object).and_then(|o| made.tok.prove_binding(private, o, spki, *binding));
        let cap = Capability::Prove { binding: binding.name().into(), key_type: kt.clone(), on: on.clone() };
        // The host verified the proof; a signature it refuses is its finding. Anything else
        // (no verifier on the host, a device failure) is no answer of the module's (E-2).
        match outcome {
            Ok(()) => profile.yes(cap, Checked::Host, None),
            Err(e @ KmError::Conflict(_)) => profile.wrong(cap, evidence(made.tok, &e)),
            Err(e) => profile.refused(&mut made.undetermined, cap, e.rv(), evidence(made.tok, &e)),
        }
    }
}

/// Sign `data` with `mech`; `check` verifies the signature on the host where it can. `Ok(true)`
/// when it verified; `Ok(false)` when there is no host verifier for this one (`None`), the
/// call succeeding all that was seen, which makes no `add` row (review 2026-11-23 D-2).
pub(super) fn sign(
    s: &Session,
    mech: &Mechanism,
    key: ObjectHandle,
    data: &[u8],
    check: impl FnOnce(&[u8]) -> sig::Verdict,
) -> std::result::Result<bool, Msg> {
    let signature = s.sign(mech, key, data).map_err(|e| ck_refusal(&e))?;
    match check(&signature) {
        Some(Err(e)) => Err(format!("the signature does not verify ({e})").into()),
        Some(Ok(())) => Ok(true),
        None => Ok(false),
    }
}

/// ECDSA, raw and with each hash the module advertises, each signature verified on the host
/// against the digest it signs; SHA-1, which the host does not compute, is signed unchecked.
pub(super) fn ec_ops(made: &mut Made, private: ObjectHandle, spki: &[u8], on: &str, hash: Option<HashAlg>) {
    // Raw ECDSA signs the curve's digest of the message.
    let raw = sig::digest(hash.unwrap_or(HashAlg::Sha256), MSG);
    let tries = [
        (Mechanism::Ecdsa, raw.clone(), Some(raw)),
        (Mechanism::EcdsaSha1, MSG.to_vec(), None),
        (Mechanism::EcdsaSha224, MSG.to_vec(), Some(Sha224::digest(MSG).to_vec())),
        (Mechanism::EcdsaSha256, MSG.to_vec(), Some(sig::digest(HashAlg::Sha256, MSG))),
        (Mechanism::EcdsaSha384, MSG.to_vec(), Some(sig::digest(HashAlg::Sha384, MSG))),
        (Mechanism::EcdsaSha512, MSG.to_vec(), Some(sig::digest(HashAlg::Sha512, MSG))),
    ];
    for (mech, data, digest) in tries {
        let mt = mech.mechanism_type();
        if made.tries(mt) {
            let check = |s: &[u8]| digest.as_deref().and_then(|d| sig::ecdsa_prehash(spki, d, s, Encoding::Raw));
            let outcome = sign(made.session, &mech, private, &data, check);
            made.record_signed(mt, on, outcome);
        }
    }
}

/// `CKM_ECDH1_DERIVE` against a host ephemeral key, as `pop-ecdh` does it: into a sealed
/// secret first, authenticated by an HMAC when the module has one; else into an extractable secret, read and
/// compared. `derive.sealed` records which, a refused sealed derivation the note.
pub(super) fn derive(made: &mut Made, profile: &mut Draft, private: ObjectHandle, spki: &[u8], on: &str) {
    let s = made.session;
    let ch = match pop::ecdh_challenge(spki, MSG) {
        Ok(ch) => ch,
        Err(e) => {
            made.undetermined.push(format!("no ECDH probe on {on}: {e}"));
            return;
        }
    };
    let d = Derivation {
        mech: Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), &ch.peer)),
        private,
        ch: &ch,
        on,
    };
    let base = [
        Attribute::Token(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
    ];
    let mut sealed =
        [&base[..], &[Attribute::Sensitive(true), Attribute::Extractable(false), Attribute::Sign(true)]].concat();
    let mut open = [&base[..], &[Attribute::Sensitive(false), Attribute::Extractable(true)]].concat();
    let outcome = match try_sealed(made, profile, &d, &mut sealed) {
        SealedPath::Derives => {
            profile.derive.sealed.get_or_insert(true);
            Ok(())
        }
        SealedPath::Wrong(m) => Err(m),
        SealedPath::Fallback(why) => try_extractable(s, profile, &d, &mut open, why),
        // Not refused, only unchecked: no `derive.sealed = no` from it.
        SealedPath::Unchecked(why) => {
            let before = profile.derive.sealed;
            let outcome = try_extractable(s, profile, &d, &mut open, why);
            profile.derive.sealed = before;
            outcome
        }
    };
    if outcome.is_ok() {
        let template = if profile.derive.sealed == Some(true) { &sealed } else { &open };
        derived_once(made, profile, &d.mech, private, template, on);
    }
    made.record(MechanismType::ECDH1_DERIVE, on, outcome);
}

/// One ECDH derivation the probe tries: against the host's ephemeral key, with the private key
/// on the token, for the key named `on`.
pub(super) struct Derivation<'a> {
    mech: Mechanism<'a>,
    private: ObjectHandle,
    ch: &'a pop::EcdhChallenge,
    on: &'a str,
}

/// What deriving into a sealed secret came to.
pub(super) enum SealedPath {
    /// It derives the shared secret, sealed: its HMAC is right.
    Derives,
    /// It derives a sealed secret the module has no HMAC to check: why. The extractable path
    /// is what `pop-ecdh` takes then, so it is what the mechanism's row is proved by, and the
    /// sealed derivation only a note (review 2026-11-23 D-12).
    Unchecked(Msg),
    /// It derives a secret that is not the shared one: the outcome, no fallback.
    Wrong(Msg),
    /// The module refuses it, cannot MAC with it, or derives only an unsealed secret: why, and
    /// the extractable path is tried.
    Fallback(Msg),
}

/// Derive into a sealed secret and MAC with it, the way `pop-ecdh` proves possession; on
/// success `template` becomes the template that took. What the secret reports, when not what
/// was asked, is a note (AWS `CloudHSM`: sensitive, but extractable \[run\]).
pub(super) fn try_sealed(
    made: &Made,
    profile: &mut Draft,
    d: &Derivation,
    template: &mut Vec<Attribute>,
) -> SealedPath {
    let s = made.session;
    let (h, used, changed) = match derive_any(s, &d.mech, d.private, template, d.ch.secret.len()) {
        Ok(derived) => derived,
        Err(e) => return SealedPath::Fallback(ck_said("a sealed (non-extractable) derived secret is refused", &e)),
    };
    let reads = s.get_attributes(h, &[AttributeType::Sensitive, AttributeType::Extractable]).unwrap_or_default();
    let reported = reads.iter().map(show).collect::<Vec<_>>().join(", ");
    let is_sealed = reads.contains(&Attribute::Sensitive(true)) && reads.contains(&Attribute::Extractable(false));
    if !is_sealed {
        profile.note("derive.secret".into(), format!("{}: the derived secret reports {reported}", d.on));
    }
    let mac = made.advertises(MechanismType::SHA256_HMAC).then(|| s.sign(&Mechanism::Sha256Hmac, h, MSG));
    destroy_derived(s, h, "sealed", d.on, profile);
    note_template(profile, d.on, changed);
    *template = used;
    match mac {
        Some(Ok(tag)) if pop::ct_eq(&d.ch.mac, &tag) => SealedPath::Derives,
        Some(Ok(_)) => SealedPath::Wrong(Msg::from("the derived secret is not the shared secret")),
        Some(Err(e)) => SealedPath::Fallback(ck_said("derives into a sealed secret, but HMAC with it fails", &e)),
        // With no HMAC to MAC with, the secret itself says whether it is sealed: a template that
        // took only without its sealing attributes made an extractable one (ykcs11).
        None if is_sealed => SealedPath::Unchecked(Msg::from(
            "derives into a sealed secret, but lists no CKM_SHA256_HMAC to check it with",
        )),
        None => {
            SealedPath::Fallback(format!("derives only into a secret that is not sealed: it reports {reported}").into())
        }
    }
}

/// Derive into an extractable secret, read it and compare it with the shared secret, after the
/// sealed path fell back for `why`; on success `template` becomes the template that took.
pub(super) fn try_extractable(
    s: &Session,
    profile: &mut Draft,
    d: &Derivation,
    template: &mut Vec<Attribute>,
    why: Msg,
) -> std::result::Result<(), Msg> {
    let (h, used, changed) = match derive_any(s, &d.mech, d.private, template, d.ch.secret.len()) {
        Ok(derived) => derived,
        Err(e) => {
            return Err(Msg::from(format!("{why}; extractable: {}", ckr(&e))).with_rv(token::rv_of(&e).or(why.rv())));
        }
    };
    note_template(profile, d.on, changed);
    *template = used;
    let value = s.get_attributes(h, &[AttributeType::Value]).ok().and_then(|v| v.into_iter().next());
    destroy_derived(s, h, "extractable", d.on, profile);
    match value {
        Some(Attribute::Value(v)) if pop::ct_eq(&d.ch.secret, &v) => {
            // The sealed path's failure is the module's no only when it refused it; derived but
            // not sealed (no return value) is what it reports of the secret, its answer too.
            match Refusal::of(why.rv()) {
                Refusal::Module | Refusal::Cakeys => {
                    profile.derive.sealed = Some(false);
                    profile.note("derive.sealed".into(), why.into_text());
                }
                class => profile.undecide(Capability::DeriveSealed, class, why.into_text()),
            }
            Ok(())
        }
        Some(Attribute::Value(_)) => Err(Msg::from("the derived secret is not the shared secret")),
        _ => {
            Err(Msg::from(format!("{why}; the extractable derived secret's CKA_VALUE is unreadable")).with_rv(why.rv()))
        }
    }
}

/// A derivation that took only with a changed template: what changed, and the first refusal.
pub(super) fn note_template(profile: &mut Draft, on: &str, changed: Option<(String, CkError)>) {
    if let Some((changed, first)) = changed {
        profile.note(
            "derive.template".into(),
            format!("{on}: the template as asked is refused ({}); derived with {changed}", ckr(&first)),
        );
    }
}

/// Destroy the secret `h` a `path` derivation made in `session`. One the module will not destroy
/// stays behind (tpm2-pkcs11 persists it): a note, since `pop-ecdh` derives one per proof.
pub(super) fn destroy_derived(session: &Session, h: ObjectHandle, path: &str, on: &str, profile: &mut Draft) {
    if let Err(e) = session.destroy_object(h) {
        profile
            .note("derive.destroy".into(), format!("{on}: the {path} derived secret cannot be destroyed: {}", ckr(&e)));
    }
}

/// After a derivation took with `template`: whether it derives the same way in a read-only
/// session, where the read-only verbs prove possession (`check`, `resolve`), and what the key
/// that derived says of itself (a spec asking `CKA_DERIVE = true` is checked against this, not
/// against what the key does).
pub(super) fn derived_once(
    made: &mut Made,
    profile: &mut Draft,
    mech: &Mechanism,
    private: ObjectHandle,
    template: &[Attribute],
    on: &str,
) {
    match made.tok.extra_session(token::Access::Read).map(|ro| (ro.derive_key(mech, private, template), ro)) {
        Ok((Ok(h), ro)) => {
            destroy_derived(&ro, h, "read-only", on, profile);
            profile.derive.read_only.get_or_insert(true);
        }
        Ok((Err(e), _)) => {
            let why = format!("{on}: in a read-only session: {}", ckr(&e));
            match Refusal::of(token::rv_of(&e)) {
                Refusal::Module => {
                    profile.derive.read_only = Some(false);
                    profile.note("derive.read-only".into(), why);
                }
                class => {
                    made.undetermined.push(format!("no derive.read-only row: {why}"));
                    profile.undecide(Capability::DeriveReadOnly, class, why);
                }
            }
        }
        Err(e) => made.undetermined.push(format!("no read-only ECDH probe on {on}: {e}")),
    }
    if let Ok(attrs) = made.session.get_attributes(private, &[AttributeType::Derive])
        && let Some(Attribute::Derive(false)) = attrs.into_iter().next()
    {
        profile
            .note("derive.key-attribute".into(), format!("{on}: derives although the key reports CKA_DERIVE = false"));
    }
}

/// A host verifier of an RSA signature over the message (`sig::rsa_pkcs1v15`, `sig::rsa_pss`),
/// or none where the host does not compute the hash.
pub(super) type RsaCheck = Option<fn(&[u8], &[u8], &[u8]) -> sig::Verdict>;

/// RSA signing (PKCS#1 v1.5 raw and hashed, PSS raw and hashed, raw X.509) and decryption
/// (PKCS#1 v1.5, OAEP per hash: `decrypt.oaep`), on a 2048-bit key.
pub(super) fn rsa_ops(made: &mut Made, profile: &mut Draft, private: ObjectHandle, spki: &[u8], on: &str) {
    let pss = |hash, mgf, len: usize| PkcsPssParams { hash_alg: hash, mgf, s_len: (len as u64).into() };
    // What raw `CKM_RSA_PKCS` signs: the digest behind its `DigestInfo` prefix.
    let digest_info = [token::digest_info(HashAlg::Sha256), Sha256::digest(MSG).as_slice()].concat();
    // Raw RSA signs one block the modulus' size, the key's whatever it is (an existing key
    // under the probes may be larger than the 2048 bits generated); a leading zero keeps it
    // below the modulus.
    let block = pop::rsa_modulus_len(spki).map(|n| [vec![0u8], vec![0x5a; n.saturating_sub(1)]].concat());
    let sha256 = Sha256::digest(MSG).to_vec();
    // Each signature verified on the host over the message, as its hash says (the raw forms sign
    // SHA-256's digest of it); SHA-1, which the host does not compute, is signed unchecked
    // (review 2026-11-23 D-2: all but two went unverified, and fed `add` rows).
    let signs: [(Mechanism, Vec<u8>, RsaCheck); 11] = [
        (Mechanism::RsaPkcs, digest_info, Some(sig::rsa_pkcs1v15::<Sha256>)),
        (Mechanism::Sha1RsaPkcs, MSG.to_vec(), None),
        (Mechanism::Sha224RsaPkcs, MSG.to_vec(), Some(sig::rsa_pkcs1v15::<Sha224>)),
        (Mechanism::Sha256RsaPkcs, MSG.to_vec(), Some(sig::rsa_pkcs1v15::<Sha256>)),
        (Mechanism::Sha384RsaPkcs, MSG.to_vec(), Some(sig::rsa_pkcs1v15::<Sha384>)),
        (Mechanism::Sha512RsaPkcs, MSG.to_vec(), Some(sig::rsa_pkcs1v15::<Sha512>)),
        (
            Mechanism::RsaPkcsPss(pss(MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32)),
            sha256,
            Some(sig::rsa_pss::<Sha256>),
        ),
        (Mechanism::Sha1RsaPkcsPss(pss(MechanismType::SHA1, PkcsMgfType::MGF1_SHA1, 20)), MSG.to_vec(), None),
        (
            Mechanism::Sha256RsaPkcsPss(pss(MechanismType::SHA256, PkcsMgfType::MGF1_SHA256, 32)),
            MSG.to_vec(),
            Some(sig::rsa_pss::<Sha256>),
        ),
        (
            Mechanism::Sha384RsaPkcsPss(pss(MechanismType::SHA384, PkcsMgfType::MGF1_SHA384, 48)),
            MSG.to_vec(),
            Some(sig::rsa_pss::<Sha384>),
        ),
        (
            Mechanism::Sha512RsaPkcsPss(pss(MechanismType::SHA512, PkcsMgfType::MGF1_SHA512, 64)),
            MSG.to_vec(),
            Some(sig::rsa_pss::<Sha512>),
        ),
    ];
    for (mech, data, check) in signs {
        let mt = mech.mechanism_type();
        if made.tries(mt) {
            let outcome = sign(made.session, &mech, private, &data, |s| check.and_then(|v| v(spki, MSG, s)));
            made.record_signed(mt, on, outcome);
        }
    }
    if made.tries(MechanismType::RSA_X_509) {
        let outcome = match &block {
            Ok(block) => sign(made.session, &Mechanism::RsaX509, private, block, |_| None),
            Err(e) => Err(e.to_string().into()),
        };
        made.record_signed(MechanismType::RSA_X_509, on, outcome);
    }
    // Decryption: the host encrypts a fresh secret to the key, the token must recover it.
    let decrypts = |made: &mut Made, mech: &Mechanism, padding| -> std::result::Result<(), Msg> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| e.to_string())?;
        let cipher = pop::rsa_encrypt(spki, padding, &secret).map_err(|e| e.to_string())?;
        let plain = made.session.decrypt(mech, private, &cipher).map_err(|e| ck_refusal(&e))?;
        if pop::ct_eq(&secret, &plain) { Ok(()) } else { Err("decrypts to something else".into()) }
    };
    if made.tries(MechanismType::RSA_PKCS) {
        let outcome = decrypts(made, &Mechanism::RsaPkcs, RsaPadding::Pkcs1v15);
        made.record(MechanismType::RSA_PKCS, &format!("{on} decrypt"), outcome);
    }
    if made.tries(MechanismType::RSA_PKCS_OAEP) {
        let mut works = Vec::new();
        // The hashes a decryption proof tries (`token::OAEP`), each on its own.
        for padding in token::OAEP {
            let Some((params, name)) = token::oaep_params(padding) else { continue };
            let outcome = decrypts(made, &Mechanism::RsaPkcsOaep(params), padding);
            let cap = Capability::DecryptOaep(name.to_owned());
            match &outcome {
                Ok(()) => works.push(name.to_owned()),
                // The host's own finding (another plaintext), or its own failure to ask.
                Err(e) if e.rv().is_none() => profile.found_wrong(cap),
                Err(e) => {
                    let class = Refusal::of(e.rv());
                    if class != Refusal::Module {
                        profile.undecide(cap, class, e.to_string());
                    }
                }
            }
            made.record(MechanismType::RSA_PKCS_OAEP, &format!("{on} decrypt {name}"), outcome);
        }
        // Probed: `[]` when no hash decrypts, distinct from never probed.
        profile.decrypt_oaep = Some(works);
    }
}
