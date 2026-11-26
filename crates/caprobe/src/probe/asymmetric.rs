//! The asymmetric probes (docs/CAPROBE.md). They generate key pairs on the EC and Edwards
//! curves, Montgomery key pairs and RSA key pairs, and they run the operations and the
//! derivations that each key's usage allows.

use super::{
    Attribute, AttributeType, Binding, Capability, Checked, CkError, Created, Curve, Digest, Draft, EcKdf,
    Ecdh1DeriveParams, EddsaParams, EddsaSignatureScheme, Encoding, GenerateRow, HashAlg, KeyKind, KeyType, KmError,
    Kt, MSG, Made, Mechanism, MechanismType, Msg, Object, ObjectCfg, ObjectClass, ObjectHandle, On, PkcsMgfType,
    PkcsPssParams, Refusal, Result, RsaPadding, Session, Sha224, Sha256, Sha384, Sha512, Target, ck_refusal, ck_said,
    ckr, derive_any, evidence, extras, pop, refused, show, sig, spec, token,
};

/// The RSA key sizes, in bits, that the write probes generate, whatever sizes the module reports
/// (the module's report is a claim, `[reported."CKK_RSA"]`). They are the sizes in common use
/// from 512 to 16384 bits. The gate answers yes for a size between two sizes that generated, so
/// these sizes cover the range.
pub(crate) const RSA_SIZES: [u32; 10] = [512, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384];

/// One curve to generate: its name, its `CKA_EC_PARAMS` value as an OID, and its
/// `CKA_EC_PARAMS` value as a `PrintableString` name where PKCS#11 3.0 allows that form.
pub(super) type CurveForm = (&'static str, &'static [u8], Option<&'static [u8]>);

/// Returns the Montgomery curves (`CKK_EC_MONTGOMERY`) of the names table
/// (`cakeys_names::Curve`), with RFC 8410's OIDs and PKCS#11 3.0's names. keys.toml cannot
/// declare a Montgomery key yet, because core has no Montgomery key type, so the probe takes
/// these curves from the names table and not from core's curves.
pub(super) fn montgomery() -> Vec<CurveForm> {
    cakeys_names::Curve::ALL
        .into_iter()
        .filter(|c| c.family() == cakeys_names::Family::Montgomery)
        .map(|c| (c.name(), c.params(), c.params_by_name()))
        .collect()
}

/// Returns the templates with which the probe tries to generate a Montgomery key pair: the
/// public template, the private template with usage, and the private template without usage. A
/// Montgomery public key verifies nothing, so its template names only the curve. The operation
/// probes need the private key to derive, so the private template with usage adds `CKA_DERIVE`.
/// The fallback pair (the public template and the private template without usage) names no
/// usage at all, so it is never stricter than the first try (review 2026-11-23 D-11).
pub(super) fn montgomery_templates(params: &[u8]) -> (Vec<Attribute>, Vec<Attribute>, Vec<Attribute>) {
    let public = vec![Attribute::EcParams(params.to_vec())];
    let private = vec![Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Sensitive(true)];
    let with_usage = [&private[..], &[Attribute::Derive(true)]].concat();
    (public, with_usage, private)
}

/// Generates a key pair on each curve and records the curve as `can` or `cannot`, with the
/// refusal's `CKR_*` value in a note, and as `by-name` when it generates only when the template
/// names the curve by name. The operation probes run on the first key of each kind immediately,
/// because in a scratch slot the next generation replaces that key.
pub(super) fn probe_curves(made: &mut Made, profile: &mut Draft) -> Result<()> {
    // The curves for which cakeys (core) has a key type: the Weierstrass curves or the Edwards
    // curves.
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
        // The probe also tries a generation mechanism that the module does not list, because the
        // list is a claim and the row records the module's answer. Where the provider uses a
        // stand-in mechanism instead (AWS CloudHSM lists no Edwards mechanism and makes Ed25519
        // keys with CKM_EC_KEY_PAIR_GEN [run]), the probe tries the stand-in. In both cases, the
        // mechanism goes into `add` if a curve generates.
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
        // The rest of the loop handles Montgomery keys. keys.toml cannot declare them, so the
        // probe uses its own templates.
        let mech = made.tok.runnable(mech);
        let mut probed_ops = false;
        for (curve, oid, name) in curves {
            let mut outcome = None;
            // The probe tries the OID first and then the curve name (`by_name` is true from the
            // second try on).
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

/// Records a generation mechanism that the module does not list and for which the provider has
/// no stand-in. The mechanism goes into `add` when a curve generated with it anyway.
pub(super) fn record_unlisted(profile: &mut Draft, unlisted: bool, keygen: MechanismType, row: &GenerateRow) {
    if unlisted && !row.can.is_empty() {
        profile.out.add.push(keygen.to_string());
        profile.note(keygen.to_string(), "not listed; generates".into());
    }
}

/// Generates a key pair of a key type that cakeys manages (`CKK_EC`, `CKK_EC_EDWARDS`) on each
/// curve, in the way that the verbs generate keys (`Token::create`). Each curve is recorded as
/// `can`, or as `cannot` with the refusal as the row's evidence, and as `by-name` when the module
/// accepts the curve only by name. The operation probes run immediately on the first key that
/// has its usage attributes, because in a scratch slot the next generation replaces that key.
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
                // The module refused the default CKA_PRIVATE = false on the public key (AWS
                // CloudHSM).
                if note.as_ref().is_some_and(|n| n.public_made_private) {
                    let said = token::PUBLIC_MADE_PRIVATE.to_owned();
                    made.template_notes.entry("template.public.CKA_PRIVATE".into()).or_insert(said);
                }
                // The operation probes, which include the proofs, run on the first key that has
                // its usage attributes. Each later key gets only the proofs.
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

/// Records a generation mechanism that the module does not list but for which the provider has
/// a stand-in (`ran`). The mechanism goes into `add` when a curve generated through the stand-in,
/// and it gets a note in both cases.
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

/// Generates an RSA key pair at each size: the sizes in [`RSA_SIZES`] up to the largest one that
/// the run requested, whatever sizes the module reports. The function records `can-bits` and
/// `cannot-bits` next to the range that the module reports, and the proofs of possession of each
/// size. The operation probes run on the 2048-bit pair, or on the next larger usable pair
/// ([`operates_on`]). On a scratch token, that pair is also the transport key of the wrap
/// probes: wrapping is encryption, so its public half wraps and its private half unwraps. In a
/// scratch slot the next size replaces that pair, so there it is not a transport key.
pub(super) fn probe_rsa(made: &mut Made, profile: &mut Draft) -> Result<Option<(ObjectHandle, ObjectHandle)>> {
    let mut row = profile.generate.remove(&KeyKind::Rsa).unwrap_or_default();
    let mut transport = None;
    let mut operated = false;
    for bits in made.rsa_sizes.clone() {
        // The probe generates the key in the way that the verbs do, with every usage attribute
        // that the proofs, the operation probes and the wrap probes need. Each attribute goes on
        // the half for which the spec defines it, because the defaults are the module's choice.
        // When the module refuses them, the probe uses the bare spec.
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

/// Returns whether the RSA operation probes run on the key of `bits` bits that was just made.
/// `usable` says whether the key has the usage attributes that the probes need, and `operated`
/// says whether the probes already ran. The probes run on the 2048-bit key or, when the module
/// does not make that key usable, on the next larger size that it makes usable. That key is also
/// the transport key of the wrap probes. A smaller key only proves possession.
pub(super) fn operates_on(bits: u32, usable: bool, operated: bool) -> bool {
    usable && !operated && bits >= 2048
}

/// Runs the operation probes on one new key pair of the kind `kt`: every mechanism that applies
/// to it (signing, ECDH derivation and decryption), whether or not the module lists it, with the
/// result verified on the host wherever cakeys can (`sig`, `pop`).
pub(super) fn operate(
    made: &mut Made,
    profile: &mut Draft,
    kt: &KeyKind,
    on: &str,
    public: ObjectHandle,
    private: ObjectHandle,
) {
    if matches!(kt, KeyKind::EcMontgomery) {
        // cakeys has no Montgomery SPKI and no host X25519, so the probe runs ECDH between two
        // key pairs on the token.
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
    // The proofs run first, because the verbs prove possession right after they generate a key.
    // A module that leaves an operation active after a failed operation (tpm2-pkcs11, on a hash
    // that the TPM lacks [run]) would otherwise refuse the proof's own C_*Init call with
    // CKR_OPERATION_ACTIVE.
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
                // The module does not list EdDSA, but the provider signs pure EdDSA with its own
                // mechanism (AWS CloudHSM's vendor mechanism [run]). EdDSA goes into `add` when
                // the host verifies the signature.
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

/// Runs [`prove`] on a key pair on which the operation probes do not run, after it reads the
/// SPKI of the pair's public half.
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

/// Runs the proofs of possession that the verbs run with a private key of the kind `kt` at `on`
/// (`Token::prove_binding`, the verbs' own code). Each proof becomes a `prove.*` row, with the
/// refusal as its evidence. The probe's token has no module profile, so each proof tries what it
/// can. A proof refused because an earlier operation left the session busy says nothing about
/// the key, so it is undetermined and never a row (tpm2-pkcs11 leaves a failed operation active
/// \[run\]).
pub(super) fn prove(made: &mut Made, profile: &mut Draft, kt: &KeyKind, on: &str, private: ObjectHandle, spki: &[u8]) {
    let (key_type, bindings): (Kt, &[Binding]) = match kt {
        KeyKind::Ec => (Kt::Ec, &[Binding::PopSign, Binding::PopEcdh]),
        KeyKind::EcEdwards => (Kt::EcEdwards, &[Binding::PopSign]),
        KeyKind::Rsa => (Kt::Rsa, &[Binding::PopSign, Binding::PopDecrypt, Binding::PopUnwrap]),
        _ => return,
    };
    // A key that the host does not compute with has an identity but no proof here. The refusal
    // comes from cakeys and says nothing about the module, as with the import rows of a size
    // that the host cannot read.
    if key_type == Kt::Rsa && !cakeys_core::pop::rsa_computes_with(spki) {
        made.undetermined.push(format!("no proofs on {on}: the host computes with no RSA key of that size"));
        return;
    }
    let mut object = ObjectCfg::new(cakeys_core::types::ObjectClass::PrivateKey, Some(key_type));
    let size = on.strip_prefix("RSA-").and_then(|b| b.parse::<u32>().ok());
    // A purpose-bound RSA key is named by its binding, because several such keys share a size
    // and each proves possession differently. The row keeps that name, and the proof uses the
    // size that the key reports.
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
        // The host verified the proof, and a signature that the host rejects is the host's
        // finding. Any other failure (no verifier on the host, or a device failure) is not an
        // answer from the module (E-2).
        match Checked::verified(outcome) {
            Ok(checked) => profile.yes(cap, checked, None),
            Err(e @ KmError::Conflict(_)) => profile.wrong(cap, evidence(made.tok, &e)),
            Err(e) => profile.refused(&mut made.undetermined, cap, e.rv(), evidence(made.tok, &e)),
        }
    }
}

/// Signs `data` with `mech`, and `check` verifies the signature on the host where it can.
/// Returns `Ok(true)` when the signature verified. Returns `Ok(false)` when the host has no
/// verifier for this mechanism (`check` returned `None`): the call succeeded, but nothing more
/// was seen, so the result produces no `add` row (review 2026-11-23 D-2).
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

/// Runs ECDSA, raw and with each hash, and verifies each signature on the host against the
/// digest that it signs. The host does not compute SHA-1, so the SHA-1 signature is not checked.
pub(super) fn ec_ops(made: &mut Made, private: ObjectHandle, spki: &[u8], on: &str, hash: Option<HashAlg>) {
    // Raw ECDSA signs the message's digest with the curve's hash (SHA-256 when the curve has
    // none).
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

/// Runs `CKM_ECDH1_DERIVE` against an ephemeral key of the host, as `pop-ecdh` does. The
/// function first derives into a sealed secret and checks it with an HMAC when the module has
/// one. Otherwise it derives into an extractable secret, reads it and compares it. The
/// `derive.sealed` row records which path worked, and a refused sealed derivation becomes the
/// row's note.
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
        // The sealed derivation was not refused, only unchecked, so it must not produce
        // `derive.sealed = no`.
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

/// The outcome of a derivation into a sealed secret.
pub(super) enum SealedPath {
    /// The module derives the shared secret into a sealed secret, and its HMAC is correct.
    Derives,
    /// The module derives a sealed secret, but it has no HMAC to check the secret with, and the
    /// message says so. `pop-ecdh` then takes the extractable path, so the extractable path
    /// proves the mechanism's row, and the sealed derivation is only a note (review 2026-11-23
    /// D-12).
    Unchecked(Msg),
    /// The module derives a secret that is not the shared secret. This is the outcome, and the
    /// probe does not try the extractable path.
    Wrong(Msg),
    /// The module refuses the derivation, cannot compute an HMAC with the secret, or derives
    /// only a secret that is not sealed. The message says which, and the probe tries the
    /// extractable path.
    Fallback(Msg),
}

/// Derives into a sealed secret and computes an HMAC with it, the way `pop-ecdh` proves
/// possession. When the derivation succeeds, `template` becomes the template that the module
/// accepted. When the secret reports other attributes than the ones asked for, they become a
/// note (AWS `CloudHSM`: sensitive, but extractable \[run\]).
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
        // Without an HMAC mechanism, the secret's own attributes show whether it is sealed. A
        // template that the module accepted only without its sealing attributes made an
        // extractable secret (ykcs11).
        None if is_sealed => SealedPath::Unchecked(Msg::from(
            "derives into a sealed secret, but lists no CKM_SHA256_HMAC to check it with",
        )),
        None => {
            SealedPath::Fallback(format!("derives only into a secret that is not sealed: it reports {reported}").into())
        }
    }
}

/// Derives into an extractable secret, reads it and compares it with the shared secret, after
/// the sealed path failed for the reason `why`. When the derivation succeeds, `template` becomes
/// the template that the module accepted.
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
            // The failure of the sealed path is the module's no when the module refused the
            // derivation. A secret that was derived but is not sealed (no return value) is also
            // the module's answer, because the module reports those attributes of the secret.
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

/// Records a note for a derivation that the module accepted only with a changed template: what
/// changed, and the first refusal.
pub(super) fn note_template(profile: &mut Draft, on: &str, changed: Option<(String, CkError)>) {
    if let Some((changed, first)) = changed {
        profile.note(
            "derive.template".into(),
            format!("{on}: the template as asked is refused ({}); derived with {changed}", ckr(&first)),
        );
    }
}

/// Destroys the secret `h` that a derivation on the path `path` made in `session`. A secret that
/// the module does not destroy stays on the token (tpm2-pkcs11 persists it). The probe then
/// records a note, because `pop-ecdh` derives one secret for each proof.
pub(super) fn destroy_derived(session: &Session, h: ObjectHandle, path: &str, on: &str, profile: &mut Draft) {
    if let Err(e) = session.destroy_object(h) {
        profile
            .note("derive.destroy".into(), format!("{on}: the {path} derived secret cannot be destroyed: {}", ckr(&e)));
    }
}

/// Runs after a derivation succeeded with `template`. The function checks whether the key
/// derives in the same way in a read-only session, where the read-only verbs (`check`,
/// `resolve`) prove possession. It also records what the key that derived reports about itself,
/// because a spec that asks for `CKA_DERIVE = true` is checked against the reported attribute
/// and not against what the key does.
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
/// or `None` where the host does not compute the hash.
pub(super) type RsaCheck = Option<fn(&[u8], &[u8], &[u8]) -> sig::Verdict>;

/// Runs RSA signing (PKCS#1 v1.5 raw and hashed, PSS raw and hashed, and raw X.509) and
/// decryption (PKCS#1 v1.5, and OAEP with each hash: `decrypt.oaep`) on the operation key, which
/// has 2048 bits or, when that key is not usable, the next larger usable size ([`operates_on`]).
pub(super) fn rsa_ops(made: &mut Made, profile: &mut Draft, private: ObjectHandle, spki: &[u8], on: &str) {
    let pss = |hash, mgf, len: usize| PkcsPssParams { hash_alg: hash, mgf, s_len: (len as u64).into() };
    // Raw `CKM_RSA_PKCS` signs the SHA-256 `DigestInfo` prefix followed by the message's
    // digest.
    let digest_info = [token::digest_info(HashAlg::Sha256), Sha256::digest(MSG).as_slice()].concat();
    // Raw RSA signs one block as long as the key's modulus, whatever its size, because the key
    // under the probes may be larger than 2048 bits. A leading zero byte keeps the block's value
    // below the modulus.
    let block = pop::rsa_modulus_len(spki).map(|n| [vec![0u8], vec![0x5a; n.saturating_sub(1)]].concat());
    let sha256 = Sha256::digest(MSG).to_vec();
    // The host verifies each signature over the message with the mechanism's hash (the raw
    // forms sign the message's SHA-256 digest). The host does not compute SHA-1, so the SHA-1
    // signatures are not checked (review 2026-11-23 D-2: before the fix, all but two signatures
    // went unverified and produced `add` rows).
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
    // Decryption: the host encrypts a new random secret to the key, and the token must recover
    // it.
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
        // The probe tries each hash that a decryption proof tries (`token::OAEP`), one at a time.
        for padding in token::OAEP {
            let Some((params, name)) = token::oaep_params(padding) else { continue };
            let outcome = decrypts(made, &Mechanism::RsaPkcsOaep(params), padding);
            let cap = Capability::DecryptOaep(name.to_owned());
            match &outcome {
                Ok(()) => works.push(name.to_owned()),
                // An error without a return value is the host's own finding (another
                // plaintext) or the host's own failure to ask, and both are recorded as the
                // host's no.
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
        // An empty list means that the probe ran and no hash decrypts, which differs from
        // `None` (never probed).
        profile.decrypt_oaep = Some(works);
    }
}
