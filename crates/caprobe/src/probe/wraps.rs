//! The wrap probes (docs/CAPROBE.md): key wrapping and unwrapping under the transport key, and
//! the check that the module also unwraps blobs that the host made.

use super::{
    Attribute, Capability, Checked, CkError, Draft, KeyType, KmError, Kt, Made, Mechanism, MechanismType, OaepHash,
    ObjectClass, ObjectHandle, PkcsMgfType, PkcsOaepParams, PkcsOaepSource, RsaPadding, RvError, Session, ckr,
    evidence, moves, pop, refused, secret_template, token,
};

/// Finds the OAEP hashes that the module actually implements, and probes the unwrap-template
/// rule. For each hash, the probe wraps the new AES key under the public half of the new RSA
/// transport key and unwraps it again with the private half, and only a complete round trip
/// counts. The module must also unwrap a blob that the host made with the same hash
/// ([`host_blob`]). The unwrap-template rule is whether the module accepts an unwrap template
/// that carries `CKA_VALUE_LEN`, which `SoftHSM` refuses with `CKR_ATTRIBUTE_READ_ONLY`.
pub(super) fn probe_wrapping(
    made: &mut Made,
    profile: &mut Draft,
    transport: (ObjectHandle, ObjectHandle),
    aes: ObjectHandle,
) {
    let session = made.session;
    let (wraps, unwraps) = transport;
    // Each parameter set uses MGF1 with the same hash, as a transport wrap does (`OaepHash`).
    let oaep_of = |hash| {
        let (params, name) = token::oaep_of(hash);
        (Mechanism::RsaPkcsOaep(params), name)
    };
    let mut round_trips = Vec::new();
    let mut failures = Vec::new();
    // The row of each hash is written in this loop. It is a yes when the host's blob decodes, or
    // an unverified yes from the module's own round trip when the host's blob cannot decide. It
    // is a no for the module's refusal or for the host's finding, and any other failure writes no
    // row (E-2).
    let mut failed = |made: &mut Made, profile: &mut Draft, name: &str, why: String, rv: Option<u64>| {
        failures.push(format!("{name}: {why}"));
        let cap = Capability::WrapOaep(name.to_owned());
        match rv {
            None => profile.wrong(cap, why),
            rv => profile.refused(&mut made.undetermined, cap, rv, why),
        }
    };
    for hash in [OaepHash::Sha1, OaepHash::Sha256] {
        let (mech, name) = oaep_of(hash);
        // Wrapping is encryption, so the public half wraps and the private half unwraps.
        let wrapped = match session.wrap_key(&mech, wraps, aes) {
            Ok(w) => w,
            Err(e) => {
                failed(made, profile, name, format!("wrapping fails: {}", ckr(&e)), token::rv_of(&e));
                continue;
            }
        };
        let label = made.scratch.label();
        let template = [
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
        ];
        match session.unwrap_key(&mech, unwraps, &wrapped, &template) {
            Ok(h) => {
                made.scratch.track(&[h], &label);
                // Only the key that was wrapped counts as the key that came back. A module that
                // wraps and unwraps with another hash than the one asked for passes its own round
                // trip, so a blob that the host made with this hash must also decode (review
                // 2026-11-23 D-3).
                if same_key(session, aes, h) == Some(false) {
                    failed(made, profile, name, "unwraps its own blob to another key".into(), None);
                    continue;
                }
                let cap = Capability::WrapOaep(name.to_owned());
                match host_blob(made, &mech, wraps, unwraps, hash) {
                    HostBlob::Decodes(checked) => {
                        round_trips.push((name, hash));
                        profile.yes(cap, checked, None);
                    }
                    HostBlob::Refused(why, rv) => failed(made, profile, name, why, rv),
                    HostBlob::Untold(why) => {
                        made.undetermined.push(format!(
                            "wrap.rsa-oaep.{name} rests on the module's own round trip, not a host-made blob: {why}"
                        ));
                        round_trips.push((name, hash));
                        profile.yes(cap, Checked::unverified(), None);
                    }
                }
            }
            Err(e) => failed(made, profile, name, format!("wraps but does not unwrap: {}", ckr(&e)), token::rv_of(&e)),
        }
    }
    // All the failures go into one note under "oaep", which the `--oaep` verdicts cite.
    if !failures.is_empty() {
        profile.note("oaep".into(), failures.join("; "));
    }
    // An empty list means that the probe ran and no hash completed a round trip, which differs
    // from `None` (never probed).
    profile.wrap_oaep = Some(round_trips.iter().map(|(name, ..)| (*name).to_owned()).collect());
    // The unwrap-template rule is probed with the first hash that completed a round trip, and it
    // stays unprobed when there is none.
    let Some((mech, _)) = round_trips.first().map(|(_, hash)| oaep_of(*hash)) else {
        return;
    };
    let wrapped = match session.wrap_key(&mech, wraps, aes) {
        Ok(wrapped) => wrapped,
        // The key wrapped a moment ago, so this failure leaves the row unprobed, with a note that
        // says why.
        Err(e) => {
            profile.note("unwrap-template".into(), format!("CKA_VALUE_LEN: wrapping the key again: {}", ckr(&e)));
            return;
        }
    };
    // The unwrapped key is a session key. SoftHSM refuses the template (CKR_ATTRIBUTE_READ_ONLY)
    // but keeps the token object that it started to create, without a label, so no cleanup can
    // find that object. A session object goes away with the session (review 2026-11-24 L4b-5,
    // caprobe's liar table).
    let label = made.scratch.label();
    let with_len = session.unwrap_key(
        &mech,
        unwraps,
        &wrapped,
        &[
            Attribute::Token(false),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::ValueLen(32.into()),
        ],
    );
    match with_len {
        Ok(h) => {
            profile.unwrap_refused = Some(Vec::new());
            made.scratch.track(&[h], &label);
        }
        Err(CkError::Pkcs11(RvError::AttributeReadOnly, _)) => {
            profile.unwrap_refused = Some(vec!["CKA_VALUE_LEN".into()]);
            profile.note("CKA_VALUE_LEN".into(), "CKR_ATTRIBUTE_READ_ONLY in an unwrap template".into());
        }
        // The module neither accepted the template nor gave the refusal that the rule names, so
        // the row stays unprobed.
        Err(e) => {
            profile.note("unwrap-template".into(), format!("CKA_VALUE_LEN: {}", ckr(&e)));
        }
    }
}

/// Tests each key wrap that the module advertises with a round trip: the AES key is wrapped and
/// unwrapped again, under a new AES key-encryption key (`CKM_AES_KEY_WRAP`,
/// `CKM_AES_KEY_WRAP_PAD`, and `CKM_AES_KEY_WRAP_KWP`) or under the RSA transport key
/// (`CKM_RSA_AES_KEY_WRAP`, with either OAEP hash). `CKM_AES_KEY_WRAP_KWP` and
/// `CKM_RSA_AES_KEY_WRAP` are tried only when this build has the `kwp` feature. A mechanism that
/// the module refuses as a mechanism (`CKR_MECHANISM_INVALID`, `CKR_FUNCTION_NOT_SUPPORTED`)
/// becomes a `subtract` row: AWS `CloudHSM` lists `CKM_AES_KEY_WRAP` and `CKM_AES_KEY_WRAP_PAD`
/// with `CKF_WRAP | CKF_UNWRAP` and refuses both \[run\]. Any other refusal becomes a note and
/// never a subtraction, because the probe's template or key may have caused it, not the
/// mechanism.
pub(super) fn probe_key_wraps(
    made: &mut Made,
    profile: &mut Draft,
    transport: (ObjectHandle, ObjectHandle),
    aes: ObjectHandle,
) {
    let session = made.session;
    let kek = wrapping_kek(made);
    // For each wrap: its name, its variants (one for each OAEP hash for CKM_RSA_AES_KEY_WRAP),
    // its wrapping key and its unwrapping key.
    let mut wraps: Vec<(&str, Vec<KeyWrap>, ObjectHandle, ObjectHandle)> = Vec::new();
    if let Some(kek) = kek {
        wraps.push(("CKM_AES_KEY_WRAP", vec![KeyWrap::Aes(Mechanism::AesKeyWrap)], kek, kek));
        wraps.push(("CKM_AES_KEY_WRAP_PAD", vec![KeyWrap::Aes(Mechanism::AesKeyWrapPad)], kek, kek));
        #[cfg(feature = "kwp")]
        wraps.push(("CKM_AES_KEY_WRAP_KWP", vec![KeyWrap::Aes(Mechanism::AesKeyWrapKwp)], kek, kek));
    }
    if cfg!(feature = "kwp") {
        let hashes = [
            KeyWrap::RsaAes(MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
            KeyWrap::RsaAes(MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
        ];
        wraps.push(("CKM_RSA_AES_KEY_WRAP", hashes.into(), transport.0, transport.1));
    }
    let advertised = made.tok.advertised();
    for (name, variants, wraps_with, unwraps_with) in wraps {
        if !advertised.iter().any(|a| a == name) {
            continue;
        }
        let mut refusals = Vec::new();
        let (mut round_trip, mut wrong_key) = (false, false);
        for variant in variants {
            let oaep;
            let mech = match variant {
                KeyWrap::Aes(m) => m,
                KeyWrap::RsaAes(hash, mgf) => {
                    oaep = PkcsOaepParams::new(hash, mgf, PkcsOaepSource::empty());
                    match rsa_aes_key_wrap(&oaep) {
                        Some(m) => m,
                        None => continue,
                    }
                }
            };
            let mech = &mech;
            let wrapped = match session.wrap_key(mech, wraps_with, aes) {
                Ok(w) => w,
                Err(e) => {
                    refusals.push(("C_WrapKey", e));
                    continue;
                }
            };
            let label = made.scratch.label();
            let template = [
                Attribute::Token(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
            ];
            match session.unwrap_key(mech, unwraps_with, &wrapped, &template) {
                Ok(h) => {
                    made.scratch.track(&[h], &label);
                    // The unwrapped key must be the key that was wrapped, not any key (review
                    // 2026-11-23 D-3).
                    match same_key(session, aes, h) {
                        Some(true) => round_trip = true,
                        Some(false) => wrong_key = true,
                        None => {
                            made.undetermined.push(format!(
                                "{name}: the unwrapped key is not compared with the one wrapped (no CKM_AES_ECB \
                                 check value of both)"
                            ));
                            round_trip = true;
                        }
                    }
                }
                Err(e) => refusals.push(("C_UnwrapKey", e)),
            }
        }
        if round_trip {
            continue;
        }
        if wrong_key {
            profile.note(name.to_owned(), "wraps, but unwraps its own blob to another key".into());
            continue;
        }
        let refused_as_such = refusals
            .iter()
            .any(|(_, e)| matches!(e, CkError::Pkcs11(RvError::MechanismInvalid | RvError::FunctionNotSupported, _)));
        let what: Vec<String> = refusals.iter().map(|(f, e)| format!("{f}: {}", ckr(e))).collect();
        if refused_as_such {
            profile.out.subtract.mechanisms.push(name.to_owned());
            profile.note(name.to_owned(), format!("advertised but refused: {}", what.join("; ")));
        } else {
            profile.note(name.to_owned(), format!("no round trip, not a mechanism refusal: {}", what.join("; ")));
        }
    }
    profile.out.subtract.mechanisms.sort();
    profile.out.subtract.mechanisms.dedup();
}

/// Generates a scratch AES-256 key that wraps and unwraps, for the AES wraps of
/// [`probe_key_wraps`]. Returns `None`, and adds a line to the undetermined list, when the token
/// does not make one.
pub(super) fn wrapping_kek(made: &mut Made) -> Option<ObjectHandle> {
    let label = made.scratch.label();
    let template = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Wrap(true),
        Attribute::Unwrap(true),
    ];
    let kek = secret_template(made.tok, Kt::Aes, &label, template)
        .map_err(|e| refused(made.tok, &e))
        .and_then(|t| made.session.generate_key(&Mechanism::AesKeyGen, &t).map_err(|e| ckr(&e)));
    match kek {
        Ok(h) => {
            made.scratch.track(&[h], &label);
            Some(h)
        }
        Err(e) => {
            made.undetermined.push(format!("no AES key wrap probes: a wrapping AES key: {e}"));
            None
        }
    }
}

/// Returns whether the AES keys `a` and `b` on the token are the same key, by comparing their
/// check values (`CKM_AES_ECB` of a zero block). Returns `None` when a check value cannot be
/// computed: the module has no ECB, or a key may not encrypt.
pub(super) fn same_key(session: &Session, a: ObjectHandle, b: ObjectHandle) -> Option<bool> {
    let kcv = |h| session.encrypt(&Mechanism::AesEcb, h, &[0; 16]).ok();
    Some(kcv(a)? == kcv(b)?)
}

/// What a blob that the host made shows about the module's RSA-OAEP with one hash
/// ([`host_blob`]).
pub(super) enum HostBlob {
    /// The blob unwrapped to the key that the host wrapped, as the host checked.
    Decodes(Checked),
    /// The blob did not unwrap to that key, so the module does not decode OAEP with this hash,
    /// whatever its own round trip showed. The values are the reason and the return value of the
    /// module's refusal, which is `None` when the host found another key.
    Refused(String, Option<u64>),
    /// The probe could not decide, and the value says why.
    Untold(String),
}

/// The host encrypts a known AES key ([`moves::AES_KEYS`]) to the transport key `public` with
/// RSA-OAEP and `hash`, and the token must unwrap the blob with `mech` and `unwraps` to that key
/// (review 2026-11-23 D-3: a module that used another hash than the one asked for passed its own
/// round trip). The function destroys the unwrapped session key afterwards.
pub(super) fn host_blob(
    made: &Made,
    mech: &Mechanism,
    public: ObjectHandle,
    unwraps: ObjectHandle,
    hash: OaepHash,
) -> HostBlob {
    let value = moves::AES_KEYS[2];
    let spki = match made.tok.material_spki(public) {
        Ok(Some(spki)) => spki,
        Ok(None) => return HostBlob::Untold("the transport key's public half carries no material".into()),
        Err(e) => return HostBlob::Untold(evidence(made.tok, &e)),
    };
    let blob = match pop::rsa_encrypt(&spki, RsaPadding::Oaep(hash), value) {
        Ok(blob) => blob,
        Err(e) => return HostBlob::Untold(evidence(made.tok, &e)),
    };
    let template = [
        Attribute::Token(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Encrypt(true),
    ];
    // The module's own blob unwrapped a moment ago, so a refusal of this blob is caused by the
    // blob (modules report it as CKR_ENCRYPTED_DATA_INVALID, CKR_WRAPPED_KEY_INVALID or
    // CKR_GENERAL_ERROR). The exception is a refusal of the template, because this template
    // differs from the template of the round trip.
    let h = match made.session.unwrap_key(mech, unwraps, &blob, &template) {
        Ok(h) => h,
        Err(
            e @ CkError::Pkcs11(
                RvError::TemplateIncomplete
                | RvError::TemplateInconsistent
                | RvError::AttributeTypeInvalid
                | RvError::AttributeValueInvalid
                | RvError::AttributeReadOnly,
                _,
            ),
        ) => return HostBlob::Untold(format!("unwrapping a host-made blob, its template: {}", ckr(&e))),
        Err(e) => {
            let why = format!("unwraps its own blob but not one the host made: {}", ckr(&e));
            return HostBlob::Refused(why, token::rv_of(&e));
        }
    };
    let verdict = match Checked::verified(moves::same_aes(made, h, value)) {
        Ok(checked) => HostBlob::Decodes(checked),
        Err(KmError::Conflict(_)) => HostBlob::Refused("unwraps a host-made blob to another key".into(), None),
        Err(e) => HostBlob::Untold(evidence(made.tok, &e)),
    };
    let _ = made.session.destroy_object(h);
    verdict
}

/// One key wrap that [`probe_key_wraps`] tries: an AES key wrap, or `CKM_RSA_AES_KEY_WRAP` with
/// RSA-OAEP of the given hash and the given MGF1 function, which uses the same hash.
pub(super) enum KeyWrap {
    Aes(Mechanism<'static>),
    RsaAes(MechanismType, PkcsMgfType),
}

/// Returns `CKM_RSA_AES_KEY_WRAP` with a 256-bit AES key and the OAEP parameters `oaep`. Only the
/// patched cryptoki names this mechanism, so this function returns it only with the `kwp`
/// feature.
#[cfg(feature = "kwp")]
#[allow(clippy::unnecessary_wraps, reason = "the unpatched build's twin has nothing to return")]
pub(super) fn rsa_aes_key_wrap<'a>(oaep: &'a PkcsOaepParams<'a>) -> Option<Mechanism<'a>> {
    Some(Mechanism::RsaAesKeyWrap(cryptoki::mechanism::rsa::RsaAesKeyWrapParams::new(256.into(), oaep)))
}

#[cfg(not(feature = "kwp"))]
pub(super) fn rsa_aes_key_wrap<'a>(_: &'a PkcsOaepParams<'a>) -> Option<Mechanism<'a>> {
    None
}
