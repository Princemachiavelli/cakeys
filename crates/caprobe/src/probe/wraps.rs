//! The wrap probes: key wrapping and unwrapping under the transport key, and the host's
//! own blobs they must agree with (docs/CAPROBE.md).

use super::{
    Attribute, Capability, Checked, CkError, Draft, KeyType, KmError, Kt, Made, Mechanism, MechanismType, OaepHash,
    ObjectClass, ObjectHandle, PkcsMgfType, PkcsOaepParams, PkcsOaepSource, RsaPadding, RvError, Session, ckr,
    evidence, moves, pop, refused, secret_template, token,
};

/// The OAEP hashes the module actually implements — wrap the fresh AES key to the fresh RSA
/// transport key (public half) and unwrap it back with the private half, only a round trip
/// counts — and the unwrap-template rule: a template carrying `CKA_VALUE_LEN`, refused with
/// `CKR_ATTRIBUTE_READ_ONLY` by `SoftHSM`.
pub(super) fn probe_wrapping(
    made: &mut Made,
    profile: &mut Draft,
    transport: (ObjectHandle, ObjectHandle),
    aes: ObjectHandle,
) {
    let session = made.session;
    let (wraps, unwraps) = transport;
    // MGF1 of the same hash: the parameter sets a transport wrap uses (`OaepHash`).
    let oaep_of = |hash| {
        let (params, name) = token::oaep_of(hash);
        (Mechanism::RsaPkcsOaep(params), name)
    };
    let mut round_trips = Vec::new();
    let mut failures = Vec::new();
    // Each hash's row is written here: yes by the host's blob (or, untold, the module's own round
    // trip), no by the module's refusal or the host's finding; any other failure no row (E-2).
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
        // Wrapping is encryption: the public half wraps, the private half unwraps.
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
                // Only the key that went in counts as coming back, and a module that wraps and
                // unwraps with another hash than asked passes its own round trip: a blob the
                // host made with this hash must decode too (review 2026-11-23 D-3).
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
    // One note under "oaep": what `--oaep` verdicts cite.
    if !failures.is_empty() {
        profile.note("oaep".into(), failures.join("; "));
    }
    // Probed: `[]` when no hash round-trips, distinct from never probed.
    profile.wrap_oaep = Some(round_trips.iter().map(|(name, ..)| (*name).to_owned()).collect());
    // The unwrap-template rule, with the first hash that round-trips; unprobed without one.
    let Some((mech, _)) = round_trips.first().map(|(_, hash)| oaep_of(*hash)) else {
        return;
    };
    let wrapped = match session.wrap_key(&mech, wraps, aes) {
        Ok(wrapped) => wrapped,
        // It wrapped a moment ago: the row stays unprobed, and says why.
        Err(e) => {
            profile.note("unwrap-template".into(), format!("CKA_VALUE_LEN: wrapping the key again: {}", ckr(&e)));
            return;
        }
    };
    // A session key: SoftHSM refuses the template (CKR_ATTRIBUTE_READ_ONLY) and keeps the token
    // object it began, unlabelled, which no cleanup can name; a session one goes with the session
    // (review 2026-11-24 L4b-5, caprobe's liar table).
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
        // Neither accepted nor the refusal the rule names: the row stays unprobed.
        Err(e) => {
            profile.note("unwrap-template".into(), format!("CKA_VALUE_LEN: {}", ckr(&e)));
        }
    }
}

/// The key wraps the module advertises, each round-tripped: the AES key wrapped and unwrapped
/// back, under a fresh AES key-encryption key (`CKM_AES_KEY_WRAP`, `_PAD`, and `_KWP` where this
/// build names it) or under the RSA transport key (`CKM_RSA_AES_KEY_WRAP`, either OAEP hash). A
/// mechanism the module refuses as such (`CKR_MECHANISM_INVALID`, `CKR_FUNCTION_NOT_SUPPORTED`)
/// is a `subtract` row: AWS `CloudHSM` lists `CKM_AES_KEY_WRAP` and `_PAD` with
/// `CKF_WRAP | CKF_UNWRAP` and refuses both \[run\]. Any other refusal is a note, never a
/// subtraction: it may be the probe's template or key, not the mechanism.
pub(super) fn probe_key_wraps(
    made: &mut Made,
    profile: &mut Draft,
    transport: (ObjectHandle, ObjectHandle),
    aes: ObjectHandle,
) {
    let session = made.session;
    let kek = wrapping_kek(made);
    // Each wrap's variants (CKM_RSA_AES_KEY_WRAP's by OAEP hash), its wrapping and unwrapping key.
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
                    // The key that went in, not any key (review 2026-11-23 D-3).
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

/// A scratch AES-256 key that wraps and unwraps, for [`probe_key_wraps`]' AES wraps; `None`,
/// said as undetermined, when the token will not make one.
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

/// Whether the AES keys `a` and `b` on the token are one key: the same check value (`CKM_AES_ECB`
/// of a zero block). `None` when that cannot be told: no ECB, or a key that may not encrypt.
pub(super) fn same_key(session: &Session, a: ObjectHandle, b: ObjectHandle) -> Option<bool> {
    let kcv = |h| session.encrypt(&Mechanism::AesEcb, h, &[0; 16]).ok();
    Some(kcv(a)? == kcv(b)?)
}

/// What a blob the host made says of the module's RSA-OAEP with one hash ([`host_blob`]).
pub(super) enum HostBlob {
    /// It unwrapped to the key the host wrapped, as the host checked.
    Decodes(Checked),
    /// It did not: the module does not decode OAEP with this hash, whatever its own round trip.
    /// The return value of its refusal; `None`: the host found another key.
    Refused(String, Option<u64>),
    /// It could not be told: why.
    Untold(String),
}

/// The host OAEP-encrypts a known AES key ([`moves::AES_KEYS`]) to the transport key `public`
/// with `hash`; the token must unwrap it with `mech` and `unwraps` to that key (review
/// 2026-11-23 D-3: a module using another hash than asked passed its own round trip). The
/// unwrapped session key is destroyed again.
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
    // Its own blob unwrapped a moment ago: a refusal of this one is the blob's (modules say so
    // as CKR_ENCRYPTED_DATA_INVALID, CKR_WRAPPED_KEY_INVALID or CKR_GENERAL_ERROR), unless it is
    // about the template, which differs from the round trip's.
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

/// One key wrap [`probe_key_wraps`] tries: an AES key wrap, or `CKM_RSA_AES_KEY_WRAP` with
/// RSA-OAEP of this hash (MGF1 of the same).
pub(super) enum KeyWrap {
    Aes(Mechanism<'static>),
    RsaAes(MechanismType, PkcsMgfType),
}

/// `CKM_RSA_AES_KEY_WRAP` with an AES-256 key and `oaep`: only the patched cryptoki names it
/// (the `kwp` feature).
#[cfg(feature = "kwp")]
#[allow(clippy::unnecessary_wraps, reason = "the unpatched build's twin has nothing to return")]
pub(super) fn rsa_aes_key_wrap<'a>(oaep: &'a PkcsOaepParams<'a>) -> Option<Mechanism<'a>> {
    Some(Mechanism::RsaAesKeyWrap(cryptoki::mechanism::rsa::RsaAesKeyWrapParams::new(256.into(), oaep)))
}

#[cfg(not(feature = "kwp"))]
pub(super) fn rsa_aes_key_wrap<'a>(_: &'a PkcsOaepParams<'a>) -> Option<Mechanism<'a>> {
    None
}
