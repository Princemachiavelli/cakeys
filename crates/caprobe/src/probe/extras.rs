//! The probes beyond the keys that cakeys manages (`docs/archive/CAPROBE_PROFILE_COVERAGE.md`,
//! Parts 3, 6, 7 and 8): the attributes that the verbs read, ECDH on Montgomery keys, the key
//! types that cakeys does not manage (`CKK_DES2`, `CKK_HKDF`), post-quantum generation, signing
//! and encapsulation, and what the module and the token claim about themselves. Every key here
//! is a session object, and the probe destroys it itself. The Montgomery ECDH, post-quantum
//! signature and ML-KEM rows rest only on the module (`by = "unverified"`), because both sides of
//! each of those checks run on the token.

use super::{Checked, Draft, Made, ck_said, ckr};
use cakeys_pkcs11::token::{self, Token};
use cakeys_profile::{Capability, KeyKind, MechanismInfo, On};
use cryptoki::mechanism::dsa::{HedgeType, SignAdditionalContext};
use cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{
    Attribute, AttributeType, KeyType, MlDsaParameterSetType, MlKemParameterSetType, ObjectClass, ObjectHandle,
    SlhDsaParameterSetType,
};
use cryptoki::session::Session;

/// The message the PQ signatures sign.
const MSG: &[u8] = b"cakeys probe: post-quantum";

/// Records the `C_GetMechanismInfo` result of every mechanism that the module lists as a claim
/// (`[mechanism-info]`), and what the token reports about itself (`[claims]`). These are not rows
/// and are never compared here. [`check_reported_ranges`] later compares the range that a module
/// reports for a key generation with what the generation probes found.
pub(super) fn record_claims(tok: &Token, profile: &mut Draft) {
    for (name, min, max, flags) in tok.mechanism_infos() {
        profile.out.mechanism_info.insert(
            name,
            MechanismInfo {
                min: u64::try_from(min).unwrap_or(u64::MAX),
                max: u64::try_from(max).unwrap_or(u64::MAX),
                flags: flags.into_iter().map(str::to_owned).collect(),
            },
        );
    }
    for (k, v) in tok.token_claims() {
        profile.out.claims.insert(k, v);
    }
    profile.out.claims.insert("interface".into(), format!("Cryptoki {}", tok.module.cryptoki));
    let s = tok.raw();
    for (class, name) in [
        (ObjectClass::HARDWARE_FEATURE, "hardware-features"),
        (ObjectClass::PROFILE, "profiles"),
        (ObjectClass::VALIDATION, "validation"),
    ] {
        if let Ok(found) = s.find_objects(&[Attribute::Class(class)]) {
            profile.out.claims.insert(format!("objects.{name}"), found.len().to_string());
        }
    }
}

/// Checks whether the key sizes that a module reports for a secret-key generation include every
/// length that the probe generated. A generated length outside `[min, max]` becomes a note under
/// `mechanism-info.<mechanism>` (kryoptic generates AES lengths outside the range that it
/// reports).
pub(super) fn check_reported_ranges(profile: &mut Draft) {
    let findings: Vec<(String, String)> = profile
        .generate
        .iter()
        .filter_map(|(kt, row)| {
            let mech = cakeys_profile::capability::generation_mechanism(kt.name())?;
            let info = profile.out.mechanism_info.get(mech)?;
            let outside: Vec<String> = row
                .can_bytes
                .iter()
                .filter(|n| info.max != 0 && (u64::from(**n) < info.min || u64::from(**n) > info.max))
                .map(ToString::to_string)
                .collect();
            (!outside.is_empty()).then(|| {
                (
                    format!("mechanism-info.{mech}"),
                    format!(
                        "generates {} bytes, outside the {}..{} it reports",
                        outside.join(", "),
                        info.min,
                        info.max
                    ),
                )
            })
        })
        .collect();
    for (k, v) in findings {
        profile.note(k, v);
    }
}

/// Generates a new 32-byte AES session key with the probe's own template (not the provider's),
/// with `CKA_EXTRACTABLE` false and with `extra` added. Returns `None` when the generation fails.
/// Review 2026-11-23 D-5: the template used to leave `CKA_EXTRACTABLE` to the module, so the
/// `CKA_NEVER_EXTRACTABLE` row could not be no on a module that makes keys extractable by
/// default.
fn aes_key(s: &Session, extra: &[Attribute]) -> Option<ObjectHandle> {
    let mut template = vec![
        Attribute::Token(false),
        Attribute::ValueLen(32.into()),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
    ];
    template.extend_from_slice(extra);
    s.generate_key(&Mechanism::AesKeyGen, &template).ok()
}

/// Writes the `attr.read.*` and `attr.set.*` rows on a generated AES key. The rows say whether
/// the module returns correct values for the provenance attributes that the verbs read
/// (`CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`, `CKA_NEVER_EXTRACTABLE`, `CKA_KEY_GEN_MECHANISM`), and
/// whether it accepts `CKA_ALLOWED_MECHANISMS` (`via = "enforced"` when it then refuses a
/// mechanism outside the list). When the module cannot generate an AES key, the probe writes none
/// of these rows and adds a line to the undetermined list.
pub(super) fn probe_attributes(made: &mut Made, profile: &mut Draft) {
    let (s, aes) = (made.session, KeyKind::Aes);
    let Some(key) = aes_key(s, &[Attribute::Encrypt(true), Attribute::Decrypt(true)]) else {
        made.undetermined.push("no attribute rows: the probe could not generate an AES key".into());
        return;
    };
    let read = s.get_attributes(
        key,
        &[
            AttributeType::Local,
            AttributeType::AlwaysSensitive,
            AttributeType::NeverExtractable,
            AttributeType::KeyGenMechanism,
            AttributeType::Extractable,
        ],
    );
    // A failed read says nothing about any one attribute, so the classifier (`Draft::refused`)
    // decides each row.
    let failed = read.as_ref().err().map(|e| (token::rv_of(e), format!("C_GetAttributeValue: {}", ckr(e))));
    let attrs = read.unwrap_or_default();
    let get = |t: AttributeType| attrs.iter().find(|a| a.attribute_type() == t);
    let row = |attr: &str, answer: Option<(bool, String)>, profile: &mut Draft, undetermined: &mut Vec<String>| {
        let cap = Capability::Attr { read: true, attr: attr.into(), key_type: aes.clone() };
        // The answer is checked before the match, because the workspace's rust-version (1.89) has
        // no `if let` guards in match arms.
        match (&failed, answer.map(|(truthful, why)| (Checked::same(&truthful, &true), why))) {
            (Some((rv, why)), _) => profile.refused(undetermined, cap, *rv, why.clone()),
            (None, Some((Some(c), _))) => profile.yes(cap, c, None),
            (None, Some((None, why))) => profile.wrong(cap, why),
            (None, None) => profile.wrong(cap, "the module does not return it".into()),
        }
    };
    row(
        "CKA_LOCAL",
        get(AttributeType::Local)
            .map(|a| (matches!(a, Attribute::Local(true)), format!("a generated key reads {a:?}"))),
        profile,
        &mut made.undetermined,
    );
    row(
        "CKA_ALWAYS_SENSITIVE",
        get(AttributeType::AlwaysSensitive)
            .map(|a| (matches!(a, Attribute::AlwaysSensitive(true)), format!("a key made sensitive reads {a:?}"))),
        profile,
        &mut made.undetermined,
    );
    row(
        "CKA_NEVER_EXTRACTABLE",
        get(AttributeType::NeverExtractable).map(|a| {
            // The value is correct when the key reads true, or when the key is extractable now.
            // A key that is not extractable now and never was must read true.
            let extractable = matches!(get(AttributeType::Extractable), Some(Attribute::Extractable(true)));
            (
                extractable || matches!(a, Attribute::NeverExtractable(true)),
                format!("a key never extractable reads {a:?}"),
            )
        }),
        profile,
        &mut made.undetermined,
    );
    row(
        "CKA_KEY_GEN_MECHANISM",
        get(AttributeType::KeyGenMechanism).map(|a| {
            (
                matches!(a, Attribute::KeyGenMechanism(m) if *m == MechanismType::AES_KEY_GEN),
                format!("an AES_KEY_GEN key reads {a:?}"),
            )
        }),
        profile,
        &mut made.undetermined,
    );
    let _ = s.destroy_object(key);
    // `CKA_ALLOWED_MECHANISMS`: the probe checks whether the module accepts the attribute,
    // returns it when it is read back, and enforces it.
    let cap = Capability::Attr { read: false, attr: "CKA_ALLOWED_MECHANISMS".into(), key_type: aes };
    let allowed = [Attribute::Encrypt(true), Attribute::AllowedMechanisms(vec![MechanismType::AES_ECB])];
    match s.generate_key(
        &Mechanism::AesKeyGen,
        &[&[Attribute::Token(false), Attribute::ValueLen(32.into())][..], &allowed].concat(),
    ) {
        Err(e) => profile.refused(&mut made.undetermined, cap, token::rv_of(&e), ckr(&e)),
        Ok(h) => {
            let back = s.get_attributes(h, &[AttributeType::AllowedMechanisms]).ok().and_then(|v| v.into_iter().next());
            let kept = matches!(&back, Some(Attribute::AllowedMechanisms(m)) if m == &vec![MechanismType::AES_ECB]);
            if kept {
                // If the module enforces the list, it must refuse CBC, which is outside the list.
                // Only a key that encrypts with the mechanism that the list allows (ECB), on a
                // module that has CBC, distinguishes a refusal because of the list from a refusal
                // of the key or of the mechanism (review 2026-11-23 D-5).
                let inside = s.encrypt(&Mechanism::AesEcb, h, &[0; 16]).is_ok();
                let outside = s.encrypt(&Mechanism::AesCbc([0; 16]), h, &[0; 16]).is_ok();
                let via = match (inside, made.tok.lists(MechanismType::AES_CBC), outside) {
                    (_, _, true) => Some("listed-only"),
                    (true, true, false) => Some("enforced"),
                    _ => {
                        made.undetermined.push(
                            "CKA_ALLOWED_MECHANISMS: whether it is enforced is not told: the key does not encrypt \
                             by CKM_AES_ECB, which its list allows, or the module has no CKM_AES_CBC to refuse"
                                .into(),
                        );
                        None
                    }
                };
                // When the probe could tell whether the module enforces the list (either
                // answer), the host checked the row. When it could not tell, the yes rests only on
                // the module (review 2026-11-24 E-4).
                let checked =
                    via.and(Checked::same(&back, &Some(Attribute::AllowedMechanisms(vec![MechanismType::AES_ECB]))));
                let checked = checked.unwrap_or_else(Checked::unverified);
                profile.yes(cap, checked, via.map(Into::into));
            } else {
                profile.wrong(cap, format!("it reads back {back:?}"));
            }
            let _ = s.destroy_object(h);
        }
    }
}

/// Writes the `generate.CKK_DES2.16` and `generate.CKK_HKDF.32` rows for the key types that
/// cakeys does not manage. The probe generates each key with its own template and the key type's
/// own mechanism, only when the module lists that mechanism, and records the result in the same
/// kind of row that the secret-key probes write.
pub(super) fn probe_unmanaged_keys(made: &mut Made, profile: &mut Draft) {
    let s = made.session;
    for (kind, mech, key_type, bytes, extra) in [
        ("CKK_DES2", Mechanism::Des2KeyGen, KeyType::DES2, 16u32, vec![]),
        ("CKK_HKDF", Mechanism::HkdfKeyGen, KeyType::HKDF, 32u32, vec![Attribute::Derive(true)]),
    ] {
        if !made.tok.lists(mech.mechanism_type()) {
            continue;
        }
        let kind = KeyKind::from(kind);
        let mut template = vec![Attribute::Token(false), Attribute::KeyType(key_type)];
        if key_type == KeyType::HKDF {
            template.push(Attribute::ValueLen(u64::from(bytes).into()));
        }
        template.extend(extra);
        let mut row = profile.generate.remove(&kind).unwrap_or_default();
        match s.generate_key(&mech, &template) {
            Ok(h) => {
                row.can_bytes.push(bytes);
                let _ = s.destroy_object(h);
            }
            Err(e) => profile.generation_refused(
                &mut made.undetermined,
                &mut row,
                (&kind, On::Bytes(bytes)),
                token::rv_of(&e),
                format!("valueLen = {bytes}: {}", ckr(&e)),
            ),
        }
        profile.generate.insert(kind, row);
    }
}

/// Returns the raw point of a public EC key in the form that `C_DeriveKey` takes: the contents of
/// the DER octet string when the module wraps the point in one, and the point unchanged
/// otherwise.
fn raw_point(p: &[u8]) -> Vec<u8> {
    match p {
        [0x04, n, rest @ ..] if usize::from(*n) == rest.len() => rest.to_vec(),
        _ => p.to_vec(),
    }
}

/// Writes the `derive.ecdh.CKK_EC_MONTGOMERY.<curve>` row: ECDH between two key pairs of the
/// curve on the token. Each private key derives with the other pair's public point into a
/// readable secret, and the two secrets must be equal. The caller passes the first pair that the
/// curve generated, and this function generates the second pair.
pub(super) fn montgomery_ecdh(
    made: &mut Made,
    profile: &mut Draft,
    curve: &str,
    params: &[&[u8]],
    (public_a, private_a): (ObjectHandle, ObjectHandle),
) {
    let s = made.session;
    let cap = Capability::DeriveEcdh { key_type: KeyKind::EcMontgomery, on: On::Item(curve.to_owned()) };
    let keygen = made.tok.runnable(Mechanism::EccMontgomeryKeyPairGen);
    let mut pair = None;
    for p in params {
        pair = Some(s.generate_key_pair(
            &keygen,
            &[Attribute::Token(false), Attribute::EcParams(p.to_vec())],
            &[Attribute::Token(false), Attribute::Derive(true), Attribute::Sensitive(true)],
        ));
        if matches!(pair, Some(Ok(_))) {
            break;
        }
    }
    let (public_b, private_b) = match pair {
        Some(Ok(p)) => p,
        Some(Err(e)) => {
            made.undetermined.push(format!("no {cap} row: a second {curve} pair: {}", ckr(&e)));
            return;
        }
        None => return,
    };
    let point = |h: ObjectHandle| {
        s.get_attributes(h, &[AttributeType::EcPoint]).ok().and_then(|v| match v.into_iter().next() {
            Some(Attribute::EcPoint(p)) => Some(raw_point(&p)),
            _ => None,
        })
    };
    let secret = |private: ObjectHandle, peer: &[u8]| -> std::result::Result<Vec<u8>, cakeys_core::Msg> {
        let mech = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), peer));
        let template = [
            Attribute::Token(false),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(32.into()),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
        ];
        let h = s.derive_key(&mech, private, &template).map_err(|e| ck_said("C_DeriveKey", &e))?;
        let v = s.get_attributes(h, &[AttributeType::Value]);
        let _ = s.destroy_object(h);
        match v.map(|v| v.into_iter().next()) {
            Ok(Some(Attribute::Value(v))) => Ok(v),
            _ => Err(cakeys_core::Msg::from("the derived secret is not readable")),
        }
    };
    if let (Some(a), Some(b)) = (point(public_a), point(public_b)) {
        match (secret(private_a, &b), secret(private_b, &a)) {
            // Both sides ran on this one module, so the yes is unverified (review 2026-11-24
            // E-3).
            (Ok(x), Ok(y)) if x == y => profile.yes(cap, Checked::unverified(), None),
            (Ok(_), Ok(_)) => profile.wrong(cap, "the two sides derive different secrets".into()),
            (Err(e), _) | (_, Err(e)) => profile.refused(&mut made.undetermined, cap, e.rv(), e.to_string()),
        }
    } else {
        made.undetermined.push(format!("no {cap} row: a {curve} public key's point is unreadable"));
    }
    for h in [public_b, private_b] {
        let _ = s.destroy_object(h);
    }
}

/// The parameter sets of one post-quantum key type.
struct PqFamily {
    key_type: &'static str,
    keygen: Mechanism<'static>,
    sets: Vec<(String, cryptoki::object::ParameterSetType)>,
}

fn pq_families() -> Vec<PqFamily> {
    let ml_dsa = [MlDsaParameterSetType::ML_DSA_44, MlDsaParameterSetType::ML_DSA_65, MlDsaParameterSetType::ML_DSA_87];
    let ml_kem =
        [MlKemParameterSetType::ML_KEM_512, MlKemParameterSetType::ML_KEM_768, MlKemParameterSetType::ML_KEM_1024];
    let slh = [
        SlhDsaParameterSetType::SHA2_128S,
        SlhDsaParameterSetType::SHAKE_128S,
        SlhDsaParameterSetType::SHA2_128F,
        SlhDsaParameterSetType::SHAKE_128F,
        SlhDsaParameterSetType::SHA2_192S,
        SlhDsaParameterSetType::SHAKE_192S,
        SlhDsaParameterSetType::SHA2_192F,
        SlhDsaParameterSetType::SHAKE_192F,
        SlhDsaParameterSetType::SHA2_256S,
        SlhDsaParameterSetType::SHAKE_256S,
        SlhDsaParameterSetType::SHA2_256F,
        SlhDsaParameterSetType::SHAKE_256F,
    ];
    vec![
        PqFamily {
            key_type: "CKK_ML_DSA",
            keygen: Mechanism::MlDsaKeyPairGen,
            sets: ml_dsa.iter().map(|p| (p.to_string(), (*p).into())).collect(),
        },
        PqFamily {
            key_type: "CKK_ML_KEM",
            keygen: Mechanism::MlKemKeyPairGen,
            sets: ml_kem.iter().map(|p| (p.to_string(), (*p).into())).collect(),
        },
        PqFamily {
            key_type: "CKK_SLH_DSA",
            keygen: Mechanism::SlhDsaKeyPairGen,
            sets: slh.iter().map(|p| (p.to_string(), (*p).into())).collect(),
        },
    ]
}

/// Returns the signing mechanisms of a post-quantum key type, by `CKM_*` name: the pure
/// mechanism and each hashed variant, with the parameters that the probe sends to the token.
fn pq_signers(key_type: &str) -> Vec<Mechanism<'static>> {
    let ctx = || SignAdditionalContext::new(HedgeType::Preferred, None);
    match key_type {
        "CKK_ML_DSA" => vec![
            Mechanism::MlDsa(ctx()),
            Mechanism::HashMlDsaSha224(ctx()),
            Mechanism::HashMlDsaSha256(ctx()),
            Mechanism::HashMlDsaSha384(ctx()),
            Mechanism::HashMlDsaSha512(ctx()),
            Mechanism::HashMlDsaSha3_224(ctx()),
            Mechanism::HashMlDsaSha3_256(ctx()),
            Mechanism::HashMlDsaSha3_384(ctx()),
            Mechanism::HashMlDsaSha3_512(ctx()),
            Mechanism::HashMlDsaShake128(ctx()),
            Mechanism::HashMlDsaShake256(ctx()),
        ],
        "CKK_SLH_DSA" => vec![
            Mechanism::SlhDsa(ctx()),
            Mechanism::HashSlhDsaSha224(ctx()),
            Mechanism::HashSlhDsaSha256(ctx()),
            Mechanism::HashSlhDsaSha384(ctx()),
            Mechanism::HashSlhDsaSha512(ctx()),
            Mechanism::HashSlhDsaSha3_224(ctx()),
            Mechanism::HashSlhDsaSha3_256(ctx()),
            Mechanism::HashSlhDsaSha3_384(ctx()),
            Mechanism::HashSlhDsaSha3_512(ctx()),
            Mechanism::HashSlhDsaShake128(ctx()),
            Mechanism::HashSlhDsaShake256(ctx()),
        ],
        _ => Vec::new(),
    }
}

/// Probes the post-quantum keys. The function writes a `generate.<type>.<parameter set>` row for
/// each parameter set. On the first key pair that generated, it writes a
/// `sign.<mechanism>.<type>.<set>` row for each signing mechanism that the module lists (signed
/// and verified on the token), or the `encapsulate.CKK_ML_KEM.<set>` row (encapsulated and
/// decapsulated, with the two secrets compared as readable keys). It tries only the key types
/// whose key-pair mechanism the module lists.
pub(super) fn probe_pq(made: &mut Made, profile: &mut Draft) {
    let s = made.session;
    for family in pq_families() {
        if !made.tok.lists(family.keygen.mechanism_type()) {
            continue;
        }
        let kind = KeyKind::from(family.key_type);
        let mut row = profile.generate.remove(&kind).unwrap_or_default();
        let kem = family.key_type == "CKK_ML_KEM";
        let mut first = true;
        for (name, set) in &family.sets {
            let (public, private) = if kem {
                (
                    vec![Attribute::Token(false), Attribute::ParameterSet(*set), Attribute::Encapsulate(true)],
                    vec![Attribute::Token(false), Attribute::Sensitive(true), Attribute::Decapsulate(true)],
                )
            } else {
                (
                    vec![Attribute::Token(false), Attribute::ParameterSet(*set), Attribute::Verify(true)],
                    vec![Attribute::Token(false), Attribute::Sensitive(true), Attribute::Sign(true)],
                )
            };
            match s.generate_key_pair(&family.keygen, &public, &private) {
                Ok((pu, pr)) => {
                    row.can.push(name.clone());
                    if first {
                        first = false;
                        if kem {
                            kem_row(made, profile, name, pu, pr);
                        } else {
                            sign_rows(made, profile, &kind, name, family.key_type, pu, pr);
                        }
                    }
                    for h in [pu, pr] {
                        let _ = s.destroy_object(h);
                    }
                }
                Err(e) => profile.generation_refused(
                    &mut made.undetermined,
                    &mut row,
                    (&kind, On::Item(name.clone())),
                    token::rv_of(&e),
                    format!("generation refused: {}", ckr(&e)),
                ),
            }
        }
        profile.generate.insert(kind, row);
    }
}

/// Writes a `sign.<mechanism>.<type>.<set>` row for each signing mechanism that the module
/// lists.
fn sign_rows(
    made: &mut Made,
    profile: &mut Draft,
    kind: &KeyKind,
    set: &str,
    key_type: &str,
    public: ObjectHandle,
    private: ObjectHandle,
) {
    let s = made.session;
    for mech in pq_signers(key_type) {
        let mt = mech.mechanism_type();
        if !made.tok.lists(mt) {
            continue;
        }
        let cap = Capability::Sign { mechanism: mt.to_string(), key_type: kind.clone(), on: On::Item(set.to_owned()) };
        match s.sign(&mech, private, MSG) {
            Err(e) => profile.refused(&mut made.undetermined, cap, token::rv_of(&e), ckr(&e)),
            // The module signed and verified, because the host has no verifier, so the yes is
            // unverified (review 2026-11-24 E-3).
            Ok(sig) => match s.verify(&mech, public, MSG, &sig) {
                Ok(()) => profile.yes(cap, Checked::unverified(), None),
                Err(e) => profile.refused(
                    &mut made.undetermined,
                    cap,
                    token::rv_of(&e),
                    format!("the signature does not verify: {}", ckr(&e)),
                ),
            },
        }
    }
}

/// Writes the `encapsulate.CKK_ML_KEM.<set>` row: yes when the secret from the encapsulation and
/// the secret from the decapsulation are the same.
fn kem_row(made: &mut Made, profile: &mut Draft, set: &str, public: ObjectHandle, private: ObjectHandle) {
    let s = made.session;
    let cap = Capability::Encapsulate { key_type: KeyKind::from("CKK_ML_KEM"), on: On::Item(set.to_owned()) };
    let template = [
        Attribute::Token(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    let mech = Mechanism::MlKem;
    let value = |h: ObjectHandle| match s.get_attributes(h, &[AttributeType::Value]).map(|v| v.into_iter().next()) {
        Ok(Some(Attribute::Value(v))) => Some(v),
        _ => None,
    };
    // A call that the binding or the interface in use cannot make (a 2.40 function list has no
    // C_EncapsulateKey) says nothing about the module, so it produces no row. Only a `CKR_*`
    // value from the module can be a no.
    let from_module = |e: &cryptoki::error::Error| matches!(e, cryptoki::error::Error::Pkcs11(..));
    match s.encapsulate_key(&mech, public, &template) {
        Err(e) if !from_module(&e) => {
            made.undetermined.push(format!("no {cap} row: C_EncapsulateKey cannot be called: {e}"));
        }
        Err(e) => {
            profile.refused(&mut made.undetermined, cap, token::rv_of(&e), format!("C_EncapsulateKey: {}", ckr(&e)));
        }
        Ok((ciphertext, encapsulated)) => match s.decapsulate_key(&mech, private, &template, &ciphertext) {
            Err(e) if !from_module(&e) => {
                made.undetermined.push(format!("no {cap} row: C_DecapsulateKey cannot be called: {e}"));
                let _ = s.destroy_object(encapsulated);
            }
            Err(e) => {
                let why = format!("C_DecapsulateKey: {}", ckr(&e));
                profile.refused(&mut made.undetermined, cap, token::rv_of(&e), why);
                let _ = s.destroy_object(encapsulated);
            }
            Ok(decapsulated) => {
                match (value(encapsulated), value(decapsulated)) {
                    // Both sides ran on this one module, so the yes is unverified (review
                    // 2026-11-24 E-3).
                    (Some(ours), Some(theirs)) if ours == theirs => profile.yes(cap, Checked::unverified(), None),
                    (Some(_), Some(_)) => profile.wrong(cap, "the two sides derive different secrets".into()),
                    _ => made.undetermined.push(format!("no {cap} row: the shared secrets are unreadable")),
                }
                for h in [encapsulated, decapsulated] {
                    let _ = s.destroy_object(h);
                }
            }
        },
    }
}

/// Runs, in order, all the extra probes that need a scratch token with labels.
pub(super) fn probe_extras(made: &mut Made, profile: &mut Draft) {
    probe_attributes(made, profile);
    probe_unmanaged_keys(made, profile);
    probe_pq(made, profile);
}
