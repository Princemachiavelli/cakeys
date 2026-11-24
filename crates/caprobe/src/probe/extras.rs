//! The probes beyond the keys cakeys manages (`docs/CAPROBE_PROFILE_COVERAGE.md`, Parts 3, 6, 7
//! and 8): the attributes the verbs read, ECDH on Montgomery keys, the key types cakeys does not
//! manage (`CKK_DES2`, `CKK_HKDF`), post-quantum generation, signing and encapsulation, and what
//! the module and token claim of themselves. Every key here is a session object the probe
//! destroys itself; each row is the module's answer on the token, never the host's.

use super::{Draft, Made, ck_said, ckr};
use cakeys_pkcs11::token::{self, Token};
use cakeys_profile::{Answer, Capability, KeyKind, MechanismInfo, On};
use cryptoki::error::RvError;
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

/// `C_GetMechanismInfo` of every mechanism the module lists, as claims (`[mechanism-info]`), and
/// what the token reports of itself (`[claims]`): not rows, never compared. The range a module
/// reports for a key generation is then set beside what the generation probes found (`finding`).
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

/// Whether the key sizes a module reports for a secret-key generation hold what the probe
/// generated: a generated length outside `[min, max]` is a finding (kryoptic reports AES lengths
/// it generates beyond).
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

/// A fresh AES key made raw, extractable false, with `extra` in its template (review 2026-11-23
/// D-5: the template left `CKA_EXTRACTABLE` to the module, so the `CKA_NEVER_EXTRACTABLE` row
/// could not be no on a module that defaults to extractable).
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

/// `attr.read.*` and `attr.set.*` on a generated AES key: whether the module returns the
/// provenance attributes the verbs read (`CKA_LOCAL`, `CKA_ALWAYS_SENSITIVE`,
/// `CKA_NEVER_EXTRACTABLE`, `CKA_KEY_GEN_MECHANISM`) truthfully, and takes
/// `CKA_ALLOWED_MECHANISMS` (`via = "enforced"` when a mechanism outside the list is then
/// refused). A module that cannot generate AES leaves these to `[untested]`'s neighbours: no row.
pub(super) fn probe_attributes(made: &mut Made, profile: &mut Draft) {
    let s = made.session;
    let aes = KeyKind::Aes;
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
    let attrs = read.unwrap_or_default();
    let get = |t: AttributeType| attrs.iter().find(|a| a.attribute_type() == t);
    let row = |attr: &str, answer: Option<(bool, String)>, profile: &mut Draft| {
        let cap = Capability::Attr { read: true, attr: attr.into(), key_type: aes.clone() };
        match answer {
            Some((true, _)) => profile.set(cap, Answer::Yes, None, None),
            Some((false, why)) => profile.set(cap, Answer::No, Some(why), None),
            None => profile.set(cap, Answer::No, Some("the module does not return it".into()), None),
        }
    };
    row(
        "CKA_LOCAL",
        get(AttributeType::Local)
            .map(|a| (matches!(a, Attribute::Local(true)), format!("a generated key reads {a:?}"))),
        profile,
    );
    row(
        "CKA_ALWAYS_SENSITIVE",
        get(AttributeType::AlwaysSensitive)
            .map(|a| (matches!(a, Attribute::AlwaysSensitive(true)), format!("a key made sensitive reads {a:?}"))),
        profile,
    );
    row(
        "CKA_NEVER_EXTRACTABLE",
        get(AttributeType::NeverExtractable).map(|a| {
            // Truthful: a key that is not extractable now, and never was, reads true.
            let extractable = matches!(get(AttributeType::Extractable), Some(Attribute::Extractable(true)));
            (
                extractable || matches!(a, Attribute::NeverExtractable(true)),
                format!("a key never extractable reads {a:?}"),
            )
        }),
        profile,
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
    );
    let _ = s.destroy_object(key);
    // `CKA_ALLOWED_MECHANISMS`: taken, read back, and kept to.
    let cap = Capability::Attr { read: false, attr: "CKA_ALLOWED_MECHANISMS".into(), key_type: aes };
    let allowed = [Attribute::Encrypt(true), Attribute::AllowedMechanisms(vec![MechanismType::AES_ECB])];
    match s.generate_key(
        &Mechanism::AesKeyGen,
        &[&[Attribute::Token(false), Attribute::ValueLen(32.into())][..], &allowed].concat(),
    ) {
        Err(e) => profile.set(cap, Answer::No, Some(ckr(&e)), None),
        Ok(h) => {
            let back = s.get_attributes(h, &[AttributeType::AllowedMechanisms]).ok().and_then(|v| v.into_iter().next());
            let kept = matches!(&back, Some(Attribute::AllowedMechanisms(m)) if m == &vec![MechanismType::AES_ECB]);
            if kept {
                // Outside the list, CBC must be refused if the module enforces it; only a key that
                // encrypts by what the list allows (ECB), on a module that has CBC, tells a
                // refusal of the list from one of the key or the mechanism (review 2026-11-23 D-5).
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
                profile.set(cap, Answer::Yes, None, via.map(Into::into));
            } else {
                profile.set(cap, Answer::No, Some(format!("it reads back {back:?}")), None);
            }
            let _ = s.destroy_object(h);
        }
    }
}

/// `generate.CKK_DES2.16` and `generate.CKK_HKDF.32`: the key types cakeys does not manage,
/// generated raw with their own mechanisms where the module lists them, through the same row
/// the secret sweep writes.
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
            Err(e) => {
                row.cannot_bytes.push(bytes);
                profile.generation_evidence(&kind, On::Bytes(bytes), format!("valueLen = {bytes}: {}", ckr(&e)));
            }
        }
        profile.generate.insert(kind, row);
    }
}

/// The raw point of a public EC key as `C_DeriveKey` takes it: the value of its DER octet
/// string when the module wraps it.
fn raw_point(p: &[u8]) -> Vec<u8> {
    match p {
        [0x04, n, rest @ ..] if usize::from(*n) == rest.len() => rest.to_vec(),
        _ => p.to_vec(),
    }
}

/// `derive.ecdh.CKK_EC_MONTGOMERY.<curve>`: ECDH of two key pairs of the curve on the token, each
/// private key with the other's public point, into readable secrets that must be equal. Called
/// with the first pair the curve generated; the second is made here.
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
            (Ok(x), Ok(y)) if x == y => profile.set(cap, Answer::Yes, None, None),
            (Ok(_), Ok(_)) => profile.set(cap, Answer::No, Some("the two sides derive different secrets".into()), None),
            (Err(e), _) | (_, Err(e)) if token::rv_is(e.rv(), RvError::OperationActive) => {
                made.undetermined.push(format!("no {cap} row: an earlier operation left the session busy"));
            }
            (Err(e), _) | (_, Err(e)) if e.rv().is_some() => profile.set(cap, Answer::No, Some(e.to_string()), None),
            (Err(e), _) | (_, Err(e)) => made.undetermined.push(format!("no {cap} row: {e}")),
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

/// The signing mechanisms of a PQ key type: the pure one and each hashed variant, as the token
/// is asked for them, by `CKM_*` name.
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

/// Post-quantum keys: `generate.<type>.<parameter set>` per set, then on the first key pair that
/// generated `sign.<mechanism>.<type>.<set>` (signed and verified on the token) per signing
/// mechanism the module lists, and `encapsulate.CKK_ML_KEM.<set>` (encapsulated, decapsulated,
/// the two secrets compared as readable keys). Only types whose key-pair mechanism the module
/// lists are tried.
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
                Err(e) => {
                    row.cannot.push(name.clone());
                    profile.generation_evidence(
                        &kind,
                        On::Item(name.clone()),
                        format!("generation refused: {}", ckr(&e)),
                    );
                }
            }
        }
        profile.generate.insert(kind, row);
    }
}

/// `sign.<mechanism>.<type>.<set>` for each signing mechanism the module lists.
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
            Err(e) => profile.set(cap, Answer::No, Some(ckr(&e)), None),
            Ok(sig) => match s.verify(&mech, public, MSG, &sig) {
                Ok(()) => profile.set(cap, Answer::Yes, None, None),
                Err(e) => {
                    profile.set(cap, Answer::No, Some(format!("the signature does not verify: {}", ckr(&e))), None);
                }
            },
        }
    }
}

/// `encapsulate.CKK_ML_KEM.<set>`: the secret both sides derive is the same.
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
    // A call the binding or the interface in use cannot make (a 2.40 function list has no
    // C_EncapsulateKey) says nothing of the module: no row, only the module's `CKR_*` is a no.
    let from_module = |e: &cryptoki::error::Error| matches!(e, cryptoki::error::Error::Pkcs11(..));
    match s.encapsulate_key(&mech, public, &template) {
        Err(e) if !from_module(&e) => {
            made.undetermined.push(format!("no {cap} row: C_EncapsulateKey cannot be called: {e}"));
        }
        Err(e) => profile.set(cap, Answer::No, Some(format!("C_EncapsulateKey: {}", ckr(&e))), None),
        Ok((ciphertext, encapsulated)) => match s.decapsulate_key(&mech, private, &template, &ciphertext) {
            Err(e) if !from_module(&e) => {
                made.undetermined.push(format!("no {cap} row: C_DecapsulateKey cannot be called: {e}"));
                let _ = s.destroy_object(encapsulated);
            }
            Err(e) => {
                profile.set(cap, Answer::No, Some(format!("C_DecapsulateKey: {}", ckr(&e))), None);
                let _ = s.destroy_object(encapsulated);
            }
            Ok(decapsulated) => {
                match (value(encapsulated), value(decapsulated)) {
                    (Some(ours), Some(theirs)) if ours == theirs => profile.set(cap, Answer::Yes, None, None),
                    (Some(_), Some(_)) => {
                        profile.set(cap, Answer::No, Some("the two sides derive different secrets".into()), None);
                    }
                    _ => made.undetermined.push(format!("no {cap} row: the shared secrets are unreadable")),
                }
                for h in [encapsulated, decapsulated] {
                    let _ = s.destroy_object(h);
                }
            }
        },
    }
}

/// All of the labels-target extras, in order.
pub(super) fn probe_extras(made: &mut Made, profile: &mut Draft) {
    probe_attributes(made, profile);
    probe_unmanaged_keys(made, profile);
    probe_pq(made, profile);
}
