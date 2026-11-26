//! The secret-key operation probes (`docs/archive/CAPROBE_PROFILE_COVERAGE.md`, Parts 1, 4 and 5): the
//! commitments cakeys computes (`commit.*`), the symmetric modes (`crypt.*`) and the key
//! derivations (`derive.CKM_*.*`). Each writes a row, yes or no, per key type it tried; a
//! mechanism the module does not list is not tried, and so is left to `[untested]`.

use super::{Checked, Draft, Made, ck_said, evidence, refused, spec};
use cakeys_core::config::ObjectCfg;
use cakeys_core::id::{BlockCipher, Commit, HmacHash};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{Msg, Result};
use cakeys_pkcs11::token;
use cakeys_profile::{Capability, KeyKind};
use cryptoki::error::RvError;
use cryptoki::mechanism::aead::GcmParams;
use cryptoki::mechanism::aes_ctr::AesCtrParams;
use cryptoki::mechanism::ekdf::AesCbcDeriveParams;
use cryptoki::mechanism::hkdf::{HkdfParams, HkdfSalt};
use cryptoki::mechanism::misc::{ExtractParams, KeyDerivationStringData};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::Session;
use sha2::{Digest, Sha256};

/// The label every commitment probe computes over.
const COMMIT_LABEL: &str = "cakeys probe: commitment";

/// The commitments each secret key type offers, as the verbs compute them (`Commit`): a
/// generic secret under each hash (the verbs use SHA-256; the others measure the mechanisms),
/// each hash-bound type under its own, AES four ways, Triple DES by its check value.
fn commit_plan() -> Vec<(Kt, Vec<Commit>)> {
    let hashes = [HmacHash::Sha1, HmacHash::Sha224, HmacHash::Sha256, HmacHash::Sha384, HmacHash::Sha512];
    let mut plan = vec![(Kt::GenericSecret, hashes.map(Commit::Hmac).to_vec())];
    for (kt, hash) in [
        (Kt::Sha1Hmac, HmacHash::Sha1),
        (Kt::Sha224Hmac, HmacHash::Sha224),
        (Kt::Sha256Hmac, HmacHash::Sha256),
        (Kt::Sha384Hmac, HmacHash::Sha384),
        (Kt::Sha512Hmac, HmacHash::Sha512),
    ] {
        plan.push((kt, vec![Commit::Hmac(hash)]));
    }
    plan.push((
        Kt::Aes,
        vec![Commit::Cmac, Commit::KcvEcb(BlockCipher::Aes), Commit::KcvEcbDecrypt(BlockCipher::Aes), Commit::Kw],
    ));
    plan.push((Kt::Des3, vec![Commit::KcvEcb(BlockCipher::Des3), Commit::KcvEcbDecrypt(BlockCipher::Des3)]));
    plan
}

/// The key lengths, in bytes, a commitment is tried at: the three AES defines, Triple DES's
/// fixed 24, and three across the free range. Only those the module generated.
fn commit_lengths(kt: Kt) -> &'static [u32] {
    match kt {
        Kt::Aes => &[16, 24, 32],
        Kt::Des3 => &[24],
        _ => &[16, 32, 64],
    }
}

/// `kt` at `bytes` as keys.toml would declare it (Triple DES's length is its type's).
pub(super) fn secret_object(kt: Kt, bytes: u32) -> ObjectCfg {
    ObjectCfg { value_len: (kt != Kt::Des3).then(|| bytes.into()), ..ObjectCfg::new(Class::SecretKey, Some(kt)) }
}

/// The lengths of `kt` the module generated (what the secret sweep recorded).
fn generated(profile: &Draft, kt: Kt) -> Vec<u32> {
    profile.generate.get(&KeyKind::from(kt.name())).map(|r| r.can_bytes.clone()).unwrap_or_default()
}

/// A refusal's row, as [`Draft::refused`] classes it: the module's `CKR_*` is the answer, no;
/// anything else says nothing of the module.
fn refusal_row(made: &mut Made, profile: &mut Draft, cap: Capability, e: &cakeys_core::KmError, what: &str) {
    profile.refused(&mut made.undetermined, cap, e.rv(), format!("{what}: {}", evidence(made.tok, e)));
}

/// `commit.<kind>.<key type>.<bytes>`: each commitment the module lists, on a key made with the
/// usage it needs, computed by the verbs' own `Token::commit` twice (a constant or random answer
/// is no commitment) and, at the first length, on a second key (another key must give another
/// value).
pub(super) fn probe_commits(made: &mut Made, profile: &mut Draft) -> Result<()> {
    for (kt, commits) in commit_plan() {
        let lengths: Vec<u32> = generated(profile, kt);
        for c in commits {
            if !made.tok.lists(token::commit_mechanism(c)) {
                continue;
            }
            let mut distinct = true;
            for &bytes in commit_lengths(kt).iter().filter(|b| lengths.contains(b)) {
                commit_row(made, profile, kt, c, bytes, distinct)?;
                distinct = false;
            }
        }
    }
    // No `CKM_DES3_CMAC`: cryptoki names no 0x138, neither to call nor in the module's list
    // (review 2026-11-23 D-10, docs/OPEN.md).
    Ok(())
}

fn commit_row(made: &mut Made, profile: &mut Draft, kt: Kt, c: Commit, bytes: u32, distinct: bool) -> Result<()> {
    let cap = Capability::Commit { kind: c.profile_kind().to_owned(), key_type: KeyKind::from(kt.name()), bytes };
    let object = secret_object(kt, bytes);
    let usage = spec(&[c.usage()], &[]);
    let key = match made.create_secret(&object, &usage)? {
        Ok(h) => h,
        Err(e) => {
            refusal_row(made, profile, cap, &e, &format!("a key with {} is refused", c.usage()));
            return Ok(());
        }
    };
    let first = match made.tok.commit(key, &object, c, COMMIT_LABEL) {
        Ok(v) => v,
        Err(e) => {
            refusal_row(made, profile, cap, &e, "the commitment");
            return Ok(());
        }
    };
    let again = match made.tok.commit(key, &object, c, COMMIT_LABEL) {
        Ok(v) => v,
        Err(e) => {
            refusal_row(made, profile, cap, &e, "the commitment, again");
            return Ok(());
        }
    };
    if again != first {
        profile.wrong(cap, "the same key does not give the same commitment twice".into());
        return Ok(());
    }
    if distinct {
        let other = match made.create_secret(&object, &usage)? {
            Ok(h) => h,
            Err(e) => {
                made.undetermined.push(format!("no distinctness check of {cap}: {}", refused(made.tok, &e)));
                profile.yes(cap, Checked::unverified(), None);
                return Ok(());
            }
        };
        if made.tok.commit(other, &object, c, COMMIT_LABEL).ok().as_ref() == Some(&first) {
            profile.wrong(cap, "another key gives the same commitment".into());
            return Ok(());
        }
    }
    // Stable and distinct, but never compared with a value the host computed (review
    // 2026-11-24 E-3): the module's word.
    profile.yes(cap, Checked::unverified(), None);
    Ok(())
}

/// One encrypt then decrypt with `m`: the plaintext comes back, and the ciphertext is not it.
fn round_trip(s: &Session, key: ObjectHandle, m: &Mechanism, plain: &[u8]) -> std::result::Result<(), Msg> {
    let cipher = s.encrypt(m, key, plain).map_err(|e| ck_said("C_Encrypt", &e))?;
    if cipher == plain {
        return Err(Msg::from("the ciphertext is the plaintext"));
    }
    let back = s.decrypt(m, key, &cipher).map_err(|e| ck_said("C_Decrypt", &e))?;
    if back == plain { Ok(()) } else { Err(Msg::from("decrypting does not give the plaintext back")) }
}

/// `crypt.<mechanism>.<key type>.<bytes>`: AES CBC, CBC with padding, CTR and GCM on a 32-byte
/// key, and Triple DES CBC and CBC with padding, each a round trip on the token. A mode the
/// module refuses with a `CKR_*` is a no; one it does not list is not tried.
pub(super) fn probe_modes(made: &mut Made, profile: &mut Draft) -> Result<()> {
    let iv16 = [7u8; 16];
    let iv8 = [7u8; 8];
    let mut gcm_iv = [9u8; 12];
    let mut modes: Vec<(Kt, u32, Variants, usize)> = vec![
        (Kt::Aes, 32, fixed(Mechanism::AesCbc(iv16)), 32),
        (Kt::Aes, 32, fixed(Mechanism::AesCbcPad(iv16)), 21),
        (Kt::Des3, 24, fixed(Mechanism::Des3Cbc(iv8)), 16),
        (Kt::Des3, 24, fixed(Mechanism::Des3CbcPad(iv8)), 13),
    ];
    let ctr = ctr_variants(iv16);
    if !ctr.is_empty() {
        modes.push((Kt::Aes, 32, ctr, 21));
    }
    if let Ok(gcm) = GcmParams::new(&mut gcm_iv, &[1, 2, 3], 128.into()) {
        modes.push((Kt::Aes, 32, fixed(Mechanism::AesGcm(gcm)), 21));
    }
    let plain: Vec<u8> = (0u8..64).collect();
    for kt in [Kt::Aes, Kt::Des3] {
        let Some(bytes) = modes.iter().find(|m| m.0 == kt).map(|m| m.1) else { continue };
        if !generated(profile, kt).contains(&bytes)
            || !modes.iter().any(|m| m.0 == kt && made.tok.lists(m.2[0].0.mechanism_type()))
        {
            continue;
        }
        let object = secret_object(kt, bytes);
        let key = match made.create_secret(&object, &spec(&["CKA_ENCRYPT", "CKA_DECRYPT"], &[]))? {
            Ok(h) => h,
            Err(e) => {
                made.undetermined.push(format!(
                    "no crypt rows on {kt}: a key that encrypts and decrypts: {}",
                    refused(made.tok, &e)
                ));
                continue;
            }
        };
        for (_, _, variants, len) in modes.iter().filter(|m| m.0 == kt) {
            if !made.tok.lists(variants[0].0.mechanism_type()) {
                continue;
            }
            crypt_row(made, profile, key, &KeyKind::from(kt.name()), bytes, variants, &plain[..*len]);
        }
    }
    Ok(())
}

/// One mechanism with the parameter choices to try, in order, each with the words naming it (empty
/// for a mechanism whose parameters are fixed): a module that answers `CKR_MECHANISM_PARAM_INVALID`
/// to one choice may take another, and that refusal is about the call, not the mechanism.
type Variants<'a> = Vec<(Mechanism<'a>, String)>;

/// A mechanism with one fixed parameter choice.
fn fixed(m: Mechanism<'_>) -> Variants<'_> {
    vec![(m, String::new())]
}

/// AES CTR with a 32-bit counter, then with the whole block as the counter: Cloud KMS takes only
/// the latter, and a token that takes either answers to the first.
fn ctr_variants<'a>(iv: [u8; 16]) -> Variants<'a> {
    [32u8, 128]
        .into_iter()
        .filter_map(|bits| {
            AesCtrParams::new(bits, iv).ok().map(|p| (Mechanism::AesCtr(p), format!("a {bits}-bit counter")))
        })
        .collect()
}

/// One `crypt.*` row: the first of `variants` the module takes, round-tripped on `key`: yes when
/// the plaintext comes back (on this module alone: unverified, review 2026-11-24 E-3), no with
/// the module's `CKR_*` when it refuses every choice, or the host's word when what came back is
/// wrong. Only `CKR_MECHANISM_PARAM_INVALID` moves on to the next choice, and a yes on any but
/// the first says which one worked. Any other failure is [`Draft::refused`]'s to class.
fn crypt_row(
    made: &mut Made,
    profile: &mut Draft,
    key: ObjectHandle,
    key_type: &KeyKind,
    bytes: u32,
    variants: &Variants<'_>,
    plain: &[u8],
) {
    let Some(mechanism) = variants.first().map(|v| v.0.mechanism_type().to_string()) else { return };
    let cap = Capability::Crypt { mechanism, key_type: key_type.clone(), bytes };
    for (i, (m, label)) in variants.iter().enumerate() {
        match round_trip(made.session, key, m, plain) {
            Ok(()) => {
                if i > 0 {
                    profile.note(
                        cap.to_string(),
                        format!("refused the first parameters tried (CKR_MECHANISM_PARAM_INVALID); works with {label}"),
                    );
                }
                profile.yes(cap, Checked::unverified(), None);
            }
            Err(e) if token::rv_is(e.rv(), RvError::MechanismParamInvalid) && i + 1 < variants.len() => continue,
            // `round_trip`'s own findings carry no return value: the host's check.
            Err(e) if e.rv().is_none() => profile.wrong(cap, e.to_string()),
            Err(e) => profile.refused(&mut made.undetermined, cap, e.rv(), e.to_string()),
        }
        return;
    }
}

/// The modes of a bound AES key (a purpose-bound module's, such as kmsp11's): each of CBC, CBC
/// with padding and CTR the key's binding serves, on the key the module generated for it, the
/// same round trip as the unbound probe. `bytes` is the key's length.
pub(super) fn probe_bound_aes(
    made: &mut Made,
    profile: &mut Draft,
    serves: &[MechanismType],
    bytes: u32,
    key: ObjectHandle,
) {
    let iv = [7u8; 16];
    let mut modes: Vec<(Variants, usize)> =
        vec![(fixed(Mechanism::AesCbc(iv)), 32), (fixed(Mechanism::AesCbcPad(iv)), 21)];
    let ctr = ctr_variants(iv);
    if !ctr.is_empty() {
        modes.push((ctr, 21));
    }
    let plain: Vec<u8> = (0u8..64).collect();
    for (variants, len) in &modes {
        let mt = variants[0].0.mechanism_type();
        if serves.contains(&mt) && made.tok.lists(mt) {
            crypt_row(made, profile, key, &KeyKind::Aes, bytes, variants, &plain[..*len]);
        }
    }
}

/// The base value every derivation starts from.
fn base_value(n: u8) -> Vec<u8> {
    (0..n).map(|i| i.wrapping_mul(29).wrapping_add(7)).collect()
}

/// A readable (not sensitive, extractable) base key of known value: the derivations' input.
fn base_key(s: &Session, key_type: KeyType, value: &[u8]) -> std::result::Result<ObjectHandle, Msg> {
    let mut template = vec![
        Attribute::Token(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(key_type),
        Attribute::Value(value.to_vec()),
        Attribute::Derive(true),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    // Only a block cipher's key encrypts: a HKDF key refuses the attribute.
    if key_type == KeyType::AES {
        template.push(Attribute::Encrypt(true));
    }
    s.create_object(&template).map_err(|e| ck_said("C_CreateObject of the base key", &e))
}

/// Derive with `m` from `base` into a readable generic secret, `len` bytes if given, and read
/// what came out.
fn derived_value(
    s: &Session,
    m: &Mechanism,
    base: ObjectHandle,
    len: Option<u64>,
) -> std::result::Result<Vec<u8>, Msg> {
    let mut template = vec![
        Attribute::Token(false),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    if let Some(n) = len {
        template.push(Attribute::ValueLen(n.into()));
    }
    let h = s.derive_key(m, base, &template).map_err(|e| ck_said("C_DeriveKey", &e))?;
    let value = s.get_attributes(h, &[AttributeType::Value]);
    let _ = s.destroy_object(h);
    match value.map(|v| v.into_iter().next()) {
        Ok(Some(Attribute::Value(v))) => Ok(v),
        Ok(_) => Err(Msg::from("the derived key has no CKA_VALUE")),
        Err(e) => Err(ck_said("reading the derived CKA_VALUE", &e)),
    }
}

/// HMAC-SHA-256 on the host, from the hash alone: HKDF's only primitive here.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let pad = |b: u8| block.iter().map(|x| x ^ b).collect::<Vec<u8>>();
    let inner = Sha256::digest([pad(0x36).as_slice(), msg].concat());
    Sha256::digest([pad(0x5c).as_slice(), inner.as_slice()].concat()).to_vec()
}

/// AES-256 in CBC mode on the host, over whole blocks, from the block cipher alone.
fn aes256_cbc(key: &[u8], iv: [u8; 16], data: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{BlockCipherEncrypt as _, KeyInit as _};
    let cipher = aes::Aes256::new_from_slice(key).ok()?;
    let mut prev = iv;
    let mut out = Vec::new();
    for chunk in data.as_chunks::<16>().0 {
        let mut block = aes::Block::default();
        for (i, b) in block.iter_mut().enumerate() {
            *b = chunk[i] ^ prev[i];
        }
        cipher.encrypt_block(&mut block);
        prev.copy_from_slice(&block);
        out.extend_from_slice(&block);
    }
    Some(out)
}

/// One derivation to try: the mechanism, the type of its base key, the bytes it should give.
struct Derivation<'a> {
    mechanism: Mechanism<'a>,
    base: ObjectHandle,
    /// Length asked of the derived key, where the mechanism does not decide it.
    len: Option<u64>,
    /// What the host computes the derived value to be.
    expected: Vec<u8>,
    key_type: KeyKind,
}

/// `derive.<mechanism>.<key type>`: HKDF, concatenation (base and data, data and base, base and
/// key), XOR with data, extraction of bits, and AES-CBC-encrypt-data, each into a readable secret
/// whose value the host computes on its own and compares. A module that derives something else
/// is a no, as one that refuses.
pub(super) fn probe_kdfs(made: &mut Made, profile: &mut Draft) {
    let s = made.session;
    let base_v = base_value(32);
    let other_v = base_value(16).iter().map(|b| b ^ 0x55).collect::<Vec<u8>>();
    let data = [0xa5u8; 16];
    let (salt, info) = ([0x0bu8; 13], [0xf0u8; 10]);
    let mut keys = Vec::new();
    let mut made_key = |kt: KeyType, v: &[u8], keys: &mut Vec<ObjectHandle>| match base_key(s, kt, v) {
        Ok(h) => {
            keys.push(h);
            Some(h)
        }
        Err(e) => {
            made.undetermined.push(format!("no derive rows on {kt}: {e}"));
            None
        }
    };
    let generic = made_key(KeyType::GENERIC_SECRET, &base_v, &mut keys);
    let second = made_key(KeyType::GENERIC_SECRET, &other_v, &mut keys);
    let aes = made_key(KeyType::AES, &base_v, &mut keys);
    let hkdf_base = made_key(KeyType::HKDF, &base_v, &mut keys).or(generic);
    let generic_kind = KeyKind::from("CKK_GENERIC_SECRET");
    let mut tries: Vec<Derivation> = Vec::new();
    if let Some(base) = generic {
        tries.push(Derivation {
            mechanism: Mechanism::ConcatenateBaseAndData(KeyDerivationStringData::new(&data)),
            base,
            len: None,
            expected: [base_v.as_slice(), &data].concat(),
            key_type: generic_kind.clone(),
        });
        tries.push(Derivation {
            mechanism: Mechanism::ConcatenateDataAndBase(KeyDerivationStringData::new(&data)),
            base,
            len: None,
            expected: [data.as_slice(), &base_v].concat(),
            key_type: generic_kind.clone(),
        });
        tries.push(Derivation {
            mechanism: Mechanism::XorBaseAndData(KeyDerivationStringData::new(&data)),
            base,
            len: None,
            expected: base_v.iter().zip(data.iter().cycle()).map(|(a, b)| a ^ b).take(data.len()).collect(),
            key_type: generic_kind.clone(),
        });
        tries.push(Derivation {
            mechanism: Mechanism::ExtractKeyFromKey(ExtractParams::new(8)),
            base,
            len: Some(16),
            expected: base_v[1..17].to_vec(),
            key_type: generic_kind.clone(),
        });
        if let Some(second) = second {
            tries.push(Derivation {
                mechanism: Mechanism::ConcatenateBaseAndKey(second),
                base,
                len: None,
                expected: [base_v.as_slice(), &other_v].concat(),
                key_type: generic_kind.clone(),
            });
        }
    }
    if let Some(base) = hkdf_base {
        let prk = hmac_sha256(&salt, &base_v);
        let okm = hmac_sha256(&prk, &[info.as_slice(), &[1]].concat());
        tries.push(Derivation {
            mechanism: Mechanism::HkdfDerive(HkdfParams::new(
                MechanismType::SHA256,
                Some(HkdfSalt::Data(&salt)),
                Some(&info),
            )),
            base,
            len: Some(32),
            expected: okm,
            key_type: generic_kind.clone(),
        });
    }
    let cbc_data = [data, data].concat();
    if let Some(base) = aes
        && let Some(expected) = aes256_cbc(&base_v, [3u8; 16], &cbc_data)
    {
        tries.push(Derivation {
            mechanism: Mechanism::AesCbcEncryptData(AesCbcDeriveParams::new([3u8; 16], &cbc_data)),
            base,
            len: Some(32),
            expected,
            key_type: KeyKind::Aes,
        });
    }
    run_derivations(made, profile, &tries);
    for h in keys {
        let _ = s.destroy_object(h);
    }
}

/// Each derivation the module lists, tried: its row is yes when the value is the host's.
fn run_derivations(made: &mut Made, profile: &mut Draft, tries: &[Derivation]) {
    for d in tries {
        let mt = d.mechanism.mechanism_type();
        if !made.tok.lists(mt) {
            continue;
        }
        let cap = Capability::Kdf { mechanism: mt.to_string(), key_type: d.key_type.clone() };
        match derived_value(made.session, &d.mechanism, d.base, d.len) {
            Ok(v) => match Checked::same(&v, &d.expected) {
                Some(checked) => profile.yes(cap, checked, None),
                None => profile.wrong(cap, format!("it derives {} bytes that are not what the host computes", v.len())),
            },
            Err(e) => profile.refused(&mut made.undetermined, cap, e.rv(), e.to_string()),
        }
    }
}
