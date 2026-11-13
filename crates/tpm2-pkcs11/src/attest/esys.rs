//! The native TPM2_Certify attestation path for tpm2-pkcs11 tokens (docs/DESIGN.md §3.7).
//!
//! tpm2-pkcs11 exposes no attestation through PKCS#11, so cakeys reaches the TPM itself:
//! the object's TPM blobs are read from the module's store, loaded under the token's primary
//! parent, and certified by an Attestation Key (AK) that cakeys provisions in the owner
//! hierarchy. `TPM2_Load` revalidates the private blob's integrity under the parent, and
//! `TPM2_Certify` signs the object's Name — so a store that lies about what it holds cannot
//! produce a matching attestation.
//!
//! Everything the host can check, it checks itself: the attestation is verified with RustCrypto
//! against the AK's public key, its Name is recomputed from the store's public blob, and the
//! key material it names is cross-checked against the object's SPKI. The qualifying data is a
//! fresh random nonce, so the response proves the object is *currently loaded in that TPM*.

use super::store::{Parent, Store, TObject};
use cakeys_core::id;
use cakeys_core::{KmError, Result};
use std::convert::TryFrom;

use aes_gcm::aead::{Aead, KeyInit};
use tss_esapi::Context;
use tss_esapi::attributes::{ObjectAttributes, ObjectAttributesBuilder};
use tss_esapi::handles::{KeyHandle, PersistentTpmHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::interface_types::structure_tags::AttestationType;
use tss_esapi::structures::{
    Attest, AttestInfo, Auth, Data, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, Name, Private,
    Public, PublicBuilder, PublicEccParametersBuilder, Signature, SignatureScheme,
};
use tss_esapi::tss2_esys as esys;
use zeroize::Zeroizing;

/// What a certify run proved, host-verified.
pub struct Certified {
    /// The attested Name (`nameAlg ‖ H(TPMT_PUBLIC)`), as the commitment hashes it.
    pub name: Vec<u8>,
    /// The attested qualified Name: where the object sits under the AK's hierarchy.
    pub qualified_name: Vec<u8>,
    /// The canonical SPKI of the AK: the anchor the lock pins.
    pub ak_spki: Vec<u8>,
    /// The signed `objectAttributes`, as the module derives CKA_LOCAL and CKA_EXTRACTABLE.
    pub local: bool,
    pub extractable: bool,
}

/// Open a context to the same TPM the module talks to.
pub fn context(conf: &tss_esapi::Tcti) -> Result<Context> {
    Context::new(conf.clone()).map_err(|e| KmError::Unavailable(format!("connecting to the TPM: {e}")))
}

/// Run `f` with the transient object `handle`, then flush it whatever `f` returned. Without a
/// resource manager (`swtpm:`, `device:/dev/tpm0`) a transient object outlives the connection,
/// and the TPM runs out of object slots after a few runs.
fn flushing<T>(ctx: &mut Context, handle: KeyHandle, f: impl FnOnce(&mut Context) -> Result<T>) -> Result<T> {
    let out = f(ctx);
    let _ = ctx.flush_context(handle.into());
    out
}

/// The attestation key: a persistent restricted signing key in the owner hierarchy with empty
/// auth, provisioned by cakeys on first attest and pinned by the realisation's
/// `attestation.root`. Owner auth must be empty (swtpm, and most desktop TPMs). Returns its
/// handle, public area and *qualified name* (the `TPMS_ATTEST.qualifiedSigner` it signs).
///
/// A key already at the handle is used only if it *is* such a key — the public area of cakeys'
/// template, restricted signing, fixedTPM: an unrestricted key there could sign a forged
/// `TPMS_ATTEST`, and the lock would pin it on first use. Only `provision` (set under `realise`)
/// creates one; a read never changes the TPM.
pub fn attestation_key(ctx: &mut Context, handle: u32, provision: bool) -> Result<(KeyHandle, Public, Name)> {
    let persistent =
        PersistentTpmHandle::new(handle).map_err(|e| KmError::Validation(format!("akHandle {handle:#010x}: {e}")))?;
    let template = ak_template()?;
    if let Ok(tr) = ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)) {
        // Already provisioned: read the key where it sits. (Evicting a persistent object again
        // would be a no-op that retires the handle.)
        let key = KeyHandle::from(tr);
        let (public, _name, qualified_name) = read_public(ctx, key)?;
        check_ak(&public, &template, handle)?;
        return Ok((key, public, qualified_name));
    }
    if !provision {
        return Err(KmError::Unavailable(format!(
            "no Attestation Key at {handle:#010x} on this TPM; `realise` provisions it"
        )));
    }
    let transient = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map_err(|e| {
            KmError::Unavailable(format!(
                "creating the Attestation Key in the owner hierarchy (is owner auth empty?): {e}"
            ))
        })?
        .key_handle;
    // The persistent copy is the key from now on; the transient one is flushed either way.
    let persisted = flushing(ctx, transient, |ctx| {
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(Provision::Owner, transient.into(), Persistent::Persistent(persistent))
        })
        .map_err(|e| {
            KmError::Unavailable(format!(
                "making the Attestation Key persistent at {handle:#010x} (is the handle free?): {e}"
            ))
        })
    })?;
    let key = KeyHandle::from(persisted);
    read_public(ctx, key).map(|(public, _name, qualified_name)| (key, public, qualified_name))
}

/// The Attestation Key's public area as cakeys provisions it (`unique` left for the TPM). A
/// restricted signing key may sign only TPM-generated structures (TPM2_Certify among them),
/// never caller-chosen data.
fn ak_template() -> Result<Public> {
    let params = PublicEccParametersBuilder::new()
        .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
        .with_curve(EccCurve::NistP256)
        .with_is_signing_key(true)
        .with_is_decryption_key(false)
        .with_restricted(true)
        .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
        .build()
        .map_err(|e| KmError::Validation(format!("AK template: {e}")))?;
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_restricted(true)
        .build()
        .map_err(|e| KmError::Validation(format!("AK attributes: {e}")))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| KmError::Validation(format!("AK public area: {e}")))
}

/// Whether the key found at the AK handle is one cakeys would have provisioned: everything of
/// the template but `unique` (the key itself) — the attributes (restricted, sign-only,
/// fixedTPM/fixedParent, TPM-generated), the scheme and curve, the name algorithm, no policy.
fn check_ak(public: &Public, template: &Public, handle: u32) -> Result<()> {
    let same = match (public, template) {
        (
            Public::Ecc { object_attributes: a, name_hashing_algorithm: n, auth_policy: p, parameters: q, .. },
            Public::Ecc { object_attributes: ta, name_hashing_algorithm: tn, auth_policy: tp, parameters: tq, .. },
        ) => a == ta && n == tn && p == tp && q == tq,
        _ => false,
    };
    if same {
        return Ok(());
    }
    Err(KmError::Conflict(format!(
        "the object at akHandle {handle:#010x} is not a cakeys Attestation Key (a restricted P-256 \
         ECDSA-SHA256 signing key, fixedTPM, empty policy): an unrestricted key could sign forged \
         attestations; free the handle or set tokens.<t>.akHandle to another"
    )))
}

fn read_public(ctx: &mut Context, key: KeyHandle) -> Result<(Public, Name, Name)> {
    ctx.read_public(key).map_err(|e| KmError::Unavailable(format!("TPM2_ReadPublic: {e}")))
}

/// The seal object's auth value: SHA-256(PIN ‖ salt) truncated to 16 bytes, *as the hex string
/// encoding them* — tpm2-pkcs11 authorizes with the ASCII hex text, not the raw digest
/// (utils.c `ssl_util_hash_pass` + `set_esys_auth`).
fn seal_auth(pin: &[u8], salt: &str) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(pin);
    h.update(salt.as_bytes());
    let digest = &h.finalize()[..16];
    let nibble = |n: u8| if n < 10 { b'0' + n } else { b'a' + n - 10 };
    digest.iter().flat_map(|&b| [nibble(b >> 4), nibble(b & 0xf)]).collect()
}

/// Load the seal object and unseal the token's wrapping key with the user PIN — the same
/// protocol the module runs at login (`token_unseal_wrapping_key`): the sealed payload is the
/// wrapping key *as a hex string*, the AES key is its 32 decoded bytes.
pub fn wrapping_key(ctx: &mut Context, store: &Store, pin: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let auth = Auth::try_from(seal_auth(pin, &store.seal.auth_salt))
        .map_err(|e| KmError::Unavailable(format!("seal auth: {e}")))?;
    // `TPM2_Load` needs no session beyond the parent's (empty-auth password), and
    // `Esys_TR_FromTPMPublic` runs `TPM2_ReadPublic`, which takes none at all: keep both
    // outside the unseal's password session.
    let seal = load(ctx, &store.parent, &store.seal.priv_blob, &store.seal.pub_blob)?;
    let unsealed = flushing(ctx, seal, |ctx| {
        ctx.tr_set_auth(seal.into(), auth).map_err(|e| KmError::Unavailable(format!("setting the seal auth: {e}")))?;
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.unseal(seal.into()).map_err(|e| {
                KmError::Unavailable(format!("TPM2_Unseal of the token's wrapping key (is the user PIN right?): {e}"))
            })
        })
    })?;
    let hex = Zeroizing::new(
        String::from_utf8(unsealed.value().to_vec())
            .map_err(|_| KmError::Conflict("the unsealed wrapping key is not hex text".into()))?,
    );
    let key = Zeroizing::new(super::store_hex(&hex)?);
    if key.len() != 32 {
        return Err(KmError::Conflict(format!("token wrapping key is {} bytes, expected 32", key.len())));
    }
    Ok(key)
}

/// The GCM-wrapped object auth (`<iv>:<tag>:<ct>` hex) under the token's wrapping key, as the
/// module's `aes256_gcm_decrypt` reads it. The plaintext is the object's authValue.
pub fn unwrap_objauth(wrapping_key: &[u8], wrapped: &str) -> Result<Zeroizing<Vec<u8>>> {
    let bad = || KmError::Conflict("CKA_TPM2_OBJAUTH_ENC is not <iv>:<tag>:<ct>".into());
    let mut parts = wrapped.split(':');
    let iv = super::store_hex(parts.next().ok_or_else(bad)?)?;
    let tag = super::store_hex(parts.next().ok_or_else(bad)?)?;
    let ct = super::store_hex(parts.next().ok_or_else(bad)?)?;
    if parts.next().is_some() || iv.len() != 12 || tag.len() != 16 {
        return Err(bad());
    }
    let cipher = aes_gcm::Aes256Gcm::new_from_slice(wrapping_key).map_err(|_| bad())?;
    let mut ct_tag = ct;
    ct_tag.extend_from_slice(&tag);
    let iv: [u8; 12] = iv.as_slice().try_into().map_err(|_| bad())?;
    let nonce: &aes_gcm::Nonce<aes_gcm::aead::consts::U12> = (&iv).into();
    cipher
        .decrypt(nonce, ct_tag.as_ref())
        .map(Zeroizing::new)
        .map_err(|_| KmError::Conflict("the object's authValue does not decrypt under the token wrapping key".into()))
}

/// `TPM2_Load` a key blob under the token's primary parent. The parent's password session is
/// enough: tpm2-pkcs11's default primary has an empty auth value.
fn load(ctx: &mut Context, parent: &Parent, priv_blob: &[u8], pub_blob: &[u8]) -> Result<KeyHandle> {
    let parent_tr = ctx
        .tr_from_tpm_public(TpmHandle::Persistent(
            PersistentTpmHandle::new(parent.handle)
                .map_err(|e| KmError::Unavailable(format!("parent handle {:#010x}: {e}", parent.handle)))?,
        ))
        .map_err(|e| KmError::Unavailable(format!("loading the token primary {:#010x}: {e}", parent.handle)))?;
    let parent_key = KeyHandle::from(parent_tr);
    ctx.tr_set_auth(
        parent_tr,
        Auth::try_from(parent.auth.clone()).map_err(|e| KmError::Unavailable(format!("parent auth: {e}")))?,
    )
    .map_err(|e| KmError::Unavailable(format!("setting the parent auth: {e}")))?;
    let (private, public) = blobs(priv_blob, pub_blob)?;
    ctx.execute_with_session(Some(AuthSession::Password), |ctx| ctx.load(parent_key, private, public))
        .map_err(|e| KmError::Unavailable(format!("TPM2_Load of the object's blob: {e}")))
}

/// The content of one size-prefixed store blob, with the prefix checked.
fn blob_content<'a>(blob: &'a [u8], what: &str) -> Result<&'a [u8]> {
    let truncated = || KmError::Conflict(format!("the store's {what} blob is truncated"));
    let size = u16::from_be_bytes(*blob.first_chunk::<2>().ok_or_else(truncated)?) as usize;
    blob.get(2..2 + size).ok_or_else(truncated)
}

/// The store's marshaled `TPM2B_PRIVATE` / `TPM2B_PUBLIC` as tss-esapi values: its buffer types
/// carry the content without the size prefix, so the prefix is checked and stripped.
fn blobs(priv_blob: &[u8], pub_blob: &[u8]) -> Result<(Private, Public)> {
    let private = Private::try_from(blob_content(priv_blob, "private")?.to_vec())
        .map_err(|e| KmError::Conflict(format!("the store's private blob: {e}")))?;
    Ok((private, unmarshal_public(pub_blob)?))
}

/// Unmarshal a marshaled `TPM2B_PUBLIC` (as the store holds it) into a tss-esapi `Public`.
pub fn unmarshal_public(pub_blob: &[u8]) -> Result<Public> {
    let mut public = esys::TPM2B_PUBLIC::default();
    let mut offset = 0u64;
    let rc = unsafe {
        esys::Tss2_MU_TPM2B_PUBLIC_Unmarshal(pub_blob.as_ptr(), pub_blob.len() as u64, &mut offset, &mut public)
    };
    if rc != 0 {
        return Err(KmError::Conflict(format!("the store's public blob does not unmarshal (rc 0x{rc:x})")));
    }
    Public::try_from(public).map_err(|e| KmError::Conflict(format!("the store's public blob: {e}")))
}

/// Certify the loaded `key` with the AK: a fresh random nonce as qualifying data (freshness),
/// both authorizations by password.
pub fn certify(ctx: &mut Context, key: KeyHandle, key_auth: &[u8], ak: KeyHandle) -> Result<(Attest, Signature)> {
    let mut nonce = vec![0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| KmError::Unavailable(format!("OS RNG: {e}")))?;
    ctx.tr_set_auth(
        key.into(),
        Auth::try_from(key_auth.to_vec()).map_err(|e| KmError::Unavailable(format!("object auth: {e}")))?,
    )
    .map_err(|e| KmError::Unavailable(format!("setting the object auth: {e}")))?;
    let data = Data::try_from(nonce.clone()).map_err(|e| KmError::Unavailable(format!("nonce: {e}")))?;
    let (attest, signature) = ctx
        .execute_with_sessions((Some(AuthSession::Password), Some(AuthSession::Password), None), |ctx| {
            ctx.certify(key.into(), ak, data, SignatureScheme::Null)
        })
        .map_err(|e| KmError::Unavailable(format!("TPM2_Certify: {e}")))?;
    // A certify statement for this run's nonce — never another statement or a replay.
    if attest.attestation_type() != AttestationType::Certify {
        return Err(KmError::Conflict(format!(
            "the attestation is a {:?}, not a certify statement",
            attest.attestation_type()
        )));
    }
    if attest.extra_data().value() != nonce {
        return Err(KmError::Conflict("the attestation names other qualifying data than this run's nonce".into()));
    }
    Ok((attest, signature))
}

/// The exact bytes the TPM signed: the `TPMS_ATTEST` re-marshaled. TPM marshaling is canonical
/// and the magic field — which the safe view drops — is part of the signature, so an
/// attestation that did not come from a TPM never verifies.
pub fn attest_bytes(attest: &Attest) -> Result<Vec<u8>> {
    let ffi = esys::TPMS_ATTEST::from(attest.clone());
    let mut buf = vec![0u8; 4096];
    let mut offset = 0u64;
    let rc = unsafe { esys::Tss2_MU_TPMS_ATTEST_Marshal(&ffi, buf.as_mut_ptr(), buf.len() as u64, &mut offset) };
    if rc != 0 {
        return Err(KmError::Unavailable(format!("marshaling the attestation (rc 0x{rc:x})")));
    }
    buf.truncate(offset as usize);
    Ok(buf)
}

/// Verify the AK's ECDSA-SHA256 signature over the attestation bytes, on the host: the TPM
/// offers `TPM2_VerifySignature`, but verification must not be the prover's.
pub fn verify_signature(signature: &Signature, ak_spki: &[u8], bytes: &[u8]) -> Result<()> {
    use cakeys_core::sig::{self, EcdsaHash, Encoding};
    let (r, s) = match signature {
        Signature::EcDsa(ecc) => (ecc.signature_r().value().to_vec(), ecc.signature_s().value().to_vec()),
        s => return Err(KmError::Unsupported(format!("the AK signed with {s:?}, not ECDSA-SHA256"))),
    };
    // r and s are minimal big-endian integers: left-pad each to the 32-byte field size. Longer
    // is no P-256 signature (an error, never a panic).
    let mut raw = [0u8; 64];
    for (half, v) in raw.as_chunks_mut::<32>().0.iter_mut().zip([&r, &s]) {
        let at = 32usize.checked_sub(v.len()).ok_or_else(|| {
            KmError::Conflict(format!("the AK's signature has a {}-byte component; P-256 has 32", v.len()))
        })?;
        half[at..].copy_from_slice(v);
    }
    match sig::ecdsa(ak_spki, bytes, &raw, Encoding::Raw, Some(EcdsaHash::Sha256)) {
        Some(Ok(())) => Ok(()),
        Some(Err(_)) => {
            Err(KmError::Conflict("the attestation signature does not verify against the pinned AK".into()))
        }
        None => Err(KmError::Conflict("the AK's public key is not an ECDSA key".into())),
    }
}

/// The canonical SPKI of a TPM public area plus the `objectAttributes` it carries (for the
/// cross-check against what the module reports): ECC points from `unique`, RSA modulus and
/// exponent (0 meaning 65537, TPM 2.0 §12.2.3.4).
pub struct Material {
    pub spki: Option<Vec<u8>>,
    pub attributes: ObjectAttributes,
}

pub fn material_of(public: &Public) -> Result<Material> {
    match public {
        Public::Ecc { object_attributes, parameters, unique, .. } => {
            let curve = match parameters.ecc_curve() {
                EccCurve::NistP256 => id::Curve::P256,
                EccCurve::NistP384 => id::Curve::P384,
                EccCurve::NistP521 => id::Curve::P521,
                c => return Err(KmError::Unsupported(format!("TPM curve {c:?} (supported: NIST P-256/P-384/P-521)"))),
            };
            let mut point = vec![0x04];
            point.extend_from_slice(unique.x().value());
            point.extend_from_slice(unique.y().value());
            Ok(Material { spki: Some(curve.spki_from_point(&point)?), attributes: *object_attributes })
        }
        Public::Rsa { object_attributes, parameters, unique, .. } => {
            let exponent = match parameters.exponent().value() {
                0 => vec![1, 0, 1], // 0 means 65537 (TPM 2.0 §12.2.3.4)
                e => e.to_be_bytes().to_vec(),
            };
            Ok(Material { spki: Some(id::rsa_spki(unique.value(), &exponent)?), attributes: *object_attributes })
        }
        // Symmetric and keyed-hash objects expose no public key to cross-check; their identity
        // stays the portable commitment plus the attested Name.
        Public::KeyedHash { object_attributes, .. } | Public::SymCipher { object_attributes, .. } => {
            Ok(Material { spki: None, attributes: *object_attributes })
        }
    }
}

/// Recompute the Name of a public blob on the host — `nameAlg ‖ H(TPMT_PUBLIC)` over the
/// store's own marshaled bytes (the blob content after its size prefix) — independently of
/// both the TPM and tss-esapi's view of it.
pub fn recompute_name(pub_blob: &[u8]) -> Result<Vec<u8>> {
    use sha2::Digest;
    let truncated = || KmError::Conflict("the store's public blob is truncated".into());
    let size = u16::from_be_bytes(*pub_blob.first_chunk::<2>().ok_or_else(truncated)?) as usize;
    let tpmt = pub_blob.get(2..2 + size).ok_or_else(truncated)?;
    let name_alg = u16::from_be_bytes(tpmt.get(2..4).ok_or_else(truncated)?.try_into().unwrap());
    let hash = match name_alg {
        0x000B => sha2::Sha256::digest(tpmt).to_vec(),
        0x000C => sha2::Sha384::digest(tpmt).to_vec(),
        0x0010 => sha2::Sha512::digest(tpmt).to_vec(),
        a => return Err(KmError::Unsupported(format!("nameAlg 0x{a:04x} (supported: SHA-256/384/512)"))),
    };
    let mut name = name_alg.to_be_bytes().to_vec();
    name.extend_from_slice(&hash);
    Ok(name)
}

/// Load, certify, verify and pin one key of the token (§3.7): the store row `tobj` whose
/// PKCS#11 object is being attested. The material SPKI (present exactly for asymmetric keys)
/// is cross-checked against the attestation — the attested key must be the key the object's
/// `rfc7093m4` names. `provision` lets a missing Attestation Key be created (`realise` only).
pub fn certify_key(
    ctx: &mut Context,
    store: &Store,
    tobj: &TObject,
    pin: Option<&[u8]>,
    ak_handle: u32,
    provision: bool,
    spki: Option<&[u8]>,
) -> Result<Certified> {
    let pin = pin.ok_or_else(|| {
        KmError::Unavailable(
            "TPM2_Certify needs the token's user PIN to unseal the object's auth value (pinFile/pinEnv)".into(),
        )
    })?;
    let wrapping = wrapping_key(ctx, store, pin)?;
    let objauth_enc = tobj
        .objauth_enc
        .as_deref()
        .ok_or_else(|| KmError::Conflict("the store object carries no encrypted auth value to unwrap".into()))?;
    let objauth = unwrap_objauth(&wrapping, objauth_enc)?;
    let priv_blob = tobj
        .priv_blob
        .as_deref()
        .ok_or_else(|| KmError::Unsupported("the store object carries no private blob to certify".into()))?;
    // The AK first: it is persistent, so nothing is left to flush if it is missing.
    let (ak, ak_public, ak_qualified_name) = attestation_key(ctx, ak_handle, provision)?;
    let key = load(ctx, &store.parent, priv_blob, &tobj.pub_blob)?;
    flushing(ctx, key, |ctx| certify_loaded(ctx, key, &objauth, tobj, ak, &ak_public, &ak_qualified_name, spki))
}

/// The certify and its host verification, for the object `key` loaded from `tobj`.
#[allow(clippy::too_many_arguments)]
fn certify_loaded(
    ctx: &mut Context,
    key: KeyHandle,
    objauth: &[u8],
    tobj: &TObject,
    ak: KeyHandle,
    ak_public: &Public,
    ak_qualified_name: &Name,
    spki: Option<&[u8]>,
) -> Result<Certified> {
    let (live_public, live_name, live_qn) = read_public(ctx, key)?;
    let (attest, signature) = certify(ctx, key, objauth, ak)?;
    // Host verification: the AK's signature over the exact attestation bytes, the attested
    // Names against both the store's public blob and the loaded object, and the signer.
    let certify_info = match attest.attested() {
        AttestInfo::Certify { info } => info,
        info => return Err(KmError::Conflict(format!("the attestation attests {info:?}, not a certify statement"))),
    };
    let name = certify_info.name().value().to_vec();
    let qualified_name = certify_info.qualified_name().value().to_vec();
    if name != recompute_name(&tobj.pub_blob)? {
        return Err(KmError::Conflict("the attested Name is not the Name of the public blob in the store".into()));
    }
    if name != live_name.value() || qualified_name != live_qn.value() {
        return Err(KmError::Conflict("the attested Names do not match the loaded object's".into()));
    }
    let ak_material = material_of(ak_public)?;
    let ak_spki =
        ak_material.spki.ok_or_else(|| KmError::Conflict("the Attestation Key exposes no public key".into()))?;
    verify_signature(&signature, &ak_spki, &attest_bytes(&attest)?)?;
    if attest.qualified_signer().value() != ak_qualified_name.value() {
        return Err(KmError::Conflict("the attestation was signed by another key than the AK".into()));
    }
    // The material cross-check (§3.7): the attested public area must be the same key the
    // object's rfc7093m4 hashes — what verifies the identity on any other token. A symmetric
    // PKCS#11 object backed by an asymmetric TPM object (or the reverse) is a different object.
    let material = material_of(&live_public)?;
    match (spki, &material.spki) {
        (Some(want), Some(attested)) if want != attested.as_slice() => {
            return Err(KmError::Conflict(format!(
                "the TPM attests the public key {}, but the object's material is {}",
                id::sri(attested),
                id::sri(want)
            )));
        }
        (Some(_), Some(_)) | (None, None) => {}
        (want, _) => {
            return Err(KmError::Conflict(format!(
                "the store object is {}, but the PKCS#11 object is {}",
                if material.spki.is_some() { "an asymmetric key" } else { "a symmetric object" },
                if want.is_some() { "an asymmetric key" } else { "a secret key" }
            )));
        }
    }
    // The signed attributes, as the module derives its immutables from them (tpm2-pkcs11:
    // CKA_LOCAL = sensitiveDataOrigin, CKA_EXTRACTABLE = !(fixedTPM|fixedParent)).
    let attributes = material.attributes;
    Ok(Certified {
        name,
        qualified_name,
        ak_spki,
        local: attributes.sensitive_data_origin(),
        extractable: !(attributes.fixed_tpm() || attributes.fixed_parent()),
    })
}
