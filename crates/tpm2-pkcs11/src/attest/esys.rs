//! The native `TPM2_Certify` attestation path for tpm2-pkcs11 tokens (docs/DESIGN.md §3.7).
//!
//! (For a module that has the `CKM_TPM2_CERTIFY` vendor mechanism see [`super::vendor`]: this is
//! the path for the others, and the one whose checks both share.)
//!
//! tpm2-pkcs11 exposes no attestation through PKCS#11, so cakeys reaches the TPM itself:
//! the object's TPM blobs are read from the module's store, loaded under the token's primary
//! parent, and certified by an Attestation Key (AK) that cakeys provisions in the owner
//! hierarchy. `TPM2_Load` revalidates the private blob's integrity under the parent, and
//! `TPM2_Certify` signs the object's Name — so a store that lies about what it holds cannot
//! produce a matching attestation.
//!
//! Everything the host can check, it checks itself: the attestation is verified with `RustCrypto`
//! against the AK's public key, its Name is recomputed from the store's public blob, and the
//! key material that blob holds (never `TPM2_ReadPublic`'s unauthenticated copy) is
//! cross-checked against the object's SPKI. The qualifying data is a
//! fresh random nonce, so the response proves the object is *currently loaded in that TPM*.

use super::credential;
use super::store::{Parent, Store, TObject};
use cakeys_core::id;
use cakeys_core::{KmError, Result};
use std::convert::TryFrom;

use aes_gcm::aead::{Aead, KeyInit};
use tss_esapi::Context;
use tss_esapi::abstraction::{AsymmetricAlgorithmSelection, ek};
use tss_esapi::attributes::{ObjectAttributes, ObjectAttributesBuilder, SessionAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::{AuthHandle, KeyHandle, PersistentTpmHandle, SessionHandle, TpmHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::dynamic_handles::Persistent;
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::interface_types::structure_tags::AttestationType;
use tss_esapi::structures::{
    Attest, AttestInfo, Auth, Data, Digest, EccPoint, EccScheme, EncryptedSecret, HashScheme, IdObject,
    KeyDerivationFunctionScheme, Name, Nonce, Private, Public, PublicBuffer, PublicBuilder, PublicEccParametersBuilder,
    Signature, SignatureScheme, SymmetricDefinition,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use zeroize::Zeroizing;

/// What a certify run proved, host-verified.
pub(crate) struct Certified {
    /// The attested Name (`nameAlg ‖ H(TPMT_PUBLIC)`), as the commitment hashes it.
    pub name: Vec<u8>,
    /// The attested qualified Name: where the object sits under the AK's hierarchy.
    pub qualified_name: Vec<u8>,
    /// The canonical SPKI of the AK: the anchor the lock pins when no EK certificate verifies.
    pub ak_spki: Vec<u8>,
    /// The signed `objectAttributes`, as the module derives `CKA_LOCAL` and `CKA_EXTRACTABLE`.
    pub local: bool,
    /// The signed `objectAttributes`' `CKA_EXTRACTABLE`.
    pub(crate) extractable: bool,
}

/// Open a context to the same TPM the module talks to.
///
/// # Errors
///
/// `Unavailable` when the TCTI connection cannot be made.
pub(crate) fn context(conf: &tss_esapi::Tcti) -> Result<Context> {
    Context::new(conf.clone()).map_err(|e| KmError::Unavailable(format!("connecting to the TPM: {e}").into()))
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
/// `TPMS_ATTEST`, and the lock would pin it on first use. Only `provision` (set under `lock`)
/// creates one; a read never changes the TPM.
///
/// # Errors
///
/// `Validation` for a malformed handle; `Unavailable` when no key sits there and `provision`
/// is off, when the TPM cannot be asked what sits there, or when creating/evicting one fails;
/// `Conflict` when the object at the handle is not a cakeys Attestation Key.
pub(crate) fn attestation_key(ctx: &mut Context, handle: u32, provision: bool) -> Result<(KeyHandle, Public, Name)> {
    let persistent = PersistentTpmHandle::new(handle)
        .map_err(|e| KmError::Validation(format!("akHandle {handle:#010x}: {e}").into()))?;
    let template = ak_template()?;
    if let Some(tr) = ak_at(handle, ctx.tr_from_tpm_public(TpmHandle::Persistent(persistent)))? {
        // Already provisioned: read the key where it sits. (Evicting a persistent object again
        // would be a no-op that retires the handle.)
        let key = KeyHandle::from(tr);
        let (public, _name, qualified_name) = read_public(ctx, key)?;
        check_ak(&public, &template, handle)?;
        return Ok((key, public, qualified_name));
    }
    if !provision {
        return Err(KmError::Unavailable(
            format!("no Attestation Key at {handle:#010x} on this TPM; `lock` provisions it").into(),
        ));
    }
    let transient = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map_err(|e| {
            KmError::Unavailable(
                format!("creating the Attestation Key in the owner hierarchy (is owner auth empty?): {e}").into(),
            )
        })?
        .key_handle;
    // The persistent copy is the key from now on; the transient one is flushed either way.
    let persisted = flushing(ctx, transient, |ctx| {
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.evict_control(Provision::Owner, transient.into(), Persistent::Persistent(persistent))
        })
        .map_err(|e| {
            KmError::Unavailable(
                format!("making the Attestation Key persistent at {handle:#010x} (is the handle free?): {e}").into(),
            )
        })
    })?;
    let key = KeyHandle::from(persisted);
    read_public(ctx, key).map(|(public, _name, qualified_name)| (key, public, qualified_name))
}

/// What `Esys_TR_FromTPMPublic` found at the AK handle: the object, or `None` when the TPM
/// says no object is there (`TPM_RC_HANDLE`). Any other failure (the transport, a TPM in
/// failure mode) is no answer, so it is never taken for an empty handle that `lock` would then
/// provision.
///
/// # Errors
///
/// `Unavailable` for any failure but `TPM_RC_HANDLE`.
fn ak_at<T>(handle: u32, found: tss_esapi::Result<T>) -> Result<Option<T>> {
    use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
    match found {
        Ok(object) => Ok(Some(object)),
        Err(tss_esapi::Error::Tss2Error(rc)) if rc.kind() == Some(Tss2ResponseCodeKind::Handle) => Ok(None),
        Err(e) => Err(KmError::Unavailable(
            format!("reading the Attestation Key's handle {handle:#010x} from the TPM: {e}").into(),
        )),
    }
}

/// The Attestation Key's public area as cakeys provisions it (`unique` left for the TPM). A
/// restricted signing key may sign only TPM-generated structures (`TPM2_Certify` among them),
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
        .map_err(|e| KmError::Validation(format!("AK template: {e}").into()))?;
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .with_decrypt(false)
        .with_restricted(true)
        .build()
        .map_err(|e| KmError::Validation(format!("AK attributes: {e}").into()))?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| KmError::Validation(format!("AK public area: {e}").into()))
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
    Err(KmError::Conflict(
        format!(
            "the object at akHandle {handle:#010x} is not a cakeys Attestation Key (a restricted P-256 \
         ECDSA-SHA256 signing key, fixedTPM, empty policy): an unrestricted key could sign forged \
         attestations; free the handle or set tokens.<t>.akHandle to another"
        )
        .into(),
    ))
}

fn read_public(ctx: &mut Context, key: KeyHandle) -> Result<(Public, Name, Name)> {
    ctx.read_public(key).map_err(|e| KmError::Unavailable(format!("TPM2_ReadPublic: {e}").into()))
}

/// The seal object's auth value: SHA-256(PIN ‖ salt) truncated to 16 bytes, *as the hex string
/// encoding them* — tpm2-pkcs11 authorizes with the ASCII hex text, not the raw digest
/// (utils.c `ssl_util_hash_pass` + `set_esys_auth`).
///
/// It unseals the wrapping key as the PIN does, so the digest is wiped and the hex text is
/// returned in the one buffer `Zeroizing` wipes.
fn seal_auth(pin: &[u8], salt: &str) -> Zeroizing<Vec<u8>> {
    use sha2::Digest;
    use zeroize::Zeroize;
    let mut h = sha2::Sha256::new();
    h.update(pin);
    h.update(salt.as_bytes());
    let mut digest = h.finalize();
    // `into_bytes` keeps the string's buffer: the hex text is never copied.
    let auth = Zeroizing::new(cakeys_core::hex::encode(&digest[..16]).into_bytes());
    digest.as_mut_slice().zeroize();
    auth
}

/// Load the seal object and unseal the token's wrapping key with the user PIN — the same
/// protocol the module runs at login (`token_unseal_wrapping_key`): the sealed payload is the
/// wrapping key *as a hex string*, the AES key is its 32 decoded bytes. Through `auth`: a
/// salted session encrypts the unsealed key on its way back.
///
/// # Errors
///
/// `Unavailable` when the seal object cannot be loaded or the unseal fails (a wrong PIN, in
/// practice); `Conflict` when the unsealed payload is not 32 bytes of hex text.
pub(crate) fn wrapping_key(
    ctx: &mut Context,
    store: &Store,
    pin: &[u8],
    auth: AuthSession,
) -> Result<Zeroizing<Vec<u8>>> {
    let session = auth;
    let auth = Auth::try_from(seal_auth(pin, &store.seal.auth_salt).as_slice())
        .map_err(|e| KmError::Unavailable(format!("seal auth: {e}").into()))?;
    // `TPM2_Load` needs no session beyond the parent's, and `Esys_TR_FromTPMPublic` runs
    // `TPM2_ReadPublic`, which takes none at all: keep both outside the unseal's session.
    let seal = load(ctx, &store.parent, &store.seal.priv_blob, &store.seal.pub_blob, session)?;
    let unsealed = flushing(ctx, seal, |ctx| {
        ctx.tr_set_auth(seal.into(), auth)
            .map_err(|e| KmError::Unavailable(format!("setting the seal auth: {e}").into()))?;
        session_attributes(ctx, session, true)?;
        let unsealed = ctx.execute_with_session(Some(session), |ctx| {
            ctx.unseal(seal.into()).map_err(|e| {
                KmError::Unavailable(
                    format!("TPM2_Unseal of the token's wrapping key (is the user PIN right?): {e}").into(),
                )
            })
        });
        session_attributes(ctx, session, false)?;
        unsealed
    })?;
    let hex = Zeroizing::new(
        String::from_utf8(unsealed.value().to_vec())
            .map_err(|_| KmError::Conflict("the unsealed wrapping key is not hex text".into()))?,
    );
    let key = Zeroizing::new(super::store_hex(&hex)?);
    if key.len() != 32 {
        return Err(KmError::Conflict(format!("token wrapping key is {} bytes, expected 32", key.len()).into()));
    }
    Ok(key)
}

/// The GCM-wrapped object auth (`<iv>:<tag>:<ct>` hex) under the token's wrapping key, as the
/// module's `aes256_gcm_decrypt` reads it. The plaintext is the object's authValue.
///
/// # Errors
///
/// `Conflict` when the value is not `<iv>:<tag>:<ct>` with the right lengths, or does not
/// decrypt under the token's wrapping key.
pub(crate) fn unwrap_objauth(wrapping_key: &[u8], wrapped: &str) -> Result<Zeroizing<Vec<u8>>> {
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

/// `TPM2_Load` a key blob under the token's primary parent, the parent authorized through
/// `auth` (tpm2-pkcs11's default primary has an empty auth value).
fn load(ctx: &mut Context, parent: &Parent, priv_blob: &[u8], pub_blob: &[u8], auth: AuthSession) -> Result<KeyHandle> {
    let parent_tr = ctx
        .tr_from_tpm_public(TpmHandle::Persistent(
            PersistentTpmHandle::new(parent.handle)
                .map_err(|e| KmError::Unavailable(format!("parent handle {:#010x}: {e}", parent.handle).into()))?,
        ))
        .map_err(|e| KmError::Unavailable(format!("loading the token primary {:#010x}: {e}", parent.handle).into()))?;
    let parent_key = KeyHandle::from(parent_tr);
    ctx.tr_set_auth(
        parent_tr,
        Auth::try_from(parent.auth.clone()).map_err(|e| KmError::Unavailable(format!("parent auth: {e}").into()))?,
    )
    .map_err(|e| KmError::Unavailable(format!("setting the parent auth: {e}").into()))?;
    let (private, public) = blobs(priv_blob, pub_blob)?;
    ctx.execute_with_session(Some(auth), |ctx| ctx.load(parent_key, private, public))
        .map_err(|e| KmError::Unavailable(format!("TPM2_Load of the object's blob: {e}").into()))
}

/// The content of one size-prefixed store blob, with the prefix checked.
fn blob_content<'a>(blob: &'a [u8], what: &str) -> Result<&'a [u8]> {
    let truncated = || KmError::Conflict(format!("the store's {what} blob is truncated").into());
    let size = u16::from_be_bytes(*blob.first_chunk::<2>().ok_or_else(truncated)?) as usize;
    blob.get(2..2 + size).ok_or_else(truncated)
}

/// The store's marshaled `TPM2B_PRIVATE` / `TPM2B_PUBLIC` as tss-esapi values: its buffer types
/// carry the content without the size prefix, so the prefix is checked and stripped.
fn blobs(priv_blob: &[u8], pub_blob: &[u8]) -> Result<(Private, Public)> {
    let private = Private::try_from(blob_content(priv_blob, "private")?.to_vec())
        .map_err(|e| KmError::Conflict(format!("the store's private blob: {e}").into()))?;
    Ok((private, unmarshal_public(pub_blob)?))
}

/// Unmarshal a marshaled `TPM2B_PUBLIC` (as the store holds it) into a tss-esapi `Public`.
///
/// # Errors
///
/// `Conflict` when the blob does not unmarshal, or is not a public area tss-esapi accepts.
pub(crate) fn unmarshal_public(pub_blob: &[u8]) -> Result<Public> {
    PublicBuffer::unmarshall(pub_blob)
        .map_err(|e| KmError::Conflict(format!("the store's public blob does not unmarshal: {e}").into()))
        .and_then(|b| {
            Public::try_from(b).map_err(|e| KmError::Conflict(format!("the store's public blob: {e}").into()))
        })
}

/// Certify the loaded `key` with the AK: a fresh random nonce as qualifying data (freshness),
/// the object's authorization through `auth`, the AK's (empty) by password.
///
/// # Errors
///
/// `Unavailable` when the OS RNG, the auth setup or `TPM2_Certify` fails; `Conflict` when the
/// response is not a certify statement for this run's nonce — never another statement or a
/// replay.
pub(crate) fn certify(
    ctx: &mut Context,
    key: KeyHandle,
    key_auth: &[u8],
    ak: KeyHandle,
    auth: AuthSession,
) -> Result<(Attest, Signature)> {
    let mut nonce = vec![0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| KmError::Unavailable(format!("OS RNG: {e}").into()))?;
    ctx.tr_set_auth(
        key.into(),
        Auth::try_from(key_auth.to_vec()).map_err(|e| KmError::Unavailable(format!("object auth: {e}").into()))?,
    )
    .map_err(|e| KmError::Unavailable(format!("setting the object auth: {e}").into()))?;
    let data = Data::try_from(nonce.clone()).map_err(|e| KmError::Unavailable(format!("nonce: {e}").into()))?;
    let (attest, signature) = ctx
        .execute_with_sessions((Some(auth), Some(AuthSession::Password), None), |ctx| {
            ctx.certify(key.into(), ak, data, SignatureScheme::Null)
        })
        .map_err(|e| KmError::Unavailable(format!("TPM2_Certify: {e}").into()))?;
    // A certify statement for this run's nonce — never another statement or a replay.
    if attest.attestation_type() != AttestationType::Certify {
        return Err(KmError::Conflict(
            format!("the attestation is a {:?}, not a certify statement", attest.attestation_type()).into(),
        ));
    }
    if attest.extra_data().value() != nonce {
        return Err(KmError::Conflict("the attestation names other qualifying data than this run's nonce".into()));
    }
    Ok((attest, signature))
}

/// The exact bytes the TPM signed: the `TPMS_ATTEST` re-marshaled. TPM marshaling is canonical
/// and the magic field — which the safe view drops — is part of the signature, so an
/// attestation that did not come from a TPM never verifies.
///
/// # Errors
///
/// `Unavailable` if the attestation cannot be re-marshaled (a TPM2 command error code).
pub(crate) fn attest_bytes(attest: &Attest) -> Result<Vec<u8>> {
    attest.marshall().map_err(|e| KmError::Unavailable(format!("marshaling the attestation: {e}").into()))
}

/// Verify the AK's ECDSA-SHA256 signature over the attestation bytes, on the host: the TPM
/// offers `TPM2_VerifySignature`, but verification must not be the prover's.
///
/// # Errors
///
/// `Unsupported` when the AK signed with something other than ECDSA-SHA256 (another scheme,
/// or ECDSA over another hash); `Conflict` when
/// the signature does not verify against the pinned AK, or a component is too long for P-256.
pub(crate) fn verify_signature(signature: &Signature, ak_spki: &[u8], bytes: &[u8]) -> Result<()> {
    use cakeys_core::sig::{self, Encoding, HashAlg};
    let (r, s) = match signature {
        // The AK's restricted scheme makes the TPM sign with SHA-256; a signature naming another
        // hash would not verify as SHA-256 either, but this says why.
        Signature::EcDsa(ecc) if ecc.hashing_algorithm() != HashingAlgorithm::Sha256 => {
            return Err(KmError::Unsupported(
                format!("the AK signed with ECDSA over {:?}, not ECDSA-SHA256", ecc.hashing_algorithm()).into(),
            ));
        }
        Signature::EcDsa(ecc) => (ecc.signature_r().value().to_vec(), ecc.signature_s().value().to_vec()),
        s => return Err(KmError::Unsupported(format!("the AK signed with {s:?}, not ECDSA-SHA256").into())),
    };
    // r and s are minimal big-endian integers: left-pad each to the 32-byte field size. Longer
    // is no P-256 signature (an error, never a panic).
    let mut raw = [0u8; 64];
    for (half, v) in raw.as_chunks_mut::<32>().0.iter_mut().zip([&r, &s]) {
        let at = 32usize.checked_sub(v.len()).ok_or_else(|| {
            KmError::Conflict(format!("the AK's signature has a {}-byte component; P-256 has 32", v.len()).into())
        })?;
        half[at..].copy_from_slice(v);
    }
    match sig::ecdsa(ak_spki, bytes, &raw, Encoding::Raw, Some(HashAlg::Sha256)) {
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
pub(crate) struct Material {
    /// The canonical SPKI; `None` for a secret key.
    pub(crate) spki: Option<Vec<u8>>,
    /// The `objectAttributes` of the public area.
    pub(crate) attributes: ObjectAttributes,
}

/// The canonical SPKI and signed attributes of a public area: what the module's objects can be
/// cross-checked against.
///
/// # Errors
///
/// `Unsupported` for a TPM curve cakeys encodes no SPKI for; `Conflict` when the unique field
/// is not a valid point or RSA key.
pub(crate) fn material_of(public: &Public) -> Result<Material> {
    match public {
        Public::Ecc { object_attributes, parameters, unique, .. } => {
            let curve = match parameters.ecc_curve() {
                EccCurve::NistP256 => id::Curve::P256,
                EccCurve::NistP384 => id::Curve::P384,
                EccCurve::NistP521 => id::Curve::P521,
                c => {
                    return Err(KmError::Unsupported(
                        format!("TPM curve {c:?} (supported: NIST P-256/P-384/P-521)").into(),
                    ));
                }
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
///
/// # Errors
///
/// `Conflict` when the blob is truncated (a size prefix past its end); `Unsupported` for a
/// `nameAlg` that is not SHA-256/384/512.
pub(crate) fn recompute_name(pub_blob: &[u8]) -> Result<Vec<u8>> {
    use sha2::Digest;
    let truncated = || KmError::Conflict("the store's public blob is truncated".into());
    let size = u16::from_be_bytes(*pub_blob.first_chunk::<2>().ok_or_else(truncated)?) as usize;
    let tpmt = pub_blob.get(2..2 + size).ok_or_else(truncated)?;
    let name_alg = u16::from_be_bytes(tpmt.get(2..4).and_then(|s| s.try_into().ok()).ok_or_else(truncated)?);
    let hash = match name_alg {
        0x000B => sha2::Sha256::digest(tpmt).to_vec(),
        0x000C => sha2::Sha384::digest(tpmt).to_vec(),
        0x0010 => sha2::Sha512::digest(tpmt).to_vec(),
        a => return Err(KmError::Unsupported(format!("nameAlg 0x{a:04x} (supported: SHA-256/384/512)").into())),
    };
    let mut name = name_alg.to_be_bytes().to_vec();
    name.extend_from_slice(&hash);
    Ok(name)
}

/// Load, certify, verify and pin one key of the token (§3.7): the store row `tobj` whose
/// PKCS#11 object is being attested. The material SPKI (present exactly for asymmetric keys)
/// is cross-checked against the attestation — the attested key must be the key the object's
/// `rfc7093m4` names. `provision` lets a missing Attestation Key be created (`lock` only).
/// With `ek`, the public key of a verified EK certificate, every authorization of the run goes
/// through a session salted to that EK ([`salted_session`]: the auth values never cross the
/// transport, the unsealed wrapping key crosses it encrypted, and the responses are
/// authenticated), and the AK that signed is then proven to reside in that EK's TPM
/// ([`activate`]). Without one, password sessions, as before.
///
/// # Errors
///
/// `Unavailable` without a PIN to unseal the object's auth value, or when any TPM call
/// fails; `Conflict` when the store row or the attestation disagrees (a Name that is not the
/// blob's, another signer, other material than `spki`) or the activation does; `Unsupported`
/// when the store object has no private blob to certify.
#[expect(
    clippy::too_many_arguments,
    reason = "the store row, its PIN, the AK and what to check it against, all from attest()"
)]
pub(crate) fn certify_key(
    ctx: &mut Context,
    store: &Store,
    tobj: &TObject,
    pin: Option<&[u8]>,
    ak_handle: u32,
    provision: bool,
    spki: Option<&[u8]>,
    ek: Option<&[u8]>,
) -> Result<Certified> {
    let pin = pin.ok_or_else(|| {
        KmError::Unavailable(
            "TPM2_Certify needs the token's user PIN to unseal the object's auth value (pinFile/pinEnv)".into(),
        )
    })?;
    let Some(ek_spki) = ek else {
        return certify_under(ctx, store, tobj, pin, ak_handle, provision, spki, AuthSession::Password)
            .map(|(certified, ..)| certified);
    };
    let ek = endorsement_key(ctx, ek_spki)?;
    flushing(ctx, ek, |ctx| {
        let session = salted_session(ctx, ek)?;
        let out = certify_under(ctx, store, tobj, pin, ak_handle, provision, spki, session).and_then(
            |(certified, ak, ak_public)| {
                // The public area whose key verified the certify is the one the credential is
                // bound to.
                activate(ctx, ak, &ak_public, ek, ek_spki).map(|()| certified)
            },
        );
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        out
    })
}

/// [`certify_key`]'s run, every authorization of the token's objects through `auth`: the AK's
/// handle and public area too, for the activation.
#[expect(clippy::too_many_arguments, reason = "certify_key's arguments, and the session it chose")]
fn certify_under(
    ctx: &mut Context,
    store: &Store,
    tobj: &TObject,
    pin: &[u8],
    ak_handle: u32,
    provision: bool,
    spki: Option<&[u8]>,
    auth: AuthSession,
) -> Result<(Certified, KeyHandle, Public)> {
    let wrapping = wrapping_key(ctx, store, pin, auth)?;
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
    let key = load(ctx, &store.parent, priv_blob, &tobj.pub_blob, auth)?;
    let certified = flushing(ctx, key, |ctx| {
        certify_loaded(ctx, key, &objauth, tobj, auth, (ak, &ak_public, &ak_qualified_name), spki)
    })?;
    Ok((certified, ak, ak_public))
}

/// The certify and its host verification, for the object `key` loaded from `tobj`, authorized
/// through `auth`; `ak` is the AK's handle, public area and qualified Name.
fn certify_loaded(
    ctx: &mut Context,
    key: KeyHandle,
    objauth: &[u8],
    tobj: &TObject,
    auth: AuthSession,
    (ak, ak_public, ak_qualified_name): (KeyHandle, &Public, &Name),
    spki: Option<&[u8]>,
) -> Result<Certified> {
    let live = read_public(ctx, key)?;
    let (attest, signature) = certify(ctx, key, objauth, ak, auth)?;
    verify_certified(&attest, &signature, &tobj.pub_blob, &live, ak_public, ak_qualified_name, spki)
}

/// The host verification of a certify statement: the AK's signature over the exact attestation
/// bytes, the attested Names against both the store's public blob and the loaded object (`live`,
/// what `TPM2_ReadPublic` answered), the signer, and the material cross-check.
///
/// The material and attributes come from `pub_blob`, the bytes whose Name was signed. `live`'s
/// public area is unauthenticated (no session covers `ReadPublic`, and ESYS does not
/// recompute its Name), so it only has to agree: an interposer that answers `ReadPublic` with
/// another key's public area beside the certified object's Name is refused (13).
///
/// # Errors
///
/// `Conflict` when the attestation, its signer, its Names or the material disagree.
fn verify_certified(
    attest: &Attest,
    signature: &Signature,
    pub_blob: &[u8],
    live: &(Public, Name, Name),
    ak_public: &Public,
    ak_qualified_name: &Name,
    spki: Option<&[u8]>,
) -> Result<Certified> {
    let (live_public, live_name, live_qn) = live;
    let certify_info = match attest.attested() {
        AttestInfo::Certify { info } => info,
        info => {
            return Err(KmError::Conflict(format!("the attestation attests {info:?}, not a certify statement").into()));
        }
    };
    let name = certify_info.name().value().to_vec();
    let qualified_name = certify_info.qualified_name().value().to_vec();
    if name != recompute_name(pub_blob)? {
        return Err(KmError::Conflict("the attested Name is not the Name of the public blob in the store".into()));
    }
    if name != live_name.value() || qualified_name != live_qn.value() {
        return Err(KmError::Conflict("the attested Names do not match the loaded object's".into()));
    }
    let ak_material = material_of(ak_public)?;
    let ak_spki =
        ak_material.spki.ok_or_else(|| KmError::Conflict("the Attestation Key exposes no public key".into()))?;
    verify_signature(signature, &ak_spki, &attest_bytes(attest)?)?;
    if attest.qualified_signer().value() != ak_qualified_name.value() {
        return Err(KmError::Conflict("the attestation was signed by another key than the AK".into()));
    }
    // The attested public area is the store blob the signed Name hashes, never ReadPublic's
    // unauthenticated copy: the material cross-check is made on it.
    let attested = unmarshal_public(pub_blob)?;
    if *live_public != attested {
        return Err(KmError::Conflict(
            "TPM2_ReadPublic answered another public area than the one the attested Name hashes".into(),
        ));
    }
    let material = material_of(&attested)?;
    cross_check(&material, spki)?;
    Ok(certified(name, qualified_name, ak_spki, &material))
}

/// The material cross-check (§3.7): the attested public area must be the same key the object's
/// rfc7093m4 hashes — what verifies the identity on any other token. A symmetric PKCS#11 object
/// backed by an asymmetric TPM object (or the reverse) is a different object.
///
/// # Errors
///
/// `Conflict` when the attested material is another key than `spki`, or of another kind.
pub(crate) fn cross_check(material: &Material, spki: Option<&[u8]>) -> Result<()> {
    match (spki, &material.spki) {
        (Some(want), Some(attested)) if want != attested.as_slice() => Err(KmError::Conflict(
            format!(
                "the TPM attests the public key {}, but the object's material is {}",
                id::sri(attested),
                id::sri(want)
            )
            .into(),
        )),
        (Some(_), Some(_)) | (None, None) => Ok(()),
        (want, _) => Err(KmError::Conflict(
            format!(
                "the TPM object is {}, but the PKCS#11 object is {}",
                if material.spki.is_some() { "an asymmetric key" } else { "a symmetric object" },
                if want.is_some() { "an asymmetric key" } else { "a secret key" }
            )
            .into(),
        )),
    }
}

/// What a certify run proved, from the Names it attested and the signed attributes, as the module
/// derives its immutables from them (tpm2-pkcs11: `CKA_LOCAL` = sensitiveDataOrigin,
/// `CKA_EXTRACTABLE` = !(fixedTPM|fixedParent)).
#[must_use]
pub(crate) fn certified(name: Vec<u8>, qualified_name: Vec<u8>, ak_spki: Vec<u8>, material: &Material) -> Certified {
    let attributes = material.attributes;
    Certified {
        name,
        qualified_name,
        ak_spki,
        local: attributes.sensitive_data_origin(),
        extractable: !(attributes.fixed_tpm() || attributes.fixed_parent()),
    }
}

/// The EK certificate the TPM keeps in NV (TCG EK Credential Profile §2.2.1.4): the P-256 one
/// at 0x01c0000a, else the RSA-2048 one at 0x01c00002; `None` when neither index is defined.
/// Only read: cakeys never defines or writes an NV index.
///
/// # Errors
///
/// `Unavailable` when the TPM cannot be asked or an index that exists cannot be read.
pub(crate) fn nv_ek_certificate(ctx: &mut Context) -> Result<Option<Vec<u8>>> {
    use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
    for (alg, index) in [
        (AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256), "0x01c0000a"),
        (AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048), "0x01c00002"),
    ] {
        match ek::retrieve_ek_pubcert(ctx, alg) {
            Ok(der) => return Ok(Some(der)),
            Err(tss_esapi::Error::Tss2Error(rc)) if rc.kind() == Some(Tss2ResponseCodeKind::Handle) => {}
            Err(e) => {
                return Err(KmError::Unavailable(
                    format!("reading the EK certificate at NV index {index}: {e}").into(),
                ));
            }
        }
    }
    Ok(None)
}

/// The TPM's endorsement key, recreated from the TCG default template (empty endorsement auth)
/// for the key of a verified EK certificate, `ek_spki`. Its public area must be that key: ESYS
/// encrypts the session salt ([`salted_session`]) to the public area `CreatePrimary` answered, so
/// one the certificate does not name would salt the session to whoever answered.
///
/// # Errors
///
/// `Unsupported` for an EK that is neither RSA-2048 nor P-256; `Unavailable` when the EK cannot
/// be created (endorsement auth not empty); `Conflict` when its key is not the certificate's.
pub(crate) fn endorsement_key(ctx: &mut Context, ek_spki: &[u8]) -> Result<KeyHandle> {
    let alg = match id::KeyAlg::of_spki(ek_spki) {
        Ok(id::KeyAlg::Rsa) => AsymmetricAlgorithmSelection::Rsa(RsaKeyBits::Rsa2048),
        Ok(id::KeyAlg::Ec(id::Curve::P256)) => AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
        _ => {
            return Err(KmError::Unsupported(
                "an EK certificate for other than the default RSA-2048 or P-256 EK".into(),
            ));
        }
    };
    let template = ek::create_ek_public_from_default_template_2(alg, None)
        .map_err(|e| KmError::Validation(format!("EK template: {e}").into()))?;
    let created = ctx
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.create_primary(Hierarchy::Endorsement, template, None, None, None, None)
        })
        .map_err(|e| {
            KmError::Unavailable(format!("creating the endorsement key (is endorsement auth empty?): {e}").into())
        })?;
    let ek = created.key_handle;
    if material_of(&created.out_public).map(|m| m.spki).ok().flatten().as_deref() != Some(ek_spki) {
        let _ = ctx.flush_context(ek.into());
        return Err(KmError::Conflict("the EK certificate names another key than this TPM's endorsement key".into()));
    }
    Ok(ek)
}

/// An HMAC session salted to the endorsement key `ek` (from [`endorsement_key`], so salted to
/// the certificate's key): only the TPM holding that EK learns the session key. Its
/// authorizations never send an auth value (the PIN-derived seal auth, the object's auth), every
/// response it covers carries an HMAC ESYS checks, and with `encrypt` set (the unseal) the
/// response parameter is encrypted (AES-128-CFB). Flushed by the caller.
///
/// # Errors
///
/// `Unavailable` when the TPM starts no session (it cannot decrypt the salt: another EK).
pub(crate) fn salted_session(ctx: &mut Context, ek: KeyHandle) -> Result<AuthSession> {
    let session = ctx
        .start_auth_session(
            Some(ek),
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| KmError::Unavailable(format!("starting the session salted to the EK: {e}").into()))?
        .ok_or_else(|| KmError::Unavailable("the TPM started no session salted to the EK".into()))?;
    if let Err(e) = session_attributes(ctx, session, false) {
        let _ = ctx.flush_context(SessionHandle::from(session).into());
        return Err(e);
    }
    Ok(session)
}

/// Set `session`'s attributes: continued, and response encryption as `encrypt` says (the unseal
/// takes it; a command with no response parameter to encrypt must not ask). A password session
/// has none to set.
fn session_attributes(ctx: &mut Context, session: AuthSession, encrypt: bool) -> Result<()> {
    if session == AuthSession::Password {
        return Ok(());
    }
    let (attributes, mask) = SessionAttributesBuilder::new().with_continue_session(true).with_encrypt(encrypt).build();
    ctx.tr_sess_set_attributes(session, attributes, mask)
        .map_err(|e| KmError::Unavailable(format!("setting the salted session's attributes: {e}").into()))
}

/// Prove that the AK at `ak` (public area `ak_public`) resides in the TPM whose endorsement key
/// is `ek_spki` (a verified EK certificate's), loaded at `ek` ([`endorsement_key`]): make a
/// credential to it on the host bound to the AK's Name ([`credential::make_credential`]), and
/// have the TPM activate it. Only a TPM holding both that EK and an object of that Name recovers
/// the secret, and an AK that is fixedTPM (as [`check_ak`] requires) never left it.
///
/// # Errors
///
/// `Unavailable` when the TPM cannot be reached; `Conflict` when the TPM refuses or answers the
/// credential wrongly.
pub(crate) fn activate(
    ctx: &mut Context,
    ak: KeyHandle,
    ak_public: &Public,
    ek: KeyHandle,
    ek_spki: &[u8],
) -> Result<()> {
    let ak_tpmt = ak_public.marshall().map_err(|e| KmError::Conflict(format!("the AK's public area: {e}").into()))?;
    let mut secret = Zeroizing::new(vec![0u8; 32]);
    getrandom::fill(&mut secret).map_err(|e| KmError::Unavailable(format!("OS RNG: {e}").into()))?;
    let cred = credential::make_credential(ek_spki, &ak_tpmt, &secret)?;
    let recovered = activate_with_ek(ctx, ak, ek, cred)?;
    if recovered.as_slice() != secret.as_slice() {
        return Err(KmError::Conflict("the TPM activated the credential to another secret".into()));
    }
    Ok(())
}

/// `TPM2_ActivateCredential` with the AK (empty auth) and the EK, whose default policy is
/// `PolicySecret(TPM_RH_ENDORSEMENT)`: a policy session satisfied with the endorsement
/// hierarchy's (empty) auth, flushed whatever happens.
fn activate_with_ek(
    ctx: &mut Context,
    ak: KeyHandle,
    ek: KeyHandle,
    cred: credential::Credential,
) -> Result<Zeroizing<Vec<u8>>> {
    use tss_esapi::constants::response_code::Tss2ResponseCodeKind;
    let unavailable = |what: &str, e: tss_esapi::Error| KmError::Unavailable(format!("{what}: {e}").into());
    let blob = IdObject::try_from(cred.blob).map_err(|e| unavailable("the credential blob", e))?;
    let secret = EncryptedSecret::try_from(cred.secret).map_err(|e| unavailable("the credential's secret", e))?;
    let session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|e| unavailable("starting the EK's policy session", e))?
        .ok_or_else(|| KmError::Unavailable("the TPM started no policy session for the EK".into()))?;
    let out = (|| {
        let policy = PolicySession::try_from(session).map_err(|e| unavailable("the EK's policy session", e))?;
        ctx.execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.policy_secret(
                policy,
                AuthHandle::Endorsement,
                Nonce::default(),
                Digest::default(),
                Nonce::default(),
                None,
            )
        })
        .map_err(|e| unavailable("PolicySecret(endorsement) for the EK (is endorsement auth empty?)", e))?;
        ctx.execute_with_sessions((Some(AuthSession::Password), Some(session), None), |ctx| {
            ctx.activate_credential(ak, ek, blob, secret)
        })
        .map(|digest| Zeroizing::new(digest.value().to_vec()))
        .map_err(|e| match e {
            // The TPM checked the credential and refused it: its HMAC does not hold for the AK's
            // Name, or its seed was not encrypted to this EK.
            tss_esapi::Error::Tss2Error(rc)
                if matches!(
                    rc.kind(),
                    Some(
                        Tss2ResponseCodeKind::Integrity
                            | Tss2ResponseCodeKind::Value
                            | Tss2ResponseCodeKind::Size
                            | Tss2ResponseCodeKind::EccPoint
                    )
                ) =>
            {
                KmError::Conflict(
                    format!("the TPM refused the credential: the AK is not in the TPM the EK certificate names ({e})")
                        .into(),
                )
            }
            e => unavailable("TPM2_ActivateCredential", e),
        })
    })();
    let _ = ctx.flush_context(SessionHandle::from(session).into());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tss_esapi::structures::{EccParameter, EccSignature, PublicKeyRsa, RsaSignature};

    /// A P-256 key's `TPM2B_PUBLIC` from the store fixture (tests/fixtures/tobject-private.yaml).
    const PUB_BLOB: &str = "00560023000b000600720000001000100003001000204fabc9186000e8016add3f0bd535700c7b7cab33c93f6c65271254321d58e4c200207a0468724ee74b1cf1496b782172a37bd56f583e4866963a76640c74a7891e90";

    fn pub_blob() -> Vec<u8> {
        crate::attest::store_hex(PUB_BLOB).unwrap()
    }

    /// The Name is the `nameAlg` and its digest of the public area, for each hash tpm2-pkcs11
    /// may use; any other algorithm and a truncated blob are refused.
    #[test]
    fn names_are_recomputed_by_their_name_alg() {
        let with_alg = |alg: u16| {
            let mut blob = pub_blob();
            blob[4..6].copy_from_slice(&alg.to_be_bytes());
            recompute_name(&blob)
        };
        for (alg, len) in [(0x000B, 32), (0x000C, 48), (0x0010, 64)] {
            let name = with_alg(alg).unwrap();
            assert_eq!((&name[..2], name.len()), (&alg.to_be_bytes()[..], 2 + len), "{alg:#06x}");
        }
        assert!(matches!(with_alg(0x0004), Err(KmError::Unsupported(m)) if m.contains("0x0004")));
        assert!(matches!(recompute_name(&pub_blob()[..40]), Err(KmError::Conflict(_))));
    }

    /// The wrapped object auth is `<iv>:<tag>:<ct>` under the token's wrapping key: it round-trips,
    /// and another shape or another key is refused (13).
    #[test]
    fn object_auth_unwraps_only_in_its_own_shape_and_key() {
        let key = [7u8; 32];
        let iv = [1u8; 12];
        let cipher = aes_gcm::Aes256Gcm::new_from_slice(&key).unwrap();
        let sealed = cipher.encrypt((&iv).into(), b"secret".as_ref()).unwrap();
        let (ct, tag) = sealed.split_at(sealed.len() - 16);
        let hex = |b: &[u8]| b.iter().fold(String::new(), |s, x| s + &format!("{x:02x}"));
        let wrapped = format!("{}:{}:{}", hex(&iv), hex(tag), hex(ct));
        assert_eq!(unwrap_objauth(&key, &wrapped).unwrap().as_slice(), b"secret");
        for bad in ["00", &format!("{wrapped}:00"), &format!("00:{}:{}", hex(tag), hex(ct))] {
            assert!(matches!(unwrap_objauth(&key, bad), Err(KmError::Conflict(m)) if m.contains("<iv>:<tag>:<ct>")));
        }
        assert!(
            matches!(unwrap_objauth(&[8u8; 32], &wrapped), Err(KmError::Conflict(m)) if m.contains("does not decrypt"))
        );
    }

    /// The AK's signature is checked on the host: an ECDSA one that does not verify, one too long
    /// for P-256, an AK that is no EC key, and a signature of another scheme are each refused.
    #[test]
    fn attestation_signatures_are_verified_on_the_host() {
        let ak = material_of(&unmarshal_public(&pub_blob()).unwrap()).unwrap().spki.unwrap();
        let ecdsa = |r: Vec<u8>, s: Vec<u8>| {
            Signature::EcDsa(
                EccSignature::create(
                    HashingAlgorithm::Sha256,
                    EccParameter::try_from(r).unwrap(),
                    EccParameter::try_from(s).unwrap(),
                )
                .unwrap(),
            )
        };
        let forged = verify_signature(&ecdsa(vec![1; 32], vec![1; 32]), &ak, b"attest");
        assert!(matches!(forged, Err(KmError::Conflict(m)) if m.contains("does not verify")));
        let long = verify_signature(&ecdsa(vec![1; 33], vec![1; 32]), &ak, b"attest");
        assert!(matches!(long, Err(KmError::Conflict(m)) if m.contains("33-byte component")));
        let rsa_ak = id::rsa_spki(&[0xc5; 256], &[1, 0, 1]).unwrap();
        let not_ec = verify_signature(&ecdsa(vec![1; 32], vec![1; 32]), &rsa_ak, b"attest");
        assert!(matches!(not_ec, Err(KmError::Conflict(m)) if m.contains("not an ECDSA key")));
        // ECDSA over another hash than the AK's SHA-256: named, not a bare "does not verify".
        let sha384 = Signature::EcDsa(
            EccSignature::create(
                HashingAlgorithm::Sha384,
                EccParameter::try_from(vec![1; 32]).unwrap(),
                EccParameter::try_from(vec![1; 32]).unwrap(),
            )
            .unwrap(),
        );
        let other_hash = verify_signature(&sha384, &ak, b"attest");
        assert!(
            matches!(&other_hash, Err(KmError::Unsupported(m)) if m.contains("Sha384") && m.contains("not ECDSA-SHA256")),
            "{:?}",
            other_hash.err()
        );
        let rsa_sig = RsaSignature::create(HashingAlgorithm::Sha256, PublicKeyRsa::try_from(vec![1; 256]).unwrap());
        let other = verify_signature(&Signature::RsaSsa(rsa_sig.unwrap()), &ak, b"attest");
        assert!(matches!(other, Err(KmError::Unsupported(m)) if m.contains("not ECDSA-SHA256")));
    }

    /// The seal auth is tpm2-pkcs11's: the hex text of SHA-256(PIN ‖ salt)'s first 16 bytes,
    /// held where it is wiped (esys.rs F2). The known answer was computed apart from the code
    /// (`printf 123456abcd | sha256sum`).
    #[test]
    fn the_seal_auth_is_the_modules_and_wiped() {
        let auth: Zeroizing<Vec<u8>> = seal_auth(b"123456", "abcd");
        assert_eq!(auth.as_slice(), b"7eb6640227367c8ff142d877496ca3ec");
    }

    /// Only the TPM's `TPM_RC_HANDLE` means no AK at the handle (`lock` then provisions one);
    /// any other failure of `Esys_TR_FromTPMPublic` is unavailable (16), naming the handle and
    /// the error, never "no AK" (esys.rs F3).
    #[test]
    fn only_tpm_rc_handle_means_no_attestation_key() {
        use tss_esapi::WrapperErrorKind;
        use tss_esapi::constants::response_code::Tss2ResponseCode;
        let tss = |rc: u32| Err::<u8, _>(tss_esapi::Error::Tss2Error(Tss2ResponseCode::from(rc)));
        assert_eq!(ak_at(0x8100_0100, Ok(7u8)).unwrap(), Some(7));
        // TPM_RC_HANDLE + TPM_RC_1: TPM2_ReadPublic's handle names no object.
        assert_eq!(ak_at(0x8100_0100, tss(0x18b)).unwrap(), None);
        // TPM_RC_FAILURE, TPM_RC_RETRY, a TCTI I/O error, and a wrapper error.
        let wrapper = Err(tss_esapi::Error::WrapperError(WrapperErrorKind::InternalError));
        for found in [tss(0x101), tss(0x922), tss(0x000a_000a), wrapper] {
            let e = ak_at(0x8100_0100, found).unwrap_err();
            assert!(matches!(&e, KmError::Unavailable(m) if m.contains("0x81000100")), "{e}");
        }
    }

    /// The fixture's P-256 public blob with its `unique` point replaced by `key`'s.
    fn blob_of(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
        use p256::pkcs8::EncodePublicKey;
        let spki = key.verifying_key().to_public_key_der().unwrap();
        let point = &spki.as_bytes()[spki.as_bytes().len() - 64..];
        let mut blob = pub_blob();
        let n = blob.len();
        // The blob ends `0020 ‖ x ‖ 0020 ‖ y`.
        blob[n - 66..n - 34].copy_from_slice(&point[..32]);
        blob[n - 32..].copy_from_slice(&point[32..]);
        blob
    }

    /// A `TPMS_ATTEST` certifying `name`/`qn`, signed by `ak` as the TPM would.
    fn certify_statement(ak: &p256::ecdsa::SigningKey, ak_qn: &[u8], name: &[u8], qn: &[u8]) -> (Attest, Signature) {
        use p256::ecdsa::signature::Signer;
        let tpm2b = |b: &[u8]| [&u16::try_from(b.len()).unwrap().to_be_bytes()[..], b].concat();
        let bytes = [
            &0xff54_4347u32.to_be_bytes()[..], // TPM_GENERATED_VALUE
            &0x8017u16.to_be_bytes(),          // TPM_ST_ATTEST_CERTIFY
            &tpm2b(ak_qn),
            &tpm2b(&[5; 32]), // extraData: the nonce, checked by `certify`
            &[0; 17],         // clockInfo
            &[0; 8],          // firmwareVersion
            &tpm2b(name),
            &tpm2b(qn),
        ]
        .concat();
        let attest = Attest::unmarshall(&bytes).unwrap();
        let sig: p256::ecdsa::Signature = ak.sign(&attest_bytes(&attest).unwrap());
        let raw = sig.to_bytes();
        let (r, s) = raw.split_at(32);
        let ecc = EccSignature::create(
            HashingAlgorithm::Sha256,
            EccParameter::try_from(r.to_vec()).unwrap(),
            EccParameter::try_from(s.to_vec()).unwrap(),
        );
        (attest, Signature::EcDsa(ecc.unwrap()))
    }

    /// The material and attributes are the store blob's — the bytes the signed Name hashes —
    /// never `TPM2_ReadPublic`'s public area, which nothing authenticates: an interposer that
    /// answers `ReadPublic` with a victim key's public area beside the certified object's Names
    /// is refused, also when the object's SPKI is the victim's (esys.rs F1).
    #[test]
    fn the_material_is_the_attested_blobs_not_read_publics() {
        let ak = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let key = p256::ecdsa::SigningKey::from_slice(&[2; 32]).unwrap();
        let victim = p256::ecdsa::SigningKey::from_slice(&[3; 32]).unwrap();
        let (ak_public, blob, victim_public) =
            (unmarshal_public(&blob_of(&ak)).unwrap(), blob_of(&key), unmarshal_public(&blob_of(&victim)).unwrap());
        let ak_qn = Name::try_from(vec![0x0b; 34]).unwrap();
        let (name, qn) = (recompute_name(&blob).unwrap(), vec![0x0c; 34]);
        let (attest, signature) = certify_statement(&ak, ak_qn.value(), &name, &qn);
        let names = (Name::try_from(name).unwrap(), Name::try_from(qn).unwrap());
        let spki_of = |p: &Public| material_of(p).unwrap().spki.unwrap();
        let (key_spki, victim_spki) = (spki_of(&unmarshal_public(&blob).unwrap()), spki_of(&victim_public));
        let verify = |live: &Public, spki: &[u8]| {
            let live = (live.clone(), names.0.clone(), names.1.clone());
            verify_certified(&attest, &signature, &blob, &live, &ak_public, &ak_qn, Some(spki))
        };
        // An honest ReadPublic: the blob's key passes, with the blob's signed attributes.
        let honest = verify(&unmarshal_public(&blob).unwrap(), &key_spki).unwrap();
        assert_eq!((honest.local, honest.extractable), (true, false));
        // ReadPublic swapped for the victim's public area: refused, whichever SPKI is asked.
        for spki in [&victim_spki, &key_spki] {
            let swapped = verify(&victim_public, spki);
            assert!(matches!(swapped, Err(KmError::Conflict(m)) if m.contains("ReadPublic")), "{spki:?}");
        }
        // The victim's SPKI against the honest blob: the cross-check refuses it.
        let other = verify(&unmarshal_public(&blob).unwrap(), &victim_spki);
        assert!(matches!(other, Err(KmError::Conflict(m)) if m.contains("attests the public key")));
    }
}
