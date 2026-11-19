//! The `tpm-certify` attestation through tpm2-pkcs11's vendor mechanisms (`src/tpm2-pkcs11-vendor.h`
//! of a module that has `CKM_TPM2_CERTIFY`): the module runs `TPM2_Certify` for the object, so
//! cakeys opens neither its sqlite store nor the token's wrapping key, and needs no TPM handle
//! for the object. The module is no more trusted than on the store path: the statement is the
//! TPM's, checked here against the object's public area and the signer's public key.
//!
//! Two signers. A persistent Attestation Key the caller owns (`akHandle`, the default) is named
//! by its TPM handle (`CKM_TPM2_CERTIFY`); cakeys still reaches the TPM to provision and read it,
//! so the root a lock pinned stays the same. A token object (`akLabel`, `CKM_TPM2_AK_PAIR_GEN`
//! and `CKM_TPM2_CERTIFY_OBJECT`) needs no TCTI at all, and is another key: another root.

use super::{Tpm2Options, esys};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::provider::AttestCtx;
use cryptoki::mechanism::vendor_defined::VendorDefinedMechanism;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use std::ffi::c_ulong;
use tss_esapi::structures::{Attest, AttestInfo, Public, Signature};
use tss_esapi::traits::{Marshall, UnMarshall};

/// `CKA_VENDOR_DEFINED | 0x0F000000 | n` (the module's vendor range, one for attributes and
/// mechanisms).
const VENDOR: c_ulong = 0x8F00_0000;
/// The object's TPM public area, a `TPM2B_PUBLIC`.
const CKA_TPM2_PUB_BLOB: c_ulong = VENDOR | 2;
/// `TPM2_Certify` by a persistent TPM key.
const CKM_TPM2_CERTIFY: c_ulong = VENDOR | 1;
/// An attestation key as an object of the token (`C_GenerateKeyPair`).
const CKM_TPM2_AK_PAIR_GEN: c_ulong = VENDOR | 2;
/// `TPM2_Certify` by an attestation key of the token.
const CKM_TPM2_CERTIFY_OBJECT: c_ulong = VENDOR | 3;

/// The parameter of both certify mechanisms: `CK_TPM2_CERTIFY_PARAMS` (the signer's persistent
/// TPM handle) and `CK_TPM2_CERTIFY_OBJECT_PARAMS` (the signer's object handle) are one `CK_ULONG`.
#[repr(C)]
struct Signer(c_ulong);

/// DER of the curve OID of NIST P-256, as `CKA_EC_PARAMS`: the one curve `esys::verify_signature`
/// verifies (ECDSA-SHA256).
const P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

fn mechanism_type(n: c_ulong) -> Result<MechanismType> {
    MechanismType::new_vendor_defined(n).map_err(|e| KmError::Unavailable(format!("mechanism {n:#x}: {e}").into()))
}

/// Whether the module has the vendor mechanism `n` (`C_GetMechanismInfo`: an unpatched cryptoki
/// cannot name it, so it is not in the list `C_GetMechanismList` returns to cakeys).
fn lists(ctx: &AttestCtx<'_>, n: c_ulong) -> bool {
    mechanism_type(n).is_ok_and(|m| (ctx.has_mechanism)(m))
}

/// Whether the module attests, and how.
pub(crate) enum Route {
    /// Through its vendor mechanisms (this module).
    Module,
    /// The module has none: its sqlite store and the TPM (`esys`).
    Store,
}

/// The way to attest through this module: its vendor mechanisms where it lists them, else the
/// store. A module that lists the mechanisms is never read around them: a failure of its own is
/// an error, not a reason to open the store.
///
/// # Errors
///
/// `Unsupported` for `akLabel` on a module without the token-key mechanisms: a persistent
/// signer cannot be a token object, so there is no other way to do what was asked.
pub(crate) fn route(ctx: &AttestCtx<'_>, opts: &Tpm2Options) -> Result<Route> {
    if opts.ak_label.is_some() {
        return if lists(ctx, CKM_TPM2_AK_PAIR_GEN) && lists(ctx, CKM_TPM2_CERTIFY_OBJECT) {
            Ok(Route::Module)
        } else {
            Err(KmError::Unsupported(
                format!(
                    "tokens.{}.options.akLabel needs a tpm2-pkcs11 that lists CKM_TPM2_AK_PAIR_GEN and \
                     CKM_TPM2_CERTIFY_OBJECT; this module ({}) does not",
                    ctx.token_name, ctx.module_version
                )
                .into(),
            ))
        };
    }
    Ok(if lists(ctx, CKM_TPM2_CERTIFY) { Route::Module } else { Route::Store })
}

/// The module's statement, parsed: the attested bytes (what the signature covers) and its
/// signature.
#[derive(Debug)]
pub struct Output {
    /// The `TPMS_ATTEST` the TPM signed, as the module returned it.
    pub attest_bytes: Vec<u8>,
    /// The same, parsed.
    pub attest: Attest,
    /// The signature over `attest_bytes`.
    pub signature: Signature,
}

/// Parse what `CKM_TPM2_CERTIFY` returns: a `TPM2B_ATTEST` followed by a `TPMT_SIGNATURE`, each as
/// the TPM marshals it and with nothing after.
///
/// # Errors
///
/// `Conflict` for anything else: truncated, another magic, a trailing byte, or a structure that
/// does not marshal back to the bytes it was read from.
pub fn parse_output(bytes: &[u8]) -> Result<Output> {
    let bad = |why: &str| KmError::Conflict(format!("the module's certify output {why}").into());
    let size = usize::from(u16::from_be_bytes(*bytes.first_chunk::<2>().ok_or_else(|| bad("is empty"))?));
    let attest_bytes = bytes.get(2..2 + size).ok_or_else(|| bad("is cut short in the attestation"))?;
    let rest = &bytes[2 + size..];
    // `Attest` checks the TPM2_GENERATED magic. Neither parse rejects trailing bytes, so each
    // structure must marshal back to exactly what it was read from.
    let attest = Attest::unmarshall(attest_bytes).map_err(|e| bad(&format!("has no attestation: {e}")))?;
    if attest.marshall().ok().as_deref() != Some(attest_bytes) {
        return Err(bad("has an attestation that is not canonical"));
    }
    let signature = Signature::unmarshall(rest).map_err(|e| bad(&format!("has no signature: {e}")))?;
    if signature.marshall().ok().as_deref() != Some(rest) {
        return Err(bad("has a signature that is not canonical, or bytes after it"));
    }
    Ok(Output { attest_bytes: attest_bytes.to_vec(), attest, signature })
}

/// `CKA_TPM2_PUB_BLOB` of `object`.
fn pub_blob(ctx: &AttestCtx<'_>, object: ObjectHandle) -> Result<Vec<u8>> {
    let attr = AttributeType::VendorDefined(CKA_TPM2_PUB_BLOB);
    let got = ctx.session.get_attributes(object, &[attr]).map_err(|e| {
        KmError::Unavailable(
            format!("C_GetAttributeValue (CKA_TPM2_PUB_BLOB): {e} (the module needs the user login)").into(),
        )
    })?;
    match got.into_iter().next() {
        Some(Attribute::VendorDefined((_, blob))) if !blob.is_empty() => Ok(blob),
        _ => Err(KmError::Unavailable("the object exposes no CKA_TPM2_PUB_BLOB".into())),
    }
}

/// The signer of the statement: its public key, which the signature is checked against, and, when
/// it is a key the host also reads from the TPM, the qualified Name the statement names it by.
struct Statement {
    spki: Vec<u8>,
    qualified: Option<Vec<u8>>,
}

/// Run the whole attestation through the module: the object's public area, the module's
/// `TPM2_Certify` over a fresh nonce, and the host's checks of what came back — the same as the
/// store path's, but the live `TPM2_ReadPublic` of the loaded object, which only the module has
/// loaded: the Name is checked against the public area the module reports, which the signature
/// covers, and that against the object's own material.
///
/// # Errors
///
/// `Unavailable` without the token's user PIN, when the module refuses, or for what the TPM is
/// asked for; `Conflict` when the statement or the signer is not what it must be.
pub(crate) fn certify(ctx: &AttestCtx<'_>, opts: &Tpm2Options) -> Result<esys::Certified> {
    if ctx.pin.is_none() {
        return Err(KmError::Unavailable(
            "attesting through the module needs the token's user PIN (pinFile/pinEnv)".into(),
        ));
    }
    let blob = pub_blob(ctx, ctx.key)?;
    let public = esys::unmarshal_public(&blob)?;
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| KmError::Unavailable(format!("OS RNG: {e}").into()))?;

    let (signer, raw) = if let Some(label) = &opts.ak_label {
        let (ak, spki) = token_ak(ctx, label)?;
        let raw = sign(ctx, CKM_TPM2_CERTIFY_OBJECT, &Signer(ak.handle()), &nonce)?;
        (Statement { spki, qualified: None }, raw)
    } else {
        let handle = opts.ak_handle(ctx.token_name)?;
        let (spki, qualified) = {
            let mut tpm = esys::context(&super::tcti(ctx, opts)?)?;
            let (_, public, qualified) = esys::attestation_key(&mut tpm, handle, ctx.provision)?;
            let spki = esys::material_of(&public)?
                .spki
                .ok_or_else(|| KmError::Conflict("the Attestation Key exposes no public key".into()))?;
            (spki, qualified.value().to_vec())
        };
        let raw = sign(ctx, CKM_TPM2_CERTIFY, &Signer(c_ulong::from(handle)), &nonce)?;
        (Statement { spki, qualified: Some(qualified) }, raw)
    };
    let out = parse_output(&raw)?;
    let info = match out.attest.attested() {
        AttestInfo::Certify { info } => info,
        other => {
            return Err(KmError::Conflict(
                format!("the attestation attests {other:?}, not a certify statement").into(),
            ));
        }
    };
    if out.attest.extra_data().value() != nonce {
        return Err(KmError::Conflict("the attestation names other qualifying data than this run's nonce".into()));
    }
    let name = info.name().value().to_vec();
    if name != esys::recompute_name(&blob)? {
        return Err(KmError::Conflict(
            "the attested Name is not the Name of the public area the module reports for the object".into(),
        ));
    }
    esys::verify_signature(&out.signature, &signer.spki, &out.attest_bytes)?;
    if let Some(qualified) = &signer.qualified
        && out.attest.qualified_signer().value() != qualified.as_slice()
    {
        return Err(KmError::Conflict("the attestation was signed by another key than the AK".into()));
    }
    let material = esys::material_of(&public)?;
    esys::cross_check(&material, ctx.spki)?;
    Ok(esys::certified(name, info.qualified_name().value().to_vec(), signer.spki, &material))
}

/// `C_SignInit` and `C_Sign` of the object to attest with `mechanism`: the statement and its
/// signature.
fn sign(ctx: &AttestCtx<'_>, mechanism: c_ulong, signer: &Signer, nonce: &[u8]) -> Result<Vec<u8>> {
    let mech = Mechanism::VendorDefined(VendorDefinedMechanism::new(mechanism_type(mechanism)?, Some(signer)));
    ctx.session
        .sign(&mech, ctx.key, nonce)
        .map_err(|e| KmError::Unavailable(format!("C_Sign (CKM_TPM2_CERTIFY, mechanism {mechanism:#x}): {e}").into()))
}

/// The token's Attestation Key labelled `label`: found, or made by `lock` (`provision`), and
/// checked to be what could not sign a forged statement — a restricted, fixed signing key. Its
/// object handle and public key.
fn token_ak(ctx: &AttestCtx<'_>, label: &str) -> Result<(ObjectHandle, Vec<u8>)> {
    let find = || {
        ctx.session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::KeyType(KeyType::EC),
                Attribute::Label(label.as_bytes().to_vec()),
            ])
            .map_err(|e| KmError::Unavailable(format!("C_FindObjects (the Attestation Key {label:?}): {e}").into()))
    };
    let ak = match find()?.as_slice() {
        [one] => *one,
        [] if ctx.provision => {
            let mech = Mechanism::VendorDefined(VendorDefinedMechanism::new::<()>(
                mechanism_type(CKM_TPM2_AK_PAIR_GEN)?,
                None,
            ));
            let public = [
                Attribute::Token(true),
                Attribute::EcParams(P256.to_vec()),
                Attribute::Label(label.as_bytes().to_vec()),
            ];
            let private =
                [Attribute::Token(true), Attribute::Private(true), Attribute::Label(label.as_bytes().to_vec())];
            ctx.session.generate_key_pair(&mech, &public, &private).map_err(|e| {
                KmError::Unavailable(format!("making the Attestation Key {label:?} (CKM_TPM2_AK_PAIR_GEN): {e}").into())
            })?;
            match find()?.as_slice() {
                [one] => *one,
                found => {
                    return Err(KmError::Unavailable(
                        format!("the Attestation Key {label:?} just made is not found ({} objects)", found.len())
                            .into(),
                    ));
                }
            }
        }
        [] => {
            return Err(KmError::Unavailable(
                format!("no Attestation Key labelled {label:?} on this token; `lock` makes it").into(),
            ));
        }
        many => {
            return Err(KmError::Conflict(
                format!("{} private keys are labelled {label:?}: the Attestation Key must be one", many.len()).into(),
            ));
        }
    };
    let public = esys::unmarshal_public(&pub_blob(ctx, ak)?)?;
    check_ak(&public, label)?;
    let spki = esys::material_of(&public)?
        .spki
        .ok_or_else(|| KmError::Conflict("the Attestation Key exposes no public key".into()))?;
    Ok((ak, spki))
}

/// Whether `public` is an Attestation Key as the module makes one, as far as the host can read it
/// from the public area: ECDSA over NIST P-256 with SHA-256, restricted (it signs only what the TPM
/// itself generates) and fixed to the TPM and its parent. Anything else could sign a forged
/// statement, and a lock would pin it on first use.
fn check_ak(public: &Public, label: &str) -> Result<()> {
    use tss_esapi::interface_types::algorithm::HashingAlgorithm;
    use tss_esapi::interface_types::ecc::EccCurve;
    use tss_esapi::structures::{EccScheme, HashScheme};
    let ok = match public {
        Public::Ecc { object_attributes: a, parameters, .. } => {
            parameters.ecc_curve() == EccCurve::NistP256
                && parameters.ecc_scheme() == EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256))
                && a.restricted()
                && a.sign_encrypt()
                && !a.decrypt()
                && a.fixed_tpm()
                && a.fixed_parent()
        }
        _ => false,
    };
    if ok {
        return Ok(());
    }
    Err(KmError::Conflict(
        format!(
            "the key labelled {label:?} is not a cakeys Attestation Key (a restricted P-256 ECDSA-SHA256 \
             signing key, fixedTPM and fixedParent): an unrestricted key could sign forged attestations; \
             rename it or set tokens.<t>.options.akLabel to another"
        )
        .into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpm2b(bytes: &[u8]) -> Vec<u8> {
        let mut v = u16::try_from(bytes.len()).unwrap().to_be_bytes().to_vec();
        v.extend_from_slice(bytes);
        v
    }

    /// A certify statement as the TPM marshals it (`TPMS_ATTEST`) for `nonce`, and an ECDSA
    /// `TPMT_SIGNATURE` over P-256: what `CKM_TPM2_CERTIFY` returns, without a TPM.
    fn statement(nonce: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let name = [&[0x00, 0x0b][..], &[7; 32]].concat();
        let mut attest = vec![0xff, b'T', b'C', b'G', 0x80, 0x17];
        attest.extend(tpm2b(&[&[0x00, 0x0b][..], &[1; 32]].concat()));
        attest.extend(tpm2b(nonce));
        attest.extend([0u8; 8]); // clock
        attest.extend([0u8; 4]); // resetCount
        attest.extend([0u8; 4]); // restartCount
        attest.push(1); // safe
        attest.extend([0u8; 8]); // firmwareVersion
        attest.extend(tpm2b(&name));
        attest.extend(tpm2b(&name));
        let mut signature = vec![0x00, 0x18, 0x00, 0x0b];
        signature.extend(tpm2b(&[0x11; 32]));
        signature.extend(tpm2b(&[0x22; 32]));
        (attest, signature)
    }

    fn output(attest: &[u8], signature: &[u8]) -> Vec<u8> {
        [tpm2b(attest), signature.to_vec()].concat()
    }

    /// `TPM2B_ATTEST ‖ TPMT_SIGNATURE` is read to the statement and its signature, and nothing
    /// that is not exactly that is: the module is not trusted to frame the TPM's bytes.
    #[test]
    fn the_modules_output_is_read_exactly_or_refused() {
        let (attest, signature) = statement(b"nonce");
        let out = parse_output(&output(&attest, &signature)).unwrap();
        assert_eq!(out.attest_bytes, attest);
        assert_eq!(out.attest.extra_data().value(), b"nonce");
        assert!(matches!(out.signature, Signature::EcDsa(_)));

        let refused = |bytes: &[u8], why: &str| {
            let e = parse_output(bytes).unwrap_err();
            assert!(matches!(&e, KmError::Conflict(m) if m.contains(why)), "{why}: {e}");
        };
        refused(&[], "is empty");
        refused(&output(&attest, &signature)[..30], "cut short");
        refused(&[output(&attest, &signature), vec![0]].concat(), "bytes after it");
        refused(&output(&attest, &signature[..signature.len() - 1]), "has no signature");
        // The attestation's own framing: a byte after it inside the TPM2B, and another magic.
        refused(&output(&[attest.clone(), vec![0]].concat(), &signature), "not canonical");
        let mut magic = attest;
        magic[0] = 0;
        refused(&output(&magic, &signature), "has no attestation");
    }

    /// The vendor numbers are the module's (`src/tpm2-pkcs11-vendor.h`): `CKA_VENDOR_DEFINED`
    /// and its `0x0F000000` range, then `n`.
    #[test]
    fn the_vendor_numbers_are_the_modules() {
        assert_eq!(CKM_TPM2_CERTIFY, 0x8F00_0001);
        assert_eq!(CKM_TPM2_AK_PAIR_GEN, 0x8F00_0002);
        assert_eq!(CKM_TPM2_CERTIFY_OBJECT, 0x8F00_0003);
        assert_eq!(CKA_TPM2_PUB_BLOB, 0x8F00_0002);
        assert_eq!(std::mem::size_of::<Signer>(), std::mem::size_of::<c_ulong>());
    }
}
