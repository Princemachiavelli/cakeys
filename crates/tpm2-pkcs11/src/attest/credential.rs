//! `TPM2_MakeCredential` on the host (TPM 2.0 Part 1 §24, Part 3 §12.6, Part 1 §11.4.9-10):
//! a secret only the TPM holding the endorsement key can recover, and only for the object whose
//! Name the credential is bound to. `TPM2_ActivateCredential` with the AK and the EK hands it back
//! (`esys::activate`), which proves the AK resides in the TPM the EK certificate names — what
//! closes the AK's first use (review D5).
//!
//! The host, never the TPM under test, makes the credential: a TPM that made it knows the secret
//! and could hand it back without holding the EK.
//!
//! Everything here is the TCG default EK template's: nameAlg SHA-256, AES-128 in CFB mode as the
//! symmetric definition, RSA-2048 (OAEP) or NIST P-256 (ECDH) for the seed. The labels carry
//! their terminating NUL, as the reference implementation hashes them.

use cakeys_core::{KmError, Result};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

/// SHA-256's TPM algorithm ID, the nameAlg the AK and the EK templates name.
const SHA256_ALG: u16 = 0x000B;
const IDENTITY: &[u8] = b"IDENTITY\0";
const STORAGE: &[u8] = b"STORAGE\0";
const INTEGRITY: &[u8] = b"INTEGRITY\0";

/// A credential for `TPM2_ActivateCredential`: the contents of its `TPM2B_ID_OBJECT` and
/// `TPM2B_ENCRYPTED_SECRET` (without their size prefixes).
pub(crate) struct Credential {
    pub(crate) blob: Vec<u8>,
    pub(crate) secret: Vec<u8>,
}

/// The Name of a public area, `nameAlg ‖ SHA-256(TPMT_PUBLIC)`, from the marshaled `TPMT_PUBLIC`
/// bytes the host itself holds: never a Name the TPM reports, which an interposer could pair with
/// another key.
///
/// # Errors
///
/// `Conflict` when the bytes are too short to name an algorithm; `Unsupported` for a nameAlg
/// other than SHA-256.
pub(crate) fn name_of(tpmt_public: &[u8]) -> Result<Vec<u8>> {
    let name = super::esys::tpmt_name(tpmt_public)?;
    let alg = u16::from_be_bytes([name[0], name[1]]);
    if alg != SHA256_ALG {
        return Err(KmError::Unsupported(format!("nameAlg 0x{alg:04x} (the credential takes SHA-256)").into()));
    }
    Ok(name)
}

/// Make a credential carrying `secret` to the EK whose public key is `ek_spki` (the verified EK
/// certificate's), bound to the object whose marshaled `TPMT_PUBLIC` is `ak_public`: its Name is
/// computed here, from those bytes.
///
/// # Errors
///
/// `Unsupported` for an EK that is neither RSA-2048 nor P-256, or a nameAlg other than SHA-256;
/// `Unavailable` when the OS random number generator or the encryption fails.
pub(crate) fn make_credential(ek_spki: &[u8], ak_public: &[u8], secret: &[u8]) -> Result<Credential> {
    let name = name_of(ak_public)?;
    let (seed, encrypted_seed) = seed_for(ek_spki)?;
    Ok(Credential { blob: wrap(&seed, &name, secret)?, secret: encrypted_seed })
}

/// The seed and how it travels to the EK: OAEP-encrypted for RSA, the ephemeral ECDH point for
/// P-256 (Part 1 §11.4.10.3 and Annex C.6.1 of the ECC key exchange).
fn seed_for(ek_spki: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    use cakeys_core::id::{Curve, KeyAlg};
    let rng_failed =
        |e: &dyn std::fmt::Display| KmError::Unavailable(format!("OS random number generator: {e}").into());
    match KeyAlg::of_spki(ek_spki).map_err(|e| KmError::Unsupported(format!("the EK's key: {e}").into()))? {
        KeyAlg::Rsa => {
            use rsa::pkcs8::DecodePublicKey as _;
            let key = rsa::PublicKey::from_public_key_der(ek_spki)
                .map_err(|e| KmError::Unsupported(format!("the EK's RSA key: {e}").into()))?;
            let mut seed = Zeroizing::new(vec![0u8; 32]);
            getrandom::fill(&mut seed).map_err(|e| rng_failed(&e))?;
            let encrypted =
                key.encrypt(&mut getrandom::SysRng, rsa::Oaep::<Sha256>::new_with_label(IDENTITY), &seed).map_err(
                    |e| KmError::Unavailable(format!("encrypting the credential's seed to the EK: {e}").into()),
                )?;
            Ok((seed, encrypted))
        }
        KeyAlg::Ec(Curve::P256) => {
            use elliptic_curve::Generate as _;
            use elliptic_curve::ecdh::EphemeralSecret;
            use elliptic_curve::sec1::ToSec1Point as _;
            use p256::pkcs8::DecodePublicKey as _;
            let ek = p256::PublicKey::from_public_key_der(ek_spki)
                .map_err(|e| KmError::Unsupported(format!("the EK's P-256 key: {e}").into()))?;
            let eph = EphemeralSecret::<p256::NistP256>::try_generate_from_rng(&mut getrandom::SysRng)
                .map_err(|e| rng_failed(&e))?;
            let z = eph.diffie_hellman(&ek);
            let (eph_point, ek_point) = (eph.public_key().to_sec1_point(false), ek.to_sec1_point(false));
            let (eph_x, eph_y) = (&eph_point.as_bytes()[1..33], &eph_point.as_bytes()[33..65]);
            let ek_x = &ek_point.as_bytes()[1..33];
            let seed = Zeroizing::new(kdfe(z.raw_secret_bytes(), IDENTITY, eph_x, ek_x));
            // TPMS_ECC_POINT: x and y, each a TPM2B.
            let mut point = Vec::with_capacity(4 + 64);
            for coordinate in [eph_x, eph_y] {
                point.extend_from_slice(&u16::try_from(coordinate.len()).unwrap_or(32).to_be_bytes());
                point.extend_from_slice(coordinate);
            }
            Ok((seed, point))
        }
        other @ KeyAlg::Ec(_) => Err(KmError::Unsupported(
            format!("an EK of {other:?} (the credential takes the default RSA-2048 or P-256 EK)").into(),
        )),
    }
}

/// The `TPM2B_ID_OBJECT` contents: `integrityHMAC ‖ encIdentity` (Part 1 §24.4-24.5).
fn wrap(seed: &[u8], name: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    let too_long = || KmError::Unsupported("a credential longer than a TPM2B allows".into());
    // encIdentity: the credential as a TPM2B_DIGEST, AES-128-CFB under a key from the seed and
    // the Name, from a zero IV.
    let mut identity = u16::try_from(secret.len()).map_err(|_| too_long())?.to_be_bytes().to_vec();
    identity.extend_from_slice(secret);
    let identity = Zeroizing::new(identity);
    let sym = Zeroizing::new(kdfa(seed, STORAGE, name, &[], 128));
    let enc_identity = aes128_cfb(&sym, &identity);
    // outerHMAC over encIdentity ‖ Name, under a key from the seed alone.
    let hmac_key = Zeroizing::new(kdfa(seed, INTEGRITY, &[], &[], 256));
    let mut mac = <Hmac<Sha256>>::new_from_slice(&hmac_key).map_err(|_| too_long())?;
    mac.update(&enc_identity);
    mac.update(name);
    let integrity = mac.finalize().into_bytes();
    let mut blob = u16::try_from(integrity.len()).map_err(|_| too_long())?.to_be_bytes().to_vec();
    blob.extend_from_slice(&integrity);
    blob.extend_from_slice(&enc_identity);
    Ok(blob)
}

/// `KDFa` with SHA-256 (Part 1 §11.4.10.2, SP 800-108 counter mode): `bits` of
/// `HMAC(key, i ‖ label ‖ contextU ‖ contextV ‖ bits)` for i = 1, 2, ...
fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], bits: u32) -> Vec<u8> {
    let bytes = (bits / 8) as usize;
    let mut out = Vec::with_capacity(bytes + 32);
    let mut counter = 1u32;
    while out.len() < bytes {
        // HMAC takes a key of any length.
        let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC takes any key length");
        for part in [&counter.to_be_bytes()[..], label, context_u, context_v, &bits.to_be_bytes()[..]] {
            mac.update(part);
        }
        out.extend_from_slice(&mac.finalize().into_bytes());
        counter += 1;
    }
    out.truncate(bytes);
    out
}

/// `KDFe` with SHA-256 for 256 bits (Part 1 §11.4.10.3, SP 800-56A's one-step KDF):
/// `SHA-256(1 ‖ Z ‖ label ‖ partyU ‖ partyV)`.
fn kdfe(z: &[u8], label: &[u8], party_u: &[u8], party_v: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    for part in [&1u32.to_be_bytes()[..], z, label, party_u, party_v] {
        h.update(part);
    }
    h.finalize().to_vec()
}

/// AES-128 in CFB mode (full-block feedback) from a zero IV, as the TPM's credential takes it.
fn aes128_cfb(key: &[u8], data: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockCipherEncrypt as _, KeyInit as _};
    let cipher = aes::Aes128::new_from_slice(key).expect("a 128-bit key from KDFa");
    let mut feedback = aes::Block::default();
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let mut stream = feedback;
        cipher.encrypt_block(&mut stream);
        let start = out.len();
        out.extend(chunk.iter().zip(stream.iter()).map(|(p, k)| p ^ k));
        // The next block's feedback is this ciphertext block (a short last block needs none).
        feedback[..chunk.len()].copy_from_slice(&out[start..]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `KDFa` is HMAC-SHA256 in counter mode: one block for up to 256 bits, two above, the
    /// counter, label, contexts and length all hashed (a recomputation, block by block).
    #[test]
    fn kdfa_is_the_counter_mode_hmac() {
        let block = |i: u32, bits: u32| {
            let mut mac = <Hmac<Sha256>>::new_from_slice(b"key").unwrap();
            for part in [&i.to_be_bytes()[..], STORAGE, b"u", b"v", &bits.to_be_bytes()[..]] {
                mac.update(part);
            }
            mac.finalize().into_bytes().to_vec()
        };
        assert_eq!(kdfa(b"key", STORAGE, b"u", b"v", 128), block(1, 128)[..16]);
        let long = kdfa(b"key", STORAGE, b"u", b"v", 384);
        assert_eq!(long[..32], block(1, 384)[..]);
        assert_eq!(long[32..], block(2, 384)[..16]);
    }

    /// CFB from a zero IV: the first block is the plaintext XOR E(0), and each later block XORs
    /// the encryption of the ciphertext before it (FIPS SP 800-38A F.3.13's key and data).
    #[test]
    fn cfb_is_the_sp800_38a_vector() {
        use aes::cipher::{BlockCipherEncrypt as _, KeyInit as _};
        let hex = |s: &str| (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect();
        let key: Vec<u8> = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let plain: Vec<u8> = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
        let iv: Vec<u8> = hex("000102030405060708090a0b0c0d0e0f");
        // The vector's IV v, from a zero IV: a lead block v ⊕ E(0) encrypts to v, which then
        // feeds back as the IV would.
        let mut e0 = aes::Block::default();
        aes::Aes128::new_from_slice(&key).unwrap().encrypt_block(&mut e0);
        let mut input: Vec<u8> = iv.iter().zip(e0.iter()).map(|(a, b)| a ^ b).collect();
        input.extend_from_slice(&plain);
        let out = aes128_cfb(&key, &input);
        assert_eq!(out[..16], iv[..], "the lead block encrypts to the IV");
        assert_eq!(out[16..], hex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b")[..]);
    }

    /// The Name is SHA-256 over exactly the bytes given, behind the algorithm ID; another
    /// nameAlg is refused rather than hashed as SHA-256.
    #[test]
    fn the_name_is_the_hosts() {
        let public = [0x00, 0x23, 0x00, 0x0B, 0xAA];
        let name = name_of(&public).unwrap();
        assert_eq!(name[..2], [0x00, 0x0B]);
        assert_eq!(name[2..], Sha256::digest(public)[..]);
        assert!(name_of(&[0x00, 0x23, 0x00, 0x0C]).is_err());
        assert!(name_of(&[0x00]).is_err());
    }

    /// The blob is `TPM2B(HMAC) ‖ encIdentity`, the HMAC over encIdentity and the Name, so a
    /// credential bound to one Name does not verify for another.
    #[test]
    fn the_blob_is_bound_to_the_name() {
        let blob = wrap(&[7; 32], b"\x00\x0bname-a", b"secret").unwrap();
        assert_eq!(blob[..2], [0, 32]);
        let enc = &blob[34..];
        assert_eq!(enc.len(), 2 + 6);
        let other = wrap(&[7; 32], b"\x00\x0bname-b", b"secret").unwrap();
        assert_ne!(blob[2..34], other[2..34], "the HMAC covers the Name");
        assert_ne!(blob[34..], other[34..], "the symmetric key comes from the Name");
    }
}
