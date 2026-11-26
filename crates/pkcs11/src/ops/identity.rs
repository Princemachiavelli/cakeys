//! A key's plaintext on the host, and the check of its identity before anything writes it
//! (review 2026-11-24 D-5). An [`Extracted`] holds the plaintext that
//! [`Token::extract`](crate::Token::extract) returns or that a key file holds. Only
//! [`check_identity`] turns an [`Extracted`] into a [`Checked`], and every writer of a key takes a
//! [`Checked`]: camigrate's key file, camigrate's import through the host, and the import through
//! `tpm2_ptool`. As a result, when a source module returns a key other than the one that it was
//! asked for, this check catches the key before a file, a slot or a TPM holds it.

use cakeys_core::config::Lock;
use cakeys_core::id::{self, BlockCipher, Commit, HmacHash, Scheme};
use cakeys_core::plan::{Target, block_commits};
use cakeys_core::reconcile::commitment_label;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{Check, KmError, Result};
use zeroize::Zeroizing;

/// A key's plaintext on the host whose identity is not checked yet: a private key's PKCS#8, or a
/// secret key's value. No writer accepts this type; [`check_identity`] must first turn it into a
/// [`Checked`].
pub struct Extracted(Zeroizing<Vec<u8>>);

impl Extracted {
    /// Wraps the plaintext that a module returned (`Token::extract`).
    pub(crate) fn new(plain: Zeroizing<Vec<u8>>) -> Extracted {
        Extracted(plain)
    }

    /// Wraps the plaintext that a key file holds.
    #[must_use]
    pub fn from_file(plain: Zeroizing<Vec<u8>>) -> Extracted {
        Extracted(plain)
    }
}

/// Gives read access to the plaintext. caprobe's `export.host` uses it to compare the key that
/// arrived with the key that caprobe made. A writer cannot use this access, because every writer
/// of a key takes a [`Checked`].
impl std::ops::Deref for Extracted {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// Formats only the length, because plaintext is never formatted.
impl std::fmt::Debug for Extracted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Extracted({} bytes)", self.0.len())
    }
}

/// A key's plaintext whose identity matches what the lock records for its object, as
/// [`check_identity`] verified.
pub struct Checked(Zeroizing<Vec<u8>>);

/// Formats only the length, because plaintext is never formatted.
impl std::fmt::Debug for Checked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Checked({} bytes)", self.0.len())
    }
}

impl Checked {
    /// Returns the plaintext to the writer that takes it.
    #[must_use]
    pub fn plaintext(&self) -> &[u8] {
        &self.0
    }
}

/// Returns `key` as a [`Checked`] once its identity matches what the lock records for the object
/// of `t`. For a private key, the identity is the `rfc7093m4` ID of the public key in its PKCS#8.
/// For a secret key, the identity is every commitment that the lock records, computed here as the
/// token computes it (`Commit::input` with the object's commitment label). A secret key for which
/// the lock records no commitment is a first use. The lock then records the commitments that the
/// target token computes after the key is created there (docs/FILE.md F3).
///
/// # Errors
///
/// - `HashMismatch` (exit 10) when an identity differs from the one that the lock records, or
///   when the lock records no `rfc7093m4` ID for a private key.
/// - `Unsupported` (exit 15) when the lock records a secret key only by commitments that this
///   process cannot compute.
/// - `Validation` for a class that is not a key, or for a PKCS#8 that does not parse.
pub fn check_identity(t: &Target, lock: &Lock, key: Extracted) -> Result<Checked> {
    let pinned = |scheme: Scheme| lock.objects.get(t.object_name).and_then(|o| o.ids.get(scheme.name()));
    let mismatch = |scheme: Scheme, got: String| KmError::HashMismatch {
        what: format!("{t}: the key on the host"),
        expected: pinned(scheme).cloned().unwrap_or_else(|| format!("a locked {}", scheme.name())),
        got,
        check: Check::IdentityMaterial,
    };
    match t.object.class {
        Class::PrivateKey => {
            let got = id::sri(&id::spki_canonical(&cakeys_core::plaintext::spki_of_pkcs8(&key.0)?)?);
            if pinned(Scheme::Rfc7093m4) != Some(&got) {
                return Err(mismatch(Scheme::Rfc7093m4, got));
            }
        }
        Class::SecretKey => {
            let label = commitment_label(t, lock);
            let mut checked = 0;
            for c in commits_of(t) {
                let Some(want) = pinned(c.scheme()) else { continue };
                let got = host_commit(c, &key.0, &c.input(&label, t.object.cfg()))
                    .map_or_else(|| format!("a {}-byte key", key.0.len()), |out| id::sri(&out));
                if &got != want {
                    return Err(mismatch(c.scheme(), got));
                }
                checked += 1;
            }
            let commitments = lock
                .objects
                .get(t.object_name)
                .map(|o| o.ids.keys().filter(|s| Scheme::from_name(s).is_some_and(Scheme::is_commitment)).count());
            if checked == 0 && commitments.unwrap_or_default() > 0 {
                return Err(KmError::Unsupported(
                    format!("{t}: the lock pins the key by commitments this process does not compute").into(),
                ));
            }
        }
        class => return Err(KmError::Validation(format!("{t}: a {class} is not a key the host holds").into())),
    }
    Ok(Checked(key.0))
}

/// Returns every commitment by which the lock may record a secret key of the key type of `t`.
fn commits_of(t: &Target) -> Vec<Commit> {
    let Some(kt) = t.object.key_type else { return vec![] };
    block_commits(kt).map_or_else(|| HmacHash::for_key_type(kt).map(Commit::Hmac).into_iter().collect(), <[_]>::to_vec)
}

/// Computes the commitment `c` of the secret key `key` over `input`, as a token computes it.
/// Returns `None` when `c` cannot take a key of this length.
fn host_commit(c: Commit, key: &[u8], input: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{BlockCipherDecrypt as _, BlockCipherEncrypt as _};
    macro_rules! hmac_of {
        ($hash:ty) => {{
            let mut m = <hmac::Hmac<$hash> as hmac::KeyInit>::new_from_slice(key).ok()?;
            hmac::Mac::update(&mut m, input);
            hmac::Mac::finalize(m).into_bytes().to_vec()
        }};
    }
    macro_rules! aes_of {
        ($aes:ty, $kw:ty) => {{
            let cipher = <$aes as aes::cipher::KeyInit>::new_from_slice(key).ok()?;
            match c {
                Commit::Cmac => {
                    let mut m = <cmac::Cmac<$aes> as aes::cipher::KeyInit>::new_from_slice(key).ok()?;
                    cmac::Mac::update(&mut m, input);
                    cmac::Mac::finalize(m).into_bytes().to_vec()
                }
                Commit::KcvEcb(_) | Commit::KcvEcbDecrypt(_) => {
                    let mut block = aes::Block::default();
                    (input.len() == block.len()).then_some(())?;
                    block.copy_from_slice(input);
                    if matches!(c, Commit::KcvEcb(_)) {
                        cipher.encrypt_block(&mut block);
                    } else {
                        cipher.decrypt_block(&mut block);
                    }
                    block.to_vec()
                }
                Commit::Kw => {
                    let mut out = vec![0u8; input.len() + 8];
                    <$kw as aes_kw::cipher::KeyInit>::new_from_slice(key).ok()?.wrap_key(input, &mut out).ok()?.to_vec()
                }
                Commit::Hmac(_) => return None,
            }
        }};
    }
    Some(match c {
        Commit::Hmac(HmacHash::Sha1) => hmac_of!(sha1::Sha1),
        Commit::Hmac(HmacHash::Sha224) => hmac_of!(sha2::Sha224),
        Commit::Hmac(HmacHash::Sha256) => hmac_of!(sha2::Sha256),
        Commit::Hmac(HmacHash::Sha384) => hmac_of!(sha2::Sha384),
        Commit::Hmac(HmacHash::Sha512) => hmac_of!(sha2::Sha512),
        Commit::KcvEcb(BlockCipher::Des3) | Commit::KcvEcbDecrypt(BlockCipher::Des3) => {
            use des::cipher::{BlockCipherDecrypt as _, BlockCipherEncrypt as _};
            let cipher = <des::TdesEde3 as des::cipher::KeyInit>::new_from_slice(key).ok()?;
            let mut block = des::cipher::Block::<des::TdesEde3>::default();
            (input.len() == block.len()).then_some(())?;
            block.copy_from_slice(input);
            if matches!(c, Commit::KcvEcb(_)) {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            block.to_vec()
        }
        _ => match key.len() {
            16 => aes_of!(aes::Aes128, aes_kw::KwAes128),
            24 => aes_of!(aes::Aes192, aes_kw::KwAes192),
            32 => aes_of!(aes::Aes256, aes_kw::KwAes256),
            _ => return None,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::config::Config;

    fn config(object: &str) -> Config {
        toml::from_str(&format!(
            "[tokens.t]\ntokenLabel = \"t\"\n\n[objects.k]\n{object}\n\n\
             [specs.s]\nobject = \"k\"\ntokens.t = {{ locator = {{ CKA_LABEL = \"k\" }} }}\n"
        ))
        .unwrap()
    }

    fn pinning(t: &Target, ids: &[(Commit, &[u8])]) -> Lock {
        let mut lock = Lock::default();
        let entry = lock.objects.entry("k".into()).or_default();
        for (c, key) in ids {
            let out = host_commit(*c, key, &c.input(id::DEFAULT_COMMITMENT_LABEL, t.object.cfg())).unwrap();
            entry.ids.insert(c.scheme().name().into(), id::sri(&out));
        }
        lock
    }

    fn checked(t: &Target, lock: &Lock, key: &[u8]) -> Result<Checked> {
        check_identity(t, lock, Extracted::from_file(Zeroizing::new(key.to_vec())))
    }

    /// A secret key matches the lock only when every commitment that the lock records matches the
    /// key (review 2026-11-24 D-5 found that every secret key passed this check). When the lock
    /// records no commitment, the key is a first use. The test
    /// `every_spelling_of_a_secret_key_imports_as_the_same_key` (camigrate's `from_files`) checks
    /// that a commitment computed here equals the commitment that a token computes: it checks
    /// each spelling after the first against the IDs that `SoftHSM` recorded.
    #[test]
    fn a_secret_key_is_its_pinned_commitments() {
        let cfg = config("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32");
        let t = Target::new(&cfg, "s", "t").unwrap();
        let (key, other) = ([7u8; 32], [8u8; 32]);
        for c in cakeys_core::plan::AES_COMMITS {
            let lock = pinning(&t, &[(c, &key)]);
            assert!(checked(&t, &lock, &key).is_ok(), "{c:?}");
            assert!(matches!(checked(&t, &lock, &other), Err(KmError::HashMismatch { .. })), "{c:?}");
            assert!(matches!(checked(&t, &lock, &key[..16]), Err(KmError::HashMismatch { .. })), "{c:?}");
        }
        let both = pinning(&t, &[(Commit::Cmac, &key), (Commit::Kw, &other)]);
        assert!(matches!(checked(&t, &both, &key), Err(KmError::HashMismatch { .. })), "one of two");
        assert!(checked(&t, &Lock::default(), &other).is_ok(), "a first use");
        let mut unknown = Lock::default();
        unknown.objects.entry("k".into()).or_default().ids.insert("commitment".into(), "sha256-x".into());
        assert!(matches!(checked(&t, &unknown, &key), Err(KmError::Unsupported(_))), "pinned by no AES commitment");
        // The input of `kcv-ecb` for this key is the first 16 bytes of the SHA-256 of the
        // scheme's own label, as the AES oracle computes it.
        let kcv = Commit::KcvEcb(BlockCipher::Aes);
        let label = "key-management/v1/kcv-ecb/CKK_AES/256";
        let digest = <sha2::Sha256 as sha2::Digest>::digest(label.as_bytes());
        assert_eq!(kcv.input(id::DEFAULT_COMMITMENT_LABEL, t.object.cfg()), digest[..16].to_vec());
    }

    /// HMAC and DES3 keys are each checked by the commitment of their key type.
    #[test]
    fn hmac_and_des3_keys_are_their_commitments() {
        for (object, key, c) in [
            (
                "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32",
                vec![1u8; 32],
                Commit::Hmac(HmacHash::Sha256),
            ),
            (
                "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA_1_HMAC\"\nvalueLen = 20",
                vec![2u8; 20],
                Commit::Hmac(HmacHash::Sha1),
            ),
            (
                "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"\nvalueLen = 24",
                (0u8..24).collect(),
                Commit::KcvEcb(BlockCipher::Des3),
            ),
        ] {
            let cfg = config(object);
            let t = Target::new(&cfg, "s", "t").unwrap();
            let lock = pinning(&t, &[(c, &key)]);
            assert!(checked(&t, &lock, &key).is_ok(), "{c:?}");
            let mut other = key.clone();
            other[0] ^= 0x80;
            assert!(matches!(checked(&t, &lock, &other), Err(KmError::HashMismatch { .. })), "{c:?}");
        }
    }
}
