//! The tables that more than one cakeys crate needs, each defined only here (review 2026-11-24
//! item 8, phase1-design §4): the named curves and the ECDSA hash of each curve, the proofs of
//! possession, the commitments and the mechanism that each one runs, the size of an RSA modulus,
//! and the return values that mean that the device failed. Every other crate uses these tables or
//! tests against them, and no other crate defines them again.
//!
//! This crate has no dependencies, so the profile crate can read the tables without cakeys-core,
//! and cakeys-core can read them without the profiles (docs/ARCHITECTURE.md). The mechanism names
//! have their own source, `p11-names`, and the key types stay in the crate that keeps them as they
//! were read (`cakeys_profile::KeyKind`).

/// The kind of curve, which determines its PKCS#11 key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// `CKK_EC`: a short Weierstrass curve, for ECDSA and ECDH.
    Weierstrass,
    /// `CKK_EC_EDWARDS`: an Edwards curve, for `EdDSA`.
    Edwards,
    /// `CKK_EC_MONTGOMERY`: a Montgomery curve, for ECDH only.
    Montgomery,
}

/// A named curve: the Weierstrass and Edwards curves for which cakeys has a key type, and the
/// Montgomery curves that the probe measures and the profiles name, which keys.toml does not
/// accept yet ([`Curve::in_core`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Curve {
    /// NIST P-256 (`secp256r1`).
    P256,
    /// NIST P-384 (`secp384r1`).
    P384,
    /// NIST P-521 (`secp521r1`).
    P521,
    /// `secp256k1`.
    Secp256k1,
    /// `brainpoolP256r1`.
    BrainpoolP256r1,
    /// `brainpoolP384r1`.
    BrainpoolP384r1,
    /// Ed25519 (`edwards25519`).
    Ed25519,
    /// Ed448 (`edwards448`).
    Ed448,
    /// X25519 (`curve25519`).
    X25519,
    /// X448 (`curve448`).
    X448,
}

impl Curve {
    /// Every named curve: the Weierstrass curves, then the Edwards curves, then the Montgomery
    /// curves.
    pub const ALL: [Curve; 10] = [
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::Secp256k1,
        Curve::BrainpoolP256r1,
        Curve::BrainpoolP384r1,
        Curve::Ed25519,
        Curve::Ed448,
        Curve::X25519,
        Curve::X448,
    ];

    /// The [`Curve::name`] of every curve, in the order of [`Curve::ALL`]. These are the curve
    /// names that a profile row or a query may use.
    pub const NAMES: [&'static str; 10] = {
        let mut names = [""; 10];
        let mut i = 0;
        while i < names.len() {
            names[i] = Curve::ALL[i].name();
            i += 1;
        }
        names
    };

    /// Returns the canonical name, which keys.toml's `curve`, the lock and a profile row use.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Curve::P256 => "secp256r1",
            Curve::P384 => "secp384r1",
            Curve::P521 => "secp521r1",
            Curve::Secp256k1 => "secp256k1",
            Curve::BrainpoolP256r1 => "brainpoolP256r1",
            Curve::BrainpoolP384r1 => "brainpoolP384r1",
            Curve::Ed25519 => "edwards25519",
            Curve::Ed448 => "edwards448",
            Curve::X25519 => "curve25519",
            Curve::X448 => "curve448",
        }
    }

    /// Returns the name that a message uses for the curve, such as `P-256` or `Ed25519`. keys.toml
    /// also accepts this name.
    #[must_use]
    pub const fn display(self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
            Curve::P521 => "P-521",
            Curve::Secp256k1 => "secp256k1",
            Curve::BrainpoolP256r1 => "brainpoolP256r1",
            Curve::BrainpoolP384r1 => "brainpoolP384r1",
            Curve::Ed25519 => "Ed25519",
            Curve::Ed448 => "Ed448",
            Curve::X25519 => "X25519",
            Curve::X448 => "X448",
        }
    }

    /// Returns the curve's family, which determines its key type.
    #[must_use]
    pub const fn family(self) -> Family {
        match self {
            Curve::P256
            | Curve::P384
            | Curve::P521
            | Curve::Secp256k1
            | Curve::BrainpoolP256r1
            | Curve::BrainpoolP384r1 => Family::Weierstrass,
            Curve::Ed25519 | Curve::Ed448 => Family::Edwards,
            Curve::X25519 | Curve::X448 => Family::Montgomery,
        }
    }

    /// Returns whether cakeys-core has a key type for the curve, so that keys.toml accepts it
    /// (`cakeys_core::id::Curve` has exactly these curves). This is every curve except the
    /// Montgomery curves, which only the probe generates.
    #[must_use]
    pub const fn in_core(self) -> bool {
        !matches!(self.family(), Family::Montgomery)
    }

    /// Returns `CKA_EC_PARAMS` as the curve's DER OID (RFC 5480, RFC 8410), with which a key is
    /// generated.
    #[must_use]
    pub const fn params(self) -> &'static [u8] {
        match self {
            Curve::P256 => &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
            Curve::P384 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22],
            Curve::P521 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23],
            Curve::Secp256k1 => &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a],
            Curve::BrainpoolP256r1 => &[0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
            Curve::BrainpoolP384r1 => &[0x06, 0x09, 0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b],
            Curve::Ed25519 => &[0x06, 0x03, 0x2b, 0x65, 0x70],
            Curve::Ed448 => &[0x06, 0x03, 0x2b, 0x65, 0x71],
            Curve::X25519 => &[0x06, 0x03, 0x2b, 0x65, 0x6e],
            Curve::X448 => &[0x06, 0x03, 0x2b, 0x65, 0x6f],
        }
    }

    /// Returns `CKA_EC_PARAMS` as a `PrintableString` of the name, which PKCS#11 3.0 allows for
    /// the Edwards and Montgomery curves. Returns `None` for a Weierstrass curve.
    #[must_use]
    pub const fn params_by_name(self) -> Option<&'static [u8]> {
        match self {
            Curve::Ed25519 => Some(b"\x13\x0cedwards25519"),
            Curve::Ed448 => Some(b"\x13\x0aedwards448"),
            Curve::X25519 => Some(b"\x13\x0acurve25519"),
            Curve::X448 => Some(b"\x13\x08curve448"),
            Curve::P256
            | Curve::P384
            | Curve::P521
            | Curve::Secp256k1
            | Curve::BrainpoolP256r1
            | Curve::BrainpoolP384r1 => None,
        }
    }

    /// Returns the curve with this canonical [`Curve::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<Curve> {
        Curve::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// A SHA-2 hash over which a signature is made, and which cakeys-core computes: the hash of ECDSA
/// on each Weierstrass curve ([`HashAlg::for_curve`]), and the hash of an RSA PKCS#1 v1.5 or PSS
/// signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
}

impl HashAlg {
    /// Returns the hash of ECDSA on `curve`, which is the hash that matches the curve's strength
    /// (FIPS 186-5). The token is asked to sign with this hash, and the host verifies with it, so
    /// one table serves both (review 2026-11-24 A-8). Returns `None` for an Edwards curve, which
    /// hashes inside the signature, and for a Montgomery curve, which does not sign.
    #[must_use]
    pub fn for_curve(curve: impl Into<Curve>) -> Option<HashAlg> {
        match curve.into() {
            Curve::P256 | Curve::Secp256k1 | Curve::BrainpoolP256r1 => Some(HashAlg::Sha256),
            Curve::P384 | Curve::BrainpoolP384r1 => Some(HashAlg::Sha384),
            Curve::P521 => Some(HashAlg::Sha512),
            Curve::Ed25519 | Curve::Ed448 | Curve::X25519 | Curve::X448 => None,
        }
    }
}

/// A proof of possession, identified by its name. The name is the `binding` that keys.toml and
/// the lock write for the proof (`cakeys_core::config::Binding`), and the `<proof>` in the
/// `prove.<proof>` key of a capability row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// `pop-sign`: the key signs a new challenge.
    PopSign,
    /// `pop-sign-pin`: `pop-sign` with the PIN for each use that a `CKA_ALWAYS_AUTHENTICATE` key
    /// demands.
    PopSignPin,
    /// `pop-ecdh`: a MAC with an ECDH secret is computed over the challenge.
    PopEcdh,
    /// `pop-decrypt`: the key decrypts a challenge from the host.
    PopDecrypt,
    /// `pop-unwrap`: the key unwraps a secret from the host, and a MAC with that secret is
    /// computed over the challenge.
    PopUnwrap,
}

impl Proof {
    /// Every proof.
    pub const ALL: [Proof; 5] =
        [Proof::PopSign, Proof::PopSignPin, Proof::PopEcdh, Proof::PopDecrypt, Proof::PopUnwrap];

    /// The [`Proof::name`] of every proof, in the order of [`Proof::ALL`].
    pub const NAMES: [&'static str; 5] = {
        let mut names = [""; 5];
        let mut i = 0;
        while i < names.len() {
            names[i] = Proof::ALL[i].name();
            i += 1;
        }
        names
    };

    /// Returns the proof's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Proof::PopSign => "pop-sign",
            Proof::PopSignPin => "pop-sign-pin",
            Proof::PopEcdh => "pop-ecdh",
            Proof::PopDecrypt => "pop-decrypt",
            Proof::PopUnwrap => "pop-unwrap",
        }
    }

    /// Returns the proof with this [`Proof::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<Proof> {
        Proof::ALL.into_iter().find(|p| p.name() == name)
    }
}

/// A secret key's commitment, identified by the kind that a `commit.<kind>.<key type>.<bytes>` row
/// names (`cakeys_core::id::Commit::kind`): the scheme's name, with the hash next to it for an
/// HMAC. The cipher of a check value is the cipher of the key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitKind {
    /// HMAC-SHA-1 over the label.
    HmacSha1,
    /// HMAC-SHA-224 over the label.
    HmacSha224,
    /// HMAC-SHA-256 over the label.
    HmacSha256,
    /// HMAC-SHA-384 over the label.
    HmacSha384,
    /// HMAC-SHA-512 over the label.
    HmacSha512,
    /// AES-CMAC over the label.
    Cmac,
    /// One block encrypted in ECB mode, which is a key check value.
    KcvEcb,
    /// One block decrypted in ECB mode, for keys that may only decrypt.
    KcvEcbDec,
    /// AES key wrap (RFC 3394) of a fixed key.
    Kw,
}

impl CommitKind {
    /// Every kind.
    pub const ALL: [CommitKind; 9] = [
        CommitKind::HmacSha1,
        CommitKind::HmacSha224,
        CommitKind::HmacSha256,
        CommitKind::HmacSha384,
        CommitKind::HmacSha512,
        CommitKind::Cmac,
        CommitKind::KcvEcb,
        CommitKind::KcvEcbDec,
        CommitKind::Kw,
    ];

    /// Returns the kind's name in a `commit.*` row.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            CommitKind::HmacSha1 => "hmac-sha1",
            CommitKind::HmacSha224 => "hmac-sha224",
            CommitKind::HmacSha256 => "hmac-sha256",
            CommitKind::HmacSha384 => "hmac-sha384",
            CommitKind::HmacSha512 => "hmac-sha512",
            CommitKind::Cmac => "cmac",
            CommitKind::KcvEcb => "kcv-ecb",
            CommitKind::KcvEcbDec => "kcv-ecb-dec",
            CommitKind::Kw => "kw",
        }
    }

    /// Returns the kind with this [`CommitKind::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<CommitKind> {
        CommitKind::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Returns the `CKM_*` mechanism that the commitment runs on a key of `key_type` (`CKK_*`).
    /// Only the cipher of a check value depends on the key type. The mechanism is what a declared
    /// `CKA_ALLOWED_MECHANISMS` must contain for the commitment, what the token is asked to run,
    /// and what a profile's `commit.*` row is measured with.
    #[must_use]
    pub fn mechanism(self, key_type: &str) -> &'static str {
        match self {
            CommitKind::HmacSha1 => "CKM_SHA_1_HMAC",
            CommitKind::HmacSha224 => "CKM_SHA224_HMAC",
            CommitKind::HmacSha256 => "CKM_SHA256_HMAC",
            CommitKind::HmacSha384 => "CKM_SHA384_HMAC",
            CommitKind::HmacSha512 => "CKM_SHA512_HMAC",
            CommitKind::Cmac => "CKM_AES_CMAC",
            CommitKind::KcvEcb | CommitKind::KcvEcbDec if key_type == "CKK_DES3" => "CKM_DES3_ECB",
            CommitKind::KcvEcb | CommitKind::KcvEcbDec => "CKM_AES_ECB",
            CommitKind::Kw => "CKM_AES_KEY_WRAP",
        }
    }
}

/// Returns the size in bits of the unsigned big-endian integer `n`, which is an RSA modulus as
/// `CKA_MODULUS` or an SPKI holds it. Leading zero bytes count as nothing, and the first nonzero
/// byte counts only its significant bits, so a 2047-bit modulus is 2047 bits, never its 256 bytes
/// times eight (review 2026-11-24 B-5, 2026-11-23 C-20). Every size that cakeys checks or records
/// goes through this function.
#[must_use]
pub fn modulus_bits(n: &[u8]) -> u64 {
    let n = &n[n.iter().take_while(|b| **b == 0).count()..];
    n.first().map_or(0, |top| n.len() as u64 * 8 - u64::from(top.leading_zeros()))
}

/// The `CKR_*` return values that mean that the device, the token or the session failed, and not
/// that something in the requested operation failed (review 2026-11-24 E-2, phase1-design §2.5).
/// A refusal that cites one of them is not an answer from the module. The probe's rows, the
/// profile loader and the token crate's `device_failed` all decide by these names.
pub const DEVICE_FAILED_RV: [&str; 11] = [
    "CKR_DEVICE_ERROR",
    "CKR_DEVICE_MEMORY",
    "CKR_DEVICE_REMOVED",
    "CKR_HOST_MEMORY",
    "CKR_GENERAL_ERROR",
    "CKR_TOKEN_NOT_PRESENT",
    "CKR_TOKEN_NOT_RECOGNIZED",
    "CKR_SESSION_CLOSED",
    "CKR_SESSION_HANDLE_INVALID",
    "CKR_CRYPTOKI_NOT_INITIALIZED",
    "CKR_FUNCTION_CANCELED",
];

/// Returns whether the return value named `name` (`CKR_DEVICE_ERROR`) is one of
/// [`DEVICE_FAILED_RV`].
#[must_use]
pub fn is_device_failure(name: &str) -> bool {
    DEVICE_FAILED_RV.contains(&name)
}

/// Returns the first of [`DEVICE_FAILED_RV`] that `text` names as a whole name
/// (`CKR_DEVICE_ERROR`, never as a part of a longer `CKR_*`).
#[must_use]
pub fn names_device_failure(text: &str) -> Option<&'static str> {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    DEVICE_FAILED_RV.into_iter().find(|name| {
        text.match_indices(name).any(|(i, _)| !text[..i].ends_with(ident) && !text[i + name.len()..].starts_with(ident))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A modulus's size is the number of its significant bits. The test compares it with an
    /// independent count, the bits of the same bytes as a `u128`, for every length up to 16 bytes
    /// and every first byte, with leading zero bytes before it (review 2026-11-24 B-5: a count of
    /// whole bytes times eight gave 2048 for a 2047-bit modulus).
    #[test]
    fn a_modulus_counts_its_significant_bits() {
        for len in 0..=16usize {
            for top in 0..=u8::MAX {
                for zeros in 0..3 {
                    let mut n = vec![0u8; zeros];
                    n.extend(std::iter::once(top).chain(std::iter::repeat_n(0xa5, len.saturating_sub(1))).take(len));
                    let mut wide = [0u8; 16];
                    wide[16 - len..].copy_from_slice(&n[zeros..]);
                    let want = 128 - u64::from(u128::from_be_bytes(wide).leading_zeros());
                    assert_eq!(modulus_bits(&n), want, "{n:02x?}");
                }
            }
        }
        // The RSA sizes as a module reports them: 256 bytes whose first byte is 0x7f are 2047
        // bits.
        let modulus = |top: u8| [&[top][..], &[0xff; 255]].concat();
        assert_eq!(modulus_bits(&modulus(0x80)), 2048);
        assert_eq!(modulus_bits(&modulus(0x7f)), 2047);
        assert_eq!(modulus_bits(&modulus(0x01)), 2041);
    }

    /// Each table reads its entries back by their names, and each name belongs to one entry: no
    /// two curves, proofs or kinds share a name.
    #[test]
    fn every_name_reads_back_as_itself() {
        fn unique<T: Ord>(items: &[T]) -> bool {
            items.iter().collect::<std::collections::BTreeSet<_>>().len() == items.len()
        }
        for c in Curve::ALL {
            assert_eq!(Curve::from_name(c.name()), Some(c), "{c:?}");
        }
        assert_eq!(Curve::NAMES.to_vec(), Curve::ALL.map(Curve::name).to_vec());
        for p in Proof::ALL {
            assert_eq!(Proof::from_name(p.name()), Some(p), "{p:?}");
        }
        assert_eq!(Proof::NAMES.to_vec(), Proof::ALL.map(Proof::name).to_vec());
        for k in CommitKind::ALL {
            assert_eq!(CommitKind::from_name(k.name()), Some(k), "{k:?}");
        }
        assert!(unique(&Curve::ALL.map(Curve::name)) && unique(&Curve::ALL.map(Curve::display)));
        assert!(unique(&Curve::ALL.map(Curve::params)) && unique(&Proof::NAMES));
        assert!(unique(&CommitKind::ALL.map(CommitKind::name)) && unique(&DEVICE_FAILED_RV));
    }

    /// A curve is named by a `PrintableString` exactly where PKCS#11 3.0 allows it (not for a
    /// Weierstrass curve), and that string is the curve's name. ECDSA has a hash only on the
    /// Weierstrass curves, and cakeys-core has a key type for every curve except the Montgomery
    /// curves.
    #[test]
    fn each_curve_is_what_its_family_says() {
        for c in Curve::ALL {
            let printable = [&[0x13, u8::try_from(c.name().len()).unwrap()][..], c.name().as_bytes()].concat();
            let weierstrass = c.family() == Family::Weierstrass;
            assert_eq!(c.params_by_name().map(<[u8]>::to_vec), (!weierstrass).then_some(printable), "{c:?}");
            assert_eq!(HashAlg::for_curve(c).is_some(), weierstrass, "{c:?}");
            assert_eq!(c.in_core(), c.family() != Family::Montgomery, "{c:?}");
            // An OID starts with the tag 6 and its length.
            assert_eq!((c.params()[0], usize::from(c.params()[1])), (0x06, c.params().len() - 2), "{c:?}");
        }
    }

    /// The mechanism of a check value follows the key's cipher. The mechanism of every other kind
    /// depends only on the kind.
    #[test]
    fn a_check_value_runs_its_ciphers_ecb() {
        for k in [CommitKind::KcvEcb, CommitKind::KcvEcbDec] {
            assert_eq!(k.mechanism("CKK_DES3"), "CKM_DES3_ECB");
            assert_eq!(k.mechanism("CKK_AES"), "CKM_AES_ECB");
        }
        for k in CommitKind::ALL.into_iter().filter(|k| !matches!(k, CommitKind::KcvEcb | CommitKind::KcvEcbDec)) {
            assert_eq!(k.mechanism("CKK_DES3"), k.mechanism("CKK_AES"), "{k:?}");
        }
    }

    /// A device failure is found as a whole name in a row's evidence, never as the prefix of a
    /// longer `CKR_*`.
    #[test]
    fn a_device_failure_is_named_whole() {
        assert_eq!(names_device_failure("C_GenerateKeyPair: CKR_DEVICE_ERROR"), Some("CKR_DEVICE_ERROR"));
        assert_eq!(names_device_failure("CKR_DEVICE_ERRORS"), None);
        assert_eq!(names_device_failure("XCKR_DEVICE_ERROR"), None);
        assert_eq!(names_device_failure("CKR_MECHANISM_INVALID"), None);
        assert!(DEVICE_FAILED_RV.iter().all(|n| is_device_failure(n)) && !is_device_failure("CKR_OK"));
    }
}
