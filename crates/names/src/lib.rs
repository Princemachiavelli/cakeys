//! The tables more than one cakeys crate needs, each with one owner here (review 2026-11-24 item
//! 8, phase1-design §4): the named curves and the ECDSA hash of each, the proofs of possession,
//! the commitments and the mechanism each runs, an RSA modulus's size, and the return values that
//! say the device failed. Every other crate uses these or tests against them; none restates one.
//!
//! No dependencies, so the profile crate reads the tables without cakeys-core and core without
//! the profiles (docs/ARCHITECTURE.md). Mechanism names have their own source, `p11-names`, and
//! key types stay where they are kept as read (`cakeys_profile::KeyKind`).

/// The kind of curve, which names its PKCS#11 key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// `CKK_EC`: a short Weierstrass curve, for ECDSA and ECDH.
    Weierstrass,
    /// `CKK_EC_EDWARDS`: an Edwards curve, for `EdDSA`.
    Edwards,
    /// `CKK_EC_MONTGOMERY`: a Montgomery curve, for ECDH only.
    Montgomery,
}

/// A named curve: the Weierstrass and Edwards curves cakeys has a key type for, and the
/// Montgomery curves the probe measures and the profiles name, which keys.toml does not take yet
/// ([`Curve::in_core`]).
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
    /// Every named curve: Weierstrass, then Edwards, then Montgomery.
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

    /// Every curve's [`Curve::name`], in [`Curve::ALL`]'s order: the curve names a profile row
    /// or a query may use.
    pub const NAMES: [&'static str; 10] = {
        let mut names = [""; 10];
        let mut i = 0;
        while i < names.len() {
            names[i] = Curve::ALL[i].name();
            i += 1;
        }
        names
    };

    /// The canonical name: keys.toml's `curve`, the lock's, and a profile row's.
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

    /// The name a message gives it: `P-256`, `Ed25519`. keys.toml takes it as well.
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

    /// Its family, and so its key type.
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

    /// Whether cakeys-core has a key type for it, so keys.toml takes it (`cakeys_core::id::Curve`
    /// is these curves): every curve but the Montgomery ones, which only the probe generates.
    #[must_use]
    pub const fn in_core(self) -> bool {
        !matches!(self.family(), Family::Montgomery)
    }

    /// `CKA_EC_PARAMS` as the curve's DER OID (RFC 5480, RFC 8410): what a key is generated with.
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

    /// `CKA_EC_PARAMS` as a `PrintableString` of the name, which PKCS#11 3.0 allows for the
    /// Edwards and Montgomery curves; `None` for a Weierstrass curve.
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

    /// The curve of this canonical [`Curve::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<Curve> {
        Curve::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// A SHA-2 hash a signature is made over, which cakeys-core computes: ECDSA's on each
/// Weierstrass curve ([`HashAlg::for_curve`]), and an RSA PKCS#1 v1.5 or PSS signature's.
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
    /// The hash of ECDSA on `curve`, the one matching its strength (FIPS 186-5): what the token
    /// is asked to sign with and what the host verifies with, one table for both (review
    /// 2026-11-24 A-8). `None` for an Edwards curve, which hashes inside the signature, and a
    /// Montgomery one, which does not sign.
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

/// A proof of possession, by its name: the `binding` keys.toml and the lock write for it
/// (`cakeys_core::config::Binding`), and the `prove.<proof>` a capability row is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proof {
    /// `pop-sign`: the key signs a fresh challenge.
    PopSign,
    /// `pop-sign-pin`: `pop-sign` with the per-use PIN a `CKA_ALWAYS_AUTHENTICATE` key demands.
    PopSignPin,
    /// `pop-ecdh`: an ECDH secret `MACs` the challenge.
    PopEcdh,
    /// `pop-decrypt`: the key decrypts a host challenge.
    PopDecrypt,
    /// `pop-unwrap`: the key unwraps a host secret that `MACs` the challenge.
    PopUnwrap,
}

impl Proof {
    /// Every proof.
    pub const ALL: [Proof; 5] =
        [Proof::PopSign, Proof::PopSignPin, Proof::PopEcdh, Proof::PopDecrypt, Proof::PopUnwrap];

    /// Every proof's [`Proof::name`], in [`Proof::ALL`]'s order.
    pub const NAMES: [&'static str; 5] = {
        let mut names = [""; 5];
        let mut i = 0;
        while i < names.len() {
            names[i] = Proof::ALL[i].name();
            i += 1;
        }
        names
    };

    /// Its name.
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

    /// The proof of this [`Proof::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<Proof> {
        Proof::ALL.into_iter().find(|p| p.name() == name)
    }
}

/// A secret key's commitment, by the kind a `commit.<kind>.<key type>.<bytes>` row names it
/// (`cakeys_core::id::Commit::kind`): the scheme's name, an HMAC's hash beside it. A check
/// value's cipher is the key type's.
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
    /// One block encrypted in ECB: a key check value.
    KcvEcb,
    /// One block decrypted in ECB, for decrypt-only keys.
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

    /// Its name in a `commit.*` row.
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

    /// The kind of this [`CommitKind::name`].
    #[must_use]
    pub fn from_name(name: &str) -> Option<CommitKind> {
        CommitKind::ALL.into_iter().find(|k| k.name() == name)
    }

    /// The `CKM_*` the commitment runs on a key of `key_type` (`CKK_*`), which only a check
    /// value's cipher depends on: what a declared `CKA_ALLOWED_MECHANISMS` must hold for it, what
    /// the token is asked to run, and what a profile's `commit.*` row is measured with.
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

/// The size in bits of the unsigned big-endian integer `n`: an RSA modulus as `CKA_MODULUS` or
/// an SPKI holds it. Leading zero bytes count nothing and the first byte only its significant
/// bits, so a 2047-bit modulus is 2047, never its 256 bytes times eight (review 2026-11-24 B-5,
/// 2026-11-23 C-20). Every size cakeys checks or records goes through it.
#[must_use]
pub fn modulus_bits(n: &[u8]) -> u64 {
    let n = &n[n.iter().take_while(|b| **b == 0).count()..];
    n.first().map_or(0, |top| n.len() as u64 * 8 - u64::from(top.leading_zeros()))
}

/// The `CKR_*` return values that say the device, the token or the session failed, rather than
/// anything of the operation asked (review 2026-11-24 E-2, phase1-design §2.5): a refusal citing
/// one is no answer of the module's. The probe's rows, the profile loader and the token crate's
/// `device_failed` all decide by these names.
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

/// Whether the return value named `name` (`CKR_DEVICE_ERROR`) is one of [`DEVICE_FAILED_RV`].
#[must_use]
pub fn is_device_failure(name: &str) -> bool {
    DEVICE_FAILED_RV.contains(&name)
}

/// The first of [`DEVICE_FAILED_RV`] that `text` names, as a whole name
/// (`CKR_DEVICE_ERROR`, never a prefix of a longer `CKR_*`).
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

    /// A modulus's size is its significant bits, against an independent count: the same bytes
    /// as a `u128`'s, for every length up to 16 bytes and every first byte, with leading zero
    /// bytes before it (review 2026-11-24 B-5: whole bytes times eight said 2048 of a 2047-bit
    /// modulus).
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
        // The RSA sizes as a module reports them: 256 bytes whose first is 0x7f is 2047 bits.
        let modulus = |top: u8| [&[top][..], &[0xff; 255]].concat();
        assert_eq!(modulus_bits(&modulus(0x80)), 2048);
        assert_eq!(modulus_bits(&modulus(0x7f)), 2047);
        assert_eq!(modulus_bits(&modulus(0x01)), 2041);
    }

    /// Each table reads back by its names, and the names are each a table's own: no two curves,
    /// proofs or kinds share one.
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

    /// A curve is named by a `PrintableString` exactly where PKCS#11 3.0 allows it (not on a
    /// Weierstrass curve), and that string is its name; ECDSA has a hash on the Weierstrass
    /// curves only, and core has a key type for all but the Montgomery ones.
    #[test]
    fn each_curve_is_what_its_family_says() {
        for c in Curve::ALL {
            let printable = [&[0x13, u8::try_from(c.name().len()).unwrap()][..], c.name().as_bytes()].concat();
            let weierstrass = c.family() == Family::Weierstrass;
            assert_eq!(c.params_by_name().map(<[u8]>::to_vec), (!weierstrass).then_some(printable), "{c:?}");
            assert_eq!(HashAlg::for_curve(c).is_some(), weierstrass, "{c:?}");
            assert_eq!(c.in_core(), c.family() != Family::Montgomery, "{c:?}");
            // An OID: tag 6 and its length.
            assert_eq!((c.params()[0], usize::from(c.params()[1])), (0x06, c.params().len() - 2), "{c:?}");
        }
    }

    /// A check value's mechanism follows the key's cipher; every other kind's is the kind's.
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
