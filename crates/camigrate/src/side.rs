//! A token's capabilities for moving keys (docs/CAMIGRATE.md D10): what it accepts, what its
//! profile probed, and the mechanisms it offers. [`crate::tokens::side`] builds them from the
//! token's capability profile. Only camigrate uses these types, so they are not in core (review
//! 2026-11-23 A-6).

use cakeys_core::config::ObjectCfg;
use cakeys_core::migrate::OaepHash;
use cakeys_core::types::{KeyType, ObjectClass};
use std::collections::BTreeSet;

/// The objects that a capability covers: a class, and optionally only some key types, curves, RSA
/// sizes or secret-key lengths. An empty constraint covers any value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Accept {
    /// The object class covered.
    pub(crate) class: ObjectClass,
    /// The key types covered. An empty list covers any key type.
    pub(crate) key_types: Vec<KeyType>,
    /// The curves covered, by canonical name. An empty list covers any curve.
    pub(crate) curves: Vec<&'static str>,
    /// The inclusive RSA modulus range in bits.
    pub(crate) modulus_bits: Option<(u32, u32)>,
    /// A secret key's length in bytes (`valueLen`).
    pub(crate) value_len: Option<u64>,
}

impl Accept {
    /// Returns a capability that covers every object of `class`.
    #[must_use]
    pub(crate) fn class(class: ObjectClass) -> Accept {
        Accept { class, key_types: vec![], curves: vec![], modulus_bits: None, value_len: None }
    }

    /// Returns a capability that covers the objects of `class` with one of `key_types`.
    #[must_use]
    pub(crate) fn key(class: ObjectClass, key_types: &[KeyType]) -> Accept {
        Accept { key_types: key_types.to_vec(), ..Accept::class(class) }
    }

    /// Returns whether this capability covers an object of type `ty`.
    #[must_use]
    pub(crate) fn covers(&self, ty: &ObjectCfg) -> bool {
        self.class == ty.class
            && (self.key_types.is_empty() || ty.key_type.is_some_and(|k| self.key_types.contains(&k)))
            && (self.curves.is_empty() || ty.curve.as_deref().is_some_and(|c| self.curves.contains(&c)))
            && match (self.modulus_bits, ty.modulus_bits) {
                (Some((lo, hi)), Some(bits)) => (u64::from(lo)..=u64::from(hi)).contains(&bits),
                (Some(_), None) => false,
                (None, _) => true,
            }
            && self.value_len.is_none_or(|n| ty.value_len == Some(n))
    }
}

/// The answer that a probed row (`docs/archive/CAPROBE_MIGRATION.md`) gives for the objects that it
/// covers, and how the operation succeeded when it has more than one way to succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Probed {
    /// The objects that the row is about: one key type with one curve, size or length.
    pub(crate) covers: Accept,
    /// The row's answer.
    pub(crate) yes: bool,
    /// How the operation succeeded: an import's path, or an export's method.
    pub(crate) via: Option<String>,
    /// The reason why the probe could not decide the row (`Profile::unknown`), such as a legacy
    /// "no" that cites a device failure, or an `[untested]` entry. It names the re-probe that is
    /// still needed. Such a "no" is not the module's own answer.
    pub(crate) unknown: Option<String>,
    /// Whether the row's "yes" rests only on the module's claim (`by = "unverified"`). The plan may
    /// use the row, and it defers the capability check to the run, which shows the result (review
    /// 2026-11-24 E-3, the part of P2 that was left over).
    pub(crate) unverified: bool,
}

impl Probed {
    /// Returns why a "no" of this row (`row`, such as `unwrap.*`) refuses, as a plan's reason.
    /// When the probe could not decide the row, the reason says that the answer is unknown and
    /// names the re-probe that is needed (phase1-design §9.1).
    pub(crate) fn said(&self, row: &str) -> String {
        self.unknown.clone().unwrap_or_else(|| format!("its {row} row says no"))
    }
}

/// A token's probed rows, grouped by the way of moving (`docs/archive/CAPROBE_MIGRATION.md`, M1).
/// When a row covers an object's type, the row decides, before the module's claims and before the
/// spec-compliant default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProbedWays {
    /// `import.*`: a plaintext key that is brought in.
    pub(crate) import: Vec<Probed>,
    /// `create.*`: a public object that is created from its value.
    pub(crate) create: Vec<Probed>,
    /// `export.host.*`: a key that is handed to the host.
    pub(crate) export_host: Vec<Probed>,
    /// `export.sealed.*`: a key that is wrapped toward another token.
    pub(crate) export_sealed: Vec<Probed>,
    /// `unwrap.*`: a wrapped key that is brought in.
    pub(crate) unwrap: Vec<Probed>,
}

impl ProbedWays {
    /// Returns the row of `rows` that covers `ty`, if one does.
    #[must_use]
    pub(crate) fn of<'a>(rows: &'a [Probed], ty: &ObjectCfg) -> Option<&'a Probed> {
        rows.iter().find(|r| r.covers.covers(ty))
    }
}

/// The way in which plaintext material gets into a token (the `host` paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlaintextImport {
    /// `C_CreateObject` with the key's attributes (for any PKCS#11 module that accepts it).
    CreateObject,
    /// `tpm2_ptool import`, for the listed objects.
    Tpm2Ptool(Vec<Accept>),
    /// The ykcs11 `C_CreateObject` as the SO into a PIV slot, for the listed objects.
    PivImport(Vec<Accept>),
}

/// One token's capabilities for moving keys, as its capability profiles describe them
/// ([`crate::tokens::side`]).
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(clippy::struct_excessive_bools, reason = "independent capability claims of a module profile")]
pub(crate) struct Side {
    /// The token's name in keys.toml.
    pub(crate) token: String,
    /// The provider that handles the token.
    pub(crate) provider: String,
    /// The usable mechanisms, as the provider and the profiles adjust them, by `CKM_*` name.
    pub(crate) mechanisms: BTreeSet<String>,
    /// Whether the module ever wraps a key out of the token (`C_WrapKey`).
    pub(crate) exports: bool,
    /// Whether the module unwraps a key into the token (`C_UnwrapKey`).
    pub(crate) unwraps: bool,
    /// Whether a secret key that the module unwraps reports its length (`CKA_VALUE_LEN`), which
    /// the import's type check reads. `SoftHSM` leaves the length at 0.
    pub(crate) secret_unwraps: bool,
    /// Whether a `CKA_WRAP_WITH_TRUSTED` key can leave toward a transport key that the SO marked
    /// `CKA_TRUSTED` (`enforced`).
    pub(crate) trusted_wrap: bool,
    /// The OAEP hashes that the module implements for wrapping, not only the hashes that it lists.
    pub(crate) oaep: Vec<OaepHash>,
    /// The public objects that the token accepts from their value or DER.
    pub(crate) public_import: Vec<Accept>,
    /// The way in which plaintext private and secret keys get into the token, if they can.
    pub(crate) plaintext_import: Option<PlaintextImport>,
    /// The keys that the token accepts by no import at all, as a target (a profile's
    /// `migration.refuses`).
    pub(crate) refuses: Vec<Accept>,
    /// The answers of the token's probed rows for each object type. They decide before the claims
    /// above.
    pub(crate) probed: ProbedWays,
    /// Whether an ECDH proof of possession derives into a sealed secret on this token, as its
    /// module profile says (`derive.ecdh.sealed`). It is `None` when the profile does not say.
    pub(crate) derive_sealed: Option<bool>,
    /// The attributes that the module refuses in an unwrap template (`unwrap.refuse`). They are
    /// left out of an unwrapped key's template.
    pub(crate) unwrap_refuse: Vec<String>,
    /// Whether the token creates public key objects. If it does, an imported private key gets its
    /// public half next to it. PIV does not, because it derives the public key from the slot.
    pub(crate) public_keys: bool,
}

impl Side {
    /// Returns the capabilities of a spec-compliant PKCS#11 module. Such a module wraps and unwraps
    /// with the mechanisms that it lists, and it imports public objects and plaintext keys with
    /// `C_CreateObject`.
    #[must_use]
    pub(crate) fn pkcs11(token: &str, provider: &str, mechanisms: impl IntoIterator<Item = String>) -> Side {
        Side {
            token: token.into(),
            provider: provider.into(),
            mechanisms: mechanisms.into_iter().collect(),
            exports: true,
            unwraps: true,
            secret_unwraps: true,
            trusted_wrap: true,
            oaep: vec![OaepHash::Sha1, OaepHash::Sha256],
            public_import: [ObjectClass::Certificate, ObjectClass::PublicKey, ObjectClass::Data]
                .into_iter()
                .map(Accept::class)
                .collect(),
            plaintext_import: Some(PlaintextImport::CreateObject),
            refuses: vec![],
            probed: ProbedWays::default(),
            derive_sealed: None,
            unwrap_refuse: vec![],
            public_keys: true,
        }
    }

    /// Returns whether the token offers `mechanism` (a `CKM_*` name).
    #[must_use]
    pub(crate) fn has(&self, mechanism: &str) -> bool {
        self.mechanisms.contains(mechanism)
    }

    /// Returns whether the token offers RFC 5649 key wrap under either of its PKCS#11 names, which
    /// produce the same format (docs/CAMIGRATE.md spike).
    #[must_use]
    pub(crate) fn kwp(&self) -> bool {
        self.has("CKM_AES_KEY_WRAP_KWP") || self.has("CKM_AES_KEY_WRAP_PAD")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(text: &str) -> ObjectCfg {
        toml::from_str(text).unwrap()
    }

    /// Checks that a capability requires every constraint that it names at once: the class, and
    /// the key type, the curve and the modulus range where the row gives one. A row that gives no
    /// constraint covers any value.
    #[test]
    fn an_accept_row_covers_what_meets_every_constraint_it_names() {
        let p256 = object("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"");
        let p384 = object("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"");
        let rsa =
            |bits: u32| object(&format!("class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = {bits}"));
        let public = object("class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"");
        let cert = object("class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"");
        let private = ObjectClass::PrivateKey;

        let any = Accept::class(private);
        assert!(any.covers(&p256) && any.covers(&rsa(2048)));
        assert!(!any.covers(&public) && !any.covers(&cert));

        let ec = Accept::key(private, &[KeyType::Ec]);
        assert_eq!(ec.key_types, [KeyType::Ec]);
        assert!(ec.covers(&p256) && ec.covers(&p384));
        assert!(!ec.covers(&rsa(2048)) && !ec.covers(&public));
        // A row of key types never covers an object that has no key type.
        assert!(!Accept::key(ObjectClass::Certificate, &[KeyType::Ec]).covers(&cert));

        let p256_only = Accept { curves: vec!["secp256r1"], ..Accept::key(private, &[KeyType::Ec]) };
        assert!(p256_only.covers(&p256));
        assert!(!p256_only.covers(&p384) && !p256_only.covers(&rsa(2048)));
        // A curve named without a key type still excludes an object that has no curve, or an
        // object of another class.
        let curve_only = Accept { curves: vec!["secp256r1"], ..Accept::class(private) };
        assert!(curve_only.covers(&p256) && !curve_only.covers(&rsa(2048)) && !curve_only.covers(&public));

        let sized = Accept { modulus_bits: Some((2048, 3072)), ..Accept::key(private, &[KeyType::Rsa]) };
        assert!(sized.covers(&rsa(2048)) && sized.covers(&rsa(3072)));
        assert!(!sized.covers(&rsa(1024)) && !sized.covers(&rsa(4096)));
        // A size range never covers an object that has no size.
        assert!(!Accept { modulus_bits: Some((0, u32::MAX)), ..Accept::class(private) }.covers(&p256));
    }

    /// Checks that a side offers the mechanisms that it lists, and that RFC 5649 is found under
    /// either of its PKCS#11 names.
    #[test]
    fn a_side_offers_what_it_lists() {
        let side = |mechanisms: &[&str]| Side::pkcs11("t", "p", mechanisms.iter().map(|m| (*m).to_owned()));
        let none = side(&["CKM_RSA_PKCS_OAEP"]);
        assert!(none.has("CKM_RSA_PKCS_OAEP") && !none.has("CKM_AES_KEY_WRAP_KWP") && !none.kwp());
        assert!(side(&["CKM_AES_KEY_WRAP_KWP"]).kwp());
        assert!(side(&["CKM_AES_KEY_WRAP_PAD"]).kwp());
        assert!(!side(&[]).has(""));
    }
}
