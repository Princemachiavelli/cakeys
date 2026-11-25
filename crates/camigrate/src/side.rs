//! A token's capabilities for moving keys (docs/CAMIGRATE.md D10): what it accepts, what its
//! profile probed, and the mechanisms it offers, built by [`crate::tokens::side`] from its
//! capability profile. camigrate's alone, so they are not in core (review 2026-11-23 A-6).

use cakeys_core::config::ObjectCfg;
use cakeys_core::migrate::OaepHash;
use cakeys_core::types::{KeyType, ObjectClass};
use std::collections::BTreeSet;

/// Which objects a capability covers: a class, and optionally only some key types, curves,
/// RSA sizes or secret-key lengths (empty: any).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Accept {
    /// The object class covered.
    pub(crate) class: ObjectClass,
    /// The key types covered (empty: any).
    pub(crate) key_types: Vec<KeyType>,
    /// The curves covered, by canonical name (empty: any).
    pub(crate) curves: Vec<&'static str>,
    /// Inclusive RSA modulus range in bits.
    pub(crate) modulus_bits: Option<(u32, u32)>,
    /// A secret key's length in bytes (`valueLen`).
    pub(crate) value_len: Option<u64>,
}

impl Accept {
    /// Every object of `class`.
    #[must_use]
    pub(crate) fn class(class: ObjectClass) -> Accept {
        Accept { class, key_types: vec![], curves: vec![], modulus_bits: None, value_len: None }
    }

    /// The objects of `class` with one of `key_types`.
    #[must_use]
    pub(crate) fn key(class: ObjectClass, key_types: &[KeyType]) -> Accept {
        Accept { key_types: key_types.to_vec(), ..Accept::class(class) }
    }

    /// Whether an object of type `ty` is one this capability covers.
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

/// What a probed row (`docs/archive/CAPROBE_MIGRATION.md`) answers for the objects it covers, and how
/// the operation succeeded where it has more than one way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Probed {
    /// The objects the row is about: one key type on one curve, size or length.
    pub(crate) covers: Accept,
    /// Its answer.
    pub(crate) yes: bool,
    /// How it succeeded: an import's path, an export's method.
    pub(crate) via: Option<String>,
    /// Why the probe could not decide it (`Profile::unknown`: a legacy no citing a device
    /// failure, an `[untested]` entry), naming the re-probe owed: a no that is not the module's.
    pub(crate) unknown: Option<String>,
}

impl Probed {
    /// Why a no of this row (`row`, as `unwrap.*`) refuses, for a plan's reason: unknown, and
    /// the re-probe owed, where the probe could not decide (phase1-design §9.1).
    pub(crate) fn said(&self, row: &str) -> String {
        self.unknown.clone().unwrap_or_else(|| format!("its {row} row says no"))
    }
}

/// A token's probed rows by way (`docs/archive/CAPROBE_MIGRATION.md`, M1): where one covers an object's
/// type it decides, before a module's claims and the spec-compliant default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ProbedWays {
    /// `import.*`: a plaintext key brought in.
    pub(crate) import: Vec<Probed>,
    /// `create.*`: a public object created from its value.
    pub(crate) create: Vec<Probed>,
    /// `export.host.*`: a key handed to the host.
    pub(crate) export_host: Vec<Probed>,
    /// `export.sealed.*`: a key wrapped toward another token.
    pub(crate) export_sealed: Vec<Probed>,
    /// `unwrap.*`: a wrapped key brought in.
    pub(crate) unwrap: Vec<Probed>,
}

impl ProbedWays {
    /// The row of `rows` that covers `ty`, if one does.
    #[must_use]
    pub(crate) fn of<'a>(rows: &'a [Probed], ty: &ObjectCfg) -> Option<&'a Probed> {
        rows.iter().find(|r| r.covers.covers(ty))
    }
}

/// How plaintext material gets into a token (the `host` paths).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PlaintextImport {
    /// `C_CreateObject` with the key's attributes (any PKCS#11 module that accepts it).
    CreateObject,
    /// `tpm2_ptool import`, for the listed objects.
    Tpm2Ptool(Vec<Accept>),
    /// ykcs11 `C_CreateObject` as SO into a PIV slot, for the listed objects.
    PivImport(Vec<Accept>),
}

/// One token's capabilities for moving keys, as its provider describes them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(clippy::struct_excessive_bools, reason = "independent capability claims of a module profile")]
pub(crate) struct Side {
    /// The token's name in keys.toml.
    pub(crate) token: String,
    /// The provider that handles it.
    pub(crate) provider: String,
    /// The usable mechanisms (provider-filtered), by `CKM_*` name.
    pub(crate) mechanisms: BTreeSet<String>,
    /// Whether the module ever wraps a key out (`C_WrapKey`).
    pub(crate) exports: bool,
    /// Whether the module unwraps a key in (`C_UnwrapKey`).
    pub(crate) unwraps: bool,
    /// Whether a secret key it unwraps reports its length (`CKA_VALUE_LEN`), which the import's
    /// type check reads: `SoftHSM` leaves it 0.
    pub(crate) secret_unwraps: bool,
    /// Whether a `CKA_WRAP_WITH_TRUSTED` key can leave toward a transport key the SO marked
    /// `CKA_TRUSTED` (`enforced`).
    pub(crate) trusted_wrap: bool,
    /// The OAEP hashes the module implements for wrapping, not only lists.
    pub(crate) oaep: Vec<OaepHash>,
    /// Public objects it accepts from their value or DER.
    pub(crate) public_import: Vec<Accept>,
    /// How plaintext private and secret keys get in, if at all.
    pub(crate) plaintext_import: Option<PlaintextImport>,
    /// Keys it takes in by no import at all, as a target (a profile's `migration.refuses`).
    pub(crate) refuses: Vec<Accept>,
    /// What its probed rows say, per object type: they decide before the claims above.
    pub(crate) probed: ProbedWays,
    /// Whether an ECDH proof of possession derives into a sealed secret here, as its module
    /// profile says (`derive.ecdh.sealed`); `None` when it does not.
    pub(crate) derive_sealed: Option<bool>,
    /// The attributes its module refuses in an unwrap template (`unwrap.refuse`), left out of an
    /// unwrapped key's.
    pub(crate) unwrap_refuse: Vec<String>,
    /// Whether it creates public key objects: an imported private key gets its public half beside
    /// it (not on PIV, which derives it from the slot).
    pub(crate) public_keys: bool,
}

impl Side {
    /// A spec-compliant PKCS#11 module: wraps and unwraps with what it lists, imports public
    /// objects and plaintext keys with `C_CreateObject`.
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

    /// Whether the token offers `mechanism` (a `CKM_*` name).
    #[must_use]
    pub(crate) fn has(&self, mechanism: &str) -> bool {
        self.mechanisms.contains(mechanism)
    }

    /// RFC 5649, under either PKCS#11 name (the same format, docs/CAMIGRATE.md spike).
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

    /// What a target accepts is every constraint it names at once: the class, then the key
    /// type, the curve and the modulus range where the row gives one; a row that gives none
    /// takes any.
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
        // A row of key types never takes an object that has none.
        assert!(!Accept::key(ObjectClass::Certificate, &[KeyType::Ec]).covers(&cert));

        let p256_only = Accept { curves: vec!["secp256r1"], ..Accept::key(private, &[KeyType::Ec]) };
        assert!(p256_only.covers(&p256));
        assert!(!p256_only.covers(&p384) && !p256_only.covers(&rsa(2048)));
        // A curve named without a key type still excludes what has no curve, or another class.
        let curve_only = Accept { curves: vec!["secp256r1"], ..Accept::class(private) };
        assert!(curve_only.covers(&p256) && !curve_only.covers(&rsa(2048)) && !curve_only.covers(&public));

        let sized = Accept { modulus_bits: Some((2048, 3072)), ..Accept::key(private, &[KeyType::Rsa]) };
        assert!(sized.covers(&rsa(2048)) && sized.covers(&rsa(3072)));
        assert!(!sized.covers(&rsa(1024)) && !sized.covers(&rsa(4096)));
        // A size range never takes an object that has no size.
        assert!(!Accept { modulus_bits: Some((0, u32::MAX)), ..Accept::class(private) }.covers(&p256));
    }

    /// A side offers the mechanisms it lists; RFC 5649 goes by either of its PKCS#11 names.
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
