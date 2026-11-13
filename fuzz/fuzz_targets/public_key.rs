//! Token bytes as a public key: an SPKI, an RSA modulus and exponent, or a curve point. Never a
//! panic, and a canonical SPKI is a fixed point.
#![no_main]

use cakeys_core::id::{self, Curve};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let fixed = |spki: Vec<u8>| assert_eq!(id::spki_canonical(&spki).unwrap(), spki);
    if let Ok(spki) = id::spki_canonical(data) {
        fixed(spki);
    }
    let (modulus, exponent) = data.split_at(data.len().saturating_sub(4));
    if let Ok(spki) = id::rsa_spki(modulus, exponent) {
        fixed(spki);
    }
    for curve in [
        Curve::P256,
        Curve::P384,
        Curve::P521,
        Curve::Secp256k1,
        Curve::BrainpoolP256r1,
        Curve::BrainpoolP384r1,
        Curve::Ed25519,
        Curve::Ed448,
    ] {
        if let Ok(spki) = curve.spki_from_point(data) {
            fixed(spki);
        }
    }
});
