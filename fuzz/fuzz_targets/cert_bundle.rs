//! A user-named certificate file (`options.ekCertificate`, `ekRoots`) as `chain::certs_of`
//! reads it: PEM blocks split by hand, or one DER certificate. Never a panic; and every
//! certificate it yields walks to an anchor among the file's own, or is refused (review
//! 2026-11-23 A-18).
#![no_main]

use cakeys_core::chain::{self, Start};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(certs) = chain::certs_of(data) {
        for cert in &certs {
            let _ = chain::chain_to_anchor(cert, Start::EndEntity, &certs, &certs, None, 4);
        }
    }
});
