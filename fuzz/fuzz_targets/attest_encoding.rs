//! The attestation encoding on any three fields: `tpm-certify`'s and `piv-attestation`'s framing
//! reads back to the fields, so two attestations hash the same input only when every field is
//! the same.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|fields: (&[u8], &[u8], &[u8])| {
    cakeys_core::fuzzing::attest_encoding_reads_back(fields.0, fields.1, fields.2);
});
