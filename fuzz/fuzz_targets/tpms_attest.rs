//! Bytes from the TPM, as the tpm-certify attestation reads them: a marshalled TPMS_ATTEST and a
//! TPM2B_PUBLIC (its Name and key material): read or refused with an error, never a panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| {
    let _ = cakeys_tpm2_pkcs11::attest::fuzzing::tpms_attest(bytes);
});
