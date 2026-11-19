//! A key file an operator hands camigrate (docs/FILE.md): PEM, DER, PKCS#8 plain or encrypted,
//! PKCS#12, a secret key's value. Read or refused, never a panic, and a private key is read only
//! from a file the shape scan says holds one (`camigrate::fuzzing::key_file`).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|bytes: &[u8]| camigrate::fuzzing::key_file(bytes));
