//! Yubico ykcs11 (YubiKey PIV). Its `CKA_PUBLIC_KEY_INFO` quirk (length 0, then
//! `CKR_ARGUMENTS_BAD`) is tolerated by the generic token code for every module.

use key_mgmnt_pkcs11::provider::Provider;
use key_mgmnt_pkcs11::token::ModuleInfo;

pub struct Ykcs11;

impl Provider for Ykcs11 {
    fn name(&self) -> &'static str {
        "ykcs11"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer.starts_with("Yubico")
    }
}
