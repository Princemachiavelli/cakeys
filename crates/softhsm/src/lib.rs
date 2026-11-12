//! SoftHSMv2: the reference module. No quirks; registered so `provider = "softhsm"` can be
//! required explicitly and so it is reported by name.

use cakeys_pkcs11::provider::Provider;
use cakeys_pkcs11::token::ModuleInfo;

pub struct SoftHsm;

impl Provider for SoftHsm {
    fn name(&self) -> &'static str {
        "softhsm"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer == "SoftHSM"
    }
}
