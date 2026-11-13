//! Built-in providers for modules whose quirks need no code of their own beyond detection and
//! advice. Modules with real fix-ups or native paths (ykcs11, tpm2-pkcs11) are provider crates.

use crate::provider::Provider;
use cakeys_core::config::ModuleInfo;

/// `SoftHSMv2`: the reference module. No quirks; registered so `provider = "softhsm"` can be
/// required explicitly and so it is reported by name.
pub struct SoftHsm;

impl Provider for SoftHsm {
    fn name(&self) -> &'static str {
        "softhsm"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer == "SoftHSM"
    }
}

/// p11-kit's client module (`p11-kit-client.so`), forwarding a token served by `p11-kit server`
/// over a socket: how real builds reach tokens. Observed with p11-kit 0.26.5:
///
/// - `C_GetInfo` describes p11-kit ("PKCS#11 Kit Proxy Module"), not the module behind it, so
///   that module's provider cannot be detected: name it with `provider = "..."` to apply its
///   fix-ups. `C_GetTokenInfo` is forwarded unchanged.
/// - The RPC only forwards mechanisms it can marshal: `CKM_AES_KEY_WRAP`, `CKM_AES_KEY_WRAP_PAD`,
///   `CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKM_EDDSA` (and `CKM_AES_CBC_ENCRYPT_DATA`) are dropped
///   from the mechanism list, so no `kw` commitment, no wrap-rebind and no Edwards keys.
/// - Login is per client connection: one client's `C_Login` does not log in another, so a build
///   that needs private objects still needs the PIN.
/// - The socket path must be short (`sun_path`, about 107 bytes); longer ones abort the server.
pub struct P11Kit;

impl Provider for P11Kit {
    fn name(&self) -> &'static str {
        "p11-kit"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer == "PKCS#11 Kit"
    }

    fn hint(&self) -> Option<&'static str> {
        Some(
            "the token is forwarded by p11-kit, whose RPC does not carry AES key wrap or EdDSA/Edwards mechanisms; the module behind it is hidden, so set `provider` to its provider for module-specific fix-ups",
        )
    }
}
