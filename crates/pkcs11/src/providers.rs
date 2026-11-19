//! Built-in providers for modules whose quirks need no code of their own beyond detection and
//! advice. Modules with real fix-ups or native paths (ykcs11, tpm2-pkcs11, kmsp11, aws-cloudhsm)
//! are provider crates; a module with no fix-ups and no advice needs neither: its profiles name and detect it
//! ([`crate::provider::Data`]).
//!
//! `softhsm` and `kryoptic` are such data providers. What was observed of them, with no code to
//! carry it:
//!
//! - `SoftHSMv2`: `CKM_RSA_PKCS_OAEP` implemented with SHA-1 only (SHA-256 is
//!   `CKR_ARGUMENTS_BAD`, docs/CAMIGRATE.md spike), recorded as its profile's `wrap.oaep`.
//! - kryoptic 1.5.4: Edwards `CKA_EC_POINT` is the raw point (3.2), or DER with
//!   `KRYOPTIC_EC_POINT_ENCODING=DER`, and cakeys reads both, to the same identity. Private keys
//!   carry `CKA_PUBLIC_KEY_INFO` of their own material, so a private key swapped under a locator
//!   fails the cross-check against the locked material (13) before the proof of possession.
//!   `C_GetInfo` reports library version 0.0, so provenance tells builds apart only by the module
//!   file and the token firmware (1.5). secp256k1 and the brainpool curves cannot be generated.

use crate::provider::Provider;
use cakeys_core::config::ModuleInfo;

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
