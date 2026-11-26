//! Built-in providers for modules whose quirks need no code of their own except detection and
//! advice. Modules with real fix-ups or native paths (ykcs11, tpm2-pkcs11, kmsp11, aws-cloudhsm)
//! have their own provider crates. A module with no fix-ups and no advice needs neither, because
//! its profiles name and detect it ([`crate::provider::Data`]).
//!
//! `softhsm` and `kryoptic` are such data providers. The following was observed of them, and no
//! code is needed for it:
//!
//! - `SoftHSMv2` implements `CKM_RSA_PKCS_OAEP` with SHA-1 only (SHA-256 returns
//!   `CKR_ARGUMENTS_BAD`, docs/CAMIGRATE.md spike). Its profile records this as `wrap.oaep`.
//! - In kryoptic 1.5.4, the Edwards `CKA_EC_POINT` is the raw point (3.2), or DER with
//!   `KRYOPTIC_EC_POINT_ENCODING=DER`. cakeys reads both forms and computes the same identity
//!   from them. Private keys carry a `CKA_PUBLIC_KEY_INFO` of their own material, so a private
//!   key that was swapped under a locator fails the cross-check against the locked material
//!   (exit 13) before the proof of possession. `C_GetInfo` reports the library version 0.0, so
//!   provenance can distinguish builds only by the module file and the token firmware (1.5).
//!   kryoptic cannot generate secp256k1 keys or keys on the brainpool curves.

use crate::provider::{Provider, Topic};
use cakeys_core::config::ModuleInfo;

/// p11-kit's client module (`p11-kit-client.so`), which forwards a token that `p11-kit server`
/// serves over a socket. Real builds reach tokens in this way. The following was observed with
/// p11-kit 0.26.5:
///
/// - `C_GetInfo` describes p11-kit ("PKCS#11 Kit Proxy Module") and not the module behind it, so
///   that module's provider cannot be detected. Name the provider with `provider = "..."` to
///   apply its fix-ups. `C_GetTokenInfo` is forwarded unchanged.
/// - The RPC forwards only the mechanisms that it can marshal. `CKM_AES_KEY_WRAP`,
///   `CKM_AES_KEY_WRAP_PAD`, `CKM_EC_EDWARDS_KEY_PAIR_GEN`, `CKM_EDDSA` (and
///   `CKM_AES_CBC_ENCRYPT_DATA`) are dropped from the mechanism list, so there is no `kw`
///   commitment, no wrap-rebind and no Edwards key.
/// - The login belongs to each client connection. One client's `C_Login` does not log in
///   another client, so a build that needs private objects still needs the PIN.
/// - The socket path must be short (`sun_path`, about 107 bytes), because a longer path makes
///   the server abort.
pub struct P11Kit;

impl Provider for P11Kit {
    fn name(&self) -> &'static str {
        "p11-kit"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer == "PKCS#11 Kit"
    }

    fn hint(&self, about: Topic) -> Option<&'static str> {
        // The advice covers the mechanisms that the RPC drops: a wrap, or the generation or the
        // signature of an Edwards key.
        matches!(about, Topic::Mechanism | Topic::Generate).then_some(
            "the token is forwarded by p11-kit, whose RPC does not carry AES key wrap or EdDSA/Edwards mechanisms; the module behind it is hidden, so set `provider` to its provider for module-specific fix-ups",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// p11-kit's advice names the mechanisms that its RPC drops, so a refused creation from a
    /// value gets no advice (review 2026-11-23 B-9).
    #[test]
    fn p11_kits_hint_is_about_mechanisms() {
        assert!(P11Kit.hint(Topic::Mechanism).is_some());
        assert!(P11Kit.hint(Topic::Generate).is_some());
        assert_eq!(P11Kit.hint(Topic::Create), None);
    }
}
