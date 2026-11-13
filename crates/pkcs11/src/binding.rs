//! The cryptoki binding layer (docs/PROVIDERS.md D3): the one layer between cakeys and every
//! module, named `cryptoki/0.12` and applied automatically. What it subtracts is decided at
//! run time — a binding with the key-type fix (the Nix patches, or the upstream PRs merged
//! and released) subtracts nothing, so the layer records the fix as soon as the implementation
//! carries it, and heals itself when upstream ships it.

use cakeys_profile::Profile;
use cryptoki::object::KeyType;
use std::os::raw::c_ulong;

/// The layer a patched binding resolves to: it subtracts nothing, and its note says why.
const PATCHED: &str = r#"
profile = "cryptoki/0.12"
mode = "delta"

[notes]
binding = "this build's cryptoki maps the SHA-2 HMAC key types correctly (the fix of upstream/rust-cryptoki, applied by the Nix build): the layer subtracts nothing"
"#;

/// Whether this build's cryptoki maps the SHA-2 HMAC key types correctly. cryptoki 0.12.1
/// gives `SHA224/384/512_HMAC` the value of `CKK_SHA256_HMAC`, so such keys can be neither
/// created nor told apart (`token::key_type_of` refuses them in such a build); the Nix patch
/// fixes it. The same signal covers the KWP patch, which the Nix build applies with it: an
/// unpatched cryptoki has no `CKM_AES_KEY_WRAP_KWP` constant to probe, and the two upstream
/// PRs ship together.
#[must_use]
pub fn patched() -> bool {
    c_ulong::from(KeyType::SHA224_HMAC) == 0x2e
        && c_ulong::from(KeyType::SHA384_HMAC) == 0x2c
        && c_ulong::from(KeyType::SHA512_HMAC) == 0x2d
}

/// The cryptoki binding layer: the committed subtractions for an unpatched binding
/// (profiles/layers/cryptoki.toml), or an empty one when [`patched`] says the fix is in.
///
/// # Errors
///
/// [`cakeys_profile::Set::embedded`]'s parse error for the committed rows: an embedded profile
/// that no longer parses is a commit-time bug, not a runtime condition.
pub fn layer() -> Result<Profile, String> {
    if patched() {
        return Profile::from_toml(PATCHED);
    }
    cakeys_profile::Set::embedded()?.find("cryptoki/0.12").cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layer matches the binding it runs against: empty when patched (the Nix build's
    /// tests), the committed subtractions when not (a plain cargo build).
    #[test]
    fn layer_records_the_binding_it_runs_on() {
        let layer = layer().unwrap();
        assert_eq!(layer.profile, "cryptoki/0.12");
        if patched() {
            assert!(layer.subtract.mechanisms.is_empty() && layer.subtract.key_types.is_empty());
        } else {
            assert_eq!(layer.subtract.key_types.len(), 3);
        }
    }
}
