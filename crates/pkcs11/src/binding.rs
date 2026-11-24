//! The cryptoki binding layer (docs/CAPROBE.md D3): the one layer between cakeys and every
//! module, named `cryptoki/0.12` and applied automatically. What it subtracts is decided at
//! run time — a binding with the key-type fix (the Nix patches, or the upstream PRs merged
//! and released) subtracts nothing, so the layer records the fix as soon as the implementation
//! carries it, and heals itself when upstream ships it.

use cakeys_profile::Profile;
use cryptoki::object::KeyType;
use std::os::raw::c_ulong;

/// The binding layer's profile name: the one layer in every stack.
pub const NAME: &str = "cryptoki/0.12";

/// The layer a patched binding resolves to: it subtracts nothing, and its note says why.
const PATCHED: &str = r#"
profile = "cryptoki/0.12"
mode = "delta"

[subtract]
mechanisms = ["CKM_AES_CFB128", "CKM_XEDDSA"]
note = "the pinned cryptoki has no name or parameter type for these, in any build"

[notes]
binding = "this build's cryptoki maps the SHA-2 HMAC key types correctly (the fix of upstream/rust-cryptoki, applied by the Nix build): the layer subtracts only what no build names"
CKM_AES_CFB128 = "the pinned cryptoki has no constant or parameter type for it; a module that lists it is recorded advertised and untested (docs/archive/CAPROBE_PROFILE_COVERAGE.md, Part 0)"
CKM_XEDDSA = "the pinned cryptoki has no constant or parameter type for it; a module that lists it is recorded advertised and untested (docs/archive/CAPROBE_PROFILE_COVERAGE.md, Part 0)"
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

/// Whether a module failure carries its `CK_RV` (`rv-value`): without it the code that branches
/// on a return value (the probe's busy-session handling) cannot tell one from another (review D3).
pub const RV_VALUE: bool = cfg!(feature = "rv-value");

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
    cakeys_profile::Set::active()?.find(NAME).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layer matches the binding it runs against: empty when patched (the Nix build's
    /// tests), the committed subtractions when not (a plain cargo build).
    #[test]
    fn layer_records_the_binding_it_runs_on() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let layer = layer().unwrap();
        assert_eq!(layer.profile, "cryptoki/0.12");
        // What no build of the binding names is subtracted either way.
        for m in ["CKM_AES_CFB128", "CKM_XEDDSA"] {
            assert!(layer.subtract.mechanisms.iter().any(|x| x == m), "{m}");
        }
        if patched() {
            assert!(layer.subtract.mechanisms.len() == 2 && layer.subtract.key_types.is_empty());
        } else {
            assert_eq!(layer.subtract.key_types.len(), 3);
        }
    }

    /// A patched binding (the Nix build's) is built with every feature that uses it, which each
    /// tool's `patched-cryptoki` turns on together (review D3): without `rv-value` the probe
    /// cannot tell a busy session from a refusal, and the feature without the patch would not
    /// compile.
    #[test]
    fn the_patched_binding_comes_with_its_features() {
        assert!(
            !patched() || RV_VALUE,
            "the patched cryptoki is linked without cakeys-pkcs11's `rv-value` (each tool's \
             `patched-cryptoki` feature; nix/package-common.nix features)"
        );
    }
}
