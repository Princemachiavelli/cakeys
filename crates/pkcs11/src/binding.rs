//! The cryptoki binding layer (docs/CAPROBE.md D3). It is the one layer that sits between cakeys
//! and every module, it is named `cryptoki/0.12`, and it is applied automatically. What it
//! subtracts is decided at run time. A binding with the key-type fix (from the Nix patches, or
//! from the upstream PRs once they are merged and released) subtracts only the mechanisms that no
//! build of the binding names. So the layer records the fix as soon as the implementation has it,
//! and it needs no change when upstream releases the fix.

use cakeys_profile::Profile;
use cryptoki::object::KeyType;
use std::os::raw::c_ulong;

/// The profile name of the binding layer, which is the one layer in every stack.
pub const NAME: &str = "cryptoki/0.12";

/// The layer for a patched binding. It subtracts only the two mechanisms that no build of the
/// pinned cryptoki names (`CKM_AES_CFB128` and `CKM_XEDDSA`), and its notes say why.
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

/// Returns whether this build's cryptoki maps the SHA-2 HMAC key types correctly. cryptoki
/// 0.12.1 gives `SHA224/384/512_HMAC` the value of `CKK_SHA256_HMAC`, so such keys can be neither
/// created nor told apart (`token::key_type_of` refuses them in such a build). The Nix patch
/// fixes this. The same check also covers the KWP patch, which the Nix build applies together
/// with it, because an unpatched cryptoki has no `CKM_AES_KEY_WRAP_KWP` constant to check, and
/// the two upstream PRs are released together.
#[must_use]
pub fn patched() -> bool {
    c_ulong::from(KeyType::SHA224_HMAC) == 0x2e
        && c_ulong::from(KeyType::SHA384_HMAC) == 0x2c
        && c_ulong::from(KeyType::SHA512_HMAC) == 0x2d
}

/// Returns the cryptoki binding layer. For an unpatched binding, this is the committed list of
/// subtractions (profiles/layers/cryptoki.toml). When [`patched`] says that the fix is present,
/// it is the `PATCHED` layer, which subtracts only the mechanisms that no build names.
///
/// # Errors
///
/// The parse error of [`cakeys_profile::Set::embedded`] for the committed rows. An embedded
/// profile that no longer parses is a bug in the commit, and not a condition at run time.
pub fn layer() -> Result<Profile, String> {
    if patched() {
        return Profile::from_toml(PATCHED);
    }
    cakeys_profile::Set::active()?.find(NAME).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The layer matches the binding against which it runs. With a patched binding (the tests
    /// of the Nix build), it subtracts only the two mechanisms that no build names. With an
    /// unpatched binding (a plain cargo build), it is the committed list of subtractions.
    #[test]
    fn layer_records_the_binding_it_runs_on() {
        cakeys_profile::Set::activate_embedded().unwrap();
        let layer = layer().unwrap();
        assert_eq!(layer.profile, "cryptoki/0.12");
        // The mechanisms that no build of the binding names are subtracted in both cases.
        for m in ["CKM_AES_CFB128", "CKM_XEDDSA"] {
            assert!(layer.subtract.mechanisms.iter().any(|x| x == m), "{m}");
        }
        if patched() {
            assert!(layer.subtract.mechanisms.len() == 2 && layer.subtract.key_types.is_empty());
        } else {
            assert_eq!(layer.subtract.key_types.len(), 3);
        }
    }
}
