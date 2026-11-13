//! The static gate (docs/PROVIDERS.md phase 4): `validate` checks each spec's needs against its
//! token's capability profiles, resolved from keys.toml and the lock — no token, no module,
//! no environment needed, so these run everywhere.

mod common;

use common::*;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_cakeys");
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn validate(config: &str) -> Output {
    Command::new(BIN).arg("--config").arg(format!("{FIXTURES}/{config}")).arg("validate").output().unwrap()
}

/// PROVIDERS.md's two static-gate cases: kryoptic asked to generate secp256k1, and a `kw`
/// commitment through p11-kit, each refused (15) naming the profile that decided it; a token
/// nothing is known about is skipped with a note.
#[test]
fn a_profile_no_refuses_and_names_its_profile() {
    let out = validate("gate.toml");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code(&out), 15, "{err}");
    assert!(err.contains("'k1' (spec 'k1-kry')") && err.contains("no — kryoptic/1.5"), "{err}");
    assert!(err.contains("'aes' (spec 'aes-kw')") && err.contains("CKM_AES_KEY_WRAP: no — p11-kit/0.26"), "{err}");
    assert!(err.contains("token 'unknown': no provider named"), "{err}");
    // What the profiles allow passes silently: P-256 on kryoptic.
    assert!(!err.contains("'p256' (spec 'p256-kry') on token 'kry'"), "{err}");
}

/// The lock's recorded module and token are the profile source when keys.toml names no
/// provider: the fixture's `SoftHSM` realisations resolve softhsm/2.7, whose rows allow every
/// spec (generation it does not record is a note, never a refusal).
#[test]
fn the_lock_resolves_a_token_keys_toml_does_not_name() {
    let out = validate("keys.toml");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(code(&out), 0, "{err}");
    assert!(err.contains("generation not decided: unknown — module profile softhsm/2.7"), "{err}");
}
