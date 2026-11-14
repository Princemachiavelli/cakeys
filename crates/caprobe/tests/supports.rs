//! `caprobe supports` (docs/CAPROBE.md): static answers from the capability profiles embedded in
//! the binary. No token and no keys.toml, so these run under a plain `cargo test` too. Yes is 0,
//! no 15, unknown 16. `checks.profiles` (checks.nix) asks the Nix-built binary the questions
//! whose answer depends on the patched binding.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;
use std::process::Command;

fn supports(args: &[&str]) -> i32 {
    let out = Command::new(BIN).arg("supports").args(args).output().unwrap();
    let said = (String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    eprintln!("$ caprobe supports {}\n  {} {}", args.join(" "), said.0.trim(), said.1.trim());
    code(&out)
}

/// The module profile decides; a layer's subtraction, a hardware pair and a class listing each
/// answer as the profiles record.
#[test]
fn supports_answers_from_the_embedded_profiles() {
    assert_eq!(supports(&["--profile", "softhsm/2.7", "CKM_SHA512_HMAC"]), 0);
    assert_eq!(supports(&["--profile", "softhsm/2.7", "secp256r1"]), 0);
    assert_eq!(supports(&["--profile", "softhsm/2.7", "--oaep"]), 0);
    assert_eq!(supports(&["--profile", "softhsm/2.7", "CKM_NOT_A_MECHANISM"]), 16);
    assert_eq!(supports(&["--profile", "softhsm/2.7", "--layer", "p11-kit/0.26", "CKM_AES_KEY_WRAP"]), 15);
    assert_eq!(supports(&["--profile", "kryoptic/1.5", "secp256k1"]), 15);
    assert_eq!(supports(&["--profile", "tpm2-pkcs11/1.10+swtpm", "--bits", "4096", "CKK_RSA"]), 15);
    // The same fact, factored out by hand into the swtpm layer.
    assert_eq!(supports(&["--profile", "tpm2-pkcs11", "--layer", "swtpm", "--bits", "4096", "CKK_RSA"]), 15);
    assert_eq!(supports(&["--class", "pq", "--profile", "softhsm/2.7"]), 15);
}

/// `--profiles <dir>` adds profiles to the embedded set: a layer of one's own subtracts.
#[test]
fn supports_reads_profiles_from_a_directory() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("supports-profiles");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let layer = "profile = \"mine\"\nmode = \"delta\"\n[subtract]\nmechanisms = [\"CKM_SHA512_HMAC\"]\n";
    std::fs::write(dir.join("layer.toml"), layer).unwrap();
    let with = ["--profile", "softhsm/2.7", "--layer", "mine", "--profiles", dir.to_str().unwrap(), "CKM_SHA512_HMAC"];
    assert_eq!(supports(&with), 15);
}
