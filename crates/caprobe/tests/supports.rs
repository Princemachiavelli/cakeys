//! `caprobe supports` (docs/CAPROBE.md): static answers from the capability profiles embedded in
//! the binary. No token and no keys.toml, so these run under a plain `cargo test` too. Yes is 0,
//! no 15, unknown 16. `checks.profiles` (checks.nix) asks the Nix-built binary the questions
//! whose answer depends on the patched binding.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;

fn supports(args: &[&str]) -> i32 {
    let out = tool(BIN).arg("supports").args(args).output().unwrap();
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
    // A key type every probed row refuses is no, never yes for want of a curve or size: the
    // swtpm profile's only Edwards rows are edwards25519 = no and edwards448 = no (it said yes).
    assert_eq!(supports(&["--profile", "tpm2-pkcs11/1.10+swtpm", "CKK_EC_EDWARDS"]), 15);
    assert_eq!(supports(&["--profile", "tpm2-pkcs11/1.10+swtpm", "CKK_EC"]), 0);
    // Between two sizes that generated only when no size between them was refused: swtpm
    // generates 1024, refuses 1536, generates 2048 and 3072: 2560 is yes, 1280 unknown (it was yes).
    assert_eq!(supports(&["--profile", "tpm2-pkcs11/1.10+swtpm", "--bits", "2560", "CKK_RSA"]), 0);
    assert_eq!(supports(&["--profile", "tpm2-pkcs11/1.10+swtpm", "--bits", "1280", "CKK_RSA"]), 16);
    assert_eq!(supports(&["--profile", "tpm2-pkcs11/1.10+swtpm", "--bits", "2048", "CKK_RSA"]), 0);
    // A PBKDF2 parameter set names no key type to generate: the profiles cannot decide it.
    assert_eq!(supports(&["--profile", "softhsm/2.7", "CKP_PKCS5_PBKD2_HMAC_SHA1"]), 16);
    // No module profile at all: only the binding layer and the baseline answer.
    assert_eq!(supports(&["CKM_SHA512_HMAC"]), 16);
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

/// `--token` asks about the profile keys.toml's token names by its `provider`; what cannot be
/// asked is refused (17), and every verb but `supports --profile` needs keys.toml.
#[test]
fn supports_asks_by_token_and_refuses_what_it_cannot_ask() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("supports-token");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("keys.toml");
    let tokens = "[tokens.soft]\ntokenLabel = \"t\"\nprovider = \"softhsm\"\n\n[tokens.bare]\ntokenLabel = \"b\"\n";
    std::fs::write(&config, tokens).unwrap();
    let ask = |args: &[&str]| {
        let out = tool(BIN).arg("--config").arg(&config).arg("supports").args(args).output().unwrap();
        (code(&out), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    assert_eq!(ask(&["--token", "soft", "secp256r1"]).0, 0);
    let refused = |args: &[&str], why: &str| {
        let (exit, said) = ask(args);
        assert!(exit == 17 && said.contains(why), "{args:?}: exit {exit}: {said}");
    };
    refused(&["--token", "nope", "secp256r1"], "unknown token 'nope'");
    refused(&["--token", "bare", "secp256r1"], "no provider named");
    refused(&["--token", "soft", "--class", "nope"], "no class 'nope'");

    // The token's own stack: its configured layers (`profiles`), and module profiles keys.toml's
    // `profileDirs` add, as token resolution and `cakeys validate` use them. `supports --token`
    // once left both out: yes from SoftHSM's profile behind p11-kit, and 17 for a profile only
    // `profileDirs` has.
    let proxied = "[tokens.proxied]\ntokenLabel = \"p\"\nprovider = \"softhsm\"\nprofiles = [\"p11-kit/0.26\"]\n";
    let tpm = "[tokens.tpm]\ntokenLabel = \"t\"\nprovider = \"tpm2-pkcs11\"\nprofiles = [\"swtpm\"]\n";
    std::fs::write(&config, format!("{tokens}\n{proxied}\n{tpm}")).unwrap();
    // The stack `validate` and `create`'s gate resolve (`gate::stack`, review D4): with no module
    // recorded, the hardware's rows decide nothing, so a size the swtpm profile generated is
    // unknown for the token, though asking the profile by name says yes. `supports --token` once
    // composed a stack of its own that took the profile whole, and said yes.
    let (exit, said) = ask(&["--token", "tpm", "--bits", "2048", "CKK_RSA"]);
    assert!(exit == 16 && said.contains("chosen by provider alone"), "exit {exit}: {said}");
    assert_eq!(ask(&["--profile", "tpm2-pkcs11/1.10+swtpm", "--bits", "2048", "CKK_RSA"]).0, 0);
    assert_eq!(ask(&["--token", "soft", "CKM_AES_KEY_WRAP"]).0, 0);
    // In the stack once, though the command line names it too.
    for args in [&["--token", "proxied"][..], &["--token", "proxied", "--layer", "p11-kit/0.26"]] {
        let (exit, said) = ask(&[args, &["CKM_AES_KEY_WRAP"]].concat());
        assert!(exit == 15 && said.contains("layers [cryptoki/0.12, p11-kit/0.26]"), "{args:?}: exit {exit}: {said}");
    }
    let profiles = dir.join("profiles");
    std::fs::create_dir_all(&profiles).unwrap();
    let committed = std::fs::read_to_string(committed_profile("modules/softhsm/2.7.toml")).unwrap();
    let renamed = committed.replacen("profile = \"softhsm/2.7\"", "profile = \"softhsm/2.7+site\"", 1);
    let subtract = "[subtract]\nmechanisms = [\"CKM_AES_KEY_WRAP\"]\n\n[match]\n";
    std::fs::write(profiles.join("site.toml"), renamed.replacen("[match]\n", subtract, 1)).unwrap();
    let site = "[tokens.site]\ntokenLabel = \"s\"\nprovider = \"softhsm\"\nmoduleProfile = \"softhsm/2.7+site\"\n";
    std::fs::write(&config, format!("profileDirs = [\"{}\"]\n\n{site}", profiles.display())).unwrap();
    let (exit, said) = ask(&["--token", "site", "CKM_AES_KEY_WRAP"]);
    assert!(exit == 15 && said.contains("softhsm/2.7+site"), "exit {exit}: {said}");
    assert_eq!(ask(&["--token", "site", "CKM_SHA512_HMAC"]).0, 0);

    // `caps` reads a token: without keys.toml it is a usage error.
    let out = tool(BIN).args(["caps", "--token", "soft"]).output().unwrap();
    assert_eq!(code(&out), 2, "{}", String::from_utf8_lossy(&out.stderr));
}
