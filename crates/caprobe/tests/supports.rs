//! `caprobe supports` (docs/CAPROBE.md): static answers from the capability profiles embedded in
//! the binary. No token and no keys.toml, so these run under a plain `cargo test` too. Yes is 0,
//! no 15, unknown 16. `checks.profiles` (checks.nix) asks the Nix-built binary the questions
//! whose answer depends on the patched binding.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;

/// `caprobe supports <args>`: its exit, and what it said (the verdicts, then the notes).
fn supports(args: &[&str]) -> (i32, String) {
    let out = tool(BIN).arg("supports").args(args).output().unwrap();
    let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    eprintln!("$ caprobe supports {}\n  {}", args.join(" "), said.trim());
    (code(&out), said)
}

fn exit(args: &[&str]) -> i32 {
    supports(args).0
}

/// The module profile decides; a layer's subtraction, a hardware pair and a class listing each
/// answer as the profiles record.
#[test]
fn supports_answers_from_the_embedded_profiles() {
    assert_eq!(exit(&["--profile", "softhsm/2.7", "CKM_SHA512_HMAC"]), 0);
    assert_eq!(exit(&["--profile", "softhsm/2.7", "secp256r1"]), 0);
    assert_eq!(exit(&["--profile", "softhsm/2.7", "--oaep"]), 0);
    // Unknown to the profile, not for want of one: the profile consulted is named (review
    // supports.rs F2: a profile not found at all answers 16 too).
    let unknown = |args: &[&str], module: &str| {
        let (exit, said) = supports(args);
        assert!(exit == 16 && said.contains(&format!("profiles: module {module},")), "{args:?}: exit {exit}: {said}");
    };
    unknown(&["--profile", "softhsm/2.7", "CKM_NOT_A_MECHANISM"], "softhsm/2.7");
    assert_eq!(exit(&["--profile", "softhsm/2.7", "--layer", "p11-kit/0.26", "CKM_AES_KEY_WRAP"]), 15);
    assert_eq!(exit(&["--profile", "kryoptic/1.5", "secp256k1"]), 15);
    assert_eq!(exit(&["--profile", "tpm2-pkcs11/1.10+swtpm", "--bits", "4096", "CKK_RSA"]), 15);
    // The same fact, factored out by hand into the swtpm layer.
    assert_eq!(exit(&["--profile", "tpm2-pkcs11", "--layer", "swtpm", "--bits", "4096", "CKK_RSA"]), 15);
    assert_eq!(exit(&["--class", "pq", "--profile", "softhsm/2.7"]), 15);
    // A key type every probed row refuses is no, never yes for want of a curve or size: the
    // swtpm profile's only Edwards rows are edwards25519 = no and edwards448 = no (it said yes).
    assert_eq!(exit(&["--profile", "tpm2-pkcs11/1.10+swtpm", "CKK_EC_EDWARDS"]), 15);
    assert_eq!(exit(&["--profile", "tpm2-pkcs11/1.10+swtpm", "CKK_EC"]), 0);
    // Between two sizes that generated only when no size between them was refused: swtpm
    // generates 1024, refuses 1536, generates 2048 and 3072: 2560 is yes, 1280 unknown (it was yes).
    assert_eq!(exit(&["--profile", "tpm2-pkcs11/1.10+swtpm", "--bits", "2560", "CKK_RSA"]), 0);
    unknown(&["--profile", "tpm2-pkcs11/1.10+swtpm", "--bits", "1280", "CKK_RSA"], "tpm2-pkcs11/1.10+swtpm");
    assert_eq!(exit(&["--profile", "tpm2-pkcs11/1.10+swtpm", "--bits", "2048", "CKK_RSA"]), 0);
    // A PBKDF2 parameter set names no key type to generate: the profiles cannot decide it.
    unknown(&["--profile", "softhsm/2.7", "CKP_PKCS5_PBKD2_HMAC_SHA1"], "softhsm/2.7");
    // No module profile at all: only the binding layer and the baseline answer.
    unknown(&["CKM_SHA512_HMAC"], "(none)");
}

/// `--json` gives the verdicts the text gives, as `{name, verdict}` rows, with the same exit.
/// NAME, `--class` and `--oaep` each ask one question: two at once are a usage error (2).
/// `--bits` asks for an RSA size, so with any NAME but `CKK_RSA` it is refused (17), never
/// dropped (review 2026-11-23 D-16).
#[test]
fn supports_asks_one_question_and_answers_it_as_json_too() {
    let query = ["--profile", "softhsm/2.7", "--class", "hmac"];
    let text = tool(BIN).arg("supports").args(query).output().unwrap();
    let json = tool(BIN).args(["--json", "supports"]).args(query).output().unwrap();
    assert_eq!(code(&json), code(&text), "{}", String::from_utf8_lossy(&json.stderr));
    let rows: Vec<serde_json::Value> = serde_json::from_slice(&json.stdout).unwrap();
    let lines: Vec<String> =
        rows.iter().map(|r| format!("{}: {}", r["name"].as_str().unwrap(), r["verdict"].as_str().unwrap())).collect();
    assert_ne!(lines, Vec::<String>::new());
    assert_eq!(lines.join("\n"), String::from_utf8_lossy(&text.stdout).trim_end());
    assert_eq!(exit(&["--profile", "softhsm/2.7", "--class", "hmac", "CKM_SHA256_HMAC"]), 2);
    assert_eq!(exit(&["--profile", "softhsm/2.7", "--class", "hmac", "--oaep"]), 2);
    assert_eq!(exit(&["--profile", "softhsm/2.7", "--bits", "2048"]), 2);
    let (exit, said) = supports(&["--profile", "softhsm/2.7", "--bits", "2048", "CKK_EC"]);
    assert!(exit == 17 && said.contains("CKK_RSA"), "{exit}: {said}");
}

/// The layers `supports --layer`'s help names resolve, and the binding layer named explicitly
/// changes nothing: it is always applied, as the build decides (review 2026-11-23 D-7: the help
/// named `cryptoki/0.12-unpatched`, which no profile is).
#[test]
fn the_layers_the_help_names_resolve() {
    let help = tool(BIN).args(["supports", "--help"]).output().unwrap();
    let help = String::from_utf8_lossy(&help.stdout);
    assert!(!help.contains("unpatched"), "{help}");
    for (module, layer) in [("softhsm/2.7", "p11-kit/0.26"), ("tpm2-pkcs11", "swtpm")] {
        assert!(help.contains(layer), "{layer} not in\n{help}");
        assert_ne!(exit(&["--profile", module, "--layer", layer, "CKM_SHA256"]), 17, "{layer}");
    }
    let kwp = ["--profile", "softhsm/2.7", "CKM_AES_KEY_WRAP_KWP"];
    assert_eq!(supports(&[&kwp[..], &["--layer", "cryptoki/0.12"]].concat()), supports(&kwp));
}

/// `--profiles <dir>` adds profiles to the embedded set: a layer of one's own subtracts.
#[test]
fn supports_reads_profiles_from_a_directory() {
    // The test's own directory (review supports.rs F3: a fixed name, shared by no rule).
    let dir = Workdir::new("supports-profiles").dir;
    let layer = "profile = \"mine\"\nmode = \"delta\"\n[subtract]\nmechanisms = [\"CKM_SHA512_HMAC\"]\n";
    std::fs::write(dir.join("layer.toml"), layer).unwrap();
    let with = ["--profile", "softhsm/2.7", "--layer", "mine", "--profiles", dir.to_str().unwrap(), "CKM_SHA512_HMAC"];
    assert_eq!(exit(&with), 15);
}

/// `--token` asks about the profile keys.toml's token names by its `provider`; what cannot be
/// asked is refused (17), and every verb but `supports --profile` needs keys.toml.
#[test]
fn supports_asks_by_token_and_refuses_what_it_cannot_ask() {
    let dir = Workdir::new("supports-token").dir;
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
