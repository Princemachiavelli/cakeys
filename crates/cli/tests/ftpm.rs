//! End-to-end tests against the host's real TPM through tpm2-pkcs11 (nix/ftpm-test-env.sh), opt-in.
//!
//! Needs `CAKEYS_FTPM_MODULE` (`libtpm2_pkcs11.so`), `CAKEYS_FTPM_PROFILE` (the committed pair
//! profile of this TPM, e.g. `tpm2-pkcs11/1.10+amd-ftpm`) and the `TPM2_PKCS11_*` environment
//! of the harness, whose fresh store holds token `kmtest` (user PIN 1234). Skipped when
//! `CAKEYS_FTPM_MODULE` is unset — never in the Nix build. Run one test at a time
//! (`--test-threads=1`), and only through the harness:
//!
//! ```console
//! $ nix shell --inputs-from . nixpkgs#{tpm2-pkcs11,tpm2-tools,tpm2-abrmd,dbus}
//! $ bash nix/ftpm-test-env.sh up /tmp/ftpm && . /tmp/ftpm/env
//! $ CAKEYS_FTPM_MODULE=.../libtpm2_pkcs11.so CAKEYS_FTPM_PROFILE=tpm2-pkcs11/1.10+amd-ftpm \
//!     cargo test -p cakeys --test ftpm -- --test-threads=1
//! $ bash nix/ftpm-test-env.sh down /tmp/ftpm
//! ```
//!
//! Nothing here touches the TPM beyond that store: no persistent handle, no NV, no attestation
//! key (tpm2.rs's attestation tests make persistent ones, so they run on swtpm only), and no
//! wrong PIN (the dictionary-attack lockout is the whole TPM's).

mod common;

use common::*;
use std::fmt::Write as _;

struct Env {
    w: Workdir,
    module: String,
    profile: String,
}

impl std::ops::Deref for Env {
    type Target = Workdir;
    fn deref(&self) -> &Workdir {
        &self.w
    }
}

fn env(name: &str) -> Option<Env> {
    let (Ok(module), Ok(profile)) = (std::env::var("CAKEYS_FTPM_MODULE"), std::env::var("CAKEYS_FTPM_PROFILE")) else {
        eprintln!("skipping {name}: CAKEYS_FTPM_MODULE and CAKEYS_FTPM_PROFILE not both set");
        return None;
    };
    Some(Env { w: Workdir::new(&format!("ftpm-{name}")), module, profile })
}

impl Env {
    /// keys.toml: the suite's token ([`ftpm_tokens`]) and `body`.
    fn config(&self, body: &str) {
        self.write_config(&(ftpm_tokens(&self.module, &self.dir) + body));
    }
}

/// Each proof of possession on the real TPM, unattended: signing (P-256), deriving (P-384,
/// tpm2-pkcs11's extractable path, and in a read-write session for the read-only `verify`) and
/// decrypting (RSA-2048, OAEP). The resolved profile is this TPM's pair, not swtpm's.
#[test]
fn keys_generate_and_prove_possession_each_way() {
    let Some(e) = env("keys") else { return };
    let cases = [
        ("p256", "keyType = \"CKK_EC\"\ncurve = \"secp256r1\"", "CKA_SIGN = true", "pop-sign"),
        ("p384", "keyType = \"CKK_EC\"\ncurve = \"secp384r1\"", "CKA_DERIVE = true", "pop-ecdh"),
        ("rsa", "keyType = \"CKK_RSA\"\nmodulusBits = 2048", "CKA_DECRYPT = true", "pop-decrypt"),
    ];
    let mut body = String::new();
    for (n, object, attributes, binding) in cases {
        let _ = write!(
            body,
            "[objects.{n}]\nclass = \"CKO_PRIVATE_KEY\"\n{object}\n\n[specs.{n}]\nobject = \"{n}\"\n\
             attributes = {{ {attributes} }}\ntokens.ftpm = {{ locator = {{ CKA_LABEL = \"ftpm-{n}\" }}, \
             autoCreate = true, binding = \"{binding}\" }}\n\n"
        );
    }
    e.config(&body);
    for (n, _, _, binding) in cases {
        let o = e.km(&["realise", n, "--token", "ftpm", "--update-lock"]);
        assert_eq!(code(&o), 0, "{n}: {}", stderr(&o));
        assert_eq!(e.lock()["realisations"][n]["ftpm"]["binding"].as_str(), Some(binding), "{n}");
        let profile = e.observation(n, "ftpm")["profile"].clone();
        assert_eq!(profile.as_str(), Some(e.profile.as_str()), "the token resolves its own pair profile");
        let o = e.km(&["verify", n, "--token", "ftpm"]);
        assert_eq!(code(&o), 0, "{n}: {}", stderr(&o));
    }
    // What the profile says it cannot do is refused before anything is generated.
    e.config(
        "[objects.big]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 3072\n\n\
         [specs.big]\nobject = \"big\"\nattributes = { CKA_SIGN = true }\n\
         tokens.ftpm = { locator = { CKA_LABEL = \"ftpm-big\" }, autoCreate = true }\n",
    );
    assert_eq!(e.code(&["realise", "big", "--token", "ftpm", "--no-update-lock"]), 15);
}

/// `pop-unwrap` (a transport key's proof, MIGRATE.md D3) on the real TPM: tpm2-pkcs11 never
/// unwraps (`C_UnwrapKey` is `CKR_FUNCTION_NOT_SUPPORTED` [run], its profile's `unwraps =
/// false`), so an unwrap-only key is refused as unsupported (15) before anything is generated.
#[test]
fn unwrap_only_keys_cannot_prove_possession() {
    let Some(e) = env("unwrap") else { return };
    e.config(
        "[objects.u]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n\
         [specs.u]\nobject = \"u\"\nattributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = false }\n\
         tokens.ftpm = { locator = { CKA_LABEL = \"ftpm-unwrap\" }, autoCreate = true, binding = \"pop-unwrap\" }\n",
    );
    let o = e.km(&["realise", "u", "--token", "ftpm", "--update-lock"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("never unwraps") && !stderr(&o).contains("created"), "{}", stderr(&o));
}
