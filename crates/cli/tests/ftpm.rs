//! Opt-in end-to-end tests against the host's real TPM through tpm2-pkcs11
//! (nix/ftpm-test-env.sh).
//!
//! The tests need `CAKEYS_FTPM_MODULE` (`libtpm2_pkcs11.so`), `CAKEYS_FTPM_PROFILE` (the committed
//! pair profile of this TPM, for example `tpm2-pkcs11/1.10+amd-ftpm`) and the `TPM2_PKCS11_*`
//! environment of the harness, whose fresh store holds the token `kmtest` (user PIN 1234). The
//! tests are skipped when neither variable is set (the Nix build never sets them), unless
//! `CAKEYS_FTPM_REQUIRE` is set. The two attestation tests are also skipped when
//! `CAKEYS_FTPM_ATTEST=1` is not set, unless `CAKEYS_FTPM_ATTEST_REQUIRE` is set. Run one test at
//! a time (`--test-threads=1`), and only through the harness:
//!
//! ```console
//! $ nix shell --inputs-from . nixpkgs#{tpm2-pkcs11,tpm2-tools,tpm2-abrmd,dbus}
//! $ bash nix/ftpm-test-env.sh up /tmp/ftpm && . /tmp/ftpm/env
//! $ CAKEYS_FTPM_MODULE=.../libtpm2_pkcs11.so CAKEYS_FTPM_PROFILE=tpm2-pkcs11/1.10+amd-ftpm \
//!     cargo test -p cakeys --test ftpm -- --test-threads=1
//! $ bash nix/ftpm-test-env.sh down /tmp/ftpm
//! ```
//!
//! Apart from the one Attestation Key at 0x81000016 that the opt-in attestation tests make,
//! nothing here touches the TPM beyond that store. The tests make no other persistent handle, no
//! NV index, and no other attestation key (tpm2.rs's attestation tests make persistent ones, so
//! they run on swtpm only). The tests also send no wrong PIN, because the dictionary-attack
//! lockout applies to the whole TPM.

mod common;

use common::*;
use std::fmt::Write as _;

/// Returns the suite for test `name` ([`ftpm_tokens`]) and the TPM's pair profile, or `None` when
/// the test is skipped.
fn env(name: &str) -> Option<(Suite, String)> {
    let [module, profile] = opted_in(name, FTPM_OPT_IN)?;
    Some((Suite::new(&format!("ftpm-{name}"), module, ftpm_tokens), profile))
}

/// Checks the attestation tests' own opt-in, `CAKEYS_FTPM_ATTEST=1` (these tests make the AK at
/// 0x81000016). When the variable is unset, test `name` is skipped ([`skip`]) unless
/// `CAKEYS_FTPM_ATTEST_REQUIRE` is set. Any value other than 1 fails (review 2026-11-24 C-7:
/// `=true` used to skip without a message, even under `CAKEYS_FTPM_REQUIRE`).
fn attest_asked(name: &str) -> bool {
    match std::env::var("CAKEYS_FTPM_ATTEST").as_deref() {
        Ok("1") => true,
        Ok(other) => panic!("{name}: CAKEYS_FTPM_ATTEST is {other:?}: 1 runs the attestation tests, unset skips them"),
        Err(_) => {
            skip(name, ATTEST_REQUIRE, "CAKEYS_FTPM_ATTEST=1 not set (it creates the AK at 0x81000016)");
            false
        }
    }
}

/// The variable that makes a run that skips the attestation tests fail. crates/test-skip.rs lists
/// it among the hardware variables.
const ATTEST_REQUIRE: &str = "CAKEYS_FTPM_ATTEST_REQUIRE";

/// Tests each proof of possession on the real TPM without user interaction: signing (P-256),
/// deriving (P-384, through tpm2-pkcs11's extractable path, and in a read-write session even for
/// the read-only `check`) and decrypting (RSA-2048, OAEP). The resolved profile is this TPM's pair
/// profile, not the swtpm profile.
#[test]
fn keys_generate_and_prove_possession_each_way() {
    let Some((e, pair)) = env("keys") else { return };
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
             attributes = {{ {attributes} }}\ntokens.ftpm = {{ locator = {{ CKA_LABEL = \"ftpm-{n}\" }}, origin = \"create\", \
             binding = \"{binding}\" }}\n\n"
        );
    }
    e.config(&body);
    for (n, _, _, binding) in cases {
        let o = e.km(&["create", "--spec", n, "--token", "ftpm"]);
        assert_eq!(code(&o), 0, "{n}: {}", stderr(&o));
        assert_eq!(e.lock()["realisations"][n]["ftpm"]["binding"].as_str(), Some(binding), "{n}");
        let profile = e.observation(n, "ftpm")["profile"].clone();
        assert_eq!(profile.as_str(), Some(pair.as_str()), "the token resolves its own pair profile");
        let o = e.km(&["check", "--spec", n, "--token", "ftpm"]);
        assert_eq!(code(&o), 0, "{n}: {}", stderr(&o));
    }
    // What the profile says it cannot do is refused before anything is generated.
    e.config(
        "[objects.big]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 3072\n\n\
         [specs.big]\nobject = \"big\"\nattributes = { CKA_SIGN = true }\n\
         tokens.ftpm = { locator = { CKA_LABEL = \"ftpm-big\" }, origin = \"create\" }\n",
    );
    assert_eq!(e.code(&["create", "--spec", "big", "--token", "ftpm", "--no-update-lock"]), 15);
}

/// `pop-unwrap` (a transport key's proof, docs/CAMIGRATE.md D3) on the real TPM: tpm2-pkcs11 never
/// unwraps (`C_UnwrapKey` returns `CKR_FUNCTION_NOT_SUPPORTED` \[run\], and its profile has
/// `unwraps = false`), so an unwrap-only key is refused as unsupported (15) before anything is
/// generated.
#[test]
fn unwrap_only_keys_cannot_prove_possession() {
    let Some((e, _)) = env("unwrap") else { return };
    e.config(
        "[objects.u]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048\n\n\
         [specs.u]\nobject = \"u\"\nattributes = { CKA_UNWRAP = true, CKA_EXTRACTABLE = false }\n\
         tokens.ftpm = { locator = { CKA_LABEL = \"ftpm-unwrap\" }, origin = \"create\", binding = \"pop-unwrap\" }\n",
    );
    let o = e.km(&["create", "--spec", "u", "--token", "ftpm"]);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("never unwraps") && !stderr(&o).contains("created"), "{}", stderr(&o));
}

/// `tpm-certify` on the real TPM (2026-11-14). The test needs two opt-ins. The harness store must
/// use the platform's storage root key as its parent (`ftpm-test-env.sh up <dir> persistent`,
/// which only reads that key), and `CAKEYS_FTPM_ATTEST=1` must be set, because the first run
/// makes the one persistent object that this suite may make: cakeys' Attestation Key at
/// 0x81000016 (owner hierarchy, empty auth). The key is trusted on first use, so it stays;
/// `tpm2_evictcontrol -C o -c 0x81000016` removes it. A generated P-256 key and an imported HMAC
/// key are certified, pinned and verified, and both resolve as a fresh proof.
#[test]
fn keys_attest_their_residence_on_the_real_tpm() {
    let Some((e, _)) = env("attest") else { return };
    if !attest_asked("attest") {
        return;
    }
    let hmac = e.dir.join("hmac.bin");
    std::fs::write(&hmac, [0x5au8; 32]).unwrap();
    ptool(&[
        "import",
        "--algorithm=hmac:sha256",
        &format!("--privkey={}", hmac.display()),
        "--key-label=ftpm-attest-hmac",
    ]);
    e.config(
        "[objects.p256]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.p256]\nobject = \"p256\"\nattributes = { CKA_SIGN = true }\n\
         tokens.ftpm = { locator = { CKA_LABEL = \"ftpm-attest-p256\" }, origin = \"create\", attestation = true }\n\n\
         [objects.hmac]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32\n\n\
         [specs.hmac]\nobject = \"hmac\"\nattributes = { CKA_SIGN = true, CKA_EXTRACTABLE = true }\n\
         tokens.ftpm = { locator = { CKA_LABEL = \"ftpm-attest-hmac\" }, origin = \"adopt\", attestation = true }\n",
    );
    // The P-256 key is generated; the HMAC key was imported above and is adopted.
    for (verb, spec) in [("create", "p256"), ("lock", "hmac")] {
        let o = e.km(&[verb, "--spec", spec, "--token", "ftpm"]);
        assert_eq!(code(&o), 0, "{spec}: {}", stderr(&o));
        let att = &e.lock()["realisations"][spec]["ftpm"]["attestation"];
        assert_eq!(att["kind"].as_str(), Some("tpm-certify"), "{spec}");
        assert_eq!(e.code(&["check", "--spec", spec, "--token", "ftpm"]), 0, "{spec}");
        let got: serde_json::Value =
            serde_json::from_str(&stdout(&e.km(&["resolve", "--spec", spec, "--token", "ftpm"]))).unwrap();
        assert_eq!(got["assurance"].as_str(), Some("proof"), "{spec}: {got}");
    }
    // One AK certifies both keys, so the same anchor is pinned next to each attestation.
    let root = |spec: &str| e.lock()["realisations"][spec]["ftpm"]["attestation"]["root"].clone();
    assert_eq!(root("p256"), root("hmac"));
}

/// `tpm-certify` anchored at the manufacturer (review D5). When `ekCertificate` names this TPM's
/// EK certificate and its intermediates (`CAKEYS_FTPM_EK_CERTIFICATE`, for example the AMD fTPM
/// bundle fetched for the development machine,
/// crates/tpm2-pkcs11/tests/fixtures/amd-ftpm-ek-ecc.pem), every attestation activates a
/// credential with the EK, and the lock pins the built-in AMD root to which the certificate
/// verifies, instead of the AK. The test needs `CAKEYS_FTPM_ATTEST=1`, as
/// [`keys_attest_their_residence_on_the_real_tpm`] does, because it uses the same AK. The EK is
/// recreated from the endorsement hierarchy (empty auth) and then flushed, so nothing else
/// persists.
#[test]
fn keys_attest_to_the_manufacturer_on_the_real_tpm() {
    let Some((e, _)) = env("attest-ek") else { return };
    // A set certificate asks for this test, which needs the AK, so without CAKEYS_FTPM_ATTEST=1
    // the test fails (C-7: it used to skip).
    let certificate = std::env::var("CAKEYS_FTPM_EK_CERTIFICATE").ok();
    let asked = attest_asked("attest-ek");
    assert!(asked || certificate.is_none(), "CAKEYS_FTPM_EK_CERTIFICATE is set, CAKEYS_FTPM_ATTEST=1 is not");
    let Some(certificate) = certificate.filter(|_| asked) else {
        if asked {
            skip("attest-ek", ATTEST_REQUIRE, "CAKEYS_FTPM_EK_CERTIFICATE not set");
        }
        return;
    };
    e.config(
        "[objects.p256]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.p256]\nobject = \"p256\"\nattributes = { CKA_SIGN = true }\n\
         tokens.ftpm = { locator = { CKA_LABEL = \"ftpm-attest-ek\" }, origin = \"create\", attestation = true }\n",
    );
    let toml = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    let with_ek = toml.replacen(
        "tokenLabel = \"kmtest\"\n",
        &format!("tokenLabel = \"kmtest\"\noptions = {{ ekCertificate = \"{certificate}\" }}\n"),
        1,
    );
    assert_ne!(with_ek, toml, "the token section names its label");
    std::fs::write(e.dir.join("keys.toml"), with_ek).unwrap();
    let o = e.km(&["create", "--spec", "p256", "--token", "ftpm"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    // The anchor is one of the built-in AMD fTPM roots (crates/tpm2-pkcs11/roots), not the AK.
    let att = &e.lock()["realisations"]["p256"]["ftpm"]["attestation"];
    let amd =
        ["sha256-iZucnW6SbECq776jkFFz8A97Uq1utNLTLm/LGXlxDis=", "sha256-XPGFn/vSzRjBM0XUdpK+pOokZPv7dCmDZPqXnoMyKfY="];
    assert!(att["root"].as_str().is_some_and(|r| amd.contains(&r)), "{att}");
    for verb in
        [&["check", "--spec", "p256", "--token", "ftpm"][..], &["check", "p256.id.tpm-certify", "--token", "ftpm"]]
    {
        let o = e.km(verb);
        assert_eq!(code(&o), 0, "{verb:?}: {}", stderr(&o));
    }
}
