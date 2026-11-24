//! `check`: the key file it prints, `check --token` over a whole token, and a scheme the token
//! can never compute.

use super::*;

/// `check --format pkcs11-provider-pem` is the key file pkcs11-provider reads (docs/CAKEYS.md,
/// "The contract with programs"): OpenSSL loads it through the provider, its public key hashes to
/// the locked `rfc7093m4`, and it signs through the URI's `pin-source` (the PIN file ends in a
/// newline) and through its `pin-value`, each signature verifying under that public key with
/// OpenSSL alone. A key without `CKA_ID` gets its key file with a warning; what the output cannot
/// carry is refused before any token is opened.
#[test]
fn check_pem_is_a_key_file_for_pkcs11_provider() {
    let name = "check_pem_is_a_key_file_for_pkcs11_provider";
    let Some(e) = env(name) else { return };
    // pkcs11-provider's directory (`ossl-modules`): OpenSSL loads `-provider pkcs11` from it.
    let Some(provider_dir) = suite_var("CAKEYS_PKCS11_PROVIDER_DIR", REF.require_var, name) else { return };
    // A CKA_ID on both halves: pkcs11-provider finds a private key's public half by CKA_ID alone,
    // and SoftHSM's private EC key carries no public point (no CKA_EC_POINT, an empty
    // CKA_PUBLIC_KEY_INFO).
    e.config(
        &(EC.replace(r#"CKA_LABEL = "ec-lifecycle""#, r#"CKA_LABEL = "check-pem", CKA_ID = "c0""#) + PEM_REFUSALS),
    );
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    let locked = e.locked_id("signing", "rfc7093m4");

    let openssl = |args: &[&str]| {
        let out = Command::new("openssl").env("PKCS11_PROVIDER_MODULE", &e.module).args(args).output().unwrap();
        eprintln!("$ openssl {}\n  exit={:?}\n  stderr={}", args.join(" "), out.status.code(), stderr(&out).trim());
        assert!(out.status.success(), "openssl {}", args.join(" "));
    };
    // `default` first, as pkcs11-provider's own test configuration lists them: listed after it,
    // the PKCS#11 provider serves the module's own OpenSSL calls too (SoftHSM 2.7.0 then
    // deadlocks, SoftHSMv2 #834).
    let via_provider = ["-provider-path", provider_dir.as_str(), "-provider", "default", "-provider", "pkcs11"];
    let data = e.dir.join("data");
    std::fs::write(&data, b"signed through a cakeys key file").unwrap();
    let (public, data) = (e.dir.join("public.der"), data.to_str().unwrap());

    for (i, extra) in [&["--uri-pin", "source"][..], &["--uri-pin", "value", "--uri-module"]].into_iter().enumerate() {
        let out = e.km(&[&["check", "signing.id.rfc7093m4", "--format", "pkcs11-provider-pem"][..], extra].concat());
        assert_eq!(code(&out), 0);
        assert!(stdout(&out).starts_with("-----BEGIN PKCS#11 PROVIDER URI-----"), "{}", stdout(&out));
        assert!(!stderr(&out).contains("CKA_ID"), "{}", stderr(&out));
        let (pem, sig) = (e.dir.join(format!("key-{i}.pem")), e.dir.join(format!("sig-{i}")));
        std::fs::write(&pem, &out.stdout).unwrap();
        let (pem, sig) = (pem.to_str().unwrap(), sig.to_str().unwrap());

        let public = public.to_str().unwrap();
        openssl(&[&["pkey"][..], &via_provider, &["-in", pem, "-pubout", "-outform", "DER", "-out", public]].concat());
        assert_eq!(sri(&std::fs::read(public).unwrap()), locked, "the key file names another key");
        openssl(&[&["dgst", "-sha256"][..], &via_provider, &["-sign", pem, "-out", sig, data]].concat());
        openssl(&["dgst", "-sha256", "-verify", public, "-keyform", "DER", "-signature", sig, data]);
    }
    // The URI says what was asked for, and the plain check is still the bare locator.
    let value = stdout(&e.km(&["check", "signing", "--uri-pin", "value", "--uri-module"]));
    assert!(value.ends_with(&format!("?module-path={}&pin-value=1234", e.module)), "{value}");
    let source = stdout(&e.km(&["check", "signing", "--uri-pin", "source", "--format", "uri"]));
    assert!(source.ends_with(&format!("?pin-source=file:{}", e.dir.join("pin").display())), "{source}");
    assert!(!stdout(&e.km(&["check", "signing"])).contains('?'));

    // A key without CKA_ID (common among existing keys) still gets its key file, but is warned:
    // OpenSSL may get no public key from it.
    assert_eq!(e.code(&["create", "--spec", "signing-noid-soft", "--token", "ref"]), 22);
    let noid = e.km(&["check", "signing-noid", "--format", "pkcs11-provider-pem"]);
    assert_eq!(code(&noid), 0, "{}", stderr(&noid));
    assert!(stdout(&noid).starts_with("-----BEGIN PKCS#11 PROVIDER URI-----"), "{}", stdout(&noid));
    assert!(stderr(&noid).contains("'signing-noid' on 'ref' has no CKA_ID"), "{}", stderr(&noid));

    // A key file names a private key; a PIN needs a token that has one. Refused unopened, so
    // the anonymous public key below is never realised.
    assert_eq!(e.code(&["check", "signing-pub", "--format", "pkcs11-provider-pem"]), 15);
    assert_eq!(e.code(&["check", "signing-pub", "--uri-pin", "source"]), 17);
    assert_eq!(e.code(&["check", "signing-pub", "--uri-pin", "value"]), 17);
}

/// `--uri-pin source` names a `pinEnv` token's variable as `pin-source=env:`, as it names a
/// `pinFile` as `file:` (docs/CAKEYS.md, "The contract with programs"; review check.rs F3).
#[test]
fn a_pin_from_the_environment_is_a_pin_source_env() {
    let Some(e) = env("pin-env-uri") else { return };
    e.config(&EC.replace("ec-lifecycle", "pin-env-uri"));
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    let pin_file = format!("pinFile = \"{}\"", e.dir.join("pin").display());
    let text = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    assert!(text.contains(&pin_file), "{text}");
    e.write_config(&text.replacen(&pin_file, "pinEnv = \"CAKEYS_TEST_URI_PIN\"", 1));
    let pin = [("CAKEYS_TEST_URI_PIN", std::path::Path::new("1234"))];
    let o = e.km_env(&["check", "signing", "--uri-pin", "source", "--format", "uri"], &pin);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stdout(&o).trim_end().ends_with("?pin-source=env:CAKEYS_TEST_URI_PIN"), "{}", stdout(&o));
}

/// [`check_pem_is_a_key_file_for_pkcs11_provider`]'s other objects: a key located by label
/// alone, so without `CKA_ID`; and for the refusals, a public key on the token without a PIN.
const PEM_REFUSALS: &str = r#"
[objects.signing-noid]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.signing-noid-soft]
object = "signing-noid"
attributes = { CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
tokens.ref = { locator = { CKA_LABEL = "check-pem-noid" }, origin = "create" }

[objects.signing-pub]
class = "CKO_PUBLIC_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.signing-pub-anon]
object = "signing-pub"
tokens.ref-anon = { locator = { CKA_LABEL = "check-pem" }, origin = "adopt" }
"#;

#[test]
fn scheme_the_token_lacks_is_refused_before_create() {
    let Some(e) = env("token_lacks") else { return };
    // The same token through a module config that hides CKM_AES_CMAC.
    let (var, no_cmac) = e.hiding("CKM_AES_CMAC");
    let env = [(var, no_cmac.as_path())];
    e.config(
        r#"
[objects.k]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.k]
object = "k"
attributes = { CKA_SIGN = true, CKA_WRAP = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false }
tokens.ref = { locator = { CKA_LABEL = "no-cmac" }, origin = "create" }
"#,
    );
    // The spec allows cmac, but this token cannot compute it: refused, nothing created.
    assert_eq!(code(&e.km_env(&["check", "k.id.cmac"], &env)), 15);
    assert_eq!(e.session().labelled("no-cmac"), []);
    // kw is still available: check finds nothing (it never creates), `create` makes the key,
    // and its first use fails with its got: (TOFU: no locked hash yet).
    assert_eq!(code(&e.km_env(&["check", "k.id.kw"], &env)), 11);
    assert_eq!(code(&e.km_env(&["create", "--spec", "k", "--token", "ref", "--no-update-lock"], &env)), 18);
    assert_eq!(code(&e.km_env(&["check", "k.id.kw"], &env)), 18);
    let o = e.km_env(&["lock", "--spec", "k", "--token", "ref"], &env);
    assert_eq!(code(&o), 22);
    let ids = lock_result(&o);
    assert_eq!(ids["ids"].as_object().unwrap().keys().collect::<Vec<_>>(), ["kw"]);
    // The hiding config is what this run saw (the lock's observation records the mechanisms).
    let seen = e.observation("k", "ref")["mechanisms"].to_string();
    assert!(
        seen.contains("CKM_AES_KEY_WRAP\"") && !seen.contains("CKM_AES_CMAC\""),
        "config did not hide CMAC: {seen}"
    );
    // With CMAC back, the same key also yields cmac, linked through the locked kw.
    assert_eq!(e.code(&["lock", "--spec", "k", "--token", "ref"]), 22);
    assert!(e.lock()["objects"]["k"]["ids"].get("cmac").is_some());
    // A spec that allows cmac alone, verified where the token hides it: nothing to compute (15).
    let text = std::fs::read_to_string(e.dir.join("keys.toml")).unwrap();
    e.write_config(&format!(
        "{text}\n[specs.k-sign]\nobject = \"k\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.ref = {{ locator = {{ CKA_LABEL = \"no-cmac\" }}, origin = \"adopt\" }}\n"
    ));
    let o = e.km_env(&["check", "--spec", "k-sign", "--token", "ref"], &env);
    assert_eq!(code(&o), 15, "{}", stderr(&o));
    assert!(stderr(&o).contains("CKM_AES_CMAC"), "names what the token lacks: {}", stderr(&o));
}

/// [`check_token_checks_every_object_on_it`]'s objects: two keys on `ref`, a third added later.
const ON_TOKEN: &str = r#"
[objects.tok-a]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.tok-a-ref]
object = "tok-a"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "tok-a" }, origin = "create" }

[objects.tok-b]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.tok-b-ref]
object = "tok-b"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "tok-b" }, origin = "create" }
"#;

const ADDED_ON_TOKEN: &str = r#"
[objects.tok-c]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.tok-c-ref]
object = "tok-c"
attributes = { CKA_SIGN = true }
tokens.ref = { locator = { CKA_LABEL = "tok-c" }, origin = "create" }
"#;

/// `check --token` alone checks every object keys.toml places on the token, in one session:
/// all pass, and it prints the module file the check loaded; any fails, and stdout is empty,
/// each failure is on stderr led by its own exit code, and the run is 20. A token nothing is
/// placed on, and a flag that shapes a URI, are 17.
#[test]
fn check_token_checks_every_object_on_it() {
    let Some(e) = env("check_token") else { return };
    e.config(ON_TOKEN);
    assert_eq!(e.code(&["create"]), 22);
    let all = e.km(&["check", "--token", "ref"]);
    assert_eq!(code(&all), 0, "{}", stderr(&all));
    let module = stdout(&all);
    let module = module.trim_end();
    assert!(!module.is_empty() && !module.contains('\n'), "{module}");
    // The same file a URI's `module-path` names.
    let uri = stdout(&e.km(&["check", "tok-a", "--uri-module"]));
    assert!(uri.trim_end().ends_with(&format!("?module-path={module}")), "{uri} / {module}");

    // tok-b gone from the token though the lock pins it (11); tok-c there but pinned by nothing
    // (18). tok-a still passes and is not listed.
    e.config(&(ON_TOKEN.to_owned() + ADDED_ON_TOKEN));
    assert_eq!(e.code(&["create", "tok-c", "--no-update-lock"]), 18);
    // Gone from the token, the lock kept as it was: a delete that records it, then the lock put
    // back (no verb destroys without recording, review 2026-11-23 C-4).
    let pinned = std::fs::read(e.dir.join("keys.lock")).unwrap();
    assert_eq!(e.code(&["delete", "tok-b"]), 22);
    std::fs::write(e.dir.join("keys.lock"), pinned).unwrap();
    let failed = e.km(&["check", "--token", "ref"]);
    assert_eq!(code(&failed), 20, "{}", stderr(&failed));
    assert!(stdout(&failed).is_empty(), "{}", stdout(&failed));
    let err = stderr(&failed);
    assert!(err.contains("exit 11: 'tok-b' (spec 'tok-b-ref')"), "{err}");
    assert!(err.contains("exit 18: 'tok-c' (spec 'tok-c-ref')"), "{err}");
    assert!(!err.contains("'tok-a'"), "{err}");

    for args in [
        &["check", "--token", "ref", "--uri-module"][..],
        &["check", "--token", "ref", "--uri-pin", "source"],
        &["check", "--token", "ref", "--format", "pkcs11-provider-pem"],
        &["check", "--token", "ref-anon"],
        &["check", "--token", "nope"],
    ] {
        assert_eq!(e.code(args), 17, "{args:?}");
    }
}

/// `check --at` and `--ignore-validity` (ISSUES.md B8) hold a key's attestation chain to its
/// validity period at another time, or not at all (the chain itself: `attest.rs`'s
/// `check_holds_the_chain_to_its_dates`); a key with no attestation is checked as ever. A time
/// that is not RFC 3339 in UTC is invalid (17), and the two together are refused.
#[test]
fn check_judges_attestation_dates_at_the_time_asked() {
    let Some(e) = env("check_validity") else { return };
    e.config(&EC.replace("ec-lifecycle", "check-validity"));
    assert_eq!(e.code(&["create", "--spec", "signing-soft", "--token", "ref"]), 22);
    assert_eq!(e.code(&["check", "signing", "--at", "2030-01-01T00:00:00Z"]), 0);
    let o = e.km(&["check", "signing", "--ignore-validity"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("certificate dates are not checked"), "{}", stderr(&o));
    let o = e.km(&["check", "signing", "--at", "2030-01-01"]);
    assert_eq!(code(&o), 17, "{}", stderr(&o));
    assert!(stderr(&o).contains("not an RFC 3339 time in UTC"), "{}", stderr(&o));
    // A usage error (2), whatever clap's wording (review check.rs F2).
    let o = e.km(&["check", "signing", "--at", "2030-01-01T00:00:00Z", "--ignore-validity"]);
    assert_eq!(code(&o), 2, "{}", stderr(&o));
}
