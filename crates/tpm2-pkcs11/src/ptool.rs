//! The plaintext import of tpm2-pkcs11 (docs/CAMIGRATE.md `tpm2-ptool`, phase 4): the module creates
//! keys from values only through `tpm2_ptool import`, a runtime dependency of this path.
//!
//! What it costs, said in every plan that uses it: the key reaches `tpm2_ptool`'s own Python
//! process, which cakeys cannot zeroize, through an in-memory file (`memfd`, named by cakeys'
//! own `/proc/<pid>/fd/N`, which the tool's own `tpm2_import` child can open too: it does not
//! inherit the descriptor; never a file on disk); and `tpm2_ptool` takes the user PIN only on its command
//! line (`--userpin`), where other local users can read it while it runs.

use crate::attest::{Tpm2Options, store_dir_of};
use cakeys_core::types::{KeyType, ObjectClass};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::provider::ImportCtx;
use std::io::Write as _;
use std::os::fd::AsRawFd as _;
use std::process::Command;
use zeroize::Zeroizing;

/// `tpm2_ptool import` of `ctx.key` into the token's store, under its locator.
///
/// # Errors
///
/// `Validation` for a locator with neither `CKA_LABEL` nor `CKA_ID`; `Unsupported` for a key
/// type the tool cannot import, or no `tpm2_ptool` on `PATH`; `Unavailable` without a user PIN,
/// or when the tool fails (its message, the PIN removed).
pub(crate) fn import(ctx: &ImportCtx<'_>) -> Result<()> {
    let opts = Tpm2Options::of(ctx.token_name, &ctx.cfg.options)?;
    let store = store_dir_of(ctx.token_name, &opts)?;
    let pin = ctx.pin.ok_or_else(|| {
        KmError::Unavailable(
            format!("tpm2_ptool import into '{}' needs the user PIN: configure pinFile or pinEnv", ctx.token_name)
                .into(),
        )
    })?;
    let (algorithm, contents) = match (ctx.object.class, ctx.object.key_type) {
        (ObjectClass::PrivateKey, Some(KeyType::Ec)) => ("ecc", pem(ctx.key)),
        (ObjectClass::PrivateKey, Some(KeyType::Rsa)) => ("rsa", pem(ctx.key)),
        (ObjectClass::SecretKey, Some(kt)) => {
            (hmac(kt).ok_or_else(|| unsupported(ctx))?, Zeroizing::new(ctx.key.to_vec()))
        }
        _ => return Err(unsupported(ctx)),
    };
    let label = &ctx.locator.label;
    if label.is_none() && ctx.locator.id.is_none() {
        return Err(KmError::Validation(
            format!("{}: tpm2_ptool imports under CKA_LABEL or CKA_ID, and the locator names neither", ctx.token_name)
                .into(),
        ));
    }
    let id = ctx.locator.id.as_deref().map(|hex| id_text(ctx.token_name, hex)).transpose()?;
    // The key never touches a disk: an anonymous in-memory file, open in this process until the
    // tool is done, which (and whose children) open it through /proc.
    let fd = rustix::fs::memfd_create("cakeys-import", rustix::fs::MemfdFlags::CLOEXEC)
        .map_err(|e| KmError::Unavailable(format!("memfd_create: {e}").into()))?;
    let mut file = std::fs::File::from(fd);
    file.write_all(&contents)
        .map_err(|e| KmError::Unavailable(format!("writing the in-memory key file: {e}").into()))?;
    drop(contents);
    let mut cmd = Command::new("tpm2_ptool");
    cmd.arg("import")
        .arg(format!("--label={}", ctx.cfg.token_label))
        .arg(format!("--userpin={pin}"))
        .arg(format!("--privkey=/proc/{}/fd/{}", std::process::id(), file.as_raw_fd()))
        .arg(format!("--algorithm={algorithm}"))
        .arg(format!("--path={}", store.display()));
    if let Some(l) = label {
        cmd.arg(format!("--key-label={l}"));
    }
    if let Some(i) = id {
        cmd.arg(format!("--id={i}"));
    }
    if let Some(tcti) = opts.tcti() {
        cmd.env("TPM2_PKCS11_TCTI", tcti).env("TPM2TOOLS_TCTI", tcti);
    }
    let out = cmd.output().map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            KmError::Unsupported("tpm2_ptool is not on PATH: the tpm2-ptool import needs it".into())
        }
        _ => KmError::Unavailable(format!("running tpm2_ptool: {e}").into()),
    })?;
    drop(file);
    if !out.status.success() {
        let said = String::from_utf8_lossy(&out.stderr);
        // An empty pattern matches between every character.
        let said = if pin.is_empty() { said.into_owned() } else { said.replace(pin, "<pin>") };
        return Err(KmError::Unavailable(
            format!("tpm2_ptool import into '{}': {}", ctx.token_name, said.trim()).into(),
        ));
    }
    Ok(())
}

/// The `--id` that makes `tpm2_ptool` store the `CKA_ID` the locator names (`hex`, the bytes in
/// hex). The tool stores the text it is given as the ID's bytes (`CKA_ID = hexlify(id.encode())`,
/// tpm2-pkcs11 1.10's `commandlets_keys.py`), so it is passed the text those bytes spell; bytes
/// that are no such text (not UTF-8, a NUL, none at all) cannot reach it, and are refused before
/// it runs.
fn id_text(token: &str, hex: &str) -> Result<String> {
    let refuse = |why: &str| {
        KmError::Validation(
            format!("{token}: tpm2_ptool takes CKA_ID as text, and the locator's CKA_ID '{hex}' {why}").into(),
        )
    };
    let bytes = cakeys_core::hex::decode(hex).ok_or_else(|| refuse("is not hex"))?;
    if bytes.is_empty() {
        return Err(refuse("is empty"));
    }
    let text = String::from_utf8(bytes).map_err(|_| refuse("is not UTF-8 text"))?;
    if text.contains('\0') {
        return Err(refuse("holds a NUL byte"));
    }
    Ok(text)
}

/// A PKCS#8 key as the PEM `tpm2_ptool` reads.
fn pem(der: &[u8]) -> Zeroizing<Vec<u8>> {
    use base64::Engine as _;
    let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(der));
    // At its final size from the start: growing it would free unzeroized copies of the key.
    let (head, tail) = (b"-----BEGIN PRIVATE KEY-----\n", b"-----END PRIVATE KEY-----\n");
    let mut out = Zeroizing::new(Vec::with_capacity(head.len() + b64.len() + b64.len() / 64 + 1 + tail.len()));
    out.extend_from_slice(head);
    for line in b64.as_bytes().chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(tail);
    out
}

/// `tpm2_ptool`'s algorithm for an HMAC key type.
fn hmac(kt: KeyType) -> Option<&'static str> {
    Some(match kt {
        KeyType::GenericSecret => "hmac",
        KeyType::Sha1Hmac => "hmac:sha1",
        KeyType::Sha256Hmac => "hmac:sha256",
        KeyType::Sha384Hmac => "hmac:sha384",
        KeyType::Sha512Hmac => "hmac:sha512",
        _ => return None,
    })
}

fn unsupported(ctx: &ImportCtx<'_>) -> KmError {
    KmError::Unsupported(
        format!(
            "tpm2_ptool imports EC and RSA private keys and HMAC keys, not a {} on '{}'",
            ctx.object.class, ctx.token_name
        )
        .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use cakeys_core::config::{Locator, ObjectCfg, parse_config_with};

    /// What the import refuses before `tpm2_ptool` runs: no PIN, a key the tool cannot import,
    /// a locator it has nothing to import under; and each HMAC key type's algorithm name. A
    /// run that fails says so without the PIN.
    #[test]
    fn imports_are_refused_before_the_tool_runs() {
        let text = "[tokens.t]\ntokenLabel = \"t\"\n[tokens.t.options]\ntpm2Store = \"/nonexistent/store\"\n";
        let cfg = parse_config_with(text, std::path::Path::new("keys.toml"), &|_| None).unwrap();
        let labelled = Locator { label: Some("k".into()), id: Some("6b".into()) };
        let nowhere = Locator { label: None, id: None };
        let ec = ObjectCfg::new(ObjectClass::PrivateKey, Some(KeyType::Ec));
        let run = |pin: Option<&str>, object: &ObjectCfg, locator: &Locator| {
            import(&ImportCtx { cfg: &cfg.tokens["t"], token_name: "t", pin, object, locator, key: b"not a key" })
        };
        let e = run(None, &ec, &labelled).unwrap_err();
        assert!(matches!(&e, KmError::Unavailable(m) if m.contains("needs the user PIN")), "{e}");
        for object in [
            ObjectCfg::new(ObjectClass::SecretKey, Some(KeyType::Aes)),
            ObjectCfg::new(ObjectClass::Certificate, None),
            ObjectCfg::new(ObjectClass::PrivateKey, Some(KeyType::EcEdwards)),
        ] {
            let e = run(Some("987654"), &object, &labelled).unwrap_err();
            assert!(matches!(&e, KmError::Unsupported(m) if m.contains("imports EC and RSA private keys")), "{e}");
        }
        let e = run(Some("987654"), &ec, &nowhere).unwrap_err();
        assert!(matches!(&e, KmError::Validation(m) if m.contains("names neither")), "{e}");
        // The tool itself, on a store that is not there (or no tool at all): a failure that
        // never repeats the PIN.
        let hmac_key = ObjectCfg::new(ObjectClass::SecretKey, Some(KeyType::Sha256Hmac));
        let e = run(Some("987654"), &hmac_key, &labelled).unwrap_err();
        assert!(
            matches!(e, KmError::Unavailable(_) | KmError::Unsupported(_)) && !e.to_string().contains("987654"),
            "{e}"
        );
        let names = [KeyType::GenericSecret, KeyType::Sha1Hmac, KeyType::Sha384Hmac, KeyType::Sha512Hmac].map(hmac);
        assert_eq!(names, [Some("hmac"), Some("hmac:sha1"), Some("hmac:sha384"), Some("hmac:sha512")]);
        assert_eq!(hmac(KeyType::Sha224Hmac), None);
        assert!(pem(&[0u8; 100]).starts_with(b"-----BEGIN PRIVATE KEY-----\n"));
    }

    /// `--id` is the text the locator's ID bytes spell, as the tool stores its text as the ID
    /// (the store fixture's `CKA_ID` "3061" is the text "0a"); an ID no text spells is refused
    /// before the tool runs, never imported under other bytes.
    #[test]
    fn the_id_is_passed_as_the_text_its_bytes_spell() {
        assert_eq!(id_text("t", "3061").unwrap(), "0a");
        assert_eq!(id_text("t", "6b6579").unwrap(), "key");
        assert_eq!(id_text("t", "C3A9").unwrap(), "é");
        assert_eq!(id_text("t", "0a01").unwrap(), "\n\u{1}");
        for (hex, why) in [("ff", "not UTF-8"), ("6b00", "NUL"), ("", "empty"), ("0", "not hex")] {
            let e = id_text("t", hex).unwrap_err();
            assert!(
                matches!(&e, KmError::Validation(m) if m.contains("takes CKA_ID as text") && m.contains(why)),
                "{hex}: {e}"
            );
        }
        // Refused in `import` itself, before the tool would run.
        let text = "[tokens.t]\ntokenLabel = \"t\"\n[tokens.t.options]\ntpm2Store = \"/nonexistent/store\"\n";
        let cfg = parse_config_with(text, std::path::Path::new("keys.toml"), &|_| None).unwrap();
        let ec = ObjectCfg::new(ObjectClass::PrivateKey, Some(KeyType::Ec));
        let locator = Locator { label: Some("k".into()), id: Some("ff".into()) };
        let e = import(&ImportCtx {
            cfg: &cfg.tokens["t"],
            token_name: "t",
            pin: Some("987654"),
            object: &ec,
            locator: &locator,
            key: b"not a key",
        })
        .unwrap_err();
        assert!(matches!(&e, KmError::Validation(m) if m.contains("not UTF-8")), "{e}");
    }
}
