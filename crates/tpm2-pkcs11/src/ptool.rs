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
pub fn import(ctx: &ImportCtx<'_>) -> Result<()> {
    let opts = Tpm2Options::of(ctx.token_name, &ctx.cfg.options)?;
    let store = store_dir_of(ctx.token_name, &opts)?;
    let pin = ctx.pin.ok_or_else(|| {
        KmError::Unavailable(format!(
            "tpm2_ptool import into '{}' needs the user PIN: configure pinFile or pinEnv",
            ctx.token_name
        ))
    })?;
    let (algorithm, contents) = match (ctx.object.class, ctx.object.key_type) {
        (ObjectClass::PrivateKey, Some(KeyType::Ec)) => ("ecc", pem(ctx.key)),
        (ObjectClass::PrivateKey, Some(KeyType::Rsa)) => ("rsa", pem(ctx.key)),
        (ObjectClass::SecretKey, Some(kt)) => {
            (hmac(kt).ok_or_else(|| unsupported(ctx))?, Zeroizing::new(ctx.key.to_vec()))
        }
        _ => return Err(unsupported(ctx)),
    };
    let (label, id) = (&ctx.locator.label, &ctx.locator.id);
    if label.is_none() && id.is_none() {
        return Err(KmError::Validation(format!(
            "{}: tpm2_ptool imports under CKA_LABEL or CKA_ID, and the locator names neither",
            ctx.token_name
        )));
    }
    // The key never touches a disk: an anonymous in-memory file, open in this process until the
    // tool is done, which (and whose children) open it through /proc.
    let fd = rustix::fs::memfd_create("cakeys-import", rustix::fs::MemfdFlags::CLOEXEC)
        .map_err(|e| KmError::Unavailable(format!("memfd_create: {e}")))?;
    let mut file = std::fs::File::from(fd);
    file.write_all(&contents).map_err(|e| KmError::Unavailable(format!("writing the in-memory key file: {e}")))?;
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
        _ => KmError::Unavailable(format!("running tpm2_ptool: {e}")),
    })?;
    drop(file);
    if !out.status.success() {
        let said = String::from_utf8_lossy(&out.stderr).replace(pin, "<pin>");
        return Err(KmError::Unavailable(format!("tpm2_ptool import into '{}': {}", ctx.token_name, said.trim())));
    }
    Ok(())
}

/// A PKCS#8 key as the PEM `tpm2_ptool` reads.
fn pem(der: &[u8]) -> Zeroizing<Vec<u8>> {
    use base64::Engine as _;
    let b64 = Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(der));
    let mut out = Zeroizing::new(b"-----BEGIN PRIVATE KEY-----\n".to_vec());
    for line in b64.as_bytes().chunks(64) {
        out.extend_from_slice(line);
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END PRIVATE KEY-----\n");
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
    KmError::Unsupported(format!(
        "tpm2_ptool imports EC and RSA private keys and HMAC keys, not a {} on '{}'",
        ctx.object.class, ctx.token_name
    ))
}
