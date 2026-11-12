//! Orchestration of the `tpm-certify` attestation commitment (docs/DESIGN.md §3.7): find the
//! store row behind the PKCS#11 object, certify it natively, and cross-check everything the
//! module reports against what the TPM signed.

pub mod esys;
pub mod store;

use cakeys_pkcs11::provider::{AttestCtx, Attested};
use cakeys_core::{KmError, Result};
use cryptoki::object::{Attribute, AttributeType};
use std::path::PathBuf;

/// cakeys' Attestation Key, provisioned at this persistent handle on first attest when
/// `tokens.<t>.akHandle` does not name one. Deliberately outside the 0x81000001..0A range the
/// common tools take (tpm2-pkcs11's primary sits at 0x81000001); change it if yours collides.
pub const DEFAULT_AK_HANDLE: u32 = 0x8100_0016;

/// One hex-text attribute, shared by the store and the unsealed wrapping key.
pub fn store_hex(s: &str) -> Result<Vec<u8>> {
    store::hex(s)
}

/// The store directory, defaulting like tpm2-pkcs11 itself (`TPM2_PKCS11_STORE`, then
/// `~/.tpm2_pkcs11`, then `/etc/tpm2_pkcs11`).
fn store_dir(cfg: &AttestCtx<'_>) -> Result<PathBuf> {
    if let Some(dir) = &cfg.cfg.tpm2_store {
        return Ok(PathBuf::from(expand_home(dir)));
    }
    if let Ok(dir) = std::env::var("TPM2_PKCS11_STORE") {
        return Ok(PathBuf::from(dir));
    }
    if let Ok(home) = std::env::var("HOME") {
        let dir = PathBuf::from(home).join(".tpm2_pkcs11");
        if dir.is_dir() {
            return Ok(dir);
        }
    }
    let dir = PathBuf::from("/etc/tpm2_pkcs11");
    if dir.is_dir() {
        return Ok(dir);
    }
    Err(KmError::Unavailable(format!(
        "no tpm2-pkcs11 store for token '{}': set tokens.{}.tpm2Store, TPM2_PKCS11_STORE, or \
         ~/.tpm2_pkcs11",
        cfg.token_name, cfg.token_name
    )))
}

/// The leading `~` of a `tpm2Store` path, when the shell could not expand it.
fn expand_home(dir: &str) -> String {
    match dir.strip_prefix("~/") {
        Some(rest) => match std::env::var("HOME") {
            Ok(home) => format!("{home}/{rest}"),
            Err(_) => dir.to_owned(),
        },
        None => dir.to_owned(),
    }
}

/// The TCTI connection to the TPM the attestation path uses: the token's `tcti` config, else
/// the same TCTI the tpm2 tools use (`$TPM2TOOLS_TCTI`, then `$TCTI`). In tss-esapi syntax —
/// `"device:/dev/tpmrm0"`, `"tabrmd:bus_type=session"`, `"swtpm:port=2321"` — not the
/// library-path form some tool environments export.
fn tcti(cfg: &AttestCtx<'_>) -> Result<tss_esapi::Tcti> {
    match &cfg.cfg.tcti {
        Some(s) => s
            .parse()
            .map_err(|e| KmError::Validation(format!("tokens.{}.tcti = {s:?}: {e}", cfg.token_name))),
        None => tss_esapi::Tcti::from_environment_variable().map_err(|_| {
            KmError::Unavailable(format!(
                "no TCTI for the TPM attestation of token '{}': set tokens.{}.tcti \
                 (e.g. \"device:/dev/tpmrm0\" or \"tabrmd:bus_type=session\")",
                cfg.token_name, cfg.token_name
            ))
        }),
    }
}

/// The AK handle: explicit config, else cakeys' default.
fn ak_handle(cfg: &AttestCtx<'_>) -> Result<u32> {
    match &cfg.cfg.ak_handle {
        None => Ok(DEFAULT_AK_HANDLE),
        Some(s) => u32::from_str_radix(s.trim_start_matches("0x"), 16)
            .map_err(|e| KmError::Validation(format!("tokens.{}.akHandle = {s:?}: {e}", cfg.token_name))),
    }
}

/// Run the whole attestation: find the store row for the PKCS#11 object, certify the TPM
/// object it names, and cross-check the module's story against the TPM's signature.
pub fn attest(ctx: &AttestCtx<'_>) -> Result<Attested> {
    // The store row is found the way the module finds the object: by the locator's CKA_ID
    // (and label), within the key's class.
    let Some(Attribute::Id(cka_id)) = ctx
        .session
        .get_attributes(ctx.key, &[AttributeType::Id])
        .map_err(|e| KmError::Unavailable(format!("C_GetAttributeValue (CKA_ID): {e}")))?
        .into_iter()
        .next()
    else {
        return Err(KmError::Unsupported("the key object exposes no CKA_ID to find its store row by".into()));
    };
    let label = match ctx.session.get_attributes(ctx.key, &[AttributeType::Label]) {
        Ok(v) => match v.into_iter().next() {
            Some(Attribute::Label(l)) => Some(l),
            _ => None,
        },
        Err(_) => None,
    };
    let class = store::store_class(&ctx.object.class)?;
    let store = store::Store::open(&store_dir(ctx)?, &ctx.cfg.token_label)?;
    let tobj = store.find(&cka_id, label.as_deref(), class)?;
    let conf = tcti(ctx)?;
    let mut esys_ctx = esys::context(&conf)?;
    let certified = esys::certify_key(&mut esys_ctx, &store, tobj, ctx.pin.map(str::as_bytes), ak_handle(ctx)?, ctx.spki)?;
    // The module's immutables rest on TPMA_OBJECT bits the attestation signed: what the module
    // reports as CKA_LOCAL/CKA_EXTRACTABLE must be what the TPM certified (13, never a pass).
    let (local, extractable) = module_reports(ctx)?;
    if local != certified.local || extractable != certified.extractable {
        return Err(KmError::Conflict(format!(
            "the module reports CKA_LOCAL {} / CKA_EXTRACTABLE {}, but the TPM certified \
             {} / {}: the store does not match what the TPM holds",
            local, extractable, certified.local, certified.extractable
        )));
    }
    Ok(Attested {
        scheme: "tpm-certify",
        id: cakeys_core::id::tpm_certify_id(&certified.name, &certified.qualified_name),
        root: cakeys_core::id::sri(&certified.ak_spki),
    })
}

/// CKA_LOCAL and CKA_EXTRACTABLE of the live object, as the module reports them.
fn module_reports(ctx: &AttestCtx<'_>) -> Result<(bool, bool)> {
    let attrs = ctx
        .session
        .get_attributes(ctx.key, &[AttributeType::Local, AttributeType::Extractable])
        .map_err(|e| KmError::Unavailable(format!("C_GetAttributeValue (CKA_LOCAL/CKA_EXTRACTABLE): {e}")))?;
    let mut local = None;
    let mut extractable = None;
    for a in attrs {
        match a {
            Attribute::Local(b) => local = Some(b),
            Attribute::Extractable(b) => extractable = Some(b),
            _ => {}
        }
    }
    Ok((
        local.ok_or_else(|| KmError::Unavailable("the object exposes no CKA_LOCAL".into()))?,
        extractable.ok_or_else(|| KmError::Unavailable("the object exposes no CKA_EXTRACTABLE".into()))?,
    ))
}
