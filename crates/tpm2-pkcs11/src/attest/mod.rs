//! Orchestration of the `tpm-certify` attestation commitment (docs/DESIGN.md §3.7): find the
//! store row behind the PKCS#11 object, certify it natively, and cross-check everything the
//! module reports against what the TPM signed.

pub mod esys;
pub mod store;

use cakeys_pkcs11::provider::{AttestCtx, Attested};
use cakeys_core::id::Scheme;
use cakeys_core::{KmError, Result};
use cryptoki::object::{Attribute, AttributeType};
use std::path::{Path, PathBuf};

/// cakeys' Attestation Key, provisioned at this persistent handle on first attest when
/// `tokens.<t>.akHandle` does not name one. Deliberately outside the 0x81000001..0A range the
/// common tools take (tpm2-pkcs11's primary sits at 0x81000001); change it if yours collides.
pub const DEFAULT_AK_HANDLE: u32 = 0x8100_0016;

/// One hex-text attribute, shared by the store and the unsealed wrapping key.
pub fn store_hex(s: &str) -> Result<Vec<u8>> {
    store::hex(s)
}

/// The store directory: `tokens.<t>.tpm2Store`, else the one tpm2-pkcs11 itself would open
/// (db.c `db_for_path`): `$TPM2_PKCS11_STORE` unconditionally, then the first of
/// `/etc/tpm2_pkcs11`, `$XDG_DATA_HOME/tpm2-pkcs11` (or `~/.local/share/tpm2-pkcs11`),
/// `~/.tpm2_pkcs11` and the working directory that holds a store file. Anything else could read
/// another store than the module the PKCS#11 object came from.
fn store_dir(cfg: &AttestCtx<'_>) -> Result<PathBuf> {
    if let Some(dir) = &cfg.cfg.tpm2_store {
        return Ok(PathBuf::from(expand_home(dir)));
    }
    if let Ok(dir) = std::env::var("TPM2_PKCS11_STORE") {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var("HOME").ok().map(PathBuf::from);
    let xdg = std::env::var("XDG_DATA_HOME")
        .ok()
        .map(|d| PathBuf::from(d).join("tpm2-pkcs11"))
        .or_else(|| home.as_ref().map(|h| h.join(".local/share/tpm2-pkcs11")));
    let candidates = [
        Some(PathBuf::from("/etc/tpm2_pkcs11")),
        xdg,
        home.map(|h| h.join(".tpm2_pkcs11")),
        std::env::current_dir().ok(),
    ];
    candidates
        .into_iter()
        .flatten()
        .find(|d| Path::new(d).join(store::DB_NAME).is_file())
        .ok_or_else(|| {
            KmError::Unavailable(format!(
                "no tpm2-pkcs11 store for token '{}': set tokens.{}.tpm2Store or TPM2_PKCS11_STORE",
                cfg.token_name, cfg.token_name
            ))
        })
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

/// A TCTI string in tss-esapi's `<name>:<conf>` syntax. The TCTI loader also accepts a library
/// name or path (`libtss2-tcti-tabrmd.so.0:bus_type=session`), which tool environments often
/// export; that form names the same TCTI, so it is reduced to `tabrmd:bus_type=session`.
fn normalize_tcti(s: &str) -> String {
    let (lib, conf) = s.split_once(':').unwrap_or((s, ""));
    let base = lib.rsplit('/').next().unwrap_or(lib);
    match base.strip_prefix("libtss2-tcti-").and_then(|b| b.split(".so").next()) {
        Some(name) => format!("{name}:{conf}"),
        None => s.to_owned(),
    }
}

/// The TCTI connection to the TPM the attestation path uses: the token's `tcti` config, else
/// the TCTI the module itself uses (`$TPM2_PKCS11_TCTI`), else the tpm2 tools' (`$TPM2TOOLS_TCTI`,
/// `$TCTI`). In tss-esapi syntax — `"device:/dev/tpmrm0"`, `"tabrmd:bus_type=session"`,
/// `"swtpm:port=2321"` — or a TCTI library name, which is reduced to it.
fn tcti(cfg: &AttestCtx<'_>) -> Result<tss_esapi::Tcti> {
    let (source, value) = match &cfg.cfg.tcti {
        Some(s) => (format!("tokens.{}.tcti", cfg.token_name), s.clone()),
        None => ["TPM2_PKCS11_TCTI", "TPM2TOOLS_TCTI", "TCTI"]
            .into_iter()
            .find_map(|var| std::env::var(var).ok().map(|v| (format!("${var}"), v)))
            .ok_or_else(|| {
                KmError::Unavailable(format!(
                    "no TCTI for the TPM attestation of token '{}': set tokens.{}.tcti \
                     (e.g. \"device:/dev/tpmrm0\" or \"tabrmd:bus_type=session\") or TPM2_PKCS11_TCTI",
                    cfg.token_name, cfg.token_name
                ))
            })?,
    };
    normalize_tcti(&value)
        .parse()
        .map_err(|e| KmError::Validation(format!("{source} = {value:?} is not a TCTI tss-esapi can open: {e}")))
}

/// The AK handle: explicit config (hex, `0x`-prefixed, a persistent handle in the owner range
/// 0x81000000..=0x817FFFFF), else cakeys' default.
fn ak_handle(cfg: &AttestCtx<'_>) -> Result<u32> {
    let Some(s) = &cfg.cfg.ak_handle else { return Ok(DEFAULT_AK_HANDLE) };
    let bad = |why: String| KmError::Validation(format!("tokens.{}.akHandle = {s:?}: {why}", cfg.token_name));
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| bad("must be hex with a 0x prefix, e.g. \"0x81000016\"".into()))?;
    let handle = u32::from_str_radix(hex, 16).map_err(|e| bad(e.to_string()))?;
    if !(0x8100_0000..=0x817F_FFFF).contains(&handle) {
        return Err(bad("not a persistent handle in the owner range 0x81000000..=0x817FFFFF".into()));
    }
    Ok(handle)
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
    let spki = ctx.required_spki()?;
    let class = store::store_class(ctx.object.class)?;
    let store = store::Store::open(&store_dir(ctx)?, &ctx.cfg.token_label)?;
    let tobj = store.find(&cka_id, label.as_deref(), class)?;
    let conf = tcti(ctx)?;
    let mut esys_ctx = esys::context(&conf)?;
    let certified = esys::certify_key(
        &mut esys_ctx,
        &store,
        tobj,
        ctx.pin.map(str::as_bytes),
        ak_handle(ctx)?,
        ctx.provision,
        spki,
    )?;
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
        scheme: Scheme::TpmCertify,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcti_library_names_reduce_to_their_tcti() {
        assert_eq!(normalize_tcti("libtss2-tcti-tabrmd.so.0:bus_type=session"), "tabrmd:bus_type=session");
        assert_eq!(normalize_tcti("/nix/store/x/lib/libtss2-tcti-swtpm.so:port=2321"), "swtpm:port=2321");
        assert_eq!(normalize_tcti("libtss2-tcti-device.so"), "device:");
        assert_eq!(normalize_tcti("device:/dev/tpmrm0"), "device:/dev/tpmrm0");
        assert_eq!(normalize_tcti("tabrmd:bus_type=session"), "tabrmd:bus_type=session");
    }
}
