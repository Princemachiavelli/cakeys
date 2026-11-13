//! Orchestration of the `tpm-certify` attestation commitment (docs/DESIGN.md §3.7): find the
//! store row behind the PKCS#11 object, certify it natively, and cross-check everything the
//! module reports against what the TPM signed.

pub mod esys;
pub mod store;

use cakeys_core::config::{Options, parse_options};
use cakeys_core::id::Scheme;
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::provider::{AttestCtx, Attested};
use cryptoki::object::{Attribute, AttributeType};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// cakeys' Attestation Key, provisioned at this persistent handle on first attest when
/// `tokens.<t>.options.akHandle` does not name one. Deliberately outside the 0x81000001..0A range the
/// common tools take (tpm2-pkcs11's primary sits at 0x81000001); change it if yours collides.
pub const DEFAULT_AK_HANDLE: u32 = 0x8100_0016;

/// One hex-text attribute, shared by the store and the unsealed wrapping key.
pub fn store_hex(s: &str) -> Result<Vec<u8>> {
    store::hex(s)
}

/// The tpm2-pkcs11 provider's `[tokens.<t>.options]`, for the native attestation path.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Tpm2Options {
    /// TCTI connection string for the native attestation path (`TPM2_Certify`),
    /// in tss-esapi `TctiNameConf` syntax (`"device:/dev/tpmrm0"`, `"tabrmd:bus_type=session"`)
    /// or a TCTI library name (`"libtss2-tcti-tabrmd.so.0:bus_type=session"`). Defaults to the
    /// module's own `$TPM2_PKCS11_TCTI`, then `$TPM2TOOLS_TCTI`, then `$TCTI`.
    tcti: Option<String>,
    /// Directory of the sqlite store backing the module, read (read-only) by
    /// the native attestation path to find the object's TPM blobs. Defaults to the store
    /// tpm2-pkcs11 itself opens: `$TPM2_PKCS11_STORE`, else the first of `/etc/tpm2_pkcs11`,
    /// `$XDG_DATA_HOME/tpm2-pkcs11` (`~/.local/share/tpm2-pkcs11`), `~/.tpm2_pkcs11` and the
    /// working directory that holds `tpm2_pkcs11.sqlite3`.
    tpm2_store: Option<String>,
    /// Persistent handle of cakeys' Attestation Key (a restricted signing key
    /// in the owner hierarchy, created by `realise` if absent, empty auth, and pinned in the
    /// lock by the `attestation.root` of the realisation). Defaults to the provider's
    /// `DEFAULT_AK_HANDLE`; `0x`-prefixed hex in 0x81000000..=0x817FFFFF, e.g. `"0x81000016"`.
    /// An object already there that is not such a key is refused (13).
    ak_handle: Option<String>,
}

impl Tpm2Options {
    /// Parse and check `token`'s options: unknown names and a malformed `akHandle` are invalid
    /// (17) when the token is opened, not first at attestation.
    pub fn of(token: &str, options: &Options) -> Result<Tpm2Options> {
        let o: Tpm2Options = parse_options(token, options)?;
        o.ak_handle(token)?;
        Ok(o)
    }

    /// The AK handle: explicit config (hex, `0x`-prefixed, a persistent handle in the owner range
    /// 0x81000000..=0x817FFFFF), else cakeys' default.
    fn ak_handle(&self, token: &str) -> Result<u32> {
        let Some(s) = &self.ak_handle else { return Ok(DEFAULT_AK_HANDLE) };
        let bad = |why: String| KmError::Validation(format!("tokens.{token}.options.akHandle = {s:?}: {why}"));
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
}

/// The store directory: `tokens.<t>.options.tpm2Store`, else the one tpm2-pkcs11 itself would open
/// (db.c `db_for_path`): `$TPM2_PKCS11_STORE` unconditionally, then the first of
/// `/etc/tpm2_pkcs11`, `$XDG_DATA_HOME/tpm2-pkcs11` (or `~/.local/share/tpm2-pkcs11`),
/// `~/.tpm2_pkcs11` and the working directory that holds a store file. Anything else could read
/// another store than the module the PKCS#11 object came from.
fn store_dir(cfg: &AttestCtx<'_>, opts: &Tpm2Options) -> Result<PathBuf> {
    if let Some(dir) = &opts.tpm2_store {
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
    candidates.into_iter().flatten().find(|d| Path::new(d).join(store::DB_NAME).is_file()).ok_or_else(|| {
        KmError::Unavailable(format!(
            "no tpm2-pkcs11 store for token '{}': set tokens.{}.options.tpm2Store or TPM2_PKCS11_STORE",
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
fn tcti(cfg: &AttestCtx<'_>, opts: &Tpm2Options) -> Result<tss_esapi::Tcti> {
    let (source, value) = match &opts.tcti {
        Some(s) => (format!("tokens.{}.options.tcti", cfg.token_name), s.clone()),
        None => ["TPM2_PKCS11_TCTI", "TPM2TOOLS_TCTI", "TCTI"]
            .into_iter()
            .find_map(|var| std::env::var(var).ok().map(|v| (format!("${var}"), v)))
            .ok_or_else(|| {
                KmError::Unavailable(format!(
                    "no TCTI for the TPM attestation of token '{}': set tokens.{}.options.tcti \
                     (e.g. \"device:/dev/tpmrm0\" or \"tabrmd:bus_type=session\") or TPM2_PKCS11_TCTI",
                    cfg.token_name, cfg.token_name
                ))
            })?,
    };
    normalize_tcti(&value)
        .parse()
        .map_err(|e| KmError::Validation(format!("{source} = {value:?} is not a TCTI tss-esapi can open: {e}")))
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
    let opts = Tpm2Options::of(ctx.token_name, &ctx.cfg.options)?;
    let store = store::Store::open(&store_dir(ctx, &opts)?, &ctx.cfg.token_label)?;
    let tobj = store.find(&cka_id, label.as_deref(), class)?;
    let conf = tcti(ctx, &opts)?;
    let mut esys_ctx = esys::context(&conf)?;
    let certified = esys::certify_key(
        &mut esys_ctx,
        &store,
        tobj,
        ctx.pin.map(str::as_bytes),
        opts.ak_handle(ctx.token_name)?,
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

/// `CKA_LOCAL` and `CKA_EXTRACTABLE` of the live object, as the module reports them.
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

    /// The provider's options are checked when the token opens: known names parse, a typo and a
    /// malformed AK handle are invalid (17), naming the token.
    #[test]
    fn options_are_checked_at_open() {
        let opts = |s: &str| Tpm2Options::of("tpm", &toml::from_str(s).unwrap());
        let o = opts("tcti = \"device:/dev/tpmrm0\"\ntpm2Store = \"~/s\"\nakHandle = \"0x81000017\"").unwrap();
        assert_eq!(o.ak_handle("tpm").unwrap(), 0x8100_0017);
        assert_eq!(opts("").unwrap().ak_handle("tpm").unwrap(), DEFAULT_AK_HANDLE);
        for (bad, why) in [
            ("tctl = \"x\"", "unknown field"),
            ("akHandle = \"81000017\"", "0x prefix"),
            ("akHandle = \"0x01\"", "owner range"),
        ] {
            let err = opts(bad).unwrap_err();
            assert!(
                matches!(&err, KmError::Validation(m) if m.contains("tokens.tpm.options") && m.contains(why)),
                "{bad}: {err}"
            );
        }
    }
}
