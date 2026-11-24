//! Orchestration of the `tpm-certify` attestation commitment (docs/DESIGN.md §3.7): find the
//! store row behind the PKCS#11 object, certify it natively, and cross-check everything the
//! module reports against what the TPM signed.

pub(crate) mod credential;
pub(crate) mod ek;
pub(crate) mod esys;
pub(crate) mod store;
pub(crate) mod vendor;

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/tpm_store_row.rs`, `tpms_attest.rs`):
/// what the attestation path parses from the store and the TPM, on arbitrary input. Each is
/// read or refused with an error, never a panic.
#[cfg(any(test, feature = "fuzzing", kani))]
pub(crate) mod fuzzing {
    use cakeys_core::Result;

    /// A `tobjects.attrs` row and a `pobjects.config` row, both from `text`.
    ///
    /// # Errors
    ///
    /// Whatever the parsers refuse.
    pub fn store_row(text: &str) -> Result<()> {
        let object = super::store::parse_tobject(text);
        let parent = super::store::parse_parent(text, "");
        object.and(parent).map(drop)
    }

    /// `bytes` as a marshalled `TPMS_ATTEST` (its certify statement's Names), as a `TPM2B_PUBLIC`
    /// blob (its Name, and its key material) and as what `CKM_TPM2_CERTIFY` returns
    /// (`TPM2B_ATTEST ‖ TPMT_SIGNATURE`).
    ///
    /// # Errors
    ///
    /// Whatever the unmarshalling and the material extraction refuse.
    pub fn tpms_attest(bytes: &[u8]) -> Result<()> {
        use tss_esapi::structures::{Attest, AttestInfo};
        use tss_esapi::traits::UnMarshall as _;
        let _ = super::vendor::parse_output(bytes);
        if let Ok(attest) = Attest::unmarshall(bytes)
            && let AttestInfo::Certify { info } = attest.attested()
        {
            let _ = (info.name().value().len(), info.qualified_name().value().len());
        }
        super::esys::recompute_name(bytes)?;
        super::esys::material_of(&super::esys::unmarshal_public(bytes)?).map(drop)
    }
}

use cakeys_core::config::{Options, parse_options};
use cakeys_core::id::Scheme;
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::provider::{AttestCtx, Attested};
use cakeys_pkcs11::token::read_attribute;
use cryptoki::object::{Attribute, AttributeType};
use serde::Deserialize;
use std::path::PathBuf;

/// cakeys' Attestation Key, provisioned at this persistent handle on first attest when
/// `tokens.<t>.options.akHandle` does not name one. Deliberately outside the 0x81000001..0A range the
/// common tools take (tpm2-pkcs11's primary sits at 0x81000001); change it if yours collides.
pub(crate) const DEFAULT_AK_HANDLE: u32 = 0x8100_0016;

/// The tpm2-pkcs11 provider's `[tokens.<t>.options]`, for the native attestation path.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Tpm2Options {
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
    /// in the owner hierarchy, created by `lock` if absent, empty auth, and pinned in the
    /// lock by the `attestation.root` of the realisation, unless `ekCertificate` anchors it at
    /// the manufacturer). Defaults to the provider's
    /// `DEFAULT_AK_HANDLE`; `0x`-prefixed hex in 0x81000000..=0x817FFFFF, e.g. `"0x81000016"`.
    /// An object already there that is not such a key is refused (13).
    ak_handle: Option<String>,
    /// The TPM's endorsement key certificate: a PEM file of the certificate followed by its
    /// intermediates, or one DER certificate. With it, every attestation proves the AK resides in
    /// that TPM (a credential activated with the EK), and the lock pins the manufacturer root the
    /// certificate verifies to rather than the AK. It must verify to a built-in root (AMD fTPM)
    /// or to `ekRoots` (13). Without it, the certificate in the TPM's NV is used when one verifies;
    /// else the AK is trusted on first use.
    ek_certificate: Option<String>,
    /// More roots to verify EK certificates to: a PEM file of self-signed CA certificates (or one
    /// DER certificate), for a TPM manufacturer cakeys pins no root for.
    ek_roots: Option<String>,
    /// `CKA_LABEL` of an Attestation Key that is an object of the token, made by `lock` through
    /// the module's `CKM_TPM2_AK_PAIR_GEN` and used through `CKM_TPM2_CERTIFY_OBJECT`: then no
    /// TCTI, TPM handle or store is needed to attest. It is another key than the persistent one
    /// (`akHandle`), so a lock made with that one pins another `attestation.root`: choosing it
    /// is re-locking. Only for a module that lists those mechanisms (15 otherwise); not with
    /// `akHandle`.
    ak_label: Option<String>,
}

impl Tpm2Options {
    /// Parse and check `token`'s options: unknown names, a malformed `akHandle` and a `tcti`
    /// tss-esapi cannot read are invalid (17) when the token is opened, not first at attestation.
    ///
    /// # Errors
    ///
    /// `Validation` for an unknown option name or a `akHandle`/`tcti`/`tpm2Store` value
    /// that cannot be used.
    pub(crate) fn of(token: &str, options: &Options) -> Result<Tpm2Options> {
        let o: Tpm2Options = parse_options(token, options)?;
        o.ak_handle(token)?;
        o.tcti_conf(token)?;
        if let Some(label) = &o.ak_label {
            if o.ak_handle.is_some() {
                return Err(KmError::Validation(
                    format!("tokens.{token}.options: akLabel and akHandle name two Attestation Keys; set one").into(),
                ));
            }
            if label.is_empty() {
                return Err(KmError::Validation(format!("tokens.{token}.options.akLabel is empty").into()));
            }
        }
        Ok(o)
    }

    /// Refuse (15) `ekCertificate` and `ekRoots` for an attestation the module performs: the
    /// credential activation is cakeys' own, on the TPM, which that path does not open. Silently
    /// leaving the AK trusted on first use would pin a weaker anchor than the one asked for.
    ///
    /// # Errors
    ///
    /// `Unsupported` when either option is set.
    pub(crate) fn refuse_ek_for_module(&self, token: &str) -> Result<()> {
        if self.ek_certificate.is_some() || self.ek_roots.is_some() {
            return Err(KmError::Unsupported(
                format!(
                    "tokens.{token}.options.ekCertificate/ekRoots chain the Attestation Key to the TPM's \
                     manufacturer through the TPM itself (tcti); a module that certifies through its own \
                     vendor mechanisms (or akLabel) is attested without it"
                )
                .into(),
            ));
        }
        Ok(())
    }

    /// The configured TCTI in tss-esapi's syntax: the one parse the open's check and the
    /// attestation's connection share (review D8); `tpm2_ptool` is handed the string as written.
    fn tcti_conf(&self, token: &str) -> Result<Option<tss_esapi::Tcti>> {
        self.tcti.as_deref().map(|s| parse_tcti(&format!("tokens.{token}.options.tcti"), s)).transpose()
    }

    /// The configured TCTI, as written (for `tpm2_ptool`, which reads the same string).
    pub(crate) fn tcti(&self) -> Option<&str> {
        self.tcti.as_deref()
    }

    /// The AK handle: explicit config (hex, `0x`-prefixed, a persistent handle in the owner range
    /// 0x81000000..=0x817FFFFF), else cakeys' default.
    fn ak_handle(&self, token: &str) -> Result<u32> {
        let Some(s) = &self.ak_handle else { return Ok(DEFAULT_AK_HANDLE) };
        let bad = |why: String| KmError::Validation(format!("tokens.{token}.options.akHandle = {s:?}: {why}").into());
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
/// another store than the module the PKCS#11 object came from. For `token_name` (the
/// attestation's and the plaintext import's).
///
/// # Errors
///
/// `Unavailable` when no store is found.
pub(crate) fn store_dir_of(token_name: &str, opts: &Tpm2Options) -> Result<PathBuf> {
    if let Some(dir) = &opts.tpm2_store {
        return Ok(PathBuf::from(expand_home(dir)));
    }
    let env = |var: &str| std::env::var(var).ok();
    let candidates = store_candidates(env, std::env::current_dir().ok());
    if env("TPM2_PKCS11_STORE").is_some() {
        return Ok(candidates.into_iter().next().unwrap_or_default());
    }
    candidates.iter().find(|d| d.join(store::DB_NAME).is_file()).cloned().ok_or_else(|| {
        let searched: Vec<String> = candidates.iter().map(|d| d.display().to_string()).collect();
        KmError::Unavailable(
            format!(
                "no tpm2-pkcs11 store ({}) for token '{token_name}' in {}: set \
                 tokens.{token_name}.options.tpm2Store or TPM2_PKCS11_STORE",
                store::DB_NAME,
                searched.join(", ")
            )
            .into(),
        )
    })
}

/// The directories tpm2-pkcs11 1.10 looks for its store in, in its order (db.c
/// `db_for_path`), from the environment `var` gives and the working directory: only
/// `$TPM2_PKCS11_STORE` when set (taken whether or not it holds a store), else `/etc/tpm2_pkcs11`
/// (the module's build-time `TPM2_PKCS11_STORE_DIR`, which a distribution may change),
/// `$XDG_DATA_HOME/tpm2-pkcs11` or `~/.local/share/tpm2-pkcs11`, `~/.tpm2_pkcs11`, then the
/// working directory. A store read from another directory than the module's fails the
/// attestation's cross-checks, never passes them: `TPM2_Load` and the Name and SPKI checks bind
/// the row to the live object, and for a secret key the HMAC commitment the loaded object
/// computes again (`esys::Expected`).
fn store_candidates(var: impl Fn(&str) -> Option<String>, cwd: Option<PathBuf>) -> Vec<PathBuf> {
    if let Some(dir) = var("TPM2_PKCS11_STORE") {
        return vec![PathBuf::from(dir)];
    }
    let home = var("HOME").map(PathBuf::from);
    let xdg = var("XDG_DATA_HOME")
        .map(|d| PathBuf::from(d).join("tpm2-pkcs11"))
        .or_else(|| home.as_ref().map(|h| h.join(".local/share/tpm2-pkcs11")));
    [Some(PathBuf::from("/etc/tpm2_pkcs11")), xdg, home.map(|h| h.join(".tpm2_pkcs11")), cwd]
        .into_iter()
        .flatten()
        .collect()
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
    if let Some(t) = opts.tcti_conf(cfg.token_name)? {
        return Ok(t);
    }
    let (source, value) = ["TPM2_PKCS11_TCTI", "TPM2TOOLS_TCTI", "TCTI"]
        .into_iter()
        .find_map(|var| std::env::var(var).ok().map(|v| (format!("${var}"), v)))
        .ok_or_else(|| {
            KmError::Unavailable(
                format!(
                    "no TCTI for the TPM attestation of token '{}': set tokens.{}.options.tcti \
                     (e.g. \"device:/dev/tpmrm0\" or \"tabrmd:bus_type=session\") or TPM2_PKCS11_TCTI",
                    cfg.token_name, cfg.token_name
                )
                .into(),
            )
        })?;
    parse_tcti(&source, &value)
}

/// `value`, from `source`, as a TCTI tss-esapi opens ([`normalize_tcti`]).
fn parse_tcti(source: &str, value: &str) -> Result<tss_esapi::Tcti> {
    normalize_tcti(value)
        .parse()
        .map_err(|e| KmError::Validation(format!("{source} = {value:?} is not a TCTI tss-esapi can open: {e}").into()))
}

/// Run the whole attestation: certify the TPM object behind the PKCS#11 object and cross-check
/// the module's story against the TPM's signature. A module with `CKM_TPM2_CERTIFY` does the
/// certify itself ([`vendor`]); one without is read through its store and the TPM ([`esys`]).
///
/// # Errors
///
/// `Unsupported` for `akLabel` on a module without the token-key mechanisms, for an
/// `ekCertificate` with a module that certifies itself (the activation needs the TPM), and, on
/// the store path, for a module version it was not tested with and a key object with no `CKA_ID`
/// to find its store row by; `Unsupported` too for a secret key that cannot be bound to the
/// object certified ([`expected`]), and for any secret key through the module's own certify;
/// `Unavailable` when the store cannot be opened, the TPM or the
/// module's mechanism fails, or the object's module attributes cannot be read; `Conflict` when
/// the module's story and the TPM's signature disagree; plus whatever the certify rejects (PIN,
/// auth, names, material cross-check or commitment, the EK's credential).
pub(crate) fn attest(ctx: &AttestCtx<'_>) -> Result<Attested> {
    let opts = Tpm2Options::of(ctx.token_name, &ctx.cfg.options)?;
    let route = vendor::route(ctx, &opts)?;
    // A token object as the signer (`akLabel`): its public area and its restricted, fixedTPM
    // attributes are what the module reports, never read from the TPM, so a module with no TPM
    // behind it could sign any statement (review 2026-11-23 B-2). Said on every run.
    let caveat = (matches!(route, vendor::Route::Module) && opts.ak_label.is_some()).then(|| {
        "its tpm-certify signer (akLabel) is a key only the module vouches for: the attestation is as \
         trustworthy as the module, not the TPM; akHandle reads the Attestation Key from the TPM"
            .to_owned()
    });
    let (certified, ek) = match route {
        vendor::Route::Module => {
            opts.refuse_ek_for_module(ctx.token_name)?;
            // A secret key is bound by the TPM computing its commitment with the object it
            // certified, which only the store path loads (review 2026-11-23 B-1).
            if ctx.object.class == cakeys_core::types::ObjectClass::SecretKey {
                return Err(KmError::Unsupported(
                    "a secret key's tpm-certify is bound to the key by the TPM computing its HMAC commitment \
                     with the object certified, which the module's own certify (CKM_TPM2_CERTIFY) never lets \
                     cakeys load: attest it through a module without the vendor mechanism, or not at all"
                        .into(),
                ));
            }
            (vendor::certify(ctx, &opts)?, None)
        }
        vendor::Route::Store => certify_through_store(ctx, &opts)?,
    };
    // The module's immutables rest on TPMA_OBJECT bits the attestation signed: what the module
    // reports as CKA_LOCAL/CKA_EXTRACTABLE must be what the TPM certified (13, never a pass).
    let (local, extractable) = module_reports(ctx)?;
    if local != certified.local || extractable != certified.extractable {
        return Err(KmError::Conflict(
            format!(
                "the module reports CKA_LOCAL {} / CKA_EXTRACTABLE {}, but the TPM certified \
             {} / {}: the module does not report what the TPM holds",
                local, extractable, certified.local, certified.extractable
            )
            .into(),
        ));
    }
    let (root, warning) = match ek {
        // The AK was proven to reside in the certified TPM: the manufacturer's root anchors it.
        Some(ek) => (ek.anchor_spki, ek.warning),
        // The AK is trusted on first use, with no certificate dates to judge.
        None => (certified.ak_spki, None),
    };
    Ok(Attested {
        scheme: Scheme::TpmCertify,
        id: cakeys_core::id::tpm_certify_id(&certified.name, &certified.qualified_name),
        root: cakeys_core::id::sri(&root),
        warning,
        caveat,
    })
}

/// The attestation of a module without the vendor mechanisms: the store row for the PKCS#11
/// object, loaded and certified by cakeys itself, with the EK it was activated against (if any).
fn certify_through_store(ctx: &AttestCtx<'_>, opts: &Tpm2Options) -> Result<(esys::Certified, Option<ek::Trusted>)> {
    check_version(ctx.module_version)?;
    // The store row is found the way the module finds the object: by the locator's CKA_ID
    // (and label), within the key's class.
    let Some(Attribute::Id(cka_id)) =
        read_attribute("CKA_ID", ctx.session.get_attributes(ctx.key, &[AttributeType::Id]))?
    else {
        return Err(KmError::Unsupported("the key object exposes no CKA_ID to find its store row by".into()));
    };
    let label = match read_attribute("CKA_LABEL", ctx.session.get_attributes(ctx.key, &[AttributeType::Label]))? {
        Some(Attribute::Label(l)) => Some(l),
        _ => None,
    };
    let want = expected(ctx)?;
    let class = store::store_class(ctx.object.class)?;
    let store = store::Store::open(&store_dir_of(ctx.token_name, opts)?, &ctx.cfg.token_label)?;
    let tobj = store.find(&cka_id, label.as_deref(), class)?;
    let conf = tcti(ctx, opts)?;
    let mut esys_ctx = esys::context(&conf)?;
    let ek = ek::trusted(ctx.token_name, opts, ctx.chain_time, &mut esys_ctx)?;
    let certified = esys::certify_key(
        &mut esys_ctx,
        &store,
        tobj,
        ctx.pin.map(str::as_bytes),
        opts.ak_handle(ctx.token_name)?,
        ctx.provision,
        want,
        ek.as_ref().map(|t| t.spki.as_slice()),
    )?;
    Ok((certified, ek))
}

/// What the certified object must be ([`esys::Expected`]): an asymmetric key's SPKI, or a secret
/// key's HMAC commitment, which the TPM computes again with the object it certified (review
/// 2026-11-23 B-1: a secret key's attestation was bound to no material).
///
/// # Errors
///
/// `Unsupported` for an asymmetric key without its SPKI, and for a secret key without an HMAC
/// commitment (an AES or Triple DES key, one without `CKA_SIGN`) or with one the TPM cannot
/// compute (SHA-224).
fn expected<'a>(ctx: &'a AttestCtx<'_>) -> Result<esys::Expected<'a>> {
    if let Some(spki) = ctx.required_spki()? {
        return Ok(esys::Expected::Spki(spki));
    }
    let hmac = ctx.commitments.iter().find_map(|c| match c.commit {
        cakeys_core::id::Commit::Hmac(hash) => Some((hash, c)),
        _ => None,
    });
    let Some((hash, c)) = hmac else {
        return Err(KmError::Unsupported(
            "tpm-certify binds a secret key to the TPM object it certifies through the key's HMAC commitment (the \
             commitment scheme: an HMAC or generic secret key with CKA_SIGN), which the TPM computes again with that \
             object; this key computes none, so its attestation could name an object that is not it"
                .into(),
        ));
    };
    Ok(esys::Expected::Commitment(esys::Bind { hash: esys::hmac_algorithm(hash)?, input: &c.input, id: &c.id }))
}

/// The tpm2-pkcs11 versions the store reader was tested with (review A8): the sqlite schema and
/// the YAML of its rows are the module's own, unversioned, so another release is refused rather
/// than read as if it were one of these.
pub(crate) const TESTED_VERSIONS: &[&str] = &["1.10"];

/// Refuse (15) a module version the store reader was not tested with, naming it.
///
/// # Errors
///
/// `Unsupported` for any version but [`TESTED_VERSIONS`] (major.minor, as `C_GetInfo` reports).
pub(crate) fn check_version(version: &str) -> Result<()> {
    let minor = version.split('.').take(2).collect::<Vec<_>>().join(".");
    if TESTED_VERSIONS.contains(&minor.as_str()) {
        return Ok(());
    }
    Err(KmError::Unsupported(
        format!(
            "tpm-certify reads tpm2-pkcs11's store, tested with {}.x only; this module reports {version}",
            TESTED_VERSIONS.join(".x, ")
        )
        .into(),
    ))
}

/// `CKA_LOCAL` and `CKA_EXTRACTABLE` of the live object, as the module reports them.
fn module_reports(ctx: &AttestCtx<'_>) -> Result<(bool, bool)> {
    let attrs = ctx
        .session
        .get_attributes(ctx.key, &[AttributeType::Local, AttributeType::Extractable])
        .map_err(|e| KmError::Unavailable(format!("C_GetAttributeValue (CKA_LOCAL/CKA_EXTRACTABLE): {e}").into()))?;
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

    /// The fuzz entry points take the fixtures the unit tests parse, and refuse bytes that are
    /// no TPM structure with an error.
    #[test]
    fn the_fuzz_entry_points_read_or_refuse() {
        // One text is tried as both row kinds: an object row is no parent row, and the reverse.
        assert!(fuzzing::store_row(include_str!("../../tests/fixtures/tobject-private.yaml")).is_err());
        assert!(fuzzing::store_row("not: [yaml").is_err());
        assert!(fuzzing::tpms_attest(b"neither an attestation nor a public area").is_err());
        // A public area as the store keeps it is read to its material.
        let row = include_str!("../../tests/fixtures/tobject-private.yaml");
        let public = super::store::parse_tobject(row).unwrap().unwrap().pub_blob;
        assert!(fuzzing::tpms_attest(&public).is_ok());
    }

    /// A configured store directory is taken as written, `~/` expanded; a TCTI and an AK handle
    /// out of the owner's persistent range are options checked at load.
    #[test]
    fn options_name_the_store_and_are_checked() {
        let options = |text: &str| -> Options { toml::from_str(text).unwrap() };
        let opts =
            Tpm2Options::of("t", &options("tpm2Store = \"/var/lib/store\"\ntcti = \"device:/dev/tpmrm0\"")).unwrap();
        assert_eq!(store_dir_of("t", &opts).unwrap(), std::path::Path::new("/var/lib/store"));
        assert_eq!(opts.tcti(), Some("device:/dev/tpmrm0"));
        let home = Tpm2Options::of("t", &options("tpm2Store = \"~/store\"")).unwrap();
        let dir = store_dir_of("t", &home).unwrap();
        assert!(dir.ends_with("store") && !dir.starts_with("~"), "{}", dir.display());
        assert!(Tpm2Options::of("t", &options("akHandle = \"0x40000001\"")).is_err());
        assert!(Tpm2Options::of("t", &options("noSuchOption = 1")).is_err());
        // A TCTI tss-esapi cannot read is refused at open, as its attestation would (review D8);
        // a library name is the TCTI it names.
        let err = Tpm2Options::of("t", &options("tcti = \"no-such-tcti:x\"")).unwrap_err();
        assert!(matches!(err, KmError::Validation(_)) && err.to_string().contains("tokens.t.options.tcti"), "{err}");
        Tpm2Options::of("t", &options("tcti = \"libtss2-tcti-swtpm.so:port=2321\"")).unwrap();
    }

    /// The store is looked for where tpm2-pkcs11 1.10 looks (attest/mod.rs F2): only
    /// `$TPM2_PKCS11_STORE` when it is set, else `/etc`, XDG (or its default under `$HOME`), the
    /// home dot directory and the working directory, in that order.
    #[test]
    fn the_store_is_looked_for_in_the_modules_order() {
        const ALL: &[(&str, &str)] = &[("TPM2_PKCS11_STORE", "/s"), ("HOME", "/h"), ("XDG_DATA_HOME", "/x")];
        let paths = |p: &[&str]| p.iter().map(PathBuf::from).collect::<Vec<_>>();
        let cwd = Some(PathBuf::from("/w"));
        let env = |vars: &'static [(&'static str, &'static str)]| {
            move |v: &str| vars.iter().find(|(k, _)| *k == v).map(|(_, x)| (*x).to_owned())
        };
        assert_eq!(store_candidates(env(ALL), cwd.clone()), paths(&["/s"]));
        assert_eq!(
            store_candidates(env(&ALL[1..]), cwd.clone()),
            paths(&["/etc/tpm2_pkcs11", "/x/tpm2-pkcs11", "/h/.tpm2_pkcs11", "/w"])
        );
        assert_eq!(
            store_candidates(env(&ALL[1..2]), cwd),
            paths(&["/etc/tpm2_pkcs11", "/h/.local/share/tpm2-pkcs11", "/h/.tpm2_pkcs11", "/w"])
        );
        assert_eq!(store_candidates(env(&[]), None), paths(&["/etc/tpm2_pkcs11"]));
    }

    /// The store reader reads only the versions it was tested with (15 otherwise, naming it).
    #[test]
    fn only_tested_module_versions_are_read() {
        assert!(check_version("1.10").is_ok());
        assert!(check_version("1.10.1").is_ok());
        for v in ["1.9", "1.11", "2.0", ""] {
            let e = check_version(v).unwrap_err();
            assert!(matches!(&e, KmError::Unsupported(m) if m.contains(v)), "{v}: {e}");
        }
    }

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
        assert_eq!(opts("akLabel = \"cakeys-ak\"").unwrap().ak_label.as_deref(), Some("cakeys-ak"));
        for (bad, why) in [
            ("tctl = \"x\"", "unknown field"),
            ("akHandle = \"81000017\"", "0x prefix"),
            ("akHandle = \"0x01\"", "owner range"),
            ("akLabel = \"ak\"\nakHandle = \"0x81000017\"", "two Attestation Keys"),
            ("akLabel = \"\"", "akLabel is empty"),
        ] {
            let err = opts(bad).unwrap_err();
            assert!(
                matches!(&err, KmError::Validation(m) if m.contains("tokens.tpm.options") && m.contains(why)),
                "{bad}: {err}"
            );
        }
    }
}
