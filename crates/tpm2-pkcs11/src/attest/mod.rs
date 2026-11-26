//! Runs the steps of the `tpm-certify` attestation commitment (docs/DESIGN.md §3.7): it finds
//! the store row behind the PKCS#11 object, certifies the object directly with the TPM, and
//! compares everything that the module reports with what the TPM signed.

pub(crate) mod credential;
pub(crate) mod ek;
pub(crate) mod esys;
pub(crate) mod store;
pub(crate) mod vendor;

/// Entry points for the fuzz targets (`fuzz/fuzz_targets/tpm_store_row.rs` and
/// `tpms_attest.rs`). They run the parsers that the attestation path uses on data from the store
/// and the TPM, on arbitrary input. Each input must be parsed or refused with an error, never
/// with a panic.
#[cfg(any(test, feature = "fuzzing", kani))]
pub(crate) mod fuzzing {
    use cakeys_core::Result;

    /// Parses `text` both as a `tobjects.attrs` row and as a `pobjects.config` row.
    ///
    /// # Errors
    ///
    /// Returns the error of either parser.
    pub fn store_row(text: &str) -> Result<()> {
        let object = super::store::parse_tobject(text);
        let parent = super::store::parse_parent(text, "");
        object.and(parent).map(drop)
    }

    /// Parses `bytes` as a marshaled `TPMS_ATTEST` (and reads the Names of its certify
    /// statement), as a `TPM2B_PUBLIC` blob (and computes its Name and key material), and as the
    /// output of `CKM_TPM2_CERTIFY` (`TPM2B_ATTEST ‖ TPMT_SIGNATURE`).
    ///
    /// # Errors
    ///
    /// Returns the error of the Name computation, of the unmarshaling of the public blob, or of
    /// the material extraction.
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
use cakeys_core::{Check, KmError, Reason, Result};
use cakeys_pkcs11::provider::{AttestCtx, Attested};
use cakeys_pkcs11::token::read_attribute;
use cryptoki::object::{Attribute, AttributeType};
use serde::Deserialize;
use std::path::PathBuf;

/// The persistent handle at which cakeys provisions its Attestation Key on the first attestation,
/// when `tokens.<t>.options.akHandle` does not name a handle. The value is deliberately outside
/// the range 0x81000001 to 0x8100000A that common tools use (the primary of tpm2-pkcs11 is at
/// 0x81000001). Change it if it collides with a handle on your TPM.
pub(crate) const DEFAULT_AK_HANDLE: u32 = 0x8100_0016;

/// The `[tokens.<t>.options]` of the tpm2-pkcs11 provider, for the native attestation path.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct Tpm2Options {
    /// The TCTI connection string for the native attestation path (`TPM2_Certify`), in the
    /// tss-esapi `TctiNameConf` syntax (`"device:/dev/tpmrm0"`, `"tabrmd:bus_type=session"`) or as
    /// a TCTI library name (`"libtss2-tcti-tabrmd.so.0:bus_type=session"`). The default is the
    /// module's own `$TPM2_PKCS11_TCTI`, then `$TPM2TOOLS_TCTI`, then `$TCTI`.
    tcti: Option<String>,
    /// The directory of the sqlite store behind the module. The native attestation path reads
    /// the store (read-only) to find the object's TPM blobs. The default is the store that
    /// tpm2-pkcs11 itself opens: `$TPM2_PKCS11_STORE`, or otherwise the first of
    /// `/etc/tpm2_pkcs11`, `$XDG_DATA_HOME/tpm2-pkcs11` (`~/.local/share/tpm2-pkcs11`),
    /// `~/.tpm2_pkcs11` and the working directory that holds `tpm2_pkcs11.sqlite3`.
    tpm2_store: Option<String>,
    /// The persistent handle of cakeys' Attestation Key. The key is a restricted signing key in
    /// the owner hierarchy with an empty auth value, which `lock` creates if it is absent. The
    /// lock pins it through the realisation's `attestation.root`, unless `ekCertificate` anchors
    /// it at the manufacturer. The default is the provider's `DEFAULT_AK_HANDLE`. The value is
    /// hex with a `0x` prefix in 0x81000000..=0x817FFFFF, for example `"0x81000016"`. An object
    /// that is already at the handle and is not such a key is refused (13).
    ak_handle: Option<String>,
    /// The TPM's endorsement key certificate: a PEM file of the certificate followed by its
    /// intermediates, or one DER certificate. With this option, every attestation proves that
    /// the AK resides in that TPM (through a credential activated with the EK), and the lock
    /// pins the manufacturer root to which the certificate verifies instead of the AK. The
    /// certificate must verify to a built-in root (AMD fTPM) or to `ekRoots` (13). Without this
    /// option, the certificate in the TPM's NV is used when it verifies, and otherwise the AK is
    /// trusted on first use.
    ek_certificate: Option<String>,
    /// Additional roots to which EK certificates can verify: a PEM file of self-signed CA
    /// certificates (or one DER certificate), for a TPM manufacturer for which cakeys pins no
    /// root.
    ek_roots: Option<String>,
    /// The `CKA_LABEL` of an Attestation Key that is an object of the token. `lock` makes the
    /// key through the module's `CKM_TPM2_AK_PAIR_GEN`, and attestation uses it through
    /// `CKM_TPM2_CERTIFY_OBJECT`, so no TCTI, TPM handle or store is needed to attest. It is a
    /// different key from the persistent key (`akHandle`), so a lock made with the persistent
    /// key pins a different `attestation.root`, and choosing this option requires locking again.
    /// The option works only for a module that lists those mechanisms (15 otherwise), and it
    /// cannot be combined with `akHandle`.
    ak_label: Option<String>,
}

impl Tpm2Options {
    /// Parses and checks the options of `token`. Unknown names, a malformed `akHandle` and a
    /// `tcti` that tss-esapi cannot read are invalid (17) when the token is opened, not only at
    /// the time of attestation.
    ///
    /// # Errors
    ///
    /// Returns `Validation` for an unknown option name, or for an `akHandle`, `tcti` or
    /// `tpm2Store` value that cannot be used.
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

    /// Refuses (15) `ekCertificate` and `ekRoots` for an attestation that the module performs.
    /// cakeys performs the credential activation itself, on the TPM, and that path does not open
    /// the TPM. Silently leaving the AK trusted on first use would pin a weaker anchor than the
    /// one that was asked for.
    ///
    /// # Errors
    ///
    /// Returns `Unsupported` when either option is set.
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

    /// Returns the configured TCTI in the tss-esapi syntax. The check at open time and the
    /// attestation's connection share this one parse (review D8). `tpm2_ptool` receives the
    /// string as written.
    fn tcti_conf(&self, token: &str) -> Result<Option<tss_esapi::Tcti>> {
        self.tcti.as_deref().map(|s| parse_tcti(&format!("tokens.{token}.options.tcti"), s)).transpose()
    }

    /// Returns the configured TCTI as written (for `tpm2_ptool`, which reads the same string).
    pub(crate) fn tcti(&self) -> Option<&str> {
        self.tcti.as_deref()
    }

    /// Returns the AK handle: the configured value (hex with a `0x` prefix, a persistent handle in
    /// the owner range 0x81000000..=0x817FFFFF), or otherwise cakeys' default.
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

/// Returns the store directory for `token_name`, which both the attestation and the plaintext
/// import use. The directory is `tokens.<t>.options.tpm2Store`, or otherwise the directory that
/// tpm2-pkcs11 itself would open (db.c `db_for_path`): `$TPM2_PKCS11_STORE` without any further
/// check, and then the first of `/etc/tpm2_pkcs11`, `$XDG_DATA_HOME/tpm2-pkcs11` (or
/// `~/.local/share/tpm2-pkcs11`), `~/.tpm2_pkcs11` and the working directory that holds a store
/// file. Any other choice could read a different store from the store of the module that the
/// PKCS#11 object came from.
///
/// # Errors
///
/// Returns `Unavailable` when no store is found.
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

/// Returns the directories in which tpm2-pkcs11 1.10 looks for its store, in its order (db.c
/// `db_for_path`), from the environment that `var` reads and from the working directory. When
/// `$TPM2_PKCS11_STORE` is set, it is the only directory (and it is used whether or not it holds
/// a store). Otherwise the directories are `/etc/tpm2_pkcs11` (the module's build-time
/// `TPM2_PKCS11_STORE_DIR`, which a distribution may change), `$XDG_DATA_HOME/tpm2-pkcs11` or
/// `~/.local/share/tpm2-pkcs11`, `~/.tpm2_pkcs11`, and then the working directory. A store read
/// from a directory other than the module's fails the attestation's checks and never passes
/// them, because `TPM2_Load` and the Name and SPKI checks bind the row to the live object, and
/// for a secret key, so does the HMAC commitment that the loaded object computes again
/// (`esys::Expected`).
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

/// Expands the leading `~` of a `tpm2Store` path, when the shell could not expand it.
fn expand_home(dir: &str) -> String {
    match dir.strip_prefix("~/") {
        Some(rest) => match std::env::var("HOME") {
            Ok(home) => format!("{home}/{rest}"),
            Err(_) => dir.to_owned(),
        },
        None => dir.to_owned(),
    }
}

/// Returns a TCTI string in the tss-esapi `<name>:<conf>` syntax. The TCTI loader also accepts
/// a library name or path (`libtss2-tcti-tabrmd.so.0:bus_type=session`), which tool
/// environments often export. That form names the same TCTI, so the function reduces it to
/// `tabrmd:bus_type=session`.
fn normalize_tcti(s: &str) -> String {
    let (lib, conf) = s.split_once(':').unwrap_or((s, ""));
    let base = lib.rsplit('/').next().unwrap_or(lib);
    match base.strip_prefix("libtss2-tcti-").and_then(|b| b.split(".so").next()) {
        Some(name) => format!("{name}:{conf}"),
        None => s.to_owned(),
    }
}

/// Returns the TCTI connection to the TPM that the attestation path uses: the token's `tcti`
/// setting, or otherwise the TCTI that the module itself uses (`$TPM2_PKCS11_TCTI`), or
/// otherwise the TCTI of the tpm2 tools (`$TPM2TOOLS_TCTI`, `$TCTI`). The value is in the
/// tss-esapi syntax (`"device:/dev/tpmrm0"`, `"tabrmd:bus_type=session"`, `"swtpm:port=2321"`),
/// or it is a TCTI library name, which is reduced to that syntax.
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

/// Parses `value`, which came from `source`, as a TCTI that tss-esapi opens
/// ([`normalize_tcti`]).
fn parse_tcti(source: &str, value: &str) -> Result<tss_esapi::Tcti> {
    normalize_tcti(value)
        .parse()
        .map_err(|e| KmError::Validation(format!("{source} = {value:?} is not a TCTI tss-esapi can open: {e}").into()))
}

/// Runs the whole attestation: it certifies the TPM object behind the PKCS#11 object and
/// compares what the module reports with what the TPM signed. A module with `CKM_TPM2_CERTIFY`
/// runs the certify itself ([`vendor`]). For a module without it, cakeys reads the store and
/// uses the TPM ([`esys`]).
///
/// # Errors
///
/// Returns `Unsupported` in these cases: `akLabel` on a module without the token-key
/// mechanisms; an `ekCertificate` with a module that certifies by itself (because the
/// activation needs the TPM); on the store path, a module version that the store reader was not
/// tested with, or a key object with no `CKA_ID` by which to find its store row; a secret key
/// that cannot be bound to the certified object ([`expected`]); and any secret key on the path
/// where the module certifies by itself. Returns `Unavailable` when the store cannot be opened,
/// when the TPM or the module's mechanism fails, or when the object's attributes cannot be read
/// from the module. Returns `Conflict` when what the module reports does not match what the TPM
/// signed. Also returns any error of the certify itself (the PIN, the auth, the Names, the
/// material check or the commitment, or the EK's credential).
pub(crate) fn attest(ctx: &AttestCtx<'_>) -> Result<Attested> {
    let opts = Tpm2Options::of(ctx.token_name, &ctx.cfg.options)?;
    let route = vendor::route(ctx, &opts)?;
    // When a token object is the signer (`akLabel`), its public area and its restricted and
    // fixedTPM attributes come from the module, never from the TPM, so a module with no TPM
    // behind it could sign any statement (review 2026-11-23 B-2). Every run reports this
    // caveat.
    let caveat = (matches!(route, vendor::Route::Module) && opts.ak_label.is_some()).then(|| {
        "its tpm-certify signer (akLabel) is a key only the module vouches for: the attestation is as \
         trustworthy as the module, not the TPM; akHandle reads the Attestation Key from the TPM"
            .to_owned()
    });
    let (certified, ek) = match route {
        vendor::Route::Module => {
            opts.refuse_ek_for_module(ctx.token_name)?;
            // A secret key is bound to the attestation by the TPM, which computes the key's
            // commitment with the object that it certified, and only the store path loads that
            // object (review 2026-11-23 B-1).
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
    // The module derives its immutable attributes from TPMA_OBJECT bits that the attestation
    // signed, so the CKA_LOCAL and CKA_EXTRACTABLE that the module reports must equal what the
    // TPM certified (13 otherwise, never a pass).
    let (local, extractable) = module_reports(ctx)?;
    if local != certified.local || extractable != certified.extractable {
        return Err(KmError::Conflict(Reason::check(
            Check::AttestTpmImmutables,
            format!(
                "the module reports CKA_LOCAL {} / CKA_EXTRACTABLE {}, but the TPM certified \
             {} / {}: the module does not report what the TPM holds",
                local, extractable, certified.local, certified.extractable
            ),
        )));
    }
    let (root, warning) = match ek {
        // The AK was proven to reside in the certified TPM, so the manufacturer's root anchors
        // it.
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

/// Runs the attestation for a module without the vendor mechanisms. cakeys itself loads and
/// certifies the store row of the PKCS#11 object, and returns the result together with the EK
/// against which the AK was activated (if any).
fn certify_through_store(ctx: &AttestCtx<'_>, opts: &Tpm2Options) -> Result<(esys::Certified, Option<ek::Trusted>)> {
    check_version(ctx.module_version)?;
    // The store row is found in the same way that the module finds the object: by the
    // locator's CKA_ID (and label), within the key's class.
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

/// Returns what the certified object must be ([`esys::Expected`]): an asymmetric key's SPKI, or
/// a secret key's HMAC commitment, which the TPM computes again with the object that it
/// certified (review 2026-11-23 B-1: before this, a secret key's attestation was bound to no
/// material).
///
/// # Errors
///
/// Returns `Unsupported` for an asymmetric key without its SPKI, for a secret key without an HMAC
/// commitment (an AES or Triple DES key, or a key without `CKA_SIGN`), and for a secret key with
/// a commitment that the TPM cannot compute (SHA-224).
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

/// The tpm2-pkcs11 versions with which the store reader was tested (review A8). The sqlite
/// schema and the YAML of its rows belong to the module and carry no version, so another release
/// is refused instead of being read as if it were one of these versions.
pub(crate) const TESTED_VERSIONS: &[&str] = &["1.10"];

/// Refuses (15) a module version with which the store reader was not tested, and names the
/// version.
///
/// # Errors
///
/// Returns `Unsupported` for any version other than [`TESTED_VERSIONS`] (compared as
/// major.minor, as `C_GetInfo` reports it).
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

/// Returns the `CKA_LOCAL` and `CKA_EXTRACTABLE` of the live object, as the module reports
/// them.
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

    /// The fuzz entry points accept the fixtures that the unit tests parse, and refuse bytes
    /// that are not a TPM structure with an error.
    #[test]
    fn the_fuzz_entry_points_read_or_refuse() {
        // One text is parsed as both kinds of row. An object row is not a parent row, and a
        // parent row is not an object row.
        assert!(fuzzing::store_row(include_str!("../../tests/fixtures/tobject-private.yaml")).is_err());
        assert!(fuzzing::store_row("not: [yaml").is_err());
        assert!(fuzzing::tpms_attest(b"neither an attestation nor a public area").is_err());
        // A public area in the form that the store keeps is parsed down to its material.
        let row = include_str!("../../tests/fixtures/tobject-private.yaml");
        let public = super::store::parse_tobject(row).unwrap().unwrap().pub_blob;
        assert!(fuzzing::tpms_attest(&public).is_ok());
    }

    /// A configured store directory is used as written, with `~/` expanded. A TCTI and an AK
    /// handle outside the owner's persistent range are options that are checked at load.
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
        // A TCTI that tss-esapi cannot read is refused at open, as its attestation would refuse
        // it (review D8). A library name is read as the TCTI that it names.
        let err = Tpm2Options::of("t", &options("tcti = \"no-such-tcti:x\"")).unwrap_err();
        assert!(matches!(err, KmError::Validation(_)) && err.to_string().contains("tokens.t.options.tcti"), "{err}");
        Tpm2Options::of("t", &options("tcti = \"libtss2-tcti-swtpm.so:port=2321\"")).unwrap();
    }

    /// cakeys looks for the store where tpm2-pkcs11 1.10 looks (attest/mod.rs F2): only in
    /// `$TPM2_PKCS11_STORE` when it is set, and otherwise in `/etc`, the XDG directory (or its
    /// default under `$HOME`), the dot directory in the home directory, and the working
    /// directory, in that order.
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

    /// The store reader reads only the versions with which it was tested (15 otherwise, with the
    /// version named).
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

    /// The provider's options are checked when the token opens. Known names parse, and a typo or
    /// a malformed AK handle is invalid (17), with the token named.
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
