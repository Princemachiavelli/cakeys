//! Token declarations: `[tokens.<name>]` in keys.toml, the probe and Nix settings, and the
//! module options each provider reads (docs/CONFIG.md).

use super::{Deserialize, PathBuf, Result, env_ref, secret_path, KmError};

/// One token (`[tokens.<name>]`): the module that reaches it, its label and credentials, and what
/// its provider needs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenCfg {
    /// The PKCS#11 module: a path, or `$NAME`/`${NAME}` read from the environment when the token
    /// is opened ([`TokenCfg::module_path`]). It is per machine, so it may be left out and given
    /// per run with `--module <token>=<path>` (what `lib.mkKeys`'s `modules.<token>` passes), which
    /// replaces it unexpanded. A bare file name is the dynamic loader's library search
    /// (`LD_LIBRARY_PATH`; on NixOS nothing else). The lock records the file actually loaded and
    /// its hash, as provenance only.
    pub module: Option<String>,
    /// Provider crate, or module profile family, handling this module's quirks; auto-detected
    /// from `C_GetInfo` if unset. A family, never one profile ([`Self::module_profile`]).
    pub provider: Option<String>,
    /// One module profile by its full name (`aws-cloudhsm/5.18+hsm2m-non-fips`), for profiles
    /// that tie on every match key (PKCS#11 reports no FIPS mode, docs/CAPROBE.md D12). Its
    /// family is the provider when `provider` is unset. Not `profiles`, which are delta layers.
    #[serde(default)]
    pub module_profile: Option<String>,
    /// Delta capability layers to compose over the module profile (docs/CAPROBE.md), by name
    /// or family: the hardware under the module (`swtpm`), or anything else between cakeys
    /// and it. The cryptoki binding layer is always applied; p11-kit is detected from the
    /// module itself. Unknown names refuse (17).
    #[serde(default)]
    pub profiles: Vec<String>,
    /// The label the token reports (`CK_TOKEN_INFO.label`): which of the module's tokens this is.
    pub token_label: String,
    /// The serial number the token reports (`CK_TOKEN_INFO.serialNumber`), when two of the
    /// module's tokens carry one label: with it, only the token with both matches.
    #[serde(default)]
    pub token_serial: Option<String>,
    /// A file holding the user PIN (`$NAME` reads the path from the environment when the PIN is
    /// read: [`Self::pin_path`]). With neither it nor `pinEnv`, the token is used without
    /// logging in.
    pub pin_file: Option<PathBuf>,
    /// An environment variable holding the user PIN; it wins over `pinFile`.
    pub pin_env: Option<String>,
    /// The Security Officer credential, for modules that create and destroy objects only in an
    /// SO session — ykcs11: the PIV management key in hex, or the PIN on a device whose
    /// management key is PIN-protected; elsewhere the SO PIN (camigrate's `transport --trusted`).
    /// `pinFile`/`pinEnv` remain the *user* credential. Read just before such a step, never by
    /// `resolve` or `check`; the user session is restored afterwards, so a user PIN is
    /// required. `soCredentialEnv` wins if both are set; `soCredentialFile` may be `$NAME`, like
    /// `pinFile`. Refused on a provider that does not need it.
    pub so_credential_file: Option<PathBuf>,
    /// An environment variable holding the SO credential; it wins over `soCredentialFile`.
    pub so_credential_env: Option<String>,
    /// Settings only the token's provider understands, as `[tokens.<t>.options]` (tpm2-pkcs11:
    /// `tcti`, `tpm2Store`, `akHandle`). The provider checks them when the token is opened, and
    /// one that takes none refuses any (17).
    #[serde(default)]
    pub options: Options,
    /// What only caprobe reads (`[tokens.<t>.probe]`).
    #[serde(default)]
    pub probe: ProbeCfg,
    /// What only camigrate reads (`[tokens.<t>.migrate]`).
    #[serde(default)]
    pub migrate: TokenMigrateCfg,
    /// What only the Nix library reads (`[tokens.<t>.nix]`).
    #[serde(default)]
    pub nix: NixCfg,
}

/// A token's settings for caprobe (`[tokens.<t>.probe]`, docs/CAPROBE.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProbeCfg {
    /// Marks the token as expendable: its write probes generate, wrap, unwrap and destroy
    /// objects, so `probe --write-probes` runs them only here and is refused (17) on any other token.
    #[serde(default)]
    pub scratch: bool,
    /// The one `CKA_ID` (hex) the write probes may generate into, on a token whose module
    /// creates only as Security Officer into fixed device slots named by `CKA_ID` (ykcs11): such
    /// a token holds real keys beside the scratch slot, so `scratch` cannot mark all of it. Each
    /// probe generation replaces the slot's key, and what the last one generated stays (PIV
    /// cannot erase a key). The probe still refuses a slot holding anything but its provider's
    /// own placeholder (`Provider::scratch_occupant`).
    pub scratch_id: Option<String>,
}

/// A token's settings for camigrate (`[tokens.<t>.migrate]`, docs/CAMIGRATE.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenMigrateCfg {
    /// The spec of this token's transport key (D3): an RSA private key realised here that may
    /// unwrap and never leaves the token. Sealed moves to this token wrap to it, never to one
    /// picked by what it can do (camigrate `--transport-spec` overrides it per run); its
    /// realisation records the public key in the lock, so any host can export to it. It never
    /// leaves the tokens its spec realises it on, as if `migrate.noExport` (camigrate refuses it
    /// named, 15, and leaves it out without names).
    pub transport_with: Option<String>,
}

/// A token's settings for the Nix library (`[tokens.<t>.nix]`, docs/CAKEYS.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NixCfg {
    /// The `requiredSystemFeatures` entry: defaults to `<featurePrefix><name>` (`lib.mkKeys`'s
    /// `featurePrefix`, default `token-`). The NixOS module advertises `<featurePrefix><n>` for
    /// each of its tokens, so this names one of those.
    pub system_feature: Option<String>,
}

/// A token's provider-specific settings (`[tokens.<t>.options]`), parsed by the provider.
pub type Options = toml::Table;

impl TokenCfg {
    /// A token labelled `token_label` with nothing else set: what a keys.toml entry naming only
    /// `tokenLabel` parses to.
    #[must_use]
    pub fn labelled(token_label: String) -> TokenCfg {
        TokenCfg {
            module: None,
            provider: None,
            module_profile: None,
            profiles: Vec::new(),
            token_label,
            token_serial: None,
            pin_file: None,
            pin_env: None,
            so_credential_file: None,
            so_credential_env: None,
            options: Options::new(),
            probe: ProbeCfg::default(),
            migrate: TokenMigrateCfg::default(),
            nix: NixCfg::default(),
        }
    }

    /// The provider keys.toml names: `provider`, else the family of `moduleProfile`
    /// (`aws-cloudhsm` for `aws-cloudhsm/5.18+hsm2m-non-fips`). `None`: detect it.
    #[must_use]
    pub fn named_provider(&self) -> Option<&str> {
        self.provider
            .as_deref()
            .or_else(|| self.module_profile.as_deref().map(|p| p.split_once('/').map_or(p, |(family, _)| family)))
    }

    /// The module to load, its `$NAME` reference resolved by `env` now: resolved when the token
    /// is opened, so an unset one fails only a run that uses this token without `--module`.
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) when `module` names an unset variable.
    pub fn module_path(&self, token: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<String>> {
        self.module.as_deref().map(|m| env_ref(m, &format!("token '{token}': module"), env)).transpose()
    }

    /// The file holding the user PIN (`pinFile`), its `$NAME` reference resolved by `env` now:
    /// resolved when the PIN is read, so an unset variable fails only a run that logs in to this
    /// token. `None` when keys.toml names no file.
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) when `pinFile` names an unset variable; `Validation` (17) for a file in
    /// the Nix store.
    pub fn pin_path(&self, token: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
        secret_path(self.pin_file.as_deref(), &format!("token '{token}': pinFile"), env)
    }

    /// The file holding the admin credential (`soCredentialFile`), resolved as [`Self::pin_path`].
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) when `soCredentialFile` names an unset variable; `Validation` (17) for
    /// a file in the Nix store.
    pub fn so_credential_path(&self, token: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
        secret_path(self.so_credential_file.as_deref(), &format!("token '{token}': soCredentialFile"), env)
    }
}

/// Parse a token's `options` into the provider's own settings type, which should deny unknown
/// fields: a typo is invalid (17), naming the token.
///
/// # Errors
///
/// `Validation` if the table does not fit `T`: an unknown option name or a bad value.
pub fn parse_options<T: serde::de::DeserializeOwned>(token: &str, options: &Options) -> Result<T> {
    options.clone().try_into().map_err(|e| KmError::Validation(format!("tokens.{token}.options: {e}").into()))
}
