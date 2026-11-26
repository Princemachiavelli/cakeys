//! The token declarations: `[tokens.<name>]` in keys.toml, the settings for the probe and for
//! Nix, and the module options that each provider reads (docs/CONFIG.md).

use super::{Deserialize, KmError, PathBuf, Result, env_ref, secret_path};

/// One token (`[tokens.<name>]`): the module through which cakeys reaches it, its label and
/// credentials, and the settings that its provider needs.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenCfg {
    /// The PKCS#11 module: a path, or `$NAME` or `${NAME}`, which is read from the environment
    /// when the token is opened ([`TokenCfg::module_path`]). The path differs between machines,
    /// so it may be left out and given for each run with `--module <token>=<path>` (which is what
    /// `lib.mkKeys`'s `modules.<token>` passes). That option replaces the value without expanding
    /// it. A file name without a directory is found by the dynamic loader's library search
    /// (`LD_LIBRARY_PATH`; on NixOS, nothing else). The lock records the file that was actually
    /// loaded and its hash, as provenance only.
    pub module: Option<String>,
    /// The provider crate, or the module profile family, that handles the unusual behavior of
    /// this module. When it is unset, the run detects it from `C_GetInfo`. It names a family,
    /// never one profile ([`Self::module_profile`]).
    pub provider: Option<String>,
    /// One module profile by its full name (`aws-cloudhsm/5.18+hsm2m-non-fips`), for profiles that
    /// no match key can tell apart (PKCS#11 reports no FIPS mode, docs/CAPROBE.md D12). Its
    /// family is the provider when `provider` is unset. It is not one of the `profiles`, which
    /// are delta layers.
    #[serde(default)]
    pub module_profile: Option<String>,
    /// The delta capability layers to apply over the module profile (docs/CAPROBE.md), by name or
    /// by family: the hardware under the module (`swtpm`), or anything else between cakeys and
    /// the hardware. The layer for the cryptoki binding is always applied, and p11-kit is
    /// detected from the module itself. An unknown name is refused (17).
    #[serde(default)]
    pub profiles: Vec<String>,
    /// The label that the token reports (`CK_TOKEN_INFO.label`), which selects one of the module's
    /// tokens.
    pub token_label: String,
    /// The serial number that the token reports (`CK_TOKEN_INFO.serialNumber`), for when two of
    /// the module's tokens have the same label. With it, only the token with both values matches.
    #[serde(default)]
    pub token_serial: Option<String>,
    /// A file that holds the user PIN (`$NAME` reads the path from the environment when the PIN
    /// is read: [`Self::pin_path`]). Without this field and without `pinEnv`, the token is used
    /// without a login.
    pub pin_file: Option<PathBuf>,
    /// An environment variable that holds the user PIN. It takes precedence over `pinFile`.
    pub pin_env: Option<String>,
    /// The Security Officer credential, for modules that create and destroy objects only in an
    /// SO session. For ykcs11, it is the PIV management key in hex, or the PIN on a device whose
    /// management key is protected by the PIN. For other modules, it is the SO PIN (camigrate's
    /// `transport --trust-on`). `pinFile` and `pinEnv` remain the *user* credential. The
    /// credential is read just before such a step, and never by `resolve` or `check`. The user
    /// session is restored afterwards, so a user PIN is required. `soCredentialEnv` takes
    /// precedence if both are set, and `soCredentialFile` may be `$NAME`, like `pinFile`. A
    /// provider that does not need the credential refuses it.
    pub so_credential_file: Option<PathBuf>,
    /// An environment variable that holds the SO credential. It takes precedence over
    /// `soCredentialFile`.
    pub so_credential_env: Option<String>,
    /// The settings that only the token's provider understands, as `[tokens.<t>.options]`
    /// (tpm2-pkcs11: `tcti`, `tpm2Store`, `akHandle`). The provider checks them when the token is
    /// opened, and a provider that takes no options refuses any option (17).
    #[serde(default)]
    pub options: Options,
    /// The settings that only caprobe reads (`[tokens.<t>.probe]`).
    #[serde(default)]
    pub probe: ProbeCfg,
    /// The settings that only camigrate reads (`[tokens.<t>.migrate]`).
    #[serde(default)]
    pub migrate: TokenMigrateCfg,
    /// The settings that only the Nix library reads (`[tokens.<t>.nix]`).
    #[serde(default)]
    pub nix: NixCfg,
}

/// A token's settings for caprobe (`[tokens.<t>.probe]`, docs/CAPROBE.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ProbeCfg {
    /// Marks the token as expendable. The write probes generate, wrap, unwrap and destroy objects,
    /// so `probe --write-probes` runs them only on such a token and is refused (17) on any other
    /// token.
    #[serde(default)]
    pub scratch: bool,
    /// The one `CKA_ID` (hex) into which the write probes may generate keys, on a token whose
    /// module creates objects only as the Security Officer, into fixed device slots that `CKA_ID`
    /// names (ykcs11). Such a token holds real keys next to the scratch slot, so `scratch` cannot
    /// mark the whole token. Each generation by the probe replaces the slot's key, and the key that
    /// the last generation made stays there (PIV cannot erase a key). The probe refuses a slot
    /// that holds anything other than its own certificate (`CN=cakeys-probe`, which each run
    /// leaves there) or nothing (review 2026-11-23 D-1).
    pub scratch_id: Option<String>,
}

/// A token's settings for camigrate (`[tokens.<t>.migrate]`, docs/CAMIGRATE.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TokenMigrateCfg {
    /// The spec of this token's transport key (D3): an RSA private key, realised on this token,
    /// that may unwrap and never leaves the token. A sealed move to this token wraps to this key,
    /// and never to a key that camigrate selects by its capabilities (camigrate's
    /// `--transport-spec` overrides it for one run). Its realisation records the public key in the
    /// lock, so any host can export to it. The key never leaves the tokens on which its spec
    /// realises it, as if it had `migrate.noExport`: camigrate refuses it (15) when a run names
    /// it, and leaves it out when a run names no objects.
    pub transport_with: Option<String>,
}

/// A token's settings for the Nix library (`[tokens.<t>.nix]`, docs/CAKEYS.md).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct NixCfg {
    /// The `requiredSystemFeatures` entry. The default is `<featurePrefix><name>` (`lib.mkKeys`'s
    /// `featurePrefix`, whose default is `token-`). The NixOS module advertises
    /// `<featurePrefix><n>` for each of its tokens, so this value names one of those features.
    pub system_feature: Option<String>,
}

/// A token's settings that are specific to its provider (`[tokens.<t>.options]`). The provider
/// parses them.
pub type Options = toml::Table;

impl TokenCfg {
    /// Returns a token with the label `token_label` and nothing else set. This is what a keys.toml
    /// entry with only `tokenLabel` parses to.
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

    /// Returns the provider that keys.toml names: `provider`, or otherwise the family of
    /// `moduleProfile` (`aws-cloudhsm` for `aws-cloudhsm/5.18+hsm2m-non-fips`). `None` means that
    /// the run detects the provider.
    #[must_use]
    pub fn named_provider(&self) -> Option<&str> {
        self.provider
            .as_deref()
            .or_else(|| self.module_profile.as_deref().map(|p| p.split_once('/').map_or(p, |(family, _)| family)))
    }

    /// Returns the module to load, with its `$NAME` reference resolved by `env` at this call. The
    /// caller calls this when it opens the token, so an unset variable fails only a run that uses
    /// this token without `--module`.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` (16) when `module` names an unset variable.
    pub fn module_path(&self, token: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<String>> {
        self.module.as_deref().map(|m| env_ref(m, &format!("token '{token}': module"), env)).transpose()
    }

    /// Returns the file that holds the user PIN (`pinFile`), with its `$NAME` reference resolved
    /// by `env` at this call. The caller calls this when it reads the PIN, so an unset variable
    /// fails only a run that logs in to this token. Returns `None` when keys.toml names no file.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` (16) when `pinFile` names an unset variable, and `Validation` (17) for
    /// a file in the Nix store.
    pub fn pin_path(&self, token: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
        secret_path(self.pin_file.as_deref(), &format!("token '{token}': pinFile"), env)
    }

    /// Returns the file that holds the admin credential (`soCredentialFile`), resolved as
    /// [`Self::pin_path`] resolves its file.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` (16) when `soCredentialFile` names an unset variable, and
    /// `Validation` (17) for a file in the Nix store.
    pub fn so_credential_path(&self, token: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
        secret_path(self.so_credential_file.as_deref(), &format!("token '{token}': soCredentialFile"), env)
    }
}

/// Parses a token's `options` into the provider's own settings type. That type should deny
/// unknown fields, so that a typo is invalid (17) and the error names the token.
///
/// # Errors
///
/// Returns `Validation` if the table does not fit `T`: an unknown option name or a bad value.
pub fn parse_options<T: serde::de::DeserializeOwned>(token: &str, options: &Options) -> Result<T> {
    options.clone().try_into().map_err(|e| KmError::Validation(format!("tokens.{token}.options: {e}").into()))
}
