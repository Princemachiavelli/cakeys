//! `keys.toml` (input) and `keys.lock` (input, updated in place).
//!
//! Our own keys are camelCase (Nix-friendly); PKCS#11 names (`CKA_*`, `CKO_*`, `CKK_*`) are verbatim.

use crate::error::{KmError, Result};
use crate::types::{KeyType, ObjectClass};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

mod address;
mod check;
mod io;
mod lock;
mod object;
mod observe;
mod spec;
mod token;
pub(crate) use check::is_name;
use check::{
    check_names, check_origins, check_scratch_slots, check_secret_files, check_token, check_transport_keys,
    check_value_len, env_ref,
};
pub use io::*;
pub use lock::*;
pub use object::*;
pub use observe::*;
pub use spec::*;
pub use token::*;

/// A parsed `keys.toml` (docs/CONFIG.md): the tokens, the objects, and the specs that realise
/// objects on tokens.
#[derive(Debug, Default, Deserialize)]
#[serde(from = "RawConfig")]
pub struct Config {
    /// The PKCS#11 tokens, by name (`[tokens.<name>]`).
    pub tokens: BTreeMap<String, TokenCfg>,
    /// The objects, by name (`[objects.<name>]`): each one's intrinsic type.
    pub objects: BTreeMap<String, ObjectCfg>,
    /// What only camigrate reads of an object (`[objects.<o>.migrate]`), by object name: kept
    /// apart from [`ObjectCfg`], which is the type the lock pins, so a per-machine path is never
    /// part of it. Objects without the table have no entry.
    pub object_migrate: BTreeMap<String, ObjectMigrateCfg>,
    /// The specs, by name (`[specs.<name>]`): an object's policy and the tokens it is realised on.
    pub specs: BTreeMap<String, SpecCfg>,
    /// Directories of module profiles to load beside the ones this build embeds
    /// (docs/CAPROBE.md): a new vendor's profile, and with it its provider by family name,
    /// without a rebuild. They only add: one may not replace an embedded profile, a layer or the
    /// baseline. `$NAME` references read the environment, as for `pinFile`.
    pub profile_dirs: Vec<PathBuf>,
}

/// keys.toml as written: [`Config`] before an object's `migrate` table is split from its type.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    tokens: BTreeMap<String, TokenCfg>,
    #[serde(default)]
    objects: BTreeMap<String, ObjectEntry>,
    #[serde(default)]
    specs: BTreeMap<String, SpecCfg>,
    #[serde(default, rename = "profileDirs")]
    profile_dirs: Vec<PathBuf>,
}

/// One `[objects.<name>]` table: the object's type ([`ObjectCfg`]'s fields) and its `migrate`
/// table. The fields are spelled out rather than flattened: serde's `flatten` would lose
/// `deny_unknown_fields`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ObjectEntry {
    class: ObjectClass,
    #[serde(default)]
    key_type: Option<KeyType>,
    #[serde(default)]
    certificate_type: Option<String>,
    #[serde(default)]
    curve: Option<String>,
    #[serde(default)]
    value_len: Option<u64>,
    #[serde(default)]
    modulus_bits: Option<u64>,
    #[serde(default)]
    migrate: Option<ObjectMigrateCfg>,
}

impl From<RawConfig> for Config {
    fn from(raw: RawConfig) -> Config {
        let mut objects = BTreeMap::new();
        let mut object_migrate = BTreeMap::new();
        for (name, o) in raw.objects {
            if let Some(m) = o.migrate {
                object_migrate.insert(name.clone(), m);
            }
            let ObjectEntry { class, key_type, certificate_type, curve, value_len, modulus_bits, .. } = o;
            objects.insert(name, ObjectCfg { class, key_type, certificate_type, curve, value_len, modulus_bits });
        }
        Config { tokens: raw.tokens, objects, object_migrate, specs: raw.specs, profile_dirs: raw.profile_dirs }
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Encoding::Raw => "raw",
            Encoding::Hex => "hex",
            Encoding::Base64 => "base64",
        })
    }
}

/// A secret file's path with its `$NAME` reference resolved, and refused when that is in the
/// world-readable Nix store ([`secret_in_store`]): what load could not see of a `$NAME` path.
fn secret_path(path: Option<&Path>, what: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
    let Some(path) = path else { return Ok(None) };
    let path = PathBuf::from(env_ref(&path.to_string_lossy(), what, env)?);
    match secret_in_store(&what, &path) {
        Some(why) => Err(KmError::Validation(why.into())),
        None => Ok(Some(path)),
    }
}

impl std::ops::Deref for Object<'_> {
    type Target = ObjectCfg;

    fn deref(&self) -> &ObjectCfg {
        self.cfg
    }
}

/// Inline-table form, as keys.toml writes it.
impl std::fmt::Display for ObjectCfg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = vec![format!("class = \"{}\"", self.class)];
        fields.extend(self.key_type.map(|k| format!("keyType = \"{k}\"")));
        fields.extend(self.certificate_type.as_ref().map(|c| format!("certificateType = {c:?}")));
        fields.extend(self.curve.as_ref().map(|c| format!("curve = {c:?}")));
        fields.extend(self.value_len.map(|n| format!("valueLen = {n}")));
        fields.extend(self.modulus_bits.map(|n| format!("modulusBits = {n}")));
        write!(f, "{{ {} }}", fields.join(", "))
    }
}

impl std::fmt::Display for AttrValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttrValue::Bool(b) => write!(f, "{b}"),
            AttrValue::Mechanisms(m) => write!(f, "[{}]", m.join(", ")),
        }
    }
}

impl std::fmt::Display for KeyOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Inline-table form, as keys.toml writes it: `{ CKA_LABEL = "k", CKA_ID = "01" }`.
impl std::fmt::Display for Locator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = Vec::new();
        if let Some(l) = &self.label {
            fields.push(format!("CKA_LABEL = {l:?}"));
        }
        if let Some(i) = &self.id {
            fields.push(format!("CKA_ID = {i:?}"));
        }
        write!(f, "{{ {} }}", fields.join(", "))
    }
}

/// Read and check keys.toml; `$NAME` path references read the process environment.
///
/// # Errors
///
/// Whatever [`load_config_with`] rejects: `Io` if the file cannot be read; `Validation` for
/// a schema violation, a malformed or unset `$NAME` path reference, an admin credential
/// without a user PIN to return to, or a spec that references an unknown object.
pub fn load_config(path: &Path) -> Result<Config> {
    load_config_with(path, &|name| std::env::var(name).ok())
}

/// [`load_config`], with `env` looking up the variables `$NAME` path references name.
///
/// # Errors
///
/// `Io` if the file cannot be read; `Validation` for a schema violation, a malformed or unset
/// `$NAME` path reference, an admin credential without a user PIN to return to, or a spec that
/// references an object keys.toml does not define.
pub fn load_config_with(path: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
    let text = std::fs::read_to_string(path).map_err(KmError::io(format_args!("reading {}", path.display())))?;
    parse_config_with(&text, path, env)
}

/// [`load_config_with`] on text already read; `path` only names it in messages.
///
/// # Errors
///
/// `Validation`, as [`load_config_with`].
pub fn parse_config_with(text: &str, path: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
    let invalid = |e: &dyn std::fmt::Display| KmError::Validation(format!("{}: {e}", path.display()).into());
    // A `$NAME` reference's error, named by the file as every other load error is: one resolved
    // at load is keys.toml's own, so unset is invalid here (17).
    let env_ref = |value: &str, what: &str, env: &dyn Fn(&str) -> Option<String>| {
        env_ref(value, what, env).map_err(|e| {
            match e {
                KmError::Unavailable(m) => KmError::Validation(m),
                e => e,
            }
            .prefixed(path.display())
        })
    };
    let mut cfg: Config = toml::from_str(text).map_err(|e| invalid(&e))?;
    check_names(&cfg).map_err(|e| invalid(&e))?;
    // These paths were TOML strings, so UTF-8: `to_string_lossy` replaces nothing.
    for dir in &mut cfg.profile_dirs {
        *dir = PathBuf::from(env_ref(&dir.to_string_lossy(), "profileDirs", env)?);
    }
    for (name, o) in &mut cfg.objects {
        o.canonicalize();
        // Every object's type, used by a spec or not (review V5); a plan reads it again.
        o.kind().map_err(|e| e.prefixed(format_args!("{}: object '{name}'", path.display())))?;
        check_value_len(o).map_err(|e| invalid(&format_args!("object '{name}': {e}")))?;
    }
    for (name, t) in &mut cfg.tokens {
        // The module resolves when the token is opened ([`TokenCfg::module_path`]): `--module`
        // may replace it, and a run never needs another token's module. Only its form is checked.
        if let Some(m) = &t.module {
            env_ref(m, &format!("token '{name}': module"), &|_| Some(String::new()))?;
        }
        // So are the PIN's and the admin credential's files ([`TokenCfg::pin_path`],
        // [`TokenCfg::so_credential_path`]): a check that opens no token (`validate`, a Nix build
        // sandbox) needs no PIN variable.
        for (what, file) in [("pinFile", &t.pin_file), ("soCredentialFile", &t.so_credential_file)] {
            if let Some(f) = file {
                env_ref(&f.to_string_lossy(), &format!("token '{name}': {what}"), &|_| Some(String::new()))?;
            }
        }
        check_token(t).map_err(|e| invalid(&format_args!("token '{name}': {e}")))?;
    }
    // An object's file resolves when camigrate reads it ([`Config::object_file`]); only its form
    // is checked here, as a module path's.
    for (name, m) in &cfg.object_migrate {
        for (what, value) in [("file", &m.file), ("passphraseFile", &m.passphrase_file)] {
            if let Some(v) = value {
                env_ref(v, &format!("object '{name}': migrate.{what}"), &|_| Some(String::new()))?;
            }
        }
    }
    check_secret_files(&cfg).map_err(|e| invalid(&e))?;
    // A spec's object reference must name something, also when no token ever uses the spec.
    for (spec, s) in &cfg.specs {
        if !cfg.objects.contains_key(&s.object) {
            return Err(invalid(&format_args!("spec '{spec}' references unknown object '{}'", s.object)));
        }
    }
    for s in cfg.specs.values_mut() {
        for v in s.attributes.values_mut().chain(s.public_attributes.values_mut()) {
            if let AttrValue::Mechanisms(m) = v {
                *v = AttrValue::mechanisms(std::mem::take(m));
            }
        }
    }
    for (spec, s) in &mut cfg.specs {
        for (token, on) in &mut s.tokens {
            on.locator.canonicalize().map_err(|e| invalid(&format_args!("spec '{spec}' on token '{token}': {e}")))?;
        }
    }
    check_origins(&cfg).map_err(|e| invalid(&e))?;
    check_transport_keys(&cfg).map_err(|e| invalid(&e))?;
    check_scratch_slots(&cfg).map_err(|e| invalid(&e))?;
    // What loads is usable (review D1): every pair names a token keys.toml defines and plans
    // (`plan_mode`), so no verb meets a spec that loaded and is refused at every use.
    for (spec, s) in &cfg.specs {
        for token in s.tokens.keys() {
            crate::plan::Target::new(&cfg, spec, token).and_then(|t| crate::plan::plan_mode(&t)).map_err(
                |e| match e {
                    KmError::Validation(m) => invalid(&m),
                    other => other,
                },
            )?;
        }
    }
    Ok(cfg)
}

impl Config {
    /// The file `object`'s material is born in (`[objects.<o>.migrate] file`, docs/FILE.md), its
    /// `$NAME` reference resolved by `env` now; `None` when the object names none. Resolved at
    /// use, as a module path is, so hosts that only check load keys.toml without the variable.
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) for an unset `$NAME`; `Validation` (17) for a secret file that resolves into
    /// `/nix/store` ([`Self::secret_material`], `secret_in_store`): the store is world-readable.
    pub fn object_file(&self, object: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<Option<PathBuf>> {
        let Some(file) = self.object_migrate.get(object).and_then(|m| m.file.as_deref()) else { return Ok(None) };
        let what = format!("object '{object}': migrate.file");
        let path = PathBuf::from(env_ref(file, &what, env)?);
        if self.secret_material(object)
            && let Some(why) = secret_in_store(&what, &path)
        {
            return Err(KmError::Validation(why.into()));
        }
        Ok(Some(path))
    }

    /// The file holding the passphrase of `object`'s encrypted key file (`migrate.passphraseFile`),
    /// `$NAME` resolved by `env`; `None` when it names none.
    ///
    /// # Errors
    ///
    /// `Unavailable` (16) for an unset `$NAME`; `Validation` (17) for a path that resolves into
    /// `/nix/store`: a passphrase is a secret whatever it decrypts.
    pub fn object_passphrase_file(
        &self,
        object: &str,
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Option<PathBuf>> {
        let Some(file) = self.object_migrate.get(object).and_then(|m| m.passphrase_file.as_deref()) else {
            return Ok(None);
        };
        let what = format!("object '{object}': migrate.passphraseFile");
        let path = PathBuf::from(env_ref(file, &what, env)?);
        if let Some(why) = secret_in_store(&what, &path) {
            return Err(KmError::Validation(why.into()));
        }
        Ok(Some(path))
    }

    /// Whether `object`'s material is secret at rest: a private or secret key, or a data object a
    /// spec declares `CKA_PRIVATE = true`.
    #[must_use]
    pub fn secret_material(&self, object: &str) -> bool {
        match self.objects.get(object).map(|o| o.class) {
            Some(ObjectClass::PrivateKey | ObjectClass::SecretKey) => true,
            Some(ObjectClass::Data) => {
                self.specs.values().any(|s| s.object == object && s.flag("CKA_PRIVATE") == Some(true))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A class or key type cakeys does not manage is invalid when keys.toml loads (17), not when
    /// a token is first asked for it.
    #[test]
    fn unknown_classes_and_key_types_are_invalid_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("keys.toml");
        for object in ["class = \"CKO_OTP_KEY\"", "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES2\""] {
            std::fs::write(&p, format!("[objects.o]\n{object}\n")).unwrap();
            let err = load_config(&p).unwrap_err();
            assert!(matches!(err, KmError::Validation(_)), "{err}");
        }
    }
}
