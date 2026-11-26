//! The configuration file `keys.toml` (an input) and the lock file `keys.lock` (an input that runs
//! update in place).
//!
//! The keys that cakeys defines are camelCase, which suits Nix. PKCS#11 names (`CKA_*`, `CKO_*`,
//! `CKK_*`) are written exactly as PKCS#11 spells them.

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
    /// The objects, by name (`[objects.<name>]`), with the intrinsic type of each object.
    pub objects: BTreeMap<String, ObjectCfg>,
    /// The settings of an object that only camigrate reads (`[objects.<o>.migrate]`), by object
    /// name. They are kept separate from [`ObjectCfg`], which is the type that the lock pins, so
    /// that a path that differs between machines is never part of that type. An object without
    /// the table has no entry.
    pub object_migrate: BTreeMap<String, ObjectMigrateCfg>,
    /// The specs, by name (`[specs.<name>]`): an object's policy and the tokens on which it is
    /// realised.
    pub specs: BTreeMap<String, SpecCfg>,
    /// Directories of module profiles to load in addition to the profiles that this build
    /// embeds (docs/CAPROBE.md). They add a new vendor's profile, and with it the vendor's
    /// provider by family name, without a rebuild. They can only add profiles: a profile in them
    /// may not replace an embedded profile, a layer or the baseline. A `$NAME` reference reads the
    /// environment, as for `pinFile`.
    pub profile_dirs: Vec<PathBuf>,
}

/// keys.toml as written: the [`Config`] before each object's `migrate` table is separated from
/// its type.
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

/// One `[objects.<name>]` table: the object's type (the fields of [`ObjectCfg`]) and its
/// `migrate` table. The fields are written out instead of flattened, because serde's `flatten`
/// would disable `deny_unknown_fields`.
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

/// Returns a secret file's path with its `$NAME` reference resolved, and refuses it when the path
/// is in the Nix store, which everyone can read ([`secret_in_store`]). This is the check that the
/// load could not make for a `$NAME` path.
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

/// Formats the object type as a TOML inline table, in the form that keys.toml uses.
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

/// Formats the locator as a TOML inline table, in the form that keys.toml uses:
/// `{ CKA_LABEL = "k", CKA_ID = "01" }`.
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

/// Reads and checks keys.toml. A `$NAME` path reference reads the process environment.
///
/// # Errors
///
/// Returns every error of [`load_config_with`]: `Io` if the file cannot be read, and `Validation`
/// for a schema violation, a malformed `$NAME` path reference (or an unset one that the load
/// resolves), an admin credential without a user PIN with which to log in again, or a spec that
/// refers to an unknown object.
pub fn load_config(path: &Path) -> Result<Config> {
    load_config_with(path, &|name| std::env::var(name).ok())
}

/// Works as [`load_config`], with `env` to look up the variables that `$NAME` path references
/// name.
///
/// # Errors
///
/// Returns `Io` if the file cannot be read. Returns `Validation` for a schema violation, a
/// malformed `$NAME` path reference (or an unset one that the load resolves), an admin credential
/// without a user PIN with which to log in again, or a spec that refers to an object that
/// keys.toml does not define.
pub fn load_config_with(path: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
    let text = std::fs::read_to_string(path).map_err(KmError::io(format_args!("reading {}", path.display())))?;
    parse_config_with(&text, path, env)
}

/// Works as [`load_config_with`] on text that was already read. `path` is used only to name the
/// file in messages.
///
/// # Errors
///
/// Returns `Validation`, as [`load_config_with`] does.
pub fn parse_config_with(text: &str, path: &Path, env: &dyn Fn(&str) -> Option<String>) -> Result<Config> {
    let invalid = |e: &dyn std::fmt::Display| KmError::Validation(format!("{}: {e}", path.display()).into());
    // The error of a `$NAME` reference starts with the file's name, as every other load error
    // does. A reference that the load resolves belongs to keys.toml itself, so an unset variable
    // is invalid here (17).
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
    // These paths were TOML strings, so they are valid UTF-8, and `to_string_lossy` replaces no
    // characters.
    for dir in &mut cfg.profile_dirs {
        *dir = PathBuf::from(env_ref(&dir.to_string_lossy(), "profileDirs", env)?);
    }
    for (name, o) in &mut cfg.objects {
        o.canonicalize();
        // The type of every object is checked, whether a spec uses the object or not (review
        // V5). A plan reads the type again.
        o.kind().map_err(|e| e.prefixed(format_args!("{}: object '{name}'", path.display())))?;
        check_value_len(o).map_err(|e| invalid(&format_args!("object '{name}': {e}")))?;
    }
    for (name, t) in &mut cfg.tokens {
        // The module path resolves when the token is opened ([`TokenCfg::module_path`]), because
        // `--module` may replace it and a run never needs the module of another token. Only the
        // form of the reference is checked here.
        if let Some(m) = &t.module {
            env_ref(m, &format!("token '{name}': module"), &|_| Some(String::new()))?;
        }
        // The files of the PIN and of the admin credential also resolve when they are used
        // ([`TokenCfg::pin_path`], [`TokenCfg::so_credential_path`]), so that a check that opens
        // no token (`validate`, or a Nix build sandbox) needs no PIN variable.
        for (what, file) in [("pinFile", &t.pin_file), ("soCredentialFile", &t.so_credential_file)] {
            if let Some(f) = file {
                env_ref(&f.to_string_lossy(), &format!("token '{name}': {what}"), &|_| Some(String::new()))?;
            }
        }
        check_token(t).map_err(|e| invalid(&format_args!("token '{name}': {e}")))?;
    }
    // An object's file resolves when camigrate reads it ([`Config::object_file`]). Only the form
    // of the reference is checked here, as for a module path.
    for (name, m) in &cfg.object_migrate {
        for (what, value) in [("file", &m.file), ("passphraseFile", &m.passphrase_file)] {
            if let Some(v) = value {
                env_ref(v, &format!("object '{name}': migrate.{what}"), &|_| Some(String::new()))?;
            }
        }
    }
    check_secret_files(&cfg).map_err(|e| invalid(&e))?;
    // The object to which a spec refers must exist, even when no token uses the spec.
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
    // A configuration that loads must be usable (review D1). Every pair must name a token that
    // keys.toml defines and must pass the plan (`plan_mode`), so that no verb meets a spec that
    // loaded but is refused at every use.
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
    /// Returns the file from which the material of `object` is created (`[objects.<o>.migrate]
    /// file`, docs/FILE.md), with its `$NAME` reference resolved by `env` at this call. Returns
    /// `None` when the object names no file. The path is resolved when it is used, as a module
    /// path is, so that hosts that only run checks can load keys.toml without the variable.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` (16) for an unset `$NAME`. Returns `Validation` (17) for a secret
    /// file that resolves into `/nix/store` ([`Self::secret_material`], `secret_in_store`),
    /// because everyone can read the store.
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

    /// Returns the file that holds the passphrase of the encrypted key file of `object`
    /// (`migrate.passphraseFile`), with `$NAME` resolved by `env`. Returns `None` when the object
    /// names no such file.
    ///
    /// # Errors
    ///
    /// Returns `Unavailable` (16) for an unset `$NAME`. Returns `Validation` (17) for a path that
    /// resolves into `/nix/store`, because a passphrase is a secret, whatever it decrypts.
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

    /// Returns whether the material of `object` is secret at rest: a private or secret key, or a
    /// data object unless every spec of it declares `CKA_PRIVATE = false`. A data object without
    /// a declaration is private (review 2026-11-24 §9.2, D-7), and so is a data object that no
    /// spec names.
    #[must_use]
    pub fn secret_material(&self, object: &str) -> bool {
        match self.objects.get(object).map(|o| o.class) {
            Some(ObjectClass::PrivateKey | ObjectClass::SecretKey) => true,
            Some(ObjectClass::Data) => {
                let mut specs = self.specs.values().filter(|s| s.object == object).peekable();
                specs.peek().is_none() || specs.any(|s| s.restricted(crate::known::Restriction::Private))
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A class or key type that cakeys does not manage is invalid when keys.toml loads (17), and
    /// not only when a run first asks a token for it.
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

    /// A data object's material is secret at rest unless every spec of it declares `CKA_PRIVATE =
    /// false`. A data object for which no spec declares the attribute is private (review
    /// 2026-11-24 §9.2, D-7), and so is a data object that any spec declares private.
    #[test]
    fn a_data_object_is_secret_unless_every_spec_says_public() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("keys.toml");
        let object = |name: &str| format!("[objects.{name}]\nclass = \"CKO_DATA\"\n\n");
        let spec = |name: &str, object: &str, private: Option<bool>| {
            let attrs = private.map_or_else(String::new, |p| format!("attributes = {{ CKA_PRIVATE = {p} }}\n"));
            format!("[specs.{name}]\nobject = \"{object}\"\n{attrs}tokens = {{}}\n\n")
        };
        let text = [
            object("unsaid"),
            spec("unsaid", "unsaid", None),
            object("public"),
            spec("public", "public", Some(false)),
            object("mixed"),
            spec("mixed-public", "mixed", Some(false)),
            spec("mixed-unsaid", "mixed", None),
            object("private"),
            spec("private", "private", Some(true)),
            object("specless"),
        ]
        .concat();
        std::fs::write(&p, text).unwrap();
        let cfg = load_config(&p).unwrap();
        let secret: Vec<(&str, bool)> =
            ["unsaid", "public", "mixed", "private", "specless"].map(|o| (o, cfg.secret_material(o))).to_vec();
        let want = [("unsaid", true), ("public", false), ("mixed", true), ("private", true), ("specless", true)];
        assert_eq!(secret, want);
    }
}
