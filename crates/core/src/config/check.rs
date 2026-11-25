//! keys.toml's load rules beyond its schema (review 2026-11-23 A-7): what `parse_config_with`
//! checks across objects, specs and tokens once the file has parsed.

use super::{Config, KeyOrigin, ObjectCfg, TokenCfg, secret_in_store};
use crate::error::{KmError, Result};
use crate::types::{KeyType, ObjectClass};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A secret key's `valueLen` is one its commitment label can carry, and the one its key type
/// fixes when it fixes one.
pub(super) fn check_value_len(o: &ObjectCfg) -> std::result::Result<(), String> {
    let Some(len) = o.value_len else { return Ok(()) };
    // The commitment label carries 8 × valueLen bits (docs/DESIGN.md §3.3): bound it so that
    // never overflows (tests/properties.rs: `commitment_labels_are_injective`).
    if len > u64::from(u32::MAX) {
        return Err(format!("valueLen {len} bytes is out of range"));
    }
    if o.class == ObjectClass::SecretKey
        && let Some(kt) = o.key_type
        && let Some(fixed) = kt.fixed_value_len()
        && len != fixed
    {
        return Err(format!("a {kt} key is {fixed} bytes; leave valueLen out or write {fixed}, not {len}"));
    }
    // Lengths no module makes: refused at load rather than by the module at `create` (review D1).
    if o.class == ObjectClass::SecretKey && o.key_type == Some(KeyType::Aes) && ![16, 24, 32].contains(&len) {
        return Err(format!("an AES key is 16, 24 or 32 bytes, not {len}"));
    }
    if o.class == ObjectClass::SecretKey && len == 0 {
        return Err("valueLen 0: a secret key has at least one byte".into());
    }
    Ok(())
}

/// One token's settings agree with each other: `provider` names a family and `moduleProfile` a
/// profile of it, `probe.scratchId` is a hex `CKA_ID`, and an SO credential comes with a user PIN.
pub(super) fn check_token(t: &TokenCfg) -> std::result::Result<(), String> {
    // `provider` names a family; one profile of it is `moduleProfile`.
    if let Some(p) = t.provider.as_deref().filter(|p| p.contains('/')) {
        return Err(format!(
            "provider = \"{p}\" names one module profile; name its family in provider and the profile in \
             moduleProfile = \"{p}\""
        ));
    }
    if let (Some(family), Some(profile)) = (t.provider.as_deref(), t.module_profile.as_deref())
        && profile.split_once('/').map_or(profile, |(f, _)| f) != family
    {
        return Err(format!("moduleProfile '{profile}' is not of provider '{family}''s family"));
    }
    if let Some(id) = &t.probe.scratch_id
        && crate::hex::decode(id).is_none_or(|b| b.is_empty())
    {
        return Err(format!("probe.scratchId {id:?} is not a hex CKA_ID"));
    }
    // An SO step logs the user out; without a user PIN to return to, the new private key could
    // not be found again, let alone proven.
    if (t.so_credential_file.is_some() || t.so_credential_env.is_some()) && t.pin_file.is_none() && t.pin_env.is_none()
    {
        return Err("soCredentialFile/soCredentialEnv needs a user PIN (pinFile or pinEnv) to return to the user \
                    session"
            .into());
    }
    Ok(())
}

/// A token's `probe.scratchId` is the `CKA_ID` of no locator keys.toml has on that token: the
/// write probes overwrite that slot's key, and a key keys.toml declares there is a real one
/// (review 2026-11-23 D-1: one digit off, the probe replaced it).
pub(super) fn check_scratch_slots(cfg: &Config) -> std::result::Result<(), String> {
    for (token, t) in &cfg.tokens {
        let Some(scratch) = t.probe.scratch_id.as_deref().and_then(crate::hex::decode) else { continue };
        let mut declared = cfg.specs.iter().filter_map(|(spec, s)| {
            let id = s.tokens.get(token)?.locator.id.as_deref().and_then(crate::hex::decode)?;
            (id == scratch).then_some(spec)
        });
        if let Some(spec) = declared.next() {
            return Err(format!(
                "token '{token}': probe.scratchId {} is the CKA_ID of spec '{spec}''s locator there: the write probes \
                 would overwrite that key; name a slot keys.toml does not use",
                crate::hex::encode(&scratch)
            ));
        }
    }
    Ok(())
}

/// Whether `n` is a name: `[A-Za-z0-9][A-Za-z0-9_-]*` ([`check_names`]; a vendor method's parts,
/// `migrate::Method::from_name`).
pub(crate) fn is_name(n: &str) -> bool {
    n.starts_with(|c: char| c.is_ascii_alphanumeric())
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Object, spec and token names are `[A-Za-z0-9][A-Za-z0-9_-]*`: `check` splits a reference on
/// `.id.`, the lock and `gc` join names with dots, and the Nix library puts them in a shell
/// command. Invalid at load (17), before any other rule names them.
pub(super) fn check_names(cfg: &Config) -> std::result::Result<(), String> {
    let names = cfg
        .objects
        .keys()
        .map(|n| ("object", n))
        .chain(cfg.specs.keys().map(|n| ("spec", n)))
        .chain(cfg.tokens.keys().map(|n| ("token", n)))
        .chain(cfg.specs.values().flat_map(|s| s.tokens.keys().map(|n| ("token", n))));
    for (what, name) in names {
        if !is_name(name) {
            return Err(format!(
                "{what} name {name:?}: names are letters, digits, '-' and '_', starting with a letter or digit"
            ));
        }
    }
    Ok(())
}

/// Each `transportWith` names a spec realised on its own token whose object is an RSA private
/// key declared to unwrap and never leave the token (docs/CAMIGRATE.md D3).
pub(super) fn check_transport_keys(cfg: &Config) -> std::result::Result<(), String> {
    for (token, t) in &cfg.tokens {
        let Some(spec) = &t.migrate.transport_with else { continue };
        let what = format!("token '{token}': migrate.transportWith = \"{spec}\"");
        let Some(s) = cfg.specs.get(spec) else { return Err(format!("{what} names no spec")) };
        if !s.tokens.contains_key(token) {
            return Err(format!("{what}, but that spec does not realise it on '{token}'"));
        }
        let rsa = cfg
            .objects
            .get(&s.object)
            .is_some_and(|o| o.class == ObjectClass::PrivateKey && o.key_type == Some(KeyType::Rsa));
        if !rsa {
            return Err(format!("{what}: a transport key is an RSA private key, and '{}' is not", s.object));
        }
        // What it protects is no better guarded than it (camigrate refuses a smaller one found
        // on a token too).
        if let Some(bits) = cfg.objects.get(&s.object).and_then(|o| o.modulus_bits).filter(|b| *b < 2048) {
            return Err(format!("{what}: a transport key has at least 2048 bits, and '{}' declares {bits}", s.object));
        }
        if s.flag("CKA_UNWRAP") != Some(true) || s.flag("CKA_EXTRACTABLE") != Some(false) {
            return Err(format!(
                "{what}: a transport key declares CKA_UNWRAP = true and CKA_EXTRACTABLE = false in its attributes"
            ));
        }
    }
    Ok(())
}

/// No file keys.toml names to hold a secret is in the world-readable Nix store
/// ([`secret_in_store`]): `pinFile`, `soCredentialFile`, `migrate.passphraseFile`, and
/// `migrate.file` when the object's material is secret ([`Config::secret_material`]). A `$NAME`
/// path is checked when it resolves ([`TokenCfg::pin_path`], [`Config::object_file`],
/// [`Config::object_passphrase_file`]), and every secret file again when it is read
/// (`secret::read`), so a link changed since load is caught too.
pub(super) fn check_secret_files(cfg: &Config) -> std::result::Result<(), String> {
    let literal = |v: &Option<String>| v.clone().filter(|f| !f.starts_with('$')).map(PathBuf::from);
    let tokens = cfg.tokens.iter().flat_map(|(name, t)| {
        [("pinFile", &t.pin_file), ("soCredentialFile", &t.so_credential_file)].into_iter().filter_map(
            move |(what, p)| {
                let p = p.clone().filter(|p| !p.to_string_lossy().starts_with('$'))?;
                Some((format!("token '{name}': {what}"), p))
            },
        )
    });
    let objects = cfg.object_migrate.iter().flat_map(|(object, m)| {
        let file = literal(&m.file).filter(|_| cfg.secret_material(object));
        [("file", file), ("passphraseFile", literal(&m.passphrase_file))]
            .into_iter()
            .filter_map(move |(what, p)| Some((format!("object '{object}': migrate.{what}"), p?)))
    });
    tokens.chain(objects).find_map(|(what, path)| secret_in_store(&what, &path)).map_or(Ok(()), Err)
}

/// Each pair's `origin` fits its object (docs/CONFIG.md): a private or secret key states it; a
/// `publicOnly` adoption, a certificate, a public key and a data object are never created; a
/// `CKA_TRUSTED` key cannot be generated; and an object is created by at most one pair, which
/// says where its material is born and with whose policy, so no order of a run decides either.
/// A file is a birthplace too (docs/FILE.md): `origin = "file"` needs the object's
/// `migrate.file`, and an object born in a file is never also created on a token.
pub(super) fn check_origins(cfg: &Config) -> std::result::Result<(), String> {
    for (object, m) in &cfg.object_migrate {
        if m.file.is_none() && (m.passphrase_file.is_some() || m.passphrase_env.is_some()) {
            return Err(format!("object '{object}': migrate.passphraseFile/passphraseEnv without migrate.file"));
        }
        if let Some(e) = m.encoding {
            if m.file.is_none() {
                return Err(format!("object '{object}': migrate.encoding without migrate.file"));
            }
            // Any other object's file is taken as it is: a data object's value may well be hex text.
            if cfg.objects.get(object).is_some_and(|o| o.class != ObjectClass::SecretKey) {
                return Err(format!(
                    "object '{object}': migrate.encoding = \"{e}\" applies to secret keys only; any other \
                     object's file is read for what it holds"
                ));
            }
        }
        // A secret key's file may hold its value or hex or base64 text of it, and only the length
        // tells them apart; without one, the file's first read would pin a guess (docs/FILE.md F4).
        if m.file.is_some()
            && m.encoding.is_none()
            && cfg.objects.get(object).is_some_and(|o| o.class == ObjectClass::SecretKey && o.value_len.is_none())
        {
            return Err(format!(
                "object '{object}': a secret key's migrate.file needs the key's valueLen or migrate.encoding = \
                 \"raw\", \"hex\" or \"base64\": its value, hex and base64 of it are told apart by length alone"
            ));
        }
    }
    // Every (spec, token) pair's origin on its own, then across pairs: at most one creates each object.
    let mut created: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for (spec_name, spec) in &cfg.specs {
        let Some(object) = cfg.objects.get(&spec.object) else { continue };
        let key = matches!(object.class, ObjectClass::PrivateKey | ObjectClass::SecretKey);
        let has_file = cfg.object_migrate.get(&spec.object).is_some_and(|m| m.file.is_some());
        for (token, on) in &spec.tokens {
            let what = format!("spec '{spec_name}' on token '{token}'");
            let Some(origin) = on.origin else {
                // Unset means "adopt", except for a key's private or secret material, which must say.
                if key && !on.public_only {
                    return Err(format!(
                        "{what}: a private or secret key states its origin: \"create\" (`cakeys create` makes it \
                         here), \"import\" (camigrate brings it), \"file\" (camigrate brings it from the object's \
                         migrate.file) or \"adopt\" (it is already there)"
                    ));
                }
                continue;
            };
            if on.public_only && origin != KeyOrigin::Adopt {
                return Err(format!("{what}: publicOnly adopts the public half, never origin = \"{origin}\""));
            }
            if origin == KeyOrigin::File && !has_file {
                return Err(format!(
                    "{what}: origin = \"file\" reads the object's migrate.file, and object '{}' names none",
                    spec.object
                ));
            }
            if origin != KeyOrigin::Create {
                continue;
            }
            if !key {
                return Err(format!("{what}: {} objects are adopted or imported, never created", object.class));
            }
            if has_file {
                return Err(format!(
                    "{what}: object '{}' is born in its migrate.file, so it is never created on a token; \
                     origin = \"file\", \"import\" or \"adopt\"",
                    spec.object
                ));
            }
            if spec.flag("CKA_TRUSTED") == Some(true) {
                return Err(format!(
                    "{what}: CKA_TRUSTED = true cannot be generated (the token's security officer sets it): \
                     origin = \"adopt\" or \"import\""
                ));
            }
            created.entry(spec.object.as_str()).or_default().push(what);
        }
    }
    if let Some((object, pairs)) = created.iter().find(|(_, pairs)| pairs.len() > 1) {
        return Err(format!(
            "object '{object}' has origin = \"create\" on several pairs ({}): a key is created once, on one \
             token and with one spec's policy; the other pairs import or adopt it",
            pairs.join(", ")
        ));
    }
    Ok(())
}

/// A whole-value environment reference in a path field: `$NAME` or `${NAME}` becomes the value of
/// the environment variable `NAME`, so one shared `keys.toml` can carry a machine-specific pin
/// file or module path. A value with no leading `$` is a literal path. A malformed reference fails
/// at load (exit 17); an unset one fails where the path is used: `module` when its token is
/// opened ([`TokenCfg::module_path`], so `--module` can stand in for it), `pinFile` and
/// `soCredentialFile` when the secret is read ([`TokenCfg::pin_path`]), so a check that touches
/// no token needs no PIN variable.
pub(super) fn env_ref(value: &str, what: &str, env: &dyn Fn(&str) -> Option<String>) -> Result<String> {
    let name = match value.strip_prefix('$') {
        Some(rest) => rest.strip_prefix('{').and_then(|r| r.strip_suffix('}')).unwrap_or(rest),
        None => return Ok(value.to_owned()),
    };
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(KmError::Validation(
            format!("{what}: \"{value}\" is neither $NAME, ${{NAME}} nor a literal path").into(),
        ));
    }
    // Unset is this host's environment not providing it, as an unset `pinEnv` is (16); only a
    // reference that is not one is invalid (review 2026-11-23 A-14).
    env(name).ok_or_else(|| {
        KmError::Unavailable(format!("{what}: environment variable {name} (\"{value}\") is not set").into())
    })
}
