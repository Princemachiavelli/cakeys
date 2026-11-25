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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_config_with, parse_config_with};
    use std::path::Path;

    /// Object, spec and token names have one grammar, checked at load (17): a reference splits
    /// on `.id.`, and shell commands are built from them.
    #[test]
    fn names_are_letters_digits_dashes_and_underscores() {
        let load = |object: &str, spec: &str, token: &str| {
            let text = format!(
                "[tokens.\"{token}\"]\ntokenLabel = \"t\"\n\n\
                 [objects.\"{object}\"]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                 [specs.\"{spec}\"]\nobject = \"{object}\"\nattributes = {{ CKA_SIGN = true }}\n\
                 tokens.\"{token}\" = {{ locator = {{ CKA_LABEL = \"k\" }}, origin = \"adopt\" }}\n"
            );
            parse_config_with(&text, Path::new("keys.toml"), &|_| None)
        };
        load("k", "k-soft_2", "0soft").unwrap();
        for (object, spec, token, what) in [
            ("a b; echo pwned #", "s", "t", "object name \"a b; echo pwned #\""),
            ("k.id.x", "s", "t", "object name \"k.id.x\""),
            ("k", "-s", "t", "spec name \"-s\""),
            ("k", "s", "my token", "token name \"my token\""),
            ("k", "s", "", "token name \"\""),
            ("k", "s", "tök", "token name \"tök\""),
        ] {
            let e = load(object, spec, token).unwrap_err();
            assert!(matches!(e, KmError::Validation(_)) && e.to_string().contains(what), "{e}");
        }
    }

    /// Every pair says how its object comes to be there (`origin`), checked at load (17): a
    /// private or secret key states it; what is never generated (a certificate, a public key, a
    /// data object, a `publicOnly` adoption, a `CKA_TRUSTED` key) is not `create`; and an object
    /// is created by one pair at most. The retired `autoCreate` and `createOn` are unknown fields.
    #[test]
    fn origins_say_how_an_object_comes_to_be_on_a_token() {
        let load = |class: &str, a: &str, b: &str, second_spec: &str| {
            // A usage each pair can prove possession by; none for what has no private half.
            let attributes = if class.contains("CKO_CERTIFICATE") || a.contains("publicOnly") {
                ""
            } else {
                "attributes = { CKA_SIGN = true }\n"
            };
            let text = format!(
                "[tokens.a]\ntokenLabel = \"a\"\n[tokens.b]\ntokenLabel = \"b\"\n\n\
                 [objects.k]\n{class}\n\n\
                 [specs.k]\nobject = \"k\"\n{attributes}\
                 tokens.a = {{ locator = {{ CKA_LABEL = \"k\" }}{a} }}\n\
                 tokens.b = {{ locator = {{ CKA_LABEL = \"k\" }}{b} }}\n{second_spec}"
            );
            parse_config_with(&text, Path::new("keys.toml"), &|_| None)
        };
        let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
        let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
        let cert = "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"";
        let (create, import, adopt) = (", origin = \"create\"", ", origin = \"import\"", ", origin = \"adopt\"");
        let cfg = load(ec, create, import, "").unwrap();
        let on = |t: &str| cfg.specs["k"].tokens[t].key_origin();
        assert_eq!((on("a"), on("b")), (KeyOrigin::Create, KeyOrigin::Import));
        load(aes, adopt, adopt, "").unwrap();
        // What is never created is adopted unless it says otherwise.
        let cfg = load(cert, "", import, "").unwrap();
        assert_eq!(cfg.specs["k"].tokens["a"].key_origin(), KeyOrigin::Adopt);
        load(ec, ", publicOnly = true", ", publicOnly = true, origin = \"adopt\"", "").unwrap();

        let refused = |r: Result<Config>, what: &str| {
            let e = r.unwrap_err();
            assert!(matches!(e, KmError::Validation(_)) && e.to_string().contains(what), "{e}");
        };
        refused(load(ec, "", adopt, ""), "spec 'k' on token 'a': a private or secret key states its origin");
        refused(load(aes, adopt, "", ""), "spec 'k' on token 'b': a private or secret key states its origin");
        refused(load(cert, create, "", ""), "CKO_CERTIFICATE objects are adopted or imported, never created");
        refused(load(ec, ", publicOnly = true, origin = \"import\"", adopt, ""), "never origin = \"import\"");
        let trusted = "\n[specs.t]\nobject = \"k\"\nattributes = { CKA_WRAP = true, CKA_TRUSTED = true }\n";
        refused(
            load(aes, adopt, adopt, &format!("{trusted}tokens.a = {{ locator = {{ CKA_LABEL = \"t\" }}{create} }}\n")),
            "CKA_TRUSTED = true cannot be generated",
        );
        // Created once: two tokens, or two specs on one token, would leave it to the run.
        refused(load(ec, create, create, ""), "has origin = \"create\" on several pairs");
        let second =
            format!("\n[specs.k2]\nobject = \"k\"\ntokens.a = {{ locator = {{ CKA_LABEL = \"k\" }}{create} }}\n");
        refused(load(ec, create, adopt, &second), "spec 'k' on token 'a', spec 'k2' on token 'a'");
        // The retired keys.
        refused(load(ec, ", autoCreate = true", adopt, ""), "unknown field `autoCreate`");
        refused(load(&format!("{ec}\ncreateOn = \"a\""), create, adopt, ""), "unknown field `createOn`");
    }

    /// An object born in a file (docs/FILE.md F1, F2): `origin = "file"` on any number of pairs,
    /// read from the object's `migrate.file`, which is never part of the type the lock pins; a
    /// file is a birthplace, so the object is never also created; a secret file is kept out of
    /// the Nix store, a literal path at load and a `$NAME` one when it is read.
    #[test]
    fn objects_born_in_files_read_their_migrate_file() {
        let load = |object: &str, a: &str, b: &str| {
            // A usage each pair can prove possession or commit by (DES3 only by encrypting).
            let attributes = match object {
                o if o.contains("CKO_CERTIFICATE") => "",
                o if o.contains("CKK_DES3") => "attributes = { CKA_ENCRYPT = true }\n",
                _ => "attributes = { CKA_SIGN = true }\n",
            };
            let text = format!(
                "[tokens.a]\ntokenLabel = \"a\"\n[tokens.b]\ntokenLabel = \"b\"\n\n\
                 [objects.k]\n{object}\n\n\
                 [specs.k]\nobject = \"k\"\n{attributes}\
                 tokens.a = {{ locator = {{ CKA_LABEL = \"k\" }}{a} }}\n\
                 tokens.b = {{ locator = {{ CKA_LABEL = \"k\" }}{b} }}\n"
            );
            parse_config_with(&text, Path::new("keys.toml"), &|_| None)
        };
        let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
        let cert = "class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"";
        let file = |path: &str| format!("\nmigrate = {{ file = \"{path}\" }}");
        let (from_file, create, adopt) = (", origin = \"file\"", ", origin = \"create\"", ", origin = \"adopt\"");
        let cfg = load(&(ec.to_owned() + &file("/run/keys/k.pem")), from_file, from_file).unwrap();
        assert_eq!(cfg.specs["k"].tokens["b"].key_origin(), KeyOrigin::File);
        assert_eq!(
            cfg.objects["k"],
            ObjectCfg { curve: Some("secp256r1".into()), ..ObjectCfg::new(ObjectClass::PrivateKey, Some(KeyType::Ec)) }
        );
        assert_eq!(cfg.object_file("k", &|_| None).unwrap(), Some(PathBuf::from("/run/keys/k.pem")));
        // A `$NAME` path resolves when it is read: unset, it fails that read, not the load.
        let cfg = load(&(ec.to_owned() + &file("$KEY_FILE")), from_file, adopt).unwrap();
        assert!(cfg.object_file("k", &|_| None).is_err());
        let store = |_: &str| Some("/nix/store/abc-k.pem".to_owned());
        assert!(cfg.object_file("k", &store).unwrap_err().to_string().contains("Nix store"));
        // A certificate is no secret: from the store it may come.
        let cfg = load(&(cert.to_owned() + &file("/nix/store/abc-c.pem")), from_file, "").unwrap();
        assert!(cfg.object_file("k", &|_| None).unwrap().is_some());

        let refused = |r: Result<Config>, what: &str| {
            let e = r.unwrap_err();
            assert!(matches!(e, KmError::Validation(_)) && e.to_string().contains(what), "{e}");
        };
        refused(
            load(ec, from_file, adopt),
            "origin = \"file\" reads the object's migrate.file, and object 'k' names none",
        );
        refused(load(&(ec.to_owned() + &file("/k.pem")), create, adopt), "is born in its migrate.file");
        refused(load(&(ec.to_owned() + &file("/nix/store/abc-k.pem")), from_file, adopt), "Nix store");
        refused(
            load(&(ec.to_owned() + "\nmigrate = { passphraseFile = \"/p\" }"), adopt, adopt),
            "without migrate.file",
        );
        refused(load(&(ec.to_owned() + &file("$")), adopt, adopt), "migrate.file");
        // A secret key's file may say how it spells the value; no other object's may.
        let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"";
        let encoded = |e: &str| format!("\nmigrate = {{ file = \"/k\", encoding = \"{e}\" }}");
        for e in ["raw", "hex", "base64"] {
            let cfg = load(&(aes.to_owned() + &encoded(e)), from_file, adopt).unwrap();
            assert_eq!(cfg.object_migrate["k"].encoding.map(|e| e.to_string()).as_deref(), Some(e));
        }
        // Without valueLen, the encoding is said; a key type's fixed length is a valueLen.
        refused(
            load(&(aes.to_owned() + &file("/k")), from_file, adopt),
            "needs the key's valueLen or migrate.encoding",
        );
        load(&(aes.to_owned() + "\nvalueLen = 16" + &file("/k")), from_file, adopt).unwrap();
        load(&("class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"".to_owned() + &file("/k")), from_file, adopt)
            .unwrap();
        refused(load(&(ec.to_owned() + &encoded("hex")), from_file, adopt), "applies to secret keys only");
        refused(load(&(aes.to_owned() + &encoded("base32")), from_file, adopt), "unknown variant `base32`");
        refused(
            load(&(aes.to_owned() + "\nmigrate = { encoding = \"hex\" }"), adopt, adopt),
            "migrate.encoding without migrate.file",
        );
        refused(load(&(ec.to_owned() + "\nmigrate = { path = \"/k\" }"), adopt, adopt), "unknown field `path`");
        refused(
            load(&(ec.to_owned() + &file("/k.pem")), ", publicOnly = true, origin = \"file\"", adopt),
            "never origin = \"file\"",
        );
    }

    /// Every file keys.toml names to hold a secret is refused (17) when it resolves into the
    /// world-readable Nix store: `pinFile`, `soCredentialFile`, `migrate.passphraseFile`, and a
    /// secret object's `migrate.file`; at load for a literal path, and for a `$NAME` one when it
    /// resolves (`pin_path` for a pin file, camigrate for a migrate path); through a symlink or a
    /// `..` as directly (review config.rs F4).
    #[test]
    fn no_secret_file_is_in_the_nix_store() {
        let dir = tempfile::tempdir().unwrap();
        let result = dir.path().join("result");
        std::os::unix::fs::symlink("/nix/store", &result).unwrap();
        let elsewhere = dir.path().join("keys");
        std::fs::create_dir(&elsewhere).unwrap();
        let in_store = [
            "/nix/store/abc-secret".to_owned(),
            format!("{}/abc-secret", result.display()),
            format!("{}/../result/abc-secret", elsewhere.display()),
        ];
        let outside = [format!("{}/secret", elsewhere.display()), format!("{}/../keys/secret", result.display())];
        let ec = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n";
        let fields = [
            ("[tokens.t]\ntokenLabel = \"t\"\npinFile = \"{}\"\n", "token 't': pinFile"),
            ("[tokens.t]\ntokenLabel = \"t\"\npinFile = \"/p\"\nsoCredentialFile = \"{}\"\n", "soCredentialFile"),
            ("{ec}migrate = { file = \"/run/k.p12\", passphraseFile = \"{}\" }\n", "migrate.passphraseFile"),
            ("{ec}migrate = { file = \"{}\" }\n", "object 'k': migrate.file"),
        ];
        let load = |text: &str| parse_config_with(text, Path::new("keys.toml"), &|_| None);
        for (template, what) in fields {
            let at = |p: &str| template.replace("{ec}", ec).replace("{}", p);
            for p in &in_store {
                let e = load(&at(p)).unwrap_err();
                assert!(
                    matches!(&e, KmError::Validation(m) if m.contains(what) && m.contains("Nix store")),
                    "{what} {p}: {e}"
                );
            }
            for p in &outside {
                load(&at(p)).unwrap_or_else(|e| panic!("{what} {p}: {e}"));
            }
        }
        // A `$NAME` pin file is checked when it resolves, as a migrate path is.
        let cfg = load("[tokens.t]\ntokenLabel = \"t\"\npinFile = \"$PIN_FILE\"\n").unwrap();
        let pin = cfg.tokens["t"].pin_path("t", &|_| Some(in_store[1].clone()));
        assert!(matches!(&pin, Err(KmError::Validation(m)) if m.contains("Nix store")), "{:?}", pin.err());
        let fine = cfg.tokens["t"].pin_path("t", &|_| Some(outside[0].clone()));
        assert_eq!(fine.unwrap(), Some(PathBuf::from(&outside[0])));
        // A `$NAME` migrate path is checked when camigrate resolves it, the passphrase's whatever
        // the object holds.
        let cfg = load(&format!("{ec}migrate = {{ file = \"$KEY\", passphraseFile = \"$PASS\" }}\n")).unwrap();
        let store = |_: &str| Some(in_store[2].clone());
        assert!(cfg.object_file("k", &store).unwrap_err().to_string().contains("Nix store"));
        assert!(cfg.object_passphrase_file("k", &store).unwrap_err().to_string().contains("Nix store"));
        let fine = |_: &str| Some(outside[0].clone());
        assert_eq!(cfg.object_passphrase_file("k", &fine).unwrap(), Some(PathBuf::from(&outside[0])));
        let cert = "[objects.k]\nclass = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"\n";
        let cfg = load(&format!("{cert}migrate = {{ file = \"$KEY\", passphraseFile = \"$PASS\" }}\n")).unwrap();
        assert!(cfg.object_file("k", &store).unwrap().is_some(), "a certificate is no secret");
        assert!(cfg.object_passphrase_file("k", &store).is_err(), "a passphrase is");
    }

    /// `$NAME`/`${NAME}` in `pinFile` and `module` read the path from the environment when it is
    /// used; a malformed reference is invalid at load (17), an unset one is unavailable where the
    /// path is resolved (16), and a spec must reference an existing object at load.
    #[test]
    fn env_references_and_object_refs_are_checked_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let dir = dir.path();
        let load = |body: &str| {
            let p = dir.join("keys.toml");
            std::fs::write(&p, body).unwrap();
            load_config_with(&p, &|name| match name {
                "KM_UNIT_TEST_PIN" => Some("/env/pin".to_owned()),
                "KM_UNIT_TEST_MGM" => Some("/env/mgm".to_owned()),
                _ => None,
            })
        };
        let head = "[tokens.t]\ntokenLabel = \"x\"\n";
        let env = |name: &str| (name == "KM_UNIT_TEST_PIN").then(|| "/env/pin".to_owned());
        // A literal path is as written; $NAME and ${NAME} expand when the path is resolved.
        let cfg = load(&format!("{head}pinFile = \"/literal/pin\"\n")).unwrap();
        assert_eq!(cfg.tokens["t"].pin_path("t", &env).unwrap(), Some(PathBuf::from("/literal/pin")));
        let cfg =
            load(&format!("{head}pinFile = \"$KM_UNIT_TEST_PIN\"\nmodule = \"${{KM_UNIT_TEST_PIN}}\"\n")).unwrap();
        assert_eq!(cfg.tokens["t"].pin_path("t", &env).unwrap(), Some(PathBuf::from("/env/pin")));
        assert_eq!(
            cfg.tokens["t"].module_path("t", &|_| Some("/env/pin".to_owned())).unwrap().as_deref(),
            Some("/env/pin")
        );
        // A malformed reference fails at load, naming the file first, as every other load error
        // does (review config.rs F6).
        let file = format!("invalid: {}: ", dir.join("keys.toml").display());
        let err = load(&format!("{head}pinFile = \"$HOME/x\"\n")).unwrap_err().to_string();
        assert!(err.starts_with(&file) && err.contains("neither $NAME"), "{err}");
        for body in [
            "profileDirs = [\"$KM_UNIT_TEST_UNSET\"]\n".to_owned(),
            format!("{head}soCredentialFile = \"$\"\n"),
            format!("{head}module = \"$HOME/x.so\"\n"),
            "[objects.o]\nclass = \"CKO_DATA\"\nmigrate = { file = \"${HOME\" }\n".to_owned(),
        ] {
            let err = load(&body).unwrap_err().to_string();
            assert!(err.starts_with(&file), "{body}: {err}");
        }
        // A module, a PIN file and a credential file resolve when used, not at load: an unset
        // variable fails only a run that opens that token (without --module for the module), so
        // `validate` and a Nix build sandbox, which set none, load the file; a malformed
        // reference still fails at load. Unset at use is the environment's, not the file's: 16
        // (review 2026-11-23 A-14).
        let unset = load(&format!(
            "{head}module = \"$KM_UNIT_TEST_UNSET\"\npinFile = \"$KM_UNIT_TEST_UNSET\"\n\
             soCredentialFile = \"$KM_UNIT_TEST_UNSET\"\n"
        ))
        .unwrap();
        let t = &unset.tokens["t"];
        for err in [
            t.module_path("t", &|_| None).unwrap_err(),
            t.pin_path("t", &|_| None).unwrap_err(),
            t.so_credential_path("t", &|_| None).unwrap_err(),
        ] {
            assert!(matches!(err, KmError::Unavailable(_)), "{err}");
            assert!(err.to_string().contains("KM_UNIT_TEST_UNSET"), "{err}");
        }
        assert!(load(&format!("{head}module = \"$HOME/x.so\"\n")).is_err());
        // soCredentialFile expands the same way; an admin credential only comes with a user PIN.
        let cfg = load(&format!("{head}pinFile = \"/p\"\nsoCredentialFile = \"$KM_UNIT_TEST_MGM\"\n")).unwrap();
        let mgm = |name: &str| (name == "KM_UNIT_TEST_MGM").then(|| "/env/mgm".to_owned());
        assert_eq!(cfg.tokens["t"].so_credential_path("t", &mgm).unwrap(), Some(PathBuf::from("/env/mgm")));
        for admin in ["soCredentialFile = \"/so\"", "soCredentialEnv = \"SO\""] {
            let err = load(&format!("{head}{admin}\n")).unwrap_err();
            assert!(err.to_string().contains("needs a user PIN"), "{err}");
        }
        // A spec's object reference must exist, also when nothing uses the spec.
        let err = load(&format!(
            "{head}\n[objects.o]\nclass = \"CKO_DATA\"\n\n[specs.s]\nobject = \"missing\"\ntokens = {{}}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown object 'missing'"), "{err}");
    }

    /// A DES3 key is 24 bytes: `valueLen` left out loads as 24 (the same type, spec digest and
    /// commitment label as writing it), and any other length is invalid at load (17).
    #[test]
    fn des3_value_len_is_the_key_types() {
        let des3 = |len: &str| {
            let text = format!("[objects.o]\nclass = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"\n{len}\n");
            parse_config_with(&text, Path::new("keys.toml"), &|_| None)
        };
        assert_eq!(des3("").unwrap().objects["o"].value_len, Some(24));
        assert_eq!(des3("").unwrap().objects["o"], des3("valueLen = 24").unwrap().objects["o"]);
        for wrong in ["valueLen = 16", "valueLen = 0", "valueLen = 32"] {
            let err = des3(wrong).unwrap_err();
            assert!(matches!(&err, KmError::Validation(m) if m.contains("a CKK_DES3 key is 24 bytes")), "{err}");
        }
        // Only a secret key takes the fixed length; another class is refused by its type at load.
        let text = "[objects.o]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_DES3\"\n";
        let err = parse_config_with(text, Path::new("keys.toml"), &|_| None).unwrap_err();
        assert!(matches!(&err, KmError::Unsupported(m) if m.contains("CKO_PRIVATE_KEY/CKK_DES3")), "{err}");
    }
}
