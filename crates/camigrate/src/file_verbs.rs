//! The verbs on key files (docs/FILE.md, docs/CAMIGRATE.md D2 `file`): `export --to-file`, and
//! `import` from a file or from each object's own. What a file holds is `file` (written) and
//! `keyfile` (read); this is the run around them: its passphrase, its plan and the lock.

#[allow(
    clippy::wildcard_imports,
    reason = "the verbs split from lib.rs work on its imports and helpers, as pkcs11's token/ (R9)"
)]
use super::*;

impl Run<'_> {
    /// `export --to-file`: one private key, through the host (`Token::extract`), into a
    /// passphrase-protected file (docs/CAMIGRATE.md D2 `file`): encrypted PKCS#8, or PKCS#12 with the
    /// certificate the lock pairs with it on the source. Written whole or not at all, mode 0600.
    #[expect(clippy::too_many_arguments, reason = "the export command's parts, as the CLI hands them over")]
    pub(super) fn export_file(
        &self,
        objects: &[&str],
        from: &str,
        dest: &Destination,
        out: &Path,
        pass: &Path,
        how: &MoveArgs,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let moves = self.plan(objects, from, dest, &[], how, false, notes)?;
        moves.ready()?;
        let [p] = moves.plans.as_slice() else {
            return Err(KmError::Validation(
                format!("a key file holds one key, and {} are planned: name the one to export", moves.plans.len())
                    .into(),
            )
            .into());
        };
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let pass = read_passphrase(pass)?;
        let src = source_target(cfg, &self.lock, &p.object, from)?;
        let source = opener.open(from, Access::Scratch, notes)?;
        cakeys_pkcs11::ops::verify(&src, &source, &self.lock, notes)?;
        let h = source
            .find_key(src.object, &src.on_token.locator, false)?
            .ok_or_else(|| KmError::NotFound(src.to_string().into()))?;
        let kwp = sealed::rfc5649(&source)
            .ok_or_else(|| source.unsupported(format!("'{from}' offers no RFC 5649 key wrap to hand the key over")))?;
        let pkcs8 = source.extract(h, &kwp)?;
        let bytes = match p.method {
            Some(Method::Pkcs12) => {
                let cert = self.paired_certificate(&p.object, from, &source, notes)?;
                let id = self
                    .lock
                    .objects
                    .get(&p.object)
                    .and_then(|o| o.ids.get(cakeys_core::id::Scheme::Rfc7093m4.name()))
                    .cloned()
                    .unwrap_or_default();
                file::write_pkcs12(&pkcs8, &cert, &pass, id.as_bytes())?
            }
            _ => file::write_pkcs8(&pkcs8, &pass)?.into_bytes(),
        };
        drop(pkcs8);
        write_whole(out, &bytes, 0o600)?;
        let method = p.method.as_ref().map_or_else(String::new, Method::name);
        notes.say(format!("wrote {} ({} by {method}, file)", out.display(), p.object));
        Ok(())
    }

    /// The certificate the lock pairs with `object` (`pairs`), as realised on `from`.
    pub(super) fn paired_certificate_target(&self, object: &str, from: &'_ str) -> Option<String> {
        let pairs = self.lock.objects.get(object).map(|o| o.pairs.clone()).unwrap_or_default();
        pairs.into_iter().find(|pair| {
            let is_cert = self.lock.objects.get(pair).and_then(|o| o.object_type.as_ref()).map(|t| t.class)
                == Some(cakeys_core::types::ObjectClass::Certificate);
            is_cert && source_target(&self.opener.cfg, &self.lock, pair, from).is_ok()
        })
    }

    /// That certificate's DER, read and verified on the open source `tok`.
    pub(super) fn paired_certificate(
        &self,
        object: &str,
        from: &str,
        tok: &cakeys_pkcs11::Token,
        notes: &mut Notes,
    ) -> anyhow::Result<Vec<u8>> {
        let pair = self.paired_certificate_target(object, from).ok_or_else(|| {
            KmError::PreconditionFailed(format!("the lock pairs no certificate with '{object}' on '{from}'").into())
        })?;
        let t = source_target(&self.opener.cfg, &self.lock, &pair, from)?;
        Ok(public::material(&t, tok, &self.lock, notes)?)
    }

    /// `import --in <key file> --passphrase-file`: decrypt the file, find the locked object by
    /// its key's identity (`rfc7093m4` of its public key), and create it under the spec that
    /// realises that object on `token` (`--spec` when several), with the certificate a PKCS#12
    /// carries when the lock pairs one with the object there too. Recorded with where it came
    /// from: a `file`.
    pub(super) fn import_file(
        &mut self,
        token: &str,
        specs: &[String],
        input: &Path,
        pass: &Path,
        dry_run: bool,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let pass = read_passphrase(pass)?;
        let bytes = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
        let read = file::read(&bytes, &pass)?;
        drop(pass);
        let spki = cakeys_core::id::spki_canonical(&cakeys_core::plaintext::spki_of_pkcs8(&read.pkcs8)?)?;
        let id = cakeys_core::id::sri(&spki);
        let object = self
            .lock
            .objects
            .iter()
            .find(|(_, o)| {
                o.ids.get(cakeys_core::id::Scheme::Rfc7093m4.name()) == Some(&id)
                    && o.object_type.as_ref().is_some_and(|t| t.class == cakeys_core::types::ObjectClass::PrivateKey)
            })
            .map(|(name, _)| name.clone())
            .ok_or_else(|| {
                KmError::PreconditionFailed(
                    format!("{}: the lock pins no private key with this key's identity ({id})", input.display()).into(),
                )
            })?;
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let pairs = self.lock.objects.get(&object).map(|o| o.pairs.clone()).unwrap_or_default();
        let objects = std::iter::once(object.as_str()).chain(pairs.iter().map(String::as_str));
        specs_select(cfg, specs, objects, token, KEY_FILE)?;
        let spec_for = |o: &str| spec_for(cfg, specs, o);
        let dst = import_target(cfg, &object, token, spec_for(&object), KEY_FILE)?;
        // The certificate a PKCS#12 carries for its key goes where the lock pairs one with the key
        // on this token.
        let cert_target = pairs.iter().find_map(|o| import_target(cfg, o, token, spec_for(o), KEY_FILE).ok());
        let certificate = keyfile::key_certificate(&read.certificates, &spki);
        if dry_run {
            // Everything the import checks before it creates anything, and nothing more.
            let target = opener.open(token, Access::Read, notes)?;
            if public::already_there(&dst, &target, &self.lock, notes)? {
                notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
            } else {
                host::free_locator(&dst, &target, Some(&spki))?;
                import_checks(&dst, &target, &read.method, opener.registry, notes)?;
                println!("{dst}: {object} by {} (file) from {}: ready", read.method, input.display());
            }
            match (&certificate, &cert_target) {
                (Some(cert), Some(t)) if !public::already_there(t, &target, &self.lock, notes)? => {
                    public::preflight(t, &target, cert)?;
                    import_checks(t, &target, &Method::Public, opener.registry, notes)?;
                    println!("{t}: its certificate: ready");
                }
                (Some(_), None) => notes.note(format_args!(
                    "the file's certificate would not be imported: the lock pairs no certificate with '{object}' on \
                     '{token}'"
                )),
                _ => {}
            }
            return Ok(());
        }
        let target = opener.open(token, Access::Write, notes)?;
        let origin = cakeys_core::config::Origin {
            from: "file".into(),
            method: read.method.name(),
            exposure: Exposure::File,
            declared: false,
        };
        let moved = host::create_and_record(&dst, &target, &mut self.lock, &read.pkcs8, Some(&spki), origin, notes)?;
        let mut tally = Tally::default();
        match moved {
            public::Moved::Imported => {
                tally.moved();
                self.record(&dst)?;
                notes.say(format!("imported {object} from {} into {dst}", input.display()));
            }
            public::Moved::AlreadyThere => {
                notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
            }
        }
        // The certificate a PKCS#12 carries, where the lock pairs one with the key on this token.
        // Its failure ends the run only after the lock is saved: the key is on the token by now.
        if let Some(cert) = &certificate {
            match cert_target {
                Some(t) => match public::create(&t, &target, cert, "file", &mut self.lock, notes) {
                    Ok(public::Moved::Imported) => {
                        tally.moved();
                        notes.say(format!("imported its certificate into {t}"));
                    }
                    Ok(public::Moved::AlreadyThere) => {}
                    Err(e) => tally.fail(format_args!("{t}: its certificate is not imported"), e, notes),
                },
                None => notes.note(format_args!(
                    "the file's certificate is not imported: the lock pairs no certificate with '{object}' on '{token}'"
                )),
            }
        }
        tally.finish(self, notes)
    }

    /// `import` without `--in` (docs/FILE.md F6): each object a pair on `token` says is born in a
    /// file (`origin = "file"`), or each of `objects`, from its object's `migrate.file`. Keys
    /// first, so a public key object finds the public half its key's import made. Each on its
    /// own, as a bundle's entries: one that fails leaves nothing, the others still import, the
    /// lock records them, and the run exits with the first failure.
    pub(super) fn import_files(
        &mut self,
        token: &str,
        objects: &[String],
        specs: &[String],
        how: &FileImport,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let cfg = &self.opener.cfg;
        let from_file = |o: &str| {
            cfg.specs
                .values()
                .any(|s| s.object == o && s.tokens.get(token).is_some_and(|t| t.key_origin() == KeyOrigin::File))
        };
        for o in objects {
            if !cfg.objects.contains_key(o) {
                return Err(KmError::Validation(format!("unknown object '{o}'").into()).into());
            }
            if !from_file(o) {
                return Err(KmError::Validation(format!(
                    "no spec realises '{o}' on '{token}' with origin = \"file\": nothing brings it from its file there"
                ).into())
                .into());
            }
        }
        let mut wanted: Vec<&str> = cfg
            .objects
            .keys()
            .map(String::as_str)
            .filter(|o| from_file(o) && (objects.is_empty() || objects.iter().any(|n| n == o)))
            .collect();
        if wanted.is_empty() {
            return Err(KmError::Validation(format!("no pair on '{token}' says origin = \"file\"").into()).into());
        }
        // Keys first: a public key object then finds the public half its key's import made.
        wanted.sort_by_key(|o| !cfg.objects[*o].class.is_key() || cfg.objects[*o].class == Class::PublicKey);
        specs_select(cfg, specs, wanted.iter().copied(), token, FROM_FILE)?;
        let access = if how.dry_run { Access::Read } else { Access::Write };
        let target = self.opener.open(token, access, notes)?;
        let mut tally = Tally::default();
        for object in wanted {
            let dst = match import_target(cfg, object, token, spec_for(cfg, specs, object), FROM_FILE) {
                Ok(dst) => dst,
                Err(err) => {
                    tally.fail(format_args!("{object}: not imported"), err, notes);
                    continue;
                }
            };
            match from_its_file((cfg, self.opener.registry), &dst, &target, &mut self.lock, how, notes) {
                Ok(None) => {}
                Ok(Some(public::Moved::Imported)) => {
                    tally.moved();
                    self.record(&dst)?;
                    notes.say(format!("imported {object} from its file into {dst}"));
                }
                Ok(Some(public::Moved::AlreadyThere)) => {
                    notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
                }
                Err(err) => tally.fail(format_args!("{dst}: not imported"), err, notes),
            }
        }
        tally.finish(self, notes)
    }
}

/// The passphrase in `path` (its one line, [`cakeys_core::secret::read`]), zeroized when dropped.
/// Never empty.
fn read_passphrase(path: &Path) -> cakeys_core::Result<Zeroizing<String>> {
    let pass = cakeys_core::secret::read("passphrase", None, Some(path))?.unwrap_or_default();
    if pass.is_empty() {
        return Err(KmError::Validation(format!("{}: the passphrase is empty", path.display()).into()));
    }
    Ok(pass)
}

/// How `import` without `--in` reads the objects' files.
pub(super) struct FileImport<'a> {
    /// `--passphrase-file`: every encrypted file's passphrase, over keys.toml's.
    pub(super) pass: Option<&'a Path>,
    /// `--allow-host-plaintext`.
    pub(super) plaintext: bool,
    /// `--dry-run`.
    pub(super) dry_run: bool,
}

/// The passphrase of `object`'s file: `--passphrase-file`, else its `migrate.passphraseEnv`,
/// else its `migrate.passphraseFile`; `None` when none is given.
fn file_passphrase(cfg: &Config, object: &str, over: Option<&Path>) -> cakeys_core::Result<Option<Zeroizing<String>>> {
    if let Some(path) = over {
        return read_passphrase(path).map(Some);
    }
    if let Some(var) = cfg.object_migrate.get(object).and_then(|m| m.passphrase_env.as_deref()) {
        return cakeys_core::secret::read(&format!("object '{object}': the passphrase"), Some(var), None);
    }
    cfg.object_passphrase_file(object, &|name| std::env::var(name).ok())?.map(|p| read_passphrase(&p)).transpose()
}

/// One object from its file, as `import` without `--in` takes it (docs/FILE.md F3, F6): read
/// and typed on the host, checked against the IDs the lock pins (10 before anything is
/// written), then created on `to` and recorded with `from = "file"`. When the lock pins
/// nothing yet, the file is the object's first use: the IDs the host computes from it are put
/// in the lock first, so the token must show exactly them, and the lock is left as it was if it
/// does not. `None` when the dry run found it ready.
fn from_its_file(
    (cfg, registry): (&Config, &Registry),
    dst: &Target,
    to: &cakeys_pkcs11::Token,
    lock: &mut Lock,
    how: &FileImport,
    notes: &mut Notes,
) -> cakeys_core::Result<Option<public::Moved>> {
    if public::already_there(dst, to, lock, notes)? {
        return Ok(Some(public::Moved::AlreadyThere));
    }
    let class = dst.object.class;
    let private_data = class == Class::Data && dst.spec.flag("CKA_PRIVATE") == Some(true);
    if (matches!(class, Class::PrivateKey | Class::SecretKey) || private_data) && !how.plaintext {
        return Err(KmError::Unsupported(
            format!(
                "{dst}: its file's {class} passes through this process's memory as plaintext; pass \
             --allow-host-plaintext (docs/CAMIGRATE.md D2, file)"
            )
            .into(),
        ));
    }
    let env = |name: &str| std::env::var(name).ok();
    let path = cfg
        .object_file(dst.object_name, &env)?
        .ok_or_else(|| KmError::Validation(format!("object '{}' names no migrate.file", dst.object_name).into()))?;
    let bytes = Zeroizing::new(std::fs::read(&path).map_err(KmError::io(format_args!("reading {}", path.display())))?);
    // A certificate or public key beside a private key is found by decoding that key.
    if keyfile::holds_private_key(&bytes) && !how.plaintext {
        return Err(KmError::Unsupported(
            format!(
                "{dst}: {} holds a private key, which reading its {class} decodes in this process's memory; pass \
             --allow-host-plaintext (docs/CAMIGRATE.md D2, file)",
                path.display()
            )
            .into(),
        ));
    }
    let pass = file_passphrase(cfg, dst.object_name, how.pass)?;
    let encoding = cfg.object_migrate.get(dst.object_name).and_then(|m| m.encoding);
    let m =
        keyfile::read(&bytes, dst.object, private_data, pass.as_ref().map(|p| p.as_str()), encoding).map_err(|e| {
            match e {
                KmError::Validation(why) => KmError::Validation(format!("{}: {why}", path.display()).into()),
                other => other,
            }
        })?;
    drop(bytes);
    let ids = keyfile::host_ids(dst.object, &m);
    let locked = lock.objects.get(dst.object_name).map(|o| &o.ids);
    for (scheme, got) in &ids {
        if let Some(want) = locked.and_then(|l| l.get(scheme.name()))
            && want != got
        {
            return Err(KmError::HashMismatch {
                what: format!("{dst}: the material in {}", path.display()),
                expected: want.clone(),
                got: got.clone(),
            });
        }
    }
    let first_use = locked.is_none_or(BTreeMap::is_empty);
    if how.dry_run {
        match class {
            Class::PrivateKey | Class::SecretKey => {
                host::free_locator(dst, to, m.spki.as_deref())?;
            }
            _ => {
                public::preflight(dst, to, &m.bytes)?;
            }
        }
        import_checks(dst, to, &m.method, registry, notes)?;
        let first = if first_use { "; its first use, the lock pins it from the file" } else { "" };
        println!("{dst}: {} by {} ({}) from {}: ready{first}", dst.object_name, m.method, m.exposure, path.display());
        return Ok(None);
    }
    let before = lock.clone();
    if first_use && !ids.is_empty() {
        let entry = lock.objects.entry(dst.object_name.to_owned()).or_default();
        entry.object_type = Some(dst.object.clone());
        entry.ids.extend(ids.iter().map(|(s, v)| (s.name().to_owned(), v.clone())));
    }
    let origin = Origin { from: "file".into(), method: m.method.name(), exposure: m.exposure, declared: false };
    let moved = match class {
        Class::PrivateKey | Class::SecretKey => {
            host::create_and_record(dst, to, lock, &m.bytes, m.spki.as_deref(), origin, notes)
        }
        _ => public::create_as(dst, to, &m.bytes, origin, lock, notes),
    };
    if moved.is_err() {
        *lock = before;
    }
    moved.map(Some)
}
