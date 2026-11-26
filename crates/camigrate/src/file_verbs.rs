//! The verbs on key files (docs/FILE.md, docs/CAMIGRATE.md D2 `file`): `export --to-key-file`, and
//! `import` from a key file or from each object's own file. The module `file` writes the content of
//! a key file, and the module `keyfile` reads it. This module runs the verbs around them: it reads
//! the passphrase, makes the plan and updates the lock.

#[allow(
    clippy::wildcard_imports,
    reason = "the verbs split from lib.rs work on its imports and helpers, as pkcs11's token/ (R9)"
)]
use super::*;
use cakeys_core::{Check, Reason};

impl Run<'_> {
    /// Runs `export --to-key-file`. It moves one private key through the host (`Token::extract`)
    /// into a passphrase-protected file (docs/CAMIGRATE.md D2 `file`). The file is encrypted
    /// PKCS#8, or PKCS#12 with the certificate that the lock pairs with the key on the source. The
    /// file is written whole or not at all, with mode 0600.
    pub(super) fn export_file(&self, ctx: &MoveCtx, out: &Path, pass: &Path, notes: &mut Notes) -> anyhow::Result<()> {
        let from = ctx.from;
        // The source is opened once, for both the plan and the extraction of the key.
        let source = self.opener.open(from, Access::Scratch, notes);
        let (moves, source, _) = self.plan(ctx, super::Show::No, source, Access::Read, notes)?;
        moves.verdict(ctx.take(), from)?;
        let [p] = moves.plans.as_slice() else { unreachable!("the verdict takes one plan, ready") };
        let cfg = &self.opener.cfg;
        let pass = read_passphrase(pass)?;
        let src = source_target(cfg, &self.lock, &p.object, from)?;
        let source = self.source(from, source, notes)?;
        cakeys_pkcs11::ops::verify(&src, &source, &self.lock, notes)?;
        let h = source
            .find_key(&src.object, &src.on_token.locator, false)?
            .ok_or_else(|| KmError::NotFound(src.to_string().into()))?;
        let kwp = sealed::rfc5649(&source).ok_or_else(|| {
            source.unsupported_for(
                cakeys_pkcs11::Topic::Mechanism,
                format!("'{from}' offers no RFC 5649 key wrap to hand the key over"),
            )
        })?;
        // The key that the source extracted must be the key that the lock pins. This is checked
        // before the key is written to a file (review 2026-11-24 D-5).
        let pkcs8 = cakeys_pkcs11::ops::check_identity(&src, &self.lock, source.extract(h, &kwp)?)?;
        let bytes = match p.method {
            Some(Method::Pkcs12) => {
                let cert = self.paired_certificate(&p.object, from, &source, notes)?;
                let id = local_key_id(&self.lock, &p.object)?;
                file::write_pkcs12(pkcs8.plaintext(), &cert, &pass, id.as_bytes())?
            }
            _ => file::write_pkcs8(pkcs8.plaintext(), &pass)?.into_bytes(),
        };
        drop(pkcs8);
        write_whole(out, &bytes, 0o600)?;
        let method = p.method.as_ref().map_or_else(String::new, Method::name);
        notes.say(format!("wrote {} ({} by {method}, file)", out.display(), p.object));
        Ok(())
    }

    /// Returns the name of the certificate object that the lock pairs with `object` (`pairs`) and
    /// that is realised on `from`, if there is one.
    pub(super) fn paired_certificate_target(&self, object: &str, from: &'_ str) -> Option<String> {
        let pairs = self.lock.objects.get(object).map(|o| o.pairs.clone()).unwrap_or_default();
        pairs.into_iter().find(|pair| {
            let is_cert = self.lock.objects.get(pair).and_then(|o| o.object_type.as_ref()).map(|t| t.class)
                == Some(cakeys_core::types::ObjectClass::Certificate);
            is_cert && source_target(&self.opener.cfg, &self.lock, pair, from).is_ok()
        })
    }

    /// Returns the DER of the certificate that the lock pairs with `object`
    /// ([`Self::paired_certificate_target`]), read and verified on the open source `tok`.
    pub(super) fn paired_certificate(
        &self,
        object: &str,
        from: &str,
        tok: &cakeys_pkcs11::Token,
        notes: &mut Notes,
    ) -> anyhow::Result<Vec<u8>> {
        let pair = self.paired_certificate_target(object, from).ok_or_else(|| {
            KmError::PreconditionFailed(Reason::check(
                Check::ImportLocked,
                format!("the lock pairs no certificate with '{object}' on '{from}'"),
            ))
        })?;
        let t = source_target(&self.opener.cfg, &self.lock, &pair, from)?;
        Ok(public::material(&t, tok, &self.lock, notes)?)
    }

    /// Runs `import --in <key file>`. It reads the file in any format that `keyfile` reads, and it
    /// decrypts the file with `pass` when the file is encrypted. It finds the locked object by the
    /// key's identity (the `rfc7093m4` of its public key), and it creates the key under the spec
    /// that realises that object on `token` (the `--spec` value when there are several specs).
    /// When the file carries a certificate and the lock pairs a certificate with the object on
    /// `token`, it imports that certificate too. The lock records the origin of each object as
    /// `file`.
    pub(super) fn import_file(
        &mut self,
        token: &str,
        specs: &[String],
        input: &Path,
        pass: Option<&Path>,
        dry_run: bool,
        notes: &mut Notes,
    ) -> anyhow::Result<()> {
        let pass = pass.map(read_passphrase).transpose()?;
        let bytes = Zeroizing::new(std::fs::read(input).with_context(|| format!("reading {}", input.display()))?);
        let (pkcs8, certificates, method) =
            keyfile::private_key(&bytes, pass.as_ref().map(|p| p.as_str())).map_err(|e| e.prefixed(input.display()))?;
        drop(pass);
        drop(bytes);
        let spki = cakeys_core::id::spki_canonical(&cakeys_core::plaintext::spki_of_pkcs8(&pkcs8)?)?;
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
                KmError::PreconditionFailed(Reason::check(
                    Check::ImportLocked,
                    format!("{}: the lock pins no private key with this key's identity ({id})", input.display()),
                ))
            })?;
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let pairs = self.lock.objects.get(&object).map(|o| o.pairs.clone()).unwrap_or_default();
        let spec_for = |o: &str| spec_for(cfg, specs, o);
        // The certificate that a PKCS#12 file carries for its key is imported under the pair on
        // this token of the certificate that the lock pairs with the key.
        let cert_target = pairs.iter().find_map(|o| import_target(cfg, o, token, spec_for(o), KEY_FILE).ok());
        let certificate = keyfile::key_certificate(&certificates, &spki);
        // A refusal before the first object still prints a row for the key and for the
        // certificate that goes with it (review 2026-11-24 L4b-1).
        let rows_of: Vec<String> = std::iter::once(object.clone())
            .chain(cert_target.as_ref().filter(|_| certificate.is_some()).map(|t| t.object_name.to_owned()))
            .collect();
        let objects = std::iter::once(object.as_str()).chain(pairs.iter().map(String::as_str));
        if let Err(e) = specs_select(cfg, specs, objects, token, KEY_FILE) {
            return unmoved(&rows_of, token, e.into());
        }
        // From here on, each refusal is printed as a row, as for the entries of a bundle. Before
        // review 2026-11-24 D-9, the refusal of a key file returned before any row was printed.
        let mut tally = Tally::default();
        let dst = match import_target(cfg, &object, token, spec_for(&object), KEY_FILE) {
            Ok(dst) => dst,
            Err(err) => {
                tally.fail(Of::object(&object, token), format_args!("{object}: not imported"), err, notes);
                return tally.finish(self, notes);
            }
        };
        let method_name = method.name();
        let access = if dry_run { Access::DryWrite } else { Access::Write };
        let target = match opener.open(token, access, notes) {
            Ok(target) => target,
            Err(e) => return unmoved(&rows_of, token, e.into()),
        };
        if dry_run {
            let paired = certificate.as_deref().map(|c| (c, cert_target.as_ref()));
            self.plan_key_file(&target, &dst, (&spki, &method), paired, input, &mut tally, notes);
            return tally.finish(self, notes);
        }
        let origin = cakeys_core::config::Origin {
            from: "file".into(),
            method: method_name.clone(),
            exposure: Exposure::File,
            declared: false,
        };
        let pkcs8 = cakeys_pkcs11::ops::Extracted::from_file(pkcs8);
        match host::create_and_record(&dst, &target, &mut self.lock, pkcs8, Some(&spki), origin, notes) {
            Ok(public::Moved::Imported) => {
                let hint = public::unrecorded_hint(&dst);
                if !tally.record(self, Of::pair(&dst), ("imported", Some(&method_name)), &hint, notes) {
                    return tally.finish(self, notes);
                }
                notes.say(format!("imported {object} from {} into {dst}", input.display()));
            }
            Ok(public::Moved::AlreadyThere) => {
                notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
                tally.done(Of::pair(&dst), "already-there", None);
            }
            // When the key fails, its certificate is not imported either.
            Err(err) => {
                tally.fail(Of::pair(&dst), format_args!("{dst}: not imported"), err, notes);
                return tally.finish(self, notes);
            }
        }
        // Import the certificate that a PKCS#12 file carries, when the lock pairs a certificate
        // with the key on this token. A failure here ends the run only after the lock is saved,
        // because the key is already on the token at this point.
        if let Some(cert) = &certificate {
            match cert_target {
                Some(t) => match public::create(&t, &target, cert, "file", &mut self.lock, notes) {
                    Ok(public::Moved::Imported) => {
                        // The lock is saved for the certificate as it was for the key. Before this
                        // save, the certificate was recorded only in memory, and `check` found a
                        // realisation that the lock did not record (14).
                        let (public, hint) = (Method::Public.name(), public::unrecorded_hint(&t));
                        if tally.record(self, Of::pair(&t), ("imported", Some(&public)), &hint, notes) {
                            notes.say(format!("imported its certificate into {t}"));
                        }
                    }
                    Ok(public::Moved::AlreadyThere) => tally.done(Of::pair(&t), "already-there", None),
                    Err(e) => tally.fail(Of::pair(&t), format_args!("{t}: its certificate is not imported"), e, notes),
                },
                None => notes.note(format_args!(
                    "the file's certificate is not imported: the lock pairs no certificate with '{object}' on '{token}'"
                )),
            }
        }
        tally.finish(self, notes)
    }

    /// Runs `import --in <key file> --dry-run`. It makes every check that the import makes before
    /// it creates anything, and nothing more. It adds one row for the key (`dst`, with the public
    /// key `spki`, by `method`) and one row for the certificate that the file carries (`paired`,
    /// when the lock pairs a certificate with the key).
    #[expect(clippy::too_many_arguments, reason = "the key file's parts, as import_file read them")]
    fn plan_key_file(
        &self,
        target: &cakeys_pkcs11::Token,
        dst: &Target,
        (spki, method): (&[u8], &Method),
        paired: Option<(&[u8], Option<&Target>)>,
        input: &Path,
        tally: &mut Tally,
        notes: &mut Notes,
    ) {
        let (object, token, registry) = (dst.object_name, dst.token_name, self.opener.registry);
        let key = public::already_there(dst, target, &self.lock, notes).and_then(|there| {
            if !there {
                public::free_locator(dst, target, Some(spki))?;
                import_checks(dst, target, method, registry, notes)?;
            }
            Ok(there)
        });
        match key {
            Ok(true) => {
                notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
                tally.done(Of::pair(dst), "already-there", None);
            }
            Ok(false) => {
                notes.say(format!("{dst}: {object} by {method} (file) from {}: ready", input.display()));
                tally.done(Of::pair(dst), "ready", Some(&method.name()));
            }
            Err(err) => tally.fail(Of::pair(dst), format_args!("{dst}: not imported"), err, notes),
        }
        match paired {
            Some((cert, Some(t))) => {
                let ready = public::already_there(t, target, &self.lock, notes).and_then(|there| {
                    if !there {
                        public::preflight(t, target, cert)?;
                        import_checks(t, target, &Method::Public, registry, notes)?;
                    }
                    Ok(!there)
                });
                match ready {
                    Ok(true) => {
                        notes.say(format!("{t}: its certificate: ready"));
                        tally.done(Of::pair(t), "ready", Some(&Method::Public.name()));
                    }
                    Ok(false) => {}
                    Err(e) => tally.fail(Of::pair(t), format_args!("{t}: its certificate is not imported"), e, notes),
                }
            }
            Some((_, None)) => notes.note(format_args!(
                "the file's certificate would not be imported: the lock pairs no certificate with '{object}' on \
                 '{token}'"
            )),
            None => {}
        }
    }

    /// Runs `import` without `--in` (docs/FILE.md F6). It imports each object for which a pair on
    /// `token` says `origin = "file"`, or each of `objects`, from its object's `migrate.file`.
    /// Private and secret keys are imported first, so that a public key object finds the public
    /// half that the import of its private key created. Each object is handled on its own, as the
    /// entries of a bundle are: an object that fails leaves nothing behind, and the other objects
    /// still import and are recorded in the lock. The run exits with the code of the first
    /// failure, or with 22 if it recorded any object in the lock.
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
        // Private and secret keys come first, so that a public key object finds the public half
        // that the import of its private key created.
        wanted.sort_by_key(|o| !cfg.objects[*o].class.is_key() || cfg.objects[*o].class == Class::PublicKey);
        // A refusal before the first object still prints a row for each object (review
        // 2026-11-24 L4b-1).
        let access = if how.dry_run { Access::DryWrite } else { Access::Write };
        let target = specs_select(cfg, specs, wanted.iter().copied(), token, FROM_FILE)
            .and_then(|()| self.opener.open(token, access, notes));
        let target = match target {
            Ok(target) => target,
            Err(e) => return unmoved(&wanted, token, e.into()),
        };
        let mut tally = Tally::default();
        for object in wanted {
            let dst = match import_target(cfg, object, token, spec_for(cfg, specs, object), FROM_FILE) {
                Ok(dst) => dst,
                Err(err) => {
                    tally.fail(Of::object(object, token), format_args!("{object}: not imported"), err, notes);
                    continue;
                }
            };
            match from_its_file((cfg, self.opener.registry), &dst, &target, &mut self.lock, how, notes) {
                Ok(Filed::Ready(method)) => tally.done(Of::pair(&dst), "ready", Some(&method)),
                Ok(Filed::Moved(public::Moved::Imported, method)) => {
                    let hint = public::unrecorded_hint(&dst);
                    if !tally.record(self, Of::pair(&dst), ("imported", Some(&method)), &hint, notes) {
                        break;
                    }
                    notes.say(format!("imported {object} from its file into {dst}"));
                }
                Ok(Filed::Moved(public::Moved::AlreadyThere, _)) => {
                    notes.note(format_args!("{dst} is already realised and verifies; nothing to import"));
                    tally.done(Of::pair(&dst), "already-there", None);
                }
                Err(err) => tally.fail(Of::pair(&dst), format_args!("{dst}: not imported"), err, notes),
            }
        }
        tally.finish(self, notes)
    }
}

/// Returns the `localKeyId` by which a PKCS#12 export pairs the key with its certificate. The
/// value is the key's locked `rfc7093m4`, so it is never empty, because importers pair the key
/// and the certificate by this value.
///
/// # Errors
///
/// `PreconditionFailed` (14) when the lock pins no `rfc7093m4` for `object`.
fn local_key_id(lock: &Lock, object: &str) -> cakeys_core::Result<String> {
    let scheme = cakeys_core::id::Scheme::Rfc7093m4.name();
    lock.objects.get(object).and_then(|o| o.ids.get(scheme)).cloned().ok_or_else(|| {
        KmError::PreconditionFailed(Reason::check(
            Check::ImportLocked,
            format!("the lock pins no {scheme} for '{object}', which a PKCS#12 pairs its key and certificate by"),
        ))
    })
}

/// Returns the passphrase in `path` (its one line, read by [`cakeys_core::secret::read`]). The
/// passphrase is zeroized when it is dropped, and it is never empty.
fn read_passphrase(path: &Path) -> cakeys_core::Result<Zeroizing<String>> {
    let pass = cakeys_core::secret::read("passphrase", None, Some(path))?.unwrap_or_default();
    non_empty(pass, &path.display())
}

/// Returns `pass`, which was read from `source`, or refuses it (17) when it is empty. Every
/// passphrase passes this one check, whether it comes from a file or from an environment variable
/// (review 2026-11-23 C-14). An empty passphrase is therefore reported as empty, and it is never
/// tried on the file, which would report that the file does not open with it.
fn non_empty(pass: Zeroizing<String>, source: &dyn std::fmt::Display) -> cakeys_core::Result<Zeroizing<String>> {
    if pass.is_empty() {
        return Err(KmError::Validation(format!("{source}: the passphrase is empty").into()));
    }
    Ok(pass)
}

/// The flags that control how `import` without `--in` reads the objects' files.
pub(super) struct FileImport<'a> {
    /// `--passphrase-file`: the passphrase of every encrypted file, which overrides the passphrase
    /// that keys.toml names.
    pub(super) pass: Option<&'a Path>,
    /// `--allow-host-plaintext`.
    pub(super) plaintext: bool,
    /// `--dry-run`.
    pub(super) dry_run: bool,
}

/// Returns the passphrase of `object`'s file: the passphrase in `--passphrase-file`, or else the
/// one in the object's `migrate.passphraseEnv`, or else the one in its `migrate.passphraseFile`.
/// The result is `None` when none of them is given.
fn file_passphrase(cfg: &Config, object: &str, over: Option<&Path>) -> cakeys_core::Result<Option<Zeroizing<String>>> {
    if let Some(path) = over {
        return read_passphrase(path).map(Some);
    }
    if let Some(var) = cfg.object_migrate.get(object).and_then(|m| m.passphrase_env.as_deref()) {
        let pass = cakeys_core::secret::read(&format!("object '{object}': the passphrase"), Some(var), None)?;
        return pass.map(|p| non_empty(p, &format_args!("object '{object}': env var {var}"))).transpose();
    }
    cfg.object_passphrase_file(object, &|name| std::env::var(name).ok())?.map(|p| read_passphrase(&p)).transpose()
}

/// Imports one object from its file, as `import` without `--in` does (docs/FILE.md F3, F6). The
/// host reads the file and determines the type of its content. The host then checks the content
/// against the IDs that the lock pins, and it exits with 10 before anything is written when they
/// differ. The object is then created on `to` and recorded with `from = "file"`. When the lock
/// pins nothing yet, the file is the object's first use. The IDs that the host computes from the
/// file are then put in the lock first, so the token must show exactly those IDs. If the token
/// does not, the lock is restored to what it was.
fn from_its_file(
    (cfg, registry): (&Config, &Registry),
    dst: &Target,
    to: &cakeys_pkcs11::Token,
    lock: &mut Lock,
    how: &FileImport,
    notes: &mut Notes,
) -> cakeys_core::Result<Filed> {
    if public::already_there(dst, to, lock, notes)? {
        return Ok(Filed::Moved(public::Moved::AlreadyThere, String::new()));
    }
    let class = dst.object.class;
    // A data object is private unless the spec says that it is public (`Target::needs_login`).
    // The lock records nothing about the object here yet (review 2026-11-24 D-7, §9.2).
    let private_data = class == Class::Data && dst.needs_login(lock);
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
    // When a file holds a private key, a certificate or public key in the same file is found by
    // decoding that private key, so reading it needs `--allow-host-plaintext`.
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
        keyfile::read(&bytes, &dst.object, private_data, pass.as_ref().map(|p| p.as_str()), encoding).map_err(|e| {
            match e {
                KmError::Validation(why) => KmError::Validation(format!("{}: {why}", path.display()).into()),
                other => other,
            }
        })?;
    drop(bytes);
    let ids = keyfile::host_ids(&dst.object, &m);
    let locked = lock.objects.get(dst.object_name).map(|o| &o.ids);
    for (scheme, got) in &ids {
        if let Some(want) = locked.and_then(|l| l.get(scheme.name()))
            && want != got
        {
            return Err(KmError::HashMismatch {
                what: format!("{dst}: the material in {}", path.display()),
                expected: want.clone(),
                got: got.clone(),
                check: Check::IdentityMaterial,
            });
        }
    }
    // A secret key's identity is its commitments, which the host computes
    // (`ops::check_identity`). They are checked here, so that the dry run refuses what the run
    // would refuse (10).
    if class == Class::SecretKey {
        cakeys_pkcs11::ops::check_identity(dst, lock, cakeys_pkcs11::ops::Extracted::from_file(m.bytes.clone()))?;
    }
    let first_use = locked.is_none_or(BTreeMap::is_empty);
    if how.dry_run {
        match class {
            Class::PrivateKey | Class::SecretKey => {
                public::free_locator(dst, to, m.spki.as_deref())?;
            }
            _ => {
                public::preflight(dst, to, &m.bytes)?;
            }
        }
        import_checks(dst, to, &m.method, registry, notes)?;
        let first = if first_use { "; its first use, the lock pins it from the file" } else { "" };
        notes.say(format!(
            "{dst}: {} by {} ({}) from {}: ready{first}",
            dst.object_name,
            m.method,
            m.exposure,
            path.display()
        ));
        return Ok(Filed::Ready(m.method.name()));
    }
    let before = lock.clone();
    if first_use && !ids.is_empty() {
        let entry = lock.objects.entry(dst.object_name.to_owned()).or_default();
        entry.object_type = Some(dst.object.cfg().clone());
        entry.ids.extend(ids.iter().map(|(s, v)| (s.name().to_owned(), v.clone())));
    }
    let method = m.method.name();
    let origin = Origin { from: "file".into(), method: method.clone(), exposure: m.exposure, declared: false };
    let moved = match class {
        Class::PrivateKey | Class::SecretKey => {
            let plain = cakeys_pkcs11::ops::Extracted::from_file(m.bytes.clone());
            host::create_and_record(dst, to, lock, plain, m.spki.as_deref(), origin, notes)
        }
        _ => public::create_as(dst, to, &m.bytes, origin, lock, notes),
    };
    if moved.is_err() {
        *lock = before;
    }
    moved.map(|moved| Filed::Moved(moved, method))
}

/// What [`from_its_file`] did with one object: the object is ready (in a dry run), or it was moved
/// or found already there, with the name of the method.
enum Filed {
    Ready(String),
    Moved(public::Moved, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that a PKCS#12 file's `localKeyId` is the key's locked `rfc7093m4`. A lock that pins
    /// no `rfc7093m4` is refused (14), so the file never gets an empty ID for importers to pair on.
    #[test]
    fn a_pkcs12_pairs_by_the_locked_rfc7093m4_or_not_at_all() {
        let mut lock = Lock::default();
        let id = cakeys_core::id::sri(b"spki");
        let mut object = cakeys_core::config::LockObject::default();
        object.ids.insert("rfc7093m4".into(), id.clone());
        lock.objects.insert("k".into(), object);
        assert_eq!(local_key_id(&lock, "k").unwrap(), id);
        lock.objects.insert("bare".into(), cakeys_core::config::LockObject::default());
        for unpinned in ["bare", "absent"] {
            let e = local_key_id(&lock, unpinned).unwrap_err();
            assert!(e.exit_code() == 14 && e.to_string().contains(unpinned), "{e}");
        }
    }

    /// Checks that an empty passphrase is refused (17) with a message that names its source,
    /// whichever source it is. Before review 2026-11-23 C-14, `passphraseEnv` skipped the check.
    #[test]
    fn an_empty_passphrase_is_refused_by_its_source() {
        let e = non_empty(Zeroizing::new(String::new()), &"object 'k': env var PASS").unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("env var PASS: the passphrase is empty"), "{e}");
        assert_eq!(non_empty(Zeroizing::new("p".into()), &"f").unwrap().as_str(), "p");
    }
}
