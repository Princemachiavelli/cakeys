//! The verbs on key files (docs/FILE.md, docs/CAMIGRATE.md D2 `file`): `export --to-key-file`, and
//! `import` from a file or from each object's own. What a file holds is `file` (written) and
//! `keyfile` (read); this is the run around them: its passphrase, its plan and the lock.

#[allow(
    clippy::wildcard_imports,
    reason = "the verbs split from lib.rs work on its imports and helpers, as pkcs11's token/ (R9)"
)]
use super::*;

impl Run<'_> {
    /// `export --to-key-file`: one private key, through the host (`Token::extract`), into a
    /// passphrase-protected file (docs/CAMIGRATE.md D2 `file`): encrypted PKCS#8, or PKCS#12 with the
    /// certificate the lock pairs with it on the source. Written whole or not at all, mode 0600.
    pub(super) fn export_file(&self, ctx: &MoveCtx, out: &Path, pass: &Path, notes: &mut Notes) -> anyhow::Result<()> {
        let from = ctx.from;
        // The source is opened once, for the plan and the hand-over.
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
        // The key the source handed over is the one the lock pins, before a file holds it
        // (review 2026-11-24 D-5).
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

    /// `import --in <key file>`: read the file (any format `keyfile` reads, decrypted under
    /// `pass` when it is encrypted), find the locked object by its key's identity (`rfc7093m4`
    /// of its public key), and create it under the spec that realises that object on `token`
    /// (`--spec` when several), with the certificate the file carries when the lock pairs one
    /// with the object there too. Recorded with where it came from: a `file`.
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
                KmError::PreconditionFailed(
                    format!("{}: the lock pins no private key with this key's identity ({id})", input.display()).into(),
                )
            })?;
        let (cfg, opener) = (&self.opener.cfg, &self.opener);
        let pairs = self.lock.objects.get(&object).map(|o| o.pairs.clone()).unwrap_or_default();
        let objects = std::iter::once(object.as_str()).chain(pairs.iter().map(String::as_str));
        specs_select(cfg, specs, objects, token, KEY_FILE)?;
        let spec_for = |o: &str| spec_for(cfg, specs, o);
        // Each refusal from here on is a row, as a bundle's entries are (review 2026-11-24 D-9:
        // a key file's returned before any row was printed).
        let mut tally = Tally::default();
        let dst = match import_target(cfg, &object, token, spec_for(&object), KEY_FILE) {
            Ok(dst) => dst,
            Err(err) => {
                tally.fail(Of::object(&object, token), format_args!("{object}: not imported"), err, notes);
                return tally.finish(self, notes);
            }
        };
        // The certificate a PKCS#12 carries for its key goes where the lock pairs one with the key
        // on this token.
        let cert_target = pairs.iter().find_map(|o| import_target(cfg, o, token, spec_for(o), KEY_FILE).ok());
        let certificate = keyfile::key_certificate(&certificates, &spki);
        let method_name = method.name();
        if dry_run {
            let target = opener.open(token, Access::Read, notes)?;
            let paired = certificate.as_deref().map(|c| (c, cert_target.as_ref()));
            self.plan_key_file(&target, &dst, (&spki, &method), paired, input, &mut tally, notes);
            return tally.finish(self, notes);
        }
        let target = opener.open(token, Access::Write, notes)?;
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
            // Its certificate goes with it, or not at all.
            Err(err) => {
                tally.fail(Of::pair(&dst), format_args!("{dst}: not imported"), err, notes);
                return tally.finish(self, notes);
            }
        }
        // The certificate a PKCS#12 carries, where the lock pairs one with the key on this token.
        // Its failure ends the run only after the lock is saved: the key is on the token by now.
        if let Some(cert) = &certificate {
            match cert_target {
                Some(t) => match public::create(&t, &target, cert, "file", &mut self.lock, notes) {
                    Ok(public::Moved::Imported) => {
                        // Saved as the key was: it was recorded only in memory, and `check` found
                        // a realisation the lock did not record (14).
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

    /// `import --in <key file> --dry-run`: everything the import checks before it creates
    /// anything, and nothing more, a row each for the key (`dst`, of public key `spki`, by
    /// `method`) and the certificate the file carries (`paired`: where the lock pairs one).
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

/// The `localKeyId` a PKCS#12 export pairs the key and its certificate by: the key's locked
/// `rfc7093m4`, which importers pair on, so never empty.
///
/// # Errors
///
/// `PreconditionFailed` (14) when the lock pins no `rfc7093m4` for `object`.
fn local_key_id(lock: &Lock, object: &str) -> cakeys_core::Result<String> {
    let scheme = cakeys_core::id::Scheme::Rfc7093m4.name();
    lock.objects.get(object).and_then(|o| o.ids.get(scheme)).cloned().ok_or_else(|| {
        KmError::PreconditionFailed(
            format!("the lock pins no {scheme} for '{object}', which a PKCS#12 pairs its key and certificate by")
                .into(),
        )
    })
}

/// The passphrase in `path` (its one line, [`cakeys_core::secret::read`]), zeroized when dropped.
/// Never empty.
fn read_passphrase(path: &Path) -> cakeys_core::Result<Zeroizing<String>> {
    let pass = cakeys_core::secret::read("passphrase", None, Some(path))?.unwrap_or_default();
    non_empty(pass, &path.display())
}

/// `pass`, read from `source`, unless it is empty (17): the one check of every passphrase, a
/// file's or an environment variable's (review 2026-11-23 C-14), so an empty one is said as
/// empty, never tried as one the file "does not open under".
fn non_empty(pass: Zeroizing<String>, source: &dyn std::fmt::Display) -> cakeys_core::Result<Zeroizing<String>> {
    if pass.is_empty() {
        return Err(KmError::Validation(format!("{source}: the passphrase is empty").into()));
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
        let pass = cakeys_core::secret::read(&format!("object '{object}': the passphrase"), Some(var), None)?;
        return pass.map(|p| non_empty(p, &format_args!("object '{object}': env var {var}"))).transpose();
    }
    cfg.object_passphrase_file(object, &|name| std::env::var(name).ok())?.map(|p| read_passphrase(&p)).transpose()
}

/// One object from its file, as `import` without `--in` takes it (docs/FILE.md F3, F6): read
/// and typed on the host, checked against the IDs the lock pins (10 before anything is
/// written), then created on `to` and recorded with `from = "file"`. When the lock pins
/// nothing yet, the file is the object's first use: the IDs the host computes from it are put
/// in the lock first, so the token must show exactly them, and the lock is left as it was if it
/// does not.
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
    // A data object is private unless the spec says it is public (`Target::needs_login`: the lock
    // records nothing of it here yet; review 2026-11-24 D-7, §9.2).
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
            });
        }
    }
    // A secret key's identity is its commitments, computed on the host (`ops::check_identity`):
    // checked here, so the dry run refuses what the run would (10).
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

/// What [`from_its_file`] did with one object: ready (a dry run), or moved or found there, with
/// the method it took.
enum Filed {
    Ready(String),
    Moved(public::Moved, String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PKCS#12's `localKeyId` is the key's locked `rfc7093m4`, and a lock that pins none is
    /// refused (14), never an empty ID importers would pair on.
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

    /// An empty passphrase is refused (17) naming where it came from, whichever source it is
    /// (review 2026-11-23 C-14: `passphraseEnv` skipped the check).
    #[test]
    fn an_empty_passphrase_is_refused_by_its_source() {
        let e = non_empty(Zeroizing::new(String::new()), &"object 'k': env var PASS").unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("env var PASS: the passphrase is empty"), "{e}");
        assert_eq!(non_empty(Zeroizing::new("p".into()), &"f").unwrap().as_str(), "p");
    }
}
