//! Moving a key through the host (MIGRATE.md D2, `host`; phase 4), only behind
//! `--allow-host-plaintext` and only within `migrate`: never into a bundle or onto disk. The
//! source hands the key over wrapped under a session key the host drew (`Token::extract`), the
//! host unwraps it in memory, and the target creates it from the plaintext (`C_CreateObject`:
//! `host-pkcs8` for a private key, `host-raw` for a secret key). Every buffer is zeroized when
//! dropped. The import is then recorded through `ops::realise_import`, the lock rules `cakeys
//! realise` uses, so the identity is checked as for any move; a mismatch removes what was made.

use crate::public::Moved;
use crate::sealed::{create_public_half, rfc5649};
use cakeys_core::config::{Lock, Origin};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::plaintext::private_from_pkcs8;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::Token;
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::token::{class_of, key_type_of, locator_attrs};
use cryptoki::object::{Attribute, ObjectHandle};

/// Move `src`'s key on `from` to `dst` on `to` through the host by `method` (`host-pkcs8` or
/// `host-raw`), and record it.
///
/// # Errors
///
/// Whatever `ops::verify` refuses on the source; `NotFound` for a key not under its locator;
/// `Unsupported` (15) when the source will not hand it over or the target will not create it;
/// `Unavailable` (16) for a target session without login; `Conflict` (13) for an object of its
/// class already under the target locator; and, after the creation, whatever
/// `ops::realise_import` refuses, with what was created removed again.
pub fn import(
    src: &Target,
    from: &Token,
    dst: &Target,
    to: &Token,
    lock: &mut Lock,
    method: &Method,
    notes: &mut Notes,
) -> Result<Moved> {
    if lock.realisation(dst.spec_name, dst.token_name).is_some() {
        ops::verify(dst, to, lock, notes)?;
        return Ok(Moved::AlreadyThere);
    }
    ops::verify(src, from, lock, notes)?;
    let loc = &src.on_token.locator;
    let h = from.find_key(src.object, loc, false)?.ok_or_else(|| KmError::NotFound(src.to_string()))?;
    let spki = (src.object.class == Class::PrivateKey).then(|| from.spki(h, loc)).transpose()?;
    let kwp = rfc5649(from)
        .ok_or_else(|| from.unsupported(format!("'{}' offers no RFC 5649 key wrap to hand the key over", from.name)))?;
    let plain = from.extract(h, &kwp)?;
    let origin =
        Origin { from: src.token_name.to_owned(), method: method.name(), exposure: Exposure::Host, declared: false };
    create_and_record(dst, to, lock, &plain, spki.as_deref(), origin, notes)
}

/// Create the key `plain` (a private key's PKCS#8, of the public key `spki`, or a secret key's
/// value) under `dst` on `to` with `C_CreateObject`, and record it with `origin`: what
/// [`import`] does once the key is in memory, and what a key file's import does (`file`).
///
/// # Errors
///
/// As [`import`], from the target's side.
pub(crate) fn create_and_record(
    dst: &Target,
    to: &Token,
    lock: &mut Lock,
    plain: &[u8],
    spki: Option<&[u8]>,
    origin: Origin,
    notes: &mut Notes,
) -> Result<Moved> {
    if lock.realisation(dst.spec_name, dst.token_name).is_some() {
        ops::verify(dst, to, lock, notes)?;
        return Ok(Moved::AlreadyThere);
    }
    // The identity on the host first, before anything is written: a token that cannot delete
    // what it imported (a YubiKey's PIV slot) must never receive the wrong key.
    if dst.object.class == Class::PrivateKey {
        let got =
            cakeys_core::id::sri(&cakeys_core::id::spki_canonical(&cakeys_core::plaintext::spki_of_pkcs8(plain)?)?);
        let locked = lock.objects.get(dst.object_name).and_then(|o| o.ids.get("rfc7093m4"));
        if locked != Some(&got) {
            return Err(KmError::HashMismatch {
                what: format!("{dst}: the key to import"),
                expected: locked.cloned().unwrap_or_else(|| "a locked rfc7093m4".into()),
                got,
            });
        }
    }
    if !to.logged_in {
        return Err(KmError::Unavailable(format!(
            "{dst}: a session without login cannot tell the locator is free; configure pinFile or pinEnv for \
             token '{}'",
            dst.token_name
        )));
    }
    let occupied = to.occupied(dst.object, &dst.on_token.locator, spki)?;
    if occupied.colliding > 0 {
        return Err(KmError::Conflict(format!(
            "{} object(s) a {} would collide with already sit under the locator of {dst}, and the lock records \
             no realisation there; refusing to import over them",
            occupied.colliding, dst.object.class
        )));
    }
    let mut made = Vec::new();
    let created = create(dst, to, plain, spki.filter(|_| occupied.public_half.is_none()), &mut made)
        .and_then(|()| ops::realise_import(dst, to, lock, origin, notes));
    match created {
        Ok(_) => Ok(Moved::Imported),
        Err(err) => {
            // Exactly what this import made: other objects may share the locator.
            match to.destroy_handles(dst.object, &dst.on_token.locator, &made) {
                Ok(0) => {}
                Ok(n) => notes.say(format!("removed {n} object(s) just imported for {dst}: {err}")),
                Err(d) => notes.say(format!("what was just imported for {dst} is still on the token ({d})")),
            }
            Err(err)
        }
    }
}

/// Move `src`'s key on `from` into the tpm2-pkcs11 token `target` holds by `tpm2_ptool import`
/// (`tpm2-ptool`), and record it. tpm2-pkcs11 loads its objects when the module is initialised,
/// so `reopen` closes the target and opens it again before the import is recorded; `target`
/// holds the new one afterwards.
///
/// # Errors
///
/// As [`import`]; and whatever the tool reports (`Token::import_plaintext`).
pub fn import_ptool(
    src: &Target,
    from: &Token,
    dst: &Target,
    target: &mut Option<Token>,
    reopen: &dyn Fn(&mut Option<Token>, &mut Notes) -> Result<()>,
    lock: &mut Lock,
    notes: &mut Notes,
) -> Result<Moved> {
    let gone = || KmError::Unavailable(format!("{dst}: the target token is not open"));
    let to = target.as_ref().ok_or_else(gone)?;
    if lock.realisation(dst.spec_name, dst.token_name).is_some() {
        ops::verify(dst, to, lock, notes)?;
        return Ok(Moved::AlreadyThere);
    }
    ops::verify(src, from, lock, notes)?;
    let loc = &src.on_token.locator;
    let h = from.find_key(src.object, loc, false)?.ok_or_else(|| KmError::NotFound(src.to_string()))?;
    let spki = (src.object.class == Class::PrivateKey).then(|| from.spki(h, loc)).transpose()?;
    let occupied = to.occupied(dst.object, &dst.on_token.locator, spki.as_deref())?;
    if occupied.colliding > 0 || occupied.public_half.is_some() {
        return Err(KmError::Conflict(format!(
            "objects already sit under the locator of {dst}, and the lock records no realisation there; \
             refusing to import over them"
        )));
    }
    let kwp = rfc5649(from)
        .ok_or_else(|| from.unsupported(format!("'{}' offers no RFC 5649 key wrap to hand the key over", from.name)))?;
    let plain = from.extract(h, &kwp)?;
    to.import_plaintext(dst.object, &dst.on_token.locator, &plain)?;
    drop(plain);
    reopen(target, notes)?;
    let to = target.as_ref().ok_or_else(gone)?;
    let origin = Origin {
        from: src.token_name.to_owned(),
        method: Method::Tpm2Ptool.name(),
        exposure: Exposure::Host,
        declared: false,
    };
    match ops::realise_import(dst, to, lock, origin, notes) {
        Ok(_) => Ok(Moved::Imported),
        Err(err) => {
            // The locator held nothing of the key's classes before: this removes only the import.
            match to.destroy(dst.object, &dst.on_token.locator) {
                Ok(0) => {}
                Ok(n) => notes.say(format!("removed {n} object(s) just imported for {dst}: {err}")),
                Err(d) => notes.say(format!("what was just imported for {dst} is still on the token ({d})")),
            }
            Err(err)
        }
    }
}

/// Create the key under `dst` from `plain`: a private key's public half first (unless one is
/// there already), then the key with the target spec's attributes.
fn create(dst: &Target, to: &Token, plain: &[u8], spki: Option<&[u8]>, made: &mut Vec<ObjectHandle>) -> Result<()> {
    // A module that makes no public key objects (ykcs11: PIV derives the public key from the
    // slot) gets the private key alone.
    if let Some(spki) = spki.filter(|_| to.accepts_public_key_objects()) {
        made.push(create_public_half(dst, to, spki)?);
    }
    let mut base = vec![
        Attribute::Token(true),
        Attribute::Class(class_of(dst.object)),
        Attribute::KeyType(key_type_of(dst.object)?),
    ];
    base.extend(locator_attrs(&dst.on_token.locator)?);
    base.extend(to.policy_template(&dst.spec.attributes)?);
    let key = match dst.object.class {
        Class::PrivateKey => {
            let kt = dst.object.key_type.ok_or_else(|| KmError::Validation(format!("{dst}: no key type")))?;
            let parts = private_from_pkcs8(plain, kt, dst.object.curve.as_deref())?;
            to.create_private(dst.object, base, &parts)?
        }
        Class::SecretKey => to.create_secret(base, plain)?,
        class => return Err(KmError::Validation(format!("{dst}: a {class} does not take the host path"))),
    };
    made.push(key);
    Ok(())
}
