//! Moving a key through the host (docs/CAMIGRATE.md D2, `host`; phase 4), only behind
//! `--allow-host-plaintext` and only within `migrate`: never into a bundle or onto disk. The
//! source hands the key over wrapped under a session key the host drew (`Token::extract`), the
//! host unwraps it in memory, and the target creates it from the plaintext (`C_CreateObject`:
//! `host-pkcs8` for a private key, `host-raw` for a secret key). Every buffer is zeroized when
//! dropped. The import is then recorded through `ops::lock_import`, the lock rules `cakeys
//! lock` uses, so the identity is checked as for any move; a mismatch removes what was made.

use crate::public::{Moved, already_there, origin, roll_back};
use crate::sealed::{create_public_half, rfc5649};
use cakeys_core::config::{Lock, Origin};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::plaintext::private_from_pkcs8;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::{Template, Token, Via, templates};
use cryptoki::object::ObjectHandle;

/// Move `src`'s key on `from` to `dst` on `to` through the host by `method` (`host-pkcs8` or
/// `host-raw`), and record it.
///
/// # Errors
///
/// Whatever `ops::verify` refuses on the source; `NotFound` for a key not under its locator;
/// `Unsupported` (15) when the source will not hand it over or the target will not create it;
/// `Conflict` (13) for an object of its
/// class already under the target locator; and, after the creation, whatever
/// `ops::lock_import` refuses, with what was created removed again.
pub(crate) fn import(
    src: &Target,
    from: &Token,
    dst: &Target,
    to: &Token,
    lock: &mut Lock,
    method: &Method,
    notes: &mut Notes,
) -> Result<Moved> {
    if already_there(dst, to, lock, notes)? {
        return Ok(Moved::AlreadyThere);
    }
    let (h, spki) = source_key(src, from, lock, notes)?;
    // The target first: nothing is in plaintext yet when it refuses.
    ops::check_import(dst, to)?;
    free_locator(dst, to, spki.as_deref())?;
    let plain = hand_over(from, h)?;
    let origin = origin(src.token_name, method, Exposure::Host);
    create_and_record(dst, to, lock, &plain, spki.as_deref(), origin, notes)
}

/// The key `src` names on `from`, verified against the lock first: its handle, and a private
/// key's canonical SPKI.
fn source_key(src: &Target, from: &Token, lock: &Lock, notes: &mut Notes) -> Result<(ObjectHandle, Option<Vec<u8>>)> {
    ops::verify(src, from, lock, notes)?;
    let loc = &src.on_token.locator;
    let h = from.find_key(src.object, loc, false)?.ok_or_else(|| KmError::NotFound(src.to_string().into()))?;
    let spki = (src.object.class == Class::PrivateKey).then(|| from.spki(h, loc)).transpose()?;
    Ok((h, spki))
}

/// The key `h` of `from` in this process's memory (`Token::extract`, by RFC 5649).
fn hand_over(from: &Token, h: ObjectHandle) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let kwp = rfc5649(from)
        .ok_or_else(|| from.unsupported(format!("'{}' offers no RFC 5649 key wrap to hand the key over", from.name)))?;
    from.extract(h, &kwp)
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
    if already_there(dst, to, lock, notes)? {
        return Ok(Moved::AlreadyThere);
    }
    // The identity on the host first, before anything is written: a token that cannot delete
    // what it imported (a YubiKey's PIV slot) must never receive the wrong key.
    if dst.object.class == Class::PrivateKey {
        let got =
            cakeys_core::id::sri(&cakeys_core::id::spki_canonical(&cakeys_core::plaintext::spki_of_pkcs8(plain)?)?);
        let locked =
            lock.objects.get(dst.object_name).and_then(|o| o.ids.get(cakeys_core::id::Scheme::Rfc7093m4.name()));
        if locked != Some(&got) {
            return Err(KmError::HashMismatch {
                what: format!("{dst}: the key to import"),
                expected: locked.cloned().unwrap_or_else(|| "a locked rfc7093m4".into()),
                got,
            });
        }
    }
    // What the record after it asks (the proof's and the commitments' templates included), before
    // anything is created.
    ops::check_import(dst, to)?;
    let occupied = free_locator(dst, to, spki)?;
    let mut made = Vec::new();
    let created = create(dst, to, plain, spki.filter(|_| occupied.public_half.is_none()), &mut made)
        .and_then(|()| ops::lock_import(dst, to, lock, origin, notes));
    match created {
        Ok(_) => Ok(Moved::Imported),
        Err(err) => Err(roll_back(dst, to, &made, err, notes)),
    }
}

/// If-None-Match before a key is created under `dst` (docs/CAMIGRATE.md D6): nothing a key of
/// its class would collide with may sit there (`Token::occupied`; the session is logged in,
/// `needs_login` refused the run otherwise). What is there, with the public half to reuse.
///
/// # Errors
///
/// `Conflict` (13) for a colliding object.
pub(crate) fn free_locator(dst: &Target, to: &Token, spki: Option<&[u8]>) -> Result<cakeys_pkcs11::token::Occupied> {
    let occupied = to.occupied(dst.object, &dst.on_token.locator, spki)?;
    if occupied.colliding > 0 {
        return Err(KmError::Conflict(
            format!(
                "{} object(s) a {} would collide with already sit under the locator of {dst}, and the lock records \
             no realisation there; refusing to import over them",
                occupied.colliding, dst.object.class
            )
            .into(),
        ));
    }
    Ok(occupied)
}

/// Move `src`'s key on `from` into the tpm2-pkcs11 token `target` holds by `tpm2_ptool import`
/// (`tpm2-ptool`), and record it. tpm2-pkcs11 loads its objects when the module is initialised,
/// so `reopen` closes the target and opens it again before the import is recorded; `target`
/// holds the new one afterwards.
///
/// # Errors
///
/// As [`import`]; and whatever the tool reports (`Token::import_plaintext`).
pub(crate) fn import_ptool(
    src: &Target,
    from: &Token,
    dst: &Target,
    target: &mut Option<Token>,
    reopen: &dyn Fn(&mut Option<Token>, &mut Notes) -> Result<()>,
    lock: &mut Lock,
    notes: &mut Notes,
) -> Result<Moved> {
    let gone = || KmError::Unavailable(format!("{dst}: the target token is not open").into());
    let to = target.as_ref().ok_or_else(gone)?;
    if already_there(dst, to, lock, notes)? {
        return Ok(Moved::AlreadyThere);
    }
    let (h, spki) = source_key(src, from, lock, notes)?;
    ops::check_import(dst, to)?;
    let occupied = free_locator(dst, to, spki.as_deref())?;
    if occupied.public_half.is_some() {
        return Err(KmError::Conflict(
            format!(
                "objects already sit under the locator of {dst}, and the lock records no realisation there; \
             refusing to import over them"
            )
            .into(),
        ));
    }
    let plain = hand_over(from, h)?;
    to.import_plaintext(dst.object, &dst.on_token.locator, &plain)?;
    drop(plain);
    // The key is in the TPM from here on: a reopen that fails leaves it there, unrecorded, and
    // the next run refuses its locator (13). Say what is there and how to resolve it.
    if let Err(err) = reopen(target, notes) {
        notes.say(format!(
            "{dst}: tpm2_ptool imported the key, but the token could not be opened again to record it: it is \
             in the TPM under its locator, unrecorded; record it with `cakeys lock --spec {} --token {}`, or \
             remove it with `tpm2_ptool rmobject`",
            dst.spec_name, dst.token_name
        ));
        return Err(err);
    }
    let to = target.as_ref().ok_or_else(gone)?;
    let origin = origin(src.token_name, &Method::Tpm2Ptool, Exposure::Host);
    match ops::lock_import(dst, to, lock, origin, notes) {
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
    // The key's template as the provider adjusts it, before anything is created.
    let base = templates::import_key(dst.into(), to.policy_template(&dst.spec.attributes)?)?;
    let base = to.provider.adjusted(&Template::Import(dst.into(), Via::CreateObject), base)?;
    // A module that makes no public key objects (ykcs11: PIV derives the public key from the
    // slot) gets the private key alone.
    if let Some(spki) = spki.filter(|_| to.accepts_public_key_objects()) {
        made.push(create_public_half(dst, to, spki)?);
    }
    let key = match dst.object.class {
        Class::PrivateKey => {
            let kt = dst.object.key_type.ok_or_else(|| KmError::Validation(format!("{dst}: no key type").into()))?;
            let parts = private_from_pkcs8(plain, kt, dst.object.curve.as_deref())?;
            to.create_private(dst.object, base, &parts)?
        }
        Class::SecretKey => to.create_secret(base, plain)?,
        class => return Err(KmError::Validation(format!("{dst}: a {class} does not take the host path").into())),
    };
    made.push(key);
    Ok(())
}
