//! Moves a key through the host (docs/CAMIGRATE.md D2, `host`; phase 4). This happens only with
//! `--allow-host-plaintext` and only within `migrate`, and the key never goes into a bundle or
//! onto disk. The source hands the key over wrapped under a session key that the host generated
//! (`Token::extract`). The host unwraps it in memory, and the target creates it from the
//! plaintext with `C_CreateObject` (`host-pkcs8` for a private key, `host-raw` for a secret key).
//! Every buffer is zeroized when it is dropped. The import is then recorded through
//! `ops::lock_import`, which applies the same lock rules that `cakeys lock` uses, so the identity
//! is checked as for any move. A mismatch removes what was made.

use crate::public::free_locator;
use crate::public::{Moved, already_there, origin, roll_back};
use crate::sealed::{create_public_half, rfc5649};
use cakeys_core::config::{Lock, Origin};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::plaintext::private_from_pkcs8;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Reason, Result};
use cakeys_pkcs11::ops::{self, Checked, Extracted, Notes, Target};
use cakeys_pkcs11::token::Occupied;
use cakeys_pkcs11::{Template, Token, Topic, Via, templates};
use cryptoki::object::ObjectHandle;

/// Moves `src`'s key on `from` to `dst` on `to` through the host by `method` (`host-pkcs8` or
/// `host-raw`), and records it.
///
/// # Errors
///
/// The errors of `ops::verify` on the source; `NotFound` (11) for a key that is not under its
/// locator; `Unsupported` (15) when the source will not hand the key over or the target will not
/// create it; `Conflict` (13) for an object of its class that is already under the target
/// locator; and, after the creation, the errors of `ops::lock_import`, in which case the created
/// objects are removed again.
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
    // Check the target first, so that no key is in plaintext yet when the target refuses.
    let occupied = landing(dst, to, spki.as_deref())?;
    let plain = hand_over(from, h, dst, lock)?;
    let origin = origin(src.token_name, method, Exposure::Host);
    create_landed(dst, to, lock, &plain, spki.as_deref(), &occupied, origin, notes)
}

/// Checks what must be true of `dst` on `to` before a key is created there, once for each
/// import. It runs the check that the record after the creation makes (`ops::check_import`,
/// which includes the templates of the proof and of the commitments), and it checks that nothing
/// would collide with the key under the locator ([`free_locator`]). It returns what is under the
/// locator.
///
/// # Errors
///
/// The errors of `ops::check_import`, and `Conflict` (13) for a colliding object.
fn landing(dst: &Target, to: &Token, spki: Option<&[u8]>) -> Result<Occupied> {
    ops::check_import(dst, to)?;
    free_locator(dst, to, spki)
}

/// Checks that the locator does not hold even the key's public half (`occupied`). `tpm2_ptool
/// import` creates the whole key pair, so it cannot reuse a public half, although a creation
/// through the module would.
///
/// # Errors
///
/// `Conflict` (13) for a public key object under the locator.
pub(crate) fn ptool_free(dst: &Target, occupied: &Occupied) -> Result<()> {
    if occupied.public_half.is_none() {
        return Ok(());
    }
    Err(KmError::Conflict(Reason::rule(
        ops::Rule::LocatorFree,
        format!(
            "objects already sit under the locator of {dst}, and the lock records no realisation there; refusing \
             to import over them. {}",
            crate::public::unrecorded_hint(dst)
        ),
    )))
}

/// Returns the key that `src` names on `from`, after it verifies the key against the lock: the
/// key's handle, and a private key's canonical SPKI. A dry run also reads the source with this
/// function ([`crate::landing::search`]).
pub(crate) fn source_key(
    src: &Target,
    from: &Token,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<(ObjectHandle, Option<Vec<u8>>)> {
    ops::verify(src, from, lock, notes)?;
    let loc = &src.on_token.locator;
    let h = from.find_key(&src.object, loc, false)?.ok_or_else(|| KmError::NotFound(src.to_string().into()))?;
    let spki = (src.object.class == Class::PrivateKey).then(|| from.spki(h, loc)).transpose()?;
    Ok((h, spki))
}

/// Brings the key `h` of `from` into this process's memory (`Token::extract`, by RFC 5649), and
/// checks its identity against what the lock pins for `dst` (`ops::check_identity`) before any
/// path can write it. A token that cannot delete what it imported (a `YubiKey`'s PIV slot, or a
/// TPM) must never receive the wrong key, and `tpm2_ptool` once did receive one (review
/// 2026-11-23 C-13). Every writer here takes the [`Checked`] value that this function returns.
fn hand_over(from: &Token, h: ObjectHandle, dst: &Target, lock: &Lock) -> Result<Checked> {
    let kwp = rfc5649(from).ok_or_else(|| {
        from.unsupported_for(
            Topic::Mechanism,
            format!("'{}' offers no RFC 5649 key wrap to hand the key over", from.name),
        )
    })?;
    ops::check_identity(dst, lock, from.extract(h, &kwp)?)
}

/// Creates the key `plain` (a private key's PKCS#8 with the public key `spki`, or a secret key's
/// value) under `dst` on `to` with `C_CreateObject`, and records it with `origin`. A key file's
/// import (`file`) uses this function. [`import`] makes the same checks, but it checks the target
/// before the key is in memory, and then it calls the same [`create_landed`].
///
/// # Errors
///
/// The errors of [`import`] that come from the target's side.
pub(crate) fn create_and_record(
    dst: &Target,
    to: &Token,
    lock: &mut Lock,
    plain: Extracted,
    spki: Option<&[u8]>,
    origin: Origin,
    notes: &mut Notes,
) -> Result<Moved> {
    if already_there(dst, to, lock, notes)? {
        return Ok(Moved::AlreadyThere);
    }
    // Check the identity on the host first, and then the target, before anything is written.
    let plain = ops::check_identity(dst, lock, plain)?;
    let occupied = landing(dst, to, spki)?;
    create_landed(dst, to, lock, &plain, spki, &occupied, origin, notes)
}

/// Runs the rest of [`create_and_record`] after its checks passed. It creates the key, records
/// it, and removes what was made when the record refuses. `occupied` is the result of
/// [`landing`], and a public half that is already there is reused.
#[expect(clippy::too_many_arguments, reason = "create_and_record's parts, with what its checks established")]
fn create_landed(
    dst: &Target,
    to: &Token,
    lock: &mut Lock,
    plain: &Checked,
    spki: Option<&[u8]>,
    occupied: &Occupied,
    origin: Origin,
    notes: &mut Notes,
) -> Result<Moved> {
    let mut made = Vec::new();
    let created = create(dst, to, plain, spki.filter(|_| occupied.public_half.is_none()), &mut made)
        .and_then(|()| ops::lock_import(dst, to, lock, origin, notes));
    match created {
        Ok(_) => Ok(Moved::Imported),
        Err(err) => Err(roll_back(dst, to, &made, err, notes)),
    }
}

/// Moves `src`'s key on `from` into the tpm2-pkcs11 token that `target` holds, by
/// `tpm2_ptool import` (`tpm2-ptool`), and records it. tpm2-pkcs11 loads its objects when the
/// module is initialised, so `reopen` closes the target and opens it again before the import is
/// recorded. Afterwards, `target` holds the reopened token.
///
/// # Errors
///
/// The errors of [`import`], and any error that the tool reports (`Token::import_plaintext`).
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
    let occupied = landing(dst, to, spki.as_deref())?;
    ptool_free(dst, &occupied)?;
    // The key is checked as on every host path, before tpm2_ptool runs. So the wrong key never
    // reaches the TPM, and the PIN is never put on tpm2_ptool's command line for it.
    let plain = hand_over(from, h, dst, lock)?;
    to.import_plaintext(&dst.object, &dst.on_token.locator, plain.plaintext())?;
    drop(plain);
    // The key is in the TPM from here on. A reopen that fails leaves it there without a record,
    // and the next run refuses its locator (13). The message says what is there and how to
    // resolve it.
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
            // The locator held no object of the key's classes before the import, so this removes
            // only the imported objects.
            match to.destroy(&dst.object, &dst.on_token.locator) {
                Ok(0) => {}
                Ok(n) => notes.say(format!("removed {n} object(s) just imported for {dst}: {err}")),
                Err(d) => notes.say(format!("what was just imported for {dst} is still on the token ({d})")),
            }
            Err(err)
        }
    }
}

/// Creates the key under `dst` from `plain`. For a private key, it first creates the public half
/// (unless one is already there), and then the key with the target spec's attributes.
fn create(dst: &Target, to: &Token, plain: &Checked, spki: Option<&[u8]>, made: &mut Vec<ObjectHandle>) -> Result<()> {
    // Build the key's template as the provider adjusts it, before anything is created.
    let base = templates::import_key(dst.into(), to.policy_template(&dst.spec.attributes)?)?;
    let base = to.provider.adjusted(&Template::Import(dst.into(), Via::CreateObject), base)?;
    // A module that makes no public key objects (ykcs11, because PIV derives the public key from
    // the slot) gets only the private key.
    if let Some(spki) = spki.filter(|_| to.accepts_public_key_objects()) {
        made.push(create_public_half(dst, to, spki)?);
    }
    let key = match dst.object.class {
        Class::PrivateKey => {
            let kt = dst.object.key_type().ok_or_else(|| KmError::Validation(format!("{dst}: no key type").into()))?;
            let parts = private_from_pkcs8(plain.plaintext(), kt, dst.object.curve())?;
            to.create_private(dst.object, base, &parts)?
        }
        Class::SecretKey => to.create_secret(base, plain.plaintext())?,
        class => return Err(KmError::Validation(format!("{dst}: a {class} does not take the host path").into())),
    };
    made.push(key);
    Ok(())
}
