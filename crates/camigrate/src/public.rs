//! Moves a public object (docs/CAMIGRATE.md phase 2, the `public` method). A certificate, a
//! public key or a data object needs no wrapping. The source object is verified against the lock,
//! and its material is taken from what that check established: a public key from its canonical
//! SPKI, and a certificate's attributes from its DER. The object is then created on the target
//! under the target spec's locator and attributes. It is recorded through `ops::lock_import`,
//! which applies the same lock rules that `cakeys lock` uses. A mismatch (10) removes what was
//! just created and leaves the lock as it was.

use cakeys_core::config::{Lock, Origin};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{Check, KmError, Reason, Result};
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::token::{Occupied, class_of, public_key_attrs, public_object_attrs, rv_of};
use cakeys_pkcs11::{Template, Token, Topic, templates};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use x509_cert::der::Decode as _;

/// The result of moving one object.
pub(crate) enum Moved {
    /// The object was created on the target and recorded with its `origin`.
    Imported,
    /// The target already holds the object, and the lock records it and it was verified, so a
    /// re-run moves nothing.
    AlreadyThere,
}

/// Moves the public object `src` (realised on `from`) to `dst` on `to`, and records it in `lock`.
/// It calls [`material`] on the source, and then [`create`] on the target.
///
/// # Errors
///
/// The errors of [`material`] and [`create`].
pub(crate) fn import(
    src: &Target,
    from: &Token,
    dst: &Target,
    to: &Token,
    lock: &mut Lock,
    notes: &mut Notes,
) -> Result<Moved> {
    if already_there(dst, to, lock, notes)? {
        return Ok(Moved::AlreadyThere);
    }
    let bytes = material(src, from, lock, notes)?;
    create(dst, to, &bytes, src.token_name, lock, notes)
}

/// Returns the public object `src` that is realised on `from`, verified against the lock, as the
/// bytes from which a target creates it (a bundle's `value`): a certificate's DER, a public key's
/// canonical SPKI, or a data object's value.
///
/// # Errors
///
/// The errors of `ops::verify`; `NotFound` (11) or `Ambiguous` (12) for the locator; `Conflict`
/// (13) for a certificate whose value is not an X.509 certificate; `Unavailable` (16) when the
/// value cannot be read; and `Validation` (17) for an object that is not a public object.
pub(crate) fn material(src: &Target, from: &Token, lock: &Lock, notes: &mut Notes) -> Result<Vec<u8>> {
    ops::verify(src, from, lock, notes)?;
    let h = one(from, src)?;
    match src.object.class {
        Class::Certificate => {
            let der = value(from, h)?;
            x509_cert::Certificate::from_der(&der).map_err(|e| {
                KmError::Conflict(Reason::check(
                    Check::CertificateDecodes,
                    format!("{src}: CKA_VALUE is not an X.509 certificate: {e}"),
                ))
            })?;
            Ok(der)
        }
        Class::Data => value(from, h),
        Class::PublicKey => from.spki(h, &src.on_token.locator),
        class => Err(KmError::Validation(format!("{src}: a {class} is not a public object").into())),
    }
}

/// Creates the public object `dst` on `to` from `bytes` (the output of [`material`]), moved from
/// the token named `from`, and records it in `lock` with that origin. A realisation that the lock
/// already records is verified, and it is not created again.
///
/// # Errors
///
/// `Conflict` (13) when an object of its class is under the target locator and the lock records
/// no realisation of `dst`. (A public key object that holds the same key is that object, so it is
/// recorded and not created again.) `Unsupported` (15) when the target refuses `C_CreateObject`.
/// After the creation, the errors of `ops::lock_import`, including a hash mismatch (10); in that
/// case, the created object is removed again.
pub(crate) fn create(
    dst: &Target,
    to: &Token,
    bytes: &[u8],
    from: &str,
    lock: &mut Lock,
    notes: &mut Notes,
) -> Result<Moved> {
    create_as(dst, to, bytes, origin(from, &Method::Public, Exposure::Public), lock, notes)
}

/// Works as [`create`], but records the object with `origin`. For example, a private data object
/// from a file is recorded with the method `raw` and the exposure `file` (docs/FILE.md), although
/// it is created in the same way as any data object.
///
/// # Errors
///
/// The errors of [`create`].
pub(crate) fn create_as(
    dst: &Target,
    to: &Token,
    bytes: &[u8],
    origin: Origin,
    lock: &mut Lock,
    notes: &mut Notes,
) -> Result<Moved> {
    if already_there(dst, to, lock, notes)? {
        return Ok(Moved::AlreadyThere);
    }
    // Run the check that the record after the creation makes, before anything is created.
    ops::check_import(dst, to)?;
    let template = template(dst, to, bytes)?;
    let public_half = preflight(dst, to, bytes)?;
    let create = || {
        to.raw().create_object(&template).map_err(|e| {
            to.refused_for(Topic::Create, &e, format!("{dst}: importing into '{}': C_CreateObject: {e}", to.name))
        })
    };
    let created = match public_half {
        Some(_) => None,
        None => Some(to.managing("importing an object", create)?),
    };
    match ops::lock_import(dst, to, lock, origin, notes) {
        Ok(_) => Ok(Moved::Imported),
        Err(e) => Err(roll_back(dst, to, created.as_slice(), e, notes)),
    }
}

/// Returns the origin of an object moved by `method` from the token `from`, for the lock's
/// `provenance.origin`. The exposure is one that cakeys established, never one that a vendor
/// declared.
pub(crate) fn origin(from: &str, method: &Method, exposure: Exposure) -> Origin {
    Origin { from: from.to_owned(), method: method.name(), exposure, declared: false }
}

/// Returns whether the lock already records `dst`'s realisation. When it does, the realisation is
/// verified, and a re-run moves nothing.
///
/// # Errors
///
/// The errors of `ops::verify` for a recorded realisation.
pub(crate) fn already_there(dst: &Target, to: &Token, lock: &Lock, notes: &mut Notes) -> Result<bool> {
    if lock.realisation(dst.spec_name, dst.token_name).is_none() {
        return Ok(false);
    }
    ops::verify(dst, to, lock, notes)?;
    Ok(true)
}

/// Cleans up after a failed import. It removes exactly the objects that the import `made`,
/// because other objects may share the locator. It reports what happened, and it returns the
/// failure `err`.
pub(crate) fn roll_back(dst: &Target, to: &Token, made: &[ObjectHandle], err: KmError, notes: &mut Notes) -> KmError {
    match to.destroy_handles(&dst.object, &dst.on_token.locator, made) {
        Ok(0) => {}
        Ok(n) => notes.say(format!("removed {n} object(s) just imported for {dst}: {err}")),
        Err(d) => notes.say(format!("what was just imported for {dst} is still on the token ({d})")),
    }
    err
}

/// Runs the If-None-Match check before [`create`] (docs/CAMIGRATE.md D6): [`free_locator`] for a
/// public object. When a key's import already created a public key object there that holds the
/// same key, that object is this object. Its handle is returned, so that it is recorded and not
/// created again.
///
/// # Errors
///
/// The errors of [`free_locator`].
pub(crate) fn preflight(dst: &Target, to: &Token, bytes: &[u8]) -> Result<Option<ObjectHandle>> {
    let spki = (dst.object.class == Class::PublicKey).then_some(bytes);
    Ok(free_locator(dst, to, spki)?.public_half)
}

/// Runs the If-None-Match check before anything is created under `dst` (docs/CAMIGRATE.md D6).
/// This is the single occupancy check of every import: no object with which an object of its
/// class would collide may be under the locator (`Token::occupied`, which decides by class; the
/// key and the certificate next to which a public object usually sits are not collisions). The
/// session is logged in, so it sees every object under the locator (`needs_login`). It returns
/// what is there, including a public key object that already holds `spki` (a key's public half),
/// which the import reuses.
///
/// # Errors
///
/// `Conflict` (13) for a colliding object.
pub(crate) fn free_locator(dst: &Target, to: &Token, spki: Option<&[u8]>) -> Result<Occupied> {
    let occupied = to.occupied(&dst.object, &dst.on_token.locator, spki)?;
    if occupied.colliding > 0 {
        return Err(KmError::Conflict(Reason::rule(
            ops::Rule::LocatorFree,
            format!(
                "{} object(s) a {} would collide with already sit under the locator of {dst}, and the lock records \
                 no realisation there; refusing to import over them. {}",
                occupied.colliding,
                dst.object.class,
                unrecorded_hint(dst)
            ),
        )));
    }
    Ok(occupied)
}

/// Returns the hint that says how to record a key that a run moved to `dst` but could not record,
/// because the lock was unwritable at that time (21). Both a collision under the locator and that
/// failure itself include this hint (review 2026-11-23 C-21). `cakeys lock` verifies and records
/// the key, but it does not record how the key was moved.
pub(crate) fn unrecorded_hint(dst: &Target) -> String {
    format!(
        "If a run moved the key there but could not record it, `cakeys lock --spec {} --token {}` records it \
         (without how it was moved)",
        dst.spec_name, dst.token_name
    )
}

/// Returns the creation template built from the object's bytes: the class and type, the material,
/// `CKA_TOKEN`, the target locator and the target spec's declared attributes, as the provider
/// adjusts them.
fn template(dst: &Target, to: &Token, bytes: &[u8]) -> Result<Vec<Attribute>> {
    let material = public_object_attrs(dst.object, bytes).map_err(|e| prefixed(dst, e))?;
    let t = templates::object(dst.into(), to.policy_template(&dst.spec.attributes)?, Some(material))?;
    to.provider.adjusted(&Template::Object(dst.into()), t)
}

/// Returns the public key's material from its canonical SPKI, in PKCS#11's encoding
/// ([`public_key_attrs`]).
pub(crate) fn public_key(src: &Target, spki: &[u8]) -> Result<Vec<Attribute>> {
    public_key_attrs(src.object, spki).map_err(|e| prefixed(src, e))
}

/// Returns a `Conflict` or `Validation` error `e` with its message prefixed by the pair that it is
/// about, and keeps the error's rule and return value. Other errors are returned unchanged.
fn prefixed(t: &Target, e: KmError) -> KmError {
    match e {
        KmError::Conflict(_) | KmError::Validation(_) => e.prefixed(t),
        other => other,
    }
}

/// Returns the one object of `t`'s class under its locator, which the caller verified just before.
fn one(tok: &Token, t: &Target) -> Result<ObjectHandle> {
    match tok.find(class_of(&t.object), &t.on_token.locator)?.as_slice() {
        [h] => Ok(*h),
        [] => Err(KmError::NotFound(t.to_string().into())),
        _ => Err(KmError::Ambiguous(Reason::check(
            Check::LocatorUnique,
            format!("{t}: several objects under the locator"),
        ))),
    }
}

/// Returns the `CKA_VALUE` of `h`.
fn value(tok: &Token, h: ObjectHandle) -> Result<Vec<u8>> {
    let read = tok.raw().get_attributes(h, &[AttributeType::Value]);
    match read.map_err(|e| read_failed(&e))?.as_slice() {
        [Attribute::Value(v)] => Ok(v.clone()),
        _ => Err(KmError::NotFound("the object has no CKA_VALUE".into())),
    }
}

/// Returns the error for a failed `C_GetAttributeValue`: `Unavailable` (16), with the module's
/// return value attached, as on the error of every module call (ISSUES.md Q3).
fn read_failed(e: &cryptoki::error::Error) -> KmError {
    KmError::Unavailable(format!("C_GetAttributeValue: {e}").into()).with_rv(rv_of(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;
    use cryptoki::error::{Error as CkError, RvError};

    /// Checks that a failed read of `CKA_VALUE` is `Unavailable` (16), with the module's return
    /// value attached where the build can name it (review public.rs F2).
    #[test]
    fn a_failed_value_read_carries_its_return_value() {
        let e = read_failed(&CkError::Pkcs11(RvError::DeviceError, Function::GetAttributeValue));
        assert_eq!(e.exit_code(), 16);
        assert_eq!(e.rv(), cakeys_pkcs11::token::rv_value(RvError::DeviceError));
        assert!(e.to_string().contains("C_GetAttributeValue"), "{e}");
    }
}
