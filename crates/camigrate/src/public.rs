//! Moving a public object (docs/CAMIGRATE.md phase 2, the `public` method): a certificate, a public key
//! or a data object needs no wrapping. The source object is verified against the lock, its
//! material taken from what that check established — a public key from its canonical SPKI, a
//! certificate's attributes from its DER — and created on the target under the target spec's
//! locator and attributes. It is then recorded through `ops::lock_import`, the lock rules
//! `cakeys lock` uses: a mismatch (10) removes what was just created and leaves the lock as
//! it was.

use cakeys_core::config::{Lock, Origin};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::token::{Occupied, class_of, public_key_attrs, public_object_attrs, rv_of};
use cakeys_pkcs11::{Template, Token, Topic, templates};
use cryptoki::object::{Attribute, AttributeType, ObjectHandle};
use x509_cert::der::Decode as _;

/// What moving one object did.
pub(crate) enum Moved {
    /// Created on the target and recorded with its `origin`.
    Imported,
    /// The target already holds it, recorded and verified: a re-run moves nothing.
    AlreadyThere,
}

/// Move the public object `src` (realised on `from`) to `dst` on `to`, and record it in `lock`:
/// [`material`] from the source, then [`create`] on the target.
///
/// # Errors
///
/// As [`material`] and [`create`].
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

/// The public object `src` realised on `from`, verified against the lock, as the bytes a target
/// creates it from (a bundle's `value`): a certificate's DER, a public key's canonical SPKI, a
/// data object's value.
///
/// # Errors
///
/// Whatever `ops::verify` refuses; `NotFound`/`Ambiguous` for the locator; `Conflict` for a
/// certificate whose value is no X.509 certificate.
pub(crate) fn material(src: &Target, from: &Token, lock: &Lock, notes: &mut Notes) -> Result<Vec<u8>> {
    ops::verify(src, from, lock, notes)?;
    let h = one(from, src)?;
    match src.object.class {
        Class::Certificate => {
            let der = value(from, h)?;
            x509_cert::Certificate::from_der(&der)
                .map_err(|e| KmError::Conflict(format!("{src}: CKA_VALUE is not an X.509 certificate: {e}").into()))?;
            Ok(der)
        }
        Class::Data => value(from, h),
        Class::PublicKey => from.spki(h, &src.on_token.locator),
        class => Err(KmError::Validation(format!("{src}: a {class} is not a public object").into())),
    }
}

/// Create the public object `dst` on `to` from `bytes` ([`material`]'s), moved from the token
/// named `from`, and record it in `lock` with that origin. A realisation the lock already has is
/// verified, not created again.
///
/// # Errors
///
/// `Conflict` (13) when an object of its class sits under the target locator without a
/// realisation of `dst` (a public key object holding the same key is that object: recorded, not
/// created again); `Unsupported` (15)
/// when the target refuses `C_CreateObject`; and, after the creation, whatever
/// `ops::lock_import` refuses — a hash mismatch (10) included — with what was created removed
/// again.
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

/// [`create`], recorded with `origin`: a private data object from a file is `raw`, exposure
/// `file` (docs/FILE.md), though it is created as any data object is.
///
/// # Errors
///
/// As [`create`].
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
    // What the record after it asks, before anything is created.
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

/// Where an object moved by `method` from the token `from` came from, for the lock's
/// `provenance.origin`: the exposure is one cakeys established, never a vendor's declared one.
pub(crate) fn origin(from: &str, method: &Method, exposure: Exposure) -> Origin {
    Origin { from: from.to_owned(), method: method.name(), exposure, declared: false }
}

/// Whether the lock already records `dst`'s realisation: then it is verified, and a re-run
/// moves nothing.
///
/// # Errors
///
/// Whatever `ops::verify` refuses of a recorded realisation.
pub(crate) fn already_there(dst: &Target, to: &Token, lock: &Lock, notes: &mut Notes) -> Result<bool> {
    if lock.realisation(dst.spec_name, dst.token_name).is_none() {
        return Ok(false);
    }
    ops::verify(dst, to, lock, notes)?;
    Ok(true)
}

/// After a failed import: remove exactly the objects it `made` (others may share the locator),
/// say what happened, and hand back the failure `err`.
pub(crate) fn roll_back(dst: &Target, to: &Token, made: &[ObjectHandle], err: KmError, notes: &mut Notes) -> KmError {
    match to.destroy_handles(&dst.object, &dst.on_token.locator, made) {
        Ok(0) => {}
        Ok(n) => notes.say(format!("removed {n} object(s) just imported for {dst}: {err}")),
        Err(d) => notes.say(format!("what was just imported for {dst} is still on the token ({d})")),
    }
    err
}

/// If-None-Match before [`create`] (docs/CAMIGRATE.md D6): [`free_locator`] for a public object,
/// whose public key object a key's import already created there is this object (returned:
/// recorded, not created).
///
/// # Errors
///
/// As [`free_locator`].
pub(crate) fn preflight(dst: &Target, to: &Token, bytes: &[u8]) -> Result<Option<ObjectHandle>> {
    let spki = (dst.object.class == Class::PublicKey).then_some(bytes);
    Ok(free_locator(dst, to, spki)?.public_half)
}

/// If-None-Match before anything is created under `dst` (docs/CAMIGRATE.md D6), the one
/// occupancy check of every import: nothing an object of its class would collide with may sit
/// there (`Token::occupied`, per class: the key and certificate a public object usually sits
/// beside are no collision). The session is logged in, so it sees everything under the locator
/// (`needs_login`). What is there, with a public key object already holding `spki` (a key's
/// public half) to reuse.
///
/// # Errors
///
/// `Conflict` (13) for a colliding object.
pub(crate) fn free_locator(dst: &Target, to: &Token, spki: Option<&[u8]>) -> Result<Occupied> {
    let occupied = to.occupied(&dst.object, &dst.on_token.locator, spki)?;
    if occupied.colliding > 0 {
        return Err(KmError::Conflict(
            format!(
                "{} object(s) a {} would collide with already sit under the locator of {dst}, and the lock records \
                 no realisation there; refusing to import over them. {}",
                occupied.colliding,
                dst.object.class,
                unrecorded_hint(dst)
            )
            .into(),
        )
        .with_rule(ops::Rule::LocatorFree.name()));
    }
    Ok(occupied)
}

/// How to record a key a run moved to `dst` but could not record (the lock unwritable then,
/// 21): what a collision under its locator says, and that failure itself (review 2026-11-23
/// C-21). `cakeys lock` verifies and records it, without how it was moved.
pub(crate) fn unrecorded_hint(dst: &Target) -> String {
    format!(
        "If a run moved the key there but could not record it, `cakeys lock --spec {} --token {}` records it \
         (without how it was moved)",
        dst.spec_name, dst.token_name
    )
}

/// The creation template from the object's bytes: the class and type, the material, `CKA_TOKEN`,
/// the target locator and the target spec's declared attributes, as the provider adjusts it.
fn template(dst: &Target, to: &Token, bytes: &[u8]) -> Result<Vec<Attribute>> {
    let material = public_object_attrs(dst.object, bytes).map_err(|e| prefixed(dst, e))?;
    let t = templates::object(dst.into(), to.policy_template(&dst.spec.attributes)?, Some(material))?;
    to.provider.adjusted(&Template::Object(dst.into()), t)
}

/// The public key's material from its canonical SPKI, in PKCS#11's encoding
/// ([`public_key_attrs`]).
pub(crate) fn public_key(src: &Target, spki: &[u8]) -> Result<Vec<Attribute>> {
    public_key_attrs(src.object, spki).map_err(|e| prefixed(src, e))
}

/// `e`, its message led by the pair it is about, its rule and return value kept.
fn prefixed(t: &Target, e: KmError) -> KmError {
    match e {
        KmError::Conflict(_) | KmError::Validation(_) => e.prefixed(t),
        other => other,
    }
}

/// The one object of `t`'s class under its locator (verified just before).
fn one(tok: &Token, t: &Target) -> Result<ObjectHandle> {
    match tok.find(class_of(&t.object), &t.on_token.locator)?.as_slice() {
        [h] => Ok(*h),
        [] => Err(KmError::NotFound(t.to_string().into())),
        _ => Err(KmError::Ambiguous(format!("{t}: several objects under the locator").into())),
    }
}

/// `CKA_VALUE` of `h`.
fn value(tok: &Token, h: ObjectHandle) -> Result<Vec<u8>> {
    let read = tok.raw().get_attributes(h, &[AttributeType::Value]);
    match read.map_err(|e| read_failed(&e))?.as_slice() {
        [Attribute::Value(v)] => Ok(v.clone()),
        _ => Err(KmError::NotFound("the object has no CKA_VALUE".into())),
    }
}

/// A `C_GetAttributeValue` that failed: unavailable (16), carrying the module's return value
/// as every module call's error does (ISSUES.md Q3).
fn read_failed(e: &cryptoki::error::Error) -> KmError {
    KmError::Unavailable(format!("C_GetAttributeValue: {e}").into()).with_rv(rv_of(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;
    use cryptoki::error::{Error as CkError, RvError};

    /// A failed read of `CKA_VALUE` is 16 with the module's return value on it (review
    /// public.rs F2), where the build can name it.
    #[test]
    fn a_failed_value_read_carries_its_return_value() {
        let e = read_failed(&CkError::Pkcs11(RvError::DeviceError, Function::GetAttributeValue));
        assert_eq!(e.exit_code(), 16);
        assert_eq!(e.rv(), cakeys_pkcs11::token::rv_value(RvError::DeviceError));
        assert!(e.to_string().contains("C_GetAttributeValue"), "{e}");
    }
}
