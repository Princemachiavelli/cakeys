//! Moving a key sealed (MIGRATE.md D2–D7, phase 3): the material leaves the source only wrapped
//! to a transport key that lives on the target — an RSA key the lock pins (D3) — and is unwrapped
//! there. The host never sees it. [`export`] wraps one object into a [`Bundle`]; [`import`]
//! checks the bundle against the lock before it touches the target, creates the key (and a
//! private key's public half) under the target spec, and records it through
//! `ops::realise_import`, the lock rules `cakeys realise` uses. `migrate` is the two in one
//! process, with the bundle in memory. A bundle carries every key of one export (one file per
//! source and target); each is imported, checked and rolled back on its own.

use crate::bundle::{BUNDLE_FORMAT, BUNDLE_VERSION, Bundle, Entry, Source, TransportRef, encode};
use crate::public::{Moved, public_key};
use crate::tokens::unwrap_refusals;
use cakeys_core::config::{Lock, Origin};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::pop::OaepHash;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::Token;
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::token::{class_of, key_type_of, locator_attrs};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, KeyType, ObjectClass, ObjectHandle};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;

/// The transport key a source wraps to: its object, its locked identity, and its public key.
pub struct TransportKey {
    pub object: String,
    pub rfc7093m4: String,
    /// The canonical SPKI DER.
    pub spki: Vec<u8>,
}

/// One key an export wraps: its source realisation, and the planned method and exposure.
pub struct Item<'a> {
    pub src: Target<'a>,
    pub method: Method,
    pub exposure: Exposure,
}

/// Wrap every item's key on `from` to `transport`, as one bundle — all or nothing: a key that
/// cannot be wrapped fails the export, and no bundle is made. Each source realisation is verified
/// against the lock first; the transport public key and the composed methods' shared KEK are
/// session objects on the source, destroyed again whatever happens.
///
/// # Errors
///
/// Whatever `ops::verify` refuses; `NotFound` for a key not under its locator; `Unsupported`
/// (15) for a method this build or the source cannot perform, or a `C_WrapKey` the source
/// refuses.
pub fn export(
    items: &[Item],
    from: &Token,
    lock: &Lock,
    transport: &TransportKey,
    notes: &mut Notes,
) -> Result<Bundle> {
    let mut found = Vec::new();
    for item in items {
        let src = &item.src;
        // A public object travels as it is: its bytes, read and verified on the source.
        let public = if item.method == Method::Public {
            Some(crate::public::material(src, from, lock, notes)?)
        } else {
            ops::verify(src, from, lock, notes)?;
            None
        };
        let locked = lock.objects.get(src.object_name).filter(|o| !o.ids.is_empty()).ok_or_else(|| {
            KmError::PreconditionFailed(format!("{src}: the lock pins no IDs for object '{}'", src.object_name))
        })?;
        let object_type = locked.object_type.clone().ok_or_else(|| {
            KmError::PreconditionFailed(format!("{src}: the lock records no type for object '{}'", src.object_name))
        })?;
        let held = if let Some(bytes) = public {
            Held::Public(bytes)
        } else {
            let loc = &src.on_token.locator;
            let h = from.find_key(src.object, loc, false)?.ok_or_else(|| KmError::NotFound(src.to_string()))?;
            Held::Key(h, (src.object.class == Class::PrivateKey).then(|| from.spki(h, loc)).transpose()?)
        };
        found.push((item, locked, object_type, held));
    }
    let session = from.raw();
    let refused = |what: &str, e: cryptoki::error::Error| from.unsupported(format!("{what} on '{}': {e}", from.name));
    let tpub = session.create_object(&rsa_public(transport)?).map_err(|e| refused("loading the transport key", e))?;
    let kek_hash = items.iter().find_map(|i| match i.method {
        Method::RsaOaepAesKwp(h) => Some(h),
        _ => None,
    });
    let wrapped = kek_hash.map(|h| kek(from, tpub, h, &refused)).transpose().and_then(|kek| {
        let keys = found
            .iter()
            .map(|(item, locked, object_type, held)| {
                let refused = |what: &str, e| refused(&format!("{}: {what}", item.src), e);
                let (public_key, wrapped, value) = match held {
                    Held::Key(h, public_key) => {
                        let blob = wrap(from, tpub, kek.as_ref().map(|k| k.0), *h, &item.method, &refused)?;
                        (public_key.as_deref().map(encode), Some(encode(&blob)), None)
                    }
                    Held::Public(bytes) => (None, None, Some(encode(bytes))),
                };
                Ok(Entry {
                    object: item.src.object_name.into(),
                    method: item.method.name(),
                    exposure: item.exposure,
                    commitment_label: locked.commitment_label.clone(),
                    public_key,
                    wrapped,
                    value,
                    object_type: object_type.clone(),
                    ids: locked.ids.clone(),
                })
            })
            .collect::<Result<Vec<Entry>>>();
        if let Some((k, _)) = &kek {
            let _ = session.destroy_object(*k);
        }
        Ok((kek.map(|k| encode(&k.1)), keys?))
    });
    let _ = session.destroy_object(tpub);
    let (kek, keys) = wrapped?;
    Ok(Bundle {
        format: BUNDLE_FORMAT.into(),
        version: BUNDLE_VERSION,
        kek,
        source: Source { token: from.name.clone(), provider: from.provider.name().into() },
        transport: TransportRef { object: transport.object.clone(), rfc7093m4: transport.rfc7093m4.clone() },
        keys,
    })
}

/// What an export found of one object on the source: a key (its handle, and a private key's
/// canonical SPKI), or a public object's bytes.
enum Held {
    Key(ObjectHandle, Option<Vec<u8>>),
    Public(Vec<u8>),
}

/// A fresh session AES-256 KEK on the source, and its blob wrapped to the transport key.
fn kek(
    from: &Token,
    tpub: ObjectHandle,
    hash: OaepHash,
    refused: &dyn Fn(&str, cryptoki::error::Error) -> KmError,
) -> Result<(ObjectHandle, Vec<u8>)> {
    let session = from.raw();
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Token(false),
        Attribute::Wrap(true),
        Attribute::Extractable(true),
    ];
    let kek = session.generate_key(&Mechanism::AesKeyGen, &template).map_err(|e| refused("making the KEK", e))?;
    match session.wrap_key(&oaep(hash), tpub, kek) {
        Ok(blob) => Ok((kek, blob)),
        Err(e) => {
            let _ = session.destroy_object(kek);
            Err(refused("wrapping the KEK", e))
        }
    }
}

/// One key's blob: under the shared KEK (RFC 5649) for the composed method, under the transport
/// key itself for the direct one.
fn wrap(
    from: &Token,
    tpub: ObjectHandle,
    kek: Option<ObjectHandle>,
    h: ObjectHandle,
    method: &Method,
    refused: &dyn Fn(&str, cryptoki::error::Error) -> KmError,
) -> Result<Vec<u8>> {
    let session = from.raw();
    match (method, kek) {
        (Method::RsaOaepAesKwp(_), Some(kek)) => {
            let kwp = rfc5649(from).ok_or_else(|| {
                from.unsupported(format!("'{}' offers no RFC 5649 key wrap this build can name", from.name))
            })?;
            session.wrap_key(&kwp, kek, h).map_err(|e| refused("wrapping the key", e))
        }
        (Method::RsaOaep(hash), _) => {
            session.wrap_key(&oaep(*hash), tpub, h).map_err(|e| refused("wrapping the key", e))
        }
        (other, _) => Err(KmError::Unsupported(format!("{other} is not a sealed method"))),
    }
}

/// Import `b`'s key `e` under `dst` on `to`, unwrapping with the transport key `tr` realised
/// there, and record it. Before the target is touched: the bundle's object, type, IDs and commitment label
/// must be the lock's (the lock is the reviewed truth, the bundle only a carrier), and its
/// transport key the one `tr` is; the locator must be empty. Whatever fails after something was
/// created removes everything under the locator again.
///
/// # Errors
///
/// `Validation` (17) for a bundle of another object; `PreconditionFailed` (14) when the lock
/// pins no IDs for it, or another type; `HashMismatch` (10) for bundle IDs, label or transport
/// key that are not the lock's, and — after the import — material whose identity is not the
/// locked one; `Conflict` (13) for an occupied locator or blobs that do not unwrap (tampered,
/// or wrapped to another key); `Unavailable` (16) for a session without login; whatever
/// `ops::realise_import` refuses.
pub fn import(
    b: &Bundle,
    e: &Entry,
    dst: &Target,
    to: &Token,
    tr: &Target,
    lock: &mut Lock,
    notes: &mut Notes,
) -> Result<Moved> {
    if lock.realisation(dst.spec_name, dst.token_name).is_some() {
        ops::verify(dst, to, lock, notes)?;
        return Ok(Moved::AlreadyThere);
    }
    if e.method == Method::Public.name() {
        check_against_lock(b, e, dst, tr, lock)?;
        let bytes = e.public_value().map_err(KmError::Validation)?;
        return crate::public::create(dst, to, &bytes, &b.source.token, lock, notes);
    }
    let ready = preflight(b, e, dst, to, tr, lock, notes)?;
    let method = e.method().map_err(KmError::Validation)?;
    let mut made = Vec::new();
    let created = create(b, e, dst, to, &ready, &method, &mut made).and_then(|()| {
        let origin =
            Origin { from: b.source.token.clone(), method: e.method.clone(), exposure: e.exposure, declared: false };
        ops::realise_import(dst, to, lock, origin, notes)
    });
    match created {
        Ok(_) => Ok(Moved::Imported),
        Err(err) => {
            // Exactly what the import made: other objects may share the locator (preflight).
            match to.destroy_handles(dst.object, &dst.on_token.locator, &made) {
                Ok(0) => {}
                Ok(n) => notes.say(format!("removed {n} object(s) just imported for {dst}: {err}")),
                Err(d) => notes.say(format!("what was just imported for {dst} is still on the token ({d})")),
            }
            Err(err)
        }
    }
}

/// Everything [`import`] checks before it touches the target (`import --dry-run` stops here):
/// the bundle against the lock, the transport key realised on the target against the lock, and
/// an empty locator a logged-in session can see. The transport key's handle, to unwrap with.
///
/// # Errors
///
/// As [`import`], for everything before the creation.
pub fn preflight(
    b: &Bundle,
    e: &Entry,
    dst: &Target,
    to: &Token,
    tr: &Target,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<Preflight> {
    check_against_lock(b, e, dst, tr, lock)?;
    if e.method == Method::Public.name() {
        crate::public::preflight(dst, to, &e.public_value().map_err(KmError::Validation)?)?;
        return Ok(Preflight { unwrapping: None, public_half: None });
    }
    ops::verify(tr, to, lock, notes)?;
    let unwrapping = to
        .find_key(tr.object, &tr.on_token.locator, false)?
        .ok_or_else(|| KmError::NotFound(format!("{tr}: the transport key")))?;
    if !to.logged_in {
        return Err(KmError::Unavailable(format!(
            "{dst}: a session without login cannot tell the locator is free; configure pinFile or pinEnv for \
             token '{}'",
            dst.token_name
        )));
    }
    // Per class (`Token::occupied`): a certificate beside the key is no collision, and a public
    // key object already holding the bundle's public key is the key's public half, reused.
    let spki = e.public_spki().map_err(KmError::Validation)?;
    let occupied = to.occupied(dst.object, &dst.on_token.locator, spki.as_deref())?;
    if occupied.colliding > 0 {
        return Err(KmError::Conflict(format!(
            "{} object(s) a {} would collide with already sit under the locator of {dst}, and the lock \
             records no realisation there; refusing to import over them",
            occupied.colliding, dst.object.class
        )));
    }
    Ok(Preflight { unwrapping: Some(unwrapping), public_half: occupied.public_half })
}

/// What [`preflight`] established: the transport key to unwrap with (none for a public object),
/// and a public key object already holding the key's public key, reused rather than created.
pub struct Preflight {
    pub unwrapping: Option<ObjectHandle>,
    pub public_half: Option<ObjectHandle>,
}

/// The bundle's key `e` against the lock: the same object, type, IDs and commitment label,
/// wrapped to the transport key `tr` realises.
fn check_against_lock(b: &Bundle, e: &Entry, dst: &Target, tr: &Target, lock: &Lock) -> Result<()> {
    if e.object != dst.object_name {
        return Err(KmError::Validation(format!("{dst}: the bundle's key is object '{}'", e.object)));
    }
    let locked = lock.objects.get(dst.object_name).filter(|o| !o.ids.is_empty()).ok_or_else(|| {
        KmError::PreconditionFailed(format!(
            "{dst}: the lock pins no IDs for object '{}', so nothing could check the imported material; \
             realise it on its source first",
            dst.object_name
        ))
    })?;
    if locked.object_type.as_ref() != Some(&e.object_type) || dst.object != &e.object_type {
        return Err(KmError::PreconditionFailed(format!(
            "{dst}: the bundle carries a {}, the lock and keys.toml another type",
            e.object_type
        )));
    }
    let mismatch = |what: &str, expected: String, got: String| KmError::HashMismatch {
        what: format!("{dst}: the bundle's {what}"),
        expected,
        got,
    };
    if e.ids != locked.ids {
        return Err(mismatch("IDs", format!("{:?}", locked.ids), format!("{:?}", e.ids)));
    }
    if e.commitment_label != locked.commitment_label {
        return Err(mismatch(
            "commitment label",
            format!("{:?}", locked.commitment_label),
            format!("{:?}", e.commitment_label),
        ));
    }
    let tr_id = lock.objects.get(tr.object_name).and_then(|o| o.ids.get("rfc7093m4"));
    if b.transport.object != tr.object_name || tr_id != Some(&b.transport.rfc7093m4) {
        return Err(mismatch(
            "transport key",
            format!("{} {}", tr.object_name, tr_id.map_or("<none>", String::as_str)),
            format!("{} {}", b.transport.object, b.transport.rfc7093m4),
        ));
    }
    Ok(())
}

/// Create the key under `dst` from the bundle's key `e`: a private key's public half first (from
/// its public key, as `generate` makes it), then the key unwrapped with the target spec's
/// attributes as its template, less what this module refuses in one (MIGRATE.md D6).
fn create(
    b: &Bundle,
    e: &Entry,
    dst: &Target,
    to: &Token,
    ready: &Preflight,
    method: &Method,
    made: &mut Vec<ObjectHandle>,
) -> Result<()> {
    let unwrapping = ready
        .unwrapping
        .ok_or_else(|| KmError::Validation(format!("{dst}: a public object is created, not unwrapped")))?;
    let session = to.raw();
    let refused = |what: &str, e: cryptoki::error::Error| {
        KmError::Conflict(format!(
            "{dst}: {what} on '{}': {e} (the bundle was tampered with, or wrapped to another key)",
            to.name
        ))
    };
    let loc = locator_attrs(&dst.on_token.locator)?;
    if let Some(spki) = e.public_spki().map_err(KmError::Validation)?.filter(|_| ready.public_half.is_none()) {
        let mut t = vec![Attribute::Token(true), Attribute::Class(ObjectClass::PUBLIC_KEY)];
        t.extend(loc.iter().cloned());
        t.extend(public_key(dst, &spki)?);
        t.extend(to.policy_template(&dst.spec.public_attributes)?);
        let declared = |n| dst.spec.attributes.contains_key(n) || dst.spec.public_attributes.contains_key(n);
        if !declared("CKA_VERIFY") {
            t.push(Attribute::Verify(true));
        }
        if !declared("CKA_PRIVATE") {
            t.push(Attribute::Private(false));
        }
        made.push(
            session
                .create_object(&t)
                .map_err(|e| to.unsupported(format!("{dst}: the public half: C_CreateObject: {e}")))?,
        );
    }
    let refusals = unwrap_refusals(to);
    let declared = dst.spec.attributes.iter().filter(|(n, _)| !refusals.contains(&n.as_str()));
    let mut template = vec![
        Attribute::Token(true),
        Attribute::Class(class_of(dst.object)),
        Attribute::KeyType(key_type_of(dst.object)?),
    ];
    template.extend(loc);
    template.extend(to.policy_template(&declared.map(|(n, v)| (n.clone(), v.clone())).collect())?);
    let key = e.wrapped_key().map_err(KmError::Validation)?;
    match method {
        Method::RsaOaepAesKwp(hash) => {
            let kwp = rfc5649(to).ok_or_else(|| {
                to.unsupported(format!("'{}' offers no RFC 5649 key wrap this build can name", to.name))
            })?;
            let kek_blob = b.wrapped_kek().map_err(KmError::Validation)?.unwrap_or_default();
            let kek_template = [
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Token(false),
                Attribute::Unwrap(true),
            ];
            let kek = session
                .unwrap_key(&oaep(*hash), unwrapping, &kek_blob, &kek_template)
                .map_err(|e| refused("unwrapping the KEK", e))?;
            let unwrapped =
                session.unwrap_key(&kwp, kek, &key, &template).map_err(|e| refused("unwrapping the key", e));
            let _ = session.destroy_object(kek);
            made.push(unwrapped?);
            Ok(())
        }
        Method::RsaOaep(hash) => {
            made.push(
                session
                    .unwrap_key(&oaep(*hash), unwrapping, &key, &template)
                    .map_err(|e| refused("unwrapping the key", e))?,
            );
            Ok(())
        }
        other => Err(KmError::Unsupported(format!("{other} is not a sealed method"))),
    }
}

/// RSA-OAEP with MGF1 of the same hash and an empty label: what the planner names.
fn oaep(hash: OaepHash) -> Mechanism<'static> {
    let (h, mgf) = match hash {
        OaepHash::Sha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
        OaepHash::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
    };
    Mechanism::RsaPkcsOaep(PkcsOaepParams::new(h, mgf, PkcsOaepSource::empty()))
}

/// The RFC 5649 key wrap a token offers, under the name it uses (MIGRATE.md spike: one format,
/// two mechanism IDs): `CKM_AES_KEY_WRAP_PAD`, or `CKM_AES_KEY_WRAP_KWP` where this build can name
/// it (the `kwp` feature, with the Nix build's patched cryptoki).
fn rfc5649(tok: &Token) -> Option<Mechanism<'static>> {
    if tok.has(MechanismType::AES_KEY_WRAP_PAD) {
        return Some(Mechanism::AesKeyWrapPad);
    }
    #[cfg(feature = "kwp")]
    if tok.has(MechanismType::AES_KEY_WRAP_KWP) {
        return Some(Mechanism::AesKeyWrapKwp);
    }
    None
}

/// The transport public key as a session object the source can wrap to.
fn rsa_public(transport: &TransportKey) -> Result<Vec<Attribute>> {
    let key = rsa::PublicKey::from_public_key_der(&transport.spki)
        .map_err(|e| KmError::Validation(format!("transport key '{}': {e}", transport.object)))?;
    Ok(vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Token(false),
        Attribute::Modulus(key.n().to_be_bytes_trimmed_vartime().to_vec()),
        Attribute::PublicExponent(key.e().to_be_bytes_trimmed_vartime().to_vec()),
        Attribute::Wrap(true),
        Attribute::Encrypt(true),
    ])
}
