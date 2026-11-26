//! A sealed move of a key (docs/CAMIGRATE.md D2 to D7, phase 3). The material leaves the source
//! only in wrapped form, under a transport key that is stored on the target, and the target
//! unwraps it. The transport key is an RSA key that the lock pins (D3). The host never sees the
//! material. [`export`] wraps the keys of one export into a [`Bundle`]. [`import`] checks the
//! bundle against the lock before it touches the target, creates the key (and a private key's
//! public half) under the target spec, and records it through `ops::lock_import`, which applies
//! the lock rules that `cakeys lock` uses. `migrate` runs both in one process, with the bundle in
//! memory. A bundle carries every key of one export (one file for each source and target), and
//! each key is imported, checked and rolled back on its own.

use crate::bundle::{BUNDLE_FORMAT, BUNDLE_VERSION, Bundle, Entry, Source, TransportRef, encode};
use crate::public::free_locator;
use crate::public::{Moved, already_there, public_key, roll_back};
use crate::side::Side;
use crate::tokens::unwrap_refusals;
use crate::trust::{BoundBundle, BoundTransport};
use cakeys_core::config::{AttrValue, Binding, Lock, Origin};
use cakeys_core::migrate::{Exposure, Method, OaepHash};
use cakeys_core::types::{KeyType, ObjectClass as Class};
use cakeys_core::{Check, KmError, Reason, Result};
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::token::{SessionObject, with_public_default_dropped};
use cakeys_pkcs11::{SessionKey, Template, Token, Topic, Via, templates};
use cryptoki::mechanism::rsa::PkcsOaepParams;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectHandle};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;
use std::collections::BTreeMap;

/// One object that an export puts into a bundle: its source realisation, and the planned method
/// and exposure.
pub(crate) struct Item<'a> {
    pub src: Target<'a>,
    pub method: Method,
    pub exposure: Exposure,
}

/// Wraps the key of every item on `from` to `transport`, which is `to`'s transport key as the
/// lock binds it, and returns the items as one bundle for `to`. The export is all or nothing: a key
/// that cannot be wrapped fails the export, and no bundle is made. Public objects need no
/// transport key. A bundle of public objects alone names no transport key, and nothing is created
/// on the source. Each source realisation is verified against the lock first. The transport public
/// key and the shared KEK of the composed methods are session objects on the source, and they are
/// destroyed when the function returns, whether it succeeds or fails.
///
/// # Errors
///
/// Every error of `ops::verify`. `NotFound` (11) for a key that is not under its locator.
/// `Unsupported` (15) for a method that this build or the source cannot perform, or for a
/// `C_WrapKey` that the source refuses. `PreconditionFailed` (14) when there is a key to wrap but
/// no transport key of `to` whose public key is known, or when the source holds no trusted copy of
/// the transport key for an enforced key.
pub(crate) fn export(
    items: &[Item],
    from: &Token,
    lock: &Lock,
    to: &str,
    transport: Option<&BoundTransport>,
    notes: &mut Notes,
) -> Result<Bundle> {
    let found = hold(items, from, lock, notes)?;
    let source = Source { token: from.name.clone(), provider: from.provider.name().into() };
    let target = Some(to.to_owned());
    let wraps = found.iter().any(|f| matches!(f.held, Held::Key(..)));
    let Some(transport) = transport.filter(|t| wraps && t.token() == to) else {
        if wraps {
            return Err(KmError::PreconditionFailed(Reason::check(
                Check::ImportTransport,
                format!("exporting keys from '{}' needs the target's transport key to wrap them to", from.name),
            )));
        }
        // The bundle holds only public objects. Nothing is wrapped, so the bundle names no
        // transport key, and nothing is created on the source.
        let keys = found.iter().map(|f| entry(f, None));
        return Ok(Bundle {
            format: BUNDLE_FORMAT.into(),
            version: BUNDLE_VERSION,
            kek: None,
            source,
            target,
            transport: None,
            keys: keys.collect(),
        });
    };
    let spki = transport.spki().ok_or_else(|| transport.no_public_key())?;
    // An enforced key is wrapped only under the trusted copy of the transport key
    // (`transport --trust-on`). Its composed method then uses `CKM_RSA_AES_KEY_WRAP`, because the
    // source trusts no key-encryption key.
    let trusted = if items.iter().any(|i| i.exposure == Exposure::Enforced) {
        let (copy, others) = from.trusted(spki)?;
        if others > 0 {
            notes.warn(format_args!(
                "{others} other object(s) on '{}' are CKA_TRUSTED: a CKA_WRAP_WITH_TRUSTED key there wraps under any \
                 of them, so `enforced` is only as narrow as that set",
                from.name
            ));
        }
        Some(copy.ok_or_else(|| {
            KmError::PreconditionFailed(Reason::check(
                Check::ImportTransport,
                format!(
                    "'{}' holds no trusted copy of transport key '{}': `{}`",
                    from.name,
                    transport.object(),
                    crate::plan::trust_command(Some(transport.object()), &from.name)
                ),
            ))
        })?)
    } else {
        None
    };
    let modulus = rsa_parts(spki)?.0.len();
    let session = from.raw();
    let refused = |what: &str, e: cryptoki::error::Error| {
        from.refused_for(Topic::Mechanism, &e, format!("{what} on '{}': {e}", from.name))
    };
    // The transport public key and the shared KEK are session objects on the source. Both are
    // destroyed when this function returns, whether it succeeds or fails.
    let tpub_template = templates::session(SessionKey::TransportKey).with_material(rsa_public(spki)?)?;
    let tpub_template = from.provider.adjusted_session(tpub_template)?;
    let tpub = session.create_object(&tpub_template).map_err(|e| refused("loading the transport key", e))?;
    let tpub = SessionObject::new(session, tpub);
    let under_kek =
        |i: &&Item| shares_kek(&i.method, i.exposure, rfc5649(from).is_some(), from.has(MechanismType::AES_KEY_GEN));
    let kek_hash = items.iter().find(under_kek).and_then(|i| match i.method {
        Method::RsaOaepAesKwp(h) => Some(h),
        _ => None,
    });
    let shared = kek_hash.map(|h| kek(from, tpub.handle(), h, &refused)).transpose()?;
    let mut keys = Vec::new();
    for f in &found {
        let refused = |what: &str, e| refused(&format!("{}: {what}", f.item.src), e);
        let wrapped = match &f.held {
            Held::Key(h, _) => {
                let enforced = f.item.exposure == Exposure::Enforced;
                let wrapping = Wrapping {
                    tpub: trusted.filter(|_| enforced).unwrap_or(tpub.handle()),
                    kek: shared.as_ref().map(|(kek, _)| kek.handle()),
                    modulus,
                };
                Some(wrap(from, &wrapping, *h, &f.item.method, f.item.exposure, &refused)?)
            }
            Held::Public(_) => None,
        };
        keys.push(entry(f, wrapped));
    }
    Ok(Bundle {
        format: BUNDLE_FORMAT.into(),
        version: BUNDLE_VERSION,
        kek: shared.map(|(_, blob)| encode(&blob)),
        source,
        target,
        transport: Some(TransportRef {
            object: transport.object().to_owned(),
            rfc7093m4: transport.rfc7093m4().to_owned(),
        }),
        keys,
    })
}

/// Builds one object's bundle entry. The entry holds a public object's bytes, or a key's `wrapped`
/// blob together with the key's own wrapped KEK when it has one (the result of [`wrap`]).
fn entry(found: &Found, wrapped: Option<Wrapped>) -> Entry {
    let Found { item, locked, object_type, held } = found;
    let (public_key, value) = match held {
        Held::Key(_, public_key) => (public_key.as_deref().map(encode), None),
        Held::Public(bytes) => (None, Some(encode(bytes))),
    };
    let (kek, wrapped) = match wrapped {
        Some(Wrapped { own_kek, blob }) => (own_kek.as_deref().map(encode), Some(encode(&blob))),
        None => (None, None),
    };
    Entry {
        object: item.src.object_name.into(),
        method: item.method.name(),
        exposure: item.exposure,
        commitment_label: locked.commitment_label.clone(),
        public_key,
        kek,
        wrapped,
        value,
        object_type: object_type.clone(),
        ids: locked.ids.clone(),
    }
}

/// One item as the source holds it ([`hold`]): the object as the lock pins it, its type, and
/// its handle or bytes.
struct Found<'a> {
    item: &'a Item<'a>,
    locked: &'a cakeys_core::config::LockObject,
    object_type: cakeys_core::config::ObjectCfg,
    held: Held,
}

/// One wrapped key ([`wrap`]): its blob, and its own wrapped KEK when it does not use the bundle's
/// shared KEK.
struct Wrapped {
    own_kek: Option<Vec<u8>>,
    blob: Vec<u8>,
}

/// Finds each item on the source, after it verifies the item against the lock.
fn hold<'a>(items: &'a [Item<'a>], from: &Token, lock: &'a Lock, notes: &mut Notes) -> Result<Vec<Found<'a>>> {
    let mut found = Vec::new();
    for item in items {
        let src = &item.src;
        // A public object is copied as it is: its bytes are read and verified on the source.
        let public = if item.method == Method::Public {
            Some(crate::public::material(src, from, lock, notes)?)
        } else {
            ops::verify(src, from, lock, notes)?;
            None
        };
        let locked = lock.objects.get(src.object_name).filter(|o| !o.ids.is_empty()).ok_or_else(|| {
            KmError::PreconditionFailed(Reason::check(
                Check::ImportLocked,
                format!("{src}: the lock pins no IDs for object '{}'", src.object_name),
            ))
        })?;
        let object_type = locked.object_type.clone().ok_or_else(|| {
            KmError::PreconditionFailed(Reason::check(
                Check::ImportLocked,
                format!("{src}: the lock records no type for object '{}'", src.object_name),
            ))
        })?;
        let held = if let Some(bytes) = public {
            Held::Public(bytes)
        } else {
            let loc = &src.on_token.locator;
            let h = from.find_key(&src.object, loc, false)?.ok_or_else(|| KmError::NotFound(src.to_string().into()))?;
            Held::Key(h, (src.object.class == Class::PrivateKey).then(|| from.spki(h, loc)).transpose()?)
        };
        found.push(Found { item, locked, object_type, held });
    }
    Ok(found)
}

/// What an export found of one object on the source: a key (its handle, and a private key's
/// canonical SPKI), or a public object's bytes.
enum Held {
    Key(ObjectHandle, Option<Vec<u8>>),
    Public(Vec<u8>),
}

/// Creates a fresh AES-256 session KEK on the source, and returns it with its blob wrapped to the
/// transport key.
fn kek<'a>(
    from: &'a Token,
    tpub: ObjectHandle,
    hash: OaepHash,
    refused: &dyn Fn(&str, cryptoki::error::Error) -> KmError,
) -> Result<(SessionObject<'a>, Vec<u8>)> {
    let session = from.raw();
    let template = from.session_template(SessionKey::ExportKek)?;
    let kek = session.generate_key(&Mechanism::AesKeyGen, &template).map_err(|e| refused("making the KEK", e))?;
    let kek = SessionObject::new(session, kek);
    let blob = session.wrap_key(&oaep(hash), tpub, kek.handle()).map_err(|e| refused("wrapping the KEK", e))?;
    Ok((kek, blob))
}

/// The keys under which an export wraps one key: the transport key on the source (its trusted copy
/// for an enforced key), the shared KEK of the sealed composed keys, and the length of the
/// transport key's modulus.
struct Wrapping {
    tpub: ObjectHandle,
    kek: Option<ObjectHandle>,
    modulus: usize,
}

/// Wraps one key and returns its blob, with its own wrapped KEK when it has one. An enforced
/// composed key is wrapped by `CKM_RSA_AES_KEY_WRAP` under the trusted transport key. That
/// mechanism wraps a fresh AES key with OAEP and then wraps the key under that AES key with RFC
/// 5649, and the output is split at the modulus length into the KEK and the key blob. A sealed
/// composed key is wrapped under the shared KEK with RFC 5649. When there is no shared KEK, a sealed
/// composed key is wrapped as an enforced key is, but under the plain transport key. A key of the
/// direct method is wrapped under the transport key itself.
fn wrap(
    from: &Token,
    w: &Wrapping,
    h: ObjectHandle,
    method: &Method,
    exposure: Exposure,
    refused: &dyn Fn(&str, cryptoki::error::Error) -> KmError,
) -> Result<Wrapped> {
    let session = from.raw();
    let shared = |blob| Wrapped { own_kek: None, blob };
    match (method, w.kek) {
        (Method::RsaOaepAesKwp(hash), kek) if exposure == Exposure::Enforced || kek.is_none() => {
            let blob = rsa_aes_wrap(from, w.tpub, h, *hash)
                .map_err(|e| refused("wrapping the key (CKM_RSA_AES_KEY_WRAP)", e))?;
            if blob.len() <= w.modulus {
                return Err(KmError::Unsupported(
                    format!("'{}': CKM_RSA_AES_KEY_WRAP returned {} bytes", from.name, blob.len()).into(),
                ));
            }
            let (kek, key) = blob.split_at(w.modulus);
            Ok(Wrapped { own_kek: Some(kek.to_vec()), blob: key.to_vec() })
        }
        (Method::RsaOaepAesKwp(_), Some(kek)) => {
            let kwp = rfc5649(from).ok_or_else(|| {
                from.unsupported_for(
                    Topic::Mechanism,
                    format!("'{}' offers no RFC 5649 key wrap this build can name", from.name),
                )
            })?;
            session.wrap_key(&kwp, kek, h).map(shared).map_err(|e| refused("wrapping the key", e))
        }
        (Method::RsaOaep(hash), _) => {
            session.wrap_key(&oaep(*hash), w.tpub, h).map(shared).map_err(|e| refused("wrapping the key", e))
        }
        (other, _) => Err(KmError::Unsupported(format!("{other} is not a sealed method").into())),
    }
}

/// Wraps `h` with `CKM_RSA_AES_KEY_WRAP` under the RSA public key `rsa`, with a fresh AES-256 key.
/// Only the patched cryptoki names this mechanism (the `kwp` feature).
#[cfg(feature = "kwp")]
fn rsa_aes_wrap(
    from: &Token,
    rsa: ObjectHandle,
    h: ObjectHandle,
    hash: OaepHash,
) -> std::result::Result<Vec<u8>, cryptoki::error::Error> {
    use cryptoki::mechanism::rsa::RsaAesKeyWrapParams;
    let params = oaep_params(hash);
    from.raw().wrap_key(&Mechanism::RsaAesKeyWrap(RsaAesKeyWrapParams::new(256.into(), &params)), rsa, h)
}

#[cfg(not(feature = "kwp"))]
fn rsa_aes_wrap(
    _: &Token,
    _: ObjectHandle,
    _: ObjectHandle,
    _: OaepHash,
) -> std::result::Result<Vec<u8>, cryptoki::error::Error> {
    Err(cryptoki::error::Error::NotSupported)
}

/// Unwraps `blob` with `CKM_RSA_AES_KEY_WRAP` and the RSA private key `rsa`. The blob holds the
/// AES-256 KEK wrapped with OAEP, followed by the key wrapped under that KEK with RFC 5649.
#[cfg(feature = "kwp")]
fn rsa_aes_unwrap(
    to: &Token,
    rsa: ObjectHandle,
    blob: &[u8],
    hash: OaepHash,
    template: &[Attribute],
) -> std::result::Result<ObjectHandle, cryptoki::error::Error> {
    use cryptoki::mechanism::rsa::RsaAesKeyWrapParams;
    let params = oaep_params(hash);
    to.raw().unwrap_key(&Mechanism::RsaAesKeyWrap(RsaAesKeyWrapParams::new(256.into(), &params)), rsa, blob, template)
}

#[cfg(not(feature = "kwp"))]
fn rsa_aes_unwrap(
    _: &Token,
    _: ObjectHandle,
    _: &[u8],
    _: OaepHash,
    _: &[Attribute],
) -> std::result::Result<ObjectHandle, cryptoki::error::Error> {
    Err(cryptoki::error::Error::NotSupported)
}

/// Imports the key `e` of `bound` under `dst` on `to`, and records it. The key is unwrapped with
/// the transport key to which the bundle is bound on `to` (`trust::BoundBundle`: `to`'s own
/// transport key, as the lock binds it). Before the target is touched, the bundle's type, IDs and
/// commitment label must equal the lock's, because the lock is the reviewed record and the bundle
/// only carries the key. The locator must also be empty. When anything fails after an object was
/// created, the import removes exactly the objects that it created ([`roll_back`]).
///
/// # Errors
///
/// `PreconditionFailed` (14) when the lock pins no IDs for the object, or records another type.
/// `HashMismatch` (10) for bundle IDs, a commitment label or a transport key that differ from the
/// lock's, and, after the import, for material whose identity is not the locked one. `Conflict`
/// (13) for an occupied locator, or for blobs that the module finds invalid (tampered with, or
/// wrapped to another key). `Unsupported` (15) for an unwrap whose mechanism or template the
/// target refuses. `Unavailable` (16) for an unwrap that the device or the session fails; some
/// modules also report a damaged blob in this way ([`unwrap_failure`]). Every error of
/// `ops::lock_import`.
pub(crate) fn import(
    bound: &BoundBundle,
    e: &Entry,
    dst: &Target,
    to: &Token,
    lock: &mut Lock,
    notes: &mut Notes,
) -> Result<Moved> {
    let (b, tr) = (bound.bundle(), bound.transport());
    if already_there(dst, to, lock, notes)? {
        return Ok(Moved::AlreadyThere);
    }
    if e.method == Method::Public.name() {
        check_against_lock(b, e, dst, tr, lock)?;
        let bytes = e.public_value().map_err(|e| KmError::Validation(e.into()))?;
        return crate::public::create(dst, to, &bytes, &b.source.token, lock, notes);
    }
    // Check what the record after the import will need (including the templates of the proof and
    // of the commitments) before anything is created.
    ops::check_import(dst, to)?;
    let ready = preflight(bound, e, dst, to, lock, notes)?;
    let method = e.method().map_err(|e| KmError::Validation(e.into()))?;
    let mut made = Vec::new();
    let created = create(b, e, dst, to, &ready, &method, &mut made).and_then(|()| {
        let origin =
            Origin { from: b.source.token.clone(), method: e.method.clone(), exposure: e.exposure, declared: false };
        // When the unwrapped key fails its proof of possession (13), it is not the key that the
        // lock pins. The error then names the check that only the run decides (`IDENTITY`), as
        // the error of a mismatched ID (10) does.
        ops::lock_import(dst, to, lock, origin, notes)
            .map_err(|err| if err.exit_code() == 13 && err.rule().is_none() { err.with_check(IDENTITY) } else { err })
    });
    match created {
        Ok(_) => Ok(Moved::Imported),
        Err(err) => Err(roll_back(dst, to, &made, err, notes)),
    }
}

/// Makes every check that [`import`] makes before it touches the target; `import --dry-run` stops
/// here. It checks the bundle against the lock, checks the transport key realised on the target
/// against the lock, and checks that the locator is empty, as a logged-in session sees it. It
/// returns the handle of the transport key for the unwrap, and the handle of a public key object
/// that already holds the key's public key.
///
/// # Errors
///
/// The same errors as [`import`] for everything before an object is created.
pub(crate) fn preflight(
    bound: &BoundBundle,
    e: &Entry,
    dst: &Target,
    to: &Token,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<Preflight> {
    let (b, tr) = (bound.bundle(), bound.transport());
    check_against_lock(b, e, dst, tr, lock)?;
    if e.method == Method::Public.name() {
        crate::public::preflight(dst, to, &e.public_value().map_err(|e| KmError::Validation(e.into()))?)?;
        return Ok(Preflight { unwrapping: None, public_half: None });
    }
    let tr = tr.ok_or_else(|| no_transport(dst))?;
    ops::verify(tr, to, lock, notes)?;
    let unwrapping = to
        .find_key(&tr.object, &tr.on_token.locator, false)?
        .ok_or_else(|| KmError::NotFound(format!("{tr}: the transport key").into()))?;
    // The locator is checked per class (`Token::occupied`). A certificate under the same locator
    // is not a collision, and a public key object that already holds the bundle's public key is
    // the key's public half, which the import reuses.
    let spki = e.public_spki().map_err(|e| KmError::Validation(e.into()))?;
    let occupied = free_locator(dst, to, spki.as_deref())?;
    Ok(Preflight { unwrapping: Some(unwrapping), public_half: occupied.public_half })
}

/// Checks a key from a bundle file (`import --in`) against the binding that `dst` records. An EC
/// or Edwards private key under `token-asserted` is refused (14) before the target is touched.
///
/// The transport key is public, so anyone can seal a key of their own to it and put it in a bundle
/// next to the lock's IDs and `publicKey`. RFC 5649 authenticates the bytes, but not who wrapped
/// them. A target that keeps no EC point with an unwrapped EC key (`SoftHSM`) takes the key's
/// identity from the public half that the import creates from that same `publicKey`. Therefore,
/// only a `pop-*` proof ties the unwrapped key to that public key. An RSA private key carries its
/// modulus, so its identity comes from the key itself. `migrate` makes its bundle in memory from
/// the locked source, so `migrate` does not call this check.
///
/// # Errors
///
/// `PreconditionFailed` (14) for an EC or Edwards private key whose binding is `token-asserted`.
pub(crate) fn check_carried(e: &Entry, dst: &Target) -> Result<()> {
    let own_identity = !matches!(dst.object.key_type, Some(KeyType::Ec | KeyType::EcEdwards));
    if own_identity || ops::binding(dst) != Some(Binding::TokenAsserted) {
        return Ok(());
    }
    Err(KmError::PreconditionFailed(Reason::check(
        Check::ImportBinding,
        format!(
            "{dst}: binding = \"token-asserted\" proves nothing of the {} key '{}' a bundle file carries: its \
             identity would rest on the public key the bundle itself names; bind it with pop-sign or pop-ecdh \
             there, or move it with `camigrate migrate`",
            dst.object.key_type.map_or_else(String::new, |k| k.to_string()),
            e.object
        ),
    )))
}

/// What [`preflight`] found: the transport key for the unwrap (`None` for a public object), and a
/// public key object that already holds the key's public key, which the import reuses instead of
/// creating one.
pub(crate) struct Preflight {
    pub unwrapping: Option<ObjectHandle>,
    pub public_half: Option<ObjectHandle>,
}

/// Returns the error (14) for a wrapped key in a bundle whose transport key is not realised on the
/// target.
fn no_transport(dst: &Target) -> KmError {
    KmError::PreconditionFailed(Reason::check(
        Check::LockRealised,
        format!(
            "{dst}: the bundle's transport key is not realised on '{}' under a spec keys.toml names",
            dst.token_name
        ),
    ))
}

/// Checks the bundle's key `e` against the lock. The entry must have the lock's type, IDs and
/// commitment label, and a wrapped key must be wrapped to the transport key that `tr` realises.
/// `dst` realises `e`'s object, because the import selects `dst` by the object's name.
fn check_against_lock(b: &Bundle, e: &Entry, dst: &Target, tr: Option<&Target>, lock: &Lock) -> Result<()> {
    let locked = lock.objects.get(dst.object_name).filter(|o| !o.ids.is_empty()).ok_or_else(|| {
        KmError::PreconditionFailed(Reason::check(
            Check::ImportLocked,
            format!(
                "{dst}: the lock pins no IDs for object '{}', so nothing could check the imported material; \
             lock it on its source first",
                dst.object_name
            ),
        ))
    })?;
    if locked.object_type.as_ref() != Some(&e.object_type) || dst.object.cfg() != &e.object_type {
        return Err(KmError::PreconditionFailed(Reason::check(
            Check::ImportLocked,
            format!("{dst}: the bundle carries a {}, the lock and keys.toml another type", e.object_type),
        )));
    }
    let mismatch = |what: &str, expected: String, got: String| KmError::HashMismatch {
        what: format!("{dst}: the bundle's {what}"),
        expected,
        got,
        check: Check::IdentityMaterial,
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
    // A public object is not wrapped, so there is no transport key to check.
    if e.wrapped.is_none() {
        return Ok(());
    }
    let (Some(tr), Some(named)) = (tr, &b.transport) else { return Err(no_transport(dst)) };
    let tr_id = lock.objects.get(tr.object_name).and_then(|o| o.ids.get(cakeys_core::id::Scheme::Rfc7093m4.name()));
    if named.object != tr.object_name || tr_id != Some(&named.rfc7093m4) {
        return Err(mismatch(
            "transport key",
            format!("{} {}", tr.object_name, tr_id.map_or("<none>", String::as_str)),
            format!("{} {}", named.object, named.rfc7093m4),
        ));
    }
    Ok(())
}

/// Creates the key under `dst` from the bundle's key `e`. For a private key, it first creates the
/// public half from the entry's public key, as `generate` creates it. It then unwraps the key with
/// the target spec's attributes as the template, without the attributes that this module refuses
/// in an unwrap template (docs/CAMIGRATE.md D6).
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
        .ok_or_else(|| KmError::Validation(format!("{dst}: a public object is created, not unwrapped").into()))?;
    let session = to.raw();
    let refused = |what: &str, e: cryptoki::error::Error| {
        unwrap_error(&format!("{dst}: {what} on '{}'", to.name), &e, |m| to.unsupported_for(Topic::Mechanism, m))
    };
    // Build the templates, as the provider adjusts them, before anything is created.
    let template = templates::import_key(
        dst.into(),
        to.policy_template(&unwrap_declared(&dst.spec.attributes, &unwrap_refusals(to)))?,
    )?;
    let template = to.provider.adjusted(&Template::Import(dst.into(), Via::Unwrap), template)?;
    // A KEK template is needed only when the KEK is unwrapped on its own, which happens for the
    // composed method on a target with RFC 5649.
    let kek_template = match method {
        Method::RsaOaepAesKwp(_) if rfc5649(to).is_some() => to.session_template(SessionKey::ImportKek)?,
        _ => Vec::new(),
    };
    if let Some(spki) =
        e.public_spki().map_err(|e| KmError::Validation(e.into()))?.filter(|_| ready.public_half.is_none())
    {
        made.push(create_public_half(dst, to, &spki)?);
    }
    let key = e.wrapped_key().map_err(|e| KmError::Validation(e.into()))?;
    match method {
        Method::RsaOaepAesKwp(hash) => {
            // A key that was wrapped by `CKM_RSA_AES_KEY_WRAP` (for example, an enforced key)
            // carries its own KEK, the first part of that mechanism's output. The other keys share
            // the bundle's KEK.
            let kek_blob = match e.wrapped_kek().map_err(|e| KmError::Validation(e.into()))? {
                Some(own) => own,
                None => b.wrapped_kek().map_err(|e| KmError::Validation(e.into()))?.unwrap_or_default(),
            };
            // A target with no RFC 5649 key wrap of its own (AWS CloudHSM lists one but refuses
            // it [run]) unwraps both parts with one `CKM_RSA_AES_KEY_WRAP`. The input of that
            // mechanism is the same two blobs, joined.
            let Some(kwp) = rfc5649(to) else {
                if !rsa_aes_key_wrap(to) {
                    return Err(to.unsupported_for(
                        Topic::Mechanism,
                        format!(
                            "'{}' offers no RFC 5649 key wrap, nor CKM_RSA_AES_KEY_WRAP, this build can name",
                            to.name
                        ),
                    ));
                }
                let joined = [kek_blob, key].concat();
                made.push(
                    rsa_aes_unwrap(to, unwrapping, &joined, *hash, &template)
                        .map_err(|e| refused("unwrapping the key (CKM_RSA_AES_KEY_WRAP)", e))?,
                );
                return Ok(());
            };
            let kek = session
                .unwrap_key(&oaep(*hash), unwrapping, &kek_blob, &kek_template)
                .map_err(|e| refused("unwrapping the KEK", e))?;
            let kek = SessionObject::new(session, kek);
            made.push(
                session
                    .unwrap_key(&kwp, kek.handle(), &key, &template)
                    .map_err(|e| refused("unwrapping the key", e))?,
            );
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
        other => Err(KmError::Unsupported(format!("{other} is not a sealed method").into())),
    }
}

/// The first check that a sealed import's dry run cannot decide and that only the real run
/// decides: whether the blob unwraps. It fails with 13, or with 16 when the module says only that
/// the unwrap failed, as with a device failure.
pub(crate) const UNWRAPS: Check = Check::ImportUnwraps;

/// The second check that only the real run decides: whether the unwrapped key is the key that the
/// lock pins. A mismatch (10) names `identity.material`, and [`crate::Tally`] renames it to this
/// check. [`import`] renames the 13 of a failed proof of possession to this check in the same way.
pub(crate) const IDENTITY: Check = Check::ImportIdentity;

/// The kind of failure of a `C_UnwrapKey`, by the module's return value. Only a blob that the
/// module finds invalid means that the bundle was tampered with or wrapped to another key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnwrapFailure {
    /// The wrapped or encrypted data is invalid or of the wrong length (13).
    Tampered,
    /// The target refuses the mechanism, its parameters, the unwrapping key or the template (15).
    Refused,
    /// The module failed and gives no detail (`CKR_DEVICE_ERROR`, `CKR_GENERAL_ERROR` or
    /// `CKR_FUNCTION_FAILED`). This is exit 16, and the message says that the blob may be damaged,
    /// because some modules report a damaged blob in this way (kryoptic does so for a tampered RFC
    /// 5649 blob \[run\]).
    Opaque,
    /// Any other failure, such as a failure of the session or of the login (16).
    Failed,
}

fn unwrap_failure(e: &cryptoki::error::Error) -> UnwrapFailure {
    use cryptoki::error::{Error as CkError, RvError};
    match e {
        CkError::Pkcs11(
            RvError::EncryptedDataInvalid
            | RvError::EncryptedDataLenRange
            | RvError::WrappedKeyInvalid
            | RvError::WrappedKeyLenRange,
            _,
        ) => UnwrapFailure::Tampered,
        CkError::Pkcs11(
            RvError::MechanismInvalid
            | RvError::MechanismParamInvalid
            | RvError::FunctionNotSupported
            | RvError::KeyFunctionNotPermitted
            | RvError::KeyTypeInconsistent
            | RvError::KeySizeRange
            | RvError::CurveNotSupported
            | RvError::DomainParamsInvalid
            | RvError::UnwrappingKeyHandleInvalid
            | RvError::UnwrappingKeySizeRange
            | RvError::UnwrappingKeyTypeInconsistent
            | RvError::TemplateIncomplete
            | RvError::TemplateInconsistent
            | RvError::AttributeReadOnly
            | RvError::AttributeTypeInvalid
            | RvError::AttributeValueInvalid,
            _,
        )
        // A mechanism that this build cannot name (`CKM_RSA_AES_KEY_WRAP` without the `kwp`
        // feature) counts as the target's refusal.
        | CkError::NotSupported => UnwrapFailure::Refused,
        CkError::Pkcs11(RvError::DeviceError | RvError::GeneralError | RvError::FunctionFailed, _) => {
            UnwrapFailure::Opaque
        }
        _ => UnwrapFailure::Failed,
    }
}

/// Returns the error of the unwrap `what` that failed with `e`, classified by
/// [`unwrap_failure`], with the return value attached. `unsupported` builds the target's refusal
/// (`Token::unsupported`, with its hint).
fn unwrap_error(what: &str, e: &cryptoki::error::Error, unsupported: impl FnOnce(String) -> KmError) -> KmError {
    let rv = cakeys_pkcs11::token::rv_of(e);
    match unwrap_failure(e) {
        UnwrapFailure::Tampered => KmError::Conflict(Reason::check(
            UNWRAPS,
            format!("{what}: {e} (the bundle was tampered with, or wrapped to another key)"),
        )),
        UnwrapFailure::Refused => unsupported(format!("{what}: {e}")),
        UnwrapFailure::Opaque => KmError::Unavailable(
            format!(
                "{what}: {e} (the module says no more: some report a damaged or altered bundle this way, \
                 so check that it is the one exported)"
            )
            .into(),
        )
        .with_check(UNWRAPS),
        UnwrapFailure::Failed => KmError::Unavailable(format!("{what}: {e}").into()),
    }
    .with_rv(rv)
}

/// Creates a private key's public half under `dst`'s locator from its canonical SPKI, as
/// `generate` creates it: with the spec's public attributes, and with `CKA_VERIFY` and public
/// unless the spec declares otherwise.
///
/// # Errors
///
/// `Unsupported` (15) when the module does not create it.
pub(crate) fn create_public_half(dst: &Target, to: &Token, spki: &[u8]) -> Result<ObjectHandle> {
    let public_policy = to.policy_template(&dst.spec.public_attributes)?;
    let t = templates::public_half(dst.into(), public_policy, Some(public_key(dst, spki)?))?;
    let t = to.provider.adjusted(&Template::PublicHalf(dst.into()), t)?;
    // As in `generate`, a module that refuses cakeys' own default `CKA_PRIVATE = false` gets the
    // public half without that attribute.
    let declared = templates::public_declares(dst.spec, "CKA_PRIVATE");
    let create = || {
        with_public_default_dropped(&t, declared, |p| to.raw().create_object(p))
            .map(|(made, _)| made)
            .map_err(|e| to.refused_for(Topic::Create, &e, format!("{dst}: the public half: C_CreateObject: {e}")))
    };
    to.managing("creating the public half", create)
}

/// Returns RSA-OAEP with MGF1 of the same hash and an empty label, which is the mechanism that the
/// planner names.
fn oaep(hash: OaepHash) -> Mechanism<'static> {
    Mechanism::RsaPkcsOaep(oaep_params(hash))
}

fn oaep_params(hash: OaepHash) -> PkcsOaepParams<'static> {
    cakeys_pkcs11::token::oaep_of(hash).0
}

/// Returns the spec's declared `attributes` without those that the target's profile refuses in an
/// unwrap template (`unwrap.refuse`, [`unwrap_refusals`]). The result is what an unwrapped key's
/// template declares.
pub(crate) fn unwrap_declared(
    attributes: &BTreeMap<String, AttrValue>,
    refusals: &[String],
) -> BTreeMap<String, AttrValue> {
    attributes.iter().filter(|(n, _)| !refusals.contains(n)).map(|(n, v)| (n.clone(), v.clone())).collect()
}

/// Returns whether a side has an RFC 5649 key wrap. It is the counterpart of [`rfc5649`] for a
/// plan, which knows a side only by its capabilities.
pub(crate) fn side_rfc5649(side: &Side) -> bool {
    let has = |m: MechanismType| side.mechanisms.contains(&m.to_string());
    #[cfg(feature = "kwp")]
    if has(MechanismType::AES_KEY_WRAP_KWP) {
        return true;
    }
    has(MechanismType::AES_KEY_WRAP_PAD)
}

/// Returns the RFC 5649 key wrap that a token offers, under the name that the token uses. Phase 0
/// in docs/CAMIGRATE.md found one format under two mechanism IDs: `CKM_AES_KEY_WRAP_PAD`, and
/// `CKM_AES_KEY_WRAP_KWP`, which this build can name only with the `kwp` feature and the Nix
/// build's patched cryptoki.
pub(crate) fn rfc5649(tok: &Token) -> Option<Mechanism<'static>> {
    if tok.has(MechanismType::AES_KEY_WRAP_PAD) {
        return Some(Mechanism::AesKeyWrapPad);
    }
    #[cfg(feature = "kwp")]
    if tok.has(MechanismType::AES_KEY_WRAP_KWP) {
        return Some(Mechanism::AesKeyWrapKwp);
    }
    None
}

/// Returns whether a token offers `CKM_RSA_AES_KEY_WRAP` and this build can name it (the `kwp`
/// feature). It asks the token as [`rfc5649`] does.
fn rsa_aes_key_wrap(tok: &Token) -> bool {
    #[cfg(feature = "kwp")]
    return tok.has(MechanismType::RSA_AES_KEY_WRAP);
    #[cfg(not(feature = "kwp"))]
    {
        let _ = tok;
        false
    }
}

/// The smallest size of an RSA transport key, in bits. A key that the transport key protects is
/// only as safe as the transport key, and the planner's limit for direct OAEP
/// (`plan::OAEP_DIRECT_MAX`) assumes at least this size.
pub(crate) const TRANSPORT_MIN_BITS: u64 = 2048;

/// Refuses a transport key smaller than [`TRANSPORT_MIN_BITS`].
///
/// # Errors
///
/// `Validation` (17) for an SPKI that is not an RSA key, or that is too small.
pub(crate) fn check_transport_size(spki: &[u8]) -> Result<()> {
    let bits = cakeys_core::id::modulus_bits(&rsa_parts(spki)?.0);
    if bits < TRANSPORT_MIN_BITS {
        return Err(KmError::Validation(
            format!("a transport key is an RSA key of at least {TRANSPORT_MIN_BITS} bits; this one has {bits}").into(),
        ));
    }
    Ok(())
}

/// Returns an RSA public key's modulus and public exponent, from its SPKI.
///
/// # Errors
///
/// `Validation` (17) for an SPKI that is not an RSA key.
pub(crate) fn rsa_parts(spki: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Validation(format!("the transport key is no RSA public key: {e}").into()))?;
    Ok((key.n().to_be_bytes_trimmed_vartime().to_vec(), key.e().to_be_bytes_trimmed_vartime().to_vec()))
}

/// Returns the transport public key's material, for the session object to which the source wraps
/// (the `TransportKey` template of `templates::session`).
fn rsa_public(spki: &[u8]) -> Result<Vec<Attribute>> {
    let (n, e) = rsa_parts(spki)?;
    Ok(vec![Attribute::Modulus(n), Attribute::PublicExponent(e)])
}

/// Returns whether an export wraps a key of `method` and `exposure` under the KEK that it shares
/// with the other composed keys. This is true for a composed key that is not `enforced` (an
/// enforced key carries its own KEK), from a source with RFC 5649 and AES key generation.
/// Otherwise, each key is wrapped by `CKM_RSA_AES_KEY_WRAP`, as on AWS `CloudHSM` \[run\]. The
/// export and the plan both decide this with this function.
pub(crate) fn shares_kek(method: &Method, exposure: Exposure, rfc5649: bool, aes_key_gen: bool) -> bool {
    matches!(method, Method::RsaOaepAesKwp(_)) && exposure != Exposure::Enforced && rfc5649 && aes_key_gen
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;
    use cryptoki::error::{Error as CkError, RvError};

    /// Checks that a transport key's size is the bit length of its modulus (`id::modulus_bits`),
    /// not its byte length times eight. A key of 2041 to 2047 bits is under the 2048-bit minimum
    /// (review 2026-11-23 C-20).
    #[test]
    fn a_transport_key_counts_its_bits() {
        let spki = |top: u8| cakeys_core::id::rsa_spki(&[&[top][..], &[0xff; 255]].concat(), &[1, 0, 1]).unwrap();
        check_transport_size(&spki(0x80)).unwrap();
        for top in [0x7f, 0x01] {
            let e = check_transport_size(&spki(top)).unwrap_err();
            assert!(e.exit_code() == 17 && e.to_string().contains("this one has 204"), "{top:#x}: {e}");
        }
    }

    /// Checks that a failed unwrap is 13 ("tampered with") only when the module says that the blob
    /// is bad. A refused mechanism, parameter, unwrapping key or template is the target's refusal
    /// (15), and a failure of the device, the session or the login is 16. When a module fails and
    /// gives no detail, the error is 16, and its message says that the bundle may be damaged
    /// (kryoptic returns `CKR_DEVICE_ERROR` for a tampered blob \[run\]). A PIN or session error
    /// never gets that message. Each error keeps the return value that it came with.
    #[test]
    fn an_unwrap_failure_is_tampering_only_when_the_data_is_bad() {
        let unsupported = |m: String| KmError::Unsupported(m.into());
        let table = [
            (RvError::EncryptedDataInvalid, 13),
            (RvError::EncryptedDataLenRange, 13),
            (RvError::WrappedKeyInvalid, 13),
            (RvError::WrappedKeyLenRange, 13),
            (RvError::MechanismInvalid, 15),
            (RvError::MechanismParamInvalid, 15),
            (RvError::FunctionNotSupported, 15),
            (RvError::KeyFunctionNotPermitted, 15),
            (RvError::UnwrappingKeyTypeInconsistent, 15),
            (RvError::UnwrappingKeySizeRange, 15),
            (RvError::TemplateInconsistent, 15),
            (RvError::TemplateIncomplete, 15),
            (RvError::AttributeValueInvalid, 15),
            (RvError::AttributeTypeInvalid, 15),
            (RvError::CurveNotSupported, 15),
            (RvError::DeviceError, 16),
            (RvError::DeviceRemoved, 16),
            (RvError::GeneralError, 16),
            (RvError::FunctionFailed, 16),
            (RvError::SessionHandleInvalid, 16),
            (RvError::UserNotLoggedIn, 16),
            (RvError::PinIncorrect, 16),
        ];
        let opaque = [RvError::DeviceError, RvError::GeneralError, RvError::FunctionFailed];
        for (rv, code) in table {
            let e = unwrap_error("unwrapping the key", &CkError::Pkcs11(rv, Function::UnwrapKey), unsupported);
            assert_eq!(e.exit_code(), code, "{rv:?}: {e}");
            assert_eq!(e.to_string().contains("tampered"), code == 13, "{rv:?}: {e}");
            assert_eq!(e.to_string().contains("damaged or altered bundle"), opaque.contains(&rv), "{rv:?}: {e}");
            assert_eq!(e.rv(), cakeys_pkcs11::token::rv_value(rv), "{rv:?}");
        }
        // A mechanism that this build cannot name is the target's refusal (15), not a tampered
        // bundle.
        assert_eq!(unwrap_error("x", &CkError::NotSupported, unsupported).exit_code(), 15);
    }
}
