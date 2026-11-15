//! Moving a key sealed (docs/CAMIGRATE.md D2–D7, phase 3): the material leaves the source only wrapped
//! to a transport key that lives on the target — an RSA key the lock pins (D3) — and is unwrapped
//! there. The host never sees it. [`export`] wraps one object into a [`Bundle`]; [`import`]
//! checks the bundle against the lock before it touches the target, creates the key (and a
//! private key's public half) under the target spec, and records it through
//! `ops::realise_import`, the lock rules `cakeys realise` uses. `migrate` is the two in one
//! process, with the bundle in memory. A bundle carries every key of one export (one file per
//! source and target); each is imported, checked and rolled back on its own.

use crate::bundle::{BUNDLE_FORMAT, BUNDLE_VERSION, Bundle, Entry, Source, TransportRef, encode};
use crate::host::free_locator;
use crate::public::{Moved, already_there, public_key, roll_back};
use crate::tokens::unwrap_refusals;
use cakeys_core::config::{Lock, Origin};
use cakeys_core::migrate::{Exposure, Method};
use cakeys_core::pop::OaepHash;
use cakeys_core::types::ObjectClass as Class;
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::Token;
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::token::{class_of, key_type_of, locator_attrs, retry_without_public_private};
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
/// cannot be wrapped fails the export, and no bundle is made. Public objects need no transport
/// key: a bundle of them alone names none, and nothing is created on the source. Each source realisation is verified
/// against the lock first; the transport public key and the composed methods' shared KEK are
/// session objects on the source, destroyed again whatever happens.
///
/// # Errors
///
/// Whatever `ops::verify` refuses; `NotFound` for a key not under its locator; `Unsupported`
/// (15) for a method this build or the source cannot perform, or a `C_WrapKey` the source
/// refuses; `PreconditionFailed` for a key to wrap and no transport key.
pub fn export(
    items: &[Item],
    from: &Token,
    lock: &Lock,
    transport: Option<&TransportKey>,
    notes: &mut Notes,
) -> Result<Bundle> {
    let found = hold(items, from, lock, notes)?;
    let source = Source { token: from.name.clone(), provider: from.provider.name().into() };
    let wraps = found.iter().any(|(.., held)| matches!(held, Held::Key(..)));
    let Some(transport) = transport.filter(|_| wraps) else {
        if wraps {
            return Err(KmError::PreconditionFailed(format!(
                "exporting keys from '{}' needs the target's transport key to wrap them to",
                from.name
            )));
        }
        // Public objects only: nothing to wrap, so no transport key and nothing made on the source.
        let keys = found.iter().map(|(item, locked, object_type, held)| entry(item, locked, object_type, held, None));
        return Ok(Bundle {
            format: BUNDLE_FORMAT.into(),
            version: BUNDLE_VERSION,
            kek: None,
            source,
            transport: None,
            keys: keys.collect(),
        });
    };
    // An enforced key wraps only under the transport key's trusted copy (`transport --trusted`),
    // the composed method by CKM_RSA_AES_KEY_WRAP: the source trusts no key-encryption key.
    let trusted = if items.iter().any(|i| i.exposure == Exposure::Enforced) {
        let (copy, others) = from.trusted(&transport.spki)?;
        if others > 0 {
            notes.warn(format_args!(
                "{others} other object(s) on '{}' are CKA_TRUSTED: a CKA_WRAP_WITH_TRUSTED key there wraps under any \
                 of them, so `enforced` is only as narrow as that set",
                from.name
            ));
        }
        Some(copy.ok_or_else(|| {
            KmError::PreconditionFailed(format!(
                "'{}' holds no trusted copy of transport key '{}': `camigrate transport <spec> --token <target> \
                 --trusted {}`",
                from.name, transport.object, from.name
            ))
        })?)
    } else {
        None
    };
    let modulus = rsa_parts(&transport.spki)?.0.len();
    let session = from.raw();
    let refused = |what: &str, e: cryptoki::error::Error| from.unsupported(format!("{what} on '{}': {e}", from.name));
    let tpub = session.create_object(&rsa_public(transport)?).map_err(|e| refused("loading the transport key", e))?;
    let kek_hash = items.iter().find_map(|i| match i.method {
        Method::RsaOaepAesKwp(h) if i.exposure != Exposure::Enforced => Some(h),
        _ => None,
    });
    let wrapped = kek_hash.map(|h| kek(from, tpub, h, &refused)).transpose().and_then(|kek| {
        let keys = found
            .iter()
            .map(|(item, locked, object_type, held)| {
                let refused = |what: &str, e| refused(&format!("{}: {what}", item.src), e);
                let wrapped = match held {
                    Held::Key(h, _) => {
                        let wrapping = Wrapping {
                            tpub: if item.exposure == Exposure::Enforced { trusted.unwrap_or(tpub) } else { tpub },
                            kek: kek.as_ref().map(|k| k.0),
                            modulus,
                        };
                        Some(wrap(from, &wrapping, *h, &item.method, item.exposure, &refused)?)
                    }
                    Held::Public(_) => None,
                };
                Ok(entry(item, locked, object_type, held, wrapped))
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
        source,
        transport: Some(TransportRef { object: transport.object.clone(), rfc7093m4: transport.rfc7093m4.clone() }),
        keys,
    })
}

/// One object's bundle entry: a public object's bytes, or a key's `wrapped` blob with its own
/// wrapped KEK when it has one ([`wrap`]'s result).
fn entry(
    item: &Item,
    locked: &cakeys_core::config::LockObject,
    object_type: &cakeys_core::config::ObjectCfg,
    held: &Held,
    wrapped: Option<(Option<Vec<u8>>, Vec<u8>)>,
) -> Entry {
    let (public_key, value) = match held {
        Held::Key(_, public_key) => (public_key.as_deref().map(encode), None),
        Held::Public(bytes) => (None, Some(encode(bytes))),
    };
    let (kek, wrapped) = match wrapped {
        Some((own_kek, blob)) => (own_kek.as_deref().map(encode), Some(encode(&blob))),
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

/// Each item as the source holds it, verified against the lock first: the object as the lock
/// pins it, its type, and its handle or bytes.
fn hold<'a>(
    items: &'a [Item<'a>],
    from: &Token,
    lock: &'a Lock,
    notes: &mut Notes,
) -> Result<Vec<(&'a Item<'a>, &'a cakeys_core::config::LockObject, cakeys_core::config::ObjectCfg, Held)>> {
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
    Ok(found)
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
        // It leaves only wrapped to the transport key: never readable, whatever the module's default.
        Attribute::Sensitive(true),
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

/// The keys one export wraps under: the transport key on the source (its trusted copy for an
/// enforced key), the shared KEK of the sealed composed keys, and the transport modulus length.
struct Wrapping {
    tpub: ObjectHandle,
    kek: Option<ObjectHandle>,
    modulus: usize,
}

/// One key's blob, and its own wrapped KEK when it has one: an enforced composed key by
/// `CKM_RSA_AES_KEY_WRAP` under the trusted transport key (OAEP of a fresh AES key, then RFC 5649
/// under it; split at the modulus length), a sealed one under the shared KEK (RFC 5649), and the
/// direct method under the transport key itself.
fn wrap(
    from: &Token,
    w: &Wrapping,
    h: ObjectHandle,
    method: &Method,
    exposure: Exposure,
    refused: &dyn Fn(&str, cryptoki::error::Error) -> KmError,
) -> Result<(Option<Vec<u8>>, Vec<u8>)> {
    let session = from.raw();
    match (method, w.kek) {
        (Method::RsaOaepAesKwp(hash), _) if exposure == Exposure::Enforced => {
            let blob = rsa_aes_wrap(from, w.tpub, h, *hash)
                .map_err(|e| refused("wrapping the key (CKM_RSA_AES_KEY_WRAP)", e))?;
            if blob.len() <= w.modulus {
                return Err(KmError::Unsupported(format!(
                    "'{}': CKM_RSA_AES_KEY_WRAP returned {} bytes",
                    from.name,
                    blob.len()
                )));
            }
            let (kek, key) = blob.split_at(w.modulus);
            Ok((Some(kek.to_vec()), key.to_vec()))
        }
        (Method::RsaOaepAesKwp(_), Some(kek)) => {
            let kwp = rfc5649(from).ok_or_else(|| {
                from.unsupported(format!("'{}' offers no RFC 5649 key wrap this build can name", from.name))
            })?;
            Ok((None, session.wrap_key(&kwp, kek, h).map_err(|e| refused("wrapping the key", e))?))
        }
        (Method::RsaOaep(hash), _) => {
            Ok((None, session.wrap_key(&oaep(*hash), w.tpub, h).map_err(|e| refused("wrapping the key", e))?))
        }
        (other, _) => Err(KmError::Unsupported(format!("{other} is not a sealed method"))),
    }
}

/// `CKM_RSA_AES_KEY_WRAP` of `h` under the RSA public key `rsa`, with a fresh AES-256 key: a
/// mechanism only the patched cryptoki names (the `kwp` feature).
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

/// Import `b`'s key `e` under `dst` on `to`, unwrapping with the transport key `tr` realised
/// there, and record it. Before the target is touched: the bundle's type, IDs and commitment
/// label must be the lock's (the lock is the reviewed truth, the bundle only a carrier), and its
/// transport key the one `tr` is; the locator must be empty. Whatever fails after something was
/// created removes everything under the locator again.
///
/// # Errors
///
/// `PreconditionFailed` (14) when the lock pins no IDs for its object, or another type;
/// `HashMismatch` (10) for bundle IDs, label or transport key that are not the lock's, and —
/// after the import — material whose identity is not the locked one; `Conflict` (13) for an
/// occupied locator or blobs that do not unwrap (tampered, or wrapped to another key);
/// whatever `ops::realise_import` refuses.
pub fn import(
    b: &Bundle,
    e: &Entry,
    dst: &Target,
    to: &Token,
    tr: Option<&Target>,
    lock: &mut Lock,
    notes: &mut Notes,
) -> Result<Moved> {
    if already_there(dst, to, lock, notes)? {
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
        Err(err) => Err(roll_back(dst, to, &made, err, notes)),
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
    tr: Option<&Target>,
    lock: &Lock,
    notes: &mut Notes,
) -> Result<Preflight> {
    check_against_lock(b, e, dst, tr, lock)?;
    if e.method == Method::Public.name() {
        crate::public::preflight(dst, to, &e.public_value().map_err(KmError::Validation)?)?;
        return Ok(Preflight { unwrapping: None, public_half: None });
    }
    let tr = tr.ok_or_else(|| no_transport(dst))?;
    ops::verify(tr, to, lock, notes)?;
    let unwrapping = to
        .find_key(tr.object, &tr.on_token.locator, false)?
        .ok_or_else(|| KmError::NotFound(format!("{tr}: the transport key")))?;
    // Per class (`Token::occupied`): a certificate beside the key is no collision, and a public
    // key object already holding the bundle's public key is the key's public half, reused.
    let spki = e.public_spki().map_err(KmError::Validation)?;
    let occupied = free_locator(dst, to, spki.as_deref())?;
    Ok(Preflight { unwrapping: Some(unwrapping), public_half: occupied.public_half })
}

/// What [`preflight`] established: the transport key to unwrap with (none for a public object),
/// and a public key object already holding the key's public key, reused rather than created.
pub struct Preflight {
    pub unwrapping: Option<ObjectHandle>,
    pub public_half: Option<ObjectHandle>,
}

/// A wrapped key in a bundle whose transport key is not realised on the target.
fn no_transport(dst: &Target) -> KmError {
    KmError::PreconditionFailed(format!(
        "{dst}: the bundle's transport key is not realised on '{}' under a spec keys.toml names",
        dst.token_name
    ))
}

/// The bundle's key `e` against the lock: the same type, IDs and commitment label, and — for a
/// wrapped key — wrapped to the transport key `tr` realises. `dst` realises `e`'s object (the
/// import picks it by that name).
fn check_against_lock(b: &Bundle, e: &Entry, dst: &Target, tr: Option<&Target>, lock: &Lock) -> Result<()> {
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
    // A public object is wrapped to nothing.
    if e.wrapped.is_none() {
        return Ok(());
    }
    let (Some(tr), Some(named)) = (tr, &b.transport) else { return Err(no_transport(dst)) };
    let tr_id = lock.objects.get(tr.object_name).and_then(|o| o.ids.get("rfc7093m4"));
    if named.object != tr.object_name || tr_id != Some(&named.rfc7093m4) {
        return Err(mismatch(
            "transport key",
            format!("{} {}", tr.object_name, tr_id.map_or("<none>", String::as_str)),
            format!("{} {}", named.object, named.rfc7093m4),
        ));
    }
    Ok(())
}

/// Create the key under `dst` from the bundle's key `e`: a private key's public half first (from
/// its public key, as `generate` makes it), then the key unwrapped with the target spec's
/// attributes as its template, less what this module refuses in one (docs/CAMIGRATE.md D6).
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
        made.push(create_public_half(dst, to, &spki)?);
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
            // An enforced key carries its own (CKM_RSA_AES_KEY_WRAP's); the others share the bundle's.
            let kek_blob = match e.wrapped_kek().map_err(KmError::Validation)? {
                Some(own) => own,
                None => b.wrapped_kek().map_err(KmError::Validation)?.unwrap_or_default(),
            };
            let kek_template = [
                Attribute::Class(ObjectClass::SECRET_KEY),
                Attribute::KeyType(KeyType::AES),
                Attribute::Token(false),
                Attribute::Unwrap(true),
                Attribute::Sensitive(true),
                Attribute::Extractable(false),
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

/// A private key's public half under `dst`'s locator, from its canonical SPKI, as `generate`
/// makes it: the spec's public attributes, `CKA_VERIFY` and public unless declared otherwise.
///
/// # Errors
///
/// `Unsupported` when the module will not create it.
pub(crate) fn create_public_half(dst: &Target, to: &Token, spki: &[u8]) -> Result<ObjectHandle> {
    let mut t = vec![Attribute::Token(true), Attribute::Class(ObjectClass::PUBLIC_KEY)];
    t.extend(locator_attrs(&dst.on_token.locator)?);
    t.extend(public_key(dst, spki)?);
    t.extend(to.policy_template(&dst.spec.public_attributes)?);
    let declared = |n| dst.spec.attributes.contains_key(n) || dst.spec.public_attributes.contains_key(n);
    if !declared("CKA_VERIFY") {
        t.push(Attribute::Verify(true));
    }
    if !declared("CKA_PRIVATE") {
        t.push(Attribute::Private(false));
    }
    // As `generate`: a module refusing cakeys' own CKA_PRIVATE = false default (AWS CloudHSM
    // makes every public key private [run]) gets the half without it.
    let create = || {
        match to.raw().create_object(&t) {
            Err(e) if retry_without_public_private(&e, declared("CKA_PRIVATE")) => {
                let without: Vec<_> = t.iter().filter(|a| **a != Attribute::Private(false)).cloned().collect();
                to.raw().create_object(&without).map_err(|_| e)
            }
            made => made,
        }
        .map_err(|e| to.unsupported(format!("{dst}: the public half: C_CreateObject: {e}")))
    };
    if to.provider.manages_as_so() { to.as_so("creating the public half", create) } else { create() }
}

/// RSA-OAEP with MGF1 of the same hash and an empty label: what the planner names.
fn oaep(hash: OaepHash) -> Mechanism<'static> {
    Mechanism::RsaPkcsOaep(oaep_params(hash))
}

fn oaep_params(hash: OaepHash) -> PkcsOaepParams<'static> {
    let (h, mgf) = match hash {
        OaepHash::Sha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
        OaepHash::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
    };
    PkcsOaepParams::new(h, mgf, PkcsOaepSource::empty())
}

/// The RFC 5649 key wrap a token offers, under the name it uses (docs/CAMIGRATE.md spike: one format,
/// two mechanism IDs): `CKM_AES_KEY_WRAP_PAD`, or `CKM_AES_KEY_WRAP_KWP` where this build can name
/// it (the `kwp` feature, with the Nix build's patched cryptoki).
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

/// The smallest RSA transport key, in bits: what it protects is no better guarded than it, and
/// the planner's direct-OAEP limit (`plan::OAEP_DIRECT_MAX`) assumes at least this.
pub const TRANSPORT_MIN_BITS: usize = 2048;

/// Refuse a transport key smaller than [`TRANSPORT_MIN_BITS`].
///
/// # Errors
///
/// `Validation` for an SPKI that is no RSA key, or one too small.
pub fn check_transport_size(spki: &[u8]) -> Result<()> {
    let bits = rsa_parts(spki)?.0.len() * 8;
    if bits < TRANSPORT_MIN_BITS {
        return Err(KmError::Validation(format!(
            "a transport key is an RSA key of at least {TRANSPORT_MIN_BITS} bits; this one has {bits}"
        )));
    }
    Ok(())
}

/// An RSA public key's modulus and public exponent, from its SPKI.
///
/// # Errors
///
/// `Validation` for an SPKI that is no RSA key.
pub fn rsa_parts(spki: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Validation(format!("the transport key is no RSA public key: {e}")))?;
    Ok((key.n().to_be_bytes_trimmed_vartime().to_vec(), key.e().to_be_bytes_trimmed_vartime().to_vec()))
}

/// The transport public key as a session object the source can wrap to.
fn rsa_public(transport: &TransportKey) -> Result<Vec<Attribute>> {
    let (n, e) = rsa_parts(&transport.spki)?;
    Ok(vec![
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::KeyType(KeyType::RSA),
        Attribute::Token(false),
        Attribute::Modulus(n),
        Attribute::PublicExponent(e),
        Attribute::Wrap(true),
        Attribute::Encrypt(true),
    ])
}
