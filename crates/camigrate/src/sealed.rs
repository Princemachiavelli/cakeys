//! Moving a key sealed (docs/CAMIGRATE.md D2–D7, phase 3): the material leaves the source only wrapped
//! to a transport key that lives on the target — an RSA key the lock pins (D3) — and is unwrapped
//! there. The host never sees it. [`export`] wraps one object into a [`Bundle`]; [`import`]
//! checks the bundle against the lock before it touches the target, creates the key (and a
//! private key's public half) under the target spec, and records it through
//! `ops::lock_import`, the lock rules `cakeys lock` uses. `migrate` is the two in one
//! process, with the bundle in memory. A bundle carries every key of one export (one file per
//! source and target); each is imported, checked and rolled back on its own.

use crate::bundle::{BUNDLE_FORMAT, BUNDLE_VERSION, Bundle, Entry, Source, TransportRef, encode};
use crate::public::free_locator;
use crate::public::{Moved, already_there, public_key, roll_back};
use crate::side::Side;
use crate::tokens::unwrap_refusals;
use crate::trust::{BoundBundle, BoundTransport};
use cakeys_core::config::{AttrValue, Binding, Lock, Origin};
use cakeys_core::migrate::{Exposure, Method, OaepHash};
use cakeys_core::types::{KeyType, ObjectClass as Class};
use cakeys_core::{KmError, Result};
use cakeys_pkcs11::ops::{self, Notes, Target};
use cakeys_pkcs11::token::{SessionObject, with_public_default_dropped};
use cakeys_pkcs11::{SessionKey, Template, Token, Topic, Via, templates};
use cryptoki::mechanism::rsa::PkcsOaepParams;
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, ObjectHandle};
use rsa::pkcs8::DecodePublicKey as _;
use rsa::traits::PublicKeyParts as _;
use std::collections::BTreeMap;

/// One key an export wraps: its source realisation, and the planned method and exposure.
pub(crate) struct Item<'a> {
    pub src: Target<'a>,
    pub method: Method,
    pub exposure: Exposure,
}

/// Wrap every item's key on `from` to `transport`, `to`'s transport key as the lock binds it, as
/// one bundle for `to` — all or nothing: a key that
/// cannot be wrapped fails the export, and no bundle is made. Public objects need no transport
/// key: a bundle of them alone names none, and nothing is created on the source. Each source realisation is verified
/// against the lock first; the transport public key and the composed methods' shared KEK are
/// session objects on the source, destroyed again whatever happens.
///
/// # Errors
///
/// Whatever `ops::verify` refuses; `NotFound` for a key not under its locator; `Unsupported`
/// (15) for a method this build or the source cannot perform, or a `C_WrapKey` the source
/// refuses; `PreconditionFailed` for a key to wrap and no transport key of `to` whose public
/// key is known.
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
            return Err(KmError::PreconditionFailed(
                format!("exporting keys from '{}' needs the target's transport key to wrap them to", from.name).into(),
            ));
        }
        // Public objects only: nothing to wrap, so no transport key and nothing made on the source.
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
    // An enforced key wraps only under the transport key's trusted copy (`transport --trust-on`),
    // the composed method by CKM_RSA_AES_KEY_WRAP: the source trusts no key-encryption key.
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
            KmError::PreconditionFailed(
                format!(
                    "'{}' holds no trusted copy of transport key '{}': `{}`",
                    from.name,
                    transport.object(),
                    crate::plan::trust_command(Some(transport.object()), &from.name)
                )
                .into(),
            )
        })?)
    } else {
        None
    };
    let modulus = rsa_parts(spki)?.0.len();
    let session = from.raw();
    let refused = |what: &str, e: cryptoki::error::Error| {
        from.refused_for(Topic::Mechanism, &e, format!("{what} on '{}': {e}", from.name))
    };
    // The transport public key and the shared KEK are session objects on the source: both go
    // when this returns, however it does.
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

/// One object's bundle entry: a public object's bytes, or a key's `wrapped` blob with its own
/// wrapped KEK when it has one ([`wrap`]'s result).
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

/// One wrapped key ([`wrap`]): its blob, and its own wrapped KEK when it does not share the
/// bundle's.
struct Wrapped {
    own_kek: Option<Vec<u8>>,
    blob: Vec<u8>,
}

/// Each item as the source holds it, verified against the lock first.
fn hold<'a>(items: &'a [Item<'a>], from: &Token, lock: &'a Lock, notes: &mut Notes) -> Result<Vec<Found<'a>>> {
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
            KmError::PreconditionFailed(format!("{src}: the lock pins no IDs for object '{}'", src.object_name).into())
        })?;
        let object_type = locked.object_type.clone().ok_or_else(|| {
            KmError::PreconditionFailed(
                format!("{src}: the lock records no type for object '{}'", src.object_name).into(),
            )
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

/// A fresh session AES-256 KEK on the source, and its blob wrapped to the transport key.
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

/// The keys one export wraps under: the transport key on the source (its trusted copy for an
/// enforced key), the shared KEK of the sealed composed keys, and the transport modulus length.
struct Wrapping {
    tpub: ObjectHandle,
    kek: Option<ObjectHandle>,
    modulus: usize,
}

/// One key's blob, and its own wrapped KEK when it has one: an enforced composed key by
/// `CKM_RSA_AES_KEY_WRAP` under the trusted transport key (OAEP of a fresh AES key, then RFC 5649
/// under it; split at the modulus length), a sealed one under the shared KEK (RFC 5649) — or as
/// the enforced one under the transport key when there is none — and the direct method under the
/// transport key itself.
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

/// `CKM_RSA_AES_KEY_WRAP`'s unwrap of `blob` (OAEP of the AES-256 KEK, then RFC 5649 under it)
/// with the RSA private key `rsa`.
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

/// Import `bound`'s key `e` under `dst` on `to`, unwrapping with the transport key the bundle
/// is bound to there (`trust::BoundBundle`: `to`'s own, as the lock binds it), and record it.
/// Before the target is touched: the bundle's type, IDs and commitment label must be the lock's
/// (the lock is the reviewed truth, the bundle only a carrier); the locator must be empty. Whatever fails after something was
/// created removes everything under the locator again.
///
/// # Errors
///
/// `PreconditionFailed` (14) when the lock pins no IDs for its object, or another type;
/// `HashMismatch` (10) for bundle IDs, label or transport key that are not the lock's, and —
/// after the import — material whose identity is not the locked one; `Conflict` (13) for an
/// occupied locator or blobs the module finds invalid (tampered, or wrapped to another key);
/// `Unsupported` (15) for an unwrap whose mechanism or template the target refuses, and
/// `Unavailable` (16) for one the device or session fails, which some modules also say of a
/// damaged blob ([`unwrap_failure`]); whatever
/// `ops::lock_import` refuses.
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
    // What the record after it asks (the proof's and the commitments' templates included), before
    // anything is created.
    ops::check_import(dst, to)?;
    let ready = preflight(bound, e, dst, to, lock, notes)?;
    let method = e.method().map_err(|e| KmError::Validation(e.into()))?;
    let mut made = Vec::new();
    let created = create(b, e, dst, to, &ready, &method, &mut made).and_then(|()| {
        let origin =
            Origin { from: b.source.token.clone(), method: e.method.clone(), exposure: e.exposure, declared: false };
        // What unwrapped and does not prove to be the key the lock pins (a failed proof of
        // possession, 13) fails the rule only the run decides, as a mismatched ID (10) does.
        ops::lock_import(dst, to, lock, origin, notes)
            .map_err(|err| if err.exit_code() == 13 && err.rule().is_none() { err.with_rule(IDENTITY) } else { err })
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
    // Per class (`Token::occupied`): a certificate beside the key is no collision, and a public
    // key object already holding the bundle's public key is the key's public half, reused.
    let spki = e.public_spki().map_err(|e| KmError::Validation(e.into()))?;
    let occupied = free_locator(dst, to, spki.as_deref())?;
    Ok(Preflight { unwrapping: Some(unwrapping), public_half: occupied.public_half })
}

/// A bundle read from a file (`import --in`) against the binding `dst` records: an EC or Edwards
/// private key under `token-asserted` is refused (14) before the target is touched.
///
/// The transport key is public, so anyone can seal a key of their own to it and set it beside
/// the lock's IDs and `publicKey`; RFC 5649 authenticates the bytes, not who wrapped them. A
/// target that keeps no point with an unwrapped EC key (`SoftHSM`) takes the key's identity
/// from the public half the import creates from that same `publicKey`, so only a `pop-*`
/// proof ties the unwrapped key to it. An RSA private key carries its modulus, so its identity
/// is its own; `migrate` makes its bundle in memory from the locked source, so it is not
/// checked here.
///
/// # Errors
///
/// `PreconditionFailed` for an EC or Edwards private key whose binding is `token-asserted`.
pub(crate) fn check_carried(e: &Entry, dst: &Target) -> Result<()> {
    let own_identity = !matches!(dst.object.key_type, Some(KeyType::Ec | KeyType::EcEdwards));
    if own_identity || ops::binding(dst) != Some(Binding::TokenAsserted) {
        return Ok(());
    }
    Err(KmError::PreconditionFailed(
        format!(
            "{dst}: binding = \"token-asserted\" proves nothing of the {} key '{}' a bundle file carries: its \
             identity would rest on the public key the bundle itself names; bind it with pop-sign or pop-ecdh \
             there, or move it with `camigrate migrate`",
            dst.object.key_type.map_or_else(String::new, |k| k.to_string()),
            e.object
        )
        .into(),
    ))
}

/// What [`preflight`] established: the transport key to unwrap with (none for a public object),
/// and a public key object already holding the key's public key, reused rather than created.
pub(crate) struct Preflight {
    pub unwrapping: Option<ObjectHandle>,
    pub public_half: Option<ObjectHandle>,
}

/// A wrapped key in a bundle whose transport key is not realised on the target.
fn no_transport(dst: &Target) -> KmError {
    KmError::PreconditionFailed(
        format!(
            "{dst}: the bundle's transport key is not realised on '{}' under a spec keys.toml names",
            dst.token_name
        )
        .into(),
    )
}

/// The bundle's key `e` against the lock: the same type, IDs and commitment label, and — for a
/// wrapped key — wrapped to the transport key `tr` realises. `dst` realises `e`'s object (the
/// import picks it by that name).
fn check_against_lock(b: &Bundle, e: &Entry, dst: &Target, tr: Option<&Target>, lock: &Lock) -> Result<()> {
    let locked = lock.objects.get(dst.object_name).filter(|o| !o.ids.is_empty()).ok_or_else(|| {
        KmError::PreconditionFailed(
            format!(
                "{dst}: the lock pins no IDs for object '{}', so nothing could check the imported material; \
             lock it on its source first",
                dst.object_name
            )
            .into(),
        )
    })?;
    if locked.object_type.as_ref() != Some(&e.object_type) || dst.object.cfg() != &e.object_type {
        return Err(KmError::PreconditionFailed(
            format!("{dst}: the bundle carries a {}, the lock and keys.toml another type", e.object_type).into(),
        ));
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
        .ok_or_else(|| KmError::Validation(format!("{dst}: a public object is created, not unwrapped").into()))?;
    let session = to.raw();
    let refused = |what: &str, e: cryptoki::error::Error| {
        unwrap_error(&format!("{dst}: {what} on '{}'", to.name), &e, |m| to.unsupported_for(Topic::Mechanism, m))
    };
    // The templates as the provider adjusts them, before anything is created.
    let template = templates::import_key(
        dst.into(),
        to.policy_template(&unwrap_declared(&dst.spec.attributes, &unwrap_refusals(to)))?,
    )?;
    let template = to.provider.adjusted(&Template::Import(dst.into(), Via::Unwrap), template)?;
    // A KEK only where one is unwrapped on its own: the composed method with RFC 5649 here.
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
            // An enforced key carries its own (CKM_RSA_AES_KEY_WRAP's); the others share the bundle's.
            let kek_blob = match e.wrapped_kek().map_err(|e| KmError::Validation(e.into()))? {
                Some(own) => own,
                None => b.wrapped_kek().map_err(|e| KmError::Validation(e.into()))?.unwrap_or_default(),
            };
            // A target with no RFC 5649 of its own (AWS CloudHSM lists one it refuses [run])
            // unwraps both in one CKM_RSA_AES_KEY_WRAP: its input is the same two blobs, joined.
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

/// The rule a sealed import's dry run cannot decide, and its run refuses by: whether the blob
/// unwraps (13; 16 where the module says only that it failed, a device failure). camigrate's own,
/// beside `ops::Rule` (docs/archive/REVIEW-2026-11-24/phase1-design.md §1.4, "deferred rules
/// today").
pub(crate) const UNWRAPS: &str = "unwraps";

/// The other: whether what unwrapped is the key the lock pins (10, which names no rule of its
/// own: [`crate::Tally`] names this one for it).
pub(crate) const IDENTITY: &str = "identity";

/// What a failed `C_UnwrapKey` says, by the module's return value: only a blob the module finds
/// invalid says the bundle was tampered with or wrapped to another key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnwrapFailure {
    /// The wrapped or encrypted data is invalid or of the wrong length (13).
    Tampered,
    /// The target refuses the mechanism, its parameters, the unwrapping key or the template (15).
    Refused,
    /// The module failed and says no more (`CKR_DEVICE_ERROR`, `CKR_GENERAL_ERROR`,
    /// `CKR_FUNCTION_FAILED`): 16, said as what may be a damaged blob, since that is how some
    /// modules report one (kryoptic, a tampered RFC 5649 blob \[run\]).
    Opaque,
    /// Anything else: the session, the login (16).
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
        // A mechanism this build cannot name (`CKM_RSA_AES_KEY_WRAP` without `kwp`).
        | CkError::NotSupported => UnwrapFailure::Refused,
        CkError::Pkcs11(RvError::DeviceError | RvError::GeneralError | RvError::FunctionFailed, _) => {
            UnwrapFailure::Opaque
        }
        _ => UnwrapFailure::Failed,
    }
}

/// The error of an unwrap `what` that failed with `e` ([`unwrap_failure`]), carrying its return
/// value; `unsupported` makes the target's refusal (`Token::unsupported`, with its hint).
fn unwrap_error(what: &str, e: &cryptoki::error::Error, unsupported: impl FnOnce(String) -> KmError) -> KmError {
    let rv = cakeys_pkcs11::token::rv_of(e);
    match unwrap_failure(e) {
        UnwrapFailure::Tampered => {
            KmError::Conflict(format!("{what}: {e} (the bundle was tampered with, or wrapped to another key)").into())
                .with_rule(UNWRAPS)
        }
        UnwrapFailure::Refused => unsupported(format!("{what}: {e}")),
        UnwrapFailure::Opaque => KmError::Unavailable(
            format!(
                "{what}: {e} (the module says no more: some report a damaged or altered bundle this way, \
                 so check that it is the one exported)"
            )
            .into(),
        )
        .with_rule(UNWRAPS),
        UnwrapFailure::Failed => KmError::Unavailable(format!("{what}: {e}").into()),
    }
    .with_rv(rv)
}

/// A private key's public half under `dst`'s locator, from its canonical SPKI, as `generate`
/// makes it: the spec's public attributes, `CKA_VERIFY` and public unless declared otherwise.
///
/// # Errors
///
/// `Unsupported` when the module will not create it.
pub(crate) fn create_public_half(dst: &Target, to: &Token, spki: &[u8]) -> Result<ObjectHandle> {
    let public_policy = to.policy_template(&dst.spec.public_attributes)?;
    let t = templates::public_half(dst.into(), public_policy, Some(public_key(dst, spki)?))?;
    let t = to.provider.adjusted(&Template::PublicHalf(dst.into()), t)?;
    // As `generate`: a module refusing cakeys' own CKA_PRIVATE = false default gets the half
    // without it.
    let declared = templates::public_declares(dst.spec, "CKA_PRIVATE");
    let create = || {
        with_public_default_dropped(&t, declared, |p| to.raw().create_object(p))
            .map(|(made, _)| made)
            .map_err(|e| to.refused_for(Topic::Create, &e, format!("{dst}: the public half: C_CreateObject: {e}")))
    };
    to.managing("creating the public half", create)
}

/// RSA-OAEP with MGF1 of the same hash and an empty label: what the planner names.
fn oaep(hash: OaepHash) -> Mechanism<'static> {
    Mechanism::RsaPkcsOaep(oaep_params(hash))
}

fn oaep_params(hash: OaepHash) -> PkcsOaepParams<'static> {
    cakeys_pkcs11::token::oaep_of(hash).0
}

/// The spec's declared `attributes` less those the target's profile refuses in an unwrap
/// template (`unwrap.refuse`, [`unwrap_refusals`]): what an unwrapped key's template declares.
pub(crate) fn unwrap_declared(
    attributes: &BTreeMap<String, AttrValue>,
    refusals: &[String],
) -> BTreeMap<String, AttrValue> {
    attributes.iter().filter(|(n, _)| !refusals.contains(n)).map(|(n, v)| (n.clone(), v.clone())).collect()
}

/// [`rfc5649`]'s twin from what a plan knows of a side: whether it has an RFC 5649 key wrap.
pub(crate) fn side_rfc5649(side: &Side) -> bool {
    let has = |m: MechanismType| side.mechanisms.contains(&m.to_string());
    #[cfg(feature = "kwp")]
    if has(MechanismType::AES_KEY_WRAP_KWP) {
        return true;
    }
    has(MechanismType::AES_KEY_WRAP_PAD)
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

/// Whether a token offers `CKM_RSA_AES_KEY_WRAP` this build can name (the `kwp` feature), asked
/// as [`rfc5649`] asks.
fn rsa_aes_key_wrap(tok: &Token) -> bool {
    #[cfg(feature = "kwp")]
    return tok.has(MechanismType::RSA_AES_KEY_WRAP);
    #[cfg(not(feature = "kwp"))]
    {
        let _ = tok;
        false
    }
}

/// The smallest RSA transport key, in bits: what it protects is no better guarded than it, and
/// the planner's direct-OAEP limit (`plan::OAEP_DIRECT_MAX`) assumes at least this.
pub(crate) const TRANSPORT_MIN_BITS: u64 = 2048;

/// Refuse a transport key smaller than [`TRANSPORT_MIN_BITS`].
///
/// # Errors
///
/// `Validation` for an SPKI that is no RSA key, or one too small.
pub(crate) fn check_transport_size(spki: &[u8]) -> Result<()> {
    let bits = cakeys_core::id::modulus_bits(&rsa_parts(spki)?.0);
    if bits < TRANSPORT_MIN_BITS {
        return Err(KmError::Validation(
            format!("a transport key is an RSA key of at least {TRANSPORT_MIN_BITS} bits; this one has {bits}").into(),
        ));
    }
    Ok(())
}

/// An RSA public key's modulus and public exponent, from its SPKI.
///
/// # Errors
///
/// `Validation` for an SPKI that is no RSA key.
pub(crate) fn rsa_parts(spki: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let key = rsa::PublicKey::from_public_key_der(spki)
        .map_err(|e| KmError::Validation(format!("the transport key is no RSA public key: {e}").into()))?;
    Ok((key.n().to_be_bytes_trimmed_vartime().to_vec(), key.e().to_be_bytes_trimmed_vartime().to_vec()))
}

/// The transport public key's material, for the session object the source wraps to
/// (`templates::session`'s `TransportKey`).
fn rsa_public(spki: &[u8]) -> Result<Vec<Attribute>> {
    let (n, e) = rsa_parts(spki)?;
    Ok(vec![Attribute::Modulus(n), Attribute::PublicExponent(e)])
}

/// Whether an export wraps a key of `method` and `exposure` under the KEK it shares with the
/// other composed keys: a composed key that is not `enforced` (that one carries its own), from a
/// source with RFC 5649 and AES key generation (else each goes by `CKM_RSA_AES_KEY_WRAP`, AWS
/// `CloudHSM` \[run\]). The export and the plan decide it alike.
pub(crate) fn shares_kek(method: &Method, exposure: Exposure, rfc5649: bool, aes_key_gen: bool) -> bool {
    matches!(method, Method::RsaOaepAesKwp(_)) && exposure != Exposure::Enforced && rfc5649 && aes_key_gen
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki::context::Function;
    use cryptoki::error::{Error as CkError, RvError};

    /// A transport key's size is its modulus's bits (`id::modulus_bits`), not its bytes times
    /// eight: a 2041- to 2047-bit key is under the 2048 minimum (review 2026-11-23 C-20).
    #[test]
    fn a_transport_key_counts_its_bits() {
        let spki = |top: u8| cakeys_core::id::rsa_spki(&[&[top][..], &[0xff; 255]].concat(), &[1, 0, 1]).unwrap();
        check_transport_size(&spki(0x80)).unwrap();
        for top in [0x7f, 0x01] {
            let e = check_transport_size(&spki(top)).unwrap_err();
            assert!(e.exit_code() == 17 && e.to_string().contains("this one has 204"), "{top:#x}: {e}");
        }
    }

    /// A failed unwrap is 13 ("tampered with") only when the module says the blob is bad; a
    /// refused mechanism, parameter, unwrapping key or template is the target's 15, and the
    /// device, session or login failing is 16. A module that fails and says no more is 16 said as
    /// what may be a damaged bundle (kryoptic's `CKR_DEVICE_ERROR` for a tampered blob \[run\]),
    /// never a PIN or session error. Each keeps the return value it came with.
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
        // A mechanism this build cannot name is the target's refusal, not a tampered bundle.
        assert_eq!(unwrap_error("x", &CkError::NotSupported, unsupported).exit_code(), 15);
    }
}
