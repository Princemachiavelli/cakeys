//! The import, create, export and unwrap probes (`docs/CAPROBE_MIGRATION.md`): fixed test keys
//! (`fixtures/import`: test keys, no secret, so a profile regenerates byte for byte) brought
//! into the token each way the module offers and taken out each way. Every row is a round trip
//! checked on the host: an imported private key proves possession of the test key's public key,
//! a secret key computes the test key's check value, an exported key is the test key again.
//!
//! On a scratch token each key is imported extractable, so one key proves its import, both
//! exports and the unwrap of what was exported. In a scratch slot (ykcs11) only what PIV holds
//! is imported, as SO, and the slot ends holding a freshly generated key and its placeholder,
//! as the generation probes leave it.

use super::{Draft, Made, Target, ckr, evidence, refused, rsa_aes_key_wrap, spec};
use cakeys_core::config::{Binding, Locator, ObjectCfg};
use cakeys_core::migrate::Method;
use cakeys_core::plaintext::{private_from_pkcs8, spki_of_pkcs8};
use cakeys_core::pop::OaepHash;
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result, id};
use cakeys_pkcs11::provider::PlaintextKind;
use cakeys_pkcs11::token::{self, SessionObject, locator_attrs, public_object_attrs};
use cakeys_pkcs11::{Declared, SessionKey, Template, Via};
use cakeys_profile::{Answer, Capability, On, Way};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};

macro_rules! fixture {
    ($file:literal) => {
        include_bytes!(concat!("../../fixtures/import/", $file))
    };
}

/// The private keys of each curve the host reads (`cakeys_core::plaintext`), as PKCS#8 DER.
const CURVE_KEYS: [(&str, &str, &[u8]); 7] = [
    ("CKK_EC", "secp256r1", fixture!("ec-secp256r1.der")),
    ("CKK_EC", "secp384r1", fixture!("ec-secp384r1.der")),
    ("CKK_EC", "secp521r1", fixture!("ec-secp521r1.der")),
    ("CKK_EC", "secp256k1", fixture!("ec-secp256k1.der")),
    ("CKK_EC", "brainpoolP256r1", fixture!("ec-brainpoolP256r1.der")),
    ("CKK_EC", "brainpoolP384r1", fixture!("ec-brainpoolP384r1.der")),
    ("CKK_EC_EDWARDS", "edwards25519", fixture!("ec-edwards25519.der")),
];

/// An RSA private key per size the generation probes try ([`super::RSA_SIZES`]) that the host
/// reads, as PKCS#8 DER. The rsa crate takes no public key under 1024 bits or over 8192, so
/// cakeys identifies no key of the other sizes, and imports none.
const RSA_KEYS: [(u32, &[u8]); 7] = [
    (1024, fixture!("rsa-1024.der")),
    (1536, fixture!("rsa-1536.der")),
    (2048, fixture!("rsa-2048.der")),
    (3072, fixture!("rsa-3072.der")),
    (4096, fixture!("rsa-4096.der")),
    (6144, fixture!("rsa-6144.der")),
    (8192, fixture!("rsa-8192.der")),
];

/// AES values of each length, in bytes.
const AES_KEYS: [&[u8]; 3] = [fixture!("aes-16.key"), fixture!("aes-24.key"), fixture!("aes-32.key")];

/// A self-signed certificate under the P-256 key.
const CERTIFICATE: &[u8] = fixture!("certificate.der");

/// A data object's value.
const DATA: &[u8] = b"cakeys probe: a data object";

/// One private key to import: its type as keys.toml and the rows name it, and its PKCS#8.
struct PrivateKey {
    object: ObjectCfg,
    kt: Kt,
    key_type: &'static str,
    on: On,
    der: &'static [u8],
}

/// The scratch token's RSA key pair the sealed exports wrap toward, `(public, private)`.
type Transport = Option<(ObjectHandle, ObjectHandle)>;

/// Bring each fixture in the way the provider imports, then (on a scratch token) take it out
/// each way. `transport` is the RSA pair the wrap probes use.
///
/// # Errors
///
/// An SO login failing, which stops the probe as it stops the generation probes.
pub(super) fn probe_moves(made: &mut Made, profile: &mut Draft, transport: Transport) -> Result<()> {
    let kind = made.tok.provider.plaintext_import();
    if kind == PlaintextKind::Tpm2Ptool {
        // tpm2_ptool writes the module's store, which this open token reads only once opened
        // again: no row rather than a refusal of the path the provider really takes.
        made.undetermined.push(format!(
            "no import rows: {} imports keys through tpm2_ptool, which the probe does not run yet",
            made.tok.provider.name()
        ));
    } else {
        let unread: Vec<String> =
            made.rsa_sizes.iter().filter(|b| !RSA_KEYS.iter().any(|(k, _)| k == *b)).map(ToString::to_string).collect();
        if !unread.is_empty() {
            made.undetermined.push(format!(
                "no import rows of RSA {} bits: the host reads no RSA key of that size",
                unread.join(", ")
            ));
        }
        for key in private_keys(&made.rsa_sizes) {
            import_private(made, profile, &key, kind, transport)?;
        }
        if matches!(made.target, Target::Labels) {
            for value in AES_KEYS {
                import_secret(made, profile, value, transport);
            }
        }
    }
    create_public(made, profile, Class::Certificate, CERTIFICATE)?;
    match made.target {
        Target::Labels => create_public(made, profile, Class::Data, DATA)?,
        // PIV's data objects are the device's own (CHUID, CCC): never written. The slot gets a
        // generated key again, which also puts its placeholder certificate back.
        Target::Slot(_) => {
            let p256 = ObjectCfg { curve: Some("secp256r1".into()), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::Ec)) };
            if let Err(e) = made.create(&p256, &spec(&[], &[]))? {
                made.undetermined.push(format!(
                    "the scratch slot holds the last key the import probes put there: generating over it: {}",
                    evidence(made.tok, &e)
                ));
            }
        }
    }
    Ok(())
}

/// The private keys the probes import: each curve, then each RSA size up to the request's
/// largest.
fn private_keys(rsa_sizes: &[u32]) -> Vec<PrivateKey> {
    let curves = CURVE_KEYS.iter().map(|(key_type, curve, der)| {
        let kt = if *key_type == "CKK_EC" { Kt::Ec } else { Kt::EcEdwards };
        PrivateKey {
            object: ObjectCfg { curve: Some((*curve).to_owned()), ..ObjectCfg::new(Class::PrivateKey, Some(kt)) },
            kt,
            key_type,
            on: On::Item((*curve).to_owned()),
            der,
        }
    });
    let rsa = RSA_KEYS.iter().filter(|(bits, _)| rsa_sizes.contains(bits)).map(|(bits, der)| PrivateKey {
        object: ObjectCfg { modulus_bits: Some((*bits).into()), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::Rsa)) },
        kt: Kt::Rsa,
        key_type: "CKK_RSA",
        on: On::Bits(*bits),
        der,
    });
    curves.chain(rsa).collect()
}

impl Made<'_> {
    /// Where the next object goes: a fresh probe label, or the scratch slot's `CKA_ID`. The
    /// label, to track what is made under it.
    fn locator(&mut self) -> (Locator, Option<String>) {
        match &self.target {
            Target::Labels => {
                let label = self.label();
                (Locator { label: Some(label.clone()), id: None }, Some(label))
            }
            Target::Slot(id) => (Locator { label: None, id: Some(cakeys_core::hex::encode(id)) }, None),
        }
    }

    /// Track `h`, made under `label`, for the cleanup and the leftover check.
    fn track(&mut self, h: ObjectHandle, label: Option<&String>) {
        let Some(label) = label else { return };
        self.handles.push(h);
        if !self.labels.contains(label) {
            self.labels.push(label.clone());
        }
    }
}

/// Whether `e` is an SO login failing: it stops the probe, never a row.
fn so_login(e: &KmError) -> bool {
    matches!(e, KmError::Unavailable(m) if m.contains(token::SO_LOGIN))
}

/// Import `key` as its provider imports (`import.*`), with its public half first on a scratch
/// token (`create.CKO_PUBLIC_KEY.*`: PIV derives its own), then export it each way.
fn import_private(
    made: &mut Made,
    profile: &mut Draft,
    key: &PrivateKey,
    kind: PlaintextKind,
    transport: Transport,
) -> Result<()> {
    let cap = Capability::Import { key_type: key.key_type.into(), on: key.on.clone() };
    let read = || -> Result<_> {
        let spki = id::spki_canonical(&spki_of_pkcs8(key.der)?)?;
        Ok((spki, private_from_pkcs8(key.der, key.kt, key.object.curve.as_deref())?))
    };
    let (spki, parts) = match read() {
        Ok(read) => read,
        Err(e) => {
            made.undetermined.push(format!("no {cap} row: the host does not read the test key: {e}"));
            return Ok(());
        }
    };
    let labels = matches!(made.target, Target::Labels);
    let (loc, label) = made.locator();
    let at = locator_attrs(&loc)?;
    // Every template as the provider adjusts it for the verbs (`Provider::template`).
    let probe_spec = spec(&[], &[]);
    let declared = Declared { object: &key.object, spec: &probe_spec, locator: &loc };
    let provider = made.tok.provider.clone();
    let adjusted = |t: Template<'_>, attrs| provider.adjusted(&t, attrs);
    if labels {
        public_half(made, profile, key, declared, label.as_ref(), &spki)?;
    }
    let mut base = vec![
        Attribute::Token(true),
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(key_type_of(key)),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
    ];
    base.extend(at);
    let import = |t| adjusted(Template::Import(declared, Via::CreateObject), t);
    // Extractable on a scratch token, so the same key proves the exports; a module refusing
    // that gets the key without it, its exports then unprobed.
    let made_key = if labels {
        let extractable = [&base[..], &[Attribute::Extractable(true)]].concat();
        match import(extractable).and_then(|t| made.tok.create_private(&key.object, t, &parts)) {
            Ok(h) => Ok((h, true)),
            Err(e) if so_login(&e) => return Err(e),
            Err(_) => import(base).and_then(|t| made.tok.create_private(&key.object, t, &parts)).map(|h| (h, false)),
        }
    } else {
        import(base).and_then(|t| made.tok.create_private(&key.object, t, &parts)).map(|h| (h, false))
    };
    let (h, extractable) = match made_key {
        Ok(made_key) => made_key,
        Err(e) if so_login(&e) => return Err(e),
        Err(e) => {
            profile.set(cap, Answer::No, Some(refused(made.tok, &e)), None);
            return Ok(());
        }
    };
    made.track(h, label.as_ref());
    match made.tok.prove_binding(h, &key.object, &spki, Binding::PopSign) {
        Ok(()) => profile.set(cap, Answer::Yes, None, Some(kind.name().into())),
        Err(e) => {
            made.undetermined
                .push(format!("no {cap} row: imported, but no proof of possession: {}", evidence(made.tok, &e)));
            return Ok(());
        }
    }
    if !extractable {
        if labels {
            made.undetermined.push(format!("no export rows of {} {}: not imported extractable", key.key_type, key.on));
        }
        return Ok(());
    }
    let same = |plain: &[u8]| spki_of_pkcs8(plain).and_then(|s| id::spki_canonical(&s)).is_ok_and(|s| s == spki);
    export_host(made, profile, (key.key_type, &key.on), h, &same);
    let template = |label: &str| {
        let t = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(key_type_of(key)),
            Attribute::Sign(true),
            Attribute::Sensitive(true),
        ];
        let locator = Locator { label: Some(label.to_owned()), id: None };
        adjusted(Template::Import(Declared { locator: &locator, ..declared }, Via::Unwrap), t)
    };
    let same = |m: &Made, h2| m.tok.prove_binding(h2, &key.object, &spki, Binding::PopSign);
    export_sealed(made, profile, (key.key_type, &key.on), h, false, transport, &template, &same);
    Ok(())
}

/// Create `key`'s public half from its canonical `spki` under `on`'s locator
/// (`create.CKO_PUBLIC_KEY.*`), read back.
///
/// # Errors
///
/// A locator the probe made that does not map, a public key the host cannot encode.
fn public_half(
    made: &mut Made,
    profile: &mut Draft,
    key: &PrivateKey,
    on: Declared<'_>,
    label: Option<&String>,
    spki: &[u8],
) -> Result<()> {
    let public = ObjectCfg { class: Class::PublicKey, ..key.object.clone() };
    let cap = Capability::Create { class: "CKO_PUBLIC_KEY".into(), key: Some((key.key_type.into(), key.on.clone())) };
    let mut t = vec![Attribute::Token(true), Attribute::Verify(true)];
    t.extend(locator_attrs(on.locator)?);
    t.extend(public_object_attrs(&public, spki)?);
    let created = made
        .tok
        .provider
        .adjusted(&Template::PublicHalf(on), t)
        .map_err(|e| refused(made.tok, &e))
        .and_then(|t| made.session.create_object(&t).map_err(|e| format!("C_CreateObject: {}", ckr(&e))));
    match created {
        Ok(h) => {
            made.track(h, label);
            match made.tok.material_spki(h) {
                Ok(Some(s)) if s == spki => profile.set(cap, Answer::Yes, None, None),
                Ok(_) => profile.set(cap, Answer::No, Some("the object holds no key, or another".into()), None),
                Err(e) => made.undetermined.push(format!("no {cap} row: reading it back: {}", evidence(made.tok, &e))),
            }
        }
        Err(why) => profile.set(cap, Answer::No, Some(why), None),
    }
    Ok(())
}

/// The `CKK_*` of `key`, as PKCS#11 names it.
fn key_type_of(key: &PrivateKey) -> KeyType {
    match key.kt {
        Kt::Ec => KeyType::EC,
        Kt::EcEdwards => KeyType::EC_EDWARDS,
        _ => KeyType::RSA,
    }
}

/// The RFC 5649 key wraps `Token::extract` hands a key to the host by: `CKM_AES_KEY_WRAP_PAD`,
/// and `_KWP` where this build names it. Tried listed or not, as every probe tries.
fn host_wraps() -> Vec<(Mechanism<'static>, MechanismType)> {
    let wraps = std::iter::once((Mechanism::AesKeyWrapPad, MechanismType::AES_KEY_WRAP_PAD));
    #[cfg(feature = "kwp")]
    let wraps = wraps.chain(std::iter::once((Mechanism::AesKeyWrapKwp, MechanismType::AES_KEY_WRAP_KWP)));
    wraps.collect()
}

/// The `export.host.*` row from handing `h` to the host (`Token::extract`, by RFC 5649): yes
/// when what arrived is the test key (`same`).
fn export_host(
    made: &Made,
    profile: &mut Draft,
    (key_type, on): (&str, &On),
    h: ObjectHandle,
    same: &dyn Fn(&[u8]) -> bool,
) {
    let cap = Capability::Export { way: Way::Host, key_type: key_type.into(), on: on.clone() };
    let mut refusals = Vec::new();
    for (mech, name) in host_wraps() {
        match made.tok.extract(h, &mech) {
            Ok(plain) if same(&plain) => return profile.set(cap, Answer::Yes, None, Some(name.to_string())),
            Ok(_) => return profile.set(cap, Answer::No, Some(format!("{name}: what arrived is another key")), None),
            Err(e) => refusals.push(format!("{name}: {}", evidence(made.tok, &e))),
        }
    }
    profile.set(cap, Answer::No, Some(refusals.join("; ")), None);
}

/// `CKM_RSA_AES_KEY_WRAP`'s parameters: RSA-OAEP of `hash`, MGF1 of the same.
fn rsa_aes(hash: OaepHash) -> PkcsOaepParams<'static> {
    let (h, mgf) = match hash {
        OaepHash::Sha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
        OaepHash::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
    };
    PkcsOaepParams::new(h, mgf, PkcsOaepSource::empty())
}

/// A sealed way out, as camigrate moves a key toward another token (docs/CAMIGRATE.md D2).
#[derive(Clone, Copy)]
enum Sealed {
    /// The key under RSA-OAEP to the transport key directly (a secret key).
    Direct(OaepHash),
    /// A fresh AES KEK under RSA-OAEP, the key under the KEK by RFC 5649.
    Composed(OaepHash),
    /// The same in one `CKM_RSA_AES_KEY_WRAP`, where there is no RFC 5649 (AWS `CloudHSM` \[run\]).
    RsaAes(OaepHash),
}

impl Sealed {
    /// The row's `via`: camigrate's method name, with the stand-in mechanism named beside it.
    fn via(self) -> String {
        match self {
            Sealed::Direct(h) => Method::RsaOaep(h).name(),
            Sealed::Composed(h) => Method::RsaOaepAesKwp(h).name(),
            Sealed::RsaAes(h) => format!("{} by CKM_RSA_AES_KEY_WRAP", Method::RsaOaepAesKwp(h).name()),
        }
    }
}

/// The sealed ways, in camigrate's order: a secret key under RSA-OAEP directly, then the
/// composed method, then `CKM_RSA_AES_KEY_WRAP`. RSA-OAEP only of a hash a wrap round-tripped
/// with ([`super::probe_wrapping`]).
fn sealed_ways(profile: &Draft, secret: bool) -> Vec<Sealed> {
    let oaep: Vec<OaepHash> = [OaepHash::Sha256, OaepHash::Sha1]
        .into_iter()
        .filter(|h| profile.wrap_oaep.iter().flatten().any(|w| w == token::oaep_of(*h).1))
        .collect();
    let direct = oaep.iter().filter(|_| secret).map(|h| Sealed::Direct(*h));
    let composed = oaep.iter().map(|h| Sealed::Composed(*h));
    direct.chain(composed).chain([Sealed::RsaAes(OaepHash::Sha256), Sealed::RsaAes(OaepHash::Sha1)]).collect()
}

/// What one sealed round trip did.
enum Trip {
    /// The key did not leave: why.
    WrapRefused(String),
    /// It left, but did not come back in here: why.
    UnwrapRefused(String),
    /// It came back in as this object.
    Unwrapped(ObjectHandle),
}

/// Wrap `h` toward the transport key `way`'s way, then unwrap it back here under `template`.
fn trip(
    made: &Made,
    way: Sealed,
    (tpub, tpriv): (ObjectHandle, ObjectHandle),
    h: ObjectHandle,
    template: &[Attribute],
) -> Trip {
    let session = made.session;
    let one = |mech: &Mechanism| match session.wrap_key(mech, tpub, h) {
        Ok(blob) => match session.unwrap_key(mech, tpriv, &blob, template) {
            Ok(h2) => Trip::Unwrapped(h2),
            Err(e) => Trip::UnwrapRefused(format!("C_UnwrapKey: {}", ckr(&e))),
        },
        Err(e) => Trip::WrapRefused(format!("C_WrapKey: {}", ckr(&e))),
    };
    match way {
        Sealed::Direct(hash) => one(&Mechanism::RsaPkcsOaep(token::oaep_of(hash).0)),
        Sealed::RsaAes(hash) => {
            let oaep = rsa_aes(hash);
            match rsa_aes_key_wrap(&oaep) {
                Some(mech) => one(&mech),
                None => Trip::WrapRefused("this build cannot name CKM_RSA_AES_KEY_WRAP".into()),
            }
        }
        Sealed::Composed(hash) => composed(made, hash, (tpub, tpriv), h, template),
    }
}

/// camigrate's composed method: a fresh AES-256 KEK, the key under it by RFC 5649, the KEK under
/// RSA-OAEP to the transport key; back in the same way. Both KEKs are session objects.
fn composed(
    made: &Made,
    hash: OaepHash,
    (tpub, tpriv): (ObjectHandle, ObjectHandle),
    h: ObjectHandle,
    template: &[Attribute],
) -> Trip {
    let session = made.session;
    // camigrate's own KEK templates (`templates::session`), as the provider adjusts them.
    let (kek, back) =
        match (made.tok.session_template(SessionKey::ExportKek), made.tok.session_template(SessionKey::ImportKek)) {
            (Ok(kek), Ok(back)) => (kek, back),
            (Err(e), _) => return Trip::WrapRefused(format!("the KEK: {}", evidence(made.tok, &e))),
            (_, Err(e)) => return Trip::UnwrapRefused(format!("the KEK: {}", evidence(made.tok, &e))),
        };
    let kek = match session.generate_key(&Mechanism::AesKeyGen, &kek) {
        Ok(k) => SessionObject::new(session, k),
        Err(e) => return Trip::WrapRefused(format!("the KEK: C_GenerateKey: {}", ckr(&e))),
    };
    let oaep = Mechanism::RsaPkcsOaep(token::oaep_of(hash).0);
    let mut refusals = Vec::new();
    for (kwp, name) in host_wraps() {
        let blob = match session.wrap_key(&kwp, kek.handle(), h) {
            Ok(blob) => blob,
            Err(e) => {
                refusals.push(format!("{name}: C_WrapKey: {}", ckr(&e)));
                continue;
            }
        };
        let kek_blob = match session.wrap_key(&oaep, tpub, kek.handle()) {
            Ok(blob) => blob,
            Err(e) => return Trip::WrapRefused(format!("the KEK: C_WrapKey: {}", ckr(&e))),
        };
        let back = match session.unwrap_key(&oaep, tpriv, &kek_blob, &back) {
            Ok(k) => SessionObject::new(session, k),
            Err(e) => return Trip::UnwrapRefused(format!("the KEK: C_UnwrapKey: {}", ckr(&e))),
        };
        return match session.unwrap_key(&kwp, back.handle(), &blob, template) {
            Ok(h2) => Trip::Unwrapped(h2),
            Err(e) => Trip::UnwrapRefused(format!("{name}: C_UnwrapKey: {}", ckr(&e))),
        };
    }
    Trip::WrapRefused(refusals.join("; "))
}

/// The `export.sealed.*` and `unwrap.*` rows of the test key `h` (imported extractable): each
/// sealed way tried until one round-trips; `same` says the unwrapped key is the test key. Only
/// a round trip shows a blob holds the key, so a key that leaves but never comes back in leaves
/// the export unprobed. An unwrapped secret key's `CKA_VALUE_LEN` is not read: stock `SoftHSM`
/// leaves it 0 and the reference suites' carries the fix (upstream #925), so a row reading it
/// would describe one build only; `move.secret-unwrap` still says it.
#[expect(clippy::too_many_arguments, reason = "one key's rows: what it is, where it goes, how it is checked")]
fn export_sealed(
    made: &mut Made,
    profile: &mut Draft,
    (key_type, on): (&str, &On),
    h: ObjectHandle,
    secret: bool,
    transport: Transport,
    template: &dyn Fn(&str) -> Result<Vec<Attribute>>,
    same: &dyn Fn(&Made, ObjectHandle) -> Result<()>,
) {
    let export = Capability::Export { way: Way::Sealed, key_type: key_type.into(), on: on.clone() };
    let unwrap = Capability::Unwrap { key_type: key_type.into(), on: on.clone() };
    let Some(transport) = transport else {
        made.undetermined.push(format!("no {export} or {unwrap} row: no RSA transport key"));
        return;
    };
    let (mut wrap_refusals, mut unwrap_refusals) = (Vec::new(), Vec::new());
    for way in sealed_ways(profile, secret) {
        let label = made.label();
        let template = match template(&label) {
            Ok(t) => t,
            Err(e) => {
                unwrap_refusals.push(format!("{}: {}", way.via(), evidence(made.tok, &e)));
                continue;
            }
        };
        match trip(made, way, transport, h, &template) {
            Trip::WrapRefused(why) => wrap_refusals.push(format!("{}: {why}", way.via())),
            Trip::UnwrapRefused(why) => unwrap_refusals.push(format!("{}: {why}", way.via())),
            Trip::Unwrapped(h2) => {
                made.track(h2, Some(&label));
                match same(made, h2) {
                    Ok(()) => {
                        profile.set(export, Answer::Yes, None, Some(way.via()));
                        profile.set(unwrap, Answer::Yes, None, Some(way.via()));
                        return;
                    }
                    Err(e) => {
                        unwrap_refusals.push(format!("{}: not the key wrapped: {}", way.via(), evidence(made.tok, &e)));
                    }
                }
            }
        }
    }
    if unwrap_refusals.is_empty() {
        profile.set(export, Answer::No, Some(wrap_refusals.join("; ")), None);
    } else {
        profile.set(unwrap, Answer::No, Some(unwrap_refusals.join("; ")), None);
        made.undetermined.push(format!("no {export} row: it leaves, but never comes back in here"));
    }
}

/// The check value of an AES key: the zero block, encrypted (`kcv-ecb` without the label).
fn host_kcv(value: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{BlockCipherEncrypt as _, KeyInit as _};
    let mut block = aes::Block::default();
    match value.len() {
        16 => aes::Aes128::new_from_slice(value).ok()?.encrypt_block(&mut block),
        24 => aes::Aes192::new_from_slice(value).ok()?.encrypt_block(&mut block),
        32 => aes::Aes256::new_from_slice(value).ok()?.encrypt_block(&mut block),
        _ => return None,
    }
    Some(block.to_vec())
}

/// Whether the AES key `h` computes `value`'s check value.
fn same_aes(made: &Made, h: ObjectHandle, value: &[u8]) -> Result<()> {
    let token = made
        .session
        .encrypt(&Mechanism::AesEcb, h, &[0; 16])
        .map_err(|e| KmError::Unsupported(format!("C_Encrypt (CKM_AES_ECB): {}", ckr(&e)).into()))?;
    if Some(token) == host_kcv(value) {
        Ok(())
    } else {
        Err(KmError::Conflict("its check value is another key's".into()))
    }
}

/// Import an AES `value` with `C_CreateObject` (`import.CKK_AES.<bytes>`), extractable, then
/// export it each way.
fn import_secret(made: &mut Made, profile: &mut Draft, value: &[u8], transport: Transport) {
    let n = u32::try_from(value.len()).unwrap_or_default();
    let on = On::Bytes(n);
    let cap = Capability::Import { key_type: "CKK_AES".into(), on: on.clone() };
    let label = made.label();
    let base = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::AES),
        Attribute::Encrypt(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(true),
    ];
    // Every template as the provider adjusts it for the verbs (`Provider::template`).
    let object = ObjectCfg { value_len: Some(n.into()), ..ObjectCfg::new(Class::SecretKey, Some(Kt::Aes)) };
    let probe_spec = spec(&[], &[]);
    let provider = made.tok.provider.clone();
    let adjusted = |label: &str, via, t| {
        let locator = Locator { label: Some(label.to_owned()), id: None };
        provider.adjusted(&Template::Import(Declared { object: &object, spec: &probe_spec, locator: &locator }, via), t)
    };
    let h = match adjusted(&label, Via::CreateObject, base).and_then(|t| made.tok.create_secret(t, value)) {
        Ok(h) => h,
        Err(e) => {
            profile.set(cap, Answer::No, Some(refused(made.tok, &e)), None);
            return;
        }
    };
    made.track(h, Some(&label));
    if let Err(e) = same_aes(made, h, value) {
        made.undetermined.push(format!("no {cap} row: imported, but its check value: {}", evidence(made.tok, &e)));
        return;
    }
    profile.set(cap, Answer::Yes, None, Some(PlaintextKind::CreateObject.name().into()));
    export_host(made, profile, ("CKK_AES", &on), h, &|plain| plain == value);
    let template = |label: &str| {
        let t = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::AES),
            Attribute::Encrypt(true),
        ];
        adjusted(label, Via::Unwrap, t)
    };
    export_sealed(made, profile, ("CKK_AES", &on), h, true, transport, &template, &|m, h2| same_aes(m, h2, value));
}

/// Create a certificate or a data object from its value (`create.CKO_*`), read back. In a
/// scratch slot, as SO into the slot.
fn create_public(made: &mut Made, profile: &mut Draft, class: Class, bytes: &[u8]) -> Result<()> {
    let object = ObjectCfg::new(class, None);
    let cap = Capability::Create { class: class.to_string(), key: None };
    let (loc, label) = made.locator();
    let mut t = vec![Attribute::Token(true)];
    t.extend(locator_attrs(&loc)?);
    t.extend(public_object_attrs(&object, bytes)?);
    if class == Class::Data {
        t.push(Attribute::Private(false));
    }
    let probe_spec = spec(&[], &[]);
    let session = made.session;
    let on = Declared { object: &object, spec: &probe_spec, locator: &loc };
    let created = made.tok.provider.adjusted(&Template::Object(on), t).and_then(|t| {
        made.tok.managing("the create probe", || {
            session.create_object(&t).map_err(|e| KmError::Unsupported(format!("C_CreateObject: {}", ckr(&e)).into()))
        })
    });
    let h = match created {
        Ok(h) => h,
        Err(e) if so_login(&e) => return Err(e),
        Err(e) => {
            profile.set(cap, Answer::No, Some(evidence(made.tok, &e)), None);
            return Ok(());
        }
    };
    made.track(h, label.as_ref());
    match made.session.get_attributes(h, &[AttributeType::Value]).as_deref() {
        Ok([Attribute::Value(v)]) if v == bytes => profile.set(cap, Answer::Yes, None, None),
        Ok(_) => profile.set(cap, Answer::No, Some("CKA_VALUE reads otherwise".into()), None),
        Err(e) => made.undetermined.push(format!("no {cap} row: reading CKA_VALUE back: {}", ckr(e))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test key is of the size or curve its rows name, at a size the generation probes
    /// try, and the host reads every one.
    #[test]
    fn the_test_keys_are_what_their_rows_name() {
        assert!(RSA_KEYS.iter().all(|(bits, _)| super::super::RSA_SIZES.contains(bits)));
        for key in private_keys(&super::super::RSA_SIZES) {
            let spki = spki_of_pkcs8(key.der).and_then(|s| id::spki_canonical(&s));
            let spki = spki.unwrap_or_else(|e| panic!("{} {}: {e}", key.key_type, key.on));
            match &key.on {
                On::Bits(bits) => {
                    let parts = private_from_pkcs8(key.der, Kt::Rsa, None).unwrap();
                    let cakeys_core::plaintext::PrivateParts::Rsa(p) = parts else { panic!("{bits}: not RSA") };
                    assert_eq!(p.modulus.len() * 8, *bits as usize);
                }
                On::Item(curve) => assert_eq!(
                    id::spki_curve(&spki).unwrap().map(cakeys_core::id::Curve::name),
                    Some(curve.as_str()),
                    "{curve}"
                ),
                On::Bytes(_) => unreachable!(),
            }
        }
        for (value, len) in AES_KEYS.iter().zip([16, 24, 32]) {
            assert_eq!(value.len(), len);
            assert!(host_kcv(value).is_some());
        }
        assert!(id::cert_spki(CERTIFICATE).is_ok());
    }
}
