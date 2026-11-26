//! The import, create, export and unwrap probes (`docs/archive/CAPROBE_MIGRATION.md`): fixed test keys
//! (`fixtures/import`: test keys, no secret, so a profile regenerates byte for byte) brought
//! into the token each way the module offers and taken out each way. Every row is a round trip
//! checked on the host: an imported private key proves possession of the test key's public key,
//! a secret key computes the test key's check value, an exported key is the test key again.
//!
//! On a scratch token each key is imported extractable, so one key proves its import, both
//! exports and the unwrap of what was exported. In a scratch slot (ykcs11) only what PIV holds
//! is imported, as SO, and the slot ends holding a freshly generated key and its placeholder,
//! as the generation probes leave it.

use super::{Checked, Created, Draft, Made, Target, ckr, evidence, refused, rsa_aes_key_wrap, so_login, spec, worst};
use cakeys_core::config::{Binding, Locator, Object, ObjectCfg};
use cakeys_core::migrate::Method;
use cakeys_core::migrate::OaepHash;
use cakeys_core::plaintext::{private_from_pkcs8, spki_of_pkcs8};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{KmError, Result, id};
use cakeys_pkcs11::provider::PlaintextKind;
use cakeys_pkcs11::token::{self, SessionObject, locator_attrs, public_object_attrs};
use cakeys_pkcs11::{Declared, SessionKey, Template, Via};
use cakeys_profile::{Capability, KeyKind, On, Way};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};

macro_rules! fixture {
    ($file:literal) => {
        include_bytes!(concat!("../../fixtures/import/", $file))
    };
}

/// The private keys of each curve the host reads (`cakeys_core::plaintext`), as PKCS#8 DER.
const CURVE_KEYS: [(Kt, &str, &[u8]); 7] = [
    (Kt::Ec, "secp256r1", fixture!("ec-secp256r1.der")),
    (Kt::Ec, "secp384r1", fixture!("ec-secp384r1.der")),
    (Kt::Ec, "secp521r1", fixture!("ec-secp521r1.der")),
    (Kt::Ec, "secp256k1", fixture!("ec-secp256k1.der")),
    (Kt::Ec, "brainpoolP256r1", fixture!("ec-brainpoolP256r1.der")),
    (Kt::Ec, "brainpoolP384r1", fixture!("ec-brainpoolP384r1.der")),
    (Kt::EcEdwards, "edwards25519", fixture!("ec-edwards25519.der")),
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
pub(super) const AES_KEYS: [&[u8]; 3] = [fixture!("aes-16.key"), fixture!("aes-24.key"), fixture!("aes-32.key")];

/// A self-signed certificate under the P-256 key.
const CERTIFICATE: &[u8] = fixture!("certificate.der");

/// What marks a scratch slot as one the probe used: its own certificate (`CN=cakeys-probe`),
/// written over the slot's last key ([`mark_slot`]) and the one occupant the next run's guard
/// accepts (`super::check_slot`).
pub(super) const SLOT_MARKER: &[u8] = CERTIFICATE;

/// A data object's value.
const DATA: &[u8] = b"cakeys probe: a data object";

/// One private key to import: its type as keys.toml and the rows name it, and its PKCS#8.
struct PrivateKey {
    object: ObjectCfg,
    kt: Kt,
    key_type: KeyKind,
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
    let kind = made.tok.provider.plaintext_import().kind();
    if kind == PlaintextKind::Tpm2Ptool {
        // tpm2_ptool writes the module's store, which this open token reads only once opened
        // again: no row rather than a refusal of the path the provider really takes.
        // TODO: import each fixture through `tpm2_ptool` (as camigrate's `import_ptool` does),
        // reopen the token, check the key by its commitment and record `import.*` rows with
        // `via = "tpm2-ptool"`; see docs/OPEN.md, "More probes".
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
        let curves = unfixtured_curves();
        if !curves.is_empty() {
            made.undetermined
                .push(format!("no import rows of {}: no test key of that curve the host reads", curves.join(", ")));
        }
        for key in private_keys(&made.rsa_sizes) {
            import_private(made, profile, &key, kind, transport)?;
        }
        if matches!(made.scratch.target, Target::Labels) {
            for value in AES_KEYS {
                import_secret(made, profile, Kt::Aes, value, transport);
            }
            for (kt, n) in OTHER_SECRETS {
                import_secret(made, profile, kt, &secret_value(n), transport);
            }
        }
    }
    create_public(made, profile, Class::Certificate, CERTIFICATE)?;
    match made.scratch.target {
        Target::Labels => create_public(made, profile, Class::Data, DATA)?,
        // PIV's data objects are the device's own (CHUID, CCC): never written. The slot gets a
        // generated key again, and then the probe's own certificate over ykcs11's placeholder.
        Target::Slot(_) => {
            let p256 = ObjectCfg { curve: Some("secp256r1".into()), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::Ec)) };
            if let Created::Refused(e) | Created::Lost(e) | Created::Undecided(e) =
                made.create(&p256, &spec(&[], &[]))?
            {
                made.undetermined.push(format!(
                    "the scratch slot holds the last key the import probes put there: generating over it: {}",
                    evidence(made.tok, &e)
                ));
            }
            mark_slot(made)?;
        }
    }
    Ok(())
}

/// Leave the scratch slot marked as the probe's: its own certificate ([`SLOT_MARKER`]) over the
/// placeholder ykcs11 wrote with the last generation. ykcs11 writes that placeholder for every
/// key it generates, so it tells a probe's slot from no real key's; the next run's guard
/// (`super::check_slot`) accepts only this certificate (review 2026-11-23 D-1). A slot left
/// unmarked is refused by the next run until it is emptied, and this run says so.
fn mark_slot(made: &mut Made) -> Result<()> {
    let object = public_object(Class::Certificate);
    let (loc, _) = made.locator();
    let mut t = vec![Attribute::Token(true)];
    t.extend(host_encoding(&loc, &object, SLOT_MARKER)?);
    let (probe_spec, session) = (spec(&[], &[]), made.session);
    let on = Declared { object: Object::new(&object)?, spec: &probe_spec, locator: &loc };
    let marked = made.tok.provider.adjusted(&Template::Object(on), t).and_then(|t| {
        made.tok.managing("marking the scratch slot", || {
            session.create_object(&t).map_err(|e| {
                KmError::Unsupported(format!("C_CreateObject: {}", ckr(&e)).into()).with_rv(token::rv_of(&e))
            })
        })
    });
    match marked {
        Ok(_) => Ok(()),
        Err(e) if so_login(&e) => Err(e),
        Err(e) => {
            made.undetermined.push(format!(
                "the scratch slot is left without the probe's certificate, so the next run refuses it until it is \
                 emptied: {}",
                evidence(made.tok, &e)
            ));
            Ok(())
        }
    }
}

/// The curves cakeys names (`id::Curve::ALL`) with no test key in [`CURVE_KEYS`]: no import
/// row, and the run says so.
fn unfixtured_curves() -> Vec<&'static str> {
    id::Curve::ALL.iter().map(|c| c.name()).filter(|c| !CURVE_KEYS.iter().any(|(_, k, _)| k == c)).collect()
}

/// The private keys the probes import: each curve, then each RSA size up to the request's
/// largest.
fn private_keys(rsa_sizes: &[u32]) -> Vec<PrivateKey> {
    let curves = CURVE_KEYS.iter().map(|&(kt, curve, der)| PrivateKey {
        object: ObjectCfg { curve: Some(curve.to_owned()), ..ObjectCfg::new(Class::PrivateKey, Some(kt)) },
        kt,
        key_type: KeyKind::from(kt.name()),
        on: On::Item(curve.to_owned()),
        der,
    });
    let rsa = RSA_KEYS.iter().filter(|(bits, _)| rsa_sizes.contains(bits)).map(|(bits, der)| PrivateKey {
        object: ObjectCfg { modulus_bits: Some((*bits).into()), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::Rsa)) },
        kt: Kt::Rsa,
        key_type: KeyKind::Rsa,
        on: On::Bits(*bits),
        der,
    });
    curves.chain(rsa).collect()
}

impl Made<'_> {
    /// Where the next object goes: a fresh probe label, or the scratch slot's `CKA_ID`. The
    /// label, to track what is made under it.
    fn locator(&mut self) -> (Locator, Option<String>) {
        match &self.scratch.target {
            Target::Labels => {
                let label = self.scratch.label();
                (Locator { label: Some(label.clone()), id: None }, Some(label))
            }
            Target::Slot(id) => (Locator { label: None, id: Some(cakeys_core::hex::encode(id)) }, None),
        }
    }

    /// Track `h`, made under `label`, for the cleanup and the leftover check.
    fn track(&mut self, h: ObjectHandle, label: Option<&String>) {
        if let Some(label) = label {
            self.scratch.track(&[h], label);
        }
    }
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
    let cap = Capability::Import { key_type: key.key_type.clone(), on: key.on.clone() };
    let read = || -> Result<_> {
        let object = Object::new(&key.object)?;
        let spki = id::spki_canonical(&spki_of_pkcs8(key.der)?)?;
        Ok((object, spki, private_from_pkcs8(key.der, key.kt, object.curve())?))
    };
    let (object, spki, parts) = match read() {
        Ok(read) => read,
        Err(e) => {
            made.undetermined.push(format!("no {cap} row: the host does not read the test key: {e}"));
            return Ok(());
        }
    };
    let labels = matches!(made.scratch.target, Target::Labels);
    let (loc, label) = made.locator();
    // cakeys' own encoding failing is no answer of the module's, and never ends the probe.
    let at = match locator_attrs(&loc) {
        Ok(at) => at,
        Err(e) => {
            made.undetermined.push(format!("no {cap} row: the host cannot encode its locator: {e}"));
            return Ok(());
        }
    };
    // Every template as the provider adjusts it for the verbs (`Provider::template`).
    let probe_spec = spec(&[], &[]);
    let declared = Declared { object, spec: &probe_spec, locator: &loc };
    let provider = made.tok.provider.clone();
    let adjusted = |t: Template<'_>, attrs| provider.adjusted(&t, attrs);
    if labels {
        public_half(made, profile, key, declared, label.as_ref(), &spki);
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
        match import(extractable).and_then(|t| made.tok.create_private(object, t, &parts)) {
            Ok(h) => Ok((h, true)),
            Err(e) if so_login(&e) => return Err(e),
            Err(_) => import(base).and_then(|t| made.tok.create_private(object, t, &parts)).map(|h| (h, false)),
        }
    } else {
        import(base).and_then(|t| made.tok.create_private(object, t, &parts)).map(|h| (h, false))
    };
    let (h, extractable) = match made_key {
        Ok(made_key) => made_key,
        Err(e) if so_login(&e) => return Err(e),
        Err(e) => {
            profile.refused(&mut made.undetermined, cap, e.rv(), refused(made.tok, &e));
            return Ok(());
        }
    };
    made.track(h, label.as_ref());
    match made.tok.prove_binding(h, object, &spki, Binding::PopSign) {
        Ok(()) => profile.yes(cap, Checked::Host, Some(kind.name().into())),
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
    let host_same = |plain: &[u8]| spki_of_pkcs8(plain).and_then(|s| id::spki_canonical(&s)).is_ok_and(|s| s == spki);
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
    let same = |m: &Made, h2| m.tok.prove_binding(h2, object, &spki, Binding::PopSign);
    let test_key = TestKey { key_type: &key.key_type, on: &key.on, h, secret: false, template: &template, same: &same };
    exports(made, profile, &test_key, &host_same, transport);
    Ok(())
}

/// Create `key`'s public half from its canonical `spki` under `on`'s locator
/// (`create.CKO_PUBLIC_KEY.*`), read back. A locator or public key the host cannot encode is
/// undetermined: cakeys' own encoding, not the module's answer.
fn public_half(
    made: &mut Made,
    profile: &mut Draft,
    key: &PrivateKey,
    on: Declared<'_>,
    label: Option<&String>,
    spki: &[u8],
) {
    let public = ObjectCfg { class: Class::PublicKey, ..key.object.clone() };
    let cap = Capability::Create { class: "CKO_PUBLIC_KEY".into(), key: Some((key.key_type.clone(), key.on.clone())) };
    let mut t = vec![Attribute::Token(true), Attribute::Verify(true)];
    match host_encoding(on.locator, &public, spki) {
        Ok(attrs) => t.extend(attrs),
        Err(e) => return made.undetermined.push(format!("no {cap} row: the host cannot encode it: {e}")),
    }
    let created =
        made.tok.provider.adjusted(&Template::PublicHalf(on), t).map_err(|e| (e.rv(), refused(made.tok, &e))).and_then(
            |t| made.session.create_object(&t).map_err(|e| (token::rv_of(&e), format!("C_CreateObject: {}", ckr(&e)))),
        );
    match created {
        Ok(h) => {
            made.track(h, label);
            match made.tok.material_spki(h) {
                Ok(Some(s)) if s == spki => profile.yes(cap, Checked::Host, None),
                Ok(_) => profile.wrong(cap, "the object holds no key, or another".into()),
                Err(e) => made.undetermined.push(format!("no {cap} row: reading it back: {}", evidence(made.tok, &e))),
            }
        }
        Err((rv, why)) => profile.refused(&mut made.undetermined, cap, rv, why),
    }
}

/// The attributes of a public object at `locator` holding `value` (a public key's SPKI, a
/// certificate, a data object's bytes), as cakeys encodes them.
///
/// # Errors
///
/// What the host cannot encode: a locator or value cakeys has no attributes for.
/// A certificate or data object of the probe's, typed as keys.toml would type it (an X.509
/// certificate), so it parses as one.
fn public_object(class: Class) -> ObjectCfg {
    let certificate_type = (class == Class::Certificate).then(|| "CKC_X_509".to_owned());
    ObjectCfg { certificate_type, ..ObjectCfg::new(class, None) }
}

fn host_encoding(locator: &Locator, object: &ObjectCfg, value: &[u8]) -> Result<Vec<Attribute>> {
    let mut t = locator_attrs(locator)?;
    t.extend(public_object_attrs(Object::new(object)?, value)?);
    Ok(t)
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
    made: &mut Made,
    profile: &mut Draft,
    (key_type, on): (&KeyKind, &On),
    h: ObjectHandle,
    same: &dyn Fn(&[u8]) -> bool,
) {
    let cap = Capability::Export { way: Way::Host, key_type: key_type.clone(), on: on.clone() };
    let (mut refusals, mut rvs) = (Vec::new(), Vec::new());
    for (mech, name) in host_wraps() {
        match made.tok.extract(h, &mech) {
            Ok(plain) if same(&plain) => return profile.yes(cap, Checked::Host, Some(name.to_string())),
            Ok(_) => return profile.wrong(cap, format!("{name}: what arrived is another key")),
            Err(e) => {
                refusals.push(format!("{name}: {}", evidence(made.tok, &e)));
                rvs.push(e.rv());
            }
        }
    }
    // The module's no only when every way was its refusal.
    profile.refused(&mut made.undetermined, cap, worst(&rvs), refusals.join("; "));
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
    /// The key did not leave: why, and the return value.
    WrapRefused(String, Option<u64>),
    /// It left, but did not come back in here: why, and the return value.
    UnwrapRefused(String, Option<u64>),
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
            Err(e) => Trip::UnwrapRefused(format!("C_UnwrapKey: {}", ckr(&e)), token::rv_of(&e)),
        },
        Err(e) => Trip::WrapRefused(format!("C_WrapKey: {}", ckr(&e)), token::rv_of(&e)),
    };
    match way {
        Sealed::Direct(hash) => one(&Mechanism::RsaPkcsOaep(token::oaep_of(hash).0)),
        Sealed::RsaAes(hash) => {
            let oaep = rsa_aes(hash);
            match rsa_aes_key_wrap(&oaep) {
                Some(mech) => one(&mech),
                None => Trip::WrapRefused("this build cannot name CKM_RSA_AES_KEY_WRAP".into(), None),
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
            (Err(e), _) => return Trip::WrapRefused(format!("the KEK: {}", evidence(made.tok, &e)), e.rv()),
            (_, Err(e)) => return Trip::UnwrapRefused(format!("the KEK: {}", evidence(made.tok, &e)), e.rv()),
        };
    let kek = match session.generate_key(&Mechanism::AesKeyGen, &kek) {
        Ok(k) => SessionObject::new(session, k),
        Err(e) => return Trip::WrapRefused(format!("the KEK: C_GenerateKey: {}", ckr(&e)), token::rv_of(&e)),
    };
    let oaep = Mechanism::RsaPkcsOaep(token::oaep_of(hash).0);
    let (mut refusals, mut rvs) = (Vec::new(), Vec::new());
    for (kwp, name) in host_wraps() {
        let blob = match session.wrap_key(&kwp, kek.handle(), h) {
            Ok(blob) => blob,
            Err(e) => {
                refusals.push(format!("{name}: C_WrapKey: {}", ckr(&e)));
                rvs.push(token::rv_of(&e));
                continue;
            }
        };
        let kek_blob = match session.wrap_key(&oaep, tpub, kek.handle()) {
            Ok(blob) => blob,
            Err(e) => return Trip::WrapRefused(format!("the KEK: C_WrapKey: {}", ckr(&e)), token::rv_of(&e)),
        };
        let back = match session.unwrap_key(&oaep, tpriv, &kek_blob, &back) {
            Ok(k) => SessionObject::new(session, k),
            Err(e) => return Trip::UnwrapRefused(format!("the KEK: C_UnwrapKey: {}", ckr(&e)), token::rv_of(&e)),
        };
        return match session.unwrap_key(&kwp, back.handle(), &blob, template) {
            Ok(h2) => Trip::Unwrapped(h2),
            Err(e) => Trip::UnwrapRefused(format!("{name}: C_UnwrapKey: {}", ckr(&e)), token::rv_of(&e)),
        };
    }
    Trip::WrapRefused(refusals.join("; "), worst(&rvs))
}

/// The `export.sealed.*` and `unwrap.*` rows of the test key `h` (imported extractable): each
/// sealed way tried until one round-trips; `same` says the unwrapped key is the test key. Only
/// a round trip shows a blob holds the key, so a key that leaves but never comes back in leaves
/// the export unprobed. An unwrapped secret key's `CKA_VALUE_LEN` is not read: stock `SoftHSM`
/// leaves it 0 and the reference suites' carries the fix (upstream #925), so a row reading it
/// would describe one build only; `move.secret-unwrap` still says it.
fn export_sealed(made: &mut Made, profile: &mut Draft, key: &TestKey, transport: Transport) {
    let export = Capability::Export { way: Way::Sealed, key_type: key.key_type.clone(), on: key.on.clone() };
    let unwrap = Capability::Unwrap { key_type: key.key_type.clone(), on: key.on.clone() };
    let Some(transport) = transport else {
        made.undetermined.push(format!("no {export} or {unwrap} row: no RSA transport key"));
        return;
    };
    let mut ways = Ways::default();
    for way in sealed_ways(profile, key.secret) {
        let label = made.scratch.label();
        // The provider refusing the unwrap template is not the module's answer: nothing was
        // sent to C_WrapKey or C_UnwrapKey.
        let template = match (key.template)(&label) {
            Ok(t) => t,
            Err(e) => {
                ways.untried.push(format!("{}: {}", way.via(), evidence(made.tok, &e)));
                continue;
            }
        };
        match trip(made, way, transport, key.h, &template) {
            Trip::WrapRefused(why, rv) => {
                ways.wrap_refused.push(format!("{}: {why}", way.via()));
                ways.rvs.push(rv);
            }
            Trip::UnwrapRefused(why, rv) => {
                ways.unwrap_refused.push(format!("{}: {why}", way.via()));
                ways.rvs.push(rv);
            }
            Trip::Unwrapped(h2) => {
                made.track(h2, Some(&label));
                match (key.same)(made, h2) {
                    // A round trip on this one module: the blob is never decoded on the host, so
                    // another token taking it is not shown (review 2026-11-24 E-3).
                    Ok(()) => {
                        profile.yes(export, Checked::Unverified, Some(way.via()));
                        profile.yes(unwrap, Checked::Unverified, Some(way.via()));
                        return;
                    }
                    Err(e) => {
                        ways.unwrap_refused.push(format!(
                            "{}: not the key wrapped: {}",
                            way.via(),
                            evidence(made.tok, &e)
                        ));
                        // Another key is the host's finding; a check that failed, no finding.
                        if matches!(e, KmError::Conflict(_)) {
                            ways.wrong = true;
                        } else {
                            ways.rvs.push(e.rv());
                        }
                    }
                }
            }
        }
    }
    // The module's no only when each way failed by its refusal; the host's when none returned
    // a value and one came back as another key.
    let rv = worst(&ways.rvs);
    match ways.rows() {
        SealedRows::UnwrapNo(why) => {
            if ways.rvs.is_empty() && ways.wrong {
                profile.wrong(unwrap, why);
            } else {
                profile.refused(&mut made.undetermined, unwrap, rv, why);
            }
            made.undetermined.push(format!("no {export} row: it leaves, but never comes back in here"));
        }
        SealedRows::ExportNo(why) => profile.refused(&mut made.undetermined, export, rv, why),
        SealedRows::Undetermined(why) => {
            made.undetermined
                .push(format!("no {export} or {unwrap} row: the provider refuses the unwrap template: {why}"));
        }
    }
}

/// One test key on the token, for its export rows: what it is, whether it is a secret key (the
/// direct RSA-OAEP way is a secret key's), how the provider templates its unwrapped copy under a
/// label, and whether an unwrapped copy is the test key.
struct TestKey<'a> {
    key_type: &'a KeyKind,
    on: &'a On,
    h: ObjectHandle,
    secret: bool,
    template: &'a dyn Fn(&str) -> Result<Vec<Attribute>>,
    same: &'a dyn Fn(&Made, ObjectHandle) -> Result<()>,
}

/// Hand `key` to the host (`export.host.*`, checked by `host_same` on what arrived), then each
/// sealed way (`export.sealed.*`, `unwrap.*`).
fn exports(
    made: &mut Made,
    profile: &mut Draft,
    key: &TestKey,
    host_same: &dyn Fn(&[u8]) -> bool,
    transport: Transport,
) {
    export_host(made, profile, (key.key_type, key.on), key.h, host_same);
    export_sealed(made, profile, key, transport);
}

/// How each sealed way of one key failed.
#[derive(Default)]
struct Ways {
    /// The key did not leave: the module's `C_WrapKey` refusals.
    wrap_refused: Vec<String>,
    /// It left but did not come back in, or came back as another key.
    unwrap_refused: Vec<String>,
    /// Not tried: the provider refuses the unwrap template.
    untried: Vec<String>,
    /// The return values of the wrap and unwrap refusals, for [`worst`].
    rvs: Vec<Option<u64>>,
    /// Whether a way came back as another key: the host's finding.
    wrong: bool,
}

/// The rows the failed ways of [`Ways`] give.
#[derive(Debug, PartialEq)]
enum SealedRows {
    /// `unwrap.* = no`: some way left and failed to come back; the export is undetermined.
    UnwrapNo(String),
    /// `export.sealed.* = no`: every way was tried, and none left.
    ExportNo(String),
    /// Neither row: a way the provider would not template was never tried.
    Undetermined(String),
}

impl Ways {
    fn rows(&self) -> SealedRows {
        if !self.unwrap_refused.is_empty() {
            SealedRows::UnwrapNo(self.unwrap_refused.join("; "))
        } else if self.untried.is_empty() {
            SealedRows::ExportNo(self.wrap_refused.join("; "))
        } else {
            SealedRows::Undetermined(self.untried.join("; "))
        }
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
///
/// # Errors
///
/// `Unavailable` when the check itself fails: it takes `CKM_AES_ECB`, which the module may
/// lack while it imports AES keys, so the message names the check, not the import. `Conflict`
/// for another key's check value.
pub(super) fn same_aes(made: &Made, h: ObjectHandle, value: &[u8]) -> Result<()> {
    let token = made.session.encrypt(&Mechanism::AesEcb, h, &[0; 16]).map_err(|e| {
        KmError::Unavailable(
            format!("the host's check of the key needs C_Encrypt with CKM_AES_ECB, which fails: {}", ckr(&e)).into(),
        )
        .with_rv(token::rv_of(&e))
    })?;
    if Some(token) == host_kcv(value) {
        Ok(())
    } else {
        Err(KmError::Conflict("its check value is another key's".into()))
    }
}

/// Import an AES `value` with `C_CreateObject` (`import.CKK_AES.<bytes>`), extractable, then
/// export it each way.
fn import_secret(made: &mut Made, profile: &mut Draft, kt: Kt, value: &[u8], transport: Transport) {
    let n = u32::try_from(value.len()).unwrap_or_default();
    let on = On::Bytes(n);
    let key_kind = KeyKind::from(kt.name());
    let cap = Capability::Import { key_type: key_kind.clone(), on: on.clone() };
    let label = made.scratch.label();
    // Every template as the provider adjusts it for the verbs (`Provider::template`).
    let object = super::secrets::secret_object(kt, n);
    let (object, key_type) = match Object::new(&object).and_then(|o| Ok((o, token::key_type_of(o)?))) {
        Ok(t) => t,
        Err(e) => {
            made.undetermined.push(format!("no {cap} row: {}", evidence(made.tok, &e)));
            return;
        }
    };
    // What the key is checked by: AES by its host-computed check value; any other type by its
    // own commitment, which the export round trip then shows is the value that was imported.
    let commit = match kt {
        Kt::Aes => None,
        Kt::Des3 => Some(id::Commit::KcvEcb(id::BlockCipher::Des3)),
        _ => id::HmacHash::for_key_type(kt).map(id::Commit::Hmac),
    };
    let usage = match commit {
        Some(id::Commit::KcvEcb(_)) | None => Attribute::Encrypt(true),
        Some(_) => Attribute::Sign(true),
    };
    let base = vec![
        Attribute::Token(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(key_type),
        usage.clone(),
        Attribute::Sensitive(true),
        Attribute::Extractable(true),
    ];
    let probe_spec = spec(&[], &[]);
    let provider = made.tok.provider.clone();
    let adjusted = |label: &str, via, t| {
        let locator = Locator { label: Some(label.to_owned()), id: None };
        provider.adjusted(&Template::Import(Declared { object, spec: &probe_spec, locator: &locator }, via), t)
    };
    let h = match adjusted(&label, Via::CreateObject, base).and_then(|t| made.tok.create_secret(t, value)) {
        Ok(h) => h,
        Err(e) => {
            profile.refused(&mut made.undetermined, cap, e.rv(), refused(made.tok, &e));
            return;
        }
    };
    made.track(h, Some(&label));
    // The imported key's commitment, which a copy that comes back must give too.
    let checked = match commit {
        Some(c) => made.tok.commit(h, &object, c, "cakeys probe: import").map(Some).map_err(|e| ("commitment", e)),
        None => same_aes(made, h, value).map(|()| None).map_err(|e| ("check value", e)),
    };
    let first = match checked {
        Ok(v) => v,
        Err((what, e)) => {
            made.undetermined.push(format!("no {cap} row: imported, but its {what}: {}", evidence(made.tok, &e)));
            return;
        }
    };
    // AES is checked against the value the host knows; another type by its own commitment, which
    // the module computes alone (review 2026-11-24 E-3).
    let checked = if commit.is_none() { Checked::Host } else { Checked::Unverified };
    profile.yes(cap, checked, Some(PlaintextKind::CreateObject.name().into()));
    let template = |label: &str| {
        let t = vec![
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(key_type),
            usage.clone(),
        ];
        adjusted(label, Via::Unwrap, t)
    };
    let same = |m: &Made, h2| match (commit, &first) {
        (Some(c), Some(first)) => match m.tok.commit(h2, &object, c, "cakeys probe: import") {
            Ok(v) if &v == first => Ok(()),
            Ok(_) => Err(KmError::Conflict("its commitment is another key's".into())),
            Err(e) => Err(e),
        },
        _ => same_aes(m, h2, value),
    };
    let test_key = TestKey { key_type: &key_kind, on: &on, h, secret: true, template: &template, same: &same };
    exports(made, profile, &test_key, &|plain| plain == value, transport);
}

/// The secret key types, other than AES, whose import and export are probed, with the length
/// of the value each is imported at: a value whose bytes the host knows, so what leaves is
/// checked against it.
const OTHER_SECRETS: [(Kt, u32); 7] = [
    (Kt::GenericSecret, 32),
    (Kt::Sha1Hmac, 32),
    (Kt::Sha224Hmac, 32),
    (Kt::Sha256Hmac, 32),
    (Kt::Sha384Hmac, 48),
    (Kt::Sha512Hmac, 64),
    (Kt::Des3, 24),
];

/// A value of `n` bytes the host knows.
fn secret_value(n: u32) -> Vec<u8> {
    (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0).wrapping_mul(29).wrapping_add(7)).collect()
}

/// Create a certificate or a data object from its value (`create.CKO_*`), read back. In a
/// scratch slot, as SO into the slot.
fn create_public(made: &mut Made, profile: &mut Draft, class: Class, bytes: &[u8]) -> Result<()> {
    let object = public_object(class);
    let cap = Capability::Create { class: class.to_string(), key: None };
    let (loc, label) = made.locator();
    let mut t = vec![Attribute::Token(true)];
    match host_encoding(&loc, &object, bytes) {
        Ok(attrs) => t.extend(attrs),
        Err(e) => {
            made.undetermined.push(format!("no {cap} row: the host cannot encode it: {e}"));
            return Ok(());
        }
    }
    if class == Class::Data {
        t.push(Attribute::Private(false));
    }
    let probe_spec = spec(&[], &[]);
    let session = made.session;
    let on = Declared { object: Object::new(&object)?, spec: &probe_spec, locator: &loc };
    let created = made.tok.provider.adjusted(&Template::Object(on), t).and_then(|t| {
        made.tok.managing("the create probe", || {
            session.create_object(&t).map_err(|e| {
                KmError::Unsupported(format!("C_CreateObject: {}", ckr(&e)).into()).with_rv(token::rv_of(&e))
            })
        })
    });
    let h = match created {
        Ok(h) => h,
        Err(e) if so_login(&e) => return Err(e),
        Err(e) => {
            profile.refused(&mut made.undetermined, cap, e.rv(), evidence(made.tok, &e));
            return Ok(());
        }
    };
    made.track(h, label.as_ref());
    match made.session.get_attributes(h, &[AttributeType::Value]).as_deref() {
        Ok([Attribute::Value(v)]) if v == bytes => profile.yes(cap, Checked::Host, None),
        Ok(_) => profile.wrong(cap, "CKA_VALUE reads otherwise".into()),
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
                    assert_eq!(id::modulus_bits(&p.modulus), u64::from(*bits));
                }
                On::Item(curve) => assert_eq!(
                    id::KeyAlg::of_spki(&spki).unwrap().curve().map(cakeys_core::id::Curve::name),
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
        // The curves cakeys names without a test key: each named in the run's undetermined
        // list (review moves F5). A new curve without a fixture fails here until it has one or
        // is listed.
        assert_eq!(unfixtured_curves(), ["edwards448"]);
    }

    /// A way the provider will not template was never sent to the module: no `no` row from it,
    /// and no export `no` while it is untried. A wrong key unwrapped is an unwrap `no`, named
    /// as such (review moves F2).
    #[test]
    fn untried_ways_decide_no_row() {
        let ways = |wrap: &[&str], unwrap: &[&str], untried: &[&str]| Ways {
            wrap_refused: wrap.iter().map(|s| (*s).to_owned()).collect(),
            unwrap_refused: unwrap.iter().map(|s| (*s).to_owned()).collect(),
            untried: untried.iter().map(|s| (*s).to_owned()).collect(),
            rvs: Vec::new(),
            wrong: false,
        };
        assert_eq!(ways(&[], &[], &["a: refused"]).rows(), SealedRows::Undetermined("a: refused".into()));
        assert_eq!(ways(&["b: C_WrapKey"], &[], &["a: refused"]).rows(), SealedRows::Undetermined("a: refused".into()));
        assert_eq!(ways(&["b: C_WrapKey"], &[], &[]).rows(), SealedRows::ExportNo("b: C_WrapKey".into()));
        let wrong = "b: not the key wrapped: another key";
        assert_eq!(ways(&[], &[wrong], &["a: refused"]).rows(), SealedRows::UnwrapNo(wrong.into()));
    }

    /// What cakeys cannot encode is an error of the host's, which the probes record as
    /// undetermined rather than end the run with (review moves F1).
    #[test]
    fn the_host_encoding_fails_as_a_value() {
        let cert = public_object(Class::Certificate);
        let ok = Locator { label: Some("cakeys-probe-01".into()), id: None };
        assert!(host_encoding(&ok, &cert, CERTIFICATE).is_ok());
        let odd = Locator { label: None, id: Some("not hex".into()) };
        assert!(host_encoding(&odd, &cert, CERTIFICATE).is_err());
    }
}
