//! The import, create, export and unwrap probes (`docs/archive/CAPROBE_MIGRATION.md`). These
//! probes import fixed test keys from `fixtures/import` into the token in each way that the
//! module offers, and they export the keys in each way. The test keys are not secret, so a
//! profile that is generated again is identical byte for byte. The host checks every row as a
//! round trip: an imported private key must prove possession of the test key's public key, an
//! imported secret key must compute the test key's check value, and an exported key must be the
//! test key again.
//!
//! On a scratch token, the probe imports each key as extractable, so one key proves its import,
//! both of its exports, and the unwrap of what was exported. In a scratch slot (ykcs11), the
//! probe imports only private keys, as SO, because a PIV slot holds no secret key. At the end of
//! a slot run, the slot holds a newly generated P-256 key and the probe's mark certificate
//! ([`slot_mark`]). [`mark_slot`] writes that certificate over the placeholder certificate that
//! ykcs11 writes for every key it generates, because the next run's guard (`super::check_slot`)
//! refuses a slot that holds ykcs11's placeholder.

use super::{Checked, Created, Draft, Made, Target, ckr, evidence, refused, rsa_aes_key_wrap, so_login, spec, worst};
use cakeys_core::config::{Binding, Locator, Object, ObjectCfg};
use cakeys_core::migrate::Method;
use cakeys_core::migrate::OaepHash;
use cakeys_core::plaintext::{private_from_pkcs8, spki_of_pkcs8};
use cakeys_core::types::{KeyType as Kt, ObjectClass as Class};
use cakeys_core::{Check, KmError, Reason, Result, id};
use cakeys_pkcs11::provider::PlaintextKind;
use cakeys_pkcs11::token::{self, SessionObject, locator_attrs, public_object_attrs};
use cakeys_pkcs11::{Declared, SessionKey, Template, Topic, Via};
use cakeys_profile::{Capability, KeyKind, On, Way};
use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
use cryptoki::mechanism::{Mechanism, MechanismType};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};

macro_rules! fixture {
    ($file:literal) => {
        include_bytes!(concat!("../../fixtures/import/", $file))
    };
}

/// The test private keys as PKCS#8 DER, one for each curve that the host can read
/// (`cakeys_core::plaintext`).
const CURVE_KEYS: [(Kt, &str, &[u8]); 7] = [
    (Kt::Ec, "secp256r1", fixture!("ec-secp256r1.der")),
    (Kt::Ec, "secp384r1", fixture!("ec-secp384r1.der")),
    (Kt::Ec, "secp521r1", fixture!("ec-secp521r1.der")),
    (Kt::Ec, "secp256k1", fixture!("ec-secp256k1.der")),
    (Kt::Ec, "brainpoolP256r1", fixture!("ec-brainpoolP256r1.der")),
    (Kt::Ec, "brainpoolP384r1", fixture!("ec-brainpoolP384r1.der")),
    (Kt::EcEdwards, "edwards25519", fixture!("ec-edwards25519.der")),
];

/// The test RSA private keys as PKCS#8 DER, one for each size in [`super::RSA_SIZES`] that the
/// host can read. The rsa crate does not accept a public key shorter than 1024 bits or longer
/// than 8192 bits. cakeys therefore cannot identify a key of another size, and the probes import
/// no key of another size.
const RSA_KEYS: [(u32, &[u8]); 7] = [
    (1024, fixture!("rsa-1024.der")),
    (1536, fixture!("rsa-1536.der")),
    (2048, fixture!("rsa-2048.der")),
    (3072, fixture!("rsa-3072.der")),
    (4096, fixture!("rsa-4096.der")),
    (6144, fixture!("rsa-6144.der")),
    (8192, fixture!("rsa-8192.der")),
];

/// The test AES key values, one of each AES key length (16, 24 and 32 bytes).
pub(super) const AES_KEYS: [&[u8]; 3] = [fixture!("aes-16.key"), fixture!("aes-24.key"), fixture!("aes-32.key")];

/// A self-signed test certificate (`CN=cakeys-probe`) for the P-256 test key [`P256_KEY`]. The
/// create probe writes it ([`create_public`]).
pub(super) const CERTIFICATE: &[u8] = fixture!("certificate.der");

/// The P-256 test private key. It signed [`CERTIFICATE`], and [`slot_mark`] signs each mark
/// certificate with it.
const P256_KEY: &[u8] = fixture!("ec-secp256r1.der");

/// Returns the mark certificate that shows that the probe used a scratch slot. The mark is a copy
/// of [`CERTIFICATE`] (`CN=cakeys-probe`) in which the public key is replaced by `spki`, the
/// public key of the slot's key, and which the P-256 test key signs again. [`mark_slot`] writes
/// the mark into the slot at the end of a run. The next run's guard (`super::check_slot`) accepts
/// the mark as the only certificate of the probe's beside that key.
///
/// The p256 crate's ECDSA signature is deterministic (RFC 6979), so the guard builds the same
/// bytes again from the key that it finds in the slot. A mark therefore matches one key, not the
/// whole slot (review 2026-11-24 E-6: a fixed certificate kept matching a key that was put into
/// the slot later). Returns `None` when this function cannot encode a certificate that holds
/// `spki`.
pub(super) fn slot_mark(spki: &[u8]) -> Option<Vec<u8>> {
    use p256::ecdsa::signature::Signer as _;
    use p256::pkcs8::DecodePrivateKey as _;
    let (cert, _) = der_element(CERTIFICATE)?;
    let (tbs, rest) = der_element(der_contents(cert)?)?;
    let (algorithm, _) = der_element(rest)?;
    let own = id::cert_spki(CERTIFICATE).ok()?;
    let body = der_contents(tbs)?;
    let at = body.windows(own.len()).position(|w| w == own.as_slice())?;
    let tbs = der_tlv(0x30, &[&body[..at], spki, &body[at + own.len()..]].concat())?;
    let key = p256::ecdsa::SigningKey::from_pkcs8_der(P256_KEY).ok()?;
    let signature: p256::ecdsa::Signature = key.sign(&tbs);
    let bits = der_tlv(0x03, &[&[0][..], &signature.to_der().to_bytes()].concat())?;
    der_tlv(0x30, &[tbs, algorithm.to_vec(), bits].concat())
}

/// Splits `der` into its first complete DER element (with its tag and its length) and the bytes
/// that follow that element.
fn der_element(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (head, len) = match *der.get(1)? {
        n @ 0..=0x7f => (2, usize::from(n)),
        0x81 => (3, usize::from(*der.get(2)?)),
        0x82 => (4, usize::from(u16::from_be_bytes([*der.get(2)?, *der.get(3)?]))),
        _ => return None,
    };
    der.split_at_checked(head + len)
}

/// The contents of the DER element `tlv`.
fn der_contents(tlv: &[u8]) -> Option<&[u8]> {
    let head = match *tlv.get(1)? {
        0..=0x7f => 2,
        0x81 => 3,
        0x82 => 4,
        _ => return None,
    };
    tlv.get(head..)
}

/// Encodes a DER element with the tag `tag` and the contents `contents`. Returns `None` when
/// `contents` is 64 KiB or longer.
fn der_tlv(tag: u8, contents: &[u8]) -> Option<Vec<u8>> {
    let n = contents.len();
    let len = match u8::try_from(n) {
        Ok(b) if b < 0x80 => vec![b],
        Ok(b) => vec![0x81, b],
        Err(_) => [&[0x82][..], &u16::try_from(n).ok()?.to_be_bytes()].concat(),
    };
    Some([&[tag][..], &len, contents].concat())
}

/// The value of the data object that the create probe writes on a scratch token.
const DATA: &[u8] = b"cakeys probe: a data object";

/// One test private key to import: its object configuration and key type (as keys.toml names
/// them), its key type and its size or curve (as the profile's rows name them), and its PKCS#8
/// DER.
struct PrivateKey {
    object: ObjectCfg,
    kt: Kt,
    key_type: KeyKind,
    on: On,
    der: &'static [u8],
}

/// The RSA test key that the probe imports as the transport key of the sealed exports. The sealed
/// exports wrap each test key under this key. The host also holds this key's private half, so the
/// host can decode what the module wraps (review 2026-11-24 E-3).
const TRANSPORT_KEY: &[u8] = fixture!("rsa-2048.der");

/// The RSA key pair under which the sealed exports wrap each test key, and the private key with
/// which the host decodes the wrapped blobs. `host` is `None` when the pair is the key pair that
/// the wrap probes generated. The probe uses that pair when the token does not accept
/// [`TRANSPORT_KEY`], and the host cannot decode blobs that are wrapped under it.
struct Transport {
    public: ObjectHandle,
    private: ObjectHandle,
    host: Option<rsa::PrivateKey>,
}

/// Imports each test key in the way that the provider imports keys and, on a scratch token,
/// exports each key in each way. The sealed exports wrap toward the imported [`TRANSPORT_KEY`]
/// or, when the token does not accept that key, toward `generated`, the RSA key pair that the
/// wrap probes use.
///
/// # Errors
///
/// Returns the error of a failed SO login, which stops the probe in the same way that it stops
/// the generation probes.
pub(super) fn probe_moves(
    made: &mut Made,
    profile: &mut Draft,
    generated: Option<(ObjectHandle, ObjectHandle)>,
) -> Result<()> {
    let transport = match made.scratch.target {
        Target::Labels => host_transport(made)
            .or_else(|| generated.map(|(public, private)| Transport { public, private, host: None })),
        Target::Slot(_) => None,
    };
    let transport = transport.as_ref();
    let kind = made.tok.provider.plaintext_import().kind();
    if kind == PlaintextKind::Tpm2Ptool {
        // tpm2_ptool writes the module's store, and the token that is open here reads that store
        // only after the token is opened again. The probe therefore writes no import row. A
        // `C_CreateObject` import would test a path that the provider does not take, so its
        // refusal would be a wrong row.
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
        // The probe creates no `CKO_DATA` object in a PIV slot, because ykcs11's data objects are
        // the device's own PIV data objects (CHUID, CCC). The probe does write the slot's
        // certificate twice: `create_public` above wrote the test certificate `CERTIFICATE`, and
        // `mark_slot` below writes the probe's mark certificate (`slot_mark`). Between the two,
        // the probe generates a P-256 key in the slot again, and ykcs11 writes its placeholder
        // certificate for that key, which the mark certificate then replaces.
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

/// Imports [`TRANSPORT_KEY`] as the transport key of the sealed exports. Its public half wraps
/// each test key, and its private half unwraps it. Returns `None`, and adds a line to the run's
/// undetermined list, when the token does not accept the key.
fn host_transport(made: &mut Made) -> Option<Transport> {
    let mut import = || -> Result<Transport> {
        use rsa::pkcs8::DecodePrivateKey as _;
        let host = rsa::PrivateKey::from_pkcs8_der(TRANSPORT_KEY)
            .map_err(|e| KmError::Unsupported(format!("the host reads no RSA test key: {e}").into()))?;
        let object = ObjectCfg { modulus_bits: Some(2048), ..ObjectCfg::new(Class::PrivateKey, Some(Kt::Rsa)) };
        let o = Object::new(&object)?;
        let spki = id::spki_canonical(&spki_of_pkcs8(TRANSPORT_KEY)?)?;
        let parts = private_from_pkcs8(TRANSPORT_KEY, Kt::Rsa, None)?;
        let (loc, label) = made.locator();
        let usage = spec(&["CKA_DECRYPT", "CKA_UNWRAP"], &["CKA_ENCRYPT", "CKA_WRAP"]);
        let declared = Declared { object: o, spec: &usage, locator: &loc };
        let mut t = vec![Attribute::Token(true), Attribute::Encrypt(true), Attribute::Wrap(true)];
        t.extend(host_encoding(&loc, &ObjectCfg { class: Class::PublicKey, ..object.clone() }, &spki)?);
        let t = made.tok.provider.adjusted(&Template::PublicHalf(declared), t)?;
        let public = made.session.create_object(&t).map_err(|e| {
            made.tok.refused_for(Topic::Create, &e, format!("its public half: C_CreateObject: {}", ckr(&e)))
        })?;
        made.track(public, label.as_ref());
        let mut t = vec![
            Attribute::Token(true),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::RSA),
            Attribute::Decrypt(true),
            Attribute::Unwrap(true),
            Attribute::Sensitive(true),
        ];
        t.extend(locator_attrs(&loc)?);
        let t = made.tok.provider.adjusted(&Template::Import(declared, Via::CreateObject), t)?;
        let private = made.tok.create_private(o, t, &parts)?;
        made.track(private, label.as_ref());
        Ok(Transport { public, private, host: Some(host) })
    };
    match import() {
        Ok(t) => Some(t),
        Err(e) => {
            let why = evidence(made.tok, &e);
            made.undetermined.push(format!(
                "the sealed exports wrap toward the wrap probes' RSA key, whose blobs the host cannot decode: the \
                 RSA test key is not imported: {why}"
            ));
            None
        }
    }
}

/// Marks the scratch slot as the probe's slot. For each key that [`slot_keys`] returns, this
/// function writes the probe's mark certificate ([`slot_mark`]) over the placeholder certificate
/// that ykcs11 wrote when the probe last generated a key. ykcs11 writes that placeholder for every
/// key that it generates, a real key included, so the placeholder does not distinguish a probe's
/// slot from a slot that holds a real key. The next run's guard (`super::check_slot`) therefore
/// accepts only the mark certificates, and only beside the keys that they name (review 2026-11-23
/// D-1; review 2026-11-24 E-6). When the marking fails, the next run refuses the slot until
/// someone empties it, and this run adds a line that says so to its undetermined list.
fn mark_slot(made: &mut Made) -> Result<()> {
    let object = public_object(Class::Certificate);
    let (loc, _) = made.locator();
    let (probe_spec, session) = (spec(&[], &[]), made.session);
    let mark = |spki: &[u8]| {
        let mark = slot_mark(spki)
            .ok_or_else(|| KmError::Unsupported("the probe's certificate cannot carry the slot's key".into()))?;
        let mut t = vec![Attribute::Token(true)];
        t.extend(host_encoding(&loc, &object, &mark)?);
        let on = Declared { object: Object::new(&object)?, spec: &probe_spec, locator: &loc };
        let t = made.tok.provider.adjusted(&Template::Object(on), t)?;
        made.tok.managing("marking the scratch slot", || {
            session
                .create_object(&t)
                .map_err(|e| made.tok.refused_for(Topic::Create, &e, format!("C_CreateObject: {}", ckr(&e))))
        })
    };
    let marked = slot_keys(made).and_then(|keys| keys.iter().try_for_each(|k| mark(k).map(drop)));
    match marked {
        Ok(()) => Ok(()),
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

/// Returns the public keys for which [`mark_slot`] writes mark certificates. These are the public
/// keys of the slot's public key objects that no mark certificate names yet, except the probe's
/// own test keys ([`test_keys`]), which the guard accepts without a mark. A PIV slot holds one
/// such key, and a module that keeps every key it was given under one `CKA_ID` can hold several.
/// When the slot holds no such key and no mark, this function returns the P-256 test key's public
/// key, so that the slot still gets one mark. That happens with a module whose SO generates no
/// key, where the slot holds only what the import probes put there.
fn slot_keys(made: &Made) -> Result<Vec<Vec<u8>>> {
    let Target::Slot(id) = &made.scratch.target else {
        return Err(KmError::Validation("no scratch slot".into()));
    };
    let find = |class| {
        made.session.find_objects(&[Attribute::Class(class), Attribute::Id(id.clone())]).map_err(|e| {
            made.tok.refused_for(Topic::Create, &e, format!("finding the slot's keys: C_FindObjects: {}", ckr(&e)))
        })
    };
    let marked: Vec<Vec<u8>> = find(ObjectClass::CERTIFICATE)?
        .into_iter()
        .filter_map(|h| match made.session.get_attributes(h, &[AttributeType::Value]).ok()?.pop()? {
            Attribute::Value(der) => id::cert_spki(&der).ok().filter(|k| slot_mark(k).as_ref() == Some(&der)),
            _ => None,
        })
        .collect();
    let (tested, mut keys) = (test_keys(), Vec::new());
    for h in find(ObjectClass::PUBLIC_KEY)? {
        // A key whose public key the host cannot read (X25519, for which cakeys encodes no SPKI)
        // gets no mark. The guard accepts such a key when the slot also holds keys whose public
        // keys it can read.
        let Ok(Some(spki)) = made.tok.material_spki(h) else { continue };
        if !marked.contains(&spki) && !tested.contains(&spki) && !keys.contains(&spki) {
            keys.push(spki);
        }
    }
    if keys.is_empty() && marked.is_empty() {
        keys.push(id::cert_spki(CERTIFICATE)?);
    }
    Ok(keys)
}

/// Returns the canonical public keys of the probe's test keys ([`CURVE_KEYS`], [`RSA_KEYS`]). The
/// private halves of these keys are committed in the repository, so a slot that holds one of them
/// does not hold a real key.
pub(super) fn test_keys() -> Vec<Vec<u8>> {
    let ders = CURVE_KEYS.iter().map(|(_, _, der)| *der).chain(RSA_KEYS.iter().map(|(_, der)| *der));
    ders.filter_map(|der| spki_of_pkcs8(der).and_then(|s| id::spki_canonical(&s)).ok()).collect()
}

/// Returns the curves that cakeys names (`id::Curve::ALL`) for which [`CURVE_KEYS`] has no test
/// key. The probe writes no import row for these curves, and the run lists them in its
/// undetermined list.
fn unfixtured_curves() -> Vec<&'static str> {
    id::Curve::ALL.iter().map(|c| c.name()).filter(|c| !CURVE_KEYS.iter().any(|(_, k, _)| k == c)).collect()
}

/// Returns the private keys that the probes import: one for each curve, and then one for each
/// RSA size in `rsa_sizes` (the sizes up to the largest one that the run requested).
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
    /// Returns the locator for the next object: a new probe label on a scratch token, or the
    /// scratch slot's `CKA_ID`. Also returns the label, if there is one, so that the caller can
    /// track what it makes under that label.
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

/// Imports `key` in the way that the provider imports keys (the `import.*` row), and then exports
/// it in each way. On a scratch token, this function first creates the key's public half (the
/// `create.CKO_PUBLIC_KEY.*` row). It skips that step in a PIV slot, because PIV derives the
/// public key from the private key.
fn import_private(
    made: &mut Made,
    profile: &mut Draft,
    key: &PrivateKey,
    kind: PlaintextKind,
    transport: Option<&Transport>,
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
    // A failure of cakeys' own encoding is not an answer from the module, so it never ends the
    // probe.
    let at = match locator_attrs(&loc) {
        Ok(at) => at,
        Err(e) => {
            made.undetermined.push(format!("no {cap} row: the host cannot encode its locator: {e}"));
            return Ok(());
        }
    };
    // The provider adjusts every template here in the same way as it does for the verbs
    // (`Provider::template`).
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
    // On a scratch token, the key is imported as extractable, so that the same key also proves
    // the exports. If the module refuses an extractable key, the probe imports the key without
    // `CKA_EXTRACTABLE` and does not probe its exports.
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
    match Checked::verified(made.tok.prove_binding(h, object, &spki, Binding::PopSign)) {
        Ok(checked) => profile.yes(cap, checked, Some(kind.name().into())),
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
    let host_same = |plain: &[u8]| {
        spki_of_pkcs8(plain).and_then(|s| id::spki_canonical(&s)).ok().and_then(|s| Checked::same(&s, &spki))
    };
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
    let same = |m: &Made, h2| Checked::verified(m.tok.prove_binding(h2, object, &spki, Binding::PopSign));
    let test_key = TestKey {
        key_type: &key.key_type,
        on: &key.on,
        h,
        secret: false,
        template: &template,
        same: &same,
        host_same: &host_same,
    };
    exports(made, profile, &test_key, transport);
    Ok(())
}

/// Creates the public half of `key` from its canonical `spki` under the locator of `on`, and
/// reads it back (the `create.CKO_PUBLIC_KEY.*` row). When the host cannot encode the locator or
/// the public key, the row is undetermined, because the failure is in cakeys' own encoding and
/// is not an answer from the module.
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
            match made.tok.material_spki(h).map(|s| s.and_then(|s| Checked::same(s.as_slice(), spki))) {
                Ok(Some(checked)) => profile.yes(cap, checked, None),
                Ok(None) => profile.wrong(cap, "the object holds no key, or another".into()),
                Err(e) => made.undetermined.push(format!("no {cap} row: reading it back: {}", evidence(made.tok, &e))),
            }
        }
        Err((rv, why)) => profile.refused(&mut made.undetermined, cap, rv, why),
    }
}

/// Returns the object configuration of a certificate or a data object that the probe creates. A
/// certificate gets the certificate type `CKC_X_509`, as keys.toml would declare it, so that cakeys
/// parses the certificate's value as an X.509 certificate.
fn public_object(class: Class) -> ObjectCfg {
    let certificate_type = (class == Class::Certificate).then(|| "CKC_X_509".to_owned());
    ObjectCfg { certificate_type, ..ObjectCfg::new(class, None) }
}

/// Returns the attributes, as cakeys encodes them, of a public object at `locator` that holds
/// `value` (a public key's SPKI, a certificate, or a data object's bytes).
///
/// # Errors
///
/// Returns an error when the host cannot encode the object: when cakeys has no attributes for the
/// locator or the value.
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

/// Returns the RFC 5649 key-wrap mechanisms with which `Token::extract` hands a key to the host:
/// `CKM_AES_KEY_WRAP_PAD`, and also `CKM_AES_KEY_WRAP_KWP` when this build has the `kwp` feature.
/// The probes try each mechanism whether or not the module lists it, as every probe does.
fn host_wraps() -> Vec<(Mechanism<'static>, MechanismType)> {
    let wraps = std::iter::once((Mechanism::AesKeyWrapPad, MechanismType::AES_KEY_WRAP_PAD));
    #[cfg(feature = "kwp")]
    let wraps = wraps.chain(std::iter::once((Mechanism::AesKeyWrapKwp, MechanismType::AES_KEY_WRAP_KWP)));
    wraps.collect()
}

/// Writes the `export.host.*` row. The function hands `h` to the host with `Token::extract` (an
/// RFC 5649 key wrap), and the row is yes when the key that arrives is the test key (`same`).
fn export_host(
    made: &mut Made,
    profile: &mut Draft,
    (key_type, on): (&KeyKind, &On),
    h: ObjectHandle,
    same: &dyn Fn(&[u8]) -> Option<Checked>,
) {
    let cap = Capability::Export { way: Way::Host, key_type: key_type.clone(), on: on.clone() };
    let (mut refusals, mut rvs) = (Vec::new(), Vec::new());
    for (mech, name) in host_wraps() {
        match made.tok.extract(h, &mech) {
            Ok(plain) => {
                return match same(&plain) {
                    Some(checked) => profile.yes(cap, checked, Some(name.to_string())),
                    None => profile.wrong(cap, format!("{name}: what arrived is another key")),
                };
            }
            Err(e) => {
                refusals.push(format!("{name}: {}", evidence(made.tok, &e)));
                rvs.push(e.rv());
            }
        }
    }
    // The row is the module's no only when the module itself refused every mechanism; `worst`
    // picks the return value that classifies all the failures.
    profile.refused(&mut made.undetermined, cap, worst(&rvs), refusals.join("; "));
}

/// Returns the parameters of `CKM_RSA_AES_KEY_WRAP`: RSA-OAEP with the hash `hash`, and MGF1
/// with the same hash.
fn rsa_aes(hash: OaepHash) -> PkcsOaepParams<'static> {
    let (h, mgf) = match hash {
        OaepHash::Sha1 => (MechanismType::SHA1, PkcsMgfType::MGF1_SHA1),
        OaepHash::Sha256 => (MechanismType::SHA256, PkcsMgfType::MGF1_SHA256),
    };
    PkcsOaepParams::new(h, mgf, PkcsOaepSource::empty())
}

/// One sealed way to export a key. Each way is one of the ways in which camigrate moves a key to
/// another token (docs/CAMIGRATE.md D2).
#[derive(Clone, Copy)]
enum Sealed {
    /// The key is wrapped directly under the transport key with RSA-OAEP. Only a secret key is
    /// exported this way.
    Direct(OaepHash),
    /// A new AES KEK is wrapped under the transport key with RSA-OAEP, and the key is wrapped
    /// under the KEK with RFC 5649.
    Composed(OaepHash),
    /// The same two wraps in one `CKM_RSA_AES_KEY_WRAP` call, for a module that has no RFC 5649
    /// mechanism (AWS `CloudHSM` \[run\]).
    RsaAes(OaepHash),
}

impl Sealed {
    /// Returns the row's `via` value: camigrate's name for the method, followed by
    /// `CKM_RSA_AES_KEY_WRAP` when that mechanism performs the composed method.
    fn via(self) -> String {
        match self {
            Sealed::Direct(h) => Method::RsaOaep(h).name(),
            Sealed::Composed(h) => Method::RsaOaepAesKwp(h).name(),
            Sealed::RsaAes(h) => format!("{} by CKM_RSA_AES_KEY_WRAP", Method::RsaOaepAesKwp(h).name()),
        }
    }
}

/// Returns the sealed ways in camigrate's order: the direct RSA-OAEP wrap (for a secret key
/// only), then the composed method, and then `CKM_RSA_AES_KEY_WRAP`. The direct and the composed
/// ways use only the OAEP hashes with which a wrap completed a round trip in
/// [`super::probe_wrapping`].
fn sealed_ways(profile: &Draft, secret: bool) -> Vec<Sealed> {
    let oaep: Vec<OaepHash> = [OaepHash::Sha256, OaepHash::Sha1]
        .into_iter()
        .filter(|h| profile.wrap_oaep.iter().flatten().any(|w| w == token::oaep_of(*h).1))
        .collect();
    let direct = oaep.iter().filter(|_| secret).map(|h| Sealed::Direct(*h));
    let composed = oaep.iter().map(|h| Sealed::Composed(*h));
    direct.chain(composed).chain([Sealed::RsaAes(OaepHash::Sha256), Sealed::RsaAes(OaepHash::Sha1)]).collect()
}

/// The outcome of one sealed round trip.
enum Trip {
    /// The wrap failed, so the key did not leave the token: the reason, and the return value.
    WrapRefused(String, Option<u64>),
    /// The key left the token as this [`Wrapped`] value. The result is the handle of the
    /// unwrapped copy, or the reason and the return value when the unwrap failed.
    Wrapped(Wrapped, std::result::Result<ObjectHandle, (String, Option<u64>)>),
}

/// What left the token in one sealed way. `key` is the wrapped key: the RSA-OAEP blob, the single
/// `CKM_RSA_AES_KEY_WRAP` blob, or, in the composed method, the RFC 5649 blob under the KEK. `kek`
/// is the KEK wrapped with RSA-OAEP, and it is set in the composed method only.
struct Wrapped {
    kek: Option<Vec<u8>>,
    key: Vec<u8>,
}

/// Wraps `h` toward the transport key `t` in the way `way`, and then unwraps the blob on the same
/// token under `template`.
fn trip(made: &Made, way: Sealed, t: &Transport, h: ObjectHandle, template: &[Attribute]) -> Trip {
    let session = made.session;
    let one = |mech: &Mechanism| match session.wrap_key(mech, t.public, h) {
        Ok(blob) => {
            let back = session
                .unwrap_key(mech, t.private, &blob, template)
                .map_err(|e| (format!("C_UnwrapKey: {}", ckr(&e)), token::rv_of(&e)));
            Trip::Wrapped(Wrapped { kek: None, key: blob }, back)
        }
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
        Sealed::Composed(hash) => composed(made, hash, t, h, template),
    }
}

/// Runs camigrate's composed method. The function generates a new AES-256 KEK, wraps the key under
/// the KEK with RFC 5649, and wraps the KEK under the transport key with RSA-OAEP. It then unwraps
/// the KEK and the key in the same way. Both KEKs (the generated one and the unwrapped one) are
/// session objects.
fn composed(made: &Made, hash: OaepHash, t: &Transport, h: ObjectHandle, template: &[Attribute]) -> Trip {
    let session = made.session;
    // camigrate's own KEK templates (`templates::session`), as the provider adjusts them.
    let kek = match made.tok.session_template(SessionKey::ExportKek) {
        Ok(kek) => kek,
        Err(e) => return Trip::WrapRefused(format!("the KEK: {}", evidence(made.tok, &e)), e.rv()),
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
        let kek_blob = match session.wrap_key(&oaep, t.public, kek.handle()) {
            Ok(blob) => blob,
            Err(e) => return Trip::WrapRefused(format!("the KEK: C_WrapKey: {}", ckr(&e)), token::rv_of(&e)),
        };
        let back = made
            .tok
            .session_template(SessionKey::ImportKek)
            .map_err(|e| (format!("the KEK: {}", evidence(made.tok, &e)), e.rv()))
            .and_then(|back| {
                session
                    .unwrap_key(&oaep, t.private, &kek_blob, &back)
                    .map(|k| SessionObject::new(session, k))
                    .map_err(|e| (format!("the KEK: C_UnwrapKey: {}", ckr(&e)), token::rv_of(&e)))
            })
            .and_then(|back| {
                session
                    .unwrap_key(&kwp, back.handle(), &blob, template)
                    .map_err(|e| (format!("{name}: C_UnwrapKey: {}", ckr(&e)), token::rv_of(&e)))
            });
        return Trip::Wrapped(Wrapped { kek: Some(kek_blob), key: blob }, back);
    }
    Trip::WrapRefused(refusals.join("; "), worst(&rvs))
}

/// Writes the `export.sealed.*` and `unwrap.*` rows of the test key `key.h`, which was imported
/// as extractable. The function tries each sealed way until the host decodes the wrapped blob to
/// the test key (`host_same`) and the unwrapped copy is the test key (`same`).
///
/// The export row is a yes only when the host recovers the key from a blob. It is a no by the
/// host's finding when the host recovers the key from none of the blobs, because another token
/// reads only the standard encoding (review 2026-11-24 E-3). The unwrap row is a yes checked by
/// the host only for a blob that the host decoded. A yes that rests only on a round trip, or on
/// the generated transport key that the host cannot decode with, is unverified: only the module
/// says that it worked. Only a round trip shows that a blob can be unwrapped again, so a key that
/// leaves the token but never comes back makes the unwrap row a no.
///
/// The function does not read the `CKA_VALUE_LEN` of an unwrapped secret key. Stock `SoftHSM`
/// leaves it at 0, and the `SoftHSM` of the reference suites carries the fix (upstream #925), so
/// a row based on it would describe only one build. The hand-written claim `move.secret-unwrap`
/// still records that defect.
fn export_sealed(made: &mut Made, profile: &mut Draft, key: &TestKey, transport: Option<&Transport>) {
    let export = Capability::Export { way: Way::Sealed, key_type: key.key_type.clone(), on: key.on.clone() };
    let unwrap = Capability::Unwrap { key_type: key.key_type.clone(), on: key.on.clone() };
    let Some(transport) = transport else {
        made.undetermined.push(format!("no {export} or {unwrap} row: no RSA transport key"));
        return;
    };
    let mut ways = Ways::default();
    for way in sealed_ways(profile, key.secret) {
        let label = made.scratch.label();
        // When the provider refuses the unwrap template, that is not the module's answer,
        // because nothing was sent to C_WrapKey or C_UnwrapKey.
        let template = match (key.template)(&label) {
            Ok(t) => t,
            Err(e) => {
                ways.untried.push(format!("{}: {}", way.via(), evidence(made.tok, &e)));
                continue;
            }
        };
        let (wrapped, unwrapped) = match trip(made, way, transport, key.h, &template) {
            Trip::WrapRefused(why, rv) => {
                ways.wrap_refused.push(format!("{}: {why}", way.via()));
                ways.rvs.push(rv);
                continue;
            }
            Trip::Wrapped(wrapped, unwrapped) => (wrapped, unwrapped),
        };
        let host = transport.host.as_ref().map(|k| host_decode(way, &wrapped, k).and_then(|p| (key.host_same)(&p)));
        match host {
            Some(Some(checked)) => {
                ways.decoded.get_or_insert_with(|| (way.via(), checked));
            }
            Some(None) => ways.undecoded.push(way.via()),
            None => {}
        }
        match unwrapped {
            Err((why, rv)) => {
                ways.unwrap_refused.push(format!("{}: {why}", way.via()));
                ways.rvs.push(rv);
            }
            Ok(h2) => {
                made.track(h2, Some(&label));
                match (key.same)(made, h2) {
                    // When the host decoded the blob, the key check decides the row. When only
                    // the module's round trip shows the unwrap, the yes is unverified.
                    Ok(checked) if matches!(host, Some(Some(_))) => {
                        ways.back = Some((way.via(), checked));
                        break;
                    }
                    Ok(_) => {
                        ways.back.get_or_insert_with(|| (way.via(), Checked::unverified()));
                    }
                    Err(e) => {
                        ways.unwrap_refused.push(format!(
                            "{}: not the key wrapped: {}",
                            way.via(),
                            evidence(made.tok, &e)
                        ));
                        // A `Conflict` means that the copy is another key, which is the host's
                        // finding. Any other error means that the check itself failed, which is
                        // not a finding.
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
    sealed_rows(made, profile, (export, unwrap), ways, transport.host.is_some());
}

/// Writes the rows from what [`export_sealed`] found in `ways`. `host` is true when the host held
/// the transport key's private key.
fn sealed_rows(
    made: &mut Made,
    profile: &mut Draft,
    (export, unwrap): (Capability, Capability),
    ways: Ways,
    host: bool,
) {
    // The export row is the host's yes, the host's no, or, when the host has no transport
    // private key, an unverified yes from the module's round trip.
    let exported = ways.decoded.is_some() || (ways.back.is_some() && !host) || !ways.undecoded.is_empty();
    match (&ways.decoded, &ways.back) {
        (Some((via, checked)), _) => profile.yes(export.clone(), *checked, Some(via.clone())),
        (None, Some((via, _))) if !host => {
            profile.yes(export.clone(), Checked::unverified(), Some(via.clone()));
        }
        (None, _) if !ways.undecoded.is_empty() => profile.wrong(
            export.clone(),
            format!("the host decodes none of what it wraps to the key: {}", ways.undecoded.join("; ")),
        ),
        (None, _) => (),
    }
    // The unwrap row is a yes as the key check decides when the host decoded the blob, and an
    // unverified yes when only the module's round trip shows the unwrap. It is the module's no
    // only when the module refused every way. It is the host's no when no way failed with a
    // return value and one way came back as another key.
    if let Some((via, checked)) = ways.back {
        return profile.yes(unwrap, checked, Some(via));
    }
    let rv = worst(&ways.rvs);
    match ways.rows() {
        SealedRows::UnwrapNo(why) => {
            if ways.rvs.is_empty() && ways.wrong {
                profile.wrong(unwrap, why);
            } else {
                profile.refused(&mut made.undetermined, unwrap, rv, why);
            }
            if !exported {
                made.undetermined.push(format!("no {export} row: it leaves, but never comes back in here"));
            }
        }
        SealedRows::ExportNo(why) if !exported => {
            profile.refused(&mut made.undetermined, export, rv, why);
        }
        SealedRows::ExportNo(_) => {}
        SealedRows::Undetermined(why) => {
            made.undetermined
                .push(format!("no {export} or {unwrap} row: the provider refuses the unwrap template: {why}"));
        }
    }
}

/// Decodes on the host, with the transport private key `key`, what the module wrapped in the way
/// `way`. Returns the key's encoding (a secret key's value, or a private key's PKCS#8), or `None`
/// when the blob is not in the standard encoding (RFC 8017 OAEP, and RFC 5649 under the KEK) that
/// camigrate and another token read.
fn host_decode(way: Sealed, wrapped: &Wrapped, key: &rsa::PrivateKey) -> Option<Vec<u8>> {
    use aes_kw::cipher::KeyInit as _;
    let oaep = |hash, blob: &[u8]| match hash {
        OaepHash::Sha1 => key.decrypt(rsa::Oaep::<sha1::Sha1>::new(), blob).ok(),
        OaepHash::Sha256 => key.decrypt(rsa::Oaep::<sha2::Sha256>::new(), blob).ok(),
    };
    let kwp = |kek: &[u8], blob: &[u8]| {
        let mut out = vec![0u8; blob.len()];
        let n = match kek.len() {
            16 => aes_kw::KwpAes128::new_from_slice(kek).ok()?.unwrap_key(blob, &mut out).ok()?.len(),
            24 => aes_kw::KwpAes192::new_from_slice(kek).ok()?.unwrap_key(blob, &mut out).ok()?.len(),
            32 => aes_kw::KwpAes256::new_from_slice(kek).ok()?.unwrap_key(blob, &mut out).ok()?.len(),
            _ => return None,
        };
        out.truncate(n);
        Some(out)
    };
    match (way, &wrapped.kek) {
        (Sealed::Direct(hash), None) => oaep(hash, &wrapped.key),
        (Sealed::Composed(hash), Some(kek)) => kwp(&oaep(hash, kek)?, &wrapped.key),
        // PKCS#11 §2.1.21: the blob is the KEK wrapped with RSA-OAEP, which is as long as the
        // modulus, followed by the key wrapped under the KEK.
        (Sealed::RsaAes(hash), None) => {
            let k = rsa::traits::PublicKeyParts::size(key);
            let (kek, blob) = wrapped.key.split_at_checked(k)?;
            kwp(&oaep(hash, kek)?, blob)
        }
        _ => None,
    }
}

/// One test key on the token, with what its export rows need: its key type and its size or curve,
/// its handle, and whether it is a secret key (only a secret key uses the direct RSA-OAEP way).
/// `template` returns the provider's template for an unwrapped copy under a label. `same` checks
/// whether an unwrapped copy is the test key, and its result says whether the host or only the
/// module's commitment checked it. `host_same` checks whether what the host decoded is the test
/// key.
struct TestKey<'a> {
    key_type: &'a KeyKind,
    on: &'a On,
    h: ObjectHandle,
    secret: bool,
    template: &'a dyn Fn(&str) -> Result<Vec<Attribute>>,
    same: &'a dyn Fn(&Made, ObjectHandle) -> Result<Checked>,
    host_same: &'a dyn Fn(&[u8]) -> Option<Checked>,
}

/// Exports `key` to the host (the `export.host.*` row, which `host_same` checks on what arrives),
/// and then in each sealed way (the `export.sealed.*` and `unwrap.*` rows).
fn exports(made: &mut Made, profile: &mut Draft, key: &TestKey, transport: Option<&Transport>) {
    export_host(made, profile, (key.key_type, key.on), key.h, key.host_same);
    export_sealed(made, profile, key, transport);
}

/// The outcomes of the sealed ways of one key: how each way failed, and what the host decoded.
#[derive(Default)]
struct Ways {
    /// The ways in which the key did not leave the token: the module's `C_WrapKey` refusals.
    wrap_refused: Vec<String>,
    /// The ways in which the key left the token but did not come back, or came back as another
    /// key.
    unwrap_refused: Vec<String>,
    /// The ways that the probe did not try, because the provider refused the unwrap template.
    untried: Vec<String>,
    /// The return values of the wrap and unwrap refusals, for [`worst`].
    rvs: Vec<Option<u64>>,
    /// Whether a way came back as another key, which is the host's finding.
    wrong: bool,
    /// The first way whose blob the host decoded to the test key, and how the host checked it.
    decoded: Option<(String, Checked)>,
    /// The ways whose blob the host decoded to no key or to another key.
    undecoded: Vec<String>,
    /// The first way whose unwrapped copy is the test key, and what checked that: the key check
    /// when the host decoded the blob, and nothing outside the module otherwise.
    back: Option<(String, Checked)>,
}

/// The rows that the failed ways in [`Ways`] produce.
#[derive(Debug, PartialEq)]
enum SealedRows {
    /// `unwrap.* = no`: a way left the token and failed to come back. The export row is
    /// undetermined.
    UnwrapNo(String),
    /// `export.sealed.* = no`: the probe tried every way, and the key left the token in none of
    /// them.
    ExportNo(String),
    /// Neither row: the probe never tried a way, because the provider refused its template.
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

/// Returns the check value of the AES key `value`: the zero block encrypted under the key (like
/// `kcv-ecb`, but without the label).
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

/// Checks that the AES key `h` computes the check value of `value`.
///
/// # Errors
///
/// Returns `Unavailable` when the check itself fails. The check needs `CKM_AES_ECB`, which a
/// module can lack even when it imports AES keys, so the message names the check, not the import.
/// Returns `Conflict` when the check value is another key's.
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
        Err(KmError::Conflict(Reason::check(Check::ProbeSameKey, "its check value is another key's")))
    }
}

/// Imports `value` as an extractable secret key of the type `kt` with `C_CreateObject` (the
/// `import.<key type>.<bytes>` row), and then exports it in each way. `kt` is AES or one of
/// [`OTHER_SECRETS`].
fn import_secret(made: &mut Made, profile: &mut Draft, kt: Kt, value: &[u8], transport: Option<&Transport>) {
    let n = u32::try_from(value.len()).unwrap_or_default();
    let on = On::Bytes(n);
    let key_kind = KeyKind::from(kt.name());
    let cap = Capability::Import { key_type: key_kind.clone(), on: on.clone() };
    let label = made.scratch.label();
    // The provider adjusts every template here in the same way as it does for the verbs
    // (`Provider::template`).
    let object = super::secrets::secret_object(kt, n);
    let (object, key_type) = match Object::new(&object).and_then(|o| Ok((o, token::key_type_of(o)?))) {
        Ok(t) => t,
        Err(e) => {
            made.undetermined.push(format!("no {cap} row: {}", evidence(made.tok, &e)));
            return;
        }
    };
    // An AES key is checked by a check value that the host computes. A key of any other type is
    // checked by its own commitment, and the export round trip then shows that the key holds the
    // imported value.
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
    // The imported key's commitment, which an unwrapped copy must also produce. An AES key is
    // checked against the value that the host knows. A key of another type is checked by its own
    // commitment, which only the module computes, so that yes is unverified (review 2026-11-24
    // E-3).
    let checked = match commit {
        Some(c) => made
            .tok
            .commit(h, &object, c, "cakeys probe: import")
            .map(|v| (Some(v), Checked::unverified()))
            .map_err(|e| ("commitment", e)),
        None => Checked::verified(same_aes(made, h, value)).map(|c| (None, c)).map_err(|e| ("check value", e)),
    };
    let (first, checked) = match checked {
        Ok(v) => v,
        Err((what, e)) => {
            made.undetermined.push(format!("no {cap} row: imported, but its {what}: {}", evidence(made.tok, &e)));
            return;
        }
    };
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
            Ok(v) if &v == first => Ok(Checked::unverified()),
            Ok(_) => Err(KmError::Conflict(Reason::check(Check::ProbeSameKey, "its commitment is another key's"))),
            Err(e) => Err(e),
        },
        _ => Checked::verified(same_aes(m, h2, value)),
    };
    let test_key = TestKey {
        key_type: &key_kind,
        on: &on,
        h,
        secret: true,
        template: &template,
        same: &same,
        host_same: &|plain| Checked::same(plain, value),
    };
    exports(made, profile, &test_key, transport);
}

/// The secret key types other than AES whose import and export the probes test, each with the
/// length of the value that the probe imports. The host knows each value ([`secret_value`]), so
/// it can check what leaves the token against that value.
const OTHER_SECRETS: [(Kt, u32); 7] = [
    (Kt::GenericSecret, 32),
    (Kt::Sha1Hmac, 32),
    (Kt::Sha224Hmac, 32),
    (Kt::Sha256Hmac, 32),
    (Kt::Sha384Hmac, 48),
    (Kt::Sha512Hmac, 64),
    (Kt::Des3, 24),
];

/// Returns a fixed value of `n` bytes that the host can compute again.
fn secret_value(n: u32) -> Vec<u8> {
    (0..n).map(|i| u8::try_from(i % 251).unwrap_or(0).wrapping_mul(29).wrapping_add(7)).collect()
}

/// Creates a certificate or a data object from `bytes` (the `create.CKO_*` row), and reads its
/// value back. In a scratch slot, the probe creates the object as SO in the slot.
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
            session
                .create_object(&t)
                .map_err(|e| made.tok.refused_for(Topic::Create, &e, format!("C_CreateObject: {}", ckr(&e))))
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
        // The match does not use an `if let` guard, because the workspace's rust-version (1.89)
        // does not have that feature.
        Ok([Attribute::Value(v)]) => match Checked::same(v.as_slice(), bytes) {
            Some(checked) => profile.yes(cap, checked, None),
            None => profile.wrong(cap, "CKA_VALUE reads otherwise".into()),
        },
        Ok(_) => profile.wrong(cap, "CKA_VALUE reads otherwise".into()),
        Err(e) => made.undetermined.push(format!("no {cap} row: reading CKA_VALUE back: {}", ckr(e))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each test key has the size or the curve that its rows name, each RSA size is one that the
    /// generation probes try, and the host reads every test key.
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
        // These are the curves that cakeys names but that have no test key. The run names each of
        // them in its undetermined list (review moves F5). A new curve without a fixture fails
        // this assertion until it gets a fixture or is added to this list.
        assert_eq!(unfixtured_curves(), ["edwards448"]);
    }

    /// The slot's mark is a certificate for the key that it is given, signed by the P-256 test
    /// key. It has the same bytes each time, because the guard builds it again from the slot's
    /// key, and it differs for another key. It is not the fixed certificate that the probe used
    /// as its mark before (review 2026-11-24 E-6: that certificate matched whatever key the slot
    /// held).
    #[test]
    fn the_slot_mark_names_its_key() {
        use cakeys_core::sig::{self, Encoding};
        let own = id::cert_spki(CERTIFICATE).unwrap();
        let other = id::spki_canonical(&spki_of_pkcs8(CURVE_KEYS[1].2).unwrap()).unwrap();
        let (mark, another) = (slot_mark(&own).unwrap(), slot_mark(&other).unwrap());
        assert_eq!(slot_mark(&own).as_ref(), Some(&mark));
        assert_ne!(mark, another);
        assert_ne!(mark, CERTIFICATE);
        for (cert, spki) in [(&mark, &own), (&another, &other)] {
            assert_eq!(&id::cert_spki(cert).unwrap(), spki);
            let (whole, _) = der_element(cert).unwrap();
            let (tbs, rest) = der_element(der_contents(whole).unwrap()).unwrap();
            let (bits, _) = der_element(der_element(rest).unwrap().1).unwrap();
            let signature = &der_contents(bits).unwrap()[1..];
            assert_eq!(sig::ecdsa(&own, tbs, signature, Encoding::Der, None), Some(Ok(())));
        }
    }

    /// A way whose template the provider refuses was never sent to the module. That way produces
    /// no `no` row, and the export row is not `no` while a way is untried. An unwrap that
    /// produces the wrong key is an unwrap `no` (review moves F2).
    #[test]
    fn untried_ways_decide_no_row() {
        let ways = |wrap: &[&str], unwrap: &[&str], untried: &[&str]| Ways {
            wrap_refused: wrap.iter().map(|s| (*s).to_owned()).collect(),
            unwrap_refused: unwrap.iter().map(|s| (*s).to_owned()).collect(),
            untried: untried.iter().map(|s| (*s).to_owned()).collect(),
            ..Ways::default()
        };
        assert_eq!(ways(&[], &[], &["a: refused"]).rows(), SealedRows::Undetermined("a: refused".into()));
        assert_eq!(ways(&["b: C_WrapKey"], &[], &["a: refused"]).rows(), SealedRows::Undetermined("a: refused".into()));
        assert_eq!(ways(&["b: C_WrapKey"], &[], &[]).rows(), SealedRows::ExportNo("b: C_WrapKey".into()));
        let wrong = "b: not the key wrapped: another key";
        assert_eq!(ways(&[], &[wrong], &["a: refused"]).rows(), SealedRows::UnwrapNo(wrong.into()));
    }

    /// A value that cakeys cannot encode is a host error. The probes record it as undetermined
    /// and do not end the run (review moves F1).
    #[test]
    fn the_host_encoding_fails_as_a_value() {
        let cert = public_object(Class::Certificate);
        let ok = Locator { label: Some("cakeys-probe-01".into()), id: None };
        assert!(host_encoding(&ok, &cert, CERTIFICATE).is_ok());
        let odd = Locator { label: None, id: Some("not hex".into()) };
        assert!(host_encoding(&odd, &cert, CERTIFICATE).is_err());
    }
}
