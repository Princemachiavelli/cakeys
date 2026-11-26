//! The content of untrusted files, and the transport key that the lock binds to the target that
//! the operator names (docs/CAMIGRATE.md D3, D5; review 2026-11-24 D-1, D-8, D-10). A transport
//! file and a bundle may cross untrusted channels, so every name read from one is wrapped in a
//! [`Claimed`] value, and no such name selects anything. The transport key to which a source seals,
//! with which a target unwraps, or which a source's SO trusts is a [`BoundTransport`]. It is the
//! key that the lock realises as the transport key of the token that the operator named (`--to`,
//! `--token`), and it must pass one rule. Its constructors are the only way to make a
//! [`BoundTransport`], and each constructor checks that rule. A [`BoundBundle`] is a bundle that
//! has been checked against such a key.

use cakeys_core::config::{Config, Lock};
use cakeys_core::id::Scheme;
use cakeys_core::known::{Known, Permission};
use cakeys_core::plan::Target;
use cakeys_core::types::{KeyType, ObjectClass};
use cakeys_core::{Check, KmError, Reason, Result};
use cakeys_pkcs11::Token;
use cakeys_pkcs11::ops::{self, Notes};

use crate::bundle::Bundle;
use crate::transport::Transport;

/// The content of a file before anything has verified it. A name in it selects nothing until
/// [`BoundTransport`] or [`BoundBundle`] has checked it against the lock and against the named
/// target.
#[derive(Debug)]
pub(crate) struct Claimed<T>(T);

impl<T> Claimed<T> {
    /// Wraps the content of a file.
    pub(crate) fn new(claim: T) -> Claimed<T> {
        Claimed(claim)
    }

    /// Returns the unverified content, for messages and for planning steps that the target will
    /// check again. A name from it must never be used to select an object or a token.
    pub(crate) fn unverified(&self) -> &T {
        &self.0
    }
}

impl Claimed<Transport> {
    /// Checks that the file is the transport file of `to`, the target that the operator named
    /// (review 2026-11-24 D-1). This check is needed because a person who swapped the file may
    /// hold the genuine transport file of another target, and the lock binds that other token's
    /// transport key just as well.
    ///
    /// # Errors
    ///
    /// `Validation` (17) for a file of another token.
    pub(crate) fn check_target(&self, path: &std::path::Path, to: &str) -> Result<()> {
        if self.0.token == to {
            return Ok(());
        }
        Err(KmError::Validation(
            format!(
                "{}: a transport file of '{}', not of '{to}' (--to): an export seals only to the transport key of \
                 the token it names",
                path.display(),
                self.0.token
            )
            .into(),
        ))
    }
}

/// A token's transport key as the lock binds it (docs/CAMIGRATE.md D3). It is the spec that is
/// named for the token (`--transport-spec`, or else the token's `transportWith`). The lock must
/// realise that spec on the token as an RSA private key that is allowed to unwrap and is known
/// never to leave the token, and the lock must pin its identity. When the public key is known, it
/// must match that identity and have at least 2048 bits.
#[derive(Debug, Clone)]
pub(crate) struct BoundTransport {
    token: String,
    spec: String,
    object: String,
    rfc7093m4: String,
    spki: Option<Vec<u8>>,
}

impl BoundTransport {
    /// Returns `to`'s transport key from the lock. The key is the spec that `spec` names
    /// (`--transport-spec`, or the spec that `transport --spec` names), or else `to`'s
    /// `transportWith`. The result includes the public key that the lock records for it, if any.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` (14) in these cases: no key is named; the named key is not realised on
    /// `to`; its spec is gone from keys.toml; the lock does not record it as a transport key; or
    /// the lock pins no identity for it. A transport key is an RSA private key with
    /// `CKA_UNWRAP = true` and `CKA_EXTRACTABLE = false`, and an attribute that the lock does not
    /// record does not count. `Validation` (17) in these cases: keys.toml says that the key is not
    /// an RSA private key; the recorded public key does not decode; or the recorded public key has
    /// fewer than 2048 bits. `HashMismatch` (10) when the hash of the recorded public key is not
    /// the locked identity.
    pub(crate) fn from_lock(cfg: &Config, lock: &Lock, to: &str, spec: Option<&str>) -> Result<BoundTransport> {
        let precondition = |check, msg: String| KmError::PreconditionFailed(Reason::check(check, msg));
        let named = spec.or_else(|| cfg.tokens.get(to).and_then(|t| t.migrate.transport_with.as_deref()));
        let Some(chosen) = named else {
            return Err(precondition(
                Check::ImportTransport,
                format!(
                    "no transport key is named for '{to}' (docs/CAMIGRATE.md D3): set transportWith in [tokens.{to}.migrate] \
                 to the spec of an RSA key there that may unwrap and never leaves the token, lock it, or pass \
                 --transport-spec"
                ),
            ));
        };
        let Some((spec, r)) =
            lock.realisations.get_key_value(chosen).and_then(|(spec, by_token)| Some((spec, by_token.get(to)?)))
        else {
            return Err(precondition(
                Check::LockRealised,
                format!("transport key '{chosen}' is not realised on '{to}' in the lock: lock it there first"),
            ));
        };
        let Some(declared) = cfg.specs.get(spec) else {
            return Err(precondition(
                Check::ImportTransport,
                format!("the transport key's spec '{spec}' is gone from keys.toml"),
            ));
        };
        let rsa = |class, key_type| class == ObjectClass::PrivateKey && key_type == Some(KeyType::Rsa);
        if let Some(o) = cfg.objects.get(&declared.object).filter(|o| !rsa(o.class, o.key_type)) {
            return Err(KmError::Validation(
                format!(
                    "'{spec}' on '{to}': a transport key is an RSA private key (docs/CAMIGRATE.md D3), not a {}",
                    o.class
                )
                .into(),
            ));
        }
        let locked = lock.objects.get(&r.object);
        let fault = if !locked.and_then(|o| o.object_type.as_ref()).is_some_and(|t| rsa(t.class, t.key_type)) {
            Some("must be an RSA private key".to_owned())
        } else if !r.observed(Permission::Unwrap.attr()).permits() {
            Some("must allow CKA_UNWRAP".to_owned())
        } else {
            // The key must be known never to leave the token. A policy that does not record
            // CKA_EXTRACTABLE gives no answer, so it fails this check (review 2026-11-24 §2.2: an
            // absent CKA_EXTRACTABLE used to pass).
            match r.observed(Permission::Extractable.attr()) {
                Known::Is(false) => None,
                Known::Is(true) => Some("must never leave the token (CKA_EXTRACTABLE = false)".to_owned()),
                unknown @ Known::Unknown(_) => Some(format!(
                    "must never leave the token (CKA_EXTRACTABLE = false), and its CKA_EXTRACTABLE is {unknown}"
                )),
            }
        };
        if let Some(why) = fault {
            return Err(precondition(
                Check::ImportTransport,
                format!("'{spec}' on '{to}' is no transport key: a transport key {why}, as the lock records it"),
            ));
        }
        let Some(id) = locked.and_then(|o| o.ids.get(Scheme::Rfc7093m4.name())) else {
            return Err(precondition(
                Check::ImportTransport,
                format!(
                    "the lock pins no key for transport key '{spec}' ('{}') on '{to}', so nothing vouches for it",
                    r.object
                ),
            ));
        };
        let bound = BoundTransport {
            token: to.to_owned(),
            spec: spec.clone(),
            object: r.object.clone(),
            rfc7093m4: id.clone(),
            spki: None,
        };
        match locked.and_then(|o| o.public_key.as_ref()) {
            None => Ok(bound),
            Some(k) => {
                use base64::Engine as _;
                let spki = base64::engine::general_purpose::STANDARD.decode(k).map_err(|e| {
                    KmError::Validation(format!("the lock's publicKey of transport key '{spec}' on '{to}': {e}").into())
                })?;
                bound.with_key(spki)
            }
        }
    }

    /// Returns `to`'s transport key from its transport file. The file must be `to`'s
    /// ([`Claimed::check_target`]), and it must name the key that [`Self::from_lock`] binds there,
    /// with that key's identity. The public key in the file must have that identity.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::from_lock`], each prefixed with the file's path. `Validation` (17)
    /// for a file of another token. `PreconditionFailed` (14) for a file that names another object
    /// or another identity.
    pub(crate) fn from_file(
        file: &Claimed<Transport>,
        path: &std::path::Path,
        cfg: &Config,
        lock: &Lock,
        to: &str,
        spec: Option<&str>,
    ) -> Result<BoundTransport> {
        file.check_target(path, to)?;
        let t = &file.0;
        let shown = path.display();
        let bound = Self::from_lock(cfg, lock, to, spec).map_err(|e| e.prefixed(&shown))?;
        if t.object != bound.object {
            return Err(KmError::PreconditionFailed(Reason::check(
                Check::ImportTransport,
                format!(
                    "{shown}: its object '{}' is not the transport key of '{to}': the lock realises '{}' there as '{}'",
                    t.object, bound.spec, bound.object
                ),
            )));
        }
        if t.rfc7093m4 != bound.rfc7093m4 {
            return Err(KmError::PreconditionFailed(Reason::check(
                Check::ImportTransport,
                format!(
                    "{shown}: its key {} is not the {} the lock pins for '{}'",
                    t.rfc7093m4, bound.rfc7093m4, t.object
                ),
            )));
        }
        bound.with_key(t.spki()?).map_err(|e| e.prefixed(&shown))
    }

    /// Reads the key from the open target `tok`, after `ops::verify` checks it there against the
    /// lock, including its proof. This is used when the lock records no public key for the key
    /// yet, and for `transport --out`.
    ///
    /// # Errors
    ///
    /// The errors of `ops::verify`; `NotFound` (11) for a key that is not under its locator; and
    /// the errors of [`Self::with_key`].
    pub(crate) fn read(self, cfg: &Config, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<BoundTransport> {
        let t = self.target(cfg)?;
        ops::verify(&t, tok, lock, notes)?;
        let h = tok
            .find_key(&t.object, &t.on_token.locator, false)?
            .ok_or_else(|| KmError::NotFound(format!("{t}: the transport key").into()))?;
        let spki = cakeys_core::id::spki_canonical(&tok.spki(h, &t.on_token.locator)?)?;
        self.with_key(spki)
    }

    /// Returns the bound key with its public key `spki`, after it checks `spki` against the locked
    /// identity (`HashMismatch`, 10) and against the size rule. The public key may come from the
    /// lock, from the transport file, or from the token.
    fn with_key(self, spki: Vec<u8>) -> Result<BoundTransport> {
        let got = cakeys_core::id::sri(&spki);
        if got != self.rfc7093m4 {
            return Err(KmError::HashMismatch {
                what: format!("transport key '{}' on '{}'", self.spec, self.token),
                expected: self.rfc7093m4,
                got,
                check: Check::ImportTransport,
            });
        }
        crate::sealed::check_transport_size(&spki)?;
        Ok(BoundTransport { spki: Some(spki), ..self })
    }

    /// The token whose transport key this is, which is the token that the operator named.
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// The name of the key's object.
    pub(crate) fn object(&self) -> &str {
        &self.object
    }

    /// The key's locked identity.
    pub(crate) fn rfc7093m4(&self) -> &str {
        &self.rfc7093m4
    }

    /// The key's public key (canonical SPKI DER), when the lock, the file or the token gave it.
    pub(crate) fn spki(&self) -> Option<&[u8]> {
        self.spki.as_deref()
    }

    /// Returns the key as a target on its token: its spec and its object in `cfg`.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` (14) when the spec or the token is gone from `cfg`, and the errors of
    /// `Target::new`. These can happen only for a `cfg` other than the one with which the key was
    /// bound.
    pub(crate) fn target<'a>(&self, cfg: &'a Config) -> Result<Target<'a>> {
        let gone = || {
            KmError::PreconditionFailed(Reason::check(
                Check::ImportTransport,
                format!("the transport key's spec '{}' is gone", self.spec),
            ))
        };
        let (spec, _) = cfg.specs.get_key_value(&self.spec).ok_or_else(gone)?;
        let (token, _) = cfg.tokens.get_key_value(&self.token).ok_or_else(gone)?;
        Target::new(cfg, spec, token)
    }

    /// Returns the transport file for this key, as `transport --out` writes it: the key, and
    /// `tok`'s provider and mechanisms.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` (14) for a key whose public key is not known. Read the key from the
    /// token first with [`Self::read`].
    pub(crate) fn transport_file(&self, tok: &Token) -> Result<Transport> {
        let spki = self.spki().ok_or_else(|| self.no_public_key())?;
        Transport::new(&tok.name, tok.provider.name(), &self.object, spki, &tok.mechanism_names())
    }

    /// Returns the refusal (14) for a key whose public key is not known.
    pub(crate) fn no_public_key(&self) -> KmError {
        KmError::PreconditionFailed(Reason::check(
            Check::ImportTransport,
            format!(
                "the lock records no public key for transport key '{}' on '{}': lock it there with \
                 migrate.transportWith naming it",
                self.spec, self.token
            ),
        ))
    }

    /// Warns when the transport key may also decrypt, because the holder of the target's PIN could
    /// then `C_Decrypt` a bundle's wrapped key-encryption key out of the token. It also warns when
    /// the lock does not record that the key cannot decrypt.
    pub(crate) fn warn_decrypting(&self, lock: &Lock, notes: &mut Notes) {
        let decrypt = lock
            .realisation(&self.spec, &self.token)
            .map_or(Known::Unknown(cakeys_core::known::Why::Unrecorded), |r| r.observed(Permission::Decrypt.attr()));
        if decrypt != Known::Is(false) {
            notes.warn(format_args!(
                "transport key '{}' on '{}' also decrypts (CKA_DECRYPT {decrypt}): whoever holds the target's PIN can \
                 decrypt what is sealed to it out of the token; a transport key that only unwraps proves possession \
                 with binding = \"pop-unwrap\"",
                self.spec, self.token
            ));
        }
    }
}

/// Returns the text of a refusal without its error class. A plan gives this text as its reason.
#[must_use]
pub(crate) fn reason(e: KmError) -> String {
    let said = e.to_string();
    e.into_msg().map_or(said, cakeys_core::Msg::into_text)
}

/// Converts the result of binding a transport key for a plan. A bound key is returned as `Ok`.
/// A key that is not bound is returned as an inner `Err` with the reason that the plan gives. A
/// malformed key (17) is returned as an error, because no plan can carry it.
///
/// # Errors
///
/// `Validation` (17), as the binding returned it.
pub(crate) fn planned(bound: Result<BoundTransport>) -> Result<std::result::Result<BoundTransport, String>> {
    match bound {
        Ok(b) => Ok(Ok(b)),
        Err(e @ KmError::Validation(_)) => Err(e),
        Err(e) => Ok(Err(reason(e))),
    }
}

/// A bundle that has been checked against the target on which it is imported. The bundle must be
/// made for that target (`target`), must come from a source that keys.toml names, and must be
/// sealed to the target's transport key as the lock binds it ([`BoundTransport`]). The key that
/// the bundle itself names is never trusted (review 2026-11-24 D-8).
pub(crate) struct BoundBundle<'a> {
    bundle: Bundle,
    transport: Option<Target<'a>>,
}

impl<'a> BoundBundle<'a> {
    /// Checks a bundle that was read from a file for an import on `to`. A version-1 bundle names
    /// no target, so it is checked only against `to`'s transport key, and a warning says so.
    /// `spec` is `--transport-spec`.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` (14) for a bundle that was made for another target, or that is sealed
    /// to another key than `to`'s transport key. `HashMismatch` (10) for a bundle that names that
    /// key with another identity. The errors of [`BoundTransport::from_lock`] for a bundle that is
    /// sealed to a transport key. `Validation` (17) for a source that keys.toml does not name.
    pub(crate) fn from_file(
        file: Claimed<Bundle>,
        cfg: &'a Config,
        lock: &Lock,
        to: &str,
        spec: Option<&str>,
        notes: &mut Notes,
    ) -> Result<BoundBundle<'a>> {
        let bundle = file.0;
        match &bundle.target {
            Some(target) if target != to => {
                return Err(KmError::PreconditionFailed(Reason::check(
                    Check::ImportTransport,
                    format!("the bundle is for '{target}', not '{to}': import it there, or export it again for '{to}'"),
                )));
            }
            Some(_) => {}
            None => notes.warn(format_args!(
                "a version-1 bundle names no target: it is held to the transport key of '{to}' alone; export it \
                 again for one that names its target"
            )),
        }
        bundle.check_source(cfg)?;
        // A bundle of public objects alone is sealed to nothing, so it needs no transport key.
        let transport = if bundle.transport.is_some() {
            let bound =
                BoundTransport::from_lock(cfg, lock, to, spec).map_err(|e| e.prefixed("the bundle's transport key"))?;
            Some(Self::sealed_to(&bundle, &bound, cfg)?)
        } else {
            None
        };
        Ok(BoundBundle { bundle, transport })
    }

    /// Checks a bundle that this run sealed to `transport` (`migrate`, in memory) in the same way
    /// as a bundle from a file.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` (14) for a bundle that was not made for `transport`'s token, and the
    /// errors of `sealed_to` for a bundle that is not sealed to `transport`.
    pub(crate) fn made(bundle: Bundle, transport: &BoundTransport, cfg: &'a Config) -> Result<BoundBundle<'a>> {
        if bundle.target.as_deref() != Some(transport.token()) {
            return Err(KmError::PreconditionFailed(Reason::check(
                Check::ImportTransport,
                format!("the bundle was not made for '{}'", transport.token()),
            )));
        }
        let transport = Some(Self::sealed_to(&bundle, transport, cfg)?);
        Ok(BoundBundle { bundle, transport })
    }

    /// Checks that the bundle's transport key is `bound`, and returns it as a target. A bundle that
    /// names another object names another key (14). A bundle that names the same object with
    /// another identity names a key that the lock does not pin (10).
    fn sealed_to(bundle: &Bundle, bound: &BoundTransport, cfg: &'a Config) -> Result<Target<'a>> {
        match &bundle.transport {
            Some(named) if named.object == bound.object && named.rfc7093m4 == bound.rfc7093m4 => bound.target(cfg),
            Some(named) if named.object == bound.object => Err(KmError::HashMismatch {
                what: format!("the bundle's transport key '{}' on '{}'", named.object, bound.token),
                expected: bound.rfc7093m4.clone(),
                got: named.rfc7093m4.clone(),
                check: Check::ImportTransport,
            }),
            Some(named) => Err(KmError::PreconditionFailed(Reason::check(
                Check::ImportTransport,
                format!(
                    "the bundle is sealed to '{}' ({}), not to the transport key of '{}', '{}' ({}, spec '{}'): name \
                     the key it was sealed to with --transport-spec if it is that token's (docs/CAMIGRATE.md D3)",
                    named.object, named.rfc7093m4, bound.token, bound.object, bound.rfc7093m4, bound.spec
                ),
            ))),
            None => Err(KmError::PreconditionFailed(Reason::check(
                Check::ImportTransport,
                "the bundle names no transport key",
            ))),
        }
    }

    /// The bundle.
    pub(crate) fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    /// The transport key on the target under which the bundle's wrapped keys unwrap. It is `None`
    /// for a bundle of public objects alone.
    pub(crate) fn transport(&self) -> Option<&Target<'a>> {
        self.transport.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    fn config(transport_with: &str, class: &str) -> Config {
        let binding = if class == RSA { "pop-unwrap" } else { "token-asserted" };
        cakeys_core::config::parse_config_with(
            &format!(
                "[tokens.tok]\ntokenLabel = \"t\"\n\n[tokens.other]\ntokenLabel = \"o\"\n\n\
                 [objects.t]\n{class}\n\n\
                 [specs.tr]\nobject = \"t\"\nattributes = {{ CKA_UNWRAP = true, CKA_EXTRACTABLE = false }}\n\
                 tokens.tok = {{ locator = {{ CKA_LABEL = \"t\" }}, origin = \"create\", binding = \"{binding}\" }}\n\
                 {transport_with}"
            ),
            std::path::Path::new("keys.toml"),
            &|_| None,
        )
        .unwrap()
    }

    const RSA: &str = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"";

    /// Returns a lock that realises the spec `tr` on `tok` as the object `t`, and records `policy`,
    /// the object's type, its identity and the public key `spki`.
    fn lock(policy: &str, spki: &[u8]) -> Lock {
        let key = base64::engine::general_purpose::STANDARD.encode(spki);
        let id = cakeys_core::id::sri(spki);
        toml::from_str(&format!(
            "version = 1\n[objects.t]\npublicKey = \"{key}\"\nids = {{ rfc7093m4 = \"{id}\" }}\n\
             type = {{ class = \"CKO_PRIVATE_KEY\", keyType = \"CKK_RSA\" }}\n\
             [realisations.tr.tok]\nobject = \"t\"\nspecDigest = \"sha256-x\"\nmode = \"direct\"\n\
             schemes = []\nlocator = {{ CKA_LABEL = \"t\" }}\npolicy = {{ {policy} }}\n"
        ))
        .unwrap()
    }

    fn spki(bytes: usize) -> Vec<u8> {
        cakeys_core::id::rsa_spki(&vec![0xc5u8; bytes], &[1, 0, 1]).unwrap()
    }

    const GOOD: &str = "CKA_UNWRAP = true, CKA_EXTRACTABLE = false, CKA_DECRYPT = false";

    /// Checks the one rule for a transport key from the lock (review 2026-11-24 D-10, §2.2). The
    /// key must be named and realised, and it must be an RSA key that may unwrap, is known never to
    /// leave the token, and has at least 2048 bits. An unrecorded `CKA_EXTRACTABLE` fails the
    /// rule.
    #[test]
    fn the_lock_binds_one_transport_key_per_target() {
        let cfg = config("", RSA);
        let (good, small) = (spki(256), spki(128));
        let b = BoundTransport::from_lock(&cfg, &lock(GOOD, &good), "tok", Some("tr")).unwrap();
        assert_eq!((b.token(), b.object(), b.spki()), ("tok", "t", Some(&good[..])));
        let refused = |l: Lock, to: &str, spec: Option<&str>, code: u8, what: &str| {
            let e = BoundTransport::from_lock(&cfg, &l, to, spec).unwrap_err();
            assert!(e.exit_code() == code && e.to_string().contains(what), "{what}: {e}");
        };
        refused(lock(GOOD, &good), "tok", None, 14, "no transport key is named for 'tok'");
        refused(lock(GOOD, &good), "other", Some("tr"), 14, "not realised on 'other'");
        refused(lock(GOOD, &small), "tok", Some("tr"), 17, "at least 2048 bits; this one has 1024");
        refused(lock("CKA_EXTRACTABLE = false", &good), "tok", Some("tr"), 14, "must allow CKA_UNWRAP");
        refused(lock("CKA_UNWRAP = true, CKA_EXTRACTABLE = true", &good), "tok", Some("tr"), 14, "never leave");
        refused(lock("CKA_UNWRAP = true", &good), "tok", Some("tr"), 14, "its CKA_EXTRACTABLE is not recorded");
        // The key may be named by transportWith in keys.toml. The binding is refused when
        // keys.toml no longer has the spec, or when keys.toml declares it as a key that is not RSA.
        let named = config("[tokens.tok.migrate]\ntransportWith = \"tr\"\n", RSA);
        assert!(BoundTransport::from_lock(&named, &lock(GOOD, &good), "tok", None).is_ok());
        let ec = config("", "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"");
        let e = BoundTransport::from_lock(&ec, &lock(GOOD, &good), "tok", Some("tr")).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("is an RSA private key"), "{e}");
        let mut gone = lock(GOOD, &good);
        gone.realisations.insert("gone".into(), gone.realisations["tr"].clone());
        let e = BoundTransport::from_lock(&cfg, &gone, "tok", Some("gone")).unwrap_err();
        assert!(e.to_string().contains("'gone' is gone from keys.toml"), "{e}");
        // A recorded public key that does not decode is refused (17). It is never treated as an
        // absent public key (review lib.rs F10).
        let mut bad = lock(GOOD, &good);
        bad.objects.get_mut("t").unwrap().public_key = Some("!".into());
        let e = BoundTransport::from_lock(&cfg, &bad, "tok", Some("tr")).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("publicKey"), "{e}");
        // When no public key is recorded, the key is bound, but there is no public key to seal to
        // until the token gives it.
        let mut none = lock(GOOD, &good);
        none.objects.get_mut("t").unwrap().public_key = None;
        let b = BoundTransport::from_lock(&cfg, &none, "tok", Some("tr")).unwrap();
        assert_eq!(b.spki(), None);
        assert_eq!(b.transport_file_without_token().unwrap_err().exit_code(), 14);
    }

    impl BoundTransport {
        /// Returns the refusal of [`Self::transport_file`], without a token to pass.
        fn transport_file_without_token(&self) -> Result<()> {
            self.spki().map(|_| ()).ok_or_else(|| self.no_public_key())
        }
    }

    /// Checks that a transport file binds only as the transport file of the named target (review
    /// 2026-11-24 D-1). The genuine file of another token is refused with 17, and a file that names
    /// another object or another identity is refused with 14.
    #[test]
    fn a_transport_file_binds_only_to_the_target_named() {
        let cfg = config("", RSA);
        let key = spki(256);
        let l = lock(GOOD, &key);
        let path = std::path::Path::new("t.toml");
        let file = |token: &str, object: &str, spki: &[u8]| {
            let t = Transport::new(token, "kryoptic", object, spki, &[]).unwrap();
            Transport::parse(&t.to_toml().unwrap(), path).unwrap()
        };
        let b = BoundTransport::from_file(&file("tok", "t", &key), path, &cfg, &l, "tok", Some("tr")).unwrap();
        assert_eq!(b.spki(), Some(&key[..]));
        let e = BoundTransport::from_file(&file("tok", "t", &key), path, &cfg, &l, "other", Some("tr")).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("a transport file of 'tok', not of 'other'"), "{e}");
        let e = BoundTransport::from_file(&file("tok", "u", &key), path, &cfg, &l, "tok", Some("tr")).unwrap_err();
        assert!(e.exit_code() == 14 && e.to_string().contains("its object 'u' is not the transport key"), "{e}");
        let other = spki(384);
        let e = BoundTransport::from_file(&file("tok", "t", &other), path, &cfg, &l, "tok", Some("tr")).unwrap_err();
        assert!(e.exit_code() == 14 && e.to_string().contains("the lock pins for 't'"), "{e}");
    }

    /// Checks that a bundle binds only on the target that it names, and only when it is sealed to
    /// that target's transport key (review 2026-11-24 D-8). A version-1 bundle names no target,
    /// and it binds with a warning.
    #[test]
    fn a_bundle_binds_only_to_its_targets_transport_key() {
        let cfg = cakeys_core::config::parse_config_with(
            &format!(
                "[tokens.softhsm]\ntokenLabel = \"s\"\n\n[tokens.tok]\ntokenLabel = \"t\"\n\n[objects.t]\n{RSA}\n\n\
                 [specs.tr]\nobject = \"t\"\nattributes = {{ CKA_UNWRAP = true, CKA_EXTRACTABLE = false }}\n\
                 tokens.tok = {{ locator = {{ CKA_LABEL = \"t\" }}, origin = \"create\", binding = \"pop-unwrap\" }}\n"
            ),
            std::path::Path::new("keys.toml"),
            &|_| None,
        )
        .unwrap();
        let key = spki(256);
        let l = lock(GOOD, &key);
        let sealed = |target: Option<&str>, object: &str, id: &str| {
            let mut b = crate::bundle::tests::sample();
            b.target = target.map(str::to_owned);
            b.transport = Some(crate::bundle::TransportRef { object: object.into(), rfc7093m4: id.into() });
            Claimed::new(b)
        };
        let id = cakeys_core::id::sri(&key);
        let bind = |c: Claimed<Bundle>, notes: &mut Notes| {
            BoundBundle::from_file(c, &cfg, &l, "tok", Some("tr"), notes).map(|b| b.transport().map(|t| t.spec_name))
        };
        let mut notes = Notes::default();
        assert_eq!(bind(sealed(Some("tok"), "t", &id), &mut notes).unwrap(), Some("tr"));
        assert!(notes.lines().is_empty(), "{:?}", notes.lines());
        let e = bind(sealed(Some("softhsm"), "t", &id), &mut notes).unwrap_err();
        assert!(e.exit_code() == 14 && e.to_string().contains("the bundle is for 'softhsm', not 'tok'"), "{e}");
        let e = bind(sealed(Some("tok"), "u", &id), &mut notes).unwrap_err();
        assert!(e.exit_code() == 14 && e.to_string().contains("sealed to 'u'"), "{e}");
        let e = bind(sealed(Some("tok"), "t", &cakeys_core::id::sri(b"another")), &mut notes).unwrap_err();
        assert!(e.exit_code() == 10 && e.to_string().contains("the bundle's transport key 't'"), "{e}");
        assert_eq!(bind(sealed(None, "t", &id), &mut notes).unwrap(), Some("tr"));
        assert!(notes.lines().iter().any(|w| w.contains("a version-1 bundle names no target")), "{:?}", notes.lines());
    }
}
