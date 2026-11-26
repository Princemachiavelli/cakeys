//! What a file claims, and the transport key the lock binds to the target the operator names
//! (docs/CAMIGRATE.md D3, D5; review 2026-11-24 D-1, D-8, D-10). A transport file and a bundle
//! may cross untrusted channels, so every name read from one is a [`Claimed`] value: it chooses
//! nothing. The transport key a source seals to, a target unwraps with or a source's SO trusts
//! is a [`BoundTransport`]: the one the lock realises as the transport key of the token the
//! operator named (`--to`, `--token`), held to one rule. Its constructors are the only way to
//! make one, and each runs that rule; a [`BoundBundle`] is a bundle held to it.

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

/// What a file says, before anything vouches for it: what it names chooses nothing until
/// [`BoundTransport`] or [`BoundBundle`] has held it to the lock and to the target named.
#[derive(Debug)]
pub(crate) struct Claimed<T>(T);

impl<T> Claimed<T> {
    /// What a file says.
    pub(crate) fn new(claim: T) -> Claimed<T> {
        Claimed(claim)
    }

    /// What it says, for messages and for planning what its target will check again: never a
    /// name to act on.
    pub(crate) fn unverified(&self) -> &T {
        &self.0
    }
}

impl Claimed<Transport> {
    /// The file is the transport file of `to`, the target the operator named (review
    /// 2026-11-24 D-1: whoever swapped it may hold another target's genuine file, whose own
    /// token the lock binds just as well).
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

/// A token's transport key as the lock binds it (docs/CAMIGRATE.md D3): the spec named for the
/// token (`--transport-spec`, else its `transportWith`), realised there as an RSA private key the
/// lock records as allowed to unwrap and known never to leave it, under its locked identity;
/// with its public key, when one is known, held to that identity and to the 2048-bit rule.
#[derive(Debug, Clone)]
pub(crate) struct BoundTransport {
    token: String,
    spec: String,
    object: String,
    rfc7093m4: String,
    spki: Option<Vec<u8>>,
}

impl BoundTransport {
    /// `to`'s transport key, from the lock: the spec `spec` names (`--transport-spec`, or the one
    /// `transport --spec` names), else `to`'s `transportWith`; and the public key the lock
    /// records for it, if any.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` (14) when no key is named, or the one named is not realised on `to`,
    /// is gone from keys.toml, is no transport key as the lock records it (an RSA private key
    /// with `CKA_UNWRAP = true` and `CKA_EXTRACTABLE = false`: one the lock does not record is
    /// none) or has no locked identity; `Validation` (17) for one keys.toml says is no RSA
    /// private key, a recorded public key that does not decode, or one below 2048 bits.
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
            // Known never to leave: a policy that does not record it is no verdict (review
            // 2026-11-24 §2.2: an absent CKA_EXTRACTABLE passed).
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

    /// `to`'s transport key, from its transport file: the file must be `to`'s
    /// ([`Claimed::check_target`]) and name the key [`Self::from_lock`] binds there, with its
    /// identity; its public key is that identity's.
    ///
    /// # Errors
    ///
    /// As [`Self::from_lock`], each led by the file's path; `Validation` (17) for a file of
    /// another token; `PreconditionFailed` (14) for a file naming another object or identity.
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

    /// The key read from the open target `tok`, verified there against the lock (its proof
    /// included): for a lock that records no public key for it yet, and for `transport --out`.
    ///
    /// # Errors
    ///
    /// What `ops::verify` refuses; `NotFound` for a key not under its locator; as
    /// [`Self::with_key`].
    pub(crate) fn read(self, cfg: &Config, tok: &Token, lock: &Lock, notes: &mut Notes) -> Result<BoundTransport> {
        let t = self.target(cfg)?;
        ops::verify(&t, tok, lock, notes)?;
        let h = tok
            .find_key(&t.object, &t.on_token.locator, false)?
            .ok_or_else(|| KmError::NotFound(format!("{t}: the transport key").into()))?;
        let spki = cakeys_core::id::spki_canonical(&tok.spki(h, &t.on_token.locator)?)?;
        self.with_key(spki)
    }

    /// The bound key with its public key `spki`, held to the locked identity and to the size
    /// rule, whichever way it came: the lock, the file or the token.
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

    /// The token it is the transport key of: the one the operator named.
    pub(crate) fn token(&self) -> &str {
        &self.token
    }

    /// Its object's name.
    pub(crate) fn object(&self) -> &str {
        &self.object
    }

    /// Its locked identity.
    pub(crate) fn rfc7093m4(&self) -> &str {
        &self.rfc7093m4
    }

    /// Its public key (canonical SPKI DER), when the lock, the file or the token gave it.
    pub(crate) fn spki(&self) -> Option<&[u8]> {
        self.spki.as_deref()
    }

    /// It, as a target on its token: its spec and object in `cfg`.
    ///
    /// # Errors
    ///
    /// As `Target::new`, for a `cfg` other than the one it was bound with.
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

    /// The transport file of it, as `transport --out` writes it: its key and `tok`'s provider
    /// and mechanisms.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` for a key with no public key known (read it first, [`Self::read`]).
    pub(crate) fn transport_file(&self, tok: &Token) -> Result<Transport> {
        let spki = self.spki().ok_or_else(|| self.no_public_key())?;
        Transport::new(&tok.name, tok.provider.name(), &self.object, spki, &tok.mechanism_names())
    }

    /// The refusal for a key whose public key is not known.
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

    /// A transport key that may also decrypt is warned about: the target's PIN holder could
    /// `C_Decrypt` a bundle's wrapped key-encryption key out of the token. One the lock does not
    /// record as unable to is warned about too.
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

/// The text of a refusal, without its class: the reason a plan gives.
#[must_use]
pub(crate) fn reason(e: KmError) -> String {
    let said = e.to_string();
    e.into_msg().map_or(said, cakeys_core::Msg::into_text)
}

/// A transport key for a plan: bound; not bound, for the reason the plan gives (`Err`); or an
/// error, for one that is malformed (17), which no plan can carry.
///
/// # Errors
///
/// `Validation`, as the binding said it.
pub(crate) fn planned(bound: Result<BoundTransport>) -> Result<std::result::Result<BoundTransport, String>> {
    match bound {
        Ok(b) => Ok(Ok(b)),
        Err(e @ KmError::Validation(_)) => Err(e),
        Err(e) => Ok(Err(reason(e))),
    }
}

/// A bundle held to the target it is imported on: made for it (`target`), from a source
/// keys.toml names, and sealed to its transport key as the lock binds it ([`BoundTransport`]),
/// never to whichever key the bundle names (review 2026-11-24 D-8).
pub(crate) struct BoundBundle<'a> {
    bundle: Bundle,
    transport: Option<Target<'a>>,
}

impl<'a> BoundBundle<'a> {
    /// A bundle read from a file, for `to`: a version-1 bundle names no target and is held to
    /// `to`'s transport key alone, said in a warning. `spec` is `--transport-spec`.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` (14) for a bundle made for another target, or sealed to another key
    /// than `to`'s transport key; `HashMismatch` (10) for one naming that key under another
    /// identity; as [`BoundTransport::from_lock`] for a bundle that seals to
    /// one; `Validation` (17) for a source keys.toml does not name.
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
        // Public objects alone are sealed to nothing, and need no transport key.
        let transport = if bundle.transport.is_some() {
            let bound =
                BoundTransport::from_lock(cfg, lock, to, spec).map_err(|e| e.prefixed("the bundle's transport key"))?;
            Some(Self::sealed_to(&bundle, &bound, cfg)?)
        } else {
            None
        };
        Ok(BoundBundle { bundle, transport })
    }

    /// A bundle this run sealed to `transport` (`migrate`, in memory), held to it as a file is.
    ///
    /// # Errors
    ///
    /// `PreconditionFailed` for a bundle that is not.
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

    /// The bundle's transport key is `bound`, as a target: another object is another key (14);
    /// the same object under another identity, a key the lock does not pin (10).
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

    /// The transport key its wrapped keys unwrap under, on the target: none for public objects
    /// alone.
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

    /// A lock realising `t` on `tok` as `tr`, recording `policy`, its type, its identity and
    /// public key `spki`.
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

    /// The one rule, from the lock (review 2026-11-24 D-10, §2.2): named, realised, an RSA key
    /// that may unwrap and is known never to leave, at least 2048 bits; an unrecorded
    /// `CKA_EXTRACTABLE` is no verdict.
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
        // keys.toml's transportWith names it; keys.toml no longer having it, or as no RSA key.
        let named = config("[tokens.tok.migrate]\ntransportWith = \"tr\"\n", RSA);
        assert!(BoundTransport::from_lock(&named, &lock(GOOD, &good), "tok", None).is_ok());
        let ec = config("", "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"");
        let e = BoundTransport::from_lock(&ec, &lock(GOOD, &good), "tok", Some("tr")).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("is an RSA private key"), "{e}");
        let mut gone = lock(GOOD, &good);
        gone.realisations.insert("gone".into(), gone.realisations["tr"].clone());
        let e = BoundTransport::from_lock(&cfg, &gone, "tok", Some("gone")).unwrap_err();
        assert!(e.to_string().contains("'gone' is gone from keys.toml"), "{e}");
        // A public key that does not decode is 17, never "none" (review lib.rs F10).
        let mut bad = lock(GOOD, &good);
        bad.objects.get_mut("t").unwrap().public_key = Some("!".into());
        let e = BoundTransport::from_lock(&cfg, &bad, "tok", Some("tr")).unwrap_err();
        assert!(e.exit_code() == 17 && e.to_string().contains("publicKey"), "{e}");
        // None recorded: bound, with no key to seal to until the token gives it.
        let mut none = lock(GOOD, &good);
        none.objects.get_mut("t").unwrap().public_key = None;
        let b = BoundTransport::from_lock(&cfg, &none, "tok", Some("tr")).unwrap();
        assert_eq!(b.spki(), None);
        assert_eq!(b.transport_file_without_token().unwrap_err().exit_code(), 14);
    }

    impl BoundTransport {
        /// [`Self::transport_file`]'s refusal, without a token to name.
        fn transport_file_without_token(&self) -> Result<()> {
            self.spki().map(|_| ()).ok_or_else(|| self.no_public_key())
        }
    }

    /// A transport file binds only as the transport file of the target named (review 2026-11-24
    /// D-1): another token's genuine file is 17; one naming another object or identity is 14.
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

    /// A bundle binds only on the target it names, sealed to that target's transport key
    /// (review 2026-11-24 D-8); a version-1 bundle, which names none, with a warning.
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
