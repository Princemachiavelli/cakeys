//! The rows that record whether a token can perform one of cakeys' own operations
//! (docs/CAPROBE.md, review 2026-11-15 §4 (d)). Every row has one type,
//! `"<capability>" = { answer, evidence, via }`, and its key is a [`Capability`] that names the
//! operation. To add a new capability, add a variant here and the probe operation that tests it.
//! The emitter, the diff and the code that combines profiles into a stack do not change. An
//! absent row means that the answer is unknown: the capability was never probed and never
//! claimed.

use crate::names::{KeyKind, Proof};
use std::collections::BTreeMap;

/// The OAEP hashes that the wrap probe tries. They are the `wrap.rsa-oaep.*` rows that this
/// version of cakeys reads.
pub const WRAP_OAEP: [&str; 2] = ["SHA-1", "SHA-256"];

/// The OAEP hashes that the decryption probe tries. They are the `decrypt.rsa-oaep.*` rows that
/// this version of cakeys reads.
pub const DECRYPT_OAEP: [&str; 3] = ["SHA-1", "SHA-256", "SHA-512"];

/// The attributes that the unwrap probe puts in a template. They are the `unwrap.template.*` rows
/// that this version of cakeys reads.
pub const UNWRAP_TEMPLATE: [&str; 1] = ["CKA_VALUE_LEN"];

/// Returns the hash of a `rsa-oaep.<hash>` row. The hash may be any single name, known or not.
fn oaep_hash(rest: &str) -> Option<String> {
    rest.strip_prefix("rsa-oaep.").filter(|h| !h.is_empty() && !h.contains('.')).map(str::to_owned)
}

/// The curve, parameter set or size of the key that a generation, import or export row is
/// about. A size is in the unit of the key type's own attribute
/// (`docs/archive/CAPROBE_MIGRATION.md`, M1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum On {
    /// A curve or parameter set, by name.
    Item(String),
    /// An RSA modulus size, in bits (`CKA_MODULUS_BITS`).
    Bits(u32),
    /// A secret key's length, in bytes (`CKA_VALUE_LEN`, keys.toml's `valueLen`).
    Bytes(u32),
}

impl On {
    /// Parses the last part of a row's key for `key_type`. A number is a size, in bits for RSA
    /// or in bytes for a secret key. Any other text is a curve. A profile's row keys go through
    /// [`Capability::parse`], which also refuses a size that is not written in the form in which
    /// [`On`] writes it back (for example, `02048` or `+2048`).
    #[must_use]
    pub fn parse(key_type: &KeyKind, on: &str) -> On {
        match on.parse() {
            Ok(n) => On::size(key_type, n),
            Err(_) => On::Item(on.to_owned()),
        }
    }

    /// Returns a size of a key of `key_type`, in the unit that its attribute takes: bits for RSA
    /// (`CKA_MODULUS_BITS`), and bytes for any other key type (`CKA_VALUE_LEN`). A row's size is
    /// read back as this value.
    #[must_use]
    pub fn size(key_type: &KeyKind, n: u32) -> On {
        if matches!(key_type, KeyKind::Rsa) { On::Bits(n) } else { On::Bytes(n) }
    }
}

impl std::fmt::Display for On {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            On::Item(i) => f.write_str(i),
            On::Bits(n) | On::Bytes(n) => write!(f, "{n}"),
        }
    }
}

/// Which way a key leaves a token (`export.*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Way {
    /// The key leaves to this process, wrapped with RFC 5649 under a key that the host generated
    /// (`Token::extract`): `export.host.*`.
    Host,
    /// The key leaves wrapped to another token's RSA key (`CKM_RSA_AES_KEY_WRAP`, or RSA-OAEP for
    /// a secret key): `export.sealed.*`.
    Sealed,
}

impl Way {
    const ALL: [Way; 2] = [Way::Host, Way::Sealed];

    fn name(self) -> &'static str {
        match self {
            Way::Host => "host",
            Way::Sealed => "sealed",
        }
    }
}

/// The public object classes that `create.*` rows name without a key type.
pub const CREATE_CLASSES: [&str; 2] = ["CKO_CERTIFICATE", "CKO_DATA"];

/// A way in which keys move between tokens (docs/CAMIGRATE.md D2, D10). These rows are claims
/// that this repository makes, and the probe never writes them. The probe therefore keeps them
/// unchanged when it regenerates a profile, as it does with `[migration]`, and the diff never
/// compares them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Move {
    /// The module wraps a key out of the token (`C_WrapKey`). ykcs11 and tpm2-pkcs11 never do.
    Export,
    /// The module unwraps a key into the token (`C_UnwrapKey`).
    Unwrap,
    /// A secret key that the module unwraps reports its length (`CKA_VALUE_LEN`), which the
    /// import's type check reads. `SoftHSM` leaves the length at 0.
    SecretUnwrap,
    /// A `CKA_WRAP_WITH_TRUSTED` key can be wrapped to a transport key that the SO marked as
    /// trusted (`enforced`). kryoptic cannot do this.
    TrustedWrap,
}

impl Move {
    const ALL: [Move; 4] = [Move::Export, Move::Unwrap, Move::SecretUnwrap, Move::TrustedWrap];

    fn name(self) -> &'static str {
        match self {
            Move::Export => "export",
            Move::Unwrap => "unwrap",
            Move::SecretUnwrap => "secret-unwrap",
            Move::TrustedWrap => "trusted-wrap",
        }
    }
}

/// One of cakeys' operations a token can be asked about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// The generation of a key of `key_type` (`CKK_*`) on a curve or of a size:
    /// `generate.CKK_EC.secp256r1`, `generate.CKK_RSA.2048`. `via = "by-name"` means that the
    /// generation works only when `CKA_EC_PARAMS` names the curve (the `PrintableString` form of
    /// PKCS#11 3.0), and never when it gives the curve's OID.
    Generate {
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve, parameter set or size.
        on: On,
    },
    /// The wrapping of a key to an RSA key with RSA-OAEP of this hash and MGF1 of the same hash,
    /// checked by a round trip: `wrap.rsa-oaep.SHA-1`.
    WrapOaep(String),
    /// The decryption, with the private key, of data that the host encrypted to that key with
    /// RSA-OAEP of this hash (`pop-decrypt`): `decrypt.rsa-oaep.SHA-256`.
    DecryptOaep(String),
    /// An unwrap with this attribute in the template: `unwrap.template.CKA_VALUE_LEN`. The answer
    /// `no` means that the module refuses the attribute in an unwrap template (`SoftHSM` does).
    UnwrapTemplate(String),
    /// ECDH into a sealed (non-extractable) secret, which `pop-ecdh` then uses on the token to
    /// compute a MAC: `derive.ecdh.sealed`. ykcs11 derives only into an extractable secret.
    DeriveSealed,
    /// ECDH in a read-only session: `derive.ecdh.read-only`. tpm2-pkcs11 stores derived secrets
    /// as rows in its store, so it refuses ECDH in a read-only session.
    DeriveReadOnly,
    /// A way keys move: `move.export`, `move.unwrap`, `move.secret-unwrap`, `move.trusted-wrap`.
    Move(Move),
    /// The proof of possession of a private key of `key_type` on a curve or of a size, by
    /// `binding`, done as the verbs do it: `prove.pop-ecdh.CKK_EC.secp256r1`,
    /// `prove.pop-decrypt.CKK_RSA.2048`.
    Prove {
        /// The proof, by its `binding` name.
        binding: Proof,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve or size.
        on: On,
    },
    /// The import of a key of `key_type` from plaintext on the host, after which the token
    /// presents that same key: `import.CKK_EC.secp256r1`, `import.CKK_AES.32`. `via` names the
    /// import path that worked: `create-object`, or the provider's own path (`tpm2-ptool`,
    /// `piv-import`).
    Import {
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve or size.
        on: On,
    },
    /// `C_CreateObject` of a public object from its value: `create.CKO_CERTIFICATE`,
    /// `create.CKO_DATA`, `create.CKO_PUBLIC_KEY.CKK_EC.secp256r1`.
    Create {
        /// The class, by `CKO_*` name.
        class: String,
        /// A public key's key type and curve or size.
        key: Option<(KeyKind, On)>,
    },
    /// The export of an extractable key of `key_type` in the direction `way`, where the key
    /// arrives as the same material: `export.host.CKK_EC.secp256r1`,
    /// `export.sealed.CKK_RSA.2048`. `via` names the mechanism.
    Export {
        /// To the host, or toward another token.
        way: Way,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve or size.
        on: On,
    },
    /// A `C_UnwrapKey` that brings in a key of `key_type` with the same material that was
    /// wrapped: `unwrap.CKK_AES.32`. `via` names the mechanism.
    Unwrap {
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve or size.
        on: On,
    },
    /// A `C_DestroyObject` that actually removes an object of the class (`CKO_*`):
    /// `delete.CKO_PRIVATE_KEY`.
    Delete(String),
    /// A secret key's commitment, computed by the operation that `kind` names
    /// (`cakeys_core::id::Commit::profile_kind`: `hmac-sha256`, `cmac`, `kcv-ecb`, `kcv-ecb-dec`,
    /// `kw`) on a key of `key_type` that is `bytes` long:
    /// `commit.hmac-sha256.CKK_GENERIC_SECRET.32`. A check value uses the cipher of the key's own
    /// type (`commit.kcv-ecb.CKK_DES3.24`).
    Commit {
        /// The commitment kind.
        kind: String,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The key's length in bytes.
        bytes: u32,
    },
    /// A symmetric mode (`CKM_AES_CBC`, `CKM_AES_GCM` and others) that encrypts and then decrypts
    /// the result again, with a key of `key_type` that is `bytes` long:
    /// `crypt.CKM_AES_CTR.CKK_AES.32`.
    Crypt {
        /// The mechanism, by `CKM_*` name.
        mechanism: String,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The key's length in bytes.
        bytes: u32,
    },
    /// A key derivation (`CKM_HKDF_DERIVE`, `CKM_SP800_108_COUNTER_KDF`...) from a base key of
    /// `key_type`: `derive.CKM_HKDF_DERIVE.CKK_GENERIC_SECRET`.
    Kdf {
        /// The mechanism, by `CKM_*` name.
        mechanism: String,
        /// The base key's type, by `CKK_*` name.
        key_type: KeyKind,
    },
    /// ECDH between keys of `key_type` on a curve that the `prove.pop-ecdh.*` rows do not cover
    /// (the Montgomery curves): `derive.ecdh.CKK_EC_MONTGOMERY.curve25519`.
    DeriveEcdh {
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve.
        on: On,
    },
    /// Signing on the token, and verifying the signature on the token, with a mechanism that no
    /// `prove.*` row covers (post-quantum, XEdDSA): `sign.CKM_ML_DSA.CKK_ML_DSA.CKP_ML_DSA_65`.
    Sign {
        /// The mechanism, by `CKM_*` name.
        mechanism: String,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The parameter set or curve.
        on: On,
    },
    /// A `C_EncapsulateKey` followed by a `C_DecapsulateKey` that produce the same secret:
    /// `encapsulate.CKK_ML_KEM.CKP_ML_KEM_768`.
    Encapsulate {
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The parameter set.
        on: On,
    },
    /// An attribute that the verbs set or read, on a key of `key_type`. For
    /// `attr.set.CKA_ALLOWED_MECHANISMS.CKK_EC`, a template carries the attribute, and a later
    /// read returns the value that was set. For `attr.read.CKA_LOCAL.CKK_AES`, the module returns
    /// the attribute with a correct value.
    Attr {
        /// True for a read row (the module reports the attribute), and false for a set row (the
        /// template carries the attribute).
        read: bool,
        /// The attribute, by `CKA_*` name.
        attr: String,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
    },
}

/// Parses `<CKK_*>.<curve or size>`, which is the end of a `generate.*` key and of the keys with
/// the same form. A size must be written as its plain number. `02048` or `+2048` would be read
/// as 2048 and written back as `2048`, so two different keys could name the same row.
fn key_and_on(rest: &str) -> Option<(KeyKind, On)> {
    let (kt, text) = rest.split_once('.').filter(|(k, o)| k.starts_with("CKK_") && !o.is_empty())?;
    let kt = KeyKind::from(kt);
    let on = On::parse(&kt, text);
    (on.to_string() == text).then_some((kt, on))
}

/// Parses `CKM_*.<CKK_*>`: a mechanism and a key type, without a size.
fn mechanism_and_key(rest: &str) -> Option<(String, KeyKind)> {
    let (mechanism, kt) = rest.split_once('.').filter(|(m, k)| m.starts_with("CKM_") && k.starts_with("CKK_"))?;
    (!kt.contains('.')).then(|| (mechanism.to_owned(), KeyKind::from(kt)))
}

/// Parses `CKM_*.<CKK_*>.<curve, set or size>`.
fn mechanism_key_and_on(rest: &str) -> Option<(String, KeyKind, On)> {
    let (mechanism, rest) = rest.split_once('.').filter(|(m, _)| m.starts_with("CKM_"))?;
    let (kt, on) = key_and_on(rest)?;
    Some((mechanism.to_owned(), kt, on))
}

/// Returns the mechanism that generates a key of `key_type`. The `generate.*` rows measure this
/// mechanism.
#[must_use]
pub fn generation_mechanism(key_type: &str) -> Option<&'static str> {
    Some(match key_type {
        "CKK_RSA" => "CKM_RSA_PKCS_KEY_PAIR_GEN",
        "CKK_EC" => "CKM_EC_KEY_PAIR_GEN",
        "CKK_EC_EDWARDS" => "CKM_EC_EDWARDS_KEY_PAIR_GEN",
        "CKK_EC_MONTGOMERY" => "CKM_EC_MONTGOMERY_KEY_PAIR_GEN",
        "CKK_AES" => "CKM_AES_KEY_GEN",
        "CKK_DES3" => "CKM_DES3_KEY_GEN",
        "CKK_DES2" => "CKM_DES2_KEY_GEN",
        "CKK_GENERIC_SECRET" => "CKM_GENERIC_SECRET_KEY_GEN",
        "CKK_HKDF" => "CKM_HKDF_KEY_GEN",
        "CKK_SHA_1_HMAC" => "CKM_SHA_1_KEY_GEN",
        "CKK_SHA224_HMAC" => "CKM_SHA224_KEY_GEN",
        "CKK_SHA256_HMAC" => "CKM_SHA256_KEY_GEN",
        "CKK_SHA384_HMAC" => "CKM_SHA384_KEY_GEN",
        "CKK_SHA512_HMAC" => "CKM_SHA512_KEY_GEN",
        "CKK_ML_DSA" => "CKM_ML_DSA_KEY_PAIR_GEN",
        "CKK_ML_KEM" => "CKM_ML_KEM_KEY_PAIR_GEN",
        "CKK_SLH_DSA" => "CKM_SLH_DSA_KEY_PAIR_GEN",
        _ => return None,
    })
}

/// Returns the mechanism with which a commitment of `kind` is computed on a key of `key_type`.
/// The mechanism comes from the names table (`cakeys_names::CommitKind::mechanism`), which core's
/// `Commit::mechanism` also reads. Returns `None` for a kind that this version of cakeys does not
/// know.
#[must_use]
pub fn commit_mechanism(kind: &str, key_type: &str) -> Option<&'static str> {
    cakeys_names::CommitKind::from_name(kind).map(|k| k.mechanism(key_type))
}

/// Returns the key length in bytes. A commitment row or a cipher row always gives its key's
/// length in bytes, so a size in bits (an RSA key) or a curve returns `None`.
fn bytes_of(on: &On) -> Option<u32> {
    match on {
        On::Bytes(n) => Some(*n),
        _ => None,
    }
}

impl Capability {
    /// Parses a row's key.
    ///
    /// # Errors
    ///
    /// Returns an error when the key names no capability.
    pub fn parse(key: &str) -> Result<Capability, String> {
        let bad = || format!("capabilities: {key:?} names no capability (docs/CAPROBE.md)");
        let (head, rest) = key.split_once('.').ok_or_else(bad)?;
        Ok(match (head, rest) {
            ("generate", rest) => {
                let (key_type, on) = key_and_on(rest).ok_or_else(bad)?;
                Capability::Generate { key_type, on }
            }
            ("import", rest) => {
                let (key_type, on) = key_and_on(rest).ok_or_else(bad)?;
                Capability::Import { key_type, on }
            }
            ("create", "CKO_PUBLIC_KEY") => return Err(bad()),
            ("create", rest) if CREATE_CLASSES.contains(&rest) => {
                Capability::Create { class: rest.to_owned(), key: None }
            }
            ("create", rest) => {
                let key = rest.strip_prefix("CKO_PUBLIC_KEY.").and_then(key_and_on).ok_or_else(bad)?;
                Capability::Create { class: "CKO_PUBLIC_KEY".into(), key: Some(key) }
            }
            ("export", rest) => {
                let (way, rest) = rest.split_once('.').ok_or_else(bad)?;
                let way = Way::ALL.into_iter().find(|w| w.name() == way).ok_or_else(bad)?;
                let (key_type, on) = key_and_on(rest).ok_or_else(bad)?;
                Capability::Export { way, key_type, on }
            }
            ("unwrap", rest) if rest.starts_with("CKK_") => {
                let (key_type, on) = key_and_on(rest).ok_or_else(bad)?;
                Capability::Unwrap { key_type, on }
            }
            ("delete", class) if class.starts_with("CKO_") && !class.contains('.') => {
                Capability::Delete(class.to_owned())
            }
            // A hash, attribute or proof that this version of cakeys does not know is loaded as
            // it was read, and it answers no query, as an unknown key type does (ISSUES.md Q28,
            // review D4). The parser checks only the form of the key, so a profile from a newer
            // cakeys still loads.
            ("wrap", rest) => Capability::WrapOaep(oaep_hash(rest).ok_or_else(bad)?),
            ("decrypt", rest) => Capability::DecryptOaep(oaep_hash(rest).ok_or_else(bad)?),
            ("unwrap", rest) => {
                let a =
                    rest.strip_prefix("template.").filter(|a| a.len() > 4 && a.starts_with("CKA_") && !a.contains('.'));
                Capability::UnwrapTemplate(a.ok_or_else(bad)?.to_owned())
            }
            ("derive", "ecdh.sealed") => Capability::DeriveSealed,
            ("derive", "ecdh.read-only") => Capability::DeriveReadOnly,
            ("derive", rest) if rest.starts_with("ecdh.") => {
                let (key_type, on) = key_and_on(&rest["ecdh.".len()..]).ok_or_else(bad)?;
                Capability::DeriveEcdh { key_type, on }
            }
            ("derive", rest) => {
                let (mechanism, key_type) = mechanism_and_key(rest).ok_or_else(bad)?;
                Capability::Kdf { mechanism, key_type }
            }
            ("commit", rest) => {
                let (kind, rest) = rest.split_once('.').filter(|(k, _)| !k.is_empty()).ok_or_else(bad)?;
                let (key_type, on) = key_and_on(rest).ok_or_else(bad)?;
                Capability::Commit { kind: kind.to_owned(), key_type, bytes: bytes_of(&on).ok_or_else(bad)? }
            }
            ("crypt", rest) => {
                let (mechanism, key_type, on) = mechanism_key_and_on(rest).ok_or_else(bad)?;
                Capability::Crypt { mechanism, key_type, bytes: bytes_of(&on).ok_or_else(bad)? }
            }
            ("sign", rest) => {
                let (mechanism, key_type, on) = mechanism_key_and_on(rest).ok_or_else(bad)?;
                Capability::Sign { mechanism, key_type, on }
            }
            ("encapsulate", rest) => {
                let (key_type, on) = key_and_on(rest).ok_or_else(bad)?;
                Capability::Encapsulate { key_type, on }
            }
            ("attr", rest) => {
                let (way, rest) = rest.split_once('.').ok_or_else(bad)?;
                let read = match way {
                    "set" => false,
                    "read" => true,
                    _ => return Err(bad()),
                };
                let (attr, kt) = rest
                    .split_once('.')
                    .filter(|(a, k)| a.starts_with("CKA_") && a.len() > 4 && k.starts_with("CKK_") && !k.contains('.'))
                    .ok_or_else(bad)?;
                Capability::Attr { read, attr: attr.to_owned(), key_type: KeyKind::from(kt) }
            }
            ("move", m) => Capability::Move(Move::ALL.into_iter().find(|x| x.name() == m).ok_or_else(bad)?),
            ("prove", rest) => {
                let (binding, rest) =
                    rest.split_once('.').filter(|(b, _)| b.len() > 4 && b.starts_with("pop-")).ok_or_else(bad)?;
                let (key_type, on) = key_and_on(rest).ok_or_else(bad)?;
                Capability::Prove { binding: Proof::from(binding), key_type, on }
            }
            _ => return Err(bad()),
        })
    }

    /// Returns the mechanisms that this row measures. An `[untested]` entry must not name these
    /// mechanisms, and the probe counts them as tried. `via` is the mechanism that an export,
    /// unwrap or import used, and it is added when it names a mechanism.
    #[must_use]
    pub fn mechanisms(&self, via: Option<&str>) -> Vec<String> {
        let mut m: Vec<String> = match self {
            Capability::Generate { key_type, .. } => {
                generation_mechanism(key_type.name()).into_iter().map(str::to_owned).collect()
            }
            Capability::WrapOaep(_) | Capability::DecryptOaep(_) => vec!["CKM_RSA_PKCS_OAEP".into()],
            Capability::DeriveSealed | Capability::DeriveReadOnly | Capability::DeriveEcdh { .. } => {
                vec!["CKM_ECDH1_DERIVE".into()]
            }
            Capability::Prove { binding: Proof::PopEcdh, .. } => vec!["CKM_ECDH1_DERIVE".into()],
            Capability::Commit { kind, key_type, .. } => {
                commit_mechanism(kind, key_type.name()).map(str::to_owned).into_iter().collect()
            }
            Capability::Crypt { mechanism, .. }
            | Capability::Kdf { mechanism, .. }
            | Capability::Sign { mechanism, .. } => {
                vec![mechanism.clone()]
            }
            Capability::Encapsulate { .. } => vec!["CKM_ML_KEM".into()],
            _ => Vec::new(),
        };
        m.extend(via.filter(|v| v.starts_with("CKM_")).map(str::to_owned));
        m
    }

    /// Returns whether the probe measures this capability. A [`Capability::Move`] is a claim, so
    /// a regeneration keeps it unchanged and the diff never compares it.
    #[must_use]
    pub fn probed(&self) -> bool {
        !matches!(self, Capability::Move(_))
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Capability::Generate { key_type, on } => write!(f, "generate.{key_type}.{on}"),
            Capability::WrapOaep(h) => write!(f, "wrap.rsa-oaep.{h}"),
            Capability::DecryptOaep(h) => write!(f, "decrypt.rsa-oaep.{h}"),
            Capability::UnwrapTemplate(a) => write!(f, "unwrap.template.{a}"),
            Capability::DeriveSealed => f.write_str("derive.ecdh.sealed"),
            Capability::DeriveReadOnly => f.write_str("derive.ecdh.read-only"),
            Capability::Move(m) => write!(f, "move.{}", m.name()),
            Capability::Prove { binding, key_type, on } => write!(f, "prove.{binding}.{key_type}.{on}"),
            Capability::Import { key_type, on } => write!(f, "import.{key_type}.{on}"),
            Capability::Create { class, key: None } => write!(f, "create.{class}"),
            Capability::Create { class, key: Some((key_type, on)) } => write!(f, "create.{class}.{key_type}.{on}"),
            Capability::Export { way, key_type, on } => write!(f, "export.{}.{key_type}.{on}", way.name()),
            Capability::Unwrap { key_type, on } => write!(f, "unwrap.{key_type}.{on}"),
            Capability::Delete(class) => write!(f, "delete.{class}"),
            Capability::Commit { kind, key_type, bytes } => write!(f, "commit.{kind}.{key_type}.{bytes}"),
            Capability::Crypt { mechanism, key_type, bytes } => write!(f, "crypt.{mechanism}.{key_type}.{bytes}"),
            Capability::Kdf { mechanism, key_type } => write!(f, "derive.{mechanism}.{key_type}"),
            Capability::DeriveEcdh { key_type, on } => write!(f, "derive.ecdh.{key_type}.{on}"),
            Capability::Sign { mechanism, key_type, on } => write!(f, "sign.{mechanism}.{key_type}.{on}"),
            Capability::Encapsulate { key_type, on } => write!(f, "encapsulate.{key_type}.{on}"),
            Capability::Attr { read, attr, key_type } => {
                write!(f, "attr.{}.{attr}.{key_type}", if *read { "read" } else { "set" })
            }
        }
    }
}

/// Yes or no. An absent row means that the answer is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Answer {
    /// The token can perform the operation.
    Yes,
    /// The token cannot perform the operation.
    No,
}

impl Answer {
    /// From a boolean.
    #[must_use]
    pub fn of(yes: bool) -> Answer {
        if yes { Answer::Yes } else { Answer::No }
    }

    /// As a boolean.
    #[must_use]
    pub fn yes(self) -> bool {
        self == Answer::Yes
    }

    /// The word the row writes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Answer::Yes => "yes",
            Answer::No => "no",
        }
    }
}

pub use cakeys_names::{DEVICE_FAILED_RV, names_device_failure};

/// The party that established a row's answer (`by`, review 2026-11-24 E-2..E-4). It tells how
/// far a reader can trust the row. A row without `by` is a legacy row, which was written before
/// the probe recorded provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum By {
    /// The module refused with a `CKR_*` code that is neither a device failure
    /// ([`DEVICE_FAILED_RV`]) nor a busy session. This value is valid only with the answer `no`.
    Module,
    /// cakeys checked the result on the host: it verified a signature, compared a key, or
    /// computed a value again. This value goes with a `yes`, or with a `no` for a result that the
    /// host found to be wrong.
    Host,
    /// The module returned `CKR_OK`, and nothing outside the module checked the result (for
    /// example, a round trip on one module). This value is valid only with the answer `yes`, and
    /// a plan that moves keys between tokens cannot rely on it.
    Unverified,
}

impl By {
    /// The word the row writes.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            By::Module => "module",
            By::Host => "host",
            By::Unverified => "unverified",
        }
    }
}

/// One answer, with its provenance, its evidence, and the way in which the operation succeeded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    /// Yes or no.
    pub answer: Answer,
    /// The party that established the answer. `None` marks a legacy row whose provenance is
    /// unknown.
    #[serde(default)]
    pub by: Option<By>,
    /// The evidence for the answer: the failure, the source or the run.
    #[serde(default)]
    pub evidence: Option<String>,
    /// The way in which the operation succeeded, when the operation has more than one way. It
    /// serves as a hint for the next attempt.
    #[serde(default)]
    pub via: Option<String>,
}

impl Row {
    /// Returns a row that holds only an answer, without provenance or evidence.
    #[must_use]
    pub fn new(answer: Answer) -> Row {
        Row { answer, by: None, evidence: None, via: None }
    }

    /// Returns the device failure that a legacy `no` row cites as its evidence. Such a row is not
    /// a real answer from the module, so it is read as unknown, and an unknown answer causes a
    /// refusal (phase1-design §2.4, §9.1).
    #[must_use]
    pub fn device_failed(&self) -> Option<&'static str> {
        (self.by.is_none() && self.answer == Answer::No)
            .then(|| self.evidence.as_deref().and_then(names_device_failure))?
    }

    /// Returns what is wrong with the row's provenance, if anything. `by = "module"` is valid
    /// only with `no`, and `by = "unverified"` is valid only with `yes`. A `no` from the module
    /// must not cite a device failure.
    fn problem(&self) -> Option<String> {
        match (self.by?, self.answer) {
            (By::Module, Answer::Yes) => Some("by = \"module\" answers only no".into()),
            (By::Unverified, Answer::No) => Some("by = \"unverified\" answers only yes".into()),
            (By::Module, Answer::No) => {
                self.evidence.as_deref().and_then(names_device_failure).map(|rv| {
                    format!("by = \"module\" cites {rv}, a device failure, which is no answer of the module's")
                })
            }
            _ => None,
        }
    }
}

/// The rows of a profile, by capability.
pub type Rows = BTreeMap<Capability, Row>;

/// Reads `[capabilities]` as TOML writes it, with string keys, and parses each key into a
/// [`Capability`]. Two keys that name the same capability are refused. The function never
/// silently keeps only one of them.
pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Rows, D::Error> {
    let raw: BTreeMap<String, Row> = serde::Deserialize::deserialize(d)?;
    let mut rows = Rows::new();
    for (key, row) in raw {
        let c = Capability::parse(&key).map_err(serde::de::Error::custom)?;
        if let Some(problem) = row.problem() {
            return Err(serde::de::Error::custom(format!("capabilities: {key:?}: {problem}")));
        }
        if rows.contains_key(&c) {
            return Err(serde::de::Error::custom(format!("capabilities: {key:?} names {c}, as another key does")));
        }
        rows.insert(c, row);
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A size that is not written in the form in which it is read back is refused, so no two
    /// keys of one profile can name the same row. If two keys did name the same row, the profile
    /// would be refused instead of keeping one of the rows (review capability.rs F1).
    #[test]
    fn one_row_has_one_key() {
        for bad in [
            "generate.CKK_RSA.02048",
            "generate.CKK_RSA.+2048",
            "import.CKK_AES.032",
            "prove.pop-decrypt.CKK_RSA.+2048",
            "create.CKO_PUBLIC_KEY.CKK_RSA.02048",
            "export.host.CKK_AES.+16",
            "unwrap.CKK_AES.00",
        ] {
            assert!(Capability::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(
            Capability::parse("unwrap.CKK_AES.0"),
            Ok(Capability::Unwrap { key_type: "CKK_AES".into(), on: On::Bytes(0) })
        );
        let rows = |a: &str, b: &str| {
            format!(
                "profile = \"m/1\"\nmode = \"observed\"\n[capabilities]\n\
                 \"{a}\" = {{ answer = \"yes\" }}\n\"{b}\" = {{ answer = \"no\" }}\n"
            )
        };
        let e = crate::Profile::from_toml(&rows("generate.CKK_RSA.2048", "generate.CKK_RSA.02048")).unwrap_err();
        assert!(e.contains("02048"), "{e}");
        crate::Profile::from_toml(&rows("generate.CKK_RSA.2048", "generate.CKK_RSA.3072")).unwrap();
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn every_capability_reads_back_from_its_key() {
        let all = [
            Capability::Generate { key_type: "CKK_EC".into(), on: On::Item("secp256r1".into()) },
            Capability::Generate { key_type: "CKK_RSA".into(), on: On::Bits(2048) },
            Capability::WrapOaep("SHA-1".into()),
            Capability::DecryptOaep("SHA-512".into()),
            Capability::UnwrapTemplate("CKA_VALUE_LEN".into()),
            Capability::DeriveSealed,
            Capability::DeriveReadOnly,
            Capability::Move(Move::Export),
            Capability::Move(Move::Unwrap),
            Capability::Move(Move::SecretUnwrap),
            Capability::Move(Move::TrustedWrap),
            Capability::Prove {
                binding: "pop-ecdh".into(),
                key_type: "CKK_EC".into(),
                on: On::Item("secp256r1".into()),
            },
            Capability::Prove { binding: "pop-unwrap".into(), key_type: "CKK_RSA".into(), on: On::Bits(2048) },
            Capability::Import { key_type: "CKK_EC".into(), on: On::Item("secp256r1".into()) },
            Capability::Import { key_type: "CKK_RSA".into(), on: On::Bits(4096) },
            Capability::Import { key_type: "CKK_AES".into(), on: On::Bytes(32) },
            Capability::Create { class: "CKO_CERTIFICATE".into(), key: None },
            Capability::Create { class: "CKO_DATA".into(), key: None },
            Capability::Create {
                class: "CKO_PUBLIC_KEY".into(),
                key: Some(("CKK_EC_EDWARDS".into(), On::Item("edwards25519".into()))),
            },
            Capability::Export { way: Way::Host, key_type: "CKK_RSA".into(), on: On::Bits(2048) },
            Capability::Export { way: Way::Sealed, key_type: "CKK_AES".into(), on: On::Bytes(16) },
            Capability::Unwrap { key_type: "CKK_AES".into(), on: On::Bytes(24) },
            Capability::Unwrap { key_type: "CKK_EC".into(), on: On::Item("secp384r1".into()) },
            Capability::Delete("CKO_PRIVATE_KEY".into()),
            Capability::Commit { kind: "hmac-sha256".into(), key_type: "CKK_GENERIC_SECRET".into(), bytes: 32 },
            Capability::Crypt { mechanism: "CKM_AES_CTR".into(), key_type: "CKK_AES".into(), bytes: 32 },
            Capability::Kdf { mechanism: "CKM_HKDF_DERIVE".into(), key_type: "CKK_GENERIC_SECRET".into() },
            Capability::DeriveEcdh { key_type: "CKK_EC_MONTGOMERY".into(), on: On::Item("curve25519".into()) },
            Capability::Sign {
                mechanism: "CKM_ML_DSA".into(),
                key_type: "CKK_ML_DSA".into(),
                on: On::Item("CKP_ML_DSA_65".into()),
            },
            Capability::Encapsulate { key_type: "CKK_ML_KEM".into(), on: On::Item("CKP_ML_KEM_768".into()) },
            Capability::Attr { read: false, attr: "CKA_ALLOWED_MECHANISMS".into(), key_type: "CKK_EC".into() },
            Capability::Attr { read: true, attr: "CKA_LOCAL".into(), key_type: "CKK_AES".into() },
        ];
        for c in all {
            assert_eq!(Capability::parse(&c.to_string()), Ok(c.clone()), "{c}");
        }
        for bad in [
            "generate.EC.p256",
            "generate.CKK_EC.",
            "wrap.SHA-1",
            "wrap.rsa-oaep.",
            "decrypt.rsa-oaep.SHA.3",
            "unwrap.template.X",
            "unwrap.template.CKA_",
            "derive.ecdh",
            "move.import",
            "prove.sign.CKK_EC.secp256r1",
            "prove.pop-.CKK_EC.secp256r1",
            "prove.pop-sign.EC.secp256r1",
            "prove.pop-sign.CKK_EC",
            "import.CKK_AES",
            "import.AES.32",
            "create.CKO_PUBLIC_KEY",
            "create.CKO_PRIVATE_KEY",
            "create.CKO_PUBLIC_KEY.CKK_EC",
            "export.CKK_EC.secp256r1",
            "export.token.CKK_EC.secp256r1",
            "unwrap.CKK_AES",
            "delete.CKK_AES",
            "delete.CKO_DATA.x",
            "commit.cmac.CKK_AES",
            "commit.cmac.CKK_RSA.2048",
            "crypt.CKM_AES_CTR.CKK_AES",
            "derive.CKM_HKDF_DERIVE",
            "derive.HKDF.CKK_AES",
            "attr.write.CKA_LOCAL.CKK_AES",
            "attr.read.LOCAL.CKK_AES",
            "nothing",
        ] {
            assert!(Capability::parse(bad).is_err(), "{bad}");
        }
        assert!(!Capability::Move(Move::Export).probed() && Capability::DeriveSealed.probed());
        // Every proof that this version of cakeys knows is read back as its known variant, not as
        // an unknown name.
        for name in Proof::NAMES {
            let key = format!("prove.{name}.CKK_EC.secp256r1");
            let Ok(Capability::Prove { binding, .. }) = Capability::parse(&key) else { panic!("{key}") };
            assert!(!matches!(binding, Proof::Other(_)), "{key}");
        }
        // The key type determines the unit of the size: bits for RSA and bytes for a secret key.
        assert_eq!(
            Capability::parse("import.CKK_RSA.2048"),
            Ok(Capability::Import { key_type: "CKK_RSA".into(), on: On::Bits(2048) })
        );
        // The names of a newer cakeys load as they were read (ISSUES.md Q28, review D4).
        for (key, row) in [
            (
                "prove.pop-later.CKK_EC.secp256r1",
                Capability::Prove {
                    binding: Proof::from("pop-later"),
                    key_type: "CKK_EC".into(),
                    on: On::Item("secp256r1".into()),
                },
            ),
            ("wrap.rsa-oaep.SHA-384", Capability::WrapOaep("SHA-384".into())),
            ("decrypt.rsa-oaep.SHA3-256", Capability::DecryptOaep("SHA3-256".into())),
            ("unwrap.template.CKA_KEY_TYPE", Capability::UnwrapTemplate("CKA_KEY_TYPE".into())),
        ] {
            assert_eq!(Capability::parse(key), Ok(row.clone()), "{key}");
            assert_eq!(row.to_string(), key);
        }
        assert_eq!(
            Capability::parse("import.CKK_AES.32"),
            Ok(Capability::Import { key_type: "CKK_AES".into(), on: On::Bytes(32) })
        );
    }
}
