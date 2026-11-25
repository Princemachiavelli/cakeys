//! What a token answers about one of cakeys' own operations (docs/CAPROBE.md, review 2026-11-15
//! §4 (d)): one row type, `"<capability>" = { answer, evidence, via }`, keyed by a
//! [`Capability`] that names the operation. A new capability is a variant here and the
//! operation that tests it; the emitter, the diff and the stack algebra do not change. An
//! absent row is unknown: never probed, never claimed.

use crate::names::{KeyKind, Proof};
use std::collections::BTreeMap;

/// The OAEP hashes the wrap probe tries: the `wrap.rsa-oaep.*` rows this cakeys reads.
pub const WRAP_OAEP: [&str; 2] = ["SHA-1", "SHA-256"];

/// The OAEP hashes the decryption probe tries: the `decrypt.rsa-oaep.*` rows this cakeys reads.
pub const DECRYPT_OAEP: [&str; 3] = ["SHA-1", "SHA-256", "SHA-512"];

/// The attributes the unwrap probe puts in a template: the `unwrap.template.*` rows this cakeys
/// reads.
pub const UNWRAP_TEMPLATE: [&str; 1] = ["CKA_VALUE_LEN"];

/// The hash of a `rsa-oaep.<hash>` row: any one name, known or not.
fn oaep_hash(rest: &str) -> Option<String> {
    rest.strip_prefix("rsa-oaep.").filter(|h| !h.is_empty() && !h.contains('.')).map(str::to_owned)
}

/// What a generation, import or export is of: a curve (or parameter set), or a size in the
/// unit of the key type's own attribute (`docs/archive/CAPROBE_MIGRATION.md`, M1).
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
    /// What a row's last part names for `key_type`: a size in RSA's bits or a secret key's
    /// bytes, else a curve. A profile's row keys go through [`Capability::parse`], which also
    /// refuses a size not written as [`On`] writes it back (`02048`, `+2048`).
    #[must_use]
    pub fn parse(key_type: &KeyKind, on: &str) -> On {
        match on.parse() {
            Ok(n) => On::size(key_type, n),
            Err(_) => On::Item(on.to_owned()),
        }
    }

    /// A size of a key of `key_type`, in the unit its attribute takes: bits for RSA
    /// (`CKA_MODULUS_BITS`), bytes for any other (`CKA_VALUE_LEN`). What a row reads back as.
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
    /// To this process, by RFC 5649 under a key the host drew (`Token::extract`): `export.host.*`.
    Host,
    /// Toward another token's RSA key (`CKM_RSA_AES_KEY_WRAP`, or RSA-OAEP for a secret key):
    /// `export.sealed.*`.
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

/// The public object classes `create.*` rows name without a key type.
pub const CREATE_CLASSES: [&str; 2] = ["CKO_CERTIFICATE", "CKO_DATA"];

/// A way keys move (docs/CAMIGRATE.md D2, D10): this repo's claims, never probe output, so the
/// probe preserves them across regenerations like `[migration]` and the diff never compares
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Move {
    /// The module wraps a key out (`C_WrapKey`): ykcs11 and tpm2-pkcs11 never.
    Export,
    /// The module unwraps a key in (`C_UnwrapKey`).
    Unwrap,
    /// A secret key it unwraps reports its length (`CKA_VALUE_LEN`), which the import's type
    /// check reads: `SoftHSM` leaves it 0.
    SecretUnwrap,
    /// A `CKA_WRAP_WITH_TRUSTED` key leaves toward a transport key the SO marked trusted
    /// (`enforced`): kryoptic cannot.
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
    /// Generating a key of `key_type` (`CKK_*`) on a curve or of a size:
    /// `generate.CKK_EC.secp256r1`, `generate.CKK_RSA.2048`. `via = "by-name"`: only with
    /// `CKA_EC_PARAMS` naming the curve (PKCS#11 3.0's `PrintableString` form), never by OID.
    Generate {
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve, parameter set or size.
        on: On,
    },
    /// Wrapping a key to an RSA key with RSA-OAEP of this hash, MGF1 of the same, round-trip:
    /// `wrap.rsa-oaep.SHA-1`.
    WrapOaep(String),
    /// Decrypting with the private key what the host encrypted to it with RSA-OAEP of this hash
    /// (`pop-decrypt`): `decrypt.rsa-oaep.SHA-256`.
    DecryptOaep(String),
    /// Unwrapping with this attribute in the template: `unwrap.template.CKA_VALUE_LEN`; `no`
    /// is the module refusing it there (`SoftHSM`).
    UnwrapTemplate(String),
    /// ECDH into a sealed (non-extractable) secret, which `pop-ecdh` MACs with on the token:
    /// `derive.ecdh.sealed`. ykcs11 derives only into an extractable one.
    DeriveSealed,
    /// ECDH in a read-only session: `derive.ecdh.read-only`. tpm2-pkcs11 keeps derived secrets
    /// as store rows, so it refuses there.
    DeriveReadOnly,
    /// A way keys move: `move.export`, `move.unwrap`, `move.secret-unwrap`, `move.trusted-wrap`.
    Move(Move),
    /// Proving possession of a private key of `key_type` on a curve or of a size, by
    /// `binding`, as the verbs prove it: `prove.pop-ecdh.CKK_EC.secp256r1`,
    /// `prove.pop-decrypt.CKK_RSA.2048`.
    Prove {
        /// The proof, by its `binding` name.
        binding: Proof,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve or size.
        on: On,
    },
    /// Bringing a key of `key_type` in from the host's plaintext, the token then showing that
    /// key: `import.CKK_EC.secp256r1`, `import.CKK_AES.32`. `via` is the path that worked:
    /// `create-object`, or the provider's own (`tpm2-ptool`, `piv-import`).
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
    /// An extractable key of `key_type` leaving `way`, and arriving as the same material:
    /// `export.host.CKK_EC.secp256r1`, `export.sealed.CKK_RSA.2048`. `via` is the mechanism.
    Export {
        /// To the host, or toward another token.
        way: Way,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve or size.
        on: On,
    },
    /// `C_UnwrapKey` bringing a key of `key_type` in as the material wrapped:
    /// `unwrap.CKK_AES.32`. `via` is the mechanism.
    Unwrap {
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve or size.
        on: On,
    },
    /// `C_DestroyObject` really removing an object of the class (`CKO_*`): `delete.CKO_PRIVATE_KEY`.
    Delete(String),
    /// A secret key's commitment, the operation `kind` names (`cakeys_core::id::Commit::
    /// profile_kind`: `hmac-sha256`, `cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`), working on a key of
    /// `key_type` of `bytes`: `commit.hmac-sha256.CKK_GENERIC_SECRET.32`. A check value's cipher
    /// is the key type's (`commit.kcv-ecb.CKK_DES3.24`).
    Commit {
        /// The commitment kind.
        kind: String,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The key's length in bytes.
        bytes: u32,
    },
    /// A symmetric mode (`CKM_AES_CBC`, `CKM_AES_GCM`...) encrypting and decrypting back on a
    /// key of `key_type` of `bytes`: `crypt.CKM_AES_CTR.CKK_AES.32`.
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
    /// ECDH between keys of `key_type` on a curve, beyond the curves `prove.pop-ecdh.*` covers
    /// (Montgomery): `derive.ecdh.CKK_EC_MONTGOMERY.curve25519`.
    DeriveEcdh {
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The curve.
        on: On,
    },
    /// Signing and verifying back on the token with a mechanism no `prove.*` row stands for
    /// (post-quantum, XEdDSA): `sign.CKM_ML_DSA.CKK_ML_DSA.CKP_ML_DSA_65`.
    Sign {
        /// The mechanism, by `CKM_*` name.
        mechanism: String,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The parameter set or curve.
        on: On,
    },
    /// `C_EncapsulateKey` then `C_DecapsulateKey` agreeing on a secret:
    /// `encapsulate.CKK_ML_KEM.CKP_ML_KEM_768`.
    Encapsulate {
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
        /// The parameter set.
        on: On,
    },
    /// An attribute the verbs set or read, on a key of `key_type`:
    /// `attr.set.CKA_ALLOWED_MECHANISMS.CKK_EC` (a template carries it, a read-back shows it) or
    /// `attr.read.CKA_LOCAL.CKK_AES` (the module returns it, truthfully).
    Attr {
        /// Read (the module reports it) rather than set (the template carries it).
        read: bool,
        /// The attribute, by `CKA_*` name.
        attr: String,
        /// The key type, by `CKK_*` name.
        key_type: KeyKind,
    },
}

/// `<CKK_*>.<curve or size>`, as `generate.*` and the rows like it end. A size is written as
/// its number alone: `02048` or `+2048` would read as 2048 and be written back as `2048`, so two
/// keys could name one row.
fn key_and_on(rest: &str) -> Option<(KeyKind, On)> {
    let (kt, text) = rest.split_once('.').filter(|(k, o)| k.starts_with("CKK_") && !o.is_empty())?;
    let kt = KeyKind::from(kt);
    let on = On::parse(&kt, text);
    (on.to_string() == text).then_some((kt, on))
}

/// `CKM_*.<CKK_*>`: a mechanism and a key type, no size.
fn mechanism_and_key(rest: &str) -> Option<(String, KeyKind)> {
    let (mechanism, kt) = rest.split_once('.').filter(|(m, k)| m.starts_with("CKM_") && k.starts_with("CKK_"))?;
    (!kt.contains('.')).then(|| (mechanism.to_owned(), KeyKind::from(kt)))
}

/// `CKM_*.<CKK_*>.<curve, set or size>`.
fn mechanism_key_and_on(rest: &str) -> Option<(String, KeyKind, On)> {
    let (mechanism, rest) = rest.split_once('.').filter(|(m, _)| m.starts_with("CKM_"))?;
    let (kt, on) = key_and_on(rest)?;
    Some((mechanism.to_owned(), kt, on))
}

/// The mechanism that generates a key of `key_type`, as `generate.*` rows measure it.
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

/// The mechanism a commitment of `kind` computes with on a key of `key_type`.
#[must_use]
pub fn commit_mechanism(kind: &str, key_type: &str) -> Option<&'static str> {
    Some(match kind {
        "hmac-sha1" => "CKM_SHA_1_HMAC",
        "hmac-sha224" => "CKM_SHA224_HMAC",
        "hmac-sha256" => "CKM_SHA256_HMAC",
        "hmac-sha384" => "CKM_SHA384_HMAC",
        "hmac-sha512" => "CKM_SHA512_HMAC",
        "cmac" => "CKM_AES_CMAC",
        "kcv-ecb" | "kcv-ecb-dec" if key_type == "CKK_DES3" => "CKM_DES3_ECB",
        "kcv-ecb" | "kcv-ecb-dec" => "CKM_AES_ECB",
        "kw" => "CKM_AES_KEY_WRAP",
        _ => return None,
    })
}

/// A key length: bytes, whatever the key type.
fn bytes_of(on: &On) -> Option<u32> {
    match on {
        On::Bytes(n) => Some(*n),
        _ => None,
    }
}

impl Capability {
    /// Parse a row's key.
    ///
    /// # Errors
    ///
    /// The key names no capability.
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
            // A hash, attribute or proof this cakeys does not know loads as read and answers
            // nothing, like an unknown key type (ISSUES.md Q28, review D4): only the shape is
            // held, so a profile from a newer cakeys loads.
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

    /// The mechanisms this row is the measurement of: what an `[untested]` entry must not
    /// name, and what the probe counts as tried. `via` is the mechanism an export, unwrap or
    /// import took, where it is one.
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
            Capability::Prove { binding, .. } if binding.name() == "pop-ecdh" => vec!["CKM_ECDH1_DERIVE".into()],
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

    /// Whether the probe measures it: a [`Capability::Move`] is a claim, preserved across
    /// regenerations and never compared.
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

/// Yes or no; an absent row is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Answer {
    /// It does.
    Yes,
    /// It does not.
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

/// The `CKR_*` return values that say the device, the token or the session failed, rather than
/// anything of the operation asked (review 2026-11-24 E-2, phase1-design §2.5): a refusal citing
/// one is no answer of the module's. The token crate's `rv::device_failed` matches by these
/// names, so the probe, the loader and the token agree.
// P4: this list moves to the leaf crate (`cakeys-names`) with the other restated tables.
pub const DEVICE_FAILED_RV: [&str; 11] = [
    "CKR_DEVICE_ERROR",
    "CKR_DEVICE_MEMORY",
    "CKR_DEVICE_REMOVED",
    "CKR_HOST_MEMORY",
    "CKR_GENERAL_ERROR",
    "CKR_TOKEN_NOT_PRESENT",
    "CKR_TOKEN_NOT_RECOGNIZED",
    "CKR_SESSION_CLOSED",
    "CKR_SESSION_HANDLE_INVALID",
    "CKR_CRYPTOKI_NOT_INITIALIZED",
    "CKR_FUNCTION_CANCELED",
];

/// The first of [`DEVICE_FAILED_RV`] that `text` names, as a whole name
/// (`CKR_DEVICE_ERROR`, never a prefix of a longer `CKR_*`).
#[must_use]
pub fn names_device_failure(text: &str) -> Option<&'static str> {
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    DEVICE_FAILED_RV.into_iter().find(|name| {
        text.match_indices(name).any(|(i, _)| !text[..i].ends_with(ident) && !text[i + name.len()..].starts_with(ident))
    })
}

/// Who showed a row's answer (`by`, review 2026-11-24 E-2..E-4): what the row is worth. A row
/// without one is legacy, written before provenance was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum By {
    /// The module refused with a `CKR_*` that is neither a device failure
    /// ([`DEVICE_FAILED_RV`]) nor a busy session: a `no` only.
    Module,
    /// cakeys checked the result on the host: a signature verified, a key compared, a value
    /// computed again. A `yes`, or a `no` for a result the host found wrong.
    Host,
    /// The module said `CKR_OK` and nothing outside it checked (a round trip on one module): a
    /// `yes` only, which a cross-token plan cannot rest on.
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

/// One answer, with what shows it and how the operation succeeded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    /// Yes or no.
    pub answer: Answer,
    /// Who showed it; `None`: legacy, provenance unknown.
    #[serde(default)]
    pub by: Option<By>,
    /// What shows it: the failure, the source, the run.
    #[serde(default)]
    pub evidence: Option<String>,
    /// How it succeeded where the operation has more than one way (a hint for the next try).
    #[serde(default)]
    pub via: Option<String>,
}

impl Row {
    /// A bare answer, of no recorded provenance.
    #[must_use]
    pub fn new(answer: Answer) -> Row {
        Row { answer, by: None, evidence: None, via: None }
    }

    /// The device failure a legacy `no` cites as its evidence: such a row is no answer of the
    /// module's, and reads unknown, which refuses (phase1-design §2.4, §9.1).
    #[must_use]
    pub fn device_failed(&self) -> Option<&'static str> {
        (self.by.is_none() && self.answer == Answer::No)
            .then(|| self.evidence.as_deref().and_then(names_device_failure))?
    }

    /// What is wrong with the row's provenance: `module` answers only no, `unverified` only yes,
    /// and the module's no never cites a device failure.
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

/// `[capabilities]` as TOML writes it: string keys, parsed into [`Capability`]. Two keys that
/// name one capability are refused, never one silently kept.
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

    /// A size not written as it reads back is refused, so no two keys of one profile name one
    /// row; and were they to, the profile is refused rather than one row kept (review
    /// capability.rs F1).
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
        // Every proof this cakeys knows reads back as itself, not as a name kept as read.
        for name in Proof::NAMES {
            let key = format!("prove.{name}.CKK_EC.secp256r1");
            let Ok(Capability::Prove { binding, .. }) = Capability::parse(&key) else { panic!("{key}") };
            assert!(!matches!(binding, Proof::Other(_)), "{key}");
        }
        // The key type names the size's unit: RSA in bits, a secret key in bytes.
        assert_eq!(
            Capability::parse("import.CKK_RSA.2048"),
            Ok(Capability::Import { key_type: "CKK_RSA".into(), on: On::Bits(2048) })
        );
        // A newer cakeys's names load as read (ISSUES.md Q28, review D4).
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
