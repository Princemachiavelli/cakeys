//! What a token answers about one of cakeys' own operations (docs/CAPROBE.md, review 2026-11-15
//! §4 (d)): one row type, `"<capability>" = { answer, evidence, via }`, keyed by a
//! [`Capability`] that names the operation. A new capability is a variant here and the
//! operation that tests it; the emitter, the diff and the stack algebra do not change. An
//! absent row is unknown: never probed, never claimed.

use crate::names::{KeyKind, Proof};
use std::collections::BTreeMap;

/// The OAEP hashes the wrap probe tries: what `wrap.rsa-oaep.*` rows can say.
pub const WRAP_OAEP: [&str; 2] = ["SHA-1", "SHA-256"];

/// The OAEP hashes the decryption probe tries: what `decrypt.rsa-oaep.*` rows can say.
pub const DECRYPT_OAEP: [&str; 3] = ["SHA-1", "SHA-256", "SHA-512"];

/// The attributes the unwrap probe puts in a template: what `unwrap.template.*` rows can say.
pub const UNWRAP_TEMPLATE: [&str; 1] = ["CKA_VALUE_LEN"];

/// The proofs of possession (docs/DESIGN.md §3.6) a token can give: what `prove.*` rows can say.
pub const PROOFS: [&str; 4] = ["pop-sign", "pop-ecdh", "pop-decrypt", "pop-unwrap"];

/// What a generation, import or export is of: a curve (or parameter set), or a size in the
/// unit of the key type's own attribute (`docs/CAPROBE_MIGRATION.md`, M1).
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
    /// bytes, else a curve.
    #[must_use]
    pub fn parse(key_type: &KeyKind, on: &str) -> On {
        match on.parse() {
            Ok(n) if matches!(key_type, KeyKind::Rsa) => On::Bits(n),
            Ok(n) => On::Bytes(n),
            Err(_) => On::Item(on.to_owned()),
        }
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
}

/// `<CKK_*>.<curve or size>`, as `generate.*` and the rows like it end.
fn key_and_on(rest: &str) -> Option<(KeyKind, On)> {
    let (kt, on) = rest.split_once('.').filter(|(k, o)| k.starts_with("CKK_") && !o.is_empty())?;
    let kt = KeyKind::from(kt);
    let on = On::parse(&kt, on);
    Some((kt, on))
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
            // Only what a probe tries: a row naming anything else could never be read.
            ("wrap", rest) => {
                let h = rest.strip_prefix("rsa-oaep.").filter(|h| WRAP_OAEP.contains(h)).ok_or_else(bad)?;
                Capability::WrapOaep(h.to_owned())
            }
            ("decrypt", rest) => {
                let h = rest.strip_prefix("rsa-oaep.").filter(|h| DECRYPT_OAEP.contains(h)).ok_or_else(bad)?;
                Capability::DecryptOaep(h.to_owned())
            }
            ("unwrap", rest) => {
                let a = rest.strip_prefix("template.").filter(|a| UNWRAP_TEMPLATE.contains(a)).ok_or_else(bad)?;
                Capability::UnwrapTemplate(a.to_owned())
            }
            ("derive", "ecdh.sealed") => Capability::DeriveSealed,
            ("derive", "ecdh.read-only") => Capability::DeriveReadOnly,
            ("move", m) => Capability::Move(Move::ALL.into_iter().find(|x| x.name() == m).ok_or_else(bad)?),
            ("prove", rest) => {
                let (binding, rest) = rest.split_once('.').filter(|(b, _)| PROOFS.contains(b)).ok_or_else(bad)?;
                let (key_type, on) = key_and_on(rest).ok_or_else(bad)?;
                Capability::Prove { binding: Proof::from(binding), key_type, on }
            }
            _ => return Err(bad()),
        })
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

/// One answer, with what shows it and how the operation succeeded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    /// Yes or no.
    pub answer: Answer,
    /// What shows it: the failure, the source, the run.
    #[serde(default)]
    pub evidence: Option<String>,
    /// How it succeeded where the operation has more than one way (a hint for the next try).
    #[serde(default)]
    pub via: Option<String>,
}

impl Row {
    /// A bare answer.
    #[must_use]
    pub fn new(answer: Answer) -> Row {
        Row { answer, evidence: None, via: None }
    }
}

/// The rows of a profile, by capability.
pub type Rows = BTreeMap<Capability, Row>;

/// `[capabilities]` as TOML writes it: string keys, parsed into [`Capability`].
pub(crate) fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Rows, D::Error> {
    let raw: BTreeMap<String, Row> = serde::Deserialize::deserialize(d)?;
    raw.into_iter().map(|(k, v)| Capability::parse(&k).map(|c| (c, v)).map_err(serde::de::Error::custom)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
        ];
        for c in all {
            assert_eq!(Capability::parse(&c.to_string()), Ok(c.clone()), "{c}");
        }
        for bad in [
            "generate.EC.p256",
            "generate.CKK_EC.",
            "wrap.SHA-1",
            "wrap.rsa-oaep.SHA-3",
            "unwrap.template.CKA_X",
            "derive.ecdh",
            "move.import",
            "prove.pop-x.CKK_EC.secp256r1",
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
            "nothing",
        ] {
            assert!(Capability::parse(bad).is_err(), "{bad}");
        }
        assert!(!Capability::Move(Move::Export).probed() && Capability::DeriveSealed.probed());
        // The key type names the size's unit: RSA in bits, a secret key in bytes.
        assert_eq!(
            Capability::parse("import.CKK_RSA.2048"),
            Ok(Capability::Import { key_type: "CKK_RSA".into(), on: On::Bits(2048) })
        );
        assert_eq!(
            Capability::parse("import.CKK_AES.32"),
            Ok(Capability::Import { key_type: "CKK_AES".into(), on: On::Bytes(32) })
        );
    }
}
