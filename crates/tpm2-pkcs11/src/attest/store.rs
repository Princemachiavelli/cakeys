//! Reading tpm2-pkcs11's sqlite store (the `esysdb` backend). The attestation path reads the
//! object's TPM blobs from it, exactly as the module itself does, and then has the TPM prove
//! they are real: `TPM2_Load` revalidates the private blob's integrity under the parent, and
//! `TPM2_Certify` signs the Name — so a tampered store cannot fake a resident key.
//!
//! The store is read-only here and its format is tpm2-pkcs11 1.10.x (schema db.c `db_init_new`,
//! attrs serialized by libyaml with explicit tags). It is *not* a stable interface; the
//! integration tests pin it against the real module.

use cakeys_core::types::ObjectClass;
use cakeys_core::{KmError, Result};
use rusqlite::{Connection, OpenFlags};
use serde_norway::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// The store's file name inside its directory (db.c `DB_NAME`).
pub const DB_NAME: &str = "tpm2_pkcs11.sqlite3";

/// Vendor attribute types in `tobjects.attrs` (src/lib/attrs.h of tpm2-pkcs11):
/// `CKA_VENDOR_DEFINED | CKA_VENDOR_TPM2_DEFINED | n`.
const ATTR_CLASS: u64 = 0; // CKA_CLASS
const ATTR_LABEL: u64 = 3; // CKA_LABEL
const ATTR_ID: u64 = 0x102; // CKA_ID
const ATTR_OBJAUTH_ENC: u64 = 0x8F00_0001; // CKA_TPM2_OBJAUTH_ENC
const ATTR_PUB_BLOB: u64 = 0x8F00_0002; // CKA_TPM2_PUB_BLOB
const ATTR_PRIV_BLOB: u64 = 0x8F00_0003; // CKA_TPM2_PRIV_BLOB

/// `CKO_PRIVATE_KEY`, `CKO_PUBLIC_KEY`, `CKO_SECRET_KEY` (`CKO_DATA` and `CKO_CERTIFICATE` have no
/// TPM blobs to certify).
const CLASS_PRIVATE_KEY: i64 = 3;

const CLASS_SECRET_KEY: i64 = 4;

/// Everything the attestation path needs from one token's store.
pub struct Store {
    /// The token's primary parent: a persistent TPM handle (from the serialized `ESYS_TR` in
    /// `pobjects.config`) with its auth value (`pobjects.objauth`, plaintext, empty by default).
    pub parent: Parent,
    /// The user seal object, whose unseal needs the PIN and yields the token wrapping key.
    pub seal: Seal,
    /// The token's key objects.
    pub tobjects: Vec<TObject>,
}

pub struct Parent {
    pub handle: u32,
    pub auth: Vec<u8>,
}

pub struct Seal {
    pub pub_blob: Vec<u8>,
    pub priv_blob: Vec<u8>,
    pub auth_salt: String,
}

pub struct TObject {
    pub class: i64,
    pub cka_label: Option<Vec<u8>>,
    pub cka_id: Option<Vec<u8>>,
    pub pub_blob: Vec<u8>,
    /// Only private-key rows carry one; the public half of a generated pair is stored without
    /// it (`TPM2_Certify` needs the private area loaded, so those rows cannot attest).
    pub priv_blob: Option<Vec<u8>>,
    /// The `<iv>:<tag>:<ct>` hex string, GCM-encrypted under the wrapping key; absent on
    /// rows that need no authorization (public halves).
    pub objauth_enc: Option<String>,
}

/// Columns are read as raw values, not by declared type: the module binds its hex strings and
/// YAML with the sqlite BLOB flag even where the schema says TEXT, and the seal blobs arrive
/// as blob-flagged hex strings.
fn text(row: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<String> {
    use rusqlite::types::ValueRef;
    Ok(match row.get_ref(i)? {
        // Blob or text: the module binds its hex strings and YAML with the sqlite BLOB flag
        // even where the schema says TEXT; anything else is an unset column.
        ValueRef::Blob(b) | ValueRef::Text(b) => String::from_utf8_lossy(b).into_owned(),
        _ => String::new(),
    })
}

impl Store {
    /// Open the store in `dir` like tpm2-pkcs11 (`<dir>/tpm2_pkcs11.sqlite3`) and read one
    /// token's rows. Read-only; the module stays the writer.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the database cannot be opened, a query fails, or a row's attrs
    /// cannot be parsed (a wrong directory is an error, never a fresh store the module might
    /// pick up); `NotFound` when the store holds no token with the label.
    pub fn open(dir: &Path, token_label: &str) -> Result<Store> {
        let path = dir.join(DB_NAME);
        // Read-only, so a wrong directory is an error — never a fresh empty store the module
        // might pick up later.
        let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| KmError::Unavailable(format!("opening tpm2-pkcs11 store {}: {e}", path.display())))?;
        // `sealobjects.tokid` and `tobjects.tokid` reference `tokens.id` (db.c schema), not the
        // primary `tokens.pid` that several tokens may share.
        let (tok_id, config, objauth) = db
            .query_row(
                "SELECT tokens.id, pobjects.config, pobjects.objauth FROM tokens
                 JOIN pobjects ON pobjects.id = tokens.pid WHERE tokens.label = ?1",
                [token_label],
                |r| Ok((r.get::<_, i64>(0)?, text(r, 1)?, text(r, 2)?)),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    KmError::NotFound(format!("token '{token_label}' in the tpm2-pkcs11 store {}", path.display()))
                }
                e => KmError::Unavailable(format!("reading pobjects: {e}")),
            })?;
        let parent = parse_parent(&config, &objauth)?;
        // The seal blobs arrive as raw marshaled `TPM2B_`s (sqlite BLOB values), the auth salt
        // as its hex string.
        let (userpub, userpriv, userauthsalt) = db
            .query_row("SELECT userpub, userpriv, userauthsalt FROM sealobjects WHERE tokid = ?1", [tok_id], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, text(r, 2)?))
            })
            .map_err(|e| KmError::Unavailable(format!("reading sealobjects: {e}")))?;
        let seal = Seal { pub_blob: userpub, priv_blob: userpriv, auth_salt: userauthsalt };
        let mut tobjects = Vec::new();
        {
            let mut stmt = db
                .prepare("SELECT attrs FROM tobjects WHERE tokid = ?1")
                .map_err(|e| KmError::Unavailable(format!("selecting tobjects: {e}")))?;
            let rows = stmt
                .query_map([tok_id], |r| text(r, 0))
                .map_err(|e| KmError::Unavailable(format!("reading tobjects: {e}")))?;
            for attrs in rows {
                let attrs = attrs.map_err(|e| KmError::Unavailable(format!("reading a tobject: {e}")))?;
                tobjects.extend(parse_tobject(&attrs)?);
            }
        }
        Ok(Store { parent, seal, tobjects })
    }
}

impl Store {
    /// The single key object under the locator's `CKA_ID` (and label, when the live object
    /// reports one) that can be certified: what the PKCS#11 handle being attested must
    /// correspond to, and carrying a private blob (`TPM2_Certify` cannot attest a public-only
    /// area).
    ///
    /// # Errors
    ///
    /// `NotFound` when no row carries the `CKA_ID`; `Ambiguous` when several do (a label
    /// narrows it, but never silently picks).
    #[expect(clippy::format_collect, reason = "the id-hex builder reads best as map-format-collect")]
    pub fn find(&self, cka_id: &[u8], label: Option<&[u8]>, class: i64) -> Result<&TObject> {
        let id = || cka_id.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let matches: Vec<&TObject> = self
            .tobjects
            .iter()
            .filter(|t| {
                t.class == class
                    && t.priv_blob.is_some()
                    && t.cka_id.as_deref() == Some(cka_id)
                    && label.is_none_or(|l| t.cka_label.as_deref() == Some(l))
            })
            .collect();
        match matches.len() {
            1 => Ok(matches[0]),
            0 => Err(KmError::NotFound(format!(
                "no certifiable store object of the key's class with CKA_ID {} in the tpm2-pkcs11 store",
                id()
            ))),
            n => Err(KmError::Ambiguous(format!("{n} store rows match the key's CKA_ID {}", id()))),
        }
    }
}

/// The class the PKCS#11 `ObjectCfg` maps to in the store, for row matching.
///
/// # Errors
///
/// `Unsupported` for a class the store keeps no key rows for (certificates, data objects:
/// nothing to certify).
pub fn store_class(class: ObjectClass) -> Result<i64> {
    match class {
        // CKO_PUBLIC_KEY objects are the public half of a pair: stored without a private blob,
        // and TPM2_Certify cannot attest a public-only area.
        ObjectClass::PrivateKey => Ok(CLASS_PRIVATE_KEY),
        ObjectClass::SecretKey => Ok(CLASS_SECRET_KEY),
        c => Err(KmError::Unsupported(format!(
            "TPM2_Certify attests private and secret keys (TPM-resident, private area loaded), not {c}"
        ))),
    }
}

/// `pobjects.config` is YAML `{esys-tr: <hex>, transient: false}`; the serialized `ESYS_TR` is
/// `TPM2_HANDLE (BE) ‖ TPM2B_NAME ‖ rsrcType (BE, 1 = key) ‖ TPM2B_PUBLIC`. Only the persistent
/// parent form is supported — transient primaries would need re-derivation from the template.
fn parse_parent(config: &str, objauth: &str) -> Result<Parent> {
    let bad = |what: &str| KmError::Unavailable(format!("tpm2-pkcs11 store: primary object: {what}"));
    let config: BTreeMap<String, Value> = serde_norway::from_str(config).map_err(|e| bad(&e.to_string()))?;
    let Some(esys_tr) = config.get("esys-tr") else {
        return Err(bad(
            "the token's primary is transient; attestation needs a persistent one (tpm2_ptool init default)",
        ));
    };
    let blob = esys_tr.as_str().and_then(|h| hex(h).ok()).ok_or_else(|| bad("esys-tr is not a hex blob"))?;
    let mut rest = blob.as_slice();
    let be32 = |r: &mut &[u8]| {
        r.first_chunk::<4>().map(|b| u32::from_be_bytes(*b)).inspect(|_| {
            *r = &r[4..];
        })
    };
    let Some(handle) = be32(&mut rest) else { return Err(bad("esys-tr has no handle")) };
    let name_len =
        rest.first_chunk::<2>().map(|b| u16::from_be_bytes(*b) as usize).ok_or_else(|| bad("esys-tr has no name"))?;
    rest = rest.get(2 + name_len..).ok_or_else(|| bad("esys-tr name is truncated"))?;
    match be32(&mut rest) {
        Some(1) => {}
        _ => return Err(bad("esys-tr is not a key resource")),
    }
    if !(0x8100_0000..=0x81FF_FFFF).contains(&handle) {
        return Err(bad(&format!("esys-tr names handle {handle:#10x}, not a persistent object")));
    }
    Ok(Parent { handle, auth: objauth.as_bytes().to_vec() })
}

/// A row's attribute map. The module can write an attribute twice (seen: `CKA_TOKEN`, type 1, on
/// keys cakeys generates [run]), which a YAML mapping type refuses; here the last value stands,
/// as it did for the line reader this replaced.
struct Attrs(BTreeMap<u64, Value>);

impl<'de> serde::Deserialize<'de> for Attrs {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Pairs;
        impl<'de> serde::de::Visitor<'de> for Pairs {
            type Value = Attrs;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map from attribute type to value")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> std::result::Result<Attrs, A::Error> {
                let mut attrs = BTreeMap::new();
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    let k =
                        k.as_u64().ok_or_else(|| serde::de::Error::custom("an attribute type is not an integer"))?;
                    attrs.insert(k, v);
                }
                Ok(Attrs(attrs))
            }
        }
        d.deserialize_map(Pairs)
    }
}

/// One `tobjects.attrs` row: a YAML map from the attribute type to its value, every scalar
/// explicitly tagged — `? !!int "258" : !!str "a1..."`. Values cakeys needs are integers and
/// hex strings; the rest (booleans, the `CKA_ALLOWED_MECHANISMS` sequences) is parsed and left.
/// `None` for a row without TPM key material (no `CKA_TPM2_PUB_BLOB`): an ECDH-derived secret,
/// which tpm2-pkcs11 1.10 keeps as a store row even from a `CKA_TOKEN = false` template [run] —
/// never certifiable, and no reason to refuse the rest of the store.
fn parse_tobject(attrs: &str) -> Result<Option<TObject>> {
    let bad = |what: &str| KmError::Unavailable(format!("tpm2-pkcs11 store: object attrs: {what}"));
    let Attrs(attrs) = serde_norway::from_str(attrs).map_err(|e| bad(&e.to_string()))?;
    let attr = |attr: u64| attrs.get(&attr);
    let bytes = |a| attr(a).and_then(Value::as_str).and_then(|h| hex(h).ok());
    let class = attr(ATTR_CLASS).and_then(Value::as_i64).ok_or_else(|| bad("no CKA_CLASS"))?;
    Ok(bytes(ATTR_PUB_BLOB).map(|pub_blob| TObject {
        class,
        cka_label: bytes(ATTR_LABEL),
        cka_id: bytes(ATTR_ID),
        pub_blob,
        priv_blob: bytes(ATTR_PRIV_BLOB),
        // The value is hex of the ASCII "<iv>:<tag>:<ct>" string.
        objauth_enc: bytes(ATTR_OBJAUTH_ENC).map(|b| String::from_utf8_lossy(&b).into_owned()),
    }))
}

/// Decode one hex string attribute (tpm2-pkcs11 stores all buffers as hex text). The error
/// never quotes the value: the unsealed wrapping key comes through here.
pub(crate) fn hex(s: &str) -> Result<Vec<u8>> {
    cakeys_core::hex::decode(s).ok_or_else(|| KmError::Unavailable("a tpm2-pkcs11 store value is not hex".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rows as tpm2-pkcs11 1.10 wrote them on swtpm (`tpm2_ptool addkey`): a P-256 pair with
    /// label "k1" and `CKA_ID` "0a" (stored as the hex of that text).
    #[test]
    fn rows_parse_as_the_module_wrote_them() {
        let private = parse_tobject(include_str!("../../tests/fixtures/tobject-private.yaml")).unwrap().unwrap();
        assert_eq!(private.class, CLASS_PRIVATE_KEY);
        assert_eq!(private.cka_label.as_deref(), Some(&b"k1"[..]));
        assert_eq!(private.cka_id.as_deref(), Some(&b"0a"[..]));
        assert_eq!(
            private.pub_blob.len(),
            2 + usize::from(u16::from_be_bytes([private.pub_blob[0], private.pub_blob[1]]))
        );
        assert!(private.priv_blob.is_some());
        // "<iv>:<tag>:<ct>", each part hex.
        let auth = private.objauth_enc.unwrap();
        assert_eq!(auth.split(':').map(|p| hex(p).unwrap().len()).collect::<Vec<_>>()[..2], [12, 16]);
        // The public half: the same public area, nothing to load or authorize.
        let public = parse_tobject(include_str!("../../tests/fixtures/tobject-public.yaml")).unwrap().unwrap();
        assert_eq!((public.class, public.pub_blob), (2, private.pub_blob));
        assert!(public.priv_blob.is_none() && public.objauth_enc.is_none());
    }

    #[test]
    fn rows_without_key_material_are_skipped_and_broken_ones_refused() {
        // An ECDH-derived secret: a class, no TPM blobs.
        assert!(parse_tobject("---\n!!map {\n  ? !!int \"0\"\n  : !!int \"4\",\n}\n").unwrap().is_none());
        // An attribute written twice: the last value stands.
        let twice = "---\n!!map {\n  ? !!int \"0\"\n  : !!int \"3\",\n  ? !!int \"0\"\n  : !!int \"4\",\n  ? !!int \"2399141890\"\n  : !!str \"00\",\n}\n";
        assert_eq!(parse_tobject(twice).unwrap().unwrap().class, CLASS_SECRET_KEY);
        for broken in ["---\n!!map {\n  ? !!int \"3\"\n  : !!str \"6b31\",\n}\n", "!!map {", "- 1\n"] {
            assert!(matches!(parse_tobject(broken), Err(KmError::Unavailable(_))), "{broken}");
        }
    }

    #[test]
    fn the_parent_is_the_persistent_handle_the_store_names() {
        let parent = parse_parent(include_str!("../../tests/fixtures/pobject-config.yaml"), "").unwrap();
        assert_eq!(parent.handle, 0x8100_0001);
        let err = parse_parent("---\n!!map {\n  ? !!str \"transient\"\n  : !!bool \"true\",\n}\n", "").err().unwrap();
        assert!(err.to_string().contains("primary is transient"), "{err}");
    }
}
