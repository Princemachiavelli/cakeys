//! Reading tpm2-pkcs11's sqlite store (the `esysdb` backend). The attestation path reads the
//! object's TPM blobs from it, exactly as the module itself does, and then has the TPM prove
//! they are real: `TPM2_Load` revalidates the private blob's integrity under the parent, and
//! `TPM2_Certify` signs the Name — so a tampered store cannot fake a resident key.
//!
//! The store is read-only here and its format is tpm2-pkcs11 1.10.x (schema db.c `db_init_new`,
//! attrs serialized by libyaml with explicit tags). It is *not* a stable interface; the
//! integration tests pin it against the real module.

use cakeys_core::types::ObjectClass;
use cakeys_core::{Check, KmError, Reason, Result};
use rusqlite::{Connection, OpenFlags};
use serde_norway::Value;
use std::collections::BTreeMap;
use std::path::Path;

/// The store's file name inside its directory (db.c `DB_NAME`).
pub(crate) const DB_NAME: &str = "tpm2_pkcs11.sqlite3";

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
pub(crate) struct Store {
    /// The token's primary parent: a persistent TPM handle (from the serialized `ESYS_TR` in
    /// `pobjects.config`) with its auth value (`pobjects.objauth`, plaintext, empty by default).
    pub parent: Parent,
    /// The user seal object, whose unseal needs the PIN and yields the token wrapping key.
    pub seal: Seal,
    /// The token's key objects.
    pub tobjects: Vec<TObject>,
    /// Why each row that could not be read was refused: kept aside, not refusing the token
    /// (attest/store.rs F1), and said only when no readable row is the one asked for.
    pub refused: Vec<KmError>,
    /// The store file, named in what [`Store::find`] reports.
    pub path: std::path::PathBuf,
}

/// The token's primary parent (`pobjects`).
pub(crate) struct Parent {
    /// Its persistent TPM handle.
    pub(crate) handle: u32,
    /// Its auth value (`pobjects.objauth`).
    pub(crate) auth: Vec<u8>,
}

/// The token's user seal object (`sealobjects`).
pub(crate) struct Seal {
    /// Its public area (`userpub`).
    pub(crate) pub_blob: Vec<u8>,
    /// Its private area (`userpriv`).
    pub(crate) priv_blob: Vec<u8>,
    /// The salt the user PIN is combined with into its auth value (`userauthsalt`).
    pub(crate) auth_salt: String,
}

/// One key object of the token (`tobjects`).
pub(crate) struct TObject {
    /// `CKA_CLASS`, as the module stores it.
    pub(crate) class: i64,
    /// `CKA_LABEL`, when it has one.
    pub(crate) cka_label: Option<Vec<u8>>,
    /// `CKA_ID`, when it has one.
    pub(crate) cka_id: Option<Vec<u8>>,
    /// The TPM public area (`CKA_TPM2_PUB_BLOB`).
    pub(crate) pub_blob: Vec<u8>,
    /// Only private-key rows carry one; the public half of a generated pair is stored without
    /// it (`TPM2_Certify` needs the private area loaded, so those rows cannot attest).
    pub priv_blob: Option<Vec<u8>>,
    /// The `<iv>:<tag>:<ct>` hex string, GCM-encrypted under the wrapping key; absent on
    /// rows that need no authorization (public halves).
    pub objauth_enc: Option<String>,
}

/// Columns are read as raw values, not by declared type: the module binds its hex strings and
/// YAML with the sqlite BLOB flag even where the schema says TEXT, and the seal blobs arrive
/// as blob-flagged hex strings. Bytes that are not UTF-8 are refused, never replaced
/// (attest/store.rs F3): a replaced byte would fail later as something else, a salt as a wrong
/// PIN.
fn text(row: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<String> {
    use rusqlite::types::{Type, ValueRef};
    match row.get_ref(i)? {
        // Blob or text: the module binds its hex strings and YAML with the sqlite BLOB flag
        // even where the schema says TEXT; anything else is an unset column.
        ValueRef::Blob(b) | ValueRef::Text(b) => std::str::from_utf8(b)
            .map(str::to_owned)
            .map_err(|e| rusqlite::Error::FromSqlConversionFailure(i, Type::Text, Box::new(e))),
        _ => Ok(String::new()),
    }
}

impl Store {
    /// Open the store in `dir` like tpm2-pkcs11 (`<dir>/tpm2_pkcs11.sqlite3`) and read one
    /// token's rows. Read-only; the module stays the writer.
    ///
    /// # Errors
    ///
    /// `Unavailable` when the database cannot be opened or a query fails (a wrong directory is
    /// an error, never a fresh store the module might pick up); `NotFound` when the store holds
    /// no token with the label, `Ambiguous` (12) when it holds several. A key row whose attrs cannot be parsed refuses no other row: it
    /// is kept aside ([`Store::refused`]).
    pub(crate) fn open(dir: &Path, token_label: &str) -> Result<Store> {
        let path = dir.join(DB_NAME);
        // Read-only, so a wrong directory is an error — never a fresh empty store the module
        // might pick up later.
        let db = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| KmError::Unavailable(format!("opening tpm2-pkcs11 store {}: {e}", path.display()).into()))?;
        // `sealobjects.tokid` and `tobjects.tokid` reference `tokens.id` (db.c schema), not the
        // primary `tokens.pid` that several tokens may share.
        // Every token of the label: two of one label are told apart by the serial the module
        // derives, which the store does not hold, so the seal and rows of the other could be read
        // (review 2026-11-23 B-13). Refused rather than guessed.
        let tokens: Vec<(i64, String, String)> = {
            let reading = |e: rusqlite::Error| KmError::Unavailable(format!("reading pobjects: {e}").into());
            let mut stmt = db
                .prepare(
                    "SELECT tokens.id, pobjects.config, pobjects.objauth FROM tokens
                     JOIN pobjects ON pobjects.id = tokens.pid WHERE tokens.label = ?1",
                )
                .map_err(reading)?;
            let rows = stmt
                .query_map([token_label], |r| Ok((r.get::<_, i64>(0)?, text(r, 1)?, text(r, 2)?)))
                .map_err(reading)?;
            rows.collect::<rusqlite::Result<_>>().map_err(reading)?
        };
        let (tok_id, config, objauth) = match <[_; 1]>::try_from(tokens) {
            Ok([one]) => one,
            Err(tokens) if tokens.is_empty() => {
                return Err(KmError::NotFound(
                    format!("token '{token_label}' in the tpm2-pkcs11 store {}", path.display()).into(),
                ));
            }
            Err(tokens) => {
                return Err(KmError::Ambiguous(Reason::check(
                    Check::TokenUnique,
                    format!(
                        "{} tokens are labelled '{token_label}' in the tpm2-pkcs11 store {}, which records no serial to \
                         tell them apart: relabel all but one",
                        tokens.len(),
                        path.display()
                    ),
                )));
            }
        };
        let parent = parse_parent(&config, &objauth)?;
        // The seal blobs arrive as raw marshaled `TPM2B_`s (sqlite BLOB values), the auth salt
        // as its hex string.
        let (userpub, userpriv, userauthsalt) = db
            .query_row("SELECT userpub, userpriv, userauthsalt FROM sealobjects WHERE tokid = ?1", [tok_id], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?, text(r, 2)?))
            })
            .map_err(|e| KmError::Unavailable(format!("reading sealobjects: {e}").into()))?;
        let seal = Seal { pub_blob: userpub, priv_blob: userpriv, auth_salt: userauthsalt };
        let (mut tobjects, mut refused) = (Vec::new(), Vec::new());
        {
            let mut stmt = db
                .prepare("SELECT attrs FROM tobjects WHERE tokid = ?1")
                .map_err(|e| KmError::Unavailable(format!("selecting tobjects: {e}").into()))?;
            let rows = stmt
                .query_map([tok_id], |r| text(r, 0))
                .map_err(|e| KmError::Unavailable(format!("reading tobjects: {e}").into()))?;
            for attrs in rows {
                // A row that is not UTF-8 is one bad row; a failing query fails the store.
                let row = match attrs {
                    Ok(attrs) => parse_tobject(&attrs),
                    Err(e @ rusqlite::Error::FromSqlConversionFailure(..)) => {
                        Err(KmError::Unavailable(format!("tpm2-pkcs11 store: object attrs: {e}").into()))
                    }
                    Err(e) => return Err(KmError::Unavailable(format!("reading a tobject: {e}").into())),
                };
                match row {
                    Ok(t) => tobjects.extend(t),
                    Err(e) => refused.push(e),
                }
            }
        }
        Ok(Store { parent, seal, tobjects, refused, path })
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
    /// `NotFound` when no row carries the `CKA_ID`, `Unavailable` instead when a row could not
    /// be read (it may be the one); `Ambiguous` when several do (a label narrows it, but never
    /// silently picks). Each names the store file.
    pub(crate) fn find(&self, cka_id: &[u8], label: Option<&[u8]>, class: i64) -> Result<&TObject> {
        let id = || cakeys_core::hex::encode(cka_id);
        let store = self.path.display();
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
        match (matches.len(), self.refused.first()) {
            (1, _) => Ok(matches[0]),
            (0, Some(first)) => Err(KmError::Unavailable(
                format!(
                    "no readable store object of the key's class with CKA_ID {} in the tpm2-pkcs11 store {store}, \
                     and {} row(s) could not be read, the first: {first}",
                    id(),
                    self.refused.len()
                )
                .into(),
            )),
            (0, None) => Err(KmError::NotFound(
                format!(
                    "no certifiable store object of the key's class with CKA_ID {} in the tpm2-pkcs11 store {store}",
                    id()
                )
                .into(),
            )),
            (n, _) => Err(KmError::Ambiguous(Reason::check(
                Check::CkaIdUnique,
                format!("{n} rows of the store {store} match the key's CKA_ID {}", id()),
            ))),
        }
    }
}

/// The class the PKCS#11 `ObjectCfg` maps to in the store, for row matching.
///
/// # Errors
///
/// `Unsupported` for a class the store keeps no key rows for (certificates, data objects:
/// nothing to certify).
pub(crate) fn store_class(class: ObjectClass) -> Result<i64> {
    match class {
        // CKO_PUBLIC_KEY objects are the public half of a pair: stored without a private blob,
        // and TPM2_Certify cannot attest a public-only area.
        ObjectClass::PrivateKey => Ok(CLASS_PRIVATE_KEY),
        ObjectClass::SecretKey => Ok(CLASS_SECRET_KEY),
        c => Err(KmError::Unsupported(
            format!("TPM2_Certify attests private and secret keys (TPM-resident, private area loaded), not {c}").into(),
        )),
    }
}

/// `pobjects.config` is YAML `{esys-tr: <hex>, transient: false}`; the serialized `ESYS_TR` is
/// `TPM2_HANDLE (BE) ‖ TPM2B_NAME ‖ rsrcType (BE, 1 = key) ‖ TPM2B_PUBLIC`. Only the persistent
/// parent form is supported — transient primaries would need re-derivation from the template.
pub(crate) fn parse_parent(config: &str, objauth: &str) -> Result<Parent> {
    let bad = |what: &str| KmError::Unavailable(format!("tpm2-pkcs11 store: primary object: {what}").into());
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
/// keys cakeys generates \[run\]), which a YAML mapping type refuses; here the last value stands,
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
/// which tpm2-pkcs11 1.10 keeps as a store row even from a `CKA_TOKEN = false` template \[run\] —
/// never certifiable, and no reason to refuse the rest of the store.
pub(crate) fn parse_tobject(attrs: &str) -> Result<Option<TObject>> {
    let bad = |what: &str| KmError::Unavailable(format!("tpm2-pkcs11 store: object attrs: {what}").into());
    let Attrs(attrs) = serde_norway::from_str(attrs).map_err(|e| bad(&e.to_string()))?;
    let attr = |attr: u64| attrs.get(&attr);
    // Absent is `None`; present but no hex string is a damaged row, never taken for absent
    // (attest/store.rs F2), which would read as "not found" (11) or "no private blob" (15).
    let bytes = |a: u64| -> Result<Option<Vec<u8>>> {
        attr(a)
            .map(|v| v.as_str().and_then(|h| hex(h).ok()).ok_or_else(|| bad(&format!("attribute {a:#x} is not hex"))))
            .transpose()
    };
    let class = attr(ATTR_CLASS).and_then(Value::as_i64).ok_or_else(|| bad("no CKA_CLASS"))?;
    let Some(pub_blob) = bytes(ATTR_PUB_BLOB)? else { return Ok(None) };
    Ok(Some(TObject {
        class,
        cka_label: bytes(ATTR_LABEL)?,
        cka_id: bytes(ATTR_ID)?,
        pub_blob,
        priv_blob: bytes(ATTR_PRIV_BLOB)?,
        // The value is hex of the ASCII "<iv>:<tag>:<ct>" string.
        objauth_enc: bytes(ATTR_OBJAUTH_ENC)?
            .map(String::from_utf8)
            .transpose()
            .map_err(|_| bad("CKA_TPM2_OBJAUTH_ENC is not text"))?,
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

    /// A value that is there but no hex string is a damaged row (16), never an absent attribute
    /// (attest/store.rs F2), and an object auth that is no text is refused, never replaced (F3).
    #[test]
    fn a_damaged_value_is_not_an_absent_one() {
        let row = include_str!("../../tests/fixtures/tobject-private.yaml");
        let id = parse_tobject(row).unwrap().unwrap().cka_id.unwrap();
        let id_hex = cakeys_core::hex::encode(&id);
        let quoted = format!("\"{id_hex}\"");
        assert!(row.contains(&quoted), "the fixture's CKA_ID is the hex {id_hex}");
        let damaged = parse_tobject(&row.replacen(&quoted, "\"zz\"", 1)).err().unwrap();
        assert!(matches!(&damaged, KmError::Unavailable(m) if m.contains("0x102 is not hex")), "{damaged}");
        // An object auth whose hex decodes to bytes that are no text ("\xff").
        let objauth = format!("? !!int \"{ATTR_OBJAUTH_ENC}\"\n  : !!str \"ff\",\n}}");
        let not_text = parse_tobject(&row.replacen('}', &format!("  {objauth}"), 1)).err();
        assert!(not_text.is_some_and(|e| e.to_string().contains("not text")));
    }

    /// One row that cannot be read refuses no other (attest/store.rs F1): the key asked for is
    /// found among the readable rows; when none is it, the unread row is the cause said (16),
    /// not "not found".
    #[test]
    fn one_unreadable_row_refuses_no_other() {
        let bad = parse_tobject("!!map {").err().unwrap();
        let store = |rows: Vec<TObject>| Store {
            parent: Parent { handle: 0x8100_0001, auth: Vec::new() },
            seal: Seal { pub_blob: Vec::new(), priv_blob: Vec::new(), auth_salt: String::new() },
            tobjects: rows,
            refused: vec![KmError::Unavailable(bad.to_string().into())],
            path: "/s/tpm2_pkcs11.sqlite3".into(),
        };
        let one = store(vec![private_row(b"k1")]);
        assert!(one.find(b"0a", Some(b"k1"), CLASS_PRIVATE_KEY).is_ok());
        let e = one.find(b"0b", None, CLASS_PRIVATE_KEY).err().unwrap();
        assert!(matches!(&e, KmError::Unavailable(m) if m.contains("1 row(s) could not be read")), "{e}");
        assert!(e.to_string().contains("/s/tpm2_pkcs11.sqlite3"), "{e}");
    }

    #[test]
    fn the_parent_is_the_persistent_handle_the_store_names() {
        let parent = parse_parent(include_str!("../../tests/fixtures/pobject-config.yaml"), "").unwrap();
        assert_eq!(parent.handle, 0x8100_0001);
        let err = parse_parent("---\n!!map {\n  ? !!str \"transient\"\n  : !!bool \"true\",\n}\n", "").err().unwrap();
        assert!(err.to_string().contains("primary is transient"), "{err}");
        // The serialized ESYS_TR: a handle, a sized Name, then the resource type (1, a key).
        let config = include_str!("../../tests/fixtures/pobject-config.yaml");
        let tr_type = 2 * (4 + 2 + 0x22);
        let start = config.find("81000001").unwrap();
        let edited = |at: usize, hex: &str| {
            let mut c = config.to_owned();
            c.replace_range(start + at..start + at + hex.len(), hex);
            parse_parent(&c, "").err().unwrap().to_string()
        };
        assert!(edited(tr_type, "00000002").contains("not a key resource"));
        assert!(edited(0, "80000001").contains("not a persistent object"));
    }

    fn private_row(label: &[u8]) -> TObject {
        let mut row = parse_tobject(include_str!("../../tests/fixtures/tobject-private.yaml")).unwrap().unwrap();
        row.cka_label = Some(label.to_vec());
        row
    }

    /// The row to certify is the one row of the key's class under its `CKA_ID` that carries a
    /// private blob: none is 11, several are 12 until the object's label tells them apart; a
    /// class the store keeps no key rows for is 15.
    #[test]
    fn the_row_to_certify_is_found_or_named() {
        let store = Store {
            parent: Parent { handle: 0x8100_0001, auth: Vec::new() },
            seal: Seal { pub_blob: Vec::new(), priv_blob: Vec::new(), auth_salt: String::new() },
            tobjects: vec![private_row(b"k1"), private_row(b"k2")],
            refused: Vec::new(),
            path: "/s/tpm2_pkcs11.sqlite3".into(),
        };
        let found = |id: &[u8], label: Option<&[u8]>, class| store.find(id, label, class).map(|t| t.cka_label.clone());
        assert_eq!(found(b"0a", Some(b"k2"), CLASS_PRIVATE_KEY).unwrap().as_deref(), Some(&b"k2"[..]));
        let several = found(b"0a", None, CLASS_PRIVATE_KEY).unwrap_err();
        assert!(
            matches!(&several, KmError::Ambiguous(m) if m.contains("2 rows of the store /s/tpm2_pkcs11.sqlite3 match")),
            "{several}"
        );
        for (id, label, class) in [
            (&b"0b"[..], None, CLASS_PRIVATE_KEY),
            (b"0a", Some(&b"k3"[..]), CLASS_PRIVATE_KEY),
            (b"0a", Some(b"k1"), CLASS_SECRET_KEY),
        ] {
            let none = found(id, label, class).unwrap_err();
            assert!(matches!(&none, KmError::NotFound(m) if m.contains("no certifiable store object")), "{none}");
        }
        assert_eq!(store_class(ObjectClass::PrivateKey).unwrap(), CLASS_PRIVATE_KEY);
        assert_eq!(store_class(ObjectClass::SecretKey).unwrap(), CLASS_SECRET_KEY);
        assert!(matches!(store_class(ObjectClass::Certificate), Err(KmError::Unsupported(_))));
    }

    /// A store file is read as the module wrote it: a token's rows, an unset `objauth` as the
    /// empty auth value. A token the store does not hold is 11, one it holds twice 12; a file
    /// that is no tpm2-pkcs11 store is unavailable (16), never taken for an empty one.
    #[test]
    fn a_store_file_is_read_or_refused() {
        let dir = std::env::temp_dir().join(format!("cakeys-tpm2-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Connection::open(dir.join(DB_NAME)).unwrap();
        let other = Store::open(&dir, "kmtest").err().unwrap();
        assert!(matches!(&other, KmError::Unavailable(m) if m.contains("reading pobjects")), "{other}");
        db.execute_batch(
            "CREATE TABLE pobjects (id INTEGER PRIMARY KEY, config TEXT, objauth TEXT);
             CREATE TABLE tokens (id INTEGER PRIMARY KEY, pid INTEGER, label TEXT);
             CREATE TABLE sealobjects (tokid INTEGER, userpub BLOB, userpriv BLOB, userauthsalt TEXT);
             CREATE TABLE tobjects (tokid INTEGER, attrs TEXT);
             INSERT INTO tokens VALUES (7, 1, 'kmtest');
             INSERT INTO sealobjects VALUES (7, x'0001', x'0002', '5a');",
        )
        .unwrap();
        db.execute(
            "INSERT INTO pobjects VALUES (1, ?1, NULL)",
            [include_str!("../../tests/fixtures/pobject-config.yaml")],
        )
        .unwrap();
        for attrs in ["tobject-private.yaml", "tobject-public.yaml"] {
            let attrs = std::fs::read(format!("{}/tests/fixtures/{attrs}", env!("CARGO_MANIFEST_DIR"))).unwrap();
            db.execute("INSERT INTO tobjects VALUES (7, ?1)", [attrs]).unwrap();
        }
        // A row that is not UTF-8 and one that is no YAML map: kept aside, refusing no other.
        db.execute("INSERT INTO tobjects VALUES (7, x'ff00')", []).unwrap();
        db.execute("INSERT INTO tobjects VALUES (7, '- 1')", []).unwrap();
        drop(db);
        let store = Store::open(&dir, "kmtest").unwrap();
        assert_eq!((store.parent.handle, store.parent.auth.len()), (0x8100_0001, 0));
        assert_eq!((store.seal.pub_blob.as_slice(), store.seal.auth_salt.as_str()), (&[0, 1][..], "5a"));
        assert_eq!((store.tobjects.len(), store.refused.len()), (2, 2));
        assert!(store.refused[0].to_string().contains("invalid utf-8"), "{}", store.refused[0]);
        assert!(store.find(b"0a", Some(b"k1"), CLASS_PRIVATE_KEY).is_ok());
        assert!(matches!(Store::open(&dir, "another"), Err(KmError::NotFound(_))));
        // A second token of the label is refused (12), never the first row taken (B-13).
        Connection::open(dir.join(DB_NAME)).unwrap().execute("INSERT INTO tokens VALUES (8, 1, 'kmtest')", []).unwrap();
        assert!(matches!(Store::open(&dir, "kmtest"), Err(KmError::Ambiguous(m)) if m.contains("2 tokens")));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
