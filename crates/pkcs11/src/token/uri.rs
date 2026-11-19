//! RFC 7512 URIs and the locator attributes they are built from.

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

impl Token {
    /// RFC 7512 URI of the object consumers use: for a key adopted public-only this is still
    /// the private key (only its verification went through the public half).
    ///
    /// # Errors
    ///
    /// `Validation` when the locator names neither `CKA_LABEL` nor `CKA_ID`, or its `CKA_ID`
    /// is not hex.
    pub fn uri(&self, object: &ObjectCfg, loc: &Locator) -> Result<String> {
        // The serial tells apart tokens that share a label (RFC 7512 `serial`).
        let mut parts = vec![format!("token={}", pct(self.label.as_bytes()))];
        if !self.token.serial.is_empty() {
            parts.push(format!("serial={}", pct(self.token.serial.as_bytes())));
        }
        if let Some(l) = &loc.label {
            parts.push(format!("object={}", pct(l.as_bytes())));
        }
        if let Some(i) = &loc.id {
            parts.push(format!("id={}", pct_all(&hex_decode(i)?)));
        }
        let kind = match class_of(object) {
            c if c == ObjectClass::PRIVATE_KEY => "private",
            c if c == ObjectClass::PUBLIC_KEY => "public",
            c if c == ObjectClass::CERTIFICATE => "cert",
            c if c == ObjectClass::DATA => "data",
            _ => "secret-key",
        };
        parts.push(format!("type={kind}"));
        // A pure locator: which module realised it is recorded separately (ModuleInfo).
        Ok(format!("pkcs11:{}", parts.join(";")))
    }
}

/// How a consumer of a checked URI gets the token's user PIN (RFC 7512 §2.3 query attributes).
pub enum PinRef {
    /// `pin-source=file:<path>`: keys.toml's `pinFile`.
    File(std::path::PathBuf),
    /// `pin-source=env:<var>`: keys.toml's `pinEnv`. A pkcs11-provider extension; RFC 7512 and
    /// p11-kit know only files.
    Env(String),
    /// `pin-value=<pin>`: the PIN itself, in whatever the output reaches.
    Value(Zeroizing<String>),
}

/// The token's user PIN as a consumer should get it: by reference (`pinEnv`, else `pinFile`,
/// as cakeys reads it, the file made absolute against the working directory) or by value.
///
/// # Errors
///
/// `Validation` when keys.toml gives the token no PIN; `Unavailable` when `by_value` and the
/// PIN cannot be read.
pub fn pin_ref(name: &str, cfg: &TokenCfg, by_value: bool) -> Result<PinRef> {
    let none =
        || KmError::Validation(format!("token '{name}' has no PIN to put in the URI (set pinFile or pinEnv)").into());
    if by_value {
        return read_pin(name, cfg)?.map(PinRef::Value).ok_or_else(none);
    }
    if let Some(var) = &cfg.pin_env {
        return Ok(PinRef::Env(var.clone()));
    }
    let file = cfg.pin_path(name, &|var| std::env::var(var).ok())?.ok_or_else(none)?;
    std::path::absolute(&file)
        .map(PinRef::File)
        .map_err(|e| KmError::Validation(format!("token '{name}': pinFile {}: {e}", file.display()).into()))
}

/// Text that may carry the user PIN (`--uri-pin value`): what [`with_query`] and
/// [`provider_pem`] give. It reads as the text, and is wiped when dropped, as `PinRef::Value`
/// is: no copy of the PIN is left behind in freed memory (uri.rs F1). Its `Debug` shows none of
/// it.
pub struct PinText(Zeroizing<String>);

impl std::ops::Deref for PinText {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PinText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Debug for PinText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinText(..)")
    }
}

/// A consumer's view of the locator `uri` ([`Token::uri`]): with `module-path` and the user PIN
/// as query attributes, when asked for. The lock never records them; `check` adds them on
/// request (docs/CAKEYS.md, "The contract with programs"). Written into one buffer sized for it
/// up front, so a PIN value is never in a copy that is not wiped.
#[must_use]
pub fn with_query(uri: &str, module_path: Option<&str>, pin: Option<&PinRef>) -> PinText {
    let mut query: Vec<(&str, &[u8])> = Vec::new();
    if let Some(m) = module_path {
        query.push(("module-path=", m.as_bytes()));
    }
    match pin {
        Some(PinRef::File(p)) => query.push(("pin-source=file:", p.as_os_str().as_encoded_bytes())),
        Some(PinRef::Env(v)) => query.push(("pin-source=env:", v.as_bytes())),
        Some(PinRef::Value(v)) => query.push(("pin-value=", v.as_bytes())),
        None => {}
    }
    // Each byte escapes to three characters at most.
    let room = uri.len() + query.iter().map(|(k, v)| 1 + k.len() + 3 * v.len()).sum::<usize>();
    let mut out = Zeroizing::new(String::with_capacity(room));
    out.push_str(uri);
    for (i, (key, value)) in query.iter().enumerate() {
        out.push(if i == 0 { '?' } else { '&' });
        out.push_str(key);
        qpct_into(&mut out, value);
    }
    PinText(out)
}

/// pkcs11-provider's "key file" for a private key URI: `SEQUENCE { VisibleString
/// "PKCS#11 Provider URI v1.0", UTF8String uri }` armored as `PKCS#11 PROVIDER URI`, what its
/// `tools/uri2pem.py` writes and its decoder reads (`src/pk11_uri.h`, 1.3), for programs that
/// take a key only as a PEM file. The URI may carry the PIN: the DER is written into one wiped
/// buffer sized for it, and the PEM is a `PinText`, wiped when dropped.
///
/// # Errors
///
/// `Validation` when the URI cannot be encoded.
pub fn provider_pem(uri: &str) -> Result<PinText> {
    // der 0.8 has no VisibleString type; the description is ASCII.
    const DESCRIPTION: &[u8] = b"PKCS#11 Provider URI v1.0";
    let tlv = |len: usize| 1 + der_length(None, len) + len;
    let body = tlv(DESCRIPTION.len()) + tlv(uri.len());
    let mut der = Zeroizing::new(Vec::with_capacity(tlv(body)));
    der.push(0x30); // SEQUENCE
    der_length(Some(&mut der), body);
    der.push(0x1a); // VisibleString
    der_length(Some(&mut der), DESCRIPTION.len());
    der.extend_from_slice(DESCRIPTION);
    der.push(0x0c); // UTF8String
    der_length(Some(&mut der), uri.len());
    der.extend_from_slice(uri.as_bytes());
    der::pem::encode_string("PKCS#11 PROVIDER URI", der::pem::LineEnding::LF, &der)
        .map(|pem| PinText(Zeroizing::new(pem)))
        .map_err(|e| KmError::Validation(format!("PEM of a URI: {e}").into()))
}

/// The DER length octets of `len`, appended to `out` when given: their count either way.
fn der_length(out: Option<&mut Vec<u8>>, len: usize) -> usize {
    let bytes = len.to_be_bytes();
    let used = &bytes[bytes.iter().take_while(|b| **b == 0).count()..];
    let octets: Vec<u8> = match u8::try_from(len) {
        Ok(short) if short < 0x80 => vec![short],
        // Long form: 0x80 | the count of length bytes, at most eight (a usize).
        _ => [&[0x80 | u8::try_from(used.len()).unwrap_or(8)][..], used].concat(),
    };
    if let Some(out) = out {
        out.extend_from_slice(&octets);
    }
    octets.len()
}

/// The template attributes that put an object under `loc`: `CKA_LABEL` and/or `CKA_ID`.
///
/// # Errors
///
/// `Validation` for a locator with neither, or a `CKA_ID` that is not hex.
pub fn locator_attrs(loc: &Locator) -> Result<Vec<Attribute>> {
    let mut v = Vec::new();
    if let Some(l) = &loc.label {
        v.push(Attribute::Label(l.as_bytes().to_vec()));
    }
    if let Some(i) = &loc.id {
        v.push(Attribute::Id(hex_decode(i)?));
    }
    if v.is_empty() {
        return Err(KmError::Validation("locator needs CKA_LABEL and/or CKA_ID".into()));
    }
    Ok(v)
}

pub(super) fn hex_decode(s: &str) -> Result<Vec<u8>> {
    cakeys_core::hex::decode(s).ok_or_else(|| KmError::Validation(format!("CKA_ID '{s}' is not hex").into()))
}

/// A path attribute's value (`token=`, `serial=`, `object=`): the unreserved characters as they
/// are, everything else escaped. `/` too: RFC 7512 §2.3 leaves it out of `pk11-pchar`.
fn pct(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// A query attribute's value, appended to `out` without a copy of its own (a PIN goes through
/// here): [`pct`], also keeping `/` and `:` (RFC 7512 `pk11-qchar`), so a path or `file:` reads
/// as written; `&`, `;` and `?` are always escaped.
fn qpct_into(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                out.push(char::from(b));
            }
            _ => {
                out.push('%');
                out.push(char::from(HEX[usize::from(b >> 4)]));
                out.push(char::from(HEX[usize::from(b & 0xf)]));
            }
        }
    }
}

#[expect(clippy::format_collect, reason = "the hex builder reads best as map-format-collect")]
pub(super) fn pct_all(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("%{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decode_rejects_non_hex_without_panicking() {
        assert_eq!(hex_decode("0aFF").unwrap(), [0x0a, 0xff]);
        for bad in ["0", "zz", "aéb", "éé", "0x12"] {
            assert!(matches!(hex_decode(bad), Err(KmError::Validation(_))), "{bad}");
        }
    }

    const LOCATOR: &str = "pkcs11:token=kmtest;serial=7c1ab3d4e5f60718;object=ec-lifecycle;type=private";
    const MODULE: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-softhsm-2.7.0/lib/softhsm/libsofthsm2.so";

    #[test]
    fn query_attributes_follow_the_locator_in_order_and_escape_separators() {
        assert_eq!(&*with_query(LOCATOR, None, None), LOCATOR);
        let pin = PinRef::File("/run/km/pin".into());
        assert_eq!(
            &*with_query(LOCATOR, Some(MODULE), Some(&pin)),
            format!("{LOCATOR}?module-path={MODULE}&pin-source=file:/run/km/pin")
        );
        assert_eq!(
            &*with_query(LOCATOR, None, Some(&PinRef::Env("KM_PIN".into()))),
            format!("{LOCATOR}?pin-source=env:KM_PIN")
        );
        // A separator in a value cannot end the attribute: pkcs11-provider splits on `;?&`.
        let value = PinRef::Value(Zeroizing::new("1;2?3&4 5%".into()));
        assert_eq!(&*with_query(LOCATOR, None, Some(&value)), format!("{LOCATOR}?pin-value=1%3B2%3F3%264%205%25"));
        assert_eq!(
            &*with_query(LOCATOR, Some("/odd dir/m;1.so"), None),
            format!("{LOCATOR}?module-path=/odd%20dir/m%3B1.so")
        );
    }

    /// Text carrying a PIN value (uri.rs F1) is written into one buffer sized for it, never
    /// grown (a reallocation leaves the old bytes behind unwiped), and shows nothing of itself
    /// in `Debug`.
    #[test]
    fn a_pin_value_is_in_one_wiped_buffer() {
        let worst = PinRef::Value(Zeroizing::new(";;;;".into()));
        let text = with_query(LOCATOR, Some("/a b"), Some(&worst));
        assert_eq!(&*text, format!("{LOCATOR}?module-path=/a%20b&pin-value=%3B%3B%3B%3B"));
        let room = LOCATOR.len() + (1 + "module-path=".len() + 3 * 4) + (1 + "pin-value=".len() + 3 * 4);
        assert_eq!(text.0.capacity(), room, "the buffer grew");
        assert_eq!(format!("{text:?}"), "PinText(..)");
        let pem = provider_pem(&text).unwrap();
        assert_eq!(format!("{pem:?}"), "PinText(..)");
    }

    /// RFC 7512 §2.3: `/` is a `pk11-qchar`, never a `pk11-pchar`.
    #[test]
    fn a_slash_is_escaped_in_the_path_and_kept_in_the_query() {
        assert_eq!(pct(b"a/b c"), "a%2Fb%20c");
        let mut q = String::new();
        qpct_into(&mut q, b"file:/a b");
        assert_eq!(q, "file:/a%20b");
    }

    /// The DER length octets: short form below 128, else long form on as few bytes as hold it.
    #[test]
    fn der_lengths_are_short_then_long() {
        let octets = |n: usize| {
            let mut out = Vec::new();
            let count = der_length(Some(&mut out), n);
            assert_eq!(count, der_length(None, n));
            out
        };
        assert_eq!(octets(0), [0]);
        assert_eq!(octets(0x7f), [0x7f]);
        assert_eq!(octets(0x80), [0x81, 0x80]);
        assert_eq!(octets(0xcb), [0x81, 0xcb]);
        assert_eq!(octets(0x132), [0x82, 0x01, 0x32]);
    }

    #[test]
    fn pin_ref_prefers_the_env_var_and_refuses_a_token_without_a_pin() {
        let cfg = |toml: &str| -> TokenCfg { toml::from_str(&format!("tokenLabel = \"t\"\n{toml}")).unwrap() };
        assert!(matches!(pin_ref("t", &cfg(""), false), Err(KmError::Validation(_))));
        assert!(matches!(pin_ref("t", &cfg(""), true), Err(KmError::Validation(_))));
        let both = cfg("pinFile = \"/p\"\npinEnv = \"KM_PIN\"");
        assert!(matches!(pin_ref("t", &both, false), Ok(PinRef::Env(v)) if v == "KM_PIN"));
        assert!(
            matches!(pin_ref("t", &cfg("pinFile = \"/p\""), false), Ok(PinRef::File(p)) if p == std::path::Path::new("/p"))
        );
        // A relative file is made absolute the way cakeys itself reads it: against the cwd.
        let Ok(PinRef::File(rel)) = pin_ref("t", &cfg("pinFile = \"pin\""), false) else { panic!() };
        assert_eq!(rel, std::env::current_dir().unwrap().join("pin"));
    }

    /// Byte for byte what pkcs11-provider 1.3's `tools/uri2pem.py` writes for the same URIs: the
    /// SEQUENCE's length in short form, then long form on one and on two bytes (`30 81 CB`,
    /// `30 82 01 32`), and the 64-column base64 lines with the final newline.
    #[test]
    fn provider_pem_matches_uri2pem() {
        let short = "pkcs11:token=kmtest;object=k;type=private";
        assert_eq!(
            &*provider_pem(short).unwrap(),
            "-----BEGIN PKCS#11 PROVIDER URI-----\n\
             MEYaGVBLQ1MjMTEgUHJvdmlkZXIgVVJJIHYxLjAMKXBrY3MxMTp0b2tlbj1rbXRl\n\
             c3Q7b2JqZWN0PWs7dHlwZT1wcml2YXRl\n\
             -----END PKCS#11 PROVIDER URI-----\n"
        );
        let mid = format!("{LOCATOR}?module-path={MODULE}");
        assert_eq!(
            &*provider_pem(&mid).unwrap(),
            "-----BEGIN PKCS#11 PROVIDER URI-----\n\
             MIHLGhlQS0NTIzExIFByb3ZpZGVyIFVSSSB2MS4wDIGtcGtjczExOnRva2VuPWtt\n\
             dGVzdDtzZXJpYWw9N2MxYWIzZDRlNWY2MDcxODtvYmplY3Q9ZWMtbGlmZWN5Y2xl\n\
             O3R5cGU9cHJpdmF0ZT9tb2R1bGUtcGF0aD0vbml4L3N0b3JlLzAxMjM0NTY3ODlh\n\
             YmNkZmdoaWprbG1ucHFyc3Z3eHl6LXNvZnRoc20tMi43LjAvbGliL3NvZnRoc20v\n\
             bGlic29mdGhzbTIuc28=\n\
             -----END PKCS#11 PROVIDER URI-----\n"
        );
        let long = format!(
            "{mid}&pin-source=file:/build/cakeys-tests/check_pem_is_a_key_file_for_pkcs11_provider/pin&pin-value=12%3B34"
        );
        assert_eq!(
            &*provider_pem(&long).unwrap(),
            "-----BEGIN PKCS#11 PROVIDER URI-----\n\
             MIIBMhoZUEtDUyMxMSBQcm92aWRlciBVUkkgdjEuMAyCARNwa2NzMTE6dG9rZW49\n\
             a210ZXN0O3NlcmlhbD03YzFhYjNkNGU1ZjYwNzE4O29iamVjdD1lYy1saWZlY3lj\n\
             bGU7dHlwZT1wcml2YXRlP21vZHVsZS1wYXRoPS9uaXgvc3RvcmUvMDEyMzQ1Njc4\n\
             OWFiY2RmZ2hpamtsbW5wcXJzdnd4eXotc29mdGhzbS0yLjcuMC9saWIvc29mdGhz\n\
             bS9saWJzb2Z0aHNtMi5zbyZwaW4tc291cmNlPWZpbGU6L2J1aWxkL2Nha2V5cy10\n\
             ZXN0cy9jaGVja19wZW1faXNfYV9rZXlfZmlsZV9mb3JfcGtjczExX3Byb3ZpZGVy\n\
             L3BpbiZwaW4tdmFsdWU9MTIlM0IzNA==\n\
             -----END PKCS#11 PROVIDER URI-----\n"
        );
    }
}
