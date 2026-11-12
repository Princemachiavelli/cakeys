//! RFC 7512 URIs and the locator attributes they are built from.

use super::*;

impl Token {
    /// RFC 7512 URI of the object consumers use: for a key adopted public-only this is still
    /// the private key (only its verification went through the public half).
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

pub(super) fn locator_attrs(loc: &Locator) -> Result<Vec<Attribute>> {
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
    // ASCII only: byte slicing below would panic inside a multi-byte character.
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return Err(KmError::Validation(format!("CKA_ID '{s}' is not hex")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| KmError::Validation(format!("CKA_ID '{s}' is not hex")))
}

fn pct(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

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
}
