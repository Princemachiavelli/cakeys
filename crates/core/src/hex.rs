//! Hex text to bytes, one rule for every caller: an even number of hex digits, either case.
//! And back, in lower case.

/// `bytes` in lower-case hex.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    base16ct::lower::encode_string(bytes)
}

/// The bytes `s` spells in hex; `None` when it is not hex of whole bytes. The empty string is
/// the empty byte string.
#[must_use]
pub fn decode(s: &str) -> Option<Vec<u8>> {
    base16ct::mixed::decode_vec(s).ok()
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    /// `decode` takes exactly hex of whole bytes, either case, and `encode` gives the lower-case
    /// form back: bolero, so the same harness is a Kani proof (docs/OPEN.md, "Kani, through
    /// bolero").
    #[test]
    #[cfg_attr(kani, kani::proof)]
    fn hex_round_trips() {
        bolero::check!().with_type::<(Vec<u8>, String)>().for_each(|(bytes, text)| {
            assert_eq!(decode(&encode(bytes)).as_deref(), Some(&bytes[..]));
            assert_eq!(decode(&encode(bytes).to_ascii_uppercase()).as_deref(), Some(&bytes[..]));
            let hex = text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit());
            match decode(text) {
                Some(v) => assert!(hex && encode(&v) == text.to_ascii_lowercase(), "{text:?}"),
                None => assert!(!hex, "{text:?}"),
            }
        });
    }

    #[test]
    fn only_whole_hex_bytes_decode() {
        assert_eq!(decode("0aFF").unwrap(), [0x0a, 0xff]);
        assert_eq!(decode("").unwrap(), [0u8; 0]);
        for bad in ["0", "zz", "aéb", "éé", "0x12", "0a ", "+1"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }
}
