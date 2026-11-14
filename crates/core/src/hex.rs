//! Hex text to bytes, one rule for every caller: an even number of hex digits, either case.

/// The bytes `s` spells in hex; `None` when it is not hex of whole bytes. The empty string is
/// the empty byte string.
#[must_use]
pub fn decode(s: &str) -> Option<Vec<u8>> {
    base16ct::mixed::decode_vec(s).ok()
}

#[cfg(test)]
mod tests {
    use super::decode;

    #[test]
    fn only_whole_hex_bytes_decode() {
        assert_eq!(decode("0aFF").unwrap(), [0x0a, 0xff]);
        assert_eq!(decode("").unwrap(), [0u8; 0]);
        for bad in ["0", "zz", "aéb", "éé", "0x12", "0a ", "+1"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
    }
}
