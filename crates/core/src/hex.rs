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

    /// The longest text `only_hex_decodes` generates: 64 bytes at random and under libFuzzer,
    /// and under Kani the length it proves every text up to.
    #[cfg(not(kani))]
    const TEXT_MAX: usize = 64;
    #[cfg(kani)]
    const TEXT_MAX: usize = 4;

    /// `encode` gives hex that `decode` reads back, in either case. Not a Kani proof: `encode`
    /// and `decode` build heap values of symbolic length, which took more than 8 GB at two
    /// bytes, for what is base16ct's code (docs/OPEN.md, "Kani, through bolero").
    #[test]
    fn hex_round_trips() {
        bolero::check!().with_type::<Vec<u8>>().for_each(|bytes| {
            assert_eq!(decode(&encode(bytes)).as_deref(), Some(&bytes[..]));
            assert_eq!(decode(&encode(bytes).to_ascii_uppercase()).as_deref(), Some(&bytes[..]));
        });
    }

    /// `decode` takes exactly hex of whole bytes, either case, and `encode` gives its lower-case
    /// form back: bolero, so the same harness is a Kani proof. The text is bytes that are UTF-8,
    /// so under Kani every char of up to four bytes is among them; at random, longer texts are
    /// mostly ASCII (`only_whole_hex_bytes_decode` names non-ASCII ones).
    ///
    /// The text is an array and a length to take of it, not bolero's `String`: under Kani that
    /// is a heap value of symbolic length, which took more than 8 GB here at two bytes, and the
    /// array 1.2 GB at four. A known cost with no bolero fix as of 2026-11 (bolero #231 made the
    /// same change for its byte-slice input, not for its generators).
    #[test]
    #[cfg_attr(kani, kani::proof, kani::unwind(5))]
    fn only_hex_decodes() {
        let text = (bolero::produce::<[u8; TEXT_MAX]>(), 0..=TEXT_MAX);
        bolero::check!().with_generator(text).for_each(|(b, n)| {
            let Ok(text) = std::str::from_utf8(&b[..*n]) else { return };
            let hex = text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit());
            match decode(text) {
                Some(v) => assert!(hex && encode(&v).eq_ignore_ascii_case(text), "{text:?}"),
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
