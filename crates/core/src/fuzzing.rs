//! Properties checked three ways (docs/OPEN.md, "Kani and fuzzing"): at random by the proptests
//! below, under libFuzzer by the fuzz targets (`fuzz/fuzz_targets/hex.rs`, `attest_encoding.rs`)
//! and, where it fits, for every input up to a bound by the Kani proofs below. Each panics when
//! what it checks does not hold.

use crate::hex::{decode, encode};
use crate::id::attest_encoding;

/// `encode` gives hex that `decode` reads back, in either case.
///
/// # Panics
///
/// When it does not.
pub fn hex_round_trips(bytes: &[u8]) {
    assert_eq!(decode(&encode(bytes)).as_deref(), Some(bytes));
    assert_eq!(decode(&encode(bytes).to_ascii_uppercase()).as_deref(), Some(bytes));
}

/// `decode` takes exactly hex of whole bytes, either case, and `encode` gives its lower-case
/// form back.
///
/// # Panics
///
/// When `decode` takes text that is not hex of whole bytes, refuses hex that is, or reads
/// bytes `encode` does not write back as the text.
pub fn only_hex_decodes(text: &str) {
    let hex = text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit());
    match decode(text) {
        Some(v) => assert!(hex && encode(&v).eq_ignore_ascii_case(text), "{text:?}"),
        None => assert!(!hex, "{text:?}"),
    }
}

/// The attestation encoding before its hash determines its fields: they read back from the
/// left, so two attestations hash the same input only when every field is the same
/// (`attestation_ids_are_injective` in tests/properties.rs checks the IDs themselves). Both
/// encodings, `tpm-certify`'s two fields and `piv-attestation`'s six, from `a`, `b` and `c`.
///
/// # Panics
///
/// When the fields do not read back.
pub fn attest_encoding_reads_back(a: &[u8], b: &[u8], c: &[u8]) {
    let tag = b"cakeys/tpm-certify/v1\0";
    assert_eq!(unframe(&attest_encoding(tag, &[a, b]), tag, 2), Some(vec![a, b]));
    let tag = b"cakeys/piv-attestation/v1\0";
    let fields = [a, b, c, b"", a, c];
    assert_eq!(unframe(&attest_encoding(tag, &fields), tag, 6).as_deref(), Some(&fields[..]));
}

/// The fields `attest_encoding` framed after `tag`, read back from the left; `None` unless `v`
/// is exactly `tag` and `n` length-prefixed fields.
fn unframe<'a>(v: &'a [u8], tag: &[u8], n: usize) -> Option<Vec<&'a [u8]>> {
    let mut rest = v.strip_prefix(tag)?;
    let mut fields = Vec::with_capacity(n);
    for _ in 0..n {
        let (len, after) = rest.split_first_chunk::<4>()?;
        let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
        let (field, after) = after.split_at_checked(len)?;
        fields.push(field);
        rest = after;
    }
    rest.is_empty().then_some(fields)
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest::prelude::*;

    /// Text that is often hex, or nearly: random strings rarely are.
    fn text() -> impl Strategy<Value = String> {
        let nearly_hex = vec(prop::sample::select(b"0123456789abcdefABCDEFgx \xc3\xa9".to_vec()), 0..64)
            .prop_filter_map("not UTF-8", |b| String::from_utf8(b).ok());
        prop_oneof![any::<String>(), nearly_hex]
    }

    proptest! {
        #[test]
        fn hex_round_trips(bytes in vec(any::<u8>(), 0..64)) {
            super::hex_round_trips(&bytes);
        }

        #[test]
        fn only_hex_decodes(text in text()) {
            super::only_hex_decodes(&text);
        }

        #[test]
        fn attest_encoding_reads_back(
            a in vec(any::<u8>(), 0..64),
            b in vec(any::<u8>(), 0..64),
            c in vec(any::<u8>(), 0..64),
        ) {
            super::attest_encoding_reads_back(&a, &b, &c);
        }
    }
}

/// The hex properties for every input up to a few bytes: `nix build .#checks.x86_64-linux.kani`,
/// or `cargo kani -p cakeys-core` with Kani on PATH (`nix build .#kani`). The inputs are a fixed
/// array and a length to take of it, never a `Vec` or `String`: CBMC turns a heap value of
/// symbolic length into array constraints that took more than 8 GB even at two bytes.
/// `attest_encoding_reads_back` has no proof: `attest_encoding` itself copies each field into
/// its `Vec` at symbolic length, and a plain proof of fields up to one byte ran out of 8 GB,
/// both encodings or `tpm-certify`'s two fields alone.
#[cfg(kani)]
mod proofs {
    fn bytes<const N: usize>() -> ([u8; N], usize) {
        let n: usize = kani::any();
        kani::assume(n <= N);
        (kani::any(), n)
    }

    /// Every input of up to two bytes: 52 s, 2.5 GB.
    #[kani::proof]
    #[kani::unwind(5)]
    fn hex_round_trips() {
        let (b, n) = bytes::<2>();
        super::hex_round_trips(&b[..n]);
    }

    /// Every text of up to four bytes, so every char: 13 s, 0.5 GB.
    #[kani::proof]
    #[kani::unwind(5)]
    fn only_hex_decodes() {
        let (b, n) = bytes::<4>();
        if let Ok(text) = std::str::from_utf8(&b[..n]) {
            super::only_hex_decodes(text);
        }
    }
}
