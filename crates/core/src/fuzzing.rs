//! Properties that are checked in three ways (docs/OPEN.md, "Kani and fuzzing"): with random
//! inputs by the proptests below, under libFuzzer by the fuzz targets
//! (`fuzz/fuzz_targets/hex.rs`, `attest_encoding.rs`), and, where it is feasible, for every input
//! up to a bound by the Kani proofs below. Each property panics when what it checks does not
//! hold.

use crate::hex::{decode, encode};
use crate::id::attest_encoding;

/// Checks that `encode` returns hex that `decode` reads back, in lower case and in upper case.
///
/// # Panics
///
/// Panics when `decode` does not read the hex back.
pub fn hex_round_trips(bytes: &[u8]) {
    assert_eq!(decode(&encode(bytes)).as_deref(), Some(bytes));
    assert_eq!(decode(&encode(bytes).to_ascii_uppercase()).as_deref(), Some(bytes));
}

/// Checks that `decode` accepts exactly the hex text of whole bytes, in upper or lower case, and
/// that `encode` returns the lower-case form of that text.
///
/// # Panics
///
/// Panics when `decode` accepts text that is not the hex of whole bytes, refuses text that is,
/// or reads bytes that `encode` does not write back as the text.
pub fn only_hex_decodes(text: &str) {
    let hex = text.len().is_multiple_of(2) && text.bytes().all(|b| b.is_ascii_hexdigit());
    match decode(text) {
        Some(v) => assert!(hex && encode(&v).eq_ignore_ascii_case(text), "{text:?}"),
        None => assert!(!hex, "{text:?}"),
    }
}

/// Checks that the attestation encoding, before it is hashed, determines its fields. The fields
/// read back from the left, so two attestations give the same input to the hash only when every
/// field is the same (`attestation_ids_are_injective` in tests/properties.rs checks the IDs
/// themselves). The check covers both encodings, the two fields of `tpm-certify` and the six
/// fields of `piv-attestation`, built from `a`, `b` and `c`.
///
/// # Panics
///
/// Panics when the fields do not read back.
pub fn attest_encoding_reads_back(a: &[u8], b: &[u8], c: &[u8]) {
    let tag = b"cakeys/tpm-certify/v1\0";
    assert_eq!(unframe(&attest_encoding(tag, &[a, b]), tag, 2), Some(vec![a, b]));
    let tag = b"cakeys/piv-attestation/v1\0";
    let fields = [a, b, c, b"", a, c];
    assert_eq!(unframe(&attest_encoding(tag, &fields), tag, 6).as_deref(), Some(&fields[..]));
}

/// Checks that keys.lock text that cakeys reads is written back in a form that cakeys reads as
/// the same lock, and that a second write gives the same text (review D9). So the next run loads
/// what `save_lock` writes without a change. Text that does not load is refused as invalid (17),
/// and never causes a panic.
///
/// # Panics
///
/// Panics when a lock that loads does not survive its own write.
pub fn lock_round_trips(text: &str) {
    let path = std::path::Path::new("keys.lock");
    let lock = match crate::config::parse_lock(text, path) {
        Ok(lock) => lock,
        Err(e) => return assert_eq!(e.exit_code(), 17, "{e}"),
    };
    let written = toml::to_string_pretty(&lock).expect("a lock that loads serializes");
    let again = crate::config::parse_lock(&written, path).unwrap_or_else(|e| panic!("{e}\n{written}"));
    // This compares every field as it was read. A field that the write drops is detected here,
    // even though both writes would give the same text.
    assert_eq!(format!("{again:?}"), format!("{lock:?}"), "the lock read back differs:\n{written}");
    assert_eq!(toml::to_string_pretty(&again).unwrap(), written, "the lock changed on its second write");
}

/// Returns the fields that `attest_encoding` framed after `tag`, read back from the left. Returns
/// `None` unless `v` is exactly `tag` followed by `n` length-prefixed fields.
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

    /// Generates text that is often hex or nearly hex, because random strings rarely are.
    fn text() -> impl Strategy<Value = String> {
        let nearly_hex = vec(prop::sample::select(b"0123456789abcdefABCDEFgx \xc3\xa9".to_vec()), 0..64)
            .prop_filter_map("not UTF-8", |b| String::from_utf8(b).ok());
        prop_oneof![any::<String>(), nearly_hex]
    }

    /// The locks in the repository round-trip. This test uses them because random text rarely
    /// loads.
    #[test]
    fn the_repository_locks_round_trip() {
        let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
        for lock in ["crates/cli/tests/fixtures/keys.lock", "examples/yubikey-secureboot.lock"] {
            let text = std::fs::read_to_string(format!("{root}/{lock}")).unwrap();
            crate::config::parse_lock(&text, std::path::Path::new(lock)).unwrap();
            super::lock_round_trips(&text);
        }
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
        fn lock_round_trips(text in text()) {
            super::lock_round_trips(&text);
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

/// The hex properties for every input of up to a few bytes. Run them with
/// `nix build .#checks.x86_64-linux.kani`, or with `cargo kani -p cakeys-core` with Kani on PATH
/// (`nix build .#kani`). The inputs are a fixed array and a length of it to take, never a `Vec`
/// or a `String`, because CBMC turns a heap value of symbolic length into array constraints that
/// took more than 8 GB even at two bytes. `attest_encoding_reads_back` has no proof, because
/// `attest_encoding` itself copies each field into its `Vec` at a symbolic length. A simple proof
/// with fields of up to one byte ran out of 8 GB, with both encodings and also with only the two
/// fields of `tpm-certify`.
#[cfg(kani)]
mod proofs {
    fn bytes<const N: usize>() -> ([u8; N], usize) {
        let n: usize = kani::any();
        kani::assume(n <= N);
        (kani::any(), n)
    }

    /// Every input of up to two bytes. The proof takes 52 s and 2.5 GB.
    #[kani::proof]
    #[kani::unwind(5)]
    fn hex_round_trips() {
        let (b, n) = bytes::<2>();
        super::hex_round_trips(&b[..n]);
    }

    /// Every text of up to four bytes, which includes every char. The proof takes 13 s and
    /// 0.5 GB.
    #[kani::proof]
    #[kani::unwind(5)]
    fn only_hex_decodes() {
        let (b, n) = bytes::<4>();
        if let Ok(text) = std::str::from_utf8(&b[..n]) {
            super::only_hex_decodes(text);
        }
    }
}
