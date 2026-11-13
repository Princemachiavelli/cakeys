//! The pinned baseline (docs/PROVIDERS.md D1): profiles/baselines/pkcs11-3.2.toml is
//! generated from the vendored OASIS headers, never edited. The first test regenerates and
//! compares on every run (`CAKEYS_UPDATE_BASELINE=1` rewrites the committed file after a
//! header bump); the second pins the frozen spellings and IDs.

use cakeys_profile::Baseline;

const TYPES: &str = include_str!("../../../profiles/baselines/headers/pkcs11-3.2/pkcs11t.h");
const FUNCTIONS: &str = include_str!("../../../profiles/baselines/headers/pkcs11-3.2/pkcs11f.h");
const COMMITTED: &str = include_str!("../../../profiles/baselines/pkcs11-3.2.toml");

#[test]
fn committed_baseline_is_generated_from_the_vendored_headers() {
    let generated = Baseline::from_headers("pkcs11-3.2", TYPES, FUNCTIONS);
    if std::env::var_os("CAKEYS_UPDATE_BASELINE").is_some() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles/baselines/pkcs11-3.2.toml");
        std::fs::write(path, generated.to_toml()).expect("writing the regenerated baseline");
    }
    let committed = Baseline::from_toml(COMMITTED).expect("the committed baseline parses");
    assert_eq!(
        committed, generated,
        "profiles/baselines/pkcs11-3.2.toml is not what the vendored headers generate; regenerate with CAKEYS_UPDATE_BASELINE=1"
    );
}

#[test]
fn names_and_ids_are_pinned() {
    let b = Baseline::from_toml(COMMITTED).unwrap();
    // Mechanisms the layers and profiles name, with their spec IDs.
    assert_eq!(b.mechanisms["CKM_AES_KEY_WRAP"], 0x2109);
    assert_eq!(b.mechanisms["CKM_AES_KEY_WRAP_PAD"], 0x210A);
    assert_eq!(b.mechanisms["CKM_AES_KEY_WRAP_KWP"], 0x210B);
    assert_eq!(b.mechanisms["CKM_EC_EDWARDS_KEY_PAIR_GEN"], 0x1055);
    assert_eq!(b.mechanisms["CKM_EDDSA"], 0x1057);
    assert_eq!(b.mechanisms["CKM_AES_CBC_ENCRYPT_DATA"], 0x1105);
    // PKCS #11 3.2's PQ mechanisms: one mechanism per algorithm, parameter sets by CKA_PARAMETER_SET.
    assert_eq!(b.mechanisms["CKM_ML_DSA"], 0x1D);
    assert_eq!(b.mechanisms["CKM_ML_KEM"], 0x17);
    assert_eq!(b.mechanisms["CKM_SLH_DSA"], 0x2E);
    assert_eq!(b.parameter_sets["CKP_ML_DSA_65"], 0x2);
    assert_eq!(b.parameter_sets["CKP_ML_KEM_1024"], 0x3);
    assert_eq!(b.parameter_sets["CKP_SLH_DSA_SHA2_256F"], 0xB);
    // The key types the cryptoki layer subtracts, with their real (patched cryptoki) IDs.
    assert_eq!(b.key_types["CKK_SHA224_HMAC"], 0x2E);
    assert_eq!(b.key_types["CKK_SHA384_HMAC"], 0x2C);
    assert_eq!(b.key_types["CKK_SHA512_HMAC"], 0x2D);
    // Attributes, the 3.2 functions, and the vendor-defined range constants staying out.
    assert_eq!(b.attributes["CKA_VALUE_LEN"], 0x161);
    assert!(b.functions.contains("C_EncapsulateKey"));
    assert!(!b.mechanisms.contains_key("CKM_VENDOR_DEFINED"));
    // The classes the queries group by, and the curve vocabulary of keys.toml.
    assert!(b.class["pq"].mechanisms.iter().any(|m| m == "CKM_ML_DSA"));
    assert!(b.class["hmac"].mechanisms.iter().any(|m| m == "CKM_SHA512_HMAC"));
    assert!(b.class["key-wrap"].mechanisms.iter().any(|m| m == "CKM_AES_KEY_WRAP_KWP"));
    assert_eq!(b.class["oaep"].mechanisms, ["CKM_RSA_PKCS_OAEP"]);
    assert!(b.curves.contains("secp256r1") && b.curves.contains("edwards25519"));
}
