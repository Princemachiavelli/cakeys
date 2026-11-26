//! What each software token's committed profile must say, whatever the probe writes (review
//! 2026-11-24 C-8: the probe writes these files, and the build compares a fresh probe with them,
//! so a change of the probe moves both). Each property is derived from PKCS #11, from DESIGN.md
//! (cakeys' spec), or from what the module's own source and documentation say it does, never
//! from the profile; each is seen failing on its row flipped in a copy.

use cakeys_profile::{Capability, Profile, Row};

const SOFTHSM: &str = "profiles/modules/softhsm/2.7.toml";
const KRYOPTIC: &str = "profiles/modules/kryoptic/1.5.toml";
const TPM2: &str = "profiles/modules/tpm2-pkcs11/1.10+swtpm.toml";

/// A property of one profile: `Err` says how the profile breaks it.
type Check = fn(&Profile) -> Result<(), String>;
/// A change of the profile's TOML that breaks the property.
type Flip = fn(&mut toml::Table);

struct Property {
    profile: &'static str,
    name: &'static str,
    source: &'static str,
    check: Check,
    flip: Flip,
}

fn row<'p>(p: &'p Profile, key: &str) -> Option<&'p Row> {
    p.capabilities.get(&Capability::parse(key).unwrap_or_else(|e| panic!("{key}: {e}")))
}

fn is_yes(p: &Profile, key: &str) -> bool {
    row(p, key).is_some_and(|r| r.answer.yes())
}

/// `yes` all answer yes, and none of `not` does (absent, no, or untested).
fn says(p: &Profile, yes: &[&str], not: &[&str]) -> Result<(), String> {
    let wrong: Vec<String> = yes
        .iter()
        .filter(|k| !is_yes(p, k))
        .map(|k| format!("{k}: {:?}, not yes", row(p, k)))
        .chain(not.iter().filter(|k| is_yes(p, k)).map(|k| format!("{k}: yes")))
        .collect();
    if wrong.is_empty() { Ok(()) } else { Err(wrong.join("; ")) }
}

/// No row whose key starts with one of `prefixes` answers yes.
fn no_yes(p: &Profile, prefixes: &[&str]) -> Result<(), String> {
    let wrong: Vec<String> = p
        .capabilities
        .iter()
        .filter(|(c, r)| r.answer.yes() && prefixes.iter().any(|x| c.to_string().starts_with(x)))
        .map(|(c, _)| format!("{c}: yes"))
        .collect();
    if wrong.is_empty() { Ok(()) } else { Err(wrong.join("; ")) }
}

/// The mechanism PKCS #11 names for what a row does, where the row's key says (v3.2: each key
/// type's generation mechanism, OAEP, ECDH, each commitment's mechanism, DESIGN.md §3.1).
fn mechanism(key: &str) -> Option<String> {
    let parts: Vec<&str> = key.split('.').collect();
    Some(match parts[..] {
        ["generate", key_type, ..] => match key_type {
            "CKK_AES" => "CKM_AES_KEY_GEN".into(),
            "CKK_DES3" => "CKM_DES3_KEY_GEN".into(),
            "CKK_GENERIC_SECRET" => "CKM_GENERIC_SECRET_KEY_GEN".into(),
            "CKK_EC" => "CKM_EC_KEY_PAIR_GEN".into(),
            "CKK_EC_EDWARDS" => "CKM_EC_EDWARDS_KEY_PAIR_GEN".into(),
            "CKK_EC_MONTGOMERY" => "CKM_EC_MONTGOMERY_KEY_PAIR_GEN".into(),
            "CKK_RSA" => "CKM_RSA_PKCS_KEY_PAIR_GEN".into(),
            "CKK_HKDF" => "CKM_HKDF_KEY_GEN".into(),
            "CKK_ML_DSA" | "CKK_ML_KEM" | "CKK_SLH_DSA" => format!("CKM_{}_KEY_PAIR_GEN", &key_type[4..]),
            hmac => format!("CKM_{}_KEY_GEN", hmac.strip_prefix("CKK_")?.strip_suffix("_HMAC")?),
        },
        ["wrap" | "decrypt", "rsa-oaep", _] => "CKM_RSA_PKCS_OAEP".into(),
        ["derive", "ecdh", ..] | ["prove", "pop-ecdh", ..] => "CKM_ECDH1_DERIVE".into(),
        ["commit", "cmac", ..] => "CKM_AES_CMAC".into(),
        ["commit", "kcv-ecb" | "kcv-ecb-dec", "CKK_DES3", ..] => "CKM_DES3_ECB".into(),
        ["commit", "kcv-ecb" | "kcv-ecb-dec", ..] => "CKM_AES_ECB".into(),
        ["commit", "kw", ..] => "CKM_AES_KEY_WRAP".into(),
        ["commit", hmac, ..] => {
            format!("CKM_{}_HMAC", hmac.strip_prefix("hmac-")?.to_uppercase().replace("SHA1", "SHA_1"))
        }
        ["crypt" | "sign", m, ..] => m.to_owned(),
        ["derive", m, ..] if m.starts_with("CKM_") => m.to_owned(),
        ["encapsulate", ..] => "CKM_ML_KEM".into(),
        _ => return None,
    })
}

/// Every yes row's mechanism, and the one it went `via`, is one the module lists
/// (`C_GetMechanismList`) or the profile adds as performed unlisted.
fn offered(p: &Profile) -> Result<(), String> {
    let listed = |m: &str| p.advertise.iter().chain(&p.add).any(|a| a == m);
    let wrong: Vec<String> = p
        .capabilities
        .iter()
        .filter(|(_, r)| r.answer.yes())
        .flat_map(|(c, r)| {
            let key = c.to_string();
            mechanism(&key)
                .into_iter()
                .chain(r.via.clone().filter(|v| v.starts_with("CKM_")))
                .filter(|m| !listed(m))
                .map(move |m| format!("{key}: {m} is neither listed nor added"))
        })
        .collect();
    if wrong.is_empty() { Ok(()) } else { Err(wrong.join("; ")) }
}

fn caps(t: &mut toml::Table) -> &mut toml::Table {
    t.get_mut("capabilities").and_then(toml::Value::as_table_mut).expect("a [capabilities] table")
}

/// Set `key`'s row: yes as the host verified it, or no as the module refused.
fn set(t: &mut toml::Table, key: &str, yes: bool) {
    let row = if yes {
        toml::toml! { answer = "yes" by = "host" }
    } else {
        toml::toml! { answer = "no" by = "module" evidence = "CKR_MECHANISM_INVALID" }
    };
    caps(t).insert(key.into(), row.into());
}

fn claim(t: &mut toml::Table, name: &str, value: &str) {
    t.get_mut("claims").and_then(toml::Value::as_table_mut).unwrap().insert(name.into(), value.into());
}

const PROPERTIES: &[Property] = &[
    Property {
        profile: SOFTHSM,
        name: "oaep-is-sha1-only",
        source: "DESIGN.md §3.6 (SoftHSM implements no other OAEP); SoftHSM's MechParamCheckRSAPKCSOAEP takes \
                 CKM_SHA_1 with CKG_MGF1_SHA1 only",
        check: |p| {
            says(
                p,
                &["wrap.rsa-oaep.SHA-1", "decrypt.rsa-oaep.SHA-1"],
                &["wrap.rsa-oaep.SHA-256", "decrypt.rsa-oaep.SHA-256", "decrypt.rsa-oaep.SHA-512"],
            )
        },
        flip: |t| set(t, "wrap.rsa-oaep.SHA-256", true),
    },
    Property {
        profile: SOFTHSM,
        name: "aes-is-16-24-or-32-bytes",
        source: "PKCS #11 v3.2 §6.8.1: an AES key's CKA_VALUE_LEN is 16, 24 or 32; SoftHSM checks it",
        check: |p| {
            says(
                p,
                &["generate.CKK_AES.16", "generate.CKK_AES.24", "generate.CKK_AES.32"],
                &["generate.CKK_AES.8", "generate.CKK_AES.48", "generate.CKK_AES.64"],
            )
        },
        flip: |t| set(t, "generate.CKK_AES.48", true),
    },
    Property {
        profile: SOFTHSM,
        name: "every-baseline-curve-generates",
        source: "SoftHSM hands CKA_EC_PARAMS to OpenSSL, which knows every curve of the baseline, and signs \
                 EdDSA on Ed25519 and Ed448",
        check: |p| {
            says(
                p,
                &[
                    "generate.CKK_EC.secp256r1",
                    "generate.CKK_EC.secp384r1",
                    "generate.CKK_EC.secp521r1",
                    "generate.CKK_EC.secp256k1",
                    "generate.CKK_EC.brainpoolP256r1",
                    "generate.CKK_EC.brainpoolP384r1",
                    "generate.CKK_EC_EDWARDS.edwards25519",
                    "generate.CKK_EC_EDWARDS.edwards448",
                ],
                &[],
            )
        },
        flip: |t| set(t, "generate.CKK_EC.secp256k1", false),
    },
    Property {
        profile: SOFTHSM,
        name: "no-hash-bound-hmac-key-or-montgomery",
        source: "SoftHSM's mechanism list has CKM_GENERIC_SECRET_KEY_GEN and CKM_EC_EDWARDS_KEY_PAIR_GEN, no \
                 CKM_SHA*_KEY_GEN and no CKM_EC_MONTGOMERY_KEY_PAIR_GEN (OPEN.md: SoftHSM 2.7 refuses an HMAC-typed \
                 generation)",
        check: |p| no_yes(p, &["generate.CKK_SHA", "generate.CKK_EC_MONTGOMERY"]),
        flip: |t| set(t, "generate.CKK_SHA256_HMAC.32", true),
    },
    Property {
        profile: SOFTHSM,
        name: "triple-des-is-24-bytes",
        source: "PKCS #11 v3.2 §6.9: a CKK_DES3 key is 24 bytes, made by CKM_DES3_KEY_GEN, which SoftHSM lists",
        check: |p| says(p, &["generate.CKK_DES3.24", "import.CKK_DES3.24"], &[]),
        flip: |t| set(t, "generate.CKK_DES3.24", false),
    },
    Property {
        profile: SOFTHSM,
        name: "rsa-is-512-to-16384-bits",
        source: "SoftHSM's OSSLRSA: getMinKeySize 512, getMaxKeySize 16384",
        check: |p| match p.reported.get("CKK_RSA") {
            Some(r) if r.min_bits == Some(512) && r.max_bits == Some(16384) => Ok(()),
            r => Err(format!("[reported.\"CKK_RSA\"] {r:?}")),
        },
        flip: |t| {
            let rsa = t["reported"]["CKK_RSA"].as_table().unwrap().clone();
            let mut rsa = rsa;
            rsa.insert("max-bits".into(), 8192.into());
            t.get_mut("reported").and_then(toml::Value::as_table_mut).unwrap().insert("CKK_RSA".into(), rsa.into());
        },
    },
    Property {
        profile: SOFTHSM,
        name: "commits-by-every-scheme",
        source: "DESIGN.md §3.1: the commitments' mechanisms, CKM_AES_CMAC, CKM_AES_ECB, CKM_AES_KEY_WRAP, \
                 CKM_DES3_ECB and CKM_SHA256_HMAC, each of which SoftHSM implements",
        check: |p| {
            let mut yes = Vec::new();
            for kind in ["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"] {
                for bytes in [16, 24, 32] {
                    yes.push(format!("commit.{kind}.CKK_AES.{bytes}"));
                }
            }
            yes.extend(["commit.kcv-ecb.CKK_DES3.24".into(), "commit.kcv-ecb-dec.CKK_DES3.24".into()]);
            yes.push("commit.hmac-sha256.CKK_GENERIC_SECRET.32".into());
            says(p, &yes.iter().map(String::as_str).collect::<Vec<_>>(), &[])
        },
        flip: |t| set(t, "commit.kw.CKK_AES.24", false),
    },
    Property {
        profile: SOFTHSM,
        name: "proves-every-binding",
        source: "DESIGN.md §3.6: pop-sign (ECDSA, EdDSA, RSA PKCS #1), pop-ecdh, pop-decrypt and pop-unwrap \
                 (OAEP SHA-1), all of which SoftHSM implements",
        check: |p| {
            says(
                p,
                &[
                    "prove.pop-sign.CKK_EC.secp256r1",
                    "prove.pop-sign.CKK_EC_EDWARDS.edwards25519",
                    "prove.pop-sign.CKK_RSA.2048",
                    "prove.pop-ecdh.CKK_EC.secp256r1",
                    "prove.pop-decrypt.CKK_RSA.2048",
                    "prove.pop-unwrap.CKK_RSA.2048",
                ],
                &[],
            )
        },
        flip: |t| set(t, "prove.pop-unwrap.CKK_RSA.2048", false),
    },
    Property {
        profile: SOFTHSM,
        name: "ecdh-is-sealed",
        source: "DESIGN.md §3.6: the extractable variant is for a token with no HMAC or no sealed derive (ykcs11, \
                 tpm2-pkcs11); SoftHSM has both, in a read-only session too",
        check: |p| says(p, &["derive.ecdh.sealed", "derive.ecdh.read-only"], &[]),
        flip: |t| set(t, "derive.ecdh.sealed", false),
    },
    Property {
        profile: KRYOPTIC,
        name: "oaep-takes-sha1-and-sha256",
        source: "kryoptic's RSA-OAEP takes the hash CK_RSA_PKCS_OAEP_PARAMS names (OpenSSL)",
        check: |p| {
            says(
                p,
                &[
                    "wrap.rsa-oaep.SHA-1",
                    "wrap.rsa-oaep.SHA-256",
                    "decrypt.rsa-oaep.SHA-1",
                    "decrypt.rsa-oaep.SHA-256",
                    "decrypt.rsa-oaep.SHA-512",
                ],
                &[],
            )
        },
        flip: |t| set(t, "wrap.rsa-oaep.SHA-256", false),
    },
    Property {
        profile: KRYOPTIC,
        name: "nist-curves-only",
        source: "kryoptic implements ECDSA on the NIST curves P-256, P-384 and P-521; no secp256k1 or brainpool",
        check: |p| {
            says(
                p,
                &["generate.CKK_EC.secp256r1", "generate.CKK_EC.secp384r1", "generate.CKK_EC.secp521r1"],
                &["generate.CKK_EC.secp256k1", "generate.CKK_EC.brainpoolP256r1", "generate.CKK_EC.brainpoolP384r1"],
            )
        },
        flip: |t| set(t, "generate.CKK_EC.secp384r1", false),
    },
    Property {
        profile: KRYOPTIC,
        name: "no-des",
        source: "OPEN.md: kryoptic 1.5 has no DES at all; its mechanism list names no CKM_DES3_*",
        check: |p| {
            no_yes(p, &["generate.CKK_DES3", "import.CKK_DES3", "unwrap.CKK_DES3", "commit.kcv-ecb.CKK_DES3"])?;
            match p.advertise.iter().find(|m| m.starts_with("CKM_DES")) {
                Some(m) => Err(format!("lists {m}")),
                None => Ok(()),
            }
        },
        flip: |t| set(t, "import.CKK_DES3.24", true),
    },
    Property {
        profile: KRYOPTIC,
        name: "hash-bound-hmac-keys-generate",
        source: "OPEN.md: an HMAC-typed key generates with CKM_SHA*_KEY_GEN on kryoptic, which implements all five",
        check: |p| {
            says(
                p,
                &[
                    "generate.CKK_SHA_1_HMAC.32",
                    "generate.CKK_SHA224_HMAC.32",
                    "generate.CKK_SHA256_HMAC.32",
                    "generate.CKK_SHA384_HMAC.32",
                    "generate.CKK_SHA512_HMAC.32",
                ],
                &[],
            )
        },
        flip: |t| set(t, "generate.CKK_SHA384_HMAC.32", false),
    },
    Property {
        profile: KRYOPTIC,
        name: "aes-without-a-length-check",
        source: "OPEN.md: kryoptic generates AES at 8, 48 and 64 bytes as at 16, 24 and 32 (a module quirk)",
        check: |p| {
            says(
                p,
                &[
                    "generate.CKK_AES.8",
                    "generate.CKK_AES.16",
                    "generate.CKK_AES.24",
                    "generate.CKK_AES.32",
                    "generate.CKK_AES.48",
                    "generate.CKK_AES.64",
                ],
                &[],
            )
        },
        flip: |t| set(t, "generate.CKK_AES.48", false),
    },
    Property {
        profile: KRYOPTIC,
        name: "edwards-and-montgomery",
        source: "kryoptic implements EdDSA on Ed25519 and Ed448 and ECDH on X25519 and X448; DESIGN.md §3.6 proves \
                 Ed25519 by pure EdDSA",
        check: |p| {
            says(
                p,
                &[
                    "generate.CKK_EC_EDWARDS.edwards25519",
                    "generate.CKK_EC_EDWARDS.edwards448",
                    "generate.CKK_EC_MONTGOMERY.curve25519",
                    "generate.CKK_EC_MONTGOMERY.curve448",
                    "prove.pop-sign.CKK_EC_EDWARDS.edwards25519",
                ],
                &[],
            )
        },
        flip: |t| set(t, "generate.CKK_EC_EDWARDS.edwards448", false),
    },
    Property {
        profile: KRYOPTIC,
        name: "post-quantum-of-3-2",
        source: "kryoptic implements PKCS #11 3.2, ML-DSA, ML-KEM and SLH-DSA with it",
        check: |p| {
            says(
                p,
                &[
                    "generate.CKK_ML_DSA.CKP_ML_DSA_44",
                    "generate.CKK_ML_DSA.CKP_ML_DSA_65",
                    "generate.CKK_ML_DSA.CKP_ML_DSA_87",
                    "generate.CKK_ML_KEM.CKP_ML_KEM_512",
                    "generate.CKK_ML_KEM.CKP_ML_KEM_768",
                    "generate.CKK_ML_KEM.CKP_ML_KEM_1024",
                    "generate.CKK_SLH_DSA.CKP_SLH_DSA_SHA2_128S",
                ],
                &[],
            )?;
            match p.claims.get("interface").map(String::as_str) {
                Some("Cryptoki 3.2") => Ok(()),
                other => Err(format!("interface {other:?}")),
            }
        },
        flip: |t| claim(t, "interface", "Cryptoki 3.0"),
    },
    Property {
        profile: KRYOPTIC,
        name: "ecdh-is-sealed",
        source: "DESIGN.md §3.6: the extractable variant is for a token with no HMAC or no sealed derive; kryoptic \
                 has both, in a read-only session too",
        check: |p| says(p, &["derive.ecdh.sealed", "derive.ecdh.read-only"], &[]),
        flip: |t| set(t, "derive.ecdh.read-only", false),
    },
    Property {
        profile: KRYOPTIC,
        name: "an-hmac-type-commits-with-its-own-hash",
        source: "DESIGN.md §3.1: a CKK_SHA*_HMAC key's commitment is the HMAC of its type's hash",
        check: |p| {
            says(
                p,
                &[
                    "commit.hmac-sha1.CKK_SHA_1_HMAC.32",
                    "commit.hmac-sha224.CKK_SHA224_HMAC.32",
                    "commit.hmac-sha256.CKK_SHA256_HMAC.32",
                    "commit.hmac-sha384.CKK_SHA384_HMAC.32",
                    "commit.hmac-sha512.CKK_SHA512_HMAC.64",
                ],
                &[],
            )
        },
        flip: |t| set(t, "commit.hmac-sha512.CKK_SHA512_HMAC.64", false),
    },
    Property {
        profile: TPM2,
        name: "ecdh-is-extractable-and-read-write",
        source: "DESIGN.md §3.6: tpm2-pkcs11 1.10 derives only into an extractable secret, and refuses C_DeriveKey \
                 in a read-only session",
        check: |p| {
            says(p, &[], &["derive.ecdh.sealed", "derive.ecdh.read-only"])?;
            match row(p, "derive.ecdh.read-only") {
                Some(r) if !r.answer.yes() => Ok(()),
                r => Err(format!("derive.ecdh.read-only: {r:?}, not no")),
            }
        },
        flip: |t| set(t, "derive.ecdh.read-only", true),
    },
    Property {
        profile: TPM2,
        name: "no-edwards-or-montgomery",
        source: "TPM 2.0 (libtpms, under swtpm) has no EdDSA or X25519 curve, and tpm2-pkcs11 1.10 no CKK_EC_EDWARDS",
        check: |p| {
            no_yes(p, &["generate.CKK_EC_EDWARDS", "generate.CKK_EC_MONTGOMERY", "prove.pop-sign.CKK_EC_EDWARDS"])
        },
        flip: |t| set(t, "generate.CKK_EC_EDWARDS.edwards25519", true),
    },
    Property {
        profile: TPM2,
        name: "never-wraps-or-unwraps",
        source: "tpm2-pkcs11 1.10 implements neither C_WrapKey nor C_UnwrapKey (CKR_FUNCTION_NOT_SUPPORTED)",
        check: |p| no_yes(p, &["wrap.", "unwrap.", "export.sealed.", "prove.pop-unwrap."]),
        flip: |t| set(t, "prove.pop-unwrap.CKK_RSA.2048", true),
    },
    Property {
        profile: TPM2,
        name: "rsa-is-1024-to-3072-bits",
        source: "libtpms (swtpm) implements RSA 1024, 2048 and 3072",
        check: |p| {
            says(
                p,
                &["generate.CKK_RSA.1024", "generate.CKK_RSA.2048", "generate.CKK_RSA.3072"],
                &["generate.CKK_RSA.512", "generate.CKK_RSA.4096"],
            )
        },
        flip: |t| set(t, "generate.CKK_RSA.4096", true),
    },
    Property {
        profile: TPM2,
        name: "no-secret-key-generation",
        source: "CAPROBE.md: tpm2-pkcs11 1.10 lists CKM_AES_KEY_GEN, but its C_GenerateKey is \
                 CKR_FUNCTION_NOT_SUPPORTED; TPM 2.0 has no DES",
        check: |p| no_yes(p, &["generate.CKK_AES", "generate.CKK_DES3", "generate.CKK_GENERIC_SECRET"]),
        flip: |t| set(t, "generate.CKK_AES.32", true),
    },
    Property {
        profile: TPM2,
        name: "cryptoki-2-40",
        source: "tpm2-pkcs11 1.10 implements PKCS #11 2.40",
        check: |p| match p.claims.get("interface").map(String::as_str) {
            Some("Cryptoki 2.40") => Ok(()),
            other => Err(format!("interface {other:?}")),
        },
        flip: |t| claim(t, "interface", "Cryptoki 3.0"),
    },
    Property {
        profile: TPM2,
        name: "nist-p256-and-p384",
        source: "the TPM 2.0 PC Client profile's curves, TPM_ECC_NIST_P256 and P384, which libtpms implements",
        check: |p| {
            says(
                p,
                &[
                    "generate.CKK_EC.secp256r1",
                    "generate.CKK_EC.secp384r1",
                    "prove.pop-sign.CKK_EC.secp256r1",
                    "prove.pop-ecdh.CKK_EC.secp256r1",
                ],
                &[],
            )
        },
        flip: |t| set(t, "generate.CKK_EC.secp384r1", false),
    },
    Property {
        profile: TPM2,
        name: "proves-by-signing-and-decrypting",
        source: "DESIGN.md §3.6: pop-sign and pop-decrypt (OAEP, which TPM2_RSA_Decrypt implements)",
        check: |p| says(p, &["prove.pop-sign.CKK_RSA.2048", "prove.pop-decrypt.CKK_RSA.2048"], &[]),
        flip: |t| set(t, "prove.pop-decrypt.CKK_RSA.2048", false),
    },
];

/// The properties every software profile keeps.
const EVERY: &[(&str, &str, Check, Flip)] = &[(
    "every-yes-uses-an-offered-mechanism",
    "PKCS #11 v3.2 §5.5: C_GetMechanismList lists what the token supports; `add` names what it performs \
     unlisted (CAPROBE.md)",
    offered,
    |t| {
        let advertise = t.get_mut("advertise").and_then(toml::Value::as_array_mut).unwrap();
        advertise.retain(|m| m.as_str() != Some("CKM_RSA_PKCS_OAEP"));
    },
)];

fn committed(path: &str) -> String {
    let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").join(path);
    std::fs::read_to_string(&file).unwrap_or_else(|e| panic!("{}: {e}", file.display()))
}

fn load(path: &str, text: &str) -> Profile {
    Profile::from_toml(text).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Every property, with its profile.
fn all() -> Vec<(&'static str, &'static str, &'static str, Check, Flip)> {
    let mut all: Vec<_> = PROPERTIES.iter().map(|p| (p.profile, p.name, p.source, p.check, p.flip)).collect();
    for profile in [SOFTHSM, KRYOPTIC, TPM2] {
        all.extend(EVERY.iter().map(|&(name, source, check, flip)| (profile, name, source, check, flip)));
    }
    all
}

#[test]
fn every_software_profile_keeps_its_properties() {
    let broken: Vec<String> = all()
        .into_iter()
        .filter_map(|(path, name, source, check, _)| {
            check(&load(path, &committed(path))).err().map(|e| format!("{path}: {name}: {e} ({source})"))
        })
        .collect();
    assert!(broken.is_empty(), "{}", broken.join("\n"));
}

/// Each property fails on its row flipped in a copy of the committed profile: none holds
/// vacuously.
#[test]
fn each_property_fails_on_its_row_flipped() {
    for (path, name, _, check, flip) in all() {
        let mut table: toml::Table = toml::from_str(&committed(path)).unwrap();
        flip(&mut table);
        let flipped = load(path, &toml::to_string(&table).unwrap());
        assert!(check(&flipped).is_err(), "{path}: {name} holds on its row flipped");
    }
}
