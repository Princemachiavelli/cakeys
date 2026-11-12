//! Helpers shared by the integration tests: CLI output parsing and an independent DER oracle.
#![allow(dead_code)] // each test binary uses a subset

use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::process::Output;

/// Whether the linked cryptoki has the HMAC key type fix (nix/patches/); the Nix build does.
/// Without it, tests needing SHA-224/384/512 HMAC keys skip, unless `require` (then they fail).
pub fn cryptoki_hmac_types_fixed(require: bool) -> bool {
    let fixed = std::os::raw::c_ulong::from(cryptoki::object::KeyType::SHA384_HMAC) == 0x2c;
    assert!(fixed || !require, "cryptoki lacks the HMAC key type fix (nix/patches/cryptoki-hmac-key-types.patch)");
    if !fixed {
        eprintln!("skipping: cryptoki lacks the HMAC key type fix; run through the Nix build");
    }
    fixed
}

pub fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

/// The writing form of a compare-only `realise`/`delete` argument list: `--no-update-lock`
/// dropped, `--update-lock` (the default, said explicitly) added.
pub fn recording<'a>(args: &[&'a str]) -> Vec<&'a str> {
    args.iter().copied().filter(|a| *a != "--no-update-lock").chain(["--update-lock"]).collect()
}

pub fn got_hash(o: &Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr);
    let line = err.lines().find(|l| l.trim_start().starts_with("got:")).expect("no got: line");
    line.split_whitespace().last().unwrap().to_owned()
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

pub fn sri(bytes: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(bytes)))
}

/// Minimal DER writer for the test oracle: independent of the crates the tool uses.
pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = body.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let len: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        v.push(0x80 | len.len() as u8);
        v.extend(len);
    }
    v.extend_from_slice(body);
    v
}

pub fn der_uint(b: &[u8]) -> Vec<u8> {
    let b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
    let mut body = if b[0] & 0x80 != 0 { vec![0] } else { vec![] };
    body.extend(b);
    tlv(0x02, &body)
}

pub fn spki(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend_from_slice(key);
    tlv(0x30, &[tlv(0x30, algorithm), tlv(0x03, &bits)].concat())
}

/// `CKA_EC_POINT` is a DER OCTET STRING around the point.
pub fn unwrap_octets(v: &[u8]) -> Vec<u8> {
    assert_eq!(v[0], 0x04);
    let (len, off) = match v[1] {
        n if n < 0x80 => (n as usize, 2),
        0x81 => (v[2] as usize, 3),
        n => panic!("length form {n:#x}"),
    };
    assert_eq!(v.len(), off + len, "{v:02x?}");
    v[off..].to_vec()
}

pub const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub const P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
pub const ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
pub const ED448: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x71];

/// SPKI of the public key object under `label`, built from its raw PKCS#11 attributes.
pub fn oracle_spki(s: &Session, label: &str) -> Vec<u8> {
    oracle_spki_with(s, label, unwrap_octets)
}

/// As [`oracle_spki`], with a custom `CKA_EC_POINT` unwrapper (for a module's known bug).
pub fn oracle_spki_with(s: &Session, label: &str, unwrap: fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let h = s
        .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::Label(label.as_bytes().to_vec())])
        .unwrap()[0];
    let a = s.get_attributes(h, &[AttributeType::KeyType]).unwrap();
    match a[0] {
        Attribute::KeyType(cryptoki::object::KeyType::RSA) => {
            let a = s.get_attributes(h, &[AttributeType::Modulus, AttributeType::PublicExponent]).unwrap();
            let (Attribute::Modulus(n), Attribute::PublicExponent(e)) = (&a[0], &a[1]) else { panic!() };
            let rsa = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
            spki(&rsa, &tlv(0x30, &[der_uint(n), der_uint(e)].concat()))
        }
        _ => {
            let a = s.get_attributes(h, &[AttributeType::EcParams, AttributeType::EcPoint]).unwrap();
            let (Attribute::EcParams(p), Attribute::EcPoint(q)) = (&a[0], &a[1]) else { panic!() };
            let point = unwrap(q);
            match p.as_slice() {
                ED25519 | ED448 => spki(p, &point),
                _ => spki(&[EC_PUBLIC_KEY, p.as_slice()].concat(), &point),
            }
        }
    }
}


/// Host oracle for the AES commitments (`cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`) of a known
/// AES-128/192/256 key.
pub fn aes_commitment(key: &[u8], scheme: &str) -> String {
    use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use cmac::Mac;
    let label = format!("key-management/v1/{scheme}/CKK_AES/{}", key.len() * 8);
    let digest = <sha2::Sha256 as sha2::Digest>::digest(label.as_bytes());
    let mut block = aes::Block::default();
    block.copy_from_slice(&digest[..16]);
    macro_rules! with_cipher {
        ($aes:ty, $kw:ty) => {
            match scheme {
                "cmac" => {
                    let mut m = <cmac::Cmac<$aes> as KeyInit>::new_from_slice(key).unwrap();
                    m.update(label.as_bytes());
                    m.finalize().into_bytes().to_vec()
                }
                "kcv-ecb" => {
                    <$aes>::new_from_slice(key).unwrap().encrypt_block(&mut block);
                    block.to_vec()
                }
                "kcv-ecb-dec" => {
                    <$aes>::new_from_slice(key).unwrap().decrypt_block(&mut block);
                    block.to_vec()
                }
                "kw" => {
                    let mut buf = [0u8; 40];
                    <$kw>::new_from_slice(key).unwrap().wrap_key(&digest, &mut buf).unwrap().to_vec()
                }
                s => panic!("{s}"),
            }
        };
    }
    let out = match key.len() {
        16 => with_cipher!(aes::Aes128, aes_kw::KwAes128),
        24 => with_cipher!(aes::Aes192, aes_kw::KwAes192),
        32 => with_cipher!(aes::Aes256, aes_kw::KwAes256),
        n => panic!("AES key of {n} bytes"),
    };
    sri(&out)
}

/// A logged-in session on `label` that finalizes the module when dropped. cryptoki >= 0.11 no
/// longer finalizes on drop, and tests need a fresh `C_Initialize` per session (tpm2-pkcs11 only
/// sees objects created by other processes after one).
pub struct TestSession {
    session: Option<Session>,
    ctx: Option<Pkcs11>,
}

impl std::ops::Deref for TestSession {
    type Target = Session;
    fn deref(&self) -> &Session {
        self.session.as_ref().unwrap()
    }
}

impl Drop for TestSession {
    fn drop(&mut self) {
        drop(self.session.take());
        if let Some(ctx) = self.ctx.take() {
            let _ = ctx.finalize();
        }
    }
}

pub fn open_session(module: &str, label: &str, pin: &str) -> TestSession {
    let ctx = Pkcs11::new(module).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().label() == label)
        .unwrap();
    let session = ctx.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(&AuthPin::new(pin.into()))).unwrap();
    TestSession { session: Some(session), ctx: Some(ctx) }
}
