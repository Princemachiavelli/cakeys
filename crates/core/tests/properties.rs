//! Property tests of the core crate (docs/VERIFICATION.md, step 2): the lock rules over generated
//! realisations, the injectivity of the identity encodings, and parsers that never panic on
//! malformed input. The same parsers are fuzz targets under `fuzz/`.

use cakeys_core::config::{
    AttrValue, Binding, Config, Immutables, LOCK_VERSION, Lock, Mode, ModuleInfo, ObjectCfg, Observed, Provenance,
    Session, TokenInfo, parse_config_with, parse_lock,
};
use cakeys_core::id::{self, Commit, Curve, HmacHash};
use cakeys_core::plan::Target;
use cakeys_core::reconcile::{Facts, LockWrite, Notes, Resolved, compare, reconcile};
use cakeys_core::types::{KeyType, ObjectClass};
use proptest::prelude::*;
use proptest::sample::Index;
use std::path::Path;

const CONFIG: &str = r#"
[tokens.t1]
tokenLabel = "t1"

[tokens.t2]
tokenLabel = "t2"

[objects.k]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[specs.s]
object = "k"
attributes = { CKA_SIGN = true }
tokens.t1 = { locator = { CKA_LABEL = "k" } }

[objects.aes]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.a]
object = "aes"
attributes = { CKA_SIGN = true, CKA_ENCRYPT = true, CKA_DECRYPT = true, CKA_WRAP = true }
tokens.t1 = { locator = { CKA_LABEL = "aes" } }
tokens.t2 = { locator = { CKA_LABEL = "aes" } }
"#;

const AES_SCHEMES: [&str; 4] = ["cmac", "kcv-ecb", "kcv-ecb-dec", "kw"];

fn config() -> Config {
    parse_config_with(CONFIG, Path::new("keys.toml"), &|_| None).unwrap()
}

fn facts() -> Facts {
    Facts {
        observed: Observed { uri: "pkcs11:token=t".into(), session: Session::User, mechanisms: vec![] },
        provenance: Provenance {
            provider: "generic".into(),
            cakeys_version: "0.1.0".into(),
            module: ModuleInfo {
                path: "/m.so".into(),
                hash: None,
                description: "m".into(),
                manufacturer: "x".into(),
                version: "1.0".into(),
                cryptoki: "3.0".into(),
            },
            token: TokenInfo { model: "m".into(), serial: "1".into(), firmware: "1.0".into() },
            extra: std::collections::BTreeMap::new(),
        },
    }
}

fn empty_lock() -> Lock {
    Lock { version: LOCK_VERSION, ..Default::default() }
}

fn snapshot(lock: &Lock) -> String {
    toml::to_string(lock).unwrap()
}

/// A realisation of the EC key as a token might report it, varied along every compared field.
#[derive(Debug, Clone)]
struct Variant {
    material: bool,
    binding: Binding,
    immutables: [Option<bool>; 3],
    policy: [bool; 2],
    spec_changed: bool,
}

fn variant() -> impl Strategy<Value = Variant> {
    let binding = prop_oneof![Just(Binding::PopSign), Just(Binding::PopEcdh), Just(Binding::TokenAsserted)];
    let flag = proptest::option::of(any::<bool>());
    (any::<bool>(), binding, [flag.clone(), flag.clone(), flag], any::<[bool; 2]>(), any::<bool>()).prop_map(
        |(material, binding, immutables, policy, spec_changed)| Variant {
            material,
            binding,
            immutables,
            policy,
            spec_changed,
        },
    )
}

fn resolved(t: &Target, v: &Variant) -> Resolved {
    let [local, never_extractable, always_sensitive] = v.immutables;
    Resolved {
        object: t.object_name.into(),
        spec: t.spec_name.into(),
        token: t.token_name.into(),
        uri: "pkcs11:token=t1;object=k;type=private".into(),
        mode: Mode::Direct,
        public_only: false,
        spec_digest: if v.spec_changed { id::sri(b"another spec") } else { id::spec_digest(t.object, t.spec) },
        ids: [("rfc7093m4".to_owned(), id::sri(&[u8::from(v.material)]))].into(),
        binding: Some(v.binding),
        assurance: cakeys_core::plan::assurance(t.object.class, Some(v.binding), None),
        policy: [("CKA_SIGN", v.policy[0]), ("CKA_DECRYPT", v.policy[1])]
            .into_iter()
            .map(|(n, b)| (n.to_owned(), AttrValue::Bool(b)))
            .collect(),
        immutables: Immutables { local, never_extractable, always_sensitive, key_gen_mechanism: None },
        commitment_label: None,
        attestation: None,
    }
}

/// An AES realisation computing `schemes` over `material`: equal material, equal IDs.
fn aes(t: &Target, material: u8, schemes: &[&str]) -> Resolved {
    Resolved {
        object: t.object_name.into(),
        spec: t.spec_name.into(),
        token: t.token_name.into(),
        uri: format!("pkcs11:token={};object=aes;type=secret-key", t.token_name),
        mode: Mode::Commitment,
        public_only: false,
        spec_digest: id::spec_digest(t.object, t.spec),
        ids: schemes.iter().map(|s| ((*s).to_owned(), id::sri(format!("{material}/{s}").as_bytes()))).collect(),
        binding: None,
        assurance: cakeys_core::plan::Assurance::Fingerprint,
        policy: std::collections::BTreeMap::new(),
        immutables: Immutables::default(),
        commitment_label: Some(id::DEFAULT_COMMITMENT_LABEL.into()),
        attestation: None,
    }
}

/// A non-empty subset of the AES schemes, from a bit mask.
fn aes_schemes() -> impl Strategy<Value = Vec<&'static str>> {
    (1u8..16).prop_map(|mask| {
        AES_SCHEMES.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, s)| *s).collect()
    })
}

fn exit(r: &cakeys_core::Result<impl Sized>) -> u8 {
    r.as_ref().err().map_or(0, cakeys_core::KmError::exit_code)
}

/// Whether `now` weakens a flag `was` recorded as true (the object was replaced).
fn weakened(was: [Option<bool>; 3], now: [Option<bool>; 3]) -> bool {
    was.iter().zip(now).any(|(w, n)| *w == Some(true) && n != Some(true))
}

proptest! {
    /// A recorded realisation compares clean, and recording it again changes nothing.
    #[test]
    fn recorded_then_compared_and_idempotent(v in variant()) {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t1").unwrap();
        let r = resolved(&t, &v);
        let mut lock = empty_lock();
        let mut notes = Notes::default();
        prop_assert!(reconcile(&t, &r, &mut lock, &facts(), LockWrite::Record, &mut notes).unwrap());
        let recorded = snapshot(&lock);
        compare(&t, &r, &lock, &facts(), LockWrite::Compare, &mut notes).unwrap();
        prop_assert!(!reconcile(&t, &r, &mut lock, &facts(), LockWrite::Record, &mut notes).unwrap());
        prop_assert_eq!(snapshot(&lock), recorded);
    }

    /// After `first` is recorded, `second`: another material is a mismatch (10), a weaker binding
    /// or a replaced object (a recorded `true` flag no longer true) a precondition failure (14),
    /// in both modes; drift the write is for (policy, spec) fails only a compare. A write that
    /// succeeds never overwrites the locked ID and leaves a lock that compares clean.
    #[test]
    fn a_write_fills_gaps_and_never_overrides(first in variant(), second in variant()) {
        let cfg = config();
        let t = Target::new(&cfg, "s", "t1").unwrap();
        let mut lock = empty_lock();
        reconcile(&t, &resolved(&t, &first), &mut lock, &facts(), LockWrite::Record, &mut Notes::default()).unwrap();
        let locked_id = lock.objects["k"].ids["rfc7093m4"].clone();
        let r = resolved(&t, &second);

        let downgrade = second.binding.rank() > first.binding.rank();
        let replaced = weakened(first.immutables, second.immutables);
        let mismatch = first.material != second.material;
        let drift = first.spec_changed != second.spec_changed
            || first.policy != second.policy
            || first.immutables != second.immutables;
        let refused = downgrade || replaced || mismatch;

        let compared = compare(&t, &r, &lock, &facts(), LockWrite::Compare, &mut Notes::default());
        prop_assert_eq!(compared.is_ok(), !refused && !drift, "compare: {:?}", compared);
        let written = reconcile(&t, &r, &mut lock, &facts(), LockWrite::Record, &mut Notes::default());
        prop_assert_eq!(written.is_ok(), !refused, "write: {:?}", written);
        if downgrade || replaced {
            prop_assert_eq!(exit(&written), 14);
        } else if mismatch {
            prop_assert_eq!(exit(&written), 10);
        } else {
            compare(&t, &r, &lock, &facts(), LockWrite::Compare, &mut Notes::default()).unwrap();
        }
        prop_assert_eq!(&lock.objects["k"].ids["rfc7093m4"], &locked_id);
    }

    /// Material links only through a shared scheme. On a second token: disjoint schemes are
    /// refused (14) and other material under a shared scheme is a mismatch (10), in both modes;
    /// otherwise the write adds the missing schemes and keeps every locked ID.
    #[test]
    fn material_links_only_through_a_shared_scheme(
        first in aes_schemes(),
        second in aes_schemes(),
        same_material in any::<bool>(),
    ) {
        let cfg = config();
        let t1 = Target::new(&cfg, "a", "t1").unwrap();
        let t2 = Target::new(&cfg, "a", "t2").unwrap();
        let mut lock = empty_lock();
        reconcile(&t1, &aes(&t1, 1, &first), &mut lock, &facts(), LockWrite::Record, &mut Notes::default()).unwrap();
        let before = lock.objects["aes"].ids.clone();
        let r = aes(&t2, if same_material { 1 } else { 2 }, &second);
        let shared = second.iter().any(|s| first.contains(s));
        let want = match (shared, same_material) {
            (false, _) => 14,
            (true, false) => 10,
            (true, true) => 0,
        };
        for write in [LockWrite::Compare, LockWrite::Record] {
            let got = reconcile(&t2, &r, &mut lock.clone(), &facts(), write, &mut Notes::default());
            // A first realisation on t2 is not recorded yet, so a clean compare is 14 too.
            let want = if want == 0 && write == LockWrite::Compare { 14 } else { want };
            prop_assert_eq!(exit(&got), want, "{:?} {:?}: {:?}", write, second, got);
        }
        if want == 0 {
            reconcile(&t2, &r, &mut lock, &facts(), LockWrite::Record, &mut Notes::default()).unwrap();
            let ids = &lock.objects["aes"].ids;
            prop_assert!(before.iter().all(|(s, id)| ids.get(s) == Some(id)), "an ID was overwritten");
            prop_assert!(second.iter().all(|s| ids.contains_key(*s)), "a scheme was not recorded");
        }
    }

    /// The attestation encodings are injective: the same bytes cut into fields at different
    /// places never give the same ID (each field is length-prefixed).
    #[test]
    fn attestation_ids_are_injective(bytes in proptest::collection::vec(any::<u8>(), 0..48), a in any::<Index>(), b in any::<Index>()) {
        let (i, j) = (a.index(bytes.len() + 1), b.index(bytes.len() + 1));
        prop_assume!(i != j);
        prop_assert_ne!(
            id::tpm_certify_id(&bytes[..i], &bytes[i..]),
            id::tpm_certify_id(&bytes[..j], &bytes[j..])
        );
        let piv = |k: usize| id::piv_attestation_id(&bytes[..k], &bytes[k..], b"", b"", b"", b"");
        prop_assert_ne!(piv(i), piv(j));
        prop_assert_ne!(piv(i), id::tpm_certify_id(&bytes[..i], &bytes[i..]), "domain-separated");
    }

    /// The commitment label `<label>/<scheme>/<keyType>/<bits>` determines its parts: two
    /// different (label, scheme, length) never share a label, whatever `/` the label holds, for
    /// every length that loads.
    #[test]
    fn commitment_labels_are_injective(
        l1 in "[a-z/]{0,12}", l2 in "[a-z/]{0,12}",
        v1 in 0..=u64::from(u32::MAX), v2 in 0..=u64::from(u32::MAX),
        c1 in 0usize..5, c2 in 0usize..5,
    ) {
        let commits = [Commit::Hmac(HmacHash::Sha256), Commit::Cmac, Commit::KcvEcb, Commit::KcvEcbDecrypt, Commit::Kw];
        let object = |v: u64| {
            let mut o = ObjectCfg::new(ObjectClass::SecretKey, Some(KeyType::Aes));
            o.value_len = Some(v);
            o
        };
        prop_assume!((&l1, v1, c1) != (&l2, v2, c2));
        prop_assert_ne!(commits[c1].label(&l1, &object(v1)), commits[c2].label(&l2, &object(v2)));
    }

    /// `is_sri` accepts exactly what `sri` writes: 32 bytes, padded standard base64.
    #[test]
    fn sri_round_trips(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        use base64::Engine;
        prop_assert!(id::is_sri(&id::sri(&bytes)));
        let raw = format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(&bytes));
        prop_assert_eq!(id::is_sri(&raw), bytes.len() == 32);
    }

    /// Public-key parsers take token bytes: they never panic, and a canonical SPKI is a fixed
    /// point.
    #[test]
    fn key_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..160), exponent in proptest::collection::vec(any::<u8>(), 0..8)) {
        if let Ok(spki) = id::spki_canonical(&bytes) {
            prop_assert_eq!(id::spki_canonical(&spki).unwrap(), spki);
        }
        let _ = id::cert_spki(&bytes);
        if let Ok(spki) = id::rsa_spki(&bytes, &exponent) {
            prop_assert_eq!(id::spki_canonical(&spki).unwrap(), spki);
        }
        for curve in [Curve::P256, Curve::P384, Curve::P521, Curve::Secp256k1, Curve::Ed25519, Curve::Ed448] {
            if let Ok(spki) = curve.spki_from_point(&bytes) {
                prop_assert_eq!(id::spki_canonical(&spki).unwrap(), spki);
            }
        }
    }

    /// The loaders never panic on a damaged keys.toml or keys.lock: it loads, or it is refused as
    /// invalid (17).
    #[test]
    fn loaders_refuse_damaged_files_without_panicking(edits in proptest::collection::vec((any::<Index>(), any::<char>()), 1..4)) {
        let damage = |text: &str| {
            let mut chars: Vec<char> = text.chars().collect();
            for (at, c) in &edits {
                let i = at.index(chars.len());
                chars[i] = *c;
            }
            chars.into_iter().collect::<String>()
        };
        let lock = parse_lock(&damage(FIXTURE_LOCK), Path::new("keys.lock"));
        prop_assert!(matches!(exit(&lock), 0 | 17), "{:?}", lock.err());
        let cfg = parse_config_with(&damage(FIXTURE_CONFIG), Path::new("keys.toml"), &|_| Some("/x".into()));
        prop_assert!(matches!(exit(&cfg), 0 | 17), "{:?}", cfg.err());
    }
}

const FIXTURE_LOCK: &str = include_str!("../../cli/tests/fixtures/keys.lock");
const FIXTURE_CONFIG: &str = include_str!("../../cli/tests/fixtures/keys.toml");

/// The fixtures themselves load: the damaged copies start from valid files.
#[test]
fn fixtures_load() {
    parse_lock(FIXTURE_LOCK, Path::new("keys.lock")).unwrap();
    parse_config_with(FIXTURE_CONFIG, Path::new("keys.toml"), &|_| Some("/x".into())).unwrap();
}

/// A `valueLen` whose bit count could overflow the commitment label is refused at load (17),
/// where it would otherwise overflow: over the full `u64` range, `commitment_labels_are_injective`
/// fails with an overflow panic; its range is now what keys.toml accepts.
#[test]
fn an_out_of_range_value_len_is_refused() {
    let text = CONFIG.replace("valueLen = 32", "valueLen = 2305843009213693952");
    let err = parse_config_with(&text, Path::new("keys.toml"), &|_| None).unwrap_err();
    assert_eq!(err.exit_code(), 17, "{err}");
    assert!(err.to_string().contains("valueLen 2305843009213693952 bytes is out of range"), "{err}");
}
