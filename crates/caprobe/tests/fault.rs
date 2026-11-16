//! caprobe against a module that fails or lies (`crates/p11-fault`, `docs/FAULT_SHIM.md`):
//! `SoftHSM` behind the shim, probed with `--write`. The probe records what it met as the
//! module's behaviour, or says what it could not determine; it never guesses.
//!
//! Needs `P11_FAULT_MODULE` naming `SoftHSM`, which the per-test runner (nix/test-tokens.sh)
//! sets; skipped without it.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;

/// A scratch token on the shim, with a P-256 key pair `decoy` no probe made.
fn scratch(name: &str) -> Option<Workdir> {
    let real = suite_var("P11_FAULT_MODULE", "CAKEYS_FAULT_REQUIRE", name)?;
    let w = Workdir::new(name);
    w.write_config(&reference_tokens(&fault_shim(), &w.dir));
    let s = open_session(&real, "kmtest", "1234");
    let label = Attribute::Label(b"decoy".to_vec());
    let p256 = vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[Attribute::Token(true), label.clone(), Attribute::EcParams(p256)],
        &[Attribute::Token(true), label, Attribute::Sign(true), Attribute::Derive(true)],
    )
    .unwrap();
    Some(w)
}

/// `caprobe probe --token ref --write` under `plan`: the profile, the notes, and the rules fired.
fn probed(w: &Workdir, name: &str, plan: &str, more: &[&str]) -> (i32, String, String, usize) {
    let (path, trace) = (w.dir.join(format!("{name}.toml")), w.dir.join(format!("{name}.jsonl")));
    std::fs::write(&path, plan).unwrap();
    let args = [&["probe", "--token", "ref", "--write", "--rsa-max-bits", "4096"][..], more].concat();
    let o = w.km_env(&args, &[("P11_FAULT_PLAN", &path), ("P11_FAULT_TRACE", &trace)]);
    let text = std::fs::read_to_string(&trace).unwrap_or_default();
    (code(&o), stdout(&o), stderr(&o), text.lines().filter(|l| !l.contains("\"rule\":null")).count())
}

/// One fault case: its name, the plan, what the profile then holds, and what the probe says it
/// could not determine.
type Case<'a> = (&'a str, String, &'a [&'a str], &'a str);

/// The calls the first key's proofs of possession make before the probes of its mechanisms (it
/// proves first, as the verbs do right after generating): pop-sign's `C_SignInit`, pop-ecdh's
/// sealed `C_DeriveKey` and the `C_SignInit` of its HMAC.
const SIGN_INITS: u64 = 2;
const DERIVES: u64 = 1;

fn rule(text: &str) -> String {
    format!("[[rule]]\n{text}\n")
}

/// Probe under each case's plan: the probe succeeds, its rule fired, and the profile and the
/// notes hold what the case says.
fn probe_cases(w: &Workdir, cases: &[Case]) {
    for (name, plan, rows, undetermined) in cases {
        let (exit, profile, said, fired) = probed(w, name, plan, &[]);
        assert_eq!(exit, 0, "{name}: {said}");
        assert!(fired > 0, "{name}: the rule never fired");
        for row in *rows {
            assert!(profile.contains(row), "{name}: expected {row:?} in\n{profile}");
        }
        assert!(said.contains(undetermined), "{name}: expected {undetermined:?} in {said}");
    }
}

/// What the write probes record when the module refuses or lies: a row of the profile and a
/// note saying what was seen, or a note of what could not be probed. Never the row a
/// well-behaved module would have earned.
#[test]
fn the_probe_records_what_a_misbehaving_module_does() {
    let Some(w) = scratch("fault-probe") else { return };
    // (the lie, what the profile then holds, what the probe says it could not determine)
    let cases: &[Case] = &[
        (
            // Every try with the usage attributes: the template as asked, then once without each
            // of the probe's own policy defaults (public CKA_PRIVATE, private CKA_SENSITIVE),
            // which a template refusal may be about; the fourth, without usage, is let through.
            "usage refused at generation",
            (1..=3)
                .map(|n| rule(&format!("fn = \"C_GenerateKeyPair\"\ncall = {n}\nrv = \"CKR_TEMPLATE_INCONSISTENT\"")))
                .collect(),
            &[],
            "no operation probes on CKK_EC keys: the module refused the usage attributes",
        ),
        (
            "a public key without its point",
            rule("fn = \"C_GetAttributeValue\"\nattribute = \"CKA_EC_POINT\"\ndrop = true"),
            &[],
            "no operation probes on secp256r1: its public key carries no material",
        ),
        (
            "another key signs",
            rule(&format!("fn = \"C_SignInit\"\ncall = {}\nuse_label = \"decoy\"", SIGN_INITS + 1)),
            &["secp256r1: the signature does not verify"],
            "",
        ),
        (
            "another key derives",
            rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nuse_label = \"decoy\"", DERIVES + 1)),
            &["the derived secret is not the shared secret"],
            "",
        ),
        (
            // Every try of the sealed template `derive_any` makes: as asked, with CKA_VALUE_LEN,
            // and each without one of its two policy defaults (CKA_SENSITIVE, CKA_EXTRACTABLE).
            "a sealed derived secret refused",
            (DERIVES + 1..=DERIVES + 6)
                .map(|n| rule(&format!("fn = \"C_DeriveKey\"\ncall = {n}\nrv = \"CKR_ATTRIBUTE_VALUE_INVALID\"")))
                .collect(),
            &[
                "\"derive.ecdh.sealed\" = { answer = \"no\", evidence = \"a sealed (non-extractable) derived secret is refused",
                "a sealed (non-extractable) derived secret is refused: CKR_ATTRIBUTE_VALUE_INVALID",
            ],
            "",
        ),
        (
            "no derivation at all",
            rule("fn = \"C_DeriveKey\"\nrv = \"CKR_ATTRIBUTE_VALUE_INVALID\""),
            &["extractable: CKR_ATTRIBUTE_VALUE_INVALID"],
            "",
        ),
        (
            "derives while reporting CKA_DERIVE false",
            rule("fn = \"C_GetAttributeValue\"\nattribute = \"CKA_DERIVE\"\nvalue = \"00\""),
            &["derives although the key reports CKA_DERIVE = false"],
            "",
        ),
        (
            "wraps but does not unwrap",
            rule("fn = \"C_UnwrapKey\"\nrv = \"CKR_DEVICE_ERROR\""),
            &[
                "\"wrap.rsa-oaep.SHA-1\" = { answer = \"no\" }\n\"wrap.rsa-oaep.SHA-256\" = { answer = \"no\" }",
                "wraps but does not unwrap: CKR_DEVICE_ERROR",
            ],
            "",
        ),
    ];
    probe_cases(&w, cases);
    // Against the committed profile, such a module drifts (15): the conformance check would
    // not let its profile stand for SoftHSM's.
    let (exit, _, said, _) = probed(&w, "drift", &cases[4].1, &["--diff", SOFTHSM.profile.0]);
    assert_eq!(exit, 15, "{said}");
    assert!(said.contains("derive.ecdh.sealed"), "{said}");
}

/// `derive_any`'s tries, in order, each taken when those before it are refused for their
/// template, and the one that took is the profile's note: `CKA_VALUE_LEN` added; then each
/// policy default dropped from the template as asked; then from the one with `CKA_VALUE_LEN`. A
/// refusal that is not about the template ends the tries, first or later.
#[test]
fn the_probe_notes_which_derive_template_took() {
    let Some(w) = scratch("fault-probe-derive") else { return };
    let cases: &[Case] = &[
        (
            "the sealed template takes with its length",
            rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_TEMPLATE_INCONSISTENT\"", DERIVES + 1)),
            &["the template as asked is refused (CKR_TEMPLATE_INCONSISTENT); derived with CKA_VALUE_LEN = 32 added\""],
            "",
        ),
        (
            "the sealed template takes without CKA_SENSITIVE",
            (DERIVES + 1..=DERIVES + 2)
                .map(|n| rule(&format!("fn = \"C_DeriveKey\"\ncall = {n}\nrv = \"CKR_TEMPLATE_INCONSISTENT\"")))
                .collect(),
            &["(CKR_TEMPLATE_INCONSISTENT); derived with CKA_SENSITIVE = true dropped\""],
            "",
        ),
        (
            "the sealed template takes with its length and without CKA_SENSITIVE",
            (DERIVES + 1..=DERIVES + 4)
                .map(|n| rule(&format!("fn = \"C_DeriveKey\"\ncall = {n}\nrv = \"CKR_TEMPLATE_INCONSISTENT\"")))
                .collect(),
            &["(CKR_TEMPLATE_INCONSISTENT); derived with CKA_VALUE_LEN = 32 added, CKA_SENSITIVE = true dropped\""],
            "",
        ),
        (
            "the sealed derivation fails",
            rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_DEVICE_ERROR\"", DERIVES + 1)),
            &["a sealed (non-extractable) derived secret is refused: CKR_DEVICE_ERROR"],
            "",
        ),
        (
            "the sealed derivation fails after a template refusal",
            rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_TEMPLATE_INCONSISTENT\"", DERIVES + 1))
                + &rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_DEVICE_ERROR\"", DERIVES + 2)),
            &["a sealed (non-extractable) derived secret is refused: CKR_DEVICE_ERROR"],
            "",
        ),
    ];
    probe_cases(&w, cases);
}

/// Objects an interrupted probe left under its own labels are removed by the next one, which
/// says so: they are no row of the profile.
#[test]
fn the_probe_clears_what_an_interrupted_run_left() {
    let Some(w) = scratch("fault-probe-stale") else { return };
    let real = std::env::var("P11_FAULT_MODULE").unwrap();
    let s = open_session(&real, "kmtest", "1234");
    let stale =
        [Attribute::Token(true), Attribute::Label(b"cakeys-probe-stale".to_vec()), Attribute::ValueLen(32.into())];
    s.generate_key(&Mechanism::AesKeyGen, &stale).unwrap();
    drop(s);
    let o = w.km(&["probe", "--token", "ref", "--write", "--rsa-max-bits", "4096"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("destroyed objects an interrupted probe left: cakeys-probe-stale"), "{}", stderr(&o));
    assert_eq!(open_session(&real, "kmtest", "1234").labelled("cakeys-probe-stale").len(), 0);
}
