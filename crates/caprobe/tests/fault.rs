//! caprobe against a module that fails or lies (`crates/p11-fault`, `docs/FAULT_SHIM.md`):
//! `SoftHSM` behind the shim, probed with `--write-probes`. The probe records what it met as the
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
    s.generate_key_pair(
        &Mechanism::EccKeyPairGen,
        &[Attribute::Token(true), label.clone(), Attribute::EcParams(P256.to_vec())],
        &[Attribute::Token(true), label, Attribute::Sign(true), Attribute::Derive(true)],
    )
    .unwrap();
    Some(w)
}

/// `caprobe probe --token ref --write-probes` under `plan`: the profile, the notes, and how many calls
/// each rule decided (the trace's `rule`, from 1), in the plan's order.
fn probed(w: &Workdir, name: &str, plan: &str, more: &[&str]) -> (i32, String, String, Vec<usize>) {
    let (path, trace) = (w.dir.join(format!("{name}.toml")), w.dir.join(format!("{name}.jsonl")));
    std::fs::write(&path, plan).unwrap();
    let _ = std::fs::remove_file(&trace);
    let args = [&["probe", "--token", "ref", "--write-probes", "--rsa-max-bits", "4096"][..], more].concat();
    let o = w.km_env(&args, &[("P11_FAULT_PLAN", &path), ("P11_FAULT_TRACE", &trace)]);
    let mut fired = vec![0; rules(plan).len()];
    for line in std::fs::read_to_string(&trace).unwrap_or_default().lines() {
        let call: serde_json::Value = serde_json::from_str(line).unwrap();
        if let Some(rule) = call["rule"].as_u64() {
            fired[usize::try_from(rule).unwrap() - 1] += 1;
        }
    }
    (code(&o), stdout(&o), stderr(&o), fired)
}

/// The plan's rules.
fn rules(plan: &str) -> Vec<toml::Value> {
    let plan: toml::Value = toml::from_str(plan).unwrap();
    plan.get("rule").and_then(toml::Value::as_array).cloned().unwrap_or_default()
}

/// Each rule fired as often as it says: a rule numbered by `call` decides that one call, once
/// (review fault.rs F2: any firing passed, so a numbered rule could land on another step, or
/// a plan's second rule never fire); one without `call` decides every call it matches, at least
/// one.
fn assert_fired(name: &str, plan: &str, fired: &[usize], said: &str) {
    for (i, (rule, n)) in rules(plan).iter().zip(fired).enumerate() {
        if rule.get("call").is_some() {
            assert_eq!(*n, 1, "{name}: rule {} fired {n} times: {said}", i + 1);
        } else {
            assert!(*n > 0, "{name}: rule {} never fired: {said}", i + 1);
        }
    }
}

/// One fault case: its name, the plan, what the profile then holds, what the probe says it
/// could not determine, and the rows of the committed `SoftHSM` profile (what the honest module
/// earns) the profile must then not hold.
type Case<'a> = (&'a str, String, &'a [&'a str], &'a str, &'a [&'a str]);

/// The rows the honest module earns that a case takes away.
const POP_SIGN: &str = "\"prove.pop-sign.CKK_EC.secp256r1\" = { answer = \"yes\" }";
const POP_ECDH: &str = "\"prove.pop-ecdh.CKK_EC.secp256r1\" = { answer = \"yes\" }";
const SEALED: &str = "\"derive.ecdh.sealed\" = { answer = \"yes\" }";
const READ_ONLY: &str = "\"derive.ecdh.read-only\" = { answer = \"yes\" }";
const OAEP_SHA1: &str = "\"wrap.rsa-oaep.SHA-1\" = { answer = \"yes\" }";

/// The calls the first key's proofs of possession make before the probes of its mechanisms (it
/// proves first, as the verbs do right after generating): pop-sign's `C_SignInit`, pop-ecdh's
/// sealed `C_DeriveKey` and the `C_SignInit` of its HMAC.
const SIGN_INITS: u64 = 2;
const DERIVES: u64 = 1;

fn rule(text: &str) -> String {
    format!("[[rule]]\n{text}\n")
}

/// Probe under each case's plan: the probe succeeds, its rule fired, the profile and the notes
/// hold what the case says, and the profile holds none of the rows the honest module would have
/// earned (review fault.rs F1: only presence was checked, so a probe that noted the lie and
/// still wrote the row passed). Each of those is a row of the committed profile, so the check
/// cannot pass on a row no probe writes.
fn probe_cases(w: &Workdir, cases: &[Case]) {
    let honest = std::fs::read_to_string(committed_profile(SOFTHSM.profile.1)).unwrap();
    // The decoy pairs no probe made (one per `scratch`, on the one reference token).
    let real = std::env::var("P11_FAULT_MODULE").unwrap();
    let decoys = || open_session(&real, "kmtest", "1234").labelled("decoy").len();
    let planted = decoys();
    assert!(planted >= 2, "no decoy pair planted");
    for (name, plan, rows, undetermined, earned) in cases {
        let (exit, profile, said, fired) = probed(w, name, plan, &[]);
        assert_eq!(exit, 0, "{name}: {said}");
        assert_fired(name, plan, &fired, &said);
        for row in *rows {
            assert!(profile.contains(row), "{name}: expected {row:?} in\n{profile}");
        }
        assert!(said.contains(undetermined), "{name}: expected {undetermined:?} in {said}");
        for row in *earned {
            assert!(honest.contains(row), "{name}: {row:?} is no row of the committed profile");
            assert!(!profile.contains(row), "{name}: the honest module's {row:?} in\n{profile}");
        }
        // Whatever the lie made the probe do, the pairs no probe made are left alone: no cleanup,
        // stale sweep or rollback reaches an object it did not make (review 2026-11-23 D-19).
        assert_eq!(decoys(), planted, "{name}: a decoy was touched");
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
            &[POP_SIGN, POP_ECDH],
        ),
        (
            "a public key without its point",
            rule("fn = \"C_GetAttributeValue\"\nattribute = \"CKA_EC_POINT\"\ndrop = true"),
            &[],
            "no operation probes on secp256r1: its public key carries no material",
            &[POP_SIGN, POP_ECDH],
        ),
        (
            // An operation probe has no row of its own: the mechanism is usable for the keys it
            // verified on, and the failure is its note (`Ops::record` puts each outcome in one
            // place). The proofs, before it, are the honest module's.
            "another key signs",
            rule(&format!("fn = \"C_SignInit\"\ncall = {}\nuse_label = \"decoy\"", SIGN_INITS + 1)),
            &["secp256r1: the signature does not verify", POP_SIGN],
            "",
            &[],
        ),
        (
            "another key derives",
            rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nuse_label = \"decoy\"", DERIVES + 1)),
            &["the derived secret is not the shared secret"],
            "",
            &[SEALED],
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
            &[SEALED],
        ),
        (
            "no derivation at all",
            rule("fn = \"C_DeriveKey\"\nrv = \"CKR_ATTRIBUTE_VALUE_INVALID\""),
            &["extractable: CKR_ATTRIBUTE_VALUE_INVALID"],
            "",
            &[SEALED, READ_ONLY, POP_ECDH],
        ),
        (
            // The key derives, as the honest module's does: its rows stand, the lie is a note.
            "derives while reporting CKA_DERIVE false",
            rule("fn = \"C_GetAttributeValue\"\nattribute = \"CKA_DERIVE\"\nvalue = \"00\""),
            &["derives although the key reports CKA_DERIVE = false"],
            "",
            &[],
        ),
        // A session an earlier operation left busy decides nothing, by the return value the
        // module gave (KmError::rv), not by the words of a message: an operation probe, then
        // the first key's proof of possession.
        (
            "an operation meets a busy session",
            rule(&format!("fn = \"C_SignInit\"\ncall = {}\nrv = \"CKR_OPERATION_ACTIVE\"", SIGN_INITS + 1)),
            &[],
            "an earlier operation left the session busy (CKR_OPERATION_ACTIVE)",
            &[],
        ),
        (
            "a proof meets a busy session",
            rule("fn = \"C_SignInit\"\ncall = 1\nrv = \"CKR_OPERATION_ACTIVE\""),
            &[],
            "no prove.pop-sign.CKK_EC.secp256r1 row",
            &[POP_SIGN],
        ),
        (
            "wraps but does not unwrap",
            rule("fn = \"C_UnwrapKey\"\nrv = \"CKR_DEVICE_ERROR\""),
            &[
                "\"wrap.rsa-oaep.SHA-1\" = { answer = \"no\" }\n\"wrap.rsa-oaep.SHA-256\" = { answer = \"no\" }",
                "wraps but does not unwrap: CKR_DEVICE_ERROR",
            ],
            "",
            &[OAEP_SHA1],
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
            &[],
        ),
        (
            "the sealed template takes without CKA_SENSITIVE",
            (DERIVES + 1..=DERIVES + 2)
                .map(|n| rule(&format!("fn = \"C_DeriveKey\"\ncall = {n}\nrv = \"CKR_TEMPLATE_INCONSISTENT\"")))
                .collect(),
            &["(CKR_TEMPLATE_INCONSISTENT); derived with CKA_SENSITIVE = true dropped\""],
            "",
            &[],
        ),
        (
            "the sealed template takes with its length and without CKA_SENSITIVE",
            (DERIVES + 1..=DERIVES + 4)
                .map(|n| rule(&format!("fn = \"C_DeriveKey\"\ncall = {n}\nrv = \"CKR_TEMPLATE_INCONSISTENT\"")))
                .collect(),
            &["(CKR_TEMPLATE_INCONSISTENT); derived with CKA_VALUE_LEN = 32 added, CKA_SENSITIVE = true dropped\""],
            "",
            &[],
        ),
        (
            "the sealed derivation fails",
            rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_DEVICE_ERROR\"", DERIVES + 1)),
            &["a sealed (non-extractable) derived secret is refused: CKR_DEVICE_ERROR"],
            "",
            &[SEALED],
        ),
        (
            "the sealed derivation fails after a template refusal",
            rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_TEMPLATE_INCONSISTENT\"", DERIVES + 1))
                + &rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_DEVICE_ERROR\"", DERIVES + 2)),
            &["a sealed (non-extractable) derived secret is refused: CKR_DEVICE_ERROR"],
            "",
            &[SEALED],
        ),
    ];
    probe_cases(&w, cases);
}

/// An OAEP hash counts only when a blob the host made with it unwraps to the host's key: a
/// module whose own wrap round trip works but which decodes no peer's blob (here the shim swaps
/// another RSA key in for the host-made blob's unwrap) gets no `wrap.rsa-oaep` yes for that hash
/// (review 2026-11-23 D-3: its own round trip was enough). The call is found in a clean run's
/// trace: the second of two OAEP SHA-1 unwraps with no wrap between them.
#[test]
fn an_oaep_hash_counts_only_when_a_host_made_blob_decodes() {
    let Some(w) = scratch("fault-probe-host-blob") else { return };
    let real = std::env::var("P11_FAULT_MODULE").unwrap();
    let label = Attribute::Label(b"decoy-rsa".to_vec());
    open_session(&real, "kmtest", "1234")
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &[
                Attribute::Token(true),
                label.clone(),
                Attribute::ModulusBits(2048.into()),
                Attribute::PublicExponent(vec![1, 0, 1]),
                Attribute::Wrap(true),
            ],
            &[Attribute::Token(true), label, Attribute::Unwrap(true), Attribute::Decrypt(true)],
        )
        .unwrap();
    let (exit, profile, said, _) = probed(&w, "clean", "", &[]);
    assert_eq!(exit, 0, "{said}");
    assert!(profile.contains(OAEP_SHA1), "the honest module's row: {profile}");
    let trace = std::fs::read_to_string(w.dir.join("clean.jsonl")).unwrap();
    let calls: Vec<serde_json::Value> = trace.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let wraps: Vec<&serde_json::Value> =
        calls.iter().filter(|c| c["fn"] == "C_WrapKey" || c["fn"] == "C_UnwrapKey").collect();
    // CKM_RSA_PKCS_OAEP (9) with CKM_SHA_1 (0x220).
    let sha1_unwrap = |c: &serde_json::Value| c["fn"] == "C_UnwrapKey" && c["mechanism"] == 9 && c["hash"] == 0x220;
    let host = wraps.windows(2).find(|p| sha1_unwrap(p[0]) && sha1_unwrap(p[1])).map(|p| p[1]);
    let host = host.unwrap_or_else(|| panic!("no host-made blob's unwrap in the trace: {wraps:?}"));
    let plan = rule(&format!("fn = \"C_UnwrapKey\"\ncall = {}\nuse_label = \"decoy-rsa\"", host["n"]));
    let (exit, profile, said, fired) = probed(&w, "blob", &plan, &[]);
    assert_eq!(exit, 0, "{said}");
    assert_fired("blob", &plan, &fired, &said);
    assert!(profile.contains("\"wrap.rsa-oaep.SHA-1\" = { answer = \"no\" }"), "{profile}");
    assert!(profile.contains("unwraps its own blob but not one the host made"), "{profile}");
}

/// `CKA_ALLOWED_MECHANISMS` is "enforced" only when the key encrypts by what its list allows
/// and the module then refuses CBC, outside it: when the in-list ECB call fails too, the CBC
/// refusal tells nothing, and the row says nothing of enforcement (review 2026-11-23 D-5: any
/// CBC failure was "enforced"). The call is the clean run's ECB `C_EncryptInit` just before
/// the CBC one.
#[test]
fn allowed_mechanisms_are_enforced_only_beside_a_working_control() {
    let Some(w) = scratch("fault-probe-allowed") else { return };
    let (exit, profile, said, _) = probed(&w, "clean", "", &[]);
    assert_eq!(exit, 0, "{said}");
    let enforced = "\"attr.set.CKA_ALLOWED_MECHANISMS.CKK_AES\" = { answer = \"yes\", via = \"enforced\" }";
    assert!(profile.contains(enforced), "the honest module's row: {profile}");
    let trace = std::fs::read_to_string(w.dir.join("clean.jsonl")).unwrap();
    let calls: Vec<serde_json::Value> = trace.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let inits: Vec<&serde_json::Value> = calls.iter().filter(|c| c["fn"] == "C_EncryptInit").collect();
    // CKM_AES_ECB (0x1081), then CKM_AES_CBC (0x1082) refused: the list kept to, not a mode probe.
    let pair = |p: &&[&serde_json::Value]| {
        p[0]["mechanism"] == 0x1081 && p[1]["mechanism"] == 0x1082 && p[1]["rv"] != "CKR_OK"
    };
    let ecb = inits.windows(2).find(pair).map(|p| p[0]);
    let ecb = ecb.unwrap_or_else(|| panic!("no ECB then refused CBC C_EncryptInit in the trace"));
    let plan = rule(&format!("fn = \"C_EncryptInit\"\ncall = {}\nrv = \"CKR_KEY_FUNCTION_NOT_PERMITTED\"", ecb["n"]));
    let (exit, profile, said, fired) = probed(&w, "control", &plan, &[]);
    assert_eq!(exit, 0, "{said}");
    assert_fired("control", &plan, &fired, &said);
    assert!(profile.contains("\"attr.set.CKA_ALLOWED_MECHANISMS.CKK_AES\" = { answer = \"yes\" }"), "{profile}");
    assert!(said.contains("whether it is enforced is not told"), "{said}");
}

/// A pair the module made but the probe cannot find under its locator (probe.rs F3) is no
/// refusal: no `cannot` row, no "generation refused" evidence, and a note saying what was seen.
/// The first probe pair is hidden from every search.
#[test]
fn a_pair_made_but_not_found_is_no_refusal() {
    let Some(w) = scratch("fault-probe-lost") else { return };
    let plan = rule("fn = \"C_FindObjects\"\nhide_label = \"cakeys-probe-01\"");
    let (exit, profile, said, fired) = probed(&w, "lost", &plan, &[]);
    assert_eq!(exit, 0, "{said}");
    assert_fired("lost", &plan, &fired, &said);
    assert!(said.contains("no generate row for CKK_EC on secp256r1: the module generated, but"), "{said}");
    assert!(!profile.contains("not under its locator"), "a refusal row for a pair the module made:\n{profile}");
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
    let o = w.km(&["probe", "--token", "ref", "--write-probes", "--rsa-max-bits", "4096"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(stderr(&o).contains("destroyed objects an interrupted probe left: cakeys-probe-stale"), "{}", stderr(&o));
    assert_eq!(open_session(&real, "kmtest", "1234").labelled("cakeys-probe-stale").len(), 0);
}

/// A probe that an error ends still destroys what it made (review D7): the first lookup after the
/// third generation fails with `CKR_DEVICE_ERROR`, which ends the run, and nothing under a probe
/// label is left. Before, every key made so far stayed for the next run's stale check.
#[test]
fn a_probe_an_error_ends_destroys_what_it_made() {
    let Some(w) = scratch("fault-probe-ends") else { return };
    let (exit, _, said, _) = probed(&w, "clean", "", &[]);
    assert_eq!(exit, 0, "{said}");
    let trace = std::fs::read_to_string(w.dir.join("clean.jsonl")).unwrap();
    let calls: Vec<serde_json::Value> = trace.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let seq = |c: &serde_json::Value| c["seq"].as_u64().unwrap();
    let third = calls.iter().filter(|c| c["fn"] == "C_GenerateKeyPair").nth(2).map(seq).unwrap();
    let after = calls.iter().find(|c| c["fn"] == "C_FindObjects" && seq(c) > third).unwrap();
    let plan = rule(&format!("fn = \"C_FindObjects\"\ncall = {}\nrv = \"CKR_DEVICE_ERROR\"", after["n"]));
    let (exit, _, said, fired) = probed(&w, "ends", &plan, &[]);
    assert_ne!(exit, 0, "{said}");
    assert_fired("ends", &plan, &fired, &said);
    let real = std::env::var("P11_FAULT_MODULE").unwrap();
    let s = open_session(&real, "kmtest", "1234");
    let left: Vec<String> =
        (1..=99).map(|n| format!("cakeys-probe-{n:02}")).filter(|l| !s.labelled(l).is_empty()).collect();
    assert!(left.is_empty(), "left on the token: {left:?}\n{said}");
}
