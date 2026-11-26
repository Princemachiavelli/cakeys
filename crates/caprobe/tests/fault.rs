//! Tests of caprobe against a module that fails or returns false answers (`crates/p11-fault`,
//! `docs/FAULT_SHIM.md`): `SoftHSM` behind the shim, probed with `--write-probes`. The probe
//! records what it saw as the module's behavior, or says what it could not determine. It never
//! guesses.
//!
//! The tests need `P11_FAULT_MODULE` to name `SoftHSM`. The per-test runner (nix/test-tokens.sh)
//! sets it, and the tests are skipped without it.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::Attribute;

/// Creates a scratch token on the shim, with a P-256 key pair labeled `decoy` that no probe
/// made.
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

/// Runs `caprobe probe --token ref --write-probes` under `plan`. Returns the exit code, the
/// profile, the notes, and the number of calls that each rule decided (from the trace's `rule`
/// field, which counts from 1), in the order of the plan's rules.
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

/// Returns the plan's rules.
fn rules(plan: &str) -> Vec<toml::Value> {
    let plan: toml::Value = toml::from_str(plan).unwrap();
    plan.get("rule").and_then(toml::Value::as_array).cloned().unwrap_or_default()
}

/// Checks that each rule fired as often as it should. A rule with a `call` number decides
/// exactly that one call, once. A rule without `call` decides every call that it matches, and
/// must decide at least one. (Review fault.rs F2: before this check, any firing passed, so a
/// numbered rule could hit another step, or a plan's second rule could never fire.)
fn assert_fired(name: &str, plan: &str, fired: &[usize], said: &str) {
    for (i, (rule, n)) in rules(plan).iter().zip(fired).enumerate() {
        if rule.get("call").is_some() {
            assert_eq!(*n, 1, "{name}: rule {} fired {n} times: {said}", i + 1);
        } else {
            assert!(*n > 0, "{name}: rule {} never fired: {said}", i + 1);
        }
    }
}

/// One fault case: its name, the plan, what the profile then holds, what the probe says that it
/// could not determine, and the rows of the committed `SoftHSM` profile that the profile must
/// then not hold. The committed rows are what `SoftHSM` earns without a fault.
type Case<'a> = (&'a str, String, &'a [&'a str], &'a str, &'a [&'a str]);

/// The rows that `SoftHSM` earns without a fault and that a case takes away.
const POP_SIGN: &str = "\"prove.pop-sign.CKK_EC.secp256r1\" = { answer = \"yes\", by = \"host\" }";
const POP_ECDH: &str = "\"prove.pop-ecdh.CKK_EC.secp256r1\" = { answer = \"yes\", by = \"host\" }";
const SEALED: &str = "\"derive.ecdh.sealed\" = { answer = \"yes\", by = \"host\" }";
const READ_ONLY: &str = "\"derive.ecdh.read-only\" = { answer = \"yes\", by = \"host\" }";
const OAEP_SHA1: &str = "\"wrap.rsa-oaep.SHA-1\" = { answer = \"yes\", by = \"host\" }";

/// The calls that the first key's proofs of possession make before the probes of its mechanisms.
/// The probe proves possession first, as the verbs do right after they generate a key. The two
/// `C_SignInit` calls are the one of pop-sign and the one of pop-ecdh's HMAC, and the one
/// `C_DeriveKey` call (`DERIVES`) is the sealed derivation of pop-ecdh.
const SIGN_INITS: u64 = 2;
const DERIVES: u64 = 1;

fn rule(text: &str) -> String {
    format!("[[rule]]\n{text}\n")
}

/// Probes under each case's plan and checks the result. The probe succeeds, its rules fired, the
/// profile and the notes hold what the case says, and the profile holds none of the rows that
/// `SoftHSM` would have earned without the fault. (Review fault.rs F1: only the presence of
/// rows was checked, so a probe that noted the fault and still wrote the row passed.) Each of
/// those rows is a row of the committed profile, so the check cannot pass on a row that no probe
/// writes.
fn probe_cases(w: &Workdir, cases: &[Case]) {
    let honest = std::fs::read_to_string(committed_profile(SOFTHSM.profile.1)).unwrap();
    // Counts the decoy pairs that no probe made (one for each `scratch` call, all on the one
    // reference token).
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
        // The profile that the probe wrote must load. This means that no row's `by` contradicts
        // its answer, that no `no` row by the module cites a device failure, and that an
        // undecided capability has no row (E-2).
        let loaded = cakeys_profile::Profile::from_toml(&profile).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(loaded.untested_problems(), Vec::<String>::new(), "{name}");
        for row in *earned {
            assert!(honest.contains(row), "{name}: {row:?} is no row of the committed profile");
            assert!(!profile.contains(row), "{name}: the honest module's {row:?} in\n{profile}");
        }
        // Whatever the fault made the probe do, the pairs that no probe made are untouched. No
        // cleanup, stale sweep or rollback reaches an object that the probe did not make (review
        // 2026-11-23 D-19).
        assert_eq!(decoys(), planted, "{name}: a decoy was touched");
    }
}

/// Checks what the write probes record when the module refuses or gives a false answer: a row
/// of the profile and a note that says what was seen, or a note that says what could not be
/// probed. The probe never writes the row that a correctly behaving module would have earned.
#[test]
fn the_probe_records_what_a_misbehaving_module_does() {
    let Some(w) = scratch("fault-probe") else { return };
    // Each case is (the fault, what the profile then holds, what the probe says that it could
    // not determine, the committed rows that it must not hold).
    let cases: &[Case] = &[
        (
            // The plan refuses every try with the usage attributes: the template as asked, and
            // then the template without each of the probe's own policy defaults (CKA_PRIVATE on
            // the public key, CKA_SENSITIVE on the private key), which a template refusal may be
            // about. The fourth try, without the usage attributes, is let through.
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
            // An operation probe has no row of its own. The mechanism is usable for the keys on
            // which it verified, and the failure becomes its note (`Ops::record` puts each
            // outcome in one place). The proofs of possession run before the fault, so they keep
            // the rows that SoftHSM earns without a fault.
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
            // The plan refuses every try of the sealed template that `derive_any` makes: the
            // template as asked, the template with CKA_VALUE_LEN, and each of those without one
            // of its two policy defaults (CKA_SENSITIVE, CKA_EXTRACTABLE).
            "a sealed derived secret refused",
            (DERIVES + 1..=DERIVES + 6)
                .map(|n| rule(&format!("fn = \"C_DeriveKey\"\ncall = {n}\nrv = \"CKR_ATTRIBUTE_VALUE_INVALID\"")))
                .collect(),
            &[
                "\"derive.ecdh.sealed\" = { answer = \"no\", by = \"module\", evidence = \"a sealed (non-extractable) derived secret is refused",
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
            // The key derives, as it does without the fault, so its rows stay, and the false
            // CKA_DERIVE value becomes a note.
            "derives while reporting CKA_DERIVE false",
            rule("fn = \"C_GetAttributeValue\"\nattribute = \"CKA_DERIVE\"\nvalue = \"00\""),
            &["derives although the key reports CKA_DERIVE = false"],
            "",
            &[],
        ),
        // A session that an earlier operation left busy decides nothing. The probe recognizes
        // this by the return value that the module gave (KmError::rv), not by the words of a
        // message. The two cases are an operation probe and the first key's proof of
        // possession.
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
        // A device failure is not an answer from the module, so it produces no `no` row, but an
        // `[untested]` entry that names it (review 2026-11-24 E-2: this case used to assert the
        // two `no` rows).
        (
            "wraps but does not unwrap",
            rule("fn = \"C_UnwrapKey\"\nrv = \"CKR_DEVICE_ERROR\""),
            &[
                "\"wrap.rsa-oaep.SHA-1\" = { why = \"device\", note = \"wraps but does not unwrap: CKR_DEVICE_ERROR\" }",
                // SoftHSM itself refuses the SHA-256 wrap before any unwrap, so that row is still
                // the module's no.
                "\"wrap.rsa-oaep.SHA-256\" = { answer = \"no\", by = \"module\", evidence = \"wrapping fails: CKR_ARGUMENTS_BAD\" }",
            ],
            "no wrap.rsa-oaep.SHA-1 row: wraps but does not unwrap: CKR_DEVICE_ERROR (the device failed",
            &[OAEP_SHA1],
        ),
        (
            "a module refusal of the unwrap is its no",
            rule("fn = \"C_UnwrapKey\"\nrv = \"CKR_MECHANISM_PARAM_INVALID\""),
            &[
                "\"wrap.rsa-oaep.SHA-1\" = { answer = \"no\", by = \"module\", evidence = \"wraps but does not unwrap: CKR_MECHANISM_PARAM_INVALID\" }",
            ],
            "",
            &[OAEP_SHA1],
        ),
    ];
    probe_cases(&w, cases);
    // Compared with the committed profile, such a module drifts (exit code 15), so the
    // conformance check would not accept its profile as SoftHSM's.
    let (exit, _, said, _) = probed(&w, "drift", &cases[4].1, &["--diff", SOFTHSM.profile.0]);
    assert_eq!(exit, 15, "{said}");
    assert!(said.contains("derive.ecdh.sealed"), "{said}");
}

/// Makes every call of one function fail with a device failure, for each function from which
/// the probe's answers come, one function at a time. No row that the probe writes is a no on a
/// device failure (review 2026-11-24 E-2, phase1-design §2.3). The profile that the probe writes
/// loads, which it would not if a `no` row by the module cited a device failure. No `no` row of
/// any provenance cites one, and the steps that the device failed are `[untested]` entries with
/// the reason `device`.
#[test]
fn a_device_failure_is_never_a_no() {
    use cakeys_profile::{Answer, Why, names_device_failure};
    let Some(w) = scratch("fault-device-sweep") else { return };
    let functions = [
        "C_GenerateKey",
        "C_GenerateKeyPair",
        "C_CreateObject",
        "C_WrapKey",
        "C_UnwrapKey",
        "C_DeriveKey",
        "C_SignInit",
    ];
    for f in functions {
        let plan = rule(&format!("fn = \"{f}\"\nrv = \"CKR_DEVICE_ERROR\""));
        let (exit, profile, said, fired) = probed(&w, f, &plan, &[]);
        assert_fired(f, &plan, &fired, &said);
        assert_eq!(exit, 0, "{f}: {said}");
        let loaded = cakeys_profile::Profile::from_toml(&profile).unwrap_or_else(|e| panic!("{f}: {e}"));
        let cited: Vec<String> = loaded
            .capabilities
            .iter()
            .filter(|(_, r)| r.answer == Answer::No && r.evidence.as_deref().and_then(names_device_failure).is_some())
            .map(|(c, _)| c.to_string())
            .collect();
        assert_eq!(cited, Vec::<String>::new(), "{f}: a no on a device failure");
        assert!(loaded.untested.values().any(|u| u.why == Why::Device), "{f}: no step left undecided");
    }
}

/// Checks the tries of `derive_any`, in order. Each try is made when the tries before it are
/// refused for their template, and the profile's note names the try that worked. The tries
/// add `CKA_VALUE_LEN`, then drop each policy default from the template as asked, and then drop
/// each policy default from the template with `CKA_VALUE_LEN`. A refusal that is not about the
/// template ends the tries, whether it comes first or later.
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
        // A device failure of the sealed derivation does not produce `derive.ecdh.sealed = no`
        // (E-2).
        (
            "the sealed derivation fails",
            rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_DEVICE_ERROR\"", DERIVES + 1)),
            &[
                "\"derive.ecdh.sealed\" = { why = \"device\", note = \"a sealed (non-extractable) derived secret is refused: CKR_DEVICE_ERROR\" }",
            ],
            "",
            &[SEALED],
        ),
        (
            "the sealed derivation fails after a template refusal",
            rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_TEMPLATE_INCONSISTENT\"", DERIVES + 1))
                + &rule(&format!("fn = \"C_DeriveKey\"\ncall = {}\nrv = \"CKR_DEVICE_ERROR\"", DERIVES + 2)),
            &[
                "\"derive.ecdh.sealed\" = { why = \"device\", note = \"a sealed (non-extractable) derived secret is refused: CKR_DEVICE_ERROR\" }",
            ],
            "",
            &[SEALED],
        ),
    ];
    probe_cases(&w, cases);
}

/// An OAEP hash counts only when a blob that the host made with that hash unwraps to the host's
/// key. A module whose own wrap round trip works, but which decodes no blob from another party,
/// gets no `wrap.rsa-oaep` yes for that hash. In this test, the shim puts another RSA key in
/// place of the unwrapping key for the unwrap of the host-made blob. (Review 2026-11-23 D-3:
/// the module's own round trip used to be enough.) The test finds the call in the trace of a
/// clean run: it is the OAEP SHA-1 unwrap that follows the wrap and the round-trip unwrap of the
/// same hash (a wrap, the round trip's unwrap, and then the unwrap of the host's blob). Earlier
/// SHA-1 unwraps by other probes have no wrap before them, so they do not match.
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
    let sha1_wrap = |c: &serde_json::Value| c["fn"] == "C_WrapKey" && c["mechanism"] == 9 && c["hash"] == 0x220;
    let host = wraps.windows(3).find(|w| sha1_wrap(w[0]) && sha1_unwrap(w[1]) && sha1_unwrap(w[2])).map(|w| w[2]);
    let host = host.unwrap_or_else(|| panic!("no host-made blob's unwrap in the trace: {wraps:?}"));
    let plan = rule(&format!("fn = \"C_UnwrapKey\"\ncall = {}\nuse_label = \"decoy-rsa\"", host["n"]));
    let (exit, profile, said, fired) = probed(&w, "blob", &plan, &[]);
    assert_eq!(exit, 0, "{said}");
    assert_fired("blob", &plan, &fired, &said);
    let unwraps: String =
        std::fs::read_to_string(w.dir.join("blob.jsonl")).unwrap().lines().collect::<Vec<_>>().join("\n");
    // The row is not a yes. It is the module's no, or no row at all when the return value is a
    // device failure.
    assert!(
        !profile.contains(OAEP_SHA1),
        "{plan}\nfired {fired:?}\nunwraps in the blob run:\n{unwraps}\n{said}\n{profile}"
    );
    assert!(profile.contains("unwraps its own blob but not one the host made"), "{profile}");
}

/// `CKA_ALLOWED_MECHANISMS` is "enforced" only when the key encrypts with a mechanism that its
/// list allows and the module then refuses CBC, which is outside the list. When the ECB call,
/// which is in the list, also fails, the CBC refusal shows nothing, and the row says nothing
/// about enforcement (review 2026-11-23 D-5: any CBC failure used to count as "enforced"). The
/// plan fails the clean run's ECB `C_EncryptInit` that comes just before the CBC one.
#[test]
fn allowed_mechanisms_are_enforced_only_beside_a_working_control() {
    let Some(w) = scratch("fault-probe-allowed") else { return };
    let (exit, profile, said, _) = probed(&w, "clean", "", &[]);
    assert_eq!(exit, 0, "{said}");
    let enforced =
        "\"attr.set.CKA_ALLOWED_MECHANISMS.CKK_AES\" = { answer = \"yes\", by = \"host\", via = \"enforced\" }";
    assert!(profile.contains(enforced), "the honest module's row: {profile}");
    let trace = std::fs::read_to_string(w.dir.join("clean.jsonl")).unwrap();
    let calls: Vec<serde_json::Value> = trace.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let inits: Vec<&serde_json::Value> = calls.iter().filter(|c| c["fn"] == "C_EncryptInit").collect();
    // CKM_AES_ECB (0x1081) followed by a refused CKM_AES_CBC (0x1082) is the allowed-mechanisms
    // check, not a mode probe.
    let pair = |p: &&[&serde_json::Value]| {
        p[0]["mechanism"] == 0x1081 && p[1]["mechanism"] == 0x1082 && p[1]["rv"] != "CKR_OK"
    };
    let ecb = inits.windows(2).find(pair).map(|p| p[0]);
    let ecb = ecb.unwrap_or_else(|| panic!("no ECB then refused CBC C_EncryptInit in the trace"));
    let plan = rule(&format!("fn = \"C_EncryptInit\"\ncall = {}\nrv = \"CKR_KEY_FUNCTION_NOT_PERMITTED\"", ecb["n"]));
    let (exit, profile, said, fired) = probed(&w, "control", &plan, &[]);
    assert_eq!(exit, 0, "{said}");
    assert_fired("control", &plan, &fired, &said);
    // The attribute is accepted, but its enforcement is not determined, so the yes rests on the
    // module's answer alone (review 2026-11-24 E-4).
    assert!(
        profile.contains("\"attr.set.CKA_ALLOWED_MECHANISMS.CKK_AES\" = { answer = \"yes\", by = \"unverified\" }"),
        "{profile}"
    );
    assert!(said.contains("whether it is enforced is not told"), "{said}");
}

/// A key pair that the module made but that the probe cannot find under its locator (probe.rs
/// F3) is not a refusal: there is no `cannot` row and no "generation refused" evidence, and a
/// note says what was seen. The plan hides the first probe pair from every search.
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

/// The next probe removes the objects that an interrupted probe left under its own labels, and
/// says so in a note. The removal is not a row of the profile.
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

/// A probe that an error ends still destroys what it made (review D7). The first lookup after the
/// third key-pair generation fails with `CKR_DEVICE_ERROR`, which ends the run, and nothing is
/// left under a probe label. Before the fix, every key made so far stayed for the next run's
/// stale check.
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

/// Checks that a probe run on a scratch slot writes the slot's mark certificate as its last write
/// (CAPROBE.md, "SO-only modules"; review 2026-11-24 E-6). The token is `SoftHSM` behind the fault
/// shim, configured with `provider = "ykcs11"`, as the scratch guard test in the reference suite
/// configures it. `SoftHSM`'s Security Officer cannot create keys, so the only write that the
/// module accepts in such a run is the mark certificate.
///
/// The first part runs the probe twice on slot 05 with no fault. In the first run, the last call
/// that writes to the token, whether the module accepts it or not, must be the `C_CreateObject`
/// of the mark certificate, and the second run must exit 0 because the slot holds its mark. The
/// second part runs the probe on slot 06 with a plan that fails the mark's `C_CreateObject` with
/// `CKR_DEVICE_ERROR`. That run leaves the slot without a mark. The next run on slot 06 must
/// exit 17 before it writes anything, and the objects in the slot must stay the same.
#[test]
fn a_slot_run_writes_its_mark_last() {
    let name = "fault-probe-mark";
    let Some(real) = suite_var("P11_FAULT_MODULE", "CAKEYS_FAULT_REQUIRE", name) else { return };
    let w = Workdir::new(name);
    std::fs::write(w.dir.join("so-pin"), "5678\n").unwrap();
    let slot = |token: &str, id: &str| {
        format!(
            "[tokens.{token}]\nmodule = \"{}\"\ntokenLabel = \"kmtest\"\nprovider = \"ykcs11\"\npinFile = \"{}\"\n\
             soCredentialFile = \"{}\"\nprobe = {{ scratchId = \"{id}\" }}\n\n",
            fault_shim(),
            w.dir.join("pin").display(),
            w.dir.join("so-pin").display(),
        )
    };
    w.write_config(&[slot("clean", "05"), slot("cut", "06")].concat());
    // This closure runs the write probes on `token` under the fault plan `plan`. It returns the
    // exit code, the standard error, and the calls that the shim recorded in its trace.
    let run = |token: &str, plan: &str| {
        let (path, trace) = (w.dir.join(format!("{token}.toml")), w.dir.join(format!("{token}.jsonl")));
        std::fs::write(&path, plan).unwrap();
        let _ = std::fs::remove_file(&trace);
        let args = ["probe", "--token", token, "--write-probes", "--rsa-max-bits", "2048"];
        let o = w.km_env(&args, &[("P11_FAULT_PLAN", &path), ("P11_FAULT_TRACE", &trace)]);
        let text = std::fs::read_to_string(&trace).unwrap_or_default();
        let calls: Vec<serde_json::Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        (code(&o), stderr(&o), calls)
    };
    let writes = [
        "C_CreateObject",
        "C_CopyObject",
        "C_GenerateKey",
        "C_GenerateKeyPair",
        "C_UnwrapKey",
        "C_DeriveKey",
        "C_DestroyObject",
        "C_SetAttributeValue",
    ];
    // The shim records the CKA_CLASS values of a template as numbers, and CKO_CERTIFICATE is 1.
    let certificate = |c: &&serde_json::Value| c["fn"] == "C_CreateObject" && c["class"] == serde_json::json!([1]);
    let (exit, said, calls) = run("clean", "");
    assert_eq!(exit, 0, "The first probe run on slot 05 failed: {said}");
    let written: Vec<&serde_json::Value> = calls.iter().filter(|c| writes.iter().any(|f| c["fn"] == *f)).collect();
    assert!(
        written.last().is_some_and(certificate),
        "The last write call of the run on slot 05 is not the C_CreateObject of the mark certificate: {:?}",
        written.last()
    );
    let (exit, said, _) = run("clean", "");
    assert_eq!(exit, 0, "The second probe run on slot 05 refused the slot that the first run marked: {said}");

    // The mark is the last certificate that a run creates, so the plan fails the creation of the
    // certificate whose number is the count of certificates that the run on slot 05 created.
    let marks = calls.iter().filter(certificate).count();
    let plan = format!(
        "[[rule]]\nfn = \"C_CreateObject\"\nclass = \"CKO_CERTIFICATE\"\nnth = {marks}\nrv = \"CKR_DEVICE_ERROR\"\n"
    );
    let (exit, said, calls) = run("cut", &plan);
    assert_eq!(exit, 0, "The probe run on slot 06 with the failed mark did not exit 0: {said}");
    let fired: Vec<&serde_json::Value> = calls.iter().filter(|c| c["rule"] == 1).collect();
    assert!(
        matches!(fired[..], [c] if certificate(&c)),
        "The plan's rule did not fail exactly one certificate creation. It decided these calls: {fired:?}"
    );
    // This closure lists the CKA_CLASS of each object in slot 06, in a fixed order.
    let held = || {
        let s = open_session(&real, "kmtest", "1234");
        let mut held: Vec<Vec<Attribute>> = s
            .find_objects(&[Attribute::Id(vec![0x06])])
            .unwrap()
            .into_iter()
            .map(|h| s.get_attributes(h, &[cryptoki::object::AttributeType::Class]).unwrap())
            .collect();
        held.sort_by_key(|a| format!("{a:?}"));
        held
    };
    let before = held();
    let (exit, said, _) = run("cut", "");
    assert_eq!(exit, 17, "The probe run on slot 06, which has no mark, was not refused with exit code 17: {said}");
    assert_eq!(held(), before, "The refused probe run changed the objects in slot 06.");
}
