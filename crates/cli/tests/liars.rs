//! cakeys' liar matrix (`tests/liars/cakeys.toml`, run by `tests/common/liars.rs`;
//! docs/archive/REVIEW-2026-11-24/phase2-3-design.md §1). `SoftHSM` runs behind p11-fault, and
//! each cell injects one fault, so that each verb of cakeys meets each fault for each kind of
//! object. There is one test per fault class, and each test uses a token of its own. Every cell
//! asserts its exit code, the rule and the device bit that its row names, what the run left of
//! the lock and the token, and that the injected fault fired. Every run, including the runs
//! without an injected fault, exits 22 exactly when it changed the lock, and a `check` changes
//! nothing.
//!
//! The tests need what `tests/fault.rs` needs: `P11_FAULT_MODULE` naming `SoftHSM`, which the
//! per-test runner (nix/test-tokens.sh) sets, and `libp11_fault.so` built next to the test
//! binaries.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use common::liars::{Fixture, Table, run_class};
use common::*;

// There is one test per fault class, written out by hand, because nix/test-count.py does not
// count a test that a macro makes. nextest runs the tests in parallel, each on a token of its
// own, and the name of a failing test names its class.

/// Class OK ([`run_class`]): a call returns `CKR_OK`, but the module does nothing.
#[test]
fn liars_ok() {
    run_class("OK");
}

/// Class OTHER ([`run_class`]): a call returns another object than the one that was asked for.
#[test]
fn liars_other() {
    run_class("OTHER");
}

/// Class FLAG ([`run_class`]): the module hides or flips something that it reports about the
/// token or about an object, such as a token flag, a mechanism or an attribute.
#[test]
fn liars_flag() {
    run_class("FLAG");
}

/// Class CHANGE ([`run_class`]): a value changes between two reads in one run.
#[test]
fn liars_change() {
    run_class("CHANGE");
}

/// Class FORGE ([`run_class`]): the module returns an output that the key did not produce.
#[test]
fn liars_forge() {
    run_class("FORGE");
}

/// Class BLOB ([`run_class`]): in a round trip, the module returns a blob that is not the blob
/// that it produced.
#[test]
fn liars_blob() {
    run_class("BLOB");
}

/// Class DEV ([`run_class`]): a call fails with a device error (`CKR_DEVICE_ERROR`), or the
/// module refuses the same call.
#[test]
fn liars_dev() {
    run_class("DEV");
}

/// Class LOSS ([`run_class`]): the device or the session is lost from one call of a run onward.
#[test]
fn liars_loss() {
    run_class("LOSS");
}

/// The lock holds hashes of the values that a token returns, never the values themselves
/// (docs/DESIGN.md §8.1, "The lock never holds token outputs"). The test plants the objects, and
/// then checks and locks them again while p11-fault records every public value that the module
/// returns (`P11_FAULT_RECORD_VALUES = public`: every key's point, modulus and public key info,
/// and each certificate). The lock must hold none of those values, as hex or as base64. Values
/// shorter than 16 bytes (a curve's OID, an RSA exponent) are left out, because a hash may contain
/// their few characters by chance.
#[test]
fn a_lock_holds_no_token_output() {
    let table = Table::cakeys();
    let mut wrong = Vec::new();
    let dir = test_dir("a-lock-holds-no-token-output");
    let _ = std::fs::create_dir_all(&dir);
    let trace = dir.with_extension("jsonl");
    let _ = std::fs::remove_file(&trace);
    let Some(f) = Fixture::plant("a-lock-holds-no-token-output", &table, Some(&trace), &mut wrong) else { return };
    for (name, o) in table.objects.iter().filter(|(_, o)| o.made) {
        for verb in ["check", "lock"] {
            let args = Fixture::args(&table, verb, name);
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            let (out, problems) = f.held(&args, None, Some(&trace));
            wrong.extend(problems);
            if code(&out) != 0 {
                wrong.push(format!("{verb} {name} ({}): exit {}: {}", o.class, code(&out), stderr(&out)));
            }
        }
    }
    let text = std::fs::read_to_string(&trace).unwrap();
    let values: std::collections::BTreeSet<String> = text
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .flat_map(|l| l["values"].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v[1].as_str().map(str::to_owned))
        .filter(|hex| hex.len() >= 32)
        .collect();
    // Expect at least one value for each made object with public material: a key pair or a
    // certificate.
    let public =
        table.objects.values().filter(|o| o.made && ["private", "public", "certificate"].contains(&o.class.as_str()));
    assert!(values.len() >= public.count(), "too few values recorded to say anything: {values:?}");
    let lock = std::fs::read_to_string(f.lock()).unwrap();
    let lower = lock.to_lowercase();
    for hex in &values {
        let bytes: Vec<u8> =
            (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        let forms =
            [(&lower, hex.clone()), (&lock, STANDARD_NO_PAD.encode(&bytes)), (&lock, URL_SAFE_NO_PAD.encode(&bytes))];
        for (text, form) in forms {
            if text.contains(form.as_str()) {
                wrong.push(format!("the lock holds a value the token returned: {form}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
