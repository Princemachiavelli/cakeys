//! cakeys' liar matrix (`tests/liars/cakeys.toml`, run by `tests/common/liars.rs`;
//! docs/archive/REVIEW-2026-11-24/phase2-3-design.md §1): `SoftHSM` behind p11-fault, told one lie
//! per cell, each verb of cakeys meeting it about each kind of object; one test per class of lie,
//! each on a token of its own. Every cell asserts its exit, the rule and device bit its row names,
//! what it left of the lock and the token, and that the lie fired; every run, the honest ones
//! too, exits 22 exactly when it changed the lock, and a `check` changes nothing.
//!
//! Needs what `tests/fault.rs` needs: `P11_FAULT_MODULE` naming `SoftHSM`, which the per-test
//! runner (nix/test-tokens.sh) sets, and `libp11_fault.so` built beside the test binaries.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use common::liars::{Fixture, Table, run_class};
use common::*;

// One test per class of lie, written out (nix/test-count.py counts no test a macro makes):
// nextest runs them at once, each on a token of its own, and a failure names its class.

/// Class OK ([`run_class`]): a call answered `CKR_OK`, and nothing done.
#[test]
fn liars_ok() {
    run_class("OK");
}

/// Class OTHER ([`run_class`]): another object than the one asked for.
#[test]
fn liars_other() {
    run_class("OTHER");
}

/// Class FLAG ([`run_class`]): what the token says of itself or of an object, hidden or flipped.
#[test]
fn liars_flag() {
    run_class("FLAG");
}

/// Class CHANGE ([`run_class`]): a value that changes between two reads of one run.
#[test]
fn liars_change() {
    run_class("CHANGE");
}

/// Class FORGE ([`run_class`]): an output the key did not make.
#[test]
fn liars_forge() {
    run_class("FORGE");
}

/// Class BLOB ([`run_class`]): a blob the module round-trips that is not what it made.
#[test]
fn liars_blob() {
    run_class("BLOB");
}

/// Class DEV ([`run_class`]): a call failing as a device, and the same call refused by the module.
#[test]
fn liars_dev() {
    run_class("DEV");
}

/// Class LOSS ([`run_class`]): the device or the session gone from one call of a run on.
#[test]
fn liars_loss() {
    run_class("LOSS");
}

/// The lock holds hashes of what a token shows, never the values (docs/DESIGN.md §8.1, "The lock
/// never holds token outputs"): planted and then checked and re-locked with every public value a
/// module returned recorded (`P11_FAULT_RECORD_VALUES = public`: every key's point, modulus and
/// public key info, each certificate), the lock has none of them, as hex or base64. The values
/// shorter than 16 bytes (a curve's OID, an RSA exponent) are left out: a hash may hold their
/// few characters by chance.
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
    // One value at least for each made object with public material: a key pair's, a certificate's.
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
