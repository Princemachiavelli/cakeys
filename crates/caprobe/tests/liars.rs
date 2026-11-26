//! caprobe's liar table (`tests/liars/caprobe.toml`), which the runner of cakeys
//! (`crates/cli/tests/common/liars.rs`) runs (docs/archive/REVIEW-2026-11-24/phase2-3-design.md
//! §1). The fixture is `SoftHSM` behind p11-fault, probed with `--write-probes`, with one false
//! answer injected for each cell. There is one test for each class of false answer in the
//! table. Every cell asserts its exit code, the profile rows and `[untested]` entries that it
//! names, that the injected fault fired, and that the token is left as it was: every run,
//! including the runs without a fault, destroys what it made (CAPROBE.md).
//!
//! The tests need what `tests/fault.rs` needs: `P11_FAULT_MODULE` naming `SoftHSM`, which the
//! per-test runner (nix/test-tokens.sh) sets, and `libp11_fault.so` built beside the test
//! binaries.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::liars::{Table, Tool, run_table};
use common::state::{Snapshot, TokenView, snapshot};
use common::*;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Output;

// There is one test for each class, written out by hand, because nix/test-count.py does not
// count a test that a macro makes.

/// Class OK ([`run_table`]): the module without a fault, which earns the rows that the faults
/// take away.
#[test]
fn liars_ok() {
    run("OK");
}

/// Class BLOB ([`run_table`]): a blob that the module round-trips but that is not the blob it
/// made (E-3).
#[test]
fn liars_blob() {
    run("BLOB");
}

/// Class DEV ([`run_table`]): a call that fails with a device failure, and the same call
/// refused by the module (E-2).
#[test]
fn liars_dev() {
    run("DEV");
}

fn run(class: &str) {
    let table = Table::caprobe();
    run_table(&table, class, Probe::plant);
}

/// The reference token behind the shim.
struct Probe {
    w: Workdir,
    /// `SoftHSM` itself, behind the shim.
    real: String,
}

impl Probe {
    /// Sets up the token `ref` on the shim for the test `name`. Returns `None`, and the test is
    /// skipped, when the module is not available.
    fn plant(name: &str, _wrong: &mut Vec<String>) -> Option<Probe> {
        let real = suite_var("P11_FAULT_MODULE", "CAKEYS_FAULT_REQUIRE", name)?;
        let w = Workdir::new(name);
        w.write_config(&reference_tokens(&fault_shim(), &w.dir));
        Some(Probe { w, real })
    }
}

impl Tool for Probe {
    fn dir(&self) -> &Path {
        &self.w.dir
    }

    /// The probe names no object, because it makes its own keys under its own labels.
    fn fill(&self, _table: &Table, args: &[String], _object: &str) -> Vec<String> {
        args.to_vec()
    }

    fn run(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        self.w.km_env(args, env)
    }

    fn state(&self) -> Snapshot {
        snapshot(&[], &[TokenView { name: "ref", module: &self.real, label: "kmtest", env: &[], db: vec![] }])
    }

    fn kind(&self, _what: &str) -> String {
        "token".to_owned()
    }

    /// A probe keeps nothing that it writes, so the exit code without a fault is 0.
    fn honest_exit(&self, _table: &Table, _verb: &str, _object: &str) -> i32 {
        0
    }

    /// Whatever the fault and the exit code are, the token must be as it was, because the probe
    /// destroys what it made.
    fn invariants(&self, args: &[&str], _exit: Option<i32>, changed: &BTreeSet<String>) -> Vec<String> {
        if changed.is_empty() { vec![] } else { vec![format!("{args:?}: the probe left the token changed")] }
    }

    /// Does nothing. A run that left anything fails its cell, and each write-probe run removes
    /// the objects that are left under the probe's own labels.
    fn restore(&self, _table: &Table) {}
}
