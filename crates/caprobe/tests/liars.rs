//! caprobe's liar matrix (`tests/liars/caprobe.toml`, run by cakeys' runner,
//! `crates/cli/tests/common/liars.rs`; docs/archive/REVIEW-2026-11-24/phase2-3-design.md §1):
//! `SoftHSM` behind p11-fault, probed with `--write-probes`, told one lie per cell; one test per
//! class of lie the table tells. Every cell asserts its exit, the profile rows and `[untested]`
//! entries it names, that the lie fired, and that the token is left as it was: every run, the
//! honest ones too, destroys what it made (CAPROBE.md).
//!
//! Needs what `tests/fault.rs` needs: `P11_FAULT_MODULE` naming `SoftHSM`, which the per-test
//! runner (nix/test-tokens.sh) sets, and `libp11_fault.so` built beside the test binaries.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use common::liars::{Table, Tool, run_table};
use common::state::{Snapshot, TokenView, snapshot};
use common::*;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Output;

// One test per class of lie, written out (nix/test-count.py counts no test a macro makes).

/// Class OK ([`run_table`]): the honest module, whose rows the lies take away.
#[test]
fn liars_ok() {
    run("OK");
}

/// Class BLOB ([`run_table`]): a blob the module round-trips that is not what it made (E-3).
#[test]
fn liars_blob() {
    run("BLOB");
}

/// Class DEV ([`run_table`]): a call failing as a device, and the same call refused (E-2).
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
    /// `ref` on the shim, as test `name`'s. `None` (skipped) without the module.
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

    /// The probe names no object: its keys are its own, under labels of its own.
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

    /// A probe writes nothing it keeps.
    fn honest_exit(&self, _table: &Table, _verb: &str, _object: &str) -> i32 {
        0
    }

    /// Whatever the lie and the exit, the token is as it was: the probe destroys what it made.
    fn invariants(&self, args: &[&str], _exit: Option<i32>, changed: &BTreeSet<String>) -> Vec<String> {
        if changed.is_empty() { vec![] } else { vec![format!("{args:?}: the probe left the token changed")] }
    }

    /// Nothing: a run that left anything fails its cell, and the probe sweeps its own labels.
    fn restore(&self, _table: &Table) {}
}
