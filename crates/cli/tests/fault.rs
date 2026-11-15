//! `p11-fault` (`crates/p11-fault`, `docs/FAULT_SHIM.md`): the reference suite (`tests/reference/`)
//! through the shim in front of `SoftHSM` with no plan, which must pass as it does directly; a
//! client that is not cakeys (`pkcs11-tool`) through it; and what cakeys does when the module
//! fails a call.
//!
//! Needs what `tests/softhsm.rs` needs, plus `P11_FAULT_MODULE` naming `SoftHSM`, which the per-test
//! runner (nix/test-tokens.sh) sets, and `libp11_fault.so` built beside the test binaries.

mod common;
mod reference;

use common::*;
use std::process::Command;

const REF: &common::Reference = &common::FAULT;

/// A test's directory with the reference tokens on the shim, a plan file and a trace file; `None`
/// (skipped) without `P11_FAULT_MODULE`.
fn faulted(name: &str, plan: &str) -> Option<(Workdir, std::path::PathBuf, std::path::PathBuf)> {
    suite_var(REF.module_var, REF.require_var, name)?;
    let w = Workdir::new(name);
    let (plan_path, trace) = (w.dir.join("plan.toml"), w.dir.join("trace.jsonl"));
    std::fs::write(&plan_path, plan).unwrap();
    w.write_config(&(reference_tokens(&fault_shim(), &w.dir) + &EC_SPEC.replace("NAME", name)));
    Some((w, plan_path, trace))
}

const EC_SPEC: &str = "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
                       [specs.k]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
                       tokens.ref = { locator = { CKA_LABEL = \"NAME\" }, autoCreate = true }\n";

/// The lines of the trace whose rule fired: a plan that matched nothing would pass a test for
/// the wrong reason.
fn fired(trace: &std::path::Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(trace).unwrap_or_default();
    text.lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|l| !l["rule"].is_null())
        .collect()
}

/// Any client loads the shim: `pkcs11-tool` lists the token through it, and under a plan that
/// fails `C_GetSlotList` it reports that return value.
#[test]
fn another_client_loads_the_shim_and_meets_its_plan() {
    let Some((w, plan, trace)) =
        faulted("fault-any-client", "[[rule]]\nfn = \"C_GetSlotList\"\nrv = \"CKR_DEVICE_ERROR\"\n")
    else {
        return;
    };
    let list = |with_plan: bool| {
        let mut c = Command::new("pkcs11-tool");
        c.args(["--module", &fault_shim(), "--list-slots"]).env("P11_FAULT_TRACE", &trace);
        if with_plan {
            c.env("P11_FAULT_PLAN", &plan);
        }
        let o = c.output().expect("pkcs11-tool (opensc) on PATH");
        (o.status.success(), String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr))
    };
    let (ok, said) = list(false);
    assert!(ok && said.contains("kmtest"), "{said}");
    let (ok, said) = list(true);
    assert!(!ok && said.contains("CKR_DEVICE_ERROR"), "{said}");
    let fired = fired(&trace);
    assert_eq!((fired.len(), fired[0]["fn"].as_str()), (1, Some("C_GetSlotList")), "{fired:?}");
    drop(w);
}

/// cakeys against a module that fails a call it should not: the failing call is named, the exit
/// is unavailable (16), and nothing is recorded. A login refused after the module accepted it
/// is the same.
#[test]
fn a_failing_module_call_is_unavailable() {
    let plan = "[[rule]]\nfn = \"C_FindObjects\"\nrv = \"CKR_DEVICE_ERROR\"\n\n\
                [[rule]]\nfn = \"C_Login\"\nwhen = \"after\"\nrv = \"CKR_PIN_INCORRECT\"\n";
    let Some((w, plan_path, trace)) = faulted("fault-module-fails", plan) else { return };
    assert_eq!(w.code(&["realise", "k", "--token", "ref", "--update-lock"]), 0, "no plan: transparent");
    let o =
        w.km_env(&["verify", "k", "--token", "ref"], &[("P11_FAULT_PLAN", &plan_path), ("P11_FAULT_TRACE", &trace)]);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    let said = stderr(&o);
    assert!(said.contains("C_Login") && said.contains("PIN is incorrect"), "{said}");
    assert_eq!(fired(&trace).last().unwrap()["fn"].as_str(), Some("C_Login"));
    // Logged in without the refusal, the search fails instead.
    let find_only = w.dir.join("find.toml");
    std::fs::write(&find_only, "[[rule]]\nfn = \"C_FindObjects\"\nrv = \"CKR_DEVICE_ERROR\"\n").unwrap();
    let o =
        w.km_env(&["verify", "k", "--token", "ref"], &[("P11_FAULT_PLAN", &find_only), ("P11_FAULT_TRACE", &trace)]);
    assert_eq!(code(&o), 16, "{}", stderr(&o));
    assert!(stderr(&o).contains("C_FindObjects"), "{}", stderr(&o));
    assert_eq!(fired(&trace).last().unwrap()["rv"].as_str(), Some("CKR_DEVICE_ERROR"));
}
