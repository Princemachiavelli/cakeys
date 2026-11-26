//! This test checks where a refusal may name no check (`cakeys_core::Reason`). Every `Conflict`,
//! `Ambiguous` and `PreconditionFailed` names the check or the rule that refused it, unless its
//! input does not parse as the expected structure. The test only reads the source files, so it
//! runs on every system.

use std::path::{Path, PathBuf};

/// The modules that parse a structure, where a refusal may use `Reason::malformed`. Input that
/// does not parse there cannot pass or fail any check. A security check that was marked as
/// malformed would name no check in its row, and the liar lint
/// (`crates/cli/tests/liar_lint.rs`) could not verify that a test makes it fire. So the list is
/// short, and each entry must be used.
const PARSERS: [&str; 3] = [
    // The X.509 certificates of an attestation chain: the DER, the signed part and the
    // extensions.
    "core/src/chain.rs",
    // TPM structures: the store's blobs and wrapped auth values, a public area, and the
    // components of the AK's signature (unmarshalled by tss-esapi).
    "tpm2-pkcs11/src/attest/esys.rs",
    // The output of CKM_TPM2_CERTIFY: a TPM2B_ATTEST and a TPMT_SIGNATURE.
    "tpm2-pkcs11/src/attest/vendor.rs",
];

/// Adds every `.rs` file under `dir` to `out`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() && !path.ends_with("target") {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Only the modules of [`PARSERS`] call `Reason::malformed`, outside their tests and comments,
/// and each of those modules calls it.
#[test]
fn malformed_only_in_parsers() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for krate in std::fs::read_dir(&crates).unwrap().flatten() {
        sources(&krate.path().join("src"), &mut files);
    }
    let mut wrong = Vec::new();
    let mut used = Vec::new();
    for file in &files {
        let name = file.strip_prefix(&crates).unwrap().to_string_lossy().replace('\\', "/");
        let text = std::fs::read_to_string(file).unwrap();
        let code = text.split("#[cfg(test)]").next().unwrap_or_default();
        for (n, line) in code.lines().enumerate() {
            if line.contains("Reason::malformed(") && !line.trim_start().starts_with("//") {
                if PARSERS.contains(&name.as_str()) {
                    used.push(name.clone());
                } else {
                    wrong.push(format!("{name}:{}: Reason::malformed outside a parser", n + 1));
                }
            }
        }
    }
    for p in PARSERS {
        if !used.iter().any(|u| u == p) {
            wrong.push(format!("{p} is listed as a parser and calls no Reason::malformed"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
