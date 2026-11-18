//! The write probes make their scratch secret keys through `Provider::template`, as the verbs
//! make theirs (ISSUES.md §4(c)): what a provider changes or refuses there, the probe measures.
//! Run in-process on `SoftHSM` with a provider that refuses every secret-key generation
//! template: the probe has no AES key, so no wrap rows, where `SoftHSM`'s own provider leaves
//! the template alone and wraps (`wrap.rsa-oaep.SHA-1`, profiles/modules/softhsm/2.7.toml, which
//! tests/reference.rs holds to a fresh probe).
//!
//! Needs the reference suite's `CAKEYS_TEST_MODULE`; skipped without it.

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use cakeys_core::KmError;
use cakeys_core::config::ModuleInfo;
use cakeys_core::types::ObjectClass;
use cakeys_pkcs11::{Attributes, Half, Provider, Template};
use common::*;
use std::process::ExitCode;

/// Refuses the template of every secret key cakeys generates, and nothing else.
struct RefusesSecrets;

impl Provider for RefusesSecrets {
    fn name(&self) -> &'static str {
        "refuses-secrets"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }

    fn template(&self, req: &Template<'_>, _: &mut Attributes) -> cakeys_core::Result<()> {
        match req {
            Template::Generate(d, Half::Key) if d.object.class == ObjectClass::SecretKey => {
                Err(KmError::Unsupported("the test provider refuses secret-key generation".into()))
            }
            _ => Ok(()),
        }
    }
}

#[test]
fn the_write_probes_make_their_secret_keys_through_the_provider() {
    let test = "probe-template-hook";
    let Some(module) = suite_var(SOFTHSM.module_var, SOFTHSM.require_var, test) else { return };
    let w = Workdir::new(test);
    let tokens = reference_tokens(&module, &w.dir);
    w.write_config(&tokens.replacen("[tokens.ref]\n", "[tokens.ref]\nprovider = \"refuses-secrets\"\n", 1));
    let (config, out) = (w.dir.join("keys.toml"), w.dir.join("profile.toml"));
    let registry = caprobe::default_registry().with(RefusesSecrets);
    let args = ["caprobe", "--config", config.to_str().unwrap(), "probe", "--token", "ref", "--write"];
    // 2048 bits: the RSA transport key the wrap probes use.
    let more = ["--rsa-max-bits", "2048", "--out", out.to_str().unwrap()];
    let exit = caprobe::main_from(&registry, args.iter().chain(&more));
    assert!(exit == ExitCode::SUCCESS, "{exit:?}");
    let profile = std::fs::read_to_string(&out).unwrap();
    // The probe ran its write probes: the RSA keys proved possession.
    assert!(profile.contains("\"prove.pop-unwrap.CKK_RSA.1024\" = { answer = \"yes\" }"), "{profile}");
    // But it made no AES key to wrap.
    assert!(!profile.contains("wrap.rsa-oaep."), "{profile}");
}
