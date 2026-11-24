//! The write probes make their scratch secret keys through `Provider::template`, as the verbs
//! make theirs (ISSUES.md §4(c)): what a provider changes or refuses there, the probe measures.
//! Run in-process on `SoftHSM` with a provider that refuses every secret-key generation
//! template: the probe has no AES key, so no wrap rows, where `SoftHSM`'s own provider leaves
//! the template alone and wraps (`wrap.rsa-oaep.SHA-1`, profiles/modules/softhsm/2.7.toml, which
//! tests/reference.rs holds to a fresh probe). The same probe with the default providers, run
//! beside it, is the control. The move probes' templates (`Import`, `PublicHalf`, `Object`) go
//! through the provider too.
//!
//! Needs the reference suite's `CAKEYS_TEST_MODULE`; skipped without it.
//!
//! The control is a run of the binary, not a second in-process `caprobe::main_from`: the
//! profile set is built once per process, and a later call reuses it only for the same profile
//! directories (caprobe's lib.rs), so the control keeps its own process and stays independent
//! of the run under test. (Review `template_hook.rs` F2 forced this when a second activation
//! was refused; since `main_from` reuses the set, it is a choice.)

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use cakeys_core::KmError;
use cakeys_core::config::ModuleInfo;
use cakeys_core::types::ObjectClass;
use cakeys_pkcs11::{Attributes, Half, Provider, Template, Via};
use common::*;
use std::process::ExitCode;
use std::sync::Mutex;

/// What each template the provider was asked is for.
static ASKED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Refuses the template of every secret key cakeys generates and of a secp256k1 pair, and
/// nothing else; records what each template is for in [`ASKED`].
struct RefusesSecrets;

impl Provider for RefusesSecrets {
    fn name(&self) -> &'static str {
        "refuses-secrets"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }

    fn template(&self, req: &Template<'_>, _: &mut Attributes) -> cakeys_core::Result<()> {
        let kind = match req {
            Template::Generate(..) => "generate",
            Template::Import(_, Via::CreateObject) => "import create-object",
            Template::Import(_, Via::Unwrap) => "import unwrap",
            Template::PublicHalf(_) => "public half",
            Template::Object(_) => "object",
            Template::TrustedCopy => "trusted copy",
            Template::Session(_) => "session",
        };
        ASKED.lock().unwrap().push(kind.to_owned());
        match req {
            Template::Generate(d, Half::Key) if d.object.class == ObjectClass::SecretKey => {
                Err(KmError::Unsupported("the test provider refuses secret-key generation".into()))
            }
            Template::Generate(d, Half::Key) if d.object.curve.as_deref() == Some("secp256k1") => {
                Err(KmError::Unsupported("the test provider refuses secp256k1".into()))
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
    let args = ["caprobe", "--config", config.to_str().unwrap(), "probe", "--token", "ref", "--write-probes"];
    // 2048 bits: the RSA transport key the wrap probes use.
    let more = ["--rsa-max-bits", "2048", "--out", out.to_str().unwrap()];
    let exit = caprobe::main_from(&registry, args.iter().chain(&more));
    assert!(exit == ExitCode::SUCCESS, "{exit:?}");
    let profile = std::fs::read_to_string(&out).unwrap();
    // The probe ran its write probes: the RSA keys proved possession.
    assert!(profile.contains("\"prove.pop-unwrap.CKK_RSA.1024\" = { answer = \"yes\" }"), "{profile}");
    // But it made no AES key to wrap.
    assert!(!profile.contains("wrap.rsa-oaep."), "{profile}");
    // A pair the provider refused was never asked of the module: no row, neither yes nor the
    // module's no (review 2026-11-23 D-4: it was written as the module's refusal).
    assert!(!profile.contains("\"generate.CKK_EC.secp256k1\""), "{profile}");
    assert!(profile.contains("\"generate.CKK_EC.secp256r1\" = { answer = \"yes\" }"), "{profile}");
    // The move probes asked the provider too (review pkcs11 templates.rs F3: no test reached
    // these hooks with a provider of its own).
    let asked = ASKED.lock().unwrap().clone();
    for kind in ["generate", "import create-object", "import unwrap", "public half", "object"] {
        assert!(asked.iter().any(|a| a == kind), "no {kind} template asked: {asked:?}");
    }

    // The control: the same probe with the default providers wraps, so the missing rows are
    // the provider's refusal, not these arguments' (review `template_hook.rs` F1: the absence
    // alone passed whatever else stopped the wrap probes).
    w.write_config(&tokens);
    let control = w.dir.join("control.toml");
    let o = Run::new(BIN, &config).output(&[&args[3..], &more[..2], &["--out", control.to_str().unwrap()]].concat());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let profile = std::fs::read_to_string(&control).unwrap();
    assert!(profile.contains("\"wrap.rsa-oaep.SHA-1\" = { answer = \"yes\" }"), "{profile}");
    assert!(profile.contains("\"generate.CKK_EC.secp256k1\" = { answer = \"yes\" }"), "{profile}");
}
