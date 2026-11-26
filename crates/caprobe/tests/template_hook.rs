//! The write probes make their scratch secret keys through `Provider::template`, as the verbs
//! make theirs (ISSUES.md §4(c)), so the probe measures what a provider changes or refuses there.
//! The test runs in-process on `SoftHSM` with a provider that refuses every secret-key generation
//! template. The probe then has no AES key, and so no wrap rows. `SoftHSM`'s own provider leaves
//! the template unchanged, and the module wraps (`wrap.rsa-oaep.SHA-1` in
//! profiles/modules/softhsm/2.7.toml, which tests/reference.rs compares with a new probe). The
//! same probe with the default providers, run beside it, is the control. The templates of the
//! move probes (`Import`, `PublicHalf`, `Object`) also go through the provider.
//!
//! The test needs the reference suite's `CAKEYS_TEST_MODULE`, and it is skipped without it.
//!
//! The control is a run of the binary, not a second in-process `caprobe::main_from` call. The
//! profile set is built once per process, and a later call reuses it only for the same profile
//! directories (caprobe's lib.rs), so the control has its own process and stays independent of
//! the run under test. (Review `template_hook.rs` F2 required this when a second activation was
//! refused. Now that `main_from` reuses the set, it is a choice.)

#[path = "../../cli/tests/common/mod.rs"]
mod common;

use cakeys_core::KmError;
use cakeys_core::config::ModuleInfo;
use cakeys_core::types::ObjectClass;
use cakeys_pkcs11::{Attributes, Half, Provider, Template, Via};
use common::*;
use std::process::ExitCode;
use std::sync::Mutex;

/// The kind of each template that the provider was asked for.
static ASKED: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// A provider that refuses the template of every secret key that cakeys generates, of a
/// secp256k1 key pair, of a secp384r1 import with `C_CreateObject`, of a secp521r1 public half,
/// and of a data object, and accepts every other template. It records the kind of each template
/// in [`ASKED`].
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
            // Each kind of move template is refused for one input (review 2026-11-24 E-2: these
            // refusals used to be written as the module's no).
            Template::Import(d, Via::CreateObject) if d.object.curve.as_deref() == Some("secp384r1") => {
                Err(KmError::Unsupported("the test provider refuses the secp384r1 import".into()))
            }
            Template::PublicHalf(d) if d.object.curve.as_deref() == Some("secp521r1") => {
                Err(KmError::Unsupported("the test provider refuses the secp521r1 public half".into()))
            }
            Template::Object(d) if d.object.class == ObjectClass::Data => {
                Err(KmError::Unsupported("the test provider refuses data objects".into()))
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
    // RSA keys go up to 2048 bits, which is the size of the RSA transport key that the wrap
    // probes use.
    let more = ["--rsa-max-bits", "2048", "--out", out.to_str().unwrap()];
    let exit = caprobe::main_from(&registry, args.iter().chain(&more));
    assert!(exit == ExitCode::SUCCESS, "{exit:?}");
    let profile = std::fs::read_to_string(&out).unwrap();
    // The probe ran its write probes, because the RSA keys proved possession.
    assert!(profile.contains("\"prove.pop-unwrap.CKK_RSA.1024\" = { answer = \"yes\", by = \"host\" }"), "{profile}");
    // But the probe made no AES key to wrap.
    assert!(!profile.contains("wrap.rsa-oaep."), "{profile}");
    // A key pair that the provider refused was never requested from the module, so it has no
    // row: neither a yes nor the module's no (review 2026-11-23 D-4: it used to be written as the
    // module's refusal).
    assert!(!profile.contains("\"generate.CKK_EC.secp256k1\" = {"), "{profile}");
    assert!(profile.contains("\"generate.CKK_EC.secp256r1\" = { answer = \"yes\", by = \"host\" }"), "{profile}");
    // A move that the provider refused also has no row. Each one is an `[untested]` entry with
    // the reason `cakeys`, never a no row, and the control below shows that the module accepts
    // each one.
    for cap in ["import.CKK_EC.secp384r1", "create.CKO_PUBLIC_KEY.CKK_EC.secp521r1", "create.CKO_DATA"] {
        assert!(!profile.contains(&format!("\"{cap}\" = {{ answer")), "{cap}: {profile}");
        assert!(profile.contains(&format!("\"{cap}\" = {{ why = \"cakeys\"")), "{cap}: {profile}");
    }
    assert!(!profile.contains("answer = \"no\", by = \"module\", evidence = \"the test provider"), "{profile}");
    let loaded = cakeys_profile::Profile::from_toml(&profile).unwrap();
    assert_eq!(loaded.untested_problems(), Vec::<String>::new());
    // The move probes also asked the provider (review pkcs11 templates.rs F3: no test reached
    // these hooks with a provider of its own).
    let asked = ASKED.lock().unwrap().clone();
    for kind in ["generate", "import create-object", "import unwrap", "public half", "object"] {
        assert!(asked.iter().any(|a| a == kind), "no {kind} template asked: {asked:?}");
    }

    // The control: the same probe with the default providers wraps, so the missing rows come
    // from the provider's refusal and not from these arguments (review `template_hook.rs` F1: a
    // check of the absence alone passed whatever else stopped the wrap probes).
    w.write_config(&tokens);
    // The control writes onto a copy of the committed softhsm/2.7 profile, from which this probe
    // (RSA up to 2048 bits) differs. The result goes beside the file as `.new` until it is
    // accepted (review 2026-11-24 C-8: a regeneration replaced the file that it was then
    // compared with).
    let committed =
        cakeys_profile::embedded::PROFILE_FILES.iter().find(|(p, _)| p.ends_with("softhsm/2.7.toml")).unwrap().1;
    let target = w.dir.join("control.toml");
    std::fs::write(&target, committed).unwrap();
    let control = w.dir.join("control.toml.new");
    let control_args = [&args[3..], &more[..2], &["--out", target.to_str().unwrap()]].concat();
    let o = Run::new(BIN, &config).output(&control_args);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        committed,
        "a probe without --accept replaced its --out file"
    );
    let profile = std::fs::read_to_string(&control).unwrap();
    assert!(profile.contains("\"wrap.rsa-oaep.SHA-1\" = { answer = \"yes\", by = \"host\" }"), "{profile}");
    assert!(profile.contains("\"generate.CKK_EC.secp256k1\" = { answer = \"yes\", by = \"host\" }"), "{profile}");
    for cap in ["import.CKK_EC.secp384r1", "create.CKO_PUBLIC_KEY.CKK_EC.secp521r1", "create.CKO_DATA"] {
        assert!(profile.contains(&format!("\"{cap}\" = {{ answer = \"yes\"")), "{cap}: {profile}");
    }
    // When the result is accepted, it replaces the file, and no `.new` file is left beside it.
    let o = Run::new(BIN, &config).output(&[&control_args[..], &["--accept"]].concat());
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert!(!control.exists(), "a stale .new stayed beside the accepted profile");
    let profile = std::fs::read_to_string(&target).unwrap();
    assert!(profile.contains("\"wrap.rsa-oaep.SHA-1\" = { answer = \"yes\", by = \"host\" }"), "{profile}");
}
