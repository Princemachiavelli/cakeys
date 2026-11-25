//! Each rule a plan asks before a write (`cakeys_pkcs11::ops::Rule`) on every entry path that
//! can meet it (docs/archive/REVIEW-2026-11-24/phase1-design.md §1.4, T-4): the static gate
//! (`validate`, `create`'s plan), the live checks before a write (`create`, `lock`, an import's
//! `check_import`) and the token's own creation, each refusing with the same exit code and naming
//! the rule (`KmError::rule`). A provider's rules are held with a provider of the test's own on
//! `SoftHSM`, through the library: the binary links the default providers only. Skipped without
//! `CAKEYS_TEST_MODULE`, unless `CAKEYS_TEST_REQUIRE=1`.

mod common;

use cakeys_core::KmError;
use cakeys_core::config::{Config, Locator, Lock};
use cakeys_pkcs11::ops::{self, LockWrite, Notes, Rule, Target};
use cakeys_pkcs11::token::{Access, CreateNote, ModuleInfo};
use cakeys_pkcs11::{ChainTime, Checked, Create, Destroy, Provider, Registry, Token};
use common::*;
use cryptoki::session::SessionState;
use std::sync::{Arc, Mutex};

/// A provider that places a key nowhere ([`Provider::placement`]) and overrides nothing else, so
/// no `create` override of its own asks the rule (review 2026-11-24 B-2).
struct PlacesNothing;

impl Provider for PlacesNothing {
    fn name(&self) -> &'static str {
        "places-nothing"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }

    fn placement(&self, loc: &Locator) -> cakeys_core::Result<()> {
        Err(KmError::Validation(format!("places-nothing places no key under {loc:?}").into()))
    }
}

/// A provider whose module creates and destroys objects only as Security Officer
/// ([`Provider::manages_as_so`]), with `create` and `destroy` overrides that never enter that
/// session themselves (review 2026-11-24 B-2): each records the session state it ran in, and
/// writes nothing.
struct SoOnly(Arc<Mutex<Vec<SessionState>>>);

impl SoOnly {
    fn saw(&self, tok: &Token) {
        self.0.lock().unwrap().push(tok.raw().get_session_info().unwrap().session_state());
    }
}

impl Provider for SoOnly {
    fn name(&self) -> &'static str {
        "so-only"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }

    fn manages_as_so(&self) -> bool {
        true
    }

    fn create(&self, tok: &Token, _: &Checked<Create<'_>>) -> cakeys_core::Result<Option<CreateNote>> {
        self.saw(tok);
        Ok(None)
    }

    fn destroy(&self, tok: &Token, req: &Checked<Destroy<'_>>) -> cakeys_core::Result<usize> {
        self.saw(tok);
        Ok(req.handles.len())
    }
}

/// A provider whose `destroy` claims every handle destroyed and destroys none, as a module whose
/// `C_DestroyObject` returns `CKR_OK` and leaves the object (review 2026-11-24 B-13).
struct KeepsAll;

impl Provider for KeepsAll {
    fn name(&self) -> &'static str {
        "keeps-all"
    }

    fn matches(&self, _: &ModuleInfo) -> bool {
        false
    }

    fn destroy(&self, _: &Token, req: &Checked<Destroy<'_>>) -> cakeys_core::Result<usize> {
        Ok(req.handles.len())
    }
}

/// The profile set is the process's, set once: no test here names `profileDirs`.
static PROFILES: std::sync::Once = std::sync::Once::new();

/// Login state is the process's, per token (PKCS#11 §5.6): an SO step in one test logs every
/// other test's session out, so the tests here take the token one at a time.
static TOKEN: Mutex<()> = Mutex::new(());

/// A test's directory and keys.toml: the `SoftHSM` token as `t`, with provider `provider` and
/// its SO PIN as `soCredentialFile`, and again as `plain` with the generic provider, and `body`;
/// `None` (skipped) without the module. The guard holds the token for the test.
fn suite(name: &str, provider: &str, body: &str) -> Option<(Workdir, Config, std::sync::MutexGuard<'static, ()>)> {
    let module = suite_var(SOFTHSM.module_var, SOFTHSM.require_var, name)?;
    let guard = TOKEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let w = Workdir::new(name);
    let (pin, so) = (w.dir.join("pin"), w.dir.join("so-pin"));
    std::fs::write(&so, "5678\n").unwrap();
    let token = |name: &str, provider: &str| {
        format!(
            "[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n\
             soCredentialFile = \"{}\"\nprovider = \"{provider}\"\n\n",
            pin.display(),
            so.display()
        )
    };
    w.write_config(&(token("t", provider) + &token("plain", "generic") + body));
    let cfg = cakeys_core::config::load_config(&w.dir.join("keys.toml")).unwrap();
    PROFILES.call_once(|| cakeys_cli_common::activate_profiles(&cfg, None, &mut Notes::default()).unwrap());
    Some((w, cfg, guard))
}

/// The token `name` of `cfg`, opened read-write with `registry`.
fn open(cfg: &Config, name: &str, registry: &Registry) -> Token {
    Token::open(name, &cfg.tokens[name], None, registry, Access::Write, ChainTime::Unchecked).unwrap()
}

/// What a refused path reported: its exit code and the rule it named.
fn refused<T>(what: &str, r: cakeys_core::Result<T>) -> (u8, Option<&'static str>) {
    match r {
        Ok(_) => panic!("{what}: not refused"),
        Err(e) => (e.exit_code(), e.rule()),
    }
}

/// A key pair to create under the label `label` on `t`.
fn ec_key(label: &str) -> String {
    format!(
        "[objects.k]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
         [specs.s]\nobject = \"k\"\nattributes = {{ CKA_SIGN = true }}\n\
         tokens.t = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"create\" }}\n"
    )
}

/// Placement (17) on every path that puts a key on a token, for a provider that overrides
/// `placement` alone: the static gate, `create` and an import's check all refuse, naming the
/// rule, and nothing is created.
#[test]
fn placement_holds_on_every_path() {
    let label = "rules-placement";
    let Some((_w, cfg, _token)) = suite("placement", "places-nothing", &ec_key(label)) else { return };
    let registry = Registry::new().with(PlacesNothing);
    let t = Target::new(&cfg, "s", "t").unwrap();
    let mode = ops::plan_mode(&t).unwrap();
    let lock = Lock { version: cakeys_core::config::LOCK_VERSION, ..Lock::default() };
    let want = (17, Some(Rule::Placement.name()));

    // The static gate, as `validate` and `create`'s plan ask it.
    let stack = cakeys_pkcs11::gate::stack("t", &cfg.tokens["t"], &lock).unwrap();
    let v = cakeys_pkcs11::gate::check(&t, mode, &stack, &registry, ops::Verb::Create).unwrap();
    let rules: Vec<(u8, Rule)> = v.refusals.iter().map(|r| (r.error.exit_code(), r.rule)).collect();
    assert_eq!(rules, [(17, Rule::Placement)], "the gate");

    let tok = open(&cfg, "t", &registry);
    tok.destroy(&t.object, &t.on_token.locator).unwrap();
    let mut notes = Notes::default();
    assert_eq!(refused("create", ops::create(&t, &tok, &mut lock.clone(), LockWrite::Record, &mut notes)), want);
    assert!(tok.find_any(&t.on_token.locator).unwrap().is_empty(), "create made a key it may not place");
    assert_eq!(refused("an import's check", ops::check_import(&t, &tok)), want);

    // The token's own creation, which every creation goes through (camigrate's public halves,
    // caprobe's probes): placement before the provider is asked to create.
    assert_eq!(refused("Token::create", tok.create(t.object, t.spec, &t.on_token.locator, None)), want);
    assert!(tok.find_any(&t.on_token.locator).unwrap().is_empty(), "Token::create made a key it may not place");
}

/// A module that writes only as SO: `Token::create` and the destroys run the provider's
/// overrides in the SO session, whether or not an override enters it, and the user's session is
/// back after each. The session's state is read after each login (review 2026-11-24,
/// lead-found through the Phase 2 design): the SO one and the user's again.
#[test]
fn a_provider_override_runs_as_so_where_the_module_needs_it() {
    let label = "rules-so";
    let Some((_w, cfg, _token)) = suite("so", "so-only", &ec_key(label)) else { return };
    let seen = Arc::new(Mutex::new(Vec::new()));
    let registry = Registry::new().with(SoOnly(seen.clone()));
    let t = Target::new(&cfg, "s", "t").unwrap();
    let tok = open(&cfg, "t", &registry);
    let user = || tok.raw().get_session_info().unwrap().session_state();
    assert_eq!(user(), SessionState::RwUser);

    tok.create(t.object, t.spec, &t.on_token.locator, None).unwrap();
    assert_eq!(user(), SessionState::RwUser, "the user's session is back after the creation");

    // Something to destroy, made with a provider that writes as the user.
    let generic = open(&cfg, "plain", &Registry::new());
    generic.create(t.object, t.spec, &t.on_token.locator, None).unwrap();
    let handles = generic.find_any(&t.on_token.locator).unwrap();
    // The override destroys nothing, and the look after it says so (review 2026-11-24 B-13).
    let kept = tok.destroy_handles(&cfg.objects["k"], &t.on_token.locator, &handles).err();
    assert_eq!(kept.map(|e| e.rule()), Some(Some(Rule::DeleteKept.name())));
    assert_eq!(user(), SessionState::RwUser, "the user's session is back after the destroy");
    generic.destroy(&cfg.objects["k"], &t.on_token.locator).unwrap();

    assert_eq!(*seen.lock().unwrap(), [SessionState::RwSecurityOfficer; 2], "create, then destroy");
}

/// What a delete destroyed is looked for again: a key still under its locator after the provider
/// said it was destroyed is `delete-kept` (16), and the lock keeps its realisation; a dry run
/// claims nothing either way.
#[test]
fn a_delete_the_module_did_not_do_keeps_the_lock() {
    let Some((_w, cfg, _token)) = suite("kept", "keeps-all", &ec_key("rules-kept")) else { return };
    let registry = Registry::new().with(KeepsAll);
    let t = Target::new(&cfg, "s", "t").unwrap();
    let tok = open(&cfg, "t", &registry);
    tok.destroy(&t.object, &t.on_token.locator).unwrap_or_default();
    let mut lock = Lock { version: cakeys_core::config::LOCK_VERSION, ..Lock::default() };
    let mut notes = Notes::default();
    ops::create(&t, &tok, &mut lock, LockWrite::Record, &mut notes).unwrap();
    let recorded = toml::to_string(&lock).unwrap();
    let (dry, _) = ops::delete(&t, &tok, &mut lock, None, true, &mut notes).unwrap();
    assert_eq!(dry, ops::Deleted::WouldDelete);
    let e = ops::delete(&t, &tok, &mut lock, None, false, &mut notes).err();
    assert_eq!(e.map(|e| (e.exit_code(), e.rule())), Some((16, Some(Rule::DeleteKept.name()))));
    assert!(lock.realisation("s", "t").is_some(), "the lock keeps the realisation");
    assert_eq!(toml::to_string(&lock).unwrap(), recorded, "and is as it was");
    assert_eq!(tok.find_any(&t.on_token.locator).unwrap().len(), 2, "the key and its public half are there");
    open(&cfg, "plain", &Registry::new()).destroy(&t.object, &t.on_token.locator).unwrap();
}

/// A module profile that measured `C_DestroyObject` leaving private keys behind (`delete.<class>
/// = no`, as tpm2-pkcs11's on swtpm) refuses the delete before anything is destroyed, a dry run
/// as the delete (`delete-refused`, 15), and the key and the lock stay (review 2026-11-24 B-13).
/// `SoftHSM`'s profile is given the row here; tests/tpm2.rs holds it on tpm2-pkcs11's own.
#[test]
fn a_profile_row_that_says_the_module_keeps_keys_refuses_the_delete() {
    use cakeys_profile::{Answer, Capability};
    let Some((_w, mut cfg, _token)) = suite("row", "generic", &ec_key("rules-row")) else { return };
    // The module's own profile, as a token with no provider named resolves it.
    let tc = cfg.tokens.get_mut("t").unwrap();
    (tc.provider, tc.module_profile) = (None, Some("softhsm/2.7".into()));
    let t = Target::new(&cfg, "s", "t").unwrap();
    let mut tok = open(&cfg, "t", &Registry::new());
    let row = Capability::Delete("CKO_PRIVATE_KEY".into());
    let module = tok.profiles.module.as_mut().expect("softhsm/2.7, named");
    assert_eq!(module.answer(&row), Some(true), "the committed row");
    module.set(row, Answer::No, Some("C_DestroyObject leaves 1 of 1 behind".into()), None);
    let mut lock = Lock { version: cakeys_core::config::LOCK_VERSION, ..Lock::default() };
    let mut notes = Notes::default();
    ops::create(&t, &tok, &mut lock, LockWrite::Record, &mut notes).unwrap();
    let recorded = toml::to_string(&lock).unwrap();
    for dry in [true, false] {
        let e = ops::delete(&t, &tok, &mut lock, None, dry, &mut notes).err();
        let said = e.as_ref().map(ToString::to_string).unwrap_or_default();
        assert_eq!(e.map(|e| (e.exit_code(), e.rule())), Some((15, Some(Rule::DeleteRefused.name()))), "dry {dry}");
        assert!(said.contains("delete.CKO_PRIVATE_KEY = no: C_DestroyObject leaves 1 of 1 behind"), "{said}");
    }
    assert_eq!(toml::to_string(&lock).unwrap(), recorded, "the lock is as it was");
    assert_eq!(tok.find_any(&t.on_token.locator).unwrap().len(), 2, "the key pair is there");
    open(&cfg, "plain", &Registry::new()).destroy(&t.object, &t.on_token.locator).unwrap();
}

/// Where each rule is held on the entry paths that meet it (docs/archive/REVIEW-2026-11-24/
/// phase1-design.md §1.4, T-4), as `<file> <test>`: a `match` with no wildcard, so a rule added
/// without its tests fails to compile here. Each test refuses with the rule's exit code and
/// name, or defers it by name, on its paths; camigrate's paths are Phase 2's, in a rules suite
/// of its own.
fn held(rule: Rule) -> &'static [&'static str] {
    match rule {
        Rule::Placement => &["rules.rs placement_holds_on_every_path"],
        Rule::AttestationCover => &["validate.rs the_gate_refuses_what_it_can_decide_and_says_what_it_cannot"],
        Rule::ImportedAttestation => &["dry_run.rs landing_checks_follow_the_spec_named"],
        Rule::OwnGeneration => &[
            "gate.rs a_provider_this_build_lacks_is_said",
            "lib.rs what_could_not_be_proven_or_shown_is_refused_before_creating",
        ],
        Rule::Templates => &[
            "gate.rs the_gate_asks_the_provider_about_a_generation",
            "templates.rs a_refused_proof_template_creates_nothing",
        ],
        Rule::Capability => &[
            "validate.rs a_profile_no_refuses_and_names_its_profile",
            "create.rs create_checks_the_profiles_before_it_makes_anything",
        ],
        Rule::LocatorFree | Rule::UnpinnedExists | Rule::PinnedLost => &[
            "create.rs a_dry_run_refuses_what_the_run_refuses_on_the_token",
            "rows.rs every_pair_has_a_row_of_one_shape",
        ],
        Rule::NeedsLogin => &[
            "create.rs a_dry_run_refuses_what_the_run_refuses_on_the_token",
            "identity.rs private_data_objects_are_identified_when_declared",
            "p11kit.rs p11kit_login_is_per_client",
        ],
        Rule::IfMatch => &["rows.rs every_pair_has_a_row_of_one_shape"],
        Rule::DeleteRefused => &[
            "rules.rs a_profile_row_that_says_the_module_keeps_keys_refuses_the_delete",
            "tpm2.rs tpm2_delete_is_refused_where_the_module_keeps_keys",
        ],
        Rule::DeleteKept => &[
            "rules.rs a_delete_the_module_did_not_do_keeps_the_lock",
            "fault.rs a_delete_the_module_does_not_do_keeps_the_lock",
        ],
        Rule::LockWritable => &["lockfile.rs lock_is_written_by_default_and_refused_where_it_cannot_be"],
    }
}

/// Every rule names tests that hold it ([`held`]), and each of them is in the tree, in a file of
/// that name.
#[test]
fn every_rule_names_the_tests_that_hold_it() {
    fn sources(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let mut files = Vec::new();
    sources(&std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(".."), &mut files);
    for rule in Rule::ALL {
        assert!(!held(*rule).is_empty(), "{rule} names no test");
        for named in held(*rule) {
            let (file, test) = named.split_once(' ').unwrap();
            let there = files
                .iter()
                .filter(|p| p.file_name().is_some_and(|f| f == file))
                .any(|p| std::fs::read_to_string(p).unwrap().contains(&format!("fn {test}()")));
            assert!(there, "{rule}: no `fn {test}()` in any {file}");
        }
    }
}
