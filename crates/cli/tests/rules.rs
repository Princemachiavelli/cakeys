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
use cakeys_pkcs11::token::{Access, ModuleInfo};
use cakeys_pkcs11::{ChainTime, Provider, Registry, Token};
use common::*;

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

/// A test's directory and keys.toml: the `SoftHSM` token as `t`, with provider `provider`, and
/// `body`; `None` (skipped) without the module.
fn suite(name: &str, provider: &str, body: &str) -> Option<(Workdir, Config)> {
    let module = suite_var(SOFTHSM.module_var, SOFTHSM.require_var, name)?;
    let w = Workdir::new(name);
    let pin = w.dir.join("pin");
    let token = format!(
        "[tokens.t]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nprovider = \"{provider}\"\n\n",
        pin.display()
    );
    w.write_config(&(token + body));
    let mut notes = Notes::default();
    let cfg = cakeys_core::config::load_config(&w.dir.join("keys.toml")).unwrap();
    cakeys_cli_common::activate_profiles(&cfg, None, &mut notes).unwrap();
    Some((w, cfg))
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
    let Some((_w, cfg)) = suite("placement", "places-nothing", &ec_key(label)) else { return };
    let registry = Registry::new().with(PlacesNothing);
    let t = Target::new(&cfg, "s", "t").unwrap();
    let mode = ops::plan_mode(&t).unwrap();
    let lock = Lock { version: cakeys_core::config::LOCK_VERSION, ..Lock::default() };
    let want = (17, Some(Rule::Placement.name()));

    // The static gate, as `validate` and `create`'s plan ask it.
    let stack = cakeys_pkcs11::gate::stack("t", &cfg.tokens["t"], &lock).unwrap().unwrap();
    let v = cakeys_pkcs11::gate::check(&t, mode, &stack, &registry, ops::Verb::Create).unwrap();
    let rules: Vec<(u8, Rule)> = v.refusals.iter().map(|r| (r.error.exit_code(), r.rule)).collect();
    assert_eq!(rules, [(17, Rule::Placement)], "the gate");

    let tok = open(&cfg, "t", &registry);
    tok.destroy(&t.object, &t.on_token.locator).unwrap();
    let mut notes = Notes::default();
    assert_eq!(refused("create", ops::create(&t, &tok, &mut lock.clone(), LockWrite::Record, &mut notes)), want);
    assert!(tok.find_any(&t.on_token.locator).unwrap().is_empty(), "create made a key it may not place");
    assert_eq!(refused("an import's check", ops::check_import(&t, &tok)), want);
}
