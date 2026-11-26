//! This test checks the lock rules against their Quint model, crates/core/spec/lock.qnt
//! (docs/DEVELOPMENT.md, "Verification beyond tests"). quint-connect runs `quint run` to simulate
//! the model and replays each trace here. Each `realise` step of a trace becomes a `Target` and a
//! `Resolved`, and the step runs the real `reconcile`. After each step, the lock that `reconcile`
//! left, projected onto the model's lock, and the result must equal the model's lock and result.
//! Each lock must also load, which checks the invariants of `parse_lock`.
//!
//! The model fixes the keys.toml below and uses only what that file names. A lock entry outside
//! that file (a pair, a public key, a provenance, `publicOnly`, or a different label) fails the
//! projection.

mod common;

use cakeys_core::config::{
    AttestationRecord, AttrValue, Binding, Config, Immutables, Lock, Mode, ObjectCfg, parse_config_with, parse_lock,
};
use cakeys_core::id;
use cakeys_core::plan::Target;
use cakeys_core::reconcile::{LockWrite, Notes, Resolved, commitment_label, reconcile};
use cakeys_core::{Check, KmError};
use common::{empty_lock, facts};
use quint_connect::{Driver, State, Step, switch};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::rc::Rc;

/// The model's keys.toml. The test replaces `CURVE` with the curve of the object `k`.
const CONFIG: &str = r#"
[tokens.t1]
tokenLabel = "t1"

[tokens.t2]
tokenLabel = "t2"

[objects.k]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "CURVE"

[objects.k2]
class = "CKO_PRIVATE_KEY"
keyType = "CKK_EC"
curve = "secp256r1"

[objects.aes]
class = "CKO_SECRET_KEY"
keyType = "CKK_AES"
valueLen = 32

[specs.s]
object = "k"
attributes = { CKA_SIGN = true }
tokens.t1 = { locator = { CKA_LABEL = "k" }, origin = "adopt" }
tokens.t2 = { locator = { CKA_LABEL = "k" }, origin = "adopt" }

[specs.s2]
object = "k2"
attributes = { CKA_SIGN = true }
tokens.t1 = { locator = { CKA_LABEL = "k2" }, origin = "adopt" }

[specs.a]
object = "aes"
attributes = { CKA_SIGN = true, CKA_ENCRYPT = true, CKA_DECRYPT = true, CKA_WRAP = true }
tokens.t1 = { locator = { CKA_LABEL = "aes" }, origin = "adopt" }
tokens.t2 = { locator = { CKA_LABEL = "aes" }, origin = "adopt" }
"#;

/// The curves that the object `k` can have in the model.
const CURVES: [&str; 2] = ["secp256r1", "secp384r1"];
/// The numbers with which the model names its materials, spec digests, attestation anchors and
/// attestation IDs: 1 and 2.
const NUMBERS: [i64; 2] = [1, 2];

// The model's values, as quint-connect reads them from a trace in the ITF format.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag")]
enum MWrite {
    Compare,
    Record,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag")]
enum MMode {
    Direct,
    Commitment,
    WrapRebind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag")]
enum MBinding {
    Unbound,
    PopSign,
    PopEcdh,
    TokenAsserted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag")]
enum Flag {
    Unset,
    Yes,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag", content = "value")]
enum MAttestation {
    Unattested,
    Attested { anchor: i64, id: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(tag = "tag", content = "value")]
enum Verdict {
    Ok(bool),
    Exit(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MImmutables {
    local: Flag,
    never_extractable: Flag,
    always_sensitive: Flag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
struct MPolicy {
    sign: Flag,
    decrypt: Flag,
}

/// The policy attributes that the model reports, in the order of their positions in `MPolicy`.
const POLICY: [&str; 2] = ["CKA_SIGN", "CKA_DECRYPT"];

impl MPolicy {
    fn flags(self) -> [Flag; 2] {
        [self.sign, self.decrypt]
    }
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct MObject {
    typ: String,
    ids: BTreeMap<String, i64>,
    labelled: bool,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MRealisation {
    object: String,
    mode: MMode,
    binding: MBinding,
    schemes: BTreeSet<String>,
    attestation: MAttestation,
    policy: MPolicy,
    immutables: MImmutables,
    spec_digest: i64,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
struct MLock {
    objects: BTreeMap<String, MObject>,
    realisations: BTreeMap<String, BTreeMap<String, MRealisation>>,
}

/// The values that the test compares after each step: the lock, the result, and the rule that
/// decided the result (the model's `rule` ghost variable). Twelve rules exit with 14, so a
/// comparison of the exit code alone would not detect that a different rule refused the step
/// (review `lock_mbt` F2).
#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Compared {
    lock: MLock,
    verdict: Verdict,
    rule: String,
}

/// The lock checks of the Rust code that the model does not have, each with the reason why the
/// model leaves it out. A replayed step that one of these checks refuses fails, because the model
/// never refuses with that check. `every_lock_rule_is_modelled_or_left_out` requires every lock
/// check to be either a rule of the model or listed here.
const LEFT_OUT: [(Check, &str); 2] = [
    (Check::LockImportIds, "the model leaves out imports: its runs have no `facts.origin`"),
    (
        Check::LockSameObject,
        "the model's keys.toml has no two specs of one object on one token under one locator, so no second spec \
         of the same token object is ever realised",
    ),
];

/// Returns the model's rule for the refusal `e` of `reconcile`, derived from the check that the
/// error names. The rule is the lock check's name without its `lock.` prefix, `mismatch` for
/// `identity.material`, and `first-use` for a `FirstUse` error, which names no check. A refusal by
/// a check that the model leaves out, by a check that is not a lock check, or by no check returns
/// an error. So a refusal that the model does not have fails the step, instead of being counted
/// as one of the model's rules (review 2026-11-24 A-6). The message markers that this function
/// replaced matched the first part of a message and ignored a suffix, so they reported a
/// different rule for a message that extended another rule's message.
fn model_rule(e: &KmError) -> quint_connect::Result<&'static str> {
    if let KmError::FirstUse { .. } = e {
        return Ok("first-use");
    }
    match e.check() {
        Some(Check::IdentityMaterial) => Ok("mismatch"),
        Some(c) if LEFT_OUT.iter().any(|(out, _)| *out == c) => {
            anyhow::bail!("{e}: the check {c}, which the model leaves out")
        }
        Some(c) => c.name().strip_prefix("lock.").ok_or_else(|| anyhow::anyhow!("{e}: the check {c} is no lock check")),
        None => anyhow::bail!("{e}: no check of the model"),
    }
}

/// Returns the rules that can decide a run of the model: the names with which the model's
/// `decidedBy` witnesses compare `rule`.
fn model_rules() -> BTreeSet<String> {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/spec/lock.qnt")).unwrap();
    spec.lines()
        .filter_map(|l| l.trim().strip_prefix("val decidedBy")?.split_once("rule == \"")?.1.strip_suffix('"'))
        .map(str::to_owned)
        .collect()
}

// These functions convert the model's numbers to the digests that the Rust code uses, and back.

fn material_id(material: i64, scheme: &str) -> String {
    id::sri(format!("material {material}/{scheme}").as_bytes())
}

fn spec_digest(n: i64) -> String {
    id::sri(format!("spec {n}").as_bytes())
}

fn anchor(n: i64) -> String {
    id::sri(format!("anchor {n}").as_bytes())
}

fn attestation_id(n: i64) -> String {
    id::sri(format!("attestation {n}").as_bytes())
}

/// Returns the model number whose digest is `digest`.
fn number(digest: &str, of: impl Fn(i64) -> String, what: &str) -> quint_connect::Result<i64> {
    NUMBERS.into_iter().find(|n| of(*n) == digest).ok_or_else(|| anyhow::anyhow!("{what} {digest} is no model value"))
}

fn flag(v: Option<bool>) -> Flag {
    match v {
        None => Flag::Unset,
        Some(true) => Flag::Yes,
        Some(false) => Flag::No,
    }
}

fn unflag(f: Flag) -> Option<bool> {
    match f {
        Flag::Unset => None,
        Flag::Yes => Some(true),
        Flag::No => Some(false),
    }
}

/// A realisation as the lock writes it: the serialized fields of `LockRealisation`, because the
/// projection reads what a keys.lock file holds. Every field is named here, including the fields
/// that the model leaves out (the header of lock.qnt lists them: the locator and the
/// observations). So a field that is added to the lock fails here until the model or this
/// projection handles it, and the field is never ignored without a decision (review `lock_mbt`
/// F1).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[expect(dead_code, reason = "the fields the model leaves out are named only to be refused when new")]
struct Written {
    object: String,
    spec_digest: String,
    mode: Mode,
    schemes: BTreeSet<String>,
    #[serde(default)]
    public_only: bool,
    #[serde(default)]
    binding: Option<Binding>,
    #[serde(default)]
    attestation: Option<AttestationRecord>,
    policy: BTreeMap<String, AttrValue>,
    #[serde(default)]
    immutables: Immutables,
    #[serde(default)]
    provenance: Option<serde_json::Value>,
    // These fields are outside the model.
    locator: serde_json::Value,
    #[serde(default)]
    observation: Option<String>,
    #[serde(default)]
    observed: Option<serde_json::Value>,
}

/// Fails when a lock or a lock object has a field that is not in `named`. `named` lists the
/// fields that the projection reads or that it leaves out with the model (`observations`). Any
/// other field is one for which no decision has been made.
fn only_named(what: &str, value: &impl serde::Serialize, named: &[&str]) -> quint_connect::Result {
    let value = serde_json::to_value(value)?;
    let unknown: Vec<&String> = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("{what} is no table"))?
        .keys()
        .filter(|k| !named.contains(&k.as_str()))
        .collect();
    anyhow::ensure!(unknown.is_empty(), "{what}: {unknown:?}, which the projection does not name");
    Ok(())
}

struct Mbt {
    /// The parsed keys.toml, keyed by the curve of the object `k`.
    configs: BTreeMap<&'static str, Config>,
    /// Every object type that the model names, with the name that the model uses for it.
    types: Vec<(String, ObjectCfg)>,
    lock: Lock,
    verdict: Verdict,
    rule: String,
    /// Every rule that decided a replayed step. The test compares this set with the model's rules.
    seen: Rc<RefCell<BTreeSet<String>>>,
}

impl Default for Mbt {
    fn default() -> Self {
        let configs: BTreeMap<_, _> = CURVES
            .into_iter()
            .map(|c| (c, parse_config_with(&CONFIG.replace("CURVE", c), Path::new("keys.toml"), &|_| None).unwrap()))
            .collect();
        let mut types: Vec<(String, ObjectCfg)> =
            configs.iter().map(|(c, cfg)| ((*c).to_owned(), cfg.objects["k"].clone())).collect();
        types.push(("aes".into(), configs["secp256r1"].objects["aes"].clone()));
        Mbt {
            configs,
            types,
            lock: empty_lock(),
            verdict: Verdict::Ok(false),
            rule: String::new(),
            seen: Rc::default(),
        }
    }
}

/// The values that the model chose for one `realise` step.
struct Input {
    target: (String, String),
    write: MWrite,
    curve: String,
    material: i64,
    schemes: BTreeSet<String>,
    mode: MMode,
    binding: MBinding,
    attestation: MAttestation,
    policy: MPolicy,
    immutables: MImmutables,
    digest: i64,
}

impl Driver for Mbt {
    type State = Compared;

    fn step(&mut self, step: &Step) -> quint_connect::Result {
        switch!(step {
            init => {
                self.lock = empty_lock();
                self.verdict = Verdict::Ok(false);
                self.rule = String::new();
            },
            realise(
                target: (String, String),
                write: MWrite,
                curve: String,
                material: i64,
                schemes: BTreeSet<String>,
                mode: MMode,
                binding: MBinding,
                attestation: MAttestation,
                policy: MPolicy,
                immutables: MImmutables,
                digest: i64
            ) => self.realise(&Input {
                target,
                write,
                curve,
                material,
                schemes,
                mode,
                binding,
                attestation,
                policy,
                immutables,
                digest,
            })?
        })
    }
}

impl Mbt {
    fn realise(&mut self, i: &Input) -> quint_connect::Result {
        let cfg = self.configs.get(i.curve.as_str()).ok_or_else(|| anyhow::anyhow!("no curve {}", i.curve))?;
        let t = Target::new(cfg, &i.target.0, &i.target.1)?;
        let binding = match i.binding {
            MBinding::Unbound => None,
            MBinding::PopSign => Some(Binding::PopSign),
            MBinding::PopEcdh => Some(Binding::PopEcdh),
            MBinding::TokenAsserted => Some(Binding::TokenAsserted),
        };
        let attestation = match i.attestation {
            MAttestation::Unattested => None,
            MAttestation::Attested { anchor: a, id } => {
                Some(AttestationRecord { kind: "tpm-certify".into(), root: anchor(a), id: attestation_id(id) })
            }
        };
        let r = Resolved {
            object: t.object_name.into(),
            spec: t.spec_name.into(),
            token: t.token_name.into(),
            uri: format!("pkcs11:token={};object={}", t.token_name, t.object_name),
            mode: match i.mode {
                MMode::Direct => Mode::Direct,
                MMode::Commitment => Mode::Commitment,
                MMode::WrapRebind => Mode::WrapRebind,
            },
            public_only: false,
            spec_digest: spec_digest(i.digest),
            ids: i.schemes.iter().map(|s| (s.clone(), material_id(i.material, s))).collect(),
            binding,
            assurance: cakeys_core::plan::assurance(
                t.object.class,
                binding,
                attestation.as_ref().map(|a| a.kind.as_str()),
            ),
            policy: POLICY
                .into_iter()
                .zip(i.policy.flags())
                .filter_map(|(n, f)| Some((n.to_owned(), AttrValue::Bool(unflag(f)?))))
                .collect(),
            immutables: Immutables {
                local: unflag(i.immutables.local),
                never_extractable: unflag(i.immutables.never_extractable),
                always_sensitive: unflag(i.immutables.always_sensitive),
                key_gen_mechanism: None,
            },
            // The label with which the commitments are computed, as `ops` receives it.
            commitment_label: (t.object_name == "aes").then(|| commitment_label(&t, &self.lock)),
            attestation,
            public_key: None,
        };
        let write = match i.write {
            MWrite::Compare => LockWrite::Compare,
            MWrite::Record => LockWrite::Record,
        };
        let rule;
        (self.verdict, rule) = match reconcile(&t, &r, &mut self.lock, &facts(), write, &mut Notes::default()) {
            Ok(changed) => (
                Verdict::Ok(changed),
                match (write, changed) {
                    (LockWrite::Compare, _) => "compared",
                    (LockWrite::Record, true) => "recorded",
                    (LockWrite::Record, false) => "unchanged",
                },
            ),
            Err(e) => (Verdict::Exit(e.exit_code().into()), model_rule(&e)?),
        };
        rule.clone_into(&mut self.rule);
        self.seen.borrow_mut().insert(self.rule.clone());
        // The lock that the run left must load, so that the lock's invariants hold after every
        // write.
        parse_lock(&toml::to_string(&self.lock)?, Path::new("keys.lock"))
            .map_err(|e| anyhow::anyhow!("the lock no longer loads: {e}"))?;
        Ok(())
    }

    /// Returns the model's name for an object type.
    fn type_name(&self, t: &ObjectCfg) -> quint_connect::Result<String> {
        self.types
            .iter()
            .find(|(_, ty)| ty == t)
            .map(|(n, _)| n.clone())
            .ok_or_else(|| anyhow::anyhow!("object type {t} is no model type"))
    }
}

impl State<Mbt> for Compared {
    fn from_driver(d: &Mbt) -> quint_connect::Result<Self> {
        only_named("the lock", &d.lock, &["version", "objects", "realisations", "observations"])?;
        let mut objects = BTreeMap::new();
        for (name, o) in &d.lock.objects {
            only_named(name, o, &["commitmentLabel", "type", "ids", "pairs", "publicKey"])?;
            anyhow::ensure!(o.pairs.is_empty() && o.public_key.is_none(), "object '{name}' has pairs or a public key");
            let labelled = match o.commitment_label.as_deref() {
                None => false,
                Some(id::DEFAULT_COMMITMENT_LABEL) => true,
                Some(other) => anyhow::bail!("object '{name}' has the commitment label {other:?}"),
            };
            let typ =
                d.type_name(o.object_type.as_ref().ok_or_else(|| anyhow::anyhow!("object '{name}' has no type"))?)?;
            let ids = o
                .ids
                .iter()
                .map(|(s, v)| Ok((s.clone(), number(v, |m| material_id(m, s), "ID")?)))
                .collect::<quint_connect::Result<_>>()?;
            objects.insert(name.clone(), MObject { typ, ids, labelled });
        }
        let mut realisations: BTreeMap<String, BTreeMap<String, MRealisation>> = BTreeMap::new();
        for (spec, by_token) in &d.lock.realisations {
            for (token, r) in by_token {
                let w: Written = serde_json::from_value(serde_json::to_value(r)?)?;
                anyhow::ensure!(
                    !w.public_only && w.provenance.is_none(),
                    "{spec} on {token}: publicOnly or provenance"
                );
                anyhow::ensure!(
                    w.policy.keys().all(|n| POLICY.contains(&n.as_str())),
                    "{spec} on {token}: policy {:?} beyond the model's",
                    w.policy.keys()
                );
                let [sign, decrypt] = POLICY.map(|n| match w.policy.get(n) {
                    None => Ok(Flag::Unset),
                    Some(AttrValue::Bool(b)) => Ok(flag(Some(*b))),
                    Some(AttrValue::Mechanisms(_)) => Err(anyhow::anyhow!("{spec} on {token}: {n} is no boolean")),
                });
                let policy = MPolicy { sign: sign?, decrypt: decrypt? };
                let attestation = match w.attestation {
                    None => MAttestation::Unattested,
                    Some(a) => MAttestation::Attested {
                        anchor: number(&a.root, anchor, "anchor")?,
                        id: number(&a.id, attestation_id, "attestation ID")?,
                    },
                };
                let realisation = MRealisation {
                    object: w.object,
                    mode: match w.mode {
                        Mode::Direct => MMode::Direct,
                        Mode::Commitment => MMode::Commitment,
                        Mode::WrapRebind => MMode::WrapRebind,
                    },
                    binding: match w.binding {
                        None => MBinding::Unbound,
                        Some(Binding::PopSign) => MBinding::PopSign,
                        Some(Binding::PopEcdh) => MBinding::PopEcdh,
                        Some(Binding::TokenAsserted) => MBinding::TokenAsserted,
                        Some(other) => anyhow::bail!("{spec} on {token}: binding {other} is no model binding"),
                    },
                    schemes: w.schemes,
                    attestation,
                    policy,
                    immutables: MImmutables {
                        local: flag(w.immutables.local),
                        never_extractable: flag(w.immutables.never_extractable),
                        always_sensitive: flag(w.immutables.always_sensitive),
                    },
                    spec_digest: number(&w.spec_digest, spec_digest, "spec digest")?,
                };
                realisations.entry(spec.clone()).or_default().insert(token.clone(), realisation);
            }
        }
        Ok(Compared { lock: MLock { objects, realisations }, verdict: d.verdict, rule: d.rule.clone() })
    }
}

/// Replays simulated traces of the model against `reconcile`. The seed is fixed, so the check
/// phase replays the same traces in every build. The replay must reach every rule that the
/// model's witnesses name (review `lock_mbt` F3). `checks.quint` counts the rules on its own,
/// larger sample, and that count says nothing about these 500 traces. The `#[quint_run]`
/// attribute expands to this call of quint-connect's `runner` (which is doc-hidden; version 0.1.2,
/// pinned by Cargo.lock). The call is written out here so that the test can read what the driver
/// saw after the run ends.
#[test]
fn reconcile_refines_the_lock_model() {
    let seen = Rc::default();
    let driver = Mbt { seen: Rc::clone(&seen), ..Mbt::default() };
    let config = quint_connect::runner::Config {
        test_name: "reconcile_refines_the_lock_model".into(),
        gen_config: quint_connect::runner::RunConfig {
            spec: "spec/lock.qnt".into(),
            main: None,
            init: None,
            step: None,
            max_samples: Some(500),
            max_steps: Some(12),
            seed: "0x1".into(),
        },
    };
    if let Err(e) = quint_connect::runner::run_test(driver, config) {
        panic!("{e}");
    }
    let rules = model_rules();
    assert_eq!(rules.len(), 18, "the witnesses the scan reads: {rules:?}");
    let seen = seen.borrow();
    let missed: Vec<&String> = rules.iter().filter(|r| !seen.contains(*r)).collect();
    assert!(missed.is_empty(), "rules no replayed trace reaches: {missed:?}");
}

/// Every lock check of the Rust code (a `Check` whose name starts with `lock.`) is either a rule
/// of the model or listed in `LEFT_OUT` with its reason, and never both. Every rule with which the
/// model refuses is a lock check, `identity.material` or `FirstUse`. Every check that
/// `reconcile.rs` names is a lock check or `identity.material`, so each refusal of `reconcile`
/// maps to the model through its check. A refusal that the model leaves out fails the replay and
/// is never counted as a modelled rule. For example, when a second spec of one token object
/// records the object with less than the first spec established (review 2026-11-23 A-2), the
/// refusal names `lock.same-object`, although its message ends with the message of the rule that
/// it extends (review 2026-11-24 A-6).
#[test]
fn every_lock_rule_is_modelled_or_left_out() {
    let modelled = model_rules();
    let left_out: Vec<Check> = LEFT_OUT.iter().map(|(c, _)| *c).collect();
    let lock_checks: Vec<Check> = Check::ALL.iter().copied().filter(|c| c.name().starts_with("lock.")).collect();
    let mut wrong = Vec::new();
    for c in &lock_checks {
        let rule = c.name().trim_start_matches("lock.");
        match (modelled.contains(rule), left_out.contains(c)) {
            (true, false) | (false, true) => {}
            (false, false) => wrong.push(format!("{c} is no rule of lock.qnt and not in LEFT_OUT")),
            (true, true) => wrong.push(format!("{c} is a rule of lock.qnt and in LEFT_OUT")),
        }
    }
    for (c, why) in &LEFT_OUT {
        if !lock_checks.contains(c) || why.trim().is_empty() {
            wrong.push(format!("LEFT_OUT names {c}, which is no lock check or has no reason"));
        }
    }
    for rule in &modelled {
        let verdict = ["compared", "recorded", "unchanged", "mismatch", "first-use"].contains(&rule.as_str());
        if !verdict && !lock_checks.iter().any(|c| c.name() == format!("lock.{rule}")) {
            wrong.push(format!("the model's rule {rule} is no lock check"));
        }
    }
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/reconcile.rs")).unwrap();
    let code = source.split("#[cfg(test)]").next().unwrap_or_default();
    for named in code.split("Check::").skip(1) {
        let variant: String = named.chars().take_while(char::is_ascii_alphanumeric).collect();
        match Check::ALL.iter().find(|c| format!("{c:?}") == variant) {
            Some(c) if lock_checks.contains(c) || *c == Check::IdentityMaterial => {}
            _ => wrong.push(format!("reconcile.rs refuses by Check::{variant}, which is no lock check")),
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    // The A-2 refusal: the spec s3 realises the same token object as the spec s, under the same
    // locator, and the lock records s with an attestation. So s3 without an attestation is
    // refused by `lock.same-object`, which the model leaves out, and the replay fails.
    let mut mbt = Mbt::default();
    for (curve, cfg) in &mut mbt.configs {
        let text = CONFIG.replace("CURVE", curve)
            + "\n[specs.s3]\nobject = \"k\"\nattributes = { CKA_SIGN = true }\n\
               tokens.t1 = { locator = { CKA_LABEL = \"k\" }, origin = \"adopt\" }\n";
        *cfg = parse_config_with(&text, Path::new("keys.toml"), &|_| None).unwrap();
    }
    let realise = |mbt: &mut Mbt, spec: &str, attestation| {
        mbt.realise(&Input {
            target: (spec.into(), "t1".into()),
            write: MWrite::Record,
            curve: CURVES[0].into(),
            material: 1,
            schemes: ["rfc7093m4".to_owned()].into(),
            mode: MMode::Direct,
            binding: MBinding::PopSign,
            attestation,
            policy: MPolicy { sign: Flag::Unset, decrypt: Flag::Unset },
            immutables: MImmutables {
                local: Flag::Unset,
                never_extractable: Flag::Unset,
                always_sensitive: Flag::Unset,
            },
            digest: 1,
        })
    };
    realise(&mut mbt, "s", MAttestation::Attested { anchor: 1, id: 1 }).unwrap();
    let e = realise(&mut mbt, "s3", MAttestation::Unattested).expect_err("a refusal the model leaves out was mapped");
    assert!(e.to_string().contains(Check::LockSameObject.name()), "{e}");
}
