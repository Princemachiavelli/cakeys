//! The lock rules against their Quint model, crates/core/spec/lock.qnt (docs/DEVELOPMENT.md,
//! "Verification beyond tests"). quint-connect has `quint run` simulate the model and replays
//! each trace here: every `realise` step becomes a `Target` and a `Resolved` and runs the real
//! `reconcile`, and after every step the lock it left, projected onto the model's, and its
//! verdict must be the model's. Each lock must also load (`parse_lock`'s invariants).
//!
//! The model fixes the keys.toml below and keeps to what it names: a lock entry outside it (a
//! pair, a public key, a provenance, `publicOnly`, another label) fails the projection.

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

/// The model's keys.toml, `CURVE` being k's curve.
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

/// The curves k takes in the model.
const CURVES: [&str; 2] = ["secp256r1", "secp384r1"];
/// The model's materials, spec digests, attestation anchors and attestation IDs: 1 and 2.
const NUMBERS: [i64; 2] = [1, 2];

// The model's values, as quint-connect reads them from a trace (ITF).

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

/// The policy attributes the model reports, by their place in `MPolicy`.
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

/// What is compared after each step: the lock, the verdict, and the rule that decided it (the
/// model's `rule` ghost). Twelve rules end in 14, so the exit code alone would let one stand in
/// for another (review `lock_mbt` F2).
#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Compared {
    lock: MLock,
    verdict: Verdict,
    rule: String,
}

/// The Rust's lock checks that the model does not have, each with the reason it leaves it out.
/// A replayed step that one of them refuses fails, because the model never refuses by it.
/// `every_lock_rule_is_modelled_or_left_out` requires every lock check to be either a rule of
/// the model or listed here.
const LEFT_OUT: [(Check, &str); 2] = [
    (Check::LockImportIds, "the model leaves out imports: its runs have no `facts.origin`"),
    (
        Check::LockSameObject,
        "the model's keys.toml has no two specs of one object on one token under one locator, so no second spec \
         of the same token object is ever realised",
    ),
];

/// The model's rule for the refusal `e` of `reconcile`, read from the check that the error names:
/// a lock check's name without its `lock.` prefix, `mismatch` for `identity.material`, and
/// `first-use` for a `FirstUse` error, which names no check. A refusal by a check that the model
/// leaves out, by a check that is not a lock check, or by no check is an error, so a refusal that
/// the model does not have fails the step instead of passing for one of the model's rules (review
/// 2026-11-24 A-6: the message markers that this replaced read a message with a suffix as the
/// rule of its first part).
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

/// The rules that decide a run of the model: the names its `decidedBy` witnesses compare `rule`
/// with.
fn model_rules() -> BTreeSet<String> {
    let spec = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/spec/lock.qnt")).unwrap();
    spec.lines()
        .filter_map(|l| l.trim().strip_prefix("val decidedBy")?.split_once("rule == \"")?.1.strip_suffix('"'))
        .map(str::to_owned)
        .collect()
}

// The model's numbers as the Rust's digests, and back.

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

/// The model number whose digest `digest` is.
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

/// A realisation as the lock writes it: `LockRealisation`'s fields as serialised, since the
/// projection reads what a keys.lock holds. Every field is named, the ones the model leaves out
/// too (lock.qnt's header: the locator, observations), so a field added to the lock fails here
/// until the model or this projection decides about it, never dropped (review `lock_mbt` F1).
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
    // Outside the model.
    locator: serde_json::Value,
    #[serde(default)]
    observation: Option<String>,
    #[serde(default)]
    observed: Option<serde_json::Value>,
}

/// The fields of a lock or a lock object the projection reads, or leaves out with the model
/// (`observations`): any other is one it has not decided about.
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
    /// keys.toml, by k's curve.
    configs: BTreeMap<&'static str, Config>,
    /// Every object type the model names, by its name there.
    types: Vec<(String, ObjectCfg)>,
    lock: Lock,
    verdict: Verdict,
    rule: String,
    /// Every rule a replayed step was decided by, for the test to hold to the model's.
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

/// One `realise` step's picks.
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
            // The label the commitments are computed with, as `ops` takes it.
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
        // Whatever the run left must load: the lock's invariants hold after every write.
        parse_lock(&toml::to_string(&self.lock)?, Path::new("keys.lock"))
            .map_err(|e| anyhow::anyhow!("the lock no longer loads: {e}"))?;
        Ok(())
    }

    /// The model's name for an object type.
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

/// Simulated traces of the model, replayed against `reconcile`: a fixed seed, so the check
/// phase replays the same traces every build. The replay must reach every rule the model's
/// witnesses name (review `lock_mbt` F3): `checks.quint` counts them on its own, larger sample,
/// which says nothing of these 500. `#[quint_run]` expands to this call of quint-connect's
/// `runner` (doc-hidden; 0.1.2, pinned by Cargo.lock), written out so that what the driver saw
/// outlives the run.
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

/// Every lock check of the Rust (a `Check` named `lock.…`) is either a rule of the model or
/// listed in `LEFT_OUT` with its reason, never both, and every rule by which the model refuses
/// is a lock check, `identity.material` or `FirstUse`. Every check that `reconcile.rs` names is a
/// lock check or `identity.material`, so each refusal of `reconcile` maps to the model by its
/// check. A refusal that the model leaves out fails the replay, never passes for a modelled rule:
/// a second spec of one token object recorded weaker than the first (review 2026-11-23 A-2)
/// refuses by `lock.same-object`, although its message ends with the message of the rule it
/// extends (review 2026-11-24 A-6).
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

    // The A-2 refusal: spec s3 is s's token object under the same locator, and the lock records
    // s with an attestation, so s3 without one is refused by lock.same-object, which the model
    // leaves out, and the replay fails.
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
