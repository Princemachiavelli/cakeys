//! The lock rules against their Quint model, crates/core/spec/lock.qnt (docs/DEVELOPMENT.md,
//! "Verification beyond tests"). quint-connect has `quint run` simulate the model and replays
//! each trace here: every `realise` step becomes a `Target` and a `Resolved` and runs the real
//! `reconcile`, and after every step the lock it left, projected onto the model's, and its
//! verdict must be the model's. Each lock must also load (`parse_lock`'s invariants).
//!
//! The model fixes the keys.toml below and keeps to what it names: a lock entry outside it (a
//! pair, a public key, a provenance, `publicOnly`, another label) fails the projection.

use cakeys_core::config::{
    AttestationRecord, AttrValue, Binding, Config, Immutables, LOCK_VERSION, Lock, Mode, ModuleInfo, ObjectCfg,
    Observation, Observed, Session, TokenInfo, parse_config_with, parse_lock,
};
use cakeys_core::id;
use cakeys_core::plan::Target;
use cakeys_core::reconcile::{Facts, LockWrite, Notes, Resolved, commitment_label, reconcile};
use quint_connect::{Driver, State, Step, quint_run, switch};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

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

/// What is compared after each step; the model's ghost variables are not.
#[derive(Debug, PartialEq, Eq, Deserialize)]
struct Compared {
    lock: MLock,
    verdict: Verdict,
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
/// projection reads what a keys.lock holds.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
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
}

struct Mbt {
    /// keys.toml, by k's curve.
    configs: BTreeMap<&'static str, Config>,
    /// Every object type the model names, by its name there.
    types: Vec<(String, ObjectCfg)>,
    lock: Lock,
    verdict: Verdict,
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
        Mbt { configs, types, lock: empty_lock(), verdict: Verdict::Ok(false) }
    }
}

fn empty_lock() -> Lock {
    Lock { version: LOCK_VERSION, ..Default::default() }
}

fn facts() -> Facts {
    Facts {
        observed: Observed { uri: "pkcs11:token=t".into(), session: Session::User },
        observation: Observation {
            provider: Some("generic".into()),
            cakeys_version: Some("0.1.0".into()),
            module: Some(ModuleInfo {
                path: "/m.so".into(),
                hash: None,
                description: "m".into(),
                manufacturer: "x".into(),
                version: "1.0".into(),
                cryptoki: "3.0".into(),
            }),
            token: Some(TokenInfo { model: "m".into(), serial: "1".into(), firmware: "1.0".into() }),
            ..Observation::default()
        },
        origin: None,
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
        self.verdict = match reconcile(&t, &r, &mut self.lock, &facts(), write, &mut Notes::default()) {
            Ok(changed) => Verdict::Ok(changed),
            Err(e) => Verdict::Exit(e.exit_code().into()),
        };
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
        let mut objects = BTreeMap::new();
        for (name, o) in &d.lock.objects {
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
        Ok(Compared { lock: MLock { objects, realisations }, verdict: d.verdict })
    }
}

/// Simulated traces of the model, replayed against `reconcile`: a fixed seed, so the check
/// phase replays the same traces every build.
#[quint_run(spec = "spec/lock.qnt", max_samples = 500, max_steps = 12, seed = "0x1")]
fn reconcile_refines_the_lock_model() -> impl Driver {
    Mbt::default()
}
