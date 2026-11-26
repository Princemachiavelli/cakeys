//! The liar matrix (docs/archive/REVIEW-2026-11-24/phase2-3-design.md §1.4–1.6): a table of the
//! lies a module can tell, each a p11-fault plan (`docs/FAULT_SHIM.md`), of the verbs each lie
//! meets and of the objects it is told about, expanded into cells with one expectation per block
//! of them (review 2026-11-24 C-6: lies were told to 3 of 7 verbs and one class of object).
//!
//! A cell's oracle is what the run did, never an exit code and a phrase alone (C-9): the exit;
//! the rule and the device bit its row names (`rule` absent: the row names none); the lock and
//! the token as they were, unless the table says which changed and why ([`super::state`]); and
//! whether the lie fired, from the shim's trace. Every run, the honest ones too, also holds two
//! invariants of the runner's own: it exits 22 exactly when it changed the lock (CAKEYS.md: "a
//! run that wrote the lock exits 22, never 0"), and a `check` changes nothing, whatever the
//! table says (CAKEYS.md: "it never writes").
//!
//! `tests/liars.rs` runs cakeys' table, one test per lie class ([`run_class`]); camigrate's and
//! caprobe's own `tests/liars.rs` run theirs through the same runner ([`run_table`]), each tool's
//! fixture the one part of a cell's run that is the tool's ([`Tool`]). The lint
//! (`tests/liar_lint.rs`) holds every table to its rules with no token: no rule of the plan without
//! a cell that fires it, a unit test that does, or an exemption ([`Table::uncovered`]); every
//! (lie class, verb, object class) covered or decided ([`Table::gaps`]); and the table's own
//! form ([`Table::problems`]).

use super::state::{Row, Snapshot, TokenView, changes, snapshot};
use super::{Workdir, code, fault_shim, open_session, stderr, stdout, suite_var};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

/// The classes of lie (§1.1), each the name of one test (`liars_<class>`).
pub const CLASSES: [&str; 8] = ["OK", "OTHER", "FLAG", "CHANGE", "FORGE", "BLOB", "DEV", "LOSS"];

/// What a cell's state oracle can name, unless the table says otherwise (`state`): the lock file
/// and the token.
pub const STATE: [&str; 2] = ["lock", "token"];

/// One liar table, as read ([`Table::load`]).
pub struct Table {
    /// The file, for what is said of it.
    pub path: PathBuf,
    /// The objects a cell may name, by name: the spec, and its locator's `CKA_LABEL`.
    pub objects: BTreeMap<String, Object>,
    /// The verbs (entry paths), by name.
    pub verbs: BTreeMap<String, Verb>,
    /// The lies, by name.
    pub lies: BTreeMap<String, Lie>,
    /// The blocks of cells.
    pub blocks: Vec<Block>,
    /// The (lie class, verb, object class) points decided without a cell.
    pub na: Vec<Na>,
    /// The rules a unit test fires instead of a cell.
    pub units: Vec<Unit>,
    /// The rules no cell or unit test fires, each with why.
    pub exempt: BTreeMap<String, String>,
    /// The most exemptions there may be: raising it is a visible diff.
    pub exempt_max: usize,
    /// What a cell's state oracle names ([`STATE`] unless the table lists its own).
    pub state: Vec<String>,
    /// The tool's own rules, beside the plan's (`cakeys_pkcs11::ops::Rule`): each name, and the
    /// source file (from the repository's root) that defines it.
    pub rules: BTreeMap<String, String>,
}

/// An object of the fixture.
pub struct Object {
    /// Its class in the completeness grid: `private`, `secret`, `certificate`, `data`, `public`.
    pub class: String,
    /// The token its spec is placed on.
    pub token: String,
    /// Whether the fixture makes it; one it does not is `create`'s to make.
    pub made: bool,
    /// Whether it is put on the token through the module and recorded by `lock`, never
    /// created (a certificate, a data object, a public key).
    pub adopted: bool,
    /// The exit every honest run on it has, where that is not the verb's own ([`Fixture::honest`]):
    /// a refusal of its token's options, which no lie changes, or a lock of one not yet locked.
    pub honest: Option<i32>,
}

/// A verb: an entry path a cell runs.
pub struct Verb {
    /// Its arguments, `{spec}` and `{token}` filled per object (and what else a tool's fixture
    /// fills, [`Tool::args`]).
    pub args: Vec<String>,
    /// What it prints for the oracle to read.
    pub form: Form,
    /// Whether the runner puts `--json` before its arguments (default: a [`Form::Rows`] verb).
    pub json: bool,
    /// The pairs it runs (default 1): a refused run's rows end at the refused one, the rows
    /// before it passing; a passing run prints one per pair.
    pub pairs: usize,
}

/// What a verb prints that the oracle reads (`rows = true`, or `form = "<form>"`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// Nothing: refused, it prints nothing at all (`check`, a real `export`).
    Nothing,
    /// A row per pair (`cakeys_cli_common::Outcome`): the rule and the device bit there.
    Rows,
    /// camigrate's plan (`--json`, a dry run): per object its method, exposure and deferrals.
    Plan,
    /// caprobe's profile, as TOML: its capability rows and its `[untested]` entries.
    Profile,
}

/// A profile row a cell expects (`row`): `answer` and `by` as written, or `absent`.
#[derive(Clone, Debug)]
pub struct RowWant {
    pub cap: String,
    pub answer: Option<String>,
    pub by: Option<String>,
    pub absent: bool,
}

/// A lie: its class, and its plan, with `{label}`, `{other}` (`{label}-other`) and
/// `{seq:C_X}` (the process's first call of `C_X` in the cell's run, found by a probe run that
/// fails that call) filled per cell.
pub struct Lie {
    pub class: String,
    pub plan: String,
}

/// What a cell must do.
#[derive(Clone, Debug)]
pub struct Expect {
    /// The exit: one of these.
    pub exit: Vec<i32>,
    /// The exit code that the refused pair's row must show when the run itself exits 22. This
    /// applies when an earlier pair of the same run wrote the lock and a later pair is refused
    /// (review 2026-11-24 L5). When it is `None`, the refused row's exit code is the run's.
    pub refused: Option<i32>,
    /// The rule the refused row names; none: it names none.
    pub rule: Option<String>,
    /// A rule the passing dry run's row lists as deferred.
    pub deferred: Option<String>,
    /// Whether the refused row says the device failed.
    pub device: bool,
    /// The passing row's outcome.
    pub outcome: Option<String>,
    /// Whether the lie fires (the trace has a line its rule changed).
    pub fired: bool,
    /// What the run changes ([`STATE`]), each a change the oracle asserts; the rest it asserts
    /// unchanged.
    pub changed: Vec<String>,
    /// Why it changes what it does.
    pub why: Option<String>,
    /// A cell known to fail its expectation, which stays what cakeys should do: the finding it
    /// waits on. Its run must still fail ([`run_class`]): one that passes has its mark taken off.
    pub red: Option<String>,
    /// The methods the plan's row must not name ([`Form::Plan`]): a plan with none passes.
    pub method_not: Vec<String>,
    /// The exposures the plan's row must not name ([`Form::Plan`]).
    pub exposure_not: Vec<String>,
    /// The profile rows ([`Form::Profile`]).
    pub rows: Vec<RowWant>,
    /// The `[untested]` entries the profile must hold ([`Form::Profile`]).
    pub untested: Vec<String>,
}

/// A block: every (lie, verb, object) of its lists is a cell, with its expectation, but where an
/// override names it.
pub struct Block {
    pub lies: Vec<String>,
    pub verbs: Vec<String>,
    pub objects: Vec<String>,
    pub expect: Expect,
    pub overrides: Vec<Override>,
    /// Runs under the cell's plan before its verb ([`Tool::before`]), each its arguments, filled
    /// as a verb's: the lie told to an earlier step, whose state the verb then meets.
    pub before: Vec<Vec<String>>,
}

/// A subset of a block's cells with an expectation of their own: a list left out is the block's.
pub struct Override {
    pub lies: Option<Vec<String>>,
    pub verbs: Option<Vec<String>>,
    pub objects: Option<Vec<String>>,
    pub expect: Expect,
}

/// Grid points decided without a cell: `*`, or a list, of lie classes, verbs and object
/// classes.
pub struct Na {
    pub classes: Option<Vec<String>>,
    pub verbs: Option<Vec<String>>,
    pub objects: Option<Vec<String>>,
    pub why: String,
}

/// A rule a test of its own fires (`test`, a `fn` in `crates/`), where no lie can.
pub struct Unit {
    pub rule: String,
    pub test: String,
    pub why: String,
}

/// One cell: a lie told to a verb about an object, and what it must do.
#[derive(Clone, Debug)]
pub struct Cell {
    pub lie: String,
    pub verb: String,
    pub object: String,
    pub expect: Expect,
    /// Its block's `before` steps.
    pub before: Vec<Vec<String>>,
}

impl Cell {
    /// `<lie>/<verb>/<object>`.
    pub fn id(&self) -> String {
        format!("{}/{}/{}", self.lie, self.verb, self.object)
    }
}

fn list(v: Option<&toml::Value>, what: &str) -> Vec<String> {
    match v {
        None => Vec::new(),
        Some(toml::Value::String(s)) => vec![s.clone()],
        Some(toml::Value::Array(a)) => {
            a.iter().map(|x| x.as_str().unwrap_or_else(|| panic!("{what}: {x} is no string")).to_owned()).collect()
        }
        Some(x) => panic!("{what}: {x} is no list"),
    }
}

/// `*` (any) or a list.
fn any_of(v: Option<&toml::Value>, what: &str) -> Option<Vec<String>> {
    match v {
        Some(toml::Value::String(s)) if s == "*" => None,
        None => panic!("{what}: give a list, or \"*\""),
        v => Some(list(v, what)),
    }
}

fn string(t: &toml::Table, key: &str, what: &str) -> String {
    t.get(key).and_then(toml::Value::as_str).unwrap_or_else(|| panic!("{what}: no {key}")).to_owned()
}

fn expect(v: &toml::Value, what: &str) -> Expect {
    let t = v.as_table().unwrap_or_else(|| panic!("{what}: expect is no table"));
    let known = [
        "exit",
        "refused",
        "rule",
        "deferred",
        "device",
        "outcome",
        "fired",
        "changed",
        "why",
        "red",
        "method_not",
        "exposure_not",
        "row",
        "untested",
    ];
    if let Some(k) = t.keys().find(|k| !known.contains(&k.as_str())) {
        panic!("{what}: expect has no {k}");
    }
    let rows = match t.get("row") {
        None => Vec::new(),
        Some(toml::Value::Table(r)) => vec![row_want(r, what)],
        Some(toml::Value::Array(a)) => {
            a.iter().map(|r| row_want(r.as_table().unwrap_or_else(|| panic!("{what}: row")), what)).collect()
        }
        Some(x) => panic!("{what}: row {x} is no table"),
    };
    let exit = match t.get("exit") {
        Some(toml::Value::Integer(n)) => vec![i32::try_from(*n).unwrap()],
        Some(toml::Value::Array(a)) => a.iter().map(|n| i32::try_from(n.as_integer().unwrap()).unwrap()).collect(),
        _ => panic!("{what}: expect has no exit"),
    };
    let opt = |k: &str| t.get(k).map(|v| v.as_str().unwrap_or_else(|| panic!("{what}: {k}")).to_owned());
    let flag = |k: &str, default| t.get(k).map_or(default, |v| v.as_bool().unwrap_or_else(|| panic!("{what}: {k}")));
    Expect {
        exit,
        refused: t
            .get("refused")
            .map(|n| i32::try_from(n.as_integer().unwrap_or_else(|| panic!("{what}: refused"))).unwrap()),
        rule: opt("rule"),
        deferred: opt("deferred"),
        device: flag("device", false),
        outcome: opt("outcome"),
        fired: flag("fired", true),
        changed: list(t.get("changed"), what),
        why: opt("why"),
        red: opt("red"),
        method_not: list(t.get("method_not"), what),
        exposure_not: list(t.get("exposure_not"), what),
        rows,
        untested: list(t.get("untested"), what),
    }
}

/// A `row` of an expectation: `{ cap, answer, by }` or `{ cap, absent = true }`.
fn row_want(t: &toml::Table, what: &str) -> RowWant {
    if let Some(k) = t.keys().find(|k| !["cap", "answer", "by", "absent"].contains(&k.as_str())) {
        panic!("{what}: a row has no {k}");
    }
    let opt = |k: &str| t.get(k).and_then(toml::Value::as_str).map(str::to_owned);
    RowWant {
        cap: string(t, "cap", what),
        answer: opt("answer"),
        by: opt("by"),
        absent: t.get("absent").and_then(toml::Value::as_bool).unwrap_or(false),
    }
}

/// Block `what` of a table.
fn block(v: &toml::Value, what: &str) -> Block {
    let t = v.as_table().unwrap_or_else(|| panic!("{what}"));
    let overrides = t
        .get("override")
        .and_then(toml::Value::as_array)
        .map(|a| {
            a.iter()
                .map(|o| {
                    let o = o.as_table().unwrap_or_else(|| panic!("{what}: override"));
                    let some = |k: &str| o.get(k).map(|v| list(Some(v), what));
                    Override {
                        lies: some("lies"),
                        verbs: some("verbs"),
                        objects: some("objects"),
                        expect: expect(o.get("expect").unwrap_or_else(|| panic!("{what}: override")), what),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let before = t
        .get("before")
        .and_then(toml::Value::as_array)
        .map(|a| a.iter().map(|step| list(Some(step), what)).collect())
        .unwrap_or_default();
    Block {
        lies: list(t.get("lies"), what),
        verbs: list(t.get("verbs"), what),
        objects: list(t.get("objects"), what),
        expect: expect(t.get("expect").unwrap_or_else(|| panic!("{what}: no expect")), what),
        overrides,
        before,
    }
}

impl Table {
    /// The table at `path` (relative to the cakeys crate, `crates/cli`).
    ///
    /// # Panics
    ///
    /// When it cannot be read, or is not of the table's shape.
    pub fn load(path: &str) -> Table {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("cli").join(path);
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let doc: toml::Table = toml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let section = |k: &str| doc.get(k).and_then(toml::Value::as_table).cloned().unwrap_or_default();
        let array = |k: &str| doc.get(k).and_then(toml::Value::as_array).cloned().unwrap_or_default();
        let objects = section("objects")
            .into_iter()
            .map(|(name, v)| {
                let t = v.as_table().unwrap_or_else(|| panic!("objects.{name}"));
                let token = t.get("token").and_then(toml::Value::as_str).unwrap_or("ref").to_owned();
                let made = t.get("made").and_then(toml::Value::as_bool).unwrap_or(true);
                let adopted = t.get("adopted").and_then(toml::Value::as_bool).unwrap_or(false);
                let honest = t.get("honest").and_then(toml::Value::as_integer).map(|n| i32::try_from(n).unwrap());
                let class = string(t, "class", &format!("objects.{name}"));
                (name, Object { class, token, made, adopted, honest })
            })
            .collect();
        let verbs = section("verbs")
            .into_iter()
            .map(|(name, v)| {
                let t = v.as_table().unwrap_or_else(|| panic!("verbs.{name}"));
                let args = list(t.get("args"), &format!("verbs.{name}"));
                let rows = t.get("rows").and_then(toml::Value::as_bool).unwrap_or(false);
                let form = match (rows, t.get("form").and_then(toml::Value::as_str)) {
                    (true, None) | (_, Some("rows")) => Form::Rows,
                    (false, None) => Form::Nothing,
                    (_, Some("plan")) => Form::Plan,
                    (_, Some("profile")) => Form::Profile,
                    (_, Some(f)) => panic!("verbs.{name}: no form {f}"),
                };
                let json = t.get("json").and_then(toml::Value::as_bool).unwrap_or(form == Form::Rows);
                let pairs = t.get("pairs").and_then(toml::Value::as_integer).map_or(1, |n| usize::try_from(n).unwrap());
                (name, Verb { args, form, json, pairs })
            })
            .collect();
        let lies = section("lies")
            .into_iter()
            .map(|(name, v)| {
                let t = v.as_table().unwrap_or_else(|| panic!("lies.{name}"));
                let what = format!("lies.{name}");
                (name, Lie { class: string(t, "class", &what), plan: string(t, "plan", &what) })
            })
            .collect();
        let blocks = array("block").iter().enumerate().map(|(i, v)| block(v, &format!("block {}", i + 1))).collect();
        let na = array("na")
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let what = format!("na {}", i + 1);
                let t = v.as_table().unwrap_or_else(|| panic!("{what}"));
                Na {
                    classes: any_of(t.get("classes"), &what),
                    verbs: any_of(t.get("verbs"), &what),
                    objects: any_of(t.get("objects"), &what),
                    why: string(t, "why", &what),
                }
            })
            .collect();
        let units = array("unit")
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let what = format!("unit {}", i + 1);
                let t = v.as_table().unwrap_or_else(|| panic!("{what}"));
                Unit { rule: string(t, "rule", &what), test: string(t, "test", &what), why: string(t, "why", &what) }
            })
            .collect();
        let exempt_table = section("exempt");
        let exempt_max =
            exempt_table.get("max").and_then(toml::Value::as_integer).map_or(0, |n| usize::try_from(n).unwrap());
        let exempt = exempt_table
            .get("rules")
            .and_then(toml::Value::as_table)
            .map(|t| t.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_owned())).collect())
            .unwrap_or_default();
        let state = doc.get("state").map_or_else(|| STATE.map(str::to_owned).to_vec(), |v| list(Some(v), "state"));
        let rules = section("rules")
            .into_iter()
            .map(|(name, v)| (name.clone(), v.as_str().unwrap_or_else(|| panic!("rules.{name}")).to_owned()))
            .collect();
        Table { path, objects, verbs, lies, blocks, na, units, exempt, exempt_max, state, rules }
    }

    /// cakeys' own table.
    pub fn cakeys() -> Table {
        Table::load("tests/liars/cakeys.toml")
    }

    /// camigrate's table.
    pub fn camigrate() -> Table {
        Table::load("../camigrate/tests/liars/camigrate.toml")
    }

    /// caprobe's table.
    pub fn caprobe() -> Table {
        Table::load("../caprobe/tests/liars/caprobe.toml")
    }

    /// The table of tpm2-pkcs11's own attestation (`CKM_TPM2_CERTIFY`), run by `tests/tpm2.rs`.
    pub fn tpm2() -> Table {
        Table::load("tests/liars/tpm2.toml")
    }

    /// Every cell, in the table's order.
    pub fn cells(&self) -> Vec<Cell> {
        let mut out = Vec::new();
        for b in &self.blocks {
            for lie in &b.lies {
                for verb in &b.verbs {
                    for object in &b.objects {
                        let names = |l: &Option<Vec<String>>, x: &String| l.as_ref().is_none_or(|l| l.contains(x));
                        let over = b
                            .overrides
                            .iter()
                            .rev()
                            .find(|o| names(&o.lies, lie) && names(&o.verbs, verb) && names(&o.objects, object));
                        let expect = over.map_or(&b.expect, |o| &o.expect).clone();
                        let before = b.before.clone();
                        out.push(Cell { lie: lie.clone(), verb: verb.clone(), object: object.clone(), expect, before });
                    }
                }
            }
        }
        out
    }

    /// The cells of lie class `class`.
    pub fn cells_of(&self, class: &str) -> Vec<Cell> {
        self.cells().into_iter().filter(|c| self.lies.get(&c.lie).is_some_and(|l| l.class == class)).collect()
    }

    /// What is wrong with the table's form: each a sentence naming where.
    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        for (name, lie) in &self.lies {
            if !CLASSES.contains(&lie.class.as_str()) {
                out.push(format!("lie {name}: class {} is none of {CLASSES:?}", lie.class));
            }
            if !self.blocks.iter().any(|b| b.lies.contains(name)) {
                out.push(format!("lie {name}: no block tells it"));
            }
        }
        let classes: BTreeSet<&str> = self.objects.values().map(|o| o.class.as_str()).collect();
        for (i, b) in self.blocks.iter().enumerate() {
            let at = format!("block {}", i + 1);
            for (names, kind, known) in [
                (&b.lies, "lie", self.lies.keys().collect::<BTreeSet<_>>()),
                (&b.verbs, "verb", self.verbs.keys().collect()),
                (&b.objects, "object", self.objects.keys().collect()),
            ] {
                if names.is_empty() {
                    out.push(format!("{at}: no {kind}"));
                }
                out.extend(names.iter().filter(|n| !known.contains(n)).map(|n| format!("{at}: no {kind} {n}")));
            }
            for o in &b.overrides {
                for (names, within) in [(&o.lies, &b.lies), (&o.verbs, &b.verbs), (&o.objects, &b.objects)] {
                    let outside = names.iter().flatten().filter(|n| !within.contains(n));
                    out.extend(outside.map(|n| format!("{at}: an override names {n}, which the block does not")));
                }
            }
        }
        let mut seen = BTreeSet::new();
        for c in self.cells() {
            let id = c.id();
            if !seen.insert(id.clone()) {
                out.push(format!("{id}: in two blocks"));
            }
            out.extend(self.cell_problems(&c));
        }
        for (i, n) in self.na.iter().enumerate() {
            let at = format!("na {}", i + 1);
            let unknown = |names: &Option<Vec<String>>, known: &dyn Fn(&str) -> bool| {
                names.iter().flatten().filter(|n| !known(n)).cloned().collect::<Vec<_>>()
            };
            for bad in unknown(&n.classes, &|c| CLASSES.contains(&c)) {
                out.push(format!("{at}: no lie class {bad}"));
            }
            for bad in unknown(&n.verbs, &|v| self.verbs.contains_key(v)) {
                out.push(format!("{at}: no verb {bad}"));
            }
            for bad in unknown(&n.objects, &|o| classes.contains(o)) {
                out.push(format!("{at}: no object class {bad}"));
            }
            if n.why.trim().is_empty() {
                out.push(format!("{at}: no why"));
            }
        }
        if self.exempt.len() > self.exempt_max {
            out.push(format!("{} exemptions, and exempt.max is {}", self.exempt.len(), self.exempt_max));
        }
        out.extend(
            self.exempt.iter().filter(|(_, why)| why.trim().is_empty()).map(|(r, _)| format!("exempt {r}: no why")),
        );
        // An exemption a cell or a unit row has come to cover is stale: it goes, and `max` with it.
        let cells = self.cells();
        for r in self.exempt.keys() {
            let rule = |c: &Cell| c.expect.rule.as_ref() == Some(r) || c.expect.deferred.as_ref() == Some(r);
            if cells.iter().any(rule) || self.units.iter().any(|u| &u.rule == r) {
                out.push(format!("exempt {r}: a cell or a unit row names it"));
            }
        }
        out.extend(self.partial(&cells));
        out
    }

    /// Returns what is wrong with the `refused` expectation of cell `id`. A cell with `refused`
    /// must expect exit 22, its verb must print rows for two or more pairs, and its `changed`
    /// list must include the lock.
    fn partial_cell(id: &str, e: &Expect, verb: &Verb) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(r) = e.refused {
            if matches!(r, 0 | 22) || e.exit != [22] || verb.pairs < 2 || verb.form != Form::Rows {
                out.push(format!(
                    "{id}: `refused = {r}` requires a verb that prints rows for two or more pairs and an expected exit of 22"
                ));
            }
            if !e.changed.iter().any(|k| k == "lock") {
                out.push(format!("{id}: `refused` is set, but `changed` does not include the lock"));
            }
        }
        out
    }

    /// What is wrong with one cell: what its expectation names that its verb cannot show, a
    /// change without its why, an object the verb never meets.
    fn cell_problems(&self, c: &Cell) -> Vec<String> {
        let mut out = Vec::new();
        let id = c.id();
        let (Some(verb), Some(object)) = (self.verbs.get(&c.verb), self.objects.get(&c.object)) else { return out };
        let e = &c.expect;
        let refused = e.refused.is_some() || e.exit.iter().any(|x| !matches!(x, 0 | 22));
        out.extend(Self::partial_cell(&id, e, verb));
        let rows = verb.form == Form::Rows;
        if verb.pairs == 0 || (verb.pairs > 1 && !rows) {
            out.push(format!("{id}: {} runs {} pairs, and its rows say which", c.verb, verb.pairs));
        }
        if !rows && (e.rule.is_some() || e.device || e.outcome.is_some()) {
            out.push(format!("{id}: {} prints no row to name a rule, a device or an outcome", c.verb));
        }
        if e.deferred.is_some() && !matches!(verb.form, Form::Rows | Form::Plan) {
            out.push(format!("{id}: {} prints no row or plan to defer a rule", c.verb));
        }
        if verb.form != Form::Plan && !(e.method_not.is_empty() && e.exposure_not.is_empty()) {
            out.push(format!("{id}: {} prints no plan to name a method", c.verb));
        }
        if verb.form != Form::Profile && !(e.rows.is_empty() && e.untested.is_empty()) {
            out.push(format!("{id}: {} prints no profile to hold a row", c.verb));
        }
        if e.rule.is_some() && !refused {
            out.push(format!("{id}: a rule, and no refusal"));
        }
        if let Some(k) = e.changed.iter().find(|k| !self.state.contains(k)) {
            out.push(format!("{id}: changed names {k}: one of {:?}", self.state));
        }
        if e.red.as_deref().is_some_and(|r| r.trim().is_empty()) {
            out.push(format!("{id}: red, and says not what it waits on"));
        }
        if !e.changed.is_empty() && e.why.is_none() {
            out.push(format!("{id}: changes {:?}, and says not why", e.changed));
        }
        if c.verb.starts_with("check") && !e.changed.is_empty() {
            out.push(format!("{id}: check never writes"));
        }
        if !object.made && !c.verb.starts_with("create") {
            out.push(format!("{id}: {} is create's to make: only create meets it", c.object));
        }
        if object.adopted && c.verb.starts_with("create") {
            out.push(format!("{id}: {} is adopted: create refuses it before any token (17)", c.object));
        }
        out
    }

    /// Requires a cell that tests a partial run if the table has a verb that prints rows and is
    /// not a dry run, because such a verb writes the lock. A partial run writes the lock for one
    /// pair and then refuses a later pair, and the runner checks that it exits 22 (the cell's
    /// `refused`). No such cell existed before review 2026-11-24 L5, so the runner never saw that
    /// such a run exited with the failure's code.
    fn partial(&self, cells: &[Cell]) -> Option<String> {
        let writes = self.verbs.values().any(|v| v.form == Form::Rows && !v.args.iter().any(|a| a == "--dry-run"));
        (writes && !cells.iter().any(|c| c.expect.refused.is_some())).then(|| {
            "no cell sets `refused`, so no cell checks that a run that writes the lock for one pair \
             and then refuses another pair exits 22"
                .to_owned()
        })
    }

    /// The (lie class, verb, object class) points no cell covers and no `na` decides, and each
    /// `na` that decides none.
    pub fn gaps(&self) -> Vec<String> {
        let covered: BTreeSet<(String, String, String)> = self
            .cells()
            .into_iter()
            .filter_map(|c| {
                Some((self.lies.get(&c.lie)?.class.clone(), c.verb, self.objects.get(&c.object)?.class.clone()))
            })
            .collect();
        let classes: BTreeSet<&str> = self.objects.values().map(|o| o.class.as_str()).collect();
        let within = |l: &Option<Vec<String>>, x: &str| l.as_ref().is_none_or(|l| l.iter().any(|y| y == x));
        let mut out = Vec::new();
        let mut used = vec![false; self.na.len()];
        for class in CLASSES {
            for verb in self.verbs.keys() {
                for object in &classes {
                    if covered.contains(&(class.to_owned(), verb.clone(), (*object).to_owned())) {
                        continue;
                    }
                    let mut decided = false;
                    for (i, n) in self.na.iter().enumerate() {
                        if within(&n.classes, class) && within(&n.verbs, verb) && within(&n.objects, object) {
                            (used[i], decided) = (true, true);
                        }
                    }
                    if !decided {
                        out.push(format!("{class} × {verb} × {object}"));
                    }
                }
            }
        }
        // An `na` whose every point a cell covers is stale: its why no longer decides anything.
        out.extend(
            used.iter()
                .enumerate()
                .filter(|(_, d)| !**d)
                .map(|(i, _)| format!("na {}: every point it decides is a cell's", i + 1)),
        );
        out
    }

    /// The names of `rules` (the plan's, `Rule::ALL`) that no cell names as its rule or deferred,
    /// no unit row fires and no exemption excuses.
    pub fn uncovered<'a>(&self, rules: &[&'a str]) -> Vec<&'a str> {
        let cells = self.cells();
        let named = |r: &str| {
            cells.iter().any(|c| c.expect.rule.as_deref() == Some(r) || c.expect.deferred.as_deref() == Some(r))
                || self.units.iter().any(|u| u.rule == r)
                || self.exempt.contains_key(r)
        };
        rules.iter().copied().filter(|r| !named(r)).collect()
    }

    /// The rules the table names (cells, unit rows, exemptions), for the check that each is one.
    pub fn named_rules(&self) -> BTreeSet<String> {
        let cells = self.cells().into_iter().flat_map(|c| [c.expect.rule, c.expect.deferred]).flatten();
        cells.chain(self.units.iter().map(|u| u.rule.clone())).chain(self.exempt.keys().cloned()).collect()
    }
}

/// The token a fixture plants on, with every object it makes and its decoy, on the shim.
pub struct Fixture {
    pub w: Workdir,
    /// The module behind the shim.
    pub real: String,
    /// The lock as the fixture left it: each cell starts from it.
    pub planted: Vec<u8>,
}

/// The keys.toml of an object of the fixture: its class and type lines, and its spec's
/// attributes and the rest of its `tokens.<token>` table.
fn declared(name: &str) -> (&'static str, &'static str, &'static str) {
    let ec = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"";
    let rsa = "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048";
    let aes = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32";
    let generic = "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32";
    match name {
        "ec-sign" | "new" => (ec, "CKA_SIGN = true", ", origin = \"create\", binding = \"pop-sign\""),
        "ec-derive" => (ec, "CKA_DERIVE = true", ", origin = \"create\", binding = \"pop-ecdh\""),
        "rsa-decrypt" => (rsa, "CKA_DECRYPT = true", ", origin = \"create\", binding = \"pop-decrypt\""),
        "rsa-unwrap" => (rsa, "CKA_UNWRAP = true", ", origin = \"create\", binding = \"pop-unwrap\""),
        "rsa-always-auth" => {
            (rsa, "CKA_ALWAYS_AUTHENTICATE = true, CKA_SIGN = true", ", origin = \"create\", binding = \"pop-sign\"")
        }
        "aes" | "new-aes" => (
            aes,
            "CKA_SIGN = true, CKA_ENCRYPT = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false",
            ", origin = \"create\"",
        ),
        "hmac" => (generic, "CKA_SIGN = true, CKA_SENSITIVE = true, CKA_EXTRACTABLE = false", ", origin = \"create\""),
        "aes-wrap" => (
            aes,
            "CKA_WRAP = true, CKA_UNWRAP = true, CKA_SIGN = false, CKA_ENCRYPT = false, CKA_SENSITIVE = true, \
             CKA_EXTRACTABLE = false",
            ", origin = \"create\"",
        ),
        "rebind" => {
            (generic, "CKA_SIGN = false, CKA_SENSITIVE = true, CKA_EXTRACTABLE = true", ", origin = \"create\"")
        }
        "cert" => ("class = \"CKO_CERTIFICATE\"\ncertificateType = \"CKC_X_509\"", "", ""),
        "data" => ("class = \"CKO_DATA\"", "CKA_PRIVATE = true", ""),
        "data-public" => ("class = \"CKO_DATA\"", "CKA_PRIVATE = false", ""),
        "pub" => ("class = \"CKO_PUBLIC_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp384r1\"", "CKA_VERIFY = true", ""),
        _ => panic!("the fixture has no object {name}"),
    }
}

impl Fixture {
    /// The table's objects planted on the token behind the shim, as test `name`'s: the keys made
    /// by `cakeys create`, the certificate, the data objects and the public key put there through
    /// the module and recorded by `cakeys lock`, all with no plan; and beside each a decoy of its
    /// kind under `<name>-other`, which no spec names, made through the module. `None` (skipped)
    /// without `P11_FAULT_MODULE`. Each run that writes the lock is held to the runner's
    /// invariants into `wrong`; with `record`, every one is traced there with the public values
    /// (`P11_FAULT_RECORD_VALUES = public`).
    ///
    /// # Panics
    ///
    /// When a planting step fails.
    pub fn plant(name: &str, table: &Table, record: Option<&Path>, wrong: &mut Vec<String>) -> Option<Fixture> {
        let real = suite_var("P11_FAULT_MODULE", "CAKEYS_FAULT_REQUIRE", name)?;
        let w = Workdir::new(name);
        let mut config = format!(
            "[tokens.ref]\nmodule = \"{shim}\"\ntokenLabel = \"kmtest\"\npinFile = \"{pin}\"\n\n\
             [tokens.mk]\nmodule = \"{shim}\"\ntokenLabel = \"kmtest\"\npinFile = \"{pin}\"\n\n",
            shim = fault_shim(),
            pin = w.dir.join("pin").display()
        );
        for (name, o) in &table.objects {
            let (kind, attributes, rest) = declared(name);
            let _ = write!(
                config,
                "[objects.{name}]\n{kind}\n\n[specs.{name}]\nobject = \"{name}\"\nattributes = {{ {attributes} }}\n\
                 tokens.{} = {{ locator = {{ CKA_LABEL = \"{name}\" }}{rest} }}\n\n",
                o.token
            );
        }
        w.write_config(&config);
        let f = Fixture { w, real, planted: Vec::new() };
        let s = open_session(&f.real, "kmtest", "1234");
        Self::put(&s, table);
        drop(s);
        for (name, o) in table.objects.iter().filter(|(_, o)| o.made) {
            let verb = if o.adopted { "lock" } else { "create" };
            let args = ["--json", verb, "--spec", name, "--token", &o.token];
            let (out, problems) = f.held(&args, None, record);
            assert_eq!(code(&out), 22, "planting {name}: {}", stderr(&out));
            wrong.extend(problems);
        }
        Some(Fixture { planted: std::fs::read(f.lock()).unwrap(), ..f })
    }

    /// What the module holds beside the keys cakeys makes: the certificate, the data objects and
    /// the public key under their own labels, and every decoy.
    fn put(s: &super::TestSession, table: &Table) {
        let label = |n: &str| Attribute::Label(n.as_bytes().to_vec());
        let token = Attribute::Token(true);
        let pair = |name: &str, public: Vec<Attribute>, private: Vec<Attribute>, m: &Mechanism| {
            let public = [vec![token.clone(), label(name)], public].concat();
            let private = [vec![token.clone(), label(name)], private].concat();
            s.generate_key_pair(m, &public, &private).unwrap()
        };
        let ec = |curve: &[u8]| vec![Attribute::EcParams(curve.to_vec())];
        let rsa = || vec![Attribute::ModulusBits(2048.into()), Attribute::PublicExponent(vec![1, 0, 1])];
        let secret = |name: &str, kind: KeyType, more: Vec<Attribute>| {
            let m = if kind == KeyType::AES { Mechanism::AesKeyGen } else { Mechanism::GenericSecretKeyGen };
            let t = [vec![token.clone(), label(name), Attribute::ValueLen(32.into()), Attribute::KeyType(kind)], more]
                .concat();
            s.generate_key(&m, &t).unwrap();
        };
        let data = |name: &str, private: bool| {
            s.create_object(&[
                Attribute::Class(ObjectClass::DATA),
                token.clone(),
                Attribute::Private(private),
                label(name),
                Attribute::Application(b"liars".to_vec()),
                Attribute::Value(format!("{name}: a value of its own, 7c1e0a9b4d2f").into_bytes()),
            ])
            .unwrap();
        };
        let cert = |name: &str, der: &[u8]| {
            s.create_object(&super::cert_object(der, name.as_bytes(), None)).unwrap();
        };
        // A public key object alone under its label: the pair's private half under another.
        let public = |name: &str| {
            let public = [vec![token.clone(), label(name), Attribute::Verify(true)], ec(super::P384)].concat();
            s.generate_key_pair(&Mechanism::EccKeyPairGen, &public, &[token.clone(), label(&format!("{name}-key"))])
                .unwrap();
        };
        let sealed = || vec![Attribute::Sensitive(true), Attribute::Extractable(false)];
        for (name, o) in &table.objects {
            let other = format!("{name}-other");
            match name.as_str() {
                "cert" => {
                    cert("cert", include_bytes!("../fixtures/adopt-cert.der"));
                    cert(&other, include_bytes!("../fixtures/adopt-cert-p384.der"));
                }
                "data" | "data-public" => {
                    data(name, name == "data");
                    data(&other, name == "data");
                }
                "pub" => {
                    public("pub");
                    public(&other);
                }
                "ec-sign" | "new" => {
                    let _ = pair(&other, ec(super::P256), vec![Attribute::Sign(true)], &Mechanism::EccKeyPairGen);
                }
                "ec-derive" => {
                    let _ = pair(&other, ec(super::P256), vec![Attribute::Derive(true)], &Mechanism::EccKeyPairGen);
                }
                "rsa-decrypt" | "rsa-unwrap" | "rsa-always-auth" => {
                    let usage = match name.as_str() {
                        "rsa-decrypt" => vec![Attribute::Decrypt(true)],
                        "rsa-unwrap" => vec![Attribute::Unwrap(true)],
                        _ => vec![Attribute::Sign(true), Attribute::AlwaysAuthenticate(true)],
                    };
                    let (_, private) = pair(&other, rsa(), usage, &Mechanism::RsaPkcsKeyPairGen);
                    // The public key the module asserts for it (SoftHSM sets none, and takes any).
                    let asserted = Attribute::PublicKeyInfo(super::oracle_spki(s, &other));
                    s.update_attributes(private, &[asserted]).unwrap();
                }
                "aes" | "new-aes" => secret(
                    &other,
                    KeyType::AES,
                    [vec![Attribute::Sign(true), Attribute::Encrypt(true)], sealed()].concat(),
                ),
                "hmac" => secret(&other, KeyType::GENERIC_SECRET, [vec![Attribute::Sign(true)], sealed()].concat()),
                "aes-wrap" => {
                    secret(
                        &other,
                        KeyType::AES,
                        [vec![Attribute::Wrap(true), Attribute::Unwrap(true)], sealed()].concat(),
                    );
                }
                "rebind" => secret(
                    &other,
                    KeyType::GENERIC_SECRET,
                    vec![Attribute::Sensitive(true), Attribute::Extractable(true)],
                ),
                _ => panic!("the fixture has no decoy for {name} ({})", o.class),
            }
        }
    }

    /// The shim's module, for each run: the process's `P11_FAULT_MODULE` is the liar suite's only.
    fn module(&self) -> (&'static str, &Path) {
        ("P11_FAULT_MODULE", Path::new(&self.real))
    }

    /// The lock file.
    pub fn lock(&self) -> PathBuf {
        self.w.dir.join("keys.lock")
    }

    /// The token as a snapshot sees it: through the module itself, not the shim.
    pub fn view(&self) -> TokenView<'_> {
        TokenView { name: "kmtest", module: &self.real, label: "kmtest", env: &[], db: vec![] }
    }

    /// `args` run through the shim under `plan` (none: no plan), traced to `trace`, and the
    /// runner's invariants over it: it exits 22 exactly when it changed the lock, and a `check`
    /// changed nothing. Returns the run, and what broke an invariant.
    pub fn held(&self, args: &[&str], plan: Option<(&Path, &Path)>, record: Option<&Path>) -> (Output, Vec<String>) {
        let mut env: Vec<(&str, &Path)> = Vec::new();
        if let Some((plan, trace)) = plan {
            env.extend([("P11_FAULT_PLAN", plan), ("P11_FAULT_TRACE", trace)]);
        } else if let Some(trace) = record {
            env.extend([("P11_FAULT_TRACE", trace), ("P11_FAULT_RECORD_VALUES", Path::new("public"))]);
        }
        held(self, args, &env)
    }

    /// The arguments of `verb` on `object`.
    pub fn args(table: &Table, verb: &str, object: &str) -> Vec<String> {
        let token = &table.objects[object].token;
        table.verbs[verb].args.iter().map(|a| a.replace("{spec}", object).replace("{token}", token)).collect()
    }
}

impl Tool for Fixture {
    fn dir(&self) -> &Path {
        &self.w.dir
    }

    fn fill(&self, table: &Table, args: &[String], object: &str) -> Vec<String> {
        let token = &table.objects[object].token;
        args.iter().map(|a| a.replace("{spec}", object).replace("{token}", token)).collect()
    }

    /// Each run names the shim's module itself ([`Fixture::module`]).
    fn run(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let env: Vec<(&str, &Path)> = std::iter::once(self.module()).chain(env.iter().copied()).collect();
        self.w.km_env(args, &env)
    }

    /// The lock and the token, now.
    fn state(&self) -> Snapshot {
        snapshot(&[&self.lock()], &[self.view()])
    }

    /// Which of [`STATE`] a change named by [`changes`] is.
    fn kind(&self, what: &str) -> String {
        if what == self.lock().display().to_string() { "lock" } else { "token" }.to_owned()
    }

    /// Returns the exit code of a run of `verb` on `object` when no fault is injected. That is
    /// the object's own code ([`Object::honest`]) if it has one. Otherwise it is 22 for a run
    /// that writes the lock, which the verb's arguments decide: `delete`, or `create` of an
    /// object that does not exist yet, without `--dry-run`. Every other run exits 0.
    fn honest_exit(&self, table: &Table, verb: &str, object: &str) -> i32 {
        let o = &table.objects[object];
        let args = &table.verbs[verb].args;
        let dry = args.iter().any(|a| a == "--dry-run");
        let writes = !dry && (args[0] == "delete" || (args[0] == "create" && !o.made));
        o.honest.unwrap_or(if writes { 22 } else { 0 })
    }

    /// It exits 22 exactly when it changed the lock, and a `check` changes nothing.
    fn invariants(&self, args: &[&str], exit: Option<i32>, changed: &BTreeSet<String>) -> Vec<String> {
        let mut wrong = lock_invariant(args, exit, changed);
        if args.contains(&"check") && !changed.is_empty() {
            wrong.push(format!("{args:?}: check changed {changed:?}"));
        }
        wrong
    }

    /// Every cell starts from the fixture: the lock as planted, and nothing `create` made left
    /// on the token.
    fn restore(&self, table: &Table) {
        std::fs::write(self.lock(), &self.planted).unwrap();
        let unmade: Vec<&str> = table.objects.iter().filter(|(_, o)| !o.made).map(|(n, _)| n.as_str()).collect();
        if !unmade.is_empty() {
            open_session(&self.real, "kmtest", "1234").clear(&unmade);
        }
    }
}

/// What a tool's runner does that is the tool's own: how a cell's verb runs, what state it may
/// change, the exit an honest run has, the invariants every run holds, and how a cell's state is
/// put back. The rest of a cell — its plan, the lie's firing, the exit and the output's oracle
/// by the verb's [`Form`] — is the runner's ([`judge`]).
pub trait Tool {
    /// Where the cells' plans and traces are written.
    fn dir(&self) -> &Path;
    /// `args` (a verb's, or a `before` step's) filled for `object` on this fixture.
    fn fill(&self, table: &Table, args: &[String], object: &str) -> Vec<String>;
    /// `args` run with `env` (the shim's plan and trace; none: an honest run).
    fn run(&self, args: &[&str], env: &[(&str, &Path)]) -> Output;
    /// A block's `before` step (its arguments filled as a verb's), under the cell's plan.
    fn before(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        self.run(args, env)
    }
    /// The state the oracle compares, now.
    fn state(&self) -> Snapshot;
    /// Which of the table's `state` a change named by [`changes`] is.
    fn kind(&self, what: &str) -> String;
    /// The exit an honest run of `verb` on `object` has.
    fn honest_exit(&self, table: &Table, verb: &str, object: &str) -> i32;
    /// What a run of `args` exiting `exit` broke of the runner's invariants, given the state it
    /// changed ([`Tool::kind`]s).
    fn invariants(&self, args: &[&str], exit: Option<i32>, changed: &BTreeSet<String>) -> Vec<String>;
    /// Put the fixture back as it was planted.
    fn restore(&self, table: &Table);
    /// The shim's plan and trace variables (a tagged shim's own, `docs/FAULT_SHIM.md`).
    fn vars(&self) -> (&'static str, &'static str) {
        ("P11_FAULT_PLAN", "P11_FAULT_TRACE")
    }
}

/// The invariant of a run that writes a lock (CAKEYS.md: "a run that wrote the lock exits 22,
/// never 0"): it exits 22 exactly when it changed the lock.
pub fn lock_invariant(args: &[&str], exit: Option<i32>, changed: &BTreeSet<String>) -> Vec<String> {
    let lock = changed.contains("lock");
    if (exit == Some(22)) == lock {
        vec![]
    } else {
        vec![format!("{args:?}: exit {exit:?}, and the lock changed: {lock}")]
    }
}

/// `args` run by `tool` with `env`, and what it broke of the tool's invariants.
pub fn held(tool: &impl Tool, args: &[&str], env: &[(&str, &Path)]) -> (Output, Vec<String>) {
    let before = tool.state();
    let out = tool.run(args, env);
    let changed = changes(&before, &tool.state(), &args.join(" ")).iter().map(|(what, _)| tool.kind(what)).collect();
    let wrong = tool.invariants(args, out.status.code(), &changed);
    (out, wrong)
}

/// `verb` on `object` with no plan through the shim: it exits as an honest run does, and
/// changes nothing unless it writes. What is wrong.
pub fn honest(tool: &impl Tool, table: &Table, verb: &str, object: &str) -> Vec<String> {
    let args = tool.fill(table, &table.verbs[verb].args, object);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let (out, mut wrong) = held(tool, &args, &[]);
    let want = tool.honest_exit(table, verb, object);
    if out.status.code() != Some(want) {
        wrong.push(format!("honest {verb} of {object}: exit {:?}, not {want}: {}", out.status.code(), stderr(&out)));
    }
    wrong
}

/// Run `cell` with `tool` and judge it. What is wrong, each line naming the cell.
pub fn judge(tool: &impl Tool, table: &Table, cell: &Cell, n: usize) -> Vec<String> {
    let id = cell.id();
    let e = &cell.expect;
    let verb = &table.verbs[&cell.verb];
    let args = tool.fill(table, &verb.args, &cell.object);
    let mut args: Vec<&str> = args.iter().map(String::as_str).collect();
    if verb.json {
        args.insert(0, "--json");
    }
    let (plan_var, trace_var) = tool.vars();
    let dir = tool.dir();
    let (plan, trace) = (dir.join(format!("cell-{n}.toml")), dir.join(format!("cell-{n}.jsonl")));
    let other = format!("{}-other", cell.object);
    let mut text = table.lies[&cell.lie].plan.replace("{label}", &cell.object).replace("{other}", &other);
    // `{seq:C_X}`: where the run first calls C_X, found by a run that fails that call, after
    // which the fixture is restored.
    while let Some(at) = text.find("{seq:") {
        let end = at + text[at..].find('}').unwrap();
        let function = text[at + 5..end].to_owned();
        let probe = dir.join(format!("cell-{n}-probe.jsonl"));
        std::fs::write(&plan, format!("[[rule]]\nfn = \"{function}\"\nnth = 1\nrv = \"CKR_DEVICE_REMOVED\"\n"))
            .unwrap();
        let _ = tool.run(&args, &[(plan_var, &plan), (trace_var, &probe)]);
        let Some(seq) = fired(&probe).first().and_then(|l| l["seq"].as_u64()) else {
            return vec![format!("{id}: the run never calls {function}")];
        };
        text.replace_range(at..=end, &seq.to_string());
        tool.restore(table);
    }
    std::fs::write(&plan, &text).unwrap();
    let env = [(plan_var, plan.as_path()), (trace_var, trace.as_path())];
    let mut wrong = Vec::new();
    for step in &cell.before {
        let filled = tool.fill(table, step, &cell.object);
        let filled: Vec<&str> = filled.iter().map(String::as_str).collect();
        let o = tool.before(&filled, &env);
        if !matches!(code(&o), 0 | 22) {
            wrong.push(format!("before step {filled:?}: exit {}: {}", code(&o), stderr(&o)));
        }
    }
    let before = tool.state();
    let out = tool.run(&args, &env);
    let after = tool.state();
    let said =
        || format!("{}{}", stdout(&out), stderr(&out).lines().last().map(|l| format!(" / {l}")).unwrap_or_default());
    let exit = out.status.code();
    if exit.is_none_or(|x| !e.exit.contains(&x)) {
        wrong.push(format!("exit {exit:?}, not {:?}", e.exit));
    }
    let changed: BTreeSet<String> = changes(&before, &after, &id).iter().map(|(what, _)| tool.kind(what)).collect();
    wrong.extend(tool.invariants(&args, exit, &changed));
    for what in &table.state {
        let should = e.changed.contains(what);
        if changed.contains(what) != should {
            let is = if changed.contains(what) { "changed" } else { "did not change" };
            wrong.push(format!("the {what} {is}"));
        }
    }
    // The exit code that the refused row must show. It is the cell's `refused` value when an
    // earlier pair wrote the lock (the run then exits 22), and otherwise the run's own code.
    let refusal = e.refused.or_else(|| exit.filter(|x| !matches!(x, 0 | 22)));
    let refused = refusal.is_some();
    match verb.form {
        Form::Rows => wrong.extend(judge_rows(e, &out, refusal, verb.pairs)),
        Form::Plan => wrong.extend(judge_plan(e, &out)),
        Form::Profile => wrong.extend(judge_profile(e, &out, refused)),
        Form::Nothing if refused && !out.stdout.is_empty() => {
            wrong.push(format!("a refusal printed {:?}", stdout(&out)));
        }
        Form::Nothing => {}
    }
    let fired = !fired(&trace).is_empty();
    if fired != e.fired {
        wrong.push(format!("the lie fired: {fired}, not {}", e.fired));
    }
    wrong.into_iter().map(|w| format!("{id}: {w}: {}", said())).collect()
}

/// The rows of a verb that prints a row per pair, one per pair it runs ([`Verb::pairs`]): a
/// refused run's end at the refused one, which names the cell's rule and device bit, the rows
/// before it passing; a passing run's each name its outcome and deferrals. `refusal` is the exit
/// code that the refused row must show, or `None` when no pair may be refused.
fn judge_rows(e: &Expect, out: &Output, refusal: Option<i32>, pairs: usize) -> Vec<String> {
    let mut wrong = Vec::new();
    match serde_json::from_slice::<Vec<Row>>(&out.stdout) {
        Err(err) => wrong.push(format!("no rows on stdout ({err})")),
        Ok(rows) => match rows.split_last() {
            Some((row, passed)) if refusal.is_some() && rows.len() <= pairs => {
                let got = (i32::from(row.exit), row.rule.as_deref(), row.device);
                let want = (refusal.unwrap_or(-1), e.rule.as_deref(), e.device);
                if got != want {
                    wrong.push(format!("the row says (exit, rule, device) {got:?}, not {want:?}"));
                }
                if let Some(row) = passed.iter().find(|r| r.exit != 0 || r.rule.is_some()) {
                    wrong.push(format!("a row before the refused one is refused: {row:?}"));
                }
            }
            Some(_) if refusal.is_none() && rows.len() == pairs => {
                for row in &rows {
                    if row.exit != 0 || row.rule.is_some() {
                        wrong.push(format!("a passing run's row is refused: {row:?}"));
                    }
                    if let Some(o) = e.outcome.as_deref().filter(|o| *o != row.outcome) {
                        wrong.push(format!("the row's outcome is {}, not {o}", row.outcome));
                    }
                    if let Some(d) = &e.deferred
                        && !row.deferred.iter().any(|r| &r.rule == d)
                    {
                        wrong.push(format!("the dry run defers {:?}, not {d}", row.deferred));
                    }
                }
            }
            _ => wrong.push(format!("{} rows, of {pairs} pairs", rows.len())),
        },
    }
    wrong
}

/// The one plan of camigrate's dry run (`--json`): the methods and exposures it must not name,
/// and the rule it must defer.
fn judge_plan(e: &Expect, out: &Output) -> Vec<String> {
    let report: serde_json::Value = match serde_json::from_slice(&out.stdout) {
        Ok(r) => r,
        Err(err) => return vec![format!("no plan on stdout ({err})")],
    };
    let Some([plan]) = report["plans"].as_array().map(Vec::as_slice) else {
        return vec![format!("not one plan: {}", report["plans"])];
    };
    let mut wrong = Vec::new();
    let named =
        |key: &str, not: &[String]| plan[key].as_str().filter(|m| not.iter().any(|n| n == m)).map(str::to_owned);
    if let Some(m) = named("method", &e.method_not) {
        wrong.push(format!("the plan's method is {m}"));
    }
    if let Some(x) = named("exposure", &e.exposure_not) {
        wrong.push(format!("the plan's exposure is {x}"));
    }
    if let Some(d) = &e.deferred {
        let deferred = plan["deferred"].as_array().cloned().unwrap_or_default();
        if !deferred.iter().any(|r| r.as_str() == Some(d)) {
            wrong.push(format!("the plan defers {deferred:?}, not {d}"));
        }
    }
    wrong
}

/// caprobe's profile (TOML on stdout): each row as the cell says, each `[untested]` entry there.
/// A refused probe prints no profile.
fn judge_profile(e: &Expect, out: &Output, refused: bool) -> Vec<String> {
    if refused {
        return if out.stdout.is_empty() { vec![] } else { vec![format!("a refusal printed {:?}", stdout(out))] };
    }
    let profile: toml::Table = match toml::from_str(&stdout(out)) {
        Ok(p) => p,
        Err(err) => return vec![format!("no profile on stdout ({err})")],
    };
    let section = |k: &str| profile.get(k).and_then(toml::Value::as_table).cloned().unwrap_or_default();
    let (caps, untested) = (section("capabilities"), section("untested"));
    let mut wrong = Vec::new();
    for want in &e.rows {
        let row = caps.get(&want.cap);
        let field = |k: &str| row.and_then(|r| r.get(k)).and_then(toml::Value::as_str).map(str::to_owned);
        if want.absent {
            if let Some(r) = row {
                wrong.push(format!("{} = {r}, not absent", want.cap));
            }
        } else if (field("answer"), field("by")) != (want.answer.clone(), want.by.clone()) {
            wrong.push(format!("{} is {:?}, not answer {:?} by {:?}", want.cap, row, want.answer, want.by));
        }
    }
    for u in &e.untested {
        if !untested.contains_key(u) {
            wrong.push(format!("no [untested] {u}"));
        }
    }
    wrong
}

/// The lines of `trace` whose rule fired: a lie that matched nothing would pass a cell for the
/// wrong reason.
pub fn fired(trace: &Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(trace).unwrap_or_default();
    text.lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|l| !l["rule"].is_null())
        .collect()
}

/// The test of lie class `class` over cakeys' table ([`run_table`]).
///
/// # Panics
///
/// When anything is wrong, listing all of it.
pub fn run_class(class: &str) {
    let table = Table::cakeys();
    run_table(&table, class, |name, wrong| Fixture::plant(name, &table, None, wrong));
}

/// The test of lie class `class` over `table`: the fixture planted afresh (`plant`, given the
/// test's name; `None`: skipped); every (verb, object) its cells meet run honestly first and
/// again after them, each as an honest run ends (so every refusal below was the lie's); each cell
/// judged from the planted state, a cell marked red ([`Expect::red`]) held to failing; and last,
/// the writes the cells refused done honestly, which change what the cells held unchanged (so
/// the comparison can fail). Every cell is run before any is judged: one run names every wrong
/// one.
///
/// # Panics
///
/// When anything is wrong, listing all of it.
pub fn run_table<T: Tool>(table: &Table, class: &str, plant: impl FnOnce(&str, &mut Vec<String>) -> Option<T>) {
    let cells = table.cells_of(class);
    assert!(!cells.is_empty(), "no cell of class {class}: its points are na, and its test goes");
    let mut wrong = Vec::new();
    let Some(f) = plant(&format!("liars-{}", class.to_lowercase()), &mut wrong) else { return };
    wrong.extend(run_cells(table, &cells, &f));
    assert!(
        wrong.is_empty(),
        "{} wrong in the {} cells of {class} and their runs:\n{}",
        wrong.len(),
        cells.len(),
        wrong.join("\n")
    );
}

/// [`run_table`]'s runs of `cells` on the fixture `f` planted of `table`, with no assertion: what
/// is wrong. What an honest run leaves as it was (every run but a write, a refusal too) is run
/// before and after the cells; the writes last, `f` restored after each.
pub fn run_cells<T: Tool>(table: &Table, cells: &[Cell], f: &T) -> Vec<String> {
    let mut wrong = Vec::new();
    let met: BTreeSet<(&str, &str)> = cells.iter().map(|c| (c.verb.as_str(), c.object.as_str())).collect();
    let reads: Vec<(&str, &str)> = met.iter().copied().filter(|(v, o)| f.honest_exit(table, v, o) != 22).collect();
    for (verb, object) in &reads {
        wrong.extend(honest(f, table, verb, object));
    }
    for (n, cell) in cells.iter().enumerate() {
        let judged = judge(f, table, cell, n);
        match &cell.expect.red {
            None => wrong.extend(judged),
            Some(red) if judged.is_empty() => wrong.push(format!("{}: marked red ({red}), and passes", cell.id())),
            Some(red) => eprintln!("red as marked ({red}):\n{}", judged.join("\n")),
        }
        f.restore(table);
    }
    for (verb, object) in &reads {
        wrong.extend(honest(f, table, verb, object));
    }
    // Restore the fixture before each write, because two writes can create the same object (the
    // first pair of a partial run and the later run of that pair), and after it.
    for (verb, object) in met.iter().filter(|(v, o)| f.honest_exit(table, v, o) == 22) {
        f.restore(table);
        wrong.extend(honest(f, table, verb, object));
        f.restore(table);
    }
    wrong
}
