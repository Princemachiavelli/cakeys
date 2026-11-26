//! The liar matrix (docs/archive/REVIEW-2026-11-24/phase2-3-design.md §1.4–1.6). A liar table
//! lists the false answers that a module can give, each as a p11-fault plan
//! (`docs/FAULT_SHIM.md`), the verbs into whose runs each fault is injected, and the objects that
//! the fault concerns. The runner expands the table into cells, with one expectation for each
//! block of cells (review 2026-11-24 C-6: faults were injected into only 3 of 7 verbs and one
//! class of object).
//!
//! A cell is judged by what the run did, never by an exit code and a phrase alone (C-9). The
//! runner checks the exit code; the rule and the device bit that the cell's row names (when
//! `rule` is absent, the row must name no rule); that the lock and the token are unchanged,
//! unless the table says which one changed and why ([`super::state`]); and, from the shim's
//! trace, whether the fault fired. Every run, including each run without a fault, must also keep
//! two invariants of the runner: the run exits 22 exactly when it changed the lock (CAKEYS.md: "a
//! run that wrote the lock exits 22, never 0"), and a `check` changes nothing, whatever the table
//! says (CAKEYS.md: "it never writes").
//!
//! `tests/liars.rs` runs the cakeys table, with one test for each fault class ([`run_class`]). The
//! `tests/liars.rs` files of camigrate and caprobe run their own tables through the same runner
//! ([`run_table`]). Each tool provides its own fixture, which is the only part of a cell's run
//! that is specific to the tool ([`Tool`]). The lint (`tests/liar_lint.rs`) checks every table
//! against its rules without a token: every rule of the plan has a cell that fires it, a unit test
//! that fires it, or an exemption ([`Table::uncovered`]); every (fault class, verb, object class)
//! is covered by a cell or decided ([`Table::gaps`]); and the table has the correct form
//! ([`Table::problems`]).

use super::state::{Row, Snapshot, TokenView, changes, snapshot};
use super::{Workdir, code, fault_shim, open_session, stderr, stdout, suite_var};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, KeyType, ObjectClass};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Output;

/// The fault classes (§1.1). Each class is the name of one test (`liars_<class>`).
pub const CLASSES: [&str; 8] = ["OK", "OTHER", "FLAG", "CHANGE", "FORGE", "BLOB", "DEV", "LOSS"];

/// The parts of the state that a cell's state check can name, unless the table lists its own
/// (`state`): the lock file and the token.
pub const STATE: [&str; 2] = ["lock", "token"];

/// One liar table, as [`Table::load`] reads it.
pub struct Table {
    /// The path of the table file, which the messages about the table name.
    pub path: PathBuf,
    /// The objects that a cell may name, by name. The name is both the spec and the `CKA_LABEL`
    /// of the spec's locator.
    pub objects: BTreeMap<String, Object>,
    /// The verbs (entry paths), by name.
    pub verbs: BTreeMap<String, Verb>,
    /// The faults (the table's `lies`), by name.
    pub lies: BTreeMap<String, Lie>,
    /// The blocks of cells.
    pub blocks: Vec<Block>,
    /// The (fault class, verb, object class) points that are decided without a cell.
    pub na: Vec<Na>,
    /// The rules that a unit test fires instead of a cell.
    pub units: Vec<Unit>,
    /// The rules that no cell or unit test fires, each with the reason.
    pub exempt: BTreeMap<String, String>,
    /// The maximum number of exemptions. A table that raises it shows the change in its diff.
    pub exempt_max: usize,
    /// The parts of the state that a cell's state check names ([`STATE`], unless the table lists
    /// its own).
    pub state: Vec<String>,
    /// The checks (`cakeys_core::Check`) that the table's cells must name as a rule or as
    /// deferred. These are the checks that only the tool's runs decide.
    pub covers: Vec<String>,
}

/// An object of the fixture.
pub struct Object {
    /// The object's class in the completeness grid: `private`, `secret`, `certificate`, `data`
    /// or `public`.
    pub class: String,
    /// The token on which the object's spec is placed.
    pub token: String,
    /// Whether the fixture makes the object. When the fixture does not make it, only `create`
    /// makes it.
    pub made: bool,
    /// Whether the object is put on the token through the module and recorded by `lock`, and
    /// never created by cakeys (a certificate, a data object, a public key).
    pub adopted: bool,
    /// The exit code of a run on this object when the fault shim injects no fault, if that code
    /// differs from the default that [`Fixture::honest_exit`] expects (22 for `delete` and for
    /// `create` of an object that does not exist yet, 0 for every other verb). Set it when the
    /// token's configuration makes the verb refuse, because no injected fault changes that
    /// refusal, or when the object is not locked yet, because `lock` then writes the lock and
    /// exits 22.
    pub honest: Option<i32>,
}

/// A verb: an entry path that a cell runs.
pub struct Verb {
    /// The verb's arguments. `{spec}` and `{token}` are filled in for each object, and a tool's
    /// fixture may fill in other placeholders ([`Tool::fill`]).
    pub args: Vec<String>,
    /// What the verb prints for the runner to check.
    pub form: Form,
    /// Whether the runner puts `--json` before the verb's arguments (by default, true for a
    /// [`Form::Rows`] verb).
    pub json: bool,
    /// The number of pairs that the verb runs (default 1). The rows of a refused run end at the
    /// refused pair, and the rows before it pass. A run that passes prints one row for each pair.
    pub pairs: usize,
}

/// What a verb prints for the runner to check (`rows = true`, or `form = "<form>"` in the table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// The verb prints nothing that the runner checks, and when it is refused, it prints nothing
    /// at all (`check`, or an `export` without `--dry-run`).
    Nothing,
    /// One row for each pair (`cakeys_cli_common::Outcome`), which holds the rule and the device
    /// bit.
    Rows,
    /// camigrate's plan (`--json`, a dry run), with the method, the exposure and the deferrals of
    /// each object.
    Plan,
    /// caprobe's profile, as TOML, with its capability rows and its `[untested]` entries.
    Profile,
}

/// A profile row that a cell expects (`row`): either `answer` and `by` exactly as written, or
/// `absent`.
#[derive(Clone, Debug)]
pub struct RowWant {
    pub cap: String,
    pub answer: Option<String>,
    pub by: Option<String>,
    pub absent: bool,
}

/// A fault: its class and its p11-fault plan. The runner fills in `{label}`, `{other}`
/// (`{label}-other`) and `{seq:C_X}` for each cell. `{seq:C_X}` becomes the process's first call
/// of `C_X` in the cell's run, which the runner finds with a probe run that fails that call.
pub struct Lie {
    pub class: String,
    pub plan: String,
}

/// The expected result of a cell.
#[derive(Clone, Debug)]
pub struct Expect {
    /// The allowed exit codes. The run must exit with one of them.
    pub exit: Vec<i32>,
    /// The exit code that the refused pair's row must show when the run itself exits 22. This
    /// applies when an earlier pair of the same run wrote the lock and a later pair is refused
    /// (review 2026-11-24 L5). When it is `None`, the refused row's exit code is the run's.
    pub refused: Option<i32>,
    /// The rule that the refused row names. When it is `None`, the row must name no rule.
    pub rule: Option<String>,
    /// A rule that the row of the passing dry run lists as deferred.
    pub deferred: Option<String>,
    /// Whether the refused row reports that the device failed.
    pub device: bool,
    /// The passing row's outcome.
    pub outcome: Option<String>,
    /// Whether the fault fires (the trace has a line that its rule changed).
    pub fired: bool,
    /// The parts of the state that the run changes ([`STATE`]). The runner asserts that each of
    /// them changed, and that the other parts did not change.
    pub changed: Vec<String>,
    /// The reason why the run changes the parts in `changed`.
    pub why: Option<String>,
    /// For a cell that is known to fail its expectation, the finding that the fix waits on. The
    /// expectation still describes what cakeys should do. The cell's run must still fail
    /// ([`run_class`]), and when it passes, the mark must be removed.
    pub red: Option<String>,
    /// The methods that the plan's row must not name ([`Form::Plan`]). A plan that names none of
    /// them passes.
    pub method_not: Vec<String>,
    /// The exposures that the plan's row must not name ([`Form::Plan`]).
    pub exposure_not: Vec<String>,
    /// The profile rows ([`Form::Profile`]).
    pub rows: Vec<RowWant>,
    /// The `[untested]` entries that the profile must hold ([`Form::Profile`]).
    pub untested: Vec<String>,
}

/// A block of cells. Every (fault, verb, object) combination of its lists is a cell with the
/// block's expectation, except where an override names the cell.
pub struct Block {
    pub lies: Vec<String>,
    pub verbs: Vec<String>,
    pub objects: Vec<String>,
    pub expect: Expect,
    pub overrides: Vec<Override>,
    /// Runs under the cell's plan before its verb ([`Tool::before`]). Each entry is a list of
    /// arguments, filled in as a verb's arguments are. The fault is injected into this earlier
    /// step, and the verb then runs on the state that the step left.
    pub before: Vec<Vec<String>>,
}

/// A subset of a block's cells with their own expectation. When the override leaves out a list,
/// the block's list applies.
pub struct Override {
    pub lies: Option<Vec<String>>,
    pub verbs: Option<Vec<String>>,
    pub objects: Option<Vec<String>>,
    pub expect: Expect,
}

/// Grid points that are decided without a cell. The fault classes, the verbs and the object
/// classes are each `*` (any) or a list.
pub struct Na {
    pub classes: Option<Vec<String>>,
    pub verbs: Option<Vec<String>>,
    pub objects: Option<Vec<String>>,
    pub why: String,
}

/// A rule that a separate test fires (`test`, a `fn` in `crates/`), where no injected fault can
/// fire it.
pub struct Unit {
    pub rule: String,
    pub test: String,
    pub why: String,
}

/// One cell: a fault injected into a verb's run on an object, and the expected result.
#[derive(Clone, Debug)]
pub struct Cell {
    pub lie: String,
    pub verb: String,
    pub object: String,
    pub expect: Expect,
    /// The `before` steps of the cell's block.
    pub before: Vec<Vec<String>>,
}

impl Cell {
    /// Returns `<lie>/<verb>/<object>`.
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

/// Reads `*` (any, returned as `None`) or a list.
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

/// Reads a `row` of an expectation: `{ cap, answer, by }` or `{ cap, absent = true }`.
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

/// Reads block `what` of a table.
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
    /// Reads the table at `path` (relative to the cakeys crate, `crates/cli`).
    ///
    /// # Panics
    ///
    /// Panics when the file cannot be read, or when its content does not have the form of a
    /// table.
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
        let covers = list(doc.get("covers"), "covers");
        Table { path, objects, verbs, lies, blocks, na, units, exempt, exempt_max, state, covers }
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

    /// Returns the cells of fault class `class`.
    pub fn cells_of(&self, class: &str) -> Vec<Cell> {
        self.cells().into_iter().filter(|c| self.lies.get(&c.lie).is_some_and(|l| l.class == class)).collect()
    }

    /// Returns the problems with the table's form, each as a sentence that names where the
    /// problem is.
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
        // An exemption for a rule that a cell or a unit row now names is stale. The exemption
        // must be removed, and `max` must be lowered with it.
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

    /// Returns the problems with one cell: an expectation that the cell's verb cannot show, a
    /// change without a reason, or an object that the verb never runs on.
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

    /// Returns the (fault class, verb, object class) points that no cell covers and no `na`
    /// decides, and each `na` that decides no point.
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
        // An `na` whose points are all covered by cells is stale, because its reason no longer
        // decides anything.
        out.extend(
            used.iter()
                .enumerate()
                .filter(|(_, d)| !**d)
                .map(|(i, _)| format!("na {}: every point it decides is a cell's", i + 1)),
        );
        out
    }

    /// Returns the names in `rules` (the plan's rules, `Rule::ALL`) that no cell names as its
    /// rule or as deferred, that no unit row fires, and that no exemption excuses.
    pub fn uncovered<'a>(&self, rules: &[&'a str]) -> Vec<&'a str> {
        let cells = self.cells();
        let named = |r: &str| {
            cells.iter().any(|c| c.expect.rule.as_deref() == Some(r) || c.expect.deferred.as_deref() == Some(r))
                || self.units.iter().any(|u| u.rule == r)
                || self.exempt.contains_key(r)
        };
        rules.iter().copied().filter(|r| !named(r)).collect()
    }

    /// Returns the rules that the table names (in cells, unit rows and exemptions), so that the
    /// lint can check that each name is a rule or a check.
    pub fn named_rules(&self) -> BTreeSet<String> {
        let cells = self.cells().into_iter().flat_map(|c| [c.expect.rule, c.expect.deferred]).flatten();
        cells.chain(self.units.iter().map(|u| u.rule.clone())).chain(self.exempt.keys().cloned()).collect()
    }
}

/// The token on which a fixture plants its objects, behind the shim, with every object that the
/// fixture makes and the object's decoy.
pub struct Fixture {
    pub w: Workdir,
    /// The module behind the shim.
    pub real: String,
    /// The lock as the fixture left it. Each cell starts from this lock.
    pub planted: Vec<u8>,
}

/// Returns the keys.toml parts of an object of the fixture: its class and type lines, its spec's
/// attributes, and the rest of its `tokens.<token>` table.
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
    /// Plants the table's objects on the token behind the shim, for test `name`. `cakeys create`
    /// makes the keys. The certificate, the data objects and the public key are put on the token
    /// through the module and recorded by `cakeys lock`. None of these runs uses a plan. Next to
    /// each object, the function makes a decoy of the same kind under `<name>-other` through the
    /// module, and no spec names the decoy. It returns `None` (the test is skipped) without
    /// `P11_FAULT_MODULE`. The function checks each run that writes the lock against the runner's
    /// invariants, and adds each violation to `wrong`. With `record`, it traces every such run to
    /// that file with the public values (`P11_FAULT_RECORD_VALUES = public`).
    ///
    /// # Panics
    ///
    /// Panics when a planting step fails.
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

    /// Puts on the token, through the module, the objects other than the keys that cakeys makes:
    /// the certificate, the data objects and the public key under their own labels, and every
    /// decoy.
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
        // A public key object alone under its label. The private half of the pair is under
        // another label (`<name>-key`).
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
                    // Set the public key that the module reports for the key (SoftHSM sets none,
                    // and accepts any).
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

    /// Returns the `P11_FAULT_MODULE` setting that each run passes to the shim: the fixture's
    /// module. Each run sets it, because the process's own `P11_FAULT_MODULE` names the liar
    /// suite's module only, and a fixture such as the one in `tests/tpm2.rs` has another module.
    fn module(&self) -> (&'static str, &Path) {
        ("P11_FAULT_MODULE", Path::new(&self.real))
    }

    /// The lock file.
    pub fn lock(&self) -> PathBuf {
        self.w.dir.join("keys.lock")
    }

    /// Returns the view of the token that a snapshot uses, through the module itself and not
    /// through the shim.
    pub fn view(&self) -> TokenView<'_> {
        TokenView { name: "kmtest", module: &self.real, label: "kmtest", env: &[], db: vec![] }
    }

    /// Runs `args` through the shim under `plan` (a plan file and the trace file; `None` means
    /// no plan), and checks the runner's invariants: the run exits 22 exactly when it changed the
    /// lock, and a `check` changed nothing. Without a plan, `record` traces the run with the
    /// public values. Returns the run, and each invariant that the run broke.
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

    /// Each run sets the shim's module itself ([`Fixture::module`]).
    fn run(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        let env: Vec<(&str, &Path)> = std::iter::once(self.module()).chain(env.iter().copied()).collect();
        self.w.km_env(args, &env)
    }

    /// Returns a snapshot of the lock and the token as they are now.
    fn state(&self) -> Snapshot {
        snapshot(&[&self.lock()], &[self.view()])
    }

    /// Returns the part of [`STATE`] to which a change that [`changes`] names belongs.
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

    /// Checks that the run exits 22 exactly when it changed the lock, and that a `check` changes
    /// nothing.
    fn invariants(&self, args: &[&str], exit: Option<i32>, changed: &BTreeSet<String>) -> Vec<String> {
        let mut wrong = lock_invariant(args, exit, changed);
        if args.contains(&"check") && !changed.is_empty() {
            wrong.push(format!("{args:?}: check changed {changed:?}"));
        }
        wrong
    }

    /// Puts the fixture back, so that every cell starts from it: the lock as planted, and no
    /// object that `create` made left on the token.
    fn restore(&self, table: &Table) {
        std::fs::write(self.lock(), &self.planted).unwrap();
        let unmade: Vec<&str> = table.objects.iter().filter(|(_, o)| !o.made).map(|(n, _)| n.as_str()).collect();
        if !unmade.is_empty() {
            open_session(&self.real, "kmtest", "1234").clear(&unmade);
        }
    }
}

/// The parts of a cell's run that are specific to a tool: how a cell's verb runs, which state it
/// may change, the exit code of a run without a fault, the invariants that every run must keep,
/// and how a cell's state is restored. The shared runner ([`judge`]) does the rest of a cell: its
/// plan, the check that the fault fired, and the checks of the exit code and of the output
/// according to the verb's [`Form`].
pub trait Tool {
    /// Where the cells' plans and traces are written.
    fn dir(&self) -> &Path;
    /// Returns `args` (a verb's arguments, or a `before` step's arguments) filled in for `object`
    /// on this fixture.
    fn fill(&self, table: &Table, args: &[String], object: &str) -> Vec<String>;
    /// Runs `args` with `env` (the shim's plan and trace; an empty `env` means a run without a
    /// fault).
    fn run(&self, args: &[&str], env: &[(&str, &Path)]) -> Output;
    /// Runs a block's `before` step (its arguments filled in as a verb's are) under the cell's
    /// plan.
    fn before(&self, args: &[&str], env: &[(&str, &Path)]) -> Output {
        self.run(args, env)
    }
    /// Returns a snapshot of the state that the runner compares.
    fn state(&self) -> Snapshot;
    /// Returns the part of the table's `state` to which a change that [`changes`] names belongs.
    fn kind(&self, what: &str) -> String;
    /// Returns the exit code of a run of `verb` on `object` when no fault is injected.
    fn honest_exit(&self, table: &Table, verb: &str, object: &str) -> i32;
    /// Returns each invariant of the runner that a run of `args` with exit code `exit` broke,
    /// given the parts of the state that the run changed (each a [`Tool::kind`]).
    fn invariants(&self, args: &[&str], exit: Option<i32>, changed: &BTreeSet<String>) -> Vec<String>;
    /// Puts the fixture back as it was planted.
    fn restore(&self, table: &Table);
    /// Returns the names of the shim's plan and trace variables (a tagged shim has its own,
    /// `docs/FAULT_SHIM.md`).
    fn vars(&self) -> (&'static str, &'static str) {
        ("P11_FAULT_PLAN", "P11_FAULT_TRACE")
    }
}

/// Checks the invariant of a run that writes a lock (CAKEYS.md: "a run that wrote the lock exits
/// 22, never 0"): the run exits 22 exactly when it changed the lock.
pub fn lock_invariant(args: &[&str], exit: Option<i32>, changed: &BTreeSet<String>) -> Vec<String> {
    let lock = changed.contains("lock");
    if (exit == Some(22)) == lock {
        vec![]
    } else {
        vec![format!("{args:?}: exit {exit:?}, and the lock changed: {lock}")]
    }
}

/// Runs `args` with `tool` and `env`, and returns the output and each invariant of the tool that
/// the run broke.
pub fn held(tool: &impl Tool, args: &[&str], env: &[(&str, &Path)]) -> (Output, Vec<String>) {
    let before = tool.state();
    let out = tool.run(args, env);
    let changed = changes(&before, &tool.state(), &args.join(" ")).iter().map(|(what, _)| tool.kind(what)).collect();
    let wrong = tool.invariants(args, out.status.code(), &changed);
    (out, wrong)
}

/// Runs `verb` on `object` through the shim with no plan. The run must exit with the code that
/// [`Tool::honest_exit`] gives, and it must keep the tool's invariants, so it changes the lock
/// only when it writes. Returns each problem.
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

/// Runs `cell` with `tool` and checks the result. Returns each problem, in a line that names the
/// cell.
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
    // Replace `{seq:C_X}` with the `seq` of the run's first call of C_X. A probe run that fails
    // that call finds it, and the fixture is restored after the probe.
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

/// Checks the rows of a verb that prints one row for each pair that it runs ([`Verb::pairs`]).
/// The rows of a refused run end at the refused pair, whose row must name the cell's rule and
/// device bit, and the rows before it must pass. Each row of a run that passes must name the
/// cell's outcome and deferral. `refusal` is the exit code that the refused row must show, or
/// `None` when no pair may be refused.
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

/// Checks the one plan of camigrate's dry run (`--json`): the methods and exposures that it must
/// not name, and the rule that it must defer.
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

/// Checks caprobe's profile (TOML on stdout): each row must be as the cell expects, and each
/// expected `[untested]` entry must be present. A refused probe must print no profile.
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

/// Returns the lines of `trace` whose rule fired. The runner checks them, because a fault that
/// matched nothing would let a cell pass for the wrong reason.
pub fn fired(trace: &Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(trace).unwrap_or_default();
    text.lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|l| !l["rule"].is_null())
        .collect()
}

/// Runs the test of fault class `class` over the cakeys table ([`run_table`]).
///
/// # Panics
///
/// Panics when anything is wrong, and lists every problem.
pub fn run_class(class: &str) {
    let table = Table::cakeys();
    run_table(&table, class, |name, wrong| Fixture::plant(name, &table, None, wrong));
}

/// Runs the test of fault class `class` over `table`. The function plants a new fixture
/// (`plant`, given the test's name; `None` means that the test is skipped). It runs every (verb,
/// object) pair that the cells use without a fault, first before the cells and again after them,
/// and each such run must end as a run without a fault ends, so every refusal in the cells came
/// from the fault. It judges each cell from the planted state, and a cell marked red
/// ([`Expect::red`]) must still fail. Last, it runs without a fault the writes that the cells
/// refused. These writes change the state that the cells kept unchanged, which shows that the
/// comparison in the cells can detect a change. The function runs every cell before it asserts,
/// so one run of the test names every wrong cell.
///
/// # Panics
///
/// Panics when anything is wrong, and lists every problem.
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

/// Does the runs of [`run_table`] for `cells` on the fixture `f` planted from `table`, without an
/// assertion, and returns each problem. The runs without a fault that leave the state unchanged
/// (every run except a write, including a run that is refused) run before and after the cells.
/// The writes run last, and `f` is restored before and after each write.
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
