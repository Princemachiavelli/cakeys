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
//! `tests/liars.rs` runs cakeys' table, one test per lie class ([`run_class`]); the lint
//! (`tests/liar_lint.rs`) holds the table to its rules with no token: no rule of the plan without
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

/// What a cell's state oracle can name: the lock file and the token.
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
}

/// A verb: an entry path a cell runs.
pub struct Verb {
    /// Its arguments, `{spec}` and `{token}` filled per object.
    pub args: Vec<String>,
    /// Whether it prints a row per pair (`lock`, `create`, `delete`): the oracle reads the
    /// rule and the device bit there. One that does not (`check`) prints nothing when refused.
    pub rows: bool,
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
}

/// A block: every (lie, verb, object) of its lists is a cell, with its expectation, but where an
/// override names it.
pub struct Block {
    pub lies: Vec<String>,
    pub verbs: Vec<String>,
    pub objects: Vec<String>,
    pub expect: Expect,
    pub overrides: Vec<Override>,
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
    let known = ["exit", "rule", "deferred", "device", "outcome", "fired", "changed", "why", "red"];
    if let Some(k) = t.keys().find(|k| !known.contains(&k.as_str())) {
        panic!("{what}: expect has no {k}");
    }
    let exit = match t.get("exit") {
        Some(toml::Value::Integer(n)) => vec![i32::try_from(*n).unwrap()],
        Some(toml::Value::Array(a)) => a.iter().map(|n| i32::try_from(n.as_integer().unwrap()).unwrap()).collect(),
        _ => panic!("{what}: expect has no exit"),
    };
    let opt = |k: &str| t.get(k).map(|v| v.as_str().unwrap_or_else(|| panic!("{what}: {k}")).to_owned());
    let flag = |k: &str, default| t.get(k).map_or(default, |v| v.as_bool().unwrap_or_else(|| panic!("{what}: {k}")));
    Expect {
        exit,
        rule: opt("rule"),
        deferred: opt("deferred"),
        device: flag("device", false),
        outcome: opt("outcome"),
        fired: flag("fired", true),
        changed: list(t.get("changed"), what),
        why: opt("why"),
        red: opt("red"),
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
    Block {
        lies: list(t.get("lies"), what),
        verbs: list(t.get("verbs"), what),
        objects: list(t.get("objects"), what),
        expect: expect(t.get("expect").unwrap_or_else(|| panic!("{what}: no expect")), what),
        overrides,
    }
}

impl Table {
    /// The table at `path` (relative to the cakeys crate).
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
                let class = string(t, "class", &format!("objects.{name}"));
                (name, Object { class, token, made, adopted })
            })
            .collect();
        let verbs = section("verbs")
            .into_iter()
            .map(|(name, v)| {
                let t = v.as_table().unwrap_or_else(|| panic!("verbs.{name}"));
                let args = list(t.get("args"), &format!("verbs.{name}"));
                let rows = t.get("rows").and_then(toml::Value::as_bool).unwrap_or(false);
                (name, Verb { args, rows })
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
        Table { path, objects, verbs, lies, blocks, na, units, exempt, exempt_max }
    }

    /// cakeys' own table.
    pub fn cakeys() -> Table {
        Table::load("tests/liars/cakeys.toml")
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
                        out.push(Cell { lie: lie.clone(), verb: verb.clone(), object: object.clone(), expect });
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
            let (Some(verb), Some(object)) = (self.verbs.get(&c.verb), self.objects.get(&c.object)) else { continue };
            let e = &c.expect;
            let refused = e.exit.iter().any(|x| !matches!(x, 0 | 22));
            if !verb.rows && (e.rule.is_some() || e.device || e.outcome.is_some() || e.deferred.is_some()) {
                out.push(format!("{id}: {} prints no row to name a rule, a device or an outcome", c.verb));
            }
            if e.rule.is_some() && !refused {
                out.push(format!("{id}: a rule, and no refusal"));
            }
            if let Some(k) = e.changed.iter().find(|k| !STATE.contains(&k.as_str())) {
                out.push(format!("{id}: changed names {k}: one of {STATE:?}"));
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
        out
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

    /// The lock file.
    pub fn lock(&self) -> PathBuf {
        self.w.dir.join("keys.lock")
    }

    /// The token as a snapshot sees it: through the module itself, not the shim.
    pub fn view(&self) -> TokenView<'_> {
        TokenView { name: "kmtest", module: &self.real, label: "kmtest", env: &[], db: vec![] }
    }

    /// The lock and the token, now.
    fn state(&self) -> Snapshot {
        snapshot(&[&self.lock()], &[self.view()])
    }

    /// Which of [`STATE`] a change named by [`changes`] is.
    fn kind(&self, what: &str) -> &'static str {
        if what == self.lock().display().to_string() { "lock" } else { "token" }
    }

    /// `args` run through the shim under `plan` (none: no plan), traced to `trace`, and the
    /// runner's invariants over it: it exits 22 exactly when it changed the lock, and a `check`
    /// changed nothing. Returns the run, and what broke an invariant.
    pub fn held(&self, args: &[&str], plan: Option<(&Path, &Path)>, record: Option<&Path>) -> (Output, Vec<String>) {
        let before = self.state();
        let mut env: Vec<(&str, &Path)> = Vec::new();
        if let Some((plan, trace)) = plan {
            env.extend([("P11_FAULT_PLAN", plan), ("P11_FAULT_TRACE", trace)]);
        } else if let Some(trace) = record {
            env.extend([("P11_FAULT_TRACE", trace), ("P11_FAULT_RECORD_VALUES", Path::new("public"))]);
        }
        let out = self.w.km_env(args, &env);
        let changed = changes(&before, &self.state(), &args.join(" "));
        let mut wrong = Vec::new();
        let lock_changed = changed.iter().any(|(what, _)| self.kind(what) == "lock");
        if (out.status.code() == Some(22)) != lock_changed {
            wrong.push(format!("{args:?}: exit {:?}, and the lock changed: {lock_changed}", out.status.code()));
        }
        if args.contains(&"check") && !changed.is_empty() {
            wrong.push(format!("{args:?}: check changed {changed:?}"));
        }
        (out, wrong)
    }

    /// The arguments of `verb` on `object`.
    pub fn args(table: &Table, verb: &str, object: &str) -> Vec<String> {
        let token = &table.objects[object].token;
        table.verbs[verb].args.iter().map(|a| a.replace("{spec}", object).replace("{token}", token)).collect()
    }

    /// The exit an honest run of `verb` on `object` has: 22 for a verb that writes (a delete, a
    /// creation of an object not made), else 0.
    fn honest_exit(table: &Table, verb: &str, object: &str) -> i32 {
        let writes = verb == "delete" || (verb == "create" && !table.objects[object].made);
        if writes { 22 } else { 0 }
    }

    /// `verb` on `object` with no plan through the shim: it exits as an honest run does, and
    /// changes nothing unless it writes. What is wrong.
    pub fn honest(&self, table: &Table, verb: &str, object: &str) -> Vec<String> {
        let args = Self::args(table, verb, object);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let (out, mut wrong) = self.held(&args, None, None);
        let want = Self::honest_exit(table, verb, object);
        if out.status.code() != Some(want) {
            wrong.push(format!(
                "honest {verb} of {object}: exit {:?}, not {want}: {}",
                out.status.code(),
                stderr(&out)
            ));
        }
        wrong
    }

    /// Run `cell` and judge it. What is wrong, each line naming the cell.
    pub fn judge(&self, table: &Table, cell: &Cell, n: usize) -> Vec<String> {
        let id = cell.id();
        let e = &cell.expect;
        let verb = &table.verbs[&cell.verb];
        let args = Self::args(table, &cell.verb, &cell.object);
        let mut args: Vec<&str> = args.iter().map(String::as_str).collect();
        if verb.rows {
            args.insert(0, "--json");
        }
        let (plan, trace) = (self.w.dir.join(format!("cell-{n}.toml")), self.w.dir.join(format!("cell-{n}.jsonl")));
        let other = format!("{}-other", cell.object);
        let mut text = table.lies[&cell.lie].plan.replace("{label}", &cell.object).replace("{other}", &other);
        // `{seq:C_X}`: where the run first calls C_X, found by a run that fails that call, after
        // which the fixture is restored.
        while let Some(at) = text.find("{seq:") {
            let end = at + text[at..].find('}').unwrap();
            let function = text[at + 5..end].to_owned();
            let probe = self.w.dir.join(format!("cell-{n}-probe.jsonl"));
            std::fs::write(&plan, format!("[[rule]]\nfn = \"{function}\"\nnth = 1\nrv = \"CKR_DEVICE_REMOVED\"\n"))
                .unwrap();
            let _ = self.w.km_env(&args, &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &probe)]);
            let Some(seq) = fired(&probe).first().and_then(|l| l["seq"].as_u64()) else {
                return vec![format!("{id}: the run never calls {function}")];
            };
            text.replace_range(at..=end, &seq.to_string());
            self.restore(table);
        }
        std::fs::write(&plan, &text).unwrap();
        let before = self.state();
        let mut wrong = Vec::new();
        let out = self.w.km_env(&args, &[("P11_FAULT_PLAN", &plan), ("P11_FAULT_TRACE", &trace)]);
        let after = self.state();
        let said = || {
            format!("{}{}", stdout(&out), stderr(&out).lines().last().map(|l| format!(" / {l}")).unwrap_or_default())
        };
        let exit = out.status.code();
        if exit.is_none_or(|x| !e.exit.contains(&x)) {
            wrong.push(format!("exit {exit:?}, not {:?}", e.exit));
        }
        let changed: BTreeSet<&str> = changes(&before, &after, &id).iter().map(|(what, _)| self.kind(what)).collect();
        if (exit == Some(22)) != changed.contains("lock") {
            wrong.push(format!("exit {exit:?}, and the lock changed: {}", changed.contains("lock")));
        }
        for what in STATE {
            let should = e.changed.iter().any(|c| c == what);
            if changed.contains(what) != should {
                let is = if changed.contains(what) { "changed" } else { "did not change" };
                wrong.push(format!("the {what} {is}"));
            }
        }
        let refused = exit.is_some_and(|x| !matches!(x, 0 | 22));
        if verb.rows {
            match serde_json::from_slice::<Vec<Row>>(&out.stdout) {
                Err(e) => wrong.push(format!("no rows on stdout ({e})")),
                Ok(rows) => match rows.as_slice() {
                    [row] if refused => {
                        let got = (i32::from(row.exit), row.rule.as_deref(), row.device);
                        let want = (exit.unwrap_or(-1), e.rule.as_deref(), e.device);
                        if got != want {
                            wrong.push(format!("the row says (exit, rule, device) {got:?}, not {want:?}"));
                        }
                    }
                    [row] => {
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
                    rows => wrong.push(format!("{} rows, not one", rows.len())),
                },
            }
        } else if refused && !out.stdout.is_empty() {
            wrong.push(format!("a refusal printed {:?}", stdout(&out)));
        }
        let fired = !fired(&trace).is_empty();
        if fired != e.fired {
            wrong.push(format!("the lie fired: {fired}, not {}", e.fired));
        }
        wrong.into_iter().map(|w| format!("{id}: {w}: {}", said())).collect()
    }

    /// Every cell starts from the fixture: the lock as planted, and nothing `create` made left
    /// on the token.
    pub fn restore(&self, table: &Table) {
        std::fs::write(self.lock(), &self.planted).unwrap();
        let unmade: Vec<&str> = table.objects.iter().filter(|(_, o)| !o.made).map(|(n, _)| n.as_str()).collect();
        if !unmade.is_empty() {
            open_session(&self.real, "kmtest", "1234").clear(&unmade);
        }
    }
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

/// The test of lie class `class` over cakeys' table: the fixture planted afresh; every (verb,
/// object) its cells meet run honestly first and again after them, each as an honest run ends
/// (so every refusal below was the lie's); each cell judged from the planted state, a cell marked
/// red ([`Expect::red`]) held to failing; and last,
/// the writes the cells refused done honestly, which change what the cells held unchanged (so
/// the comparison can fail). Every cell is run before any is judged: one run names every wrong
/// one.
///
/// # Panics
///
/// When anything is wrong, listing all of it.
pub fn run_class(class: &str) {
    let table = Table::cakeys();
    let cells = table.cells_of(class);
    assert!(!cells.is_empty(), "no cell of class {class}: its points are na, and its test goes");
    let mut wrong = Vec::new();
    let Some(f) = Fixture::plant(&format!("liars-{}", class.to_lowercase()), &table, None, &mut wrong) else { return };
    let met: BTreeSet<(&str, &str)> = cells.iter().map(|c| (c.verb.as_str(), c.object.as_str())).collect();
    let reads: Vec<(&str, &str)> =
        met.iter().copied().filter(|(v, o)| Fixture::honest_exit(&table, v, o) == 0).collect();
    for (verb, object) in &reads {
        wrong.extend(f.honest(&table, verb, object));
    }
    for (n, cell) in cells.iter().enumerate() {
        let judged = f.judge(&table, cell, n);
        match &cell.expect.red {
            None => wrong.extend(judged),
            Some(red) if judged.is_empty() => wrong.push(format!("{}: marked red ({red}), and passes", cell.id())),
            Some(red) => eprintln!("red as marked ({red}):\n{}", judged.join("\n")),
        }
        f.restore(&table);
    }
    for (verb, object) in &reads {
        wrong.extend(f.honest(&table, verb, object));
    }
    for (verb, object) in met.iter().filter(|(v, o)| Fixture::honest_exit(&table, v, o) == 22) {
        wrong.extend(f.honest(&table, verb, object));
    }
    assert!(
        wrong.is_empty(),
        "{} wrong in the {} cells of {class} and their runs:\n{}",
        wrong.len(),
        cells.len(),
        wrong.join("\n")
    );
}
