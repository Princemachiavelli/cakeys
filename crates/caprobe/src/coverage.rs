//! Coverage as data (docs/PLAN.md A1): profiles/coverage/cakeys.toml gives every row of the spec
//! baseline (every function, mechanism, key type, attribute, object class, return value, flag,
//! …) one status, and is generated, never edited. Test-only, like the baseline's generator:
//!
//! - `used`: a call of cakeys, caprobe or camigrate reached it in the traced test run
//!   (nix/test-tokens.sh with `CAKEYS_TRACE_DIR`: every module behind p11-fault).
//! - `refused`, `out-of-scope`, `gap`: profiles/coverage/manual.toml, hand-kept rules by table
//!   and name pattern, each with its reason (the exit code of a refusal, the OPEN.md item of a
//!   gap). The first rule that matches a row decides it.
//! - `profile`: none of the above, but a capability profile (profiles/modules, layers,
//!   hardware) records it.
//!
//! A row with none of these fails the test, which lists it: a new spec revision or a new code
//! path shows up as a diff. With `CAKEYS_COVERAGE_TRACE` naming a trace directory, the `used`
//! rows come from the trace, and `CAKEYS_UPDATE_COVERAGE=1` rewrites the committed file (and
//! writes `coverage-report.txt`, the tests behind each used row, into the trace directory).
//! Without it, the committed file's own `used` rows stand in for the trace, so every other
//! status is still checked on every run.

use cakeys_profile::Baseline;
use cakeys_profile::baseline::TABLES;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// The programs whose calls count: the three tools, never a test harness, pkcs11-tool,
/// `p11-kit remote` or OpenSSL.
const TOOLS: [&str; 3] = ["cakeys", "caprobe", "camigrate"];

/// The statuses a manual rule may give.
const MANUAL: [&str; 3] = ["refused", "out-of-scope", "gap"];

/// The session flags `C_OpenSession` takes, by value: the trace has the flag word, and `CKF_`
/// values repeat across flag families, so the names are this function's.
const SESSION_FLAGS: [&str; 2] = ["CKF_RW_SESSION", "CKF_SERIAL_SESSION"];

/// A row of the baseline: its table (`functions`, or one of [`TABLES`]) and name.
type Row = (String, String);

/// What the traced run reached: the rows, and for each the tests (`suite/test`) that did.
#[derive(Debug, Default)]
struct Observed {
    rows: BTreeMap<Row, BTreeSet<String>>,
    /// Numbers no baseline row names (vendor mechanisms), by table.
    unnamed: BTreeMap<String, BTreeSet<u64>>,
}

/// A rule of manual.toml.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    table: String,
    /// A name, or a pattern where `*` stands for any run of characters.
    #[serde(rename = "match")]
    pattern: String,
    status: String,
    reason: String,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Manual {
    rule: Vec<Rule>,
}

/// `pattern` (with `*` wildcards) matches all of `name`.
fn glob(pattern: &str, name: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = name.strip_prefix(first) else { return false };
    let parts: Vec<&str> = parts.collect();
    let Some((last, middle)) = parts.split_last() else { return rest.is_empty() };
    for part in middle {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.len() >= last.len() && rest.ends_with(last)
}

/// Every row of `b`, table by table.
fn rows(b: &Baseline) -> Vec<Row> {
    let functions = b.functions.iter().map(|f| ("functions".to_owned(), f.clone()));
    let tables =
        TABLES.iter().flat_map(|t| b.table(t).into_iter().flatten().map(|(n, _)| ((*t).to_owned(), n.clone())));
    functions.chain(tables).collect()
}

/// The names of `table` by value; where several names share one (the flag families), all.
fn by_value(b: &Baseline, table: &str) -> BTreeMap<u64, Vec<String>> {
    let mut map: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for (name, id) in b.table(table).into_iter().flatten() {
        map.entry(*id).or_default().push(name.clone());
    }
    map
}

/// Read every `*.jsonl` under `dir` (the trace of nix/test-tokens.sh: `<suite>/<test>.jsonl`).
fn observe(b: &Baseline, dir: &Path) -> Observed {
    let mut seen = Observed::default();
    let names: BTreeMap<&str, BTreeMap<u64, Vec<String>>> =
        ["mechanisms", "attributes", "objects", "key-types", "certificate-types", "user-types"]
            .into_iter()
            .map(|t| (t, by_value(b, t)))
            .collect();
    let mut files = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for entry in std::fs::read_dir(&d).unwrap_or_else(|e| panic!("{}: {e}", d.display())) {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "jsonl") {
                files.push(path);
            }
        }
    }
    files.sort();
    for file in files {
        let test = file.strip_prefix(dir).unwrap().with_extension("").display().to_string();
        let text = std::fs::read_to_string(&file).unwrap();
        for line in text.lines() {
            let call: serde_json::Value =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("{}: {e}: {line}", file.display()));
            if !call["exe"].as_str().is_some_and(|exe| TOOLS.contains(&exe)) {
                continue;
            }
            let mut add = |table: &str, name: &str| {
                seen.rows.entry((table.to_owned(), name.to_owned())).or_default().insert(test.clone());
            };
            add("functions", call["fn"].as_str().unwrap());
            add("return-values", call["rv"].as_str().unwrap());
            let mut numbers = |table: &str, field: &str| {
                let values = match &call[field] {
                    serde_json::Value::Array(a) => a.iter().filter_map(serde_json::Value::as_u64).collect(),
                    v => v.as_u64().into_iter().collect::<Vec<_>>(),
                };
                for v in values {
                    match names[table].get(&v) {
                        Some(ns) => ns.iter().for_each(|n| add(table, n)),
                        None => _ = seen.unnamed.entry(table.to_owned()).or_default().insert(v),
                    }
                }
            };
            numbers("mechanisms", "mechanism");
            numbers("attributes", "attributes");
            numbers("objects", "class");
            numbers("key-types", "key_type");
            numbers("certificate-types", "certificate_type");
            numbers("user-types", "user");
            if let Some(flags) = call["flags"].as_u64().filter(|_| call["fn"] == "C_OpenSession") {
                for name in SESSION_FLAGS {
                    if b.flags.get(name).is_some_and(|bit| flags & bit != 0) {
                        add("flags", name);
                    }
                }
            }
        }
    }
    seen
}

/// Every `CK?_` name the capability profiles under `profiles` mention.
fn profile_names(profiles: &Path) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for sub in ["modules", "layers", "hardware"] {
        let mut dirs = vec![profiles.join(sub)];
        while let Some(d) = dirs.pop() {
            for entry in std::fs::read_dir(&d).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap();
                let word = |c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_';
                for token in text.split(|c: char| !word(c)) {
                    if token.len() > 4 && token.starts_with("CK") && token.as_bytes()[3] == b'_' {
                        names.insert(token.to_owned());
                    }
                }
            }
        }
    }
    names
}

/// The generated file and the rows nothing classifies (each with why not), from the baseline,
/// the rows a run reached, the manual rules and the profiles' names.
fn generate(
    b: &Baseline,
    used: &BTreeSet<Row>,
    manual: &Manual,
    profiles: &BTreeSet<String>,
) -> Result<String, Vec<String>> {
    let mut problems = Vec::new();
    let rows = rows(b);
    for r in &manual.rule {
        if !MANUAL.contains(&r.status.as_str()) {
            problems.push(format!("manual rule {} {}: status {:?} is not one of {MANUAL:?}", r.table, r.pattern, r.status));
        }
        if r.reason.trim().is_empty() {
            problems.push(format!("manual rule {} {}: no reason", r.table, r.pattern));
        }
        let matched: Vec<&Row> = rows.iter().filter(|(t, n)| *t == r.table && glob(&r.pattern, n)).collect();
        if matched.is_empty() {
            problems.push(format!("manual rule {} {} matches no row", r.table, r.pattern));
        }
        if !r.pattern.contains('*') && matched.iter().any(|row| used.contains(*row)) {
            problems.push(format!("manual rule {} {} names a used row", r.table, r.pattern));
        }
    }
    let mut status: BTreeMap<&str, BTreeMap<&str, &str>> = BTreeMap::new();
    for (table, name) in &rows {
        let row = (table.clone(), name.clone());
        let s = if used.contains(&row) {
            "used"
        } else if let Some(r) = manual.rule.iter().find(|r| r.table == *table && glob(&r.pattern, name)) {
            r.status.as_str()
        } else if profiles.contains(name) {
            "profile"
        } else {
            problems.push(format!("{table} {name}: no status (not traced, no manual rule, in no profile)"));
            continue;
        };
        status.entry(table).or_default().insert(name, s);
    }
    if !problems.is_empty() {
        return Err(problems);
    }
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# Generated by caprobe's coverage test (crates/caprobe/src/coverage.rs) from the traced\n\
         # test run, the spec baseline, the capability profiles and profiles/coverage/manual.toml.\n\
         # Never edit by hand: change manual.toml, or regenerate from a trace (docs/CAPROBE.md,\n\
         # \"Coverage\")."
    );
    let _ = writeln!(s, "baseline = \"{}\"", b.baseline);
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for table in status.values() {
        for s in table.values() {
            *counts.entry(s).or_default() += 1;
        }
    }
    let _ = writeln!(s, "\n[summary]");
    for (k, n) in &counts {
        let _ = writeln!(s, "{k} = {n}");
    }
    for table in std::iter::once("functions").chain(TABLES) {
        let Some(rows) = status.get(table) else { continue };
        let _ = writeln!(s, "\n[{table}]");
        for (name, st) in rows {
            let _ = writeln!(s, "{name} = \"{st}\"");
        }
    }
    Ok(s)
}

/// The rows the committed file marks `used`.
fn committed_used(text: &str) -> BTreeSet<Row> {
    let doc: toml::Table = toml::from_str(text).expect("the committed coverage parses");
    let mut used = BTreeSet::new();
    for (table, rows) in &doc {
        let Some(rows) = rows.as_table().filter(|_| table != "summary") else { continue };
        for (name, st) in rows {
            if st.as_str() == Some("used") {
                used.insert((table.clone(), name.clone()));
            }
        }
    }
    used
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn committed_coverage_is_generated_from_the_trace() {
    let root = repo();
    let b = Baseline::from_toml(&read(&root.join("profiles/baselines/pkcs11-3.2.toml"))).unwrap();
    let path = root.join("profiles/coverage/cakeys.toml");
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    let manual: Manual = toml::from_str(&read(&root.join("profiles/coverage/manual.toml"))).expect("manual.toml");
    let profiles = profile_names(&root.join("profiles"));
    let trace = std::env::var_os("CAKEYS_COVERAGE_TRACE").map(PathBuf::from);
    let used: BTreeSet<Row> = match &trace {
        Some(dir) => {
            let seen = observe(&b, dir);
            assert!(!seen.rows.is_empty(), "no tool call in the trace under {}", dir.display());
            if std::env::var_os("CAKEYS_UPDATE_COVERAGE").is_some() {
                let mut report = String::new();
                for ((table, name), tests) in &seen.rows {
                    let _ = writeln!(report, "{table} {name}: {}", tests.iter().cloned().collect::<Vec<_>>().join(" "));
                }
                for (table, values) in &seen.unnamed {
                    let _ = writeln!(report, "{table}, no baseline name: {values:#x?}");
                }
                std::fs::write(dir.join("coverage-report.txt"), report).unwrap();
            }
            seen.rows.into_keys().collect()
        }
        None => committed_used(&committed),
    };
    let generated = match generate(&b, &used, &manual, &profiles) {
        Ok(g) => g,
        Err(problems) => panic!("{} problems:\n{}", problems.len(), problems.join("\n")),
    };
    if trace.is_some() && std::env::var_os("CAKEYS_UPDATE_COVERAGE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
        return;
    }
    assert!(
        committed == generated,
        "profiles/coverage/cakeys.toml is not what the {} and manual.toml give; regenerate (docs/CAPROBE.md, \"Coverage\")",
        if trace.is_some() { "trace" } else { "committed used rows" },
    );
}

#[test]
fn patterns_match_whole_names() {
    assert!(glob("CKM_SSL3_*", "CKM_SSL3_MD5_MAC"));
    assert!(glob("CKM_*_KEY_GEN", "CKM_AES_KEY_GEN"));
    assert!(!glob("CKM_*_KEY_GEN", "CKM_AES_KEY_GEN_X"));
    assert!(glob("*", "C_Login") && glob("C_Login", "C_Login"));
    assert!(!glob("C_Log", "C_Login") && !glob("CKM_A*B*C", "CKM_AB"));
    assert!(glob("CKM_A*B*C", "CKM_AxBxC") && glob("CKM_*ECDSA*", "CKM_ECDSA"));
}
