//! Coverage as data (docs/PLAN.md A1): spec-coverage/cakeys.toml gives every row of the spec
//! baseline (every function, mechanism, key type, attribute, object class, return value, flag,
//! …) one status, and is generated, never edited. Test-only, like the baseline's generator:
//!
//! - `used`: a call of cakeys, caprobe or camigrate reached it in the traced test run
//!   (nix/test-tokens.sh with `CAKEYS_TRACE_DIR`: every module behind p11-fault).
//! - `refused`, `out-of-scope`, `gap`: spec-coverage/manual.toml, hand-kept rules by table
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

/// The flag families, by the trace field that carries a flag word of each: `CKF_` values repeat
/// across families, so a set bit is named within its own (pkcs11t.h's sections).
const FLAG_FAMILIES: [(&str, &[&str]); 5] = [
    ("flags", &["CKF_RW_SESSION", "CKF_SERIAL_SESSION", "CKF_ASYNC_SESSION"]),
    ("init_flags", &["CKF_LIBRARY_CANT_CREATE_OS_THREADS", "CKF_OS_LOCKING_OK"]),
    ("slot_flags", &["CKF_TOKEN_PRESENT", "CKF_REMOVABLE_DEVICE", "CKF_HW_SLOT"]),
    (
        "token_flags",
        &[
            "CKF_RNG",
            "CKF_WRITE_PROTECTED",
            "CKF_LOGIN_REQUIRED",
            "CKF_USER_PIN_INITIALIZED",
            "CKF_RESTORE_KEY_NOT_NEEDED",
            "CKF_CLOCK_ON_TOKEN",
            "CKF_PROTECTED_AUTHENTICATION_PATH",
            "CKF_DUAL_CRYPTO_OPERATIONS",
            "CKF_TOKEN_INITIALIZED",
            "CKF_SECONDARY_AUTHENTICATION",
            "CKF_USER_PIN_COUNT_LOW",
            "CKF_USER_PIN_FINAL_TRY",
            "CKF_USER_PIN_LOCKED",
            "CKF_USER_PIN_TO_BE_CHANGED",
            "CKF_SO_PIN_COUNT_LOW",
            "CKF_SO_PIN_FINAL_TRY",
            "CKF_SO_PIN_LOCKED",
            "CKF_SO_PIN_TO_BE_CHANGED",
            "CKF_ERROR_STATE",
            "CKF_SEED_RANDOM_REQUIRED",
            "CKF_ASYNC_SESSION_SUPPORTED",
        ],
    ),
    (
        "mechanism_flags",
        &[
            "CKF_HW",
            "CKF_MESSAGE_ENCRYPT",
            "CKF_MESSAGE_DECRYPT",
            "CKF_MESSAGE_SIGN",
            "CKF_MESSAGE_VERIFY",
            "CKF_MULTI_MESSAGE",
            "CKF_FIND_OBJECTS",
            "CKF_ENCRYPT",
            "CKF_DECRYPT",
            "CKF_DIGEST",
            "CKF_SIGN",
            "CKF_SIGN_RECOVER",
            "CKF_VERIFY",
            "CKF_VERIFY_RECOVER",
            "CKF_GENERATE",
            "CKF_GENERATE_KEY_PAIR",
            "CKF_WRAP",
            "CKF_UNWRAP",
            "CKF_DERIVE",
            "CKF_EC_F_P",
            "CKF_EC_F_2M",
            "CKF_EC_ECPARAMETERS",
            "CKF_EC_OID",
            "CKF_EC_UNCOMPRESS",
            "CKF_EC_COMPRESS",
            "CKF_EC_CURVENAME",
            "CKF_ENCAPSULATE",
            "CKF_DECAPSULATE",
            "CKF_EXTENSION",
        ],
    ),
];

/// A row of the baseline: its table (`functions`, or one of [`TABLES`]) and name.
type Row = (String, String);

/// What the traced run reached: the rows, and for each the tests (`suite/test`) that did.
#[derive(Debug, Default)]
struct Observed {
    rows: BTreeMap<Row, BTreeSet<String>>,
    /// What no baseline row names, by table: vendor mechanism numbers (hex), vendor return
    /// values, functions the baseline lacks. Listed in the report, never a row.
    unnamed: BTreeMap<String, BTreeSet<String>>,
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
    #[serde(default)]
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
    let names: BTreeMap<&str, BTreeMap<u64, Vec<String>>> = [
        "mechanisms",
        "attributes",
        "objects",
        "key-types",
        "certificate-types",
        "user-types",
        "generators",
        "sources",
        "kdfs",
    ]
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
        let calls = std::fs::read_to_string(&file).unwrap();
        for line in calls.lines() {
            let call: serde_json::Value =
                serde_json::from_str(line).unwrap_or_else(|e| panic!("{}: {e}: {line}", file.display()));
            if !call["exe"].as_str().is_some_and(|exe| TOOLS.contains(&exe)) {
                continue;
            }
            let mut add = |table: &str, name: &str| {
                seen.rows.entry((table.to_owned(), name.to_owned())).or_default().insert(test.clone());
            };
            // How the program loaded the module: the shim answers it itself, untraced.
            add("functions", "C_GetFunctionList");
            for (table, name) in
                [("functions", call["fn"].as_str().unwrap()), ("return-values", call["rv"].as_str().unwrap())]
            {
                let in_baseline = match table {
                    "functions" => b.functions.contains(name),
                    _ => b.return_values.contains_key(name),
                };
                if in_baseline {
                    add(table, name);
                } else {
                    seen.unnamed.entry(table.to_owned()).or_default().insert(name.to_owned());
                }
            }
            // The names of `table` with `field`'s values, among those starting with `prefix`
            // (a table whose values repeat across uses: CKG_ holds the MGFs and the IV
            // generators, CKZ_ the OAEP and the PBKDF2 sources).
            let mut numbers = |table: &str, field: &str, prefix: &str| {
                let values = match &call[field] {
                    serde_json::Value::Array(a) => a.iter().filter_map(serde_json::Value::as_u64).collect(),
                    v => v.as_u64().into_iter().collect::<Vec<_>>(),
                };
                for v in values {
                    let matching: Vec<&String> =
                        names[table].get(&v).into_iter().flatten().filter(|n| n.starts_with(prefix)).collect();
                    if matching.is_empty() {
                        seen.unnamed.entry(table.to_owned()).or_default().insert(format!("{v:#x}"));
                    }
                    for n in matching {
                        add(table, n);
                    }
                }
            };
            numbers("mechanisms", "mechanism", "CKM_");
            numbers("attributes", "attributes", "CKA_");
            numbers("objects", "class", "CKO_");
            numbers("key-types", "key_type", "CKK_");
            numbers("certificate-types", "certificate_type", "CKC_");
            numbers("user-types", "user", "CKU_");
            // From mechanism parameters: the hash inside OAEP or PSS is a mechanism too.
            numbers("mechanisms", "hash", "CKM_");
            numbers("generators", "mgf", "CKG_MGF1_");
            numbers("sources", "source", "CKZ_DATA_SPECIFIED");
            numbers("kdfs", "kdf", "CKD_");
            for (field, family) in FLAG_FAMILIES {
                let Some(word) = call[field].as_u64() else { continue };
                for name in family {
                    if b.flags.get(*name).is_some_and(|bit| word & bit != 0) {
                        add("flags", name);
                    }
                }
            }
        }
    }
    seen
}

/// The keys whose values are prose (why, and from where): a `CK?_` name there is mentioned, not
/// recorded. The `[notes]` and `[manual]` tables' values are prose too; their keys are not.
const PROSE: [&str; 4] = ["evidence", "finding", "note", "requires-provider"];

/// Every `CK?_` name the capability profiles under `profiles` record: in a row's key, a list
/// (`advertise`, `add`, `subtract`, `key-types`) or a value (`class`, `via`), never in a
/// comment or a prose field ([`PROSE`]).
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
                let doc: toml::Value =
                    toml::from_str(&read(&path)).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                recorded_names(&doc, false, &mut names);
            }
        }
    }
    names
}

/// The `CK?_` names in `v`'s keys, and in its strings unless they are `prose`.
fn recorded_names(v: &toml::Value, prose: bool, names: &mut BTreeSet<String>) {
    match v {
        toml::Value::String(s) if !prose => names.extend(ck_names(s)),
        toml::Value::Array(a) => a.iter().for_each(|v| recorded_names(v, prose, names)),
        toml::Value::Table(t) => {
            for (k, v) in t {
                names.extend(ck_names(k));
                let prose = prose || PROSE.contains(&k.as_str()) || k == "notes" || k == "manual";
                recorded_names(v, prose, names);
            }
        }
        _ => {}
    }
}

/// The `CK?_` words of `text`.
fn ck_names(text: &str) -> impl Iterator<Item = String> + '_ {
    let word = |c: char| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_';
    text.split(move |c: char| !word(c))
        .filter(|t| t.len() > 4 && t.starts_with("CK") && t.as_bytes()[3] == b'_')
        .map(str::to_owned)
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
            problems
                .push(format!("manual rule {} {}: status {:?} is not one of {MANUAL:?}", r.table, r.pattern, r.status));
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
        } else if !matched.is_empty() && matched.iter().all(|row| used.contains(*row)) {
            // A wildcard whose every row is used decides nothing: it names used rows only.
            problems.push(format!("manual rule {} {} names used rows only", r.table, r.pattern));
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
         # test run, the spec baseline, the capability profiles and spec-coverage/manual.toml.\n\
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
    let path = root.join("spec-coverage/cakeys.toml");
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    let manual: Manual = toml::from_str(&read(&root.join("spec-coverage/manual.toml"))).expect("manual.toml");
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
                    let values = values.iter().cloned().collect::<Vec<_>>().join(" ");
                    let _ = writeln!(report, "{table}, no baseline name: {values}");
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
        "spec-coverage/cakeys.toml is not what the {} and manual.toml give; regenerate (docs/CAPROBE.md, \"Coverage\")",
        if trace.is_some() { "trace" } else { "committed used rows" },
    );
}

/// Every flag the families name is a baseline flag, and none is named in two families.
#[test]
fn flag_families_name_baseline_flags_once() {
    let b = Baseline::from_toml(&read(&repo().join("profiles/baselines/pkcs11-3.2.toml"))).unwrap();
    let mut named = BTreeSet::new();
    for (_, family) in FLAG_FAMILIES {
        for name in family {
            assert!(b.flags.contains_key(*name), "{name} is not a baseline flag");
            assert!(named.insert(*name), "{name} is in two families");
        }
    }
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

/// A name a profile only mentions — in a comment, evidence, a finding or a note — is not one it
/// records: only keys, lists and values give a row the status `profile` (review coverage F1).
#[test]
fn profiles_record_names_outside_their_prose() {
    let doc: toml::Value = toml::from_str(
        r#"
        # CKM_IN_A_COMMENT
        profile = "x/1.0"
        advertise = ["CKM_LISTED"]
        [subtract]
        mechanisms = ["CKM_SUBTRACTED"]
        note = "drops CKM_IN_A_NOTE"
        [capabilities]
        "generate.CKK_IN_A_KEY.secp256r1" = { answer = "no", evidence = "C_GenerateKeyPair: CKR_IN_EVIDENCE" }
        [[migration.public-accepts]]
        class = "CKO_IN_A_VALUE"
        [notes]
        "CKM_NOTED" = "advertised but refused: CKR_IN_A_NOTE_VALUE"
        [manual."x"]
        finding = "CKA_IN_A_FINDING"
        "#,
    )
    .unwrap();
    let mut names = BTreeSet::new();
    recorded_names(&doc, false, &mut names);
    let want = ["CKM_LISTED", "CKM_SUBTRACTED", "CKK_IN_A_KEY", "CKO_IN_A_VALUE", "CKM_NOTED"];
    assert_eq!(names, want.into_iter().map(str::to_owned).collect());
}

fn rule(table: &str, pattern: &str) -> Rule {
    Rule { table: table.into(), pattern: pattern.into(), status: "gap".into(), reason: "why".into() }
}

/// A wildcard manual rule whose every row is used fails, as a plain name of a used row does:
/// it decides nothing (review coverage F2).
#[test]
fn a_wildcard_rule_over_used_rows_only_fails() {
    let b = Baseline::from_toml(&read(&repo().join("profiles/baselines/pkcs11-3.2.toml"))).unwrap();
    let all: BTreeSet<Row> = rows(&b).into_iter().collect();
    let manual = Manual { rule: vec![rule("functions", "C_Log*")] };
    assert_eq!(
        generate(&b, &all, &manual, &BTreeSet::new()).unwrap_err(),
        ["manual rule functions C_Log* names used rows only"]
    );
    // One of its rows not used: the rule decides it.
    let mut used = all.clone();
    used.remove(&("functions".to_owned(), "C_Login".to_owned()));
    assert!(generate(&b, &used, &manual, &BTreeSet::new()).is_ok());
}

/// A traced function or return value the baseline does not name is listed as unnamed, as a
/// vendor mechanism is, never a row the report drops (review coverage F3).
#[test]
fn traced_names_outside_the_baseline_are_unnamed() {
    let b = Baseline::from_toml(&read(&repo().join("profiles/baselines/pkcs11-3.2.toml"))).unwrap();
    let dir = std::env::temp_dir().join(format!("caprobe-coverage-unnamed-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("suite")).unwrap();
    let lines = [
        r#"{"exe":"cakeys","fn":"C_Login","rv":"CKR_OK"}"#,
        r#"{"exe":"cakeys","fn":"C_VendorThing","rv":"0x80000001","mechanism":2147483649}"#,
    ];
    std::fs::write(dir.join("suite/test.jsonl"), lines.join("\n")).unwrap();
    let seen = observe(&b, &dir);
    std::fs::remove_dir_all(&dir).unwrap();
    let row = |t: &str, n: &str| (t.to_owned(), n.to_owned());
    assert!(
        seen.rows.contains_key(&row("functions", "C_Login")) && seen.rows.contains_key(&row("return-values", "CKR_OK"))
    );
    assert!(!seen.rows.contains_key(&row("functions", "C_VendorThing")));
    assert!(!seen.rows.contains_key(&row("return-values", "0x80000001")));
    let unnamed = |t: &str| seen.unnamed[t].iter().cloned().collect::<Vec<_>>();
    assert_eq!(
        (unnamed("functions"), unnamed("return-values"), unnamed("mechanisms")),
        (vec!["C_VendorThing".to_owned()], vec!["0x80000001".to_owned()], vec!["0x80000001".to_owned()])
    );
}
