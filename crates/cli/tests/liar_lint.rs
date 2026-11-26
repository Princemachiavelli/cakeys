//! The liar tables' rules (docs/archive/REVIEW-2026-11-24/phase2-3-design.md §1.6), with no token:
//! no rule of the plan (`cakeys_core::Rule`) without a cell that fires it, a unit test that does,
//! or an exemption that says why none can; no name that is neither a rule nor a check
//! (`cakeys_core::Check`); every check that a table `covers` named by one of its cells; every
//! (lie class, verb, object class) of a table covered by a cell or decided with why; and a table
//! of the shape its runner reads (`tests/common/liars.rs`). Pure: plain `cargo test`, on every
//! system.

mod common;

use cakeys_core::{Check, Rule};
use common::liars::Table;
use std::path::{Path, PathBuf};

/// The tables, each read by its tool's runner.
fn tables() -> Vec<Table> {
    vec![Table::cakeys(), Table::camigrate(), Table::caprobe(), Table::tpm2()]
}

/// Every rule a plan can refuse by is named by a cell of some table (its `rule`, or a dry run's
/// `deferred`), by a unit row whose test fires it, or by an exemption with its why, under the
/// table's `exempt.max`: a check no liar fires is a finding (review 2026-11-24 C-6).
#[test]
fn every_rule_has_a_liar_that_fires_it() {
    let names: Vec<&str> = Rule::ALL.iter().map(|r| r.name()).collect();
    let tables = tables();
    let uncovered: Vec<&str> =
        names.iter().copied().filter(|r| tables.iter().all(|t| t.uncovered(&[r]).contains(r))).collect();
    assert!(uncovered.is_empty(), "no cell, unit row or exemption names these rules: {uncovered:?}");
    for t in &tables {
        let unknown: Vec<String> =
            t.named_rules().into_iter().filter(|r| Rule::named(r).is_none() && Check::named(r).is_none()).collect();
        assert!(unknown.is_empty(), "{}: names no rule or check: {unknown:?}", t.path.display());
        let unknown: Vec<&String> = t.covers.iter().filter(|c| Check::named(c).is_none()).collect();
        assert!(unknown.is_empty(), "{}: covers no check: {unknown:?}", t.path.display());
        let covers: Vec<&str> = t.covers.iter().map(String::as_str).collect();
        let uncovered = t.uncovered(&covers);
        assert!(uncovered.is_empty(), "{}: no cell names these checks that it covers: {uncovered:?}", t.path.display());
    }
}

/// Each unit row's test is a `fn` in `crates/` whose body names its rule (`Rule::<Variant>` or
/// the name quoted), or whose body asserts its check (`assert_fires` and `Check::<Variant>`): a
/// row cannot point at a test that does not exist, or at one that never meets the rule.
#[test]
fn every_unit_row_names_a_test_that_fires_its_rule() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    sources(&crates, &mut files);
    let texts: Vec<String> = files.iter().filter_map(|f| std::fs::read_to_string(f).ok()).collect();
    let mut wrong = Vec::new();
    for t in tables() {
        for u in &t.units {
            let fires: Vec<String> = match (Rule::named(&u.rule), Check::named(&u.rule)) {
                (Some(rule), _) => vec![format!("Rule::{rule:?}"), format!("\"{}\"", rule.name())],
                (None, Some(check)) => vec![format!("Check::{check:?}")],
                (None, None) => {
                    wrong.push(format!("unit {}: no rule or check {}", u.test, u.rule));
                    continue;
                }
            };
            let check = Check::named(&u.rule).is_some();
            let bodies: Vec<&str> = texts.iter().filter_map(|text| body(text, &u.test)).collect();
            let named =
                |b: &&str| fires.iter().any(|f| b.contains(f.as_str())) && (!check || b.contains("assert_fires("));
            if bodies.is_empty() {
                wrong.push(format!("unit {}: no fn {} in crates/", u.rule, u.test));
            } else if !bodies.iter().any(named) {
                wrong.push(format!("unit {}: fn {} names none of {fires:?}", u.rule, u.test));
            }
            if u.why.trim().is_empty() {
                wrong.push(format!("unit {}: no why", u.rule));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// Every (lie class, verb, object class) of each table is a cell's, or an `na` row decides it
/// with why (C-6's class fix: a lie class never told to a verb was invisible), and the table is
/// of the shape its runner reads: every lie, verb and object a block names exists, every lie is
/// told, no cell is in two blocks, a rule only where a row can name it and a change only with
/// its why, and the exemptions no more than `exempt.max`.
#[test]
fn every_point_of_the_grid_is_a_cell_or_decided() {
    for t in tables() {
        let problems = t.problems();
        assert!(problems.is_empty(), "{}:\n{}", t.path.display(), problems.join("\n"));
        let gaps = t.gaps();
        assert!(gaps.is_empty(), "{}: no cell and no na:\n{}", t.path.display(), gaps.join("\n"));
    }
}

/// Every `.rs` file under `dir`.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() && !path.ends_with("target") {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The body of `fn name` in `text`, braces matched outside string literals.
fn body<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let at = text.find(&format!("fn {name}("))?;
    let open = at + text[at..].find('{')?;
    let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
    for (i, c) in text[open..].char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            '{' if !quoted => depth += 1,
            '}' if !quoted => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[open..=open + i]);
                }
            }
            _ => {}
        }
    }
    None
}
