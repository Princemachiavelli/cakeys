//! The rows a per-object verb prints (`lock`, `create`, `delete`, and their dry runs): one shape
//! for every pair, whether it passed or failed, so a caller reads what happened to each from the
//! rows alone (review 2026-11-24 C-1).

use super::*;

/// The keys every row carries, a passing one's and a failing one's.
const ROW: [&str; 6] = ["object", "spec", "token", "outcome", "exit", "device"];

/// Each row of `o`'s JSON array, checked to carry [`ROW`]: (spec, outcome, exit, rule).
fn rows(o: &Output) -> Vec<(String, String, u64, Option<String>)> {
    let rows: Vec<serde_json::Value> =
        serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", stdout(o)));
    rows.iter()
        .map(|r| {
            for key in ROW {
                assert!(r.get(key).is_some(), "no {key:?} in {r}");
            }
            assert_eq!(r["device"].as_bool(), Some(false), "{r}");
            assert_eq!(r["exit"].as_u64() == Some(0), r.get("error").is_none(), "a failure says why: {r}");
            let s = |k: &str| r[k].as_str().map(str::to_owned);
            (s("spec").unwrap(), s("outcome").unwrap(), r["exit"].as_u64().unwrap(), s("rule"))
        })
        .collect()
}

/// `lock`, `create` and `delete`, each once passing and once failing, and their dry runs: every
/// pair has its row, the failing one with its exit code and the rule that refused it; the run
/// exits with that code. A `lock` and a `delete` row once lacked `exit`, a passing `lock` row
/// `outcome` too, and `create` printed no row for a failure (review 2026-11-24 C-1).
#[test]
fn every_pair_has_a_row_of_one_shape() {
    let Some(e) = env("rows") else { return };
    let s = e.session();
    s.create_object(&cert_object(ADOPT_CERT, b"rows-taken", None)).unwrap();
    let key = |name: &str, label: &str, origin: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"{origin}\" }}\n\n"
        )
    };
    e.config(
        &(key("a", "rows-a", "create") + &key("lost", "rows-nowhere", "adopt") + &key("taken", "rows-taken", "create")),
    );
    let row = |spec: &str, outcome: &str, exit: u64, rule: Option<&str>| {
        (spec.to_owned(), outcome.to_owned(), exit, rule.map(str::to_owned))
    };

    // create: a passing pair, then one refused on the token, and its dry run.
    let o = e.km(&["create", "--spec", "a", "--token", "ref"]);
    assert_eq!((code(&o), rows(&o)), (22, vec![row("a", "created", 0, None)]), "{}", stderr(&o));
    let o = e.km(&["create", "--spec", "a", "--token", "ref"]);
    assert_eq!((code(&o), rows(&o)), (0, vec![row("a", "verified", 0, None)]), "{}", stderr(&o));
    for dry in [true, false] {
        let args = ["create", "--spec", "taken", "--token", "ref"];
        let o = e.km(if dry { [&args[..], &["--dry-run"]].concat() } else { args.to_vec() }.as_slice());
        let want = row("taken", if dry { "refuse" } else { "failed" }, 13, Some("locator-free"));
        assert_eq!((code(&o), rows(&o)), (13, vec![want]), "dry {dry}: {}", stderr(&o));
    }

    // lock: two pairs, the passing one's row before the failing one's.
    for dry in [true, false] {
        let args = ["lock", "a", "lost", "--token", "ref"];
        let o = e.km(if dry { [&args[..], &["--dry-run"]].concat() } else { args.to_vec() }.as_slice());
        let got = rows(&o);
        assert_eq!(code(&o), 11, "dry {dry}: {}", stderr(&o));
        assert_eq!(got.iter().map(|r| (r.0.as_str(), r.2)).collect::<Vec<_>>(), [("a", 0), ("lost", 11)], "{got:?}");
    }

    // delete: refused by If-Match, then done.
    let o = e.km(&["delete", "--spec", "a", "--token", "ref", "--if-match", "sha256-AAAA"]);
    assert_eq!((code(&o), rows(&o)), (14, vec![row("a", "failed", 14, Some("if-match"))]), "{}", stderr(&o));
    let o = e.km(&["delete", "--spec", "a", "--token", "ref", "--dry-run"]);
    assert_eq!((code(&o), rows(&o)), (0, vec![row("a", "would-delete", 0, None)]), "{}", stderr(&o));
    let o = e.km(&["delete", "--spec", "a", "--token", "ref"]);
    assert_eq!((code(&o), rows(&o)), (22, vec![row("a", "deleted", 0, None)]), "{}", stderr(&o));
}

/// This test checks that a run that wrote the lock exits 22 even if a later pair fails. It runs
/// `create`, `lock` and `delete` on two pairs each. The first pair writes the lock (a key is
/// created and recorded, a key is locked, a realisation is removed), and the token refuses the
/// second pair. Each run must exit 22 and print both rows, the refused row with its own exit code
/// and rule, and the lock must hold the first pair's change and nothing for the second pair. Each
/// dry run must write nothing and exit with the refusal's code. Before review 2026-11-24 L5, such
/// a run exited with the refusal's code, so a script that reviews the lock on exit 22 missed the
/// change (CAKEYS.md, "Exit codes").
#[test]
fn a_run_that_wrote_the_lock_exits_22_whatever_failed_after() {
    let Some(e) = env("partial") else { return };
    // Put a certificate under the locator of `taken`, so that `create` of `taken` is refused on
    // the token with 13 (rule locator-free).
    e.session().create_object(&cert_object(ADOPT_CERT, b"partial-taken", None)).unwrap();
    let key = |name: &str, label: &str, origin: &str| {
        format!(
            "[objects.{name}]\nclass = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"\n\n\
             [specs.{name}]\nobject = \"{name}\"\nattributes = {{ CKA_SIGN = true }}\n\
             tokens.ref = {{ locator = {{ CKA_LABEL = \"{label}\" }}, origin = \"{origin}\" }}\n\n"
        )
    };
    let mut body = String::new();
    for (name, origin) in [("a", "create"), ("b", "create"), ("c", "create"), ("taken", "create"), ("lost", "adopt")] {
        body += &key(name, &format!("partial-{name}"), origin);
    }
    e.config(&body);
    // Create b and c on the token without recording them in the lock (each run exits 18, a first
    // use). The `lock` run records b, and the `delete` run refuses c with 14 because the lock has
    // no expected ID for it.
    for spec in ["b", "c"] {
        assert_eq!(e.code(&["create", spec, "--token", "ref", "--no-update-lock"]), 18, "{spec}");
    }
    let recorded = |spec: &str| e.lock()["realisations"].get(spec).is_some_and(|r| r.get("ref").is_some());
    let row = |spec: &str, outcome: &str, exit: u64, rule: Option<&str>| {
        (spec.to_owned(), outcome.to_owned(), exit, rule.map(str::to_owned))
    };
    // Each entry holds the run's arguments, the dry run's rows, the run's rows, the dry run's
    // exit code, and whether the lock records each spec after the run.
    let table = [
        (
            vec!["create", "a", "taken"],
            vec![row("a", "create", 0, None), row("taken", "refuse", 13, Some("locator-free"))],
            vec![row("a", "created", 0, None), row("taken", "failed", 13, Some("locator-free"))],
            13,
            [("a", true), ("taken", false)],
        ),
        (
            vec!["lock", "b", "lost"],
            vec![row("b", "failed", 18, None)],
            vec![row("b", "locked", 0, None), row("lost", "failed", 11, None)],
            18,
            [("b", true), ("lost", false)],
        ),
        (
            vec!["delete", "a", "c"],
            vec![row("a", "would-delete", 0, None), row("c", "failed", 14, Some("if-match"))],
            vec![row("a", "deleted", 0, None), row("c", "failed", 14, Some("if-match"))],
            14,
            [("a", false), ("c", false)],
        ),
    ];
    // Run every verb and collect every mismatch, so that the failure message lists all of them.
    let mut wrong = Vec::new();
    for (verb, dry_rows, run_rows, dry_exit, after) in table {
        let args = [&verb[..], &["--token", "ref"]].concat();
        let lock = || std::fs::read(e.dir.join("keys.lock")).unwrap();
        let before = lock();
        let o = e.km(&[&args[..], &["--dry-run"]].concat());
        if (code(&o), rows(&o)) != (dry_exit, dry_rows.clone()) || lock() != before {
            wrong.push(format!(
                "{verb:?} --dry-run: exit {}, rows {:?}, the lock written: {}",
                code(&o),
                rows(&o),
                lock() != before
            ));
        }
        let o = e.km(&args);
        if (code(&o), rows(&o)) != (22, run_rows.clone()) || lock() == before {
            wrong.push(format!(
                "{verb:?}: exit {}, rows {:?}, the lock written: {}",
                code(&o),
                rows(&o),
                lock() != before
            ));
        }
        for (spec, want) in after.into_iter().filter(|(spec, want)| recorded(spec) != *want) {
            wrong.push(format!("{verb:?}: the lock records {spec}: {}, not {want}", !want));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert!(!e.session().labelled("partial-c").is_empty(), "the refused delete destroyed the object of c");
}
