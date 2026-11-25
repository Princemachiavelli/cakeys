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
