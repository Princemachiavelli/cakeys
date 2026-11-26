//! Lists every rule that a write checks (`cakeys_pkcs11::ops::Rule`), and where camigrate enforces
//! it (docs/archive/REVIEW-2026-11-24/phase1-design.md §1.4, T-4). For each rule, the list names
//! the tests that run it on camigrate's entry paths (`migrate`, `export`, and `import` of a
//! bundle, of a key file or of objects' own files), both in a dry run and in a real run, or it
//! says why none of those paths meets the rule. The `match` has no wildcard, so a new rule without
//! its case does not compile. These tests need no token.

use cakeys_pkcs11::ops::Rule;

/// Where camigrate enforces a rule.
enum Held {
    /// These tests enforce it, given as (`file` under the package, `fn`). Each test runs the rule
    /// in a dry run and in a real run.
    By(&'static [(&'static str, &'static str)]),
    /// No entry path of camigrate meets the rule, for the given reason.
    NotMet(&'static str),
}

fn held(rule: Rule) -> Held {
    match rule {
        Rule::Placement => Held::By(&[("tests/dry_run.rs", "placement_is_planned_where_a_move_lands")]),
        Rule::AttestationCover => Held::By(&[("tests/dry_run.rs", "exports_plan_against_their_target_either_way")]),
        Rule::ImportedAttestation => {
            Held::By(&[("tests/from_files.rs", "an_import_the_provider_cannot_attest_is_refused_before_the_write")])
        }
        Rule::OwnGeneration => Held::NotMet("camigrate generates nothing: a move creates what it imports"),
        Rule::Templates => Held::By(&[("src/tokens.rs", "a_plan_asks_the_providers_what_the_move_sends")]),
        Rule::Capability => Held::By(&[("tests/dry_run.rs", "export_plans_follow_each_sides_capabilities")]),
        Rule::LocatorFree => Held::By(&[
            ("tests/dry_run.rs", "an_occupied_locator_is_planned"),
            ("tests/dry_run.rs", "objects_sharing_a_locator_move_in_any_order"),
        ]),
        Rule::UnpinnedExists | Rule::PinnedLost => {
            Held::NotMet("`create`'s: camigrate lands only what the lock pins, on a pair that says import or file")
        }
        Rule::NeedsLogin => Held::By(&[("tests/dry_run.rs", "a_target_without_a_pin_is_refused_before_any_plan")]),
        Rule::IfMatch | Rule::DeleteRefused | Rule::DeleteKept => {
            Held::NotMet("`delete`'s: camigrate removes only what its own run just made")
        }
        Rule::LockWritable => Held::By(&[("tests/dry_run.rs", "a_lock_that_cannot_be_saved_mid_run_keeps_the_rows")]),
    }
}

/// Checks that each rule is enforced by tests that exist, or is stated as not met.
#[test]
fn every_rule_is_held_or_said_not_to_be_met() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for &rule in Rule::ALL {
        match held(rule) {
            Held::By(tests) => {
                assert!(!tests.is_empty(), "{}: held by no test", rule.name());
                for (file, name) in tests {
                    let text = std::fs::read_to_string(root.join(file)).unwrap();
                    assert!(text.contains(&format!("fn {name}()")), "{}: {file} has no test {name}", rule.name());
                }
            }
            Held::NotMet(why) => assert!(!why.is_empty(), "{}", rule.name()),
        }
    }
}
