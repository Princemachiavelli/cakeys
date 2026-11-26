//! Checks that an integration test uses every verb and flag of `camigrate`
//! (crates/cli/tests/common/surface.rs).

#[path = "../../cli/tests/common/mod.rs"]
mod common;

/// The verbs and flags that no integration test uses yet, each with the reason.
const UNTESTED: &[(&str, &str)] = &[];

#[test]
fn every_verb_and_flag_is_used_by_a_test() {
    let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    common::surface::assert_covered(&camigrate::command(), &tests, UNTESTED);
}
