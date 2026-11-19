//! Every verb and flag of `cakeys` is used by an integration test (tests/common/surface.rs).

mod common;

/// Verbs and flags no integration test uses yet, each with why.
const UNTESTED: &[(&str, &str)] = &[];

#[test]
fn every_verb_and_flag_is_used_by_a_test() {
    let tests = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    common::surface::assert_covered(&cakeys::command(), &tests, UNTESTED);
}
