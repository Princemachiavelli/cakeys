//! docs/CONFIG.md's annotated example loads as written (review 2026-11-23 A-15: it said so, and
//! no test loaded it).

use std::path::Path;

/// The first `toml` block after "An annotated example" is a keys.toml that loads, with no
/// environment: load checks a `$NAME` reference's form, and only reading the file needs it set.
#[test]
fn the_annotated_config_example_loads() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/CONFIG.md");
    let doc = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let after = &doc[doc.find("## An annotated example").expect("CONFIG.md has its annotated example")..];
    let start = after.find("```toml\n").expect("the example is a toml block") + "```toml\n".len();
    let text = &after[start..start + after[start..].find("```").expect("the block ends")];
    let cfg = cakeys_core::config::parse_config_with(text, Path::new("keys.toml"), &|_| None)
        .unwrap_or_else(|e| panic!("docs/CONFIG.md's example does not load: {e}"));
    assert!(!cfg.specs.is_empty() && !cfg.tokens.is_empty(), "the example names no specs or tokens");
}
