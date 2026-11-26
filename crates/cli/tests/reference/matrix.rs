//! The object matrix (`tests/object_matrix/`) on the reference token. Beside the reference suite,
//! not in it: `tests/softhsm.rs` and `tests/kryoptic.rs` include it, `tests/fault.rs` does not,
//! where through p11-fault it would be `SoftHSM`'s table again (review 2026-11-24 C-11: it was a
//! skip there, by design, and passed).

use crate::REF;
use crate::common::*;
use crate::reference::env;

#[path = "../object_matrix/mod.rs"]
mod object_matrix;

#[test]
fn object_matrix_is_the_committed_one() {
    let Some(e) = env("object-matrix") else { return };
    object_matrix::check(&object_matrix::Target {
        name: REF.provider,
        token: "ref",
        tokens: &|dir| reference_tokens(&e.module, dir),
        session: &|| e.session(),
        batch: usize::MAX,
        dir: &e.dir,
        workers: std::thread::available_parallelism().map_or(4, |n| n.get().min(8)),
    });
}

/// Every committed table keeps the properties (`object_matrix/properties.rs`): no token, so on
/// every build and platform, the tables of tokens this one is not included.
#[test]
fn every_committed_table_keeps_the_properties() {
    let tables = object_matrix::properties::committed();
    assert!(tables.len() >= 3, "{:?}", tables.iter().map(|(n, _)| n).collect::<Vec<_>>());
    for (name, table) in tables {
        let broken = object_matrix::properties::violations(&table);
        assert!(broken.is_empty(), "spec-coverage/objects/{name}:\n{}", broken.join("\n"));
    }
}

/// Each property fails on its row flipped in a copy of this token's committed table, and only
/// the flip makes it fail: none holds vacuously.
#[test]
fn each_property_fails_on_its_row_flipped() {
    let path = format!("spec-coverage/objects/{}.toml", REF.provider);
    let (_, table) =
        object_matrix::properties::committed().into_iter().find(|(n, _)| path.ends_with(n.as_str())).unwrap();
    for (property, row, outcome) in object_matrix::properties::FLIPS {
        let broken = object_matrix::properties::violations(&object_matrix::properties::flipped(&table, row, outcome));
        assert!(
            broken.iter().any(|b| b.starts_with(&format!("{property}: "))),
            "{path}: {row:?} = {outcome:?} breaks no {property}: {broken:?}"
        );
    }
}
