//! The object matrix (`tests/object_matrix/`) on the reference token.

use super::*;

#[path = "../object_matrix/mod.rs"]
mod object_matrix;

#[test]
fn object_matrix_is_the_committed_one() {
    let Some(e) = env("object-matrix") else { return };
    // Through p11-fault it would repeat SoftHSM's table.
    if REF.through_fault_shim {
        return;
    }
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
