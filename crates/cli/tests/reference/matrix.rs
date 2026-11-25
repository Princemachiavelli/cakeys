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
