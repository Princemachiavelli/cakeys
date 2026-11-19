//! Fixtures the lock-rule tests share (`properties.rs`, `lock_mbt.rs`): one token's facts and an
//! empty lock, so a change to `Facts` or `Observation` is made once (review `lock_mbt.rs` F4).
#![allow(dead_code, reason = "each test binary uses a subset")]

use cakeys_core::config::{LOCK_VERSION, Lock, ModuleInfo, Observation, Observed, Session, TokenInfo};
use cakeys_core::reconcile::Facts;

/// What a run saw of its token: a logged-in session on a generic module, no origin.
pub(crate) fn facts() -> Facts {
    Facts {
        observed: Observed { uri: "pkcs11:token=t".into(), session: Session::User },
        observation: Observation {
            provider: Some("generic".into()),
            cakeys_version: Some("0.1.0".into()),
            module: Some(ModuleInfo {
                path: "/m.so".into(),
                hash: None,
                description: "m".into(),
                manufacturer: "x".into(),
                version: "1.0".into(),
                cryptoki: "3.0".into(),
            }),
            token: Some(TokenInfo { model: "m".into(), serial: "1".into(), firmware: "1.0".into() }),
            ..Observation::default()
        },
        origin: None,
    }
}

/// A lock that records nothing yet.
pub(crate) fn empty_lock() -> Lock {
    Lock { version: LOCK_VERSION, ..Default::default() }
}
