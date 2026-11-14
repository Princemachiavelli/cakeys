//! The files this build ships (docs/CAPROBE.md D11): committed under profiles/, embedded so
//! the binary answers without the checkout, and listed explicitly — a new profile is an entry
//! here plus the file, and nothing else.

/// The embedded baselines: (path for messages, content).
pub const BASELINE_FILES: &[(&str, &str)] =
    &[("profiles/baselines/pkcs11-3.2.toml", include_str!("../../../profiles/baselines/pkcs11-3.2.toml"))];

/// The embedded profiles (layers, hardware, modules): (path for messages, content).
pub const PROFILE_FILES: &[(&str, &str)] = &[
    ("profiles/hardware/swtpm.toml", include_str!("../../../profiles/hardware/swtpm.toml")),
    ("profiles/layers/cryptoki.toml", include_str!("../../../profiles/layers/cryptoki.toml")),
    ("profiles/layers/p11-kit.toml", include_str!("../../../profiles/layers/p11-kit.toml")),
    ("profiles/modules/kryoptic/1.5.toml", include_str!("../../../profiles/modules/kryoptic/1.5.toml")),
    ("profiles/modules/softhsm/2.7.toml", include_str!("../../../profiles/modules/softhsm/2.7.toml")),
    (
        "profiles/modules/tpm2-pkcs11/1.10+amd-ftpm.toml",
        include_str!("../../../profiles/modules/tpm2-pkcs11/1.10+amd-ftpm.toml"),
    ),
    (
        "profiles/modules/tpm2-pkcs11/1.10+swtpm.toml",
        include_str!("../../../profiles/modules/tpm2-pkcs11/1.10+swtpm.toml"),
    ),
    ("profiles/modules/ykcs11/2.7.toml", include_str!("../../../profiles/modules/ykcs11/2.7.toml")),
];
