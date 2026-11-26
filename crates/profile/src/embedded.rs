//! The profile files that this build ships (docs/CAPROBE.md D11). They are committed under
//! profiles/ and embedded in the binary, so the binary can answer queries without the source
//! checkout. They are listed explicitly. To add a new profile, add its file and an entry here,
//! and nothing else.

/// The embedded baselines: (path for messages, content).
pub const BASELINE_FILES: &[(&str, &str)] =
    &[("profiles/baselines/pkcs11-3.2.toml", include_str!("../../../profiles/baselines/pkcs11-3.2.toml"))];

/// The embedded profiles (layers, hardware, modules): (path for messages, content).
pub const PROFILE_FILES: &[(&str, &str)] = &[
    ("profiles/hardware/swtpm.toml", include_str!("../../../profiles/hardware/swtpm.toml")),
    ("profiles/layers/cryptoki.toml", include_str!("../../../profiles/layers/cryptoki.toml")),
    ("profiles/layers/p11-kit.toml", include_str!("../../../profiles/layers/p11-kit.toml")),
    (
        "profiles/modules/aws-cloudhsm/5.18+hsm2m-fips.toml",
        include_str!("../../../profiles/modules/aws-cloudhsm/5.18+hsm2m-fips.toml"),
    ),
    // This profile comes after the FIPS profile of the same module. PKCS#11 reports no FIPS
    // mode, so the two profiles match a module equally, and resolution then selects the first.
    (
        "profiles/modules/aws-cloudhsm/5.18+hsm2m-non-fips.toml",
        include_str!("../../../profiles/modules/aws-cloudhsm/5.18+hsm2m-non-fips.toml"),
    ),
    // The FIPS build comes first, as for CloudHSM. The two builds report the same C_GetInfo, so
    // they match equally, and resolution selects the first.
    ("profiles/modules/kmsp11/1.9+hsm-fips.toml", include_str!("../../../profiles/modules/kmsp11/1.9+hsm-fips.toml")),
    ("profiles/modules/kmsp11/1.9+hsm.toml", include_str!("../../../profiles/modules/kmsp11/1.9+hsm.toml")),
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
