//! The object matrix (docs/PLAN.md A4; docs/OPEN.md, "A matrix of what can be created, and at
//! what assurance"): what cakeys makes of objects it did not create. A fixed grid of objects is
//! created on the reference token straight through cryptoki, generated or imported as a legacy
//! key would arrive; each is declared exactly as it is (its usage bits, sensitivity,
//! extractability, per-use PIN and allowed mechanisms) and realised. The outcome per object —
//! the mode, schemes and binding recorded, or the exit code, or the token refusing to hold such
//! an object — is profiles/coverage/objects/<token>.toml, generated and pinned:
//! `CAKEYS_UPDATE_OBJECTS=$PWD/profiles/coverage/objects` rewrites it there
//! (`scripts/local-tests.sh -E 'test(object_matrix)'`).
//! What each refused row printed is in the test's directory, `report.txt`.

use super::*;
use cryptoki::object::KeyType;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The kinds of object the grid holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Aes,
    Des3,
    Generic,
    HmacSha256,
    Ec,
    Rsa,
    Ed25519,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Aes => "aes",
            Kind::Des3 => "des3",
            Kind::Generic => "generic",
            Kind::HmacSha256 => "hmac-sha256",
            Kind::Ec => "ec-p256",
            Kind::Rsa => "rsa-2048",
            Kind::Ed25519 => "ed25519",
        }
    }

    fn secret(self) -> bool {
        matches!(self, Kind::Aes | Kind::Des3 | Kind::Generic | Kind::HmacSha256)
    }

    /// The usage bits a row may set: for a secret key the ones a commitment uses, then the ones
    /// no commitment can (an unwrap-only or derive-only key); for a private key its operations.
    fn usage(self) -> &'static [&'static str] {
        match self {
            Kind::Aes => &["CKA_SIGN", "CKA_ENCRYPT", "CKA_DECRYPT", "CKA_WRAP"],
            Kind::Des3 => &["CKA_ENCRYPT", "CKA_DECRYPT"],
            Kind::Generic | Kind::HmacSha256 | Kind::Ed25519 => &["CKA_SIGN"],
            Kind::Ec => &["CKA_SIGN", "CKA_DERIVE", "CKA_UNWRAP"],
            Kind::Rsa => &["CKA_SIGN", "CKA_DECRYPT", "CKA_UNWRAP"],
        }
    }

    /// The `CKA_ALLOWED_MECHANISMS` a row may carry (besides none): one the identity uses, one
    /// it does not.
    fn allowed(self) -> &'static [&'static str] {
        match self {
            Kind::Aes => &["CKM_AES_CMAC", "CKM_AES_ECB", "CKM_AES_GCM"],
            Kind::Des3 => &["CKM_DES3_ECB", "CKM_DES3_CBC_PAD"],
            Kind::Generic | Kind::HmacSha256 => &["CKM_SHA256_HMAC", "CKM_SHA_1_HMAC"],
            Kind::Ec => &["CKM_ECDSA", "CKM_ECDH1_DERIVE"],
            Kind::Rsa => &["CKM_SHA256_RSA_PKCS", "CKM_RSA_PKCS", "CKM_RSA_PKCS_OAEP"],
            Kind::Ed25519 => &["CKM_EDDSA"],
        }
    }

    /// The keys.toml object of this kind.
    fn object(self) -> &'static str {
        match self {
            Kind::Aes => "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_AES\"\nvalueLen = 32",
            Kind::Des3 => "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_DES3\"",
            Kind::Generic => "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_GENERIC_SECRET\"\nvalueLen = 32",
            Kind::HmacSha256 => "class = \"CKO_SECRET_KEY\"\nkeyType = \"CKK_SHA256_HMAC\"\nvalueLen = 32",
            Kind::Ec => "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC\"\ncurve = \"secp256r1\"",
            Kind::Rsa => "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_RSA\"\nmodulusBits = 2048",
            Kind::Ed25519 => "class = \"CKO_PRIVATE_KEY\"\nkeyType = \"CKK_EC_EDWARDS\"\ncurve = \"edwards25519\"",
        }
    }
}

/// How the object came to be on the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    /// `C_GenerateKey` or `C_GenerateKeyPair`: `CKA_LOCAL` true.
    Generated,
    /// `C_CreateObject` with a value: `CKA_LOCAL` false, as an imported legacy key.
    Imported,
}

/// One object of the grid.
#[derive(Clone, Debug)]
struct Row {
    kind: Kind,
    origin: Origin,
    /// The usage bits set; the kind's others are false.
    usage: Vec<&'static str>,
    extractable: bool,
    sensitive: bool,
    always_authenticate: bool,
    allowed: Option<&'static str>,
}

impl Row {
    /// The row's key in the table: every dimension, in a fixed order.
    fn key(&self) -> String {
        let origin = match self.origin {
            Origin::Generated => "generated",
            Origin::Imported => "imported",
        };
        let usage = if self.usage.is_empty() {
            "none".to_owned()
        } else {
            self.usage.iter().map(|u| u.trim_start_matches("CKA_")).collect::<Vec<_>>().join("+")
        };
        let mut key = format!(
            "{} {origin} usage={usage} {}extractable {}sensitive",
            self.kind.name(),
            if self.extractable { "" } else { "non-" },
            if self.sensitive { "" } else { "non-" },
        );
        if self.always_authenticate {
            key.push_str(" always-authenticate");
        }
        if let Some(m) = self.allowed {
            let _ = write!(key, " allowed={m}");
        }
        key
    }

    /// The spec's declared attributes: exactly what the object carries.
    fn attributes(&self) -> String {
        let mut attrs: Vec<String> =
            self.kind.usage().iter().map(|u| format!("{u} = {}", self.usage.contains(u))).collect();
        attrs.push(format!("CKA_EXTRACTABLE = {}", self.extractable));
        attrs.push(format!("CKA_SENSITIVE = {}", self.sensitive));
        if self.always_authenticate {
            attrs.push("CKA_ALWAYS_AUTHENTICATE = true".into());
        }
        if let Some(m) = self.allowed {
            attrs.push(format!("CKA_ALLOWED_MECHANISMS = [\"{m}\"]"));
        }
        attrs.join(", ")
    }

    /// A private key's binding, as its spec's author would choose it from what the key may do:
    /// signing first (the default), then deriving (EC) or decrypting (RSA), else the token's
    /// word (DESIGN.md §3.6). Secret keys have none.
    fn binding(&self) -> &'static str {
        let may = |bit| self.usage.contains(&bit);
        match self.kind {
            _ if self.kind.secret() || may("CKA_SIGN") => "",
            Kind::Ec if may("CKA_DERIVE") => ", binding = \"pop-ecdh\"",
            Kind::Rsa if may("CKA_DECRYPT") => ", binding = \"pop-decrypt\"",
            _ => ", binding = \"token-asserted\"",
        }
    }
}

/// The grid. Secret keys: every subset of the commitment bits, plus unwrap-only and derive-only
/// (the keys DESIGN.md §3.4 refuses); every extractable × sensitive; generated and imported.
/// Private keys: every subset of their operations, with and without a per-use PIN; generated.
/// Each also unrestricted and under each allowed-mechanism variant.
fn grid() -> Vec<Row> {
    let mut rows = Vec::new();
    for kind in [Kind::Aes, Kind::Des3, Kind::Generic, Kind::HmacSha256, Kind::Ec, Kind::Rsa, Kind::Ed25519] {
        let bits = kind.usage();
        let mut usages: Vec<Vec<&'static str>> = (0..1u32 << bits.len())
            .map(|mask| bits.iter().enumerate().filter(|(i, _)| mask & (1 << i) != 0).map(|(_, b)| *b).collect())
            .collect();
        if kind.secret() {
            usages.push(vec!["CKA_UNWRAP"]);
            usages.push(vec!["CKA_DERIVE"]);
        }
        let origins: &[Origin] =
            if kind.secret() { &[Origin::Generated, Origin::Imported] } else { &[Origin::Generated] };
        let protections: &[(bool, bool)] = if kind.secret() {
            &[(false, true), (true, true), (true, false), (false, false)]
        } else {
            &[(false, true)]
        };
        let authentications: &[bool] = if kind.secret() { &[false] } else { &[false, true] };
        let allowed: Vec<Option<&'static str>> =
            std::iter::once(None).chain(kind.allowed().iter().copied().map(Some)).collect();
        for &origin in origins {
            for usage in &usages {
                for &(extractable, sensitive) in protections {
                    for &always_authenticate in authentications {
                        for &allowed in &allowed {
                            rows.push(Row {
                                kind,
                                origin,
                                usage: usage.clone(),
                                extractable,
                                sensitive,
                                always_authenticate,
                                allowed,
                            });
                        }
                    }
                }
            }
        }
    }
    rows
}

/// The mechanism of a `CKM_` name the grid uses.
fn mechanism(name: &str) -> MechanismType {
    match name {
        "CKM_AES_CMAC" => MechanismType::AES_CMAC,
        "CKM_AES_ECB" => MechanismType::AES_ECB,
        "CKM_AES_GCM" => MechanismType::AES_GCM,
        "CKM_DES3_ECB" => MechanismType::DES3_ECB,
        "CKM_DES3_CBC_PAD" => MechanismType::DES3_CBC_PAD,
        "CKM_SHA256_HMAC" => MechanismType::SHA256_HMAC,
        "CKM_SHA_1_HMAC" => MechanismType::SHA1_HMAC,
        "CKM_ECDSA" => MechanismType::ECDSA,
        "CKM_ECDH1_DERIVE" => MechanismType::ECDH1_DERIVE,
        "CKM_SHA256_RSA_PKCS" => MechanismType::SHA256_RSA_PKCS,
        "CKM_RSA_PKCS" => MechanismType::RSA_PKCS,
        "CKM_RSA_PKCS_OAEP" => MechanismType::RSA_PKCS_OAEP,
        "CKM_EDDSA" => MechanismType::EDDSA,
        other => panic!("no mechanism {other} in the grid"),
    }
}

/// The attribute of a usage bit's name, set to `on`.
fn usage_attribute(name: &str, on: bool) -> Attribute {
    match name {
        "CKA_SIGN" => Attribute::Sign(on),
        "CKA_ENCRYPT" => Attribute::Encrypt(on),
        "CKA_DECRYPT" => Attribute::Decrypt(on),
        "CKA_WRAP" => Attribute::Wrap(on),
        "CKA_UNWRAP" => Attribute::Unwrap(on),
        "CKA_DERIVE" => Attribute::Derive(on),
        other => panic!("no usage bit {other} in the grid"),
    }
}

/// Create `row`'s object on the token, labelled `label`, or say why the token would not
/// (the return value's name).
fn create(s: &Session, row: &Row, label: &str) -> Result<(), String> {
    let usage = |set: &[&str]| -> Vec<Attribute> {
        // Every usage bit the kind has, and the two a secret key's grid adds, set as the row says.
        let mut names: Vec<&str> = row.kind.usage().to_vec();
        if row.kind.secret() {
            names.extend(["CKA_UNWRAP", "CKA_DERIVE"]);
        }
        names.dedup();
        names.into_iter().map(|n| usage_attribute(n, set.contains(&n))).collect()
    };
    let mut private = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Extractable(row.extractable),
        Attribute::Sensitive(row.sensitive),
    ];
    private.extend(usage(&row.usage));
    if row.always_authenticate {
        private.push(Attribute::AlwaysAuthenticate(true));
    }
    if let Some(m) = row.allowed {
        private.push(Attribute::AllowedMechanisms(vec![mechanism(m)]));
    }
    let failed = |e: cryptoki::error::Error| match e {
        cryptoki::error::Error::Pkcs11(rv, _) => format!("{rv:?}"),
        other => other.to_string(),
    };
    let (key_type, len, keygen) = match row.kind {
        Kind::Aes => (KeyType::AES, 32, Mechanism::AesKeyGen),
        Kind::Des3 => (KeyType::DES3, 24, Mechanism::Des3KeyGen),
        Kind::Generic => (KeyType::GENERIC_SECRET, 32, Mechanism::GenericSecretKeyGen),
        // PKCS#11 3.0's own generation for the type (SoftHSM 2.7 has none: not created there).
        Kind::HmacSha256 => (KeyType::SHA256_HMAC, 32, Mechanism::Sha256KeyGen),
        Kind::Ec | Kind::Rsa | Kind::Ed25519 => {
            let public = vec![
                Attribute::Token(true),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Verify(row.usage.contains(&"CKA_SIGN")),
            ];
            let (mechanism, public) = match row.kind {
                Kind::Ec => {
                    (Mechanism::EccKeyPairGen, [public, vec![Attribute::EcParams(P256_PARAMS.to_vec())]].concat())
                }
                Kind::Ed25519 => (
                    Mechanism::EccEdwardsKeyPairGen,
                    [public, vec![Attribute::EcParams(ED25519_PARAMS.to_vec())]].concat(),
                ),
                _ => (
                    Mechanism::RsaPkcsKeyPairGen,
                    [public, vec![Attribute::ModulusBits(2048.into()), Attribute::PublicExponent(vec![1, 0, 1])]]
                        .concat(),
                ),
            };
            return s.generate_key_pair(&mechanism, &public, &private).map(|_| ()).map_err(failed);
        }
    };
    let mut secret = vec![Attribute::Class(cryptoki::object::ObjectClass::SECRET_KEY), Attribute::KeyType(key_type)];
    secret.extend(private);
    match row.origin {
        Origin::Generated => {
            if row.kind != Kind::Des3 {
                secret.push(Attribute::ValueLen(len.into()));
            }
            s.generate_key(&keygen, &secret).map(|_| ()).map_err(failed)
        }
        Origin::Imported => {
            // The token's own randomness: a key nothing relies on.
            let value = s.generate_random_vec(u32::try_from(len).unwrap()).map_err(failed)?;
            secret.push(Attribute::Value(value));
            s.create_object(&secret).map(|_| ()).map_err(failed)
        }
    }
}

/// The DER `CKA_EC_PARAMS` of the grid's curves: the named curve's OID.
const P256_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const ED25519_PARAMS: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];

/// What realising a row gave: what the lock recorded, or the exit code.
fn outcome(w: &Workdir, spec: &str) -> Result<String, (i32, String)> {
    let o = w.km(&["realise", spec, "--token", "ref", "--update-lock"]);
    if code(&o) != 0 {
        return Err((code(&o), stderr(&o)));
    }
    let r = &w.lock()["realisations"][spec]["ref"];
    let mut got = r["mode"].as_str().unwrap().to_owned();
    let schemes: Vec<&str> = r["schemes"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
    let _ = write!(got, " {}", schemes.join(","));
    if let Some(b) = r.get("binding").and_then(toml::Value::as_str) {
        let _ = write!(got, " {b}");
    }
    Ok(got)
}

#[test]
fn object_matrix_is_the_committed_one() {
    let Some(e) = env("object-matrix") else { return };
    // Through p11-fault it would repeat SoftHSM's table.
    if REF.through_fault_shim {
        return;
    }
    let rows = grid();
    // Create every object first, in one session.
    let created: Vec<Result<(), String>> = {
        let s = e.session();
        rows.iter().enumerate().map(|(i, row)| create(&s, row, &format!("m{i}"))).collect()
    };
    let results: Mutex<Vec<Option<String>>> = Mutex::new(vec![None; rows.len()]);
    let report: Mutex<Vec<(usize, String)>> = Mutex::new(Vec::new());
    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(row) = rows.get(i) else { break };
                    let got = if let Err(rv) = &created[i] {
                        format!("not created: {rv}")
                    } else {
                        let w = Workdir::new(&format!("object-matrix-{i}"));
                        w.write_config(&format!(
                            "{}\n[objects.o]\n{}\n\n[specs.m]\nobject = \"o\"\nattributes = {{ {} }}\n\
                                 tokens.ref = {{ locator = {{ CKA_LABEL = \"m{i}\" }}, origin = \"adopt\"{} }}\n",
                            reference_tokens(&e.module, &w.dir),
                            row.kind.object(),
                            row.attributes(),
                            row.binding(),
                        ));
                        match outcome(&w, "m") {
                            Ok(got) => got,
                            Err((code, said)) => {
                                report.lock().unwrap().push((i, said));
                                format!("exit {code}")
                            }
                        }
                    };
                    results.lock().unwrap()[i] = Some(got);
                }
            });
        }
    });
    let results = results.into_inner().unwrap();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut table = String::new();
    for (row, got) in rows.iter().zip(&results) {
        let got = got.as_deref().unwrap();
        let class = got.split_whitespace().next().unwrap();
        *counts.entry(if class == "not" { "not created" } else { class }).or_default() += 1;
        let _ = writeln!(table, "{:?} = {:?}", row.key(), got);
    }
    let mut text = format!(
        "# Generated by the object-matrix test (crates/cli/tests/reference/matrix.rs) on {}: what\n\
         # cakeys makes of objects it did not create. Never edit: CAKEYS_UPDATE_OBJECTS=<dir> rewrites it.\n\
         # Each row: the mode, schemes and binding recorded; or the exit code; or the token's refusal.\n\
         token = \"{}\"\n\n[summary]\n",
        REF.provider, REF.provider
    );
    for (k, n) in &counts {
        let _ = writeln!(text, "{k:?} = {n}");
    }
    let _ = write!(text, "\n[rows]\n{table}");
    let mut said = String::new();
    for (i, s) in report.into_inner().unwrap().into_iter().collect::<BTreeMap<_, _>>() {
        let _ = writeln!(said, "## {}\n{s}", rows[i].key());
    }
    std::fs::write(e.dir.join("report.txt"), said).unwrap();
    let file = format!("{}.toml", REF.provider);
    // The directory to rewrite the table in: the repository's, from wherever the test runs
    // (scripts/local-tests.sh runs a copy of the tree).
    if let Some(dir) = std::env::var_os("CAKEYS_UPDATE_OBJECTS") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(Path::new(&dir).join(&file), &text).unwrap();
        return;
    }
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles/coverage/objects").join(&file);
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == text,
        "{} is not what the grid gives on this token (report: {}); regenerate with \
         CAKEYS_UPDATE_OBJECTS=$PWD/profiles/coverage/objects",
        path.display(),
        e.dir.join("report.txt").display()
    );
}
