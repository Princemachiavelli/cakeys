//! What every object matrix table must say, whatever the code under test makes of the grid
//! (review 2026-11-24 C-8: the tables are written by that code, so comparing with them detects a
//! change, never an error). Each property is derived from DESIGN.md, cakeys' spec, or from
//! PKCS #11, never from a table. [`check`](super::check) holds a token's fresh table to them
//! before it compares or regenerates it; `reference/matrix.rs` holds every committed table to
//! them on every build, and sees each fail on its row flipped in a copy.
#![allow(dead_code, reason = "tests/tpm2.rs holds its fresh table to them, reference/matrix.rs every committed one")]

use std::collections::BTreeMap;

/// A row's key, read back into the grid's dimensions.
struct Key<'a> {
    kind: &'a str,
    /// `generated` or `imported` (a key), else none.
    origin: Option<&'a str>,
    /// Where an imported private key's public half is.
    public: Option<&'a str>,
    usage: Vec<&'a str>,
    extractable: bool,
    always_authenticate: bool,
    allowed: Option<&'a str>,
    /// A certificate's or data object's `CKA_PRIVATE`, and whether its spec declares it.
    privacy: (bool, bool),
    /// The certificate (`malformed`, or its key) or the data object's length.
    what: &'a str,
}

impl<'a> Key<'a> {
    fn parse(key: &'a str) -> Key<'a> {
        let words: Vec<&str> = key.split(' ').collect();
        let mut k = Key {
            kind: words[0],
            origin: None,
            public: None,
            usage: Vec::new(),
            extractable: false,
            always_authenticate: false,
            allowed: None,
            privacy: (words.get(2) == Some(&"private"), !key.ends_with(" undeclared")),
            what: words.get(1).copied().unwrap_or_default(),
        };
        for w in &words[1..] {
            match *w {
                "generated" | "imported" => k.origin = Some(w),
                "extractable" => k.extractable = true,
                "always-authenticate" => k.always_authenticate = true,
                "usage=none" => {}
                _ if w.starts_with("usage=") => k.usage = w["usage=".len()..].split('+').collect(),
                _ if w.starts_with("public=") => k.public = Some(&w["public=".len()..]),
                _ if w.starts_with("allowed=") => k.allowed = Some(&w["allowed=".len()..]),
                _ => {}
            }
        }
        k
    }

    fn private(&self) -> bool {
        self.privacy.0
    }

    fn declared(&self) -> bool {
        self.privacy.1
    }

    fn secret(&self) -> bool {
        matches!(self.kind, "aes" | "des3" | "generic" | "hmac-sha256")
    }

    fn private_key(&self) -> bool {
        matches!(self.kind, "ec-p256" | "rsa-2048" | "ed25519")
    }

    fn may(&self, bit: &str) -> bool {
        self.usage.contains(&bit)
    }

    /// The commitment schemes of the key's type, strongest first, each with the usage bit and
    /// mechanism it needs (DESIGN.md §3.1). A generic secret has no hash of its own: the grid
    /// names SHA-256 as the one its identity uses.
    fn schemes(&self) -> &'static [(&'static str, &'static str, &'static str)] {
        match self.kind {
            "aes" => &[
                ("cmac", "SIGN", "CKM_AES_CMAC"),
                ("kcv-ecb", "ENCRYPT", "CKM_AES_ECB"),
                ("kcv-ecb-dec", "DECRYPT", "CKM_AES_ECB"),
                ("kw", "WRAP", "CKM_AES_KEY_WRAP"),
            ],
            "des3" => &[("kcv-ecb", "ENCRYPT", "CKM_DES3_ECB"), ("kcv-ecb-dec", "DECRYPT", "CKM_DES3_ECB")],
            "generic" | "hmac-sha256" => &[("commitment", "SIGN", "CKM_SHA256_HMAC")],
            _ => &[],
        }
    }

    /// The commitments the declared usage bits allow and the declared allowed list does too
    /// (DESIGN.md §3.1, §3.4).
    fn usable(&self) -> Vec<&'static str> {
        let allows = |m: &str| self.allowed.is_none_or(|a| a == m);
        self.schemes().iter().filter(|(_, bit, m)| self.may(bit) && allows(m)).map(|(s, ..)| *s).collect()
    }

    /// The binding a private key's spec declares (DESIGN.md §3.6, as the grid declares it).
    fn binding(&self) -> &'static str {
        match self.kind {
            _ if self.may("SIGN") => "pop-sign",
            "ec-p256" if self.may("DERIVE") => "pop-ecdh",
            "rsa-2048" if self.may("DECRYPT") => "pop-decrypt",
            _ => "token-asserted",
        }
    }

    /// The mechanisms the declared binding proves with (DESIGN.md §3.6); none for
    /// `token-asserted`, which proves nothing.
    fn proofs(&self) -> &'static [&'static str] {
        match (self.kind, self.binding()) {
            ("ec-p256", "pop-sign") => &["CKM_ECDSA_SHA256", "CKM_ECDSA"],
            ("ed25519", "pop-sign") => &["CKM_EDDSA"],
            ("rsa-2048", "pop-sign") => &[
                "CKM_SHA256_RSA_PKCS",
                "CKM_RSA_PKCS",
                "CKM_SHA384_RSA_PKCS",
                "CKM_SHA512_RSA_PKCS",
                "CKM_RSA_PKCS_PSS",
                "CKM_SHA256_RSA_PKCS_PSS",
                "CKM_SHA384_RSA_PKCS_PSS",
                "CKM_SHA512_RSA_PKCS_PSS",
            ],
            ("ec-p256", "pop-ecdh") => &["CKM_ECDH1_DERIVE"],
            ("rsa-2048", "pop-decrypt") => &["CKM_RSA_PKCS_OAEP", "CKM_RSA_PKCS"],
            _ => &[],
        }
    }
}

/// A row's outcome, read back.
#[derive(PartialEq, Eq)]
enum Outcome<'a> {
    Exit(u8),
    /// The token refused to hold the object: nothing of cakeys is in it.
    NotCreated,
    Identified {
        mode: &'a str,
        schemes: Vec<&'a str>,
        binding: Option<&'a str>,
    },
}

impl<'a> Outcome<'a> {
    fn parse(outcome: &'a str) -> Outcome<'a> {
        if let Some(code) = outcome.strip_prefix("exit ") {
            return Outcome::Exit(code.parse().unwrap_or(u8::MAX));
        }
        if outcome.starts_with("not created") {
            return Outcome::NotCreated;
        }
        let mut words = outcome.split(' ');
        let mode = words.next().unwrap_or_default();
        let schemes = words.next().unwrap_or_default().split(',').collect();
        let binding = words.find(|w| !w.starts_with("immutables="));
        Outcome::Identified { mode, schemes, binding }
    }

    fn identified(&self) -> bool {
        matches!(self, Outcome::Identified { .. })
    }

    fn mode(&self) -> Option<&str> {
        match self {
            Outcome::Identified { mode, .. } => Some(mode),
            _ => None,
        }
    }

    /// Refused at load (17), or never on the token at all.
    fn refused(&self) -> bool {
        matches!(self, Outcome::Exit(17) | Outcome::NotCreated)
    }
}

/// Whether `o` identified the object: a free function, so its lifetimes are its own.
fn identified(o: &Outcome<'_>) -> bool {
    o.identified()
}

/// A property of one row: `Err` says how the row breaks it.
type Rule = fn(&Key<'_>, &Outcome<'_>) -> Result<(), String>;

/// The part of a row's key a property varies, as it is spelled there; none where it does not
/// apply.
type Dimension = fn(&Key<'_>) -> Option<String>;

/// The properties of one row: name, source, rule.
const ROWS: &[(&str, &str, Rule)] = &[
    (
        "mode-by-class",
        "DESIGN.md §3.4: direct for public material, commitment or wrap-rebind for a secret key",
        |k, o| match o.mode() {
            Some(m) if k.secret() && !matches!(m, "commitment" | "wrap-rebind") => {
                Err(format!("a secret key is never {m}"))
            }
            Some(m) if !k.secret() && m != "direct" => Err(format!("public material is direct, not {m}")),
            _ => Ok(()),
        },
    ),
    ("schemes-by-class", "DESIGN.md §3.1, scheme strength: the schemes of each class, strongest first", |k, o| {
        let Outcome::Identified { schemes, .. } = o else { return Ok(()) };
        let want: Vec<&str> = match k.kind {
            "ec-p256" | "rsa-2048" | "ed25519" => vec!["rfc7093m4"],
            "data" => vec!["valuehash"],
            "certificate" if k.what == "malformed" => vec!["certhash"],
            "certificate" => vec!["certhash", "rfc7093m4"],
            _ => k.schemes().iter().map(|(s, ..)| *s).filter(|s| schemes.contains(s)).collect(),
        };
        if *schemes == want && !want.is_empty() { Ok(()) } else { Err(format!("schemes {want:?}")) }
    }),
    (
        "commitment-computes-only-what-is-declared",
        "DESIGN.md §3.1: which commitments are computed follows the declared usage bits; §3.4: and the declared CKA_ALLOWED_MECHANISMS",
        |k, o| match o {
            Outcome::Identified { mode: "commitment", schemes, .. }
                if schemes.iter().any(|s| !k.usable().contains(s)) =>
            {
                Err(format!("the declaration allows only {:?}", k.usable()))
            }
            _ => Ok(()),
        },
    ),
    (
        "a-declared-commitment-is-used",
        "DESIGN.md §3.4: a secret key whose declaration allows a commitment is identified by commitment",
        |k, o| {
            if !k.secret() || k.usable().is_empty() || !(o.mode() == Some("wrap-rebind") || *o == Outcome::Exit(17)) {
                return Ok(());
            }
            Err(format!("its declaration allows {:?}", k.usable()))
        },
    ),
    (
        "wrap-rebind-only-without-a-commitment",
        "DESIGN.md §3.4: wrap-rebind is for extractable secret keys without such bits",
        |k, o| {
            if o.mode() == Some("wrap-rebind") && !(k.extractable && k.usable().is_empty()) {
                return Err("only an extractable key with no declared commitment".into());
            }
            Ok(())
        },
    ),
    (
        "nothing-to-identify-by-is-refused",
        "DESIGN.md §3.4: a secret key that fits no mode is refused at validation (17)",
        |k, o| {
            if k.secret() && !k.extractable && k.usable().is_empty() && !o.refused() {
                return Err("non-extractable, with no declared commitment: 17".into());
            }
            Ok(())
        },
    ),
    (
        "wrap-rebind-computes-every-scheme",
        "DESIGN.md §3.4: the session copy allows every scheme of its type, and every one is computed",
        |k, o| {
            let Outcome::Identified { mode: "wrap-rebind", schemes, .. } = o else { return Ok(()) };
            let every: Vec<&str> = k.schemes().iter().map(|(s, ..)| *s).collect();
            if *schemes == every { Ok(()) } else { Err(format!("every scheme: {every:?}")) }
        },
    ),
    (
        "a-proof-the-list-allows",
        "DESIGN.md §3.6: a binding whose mechanisms the declared list allows none of is refused at load (17); review 2026-11-24 A-10",
        |k, o| match k.allowed {
            Some(m) if k.private_key() && !k.proofs().is_empty() && !k.proofs().contains(&m) && !o.refused() => {
                Err(format!("{} proves by {:?}, which {m} is none of: 17", k.binding(), k.proofs()))
            }
            _ => Ok(()),
        },
    ),
    (
        "a-per-use-pin-only-signs",
        "DESIGN.md §3.6: the other proofs have no per-use login, so CKA_ALWAYS_AUTHENTICATE with them is invalid (17)",
        |k, o| {
            if k.always_authenticate && matches!(k.binding(), "pop-ecdh" | "pop-decrypt") && !o.refused() {
                return Err(format!("{} under a per-use PIN: 17", k.binding()));
            }
            Ok(())
        },
    ),
    (
        "the-declared-binding",
        "DESIGN.md §3.6: a private key is bound as its spec declares, pop-sign-pin where a per-use PIN guards the signature",
        |k, o| {
            let Outcome::Identified { binding, .. } = o else { return Ok(()) };
            if !k.private_key() {
                return Ok(());
            }
            let want = match k.binding() {
                "pop-sign" if k.always_authenticate => "pop-sign-pin",
                b => b,
            };
            if *binding == Some(want) { Ok(()) } else { Err(format!("bound by {want}")) }
        },
    ),
    (
        "an-ec-key-with-nothing-beside-it",
        "DESIGN.md §3.2: a PKCS #11 EC private key holds no point; with no public key, CKA_PUBLIC_KEY_INFO or certificate beside it, it has no public half (11)",
        |k, o| {
            if k.kind == "ec-p256" && k.public == Some("none") && o.identified() {
                return Err("no public half to hash".into());
            }
            Ok(())
        },
    ),
    ("a-data-object-has-no-type", "PKCS #11 §4.5: a data object has no key type, so no type conflict (13)", |k, o| {
        if k.kind == "data" && *o == Outcome::Exit(13) {
            Err("a conflict over a type it has not".into())
        } else {
            Ok(())
        }
    }),
    (
        "a-data-object-is-its-value",
        "DESIGN.md §3.1, valuehash: a public value, or one declared private, is hashed",
        |k, o| {
            if k.kind == "data" && (!k.private() || k.declared()) && !(o.identified() || *o == Outcome::NotCreated) {
                return Err("its value is readable".into());
            }
            Ok(())
        },
    ),
    (
        "a-private-value-is-read-only-when-declared",
        "DESIGN.md §3.1, valuehash: a private value needs a spec declaring CKA_PRIVATE = true",
        |k, o| {
            if k.kind == "data" && k.private() && !k.declared() && o.identified() {
                return Err("identified by a private value its spec does not declare".into());
            }
            Ok(())
        },
    ),
];

/// How `table` breaks the properties: one line per row and property, none when it keeps them.
#[must_use]
pub fn violations(table: &str) -> Vec<String> {
    let parsed: toml::Table = match toml::from_str(table) {
        Ok(t) => t,
        Err(e) => return vec![format!("the table does not parse: {e}")],
    };
    let rows: BTreeMap<&str, &str> = parsed
        .get("rows")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
        .filter_map(|(k, v)| Some((k.as_str(), v.as_str()?)))
        .collect();
    let mut out = Vec::new();
    for (&key, &outcome) in &rows {
        let (k, o) = (Key::parse(key), Outcome::parse(outcome));
        for (name, source, rule) in ROWS {
            if let Err(why) = rule(&k, &o) {
                out.push(format!("{name}: {key:?} = {outcome:?}: {why} ({source})"));
            }
        }
    }
    // Rows that differ only in a dimension the spec says decides nothing have one outcome: of
    // those `counted` (a token's refusal to hold the object is no outcome of cakeys').
    let same =
        |name: &str, source: &str, dimension: Dimension, counted: fn(&Outcome<'_>) -> bool, out: &mut Vec<String>| {
            let mut groups: BTreeMap<String, Vec<(&str, &str)>> = BTreeMap::new();
            for (&key, &outcome) in &rows {
                let Some(varied) = dimension(&Key::parse(key)) else { continue };
                if counted(&Outcome::parse(outcome)) {
                    groups.entry(key.replacen(&varied, "*", 1)).or_default().push((key, outcome));
                }
            }
            for members in groups.values() {
                if members.iter().any(|(_, o)| *o != members[0].1) {
                    out.push(format!("{name}: {members:?}: one outcome ({source})"));
                }
            }
        };
    same(
        "an-rsa-key-is-its-own-public-half",
        "DESIGN.md §3.2: an RSA private key holds its modulus and exponent, so where else its public half is decides nothing",
        |k| (k.kind == "rsa-2048").then_some(k.public?).map(|p| format!("public={p}")),
        |o| *o != Outcome::NotCreated,
        &mut out,
    );
    same(
        "origin-does-not-decide",
        "DESIGN.md §3.4: a secret key's mode follows its declaration, never CKA_LOCAL (a token may hold one \
         origin differently, so only identified rows count)",
        |k| k.secret().then_some(k.origin?).map(|o| format!(" {o} ")),
        identified,
        &mut out,
    );
    out
}

/// Fail, naming each property `table` (token `name`'s) breaks and the report of what each row
/// printed.
///
/// # Panics
///
/// When it breaks one.
pub fn assert_kept(name: &str, table: &str, report: &std::path::Path) {
    let broken = violations(table);
    assert!(
        broken.is_empty(),
        "the {name} table breaks {} properties (tests/object_matrix/properties.rs; report: {}):\n{}",
        broken.len(),
        report.display(),
        broken.join("\n")
    );
}

/// Each property with a row of the grid flipped to an outcome it forbids.
pub const FLIPS: &[(&str, &str, &str)] = &[
    ("mode-by-class", "data 32B public", "commitment valuehash"),
    ("schemes-by-class", "ec-p256 generated usage=SIGN non-extractable sensitive", "direct certhash pop-sign"),
    ("schemes-by-class", "certificate ec-p256 public", "direct certhash"),
    (
        "commitment-computes-only-what-is-declared",
        "aes generated usage=SIGN non-extractable sensitive",
        "commitment cmac,kw",
    ),
    ("a-declared-commitment-is-used", "aes generated usage=SIGN non-extractable sensitive", "exit 17"),
    (
        "wrap-rebind-only-without-a-commitment",
        "aes generated usage=none non-extractable sensitive",
        "wrap-rebind cmac,kcv-ecb,kcv-ecb-dec,kw",
    ),
    ("nothing-to-identify-by-is-refused", "aes generated usage=none non-extractable sensitive", "exit 15"),
    ("wrap-rebind-computes-every-scheme", "aes generated usage=none extractable sensitive", "wrap-rebind cmac,kw"),
    (
        "a-proof-the-list-allows",
        "ec-p256 generated usage=SIGN non-extractable sensitive allowed=CKM_ECDH1_DERIVE",
        "direct rfc7093m4 pop-sign",
    ),
    (
        "a-per-use-pin-only-signs",
        "ec-p256 generated usage=DERIVE non-extractable sensitive always-authenticate",
        "direct rfc7093m4 pop-ecdh",
    ),
    ("the-declared-binding", "rsa-2048 generated usage=DECRYPT non-extractable sensitive", "direct rfc7093m4 pop-sign"),
    (
        "an-ec-key-with-nothing-beside-it",
        "ec-p256 imported public=none usage=SIGN non-extractable sensitive",
        "direct rfc7093m4 pop-sign immutables=none",
    ),
    ("a-data-object-has-no-type", "data 32B public", "exit 13"),
    ("a-data-object-is-its-value", "data 32B public", "exit 11"),
    ("a-private-value-is-read-only-when-declared", "data 32B private undeclared", "direct valuehash"),
    (
        "an-rsa-key-is-its-own-public-half",
        "rsa-2048 imported public=none usage=SIGN non-extractable sensitive",
        "exit 11",
    ),
    ("origin-does-not-decide", "aes imported usage=SIGN+ENCRYPT non-extractable sensitive", "commitment cmac"),
];

/// `table` with `row`'s outcome replaced by `outcome`.
///
/// # Panics
///
/// When `table` has no such row.
#[must_use]
pub fn flipped(table: &str, row: &str, outcome: &str) -> String {
    let prefix = format!("{row:?} = ");
    let line = table.lines().find(|l| l.starts_with(&prefix)).unwrap_or_else(|| panic!("no row {row:?}"));
    table.replacen(line, &format!("{prefix}{outcome:?}"), 1)
}

/// The committed tables, by file name.
#[must_use]
pub fn committed() -> Vec<(String, String)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../spec-coverage/objects");
    let mut tables: Vec<(String, String)> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "toml"))
        .map(|p| (p.file_name().unwrap().to_string_lossy().into_owned(), std::fs::read_to_string(&p).unwrap()))
        .collect();
    tables.sort();
    tables
}
