//! This test pins what every committed profile answers, beyond its mechanism list. For every
//! embedded profile, it records the generation, curve and OAEP verdicts that `Effective` gives
//! over the whole baseline (with their notes), and each row that a consumer reads directly. The
//! pinned text is `tests/answers.txt`. A change of the profile format must leave this text
//! unchanged. After a change of what a profile says, regenerate the text with
//! `CAKEYS_WRITE_ANSWERS=1 cargo test -p cakeys-profile --test answers`. That run writes
//! `answers.txt.new` (`cakeys_profile::regenerate`) and then fails, so a regenerating run never
//! passes. Review the new file, run the test again with `CAKEYS_ACCEPT=1` as well, and then run
//! it once more without either variable.

use cakeys_profile::profile::Mode;
use cakeys_profile::{By, Capability, Effective, Move, Profile, Set, Verdict, regenerate};
use std::fmt::Write as _;
use std::path::Path;

/// The RSA sizes that the test asks about: the edges of the reported ranges and the sizes that
/// the probes generate.
const BITS: [u32; 8] = [512, 1024, 2048, 3072, 4096, 8192, 15360, 16384];

/// The secret key types that cakeys generates. A generation row gives their sizes in bytes.
const SECRET_KEYS: [&str; 10] = [
    "CKK_AES",
    "CKK_DES2",
    "CKK_DES3",
    "CKK_HKDF",
    "CKK_GENERIC_SECRET",
    "CKK_SHA_1_HMAC",
    "CKK_SHA224_HMAC",
    "CKK_SHA256_HMAC",
    "CKK_SHA384_HMAC",
    "CKK_SHA512_HMAC",
];

/// The post-quantum key types. A generation row names them by parameter set, never by curve or
/// bits, so the test asks about each of them once, as the key type.
const PARAMETER_SET_KEYS: [&str; 3] = ["CKK_ML_DSA", "CKK_ML_KEM", "CKK_SLH_DSA"];

/// The secret-key lengths that the test asks about: the three AES lengths, the edges, and lengths
/// between and beyond the lengths that the probes generate.
const BYTES: [u32; 10] = [1, 8, 16, 24, 32, 48, 64, 128, 1024, 4096];

/// Formats a list in sorted order, because no consumer reads the order of these lists.
fn sorted<T: Ord + Clone + std::fmt::Debug>(v: &[T]) -> String {
    let mut v = v.to_vec();
    v.sort();
    format!("{v:?}")
}

/// Formats the rows that a consumer reads from a profile directly, not through [`Effective`]:
/// the ECDH and decryption choices of the possession proofs, the sides of camigrate, and the
/// hardware rows that resolution clears (`clear_hardware_rows` in cakeys-pkcs11).
fn rows(p: &Profile) -> String {
    let mut out = String::new();
    let list = |v: &Option<Vec<String>>| v.as_ref().map(|v| sorted(v));
    let _ = writeln!(out, "  wrap.oaep {:?}", list(&p.wrap_oaep()));
    let _ = writeln!(out, "  decrypt.oaep {:?}", list(&p.decrypt_oaep()));
    let _ = writeln!(out, "  unwrap.refuse {:?}", list(&p.unwrap_refuse()));
    let _ = writeln!(out, "  derive.sealed {:?}", p.answer(&Capability::DeriveSealed));
    let _ = writeln!(out, "  derive.read-only {:?}", p.answer(&Capability::DeriveReadOnly));
    let m = p.migration.clone().unwrap_or_default();
    let _ = writeln!(
        out,
        "  migration exports {:?} unwraps {:?} secret-unwraps {:?} trusted-wrap {:?} plaintext {:?}",
        p.moves(Move::Export),
        p.moves(Move::Unwrap),
        p.moves(Move::SecretUnwrap),
        p.moves(Move::TrustedWrap),
        m.plaintext_import
    );
    let _ = writeln!(out, "  migration accepts {:?} {:?} {:?}", m.public_accepts, m.plaintext_accepts, m.refuses);
    for kt in p.generation_key_types() {
        let g = p.generation(kt).unwrap();
        let _ = writeln!(
            out,
            "  generate {kt}: can {} cannot {} bits {:?}..{:?} can {} cannot {} by-name {} bytes can {} cannot {}",
            sorted(&g.can),
            sorted(&g.cannot),
            g.min_bits,
            g.max_bits,
            sorted(&g.can_bits),
            sorted(&g.cannot_bits),
            sorted(&g.by_name),
            sorted(&g.can_bytes),
            sorted(&g.cannot_bytes)
        );
    }
    out
}

fn answers(set: &Set) -> String {
    let baseline = set.baseline().unwrap();
    let mut out = String::new();
    for p in set.all() {
        let layers = [p];
        let eff = match p.mode {
            Mode::Observed => Effective::new(baseline, Some(p), &[]),
            Mode::Delta => Effective::new(baseline, None, &layers),
        };
        let _ = writeln!(out, "# {}\n{}", p.profile, rows(p));
        // A layer alone answers a generation question only where it subtracts or restricts.
        // Without a module profile, every other answer is unknown for that reason alone, so the
        // test leaves those answers out. The test identifies them by the stack and the verdict's
        // variant, not by the verdict's words (review answers.rs F3).
        let alone = p.mode == Mode::Delta;
        let mut answer = |what: String, v: Verdict| {
            if !(alone && matches!(v, Verdict::Unknown { .. })) {
                let _ = writeln!(out, "  {what}: {v}");
            }
        };
        for kt in baseline.key_types.keys() {
            // The test asks about a secret key type by length in bytes, never by curve or bits.
            if SECRET_KEYS.contains(&kt.as_str()) {
                answer(kt.clone(), eff.generate_secret(kt, None));
                if alone || p.generation(kt).is_some() {
                    for n in BYTES {
                        answer(format!("{kt} {n} bytes"), eff.generate_secret(kt, Some(n)));
                    }
                }
                continue;
            }
            let bare = eff.generate(kt, None, None);
            // When the module profile has no row for the key type, every curve and size would
            // give the same answer, so the test asks only about the key type.
            let none = !alone && p.generation(kt).is_none();
            answer(kt.clone(), bare);
            if none || PARAMETER_SET_KEYS.contains(&kt.as_str()) {
                continue;
            }
            for c in &baseline.curves {
                answer(format!("{kt} {c}"), eff.generate(kt, Some(c), None));
            }
            for b in BITS {
                answer(format!("{kt} {b}"), eff.generate(kt, None, Some(b)));
            }
        }
        for c in &baseline.curves {
            answer(format!("curve {c}"), eff.curve(c));
        }
        for (h, v) in eff.oaep() {
            answer(format!("oaep {h}"), v);
        }
        // The test asks about each commitment for which the profile has rows: without a length,
        // at each length that its rows name, and at the lengths at which generation is asked.
        // Earlier, no commitment verdict was pinned, so a wrong verdict went unnoticed (review
        // 2026-11-23 A-16). A test that asked only at lengths that rows decide never ran the rule
        // for an untried length (review 2026-11-24 A-9).
        let mut commits = std::collections::BTreeMap::<(String, String), Vec<u32>>::new();
        for c in p.capabilities.keys() {
            if let Capability::Commit { kind, key_type, bytes } = c {
                commits.entry((kind.clone(), key_type.name().to_owned())).or_default().push(*bytes);
            }
        }
        for ((kind, kt), lengths) in commits {
            answer(format!("commit {kind} {kt}"), eff.commit(&kind, &kt, None));
            let lengths: std::collections::BTreeSet<u32> = lengths.into_iter().chain(BYTES).collect();
            for n in lengths {
                answer(format!("commit {kind} {kt} {n} bytes"), eff.commit(&kind, &kt, Some(n)));
            }
        }
    }
    out
}

/// Describes where `got` and `pinned` first differ, in a form that shows the extra lines of
/// either side: the line number, both versions of the line, and both line counts. Returns `None`
/// when the texts are the same.
fn first_difference(got: &str, pinned: &str) -> Option<String> {
    if got == pinned {
        return None;
    }
    let (now, was): (Vec<&str>, Vec<&str>) = (got.lines().collect(), pinned.lines().collect());
    let Some(n) = (0..now.len().max(was.len())).find(|&i| now.get(i) != was.get(i)) else {
        return Some("profile answers differ in their line endings only".into());
    };
    let at = |lines: &[&str]| lines.get(n).map_or_else(|| "<end>".to_owned(), |l| format!("{l:?}"));
    Some(format!(
        "profile answers changed at line {} ({} lines now, {} pinned):\n  now:    {}\n  pinned: {}",
        n + 1,
        now.len(),
        was.len(),
        at(&now),
        at(&was)
    ))
}

/// Compares `got` with the pinned text at `path`. When `write` is true, it instead writes `got`
/// there through [`regenerate::write`], which replaces the file only when `accept` is true.
/// Writing always returns an error, so a regenerating run never passes (review answers.rs F1: a
/// shell that still had the variable set accepted every change silently).
fn pinned_or_written(got: &str, path: &Path, write: bool, accept: bool) -> Result<(), String> {
    if write {
        let written = regenerate::write(path, got, accept).map_err(|e| format!("{}: {e}", path.display()))?;
        return Err(format!("{written} (CAKEYS_WRITE_ANSWERS): review its diff, then run again without the variable"));
    }
    let pinned = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    first_difference(got, &pinned).map_or(Ok(()), Err)
}

#[test]
fn every_profile_answers_as_pinned() {
    let got = answers(&Set::embedded().unwrap());
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/answers.txt"));
    let write = std::env::var_os("CAKEYS_WRITE_ANSWERS").is_some();
    if let Err(e) = pinned_or_written(&got, path, write, regenerate::accepted()) {
        panic!("{e}");
    }
}

/// Writing the answers fails the run after it writes them. When one text is a prefix of the
/// other, the message names the side with more lines and its first extra line, and it never
/// shows `<end>` against `<end>`.
#[test]
fn regenerating_fails_and_a_difference_says_where() {
    let path = std::env::temp_dir().join(format!("cakeys-answers-{}.txt", std::process::id()));
    let e = pinned_or_written("a\nb\n", &path, true, false).unwrap_err();
    assert!(e.contains("wrote"), "{e}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");
    assert_eq!(pinned_or_written("a\nb\n", &path, false, false), Ok(()));
    // When a pinned file exists, the regeneration is written next to it and stays there until it
    // is accepted (review 2026-11-24 C-8).
    let new = regenerate::pending(&path);
    let e = pinned_or_written("a\nB\n", &path, true, false).unwrap_err();
    assert!(e.contains(&new.display().to_string()), "{e}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");
    assert_eq!(std::fs::read_to_string(&new).unwrap(), "a\nB\n");
    let e = pinned_or_written("a\nb\n", &path, true, true).unwrap_err();
    assert!(e.contains("unchanged"), "{e}");
    assert!(!new.exists());
    let e = pinned_or_written("a\nb\nc\n", &path, false, false).unwrap_err();
    assert!(e.contains("line 3 (3 lines now, 2 pinned)") && e.contains("now:    \"c\"\n  pinned: <end>"), "{e}");
    let e = pinned_or_written("a\n", &path, false, false).unwrap_err();
    assert!(e.contains("line 2 (1 lines now, 2 pinned)") && e.contains("now:    <end>\n  pinned: \"b\""), "{e}");
    std::fs::remove_file(&path).unwrap();
}

/// Returns two lists of profiles from profiles/LEDGER.toml: the profiles that every build
/// regenerates (`verified-by`), and the profiles that it records as runs on hardware or in a
/// cloud (`[artifact.probed]`). The ledger's fixtures and locks are skipped.
fn ledger_profiles() -> (Vec<String>, Vec<String>) {
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../profiles/LEDGER.toml"));
    let ledger: toml::Table = toml::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let (mut regenerated, mut hardware) = (Vec::new(), Vec::new());
    for a in ledger["artifact"].as_array().unwrap().iter().filter_map(toml::Value::as_table) {
        let file = a["path"].as_str().unwrap().to_owned();
        if !file.starts_with("profiles/") {
            continue;
        }
        if a.contains_key("verified-by") {
            regenerated.push(file);
        } else if a.contains_key("probed") {
            hardware.push(file);
        }
    }
    (regenerated, hardware)
}

/// Returns what is wrong with the provenance of the yes rows in `text` (review 2026-11-24 §3.1).
/// In a profile that every build regenerates, each yes must record whether the host checked it
/// (`host`) or only the module reported it (`unverified`). A yes without recorded provenance (a
/// legacy row) is allowed only in a profile that was last probed on hardware, for which the
/// ledger records that a new run is owed.
fn yes_provenance(path: &str, text: &str, regenerated: &[String], hardware: &[String]) -> Vec<String> {
    let profile = Profile::from_toml(text).unwrap_or_else(|e| panic!("{path}: {e}"));
    let regenerated = regenerated.iter().any(|r| r == path);
    let mut out = Vec::new();
    for (cap, row) in profile.capabilities.iter().filter(|(c, r)| c.probed() && r.answer.yes()) {
        match row.by {
            Some(By::Host | By::Unverified) => {}
            Some(by) => out.push(format!("{path}: {cap} = yes by {by:?}")),
            None if regenerated => out.push(format!("{path}: {cap} = yes, of no provenance, in a regenerated profile")),
            None if !hardware.iter().any(|h| h == path) => {
                out.push(format!("{path}: {cap} = yes, of no provenance, and the ledger records no run of it"));
            }
            None => {}
        }
    }
    out
}

#[test]
fn every_regenerated_yes_says_by_whom() {
    let (regenerated, hardware) = ledger_profiles();
    assert_eq!(regenerated.len(), 3, "the software profiles every build regenerates: {regenerated:?}");
    let embedded: Vec<&str> = cakeys_profile::embedded::PROFILE_FILES.iter().map(|(p, _)| *p).collect();
    for path in regenerated.iter().chain(&hardware) {
        assert!(embedded.contains(&path.as_str()), "{path}: in the ledger, not embedded");
    }
    let wrong: Vec<String> = cakeys_profile::embedded::PROFILE_FILES
        .iter()
        .flat_map(|(path, text)| yes_provenance(path, text, &regenerated, &hardware))
        .collect();
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // The check is seen to fail for a yes without its `by` in a regenerated profile, and for a
    // legacy yes in a hardware profile that the ledger does not record.
    let softhsm =
        cakeys_profile::embedded::PROFILE_FILES.iter().find(|(p, _)| p.ends_with("softhsm/2.7.toml")).unwrap();
    let stripped = softhsm.1.replacen(
        "\"wrap.rsa-oaep.SHA-1\" = { answer = \"yes\", by = \"host\" }",
        "\"wrap.rsa-oaep.SHA-1\" = { answer = \"yes\" }",
        1,
    );
    assert_ne!(stripped, softhsm.1);
    assert_eq!(yes_provenance(softhsm.0, &stripped, &regenerated, &hardware).len(), 1);
    let ykcs11 = cakeys_profile::embedded::PROFILE_FILES.iter().find(|(p, _)| p.ends_with("ykcs11/2.7.toml")).unwrap();
    assert!(!yes_provenance(ykcs11.0, ykcs11.1, &[], &[]).is_empty(), "ykcs11/2.7 holds no legacy yes to refuse");
}
