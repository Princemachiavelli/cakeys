//! What every committed profile answers, pinned, beyond its mechanism list: the generation,
//! curve and OAEP verdicts `Effective` gives (notes included) over the whole baseline, and each
//! row a consumer reads directly, for every embedded profile. A change of
//! the profile format must leave this text unchanged (`tests/answers.txt`); a change of what a
//! profile says regenerates it with `CAKEYS_WRITE_ANSWERS=1 cargo test -p cakeys-profile --test
//! answers`, which then fails, so a regenerating run is never a pass: review the diff, then run
//! again without the variable.

use cakeys_profile::profile::Mode;
use cakeys_profile::{Capability, Effective, Move, Profile, Set, Verdict};
use std::fmt::Write as _;
use std::path::Path;

/// The RSA sizes asked after: the reported ranges' edges and the sizes probes generate.
const BITS: [u32; 8] = [512, 1024, 2048, 3072, 4096, 8192, 15360, 16384];

/// The secret key types cakeys generates, which a generation row reads in bytes.
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

/// The post-quantum key types, which a generation row reads by parameter set, never by curve or
/// bits: asked once, as the key type.
const PARAMETER_SET_KEYS: [&str; 3] = ["CKK_ML_DSA", "CKK_ML_KEM", "CKK_SLH_DSA"];

/// The secret-key lengths asked after: the three AES lengths, the edges and the lengths between
/// and beyond those the probes generate.
const BYTES: [u32; 10] = [1, 8, 16, 24, 32, 48, 64, 128, 1024, 4096];

/// A list as a set: no consumer reads these lists' order.
fn sorted<T: Ord + Clone + std::fmt::Debug>(v: &[T]) -> String {
    let mut v = v.to_vec();
    v.sort();
    format!("{v:?}")
}

/// The rows a consumer reads from a profile itself rather than through [`Effective`]:
/// possession's ECDH and decryption choices, camigrate's sides, resolution's clearing.
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
        // A layer alone answers generation only where it subtracts or restricts: with no module
        // profile, every other answer is unknown for that reason alone. Told by the stack and
        // the variant, not by the verdict's words (review answers.rs F3).
        let alone = p.mode == Mode::Delta;
        let mut answer = |what: String, v: Verdict| {
            if !(alone && matches!(v, Verdict::Unknown { .. })) {
                let _ = writeln!(out, "  {what}: {v}");
            }
        };
        for kt in baseline.key_types.keys() {
            // A secret key type is asked by length in bytes, never by curve or bits.
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
            // The module profile has no row for the key type: each curve and size would say the
            // same.
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
        // Each commitment the profile has rows for, at no length and at each length its rows
        // name: no commit verdict was pinned, so a wrong one went unseen (review 2026-11-23
        // A-16).
        let mut commits = std::collections::BTreeMap::<(String, String), Vec<u32>>::new();
        for c in p.capabilities.keys() {
            if let Capability::Commit { kind, key_type, bytes } = c {
                commits.entry((kind.clone(), key_type.name().to_owned())).or_default().push(*bytes);
            }
        }
        for ((kind, kt), lengths) in commits {
            answer(format!("commit {kind} {kt}"), eff.commit(&kind, &kt, None));
            for n in lengths {
                answer(format!("commit {kind} {kt} {n} bytes"), eff.commit(&kind, &kt, Some(n)));
            }
        }
    }
    out
}

/// Where `got` and `pinned` first differ, said so that either side's extra lines show: the line,
/// both sides of it, and both line counts. `None` when they are the same text.
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

/// Compare `got` with the pinned text at `path`, or with `write`, put `got` there: an error
/// either way, so a regenerating run never passes (review answers.rs F1: a shell that kept the
/// variable accepted every change silently).
fn pinned_or_written(got: &str, path: &Path, write: bool) -> Result<(), String> {
    if write {
        std::fs::write(path, got).map_err(|e| format!("{}: {e}", path.display()))?;
        return Err(format!(
            "{} rewritten (CAKEYS_WRITE_ANSWERS): review its diff, then run again without the variable",
            path.display()
        ));
    }
    let pinned = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    first_difference(got, &pinned).map_or(Ok(()), Err)
}

#[test]
fn every_profile_answers_as_pinned() {
    let got = answers(&Set::embedded().unwrap());
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/answers.txt"));
    if let Err(e) = pinned_or_written(&got, path, std::env::var_os("CAKEYS_WRITE_ANSWERS").is_some()) {
        panic!("{e}");
    }
}

/// Writing the answers fails the run, after writing them; a text that is a prefix of the other
/// names the side with more lines and its first extra one, never `<end>` against `<end>`.
#[test]
fn regenerating_fails_and_a_difference_says_where() {
    let path = std::env::temp_dir().join(format!("cakeys-answers-{}.txt", std::process::id()));
    let e = pinned_or_written("a\nb\n", &path, true).unwrap_err();
    assert!(e.contains("rewritten"), "{e}");
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "a\nb\n");
    assert_eq!(pinned_or_written("a\nb\n", &path, false), Ok(()));
    let e = pinned_or_written("a\nb\nc\n", &path, false).unwrap_err();
    assert!(e.contains("line 3 (3 lines now, 2 pinned)") && e.contains("now:    \"c\"\n  pinned: <end>"), "{e}");
    let e = pinned_or_written("a\n", &path, false).unwrap_err();
    assert!(e.contains("line 2 (1 lines now, 2 pinned)") && e.contains("now:    <end>\n  pinned: \"b\""), "{e}");
    std::fs::remove_file(&path).unwrap();
}
