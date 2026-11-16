//! What every committed profile answers, pinned, beyond its mechanism list: the generation,
//! curve and OAEP verdicts `Effective` gives (notes included) over the whole baseline, and each
//! row a consumer reads directly, for every embedded profile. A change of
//! the profile format must leave this text unchanged (`tests/answers.txt`); a change of what a
//! profile says regenerates it with `CAKEYS_WRITE_ANSWERS=1 cargo test -p cakeys-profile --test
//! answers` and shows in its diff.

use cakeys_profile::profile::Mode;
use cakeys_profile::{Capability, Effective, Move, Profile, Set};
use std::fmt::Write as _;

/// The RSA sizes asked after: the reported ranges' edges and the sizes probes generate.
const BITS: [u32; 8] = [512, 1024, 2048, 3072, 4096, 8192, 15360, 16384];

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
            "  generate {kt}: can {} cannot {} bits {:?}..{:?} can {} cannot {} by-name {}",
            sorted(&g.can),
            sorted(&g.cannot),
            g.min_bits,
            g.max_bits,
            sorted(&g.can_bits),
            sorted(&g.cannot_bits),
            sorted(&g.by_name)
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
        // A layer alone answers generation only where it subtracts or restricts.
        let mut answer = |what: String, v: cakeys_profile::Verdict| {
            if !v.to_string().contains("no module profile selected") {
                let _ = writeln!(out, "  {what}: {v}");
            }
        };
        for kt in baseline.key_types.keys() {
            let bare = eff.generate(kt, None, None);
            // No row for the key type: each curve and size would say the same.
            let none = bare.to_string().contains(&format!("records no {kt} generation"));
            answer(kt.clone(), bare);
            if none {
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
    }
    out
}

#[test]
fn every_profile_answers_as_pinned() {
    let got = answers(&Set::embedded().unwrap());
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/answers.txt");
    if std::env::var_os("CAKEYS_WRITE_ANSWERS").is_some() {
        std::fs::write(path, &got).unwrap();
        return;
    }
    let pinned = std::fs::read_to_string(path).unwrap();
    if got != pinned {
        let (n, (a, b)) = got
            .lines()
            .zip(pinned.lines())
            .enumerate()
            .find(|(_, (a, b))| a != b)
            .unwrap_or((got.lines().count().min(pinned.lines().count()), ("<end>", "<end>")));
        panic!("profile answers changed at line {}:\n  now:    {a}\n  pinned: {b}", n + 1);
    }
}
