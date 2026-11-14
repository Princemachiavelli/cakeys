//! The cross-reference harness (`cakeys`' tests/references.rs, `camigrate`'s dry-run tests): every
//! reference token whose suite variables are set, one keys.toml naming them all, and runs of
//! either binary against it.

use super::{BIN, sibling};
use std::fmt::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

/// How a reference gets the material.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Plant {
    /// `C_CreateObject` through the module.
    Create,
    /// `tpm2_ptool import` (tpm2-pkcs11 creates no keys from values).
    Ptool,
    /// The token of the reference before it, through another configuration.
    Shared,
}

pub struct Ref {
    /// The token's name in keys.toml.
    pub name: &'static str,
    pub module: String,
    pub token_label: &'static str,
    /// Environment of every cakeys run against it.
    pub env: &'static [(&'static str, &'static str)],
    pub plant: Plant,
    /// `CKM_EDDSA` is usable: not through p11-kit, whose RPC drops it.
    pub eddsa: bool,
}

pub struct Env {
    pub dir: PathBuf,
    pub refs: Vec<Ref>,
}

fn module(var: &str, require: &str) -> Option<String> {
    let m = std::env::var(var).ok();
    assert!(m.is_some() || std::env::var(require).is_err(), "{var} is required");
    m
}

pub fn env(name: &str) -> Option<Env> {
    let mut refs = Vec::new();
    let r = |name, module, token_label, env, plant, eddsa| Ref { name, module, token_label, env, plant, eddsa };
    if let Some(m) = module("CAKEYS_TEST_MODULE", "CAKEYS_TEST_REQUIRE") {
        refs.push(r("softhsm", m, "kmtest", &[], Plant::Create, true));
    }
    if let Some(m) = module("CAKEYS_KRYOPTIC_MODULE", "CAKEYS_KRYOPTIC_REQUIRE") {
        refs.push(r("kryoptic", m.clone(), "kmtest", &[], Plant::Create, true));
        let der: &[(&str, &str)] = &[("KRYOPTIC_EC_POINT_ENCODING", "DER")];
        refs.push(r("kryoptic-der", m, "kmtest", der, Plant::Shared, true));
    }
    if let Some(m) = module("CAKEYS_P11KIT_CLIENT", "CAKEYS_P11KIT_REQUIRE") {
        refs.push(r("p11kit", m, "kmp11", &[], Plant::Create, false));
    }
    if let Some(m) = module("CAKEYS_TPM_MODULE", "CAKEYS_TPM_REQUIRE") {
        refs.push(r("tpm2", m, "kmtest", &[], Plant::Ptool, false));
    }
    if refs.len() < 2 {
        eprintln!("skipping {name}: fewer than two reference tokens set");
        return None;
    }
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("xref-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("pin"), "1234\n").unwrap();
    Some(Env { dir, refs })
}

impl Env {
    /// keys.toml: one token per reference, then `body`.
    pub fn config(&self, body: &str) {
        self.config_with(body, &|_| String::new());
    }

    /// [`Self::config`], with `extra` lines in each reference's token table (a table TOML cannot
    /// reopen once written).
    pub fn config_with(&self, body: &str, extra: &dyn Fn(&Ref) -> String) {
        let pin = self.dir.join("pin");
        let mut text = String::new();
        for r in &self.refs {
            let (name, module, label) = (r.name, &r.module, r.token_label);
            writeln!(text, "[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"{label}\"").unwrap();
            writeln!(text, "{}pinFile = \"{}\"\n", extra(r), pin.display()).unwrap();
        }
        std::fs::write(self.dir.join("keys.toml"), text + body).unwrap();
    }

    /// The package's own binary ([`BIN`]) against reference `r`.
    pub fn km(&self, r: &Ref, args: &[&str]) -> Output {
        self.run(std::path::Path::new(BIN), r, args)
    }

    /// `cakeys` itself, from a package whose own binary is another (`camigrate`'s tests record
    /// the realisations they plan from with it): [`sibling`].
    pub fn cakeys(&self, r: &Ref, args: &[&str]) -> Output {
        self.run(&sibling("cakeys"), r, args)
    }

    fn run(&self, bin: &std::path::Path, r: &Ref, args: &[&str]) -> Output {
        let out = Command::new(bin)
            .env_remove("NIX_BUILD_TOP")
            .env_remove("IN_NIX_SHELL")
            .envs(r.env.iter().copied())
            .arg("--config")
            .arg(self.dir.join("keys.toml"))
            .args(args)
            .output()
            .unwrap();
        eprintln!(
            "$ {} {} ({})\n  exit={:?}\n  stdout={}\n  stderr={}",
            bin.file_name().unwrap().to_string_lossy(),
            args.join(" "),
            r.name,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        out
    }

    pub fn refs(&self, keep: impl Fn(&Ref) -> bool) -> Vec<&Ref> {
        self.refs.iter().filter(|r| keep(r)).collect()
    }

    /// A spec over `object` on `refs`, located by `label`; `extra` is appended to each token entry.
    pub fn spec(name: &str, object: &str, attributes: &str, refs: &[&Ref], label: &str, extra: &str) -> String {
        let mut s = format!("[specs.{name}]\nobject = \"{object}\"\n{attributes}");
        for r in refs {
            writeln!(s, "tokens.{} = {{ locator = {{ CKA_LABEL = \"{label}\" }}{extra} }}", r.name).unwrap();
        }
        s + "\n"
    }
}
