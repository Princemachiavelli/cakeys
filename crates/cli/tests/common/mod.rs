//! Helpers shared by the integration tests of `cakeys`, `caprobe` and `camigrate` (each includes
//! this file): running the package's own binary, the token headers of each suite's keys.toml,
//! the cross-reference harness ([`xref`]), CLI output parsing and an independent DER oracle.
#![allow(dead_code, reason = "each test binary uses a subset")]
#![expect(unreachable_pub, reason = "its crate is a test binary: pub and pub(crate) say the same")]

pub mod surface;
pub mod xref;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// The binary under test, and its name for the logs: the including package's own (Cargo sets
/// `CARGO_BIN_EXE_<name>` only for the package's binaries).
pub const BIN: &str = match (
    option_env!("CARGO_BIN_EXE_cakeys"),
    option_env!("CARGO_BIN_EXE_caprobe"),
    option_env!("CARGO_BIN_EXE_camigrate"),
) {
    (Some(b), _, _) | (None, Some(b), _) | (None, None, Some(b)) => b,
    (None, None, None) => panic!("included by a package with no cakeys, caprobe or camigrate binary"),
};
pub const TOOL: &str = match (option_env!("CARGO_BIN_EXE_cakeys"), option_env!("CARGO_BIN_EXE_caprobe")) {
    (Some(_), _) => "cakeys",
    (None, Some(_)) => "caprobe",
    (None, None) => "camigrate",
};

/// Another binary of this workspace, beside [`BIN`] in the target directory. Cargo gives a test
/// only its own package's binaries; `cargo test --workspace` (the Nix check phase) builds them
/// all before any test runs.
///
/// # Panics
///
/// When that binary is not built (`cargo test -p <package>` alone): build the workspace first.
pub fn sibling(name: &str) -> PathBuf {
    let path = Path::new(BIN).with_file_name(name);
    assert!(path.exists(), "{} is not built: run `cargo build --workspace` first", path.display());
    path
}

/// The value of the suite variable `var` (a module path), else `None` with a skip message —
/// unless `require` is set, which makes a missing one a failure.
pub fn suite_var(var: &str, require: &str, test: &str) -> Option<String> {
    let Ok(v) = std::env::var(var) else {
        assert!(std::env::var(require).is_err(), "{var} is required");
        eprintln!("skipping {test}: {var} not set");
        return None;
    };
    Some(v)
}

/// The reference suite's tokens: `ref` (scratch: the token is created for the run and thrown
/// away, which is exactly what the probe's write probes demand, docs/CAPROBE.md) and
/// `ref-anon`, the same token without a PIN: it sees only public objects, like a PIV token used
/// without login.
pub fn reference_tokens(module: &str, dir: &Path) -> String {
    format!(
        "[tokens.ref]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nscratch = true\n\n\
         [tokens.ref-anon]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\n\n",
        dir.join("pin").display(),
    )
}

/// tpm2-pkcs11 on swtpm: `tpm` (logged in, scratch: the swtpm token is created for the run),
/// `tpm-anon` (no PIN) and `tpm-generic` (logged in, but without the tpm2-pkcs11 provider's
/// fix-ups). The native attestation path finds the TPM the way the module does —
/// `$TPM2_PKCS11_TCTI`, which the harness exports in the TCTI library-path form — and the store
/// through `$TPM2_PKCS11_STORE`.
pub fn tpm2_tokens(module: &str, dir: &Path) -> String {
    let pin = dir.join("pin");
    let token =
        |name: &str, extra: &str| format!("[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\n{extra}\n");
    token("tpm", &format!("pinFile = \"{}\"\nscratch = true", pin.display()))
        + &token("tpm-anon", "")
        + &token("tpm-generic", &format!("pinFile = \"{}\"\nprovider = \"generic\"", pin.display()))
}

/// The host's real TPM: `ftpm` (logged in, scratch: the harness's store is made for the run).
pub fn ftpm_tokens(module: &str, dir: &Path) -> String {
    format!(
        "[tokens.ftpm]\nmodule = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\nscratch = true\n\n",
        dir.join("pin").display()
    )
}

/// p11-kit forwarding: `fwd` (through p11-kit), `fwd-anon` (no PIN), `fwd-softhsm` (provider
/// named), `fwd-other` (a token the server does not export) and `direct` (`SoftHSM` itself).
pub fn p11kit_tokens(client: &str, direct: &str, dir: &Path) -> String {
    let pin = format!("pinFile = \"{}\"", dir.join("pin").display());
    let token = |name: &str, module: &str, label: &str, extra: &str| {
        format!("[tokens.{name}]\nmodule = \"{module}\"\ntokenLabel = \"{label}\"\n{extra}\n\n")
    };
    token("fwd", client, "kmp11", &pin)
        + &token("fwd-anon", client, "kmp11", "")
        + &token("fwd-softhsm", client, "kmp11", &format!("{pin}\nprovider = \"softhsm\""))
        + &token("fwd-other", client, "kmtest", &pin)
        + &token("direct", direct, "kmp11", &pin)
}

/// A real `YubiKey`: the token with both credentials (file paths), `extra` added to it.
pub fn yubikey_token(module: &str, pin: &str, mgm: &str, extra: &str) -> String {
    format!(
        "[tokens.yubikey]\nmodule = \"{module}\"\ntokenLabel = \"{}\"\npinFile = \"{pin}\"\nmgmKeyFile = \"{mgm}\"\n{extra}\n",
        yubikey_label(module)
    )
}

/// The label of the first `YubiKey` the module sees, so the config names the right token.
pub fn yubikey_label(module: &str) -> String {
    let ctx = Pkcs11::new(module).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().model().starts_with("YubiKey"))
        .unwrap();
    ctx.get_token_info(slot).unwrap().label().to_string()
}

/// Run the binary on `config` bounded in time: on hardware, a touch or PIN prompt fails the
/// test instead of hanging it.
///
/// # Panics
///
/// When the run takes longer than `limit`.
pub fn run_within(config: &Path, args: &[&str], limit: Duration) -> Output {
    let mut child = Command::new(BIN)
        .env_remove("NIX_BUILD_TOP")
        .arg("--config")
        .arg(config)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            // The child is done; the pipes still hold (and now end) its output.
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            if let Some(mut p) = child.stdout.take() {
                std::io::Read::read_to_end(&mut p, &mut stdout).unwrap();
            }
            if let Some(mut p) = child.stderr.take() {
                std::io::Read::read_to_end(&mut p, &mut stderr).unwrap();
            }
            eprintln!(
                "$ {TOOL} {}\n  exit={:?}\n  stdout={}\n  stderr={}",
                args.join(" "),
                status.code(),
                String::from_utf8_lossy(&stdout).trim(),
                String::from_utf8_lossy(&stderr).trim()
            );
            return Output { status, stdout, stderr };
        }
        if started.elapsed() > limit {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{TOOL} {} did not finish within {limit:?}: user presence (touch or PIN) needed?", args.join(" "));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether the linked cryptoki has the HMAC key type fix (nix/patches/); the Nix build does.
/// Without it, tests needing SHA-224/384/512 HMAC keys skip, unless `require` (then they fail).
pub fn cryptoki_hmac_types_fixed(require: bool) -> bool {
    let fixed = std::os::raw::c_ulong::from(cryptoki::object::KeyType::SHA384_HMAC) == 0x2c;
    assert!(fixed || !require, "cryptoki lacks the HMAC key type fix (nix/patches/cryptoki-hmac-key-types.patch)");
    if !fixed {
        eprintln!("skipping: cryptoki lacks the HMAC key type fix; run through the Nix build");
    }
    fixed
}

/// A software PKCS#11 token the shared suite (`tests/reference/`) runs against: the facts the
/// suite needs about it, so its tests assert the same verdicts on every reference.
pub struct Reference {
    /// Path of the module; the suite skips when it is unset.
    pub module_var: &'static str,
    /// When set, a missing module fails instead of skipping.
    pub require_var: &'static str,
    /// The module's own configuration file.
    pub conf_var: &'static str,
    /// The provider cakeys detects from `C_GetInfo`.
    pub provider: &'static str,
    /// `C_GetInfo` manufacturer and `C_GetTokenInfo` model, as recorded in provenance.
    pub manufacturer: &'static str,
    pub model: &'static str,
    /// Curves (`keys.toml` names) it cannot generate: refused as unsupported (15).
    pub missing_curves: &'static [&'static str],
    /// Whether it implements Triple DES (`CKM_DES3_ECB`, `CKM_DES3_KEY_GEN`); without it a
    /// `CKK_DES3` spec is refused as unsupported (15).
    pub des3: bool,
    /// Whether it generates the hash-bound HMAC key types (PKCS#11 3.0's `CKM_SHA*_KEY_GEN`).
    pub hmac_key_gen: bool,
    /// Its committed capability profile: name, and path under profiles/.
    pub profile: (&'static str, &'static str),
    /// The module's configuration (`conf_var`'s file) with one mechanism hidden.
    pub hide_mechanism: fn(conf: &str, mechanism: &str) -> String,
    /// Whether the suite loads the module through `p11-fault` (`P11_FAULT_MODULE` names it), with no
    /// fault plan: the forwarder must be transparent.
    pub through_fault_shim: bool,
}

pub const SOFTHSM: Reference = Reference {
    module_var: "CAKEYS_TEST_MODULE",
    require_var: "CAKEYS_TEST_REQUIRE",
    conf_var: "SOFTHSM2_CONF",
    provider: "softhsm",
    manufacturer: "SoftHSM",
    model: "SoftHSM v2",
    missing_curves: &[],
    des3: true,
    hmac_key_gen: false,
    profile: ("softhsm/2.7", "modules/softhsm/2.7.toml"),
    hide_mechanism: |conf, m| format!("{conf}\nslots.mechanisms = -{m}\n"),
    through_fault_shim: false,
};

/// kryoptic 1.5.4 (its `OpenSSL` backend) generates none of secp256k1 or the brainpool curves, and
/// has no DES mechanism at all (`pkcs11-tool -M` \[run\], 2026-11-15). The harness
/// (nix/package.nix) ends `KRYOPTIC_CONF` with the token's `[[slots]]` table, so an appended key
/// belongs to it.
pub const KRYOPTIC: Reference = Reference {
    module_var: "CAKEYS_KRYOPTIC_MODULE",
    require_var: "CAKEYS_KRYOPTIC_REQUIRE",
    conf_var: "KRYOPTIC_CONF",
    provider: "kryoptic",
    manufacturer: "Kryoptic",
    model: "v1",
    missing_curves: &["secp256k1", "brainpoolP256r1", "brainpoolP384r1"],
    des3: false,
    hmac_key_gen: true,
    profile: ("kryoptic/1.5", "modules/kryoptic/1.5.toml"),
    hide_mechanism: |conf, m| format!("{conf}\nmechanisms = [\"DENY\", \"{m}\"]\n"),
    through_fault_shim: false,
};

/// `SoftHSM` behind `p11-fault` (`docs/FAULT_SHIM.md`) with no fault plan: the whole suite runs a
/// third time through the shim, and must pass as it does directly. The per-test runner
/// (nix/test-tokens.sh) points `P11_FAULT_MODULE` at the test's own `SoftHSM` token; the token's
/// module is the shim.
pub const FAULT: Reference = Reference {
    module_var: "P11_FAULT_MODULE",
    require_var: "CAKEYS_FAULT_REQUIRE",
    through_fault_shim: true,
    ..SOFTHSM
};

/// `libp11_fault.so`: beside the binaries after a build of the workspace, else among the
/// dependencies of the tests (`deps/`), where the `cakeys` tests' dev-dependency on `p11-fault`
/// has every test build put it.
///
/// # Panics
///
/// When it is in neither place.
pub fn fault_shim() -> String {
    let beside = Path::new(BIN).with_file_name("libp11_fault.so");
    let path = if beside.exists() { beside } else { Path::new(BIN).with_file_name("deps").join("libp11_fault.so") };
    assert!(path.exists(), "libp11_fault.so is built neither beside {BIN} nor in deps/");
    path.to_str().unwrap().to_owned()
}

pub fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

/// A committed capability profile's file (profiles/, docs/CAPROBE.md): what the conformance
/// tests regenerate and compare byte for byte.
pub fn committed_profile(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles").join(path)
}

/// The conformance check every reference token runs (docs/CAPROBE.md): the committed
/// module profile `name` (at `path` under profiles/) is exactly what a fresh probe of token
/// `token` observes, and regenerating it — the maintenance flow — changes no byte. `km` runs
/// the CLI against the test's keys.toml; `scratch` is a file the regeneration may write.
///
/// One write probe only: it diffs and regenerates in the same run. A second would see what the
/// first left behind on modules that cannot destroy everything they make (tpm2-pkcs11's sealed
/// derived secrets: profiles/modules/tpm2-pkcs11/1.10+amd-ftpm.toml, `derive.destroy`).
pub fn assert_profile_conforms(
    km: impl Fn(&[&str]) -> Output,
    token: &str,
    name: &str,
    path: &str,
    scratch: &std::path::Path,
) {
    let committed = std::fs::read(committed_profile(path)).unwrap();
    std::fs::write(scratch, &committed).unwrap();
    let out = scratch.to_str().unwrap();
    let probe = km(&["probe", "--token", token, "--write", "--diff", name, "--out", out]);
    assert_eq!(code(&probe), 0, "a fresh probe drifts from {name}: {}", String::from_utf8_lossy(&probe.stderr));
    assert!(
        std::fs::read(scratch).unwrap() == committed,
        "{path} is not what the probe generates: regenerate it with `caprobe probe --token <t> --write \
         --diff {name} --out profiles/{path}`, never by hand"
    );
    // A read-only probe conforms on what it observes; it may never overwrite the file.
    assert_eq!(code(&km(&["probe", "--token", token, "--diff", name])), 0);
    assert_eq!(code(&km(&["probe", "--token", token, "--out", out])), 17);
    assert_eq!(std::fs::read(scratch).unwrap(), committed, "a read-only probe overwrote the file");
}

/// The writing form of a compare-only `realise`/`delete` argument list: `--no-update-lock`
/// dropped, `--update-lock` (the default, said explicitly) added.
pub fn recording<'a>(args: &[&'a str]) -> Vec<&'a str> {
    args.iter().copied().filter(|a| *a != "--no-update-lock").chain(["--update-lock"]).collect()
}

pub fn got_hash(o: &Output) -> String {
    let err = String::from_utf8_lossy(&o.stderr);
    let line = err.lines().find(|l| l.trim_start().starts_with("got:")).expect("no got: line");
    line.split_whitespace().last().unwrap().to_owned()
}

pub fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_owned()
}

pub fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A test's scratch directory — keys.toml, keys.lock and a PIN file holding `1234` — and the
/// `cakeys` runs against it. Each suite's `Env` holds one (and derefs to it) beside its own
/// skip/require gate and token header.
pub struct Workdir {
    pub dir: PathBuf,
}

/// The directory of one test under the integration tests' tmpdir, which every package and test
/// binary shares: named for both, so suites that run at once (and the shared reference suite,
/// which two binaries run under the same test names) never meet in one.
pub fn test_dir(name: &str) -> PathBuf {
    let binary = concat!(env!("CARGO_PKG_NAME"), "-", env!("CARGO_CRATE_NAME"));
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{binary}-{name}"))
}

impl Workdir {
    /// A fresh directory `name` under the integration tests' tmpdir.
    pub fn new(name: &str) -> Workdir {
        let dir = test_dir(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pin"), "1234\n").unwrap();
        Workdir { dir }
    }

    pub fn write_config(&self, text: &str) {
        std::fs::write(self.dir.join("keys.toml"), text).unwrap();
    }

    pub fn km(&self, args: &[&str]) -> Output {
        self.km_env(args, &[])
    }

    /// `cakeys --config keys.toml <args>` with `envs` set, logged for the test's output. The
    /// suites themselves run in a Nix build: only a test that sets `NIX_BUILD_TOP` means it.
    pub fn km_env(&self, args: &[&str], envs: &[(&str, &Path)]) -> Output {
        let out = Command::new(BIN)
            .env_remove("NIX_BUILD_TOP")
            .env_remove("IN_NIX_SHELL")
            .envs(envs.iter().copied())
            .arg("--config")
            .arg(self.dir.join("keys.toml"))
            .args(args)
            .output()
            .unwrap();
        eprintln!(
            "$ {TOOL} {}\n  exit={:?}\n  stdout={}\n  stderr={}",
            args.join(" "),
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        out
    }

    /// The exit code of [`Self::km`].
    pub fn code(&self, args: &[&str]) -> i32 {
        code(&self.km(args))
    }

    pub fn lock(&self) -> toml::Value {
        toml::from_str(&std::fs::read_to_string(self.dir.join("keys.lock")).unwrap()).unwrap()
    }

    /// The `observations` entry the realisation of `spec` on `token` names.
    pub fn observation(&self, spec: &str, token: &str) -> toml::Value {
        let lock = self.lock();
        let key = lock["realisations"][spec][token]["observation"].as_str().unwrap().to_owned();
        lock["observations"][key.as_str()].clone()
    }

    pub fn locked_id(&self, object: &str, scheme: &str) -> String {
        self.lock()["objects"][object]["ids"][scheme].as_str().unwrap().to_owned()
    }
}

pub fn sri(bytes: &[u8]) -> String {
    use base64::Engine;
    use sha2::Digest;
    format!("sha256-{}", base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(bytes)))
}

/// Minimal DER writer for the test oracle: independent of the crates the tool uses.
pub fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = body.len();
    if n < 0x80 {
        v.push(u8::try_from(n).unwrap());
    } else {
        let len: Vec<u8> = n.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        v.push(0x80 | u8::try_from(len.len()).unwrap());
        v.extend(len);
    }
    v.extend_from_slice(body);
    v
}

/// One DER element: (tag, contents, rest). Independent of the crates cakeys uses.
pub fn der(input: &[u8]) -> (u8, &[u8], &[u8]) {
    let (tag, first) = (input[0], input[1]);
    let (len, off) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        (input[2..2 + n].iter().fold(0, |acc, b| (acc << 8) | usize::from(*b)), 2 + n)
    };
    (tag, &input[off..off + len], &input[off + len..])
}

/// The DER inside a PEM file.
pub fn pem_der(path: &str) -> Vec<u8> {
    use base64::Engine;
    let text = std::fs::read_to_string(path).unwrap();
    let b64: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).unwrap()
}

/// A PKCS#8 EC key: (curve OID as DER, private scalar, uncompressed public point).
pub fn ec_fixture(pkcs8: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (_, info, _) = der(pkcs8);
    let (_, _, rest) = der(info); // version
    let (_, alg, rest) = der(rest);
    let (_, _, curve) = der(alg); // id-ecPublicKey
    let curve_len = curve.len() - der(curve).2.len();
    let (_, inner, _) = der(rest); // OCTET STRING { ECPrivateKey }
    let (_, ec, _) = der(inner);
    let (_, _, rest) = der(ec); // version
    let (_, scalar, mut rest) = der(rest);
    loop {
        let (tag, body, next) = der(rest);
        if tag == 0xa1 {
            let (_, bits, _) = der(body);
            return (curve[..curve_len].to_vec(), scalar.to_vec(), bits[1..].to_vec());
        }
        rest = next;
    }
}

/// A PKCS#8 Ed25519 key (RFC 8410): its 32-byte seed.
pub fn ed25519_fixture(pkcs8: &[u8]) -> Vec<u8> {
    let (_, info, _) = der(pkcs8);
    let (_, _, rest) = der(info); // version
    let (_, _, rest) = der(rest); // algorithm
    let (_, inner, _) = der(rest); // OCTET STRING { CurvePrivateKey }
    der(inner).1.to_vec()
}

/// A PKCS#8 RSA key: modulus, public and private exponents, primes, CRT exponents, coefficient.
pub fn rsa_fixture(pkcs8: &[u8]) -> Vec<Vec<u8>> {
    let (_, info, _) = der(pkcs8);
    let (_, _, rest) = der(info); // version
    let (_, _, rest) = der(rest); // algorithm
    let (_, inner, _) = der(rest);
    let (_, key, _) = der(inner);
    let (_, _, mut rest) = der(key); // version
    let mut ints = Vec::new();
    while !rest.is_empty() {
        let (_, int, next) = der(rest);
        ints.push(int.iter().copied().skip_while(|b| *b == 0).collect());
        rest = next;
    }
    ints
}

pub fn der_uint(b: &[u8]) -> Vec<u8> {
    let b: Vec<u8> = b.iter().copied().skip_while(|x| *x == 0).collect();
    let mut body = if b[0] & 0x80 != 0 { vec![0] } else { vec![] };
    body.extend(b);
    tlv(0x02, &body)
}

pub fn spki(algorithm: &[u8], key: &[u8]) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend_from_slice(key);
    tlv(0x30, &[tlv(0x30, algorithm), tlv(0x03, &bits)].concat())
}

/// `CKA_EC_POINT` is a DER OCTET STRING around the point.
pub fn unwrap_octets(v: &[u8]) -> Vec<u8> {
    assert_eq!(v[0], 0x04);
    let (len, off) = match v[1] {
        n if n < 0x80 => (n as usize, 2),
        0x81 => (v[2] as usize, 3),
        n => panic!("length form {n:#x}"),
    };
    assert_eq!(v.len(), off + len, "{v:02x?}");
    v[off..].to_vec()
}

pub const EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
pub const P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
pub const ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
pub const ED448: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x71];

/// SPKI of the public key object under `label`, built from its raw PKCS#11 attributes.
pub fn oracle_spki(s: &Session, label: &str) -> Vec<u8> {
    oracle_spki_with(s, label, unwrap_octets)
}

/// As [`oracle_spki`], with a custom `CKA_EC_POINT` unwrapper (for a module's known bug).
#[expect(
    clippy::many_single_char_names,
    reason = "the DER-oracle bindings mirror the names in the specs they hand-roll"
)]
pub fn oracle_spki_with(s: &Session, label: &str, unwrap: fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let h = s
        .find_objects(&[Attribute::Class(ObjectClass::PUBLIC_KEY), Attribute::Label(label.as_bytes().to_vec())])
        .unwrap()[0];
    let a = s.get_attributes(h, &[AttributeType::KeyType]).unwrap();
    if let Attribute::KeyType(cryptoki::object::KeyType::RSA) = a[0] {
        let a = s.get_attributes(h, &[AttributeType::Modulus, AttributeType::PublicExponent]).unwrap();
        let (Attribute::Modulus(n), Attribute::PublicExponent(e)) = (&a[0], &a[1]) else { panic!() };
        let rsa = [0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00];
        spki(&rsa, &tlv(0x30, &[der_uint(n), der_uint(e)].concat()))
    } else {
        let a = s.get_attributes(h, &[AttributeType::EcParams, AttributeType::EcPoint]).unwrap();
        let (Attribute::EcParams(p), Attribute::EcPoint(q)) = (&a[0], &a[1]) else { panic!() };
        // PKCS#11 3.2 holds Edwards points raw (kryoptic's default); earlier modules wrap them
        // in an OCTET STRING. The raw length is exact, two bytes short of the wrapped form.
        let raw = match p.as_slice() {
            ED25519 => Some(32),
            ED448 => Some(57),
            _ => None,
        };
        let point = if raw == Some(q.len()) { q.clone() } else { unwrap(q) };
        match p.as_slice() {
            ED25519 | ED448 => spki(p, &point),
            _ => spki(&[EC_PUBLIC_KEY, p.as_slice()].concat(), &point),
        }
    }
}

/// Host oracle for the AES commitments (`cmac`, `kcv-ecb`, `kcv-ecb-dec`, `kw`) of a known
/// AES-128/192/256 key.
pub fn aes_commitment(key: &[u8], scheme: &str) -> String {
    use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    use cmac::Mac;
    let label = format!("key-management/v1/{scheme}/CKK_AES/{}", key.len() * 8);
    let digest = <sha2::Sha256 as sha2::Digest>::digest(label.as_bytes());
    let mut block = aes::Block::default();
    block.copy_from_slice(&digest[..16]);
    macro_rules! with_cipher {
        ($aes:ty, $kw:ty) => {
            match scheme {
                "cmac" => {
                    let mut m = <cmac::Cmac<$aes> as KeyInit>::new_from_slice(key).unwrap();
                    m.update(label.as_bytes());
                    m.finalize().into_bytes().to_vec()
                }
                "kcv-ecb" => {
                    <$aes>::new_from_slice(key).unwrap().encrypt_block(&mut block);
                    block.to_vec()
                }
                "kcv-ecb-dec" => {
                    <$aes>::new_from_slice(key).unwrap().decrypt_block(&mut block);
                    block.to_vec()
                }
                "kw" => {
                    let mut buf = [0u8; 40];
                    <$kw>::new_from_slice(key).unwrap().wrap_key(&digest, &mut buf).unwrap().to_vec()
                }
                s => panic!("{s}"),
            }
        };
    }
    let out = match key.len() {
        16 => with_cipher!(aes::Aes128, aes_kw::KwAes128),
        24 => with_cipher!(aes::Aes192, aes_kw::KwAes192),
        32 => with_cipher!(aes::Aes256, aes_kw::KwAes256),
        n => panic!("AES key of {n} bytes"),
    };
    sri(&out)
}

/// The host oracle of a DES3 check value (`kcv-ecb`, `kcv-ecb-dec`): `RustCrypto`'s `des`
/// (three-key EDE) over the first 8 bytes of SHA-256 of the commitment label.
pub fn des3_commitment(key: &[u8; 24], scheme: &str) -> String {
    use des::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
    let label = format!("key-management/v1/{scheme}/CKK_DES3/192");
    let digest = <sha2::Sha256 as sha2::Digest>::digest(label.as_bytes());
    let mut block = des::cipher::Block::<des::TdesEde3>::default();
    block.copy_from_slice(&digest[..8]);
    let cipher = des::TdesEde3::new_from_slice(key).unwrap();
    match scheme {
        "kcv-ecb" => cipher.encrypt_block(&mut block),
        "kcv-ecb-dec" => cipher.decrypt_block(&mut block),
        s => panic!("{s}"),
    }
    sri(&block)
}

/// A logged-in session on `label` that finalizes the module when dropped. cryptoki >= 0.11 no
/// longer finalizes on drop, and tests need a fresh `C_Initialize` per session (tpm2-pkcs11 only
/// sees objects created by other processes after one).
pub struct TestSession {
    session: Option<Session>,
    ctx: Option<Pkcs11>,
}

impl std::ops::Deref for TestSession {
    type Target = Session;
    fn deref(&self) -> &Session {
        self.session.as_ref().unwrap()
    }
}

impl TestSession {
    /// Every object labelled `label`.
    pub fn labelled(&self, label: &str) -> Vec<cryptoki::object::ObjectHandle> {
        self.find_objects(&[Attribute::Label(label.as_bytes().to_vec())]).unwrap()
    }

    /// Destroy every object labelled with one of `labels`: the token is shared between runs.
    pub fn clear(&self, labels: &[&str]) {
        for h in labels.iter().flat_map(|l| self.labelled(l)) {
            self.destroy_object(h).unwrap();
        }
    }
}

impl Drop for TestSession {
    fn drop(&mut self) {
        drop(self.session.take());
        if let Some(ctx) = self.ctx.take() {
            let _ = ctx.finalize();
        }
    }
}

// TODO(docs/OPEN.md, "Engineering"): sessions opened on several test threads finalize the module under
// each other (SIGSEGV); the Nix builds run each test in a process of its own (nix/test-tokens.sh).
pub fn open_session(module: &str, label: &str, pin: &str) -> TestSession {
    let ctx = Pkcs11::new(module).unwrap();
    ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).unwrap();
    let slot = ctx
        .get_slots_with_token()
        .unwrap()
        .into_iter()
        .find(|s| ctx.get_token_info(*s).unwrap().label() == label)
        .unwrap();
    let session = ctx.open_rw_session(slot).unwrap();
    session.login(UserType::User, Some(&AuthPin::new(pin.into()))).unwrap();
    TestSession { session: Some(session), ctx: Some(ctx) }
}
