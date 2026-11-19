//! One module, named two ways, is one library (token/mod.rs F3): a token naming it by its bare
//! file name (the loader's search) and one naming it by path open side by side, the second
//! sharing the library the first initialized; a second `C_Initialize` would be refused
//! (`CKR_CRYPTOKI_ALREADY_INITIALIZED`). Skipped without `CAKEYS_TEST_MODULE`.

use cakeys_core::config::TokenCfg;
use cakeys_pkcs11::token::Access;
use cakeys_pkcs11::{ChainTime, Registry, Token};

/// Set in the run this test starts of itself, with the loader's search path.
const CHILD: &str = "CAKEYS_LIBRARY_CHILD";

fn token(module: &str, pin: &std::path::Path) -> TokenCfg {
    toml::from_str(&format!("module = \"{module}\"\ntokenLabel = \"kmtest\"\npinFile = \"{}\"\n", pin.display()))
        .unwrap()
}

#[test]
fn a_bare_name_and_a_path_share_one_library() {
    let Ok(module) = std::env::var("CAKEYS_TEST_MODULE") else {
        // As every token suite: required where the harness says so.
        assert!(std::env::var("CAKEYS_TEST_REQUIRE").is_err(), "CAKEYS_TEST_MODULE is required");
        eprintln!("skipping library: CAKEYS_TEST_MODULE is not set");
        return;
    };
    let path = std::path::Path::new(&module);
    let (dir, name) = (path.parent().unwrap(), path.file_name().unwrap().to_str().unwrap());
    if std::env::var_os(CHILD).is_none() {
        // The loader reads its search path when the process starts: this test, again, with it.
        let o = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["a_bare_name_and_a_path_share_one_library", "--exact", "--nocapture"])
            .env(CHILD, "1")
            .env("LD_LIBRARY_PATH", dir)
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
        assert!(o.status.success() && said.contains("1 passed"), "{said}");
        return;
    }
    cakeys_profile::Set::activate_embedded().unwrap();
    let pin = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cakeys-pkcs11-library-pin");
    std::fs::write(&pin, "1234\n").unwrap();
    let registry = Registry::new();
    let bare = Token::open("bare", &token(name, &pin), None, &registry, Access::Read, ChainTime::Unchecked).unwrap();
    let pathed = Token::open("pathed", &token(&module, &pin), None, &registry, Access::Read, ChainTime::Unchecked)
        .unwrap_or_else(|e| panic!("the module by path, beside it by bare name: {e}"));
    drop((bare, pathed));
}
