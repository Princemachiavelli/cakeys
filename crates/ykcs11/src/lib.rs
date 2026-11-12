//! Yubico ykcs11 (YubiKey PIV). Its `CKA_PUBLIC_KEY_INFO` quirk (length 0, then
//! `CKR_ARGUMENTS_BAD`) is tolerated by the generic token code for every module.

use cakeys_pkcs11::provider::{user_login, Provider};
use cryptoki::error::Error as CkError;
use cryptoki::error::RvError;
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use cakeys_pkcs11::token::ModuleInfo;
use cakeys_core::{KmError, Result};

pub struct Ykcs11;

impl Provider for Ykcs11 {
    fn name(&self) -> &'static str {
        "ykcs11"
    }

    fn matches(&self, m: &ModuleInfo) -> bool {
        m.manufacturer.starts_with("Yubico")
    }

    /// ykcs11 keeps one login state per token, and its management operations (generate, import,
    /// delete) need the SO state, which a user login cannot coexist with. With an admin
    /// credential configured (`mgmKeyFile`/`mgmKeyEnv`: the PIV management key in hex, or the
    /// PIN on PIN-protected-management-key devices), log in as SO instead — that path also
    /// verifies the PIN, so private-key operations work in the same run. Without one, this is
    /// the default user login.
    fn login(&self, session: &Session, pin: Option<&str>, admin: Option<&str>) -> Result<()> {
        match admin {
            Some(cred) => match session.login(UserType::So, Some(&AuthPin::new(cred.to_owned().into()))) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
                Err(e) => Err(KmError::Unavailable(format!(
                    "C_Login(SO) with the management-key credential: {e}; mgmKeyFile/mgmKeyEnv \
                     must hold the PIV management key, or the PIN on a PIN-protected device"
                ))),
            },
            None => user_login(session, pin),
        }
    }
}
