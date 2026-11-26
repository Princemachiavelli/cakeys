//! The login code: the PIN guard, the session that a token opens, and the SO steps (review
//! 2026-11-23 B-5).

#[allow(
    clippy::wildcard_imports,
    reason = "the token/ split files work on the parent module's imports (R9); `expect` is not fulfilled on a `use` item"
)]
use super::*;

/// The PIN counters that `C_GetTokenInfo` reports (M2). A login on the final try, or with a
/// locked PIN, is refused before it is attempted, so that a wrong PIN file never uses up the last
/// retry (PIV allows only a few retries).
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct PinState {
    pub(super) user: Pin,
    pub(super) so: Pin,
}

/// The counters of one PIN.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Pin {
    pub(super) locked: bool,
    pub(super) final_try: bool,
    /// A login has failed since the last success, but retries remain. This is a warning, and it
    /// never causes a refusal.
    pub(super) count_low: bool,
}

impl Pin {
    /// Refuses a login as `who` (the user or the SO) with `Unavailable` when the counters say
    /// that the PIN is locked or that only the final try is left.
    fn guard(self, token: &str, who: &str) -> Result<()> {
        let Pin { locked, final_try, .. } = self;
        if locked {
            return Err(KmError::Unavailable(
                format!(
                    "token '{token}': the {who} PIN is locked (CKF_{}_PIN_LOCKED); unlock it with the vendor's tools",
                    who.to_uppercase()
                )
                .into(),
            ));
        }
        if final_try {
            return Err(KmError::Unavailable(
                format!(
                    "token '{token}': one {who} PIN try is left before it locks (CKF_{}_PIN_FINAL_TRY); cakeys will \
                 not spend it on a PIN file that may be wrong — log in once by hand with the right PIN to reset \
                 the counter",
                    who.to_uppercase()
                )
                .into(),
            ));
        }
        Ok(())
    }
}

impl Token {
    /// Runs `step` in a Security Officer session (`soCredentialFile` or `soCredentialEnv`), for
    /// modules that create and destroy objects only as the SO, and then returns to the user
    /// session. The login state belongs to the token, so the user is logged out first. The admin
    /// credential is read here, never at open, and it is zeroized when the step ends. A step that
    /// is already in the SO session runs directly. `Token::create` and the destroys enter the SO
    /// session before the provider's override runs, and the override may ask for it again
    /// ([`Token::managing`]).
    ///
    /// # Errors
    ///
    /// - `Unsupported` when no admin credential is configured.
    /// - `Unavailable` when the SO login, the logout or the return to the user session fails,
    ///   when the PIN counters refuse a login, or when the SO credential was already refused
    ///   earlier in this run.
    /// - Otherwise, whatever `step` returns.
    pub fn as_so<T>(&self, what: &str, step: impl FnOnce() -> Result<T>) -> Result<T> {
        use std::sync::atomic::Ordering;
        if self.in_so.load(Ordering::Relaxed) {
            return step();
        }
        let so = read_so_credential(&self.name, &self.cfg)?.ok_or_else(|| {
            self.unsupported(format!(
                "{what} on '{}' needs a Security Officer session: set tokens.{}.soCredentialFile or soCredentialEnv",
                self.name, self.name
            ))
        })?;
        self.pins.so.guard(&self.name, "SO")?;
        if self.so_refused.load(Ordering::Relaxed) {
            return Err(KmError::Unavailable(
                format!(
                    "token '{}': the SO credential was refused earlier in this run; it is not tried again, \
                     which could spend the last retry",
                    self.name
                )
                .into(),
            ));
        }
        if self.logged_in {
            self.session.logout().map_err(ck("C_Logout"))?;
        }
        let out = match self.session.login(UserType::So, Some(&AuthPin::new(so.as_str().to_owned().into()))) {
            Ok(()) => {
                self.in_so.store(true, Ordering::Relaxed);
                let out = logged_in_as(&self.session, UserType::So, &self.name).and_then(|()| step());
                self.in_so.store(false, Ordering::Relaxed);
                let logout = self.session.logout().map_err(ck("C_Logout (SO)"));
                so_outcome(what, &self.name, out, logout)
            }
            Err(e) => Err({
                self.so_refused.store(true, Ordering::Relaxed);
                KmError::Unavailable(
                    format!(
                        "{SO_LOGIN} with soCredentialFile/soCredentialEnv: {rv}; it must hold the module's admin \
                 credential (the SO PIN; ykcs11: the PIV management key in hex, or the PIN on a \
                 device whose management key is PIN-protected)",
                        rv = rv_name(&e)
                    )
                    .into(),
                )
                .with_rv(rv_of(&e))
            }),
        };
        drop(so);
        if !self.logged_in {
            return out;
        }
        let back = match self.pin.as_deref() {
            None => Err(KmError::Unavailable("no user PIN to log back in with".into())),
            Some(pin) => match self.session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
                Ok(()) | Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {
                    logged_in_as(&self.session, UserType::User, &self.name)
                }
                Err(e) => Err(KmError::Unavailable(format!("C_Login (back to the user): {}", rv_name(&e)).into())
                    .with_rv(rv_of(&e))),
            },
        };
        so_outcome(what, &self.name, out, back)
    }
}

/// Checks that `session` shows the login as `who` that the module just accepted. A module that
/// answers `CKR_OK` to `C_Login` but leaves the session public hides every private object, so a
/// search would report a key that it cannot see as absent (review 2026-11-24, found by the lead
/// through the Phase 2 design). `C_GetSessionInfo` reports the session's state.
///
/// # Errors
///
/// `Unavailable` (exit 16) when the session is not in the state of `who`, or when the state
/// cannot be read.
pub(super) fn logged_in_as(session: &Session, who: UserType, token: &str) -> Result<()> {
    use cryptoki::session::SessionState;
    let state = session.get_session_info().map_err(ck("C_GetSessionInfo"))?.session_state();
    let shown = match who {
        UserType::So => state == SessionState::RwSecurityOfficer,
        _ => matches!(state, SessionState::RoUser | SessionState::RwUser),
    };
    if shown {
        return Ok(());
    }
    Err(KmError::Unavailable(
        format!(
            "token '{token}': C_Login ({who:?}) succeeded, but the session is not logged in (C_GetSessionInfo: \
             {state:?}): the module would hide every private object, so nothing it finds or misses is trusted"
        )
        .into(),
    ))
}

/// Returns the result of [`Token::as_so`] after the session is restored (`after` is the result of
/// the SO logout and then of the user's login). The step's own result comes first. A step that
/// failed is reported with its own error, and never with the session error that followed it.
/// When the step succeeded but the session could not be restored, the error says that the step
/// was done, so that a caller never believes that a key it made (or a trusted copy) was not
/// made.
pub(super) fn so_outcome<T>(what: &str, token: &str, step: Result<T>, after: Result<()>) -> Result<T> {
    match (step, after) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), _) => Err(e),
        (Ok(_), Err(e)) => {
            let rv = e.rv();
            Err(KmError::Unavailable(
                format!(
                    "{what} on '{token}' was done, but the session could not be restored afterwards ({e}): \
                     what it made or changed is on the token"
                )
                .into(),
            )
            .with_rv(rv))
        }
    }
}

/// Returns whether `access` opens a read-write session on the token `name`, given whether the
/// token is `write_protected`. A session is read-write only for a write, or for scratch objects
/// when the token allows it. A write on a write-protected token is refused (exit 15). Its dry run
/// is refused too, although it opens read-only, because a dry run refuses what its real run
/// refuses (review 2026-11-24 L4a-3).
fn read_write(access: Access, write_protected: bool, name: &str) -> Result<bool> {
    match access {
        Access::Write | Access::DryWrite if write_protected => Err(KmError::Unsupported(
            format!(
                "token '{name}' is write-protected (CKF_WRITE_PROTECTED): it can be read, never created on or \
                 deleted from"
            )
            .into(),
        )),
        Access::Write => Ok(true),
        Access::Scratch => Ok(!write_protected),
        Access::Read | Access::DryWrite => Ok(false),
    }
}

/// Opens the session that `access` asks for (M1, [`read_write`]), and logs in as the user when a
/// PIN is configured. The login is refused when the counters say that it must not be tried (M2).
#[expect(clippy::too_many_arguments, reason = "the open's parts, as Token::open has them")]
pub(super) fn session(
    ctx: &Pkcs11,
    logins: &Logins,
    slot: cryptoki::slot::Slot,
    name: &str,
    cfg: &TokenCfg,
    access: Access,
    write_protected: bool,
    pins: PinState,
) -> Result<(Session, Option<Zeroizing<String>>)> {
    let session = if read_write(access, write_protected, name)? {
        ctx.open_rw_session(slot).map_err(ck("C_OpenSession"))?
    } else {
        ctx.open_ro_session(slot).map_err(ck("C_OpenSession (read-only)"))?
    };
    let pin = read_pin(name, cfg)?;
    if let Some(pin) = pin.as_deref() {
        pins.user.guard(name, "user")?;
        let mut logins = logins.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match session.login(UserType::User, Some(&AuthPin::new(pin.to_owned().into()))) {
            Ok(()) => {
                logins.insert(slot.id(), Zeroizing::new(pin.to_owned()));
            }
            // An existing login is kept only when this process logged in with the same PIN,
            // because the PIN is used again in places where a wrong PIN uses up a retry (a PIV
            // context login, the TPM unseal).
            Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _))
                if logins.get(&slot.id()).is_some_and(|p| p.as_str() == pin) => {}
            Err(CkError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {
                return Err(KmError::Unavailable(
                    format!(
                        "token '{name}': already logged in by another session of this process with another PIN, so \
                         this token's PIN cannot be checked"
                    )
                    .into(),
                ));
            }
            Err(e) => return Err(KmError::Unavailable(format!("C_Login: {}", rv_name(&e)).into()).with_rv(rv_of(&e))),
        }
        logged_in_as(&session, UserType::User, name)?;
    }
    Ok((session, pin))
}

/// Reads the user PIN from `pinEnv`, or otherwise from `pinFile`, whose `$NAME` variables are
/// resolved at this point.
pub(super) fn read_pin(name: &str, cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    // `pinEnv` takes precedence, so an unset variable in `pinFile` is not an error in that case.
    let file = if cfg.pin_env.is_some() { None } else { cfg.pin_path(name, &|var| std::env::var(var).ok())? };
    cakeys_core::secret::read("PIN", cfg.pin_env.as_deref(), file.as_deref())
}

/// Returns whether keys.toml gives the token an admin (Security Officer) credential, which
/// [`Token::as_so`] reads.
#[must_use]
pub fn has_admin(cfg: &TokenCfg) -> bool {
    cfg.so_credential_file.is_some() || cfg.so_credential_env.is_some()
}

/// Reads the admin credential from `soCredentialEnv`, or otherwise from `soCredentialFile`. It is
/// read only for an SO step. The module defines the format: ykcs11 takes the PIV management key
/// in hex, or the PIN on devices whose management key is PIN-protected.
pub(super) fn read_so_credential(name: &str, cfg: &TokenCfg) -> Result<Option<Zeroizing<String>>> {
    let file = if cfg.so_credential_env.is_some() {
        None
    } else {
        cfg.so_credential_path(name, &|var| std::env::var(var).ok())?
    };
    cakeys_core::secret::read("SO credential", cfg.so_credential_env.as_deref(), file.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests every access on a write-protected token and on a token that is not. A dry run of a
    /// write refuses exactly what the write refuses (exit 15), and it never opens a read-write
    /// session. Only a write and scratch work open read-write sessions, and scratch work never
    /// does so on a write-protected token. A read refuses nothing (review 2026-11-24 L4a-3:
    /// `create --dry-run` and `delete --dry-run` used to pass on a write-protected token).
    #[test]
    fn a_dry_run_refuses_the_token_its_write_refuses() {
        for access in [Access::Read, Access::Write, Access::Scratch, Access::DryWrite] {
            let writes = match access {
                Access::Write | Access::DryWrite => true,
                Access::Read | Access::Scratch => false,
            };
            for protected in [false, true] {
                let got = read_write(access, protected, "t").map_err(|e| e.exit_code());
                let want = match access {
                    _ if writes && protected => Err(15),
                    Access::Write => Ok(true),
                    Access::Scratch => Ok(!protected),
                    Access::Read | Access::DryWrite => Ok(false),
                };
                assert_eq!(got, want, "{access:?}, write-protected {protected}");
            }
        }
        for protected in [false, true] {
            assert_eq!(
                read_write(Access::DryWrite, protected, "t").is_err(),
                read_write(Access::Write, protected, "t").is_err(),
                "write-protected {protected}"
            );
        }
    }

    /// `as_so` reports the step's result first (token/mod.rs F2). When a step succeeded and the
    /// logout or the login that follows fails, the error says that the step was done. A step that
    /// failed is never hidden behind the session error that followed it.
    #[test]
    fn the_so_step_is_reported_before_the_session_trouble() {
        let trouble = || Err(KmError::Unavailable("C_Logout (SO): CKR_DEVICE_ERROR".into()));
        assert_eq!(so_outcome("generating a key", "piv", Ok(7), Ok(())).unwrap(), 7);
        let done = so_outcome("generating a key", "piv", Ok(7), trouble()).unwrap_err();
        assert!(
            matches!(&done, KmError::Unavailable(m) if m.contains("generating a key on 'piv' was done")
                && m.contains("CKR_DEVICE_ERROR")),
            "{done}"
        );
        let failed =
            so_outcome::<()>("generating a key", "piv", Err(KmError::Unsupported("refused".into())), trouble());
        assert!(matches!(failed, Err(KmError::Unsupported(m)) if *m == *"refused"));
    }
}
