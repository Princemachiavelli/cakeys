//! The forwarders: one `extern "C"` function for each slot of the 2.40 `CK_FUNCTION_LIST`. Each
//! forwarder counts its call, asks the plan, and otherwise calls the real module's function with
//! the caller's arguments unchanged. The list below has the signatures of `cryptoki-sys`. The
//! table literal names every slot, so the code does not compile when a slot is missing.
//!
//! `=> hook` hands the call to `hooks::hook`, which forwards the call itself and may change what
//! the caller sees. `=> substitute_key` forwards the call with the third argument, a key,
//! replaced by the key that a rule names. (`=> wrap_key` and `=> unwrap_key` do this too, and
//! also replace the wrapped key or the unwrapped blob.) `=> corrupt_output` forwards the call
//! and then changes the returned bytes where a rule says so (`=> wrap_key` does this too).
//!
//! `[kind(args), ...]` names what is read from the arguments (`trace::Detail`). Before the call,
//! it is what the plan's matchers see: the mechanism, an input template's class and key type,
//! and the session and objects that `of_label` looks at. After the call returns, it is what the
//! trace records: the mechanism, a template, the user type, the session flags, and what an
//! output holds.

use crate::{Fatal, guard, hooks, shim};
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_BYTE, CK_FLAGS, CK_FUNCTION_LIST, CK_INFO, CK_MECHANISM, CK_MECHANISM_INFO,
    CK_MECHANISM_TYPE, CK_NOTIFY, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SESSION_INFO, CK_SLOT_ID,
    CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CK_USER_TYPE, CK_UTF8CHAR, CK_VERSION,
};
use std::os::raw::c_void;

macro_rules! forward {
    (@real $shim:ident, $name:ident) => {
        $shim.real.$name.ok_or_else(|| Fatal(format!("{} has no function", stringify!($name))))?
    };
    (@body $shim:ident, $call:ident, $name:ident, ($($arg:ident),*)) => {{
        let _ = $call;
        let real = forward!(@real $shim, $name);
        // SAFETY: the caller's arguments, passed on unchanged to the function the real module's
        // table holds in this slot; its contract is the caller's.
        Ok((unsafe { real($($arg),*) }, None))
    }};
    (@body $shim:ident, $call:ident, $name:ident, ($session:ident, $mechanism:ident, $key:ident $(, $rest:ident)*), substitute_key) => {{
        // SAFETY: the caller's session and key handle.
        let (key, fired) = unsafe { hooks::substitute_key($shim, $call, $session, $key) }?;
        let real = forward!(@real $shim, $name);
        // SAFETY: the caller's arguments, with the key a rule names in place of the caller's.
        Ok((unsafe { real($session, $mechanism, key $(, $rest)*) }, fired))
    }};
    (@body $shim:ident, $call:ident, $name:ident, ($session:ident, $input:ident, $n:ident, $out:ident, $len:ident), corrupt_output) => {{
        let real = forward!(@real $shim, $name);
        // SAFETY: the caller's arguments, forwarded unchanged; then the buffer it gave.
        Ok(unsafe { hooks::corrupt_output($shim, $call, $out, $len, || real($session, $input, $n, $out, $len)) })
    }};
    (@body $shim:ident, $call:ident, $name:ident, ($session:ident, $out:ident, $len:ident), corrupt_output) => {{
        let real = forward!(@real $shim, $name);
        // SAFETY: the caller's arguments, forwarded unchanged; then the buffer it gave.
        Ok(unsafe { hooks::corrupt_output($shim, $call, $out, $len, || real($session, $out, $len)) })
    }};
    (@body $shim:ident, $call:ident, $name:ident, ($($arg:ident),*), $hook:ident) => {
        // SAFETY: the caller's arguments; the hook forwards them under the caller's contract.
        unsafe { hooks::$hook($shim, $call, $($arg),*) }
    };
    (@hook) => {
        None
    };
    (@hook $hook:ident) => {
        Some(stringify!($hook))
    };
    ($($name:ident($($arg:ident: $ty:ty),* $(,)?) $(=> $hook:ident)? $([$($kind:ident($($oarg:ident),*)),+])?;)*) => {
        /// A forwarded function, which a plan names, and the index of its call counter.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[expect(non_camel_case_types, reason = "the PKCS#11 function names")]
        pub enum Fn {
            $(#[doc = concat!("`", stringify!($name), "`.")] $name),*
        }

        impl Fn {
            /// Every forwarded function, in table order.
            pub const ALL: &[Fn] = &[$(Fn::$name),*];

            /// The PKCS#11 name.
            #[must_use]
            pub fn name(self) -> &'static str {
                match self {
                    $(Fn::$name => stringify!($name)),*
                }
            }

            /// Returns what is read from the function's arguments (`[kind(args), ...]` in the
            /// table), which is what a rule's matchers can see of its calls. The list comes from
            /// the table and is not kept in a separate list.
            #[must_use]
            pub fn reads(self) -> &'static [&'static str] {
                match self {
                    $(Fn::$name => &[$($(stringify!($kind)),+)?]),*
                }
            }

            /// Returns the hook that the function's forwarder runs (`=> hook` in the table), if
            /// any, which decides what the plan parser lets a rule ask of the function. The value
            /// comes from the table and is not kept in a separate list (review 2026-11-23 B-18).
            #[must_use]
            pub fn hook(self) -> Option<&'static str> {
                match self {
                    $(Fn::$name => forward!(@hook $($hook)?)),*
                }
            }
        }

        $(
            #[expect(non_snake_case, reason = "the PKCS#11 function name")]
            unsafe extern "C" fn $name($($arg: $ty),*) -> CK_RV {
                guard(|| {
                    let shim = shim()?;
                    shim.call(
                        Fn::$name,
                        |call| forward!(@body shim, call, $name, ($($arg),*) $(, $hook)?),
                        |detail: &mut crate::trace::Detail| {
                            let _ = &detail;
                            // SAFETY: these are the caller's arguments, and the caller's call
                            // has not returned yet, so what the contract made readable at the
                            // start of the call is still readable now.
                            $($(
                                #[allow(unused_unsafe, reason = "one block for the safe readers and the unsafe ones")]
                                unsafe { detail.$kind($($oarg),*) };
                            )+)?
                        },
                    )
                })
            }
        )*

        /// Returns the shim's table: the real table's version, but never above 2.40, the shim's
        /// forwarder in every slot that the real module fills, and `NULL` where the real module
        /// leaves a slot empty. The table has the 2.40 layout, so a 3.x version on it would
        /// tell a client that picks the layout by version to read 24 slots past its end.
        pub(crate) fn table(real: &CK_FUNCTION_LIST) -> CK_FUNCTION_LIST {
            let v240 = CK_VERSION { major: 2, minor: 40 };
            CK_FUNCTION_LIST {
                version: if (real.version.major, real.version.minor) > (2, 40) { v240 } else { real.version },
                C_GetFunctionList: Some(crate::get_function_list),
                $($name: if real.$name.is_some() { Some($name) } else { None },)*
            }
        }
    };
}

forward! {
    C_Initialize(arg1: *mut c_void) [initialize(arg1)];
    C_Finalize(arg1: *mut c_void);
    C_GetInfo(arg1: *mut CK_INFO);
    C_GetSlotList(arg1: CK_BBOOL, arg2: *mut CK_SLOT_ID, arg3: *mut CK_ULONG);
    C_GetSlotInfo(arg1: CK_SLOT_ID, arg2: *mut CK_SLOT_INFO) => slot_info [slot_info(arg2)];
    C_GetTokenInfo(arg1: CK_SLOT_ID, arg2: *mut CK_TOKEN_INFO) => token_info [token_info(arg2)];
    C_GetMechanismList(arg1: CK_SLOT_ID, arg2: *mut CK_MECHANISM_TYPE, arg3: *mut CK_ULONG) => mechanism_list;
    C_GetMechanismInfo(arg1: CK_SLOT_ID, arg2: CK_MECHANISM_TYPE, arg3: *mut CK_MECHANISM_INFO) [mechanism_type(arg2), mechanism_info(arg3)];
    C_InitToken(arg1: CK_SLOT_ID, arg2: *mut CK_UTF8CHAR, arg3: CK_ULONG, arg4: *mut CK_UTF8CHAR);
    C_InitPIN(arg1: CK_SESSION_HANDLE, arg2: *mut CK_UTF8CHAR, arg3: CK_ULONG);
    C_SetPIN(arg1: CK_SESSION_HANDLE, arg2: *mut CK_UTF8CHAR, arg3: CK_ULONG, arg4: *mut CK_UTF8CHAR, arg5: CK_ULONG);
    C_OpenSession(arg1: CK_SLOT_ID, arg2: CK_FLAGS, arg3: *mut c_void, arg4: CK_NOTIFY, arg5: *mut CK_SESSION_HANDLE) [flags(arg2)];
    C_CloseSession(arg1: CK_SESSION_HANDLE);
    C_CloseAllSessions(arg1: CK_SLOT_ID);
    C_GetSessionInfo(arg1: CK_SESSION_HANDLE, arg2: *mut CK_SESSION_INFO);
    C_GetOperationState(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG);
    C_SetOperationState(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: CK_OBJECT_HANDLE, arg5: CK_OBJECT_HANDLE);
    C_Login(arg1: CK_SESSION_HANDLE, arg2: CK_USER_TYPE, arg3: *mut CK_UTF8CHAR, arg4: CK_ULONG) [user(arg2)];
    C_Logout(arg1: CK_SESSION_HANDLE);
    C_CreateObject(arg1: CK_SESSION_HANDLE, arg2: *mut CK_ATTRIBUTE, arg3: CK_ULONG, arg4: *mut CK_OBJECT_HANDLE) [template(arg2, arg3)];
    C_CopyObject(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG, arg5: *mut CK_OBJECT_HANDLE) [session(arg1), object(arg2), template(arg3, arg4)];
    C_DestroyObject(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE) [session(arg1), object(arg2)];
    C_GetObjectSize(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE, arg3: *mut CK_ULONG) [session(arg1), object(arg2)];
    C_GetAttributeValue(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG) => attribute_value [session(arg1), object(arg2), filled_template(arg3, arg4)];
    C_SetAttributeValue(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG) [session(arg1), object(arg2), template(arg3, arg4)];
    C_FindObjectsInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_ATTRIBUTE, arg3: CK_ULONG) => find_objects_init [template(arg2, arg3)];
    C_FindObjects(arg1: CK_SESSION_HANDLE, arg2: *mut CK_OBJECT_HANDLE, arg3: CK_ULONG, arg4: *mut CK_ULONG) => find_objects;
    C_FindObjectsFinal(arg1: CK_SESSION_HANDLE) => find_objects_final;
    C_EncryptInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE) => substitute_key [session(arg1), mechanism(arg2), object(arg3)];
    C_Encrypt(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG) => corrupt_output;
    C_EncryptUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_EncryptFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG);
    C_DecryptInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE) => substitute_key [session(arg1), mechanism(arg2), object(arg3)];
    C_Decrypt(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG) => corrupt_output;
    C_DecryptUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DecryptFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG);
    C_DigestInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM) [mechanism(arg2)];
    C_Digest(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DigestUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_DigestKey(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE) [session(arg1), object(arg2)];
    C_DigestFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG);
    C_SignInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE) => substitute_key [session(arg1), mechanism(arg2), object(arg3)];
    C_Sign(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG) => corrupt_output [session(arg1), signed(arg2, arg3, arg4, arg5)];
    C_SignUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_SignFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG) => corrupt_output;
    C_SignRecoverInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE) [session(arg1), mechanism(arg2), object(arg3)];
    C_SignRecover(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_VerifyInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE) => substitute_key [session(arg1), mechanism(arg2), object(arg3)];
    C_Verify(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: CK_ULONG);
    C_VerifyUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_VerifyFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_VerifyRecoverInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE) [session(arg1), mechanism(arg2), object(arg3)];
    C_VerifyRecover(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DigestEncryptUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DecryptDigestUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_SignEncryptUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DecryptVerifyUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_GenerateKey(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG, arg5: *mut CK_OBJECT_HANDLE) [mechanism(arg2), template(arg3, arg4)];
    C_GenerateKeyPair(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG, arg5: *mut CK_ATTRIBUTE, arg6: CK_ULONG, arg7: *mut CK_OBJECT_HANDLE, arg8: *mut CK_OBJECT_HANDLE) [mechanism(arg2), template(arg3, arg4), template(arg5, arg6)];
    C_WrapKey(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE, arg4: CK_OBJECT_HANDLE, arg5: *mut CK_BYTE, arg6: *mut CK_ULONG) => wrap_key [session(arg1), mechanism(arg2), object(arg3), object(arg4)];
    C_UnwrapKey(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE, arg4: *mut CK_BYTE, arg5: CK_ULONG, arg6: *mut CK_ATTRIBUTE, arg7: CK_ULONG, arg8: *mut CK_OBJECT_HANDLE) => unwrap_key [session(arg1), mechanism(arg2), object(arg3), template(arg6, arg7)];
    C_DeriveKey(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE, arg4: *mut CK_ATTRIBUTE, arg5: CK_ULONG, arg6: *mut CK_OBJECT_HANDLE) => substitute_key [session(arg1), mechanism(arg2), object(arg3), template(arg4, arg5)];
    C_SeedRandom(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_GenerateRandom(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_GetFunctionStatus(arg1: CK_SESSION_HANDLE);
    C_CancelFunction(arg1: CK_SESSION_HANDLE);
    C_WaitForSlotEvent(arg1: CK_FLAGS, arg2: *mut CK_SLOT_ID, arg3: *mut c_void);
}

#[cfg(test)]
mod tests {
    use super::table;
    use cryptoki_sys::CK_VERSION;

    /// The shim's table has the 2.40 layout, so it reports no version above 2.40, whatever the
    /// module behind it reports. An older version is passed on unchanged.
    #[test]
    fn the_table_says_no_more_than_2_40() {
        for ((major, minor), says) in [((3, 0), (2, 40)), ((3, 2), (2, 40)), ((2, 40), (2, 40)), ((2, 20), (2, 20))] {
            let mut real = crate::empty_table();
            real.version = CK_VERSION { major, minor };
            let v = table(&real).version;
            assert_eq!((v.major, v.minor), says, "a module reporting {major}.{minor}");
        }
    }
}
