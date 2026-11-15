//! The forwarders: one `extern "C"` function per slot of the 2.40 `CK_FUNCTION_LIST`, each
//! counting its call, asking the plan, and otherwise calling the real module's function with
//! the caller's arguments unchanged. The list below is `cryptoki-sys`'s signatures; the table
//! literal names every slot, so a slot missing from it does not compile.

use crate::{guard, shim};
use cryptoki_sys::{
    CK_ATTRIBUTE, CK_BBOOL, CK_BYTE, CK_FLAGS, CK_FUNCTION_LIST, CK_INFO, CK_MECHANISM, CK_MECHANISM_INFO,
    CK_MECHANISM_TYPE, CK_NOTIFY, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SESSION_INFO, CK_SLOT_ID,
    CK_SLOT_INFO, CK_TOKEN_INFO, CK_ULONG, CK_USER_TYPE, CK_UTF8CHAR,
};
use std::os::raw::c_void;

macro_rules! forward {
    ($($name:ident($($arg:ident: $ty:ty),* $(,)?);)*) => {
        /// A forwarded function: what a plan names, and the index of its call counter.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        #[expect(non_camel_case_types, reason = "the PKCS#11 function names")]
        pub enum Fn {
            $($name),*
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
        }

        $(
            #[expect(non_snake_case, reason = "the PKCS#11 function name")]
            unsafe extern "C" fn $name($($arg: $ty),*) -> CK_RV {
                guard(|| {
                    shim()?.call(Fn::$name, |real| {
                        // SAFETY: the caller's arguments, passed on unchanged to the function the
                        // real module's table holds in this slot; its contract is the caller's.
                        real.$name.map(|f| unsafe { f($($arg),*) })
                    })
                })
            }
        )*

        /// The shim's table: the real one's version, our forwarder in every slot the real
        /// module fills, and `NULL` where it leaves one empty.
        pub(crate) fn table(real: &CK_FUNCTION_LIST) -> CK_FUNCTION_LIST {
            CK_FUNCTION_LIST {
                version: real.version,
                C_GetFunctionList: Some(crate::C_GetFunctionList),
                $($name: if real.$name.is_some() { Some($name) } else { None },)*
            }
        }
    };
}

forward! {
    C_Initialize(arg1: *mut c_void);
    C_Finalize(arg1: *mut c_void);
    C_GetInfo(arg1: *mut CK_INFO);
    C_GetSlotList(arg1: CK_BBOOL, arg2: *mut CK_SLOT_ID, arg3: *mut CK_ULONG);
    C_GetSlotInfo(arg1: CK_SLOT_ID, arg2: *mut CK_SLOT_INFO);
    C_GetTokenInfo(arg1: CK_SLOT_ID, arg2: *mut CK_TOKEN_INFO);
    C_GetMechanismList(arg1: CK_SLOT_ID, arg2: *mut CK_MECHANISM_TYPE, arg3: *mut CK_ULONG);
    C_GetMechanismInfo(arg1: CK_SLOT_ID, arg2: CK_MECHANISM_TYPE, arg3: *mut CK_MECHANISM_INFO);
    C_InitToken(arg1: CK_SLOT_ID, arg2: *mut CK_UTF8CHAR, arg3: CK_ULONG, arg4: *mut CK_UTF8CHAR);
    C_InitPIN(arg1: CK_SESSION_HANDLE, arg2: *mut CK_UTF8CHAR, arg3: CK_ULONG);
    C_SetPIN(arg1: CK_SESSION_HANDLE, arg2: *mut CK_UTF8CHAR, arg3: CK_ULONG, arg4: *mut CK_UTF8CHAR, arg5: CK_ULONG);
    C_OpenSession(arg1: CK_SLOT_ID, arg2: CK_FLAGS, arg3: *mut c_void, arg4: CK_NOTIFY, arg5: *mut CK_SESSION_HANDLE);
    C_CloseSession(arg1: CK_SESSION_HANDLE);
    C_CloseAllSessions(arg1: CK_SLOT_ID);
    C_GetSessionInfo(arg1: CK_SESSION_HANDLE, arg2: *mut CK_SESSION_INFO);
    C_GetOperationState(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG);
    C_SetOperationState(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: CK_OBJECT_HANDLE, arg5: CK_OBJECT_HANDLE);
    C_Login(arg1: CK_SESSION_HANDLE, arg2: CK_USER_TYPE, arg3: *mut CK_UTF8CHAR, arg4: CK_ULONG);
    C_Logout(arg1: CK_SESSION_HANDLE);
    C_CreateObject(arg1: CK_SESSION_HANDLE, arg2: *mut CK_ATTRIBUTE, arg3: CK_ULONG, arg4: *mut CK_OBJECT_HANDLE);
    C_CopyObject(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG, arg5: *mut CK_OBJECT_HANDLE);
    C_DestroyObject(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE);
    C_GetObjectSize(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE, arg3: *mut CK_ULONG);
    C_GetAttributeValue(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG);
    C_SetAttributeValue(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG);
    C_FindObjectsInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_ATTRIBUTE, arg3: CK_ULONG);
    C_FindObjects(arg1: CK_SESSION_HANDLE, arg2: *mut CK_OBJECT_HANDLE, arg3: CK_ULONG, arg4: *mut CK_ULONG);
    C_FindObjectsFinal(arg1: CK_SESSION_HANDLE);
    C_EncryptInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE);
    C_Encrypt(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_EncryptUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_EncryptFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG);
    C_DecryptInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE);
    C_Decrypt(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DecryptUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DecryptFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG);
    C_DigestInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM);
    C_Digest(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DigestUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_DigestKey(arg1: CK_SESSION_HANDLE, arg2: CK_OBJECT_HANDLE);
    C_DigestFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG);
    C_SignInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE);
    C_Sign(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_SignUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_SignFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: *mut CK_ULONG);
    C_SignRecoverInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE);
    C_SignRecover(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_VerifyInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE);
    C_Verify(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: CK_ULONG);
    C_VerifyUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_VerifyFinal(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_VerifyRecoverInit(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE);
    C_VerifyRecover(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DigestEncryptUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DecryptDigestUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_SignEncryptUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_DecryptVerifyUpdate(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG, arg4: *mut CK_BYTE, arg5: *mut CK_ULONG);
    C_GenerateKey(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG, arg5: *mut CK_OBJECT_HANDLE);
    C_GenerateKeyPair(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: *mut CK_ATTRIBUTE, arg4: CK_ULONG, arg5: *mut CK_ATTRIBUTE, arg6: CK_ULONG, arg7: *mut CK_OBJECT_HANDLE, arg8: *mut CK_OBJECT_HANDLE);
    C_WrapKey(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE, arg4: CK_OBJECT_HANDLE, arg5: *mut CK_BYTE, arg6: *mut CK_ULONG);
    C_UnwrapKey(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE, arg4: *mut CK_BYTE, arg5: CK_ULONG, arg6: *mut CK_ATTRIBUTE, arg7: CK_ULONG, arg8: *mut CK_OBJECT_HANDLE);
    C_DeriveKey(arg1: CK_SESSION_HANDLE, arg2: *mut CK_MECHANISM, arg3: CK_OBJECT_HANDLE, arg4: *mut CK_ATTRIBUTE, arg5: CK_ULONG, arg6: *mut CK_OBJECT_HANDLE);
    C_SeedRandom(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_GenerateRandom(arg1: CK_SESSION_HANDLE, arg2: *mut CK_BYTE, arg3: CK_ULONG);
    C_GetFunctionStatus(arg1: CK_SESSION_HANDLE);
    C_CancelFunction(arg1: CK_SESSION_HANDLE);
    C_WaitForSlotEvent(arg1: CK_FLAGS, arg2: *mut CK_SLOT_ID, arg3: *mut c_void);
}
