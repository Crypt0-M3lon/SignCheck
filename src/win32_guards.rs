// RAII-style guards for Win32 handles and contexts
// These automatically clean up resources when dropped, ensuring exception-safe code

use std::ops::Deref;
use std::ptr;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Cryptography::Catalog::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::WinTrust::*;

/// RAII guard for certificate context handles
/// Automatically calls CertFreeCertificateContext on drop
pub struct CertContextHandle(*mut CERT_CONTEXT);

impl CertContextHandle {
    pub fn as_ptr(&self) -> *mut CERT_CONTEXT {
        self.0
    }

    /// Initializes a certificate context by extracting the signer from a crypto message
    pub fn from_crypto_message(h_msg: *mut std::ffi::c_void) -> Result<Self> {
        let mut signer_cert: *mut CERT_CONTEXT = ptr::null_mut();
        let result =
            unsafe { CryptMsgGetAndVerifySigner(h_msg, None, 0, Some(&mut signer_cert), None) };

        match result {
            Ok(_) => Ok(CertContextHandle(signer_cert)),
            Err(e) => Err(e),
        }
    }
}

impl Deref for CertContextHandle {
    type Target = *mut CERT_CONTEXT;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for CertContextHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0));
            }
        }
    }
}

/// RAII guard for cryptographic message handles
/// Automatically calls CryptMsgClose on drop
pub struct CryptMsgHandle(*mut std::ffi::c_void);

impl CryptMsgHandle {
    pub fn new(ptr: *mut std::ffi::c_void) -> Self {
        CryptMsgHandle(ptr)
    }
}

impl Deref for CryptMsgHandle {
    type Target = *mut std::ffi::c_void;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for CryptMsgHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CryptMsgClose(Some(self.0));
            }
        }
    }
}

/// RAII guard for certificate store handles
/// Automatically calls CertCloseStore on drop
pub struct CertStoreHandle(HCERTSTORE);

impl CertStoreHandle {
    pub fn new(handle: HCERTSTORE) -> Self {
        CertStoreHandle(handle)
    }
}

impl Deref for CertStoreHandle {
    type Target = HCERTSTORE;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for CertStoreHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CertCloseStore(self.0, 0);
        }
    }
}

/// RAII guard for catalog context handles within a catalog admin context
/// Takes ownership of the catalog admin context to ensure proper cleanup order
pub struct CatalogGuard {
    h_cat_admin: isize,
    catalog_handle: isize,
}

impl CatalogGuard {
    pub fn new(h_cat_admin: isize, catalog_handle: isize) -> Self {
        CatalogGuard {
            h_cat_admin,
            catalog_handle,
        }
    }
}

impl Drop for CatalogGuard {
    fn drop(&mut self) {
        unsafe {
            // Release catalog context first, then admin context
            let _ = CryptCATAdminReleaseCatalogContext(self.h_cat_admin, self.catalog_handle, 0);
            let _ = CryptCATAdminReleaseContext(self.h_cat_admin, 0);
        }
    }
}

/// RAII guard for WinVerifyTrust state data
/// Automatically calls WTD_STATEACTION_CLOSE on drop if state was opened
pub struct WinVerifyTrustGuard {
    state_data: HANDLE,
}

impl WinVerifyTrustGuard {
    pub fn new(state_data: HANDLE) -> Self {
        WinVerifyTrustGuard { state_data }
    }

    /// Close the state if it was opened (state_data is not null)
    pub fn close_if_needed(&mut self) {
        if self.state_data != HANDLE(ptr::null_mut()) {
            unsafe {
                let trust_data = WINTRUST_DATA {
                    cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
                    pPolicyCallbackData: ptr::null_mut(),
                    pSIPClientData: ptr::null_mut(),
                    dwUIChoice: WTD_UI_NONE,
                    fdwRevocationChecks: WTD_REVOKE_NONE,
                    dwUnionChoice: WTD_CHOICE_FILE,
                    Anonymous: std::mem::zeroed(),
                    dwStateAction: WTD_STATEACTION_CLOSE,
                    hWVTStateData: self.state_data,
                    pwszURLReference: PWSTR(ptr::null_mut()),
                    dwProvFlags: WTD_REVOCATION_CHECK_NONE,
                    dwUIContext: WINTRUST_DATA_UICONTEXT(0),
                    pSignatureSettings: ptr::null_mut(),
                };

                let action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                let _ = WinVerifyTrust(
                    HWND(ptr::null_mut()),
                    &action as *const GUID as *mut GUID,
                    &trust_data as *const WINTRUST_DATA as *mut std::ffi::c_void,
                );
            }
        }
    }
}

impl Drop for WinVerifyTrustGuard {
    fn drop(&mut self) {
        self.close_if_needed();
    }
}
