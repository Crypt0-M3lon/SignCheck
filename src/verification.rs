use crate::error::{hr_to_trust_error, TrustError};
use crate::utils::to_wide_null_terminated;
use crate::win32_guards::*;
use std::fs::File;
use std::ptr;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Cryptography::Catalog::*;
use windows::Win32::Security::WinTrust::*;

/// Maximum length for catalog file paths
pub const MAX_CATALOG_PATH_LEN: usize = 260;

/// Represents the signature status of a file
#[non_exhaustive]
#[derive(Debug, PartialEq, Clone)]
pub enum SignatureStatus {
    /// File is signed and the signature is valid
    SignedAndValid,
    /// File has no signature
    NotSigned,
    /// Signature verification failed with a specific error
    VerificationFailed(TrustError),
    /// Unable to determine signature status
    Unknown,
}

/// Result of signature verification for a file
#[derive(Debug)]
pub struct VerificationResult {
    /// Path to the file that was verified
    pub file_path: String,
    /// Signature status of the file
    pub status: SignatureStatus,
    /// Path to the catalog file if catalog-signed, or the original file if embedded-signed
    pub cert_path: String,
    /// Whether the signature was via catalog or embedded
    pub is_catalog_signed: bool,
}

impl VerificationResult {
    /// Creates a new verification result
    pub fn new(
        file_path: String,
        status: SignatureStatus,
        cert_path: String,
        is_catalog_signed: bool,
    ) -> Self {
        Self {
            file_path,
            status,
            cert_path,
            is_catalog_signed,
        }
    }

    /// Returns the signature type description
    pub fn signature_type(&self) -> &str {
        if self.is_catalog_signed {
            "catalog"
        } else {
            "an embedded signature"
        }
    }
}

/// Checks for embedded (Authenticode) signatures in a PE file
///
/// # Arguments
/// * `path` - File path to check for embedded signatures
///
/// # Returns
/// A VerificationResult containing the status and paths
///
/// # Note
/// This function calls WinVerifyTrust with the file path to verify embedded signatures.
/// It properly cleans up WinVerifyTrust state data before returning.
pub fn check_embedded_signatures(path: &str) -> VerificationResult {
    // Convert path to wide string
    let wide_path: Vec<u16> = to_wide_null_terminated(path);

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR::from_raw(wide_path.as_ptr()),
        hFile: HANDLE(ptr::null_mut()),
        pgKnownSubject: ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: ptr::null_mut(),
        pSIPClientData: ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: unsafe { std::mem::zeroed() }, // Initialize union to zero
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: HANDLE(ptr::null_mut()),
        pwszURLReference: PWSTR(ptr::null_mut()),
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN,
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: ptr::null_mut(),
    };

    trust_data.Anonymous.pFile = &mut file_info as *mut _;

    let action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hr = unsafe {
        WinVerifyTrust(
            HWND(ptr::null_mut()),
            &action as *const GUID as *mut GUID,
            &trust_data as *const WINTRUST_DATA as *mut std::ffi::c_void,
        )
    };

    // Map HRESULT to our `SignatureStatus`. WinVerifyTrust state is automatically
    // cleaned up via the WinVerifyTrustGuard when it goes out of scope.
    let _guard = WinVerifyTrustGuard::new(trust_data.hWVTStateData);

    let status = if hr == S_OK.0 {
        SignatureStatus::SignedAndValid
    } else if hr == TRUST_E_NOSIGNATURE.0 {
        SignatureStatus::NotSigned
    } else {
        SignatureStatus::VerificationFailed(hr_to_trust_error(hr))
    };

    VerificationResult::new(path.to_string(), status, path.to_string(), false)
}

/// Checks for catalog signatures for a file
///
/// # Arguments
/// * `path` - File path to check for catalog signatures
///
/// # Returns
/// A VerificationResult containing the status and catalog path
///
/// # Note
/// This function computes the file's hash, searches for a matching catalog in the system,
/// and verifies the catalog's signature. It properly releases all acquired resources.
pub fn check_catalog_signatures(path: &str) -> VerificationResult {
    // Convert path to wide string
    let wide_path: Vec<u16> = to_wide_null_terminated(path);

    let mut catalog_info = WINTRUST_CATALOG_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
        dwCatalogVersion: 0,
        pcwszCatalogFilePath: PCWSTR(ptr::null_mut()),
        pcwszMemberTag: PCWSTR(ptr::null_mut()),
        pcwszMemberFilePath: PCWSTR::from_raw(wide_path.as_ptr()),
        hMemberFile: HANDLE(ptr::null_mut()),
        pbCalculatedFileHash: ptr::null_mut(),
        cbCalculatedFileHash: 0,
        pcCatalogContext: ptr::null_mut(),
        hCatAdmin: 0,
    };

    // Use CryptCATAdminCalcHashFromFileHandle2 to compute the catalog file hash
    // Open file and obtain native HANDLE
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open file for catalog verification: {e}");
            return VerificationResult::new(
                path.to_string(),
                SignatureStatus::Unknown,
                path.to_string(),
                true,
            );
        }
    };
    use std::os::windows::io::AsRawHandle;
    let raw = file.as_raw_handle();

    // Acquire a catalog admin context first; CryptCATAdminCalcHashFromFileHandle2
    // requires a valid hCatAdmin.
    let mut h_cat_admin: isize = 0;
    unsafe {
        let res = CryptCATAdminAcquireContext2(
            &mut h_cat_admin as *mut isize,
            Some(&DRIVER_ACTION_VERIFY as *const GUID),
            PCWSTR::null(), // pwszHashAlgorithm
            None,           // pStrongSignPara
            0u32,           // dwFlags
        );
        if res.is_ok() && h_cat_admin != 0 {
            catalog_info.hCatAdmin = h_cat_admin;
        } else if res.is_err() {
            // Failed to acquire context
            eprintln!(
                "CryptCATAdminAcquireContext2 failed: {}",
                res.err().unwrap()
            );
            return VerificationResult::new(
                path.to_string(),
                SignatureStatus::Unknown,
                path.to_string(),
                true,
            );
        } else {
            // No context acquired
            eprintln!("CryptCATAdminAcquireContext2 returned no context.");
            return VerificationResult::new(
                path.to_string(),
                SignatureStatus::Unknown,
                path.to_string(),
                true,
            );
        }
    }

    // First call to get the required buffer size, then allocate and call again
    let mut cb_hash: u32 = 0;

    // Convert raw handle to `HANDLE` for the windows API
    let h_file = HANDLE(raw);

    let res = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            h_cat_admin,
            h_file,
            &mut cb_hash as *mut u32,
            None, // pbHash
            0u32,
        )
    };

    if res.is_err() || cb_hash == 0 {
        eprintln!("Failed to calculate file hash for catalog verification.");
        unsafe {
            let _ = CryptCATAdminReleaseContext(h_cat_admin, 0);
        }
        return VerificationResult::new(
            path.to_string(),
            SignatureStatus::Unknown,
            path.to_string(),
            true,
        );
    }

    let mut digest_vec = vec![0u8; cb_hash as usize];
    let res = unsafe {
        CryptCATAdminCalcHashFromFileHandle2(
            h_cat_admin,
            h_file,
            &mut cb_hash as *mut u32,
            Some(digest_vec.as_mut_ptr()),
            0u32,
        )
    };

    if res.is_err() {
        eprintln!("Failed to calculate file hash for catalog verification.");
        unsafe {
            let _ = CryptCATAdminReleaseContext(h_cat_admin, 0);
        }
        return VerificationResult::new(
            path.to_string(),
            SignatureStatus::Unknown,
            path.to_string(),
            true,
        );
    }

    catalog_info.pbCalculatedFileHash = digest_vec.as_mut_ptr();
    catalog_info.cbCalculatedFileHash = digest_vec.len() as u32;

    // Try to enumerate a catalog that contains this hash and obtain its file path
    let catalog_handle: isize;
    unsafe {
        let res = CryptCATAdminEnumCatalogFromHash(
            h_cat_admin,
            &digest_vec[..],
            0u32, // dwFlags
            None, // previous catalog info handle
        );

        if res != 0 {
            catalog_handle = res;
        } else {
            // No catalog found for this hash; log last error
            let last_error: WIN32_ERROR = GetLastError();
            let _ = CryptCATAdminReleaseContext(h_cat_admin, 0);
            match last_error {
                ERROR_SERVICE_NOT_ACTIVE => {
                    eprintln!("CryptCATAdminEnumCatalogFromHash: CryptSvc service not active.");
                    return VerificationResult::new(
                        path.to_string(),
                        SignatureStatus::Unknown,
                        path.to_string(),
                        true,
                    );
                }
                ERROR_SERVICE_DISABLED => {
                    eprintln!("CryptCATAdminEnumCatalogFromHash: CryptSvc service disabled.");
                    return VerificationResult::new(
                        path.to_string(),
                        SignatureStatus::Unknown,
                        path.to_string(),
                        true,
                    );
                }
                ERROR_NOT_FOUND => {
                    return VerificationResult::new(
                        path.to_string(),
                        SignatureStatus::NotSigned,
                        path.to_string(),
                        true,
                    );
                }
                _ => {
                    eprintln!(
                        "CryptCATAdminEnumCatalogFromHash: failed with error code {}.",
                        last_error.0
                    );
                    return VerificationResult::new(
                        path.to_string(),
                        SignatureStatus::Unknown,
                        path.to_string(),
                        true,
                    );
                }
            }
        }
    }

    // If we got a catalog context, try to read its info (catalog file path)
    // and copy the embedded `wszCatalogFile` into `catalog_info.pcwszCatalogFilePath`.
    // Keep `cat_info_struct` alive until WinVerifyTrust returns.
    let catalog_path: String;
    unsafe {
        let mut cat_info_struct: CATALOG_INFO = std::mem::zeroed();
        match CryptCATCatalogInfoFromContext(catalog_handle, &mut cat_info_struct, 0u32) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("CryptCATCatalogInfoFromContext: failed: {e}");
                let _ = CryptCATAdminReleaseCatalogContext(h_cat_admin, catalog_handle, 0);
                let _ = CryptCATAdminReleaseContext(h_cat_admin, 0);
                return VerificationResult::new(
                    path.to_string(),
                    SignatureStatus::Unknown,
                    path.to_string(),
                    true,
                );
            }
        }
        // Extract catalog file path as String
        let ptr_to_array = &cat_info_struct.wszCatalogFile as *const _ as *const u16;
        let len = (0..MAX_CATALOG_PATH_LEN)
            .position(|i| *ptr_to_array.add(i) == 0)
            .unwrap_or(MAX_CATALOG_PATH_LEN);
        let slice = std::slice::from_raw_parts(ptr_to_array, len);
        catalog_path = String::from_utf16_lossy(slice);
        catalog_info.pcwszCatalogFilePath = PCWSTR(ptr_to_array);
    }

    catalog_info.pcwszMemberFilePath = PCWSTR::from_raw(wide_path.as_ptr());

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: ptr::null_mut(),
        pSIPClientData: ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: unsafe { std::mem::zeroed() }, // Initialize union to zero
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: HANDLE(ptr::null_mut()),
        pwszURLReference: PWSTR(ptr::null_mut()),
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN,
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: ptr::null_mut(),
    };

    trust_data.Anonymous.pCatalog = &catalog_info as *const _ as *mut _;

    let action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hr = unsafe {
        WinVerifyTrust(
            HWND(ptr::null_mut()),
            &action as *const GUID as *mut GUID,
            &trust_data as *const WINTRUST_DATA as *mut std::ffi::c_void,
        )
    };

    let status = if hr == S_OK.0 {
        SignatureStatus::SignedAndValid
    } else if hr == TRUST_E_NOSIGNATURE.0 {
        SignatureStatus::NotSigned
    } else {
        SignatureStatus::VerificationFailed(hr_to_trust_error(hr))
    };

    // Catalog resources are automatically cleaned up via CatalogGuard when it goes out of scope
    let _guard = CatalogGuard::new(h_cat_admin, catalog_handle);

    VerificationResult::new(path.to_string(), status, catalog_path, true)
}
