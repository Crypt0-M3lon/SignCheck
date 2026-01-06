use crate::error::{hr_to_trust_error, TrustError};
use crate::win32_guards::*;
use std::fs::File;
use std::ptr;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Cryptography::Catalog::*;
use windows::Win32::Security::WinTrust::*;

/// Maximum length for catalog file paths
pub const MAX_CATALOG_PATH_LEN: usize = 260;

/// PE signature constants
const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // MZ
const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // PE\0\0

/// Checks if a PE file has a security directory entry but no valid signature data
/// This can indicate a stripped signature
fn detect_stripped_signature(path: &str) -> bool {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    use std::io::{Read, Seek, SeekFrom};

    // Read DOS header
    let mut dos_header = [0u8; 64];
    if file.read_exact(&mut dos_header).is_err() {
        return false;
    }

    // Check MZ signature
    let dos_sig = u16::from_le_bytes([dos_header[0], dos_header[1]]);
    if dos_sig != IMAGE_DOS_SIGNATURE {
        return false;
    }

    // Get PE header offset
    let pe_offset = u32::from_le_bytes([
        dos_header[60],
        dos_header[61],
        dos_header[62],
        dos_header[63],
    ]);

    // Seek to PE header
    if file.seek(SeekFrom::Start(pe_offset as u64)).is_err() {
        return false;
    }

    // Read PE signature
    let mut pe_sig = [0u8; 4];
    if file.read_exact(&mut pe_sig).is_err() {
        return false;
    }

    if u32::from_le_bytes(pe_sig) != IMAGE_NT_SIGNATURE {
        return false;
    }

    // Read COFF header (20 bytes)
    let mut coff_header = [0u8; 20];
    if file.read_exact(&mut coff_header).is_err() {
        return false;
    }

    let size_of_optional_header = u16::from_le_bytes([coff_header[16], coff_header[17]]);
    if size_of_optional_header < 96 {
        return false; // Too small to contain data directories
    }

    // Read optional header magic to determine PE32 vs PE32+
    let mut magic = [0u8; 2];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }

    let magic_val = u16::from_le_bytes(magic);
    let data_dir_offset = match magic_val {
        0x10b => 96,  // PE32
        0x20b => 112, // PE32+
        _ => return false,
    };

    // Seek to data directories (skip rest of optional header standard fields)
    if file
        .seek(SeekFrom::Start(
            pe_offset as u64 + 24 + 20 + data_dir_offset,
        ))
        .is_err()
    {
        return false;
    }

    // Read security directory entry (5th directory entry, 8 bytes)
    // Skip first 4 directory entries (32 bytes each = 8 bytes)
    let mut skip = [0u8; 32];
    if file.read_exact(&mut skip).is_err() {
        return false;
    }

    let mut security_dir = [0u8; 8];
    if file.read_exact(&mut security_dir).is_err() {
        return false;
    }

    let security_rva = u32::from_le_bytes([
        security_dir[0],
        security_dir[1],
        security_dir[2],
        security_dir[3],
    ]);
    let security_size = u32::from_le_bytes([
        security_dir[4],
        security_dir[5],
        security_dir[6],
        security_dir[7],
    ]);

    // If security directory exists but points to nothing or invalid data
    if security_rva == 0 && security_size == 0 {
        return false; // No security directory entry at all
    }

    if security_rva != 0 && security_size > 0 {
        // Security directory exists, check if data is actually there and valid
        if file.seek(SeekFrom::Start(security_rva as u64)).is_err() {
            return true; // Directory points to invalid location
        }

        let mut sig_header = [0u8; 8];
        if file.read_exact(&mut sig_header).is_err() {
            return true; // Can't read signature data
        }

        let actual_size =
            u32::from_le_bytes([sig_header[0], sig_header[1], sig_header[2], sig_header[3]]);

        // Check if the signature appears to be zeroed out or invalid
        if actual_size == 0 || actual_size != security_size {
            return true; // Signature data is invalid
        }
    }

    false
}

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
    /// Signature appears to have been stripped (security directory exists but signature is invalid/missing)
    SignatureStripped,
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
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

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
        // Check if signature was stripped
        if detect_stripped_signature(path) {
            SignatureStatus::SignatureStripped
        } else {
            SignatureStatus::NotSigned
        }
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
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

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
