use chrono::{DateTime, Utc};
use std::env;
use std::fmt;
use std::fs::File;
use std::ptr;
use windows::core::*;
use windows::Win32::Foundation::*;
use windows::Win32::Security::Cryptography::Catalog::*;
use windows::Win32::Security::Cryptography::*;
use windows::Win32::Security::WinTrust::*;

#[derive(Debug, PartialEq)]
enum TrustError {
    ProviderUnknown,
    SubjectNotTrusted,
    SubjectFormUnknown,
    NoSignature,
    BadDigest,
    TimeStamp,
    Critical,
    Expired,
    Revoked,
    UntrustedRoot,
    SecuritySettings,
    Chaining,
    UntrustedTestRoot,
    WrongUsage,
    NoRevocationCheck,
    RevocationOffline,
    CNNoMatch,
    FileError,
    Unknown(i32),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::ProviderUnknown => write!(f, "TRUST_E_PROVIDER_UNKNOWN: The trust provider is not recognized on this system."),
            TrustError::SubjectNotTrusted => write!(f, "TRUST_E_SUBJECT_NOT_TRUSTED: The subject failed the specified verification action."),
            TrustError::SubjectFormUnknown => write!(f, "TRUST_E_SUBJECT_FORM_UNKNOWN: The subject form specified is not one supported or known by the trust provider."),
            TrustError::NoSignature => write!(f, "TRUST_E_NOSIGNATURE: No signature was present in the subject."),
            TrustError::BadDigest => write!(f, "TRUST_E_BAD_DIGEST: The file's digest does not match the expected value."),
            TrustError::TimeStamp => write!(f, "TRUST_E_TIME_STAMP: The timestamp is invalid."),
            TrustError::Critical => write!(f, "CERT_E_CRITICAL: A certificate contains an unknown extension that is marked 'critical'."),
            TrustError::Expired => write!(f, "CERT_E_EXPIRED: The certificate has expired."),
            TrustError::Revoked => write!(f, "CERT_E_REVOKED: The certificate has been revoked."),
            TrustError::UntrustedRoot => write!(f, "CERT_E_UNTRUSTEDROOT: The certificate chain is not trusted."),
            TrustError::SecuritySettings => write!(f, "CRYPT_E_SECURITY_SETTINGS: Security settings prevented verification."),
            TrustError::Chaining => write!(f, "CERT_E_CHAINING: The certificate chain could not be built."),
            TrustError::UntrustedTestRoot => write!(f, "CERT_E_UNTRUSTEDTESTROOT: The certificate is based on an untrusted test root."),
            TrustError::WrongUsage => write!(f, "CERT_E_WRONG_USAGE: The certificate is not valid for the requested usage."),
            TrustError::NoRevocationCheck => write!(f, "CRYPT_E_NO_REVOCATION_CHECK: Revocation check was not performed."),
            TrustError::RevocationOffline => write!(f, "CRYPT_E_REVOCATION_OFFLINE: Revocation check failed because the revocation server was offline."),
            TrustError::CNNoMatch => write!(f, "CERT_E_CN_NO_MATCH: The certificate's common name does not match the expected name."),
            TrustError::FileError => write!(f, "CRYPT_E_FILE_ERROR: An error occurred while accessing a file."),
            TrustError::Unknown(code) => write!(f, "Unknown trust error (0x{:X})", code),
        }
    }
}

fn hr_to_trust_error(hr: i32) -> TrustError {
    match hr {
        x if x == TRUST_E_PROVIDER_UNKNOWN.0 => TrustError::ProviderUnknown,
        x if x == TRUST_E_SUBJECT_NOT_TRUSTED.0 => TrustError::SubjectNotTrusted,
        x if x == TRUST_E_SUBJECT_FORM_UNKNOWN.0 => TrustError::SubjectFormUnknown,
        x if x == TRUST_E_NOSIGNATURE.0 => TrustError::NoSignature,
        x if x == TRUST_E_BAD_DIGEST.0 => TrustError::BadDigest,
        x if x == TRUST_E_TIME_STAMP.0 => TrustError::TimeStamp,
        x if x == CERT_E_CRITICAL.0 => TrustError::Critical,
        x if x == CERT_E_EXPIRED.0 => TrustError::Expired,
        x if x == CERT_E_REVOKED.0 => TrustError::Revoked,
        x if x == CERT_E_UNTRUSTEDROOT.0 => TrustError::UntrustedRoot,
        x if x == CRYPT_E_SECURITY_SETTINGS.0 => TrustError::SecuritySettings,
        x if x == CERT_E_CHAINING.0 => TrustError::Chaining,
        x if x == CERT_E_UNTRUSTEDTESTROOT.0 => TrustError::UntrustedTestRoot,
        x if x == CERT_E_WRONG_USAGE.0 => TrustError::WrongUsage,
        x if x == CRYPT_E_NO_REVOCATION_CHECK.0 => TrustError::NoRevocationCheck,
        x if x == CRYPT_E_REVOCATION_OFFLINE.0 => TrustError::RevocationOffline,
        x if x == CERT_E_CN_NO_MATCH.0 => TrustError::CNNoMatch,
        x if x == CRYPT_E_FILE_ERROR.0 => TrustError::FileError,
        _ => TrustError::Unknown(hr),
    }
}

#[derive(Debug, PartialEq)]
enum SignatureStatus {
    SignedAndValid,
    NotSigned,
    VerificationFailed(TrustError),
    Unknown,
}

fn check_embedded_signatures(path: &str) -> (SignatureStatus, String) {
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

    // Map HRESULT to our `SignatureStatus` but ensure we close any WinVerifyTrust
    // state data via a final call with `WTD_STATEACTION_CLOSE` before returning.
    let status = if hr == S_OK.0 {
        SignatureStatus::SignedAndValid
    } else if hr == TRUST_E_NOSIGNATURE.0 {
        SignatureStatus::NotSigned
    } else {
        SignatureStatus::VerificationFailed(hr_to_trust_error(hr))
    };

    // If WinVerifyTrust populated `hWVTStateData`, close it to free resources.
    if trust_data.hWVTStateData != HANDLE(ptr::null_mut()) {
        unsafe {
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                HWND(ptr::null_mut()),
                &action as *const GUID as *mut GUID,
                &trust_data as *const WINTRUST_DATA as *mut std::ffi::c_void,
            );
        }
    }

    (status, path.to_string())
}

fn check_catalog_signatures(path: &str) -> (SignatureStatus, String) {
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
            return (SignatureStatus::Unknown, path.to_string());
        }
    };
    use std::os::windows::io::AsRawHandle;
    let raw = file.as_raw_handle();

    // Acquire a catalog admin context first; CryptCATAdminCalcHashFromFileHandle2
    // requires a valid hCatAdmin.
    let acquired_hcatadmin: Option<isize>;
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
            acquired_hcatadmin = Some(h_cat_admin);
        } else if res.is_err() {
            // Failed to acquire context
            eprintln!(
                "CryptCATAdminAcquireContext2 failed: {}",
                res.err().unwrap()
            );
            return (SignatureStatus::Unknown, path.to_string());
        } else {
            // No context acquired
            eprintln!("CryptCATAdminAcquireContext2 returned no context.");
            return (SignatureStatus::Unknown, path.to_string());
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
        return (SignatureStatus::Unknown, path.to_string());
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
        return (SignatureStatus::Unknown, path.to_string());
    }

    catalog_info.pbCalculatedFileHash = digest_vec.as_mut_ptr();
    catalog_info.cbCalculatedFileHash = digest_vec.len() as u32;

    // Try to enumerate a catalog that contains this hash and obtain its file path
    let h_cat_info: isize;
    unsafe {
        let res = CryptCATAdminEnumCatalogFromHash(
            h_cat_admin,
            &digest_vec[..],
            0u32, // dwFlags
            None, // previous catalog info handle
        );

        if res != 0 {
            h_cat_info = res;
        } else {
            // No catalog found for this hash; log last error
            let last_error: WIN32_ERROR = GetLastError();
            match last_error {
                ERROR_SERVICE_NOT_ACTIVE => {
                    eprintln!("CryptCATAdminEnumCatalogFromHash: CryptSvc service not active.");
                    return (SignatureStatus::Unknown, path.to_string());
                }
                ERROR_SERVICE_DISABLED => {
                    eprintln!("CryptCATAdminEnumCatalogFromHash: CryptSvc service disabled.");
                    return (SignatureStatus::Unknown, path.to_string());
                }
                ERROR_NOT_FOUND => {
                    return (SignatureStatus::NotSigned, path.to_string());
                }
                _ => {
                    eprintln!(
                        "CryptCATAdminEnumCatalogFromHash: failed with error code {}.",
                        last_error.0
                    );
                    return (SignatureStatus::Unknown, path.to_string());
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
        match CryptCATCatalogInfoFromContext(h_cat_info, &mut cat_info_struct, 0u32) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("CryptCATCatalogInfoFromContext: failed: {e}");
                return (SignatureStatus::Unknown, path.to_string());
            }
        }
        // Extract catalog file path as String
        let ptr_to_array = &cat_info_struct.wszCatalogFile as *const _ as *const u16;
        let len = (0..260)
            .position(|i| *ptr_to_array.add(i) == 0)
            .unwrap_or(260);
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

    // Release catalog admin handle if we acquired one
    if let Some(h) = acquired_hcatadmin {
        unsafe {
            let _ = CryptCATAdminReleaseContext(h, 0);
        }
    }

    let status = if hr == S_OK.0 {
        SignatureStatus::SignedAndValid
    } else if hr == TRUST_E_NOSIGNATURE.0 {
        SignatureStatus::NotSigned
    } else {
        SignatureStatus::VerificationFailed(hr_to_trust_error(hr))
    };

    // Close WinVerifyTrust state if present
    if trust_data.hWVTStateData != HANDLE(ptr::null_mut()) {
        unsafe {
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
            let _ = WinVerifyTrust(
                HWND(ptr::null_mut()),
                &action as *const GUID as *mut GUID,
                &trust_data as *const WINTRUST_DATA as *mut std::ffi::c_void,
            );
        }
    }

    (status, catalog_path)
}

fn filetime_to_datetime(ft: FILETIME) -> DateTime<Utc> {
    let time = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
    let unix = (time - 116444736000000000) / 10000000;
    DateTime::from_timestamp(unix as i64, 0)
        .unwrap_or_else(|| DateTime::from_timestamp(0, 0).unwrap())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];

    let (mut status, mut cert_path) = check_embedded_signatures(path);

    let signed_via;

    match status {
        SignatureStatus::NotSigned => {
            let (cat_status, cat_path) = check_catalog_signatures(path);
            status = cat_status;
            cert_path = cat_path;
            signed_via = "catalog";
        }
        SignatureStatus::VerificationFailed(TrustError::FileError) => {
            // Some files (catalog-signed) may return a file-access error during
            // embedded verification; try catalog verification as a fallback.
            let (cat_status, cat_path) = check_catalog_signatures(path);
            status = cat_status;
            cert_path = cat_path;
            signed_via = "catalog";
        }
        _ => {
            signed_via = "an embedded signature";
        }
    }

    match status {
        SignatureStatus::SignedAndValid => {
        println!("{path} is signed via {signed_via} and the signature is valid.");
        }
        SignatureStatus::VerificationFailed(err) => {
            println!("{path} signature verification failed: {}", err);
        }
        SignatureStatus::NotSigned => {
            println!("{path} is not signed.");
            return;
        }
        SignatureStatus::Unknown => {
            println!("{path} signature status is unknown.");
            return;
        }
    }

    // Use the correct path (original or catalog) for certificate extraction
    let wide_path: Vec<u16> = cert_path.encode_utf16().chain(std::iter::once(0)).collect();

    // Get signer information using CryptQueryObject
    let mut h_store = HCERTSTORE(ptr::null_mut());
    let mut h_msg: *mut std::ffi::c_void = ptr::null_mut();
    let mut dw_encoding_type: CERT_QUERY_ENCODING_TYPE = CERT_QUERY_ENCODING_TYPE(0);
    let mut dw_content_type: CERT_QUERY_CONTENT_TYPE = CERT_QUERY_CONTENT_TYPE(0);
    let mut dw_format_type: CERT_QUERY_FORMAT_TYPE = CERT_QUERY_FORMAT_TYPE(0);

    let result = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const std::ffi::c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            Some(&mut dw_encoding_type as *mut CERT_QUERY_ENCODING_TYPE),
            Some(&mut dw_content_type as *mut CERT_QUERY_CONTENT_TYPE),
            Some(&mut dw_format_type as *mut CERT_QUERY_FORMAT_TYPE),
            Some(&mut h_store as *mut HCERTSTORE),
            Some(&mut h_msg),
            None,
        )
    };

    if result.is_err() {
        println!("Failed to query the signed file.");
        return;
    }

    // Get the signer certificate
    let mut signer_cert: *mut CERT_CONTEXT = ptr::null_mut();
    let result =
        unsafe { CryptMsgGetAndVerifySigner(h_msg, None, 0, Some(&mut signer_cert), None) };

    if result.is_err() {
        println!("Failed to get the signer certificate.");
        unsafe {
            let _ = CryptMsgClose(Some(h_msg));
            let _ = CertCloseStore(h_store, 0);
        }
        return;
    }

    // Get the subject name
    let cert_info = unsafe { (*signer_cert).pCertInfo };
    let subject = unsafe { &(*cert_info).Subject };

    let mut subject_str = vec![0u16; 256];
    let len = unsafe {
        CertNameToStrW(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            subject as *const CRYPT_INTEGER_BLOB,
            CERT_SIMPLE_NAME_STR,
            Some(&mut subject_str),
        )
    };

    if len > 0 {
        subject_str.truncate(len as usize - 1); // remove null terminator
        let subject_name = String::from_utf16_lossy(&subject_str);
        println!("Signed by: {}", subject_name);

        let not_before = unsafe { (*cert_info).NotBefore };
        let not_after = unsafe { (*cert_info).NotAfter };
        let valid_from = filetime_to_datetime(not_before);
        let valid_to = filetime_to_datetime(not_after);
        println!("Valid from: {}", valid_from.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("Valid to: {}", valid_to.format("%Y-%m-%d %H:%M:%S UTC"));
    } else {
        println!("Failed to get the subject name.");
    }

    // Clean up
    unsafe {
        let _ = CertFreeCertificateContext(Some(signer_cert));
        let _ = CryptMsgClose(Some(h_msg));
        let _ = CertCloseStore(h_store, 0);
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn firefox_signature_is_valid() {
        // Path to the Firefox binary (typical install location on Windows)
        let path = r"C:\Program Files\Mozilla Firefox\firefox.exe";
        if !std::path::Path::new(path).exists() {
            panic!(
                "Firefox binary not found at {}. Please install Firefox to run this test.",
                path
            );
        }

        let (status, _path_used) = check_embedded_signatures(path);

        match status {
            SignatureStatus::SignedAndValid => {}
            _ => panic!("Firefox signature is not valid: {:?}", status),
        }
    }

    #[test]
    fn self_signed_test_binary_is_not_trusted() {
        // Path to the test app built by `test_apps/self_signed`
        let path = "test_apps/self_signed/target/release/self_signed.exe";

        if !std::path::Path::new(path).exists() {
            panic!("Test binary not found at {}. Build and sign it with: scripts\\create_self_signed_and_sign.ps1", path);
        }

        let (status, _path_used) = check_embedded_signatures(path);

        // Because the certificate is self-signed and NOT imported into the user store,
        // WinVerifyTrust should return `CERT_E_UNTRUSTEDROOT`.
        match status {
            SignatureStatus::VerificationFailed(TrustError::UntrustedRoot) => {}
            _ => panic!("Expected CERT_E_UNTRUSTEDROOT, got: {:?}", status),
        }
    }

    #[test]
    fn system_cmd_catalog_path() {
        // Path to Windows cmd.exe (catalog-signed on modern Windows)
        let path = r"C:\Windows\System32\cmd.exe";
        if !std::path::Path::new(path).exists() {
            panic!(
                "cmd.exe not found at {}. This test requires a standard Windows install.",
                path
            );
        }

        let (status, checked_path) = check_embedded_signatures(path);

        // cmd.exe should not be signed with an embedded signature
        assert!(
            status != SignatureStatus::SignedAndValid,
            "cmd.exe should not be signed with embedded signature"
        );

        let (final_status, final_path) = match status {
            SignatureStatus::NotSigned
            | SignatureStatus::VerificationFailed(TrustError::FileError) => {
                check_catalog_signatures(path)
            }
            _ => (status, checked_path.clone()),
        };

        match final_status {
            SignatureStatus::SignedAndValid => {
                // The checked path should be the catalog, not the original file
                assert_ne!(
                    final_path.to_lowercase(),
                    path.to_lowercase(),
                    "Catalog path should differ from input file path"
                );
                assert!(
                    final_path.to_lowercase().ends_with(".cat"),
                    "Catalog path should end with .cat, got: {}",
                    final_path
                );
            }
            _ => panic!(
                "cmd.exe should be catalog-signed, got status: {:?}, path: {}",
                final_status, final_path
            ),
        }
    }
}
