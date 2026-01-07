use crate::utils::filetime_to_datetime;
use crate::win32_guards::*;
use chrono::{DateTime, Utc};
use std::ptr;
use windows::Win32::Security::Cryptography::*;

/// Maximum length for certificate subject name strings
const MAX_SUBJECT_NAME_LEN: usize = 256;

/// Information extracted from a certificate's signer
#[derive(Debug, Clone)]
pub struct SignerInfo {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
    pub thumbprint_sha1: String,
    pub thumbprint_sha256: String,
    pub valid_from: DateTime<Utc>,
    pub valid_to: DateTime<Utc>,
    pub signature_algorithm: String,
    pub digest_algorithm: String,
}

impl std::fmt::Display for SignerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Signed by: {}\nIssued by: {}\nSerial: {}\nSHA1 Thumbprint: {}\nSHA256 Thumbprint: {}\nValid from: {}\nValid to: {}\nSignature Algorithm: {}\nDigest Algorithm: {}",
            self.subject,
            self.issuer,
            self.serial_number,
            self.thumbprint_sha1,
            self.thumbprint_sha256,
            self.valid_from.format("%Y-%m-%d %H:%M:%S UTC"),
            self.valid_to.format("%Y-%m-%d %H:%M:%S UTC"),
            self.signature_algorithm,
            self.digest_algorithm
        )
    }
}

/// Extracts signer information from a signed file
///
/// # Arguments
/// * `path` - Path to the signed file (can be original file or catalog)
///
/// # Returns
/// Some(SignerInfo) if signer information was successfully extracted, None otherwise
///
/// # Note
/// This function uses CryptQueryObject to open the file's signature and extract
/// the signer certificate information. All resources are properly cleaned up.
pub fn extract_signer_info(path: &str) -> Option<SignerInfo> {
    let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

    let mut h_store = HCERTSTORE(ptr::null_mut());
    let mut h_msg: *mut std::ffi::c_void = ptr::null_mut();
    let mut dw_encoding_type: CERT_QUERY_ENCODING_TYPE = CERT_QUERY_ENCODING_TYPE(0);
    let mut dw_content_type: CERT_QUERY_CONTENT_TYPE = CERT_QUERY_CONTENT_TYPE(0);
    let mut dw_format_type: CERT_QUERY_FORMAT_TYPE = CERT_QUERY_FORMAT_TYPE(0);

    // Broaden supported content/format types to cover PS1 (PKCS7), catalogs (.cat as CTL) and others
    let content_flags = CERT_QUERY_CONTENT_TYPE_FLAGS(
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED.0
            | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED.0
            | CERT_QUERY_CONTENT_FLAG_CTL.0,
    );
    let format_flags = CERT_QUERY_FORMAT_TYPE_FLAGS(CERT_QUERY_FORMAT_FLAG_ALL.0);

    let result = unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide_path.as_ptr() as *const std::ffi::c_void,
            content_flags,
            format_flags,
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
        return None;
    }

    // Create guards for automatic resource cleanup
    let _store_guard = CertStoreHandle::new(h_store);
    let _msg_guard = CryptMsgHandle::new(h_msg);

    // Get the signer certificate - guard initializes the certificate context
    let cert_guard = std::ptr::NonNull::new(h_msg)
        .and_then(|h| CertContextHandle::from_crypto_message(h).ok())?;

    // Get the subject name
    let cert_info = unsafe { (*cert_guard.as_ptr()).pCertInfo };
    let subject = unsafe { &(*cert_info).Subject };
    let issuer = unsafe { &(*cert_info).Issuer };

    let mut subject_str = vec![0u16; MAX_SUBJECT_NAME_LEN];
    let subject_len = unsafe {
        CertNameToStrW(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            subject as *const CRYPT_INTEGER_BLOB,
            CERT_SIMPLE_NAME_STR,
            Some(&mut subject_str),
        )
    };

    let mut issuer_str = vec![0u16; MAX_SUBJECT_NAME_LEN];
    let issuer_len = unsafe {
        CertNameToStrW(
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            issuer as *const CRYPT_INTEGER_BLOB,
            CERT_SIMPLE_NAME_STR,
            Some(&mut issuer_str),
        )
    };

    if subject_len == 0 || issuer_len == 0 {
        return None;
    }

    subject_str.truncate(subject_len as usize - 1);
    let subject_name = String::from_utf16_lossy(&subject_str);

    issuer_str.truncate(issuer_len as usize - 1);
    let issuer_name = String::from_utf16_lossy(&issuer_str);

    // Extract serial number
    let serial_number_blob = unsafe { &(*cert_info).SerialNumber };
    let serial_bytes = unsafe {
        std::slice::from_raw_parts(
            serial_number_blob.pbData,
            serial_number_blob.cbData as usize,
        )
    };
    let serial_number = serial_bytes
        .iter()
        .rev()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join("");

    // Compute SHA1 thumbprint
    let cert_blob = unsafe { (*cert_guard.as_ptr()).pbCertEncoded };
    let cert_size = unsafe { (*cert_guard.as_ptr()).cbCertEncoded };
    let cert_data = unsafe { std::slice::from_raw_parts(cert_blob, cert_size as usize) };

    let mut sha1_hash = vec![0u8; 20];
    let mut sha1_len = 20u32;
    let sha1_result = unsafe {
        CryptHashCertificate(
            None,
            CALG_SHA1,
            0,
            cert_data,
            Some(sha1_hash.as_mut_ptr()),
            &mut sha1_len,
        )
    };

    let thumbprint_sha1 = if sha1_result.is_ok() {
        sha1_hash
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("")
    } else {
        String::from("Unknown")
    };

    // Compute SHA256 thumbprint
    let mut sha256_hash = vec![0u8; 32];
    let mut sha256_len = 32u32;
    let sha256_result = unsafe {
        CryptHashCertificate(
            None,
            CALG_SHA_256,
            0,
            cert_data,
            Some(sha256_hash.as_mut_ptr()),
            &mut sha256_len,
        )
    };

    let thumbprint_sha256 = if sha256_result.is_ok() {
        sha256_hash
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("")
    } else {
        String::from("Unknown")
    };

    // Get signature algorithm
    let sig_alg_oid = unsafe { (*cert_info).SignatureAlgorithm.pszObjId };
    let signature_algorithm = if !sig_alg_oid.is_null() {
        let oid_str = unsafe { sig_alg_oid.to_string() };
        match oid_str.ok().as_deref() {
            Some("1.2.840.113549.1.1.5") => "sha1RSA".to_string(),
            Some("1.2.840.113549.1.1.11") => "sha256RSA".to_string(),
            Some("1.2.840.113549.1.1.12") => "sha384RSA".to_string(),
            Some("1.2.840.113549.1.1.13") => "sha512RSA".to_string(),
            Some("1.2.840.10045.4.3.2") => "sha256ECDSA".to_string(),
            Some("1.2.840.10045.4.3.3") => "sha384ECDSA".to_string(),
            Some("1.2.840.10045.4.3.4") => "sha512ECDSA".to_string(),
            Some(oid) => oid.to_string(),
            None => "Unknown".to_string(),
        }
    } else {
        "Unknown".to_string()
    };

    // Get digest algorithm from message
    let mut digest_alg_param_size: u32 = 0;
    let get_param_result = unsafe {
        CryptMsgGetParam(
            h_msg,
            CMSG_SIGNER_HASH_ALGORITHM_PARAM,
            0,
            None,
            &mut digest_alg_param_size,
        )
    };

    let digest_algorithm = if get_param_result.is_ok() && digest_alg_param_size > 0 {
        let mut alg_buffer = vec![0u8; digest_alg_param_size as usize];
        let get_param_result2 = unsafe {
            CryptMsgGetParam(
                h_msg,
                CMSG_SIGNER_HASH_ALGORITHM_PARAM,
                0,
                Some(alg_buffer.as_mut_ptr() as *mut _),
                &mut digest_alg_param_size,
            )
        };

        if get_param_result2.is_ok() {
            let alg_info = unsafe { &*(alg_buffer.as_ptr() as *const CRYPT_ALGORITHM_IDENTIFIER) };
            let digest_oid = alg_info.pszObjId;
            if !digest_oid.is_null() {
                let oid_str = unsafe { digest_oid.to_string() };
                match oid_str.ok().as_deref() {
                    Some("1.3.14.3.2.26") => "SHA1".to_string(),
                    Some("2.16.840.1.101.3.4.2.1") => "SHA256".to_string(),
                    Some("2.16.840.1.101.3.4.2.2") => "SHA384".to_string(),
                    Some("2.16.840.1.101.3.4.2.3") => "SHA512".to_string(),
                    Some(oid) => oid.to_string(),
                    None => "Unknown".to_string(),
                }
            } else {
                "Unknown".to_string()
            }
        } else {
            "Unknown".to_string()
        }
    } else {
        "Unknown".to_string()
    };

    let not_before = unsafe { (*cert_info).NotBefore };
    let not_after = unsafe { (*cert_info).NotAfter };
    let valid_from = filetime_to_datetime(not_before);
    let valid_to = filetime_to_datetime(not_after);

    Some(SignerInfo {
        subject: subject_name.to_string(),
        issuer: issuer_name.to_string(),
        serial_number,
        thumbprint_sha1,
        thumbprint_sha256,
        valid_from,
        valid_to,
        signature_algorithm,
        digest_algorithm,
    })
}
