use std::fmt;

/// Represents errors that can occur during signature verification
#[derive(Debug, PartialEq, Clone)]
pub enum TrustError {
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

/// Converts an HRESULT code to a TrustError enum
///
/// # Arguments
/// * `hr` - The HRESULT code from a Windows trust verification API
///
/// # Returns
/// A TrustError variant corresponding to the HRESULT, or Unknown if not recognized
pub fn hr_to_trust_error(hr: i32) -> TrustError {
    match hr {
        -2146869247 => TrustError::ProviderUnknown, // TRUST_E_PROVIDER_UNKNOWN
        -2146762751 => TrustError::SubjectNotTrusted, // TRUST_E_SUBJECT_NOT_TRUSTED
        -2146869246 => TrustError::SubjectFormUnknown, // TRUST_E_SUBJECT_FORM_UNKNOWN
        -2146762496 => TrustError::NoSignature,     // TRUST_E_NOSIGNATURE
        -2146869244 => TrustError::BadDigest,       // TRUST_E_BAD_DIGEST
        -2146869243 => TrustError::TimeStamp,       // TRUST_E_TIME_STAMP
        -2146762491 => TrustError::Critical,        // CERT_E_CRITICAL
        -2146762495 => TrustError::Expired,         // CERT_E_EXPIRED
        -2146762484 => TrustError::Revoked,         // CERT_E_REVOKED
        -2146762487 => TrustError::UntrustedRoot,   // CERT_E_UNTRUSTEDROOT
        -2146893819 => TrustError::SecuritySettings, // CRYPT_E_SECURITY_SETTINGS
        -2146762485 => TrustError::Chaining,        // CERT_E_CHAINING
        -2146762483 => TrustError::UntrustedTestRoot, // CERT_E_UNTRUSTEDTESTROOT
        -2146762482 => TrustError::WrongUsage,      // CERT_E_WRONG_USAGE
        -2146885616 => TrustError::NoRevocationCheck, // CRYPT_E_NO_REVOCATION_CHECK
        -2146885615 => TrustError::RevocationOffline, // CRYPT_E_REVOCATION_OFFLINE
        -2146762481 => TrustError::CNNoMatch,       // CERT_E_CN_NO_MATCH
        -2146885629 => TrustError::FileError,       // CRYPT_E_FILE_ERROR
        _ => TrustError::Unknown(hr),
    }
}
