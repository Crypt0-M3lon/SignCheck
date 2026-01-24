use std::fmt;

// HRESULT codes from Windows SDK (WinTrust/Crypto APIs)
// Using hex format for easier verification against Microsoft documentation
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B_0001_u32 as i32;
const TRUST_E_SUBJECT_NOT_TRUSTED: i32 = 0x800B_0004_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0002_u32 as i32;
const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100_u32 as i32;
const TRUST_E_BAD_DIGEST: i32 = 0x800B_0104_u32 as i32;
const TRUST_E_TIME_STAMP: i32 = 0x8009_6005_u32 as i32;
const CERT_E_CRITICAL: i32 = 0x800B_0105_u32 as i32;
const CERT_E_EXPIRED: i32 = 0x800B_0101_u32 as i32;
const CERT_E_REVOKED: i32 = 0x800B_010C_u32 as i32;
const CERT_E_UNTRUSTEDROOT: i32 = 0x800B_0109_u32 as i32;
const CRYPT_E_SECURITY_SETTINGS: i32 = 0x8009_2026_u32 as i32;
const CERT_E_CHAINING: i32 = 0x800B_010A_u32 as i32;
const CERT_E_UNTRUSTEDTESTROOT: i32 = 0x800B_010D_u32 as i32;
const CERT_E_WRONG_USAGE: i32 = 0x800B_0110_u32 as i32;
const CRYPT_E_NO_REVOCATION_CHECK: i32 = 0x8009_2012_u32 as i32;
const CRYPT_E_REVOCATION_OFFLINE: i32 = 0x8009_2013_u32 as i32;
const CERT_E_CN_NO_MATCH: i32 = 0x800B_010F_u32 as i32;
const CRYPT_E_FILE_ERROR: i32 = 0x8009_2003_u32 as i32;

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
        TRUST_E_PROVIDER_UNKNOWN => TrustError::ProviderUnknown,
        TRUST_E_SUBJECT_NOT_TRUSTED => TrustError::SubjectNotTrusted,
        TRUST_E_SUBJECT_FORM_UNKNOWN => TrustError::SubjectFormUnknown,
        TRUST_E_NOSIGNATURE => TrustError::NoSignature,
        TRUST_E_BAD_DIGEST => TrustError::BadDigest,
        TRUST_E_TIME_STAMP => TrustError::TimeStamp,
        CERT_E_CRITICAL => TrustError::Critical,
        CERT_E_EXPIRED => TrustError::Expired,
        CERT_E_REVOKED => TrustError::Revoked,
        CERT_E_UNTRUSTEDROOT => TrustError::UntrustedRoot,
        CRYPT_E_SECURITY_SETTINGS => TrustError::SecuritySettings,
        CERT_E_CHAINING => TrustError::Chaining,
        CERT_E_UNTRUSTEDTESTROOT => TrustError::UntrustedTestRoot,
        CERT_E_WRONG_USAGE => TrustError::WrongUsage,
        CRYPT_E_NO_REVOCATION_CHECK => TrustError::NoRevocationCheck,
        CRYPT_E_REVOCATION_OFFLINE => TrustError::RevocationOffline,
        CERT_E_CN_NO_MATCH => TrustError::CNNoMatch,
        CRYPT_E_FILE_ERROR => TrustError::FileError,
        _ => TrustError::Unknown(hr),
    }
}
