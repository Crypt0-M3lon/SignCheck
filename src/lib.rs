//! SignCheck - Windows code signature verification library
//!
//! This library provides functionality to verify both embedded (Authenticode) and catalog-based
//! code signatures on Windows PE files using Win32 WinTrust and Cryptography APIs.
//!
//! # Examples
//!
//! ```no_run
//! use signcheck::{check_embedded_signatures, check_catalog_signatures, SignatureStatus};
//!
//! let path = r"C:\Windows\System32\cmd.exe";
//! let embedded_result = check_embedded_signatures(path);
//! let catalog_result = check_catalog_signatures(path);
//!
//! if embedded_result.status == SignatureStatus::SignedAndValid {
//!     println!("File has valid embedded signature");
//! }
//! ```

pub mod error;
pub mod signer_info;
pub mod utils;
pub mod verification;
pub mod win32_guards;

#[cfg(test)]
mod tests;

// Re-export commonly used types for convenience
pub use error::{hr_to_trust_error, TrustError};
pub use signer_info::{extract_signer_info, SignerInfo};
pub use verification::{
    check_catalog_signatures, check_embedded_signatures, SignatureStatus, VerificationResult,
};
