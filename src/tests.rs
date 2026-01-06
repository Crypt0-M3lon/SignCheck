#[cfg(test)]
mod tests {
    use crate::error::TrustError;
    use crate::verification::{
        check_catalog_signatures, check_embedded_signatures, SignatureStatus,
    };

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

        let result = check_embedded_signatures(path);

        match result.status {
            SignatureStatus::SignedAndValid => {}
            _ => panic!("Firefox signature is not valid: {:?}", result.status),
        }
    }

    #[test]
    fn self_signed_test_binary_is_not_trusted() {
        // Path to the test app built by `test_apps/self_signed`
        let path = "test_apps/self_signed/target/release/self_signed.exe";

        if !std::path::Path::new(path).exists() {
            panic!("Test binary not found at {}. Build and sign it with: scripts\\create_self_signed_and_sign.ps1", path);
        }

        let result = check_embedded_signatures(path);

        // Because the certificate is self-signed and NOT imported into the user store,
        // WinVerifyTrust should return `CERT_E_UNTRUSTEDROOT`.
        match result.status {
            SignatureStatus::VerificationFailed(TrustError::UntrustedRoot) => {}
            _ => panic!("Expected CERT_E_UNTRUSTEDROOT, got: {:?}", result.status),
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

        let mut result = check_embedded_signatures(path);

        // cmd.exe should not be signed with an embedded signature
        assert!(
            result.status != SignatureStatus::SignedAndValid,
            "cmd.exe should not be signed with embedded signature"
        );

        result = match result.status {
            SignatureStatus::NotSigned
            | SignatureStatus::VerificationFailed(TrustError::FileError) => {
                check_catalog_signatures(path)
            }
            _ => result,
        };

        match result.status {
            SignatureStatus::SignedAndValid => {
                // The checked path should be the catalog, not the original file
                assert_ne!(
                    result.cert_path.to_lowercase(),
                    path.to_lowercase(),
                    "Catalog path should differ from input file path"
                );
                assert!(
                    result.cert_path.to_lowercase().ends_with(".cat"),
                    "Catalog path should end with .cat, got: {}",
                    result.cert_path
                );
                assert!(
                    result.is_catalog_signed,
                    "Should be marked as catalog-signed"
                );
            }
            _ => panic!(
                "cmd.exe should be catalog-signed, got status: {:?}, path: {}",
                result.status, result.cert_path
            ),
        }
    }

    #[test]
    fn self_signed_powershell_script_is_not_trusted() {
        let path = "test_apps/self_signed_ps1/test.ps1";
        if !std::path::Path::new(path).exists() {
            panic!("PS1 script not found at {}. Generate and sign it with: scripts\\create_self_signed_ps1_and_sign.ps1", path);
        }

        let result = check_embedded_signatures(path);
        match result.status {
            SignatureStatus::VerificationFailed(TrustError::UntrustedRoot) => {}
            _ => panic!("Expected CERT_E_UNTRUSTEDROOT for self-signed PS1, got: {:?}", result.status),
        }
    }
}
