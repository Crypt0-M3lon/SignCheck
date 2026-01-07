use signcheck::{
    check_catalog_signatures, check_embedded_signatures, extract_signer_info, SignatureStatus,
    VerificationResult,
};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];

    // Check both embedded and catalog signatures
    let embedded_result = check_embedded_signatures(path);
    let catalog_result = check_catalog_signatures(path);

    // Check if either signature is valid
    let is_embedded_valid = embedded_result.status == SignatureStatus::SignedAndValid;
    let is_catalog_valid = catalog_result.status == SignatureStatus::SignedAndValid;

    // Determine final result: prefer catalog over embedded if both valid
    let final_result = if is_catalog_valid {
        catalog_result
    } else if is_embedded_valid {
        embedded_result
    } else {
        // Return the more informative error from either embedded or catalog
        match (&embedded_result.status, &catalog_result.status) {
            (SignatureStatus::NotSigned, SignatureStatus::NotSigned) => VerificationResult::new(
                path.to_string(),
                SignatureStatus::NotSigned,
                path.to_string(),
                false,
            ),
            (SignatureStatus::VerificationFailed(err), _) => VerificationResult::new(
                path.to_string(),
                SignatureStatus::VerificationFailed(err.clone()),
                path.to_string(),
                false,
            ),
            (_, SignatureStatus::VerificationFailed(err)) => VerificationResult::new(
                path.to_string(),
                SignatureStatus::VerificationFailed(err.clone()),
                path.to_string(),
                false,
            ),
            _ => embedded_result,
        }
    };

    match &final_result.status {
        SignatureStatus::SignedAndValid => {
            println!(
                "{} is signed via {} and the signature is valid.",
                final_result.file_path,
                final_result.signature_type()
            );
        }
        SignatureStatus::VerificationFailed(err) => {
            println!(
                "{} signature verification failed: {}",
                final_result.file_path, err
            );
        }
        SignatureStatus::NotSigned => {
            println!("{} is not signed.", final_result.file_path);
            return;
        }
        SignatureStatus::SignatureStripped => {
            println!(
                "{} WARNING: Signature appears to have been stripped! Security directory exists but signature data is invalid.",
                final_result.file_path
            );
            return;
        }
        SignatureStatus::Unknown => {
            println!("{} signature status is unknown.", final_result.file_path);
            return;
        }
        _ => {
            println!(
                "{} has an unrecognized signature status.",
                final_result.file_path
            );
            return;
        }
    }

    // Extract and print signer information
    if let Some(signer_info) = extract_signer_info(&final_result.cert_path) {
        println!("{}", signer_info);
    } else {
        println!("Failed to extract signer information.");
    }
}
