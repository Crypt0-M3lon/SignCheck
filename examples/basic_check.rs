//! Example: Basic signature verification
//!
//! This example demonstrates how to use the signcheck library to verify
//! both embedded and catalog-based signatures on Windows PE files.

use signcheck::{
    check_catalog_signatures, check_embedded_signatures, extract_signer_info, SignatureStatus,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path_to_file>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    println!("Checking signatures for: {}\n", path);

    // Check embedded signature
    let embedded = check_embedded_signatures(path);
    println!("Embedded signature: {:?}", embedded.status);

    // Check catalog signature
    let catalog = check_catalog_signatures(path);
    println!("Catalog signature: {:?}", catalog.status);

    // Determine which one is valid
    let is_embedded_valid = embedded.status == SignatureStatus::SignedAndValid;
    let is_catalog_valid = catalog.status == SignatureStatus::SignedAndValid;

    if is_embedded_valid || is_catalog_valid {
        println!("\n✓ File is signed and valid");

        let cert_path = if is_catalog_valid {
            &catalog.cert_path
        } else {
            &embedded.cert_path
        };

        if let Some(signer) = extract_signer_info(cert_path) {
            println!("\nSigner Information:");
            println!("{}", signer);
        }
    } else {
        println!("\n✗ File signature verification failed or not signed");
    }
}
