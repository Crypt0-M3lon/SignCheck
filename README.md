# SignCheck

A Windows-native library for verifying code signatures on PE files, supporting both embedded (Authenticode) and catalog-based signatures.

## Features

- ✅ Embedded signature verification (Authenticode)
- ✅ Catalog signature verification
- ✅ Certificate information extraction (subject, issuer, serial, thumbprints, algorithms)
- ✅ Signature stripping detection
- ✅ PowerShell script signature support (PKCS7)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
signcheck = "0.1.0"
```

## Usage as Library

```rust
use signcheck::{check_embedded_signatures, check_catalog_signatures, SignatureStatus};

fn main() {
    let path = r"C:\Windows\System32\notepad.exe";
    
    let embedded = check_embedded_signatures(path);
    let catalog = check_catalog_signatures(path);
    
    if embedded.status == SignatureStatus::SignedAndValid {
        println!("Valid embedded signature");
    }
    
    if catalog.status == SignatureStatus::SignedAndValid {
        println!("Valid catalog signature");
    }
}
```

## Usage as CLI

```powershell
# Build and run
cargo run --release -- "C:\Windows\System32\cmd.exe"

# Or install globally
cargo install --path .
signcheck "C:\path\to\file.exe"
```

## Examples

Run the example:
```powershell
cargo run --example basic_check -- "C:\Windows\System32\notepad.exe"
```

## API Documentation

### Core Functions

- `check_embedded_signatures(path: &str) -> VerificationResult`
- `check_catalog_signatures(path: &str) -> VerificationResult`
- `extract_signer_info(path: &str) -> Option<SignerInfo>`

### Types

- `SignatureStatus`: Enum representing signature status
  - `SignedAndValid`
  - `NotSigned`
  - `VerificationFailed(TrustError)`
  - `SignatureStripped`
  - `Unknown`

- `VerificationResult`: Contains verification status and paths
- `SignerInfo`: Certificate details (subject, issuer, validity, algorithms, etc.)

## Platform Support

**Windows only** - Uses Win32 WinTrust and Cryptography APIs via the `windows` crate.

## Testing

```powershell
# Run tests (requires Windows with Firefox installed)
cargo test

# Generate test materials
.\scripts\create_self_signed_and_sign.ps1
.\scripts\create_self_signed_ps1_and_sign.ps1
```

## License

MIT OR Apache-2.0
