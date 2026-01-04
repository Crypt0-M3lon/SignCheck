# Build the test app and create a self-signed code-signing certificate (trusted locally), then sign the binary.
# Usage: run from repository root in an elevated PowerShell session if necessary.

Write-Host "Building test app..."
Push-Location "test_apps/self_signed"
cargo build --release
Pop-Location

# Compute the path to the built exe
try {
    $releaseDir = Resolve-Path "test_apps/self_signed/target/release"
} catch {
    Write-Error "Failed to locate release directory: $_"
    exit 1
}

$exePath = Join-Path -Path $releaseDir -ChildPath "self_signed.exe"

if (-not (Test-Path $exePath)) {
    Write-Error "Failed to build test app at $exePath"
    exit 1
}


Write-Host "Creating a self-signed code-signing certificate in CurrentUser\My (will NOT be imported into Trusted Root)..."
# Create the certificate in the Personal store first (New-SelfSignedCertificate typically installs there)
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=SignCheck Test" -KeyExportPolicy Exportable -KeySpec Signature -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)

if (-not $cert) {
    Write-Error "Failed to create certificate. Ensure you have the required permissions and PowerShell version."
    exit 1
}


Write-Host "Signing $exePath using Set-AuthenticodeSignature (certificate will NOT be trusted/imported)..."
$signature = Set-AuthenticodeSignature -FilePath $exePath -Certificate $cert -HashAlgorithm SHA256

if ($signature.Status -ne 'Valid') {
    Write-Warning "Signature status: $($signature.Status). The file was signed but the signature may not be trusted by other systems."
} else {
    Write-Host "Successfully signed $exePath"
}

Write-Host "Self-signed certificate thumbprint: $($cert.Thumbprint)"
Write-Host "The certificate remains in CurrentUser\My and is NOT imported into Trusted Root (so the signature will remain untrusted)."
Write-Host "If you need an exportable PFX, export via Export-PfxCertificate." 
