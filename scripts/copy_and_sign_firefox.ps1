# Copy cmd.exe to samples directory and sign with an untrusted self-signed certificate
# Run this script from the repository root with elevated privileges

$ErrorActionPreference = "Stop"

# Define paths
$repoRoot = Split-Path $PSScriptRoot -Parent
$samplesDir = Join-Path $repoRoot "samples"
$sourceCmdPath = "C:\Program Files\Mozilla Firefox\firefox.exe"
$targetCmdPath = Join-Path $samplesDir "firefox_self_signed.exe"

# Ensure samples directory exists
if (-not (Test-Path $samplesDir)) {
    New-Item -ItemType Directory -Path $samplesDir -Force | Out-Null
    Write-Host "Created samples directory: $samplesDir"
}

# Copy cmd.exe to samples
Write-Host "Copying cmd.exe to samples directory..."
Copy-Item -Path $sourceCmdPath -Destination $targetCmdPath -Force
Write-Host "Copied to: $targetCmdPath"

# Create a self-signed certificate (NOT added to trusted roots)
Write-Host "Creating self-signed certificate..."
$cert = New-SelfSignedCertificate `
    -Subject "CN=SignCheck Test Certificate" `
    -Type CodeSigningCert `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(1)

Write-Host "Certificate created with thumbprint: $($cert.Thumbprint)"
Write-Host "Certificate is stored in CurrentUser\My but NOT in trusted roots"

# Sign the copied file - append signature instead of replacing existing one
Write-Host "Adding signature to $targetCmdPath with the self-signed certificate..."

# Export the certificate to a temporary PFX file for signtool.exe
$pfxPath = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.pfx'
$password = ConvertTo-SecureString -String "temp" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password | Out-Null

try {
    # Use signtool.exe with /as flag to append signature instead of replacing
    $signtoolPath = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
    if (-not (Test-Path $signtoolPath)) {
        # Try alternate Windows SDK path
        $signtoolPath = "C:\Program Files\Windows Kits\10\bin\x64\signtool.exe"
    }
    
    if (Test-Path $signtoolPath) {
        & $signtoolPath sign /f $pfxPath /p "temp" /as /fd sha256 /td sha256 /tr "http://timestamp.digicert.com" "$targetCmdPath"
        Write-Host "Signature appended successfully"
    } else {
        Write-Host "signtool.exe not found, falling back to Set-AuthenticodeSignature (will replace signature)"
        Set-AuthenticodeSignature -FilePath $targetCmdPath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" | Out-Null
    }
} finally {
    # Clean up temporary PFX file
    if (Test-Path $pfxPath) {
        Remove-Item $pfxPath -Force
    }
}

Write-Host ""
Write-Host "Done! The file has been signed with an untrusted certificate."
Write-Host "File location: $targetCmdPath"
Write-Host "Certificate thumbprint: $($cert.Thumbprint)"
Write-Host ""
Write-Host "To verify the signature is untrusted, run:"
Write-Host "  cargo run -- `"$targetCmdPath`""
Write-Host ""
Write-Host "To remove the certificate later, run:"
Write-Host "  Get-ChildItem Cert:\CurrentUser\My\$($cert.Thumbprint) | Remove-Item"
