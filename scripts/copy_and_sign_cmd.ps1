# Copy cmd.exe to samples directory and sign with an untrusted self-signed certificate
# Run this script from the repository root with elevated privileges

$ErrorActionPreference = "Stop"

# Define paths
$repoRoot = Split-Path $PSScriptRoot -Parent
$samplesDir = Join-Path $repoRoot "samples"
$sourceCmdPath = "C:\Windows\System32\cmd.exe"
$targetCmdPath = Join-Path $samplesDir "cmd_self_signed.exe"

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

# Sign the copied cmd.exe
Write-Host "Signing $targetCmdPath with the self-signed certificate..."
Set-AuthenticodeSignature -FilePath $targetCmdPath -Certificate $cert -TimestampServer "http://timestamp.digicert.com"

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
