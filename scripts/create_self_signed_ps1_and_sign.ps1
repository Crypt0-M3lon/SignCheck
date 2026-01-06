# Create a minimal PowerShell script and sign it with a self-signed code signing certificate.
# Usage: run from repository root in PowerShell.

param(
    [string]$ScriptPath = "test_apps/self_signed_ps1/test.ps1",
    [string]$Subject = "CN=SignCheck PS1 Test"
)

Write-Host "Preparing self-signed PowerShell script at $ScriptPath ..."

# Ensure target directory exists
$targetDir = Split-Path -Parent $ScriptPath
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir | Out-Null
}

# Create a minimal script content
$content = @'
Write-Output "Hello from a self-signed PowerShell script"
'@

Set-Content -Path $ScriptPath -Value $content -Encoding UTF8

Write-Host "Creating a self-signed code-signing certificate in CurrentUser\\My ..."
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -KeyExportPolicy Exportable -KeySpec Signature -CertStoreLocation "Cert:\\CurrentUser\\My" -NotAfter (Get-Date).AddYears(3)

if (-not $cert) {
    Write-Error "Failed to create certificate. Ensure required permissions and PowerShell version (5+) are available."
    exit 1
}

Write-Host "Signing $ScriptPath using Set-AuthenticodeSignature (self-signed; not trusted by default) ..."
$signature = Set-AuthenticodeSignature -FilePath $ScriptPath -Certificate $cert -HashAlgorithm SHA256

Write-Host "Signature Status: $($signature.Status)"
Write-Host "Certificate Thumbprint: $($cert.Thumbprint)"
Write-Host "Note: The certificate remains only in CurrentUser\\My and is NOT imported into Trusted Root, so verification should report UntrustedRoot."

if ($signature.Status -ne 'Valid') {
    Write-Warning "The signature was applied, but its status is $($signature.Status)."
}

Write-Host "Done. Script signed at: $ScriptPath"
