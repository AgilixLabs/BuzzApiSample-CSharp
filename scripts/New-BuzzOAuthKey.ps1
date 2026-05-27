<#
.SYNOPSIS
    Generates an RSA key pair for Buzz OAuth 2.0 authentication.

.DESCRIPTION
    Generates a 2048-bit (or larger) RSA private key and its corresponding public key in PEM
    format.  Only the public key is ever sent to Buzz; the private key must remain secret.

    Key generation uses built-in .NET APIs when running under PowerShell 7+ (.NET 5 or later),
    or falls back to OpenSSL when running under Windows PowerShell 5.1.
    OpenSSL is included with Git for Windows and available via winget: winget install Git.Git

.PARAMETER OutputDir
    Directory to write private_key.pem and public_key.pem into.  Defaults to the current
    directory.  The directory is created if it does not exist.

.PARAMETER KeySize
    RSA key size in bits.  Minimum accepted by Buzz is 2048 (default).
    3072 or 4096 bits are recommended for new integrations.

.EXAMPLE
    # Generate keys in the current directory
    .\scripts\New-BuzzOAuthKey.ps1

.EXAMPLE
    # Generate 4096-bit keys in C:\secrets\myapp
    .\scripts\New-BuzzOAuthKey.ps1 -OutputDir C:\secrets\myapp -KeySize 4096

.NOTES
    SECURITY
    - Add private_key.pem to .gitignore immediately.
    - Store the private key in a secrets manager (Azure Key Vault, AWS Secrets Manager, etc.)
      or an encrypted location — never in plain-text config files or source control.
    - Restrict file-system permissions so only the service account running your application
      can read private_key.pem.
    - Rotate keys periodically.  See README.md for key rotation guidance.
#>

[CmdletBinding()]
param(
    [string] $OutputDir = ".",
    [ValidateRange(2048, 16384)]
    [int]    $KeySize   = 2048
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve output paths ────────────────────────────────────────────────────
$OutputDir       = [System.IO.Path]::GetFullPath($OutputDir)
$privateKeyPath  = Join-Path $OutputDir "private_key.pem"
$publicKeyPath   = Join-Path $OutputDir "public_key.pem"

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
    Write-Host "Created output directory: $OutputDir"
}

# Warn if a key already exists to avoid silent overwrites
if ((Test-Path $privateKeyPath) -or (Test-Path $publicKeyPath)) {
    Write-Warning "Key file(s) already exist in $OutputDir. They will be overwritten."
    $confirm = Read-Host "Continue? [y/N]"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Aborted."
        exit 0
    }
}

# ── Generate with built-in .NET APIs (PowerShell 7 / .NET 5+) ───────────────
if ($PSVersionTable.PSVersion.Major -ge 7) {
    Write-Host "Generating $KeySize-bit RSA key pair using .NET APIs..."

    $rsa = [System.Security.Cryptography.RSA]::Create()
    $rsa.KeySize = $KeySize
    try {
        [System.IO.File]::WriteAllText($privateKeyPath, $rsa.ExportRSAPrivateKeyPem())
        [System.IO.File]::WriteAllText($publicKeyPath,  $rsa.ExportSubjectPublicKeyInfoPem())
    }
    finally {
        $rsa.Dispose()
    }
}
else {
    # ── Fall back to OpenSSL (Windows PowerShell 5.1) ──────────────────────
    $openssl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($null -eq $openssl) {
        Write-Error @"
OpenSSL was not found on PATH, and this script is running under Windows PowerShell 5.1
which does not have the .NET 5 key-export APIs.

Options:
  1. Upgrade to PowerShell 7:  winget install Microsoft.PowerShell
                                https://aka.ms/powershell
  2. Install Git for Windows (includes OpenSSL):
                                winget install Git.Git
                                https://git-scm.com/
  3. Run the script again after adding OpenSSL to PATH.
"@
        exit 1
    }

    Write-Host "Generating $KeySize-bit RSA key pair using OpenSSL ($($openssl.Source))..."

    & openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$KeySize" -out $privateKeyPath
    if ($LASTEXITCODE -ne 0) { throw "openssl genpkey failed (exit $LASTEXITCODE)" }

    & openssl pkey -in $privateKeyPath -pubout -out $publicKeyPath
    if ($LASTEXITCODE -ne 0) { throw "openssl pkey -pubout failed (exit $LASTEXITCODE)" }
}

# ── Summary ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "RSA key pair generated ($KeySize bits):"
Write-Host "  Private key : $privateKeyPath"
Write-Host "  Public key  : $publicKeyPath"
Write-Host ""
Write-Host "Next step: register the public key with Buzz."
Write-Host "  .\scripts\Register-BuzzOAuthKey.ps1 ``"
Write-Host "      -ServerUrl  <https://api.agilixbuzz.com> ``"
Write-Host "      -AdminToken <bearer-token-of-an-admin-user> ``"
Write-Host "      -UserId     <userid-of-application-identity-account> ``"
Write-Host "      -Kid        <key-id-you-choose, e.g. 2025-q2> ``"
Write-Host "      -PublicKeyPath $publicKeyPath"
Write-Host ""
Write-Host "IMPORTANT: Never commit private_key.pem to source control."
Write-Host "  Add it to .gitignore:  echo private_key.pem >> .gitignore"
