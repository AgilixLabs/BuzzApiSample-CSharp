<#
.SYNOPSIS
    Generates an RSA key pair for Buzz OAuth 2.0 authentication.

.DESCRIPTION
    Generates a 2048-bit (or larger) RSA private key and its corresponding public key in PEM
    format.  Only the public key is ever sent to Buzz; the private key must remain secret.

    Runs on Windows PowerShell 5.1 (the shell that ships with Windows 11) and on
    PowerShell 7+, with no external tools.  OpenSSL is not required.

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
    Prefer .\scripts\Setup-BuzzOAuth.ps1 for new setups.  It keeps the private key in the
    OS certificate store so it never exists as a file at all.  This script is for cases
    that need a PEM file — containers, non-Windows hosts, or an external secrets manager.

    SECURITY
    - Add private_key.pem to .gitignore immediately.
    - Store the private key in a secrets manager (Azure Key Vault, AWS Secrets Manager, etc.)
      or an encrypted location — never in plain-text config files or source control.
    - Restrict file-system permissions so only the service account running your application
      can read private_key.pem.  This script applies those restrictions when creating the file.
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

. (Join-Path $PSScriptRoot "BuzzPem.ps1")

# $IsWindows is an automatic variable in PS6+; define it for Windows PowerShell 5.1.
if ($null -eq (Get-Variable 'IsWindows' -ErrorAction SilentlyContinue)) {
    $IsWindows = $env:OS -eq 'Windows_NT'
}

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

# ── Restrict the private key file to the current user ───────────────────────
# Called before any key material is written, so the file is never briefly readable
# by other accounts.
function Protect-KeyFile([string] $Path) {
    # Truncate/create the file so there is something to apply permissions to.
    [System.IO.File]::WriteAllText($Path, "")

    if ($IsWindows) {
        $acl = Get-Acl $Path
        $acl.SetAccessRuleProtection($true, $false)   # break inheritance, drop inherited rules
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
        Set-Acl $Path $acl
    } else {
        & chmod 600 $Path
    }
}

# ── Generate the key pair ───────────────────────────────────────────────────
Write-Host "Generating $KeySize-bit RSA key pair (PowerShell $($PSVersionTable.PSVersion))..."

$rsa = New-BuzzRsaKey -KeySize $KeySize
try {
    Protect-KeyFile $privateKeyPath
    [System.IO.File]::WriteAllText($privateKeyPath, (Export-BuzzPkcs1Pem $rsa))
    [System.IO.File]::WriteAllText($publicKeyPath,  (Export-BuzzSpkiPem  $rsa))
}
finally {
    $rsa.Dispose()
}

# ── Summary ─────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "RSA key pair generated ($KeySize bits):"
Write-Host "  Private key : $privateKeyPath"
Write-Host "  Public key  : $publicKeyPath"
Write-Host ""
Write-Host "Next step: register the public key with Buzz."
Write-Host "  .\scripts\Register-BuzzOAuthKey.ps1 ``"
Write-Host "      -ServerUrl  <https://backgroundapi.agilixbuzz.com> ``"
Write-Host "      -AdminToken <bearer-token-of-an-admin-user> ``"
Write-Host "      -UserId     <userid-of-application-identity-account> ``"
Write-Host "      -Kid        <key-id-you-choose, e.g. 2025-q2> ``"
Write-Host "      -PublicKeyPath $publicKeyPath"
Write-Host ""
Write-Host "IMPORTANT: Never commit private_key.pem to source control."
Write-Host "  Add it to .gitignore:  echo private_key.pem >> .gitignore"
