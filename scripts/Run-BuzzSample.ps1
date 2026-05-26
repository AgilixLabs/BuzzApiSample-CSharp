<#
.SYNOPSIS
    Entry-point for BuzzApiSample on Windows and macOS.

.DESCRIPTION
    If setup has not been done (buzz-config.json is missing or the certificate is
    not installed in the OS certificate store), the setup script is run interactively
    first.  Then the sample is started with dotnet run.

.PARAMETER ForceSetup
    Run the setup script even if setup appears to be already complete.

.EXAMPLE
    .\scripts\Run-BuzzSample.ps1

.EXAMPLE
    .\scripts\Run-BuzzSample.ps1 -ForceSetup
#>
[CmdletBinding()]
param(
    [switch]$ForceSetup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Safe property accessor — returns $null for missing fields without triggering StrictMode errors.
function Get-JsonProp([psobject]$obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($null -ne $p) { return $p.Value }
    return $null
}

$ScriptDir   = $PSScriptRoot
$ProjectRoot = Split-Path $ScriptDir -Parent
$ConfigFile  = Join-Path $ProjectRoot 'buzz-config.json'
$SetupScript = Join-Path $ScriptDir 'Setup-BuzzOAuth.ps1'

# ── Check if setup is complete ────────────────────────────────────────────────
function Test-SetupComplete {
    # 1. Config file must exist
    if (-not (Test-Path $ConfigFile)) { return $false }

    $cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json

    # 2. Required fields
    if (-not $cfg.serverUrl -or -not $cfg.oauthUserId -or -not $cfg.oauthKid) {
        return $false
    }

    # 3. Either a certificate thumbprint or a PEM file
    $thumbprintVal  = Get-JsonProp $cfg 'certThumbprint'
    $storeLocVal    = Get-JsonProp $cfg 'certStoreLocation'
    $privateKeyVal  = Get-JsonProp $cfg 'privateKeyPath'

    if ($thumbprintVal) {
        $storeLocation = if ($storeLocVal -eq 'LocalMachine') {
            [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
        } else {
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        }

        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            $storeLocation)
        try {
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $thumbprint = ([string]$thumbprintVal) -replace '\s', ''
            $certs = $store.Certificates.Find(
                [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
                $thumbprint, $false)
            if ($certs.Count -eq 0) { return $false }
        } finally {
            $store.Close()
        }
    } elseif ($privateKeyVal) {
        if (-not (Test-Path ([string]$privateKeyVal))) { return $false }
    } else {
        return $false
    }

    return $true
}

# ── Run setup if needed ───────────────────────────────────────────────────────
if ($ForceSetup -or -not (Test-SetupComplete)) {
    Write-Host ''
    if ($ForceSetup) {
        Write-Host '── Running setup (-ForceSetup) ──────────────────────────────────'
    } else {
        Write-Host '── Setup not complete — starting interactive setup ───────────────'
    }
    Write-Host ''

    & $SetupScript

    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        Write-Error 'Setup did not complete.  Exiting.'
        exit 1
    }

    if (-not (Test-SetupComplete)) {
        Write-Error 'Setup did not produce a valid configuration.  Exiting.'
        exit 1
    }
}

# ── Run the sample ────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '── Running BuzzApiSample ────────────────────────────────────────'
Write-Host ''

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Error 'dotnet is not on PATH.  Install .NET: https://learn.microsoft.com/dotnet/core/install'
    exit 1
}

Push-Location $ProjectRoot
try {
    dotnet run
} finally {
    Pop-Location
}
