<#
.SYNOPSIS
    Entry-point for BuzzApiSample on Windows.

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
    # 1. Config file must exist and contain valid JSON
    if (-not (Test-Path $ConfigFile)) { return $false }

    $cfg = $null
    try {
        $cfg = Get-Content $ConfigFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $false
    }

    # 2. Required fields
    $serverUrlVal   = Get-JsonProp $cfg 'serverUrl'
    $oauthUserIdVal = Get-JsonProp $cfg 'oauthUserId'
    $oauthKidVal    = Get-JsonProp $cfg 'oauthKid'
    if (-not $serverUrlVal -or -not $oauthUserIdVal -or -not $oauthKidVal) {
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

    try {
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            # Setup-BuzzOAuth.ps1 targets Windows PowerShell 5.1; re-invoke under powershell.exe
            $ps51 = Get-Command powershell.exe -ErrorAction SilentlyContinue
            if ($null -eq $ps51) {
                throw "Setup-BuzzOAuth.ps1 requires Windows PowerShell 5.1 (powershell.exe), which was not found on PATH."
            }
            & powershell.exe -File $SetupScript
            if ($LASTEXITCODE -ne 0) { throw "Setup script exited with code $LASTEXITCODE." }
        } else {
            & $SetupScript
        }
    } catch {
        $setupErrorMessage = $_.Exception.Message
        if ([string]::IsNullOrWhiteSpace($setupErrorMessage)) { $setupErrorMessage = $_.ToString() }
        Write-Error ("Setup did not complete.  Exiting.  Underlying error: {0}" -f $setupErrorMessage)
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
    # Pick the highest netX.Y framework in the .csproj so no script update is
    # needed when a new SDK year is added to TargetFrameworks.
    $csproj = Get-ChildItem -Path $ProjectRoot -Filter '*.csproj' -Recurse -File |
              Where-Object {
                  $rel = $_.FullName.Substring($ProjectRoot.Length).TrimStart('\', '/')
                  ($rel -split '[\\/]').Count -le 2
              } |
              Select-Object -First 1
    $framework = $null
    if ($csproj) {
        [xml]$proj = Get-Content $csproj.FullName -Raw
        $tfsNode = $proj.SelectSingleNode('/Project/PropertyGroup/TargetFrameworks')
        $tfs = if ($null -ne $tfsNode) { $tfsNode.InnerText } else { $null }
        if (-not $tfs) {
            $tfsNode = $proj.SelectSingleNode('/Project/PropertyGroup/TargetFramework')
            $tfs = if ($null -ne $tfsNode) { $tfsNode.InnerText } else { $null }
        }
        if ($tfs) {
            $nets = $tfs -split ';' |
                    Where-Object { $_ -match '^net\d' } |
                    Sort-Object { $m = [regex]::Match($_, '[\d.]+'); if ($m.Success) { [version]$m.Value } else { [version]'0.0' } } |
                    Select-Object -Last 1
            $framework = $nets
        }
    }
    if ($framework) {
        dotnet run --framework $framework
    } else {
        dotnet run
    }
} finally {
    Pop-Location
}
