<#
.SYNOPSIS
    Remove all artifacts created by Setup-BuzzOAuth.ps1.

.DESCRIPTION
    This script:
      1. Reads buzz-config.json to find the OAuth account details
      2. Logs in as a Buzz admin (supports MFA)
      3. Deletes the registered OAuth public key from Buzz
      4. Deletes the Application Identity account from Buzz
      5. Removes the certificate from the OS certificate store
      6. Deletes buzz-config.json

    After running, the environment is back to a completely clean state.
    Run .\scripts\Run-BuzzSample.ps1 to go through setup again.

.EXAMPLE
    .\scripts\Cleanup-BuzzSample.ps1
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -UseBasicParsing is required on Windows PowerShell 5.1 but unavailable in PowerShell 7+.
$_bp = if ($PSVersionTable.PSVersion.Major -lt 6) { @{ UseBasicParsing = $true } } else { @{} }

Add-Type -AssemblyName System.Security

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

# ── Load config ───────────────────────────────────────────────────────────────
if (-not (Test-Path $ConfigFile)) {
    Write-Host 'buzz-config.json not found — nothing to clean up.'
    exit 0
}

$cfg = Get-Content $ConfigFile -Raw | ConvertFrom-Json

$_url           = Get-JsonProp $cfg 'serverUrl'
$ServerUrl      = if ($_url) { ([string]$_url).TrimEnd('/') } else { '' }
$OAuthUserId    = Get-JsonProp $cfg 'oauthUserId'
$OAuthKid       = Get-JsonProp $cfg 'oauthKid'
$CertThumbprint = Get-JsonProp $cfg 'certThumbprint'
$StoreLocStr    = Get-JsonProp $cfg 'certStoreLocation'
$PrivKeyPath    = Get-JsonProp $cfg 'privateKeyPath'

if (-not $ServerUrl -or -not $OAuthUserId) {
    Write-Error 'buzz-config.json is missing required fields (serverUrl, oauthUserId).'
    exit 1
}

$StoreLocation = if ($StoreLocStr -eq 'LocalMachine') {
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
} else {
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '════════════════════════════════════════════════════════'
Write-Host '  Buzz API Sample — Cleanup'
Write-Host '════════════════════════════════════════════════════════'
Write-Host ''
Write-Host 'This script will:'
Write-Host "  • Delete OAuth public key (kid: $OAuthKid) from Buzz"
Write-Host "  • Delete Application Identity account (userid: $OAuthUserId) from Buzz"
if ($CertThumbprint) {
    Write-Host "  • Remove certificate $CertThumbprint from the OS certificate store"
}
if ($PrivKeyPath -and (Test-Path $PrivKeyPath)) {
    Write-Host "  • Delete private key file: $PrivKeyPath"
}
Write-Host '  • Delete buzz-config.json'
Write-Host ''
$confirm = Read-Host 'This action is irreversible.  Continue? [y/N]'
if ($confirm -notmatch '^[Yy]') {
    Write-Host 'Aborted.'
    exit 0
}

# ── Admin login ───────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '── Admin login ──────────────────────────────────────────'
Write-Host "Enter credentials for a Buzz admin account with rights to"
Write-Host "delete users and manage keys on account $OAuthUserId."
Write-Host ''

$AdminToken = $null
while ($null -eq $AdminToken) {
    $adminUser = ''
    while (-not ($adminUser -match '^[^/]+/[^/]+$')) {
        $adminUser = (Read-Host 'Admin username (userspace/username, e.g. myschool/admin)').Trim()
        if (-not ($adminUser -match '^[^/]+/[^/]+$')) {
            Write-Host '  Username must be in userspace/username format.' -ForegroundColor Yellow
        }
    }
    $adminPass = Read-Host 'Admin password' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPass)
    $adminPassPlain = $null
    try     { $adminPassPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

    Write-Host 'Logging in...' -NoNewline

    $loginBody = [ordered]@{
        request = [ordered]@{
            cmd      = 'login3'
            username = $adminUser
            password = $adminPassPlain
        }
    } | ConvertTo-Json -Depth 5
    $adminPassPlain = $null

    $loginResp = $null
    try {
        $loginResp = Invoke-RestMethod @_bp -Method Post -Uri "$ServerUrl/cmd/login3" `
            -ContentType 'application/json' -Body $loginBody -ErrorAction Stop
    } catch {
        Write-Host ''
        Write-Host "  Network error: $_" -ForegroundColor Red
        Write-Host '  Please check the server URL and try again.  Press Ctrl+C to abort.' -ForegroundColor Yellow
        Write-Host ''
        continue
    }
    $loginBody = $null

    $loginCode = Get-JsonProp (Get-JsonProp $loginResp 'response') 'code'
    if (-not $loginCode) { $loginCode = Get-JsonProp $loginResp 'code' }

    # MFA check
    if ($loginCode -match '(?i)(factor|challenge|otp|mfa|verify|multifactor)') {
        Write-Host ' MFA verification required.' -ForegroundColor Yellow
        $mfaCode  = Read-Host 'Enter your MFA code'
        $mfaToken = Get-JsonProp (Get-JsonProp $loginResp 'response') 'token'

        $mfaBody = [ordered]@{
            request = [ordered]@{
                cmd   = 'verifylogin'
                token = $mfaToken
                code  = $mfaCode
            }
        } | ConvertTo-Json -Depth 5
        $mfaToken = $null

        try {
            $loginResp = Invoke-RestMethod @_bp -Method Post -Uri "$ServerUrl/cmd/verifylogin" `
                -ContentType 'application/json' -Body $mfaBody -ErrorAction Stop
        } catch {
            $mfaBody = $null
            Write-Host ''
            Write-Host "  MFA request failed: $_" -ForegroundColor Red
            Write-Host '  Please try again.  Press Ctrl+C to abort.' -ForegroundColor Yellow
            Write-Host ''
            continue
        }
        $mfaBody = $null

        $loginCode = Get-JsonProp (Get-JsonProp $loginResp 'response') 'code'
        if (-not $loginCode) { $loginCode = Get-JsonProp $loginResp 'code' }
    }

    if ($loginCode -ne 'OK') {
        Write-Host ''
        $loginMsg = Get-JsonProp (Get-JsonProp $loginResp 'response') 'message'
        $suffix = if ($loginMsg) { ": $loginMsg" } else { '' }
        Write-Host "  Login failed (code: $loginCode)$suffix." -ForegroundColor Red
        Write-Host '  Please check your credentials and try again.  Press Ctrl+C to abort.' -ForegroundColor Yellow
        Write-Host ''
        continue
    }

    $candidateToken = Get-JsonProp (Get-JsonProp (Get-JsonProp $loginResp 'response') 'user') 'token'
    if ([string]::IsNullOrEmpty($candidateToken)) {
        Write-Host ''
        Write-Host '  Login succeeded but no token was returned.' -ForegroundColor Red
        Write-Host '  Please try again.  Press Ctrl+C to abort.' -ForegroundColor Yellow
        Write-Host ''
        continue
    }

    $AdminToken = $candidateToken
}
Write-Host ' OK' -ForegroundColor Green
Write-Host 'Logged in successfully.'

# ── Delete OAuth public key from Buzz ─────────────────────────────────────────
Write-Host ''
Write-Host "── Deleting OAuth key (kid: $OAuthKid) ─────────────────────────"

if ($OAuthKid) {
    $keyUrl = "$ServerUrl/api/users/$OAuthUserId/keys/$OAuthKid"
    try {
        $keyResp = Invoke-WebRequest @_bp -Method Delete -Uri $keyUrl `
            -Headers @{ Authorization = "Bearer $AdminToken" } -ErrorAction Stop
        Write-Host "OAuth key deleted (HTTP $($keyResp.StatusCode))."
    } catch {
        $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
        if ($status -eq 404) {
            Write-Host 'OAuth key not found on server (already deleted or never registered).'
        } else {
            Write-Warning "HTTP $status deleting key — continuing with remaining cleanup."
        }
    }
} else {
    Write-Host 'No kid in config — skipping key deletion.'
}

# ── Delete Application Identity account from Buzz ─────────────────────────────
Write-Host ''
Write-Host "── Deleting Application Identity account (userid: $OAuthUserId) ──"

$deleteBody = @{
    requests = @{
        user = @(@{ userid = $OAuthUserId })
    }
} | ConvertTo-Json -Depth 5

try {
    $deleteResp = Invoke-RestMethod @_bp -Method Post -Uri "$ServerUrl/cmd/deleteusers" `
        -Headers @{ Authorization = "Bearer $AdminToken" } `
        -ContentType 'application/json' -Body $deleteBody -ErrorAction Stop

    # deleteusers can return code at several paths depending on API version; probe each safely.
    $deleteCode = Get-JsonProp $deleteResp 'code'
    if (-not $deleteCode) {
        $resp1 = Get-JsonProp $deleteResp 'response'
        $deleteCode = Get-JsonProp $resp1 'code'
    }
    if (-not $deleteCode) {
        $resps = Get-JsonProp $deleteResp 'responses'
        $userArr = Get-JsonProp $resps 'user'
        $first = if ($userArr -is [array]) { $userArr[0] } else { $userArr }
        $deleteCode = Get-JsonProp $first 'code'
    }

    if ($deleteCode -eq 'OK') {
        Write-Host 'Application Identity account deleted.'
    } else {
        Write-Warning "Delete returned code '$deleteCode' — continuing."
    }
} catch {
    Write-Warning "Error deleting account: $($_.Exception.Message) — continuing."
}
$AdminToken = $null

# ── Remove certificate from OS cert store ────────────────────────────────────
if ($CertThumbprint) {
    Write-Host ''
    Write-Host '── Removing certificate from OS certificate store ───────'

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        $StoreLocation)
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $thumbprint = $CertThumbprint -replace '\s', ''
        $certs = $store.Certificates.Find(
            [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint,
            $thumbprint, $false)

        if ($certs.Count -gt 0) {
            foreach ($cert in $certs) {
                $store.Remove($cert)
            }
            Write-Host "Certificate removed from $StoreLocation store."
        } else {
            Write-Host "Certificate not found in store (already removed)."
        }
    } finally {
        $store.Close()
    }
}

# ── Remove private key file ───────────────────────────────────────────────────
if ($PrivKeyPath -and (Test-Path $PrivKeyPath)) {
    Write-Host ''
    Write-Host '── Removing private key file ────────────────────────────'
    Write-Host "  Path: $PrivKeyPath"
    $confirmKey = Read-Host 'Delete this file? [y/N]'
    if ($confirmKey -match '^[Yy]') {
        Remove-Item $PrivKeyPath -Force
        Write-Host "Private key deleted: $PrivKeyPath"
    } else {
        Write-Host 'Skipped private key deletion.'
    }
}

# ── Delete buzz-config.json ───────────────────────────────────────────────────
Write-Host ''
Write-Host '── Deleting buzz-config.json ────────────────────────────'
Remove-Item $ConfigFile -Force
Write-Host 'buzz-config.json deleted.'

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host ''
Write-Host '════════════════════════════════════════════════════════'
Write-Host '  Cleanup complete.  Environment is back to a clean state.'
Write-Host '  Run .\scripts\Run-BuzzSample.ps1 to set up and run again.'
Write-Host '════════════════════════════════════════════════════════'
Write-Host ''
