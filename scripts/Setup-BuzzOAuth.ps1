<#
.SYNOPSIS
    Interactive guided setup for Buzz OAuth 2.0 authentication.

.DESCRIPTION
    Walks you through the one-time setup needed to authenticate a background service
    or integration to the Buzz API using OAuth 2.0 JWT client credentials.

    What this script does (Steps 1–8):
      1. Prompts for the Buzz server URL (defaults to https://backgroundapi.agilixbuzz.com,
         the host intended for server-to-server integrations).
      2. Logs in as a Buzz administrator.  Accounts with multi-factor authentication are
         supported: login3 answers SecondFactorRequired, and the script then prompts for
         the one-time code and completes the login with secondfactorauthenticate.
         Credentials are verified early so mistakes are caught before anything else
         is entered.
      3. Prompts for certificate store location (CurrentUser or LocalMachine).
      4. Prompts for contact info and application name.
      5. Creates (or reuses) an Application Identity user account in Buzz.
         This account is the OAuth identity of your integration — it has no password
         and cannot be used for interactive login.
      6. Generates an RSA key pair and wraps the private key in a self-signed
         certificate imported into the Windows Certificate Store — no plaintext
         key files remain on disk.
      7. Registers the public key with Buzz.
      8. Writes buzz-config.json in the project root with all values filled in,
         so `dotnet run` works immediately.

    Requires: Windows PowerShell 5.1 — the version that ships with Windows 11, along
    with the .NET Framework 4.8 it needs.  Nothing else has to be installed; in
    particular OpenSSL is not required (see BuzzPem.ps1).

.PARAMETER ServerUrl
    Buzz API server URL.  If omitted, you are prompted, with
    https://backgroundapi.agilixbuzz.com offered as the default.

.PARAMETER ConfigOutput
    Path to write buzz-config.json.  Defaults to buzz-config.json in the project root
    (the parent directory of the scripts\ folder).

.PARAMETER StoreLocation
    Where to install the certificate.
    CurrentUser  — installs for the current user account (default; works for user-level services).
    LocalMachine — installs machine-wide; needed for Windows services running as SYSTEM or a
                   service account.  Requires running this script as Administrator.

.PARAMETER KeySize
    RSA key size in bits.  Minimum accepted by Buzz is 2048 (default).
    3072 or 4096 are recommended for new integrations.

.EXAMPLE
    # Standard guided setup
    .\scripts\Setup-BuzzOAuth.ps1

.EXAMPLE
    # For a Windows service (run as Administrator)
    .\scripts\Setup-BuzzOAuth.ps1 -StoreLocation LocalMachine

.EXAMPLE
    # Pre-supply the server URL
    .\scripts\Setup-BuzzOAuth.ps1 -ServerUrl https://backgroundapi.agilixbuzz.com

.NOTES
    SECURITY
    - The private key is stored in the OS certificate store, not in a file.
    - buzz-config.json contains the certificate thumbprint (not any secret material) and
      is gitignored.
    - The setup admin token is used only during this script and is never written to disk.
    - On Linux the dotnet cert store is a directory of PFX files under ~/.dotnet/. Restrict
      that directory's permissions: chmod 700 ~/.dotnet/corefx/cryptography/x509stores/my
    - On Windows the private key is non-exportable by default (set via -KeyExportPolicy
      NonExportable in New-SelfSignedCertificate). To allow backup/migration add
      -KeyExportPolicy ExportableEncrypted to the New-SelfSignedCertificate call.
#>

[CmdletBinding()]
param(
    [string] $ServerUrl    = "",
    [string] $ConfigOutput = "",
    [ValidateSet("CurrentUser","LocalMachine")]
    [string] $StoreLocation = "CurrentUser",
    [ValidateRange(2048,16384)]
    [int]    $KeySize = 2048
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -UseBasicParsing is required on Windows PowerShell 5.1 but unavailable in PowerShell 7+.
$_bp = if ($PSVersionTable.PSVersion.Major -lt 6) { @{ UseBasicParsing = $true } } else { @{} }

# $IsWindows / $IsLinux / $IsMacOS are automatic variables in PS6+; define them for PS5.1
if ($null -eq (Get-Variable 'IsWindows' -ErrorAction SilentlyContinue)) {
    $IsWindows = $env:OS -eq 'Windows_NT'
    $IsLinux   = $false
    $IsMacOS   = $false
}

# ── Resolve paths ─────────────────────────────────────────────────────────────
$projectRoot = Split-Path $PSScriptRoot -Parent
if ([string]::IsNullOrEmpty($ConfigOutput)) {
    $ConfigOutput = Join-Path $projectRoot "buzz-config.json"
}

# ── Banner ────────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Buzz OAuth 2.0 Application Setup" -ForegroundColor Cyan
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "This script performs a one-time setup so your application can"
Write-Host "authenticate to the Buzz API without a username or password."
Write-Host ""

# ── RSA key generation and PEM export ─────────────────────────────────────────
# BuzzPem.ps1 writes the ASN.1 DER by hand so this works on Windows PowerShell 5.1
# (.NET Framework 4.x), which has none of the PEM APIs added in .NET 5.  No OpenSSL.
. (Join-Path $PSScriptRoot "BuzzPem.ps1")

function Get-BuzzCode([psobject] $response) {
    # Buzz responses nest the code under .response.code or directly under .code.
    # Use PSObject.Properties to avoid StrictMode errors on missing members.
    if ($null -ne $response -and $response.PSObject.Properties['response']) {
        $inner = $response.response
        if ($null -ne $inner -and $inner.PSObject.Properties['code']) {
            return $inner.code
        }
    }
    if ($null -ne $response -and $response.PSObject.Properties['code']) {
        return $response.code
    }
    return $null
}

function Get-BuzzProp([psobject] $obj, [string] $name) {
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($null -ne $p) { return $p.Value }
    return $null
}

# A successful login3 / secondfactorauthenticate returns the session token at
# response.user.token.
function Get-BuzzLoginToken([psobject] $response) {
    $inner = Get-BuzzProp $response 'response'
    if ($null -eq $inner) { $inner = $response }
    return Get-BuzzProp (Get-BuzzProp $inner 'user') 'token'
}

# Recursively find a 'token' property.  Skips remembermfa, whose token is a
# remember-this-device credential and cannot complete a second-factor login.
function Find-BuzzToken([object] $node, [int] $depth = 0) {
    if ($null -eq $node -or $depth -gt 6) { return $null }
    if ($node -is [string] -or $node -is [ValueType]) { return $null }

    if ($node -is [System.Collections.IEnumerable]) {
        foreach ($item in $node) {
            $found = Find-BuzzToken $item ($depth + 1)
            if ($found) { return $found }
        }
        return $null
    }

    # Prefer a token on this level before descending.
    foreach ($p in $node.PSObject.Properties) {
        if ($p.Name -eq 'remembermfa') { continue }
        if ($p.Name -eq 'token' -and $p.Value -is [string] -and $p.Value) { return $p.Value }
    }
    foreach ($p in $node.PSObject.Properties) {
        if ($p.Name -eq 'remembermfa') { continue }
        $found = Find-BuzzToken $p.Value ($depth + 1)
        if ($found) { return $found }
    }
    return $null
}

# The short-lived token login3 returns alongside SecondFactorRequired.
#
# Observed shape of a real SecondFactorRequired response (the API reference
# documents only the *successful* login shape, which is different):
#
#   response.code            "SecondFactorRequired"
#   response.message
#   response.errorId
#   response.token           <- the short-lived second-factor token
#   response.body.token      <- the same value, duplicated
#   response.body.mfa.type   <- which second factor the account uses
#
# Note there is no "user" node at all here, so response.user.token — where the
# session token lives on a *successful* login — does not exist yet.  The probe
# order below still checks it first, harmlessly, before falling back to
# response.token, so both shapes work.
function Get-BuzzSecondFactorToken([psobject] $response) {
    $inner = Get-BuzzProp $response 'response'
    if ($null -eq $inner) { $inner = $response }

    $candidate = Get-BuzzProp (Get-BuzzProp $inner 'user') 'token'
    if (-not [string]::IsNullOrEmpty($candidate)) { return $candidate }

    foreach ($name in 'token', 'mfatoken', 'secondfactortoken', 'logintoken') {
        $candidate = Get-BuzzProp $inner $name
        if ($candidate -is [string] -and -not [string]::IsNullOrEmpty($candidate)) { return $candidate }
    }

    # response.body.token carries the same value on the observed shape.
    $candidate = Get-BuzzProp (Get-BuzzProp $inner 'body') 'token'
    if ($candidate -is [string] -and -not [string]::IsNullOrEmpty($candidate)) { return $candidate }

    return (Find-BuzzToken $inner)
}

# Describe a response's structure — property names and value kinds only, never
# values, since this is printed to the console to diagnose a failed login.
function Get-BuzzShape([object] $node, [string] $prefix = '', [int] $depth = 0) {
    $lines = @()
    if ($null -eq $node -or $depth -gt 6) { return $lines }

    if ($node -is [string] -or $node -is [ValueType]) {
        $lines += "  $($prefix.TrimEnd('.')) : $($node.GetType().Name)"
        return $lines
    }
    if ($node -is [System.Collections.IEnumerable]) {
        $i = 0
        foreach ($item in $node) {
            $lines += Get-BuzzShape $item "$($prefix.TrimEnd('.'))[$i]." ($depth + 1)
            $i++
        }
        return $lines
    }
    foreach ($p in $node.PSObject.Properties) {
        if ($null -ne $p.Value -and -not ($p.Value -is [string]) -and -not ($p.Value -is [ValueType])) {
            $lines += Get-BuzzShape $p.Value "$prefix$($p.Name)." ($depth + 1)
        } else {
            $kind = if ($null -eq $p.Value) { 'null' } else { $p.Value.GetType().Name }
            $lines += "  $prefix$($p.Name) : $kind"
        }
    }
    return $lines
}

# Plain-language guidance for the login3 failure codes the API documents.
function Get-BuzzLoginHint([string] $code) {
    switch ($code) {
        'InvalidCredentials'   { return "The username or password is not correct." }
        'AccountLockout'       { return "The account is locked out after too many failed password attempts. An administrator must unlock it." }
        'PasswordExpired'      { return "The password has expired and must be changed in Buzz before this account can be used here." }
        'DeactivatedUserOrDomain' { return "The account or its domain has been deactivated." }
        'LoginMethodNotAllowed'   { return "This account does not allow password login (SSO-only accounts, for example). Use a different admin account." }
        'PasswordPolicyRequirementsNotMet' { return "The password no longer meets the domain password policy and must be reset in Buzz first." }
        'LicenseLimitExceeded' { return "The domain's license limit is exceeded for one of this account's personas." }
        'LicenseExpired'       { return "The domain's license has expired." }
        'LicenseNotYetValid'   { return "The domain's license is not valid yet." }
        'NoLicense'            { return "The domain has no license." }
        default                { return $null }
    }
}

# ── Step 1: Server URL ────────────────────────────────────────────────────────
# backgroundapi is the host intended for server-to-server integrations like this one.
$defaultServerUrl = "https://backgroundapi.agilixbuzz.com"

Write-Host "─── Step 1: Buzz Server URL ───────────────────────────────" -ForegroundColor Yellow
if ([string]::IsNullOrEmpty($ServerUrl)) {
    $ServerUrl = (Read-Host "Buzz API server URL [default: $defaultServerUrl]").Trim()
    if ([string]::IsNullOrEmpty($ServerUrl)) { $ServerUrl = $defaultServerUrl }
}
if ([string]::IsNullOrEmpty($ServerUrl)) {
    throw "Server URL is required."
}
$ServerUrl = $ServerUrl.TrimEnd('/')
Write-Host "  Server: $ServerUrl" -ForegroundColor Green
Write-Host ""

# ── Step 2: Admin login ───────────────────────────────────────────────────────
Write-Host "─── Step 2: Admin Login ───────────────────────────────────" -ForegroundColor Yellow
Write-Host "Log in as a Buzz administrator who has rights to create users"
Write-Host "and register OAuth keys.  This session is used only during setup"
Write-Host "and is not stored anywhere."
Write-Host ""

$adminToken = $null
while ($null -eq $adminToken) {
    $adminLogin = ""
    while (-not ($adminLogin -match '^[^/]+/[^/]+$')) {
        $adminLogin = (Read-Host "Admin username (userspace/username, e.g. myschool/admin)").Trim()
        if (-not ($adminLogin -match '^[^/]+/[^/]+$')) {
            Write-Host "  Username must be in userspace/username format." -ForegroundColor Yellow
        }
    }
    $adminPassSec  = Read-Host "Admin password" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPassSec)
    $adminPassword = $null
    try     { $adminPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    Write-Host ""

    Write-Host "Logging in..." -NoNewline
    $loginBody = @{
        request = @{
            cmd      = "login3"
            username = $adminLogin
            password = $adminPassword
        }
    } | ConvertTo-Json -Depth 5
    $adminPassword = $null

    $loginResult = $null
    try {
        $loginResult = Invoke-RestMethod @_bp `
            -Uri             "$ServerUrl/cmd/login3" `
            -Method          Post `
            -ContentType     "application/json" `
            -Headers         @{ Accept = "application/json" } `
            -Body            $loginBody
    } catch {
        $loginBody = $null
        Write-Host ""
        Write-Host "  Network error: $_" -ForegroundColor Red
        Write-Host "  Please check the server URL and try again.  Press Ctrl+C to abort." -ForegroundColor Yellow
        Write-Host ""
        continue
    }
    $loginBody = $null

    $loginCode = Get-BuzzCode $loginResult

    # ── Multi-factor authentication ───────────────────────────────────────────
    # login3 returns SecondFactorRequired when the password was correct but the
    # account has MFA configured.  The token it returns alongside that code is a
    # short-lived token good only for secondfactorauthenticate, which returns the
    # real session token.  See:
    #   https://api.agilixbuzz.com/docs/entry/Command/Login3.md
    #   https://api.agilixbuzz.com/docs/entry/Command/SecondFactorAuthenticate.md
    if ($loginCode -eq "SecondFactorConfigurationNowRequired") {
        Write-Host ""
        Write-Host "  This account must configure multi-factor authentication before it can" -ForegroundColor Red
        Write-Host "  be used.  Sign in to Buzz with this account, complete the MFA setup," -ForegroundColor Yellow
        Write-Host "  then re-run this script.  Press Ctrl+C to abort." -ForegroundColor Yellow
        Write-Host ""
        continue
    }

    if ($loginCode -eq "SecondFactorRequired") {
        Write-Host " multi-factor authentication required." -ForegroundColor Yellow

        # Short-lived token that authorises only the secondfactorauthenticate call.
        $partialToken = Get-BuzzSecondFactorToken $loginResult
        if ([string]::IsNullOrEmpty($partialToken)) {
            Write-Host ""
            Write-Host "  Buzz asked for a second factor but no token could be found in its reply." -ForegroundColor Red
            Write-Host "  Response structure (names and types only — no values are shown):" -ForegroundColor Yellow
            Get-BuzzShape $loginResult | ForEach-Object { Write-Host $_ -ForegroundColor DarkGray }
            Write-Host "  Please report the above.  Press Ctrl+C to abort." -ForegroundColor Yellow
            Write-Host ""
            continue
        }

        $otp = ""
        while ([string]::IsNullOrEmpty($otp)) {
            $otp = (Read-Host "One-time code from your authenticator app or email").Trim()
        }

        # The token goes in the Authorization: Bearer header — not in the request
        # body, and not in the query string.  A "token" field in the body is ignored
        # and answered with AccessDenied userId='-1' (the API reference's worked
        # example showing it there is wrong; its request-field table correctly lists
        # only cmd/otp/rememberdevice).  A _token query parameter is accepted, but
        # putting credentials in a URL leaks them into server and proxy logs.
        $mfaBody = @{
            request = @{
                cmd = "secondfactorauthenticate"
                otp = $otp
            }
        } | ConvertTo-Json -Depth 5
        $mfaHeaders = @{ Accept = "application/json"; Authorization = "Bearer $partialToken" }
        $partialToken = $null
        $otp          = $null

        try {
            $loginResult = Invoke-RestMethod @_bp `
                -Uri             "$ServerUrl/cmd/secondfactorauthenticate" `
                -Method          Post `
                -ContentType     "application/json" `
                -Headers         $mfaHeaders `
                -Body            $mfaBody
        } catch {
            $mfaBody = $null
            Write-Host ""
            Write-Host "  Second-factor request failed: $_" -ForegroundColor Red
            Write-Host "  Please try again.  Press Ctrl+C to abort." -ForegroundColor Yellow
            Write-Host ""
            continue
        }
        $mfaBody = $null
        $loginCode = Get-BuzzCode $loginResult
    }

    if ($loginCode -ne "OK") {
        Write-Host ""
        $loginMsg = $null
        if ($loginResult.PSObject.Properties['response']) {
            $r = $loginResult.response
            if ($null -ne $r -and $r.PSObject.Properties['message']) { $loginMsg = [string]$r.message }
        }
        $suffix = if ($loginMsg) { ": $loginMsg" } else { "" }
        Write-Host "  Login failed (code: $loginCode)$suffix." -ForegroundColor Red
        $hint = Get-BuzzLoginHint $loginCode
        if ($hint) { Write-Host "  $hint" -ForegroundColor Yellow }
        Write-Host "  Please check your credentials and try again.  Press Ctrl+C to abort." -ForegroundColor Yellow
        Write-Host ""
        continue
    }

    $candidateToken = Get-BuzzLoginToken $loginResult

    if ([string]::IsNullOrEmpty($candidateToken)) {
        Write-Host ""
        Write-Host "  Login succeeded but no token was returned." -ForegroundColor Red
        Write-Host "  Please try again.  Press Ctrl+C to abort." -ForegroundColor Yellow
        Write-Host ""
        continue
    }

    $adminToken = $candidateToken
}
Write-Host " OK" -ForegroundColor Green
Write-Host ""

# ── Step 3: Certificate store ─────────────────────────────────────────────────
Write-Host "─── Step 3: Certificate Store Location ────────────────────" -ForegroundColor Yellow
Write-Host "The private key is stored in the OS certificate store so it"
Write-Host "never exists as a plaintext file."
Write-Host ""
Write-Host "  CurrentUser  — for interactive users and per-user services (default)"
Write-Host "  LocalMachine — for Windows services running as SYSTEM or a service account"
Write-Host "                 (requires running this script as Administrator)"
Write-Host ""
if (-not $PSBoundParameters.ContainsKey('StoreLocation')) {
    while ($true) {
        $storeInput = (Read-Host "Store location [CurrentUser/LocalMachine] (default: CurrentUser)").Trim()
        if ([string]::IsNullOrEmpty($storeInput)) { $StoreLocation = "CurrentUser"; break }
        if ($storeInput -eq "CurrentUser" -or $storeInput -eq "LocalMachine") {
            $StoreLocation = $storeInput; break
        }
        Write-Host "  Please enter 'CurrentUser' or 'LocalMachine'." -ForegroundColor Yellow
    }
}
Write-Host "  Store: $StoreLocation" -ForegroundColor Green
Write-Host ""

if ($StoreLocation -eq 'LocalMachine') {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        $adminToken = $null
        throw "LocalMachine certificate store requires Administrator rights.`nRe-run PowerShell as Administrator and try again."
    }
}

# ── Step 4: Application info ──────────────────────────────────────────────────
Write-Host "─── Step 4: Application Information ──────────────────────" -ForegroundColor Yellow
Write-Host "These describe the calling application, not the Buzz account.  They are"
Write-Host "sent in the User-Agent header on every request so Agilix support can"
Write-Host "identify your integration in server logs.  Nothing here is stored on a"
Write-Host "Buzz account; step 5 asks separately for the account's own details."
Write-Host ""
$contactInformation     = (Read-Host "Your contact info (name, email, or URL)").Trim()
$applicationInformation = (Read-Host "Application name (e.g. SisSync, RosterImport)").Trim()
if ([string]::IsNullOrEmpty($contactInformation))     { throw "Contact information is required." }
if ([string]::IsNullOrEmpty($applicationInformation)) { throw "Application name is required." }
Write-Host ""

# ── Step 5: Application Identity account ─────────────────────────────────────
Write-Host "─── Step 5: Application Identity Account ──────────────────" -ForegroundColor Yellow
Write-Host "This is the Buzz user account that represents your application."
Write-Host "It authenticates via OAuth only — it has no password."
Write-Host ""

$createNew = $null
while ($createNew -notin @("N","Y")) {
    $createNew = (Read-Host "Create a new Application Identity account? [Y/n]").Trim().ToUpper()
    if ([string]::IsNullOrEmpty($createNew)) { $createNew = "Y" }
    elseif ($createNew -notin @("N","Y")) {
        Write-Host "  Please enter 'Y' or 'N'." -ForegroundColor Yellow
    }
}

$oauthUserId = ""

if ($createNew -eq "Y") {
    Write-Host "Fetching available domains..." -NoNewline
    try {
        # ListDomains, not "getdomains" — the latter is not a Buzz command and always
        # failed, silently falling through to the manual domain-ID prompt below.
        # domainid=0 means "every domain this account has ReadDomain rights on";
        # limit=0 lifts the default 100-domain cap (capped server-side at 1000 for
        # domainid=0).  https://api.agilixbuzz.com/docs/entry/Command/ListDomains.md
        $domainsResult = Invoke-RestMethod @_bp `
            -Uri             "$ServerUrl/cmd/listdomains?domainid=0&limit=0" `
            -Method          Get `
            -Headers         @{ Accept = "application/json"; Authorization = "Bearer $adminToken" }
        Write-Host " done" -ForegroundColor Green

        $domains = @()
        # ListDomains nests the list as .response.domains.domain, but when the account can
        # read no domains it answers code OK with an EMPTY object -- "domains":{} -- which
        # has no "domain" child at all.  Probe every level with PSObject.Properties;
        # dereferencing .domains.domain directly throws under Set-StrictMode -Version Latest.
        $rawDomains = $null
        $respObj = Get-BuzzProp $domainsResult 'response'
        if ($null -eq $respObj) { $respObj = $domainsResult }
        $domainsNode = Get-BuzzProp $respObj 'domains'
        if ($null -ne $domainsNode) {
            $rawDomains = Get-BuzzProp $domainsNode 'domain'
        }
        if ($null -eq $rawDomains) {
            $rawDomains = Get-BuzzProp $respObj 'domain'
        }

        if ($rawDomains -is [array]) { $domains = $rawDomains }
        elseif ($rawDomains)         { $domains = @($rawDomains) }

        # The Domain schema names this "id", not "domainid" -- reading "domainid" here
        # yields an empty value, and selecting a domain by number then sends a blank
        # domainid to CreateUsers2.  ("domainid" is the name used when *supplying* a
        # domain, e.g. the CreateUsers2 request field.)
        if ($domains.Count -gt 0) {
            Write-Host ""
            Write-Host "Available domains:"
            $i = 1
            foreach ($d in $domains) {
                Write-Host ("  {0,2}. {1,-30} (id: {2})" -f $i, (Get-BuzzProp $d 'name'), (Get-BuzzProp $d 'id'))
                $i++
            }
            Write-Host ""
            $domainChoice = (Read-Host "Enter domain number or type the domainid directly").Trim()
            if ($domainChoice -match '^\d+$' -and [int]$domainChoice -ge 1 -and [int]$domainChoice -le $domains.Count) {
                $targetDomainId = Get-BuzzProp $domains[[int]$domainChoice - 1] 'id'
            } else {
                $targetDomainId = $domainChoice
            }
        } else {
            # An empty list is normal when the admin holds no ReadDomain right anywhere,
            # or when the domain simply has no child domains.  Not an error — just ask.
            Write-Host ""
            Write-Host "  No domains were listed for this account, so enter the target domain directly." -ForegroundColor Yellow
            $targetDomainId = (Read-Host "Domain ID for the new account (e.g. //myschool or 12345678)").Trim()
        }
    } catch {
        Write-Host " (could not fetch domains: $_)" -ForegroundColor Yellow
        $targetDomainId = (Read-Host "Domain ID for the new account (e.g. //myschool)").Trim()
    }

    Write-Host ""
    $appUsername  = (Read-Host "Username for the Application Identity account (e.g. sis-sync)").Trim()
    $appFirstName = (Read-Host "First name (e.g. SIS)").Trim()
    $appLastName  = (Read-Host "Last name (e.g. Sync)").Trim()
    # Distinguish this from the Step 4 contact info: that string goes in the User-Agent
    # header, whereas this becomes the "email" attribute of the account being created.
    $appEmail     = (Read-Host "Email address for this account (optional, press Enter to skip)").Trim()

    Write-Host ""
    Write-Host "Creating Application Identity account '$appUsername'..." -NoNewline

    $userFields = @{
        domainid  = $targetDomainId
        type      = "applicationidentity"
        username  = $appUsername
        firstname = $appFirstName
        lastname  = $appLastName
    }
    if ($appEmail) { $userFields["email"] = $appEmail }

    # CreateUsers2 acts on one or more users, so the documented body shape is a "user"
    # list under "requests"; we send a single-element list because we create one account.
    # (There is no singular {"request":{...}} form for this command -- the server rejects
    # that outright with code Format.)
    $createBody = @{
        requests = @{
            user = @($userFields)
        }
    } | ConvertTo-Json -Depth 10

    try {
        $createResult = Invoke-RestMethod @_bp `
            -Uri             "$ServerUrl/cmd/createusers2" `
            -Method          Post `
            -ContentType     "application/json" `
            -Headers         @{ Accept = "application/json"; Authorization = "Bearer $adminToken" } `
            -Body            $createBody
    } catch {
        $adminToken = $null
        Write-Host ""
        throw "CreateUsers2 request failed: $_"
    }

    $createCode = Get-BuzzCode $createResult
    if ($createCode -ne "OK") {
        $adminToken = $null
        throw "CreateUsers2 failed: code=$createCode  $(ConvertTo-Json $createResult -Depth 5)"
    }

    # CreateUsers2 reports the outcome for the user it created under responses.response,
    # NOT in the outer code: the outer code is OK whenever the request was well formed,
    # so a per-user AccessDenied arrives inside an "OK" envelope.  This holds even for a
    # single user, so reading the inner code is the only way to know whether the account
    # was actually created.  (BuzzApiClient.cs does the same via VerifyResponse's
    # checkChildResponses pass.)
    $respNode      = Get-BuzzProp $createResult 'response'
    $responsesNode = Get-BuzzProp $respNode 'responses'
    $firstResponse = Get-BuzzProp $responsesNode 'response'
    if ($firstResponse -is [array]) { $firstResponse = $firstResponse[0] }

    $itemCode = Get-BuzzProp $firstResponse 'code'
    if ($itemCode -and $itemCode -ne 'OK') {
        $itemMsg = Get-BuzzProp $firstResponse 'message'
        $adminToken = $null
        Write-Host ""
        if ($itemCode -eq 'AccessDenied') {
            throw ("CreateUsers2 was denied (code: $itemCode$(if ($itemMsg) { " - $itemMsg" })).`n" +
                   "The admin account needs the CreateUser right on domain $targetDomainId.`n" +
                   "Grant it that right (and UpdateUser, so it can register the OAuth key in step 7), then re-run.")
        }
        throw "CreateUsers2 failed for the requested user: code=$itemCode$(if ($itemMsg) { " - $itemMsg" })"
    }

    $oauthUserId = Get-BuzzProp (Get-BuzzProp $firstResponse 'user') 'userid'

    if ([string]::IsNullOrEmpty($oauthUserId)) {
        $adminToken = $null
        throw "CreateUsers2 succeeded but returned no userid.`nResponse: $(ConvertTo-Json $createResult -Depth 5)"
    }
    Write-Host " OK (userid: $oauthUserId)" -ForegroundColor Green
} else {
    $oauthUserId = (Read-Host "Enter the existing Application Identity account userid").Trim()
    if ([string]::IsNullOrEmpty($oauthUserId)) { throw "userid is required." }
    Write-Host "  Using existing account: $oauthUserId" -ForegroundColor Green
}
Write-Host ""

# ── Step 6: Key generation + certificate store ────────────────────────────────
Write-Host "─── Step 6: RSA Key Generation ────────────────────────────" -ForegroundColor Yellow

if (-not $PSBoundParameters.ContainsKey('KeySize')) {
    while ($true) {
        $sizeInput = (Read-Host "RSA key size in bits [2048/3072/4096] (default: 2048)").Trim()
        if ([string]::IsNullOrEmpty($sizeInput)) { $KeySize = 2048; break }
        $parsed = 0
        if ([int]::TryParse($sizeInput, [ref]$parsed) -and $parsed -ge 2048 -and $parsed -le 16384) {
            $KeySize = $parsed; break
        }
        Write-Host "  Key size must be between 2048 and 16384 bits." -ForegroundColor Yellow
    }
}

Write-Host "Generating a $KeySize-bit RSA key pair and importing the private key"
Write-Host "into the $StoreLocation certificate store."
Write-Host ""

$quarter    = [Math]::Ceiling([datetime]::UtcNow.Month / 3)
$defaultKid = "$([datetime]::UtcNow.Year)-q$quarter"
$kid = (Read-Host "Key ID (kid) for this key [default: $defaultKid]").Trim()
if ([string]::IsNullOrEmpty($kid)) { $kid = $defaultKid }
if ($kid -notmatch '^[A-Za-z0-9\-_\.]{1,128}$') {
    $adminToken = $null
    throw "Invalid kid '$kid'. Allowed: ASCII letters, digits, -, _, .  Max 128 chars."
}

$certSubject = "CN=BuzzOAuth-$($applicationInformation -replace '[,=+<>#;"\\]', '')-$kid"

Write-Host "  Kid         : $kid"
Write-Host "  Cert subject: $certSubject"
Write-Host "  Store       : $StoreLocation/My"
Write-Host ""
Write-Host "Generating key..." -NoNewline

if ($IsWindows) {
    # Use New-SelfSignedCertificate which stores the private key directly as CNG (KSP)
    # in the certificate store, with no PFX round-trip. In .NET Framework (PS5.1),
    # X509Certificate2 PFX import silently converts any CNG key to CAPI, and
    # GetRSAPrivateKey() returns null for CAPI-backed certs in .NET 5+ (dotnet run / PS7).
    $certObj = New-SelfSignedCertificate `
        -Subject $certSubject `
        -KeyAlgorithm RSA `
        -KeyLength $KeySize `
        -KeyExportPolicy NonExportable `
        -NotAfter ([datetime]::UtcNow.AddYears(100)) `
        -CertStoreLocation "Cert:\$StoreLocation\My" `
        -Provider "Microsoft Software Key Storage Provider" `
        -HashAlgorithm SHA256
    $thumbprint   = $certObj.Thumbprint
    # PublicKey.Key is a plain property (works in PS5.1); GetRSAPrivateKey() is an
    # extension method and cannot be called as an instance method in PS5.1.
    $publicKeyPem = Export-BuzzSpkiPem $certObj.PublicKey.Key
    $certObj.Dispose()
} else {
    # Pass the size to Create().  The parameterless overload ignores a later
    # KeySize assignment (the property is read-only on .NET Framework) and would
    # yield a key below the 2048-bit minimum Buzz accepts.
    $rsa = New-BuzzRsaKey -KeySize $KeySize

    $certReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $certSubject,
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $notBefore = [DateTimeOffset]::UtcNow
    $notAfter  = $notBefore.AddYears(100)
    $cert      = $certReq.CreateSelfSigned($notBefore, $notAfter)

    $store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::My,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::$StoreLocation
    )
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        $store.Add($cert)
    } finally {
        $store.Close()
    }
    $thumbprint = $cert.Thumbprint
    $cert.Dispose()

    $publicKeyPem = Export-BuzzSpkiPem $rsa
    $rsa.Dispose()
}

Write-Host " done" -ForegroundColor Green
Write-Host "  Thumbprint: $thumbprint" -ForegroundColor Green

if ($IsLinux) {
    $storeDir = Join-Path $env:HOME ".dotnet/corefx/cryptography/x509stores/my"
    if (Test-Path $storeDir) {
        & chmod 700 $storeDir 2>&1 | Out-Null
        Write-Host ""
        Write-Host "NOTE (Linux): Tightened cert store permissions: chmod 700 $storeDir" -ForegroundColor Yellow
        Write-Host "  Ensure the service account running your app owns that directory."
    }
}
Write-Host ""

# ── Step 7: Register the public key with Buzz ─────────────────────────────────
Write-Host "─── Step 7: Registering Public Key with Buzz ──────────────" -ForegroundColor Yellow
$keyRegUrl = "$ServerUrl/api/users/$oauthUserId/keys/$kid"
Write-Host "  PUT $keyRegUrl" -NoNewline

try {
    $regResponse = Invoke-WebRequest @_bp `
        -Uri             $keyRegUrl `
        -Method          Put `
        -Headers         @{ Authorization = "Bearer $adminToken" } `
        -ContentType     "application/x-pem-file" `
        -Body            ([System.Text.Encoding]::UTF8.GetBytes($publicKeyPem))
} catch {
    $adminToken = $null
    Write-Host ""
    $sc = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $null }
    if ($sc -eq 400) {
        throw "HTTP 400: public key rejected. Verify account $oauthUserId was created with type=applicationidentity."
    } elseif ($sc -eq 401 -or $sc -eq 403) {
        throw "HTTP ${sc}: admin account lacks Update User rights on account $oauthUserId."
    }
    throw "Key registration failed: $_"
}

if ($regResponse.StatusCode -ne 204) {
    $adminToken = $null
    throw "Expected HTTP 204 from key registration, got $($regResponse.StatusCode)."
}
Write-Host " 204 OK" -ForegroundColor Green
$adminToken = $null
Write-Host ""

# ── Step 8: Write buzz-config.json ────────────────────────────────────────────
Write-Host "─── Step 8: Writing Configuration ─────────────────────────" -ForegroundColor Yellow

$config = [ordered]@{
    serverUrl              = $ServerUrl
    contactInformation     = $contactInformation
    applicationInformation = $applicationInformation
    oauthUserId            = $oauthUserId
    oauthKid               = $kid
    certThumbprint         = $thumbprint
    certStoreLocation      = $StoreLocation
}

# Write UTF-8 without BOM so the file is portable across all platforms
$configDir = Split-Path $ConfigOutput -Parent
if ($configDir -and -not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Force -Path $configDir | Out-Null
}
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
[System.IO.File]::WriteAllText($ConfigOutput, ($config | ConvertTo-Json), $utf8NoBom)
Write-Host "  Written: $ConfigOutput" -ForegroundColor Green
Write-Host ""

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Setup complete!" -ForegroundColor Green
Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "OAuth User ID  : $oauthUserId"
Write-Host "Key ID (kid)   : $kid"
Write-Host "Cert Thumbprint: $thumbprint"
Write-Host "Config file    : $ConfigOutput"
Write-Host ""
Write-Host "To test the configuration:" -ForegroundColor Cyan
Write-Host "  cd $projectRoot"
Write-Host "  dotnet run"
Write-Host ""
Write-Host "Security reminders:" -ForegroundColor Yellow
Write-Host "  - The private key is in the $StoreLocation certificate store, not a file."
Write-Host "  - buzz-config.json contains no secrets and is gitignored."
Write-Host "  - To rotate the key later, re-run this script with a new kid."
Write-Host "  - To revoke an access token: POST $ServerUrl/api/oauth/revoke with form body token=<access_token>"
Write-Host ""
