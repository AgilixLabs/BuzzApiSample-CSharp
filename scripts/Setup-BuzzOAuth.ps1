<#
.SYNOPSIS
    Interactive guided setup for Buzz OAuth 2.0 authentication.

.DESCRIPTION
    Walks you through the one-time setup needed to authenticate a background service
    or integration to the Buzz API using OAuth 2.0 JWT client credentials.

    What this script does (Steps 1–8):
      1. Prompts for the Buzz server URL.
      2. Logs in as a Buzz administrator (supports MFA).  Credentials are verified
         early so mistakes are caught before any other information is entered.
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

    Requires: Windows PowerShell 5.1.
    On Windows 11 the required .NET Framework 4.8 is already installed.

.PARAMETER ServerUrl
    Buzz API server URL (e.g. https://api.agilixbuzz.com).  Prompted interactively if omitted.

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
    .\scripts\Setup-BuzzOAuth.ps1 -ServerUrl https://api.agilixbuzz.com

.NOTES
    SECURITY
    - The private key is stored in the OS certificate store, not in a file.
    - buzz-config.json contains the certificate thumbprint (not any secret material) and
      is gitignored.
    - The setup admin token is used only during this script and is never written to disk.
    - On Linux the dotnet cert store is a directory of PFX files under ~/.dotnet/. Restrict
      that directory's permissions: chmod 700 ~/.dotnet/corefx/cryptography/x509stores/my
    - On Windows you can make the private key non-exportable for extra hardening; see the
      comment near "X509Certificate2::new(...PersistKeySet...)" in the script.
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

# ── Helper: export RSA public key as SubjectPublicKeyInfo PEM ─────────────────
# Compatible with PS5.1 / .NET Framework 4.x — no .NET 5+ APIs needed.
function Export-SpkiPem([System.Security.Cryptography.RSA] $rsaKey) {
    $p = $rsaKey.ExportParameters($false)

    function Encode-DerLength([int] $len) {
        if ($len -lt 0x80) { return [byte[]] @($len) }
        if ($len -lt 0x100) { return [byte[]] @(0x81, $len) }
        return [byte[]] @(0x82, [byte]($len -shr 8), [byte]($len -band 0xFF))
    }
    function Encode-TLV([byte] $tag, [byte[]] $value) {
        return [byte[]] @($tag) + (Encode-DerLength $value.Length) + $value
    }
    function Encode-DerInt([byte[]] $bytes) {
        # Strip leading zero bytes (keep at least one)
        $i = 0
        while ($i -lt ($bytes.Length - 1) -and $bytes[$i] -eq 0x00) { $i++ }
        $bytes = $bytes[$i..($bytes.Length - 1)]
        # Prepend 0x00 if the high bit is set (signals a positive integer in DER)
        if ($bytes[0] -band 0x80) { $bytes = [byte[]] @(0x00) + $bytes }
        return Encode-TLV 0x02 $bytes
    }

    # RSA public key inner SEQUENCE: { INTEGER modulus, INTEGER exponent }
    $rsaKeyBody = Encode-TLV 0x30 ((Encode-DerInt $p.Modulus) + (Encode-DerInt $p.Exponent))

    # BIT STRING: leading 0x00 (zero unused bits) + the RSA key body
    $bitString = Encode-TLV 0x03 ([byte[]] @(0x00) + $rsaKeyBody)

    # AlgorithmIdentifier: SEQUENCE { OID rsaEncryption (1.2.840.113549.1.1.1), NULL }
    # Pre-encoded: 30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00
    $algId = [byte[]] @(0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                        0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00)

    # SubjectPublicKeyInfo outer SEQUENCE: { algId, bitString }
    $spki = Encode-TLV 0x30 ($algId + $bitString)

    $b64 = [Convert]::ToBase64String($spki)
    $sb  = [System.Text.StringBuilder]::new()
    $sb.AppendLine("-----BEGIN PUBLIC KEY-----") | Out-Null
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        $sb.AppendLine($b64.Substring($i, [Math]::Min(64, $b64.Length - $i))) | Out-Null
    }
    $sb.Append("-----END PUBLIC KEY-----") | Out-Null
    return $sb.ToString()
}

function Get-BuzzCode([psobject] $response) {
    # Buzz responses nest the code under .response.code or directly under .code
    if ($null -ne $response.response -and $null -ne $response.response.code) {
        return $response.response.code
    }
    return $response.code
}

# ── Step 1: Server URL ────────────────────────────────────────────────────────
Write-Host "─── Step 1: Buzz Server URL ───────────────────────────────" -ForegroundColor Yellow
if ([string]::IsNullOrEmpty($ServerUrl)) {
    $ServerUrl = (Read-Host "Buzz API server URL (e.g. https://api.agilixbuzz.com)").Trim()
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

    # ── MFA handling ──────────────────────────────────────────────────────────
    if ($loginCode -match "(?i)(factor|challenge|otp|mfa|verify|multifactor)") {
        Write-Host " MFA required." -ForegroundColor Yellow
        $mfaCode = (Read-Host "Enter your MFA / one-time code").Trim()

        $partialToken = if ($null -ne $loginResult.response) { $loginResult.response.token } else { $loginResult.token }

        $mfaCmd  = "verifylogin"
        $mfaBody = @{
            request = @{
                cmd   = $mfaCmd
                token = $partialToken
                code  = $mfaCode
            }
        } | ConvertTo-Json -Depth 5
        $partialToken = $null

        try {
            $loginResult = Invoke-RestMethod @_bp `
                -Uri             "$ServerUrl/cmd/$mfaCmd" `
                -Method          Post `
                -ContentType     "application/json" `
                -Body            $mfaBody
        } catch {
            $mfaBody = $null
            Write-Host ""
            Write-Host "  MFA request failed: $_" -ForegroundColor Red
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
        Write-Host "  Please check your credentials and try again.  Press Ctrl+C to abort." -ForegroundColor Yellow
        Write-Host ""
        continue
    }

    $candidateToken = $null
    if ($null -ne $loginResult.response -and $null -ne $loginResult.response.user) {
        $candidateToken = $loginResult.response.user.token
    } elseif ($null -ne $loginResult.user) {
        $candidateToken = $loginResult.user.token
    }

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
Write-Host "This is included in the User-Agent header so Agilix support"
Write-Host "can identify your integration if you need help."
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
        $domainsResult = Invoke-RestMethod @_bp `
            -Uri             "$ServerUrl/cmd/getdomains?_token=$([Uri]::EscapeDataString($adminToken))" `
            -Method          Get
        Write-Host " done" -ForegroundColor Green

        $domains = @()
        # Use PSObject.Properties to safely probe optional fields under Set-StrictMode -Version Latest.
        # The Buzz getdomains response may nest domains as .response.domains.domain or .response.domain.
        $rawDomains = $null
        $respObj = if ($domainsResult.PSObject.Properties['response']) { $domainsResult.response } else { $domainsResult }
        if ($respObj.PSObject.Properties['domains']) {
            $rawDomains = $respObj.domains.domain
        } elseif ($respObj.PSObject.Properties['domain']) {
            $rawDomains = $respObj.domain
        }

        if ($rawDomains -is [array]) { $domains = $rawDomains }
        elseif ($rawDomains)         { $domains = @($rawDomains) }

        if ($domains.Count -gt 0) {
            Write-Host ""
            Write-Host "Available domains:"
            $i = 1
            foreach ($d in $domains) {
                Write-Host ("  {0,2}. {1,-30} (id: {2})" -f $i, $d.name, $d.domainid)
                $i++
            }
            Write-Host ""
            $domainChoice = (Read-Host "Enter domain number or type the domainid directly").Trim()
            if ($domainChoice -match '^\d+$' -and [int]$domainChoice -ge 1 -and [int]$domainChoice -le $domains.Count) {
                $targetDomainId = $domains[[int]$domainChoice - 1].domainid
            } else {
                $targetDomainId = $domainChoice
            }
        } else {
            $targetDomainId = (Read-Host "Domain ID for the new account (e.g. //myschool)").Trim()
        }
    } catch {
        Write-Host " (could not fetch domains: $_)" -ForegroundColor Yellow
        $targetDomainId = (Read-Host "Domain ID for the new account (e.g. //myschool)").Trim()
    }

    Write-Host ""
    $appUsername  = (Read-Host "Username for the Application Identity account (e.g. sis-sync)").Trim()
    $appFirstName = (Read-Host "First name (e.g. SIS)").Trim()
    $appLastName  = (Read-Host "Last name (e.g. Sync)").Trim()
    $appEmail     = (Read-Host "Email address (optional, press Enter to skip)").Trim()

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

    $createBody = @{
        requests = @{
            user = @($userFields)
        }
    } | ConvertTo-Json -Depth 10

    try {
        $createResult = Invoke-RestMethod @_bp `
            -Uri             "$ServerUrl/cmd/createusers2?_token=$([Uri]::EscapeDataString($adminToken))" `
            -Method          Post `
            -ContentType     "application/json" `
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

    $firstResponse = if ($null -ne $createResult.response -and $null -ne $createResult.response.responses) {
        $createResult.response.responses.response
    } else { $null }
    if ($firstResponse -is [array]) { $firstResponse = $firstResponse[0] }

    $oauthUserId = if ($null -ne $firstResponse -and $null -ne $firstResponse.user) {
        $firstResponse.user.userid
    } else { $null }

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

# Generate RSA key.
# Use RSACng on Windows (CNG-backed key) so that GetRSAPrivateKey() returns a non-null
# object in both .NET Framework (PS5.1) and .NET 5+ (PS7/dotnet run).
# RSACryptoServiceProvider (CAPI) keys return null from GetRSAPrivateKey() in .NET 5+.
$rsa = if ($IsWindows) {
    [System.Security.Cryptography.RSACng]::new($KeySize)
} else {
    $r = [System.Security.Cryptography.RSA]::Create()
    $r.KeySize = $KeySize
    $r
}

# Build a self-signed certificate as a container for the key.
# CertificateRequest is available in .NET Framework 4.7.2+ (included in Windows 11).
$certReq = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    $certSubject,
    $rsa,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
)

$notBefore = [DateTimeOffset]::UtcNow
$notAfter  = $notBefore.AddYears(100)
$cert      = $certReq.CreateSelfSigned($notBefore, $notAfter)

if ($IsWindows) {
    # Re-create from PFX with PersistKeySet so the CNG key is stored permanently
    # and is accessible by background services.
    # The key is non-exportable by default. Add X509KeyStorageFlags::PrivateKeyExportable
    # to the flags below if you need to back up or migrate the private key (less secure).
    $pfxBytes = $cert.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, "")
    $cert.Dispose()
    $keySetFlag = if ($StoreLocation -eq 'LocalMachine') {
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet
    } else {
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::UserKeySet
    }
    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $pfxBytes, "",
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
        $keySetFlag
    )
}

# Import into the OS certificate store
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

Write-Host " done" -ForegroundColor Green
Write-Host "  Thumbprint: $thumbprint" -ForegroundColor Green

# Export public key PEM from the RSA key object (compatible with PS5.1 / .NET Framework)
$publicKeyPem = Export-SpkiPem $rsa
$rsa.Dispose()

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
