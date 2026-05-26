<#
.SYNOPSIS
    Registers an RSA public key with Buzz for OAuth 2.0 authentication.

.DESCRIPTION
    Uploads a PEM public key to PUT {server}/api/users/{userid}/keys/{kid}.
    A 204 response means the key is stored and the Application Identity account can now
    authenticate via OAuth.  The caller must hold the Update User right on the account.

    Run this script once for each key you generate.  You can register multiple keys
    per account (for zero-downtime rotation) and delete old keys when no longer needed.

.PARAMETER ServerUrl
    Buzz API server URL, e.g. https://api.agilixbuzz.com  (no trailing slash).

.PARAMETER AdminToken
    A valid Bearer access token for an account with the Update User right on the
    Application Identity account.

    To obtain an admin token via OAuth (if you already have another OAuth app set up):
        .\scripts\Get-BuzzOAuthToken.ps1 ...

    To obtain a token using the legacy login3 command:
        $r = Invoke-RestMethod -Uri "$ServerUrl/cmd/login3" -Method Post `
                 -ContentType "application/json" `
                 -Body '{"request":{"cmd":"login3","username":"space/user","password":"..."}}'
        $AdminToken = $r.response.user.token

.PARAMETER UserId
    The userid of the Application Identity account.  This is the value returned by
    CreateUsers2 when you created the account with type=applicationidentity.

.PARAMETER Kid
    A short identifier for this key, e.g. "2025-q2" or "v1".
    Allowed characters: ASCII letters, digits, hyphens (-), underscores (_), dots (.).
    Maximum 128 characters.  PUTting an existing kid REPLACES the key immediately —
    use a new kid for rotation (see README.md).

.PARAMETER PublicKeyPath
    Path to the PEM public key file in SubjectPublicKeyInfo (SPKI) format.
    This is the public_key.pem produced by New-BuzzOAuthKey.ps1 or:
        openssl pkey -in private_key.pem -pubout -out public_key.pem

.EXAMPLE
    # Basic usage
    .\scripts\Register-BuzzOAuthKey.ps1 `
        -ServerUrl   https://api.agilixbuzz.com `
        -AdminToken  "~0.ABC123..." `
        -UserId      12345678 `
        -Kid         "2025-q2" `
        -PublicKeyPath .\public_key.pem

.EXAMPLE
    # Store the admin token in a variable first to avoid it appearing in shell history
    $token = Read-Host -AsSecureString "Admin Bearer token"
    $plainToken = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($token))
    .\scripts\Register-BuzzOAuthKey.ps1 -ServerUrl https://api.agilixbuzz.com `
        -AdminToken $plainToken -UserId 12345678 -Kid "2025-q2" -PublicKeyPath .\public_key.pem

.NOTES
    After registration the Application Identity account is ready.  Configure your app with:
        buzzServerUrl = <ServerUrl>
        oauthUserId   = <UserId>
        oauthKid      = <Kid>
        privateKeyPath = path to private_key.pem
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ServerUrl,
    [Parameter(Mandatory)] [string] $AdminToken,
    [Parameter(Mandatory)] [string] $UserId,
    [Parameter(Mandatory)] [string] $Kid,
    [Parameter(Mandatory)] [string] $PublicKeyPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Validate inputs ──────────────────────────────────────────────────────────
$ServerUrl = $ServerUrl.TrimEnd('/')

if (-not (Test-Path $PublicKeyPath)) {
    Write-Error "Public key file not found: $PublicKeyPath"
    exit 1
}

if ($Kid -notmatch '^[A-Za-z0-9\-_\.]{1,128}$') {
    Write-Error "Invalid kid '$Kid'. Allowed characters: ASCII letters, digits, -, _, .  Max 128 characters."
    exit 1
}

$publicKeyPem = Get-Content -Path $PublicKeyPath -Raw -Encoding UTF8

if ($publicKeyPem -notmatch '-----BEGIN PUBLIC KEY-----') {
    Write-Error "File '$PublicKeyPath' does not appear to be a SubjectPublicKeyInfo PEM public key.`nExpected a '-----BEGIN PUBLIC KEY-----' header.`nGenerate one with: openssl pkey -in private_key.pem -pubout -out public_key.pem"
    exit 1
}

# ── Register the key ─────────────────────────────────────────────────────────
$url = "$ServerUrl/api/users/$UserId/keys/$Kid"
Write-Host "Registering public key..."
Write-Host "  URL    : $url"
Write-Host "  Kid    : $Kid"
Write-Host "  Key file: $([System.IO.Path]::GetFullPath($PublicKeyPath))"
Write-Host ""

try {
    $response = Invoke-WebRequest `
        -Uri             $url `
        -Method          Put `
        -Headers         @{ Authorization = "Bearer $AdminToken" } `
        -ContentType     "application/x-pem-file" `
        -Body            ([System.Text.Encoding]::UTF8.GetBytes($publicKeyPem)) `
        -UseBasicParsing

    if ($response.StatusCode -eq 204) {
        Write-Host "Public key registered successfully (HTTP 204)."
        Write-Host ""
        Write-Host "Configure your application with:"
        Write-Host "  buzzServerUrl = $ServerUrl"
        Write-Host "  oauthUserId   = $UserId"
        Write-Host "  oauthKid      = $Kid"
        Write-Host "  privateKeyPath = <path to your private_key.pem>"
    } else {
        Write-Warning "Unexpected HTTP status: $($response.StatusCode)"
        Write-Host $response.Content
    }
}
catch {
    $statusCode = $null
    if ($_.Exception.Response) {
        $statusCode = [int]$_.Exception.Response.StatusCode
    }

    Write-Host "ERROR: Key registration failed." -ForegroundColor Red

    switch ($statusCode) {
        400 {
            Write-Host "HTTP 400 Bad Request — possible causes:" -ForegroundColor Yellow
            Write-Host "  - The public key is not in SubjectPublicKeyInfo (SPKI) PEM format."
            Write-Host "    Re-generate with: openssl pkey -in private_key.pem -pubout -out public_key.pem"
            Write-Host "  - The key is smaller than the 2048-bit minimum."
            Write-Host "  - Account $UserId was not created with type=applicationidentity."
        }
        { $_ -eq 401 -or $_ -eq 403 } {
            Write-Host "HTTP $statusCode Unauthorized/Forbidden — possible causes:" -ForegroundColor Yellow
            Write-Host "  - The AdminToken has expired or is invalid."
            Write-Host "  - The admin account does not have the Update User right on account $UserId."
        }
        404 {
            Write-Host "HTTP 404 Not Found — possible causes:" -ForegroundColor Yellow
            Write-Host "  - ServerUrl '$ServerUrl' is incorrect."
            Write-Host "  - UserId '$UserId' does not exist."
        }
        default {
            if ($statusCode) { Write-Host "HTTP $statusCode" -ForegroundColor Yellow }
            Write-Host $_.Exception.Message
        }
    }
    exit 1
}
