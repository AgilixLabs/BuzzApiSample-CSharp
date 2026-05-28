# BuzzApiSample-CSharp

A C# sample and reusable client library for the Buzz API.  The `BuzzApiClient` class handles
OAuth 2.0 authentication, automatic token refresh, exponential backoff, and rate-limit
compliance so your integration code can focus on business logic.

## Authentication

The preferred authentication method for integrations is **OAuth 2.0 JWT Client Credentials**
([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) +
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)).
An RSA private key signs a short-lived JWT assertion; Buzz verifies the signature against the
registered public key and returns a Bearer access token valid for one hour.  The private key
never leaves your system — there is no shared secret to intercept.

The legacy username/password (`login3`) flow is still supported for backward compatibility but
is not recommended for new integrations.

---

## Overview

The Buzz API is an HTTP API consisting of GET and POST requests, accepting and returning JSON
(or XML).  The typical workflow is: authenticate, then perform operations.

**BuzzApiSample** demonstrates read-only access:
1. Configuring `BuzzApiClient` with OAuth credentials and a Buzz server URL
2. Calling `GetUser2` to verify authentication and discover the home domain
3. Calling `GetDomain2` to read domain details

The sample is intentionally read-only — it can be run repeatedly without modifying
any data in the target domain.

**BuzzApiClient** simplifies integration by:
- Managing OAuth tokens automatically — requests and refreshes Bearer tokens as needed
- Retrying transient failures with exponential backoff (1 s → 64 s, up to 5 retries)
- Honouring `Retry-After` and `X-RateLimit-Reset` headers from the server
- Providing `JsonRequest` and `VerifyResponse` helpers for common JSON API patterns

---

## Quickest Start

### Run (setup + demo in one command)

The run script checks whether one-time setup has been completed.  If not, it runs
the interactive setup first, then executes the read-only demo.

**Linux / macOS** (bash, requires `openssl curl python3 dotnet`):
```bash
chmod +x scripts/run-buzz-sample.sh
./scripts/run-buzz-sample.sh
```

**Windows** (PowerShell 5.1 or 7+):
```powershell
.\scripts\Run-BuzzSample.ps1
```

To force re-running the setup even when already configured:
```bash
./scripts/run-buzz-sample.sh --setup          # Linux / macOS
.\scripts\Run-BuzzSample.ps1 -ForceSetup      # Windows
```

### Cleanup (return to a completely clean state)

The cleanup script removes all artifacts from a previous setup run: deletes the
Application Identity account from Buzz, removes the registered OAuth key, removes
the local certificate, and deletes `buzz-config.json`.

**Linux / macOS**:
```bash
chmod +x scripts/cleanup-buzz-sample.sh
./scripts/cleanup-buzz-sample.sh
```

**Windows**:
```powershell
.\scripts\Cleanup-BuzzSample.ps1
```

After cleanup you can run the setup again from scratch.

---

## Setup Script (standalone)

If you prefer to run setup separately without immediately launching the sample:

**Linux / macOS** (bash, requires `openssl curl python3`):
```bash
chmod +x scripts/setup-buzz-oauth.sh
./scripts/setup-buzz-oauth.sh
```

For a system service (installs to `/etc/dotnet/...`, requires root):
```bash
sudo ./scripts/setup-buzz-oauth.sh -l LocalMachine
```

If the service runs as a dedicated user, run the script **as that user** so the
certificate lands in the right home directory:
```bash
sudo -u buzzservice ./scripts/setup-buzz-oauth.sh
```

**Windows** (PowerShell 5.1):
```powershell
.\scripts\Setup-BuzzOAuth.ps1
# For Windows services (run as Administrator):
.\scripts\Setup-BuzzOAuth.ps1 -StoreLocation LocalMachine
```

The setup script:
1. Prompts for your server URL and logs you in as an admin (supports MFA)
2. Prompts for cert store location, contact info, and application name
3. Creates an Application Identity account (or reuses an existing one)
4. Generates an RSA key pair and stores the private key in the OS certificate store
   — no plaintext key files left on disk after setup
5. Registers the public key with Buzz
6. Writes `buzz-config.json` so `dotnet run` works immediately

---

## OAuth Setup (one time per application)

These steps are performed once.  After setup, your application only needs the private key file,
the user ID, and the key ID.

### Step 1 — Create an Application Identity account

An Application Identity account is a special user type that authenticates exclusively via OAuth.
Create it using the `CreateUsers2` API with `type=applicationidentity`.  Use an admin account
that has the Create User right in the target domain.

```json
POST {server}/cmd/createusers2
{
  "requests": {
    "user": [
      {
        "domainid": "//yourschool",
        "type": "applicationidentity",
        "username": "sis-sync",
        "firstname": "SIS",
        "lastname": "Sync",
        "email": "sis-sync@example.com"
      }
    ]
  }
}
```

Record the `userid` from the response — this is your **OAuth User ID** (`oauthUserId`),
used as the `client_id` for all subsequent OAuth operations.

Grant the account only the rights it needs.  Use a separate Application Identity account for
each independent process or service; revoking one account's credentials does not affect others.

### Step 2 — Generate an RSA key pair

Run the included script to generate a 2048-bit RSA key pair:

```powershell
.\scripts\New-BuzzOAuthKey.ps1
```

Or specify an output directory and key size:

```powershell
.\scripts\New-BuzzOAuthKey.ps1 -OutputDir C:\secrets\myapp -KeySize 4096
```

This creates two files:
- `private_key.pem` — **keep secret**.  Never commit to source control.
- `public_key.pem` — uploaded to Buzz in the next step.

Also choose a **Key ID** (`kid`) — a short string that identifies this key, e.g. `2025-q2` or
`v1`.  Allowed characters: ASCII letters, digits, `-`, `_`, `.`.  Maximum 128 characters.

**Requires** PowerShell 7+ or OpenSSL on PATH (included with Git for Windows).
See the script's `-?` help for installation links.

If you prefer to generate the key manually with OpenSSL:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key.pem
openssl pkey -in private_key.pem -pubout -out public_key.pem
```

> **SECURITY** — Add `private_key.pem` to `.gitignore` immediately.  Store the private key
> in a secrets manager (Azure Key Vault, AWS Secrets Manager, GCP Secret Manager) or
> encrypted storage.  Never store it in plaintext config files, environment variables that
> appear in logs, or source control.

### Step 3 — Register the public key with Buzz

Upload the public key using the included script.  You need a Bearer token for an admin account
with the Update User right on the Application Identity account (see the script's `-AdminToken`
parameter help for how to obtain one).

```powershell
.\scripts\Register-BuzzOAuthKey.ps1 `
    -ServerUrl   https://api.agilixbuzz.com `
    -AdminToken  "<bearer-token-of-an-admin-account>" `
    -UserId      12345678 `
    -Kid         "2025-q2" `
    -PublicKeyPath .\public_key.pem
```

A `204 No Content` response means the key is stored.  The Application Identity account can now
authenticate.

You can also register a key with `curl`:

```bash
curl -X PUT \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -H "Content-Type: application/x-pem-file" \
     --data-binary @public_key.pem \
     "https://api.agilixbuzz.com/api/users/12345678/keys/2025-q2"
```

### Step 4 — Create buzz-config.json and run the sample

Create `buzz-config.json` in the project root with the values from the previous steps:

```json
{
  "serverUrl":             "https://api.agilixbuzz.com",
  "contactInformation":    "+https://example.com/; admin@example.com",
  "applicationInformation":"MySisSync",
  "oauthUserId":           "12345678",
  "oauthKid":              "2025-q2",
  "privateKeyPath":        "C:\\secrets\\myapp\\private_key.pem"
}
```

Or, to use the OS certificate store instead of a PEM file (recommended):

```json
{
  "serverUrl":             "https://api.agilixbuzz.com",
  "contactInformation":    "+https://example.com/; admin@example.com",
  "applicationInformation":"MySisSync",
  "oauthUserId":           "12345678",
  "oauthKid":              "2025-q2",
  "certThumbprint":        "ABCDEF1234...",
  "certStoreLocation":     "CurrentUser"
}
```

Then run:

```bash
dotnet run        # or: ./scripts/run-buzz-sample.sh
```

---

## Using BuzzApiClient in Your Own Code

### OAuth via OS certificate store (recommended — no key files)

After running `Setup-BuzzOAuth.ps1`, the private key lives in the OS certificate store.
Load it by thumbprint:

```csharp
// cert and rsa must share lifetime — dispose together
using X509Certificate2 cert = BuzzApiClient.LoadCertificateFromStore(
    thumbprint:    "ABCDEF1234...",
    storeLocation: StoreLocation.CurrentUser);  // or LocalMachine for Windows services
using RSA rsa = cert.GetRSAPrivateKey()!;

BuzzApiClient client = new(
    serverUrl:   "https://api.agilixbuzz.com",
    userAgent:   "MyApp/1.0 (CSharp; MyApp; admin@example.com)",
    oauthUserId: "12345678",
    oauthKid:    "2025-q2",
    privateKey:  rsa);

// BuzzApiClient obtains and refreshes Bearer tokens automatically.
JsonNode response = client.VerifyResponse(
    await client.JsonRequest(HttpMethod.Get, "getdomains"));
```

**Platform notes (Windows / Linux cert-store path):**
- **Windows** — key stored in Windows CNG (can be hardware-backed via TPM).  Use
  `-StoreLocation LocalMachine` in the setup script for services running as SYSTEM.
- **Linux** — key stored in `~/.dotnet/corefx/cryptography/x509stores/my/` as a PFX file.
  Restrict permissions: `chmod 700 ~/.dotnet/corefx/cryptography/x509stores/my`.
  For high-security Linux deployments consider a hardware token or secrets manager instead.
- **macOS** — `setup-buzz-oauth.sh` stores the private key as a PEM file at
  `~/.config/buzz-oauth/private_key.pem` and writes `privateKeyPath` to `buzz-config.json`
  (see "OAuth via PEM file" below).  The cert-store API above requires a manual Keychain import.

### OAuth via PEM file (simpler, use for development only)

```csharp
using RSA rsa = RSA.Create();
rsa.ImportFromPem(File.ReadAllText("private_key.pem"));

BuzzApiClient client = new(
    serverUrl:   "https://api.agilixbuzz.com",
    userAgent:   "MyApp/1.0 (CSharp; MyApp; admin@example.com)",
    oauthUserId: "12345678",
    oauthKid:    "2025-q2",
    privateKey:  rsa);
```

### Legacy password login (not recommended for new integrations)

```csharp
BuzzApiClient client = new(
    serverUrl: "https://api.agilixbuzz.com",
    userAgent: "MyApp/1.0 (CSharp; MyApp; admin@example.com)",
    userspace: "myschool",
    username:  "admin",
    password:  "secret");

JsonNode response = client.VerifyResponse(
    await client.JsonRequest(HttpMethod.Get, "getdomains"));
```

---

## Key Management

### Finding installed certificates (Linux)

```bash
# List .pfx files in the CurrentUser dotnet cert store
ls -la ~/.dotnet/corefx/cryptography/x509stores/my/

# Inspect a certificate's details (thumbprint, CN, expiry)
openssl pkcs12 -in ~/.dotnet/corefx/cryptography/x509stores/my/THUMBPRINT.pfx \
    -passin pass: -nokeys 2>/dev/null \
    | openssl x509 -noout -subject -fingerprint -sha1 -dates
```

### Listing registered keys (Buzz API)

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     "https://api.agilixbuzz.com/api/users/12345678/keys"
```

### Rotating a key (zero downtime)

1. Generate a new key pair and choose a new `kid`:
   ```powershell
   .\scripts\New-BuzzOAuthKey.ps1 -OutputDir C:\secrets\myapp\new
   ```
2. Register the new public key (PUTting a new `kid` leaves the old key active):
   ```powershell
   .\scripts\Register-BuzzOAuthKey.ps1 ... -Kid "2025-q3" -PublicKeyPath .\new\public_key.pem
   ```
3. Update your application configuration to use the new private key and `kid`.
4. Once all running instances have switched over, delete the old key:
   ```bash
   curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
        "https://api.agilixbuzz.com/api/users/12345678/keys/2025-q2"
   ```

### Revoking a compromised key

If a private key is compromised:

1. Register a new key pair immediately (Step 2–3 above with a new `kid`).
2. Update your application to use the new key.
3. Delete the compromised public key from Buzz:
   ```bash
   curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" \
        "https://api.agilixbuzz.com/api/users/12345678/keys/compromised-kid"
   ```
4. Revoke all outstanding tokens for the account (invalidates any tokens the attacker holds):
   ```bash
   curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "token=$CURRENT_ACCESS_TOKEN" \
        "https://api.agilixbuzz.com/api/oauth/revoke"
   ```
   Or, as an administrator, use the `TerminateUserSessions` command with the account's `userid`.

---

## Buzz Server URL

The Buzz API documentation recommends using the background/batch server URL for long-running
integrations to avoid time limits that apply to interactive API calls.

See [API Time Limiting](https://api.agilixbuzz.com/docs/#!/Concept/ApiTimeLimiting) for guidance
on choosing the correct server URL for your use case.

---

## Troubleshooting OAuth

| Error | Cause | Fix |
|-------|-------|-----|
| `invalid_client: The client_assertion JWT has expired.` | The JWT was built more than 2 minutes ago or your clock is skewed. | Ensure your system clock is synchronised (NTP). `BuzzApiClient` builds a fresh JWT for every token request. |
| `invalid_client: No active key found for the specified 'kid'.` | The `kid` in code does not match a registered key. | Re-run `Register-BuzzOAuthKey.ps1` and verify the `kid` matches exactly. |
| `invalid_client: The client_assertion JWT signature or claims are invalid.` | Wrong private key, wrong `aud`, or `iss` ≠ `sub`. | Confirm `oauthUserId` matches the Application Identity account's `userid`, and that the private key corresponds to the registered public key. |
| `invalid_client: No application identity account found for the specified 'sub'.` | The `oauthUserId` is not an Application Identity account. | Recreate the account with `type=applicationidentity`. |
| HTTP 400 on `Register-BuzzOAuthKey.ps1` | Wrong PEM format or key too small. | Use `openssl pkey -pubout` to produce a SubjectPublicKeyInfo PEM (starts with `-----BEGIN PUBLIC KEY-----`). Minimum key size is 2048 bits. |
| HTTP 401/403 on `Register-BuzzOAuthKey.ps1` | Admin token lacks Update User rights on the account. | Use an admin token for an account with the Update User right in the relevant domain. |
