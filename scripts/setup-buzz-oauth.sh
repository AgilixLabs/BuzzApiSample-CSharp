#!/usr/bin/env bash
# setup-buzz-oauth.sh — Interactive guided setup for Buzz OAuth 2.0 authentication.
#
# Usage:
#   ./scripts/setup-buzz-oauth.sh [OPTIONS]
#
# Options:
#   -s URL        Buzz API server URL (prompted if omitted)
#   -o PATH       Output path for buzz-config.json (default: project root)
#   -l LOCATION   Certificate store location: CurrentUser (default) or LocalMachine
#                 (Linux only; ignored on macOS which uses the PEM file approach)
#                 LocalMachine installs under /etc/dotnet/... and requires root.
#   -b BITS       RSA key size in bits (default: 2048; 3072 or 4096 recommended for new keys)
#   -h            Show this help
#
# What this script does (Steps 1–8):
#   1. Prompts for the Buzz server URL.
#   2. Logs in as a Buzz administrator (supports MFA).  Credentials are verified
#      early so mistakes are caught before any other information is entered.
#   3. Linux: prompts for certificate store location (CurrentUser or LocalMachine).
#      macOS: shows the PEM file storage path (~/.config/buzz-oauth/private_key.pem).
#   4. Prompts for contact info and application name.
#   5. Creates (or reuses) an Application Identity account in Buzz — the OAuth
#      identity of your integration, with no password and no interactive login.
#   6. Generates an RSA key pair.
#      Linux: imports private key into the .NET certificate store as a PFX file.
#      macOS: stores private key as a PEM file at ~/.config/buzz-oauth/private_key.pem.
#   7. Registers the public key with Buzz.
#   8. Writes buzz-config.json so `dotnet run` works immediately.
#
# Requires:
#   openssl   — key generation and certificate operations
#   curl      — Buzz API calls
#   python3   — JSON building and parsing (standard on modern Linux/macOS)
#   jq        — optional; used for JSON if available (apt install jq / brew install jq)
#
# Platform:
#   Linux and macOS.  On Windows, use scripts/Setup-BuzzOAuth.ps1 instead.
#
# Key storage on Linux:
#   The private key is wrapped in a self-signed certificate and stored as a PKCS#12
#   (.pfx) file in the .NET file-based certificate store:
#     CurrentUser  — ~/.dotnet/corefx/cryptography/x509stores/my/
#     LocalMachine — /etc/dotnet/corefx/cryptography/x509stores/my/  (requires root)
#   The .NET runtime discovers certificates by scanning that directory.
#
# Key storage on macOS:
#   The private key is stored as a PEM file at ~/.config/buzz-oauth/private_key.pem
#   (chmod 600).  buzz-config.json uses the "privateKeyPath" field to point to it.
#   The .NET runtime loads the key directly via RSA.ImportFromPem().
#
# Service account deployments (Linux):
#   Run this script AS the service account user (or sudo -u serviceuser) so the
#   certificate lands in that user's home directory and the service can read it.
#   Alternatively, copy the .pfx manually:
#     sudo -u serviceuser cp /tmp/setup-output/*.pfx \
#       /home/serviceuser/.dotnet/corefx/cryptography/x509stores/my/
#
# Extra curl options (e.g. for proxies):
#   export CURL_OPTS="--proxy http://proxy.example.com:8080"

set -euo pipefail

# ── Platform check ────────────────────────────────────────────────────────────
case "$(uname -s)" in
    Linux|Darwin) ;;
    *)
        printf 'Error: this script is for Linux and macOS only.\n' >&2
        printf 'On Windows, use: .\\scripts\\Setup-BuzzOAuth.ps1\n' >&2
        exit 1
        ;;
esac

# ── Defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SERVER_URL=""
CONFIG_OUTPUT="${PROJECT_ROOT}/buzz-config.json"
STORE_LOCATION="CurrentUser"
KEY_BITS=2048
STORE_LOCATION_GIVEN=false
KEY_BITS_GIVEN=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while getopts ":s:o:l:b:h" opt; do
    case "$opt" in
        s) SERVER_URL="$OPTARG"     ;;
        o) CONFIG_OUTPUT="$OPTARG"  ;;
        l) STORE_LOCATION="$OPTARG"; STORE_LOCATION_GIVEN=true ;;
        b) KEY_BITS="$OPTARG"; KEY_BITS_GIVEN=true ;;
        h) sed -n '2,/^[^#]/{ /^[^#]/q; s/^# \{0,1\}//; p }' "$0"; exit 0 ;;
        :) printf 'Error: -%s requires an argument\n' "$OPTARG" >&2; exit 1 ;;
        ?) printf 'Error: unknown option -%s\n' "$OPTARG"        >&2; exit 1 ;;
    esac
done

case "$STORE_LOCATION" in
    CurrentUser|LocalMachine) ;;
    *) printf 'Error: -l must be CurrentUser or LocalMachine\n' >&2; exit 1 ;;
esac

# Root check for LocalMachine is deferred until after the interactive store
# location prompt below, so it catches both flag-supplied and user-entered values.

# ── Dependency check ──────────────────────────────────────────────────────────
MISSING_DEPS=0
for cmd in openssl curl python3; do
    if ! command -v "$cmd" &>/dev/null; then
        printf 'Error: %s is required but not found.\n' "$cmd" >&2
        MISSING_DEPS=1
    fi
done
if [ "$MISSING_DEPS" -ne 0 ]; then
    printf '\nInstall missing dependencies:\n'                  >&2
    printf '  Debian/Ubuntu : apt-get install openssl curl python3\n' >&2
    printf '  RHEL/CentOS   : yum install openssl curl python3\n'     >&2
    printf '  Alpine        : apk add openssl curl python3\n'         >&2
    exit 1
fi

USE_JQ=0
command -v jq &>/dev/null && USE_JQ=1

# ── Helpers ───────────────────────────────────────────────────────────────────
die() { printf '\nError: %s\n' "$*" >&2; exit 1; }

# ── Temporary workspace (cleaned up on exit) ──────────────────────────────────
TMPDIR_SETUP="$(mktemp -d 2>/dev/null || mktemp -d -t buzz-oauth)"
[ -d "$TMPDIR_SETUP" ] || die "Failed to create temporary directory."
chmod 700 "$TMPDIR_SETUP"
trap 'rm -rf "$TMPDIR_SETUP"' EXIT

# Print a coloured section header
section() { printf '\n\033[1;33m─── %s \033[0m\n' "$*"; }
ok()      { printf '\033[1;32m%s\033[0m\n' "$*"; }
info()    { printf '  %s\n' "$*"; }

# Read a non-empty value from the user
prompt_required() {
    local label="$1" var_name="$2" default="${3:-}"
    local value=""
    while [ -z "$value" ]; do
        if [ -n "$default" ]; then
            printf '%s [%s]: ' "$label" "$default"
        else
            printf '%s: ' "$label"
        fi
        read -r value
        [ -z "$value" ] && value="$default"
        [ -z "$value" ] && printf '  (required)\n'
    done
    printf -v "$var_name" '%s' "$value"
}

# Read an optional value (may be empty)
prompt_optional() {
    local label="$1" var_name="$2"
    printf '%s (optional, press Enter to skip): ' "$label"
    local value=""
    read -r value
    printf -v "$var_name" '%s' "$value"
}

# Read a password with * masking, one character at a time.
# Handles backspace/delete to erase the last character.
prompt_password() {
    local label="$1" var_name="$2"
    local value="" char
    printf '%s: ' "$label"
    while IFS= read -r -s -n1 char; do
        if [ -z "$char" ]; then
            break  # Enter
        elif [ "$char" = $'\x7f' ] || [ "$char" = $'\x08' ]; then
            if [ -n "$value" ]; then
                value="${value%?}"
                printf '\b \b'
            fi
        else
            value="${value}${char}"
            printf '*'
        fi
    done
    printf '\n'
    printf -v "$var_name" '%s' "$value"
}

# ── JSON helpers ──────────────────────────────────────────────────────────────

# Extract a dot-separated path from a JSON string.
# json_get '{"a":{"b":"val"}}' 'a.b'  →  val
json_get() {
    local json="$1" path="$2"
    if [ "$USE_JQ" -eq 1 ]; then
        printf '%s' "$json" | jq -r ".$path // empty" 2>/dev/null || true
    else
        python3 - "$json" "$path" <<'PYEOF'
import sys, json
try:
    data = json.loads(sys.argv[1])
    val = data
    for key in sys.argv[2].split('.'):
        val = val.get(key) if isinstance(val, dict) else None
    if val is not None and not isinstance(val, (dict, list)):
        sys.stdout.write(str(val))
except Exception:
    pass
PYEOF
    fi
}

# Safely build a JSON body from key=value pairs using python3.
# json_build key1 val1 key2 val2 ...
# Nested keys use dot notation: json_build request.cmd login3 request.username admin
json_build() {
    printf '%s\0' "$@" | python3 - <<'PYEOF'
import sys, json

def set_nested(d, keys, value):
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value

items = sys.stdin.buffer.read().split(b'\x00')
if items and items[-1] == b'':
    items = items[:-1]
result = {}
for i in range(0, len(items) - 1, 2):
    set_nested(result, items[i].decode('utf-8').split('.'), items[i+1].decode('utf-8'))
print(json.dumps(result))
PYEOF
}

# Parse a scalar field from a Buzz API response — handles both JSON and XML.
# Usage: buzz_get_field <response_text> <field>
# Supported fields: code  token  partial_token  message  userid
buzz_get_field() {
    local resp="$1" field="$2"
    printf '%s' "$resp" | python3 - "$field" <<'PYEOF'
import sys
field = sys.argv[1]
resp = sys.stdin.read()
result = ''
try:
    import json
    d = json.loads(resp)
    if field == 'code':
        for path in (['response','code'], ['code'], ['responses','code']):
            v = d
            for k in path:
                v = v.get(k) if isinstance(v, dict) else None
            if isinstance(v, str) and v:
                result = v; break
    elif field == 'token':
        result = (((d.get('response') or {}).get('user') or {}).get('token') or
                  (d.get('user') or {}).get('token', ''))
    elif field == 'partial_token':
        result = ((d.get('response') or {}).get('token') or d.get('token', ''))
    elif field == 'message':
        result = ((d.get('response') or {}).get('message') or d.get('message', ''))
    elif field == 'userid':
        r = d.get('response', d)
        inner = r.get('responses', {}).get('response', {})
        if isinstance(inner, list): inner = inner[0]
        result = str(inner.get('user', {}).get('userid', '') or '')
except Exception:
    pass
if not result:
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(resp)
        r = root if root.tag == 'response' else root.find('.//response')
        if r is not None:
            if field == 'code':
                result = r.get('code', '')
            elif field == 'token':
                u = r.find('user')
                result = u.get('token', '') if u is not None else ''
            elif field == 'partial_token':
                result = r.get('token', '')
                if not result:
                    u = r.find('user')
                    result = u.get('token', '') if u is not None else ''
            elif field == 'message':
                result = r.get('message', '')
            elif field == 'userid':
                u = r.find('.//user')
                result = u.get('userid', '') if u is not None else ''
    except Exception:
        pass
if result:
    sys.stdout.write(result)
PYEOF
}

# ── Buzz API helpers ──────────────────────────────────────────────────────────

# POST a JSON body to a Buzz command endpoint.
# buzz_post <command> <json_body> [bearer_token]
# Returns the full response body.
buzz_post() {
    local cmd="$1" body="$2" token="${3:-}"
    local -a headers=("-H" "Content-Type: application/json")
    [ -n "$token" ] && headers+=("-H" "Authorization: Bearer $token")
    printf '%s' "$body" | curl -sL ${CURL_OPTS:-} -X POST "${SERVER_URL}/cmd/${cmd}" \
        "${headers[@]}" --data-binary @-
}

# PUT raw content to a Buzz REST endpoint.
buzz_put() {
    local url="$1" content_type="$2" body="$3" token="$4"
    local result http_code curl_exit
    curl_exit=0
    result=$(curl -s ${CURL_OPTS:-} -w '\n%{http_code}' \
        -X PUT "$url" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: $content_type" \
        --data-binary "$body") || curl_exit=$?
    if [ "$curl_exit" -ne 0 ]; then
        printf '\n' >&2
        die "Network error reaching $url (curl exit $curl_exit). Check the server URL and connectivity."
    fi
    http_code=$(printf '%s' "$result" | tail -n1)
    printf '%s' "$http_code"
}

# GET a Buzz command endpoint.
buzz_get() {
    local cmd="$1" params="${2:-}" token="${3:-}"
    local url="${SERVER_URL}/cmd/${cmd}"
    [ -n "$params" ] && url="${url}?${params}"
    local -a headers=()
    [ -n "$token" ] && headers+=("-H" "Authorization: Bearer $token")
    curl -sL ${CURL_OPTS:-} "${headers[@]}" "$url"
}

# ── Banner ────────────────────────────────────────────────────────────────────
printf '\n'
printf '\033[1;36m══════════════════════════════════════════════════════════\033[0m\n'
printf '\033[1;36m  Buzz OAuth 2.0 Application Setup\033[0m\n'
printf '\033[1;36m══════════════════════════════════════════════════════════\033[0m\n'
printf '\n'
printf 'This script performs a one-time setup so your application can\n'
printf 'authenticate to the Buzz API without a username or password.\n'
printf '\n'

# ── Step 1: Server URL ────────────────────────────────────────────────────────
section "Step 1: Buzz Server URL"
if [ -z "$SERVER_URL" ]; then
    prompt_required "Buzz API server URL (e.g. https://api.agilixbuzz.com)" SERVER_URL
fi
SERVER_URL="${SERVER_URL%/}"  # strip trailing slash
ok "  Server: $SERVER_URL"

# ── Step 2: Admin login ───────────────────────────────────────────────────────
section "Step 2: Admin Login"
printf 'Log in as a Buzz administrator to perform the one-time setup.\n'
printf 'This session is used only during setup and is not stored anywhere.\n\n'

ADMIN_TOKEN=""
while [ -z "$ADMIN_TOKEN" ]; do
    while true; do
        printf 'Admin username (userspace/username, e.g. myschool/admin): '
        read -r ADMIN_LOGIN
        if printf '%s' "$ADMIN_LOGIN" | grep -qE '^[^/]+/[^/]+$'; then
            break
        fi
        printf '  Username must be in userspace/username format.\n'
    done
    prompt_password "Admin password" ADMIN_PASSWORD

    printf 'Logging in...'

    LOGIN_BODY=$(json_build \
        "request.cmd"      "login3" \
        "request.username" "$ADMIN_LOGIN" \
        "request.password" "$ADMIN_PASSWORD")
    ADMIN_PASSWORD=""

    LOGIN_RESPONSE=$(buzz_post "login3" "$LOGIN_BODY" 2>/dev/null || true)
    LOGIN_BODY=""

    if [ -z "$LOGIN_RESPONSE" ]; then
        printf '\n  Network error: could not reach server.\n'
        printf '  Please check the server URL and try again.  Press Ctrl+C to abort.\n\n'
        continue
    fi

    # Extract the response code — handles both JSON and XML Buzz API responses.
    LOGIN_CODE=$(buzz_get_field "$LOGIN_RESPONSE" code)

    # ── MFA handling ──────────────────────────────────────────────────────────
    # If the server returns a code indicating MFA is required, prompt for the code
    # and call verifylogin to complete authentication.
    # NOTE: The exact command name and field names depend on your server configuration.
    #       Adjust MFA_CMD below if your server uses a different command.
    if printf '%s' "$LOGIN_CODE" | grep -qiE '(factor|mfa|otp|challenge|verify|multifactor)'; then
        printf ' MFA required.\n'
        prompt_required "MFA / one-time code" MFA_CODE

        PARTIAL_TOKEN=$(buzz_get_field "$LOGIN_RESPONSE" partial_token)

        MFA_CMD="verifylogin"   # ← adjust if your server uses a different command name
        MFA_BODY=$(json_build \
            "request.cmd"   "$MFA_CMD" \
            "request.token" "$PARTIAL_TOKEN" \
            "request.code"  "$MFA_CODE")
        PARTIAL_TOKEN=""

        LOGIN_RESPONSE=$(buzz_post "$MFA_CMD" "$MFA_BODY" 2>/dev/null || true)
        MFA_BODY=""

        if [ -z "$LOGIN_RESPONSE" ]; then
            printf '  MFA request failed: network error.  Press Ctrl+C to abort.\n\n'
            continue
        fi

        LOGIN_CODE=$(buzz_get_field "$LOGIN_RESPONSE" code)
    fi

    if [ "$LOGIN_CODE" != "OK" ]; then
        LOGIN_MSG=$(buzz_get_field "$LOGIN_RESPONSE" message)
        printf '\n  Login failed (code: %s)%s\n' "$LOGIN_CODE" "${LOGIN_MSG:+: $LOGIN_MSG}"
        # If the code is empty the response format was not recognised — show it raw for diagnosis.
        if [ -z "$LOGIN_CODE" ]; then
            printf '  Server response: %.400s\n' "$LOGIN_RESPONSE"
        fi
        printf '  Please check your credentials and try again.  Press Ctrl+C to abort.\n\n'
        continue
    fi

    CANDIDATE_TOKEN=$(buzz_get_field "$LOGIN_RESPONSE" token)

    if [ -z "$CANDIDATE_TOKEN" ]; then
        printf '\n  Login succeeded but no token was returned.  Press Ctrl+C to abort.\n\n'
        continue
    fi

    ADMIN_TOKEN="$CANDIDATE_TOKEN"
done
ok " OK"

# ── Step 3: Key storage location ─────────────────────────────────────────────
section "Step 3: Key Storage"
if [ "$(uname -s)" = "Darwin" ]; then
    # macOS: .NET uses the Keychain for X509Store, but importing keys there requires
    # interactive Security framework prompts.  Use the PEM file approach instead.
    printf 'macOS detected.  The private key will be stored as a PEM file:\n'
    printf '  %s/.config/buzz-oauth/private_key.pem\n' "$HOME"
    printf '(chmod 600; buzz-config.json will reference it via "privateKeyPath")\n'
else
    printf 'The private key is wrapped in a self-signed certificate and stored in\n'
    printf 'the .NET file-based certificate store (a directory of .pfx files).\n\n'
    printf '  CurrentUser  — for interactive users and per-user services (default)\n'
    printf '  LocalMachine — for services running as root (requires sudo)\n\n'
    if ! $STORE_LOCATION_GIVEN; then
        while true; do
            printf 'Store location [CurrentUser/LocalMachine] (default: CurrentUser): '
            read -r store_input
            if [ -z "$store_input" ]; then
                STORE_LOCATION="CurrentUser"; break
            fi
            case "$store_input" in
                CurrentUser|LocalMachine) STORE_LOCATION="$store_input"; break ;;
                *) printf "  Please enter 'CurrentUser' or 'LocalMachine'.\n" ;;
            esac
        done
    fi
    if [ "$STORE_LOCATION" = "LocalMachine" ] && [ "$(id -u)" -ne 0 ]; then
        printf 'Error: LocalMachine store requires root.  Run with sudo.\n' >&2
        exit 1
    fi
fi
if [ "$(uname -s)" = "Darwin" ]; then
    ok "  Key path: ${HOME}/.config/buzz-oauth/private_key.pem"
else
    ok "  Store: $STORE_LOCATION"
fi

# ── Step 4: Application info ──────────────────────────────────────────────────
section "Step 4: Application Information"
printf 'This is included in the User-Agent header so Agilix support\n'
printf 'can identify your integration if you need help.\n\n'
prompt_required "Your contact info (name, email, or URL)" CONTACT_INFO
prompt_required "Application name (e.g. SisSync, RosterImport)" APP_NAME

# ── Step 5: Application Identity account ─────────────────────────────────────
section "Step 5: Application Identity Account"
printf 'This Buzz user account represents your application.\n'
printf 'It authenticates via OAuth only — it has no password.\n\n'

printf 'Create a new Application Identity account? [Y/n]: '
read -r CREATE_NEW
[ -z "$CREATE_NEW" ] && CREATE_NEW="Y"

OAUTH_USER_ID=""

if printf '%s' "$CREATE_NEW" | grep -qiE '^y'; then

    # List available domains to help the user choose
    printf 'Fetching available domains...'
    DOMAINS_RESPONSE=$(buzz_get "getdomains" "" "$ADMIN_TOKEN" 2>/dev/null || true)
    DOMAIN_CODE=$(buzz_get_field "$DOMAINS_RESPONSE" code)

    if [ "$DOMAIN_CODE" = "OK" ]; then
        printf ' done\n\n'

        # Build a numbered list of domains for the user to choose from
        DOMAIN_IDS=()
        DOMAIN_NAMES=()
        while IFS= read -r line; do
            DOMAIN_IDS+=("$line")
        done < <(printf '%s' "$DOMAINS_RESPONSE" | python3 - domainid <<'PYEOF'
import sys
field = sys.argv[1]
resp = sys.stdin.read()
results = []
try:
    import json
    items = json.loads(resp).get('response', {}).get('domains', {}).get('domain', [])
    if isinstance(items, dict): items = [items]
    results = [str(d.get(field, '')) for d in (items or [])]
except Exception:
    pass
if not results:
    try:
        import xml.etree.ElementTree as ET
        results = [d.get(field, '') for d in ET.fromstring(resp).findall('.//domain')]
    except Exception:
        pass
for r in results:
    if r: print(r)
PYEOF
) || true
        while IFS= read -r line; do
            DOMAIN_NAMES+=("$line")
        done < <(printf '%s' "$DOMAINS_RESPONSE" | python3 - name <<'PYEOF'
import sys
field = sys.argv[1]
resp = sys.stdin.read()
results = []
try:
    import json
    items = json.loads(resp).get('response', {}).get('domains', {}).get('domain', [])
    if isinstance(items, dict): items = [items]
    results = [str(d.get(field, '')) for d in (items or [])]
except Exception:
    pass
if not results:
    try:
        import xml.etree.ElementTree as ET
        results = [d.get(field, '') for d in ET.fromstring(resp).findall('.//domain')]
    except Exception:
        pass
for r in results:
    if r: print(r)
PYEOF
) || true

        if [ "${#DOMAIN_IDS[@]}" -gt 0 ]; then
            printf 'Available domains:\n'
            for i in "${!DOMAIN_IDS[@]}"; do
                printf '  %2d. %-30s (id: %s)\n' "$((i+1))" "${DOMAIN_NAMES[$i]}" "${DOMAIN_IDS[$i]}"
            done
            printf '\n'
            printf 'Enter domain number or type the domainid directly: '
            read -r domain_choice
            if printf '%s' "$domain_choice" | grep -qE '^[0-9]+$' \
               && [ "$domain_choice" -ge 1 ] \
               && [ "$domain_choice" -le "${#DOMAIN_IDS[@]}" ] 2>/dev/null; then
                TARGET_DOMAIN="${DOMAIN_IDS[$((domain_choice-1))]}"
            else
                TARGET_DOMAIN="$domain_choice"
            fi
        else
            prompt_required "Domain ID for the new account (e.g. //myschool)" TARGET_DOMAIN
        fi
    else
        printf ' (could not fetch domains)\n\n'
        prompt_required "Domain ID for the new account (e.g. //myschool)" TARGET_DOMAIN
    fi

    prompt_required "Username for the account (e.g. sis-sync)"        APP_USERNAME
    prompt_required "First name (e.g. SIS)"                           APP_FIRSTNAME
    prompt_required "Last name (e.g. Sync)"                           APP_LASTNAME
    prompt_optional "Email address"                                    APP_EMAIL

    printf '\nCreating Application Identity account '\''%s'\''...' "$APP_USERNAME"

    # Build the request body; email is optional
    CREATE_BODY=$(python3 - "$TARGET_DOMAIN" "$APP_USERNAME" "$APP_FIRSTNAME" "$APP_LASTNAME" "$APP_EMAIL" <<'PYEOF'
import sys, json
domain, username, firstname, lastname, email = sys.argv[1:6]
user = {
    "domainid":  domain,
    "type":      "applicationidentity",
    "username":  username,
    "firstname": firstname,
    "lastname":  lastname,
}
if email:
    user["email"] = email
body = {"requests": {"user": [user]}}
print(json.dumps(body))
PYEOF
)

    CREATE_RESPONSE=$(buzz_post "createusers2" "$CREATE_BODY" "$ADMIN_TOKEN")
    CREATE_CODE=$(buzz_get_field "$CREATE_RESPONSE" code)

    if [ "$CREATE_CODE" != "OK" ]; then
        printf '\n'
        die "CreateUsers2 failed (code: $CREATE_CODE).  Response: $CREATE_RESPONSE"
    fi

    OAUTH_USER_ID=$(buzz_get_field "$CREATE_RESPONSE" userid)
    [ -n "$OAUTH_USER_ID" ] || die "CreateUsers2 succeeded but returned no userid.  Response: $CREATE_RESPONSE"
    ok " OK (userid: $OAUTH_USER_ID)"

else
    prompt_required "Existing Application Identity account userid" OAUTH_USER_ID
    ok "  Using existing account: $OAUTH_USER_ID"
fi

# ── Step 6: RSA key pair + key installation ───────────────────────────────────
section "Step 6: RSA Key Generation and Key Installation"

# Interactive key size prompt when not provided via -b flag
if ! $KEY_BITS_GIVEN; then
    while true; do
        printf 'RSA key size in bits [2048/3072/4096] (default: 2048): '
        read -r size_input
        if [ -z "$size_input" ]; then
            KEY_BITS=2048; break
        fi
        if printf '%s' "$size_input" | grep -qE '^[0-9]+$' \
           && [ "$size_input" -ge 2048 ] && [ "$size_input" -le 16384 ] 2>/dev/null; then
            KEY_BITS="$size_input"; break
        fi
        printf '  Key size must be between 2048 and 16384 bits.\n'
    done
fi

# Suggest a kid based on current quarter
CURRENT_YEAR=$(date -u '+%Y')
CURRENT_MONTH=$(date -u '+%m')
CURRENT_QUARTER=$(( (10#$CURRENT_MONTH + 2) / 3 ))
DEFAULT_KID="${CURRENT_YEAR}-q${CURRENT_QUARTER}"

printf 'Key ID (kid) for this key [%s]: ' "$DEFAULT_KID"
read -r KID
[ -z "$KID" ] && KID="$DEFAULT_KID"

if ! printf '%s' "$KID" | grep -qE '^[A-Za-z0-9._-]{1,128}$'; then
    die "Invalid kid '$KID'.  Allowed: ASCII letters, digits, -, _, .  Max 128 chars."
fi

info "Kid : $KID"
printf '\n'

# All key material lives in the secure temp directory until we're done
PRIV_KEY="${TMPDIR_SETUP}/private_key.pem"
CERT_PEM="${TMPDIR_SETUP}/cert.pem"
PUB_KEY="${TMPDIR_SETUP}/public_key.pem"
PFX_FILE="${TMPDIR_SETUP}/cert.pfx"
THUMBPRINT=""
PEM_PATH=""
STORE_DIR=""

# Validate KEY_BITS when supplied via -b flag (interactive prompt already validates).
if $KEY_BITS_GIVEN; then
    case "$KEY_BITS" in
        ''|*[!0-9]*) die "Invalid key size '$KEY_BITS'. Must be a numeric value between 2048 and 16384." ;;
    esac
    if [ "$KEY_BITS" -lt 2048 ] || [ "$KEY_BITS" -gt 16384 ]; then
        die "Invalid key size '$KEY_BITS'. Must be between 2048 and 16384 bits."
    fi
fi

# 1. Generate RSA private key (common to all platforms)
openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${KEY_BITS}" \
    -out "$PRIV_KEY"
[ -s "$PRIV_KEY" ] || die "Failed to generate RSA private key."
chmod 600 "$PRIV_KEY"

# 3. Extract public key in SubjectPublicKeyInfo (SPKI) PEM format — what Buzz expects
openssl pkey -in "$PRIV_KEY" -pubout -out "$PUB_KEY"
[ -s "$PUB_KEY" ] || die "Failed to extract RSA public key."

if [ "$(uname -s)" = "Darwin" ]; then
    # macOS: .NET uses the Keychain for X509Store, which requires interactive Security
    # framework prompts not suitable for scripted setup.  Store the private key as a
    # PEM file at a well-known path; buzz-config.json will reference it via "privateKeyPath".
    printf 'Generating %d-bit RSA key pair...' "$KEY_BITS"

    MACOS_KEY_DIR="${HOME}/.config/buzz-oauth"
    mkdir -p "$MACOS_KEY_DIR"
    chmod 700 "$MACOS_KEY_DIR"
    PEM_PATH="${MACOS_KEY_DIR}/private_key.pem"
    cp "$PRIV_KEY" "$PEM_PATH"
    chmod 600 "$PEM_PATH"

    ok " done"
    info "Private key : $PEM_PATH"
else
    # Linux: wrap the key in a self-signed certificate and install as a PFX in the
    # .NET file-based certificate store.  The store is a directory of .pfx files;
    # .NET discovers them by thumbprint filename.
    CERT_CN="BuzzOAuth-$(printf '%s' "${APP_NAME}-${KID}" | tr -cd 'A-Za-z0-9._-' | tr ' ' '-')"
    info "Cert CN     : $CERT_CN"
    info "Store       : $STORE_LOCATION/My"
    printf '\n'
    printf 'Generating %d-bit RSA key pair and creating self-signed certificate...' "$KEY_BITS"

    # 2. Self-signed certificate wrapping the key (100-year validity; kid can be rotated earlier)
    openssl req -new -x509 \
        -key "$PRIV_KEY" \
        -out "$CERT_PEM" \
        -days 36500 \
        -subj "/CN=${CERT_CN}"
    [ -s "$CERT_PEM" ] || die "Failed to create self-signed certificate."

    # 4. Compute the SHA-1 thumbprint (uppercase hex, no colons) — used as the filename in the store
    THUMBPRINT=$(openssl x509 -in "$CERT_PEM" -fingerprint -sha1 -noout \
        | sed 's/.*Fingerprint=//' \
        | tr -d ':' \
        | tr '[:lower:]' '[:upper:]')

    [ -n "$THUMBPRINT" ] || die "Failed to compute certificate thumbprint."

    # 5. Export as PKCS#12 (.pfx) with empty password
    #    On OpenSSL 3.x the -legacy flag avoids algorithm warnings; .NET reads both formats.
    OPENSSL_MAJOR=$(openssl version 2>/dev/null | grep -oE '^OpenSSL [0-9]+' | grep -oE '[0-9]+$' || true)
    PKCS12_LEGACY_FLAG=""
    [ "${OPENSSL_MAJOR:-1}" -ge 3 ] 2>/dev/null && PKCS12_LEGACY_FLAG="-legacy"

    openssl pkcs12 -export \
        -in      "$CERT_PEM" \
        -inkey   "$PRIV_KEY" \
        -out     "$PFX_FILE" \
        -passout pass: \
        $PKCS12_LEGACY_FLAG
    [ -s "$PFX_FILE" ] || die "Failed to export PKCS#12 file."

    # 6. Install into the .NET certificate store
    case "$STORE_LOCATION" in
        CurrentUser)  STORE_DIR="${HOME}/.dotnet/corefx/cryptography/x509stores/my" ;;
        LocalMachine) STORE_DIR="/etc/dotnet/corefx/cryptography/x509stores/my"     ;;
    esac

    mkdir -p "$STORE_DIR"
    chmod 700 "$STORE_DIR"
    cp "$PFX_FILE" "${STORE_DIR}/${THUMBPRINT}.pfx"
    chmod 600 "${STORE_DIR}/${THUMBPRINT}.pfx"

    ok " done"
    info "Thumbprint: $THUMBPRINT"
    info "Stored at : ${STORE_DIR}/${THUMBPRINT}.pfx"
fi

# ── Step 7: Register the public key with Buzz ─────────────────────────────────
section "Step 7: Registering Public Key with Buzz"

KEY_URL="${SERVER_URL}/api/users/${OAUTH_USER_ID}/keys/${KID}"
info "PUT $KEY_URL"
printf '  Uploading...'

HTTP_CODE=$(buzz_put "$KEY_URL" "application/x-pem-file" "@${PUB_KEY}" "$ADMIN_TOKEN")

case "$HTTP_CODE" in
    204)
        ok " 204 OK"
        ;;
    400)
        printf '\n'
        die "HTTP 400: public key rejected.  Verify account $OAUTH_USER_ID was created with type=applicationidentity."
        ;;
    401|403)
        printf '\n'
        die "HTTP ${HTTP_CODE}: admin account lacks Update User rights on account ${OAUTH_USER_ID}."
        ;;
    *)
        printf '\n'
        die "Key registration returned unexpected HTTP ${HTTP_CODE}."
        ;;
esac

# ── Step 8: Write buzz-config.json ────────────────────────────────────────────
section "Step 8: Writing Configuration"

mkdir -p "$(dirname "$CONFIG_OUTPUT")"

if [ "$(uname -s)" = "Darwin" ]; then
    python3 - "$SERVER_URL" "$CONTACT_INFO" "$APP_NAME" "$OAUTH_USER_ID" \
              "$KID" "$PEM_PATH" "$CONFIG_OUTPUT" <<'PYEOF'
import sys, json
server_url, contact, app, user_id, kid, pem_path, out_path = sys.argv[1:8]
config = {
    "serverUrl":              server_url,
    "contactInformation":     contact,
    "applicationInformation": app,
    "oauthUserId":            user_id,
    "oauthKid":               kid,
    "privateKeyPath":         pem_path,
}
with open(out_path, 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')
PYEOF
else
    python3 - "$SERVER_URL" "$CONTACT_INFO" "$APP_NAME" "$OAUTH_USER_ID" \
              "$KID" "$THUMBPRINT" "$STORE_LOCATION" "$CONFIG_OUTPUT" <<'PYEOF'
import sys, json
server_url, contact, app, user_id, kid, thumb, store_loc, out_path = sys.argv[1:9]
config = {
    "serverUrl":              server_url,
    "contactInformation":     contact,
    "applicationInformation": app,
    "oauthUserId":            user_id,
    "oauthKid":               kid,
    "certThumbprint":         thumb,
    "certStoreLocation":      store_loc,
}
with open(out_path, 'w') as f:
    json.dump(config, f, indent=2)
    f.write('\n')
PYEOF
fi

ok "  Written: $CONFIG_OUTPUT"

# ── Done ──────────────────────────────────────────────────────────────────────
printf '\n'
printf '\033[1;32m══════════════════════════════════════════════════════════\033[0m\n'
printf '\033[1;32m  Setup complete!\033[0m\n'
printf '\033[1;32m══════════════════════════════════════════════════════════\033[0m\n'
printf '\n'
printf 'OAuth User ID  : %s\n' "$OAUTH_USER_ID"
printf 'Key ID (kid)   : %s\n' "$KID"
if [ "$(uname -s)" = "Darwin" ]; then
    printf 'Private key    : %s\n' "$PEM_PATH"
else
    printf 'Cert Thumbprint: %s\n' "$THUMBPRINT"
    printf 'Cert store     : %s\n' "$STORE_DIR"
fi
printf 'Config file    : %s\n' "$CONFIG_OUTPUT"
printf '\n'
printf '\033[1;36mTo test the configuration:\033[0m\n'
printf '  cd %s\n' "$PROJECT_ROOT"
printf '  dotnet run\n'
printf '\n'
printf '\033[1;33mSecurity notes:\033[0m\n'
if [ "$(uname -s)" = "Darwin" ]; then
    printf '  - The private key is stored at %s (chmod 600).\n' "$PEM_PATH"
    printf '  - Never commit this file to source control.\n'
else
    printf '  - The private key is in the %s certificate store, not a file.\n' "$STORE_LOCATION"
    printf '  - If this service runs as a different user, copy the cert:\n'
    printf '      sudo -u <serviceuser> mkdir -p /home/<serviceuser>/.dotnet/corefx/cryptography/x509stores/my\n'
    printf '      sudo cp "%s/%s.pfx" /home/<serviceuser>/.dotnet/corefx/cryptography/x509stores/my/\n' \
        "$STORE_DIR" "$THUMBPRINT"
    printf '      sudo chown <serviceuser>: /home/<serviceuser>/.dotnet/corefx/cryptography/x509stores/my/%s.pfx\n' \
        "$THUMBPRINT"
fi
printf '  - buzz-config.json contains no secrets and is gitignored.\n'
printf '  - To rotate the key: re-run this script with a new kid.\n'
printf '  - To revoke all tokens: POST %s/api/oauth/revoke\n' "$SERVER_URL"
printf '\n'
