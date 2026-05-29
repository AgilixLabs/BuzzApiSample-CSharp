#!/usr/bin/env bash
# cleanup-buzz-sample.sh — Remove all artifacts created by setup-buzz-oauth.sh.
#
# This script:
#   1. Reads buzz-config.json to find the OAuth account details
#   2. Logs in as a Buzz admin (supports MFA)
#   3. Deletes the registered OAuth public key from Buzz
#   4. Deletes the Application Identity account from Buzz
#   5. Removes the certificate/private key from the local certificate store
#   6. Deletes buzz-config.json
#
# After running, the environment is back to a completely clean state.
#
# Usage:
#   ./scripts/cleanup-buzz-sample.sh
#
# Requires: curl, python3 (jq recommended but optional)

set -euo pipefail

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

# Convert CURL_OPTS string to an array for safe quoted expansion.
CURL_OPTS_ARR=()
[ -n "${CURL_OPTS:-}" ] && read -ra CURL_OPTS_ARR <<< "$CURL_OPTS"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/buzz-config.json"

# ── Platform check ────────────────────────────────────────────────────────────
case "$(uname -s)" in
    Linux|Darwin) ;;
    *)
        printf 'This script is for Linux and macOS only.\n' >&2
        printf 'On Windows, run: .\\scripts\\Cleanup-BuzzSample.ps1\n' >&2
        exit 1
        ;;
esac

# ── Dependency checks ─────────────────────────────────────────────────────────
for cmd in curl python3; do
    command -v "$cmd" &>/dev/null || {
        printf 'Error: %s is required but not found.\n' "$cmd" >&2
        exit 1
    }
done

# ── JSON helpers ──────────────────────────────────────────────────────────────
json_get() {
    local json="$1" key="$2"
    if command -v jq &>/dev/null; then
        printf '%s' "$json" | jq -r --arg k "$key" '.[$k] // empty' 2>/dev/null || true
    else
        printf '%s' "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    v = d.get(sys.argv[1])
    if v is not None:
        print(v, end='')
except Exception:
    pass
" "$key"
    fi
}

json_get_nested() {
    local json="$1" path="$2"   # path like .response.user.token
    if command -v jq &>/dev/null; then
        printf '%s' "$json" | jq -r "${path} // empty" 2>/dev/null || true
    else
        printf '%s' "$json" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    keys = sys.argv[1].lstrip('.').split('.')
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k)
        else:
            d = None
        if d is None:
            break
    if d is not None:
        print(d, end='')
except Exception:
    pass
" "$path"
    fi
}

# Parse a scalar field from a Buzz API response — handles both JSON and XML.
# Usage: buzz_get_field <response_text> <field>
# Supported fields: code  token  partial_token  message
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
    except Exception:
        pass
if result:
    sys.stdout.write(result)
PYEOF
}

# Read a password with * masking, one character at a time.
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

# ── Load config ───────────────────────────────────────────────────────────────
if [ ! -f "$CONFIG_FILE" ]; then
    printf 'buzz-config.json not found — nothing to clean up.\n'
    exit 0
fi

config="$(cat "$CONFIG_FILE")"

SERVER_URL="$(json_get "$config" serverUrl)"
OAUTH_USER_ID="$(json_get "$config" oauthUserId)"
OAUTH_KID="$(json_get "$config" oauthKid)"
CERT_THUMBPRINT="$(json_get "$config" certThumbprint)"
STORE_LOCATION_STR="$(json_get "$config" certStoreLocation)"
PRIVATE_KEY_PATH="$(json_get "$config" privateKeyPath)"

SERVER_URL="${SERVER_URL%/}"

if [ -z "$SERVER_URL" ] || [ -z "$OAUTH_USER_ID" ]; then
    printf 'buzz-config.json is missing required fields (serverUrl, oauthUserId).\n' >&2
    exit 1
fi

# ── Cert store path ───────────────────────────────────────────────────────────
if [ "$STORE_LOCATION_STR" = "LocalMachine" ]; then
    STORE_DIR="/etc/dotnet/corefx/cryptography/x509stores/my"
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        printf 'Error: removing a LocalMachine certificate requires root privileges.\n' >&2
        printf 'Please re-run with: sudo ./scripts/cleanup-buzz-sample.sh\n' >&2
        exit 1
    fi
else
    STORE_DIR="${HOME}/.dotnet/corefx/cryptography/x509stores/my"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
printf '\n'
printf '════════════════════════════════════════════════════════\n'
printf '  Buzz API Sample — Cleanup\n'
printf '════════════════════════════════════════════════════════\n'
printf '\n'
printf 'This script will:\n'
printf '  • Delete OAuth public key (kid: %s) from Buzz\n' "$OAUTH_KID"
printf '  • Delete Application Identity account (userid: %s) from Buzz\n' "$OAUTH_USER_ID"
if [ -n "$CERT_THUMBPRINT" ]; then
    printf '  • Remove certificate %s from local cert store\n' "$CERT_THUMBPRINT"
fi
if [ -n "$PRIVATE_KEY_PATH" ] && [ -f "$PRIVATE_KEY_PATH" ]; then
    printf '  • Delete private key file: %s\n' "$PRIVATE_KEY_PATH"
fi
printf '  • Delete buzz-config.json\n'
printf '\n'
printf 'This action is irreversible.  Continue? [y/N] '
read -r confirm
case "$confirm" in [Yy]) ;; *) printf 'Aborted.\n'; exit 0 ;; esac

# ── Admin login ───────────────────────────────────────────────────────────────
printf '\n── Admin login ──────────────────────────────────────────\n'
printf 'Enter credentials for a Buzz admin account with rights to\n'
printf 'delete users and manage keys on account %s.\n\n' "$OAUTH_USER_ID"

ADMIN_TOKEN=""
while [ -z "$ADMIN_TOKEN" ]; do
    while true; do
        printf 'Admin username (userspace/username, e.g. myschool/admin): '
        read -r ADMIN_USERNAME
        if printf '%s' "$ADMIN_USERNAME" | grep -qE '^[^/]+/[^/]+$'; then
            break
        fi
        printf '  Username must be in userspace/username format.\n'
    done

    prompt_password "Admin password" ADMIN_PASSWORD

    printf 'Logging in...'

    login_body="$(printf '%s\n%s\n' "$ADMIN_USERNAME" "$ADMIN_PASSWORD" | python3 -c "
import sys, json
lines = sys.stdin.read().splitlines()
body = {
    'request': {
        'cmd': 'login3',
        'username': lines[0],
        'password': lines[1]
    }
}
print(json.dumps(body), end='')
")"
    ADMIN_PASSWORD=""

    login_response="$(printf '%s' "$login_body" | curl -sL -X POST \
        -H "Content-Type: application/json" \
        --data-binary @- \
        "${SERVER_URL}/cmd/login3" "${CURL_OPTS_ARR[@]+"${CURL_OPTS_ARR[@]}"}" || true)"
    login_body=""

    if [ -z "$login_response" ]; then
        printf '\n  Network error: could not reach server.\n'
        printf '  Please check the server URL and try again.  Press Ctrl+C to abort.\n\n'
        continue
    fi

    # Extract code — tries multiple paths used by different Buzz API versions.
    login_code="$(buzz_get_field "$login_response" code)"

    # MFA check
    if printf '%s' "$login_code" | grep -qiE '(factor|challenge|otp|mfa|verify|multifactor)'; then
        printf ' MFA verification required.\n'
        printf 'Enter your MFA code: '
        read -r MFA_CODE

        mfa_token="$(buzz_get_field "$login_response" partial_token)"

        mfa_body="$(printf '%s\n%s\n' "$mfa_token" "$MFA_CODE" | python3 -c "
import sys, json
lines = sys.stdin.read().splitlines()
body = {
    'request': {
        'cmd': 'verifylogin',
        'token': lines[0],
        'code':  lines[1]
    }
}
print(json.dumps(body), end='')
")"
        mfa_token=""

        login_response="$(printf '%s' "$mfa_body" | curl -sL -X POST \
            -H "Content-Type: application/json" \
            --data-binary @- \
            "${SERVER_URL}/cmd/verifylogin" "${CURL_OPTS_ARR[@]+"${CURL_OPTS_ARR[@]}"}" || true)"
        mfa_body=""

        if [ -z "$login_response" ]; then
            printf '  MFA request failed: network error.  Press Ctrl+C to abort.\n\n'
            continue
        fi

        login_code="$(buzz_get_field "$login_response" code)"
    fi

    if [ "$login_code" != "OK" ]; then
        login_msg="$(buzz_get_field "$login_response" message)"
        printf '\n  Login failed (code: %s)%s\n' "$login_code" "${login_msg:+: $login_msg}"
        # If the code is empty the response format was not recognised — show it raw for diagnosis.
        if [ -z "$login_code" ]; then
            printf '  Server response: %.400s\n' "$login_response"
        fi
        printf '  Please check your credentials and try again.  Press Ctrl+C to abort.\n\n'
        continue
    fi

    candidate_token="$(buzz_get_field "$login_response" token)"
    if [ -z "$candidate_token" ]; then
        printf '\n  Login succeeded but no token was returned.  Press Ctrl+C to abort.\n\n'
        continue
    fi

    ADMIN_TOKEN="$candidate_token"
done
printf ' OK\n'
printf 'Logged in successfully.\n'

# ── Delete OAuth public key from Buzz ─────────────────────────────────────────
printf '\n── Deleting OAuth key (kid: %s) ─────────────────────────\n' "$OAUTH_KID"

if [ -n "$OAUTH_KID" ]; then
    key_url="${SERVER_URL}/api/users/${OAUTH_USER_ID}/keys/${OAUTH_KID}"
    key_response="$(curl -s -w '\n%{http_code}' \
        -X DELETE "$key_url" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        "${CURL_OPTS_ARR[@]+"${CURL_OPTS_ARR[@]}"}")"

    key_http_code="$(printf '%s' "$key_response" | tail -n1)"
    key_body="$(printf '%s' "$key_response" | sed '$d')"

    case "$key_http_code" in
        204|200)
            printf 'OAuth key deleted (HTTP %s).\n' "$key_http_code"
            ;;
        404)
            printf 'OAuth key not found on server (already deleted or never registered).\n'
            ;;
        401|403)
            printf 'Warning: HTTP %s — insufficient rights to delete key.\n' "$key_http_code" >&2
            printf '  Continuing with remaining cleanup steps.\n' >&2
            ;;
        *)
            printf 'Warning: unexpected HTTP %s deleting key.\n' "$key_http_code" >&2
            [ -n "$key_body" ] && printf '  Response: %s\n' "$key_body" >&2
            printf '  Continuing with remaining cleanup steps.\n' >&2
            ;;
    esac
else
    printf 'No kid in config — skipping key deletion.\n'
fi

# ── Delete Application Identity account from Buzz ─────────────────────────────
printf '\n── Deleting Application Identity account (userid: %s) ──\n' "$OAUTH_USER_ID"

delete_body="$(python3 -c "
import sys, json
body = {
    'requests': {
        'user': [{'userid': sys.argv[1]}]
    }
}
print(json.dumps(body), end='')
" "$OAUTH_USER_ID")"

_token_enc="$(printf '%s' "$ADMIN_TOKEN" | python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.stdin.read(),safe=""),end="")')"
delete_response="$(printf '%s' "$delete_body" | curl -s -X POST \
    "${SERVER_URL}/cmd/deleteusers?_token=${_token_enc}" \
    -H "Content-Type: application/json" \
    --data-binary @- \
    "${CURL_OPTS_ARR[@]+"${CURL_OPTS_ARR[@]}"}")"
_token_enc=""

delete_code="$(buzz_get_field "$delete_response" code)"

case "$delete_code" in
    OK)
        printf 'Application Identity account deleted.\n'
        ;;
    "")
        printf 'Warning: could not parse delete response.\n' >&2
        printf '  Response: %s\n' "$delete_response" >&2
        printf '  Continuing with remaining cleanup steps.\n' >&2
        ;;
    *)
        printf 'Warning: delete returned code "%s".\n' "$delete_code" >&2
        printf '  Continuing with remaining cleanup steps.\n' >&2
        ;;
esac

# ── Remove certificate from local cert store ──────────────────────────────────
if [ -n "$CERT_THUMBPRINT" ]; then
    printf '\n── Removing certificate from local cert store ───────────\n'
    if ! printf '%s' "$CERT_THUMBPRINT" | grep -qE '^[0-9A-Fa-f]{40}$'; then
        die "certThumbprint in buzz-config.json is not a valid SHA-1 hex string: $CERT_THUMBPRINT"
    fi
    PFX_PATH="${STORE_DIR}/${CERT_THUMBPRINT}.pfx"

    if [ -f "$PFX_PATH" ]; then
        rm -f "$PFX_PATH"
        printf 'Certificate removed: %s\n' "$PFX_PATH"
    else
        printf 'Certificate file not found (already removed): %s\n' "$PFX_PATH"
    fi
fi

# ── Remove private key file ───────────────────────────────────────────────────
if [ -n "$PRIVATE_KEY_PATH" ] && [ -f "$PRIVATE_KEY_PATH" ]; then
    printf '\n── Removing private key file ────────────────────────────\n'
    printf '  Path: %s\n' "$PRIVATE_KEY_PATH"
    printf 'Delete this file? [y/N] '
    read -r confirm_key
    case "$confirm_key" in
        [Yy])
            rm -f "$PRIVATE_KEY_PATH"
            printf 'Private key deleted: %s\n' "$PRIVATE_KEY_PATH"
            ;;
        *)
            printf 'Skipped private key deletion.\n'
            ;;
    esac
fi

# ── Delete buzz-config.json ───────────────────────────────────────────────────
printf '\n── Deleting buzz-config.json ────────────────────────────\n'
rm -f "$CONFIG_FILE"
printf 'buzz-config.json deleted.\n'

# ── Done ──────────────────────────────────────────────────────────────────────
printf '\n'
printf '════════════════════════════════════════════════════════\n'
printf '  Cleanup complete.  Environment is back to a clean state.\n'
printf '  Run ./scripts/run-buzz-sample.sh to set up and run the sample again.\n'
printf '════════════════════════════════════════════════════════\n'
printf '\n'
