#!/usr/bin/env bash
# cleanup.sh — Remove all artifacts created by setup-buzz-oauth.sh.
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
#   ./scripts/cleanup.sh
#
# Requires: curl, python3 (jq recommended but optional)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/buzz-config.json"

# ── Platform check ────────────────────────────────────────────────────────────
if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'This script is for Linux only.\n' >&2
    printf 'On Windows/macOS, run: .\\scripts\\Cleanup-BuzzSample.ps1\n' >&2
    exit 1
fi

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
        printf '%s' "$json" | jq -r --arg k "$key" '.[$k] // empty'
    else
        printf '%s' "$json" | python3 -c "
import sys, json
d = json.load(sys.stdin)
v = d.get(sys.argv[1])
if v is not None:
    print(v, end='')
" "$key"
    fi
}

json_get_nested() {
    local json="$1" path="$2"   # path like .response.user.token
    if command -v jq &>/dev/null; then
        printf '%s' "$json" | jq -r "${path} // empty"
    else
        printf '%s' "$json" | python3 -c "
import sys, json
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
" "$path"
    fi
}

json_build() {
    python3 -c "
import sys, json
args = sys.argv[1:]
d = {}
for i in range(0, len(args), 2):
    d[args[i]] = args[i+1]
print(json.dumps(d), end='')
" "$@"
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

printf 'Admin username (userspace/username or just username): '
read -r ADMIN_USERNAME

printf 'Admin password: '
read -rs ADMIN_PASSWORD
printf '\n'

login_body="$(python3 -c "
import sys, json
body = {
    'request': {
        'cmd': 'login3',
        'username': sys.argv[1],
        'password': sys.argv[2]
    }
}
print(json.dumps(body), end='')
" "$ADMIN_USERNAME" "$ADMIN_PASSWORD")"

login_response="$(curl -s -X POST \
    -H "Content-Type: application/json" \
    --data-raw "$login_body" \
    "${SERVER_URL}/cmd/login3" ${CURL_OPTS:-})"

login_code="$(json_get_nested "$login_response" ".response.code")"

# MFA check
if printf '%s' "$login_code" | grep -qiE '(factor|challenge|otp|mfa|verify|multifactor)'; then
    printf '\nMFA verification required.\n'
    printf 'Enter your MFA code: '
    read -r MFA_CODE

    mfa_token="$(json_get_nested "$login_response" ".response.user.token")"

    mfa_body="$(python3 -c "
import sys, json
body = {
    'request': {
        'cmd': 'verifylogin',
        'token': sys.argv[1],
        'code':  sys.argv[2]
    }
}
print(json.dumps(body), end='')
" "$mfa_token" "$MFA_CODE")"

    login_response="$(curl -s -X POST \
        -H "Content-Type: application/json" \
        --data-raw "$mfa_body" \
        "${SERVER_URL}/cmd/verifylogin" ${CURL_OPTS:-})"

    login_code="$(json_get_nested "$login_response" ".response.code")"
fi

if [ "$login_code" != "OK" ]; then
    printf 'Login failed (code: %s).\n' "$login_code" >&2
    json_get_nested "$login_response" ".response.message" >&2 || true
    exit 1
fi

ADMIN_TOKEN="$(json_get_nested "$login_response" ".response.user.token")"
if [ -z "$ADMIN_TOKEN" ]; then
    printf 'Login succeeded but no token was returned.\n' >&2
    exit 1
fi

printf 'Logged in successfully.\n'

# ── Delete OAuth public key from Buzz ─────────────────────────────────────────
printf '\n── Deleting OAuth key (kid: %s) ─────────────────────────\n' "$OAUTH_KID"

if [ -n "$OAUTH_KID" ]; then
    key_url="${SERVER_URL}/api/users/${OAUTH_USER_ID}/keys/${OAUTH_KID}"
    key_response="$(curl -s -w '\n%{http_code}' \
        -X DELETE "$key_url" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        ${CURL_OPTS:-})"

    key_http_code="$(printf '%s' "$key_response" | tail -n1)"
    key_body="$(printf '%s' "$key_response" | head -n -1)"

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

delete_response="$(curl -s -X POST \
    "${SERVER_URL}/cmd/deleteusers" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    --data-raw "$delete_body" \
    ${CURL_OPTS:-})"

delete_code="$(json_get_nested "$delete_response" ".responses.user[0].code" 2>/dev/null \
    || json_get_nested "$delete_response" ".response.code" 2>/dev/null || true)"

if [ -z "$delete_code" ] && command -v jq &>/dev/null; then
    delete_code="$(printf '%s' "$delete_response" | jq -r '.responses.user[0].code // .response.code // empty')"
fi

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
    rm -f "$PRIVATE_KEY_PATH"
    printf 'Private key deleted: %s\n' "$PRIVATE_KEY_PATH"
fi

# ── Delete buzz-config.json ───────────────────────────────────────────────────
printf '\n── Deleting buzz-config.json ────────────────────────────\n'
rm -f "$CONFIG_FILE"
printf 'buzz-config.json deleted.\n'

# ── Done ──────────────────────────────────────────────────────────────────────
printf '\n'
printf '════════════════════════════════════════════════════════\n'
printf '  Cleanup complete.  Environment is back to a clean state.\n'
printf '  Run ./scripts/run.sh to set up and run the sample again.\n'
printf '════════════════════════════════════════════════════════\n'
printf '\n'
