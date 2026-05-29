#!/usr/bin/env bash
# register-buzz-oauth-key.sh — Register an RSA public key with Buzz for OAuth 2.0 authentication.
#
# Usage:
#   ./scripts/register-buzz-oauth-key.sh -s SERVER_URL -u USER_ID -k KID -p PUBLIC_KEY_PATH
#
# Options:
#   -s URL    Buzz API server URL, e.g. https://api.agilixbuzz.com  (no trailing slash)
#   -t TOKEN  Bearer token (optional — prefer BUZZ_ADMIN_TOKEN env var or interactive prompt to
#             avoid exposing the token in shell history and process listings)
#   -u ID     userid of the Application Identity account (from OAuth Setup Step 5)
#   -k KID    Key ID for this key, e.g. "2025-q2".
#             Allowed characters: ASCII letters, digits, -, _, .  Max 128 chars.
#             PUTting an existing kid REPLACES the key immediately — use a new kid to rotate.
#   -p PATH   Path to the PEM public key file (SubjectPublicKeyInfo format)
#   -h        Show this help
#
# Getting an admin Bearer token:
#   If you already have an OAuth application set up, use it.
#   Otherwise, use the legacy login3 command.  Use 'read -rsp' to avoid
#   exposing the password in shell history or process listings:
#
#     read -rsp 'Admin password: ' ADMIN_PASS; printf '\n'
#     TOKEN=$(printf '%s\n%s' "myspace/admin" "$ADMIN_PASS" | python3 -c "
# import sys, json
# u, p = sys.stdin.read().splitlines()[:2]
# print(json.dumps({'request':{'cmd':'login3','username':u,'password':p}}))" | \
#               curl -s -X POST https://api.agilixbuzz.com/cmd/login3 \
#                   -H 'Content-Type: application/json' --data-binary @- | \
#               python3 -c "import sys,json; print(json.load(sys.stdin)['response']['user']['token'])")
#     ADMIN_PASS=''
#
# Requires: curl
#
# Examples:
#   ./scripts/register-buzz-oauth-key.sh \
#       -s https://api.agilixbuzz.com \
#       -t "~0.ABC123..." \
#       -u 12345678 \
#       -k "2025-q2" \
#       -p public_key.pem

set -euo pipefail

# Convert CURL_OPTS string to an array for safe quoted expansion.
CURL_OPTS_ARR=()
[ -n "${CURL_OPTS:-}" ] && read -ra CURL_OPTS_ARR <<< "$CURL_OPTS"

# ── Argument parsing ──────────────────────────────────────────────────────────
SERVER_URL=""
ADMIN_TOKEN=""
USER_ID=""
KID=""
PUBLIC_KEY_PATH=""

usage() {
    sed -n '2,${/^[^#]/q; s/^# \{0,1\}//; /^$/d; p}' "$0"
    exit 0
}

while getopts ":s:t:u:k:p:h" opt; do
    case "$opt" in
        s) SERVER_URL="$OPTARG"     ;;
        t) ADMIN_TOKEN="$OPTARG"    ;;
        u) USER_ID="$OPTARG"        ;;
        k) KID="$OPTARG"            ;;
        p) PUBLIC_KEY_PATH="$OPTARG";;
        h) usage                    ;;
        :) printf 'Error: -%s requires an argument\n' "$OPTARG" >&2; exit 1 ;;
        ?) printf 'Error: unknown option -%s\n' "$OPTARG"        >&2; exit 1 ;;
    esac
done

# ── Validate inputs ───────────────────────────────────────────────────────────
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

# Validate non-token required args first so the user isn't prompted for a token
# only to hit a missing-argument error immediately after.
[ -n "$SERVER_URL" ]      || die "Server URL is required (-s)"
[ -n "$USER_ID" ]         || die "User ID is required (-u)"
[ -n "$KID" ]             || die "Key ID is required (-k)"
[ -n "$PUBLIC_KEY_PATH" ] || die "Public key path is required (-p)"

# ── Resolve admin token ───────────────────────────────────────────────────────
# Prefer BUZZ_ADMIN_TOKEN env var or interactive prompt over -t to keep the
# token out of shell history and process listings.
if [ -z "$ADMIN_TOKEN" ]; then
    if [ -n "${BUZZ_ADMIN_TOKEN:-}" ]; then
        ADMIN_TOKEN="$BUZZ_ADMIN_TOKEN"
    else
        read -rsp 'Admin Bearer token: ' ADMIN_TOKEN
        printf '\n'
    fi
fi

[ -n "$ADMIN_TOKEN" ]     || die "Admin token is required (-t, BUZZ_ADMIN_TOKEN, or interactive prompt)"

SERVER_URL="${SERVER_URL%/}"  # strip trailing slash

if ! printf '%s' "$KID" | grep -qE '^[A-Za-z0-9._-]{1,128}$'; then
    die "Invalid kid '$KID'. Allowed characters: ASCII letters, digits, -, _, .  Max 128 chars."
fi

if [ ! -f "$PUBLIC_KEY_PATH" ]; then
    die "Public key file not found: $PUBLIC_KEY_PATH"
fi

# Verify it looks like a SubjectPublicKeyInfo PEM (not a private key or certificate)
if ! grep -q 'BEGIN PUBLIC KEY' "$PUBLIC_KEY_PATH"; then
    die "File '$PUBLIC_KEY_PATH' does not appear to be a SubjectPublicKeyInfo PEM public key.
Expected a '-----BEGIN PUBLIC KEY-----' header.
Generate one with: openssl pkey -in private_key.pem -pubout -out public_key.pem"
fi

if ! command -v curl &>/dev/null; then
    die "curl is required but not found.  Install with: apt-get install curl"
fi

# ── Register the key ──────────────────────────────────────────────────────────
URL="${SERVER_URL}/api/users/${USER_ID}/keys/${KID}"

printf 'Registering public key...\n'
printf '  URL  : %s\n' "$URL"
printf '  Kid  : %s\n' "$KID"
printf '  File : %s\n' "$(cd -P "$(dirname -- "$PUBLIC_KEY_PATH")" && printf '%s/%s' "$PWD" "$(basename -- "$PUBLIC_KEY_PATH")")"
printf '\n'

# Capture HTTP status code alongside response body
curl_exit=0
http_response=$(curl -sL -w '\n%{http_code}' \
    -X PUT "$URL" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/x-pem-file" \
    --data-binary "@${PUBLIC_KEY_PATH}" \
    "${CURL_OPTS_ARR[@]+"${CURL_OPTS_ARR[@]}"}") || curl_exit=$?
if [ "$curl_exit" -ne 0 ]; then
    die "curl failed for $URL (exit $curl_exit). Check the server URL, connectivity, and any CURL_OPTS."
fi

http_code=$(printf '%s' "$http_response" | tail -n1)
response_body=$(printf '%s' "$http_response" | sed '$d')

case "$http_code" in
    204)
        printf 'Public key registered successfully (HTTP 204).\n\n'
        printf 'Configure your application:\n'
        printf '  oauthUserId   = %s\n' "$USER_ID"
        printf '  oauthKid      = %s\n' "$KID"
        printf '  certThumbprint or privateKeyPath = (see setup-buzz-oauth.sh or README.md)\n'
        ;;
    400)
        printf 'Error: HTTP 400 Bad Request\n'                                              >&2
        printf 'Possible causes:\n'                                                         >&2
        printf '  - The public key is not in SubjectPublicKeyInfo (SPKI) PEM format.\n'    >&2
        printf '    Regenerate with: openssl pkey -in private_key.pem -pubout -out public_key.pem\n' >&2
        printf '  - The RSA key is smaller than the 2048-bit minimum.\n'                   >&2
        printf '  - Account %s was not created with type=applicationidentity.\n' "$USER_ID" >&2
        [ -n "$response_body" ] && printf 'Response: %s\n' "$response_body"                >&2
        exit 1
        ;;
    401|403)
        printf 'Error: HTTP %s — the admin token lacks Update User rights on account %s.\n' \
            "$http_code" "$USER_ID" >&2
        exit 1
        ;;
    404)
        printf 'Error: HTTP 404 — server URL or user ID not found.\n'           >&2
        printf '  Server URL : %s\n' "$SERVER_URL"                              >&2
        printf '  User ID    : %s\n' "$USER_ID"                                 >&2
        exit 1
        ;;
    *)
        printf 'Error: unexpected HTTP %s\n' "$http_code" >&2
        [ -n "$response_body" ] && printf 'Response: %s\n' "$response_body"    >&2
        exit 1
        ;;
esac
