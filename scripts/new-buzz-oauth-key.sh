#!/usr/bin/env bash
# new-buzz-oauth-key.sh — Generate an RSA key pair for Buzz OAuth 2.0 authentication.
#
# Usage:
#   ./scripts/new-buzz-oauth-key.sh [OPTIONS]
#
# Options:
#   -o DIR     Output directory for key files (default: current directory)
#   -b BITS    RSA key size in bits; minimum accepted by Buzz is 2048 (default)
#   -h         Show this help
#
# Outputs:
#   private_key.pem  — RSA private key  (keep secret; never commit to source control)
#   public_key.pem   — RSA public key   (upload to Buzz with register-buzz-oauth-key.sh)
#
# Requires: openssl (available on virtually all Linux distributions)
#
# Examples:
#   ./scripts/new-buzz-oauth-key.sh
#   ./scripts/new-buzz-oauth-key.sh -o /etc/myapp/keys -b 4096
#
# SECURITY
#   Add private_key.pem to .gitignore immediately.
#   Store the private key in a secrets manager (HashiCorp Vault, AWS Secrets Manager,
#   Azure Key Vault, GCP Secret Manager) or use setup-buzz-oauth.sh which imports the key
#   directly into the .NET certificate store so no plaintext key file is left on disk.

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
OUTPUT_DIR="."
KEY_BITS=2048

# ── Argument parsing ──────────────────────────────────────────────────────────
usage() {
    sed -n '2,${/^[^#]/q; s/^# \{0,1\}//; /^$/d; p}' "$0"
    exit 0
}

while getopts ":o:b:h" opt; do
    case "$opt" in
        o) OUTPUT_DIR="$OPTARG" ;;
        b) KEY_BITS="$OPTARG"   ;;
        h) usage                ;;
        :) printf 'Error: -%s requires an argument\n' "$OPTARG" >&2; exit 1 ;;
        ?) printf 'Error: unknown option -%s\n' "$OPTARG"        >&2; exit 1 ;;
    esac
done

# ── Validate ──────────────────────────────────────────────────────────────────
if ! command -v openssl &>/dev/null; then
    printf 'Error: openssl is required but not found.\n'       >&2
    printf 'Install with:  apt-get install openssl\n'          >&2
    printf '               yum install openssl\n'              >&2
    exit 1
fi

if [ "$KEY_BITS" -lt 2048 ] 2>/dev/null; then
    printf 'Error: key size must be at least 2048 bits (Buzz minimum).\n' >&2
    exit 1
fi

# ── Prepare output directory ──────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
PRIV_KEY="$OUTPUT_DIR/private_key.pem"
PUB_KEY="$OUTPUT_DIR/public_key.pem"

if [ -f "$PRIV_KEY" ] || [ -f "$PUB_KEY" ]; then
    printf 'WARNING: Key file(s) already exist in %s and will be overwritten.\n' "$OUTPUT_DIR"
    printf 'Continue? [y/N] '
    read -r confirm
    case "$confirm" in [Yy]) ;; *) printf 'Aborted.\n'; exit 0 ;; esac
fi

# ── Generate key pair ─────────────────────────────────────────────────────────
printf 'Generating %d-bit RSA key pair...\n' "$KEY_BITS"

# Generate private key (PKCS#8 format via genpkey, widely supported)
openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${KEY_BITS}" -out "$PRIV_KEY" 2>/dev/null

# Extract public key in SubjectPublicKeyInfo (SPKI) PEM format — required by Buzz
openssl pkey -in "$PRIV_KEY" -pubout -out "$PUB_KEY" 2>/dev/null

# Restrict private key permissions immediately
chmod 600 "$PRIV_KEY"

printf '\nRSA key pair generated (%d bits):\n' "$KEY_BITS"
printf '  Private key : %s\n' "$(python3 -c "import os,sys;print(os.path.realpath(sys.argv[1]))" "$PRIV_KEY")"
printf '  Public key  : %s\n' "$(python3 -c "import os,sys;print(os.path.realpath(sys.argv[1]))" "$PUB_KEY")"
printf '\n'
printf 'Next step: register the public key with Buzz.\n'
printf '  ./scripts/register-buzz-oauth-key.sh \\\n'
printf '      -s <https://api.agilixbuzz.com> \\\n'
printf '      -t <bearer-token-of-admin-account> \\\n'
printf '      -u <userid-of-application-identity-account> \\\n'
printf '      -k <key-id-you-choose, e.g. 2025-q2> \\\n'
printf '      -p %s\n' "$PUB_KEY"
printf '\n'
printf 'IMPORTANT: Never commit private_key.pem to source control.\n'
printf '  echo private_key.pem >> .gitignore\n'
