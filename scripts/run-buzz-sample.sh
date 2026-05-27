#!/usr/bin/env bash
# run-buzz-sample.sh — Entry-point for BuzzApiSample on Linux.
#
# If setup has not been done (buzz-config.json is missing or the certificate is
# not installed), the setup script is run interactively first.  Then the sample
# is started with `dotnet run`.
#
# Usage:
#   ./scripts/run-buzz-sample.sh
#
# To force re-running setup even if it was already completed:
#   ./scripts/run-buzz-sample.sh --setup
#
# Requires: dotnet (https://learn.microsoft.com/dotnet/core/install/linux)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/buzz-config.json"
SETUP_SCRIPT="$SCRIPT_DIR/setup-buzz-oauth.sh"

# ── Argument parsing ──────────────────────────────────────────────────────────
FORCE_SETUP=false
for arg in "$@"; do
    case "$arg" in
        --setup) FORCE_SETUP=true ;;
        -h|--help)
            printf 'Usage: %s [--setup]\n' "$0"
            printf '  --setup  Force re-run setup even if already configured\n'
            exit 0
            ;;
        *) printf 'Unknown argument: %s\n' "$arg" >&2; exit 1 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
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

# ── Check if setup is complete ────────────────────────────────────────────────
setup_complete() {
    # 1. Config file must exist
    [ -f "$CONFIG_FILE" ] || return 1

    config="$(cat "$CONFIG_FILE")"

    # 2. Required fields must be present
    server_url="$(json_get "$config" serverUrl)"
    oauth_user_id="$(json_get "$config" oauthUserId)"
    oauth_kid="$(json_get "$config" oauthKid)"
    [ -n "$server_url" ] && [ -n "$oauth_user_id" ] && [ -n "$oauth_kid" ] || return 1

    # 3. Either a certificate thumbprint or a PEM file must be configured
    cert_thumbprint="$(json_get "$config" certThumbprint)"
    private_key_path="$(json_get "$config" privateKeyPath)"

    if [ -n "$cert_thumbprint" ]; then
        # Certificate store path (Linux .NET cert store)
        store_location="$(json_get "$config" certStoreLocation)"
        if [ "$store_location" = "LocalMachine" ]; then
            store_dir="/etc/dotnet/corefx/cryptography/x509stores/my"
        else
            store_dir="${HOME}/.dotnet/corefx/cryptography/x509stores/my"
        fi
        pfx_path="${store_dir}/${cert_thumbprint}.pfx"
        [ -f "$pfx_path" ] || return 1
    elif [ -n "$private_key_path" ]; then
        [ -f "$private_key_path" ] || return 1
    else
        return 1
    fi

    return 0
}

# ── Run setup if needed ───────────────────────────────────────────────────────
if $FORCE_SETUP || ! setup_complete; then
    printf '\n'
    if $FORCE_SETUP; then
        printf '── Running setup (--setup flag) ─────────────────────────────────\n'
    else
        printf '── Setup not complete — starting interactive setup ───────────────\n'
    fi
    printf '\n'

    if [ ! -x "$SETUP_SCRIPT" ]; then
        chmod +x "$SETUP_SCRIPT"
    fi

    bash "$SETUP_SCRIPT" || {
        printf '\nSetup did not complete.  Exiting.\n' >&2
        exit 1
    }

    # Re-check after setup
    if ! setup_complete; then
        printf '\nSetup did not produce a valid configuration.  Exiting.\n' >&2
        exit 1
    fi
fi

# ── Run the sample ────────────────────────────────────────────────────────────
printf '\n'
printf '── Running BuzzApiSample ────────────────────────────────────────\n'
printf '\n'

if ! command -v dotnet &>/dev/null; then
    printf 'Error: dotnet is not on PATH.\n' >&2
    printf 'Install .NET: https://learn.microsoft.com/dotnet/core/install/linux\n' >&2
    exit 1
fi

cd "$PROJECT_ROOT"

# Pick the highest netX.Y framework listed in the .csproj so the script never
# needs updating when a new SDK year is added to TargetFrameworks.
CSPROJ=$(find "$PROJECT_ROOT" -maxdepth 2 -name '*.csproj' | head -1)
FRAMEWORK=""
if [ -n "$CSPROJ" ]; then
    FRAMEWORK=$(python3 - "$CSPROJ" <<'PYEOF'
import sys, re
try:
    from xml.etree import ElementTree as ET
    root = ET.parse(sys.argv[1]).getroot()
    tfs = (root.findtext('.//TargetFrameworks') or
           root.findtext('.//TargetFramework') or '')
    nets = [(f.strip(), [int(x) for x in re.findall(r'\d+', f)])
            for f in tfs.split(';') if re.match(r'^net\d', f.strip())]
    if nets:
        print(max(nets, key=lambda x: x[1])[0])
except Exception:
    pass
PYEOF
)
fi

if [ -n "$FRAMEWORK" ]; then
    dotnet run --framework "$FRAMEWORK"
else
    dotnet run
fi
