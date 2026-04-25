#!/usr/bin/env bash
# Issue a new contractor token. Run as root on the bastion.
#
# Usage: ./issue-token.sh <contractor-name>
# Prints the token to stdout — copy it once, can't recover later.

set -euo pipefail

TOKENS_FILE="${TOKENS_FILE:-/etc/mrc-refresh-mcp/tokens.yml}"

[[ $# -eq 1 ]] || { echo "usage: $0 <contractor-name>" >&2; exit 1; }
CONTRACTOR="$1"
[[ "$CONTRACTOR" =~ ^[a-z0-9_-]+$ ]] || { echo "contractor name must be [a-z0-9_-]+" >&2; exit 1; }
[[ -w "$TOKENS_FILE" ]] || { echo "$TOKENS_FILE not writable — run as root" >&2; exit 1; }

# 32 bytes of entropy, URL-safe base64, no padding.
TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')

# Append to tokens.yml. The format is "<token>: <name>" — YAML treats the
# token as a string key. (Tokens contain only [A-Za-z0-9_-], YAML-safe.)
printf '%s: %s\n' "$TOKEN" "$CONTRACTOR" >> "$TOKENS_FILE"

cat <<EOF
Issued token for: $CONTRACTOR
Token (copy now — it will not be displayed again):

  $TOKEN

To revoke: edit $TOKENS_FILE and remove the line. No restart needed.
EOF
