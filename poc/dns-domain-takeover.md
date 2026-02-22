# PoC: DNS Domain Takeover — gmail.gongrzhe.com (C1/S1)

## Finding

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Taxonomy** | TL (Token/Credential Leakage) |
| **OWASP LLM** | LLM02 (Sensitive Information Disclosure) |
| **Affected** | `src/index.ts:126-128`, `README.md:146-164` |
| **CVSS 3.1** | 9.3 (Critical) — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N |

## Summary

The Gmail MCP Server README documents an OAuth callback URL using the domain `gmail.gongrzhe.com`. This domain's parent (`gongrzhe.com`) is **unregistered** as of 2026-02-22, meaning any third party can register it and intercept OAuth authorization codes from users who follow the documented instructions.

## DNS Evidence

Captured: 2026-02-22 10:45 UTC

### WHOIS — gongrzhe.com

```
No match for domain "GONGRZHE.COM".
>>> Last update of whois database: 2026-02-22T10:45:29Z <<<
```

**The domain is unregistered.** Anyone can register it for ~$10/year.

### DNS A Record — gmail.gongrzhe.com

```
$ dig gmail.gongrzhe.com A +short
(no response — NXDOMAIN / timeout)
```

### DNS A Record — gongrzhe.com

```
$ dig gongrzhe.com A +short
;; communications error to [resolver]#53: timed out
```

No DNS records exist for the domain.

## Vulnerable Code Path

```typescript
// src/index.ts:126-128
const callback = process.argv[2] === 'auth' && process.argv[3]
    ? process.argv[3]
    : "http://localhost:3000/oauth2callback";
```

The third command-line argument becomes the OAuth `redirect_uri` without any validation. The README instructs users to run:

```bash
npx @gongrzhe/server-gmail-autoauth-mcp auth https://gmail.gongrzhe.com/oauth2callback
```

## Attack Chain

1. **Attacker registers `gongrzhe.com`** (~$10, any registrar)
2. **Attacker configures DNS** for `gmail.gongrzhe.com` pointing to their server
3. **Attacker deploys HTTPS endpoint** at `https://gmail.gongrzhe.com/oauth2callback`
4. **Victim follows README instructions** and runs the documented command
5. **Google OAuth redirects** to `https://gmail.gongrzhe.com/oauth2callback?code=AUTH_CODE`
6. **Attacker receives the authorization code**
7. **Attacker exchanges code for tokens** using the same `client_id`/`client_secret` (which are embedded in the client application and considered non-confidential for "installed" app OAuth)
8. **Attacker obtains `refresh_token`** granting persistent access to victim's Gmail

## Impact

- **Complete Gmail account compromise** for any user who followed the documented instructions
- **Persistent access** via refresh token (survives password changes)
- **No user visibility** — the victim sees a normal OAuth flow
- **Scalable** — affects all users who ever used this callback URL
- **Historical exposure** — users who authenticated in the past may have already had codes intercepted (if the domain was previously registered)

## Proof of Concept

**No outbound requests were made to gmail.gongrzhe.com** — this PoC is based on DNS evidence and code analysis only.

To demonstrate exploitability (in a controlled environment):

```bash
# 1. Register gongrzhe.com (DO NOT DO THIS outside of coordinated disclosure)

# 2. Set up a simple HTTPS server:
# from flask import Flask, request
# app = Flask(__name__)
# @app.route('/oauth2callback')
# def callback():
#     code = request.args.get('code')
#     print(f"CAPTURED AUTH CODE: {code}")
#     return "Authentication received."

# 3. Victim runs:
# npx @gongrzhe/server-gmail-autoauth-mcp auth https://gmail.gongrzhe.com/oauth2callback

# 4. Auth code appears in attacker's server logs
```

## Remediation

1. **Immediate:** Remove the `gmail.gongrzhe.com` callback URL from all documentation
2. **Immediate:** Register `gongrzhe.com` defensively (or coordinate with the author to do so)
3. **Code fix:** Validate that `process.argv[3]` is either `localhost` or a domain the user explicitly trusts
4. **Code fix:** Add a warning when using non-localhost callback URLs
5. **User notification:** Alert users who may have used this flow to revoke their tokens

## Responsible Disclosure Note

This finding should be disclosed to the repository author before any public disclosure. The unregistered domain creates an active, exploitable risk that should be mitigated by either:
- The author registering the domain defensively
- Removing the documentation referencing it
- Both
