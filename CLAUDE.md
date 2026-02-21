# Gmail MCP Server — Security Audit

## Project Overview

This is a security audit of [`GongRzhe/Gmail-MCP-Server`](https://github.com/GongRzhe/Gmail-MCP-Server), conducted as part of an MSc research project on MCP (Model Context Protocol) server vulnerabilities.

The audit has two goals:
1. Produce academically rigorous findings that contribute to a vulnerability taxonomy of MCP-specific attack classes
2. Produce practical, reproducible security outputs (annotated code, PoC exploits, findings report)

You have full autonomy to explore, run tools, and test payloads. Flag before doing anything that touches external systems beyond the audit target (e.g. sending real emails, making outbound OAuth requests to third-party domains).

---

## Repository

```bash
git clone https://github.com/GongRzhe/Gmail-MCP-Server
cd Gmail-MCP-Server
```

---

## Audit Methodology

Work through the following phases in order. Do not skip phases. Document findings as you go in `findings/`.

### Phase 1 — Reconnaissance & Surface Mapping

- Read all source files; map every tool exposed via MCP (name, description, parameters, permissions required)
- Identify all external calls: OAuth endpoints, token storage paths, third-party domains
- Identify all file I/O: what is read, what is written, where credentials land on disk
- Map OAuth scopes requested vs. scopes actually needed for each tool
- Note any `autoApprove` or `alwaysAllow` patterns in documentation or code
- Flag the `gmail.gongrzhe.com` external callback URL — determine what this domain does, whether the author controls it, and whether tokens are transmitted to it

Output: `findings/01-surface-map.md`

### Phase 2 — Static Analysis

Analyse the source code for:

**Authentication & token handling**
- OAuth token storage: file permissions, storage path, exposure to other processes
- Refresh token handling: is it logged, printed, or serialised insecurely?
- Client secret handling: hardcoded, env var, or config file? Is it ever logged?
- Token scope: does the server request `https://mail.google.com/` (full access) or narrower scopes? Is scope enforced per-tool or granted globally?

**Input validation**
- Are tool parameters sanitised before being passed to Gmail API calls?
- Are there any parameters that get interpolated into strings, shell commands, or file paths?
- Can parameter values influence control flow in unintended ways?

**Tool descriptions as an attack surface**
- Read every MCP tool description carefully — these are fed directly to the LLM
- Assess whether any description could be crafted to manipulate LLM behaviour (tool shadowing, instruction injection)

**Confused deputy potential**
- Identify which tools have destructive or exfiltration capability (send_email, delete, etc.)
- Assess whether these tools have any confirmation logic or are callable silently

**Dependency audit**
- Run `npm audit` or equivalent
- Check for pinned vs. unpinned dependencies
- Note any dependencies that handle OAuth, HTTP, or file I/O

Output: `findings/02-static-analysis.md`

### Phase 3 — Dynamic Testing

Set up a local instance against a test Gmail account (do not use a real personal or institutional account).

**OAuth flow testing**
- Capture the full OAuth flow with a proxy (mitmproxy or Burp); document exactly what is sent where
- Test the external callback URL feature: does `npx ... auth https://gmail.gongrzhe.com/oauth2callback` transmit the auth code or token to that domain?
- Check token file permissions after auth completes (`ls -la ~/.gmail-mcp/`)
- Attempt to read the token file from a separate process to confirm exposure

**Prompt injection via email content**
- Send test emails to the account containing MCP-style instruction payloads in subject/body
- Use the MCP server's read tool to retrieve these emails via an LLM
- Test whether injected instructions in email content can cause the LLM to call other tools (e.g. forward emails, send to attacker address)
- Document successful injection chains with full payloads

**Confused deputy testing**
- With the server running alongside a second MCP server (e.g. a simple echo server), test whether output from the second server can trigger Gmail tool calls
- Attempt to construct a cross-server injection chain

**Scope and permission testing**
- Verify which Gmail API scopes are actually granted during OAuth
- Test whether the server enforces least-privilege per tool or uses a single broad token for all operations

Output: `findings/03-dynamic-testing.md` and `poc/` directory containing any working exploit scripts

### Phase 4 — Findings Synthesis

Produce the following files:

**`report/vulnerability-report.md`** — structured findings report with:
- Executive summary
- Each finding as a separate section:
  - Title
  - Severity (Critical / High / Medium / Low / Informational) with CVSS score where applicable
  - Vulnerability class (map to MCP taxonomy — see taxonomy section below)
  - Description
  - Affected component (file + line number)
  - Reproduction steps
  - Impact
  - Remediation recommendation

**`report/annotated-source/`** — copy of key source files with inline comments marking vulnerable lines, misconfigurations, and security observations

**`poc/`** — working proof-of-concept scripts for any exploitable findings. Each PoC should:
- Be self-contained and runnable
- Include a header comment explaining what it demonstrates and prerequisites
- Not depend on external infrastructure you don't control

**`report/thesis-section.md`** — academic write-up of findings suitable for inclusion in an MSc thesis, covering:
- Methodology
- Findings mapped to the MCP vulnerability taxonomy
- Discussion of root causes (design vs. implementation issues)
- Comparison to analogous vulnerabilities in non-MCP systems
- Recommendations for the MCP ecosystem

---

## MCP Vulnerability Taxonomy

Map each finding to one or more of these classes. OWASP mappings reference the [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

| Code | MCP Class | Description | OWASP LLM 2025 |
|---|---|---|---|
| **PI-TR** | Prompt Injection via Tool Response | Malicious content returned by a tool hijacks LLM behaviour | LLM01: Prompt Injection |
| **TDM** | Tool Description Manipulation | Tool metadata influences LLM in unintended ways | LLM01: Prompt Injection |
| **CD** | Confused Deputy | LLM acts as intermediary, performing privileged actions on behalf of untrusted input | LLM06: Excessive Agency |
| **CST** | Cross-Server Trust Confusion | Content from one MCP server influences actions via another | LLM06: Excessive Agency |
| **TL** | Token/Credential Leakage | Auth material exposed via logging, file permissions, network, or third parties | LLM02: Sensitive Information Disclosure |
| **SE** | Scope Escalation | Server requests or uses broader permissions than necessary | LLM08: Excessive Permissions |
| **RP** | Rug Pull / Behavioural Change | Server changes behaviour post-trust establishment | LLM05: Supply Chain Vulnerabilities |
| **II** | Input Injection | Unsanitised parameters passed to downstream APIs or system calls | LLM01: Prompt Injection¹ |

¹ II maps to LLM01 where the injection is LLM-mediated. Where it occurs independently of LLM input (e.g. a traditional API injection via a fixed parameter), it falls outside the OWASP LLM Top 10 and should be noted as a conventional vulnerability occurring in an MCP context.

## Output Structure

```
findings/
  01-surface-map.md
  02-static-analysis.md
  03-dynamic-testing.md
poc/
  [finding-name].py / .js / .sh
report/
  vulnerability-report.md
  thesis-section.md
  annotated-source/
    [key-files-with-comments]
```

---

## Constraints & Guardrails

- **Test account only** — run all dynamic tests against a dedicated throwaway Gmail account, never a real one
- **No live exfiltration** — PoC exploits should demonstrate the vulnerability (e.g. print what would be exfiltrated) without actually sending data to external attacker infrastructure
- **Flag before** making any outbound request to `gmail.gongrzhe.com` or any domain not part of the official Google OAuth infrastructure — document the intent first
- **No destructive actions** on the test account that can't be reversed (mass delete, etc.) without prior documentation
- **Disclose responsibly** — findings should be written up before any public disclosure; note candidate CVE-worthy findings for responsible disclosure to the author

---

## Notes on Key Areas of Interest

These were identified during pre-audit reconnaissance and should receive particular attention:

1. **`gmail.gongrzhe.com` callback URL** — explicitly documented as a feature for "cloud server environments." Determine whether this routes auth codes or access tokens through a third-party server. If so, this is likely the highest-severity finding.

2. **Global credential storage in `~/.gmail-mcp/`** — assess whether file permissions prevent other local processes or MCP servers from reading stored tokens.

3. **Full mailbox scope** — the server appears to request `https://mail.google.com/` which is the broadest possible Gmail scope. Assess whether this is necessary and whether it is enforced uniformly or could be downscoped per tool.

4. **Batch processing (up to 50 emails)** — a single tool call can process 50 emails. If prompt injection via email content is possible, the blast radius scales with batch size.

5. **`autoApprove` patterns** — check whether any tools are configured to bypass confirmation in the documented setup instructions.
