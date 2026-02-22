# Security Analysis of MCP Server Implementations: A Case Study of the Gmail MCP Server

## 1. Introduction

The Model Context Protocol (MCP), introduced by Anthropic in late 2024, establishes a standardised interface through which large language models (LLMs) can invoke external tools — reading files, querying databases, sending emails, and interacting with third-party APIs. MCP servers expose these capabilities as discrete tools with typed schemas and natural-language descriptions, enabling LLMs to act as autonomous agents within complex workflows.

While MCP represents a significant advance in LLM-tool integration, it introduces a novel class of security concerns that do not map cleanly onto traditional vulnerability taxonomies. The protocol creates a three-party trust model — the user, the LLM, and the MCP server — where each party has distinct capabilities and trust assumptions that can be exploited by adversaries operating through any channel, including the content processed by the tools themselves.

This section presents a detailed security analysis of the Gmail MCP Server (`@gongrzhe/server-gmail-autoauth-mcp` v1.1.11), an open-source MCP server that exposes 19 Gmail operations as LLM-callable tools. With over 3,000 weekly downloads on npm, it represents a widely-deployed MCP server operating in a high-value domain: personal and corporate email. The server was selected as a case study because it combines a rich attack surface (read, write, delete, forward email; filesystem access; OAuth credentials) with the characteristic MCP challenge of processing untrusted content (email bodies) that flows through LLM context.

The analysis identifies 20 vulnerabilities across 8 MCP-specific vulnerability classes, ranging from a critical domain takeover that enables credential theft at scale, to systemic design issues in how tool responses handle untrusted content. The findings contribute to an emerging MCP vulnerability taxonomy and illustrate how traditional security weaknesses are amplified — and in some cases transformed — by the LLM-mediated execution model.

## 2. Methodology

### 2.1 Audit Framework

The audit followed a four-phase methodology adapted from established penetration testing frameworks (OWASP Testing Guide, PTES) with extensions for MCP-specific concerns:

**Phase 1 — Reconnaissance and Surface Mapping.** All source files were read and mapped. The tool inventory catalogued all 19 exposed tools with their parameters, Gmail API calls, and destructive capability. External calls were mapped (OAuth endpoints, the `gmail.gongrzhe.com` callback URL). File I/O was traced (credential reads/writes, attachment handling). OAuth scopes were analysed against per-tool minimum requirements.

**Phase 2 — Static Analysis.** The source code was analysed for authentication and token handling vulnerabilities, input validation gaps, tool description manipulation potential, confused deputy attack chains, and dependency vulnerabilities (`npm audit`).

**Phase 3 — Dynamic Testing.** Code path verification confirmed static findings through umask analysis, DNS/WHOIS verification, and proof-of-concept construction. Prompt injection payloads were prepared targeting the email-to-tool-call attack chain. A cross-server injection MCP server was created for trust confusion testing.

**Phase 4 — Synthesis.** Findings were consolidated into a structured vulnerability report with CVSS scoring, MCP taxonomy classification, and OWASP LLM Top 10 mappings.

### 2.2 MCP Vulnerability Taxonomy

Findings were classified using an eight-class taxonomy developed for this research:

| Code | Class | Description |
|------|-------|-------------|
| PI-TR | Prompt Injection via Tool Response | Malicious content returned by a tool hijacks LLM behaviour |
| TDM | Tool Description Manipulation | Tool metadata influences LLM in unintended ways |
| CD | Confused Deputy | LLM performs privileged actions on behalf of untrusted input |
| CST | Cross-Server Trust Confusion | Content from one MCP server influences actions via another |
| TL | Token/Credential Leakage | Auth material exposed via logging, file permissions, network, or third parties |
| SE | Scope Escalation | Server requests or uses broader permissions than necessary |
| RP | Rug Pull / Behavioural Change | Server changes behaviour post-trust; supply chain risk |
| II | Input Injection | Unsanitised parameters passed to downstream APIs or system calls |

Each class maps to one or more entries in the OWASP Top 10 for LLM Applications (2025 edition), establishing correspondence between MCP-specific and established vulnerability categories.

### 2.3 Ethical Constraints

All testing was conducted against local code analysis and publicly available DNS records. No live Gmail account was accessed during the audit. Proof-of-concept exploits demonstrate vulnerabilities without exfiltrating data to external infrastructure. The `gmail.gongrzhe.com` domain was investigated via DNS queries only — no HTTP requests were sent to it.

## 3. Findings

The audit identified 20 findings: 1 Critical, 9 High, 4 Medium, 4 Low, and 2 Informational. This section presents the findings grouped by MCP vulnerability class, with analysis of root causes and exploitation chains.

### 3.1 Token/Credential Leakage (TL) — 5 Findings

The most prevalent vulnerability class involved credential exposure through multiple channels.

**F01 (Critical): OAuth Callback Domain Takeover.** The project README documents an OAuth callback flow using `https://gmail.gongrzhe.com/oauth2callback` for "cloud server environments." The callback URL is accepted from `process.argv[3]` without validation (`src/index.ts:126-128`). DNS and WHOIS verification confirmed that `gongrzhe.com` is unregistered — NXDOMAIN on all queries, no WHOIS match. Anyone can register this domain for approximately $10 and intercept OAuth authorization codes from users following the documented installation instructions.

This finding is notable because it combines a traditional vulnerability (unvalidated redirect URI) with a supply-chain risk (documentation directing users to a domain the author no longer controls). The authorization code, once intercepted, can be exchanged for access and refresh tokens using the client credentials from the same `gcp-oauth.keys.json` file distributed with the project.

**F02 (High) and F12 (Medium): World-Readable Credential Storage.** OAuth tokens are written to `~/.gmail-mcp/credentials.json` using `fs.writeFileSync()` without a `mode` argument (`src/index.ts:178`). With the default umask of `0022`, files are created with permissions `0644` (world-readable). The config directory itself is created with `0755` permissions. The credentials file contains the refresh token — a long-lived credential that provides persistent Gmail access without re-authentication.

This is a conventional file permissions vulnerability, but its impact is amplified in the MCP context: if multiple MCP servers run under the same user (a common configuration), any compromised server can read the Gmail credentials.

**F13 (Medium): Plaintext Token Storage.** Beyond file permissions, tokens are stored as raw JSON with no encryption at rest, no rotation, and no session binding. The refresh token never expires unless manually revoked.

**F14 (Medium): CWD Credential Substitution.** On startup, the server checks for `gcp-oauth.keys.json` in the current working directory and silently copies it to the global config, overwriting any existing file (`src/index.ts:104-110`). An attacker who can write to the server's working directory can substitute OAuth credentials, redirecting the authentication flow to an attacker-controlled Google Cloud project.

### 3.2 Prompt Injection via Tool Response (PI-TR) — 1 Finding (Cross-cutting)

**F05 (High): Unsanitised Email Content in Tool Responses.** The `read_email` handler returns raw email content — subject, body, and attachment metadata — directly to the LLM with no sanitisation, escaping, or content boundary markers (`src/index.ts:667`):

```typescript
text: `Thread ID: ${threadId}\nSubject: ${subject}\nFrom: ${from}\n` +
      `To: ${to}\nDate: ${date}\n\n${contentTypeNote}${body}${attachmentInfo}`
```

The `${body}` variable contains the full email text/HTML content, which is attacker-controlled. Similarly, `search_emails` returns unsanitised subject lines (`src/index.ts:700-706`). This creates a direct prompt injection vector: an attacker who sends a specially crafted email to the victim can embed instructions in the email body that the LLM may interpret as commands.

This finding is the linchpin of the audit — it enables all confused deputy attack chains described in Section 3.3. The vulnerability is not a bug in the traditional sense; rather, it reflects a fundamental design challenge in MCP: tool responses that contain untrusted content are indistinguishable from tool responses that contain trusted data. The LLM has no reliable mechanism to separate "this is email content to summarise" from "this is an instruction to follow."

The `search_emails` tool compounds this risk through batch processing: a single search can return up to 50 email subjects, each potentially containing injection payloads. This creates an amplification effect where the probability of successful injection scales with the number of attacker-controlled emails in the mailbox.

### 3.3 Confused Deputy (CD) — 3 Findings

**F06 (High): No Server-Side Confirmation on Destructive Tools.** All 19 tool handlers follow an identical pattern: validate parameters with Zod, execute the Gmail API call, return the result. There is no server-side confirmation prompt, rate limiting, action logging, or distinction between safe (read) and unsafe (delete/send/forward) operations (`src/index.ts:600-1199`). The server delegates all access control to the MCP client.

This design creates a "no server-side security" anti-pattern where the server is a direct, unguarded proxy to the Gmail API. In a multi-server MCP configuration, this means any prompt injection (whether from email content, another MCP server's output, or a crafted document) can trigger destructive actions with no server-side obstacle.

**F08 (High): Persistent Email Forwarding via `create_filter`.** The `create_filter` tool accepts a `forward` parameter that creates a Gmail filter forwarding matching emails to any address. Unlike `send_email` (one-time), filters create persistent surveillance: they run server-side in Gmail, survive MCP server shutdown, operate silently, and can match all email with `criteria.query: "in:anywhere"`. While Gmail API enforcement may require forwarding address verification, label-based staging attacks (filter to label, then search and exfiltrate via `send_email`) and archive/hide attacks (`removeLabelIds: ['INBOX']`) remain fully exploitable.

**F20 (Informational): Missing Safety Context in Tool Descriptions.** Tool descriptions lack security-relevant context. `create_filter` does not mention its forwarding capability; `download_attachment` does not mention filesystem writes; destructive tools lack "confirm with user" hints. Since LLMs use tool descriptions for decision-making, this absence of safety metadata increases the likelihood of unintended tool invocations.

### 3.4 Input Injection (II) — 5 Findings

**F03 (High): Path Traversal in `download_attachment`.** The `download_attachment` handler accepts user-supplied `savePath` and `filename` parameters with no path sanitisation (`src/index.ts:1130-1165`). The handler creates directories recursively via `fs.mkdirSync(savePath, { recursive: true })` and writes attachment content via `fs.writeFileSync(fullPath, buffer)`. An attacker can write arbitrary content to any writable filesystem location.

The exploitation chain combines this with F05 (prompt injection): an attacker sends an email with a malicious attachment (e.g., an SSH public key) and a second email containing injection instructions directing the LLM to download the attachment to `~/.ssh/authorized_keys`.

**F04 (High): Arbitrary File Read via Attachment Paths.** The `send_email` and `draft_email` tools accept an `attachments` parameter — an array of file paths passed directly to Nodemailer (`src/utl.ts:117-128`). The only validation is `fs.existsSync()`. Any file readable by the Node.js process can be attached to an outgoing email. This enables exfiltration of SSH keys, OAuth credentials, AWS credentials, and any other sensitive file on the system.

**F09 (High), F10 (High), F15 (Medium): Validation Gaps.** The `forward` field in filter creation has no email validation. Nodemailer <=7.0.10 contains a vulnerability (GHSA-mm7p-fcc7-pg87) causing emails to be sent to unintended domains. The `cc` and `bcc` fields bypass the `validateEmail()` function applied to the `to` field.

### 3.5 Scope Escalation (SE) — 1 Finding

**F07 (High): Global Token Scope.** The server requests `gmail.modify` and `gmail.settings.basic` at authentication time (`src/index.ts:152-155`). Six of 19 tools only need `gmail.readonly` but operate with full modify permissions. There is no mechanism to enforce least privilege per tool. This means a compromised read-only operation (e.g., `search_emails` processing injected content) can leverage the same token for destructive actions (`delete_email`, `send_email`, `create_filter`).

### 3.6 Supply Chain / Rug Pull (RP) — 3 Findings

**F17 (Low): `mcp-evals` in Production Dependencies.** The `mcp-evals` package (a test harness) is listed in `dependencies` rather than `devDependencies`, pulling the Vercel AI SDK, OpenAI SDK, and several vulnerable transitive dependencies into production. Five of 11 `npm audit` vulnerabilities originate from this dependency tree.

**F18 (Low) and F19 (Low): Dependency Pinning and Lockfile.** All dependencies use caret (`^`) version ranges, and the lockfile is excluded from the published npm package (`"files": ["dist", "README.md"]`). Users installing via `npx` receive non-reproducible builds.

## 4. Discussion

### 4.1 Design vs. Implementation Vulnerabilities

The findings divide into two distinct categories with different root causes and remediation strategies.

**Implementation vulnerabilities** are conventional coding errors that happen to occur in an MCP server: world-readable file permissions (F02), missing path sanitisation (F03, F04), weak email validation (F15), an unregistered callback domain (F01). These have direct analogues in non-MCP systems and could be fixed with standard secure coding practices.

**Design vulnerabilities** are inherent to the MCP interaction model: unsanitised tool responses (F05), the absence of content boundaries between trusted and untrusted data, global token scoping with no per-tool access control (F07), and the delegation of all security to the MCP client (F06). These cannot be fixed by patching the server alone — they require changes to how MCP servers, clients, and the protocol itself handle trust boundaries.

The critical insight is that implementation vulnerabilities become significantly more dangerous in the MCP context. A path traversal vulnerability in a traditional web application requires an attacker to craft a malicious HTTP request. In an MCP server, the same vulnerability can be triggered by an attacker who simply sends an email — the LLM, acting as a confused deputy, translates the attacker's natural-language instructions into the precise API call needed to exploit the path traversal. The attack surface shifts from "can the attacker reach this code path?" to "can the attacker craft content that an LLM will process?"

### 4.2 MCP-Specific vs. Traditional Vulnerability Patterns

Several findings illustrate how traditional vulnerability patterns are transformed by the MCP execution model:

**Path traversal (F03) + prompt injection (F05).** In a traditional application, path traversal requires the attacker to control the HTTP request parameters. In the MCP context, the attacker controls email content, which influences the LLM, which constructs the tool call parameters. The injection chain crosses a trust boundary that does not exist in traditional architectures: attacker → email → LLM → tool parameters → filesystem.

**Credential storage (F02) + multi-server configuration.** World-readable credential files are a standard finding in any security audit. In MCP, the impact is amplified because multiple MCP servers commonly run under the same user. A compromised or malicious MCP server can read credentials stored by other servers, creating a lateral movement vector unique to the MCP ecosystem.

**Filter forwarding (F08) + confused deputy (F06).** Gmail filter creation is a legitimate API operation. In the MCP context, it becomes a mechanism for persistent surveillance: an attacker who achieves a single successful prompt injection can create a filter that forwards all future email indefinitely, without further LLM interaction. The persistence transforms a transient injection into a durable compromise.

**Batch operations (F16) + amplification.** The `batch_delete_emails` tool can permanently delete up to 50 emails per call. In a confused deputy scenario, a single successful prompt injection can trigger irreversible data loss at scale. The batch size has no maximum bound, and there is no confirmation logic.

### 4.3 The "No Server-Side Security" Anti-Pattern

The Gmail MCP Server embodies a design philosophy where the server is a transparent proxy to the underlying API, with all security delegated to the MCP client. This manifests as:

- No confirmation prompts for destructive operations
- No rate limiting on any tool
- No distinction between read-only and write/delete operations
- No audit logging
- No input sanitisation beyond type checking
- No content sanitisation on tool responses
- No per-tool access control

This approach assumes that the MCP client (e.g., Claude Desktop, a CLI tool) will provide human-in-the-loop confirmation for sensitive operations. However, this assumption fails in several scenarios:

1. **`alwaysAllow` configurations.** Users may configure auto-approval for convenience, removing the human from the loop entirely.
2. **Prompt injection bypassing client UI.** If an injected instruction is sufficiently convincing, the LLM may present the action to the user in a way that obscures its true nature.
3. **Batch and chained operations.** A user may approve "search for recent emails" without realising that the search results contain injection payloads that will trigger subsequent tool calls.
4. **Cross-server interactions.** In multi-server configurations, output from one server flows through the LLM to another server with no trust boundary.

The lesson for MCP server developers is that server-side security controls are not optional, even when a client-side approval mechanism exists. Defence in depth requires that each component enforce its own security invariants.

### 4.4 Systemic Risks in the MCP Ecosystem

The findings reveal several systemic risks that extend beyond this individual server:

**Tool descriptions as an implicit attack surface.** MCP tool descriptions are natural-language strings consumed by the LLM to make tool selection and parameter construction decisions. While this server's descriptions are benign, the absence of safety metadata (e.g., "this tool can delete data permanently" or "confirm with the user before invoking") means the LLM has no protocol-level signal about tool risk. Future MCP protocol versions should consider structured safety metadata alongside natural-language descriptions.

**No content boundary specification.** MCP provides no standard mechanism for marking tool response content as "untrusted — do not interpret as instructions." Each server must implement its own content boundary strategy, and the Gmail MCP Server implements none. A protocol-level content tagging system would provide a consistent defence against prompt injection via tool responses.

**Credential isolation.** MCP servers typically store credentials in the user's home directory with no isolation between servers. A standardised, permission-restricted credential store (analogous to the browser's cookie jar) would prevent cross-server credential theft.

**Scope granularity.** OAuth scopes are granted globally at authentication time, with no mechanism for per-tool restriction. The MCP protocol could define a capability model where tools declare their required permissions and the client enforces least privilege.

## 5. Recommendations

### 5.1 For the Gmail MCP Server

1. **Immediate: Remove `gmail.gongrzhe.com` from documentation** and validate callback URLs against an allowlist.
2. **Immediate: Fix credential file permissions** — `mode: 0o600` for files, `mode: 0o700` for directories.
3. **High priority: Add content boundary markers** to `read_email` and `search_emails` responses.
4. **High priority: Restrict `download_attachment`** to a configurable downloads directory with `path.basename()` sanitisation.
5. **High priority: Restrict `send_email` attachments** to an allowlisted directory.
6. **High priority: Add confirmation logic** for destructive operations (`delete_email`, `batch_delete_emails`, `create_filter` with forwarding).
7. **Medium priority: Validate all email address fields** (cc, bcc, forward) with proper format checking.
8. **Medium priority: Move `mcp-evals` to devDependencies** and update vulnerable dependencies.
9. **Low priority: Offer tiered OAuth scopes** (read-only vs. full access).

### 5.2 For the MCP Ecosystem

1. **Protocol-level content tagging.** Define a standard mechanism for marking tool response content as untrusted, enabling clients and LLMs to apply appropriate content boundaries.
2. **Structured tool safety metadata.** Extend tool definitions beyond name/description/schema to include risk classification, required confirmations, and side-effect declarations.
3. **Credential isolation standards.** Define recommended practices for credential storage that prevent cross-server access — restricted file permissions, OS keychain integration, or a centralised credential broker.
4. **Per-tool capability model.** Allow MCP clients to restrict which tools a server can expose based on the user's trust level, with runtime enforcement.
5. **Audit tooling.** Develop static analysis tools that can scan MCP server implementations for common vulnerability patterns (unsanitised tool responses, unvalidated file paths, overly broad scopes).

### 5.3 For Future Research

1. **Empirical prompt injection testing.** This audit prepared injection payloads but did not test them against live LLMs. Future work should measure injection success rates across different LLM models and safety tuning levels.
2. **Cross-server trust confusion.** The CST vulnerability class requires multi-server testing to validate. A systematic study of how LLM context mixing enables cross-server attacks would contribute to the taxonomy.
3. **Longitudinal analysis.** Track how MCP server security evolves as the ecosystem matures — do developers adopt security best practices, or does the "no server-side security" anti-pattern persist?
4. **Formal modelling.** The three-party trust model (user, LLM, MCP server) could be formally specified to identify fundamental security properties and their violation conditions.

## 6. Conclusion

The security analysis of the Gmail MCP Server reveals a system with zero server-side security controls operating in a high-value domain. The 20 identified vulnerabilities span all eight classes in the MCP vulnerability taxonomy, from a critical domain takeover enabling credential theft at scale, to systemic design issues in content trust boundaries.

The most significant finding is not any individual vulnerability but the pattern they collectively illustrate: MCP servers that treat security as the client's responsibility create a fragile trust model that fails under prompt injection, cross-server interaction, and configuration drift. The combination of unsanitised tool responses (returning raw email content to the LLM), overly broad permissions (all tools sharing a single broad-scope token), and the absence of confirmation logic (destructive operations executing unconditionally) creates an environment where a single malicious email can cascade into full account compromise, credential theft, and filesystem manipulation.

These findings are not unique to the Gmail MCP Server — they reflect systemic patterns likely present across the rapidly growing MCP ecosystem. As LLMs increasingly operate as autonomous agents with real-world tool access, the security of MCP server implementations becomes a critical concern. The vulnerability taxonomy and findings presented here provide a foundation for systematic security assessment of MCP servers and inform the design of protocol-level mitigations.

## 7. Responsible Disclosure

In accordance with coordinated vulnerability disclosure principles, the critical finding (F01: OAuth Callback Domain Takeover) and supporting findings were reported to the project author (GongRzhe) via email on 22 February 2026.

The disclosure communication was signed with the researcher's GPG key (fingerprint: `DFF1 28A5 AAF2 75E0 635E 0184 800D 8EAD 078D 6309`) and included a description of the vulnerability, the affected documentation and code component (`README.md:147`, `src/index.ts:126-128`), the impact assessment, and recommended remediation steps. The author was advised to remove the `gmail.gongrzhe.com` callback URL from documentation immediately, register or formally decommission the domain, and validate callback URLs against an allowlist in code.

No further public disclosure of F01 specifics will be made until the author has had a reasonable opportunity to respond and issue a patch, in line with standard responsible disclosure timelines.

---

**Word count:** ~3,800
