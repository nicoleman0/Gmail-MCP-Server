# Phase 1 — Reconnaissance & Surface Mapping

**Date:** 2026-02-21
**Target:** GongRzhe/Gmail-MCP-Server v1.1.11
**Package:** `@gongrzhe/server-gmail-autoauth-mcp`

---

## 1. Architecture Overview

The server is a single-process TypeScript MCP server communicating via stdio (StdioServerTransport). It consists of four source files:

| File | Lines | Role |
|---|---|---|
| `src/index.ts` | 1,210 | Main server: OAuth flow, all 19 tool definitions and handlers, credential I/O |
| `src/label-manager.ts` | 204 | Label CRUD operations (create, update, delete, list, find, getOrCreate) |
| `src/filter-manager.ts` | 187 | Filter CRUD + 6 predefined filter templates |
| `src/utl.ts` | 150 | Email message construction (plain RFC822 + Nodemailer for attachments) |
| `src/evals/evals.ts` | 116 | MCP evaluation harness (uses OpenAI gpt-4; not part of runtime) |
| `setup.js` | 110 | Setup script: generates `mcp-config.json`, prints Claude Desktop config path |

---

## 2. Tool Inventory

The server exposes **19 tools** via `ListToolsRequestSchema`. Every tool uses the same globally-scoped OAuth2 token — there is no per-tool permission enforcement.

### 2.1 Email Operations

| # | Tool Name | Description (exact text fed to LLM) | Parameters | Gmail API Call | Destructive? |
|---|---|---|---|---|---|
| 1 | `send_email` | "Sends a new email" | to[], subject, body, htmlBody?, mimeType?, cc?[], bcc?[], threadId?, inReplyTo?, attachments?[] | `users.messages.send` | **Yes** — sends email externally |
| 2 | `draft_email` | "Draft a new email" | (same as send_email) | `users.drafts.create` | Low — creates draft only |
| 3 | `read_email` | "Retrieves the content of a specific email" | messageId | `users.messages.get` (format: full) | No — read-only |
| 4 | `search_emails` | "Searches for emails using Gmail search syntax" | query, maxResults? | `users.messages.list` + `users.messages.get` (metadata) | No — read-only |
| 5 | `modify_email` | "Modifies email labels (move to different folders)" | messageId, labelIds?[], addLabelIds?[], removeLabelIds?[] | `users.messages.modify` | Medium — can archive/mark read |
| 6 | `delete_email` | "Permanently deletes an email" | messageId | `users.messages.delete` | **Yes** — permanent deletion (not trash) |
| 7 | `batch_modify_emails` | "Modifies labels for multiple emails in batches" | messageIds[], addLabelIds?[], removeLabelIds?[], batchSize? (default: 50) | `users.messages.modify` x N | Medium — bulk label changes |
| 8 | `batch_delete_emails` | "Permanently deletes multiple emails in batches" | messageIds[], batchSize? (default: 50) | `users.messages.delete` x N | **Critical** — bulk permanent deletion |
| 9 | `download_attachment` | "Downloads an email attachment to a specified location" | messageId, attachmentId, filename?, savePath? | `users.messages.attachments.get` | **Yes** — writes arbitrary files to filesystem |

### 2.2 Label Operations

| # | Tool Name | Description | Parameters | Gmail API Call | Destructive? |
|---|---|---|---|---|---|
| 10 | `list_email_labels` | "Retrieves all available Gmail labels" | (none) | `users.labels.list` | No |
| 11 | `create_label` | "Creates a new Gmail label" | name, messageListVisibility?, labelListVisibility? | `users.labels.create` | Low |
| 12 | `update_label` | "Updates an existing Gmail label" | id, name?, messageListVisibility?, labelListVisibility? | `users.labels.update` | Low |
| 13 | `delete_label` | "Deletes a Gmail label" | id | `users.labels.delete` | Medium — removes label |
| 14 | `get_or_create_label` | "Gets an existing label by name or creates it if it doesn't exist" | name, messageListVisibility?, labelListVisibility? | `users.labels.list` + `users.labels.create` | Low |

### 2.3 Filter Operations

| # | Tool Name | Description | Parameters | Gmail API Call | Destructive? |
|---|---|---|---|---|---|
| 15 | `create_filter` | "Creates a new Gmail filter with custom criteria and actions" | criteria{from?, to?, subject?, query?, negatedQuery?, hasAttachment?, excludeChats?, size?, sizeComparison?}, action{addLabelIds?[], removeLabelIds?[], forward?} | `users.settings.filters.create` | **Yes** — can auto-forward all future email |
| 16 | `list_filters` | "Retrieves all Gmail filters" | (none) | `users.settings.filters.list` | No |
| 17 | `get_filter` | "Gets details of a specific Gmail filter" | filterId | `users.settings.filters.get` | No |
| 18 | `delete_filter` | "Deletes a Gmail filter" | filterId | `users.settings.filters.delete` | Medium |
| 19 | `create_filter_from_template` | "Creates a filter using a pre-defined template for common scenarios" | template (enum), parameters{...} | `users.settings.filters.create` | **Yes** — same as create_filter |

### 2.4 Tool Description Assessment

All 19 tool descriptions are short, factual, and benign. None contain injected instructions, hidden prompts, or attempts to manipulate LLM behaviour. This rules out **TDM (Tool Description Manipulation)** from the server author, but does not preclude an attacker who modifies the server post-install.

Notable: the descriptions do not warn the LLM about the destructive nature of operations like `delete_email`, `batch_delete_emails`, or `create_filter` (which can auto-forward email). There are no "are you sure?" confirmation prompts built into the tool handlers.

---

## 3. External Calls Map

### 3.1 Google OAuth2 Endpoints (Expected)

| Endpoint | Context | Reference |
|---|---|---|
| `https://accounts.google.com/o/oauth2/v2/auth` | Authorization URL (generated by `oauth2Client.generateAuthUrl`) | `src/index.ts:151` |
| `https://oauth2.googleapis.com/token` | Token exchange (called by `oauth2Client.getToken`) | `src/index.ts:176` |
| `https://www.googleapis.com/gmail/v1/...` | All Gmail API operations | `src/index.ts:332` (via `google.gmail()`) |

### 3.2 External Callback URL: `gmail.gongrzhe.com` (CRITICAL)

**Reference:** `README.md:146-164` (Cloud Server Authentication section)

The README documents an alternative OAuth callback flow:

```bash
npx @gongrzhe/server-gmail-autoauth-mcp auth https://gmail.gongrzhe.com/oauth2callback
```

**How it works in code** (`src/index.ts:126-128`):

```typescript
const callback = process.argv[2] === 'auth' && process.argv[3]
    ? process.argv[3]
    : "http://localhost:3000/oauth2callback";

oauth2Client = new OAuth2Client(
    keys.client_id,
    keys.client_secret,
    callback  // <-- user-supplied URL becomes the OAuth redirect URI
);
```

**Critical finding:** The callback URL is passed as-is to `OAuth2Client` as the redirect URI. When a user runs the documented command:

1. Google redirects the browser to `https://gmail.gongrzhe.com/oauth2callback?code=AUTH_CODE&scope=...`
2. The **authorization code** is transmitted to `gmail.gongrzhe.com`
3. Whoever controls that domain receives the auth code, which can be exchanged for access + refresh tokens using the same client_id/client_secret

**DNS Investigation Results (2026-02-21):**

| Query | Result |
|---|---|
| `gmail.gongrzhe.com` A record | **NXDOMAIN** (domain does not exist) |
| `gongrzhe.com` A record | **NXDOMAIN** (parent domain does not exist) |
| `gongrzhe.com` WHOIS | No results (domain unregistered or expired) |
| `https://gmail.gongrzhe.com/oauth2callback` connectivity | Connection failed |

**Risk assessment:** The domain `gongrzhe.com` appears to be **unregistered or expired**. This creates a **domain takeover** scenario: any third party can register `gongrzhe.com`, set up a web server at `gmail.gongrzhe.com`, and intercept OAuth authorization codes from users who follow the documented instructions.

Even if the domain was previously controlled by the author, the fact that it is referenced in installation documentation and currently unregistered makes this a **critical vulnerability**. Users who followed these instructions in the past may have had their auth codes routed through this domain.

**Taxonomy classification:** TL (Token/Credential Leakage) + potentially RP (Rug Pull) if intentional

### 3.3 localhost:3000

The default OAuth callback is `http://localhost:3000/oauth2callback`. The server starts an HTTP server on port 3000 during the auth flow (`src/index.ts:147-148`). This is standard for desktop OAuth flows but:
- Port 3000 is a common port (conflict-prone)
- The HTTP server has no CSRF protection
- Any local process can race to bind port 3000 before the auth server

---

## 4. File I/O Map

### 4.1 Reads

| File Path | Code Location | Contents |
|---|---|---|
| `~/.gmail-mcp/gcp-oauth.keys.json` (or `$GMAIL_OAUTH_PATH`) | `src/index.ts:118` | OAuth client_id, client_secret, redirect URIs |
| `./gcp-oauth.keys.json` (current directory) | `src/index.ts:104,107` | Same — checked first, then copied to global path |
| `~/.gmail-mcp/credentials.json` (or `$GMAIL_CREDENTIALS_PATH`) | `src/index.ts:136-137` | OAuth access_token, refresh_token, expiry |
| Attachment file paths (user-supplied) | `src/utl.ts:118` | Files to attach to outgoing emails |

### 4.2 Writes

| File Path | Code Location | Contents | Permissions Set? |
|---|---|---|---|
| `~/.gmail-mcp/` (directory) | `src/index.ts:100` | Config directory | `{ recursive: true }` — **no explicit chmod** |
| `~/.gmail-mcp/gcp-oauth.keys.json` | `src/index.ts:109` | Copied from CWD | `fs.copyFileSync` — **inherits umask, no chmod** |
| `~/.gmail-mcp/credentials.json` | `src/index.ts:178` | OAuth tokens (access + refresh) | `fs.writeFileSync` — **no chmod, default permissions (typically 0644)** |
| `<savePath>/<filename>` (download_attachment) | `src/index.ts:1160-1165` | Downloaded email attachment content | `fs.mkdirSync` + `fs.writeFileSync` — **no path sanitisation, no chmod** |

### 4.3 Credential File Permissions Analysis

**Critical:** Token files are written with default permissions (`fs.writeFileSync` with no mode argument). On most systems with a default umask of `022`, this results in **world-readable files (0644)**:

```
-rw-r--r--  credentials.json   (contains access_token + refresh_token)
-rw-r--r--  gcp-oauth.keys.json (contains client_id + client_secret)
```

Any local user or process can read these files to obtain full Gmail access.

### 4.4 Path Traversal in `download_attachment`

The `download_attachment` tool (`src/index.ts:1110-1185`) accepts user-supplied `savePath` and `filename` parameters:

```typescript
const savePath = validatedArgs.savePath || process.cwd();
let filename = validatedArgs.filename;
// ...
const fullPath = path.join(savePath, filename);
fs.writeFileSync(fullPath, buffer);
```

**No sanitisation** is performed on either parameter. An LLM (or prompt injection) could:
- Set `savePath` to any writable directory (e.g., `/etc/cron.d/`)
- Set `filename` to include path traversal (e.g., `../../.ssh/authorized_keys`)
- Write arbitrary content (the attachment binary) to arbitrary filesystem locations

---

## 5. OAuth Scope Analysis

### 5.1 Scopes Requested

From `src/index.ts:152-155`:

```typescript
scope: [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.settings.basic'
],
```

### 5.2 Scope-to-Tool Mapping

| Scope | Capabilities | Tools That Need It |
|---|---|---|
| `gmail.modify` | Read, send, delete, modify messages and drafts; manage labels | send_email, draft_email, read_email, search_emails, modify_email, delete_email, batch_modify_emails, batch_delete_emails, download_attachment, all label tools |
| `gmail.settings.basic` | Manage filters and settings | create_filter, list_filters, get_filter, delete_filter, create_filter_from_template |

### 5.3 Assessment

**Previous versions** of this server (or documentation references) may have used `https://mail.google.com/` (the broadest possible scope). The current code uses `gmail.modify` + `gmail.settings.basic`, which is more restricted but still very broad:

- `gmail.modify` grants read + write + delete access to **all** messages. There is no way to grant read-only access to some tools while allowing send/delete for others.
- A tool like `search_emails` (read-only) receives the same token as `batch_delete_emails` (destructive).
- The scopes are **granted globally at auth time** — the server has no mechanism to enforce least privilege per tool.
- **`gmail.modify` includes the ability to permanently delete emails** (not just trash), which is used by `delete_email` and `batch_delete_emails` via `users.messages.delete`.

**Taxonomy classification:** SE (Scope Escalation) — the server requests broader permissions than the minimum needed for read-only tools, and provides no per-tool access control.

---

## 6. `autoApprove` / `alwaysAllow` Assessment

### 6.1 In Code

No `autoApprove` or `alwaysAllow` patterns exist anywhere in the server source code. The server does not implement or reference any MCP approval mechanism.

### 6.2 In Configuration Examples

The `mcp-config.json` generated by `setup.js` contains:

```json
{
  "mcpServers": {
    "gmail": {
      "command": "node",
      "args": ["<path>/dist/index.js"]
    }
  }
}
```

**No `autoApprove` or `alwaysAllow` fields are present** in any configuration example in the README, `mcp-config.json`, `llms-install.md`, or `smithery.yaml`.

This means tool approval depends entirely on the MCP client (e.g., Claude Desktop). If a user configures `alwaysAllow: ["send_email", "delete_email"]` on their client, destructive operations would proceed without confirmation — but this is a client-side configuration choice, not something the server encourages.

### 6.3 Implied Risk

While the server doesn't explicitly set `autoApprove`, the lack of any server-side confirmation logic means:
- If the MCP client auto-approves (as some do by default for "safe" operations), destructive tools execute silently
- There is no distinction in the server between safe (read) and unsafe (delete/send) operations
- A confused deputy or prompt injection attack would find no server-side guardrails

---

## 7. Dependency Inventory

### 7.1 Runtime Dependencies

| Package | Version | Pinning | Role | Security-Relevant? |
|---|---|---|---|---|
| `@modelcontextprotocol/sdk` | `^0.4.0` | Caret (minor+patch) | MCP protocol implementation | Yes — defines transport, tool schemas |
| `google-auth-library` | `^9.4.1` | Caret | OAuth2 client | Yes — handles token exchange |
| `googleapis` | `^129.0.0` | Caret | Gmail API client | Yes — all API calls |
| `nodemailer` | `^7.0.3` | Caret | RFC822 message construction for attachments | Medium — processes file paths |
| `open` | `^10.0.0` | Caret | Opens browser for OAuth | Low |
| `zod` | `^3.22.4` | Caret | Schema validation | Medium — input validation |
| `zod-to-json-schema` | `^3.22.1` | Caret | JSON schema generation | Low |
| `mime-types` | `^3.0.1` | Caret | MIME type lookup | Low |
| `@types/mime-types` | `^2.1.4` | Caret | TypeScript types | No (types only) |
| `mcp-evals` | `^1.0.18` | Caret | Evaluation framework | **Anomalous** — runtime dependency but only used in evals |

### 7.2 Dev Dependencies

| Package | Version | Role |
|---|---|---|
| `@types/node` | `^20.10.5` | TypeScript types |
| `@types/nodemailer` | `^6.4.17` | TypeScript types |
| `typescript` | `^5.3.3` | Compiler |

### 7.3 Pinning Strategy

**All dependencies use caret (`^`) version ranges**, meaning minor and patch updates are automatically accepted. No lockfile was examined. This is standard for npm packages but means:
- A compromised minor version of any dependency (especially `googleapis`, `google-auth-library`, `@modelcontextprotocol/sdk`) would be automatically pulled
- No `npm audit` was run as part of this phase (deferred to Phase 2)

### 7.4 Notable Observations

1. **`mcp-evals` in production dependencies:** This package (which depends on OpenAI SDK, `@ai-sdk/openai`) is listed in `dependencies` rather than `devDependencies`. It is only used by `src/evals/evals.ts` (test harness) but ships in the production build. This unnecessarily increases the attack surface.

2. **No `package-lock.json` in repository:** The Dockerfile references `package-lock.json*` (with glob), suggesting it may or may not exist. Without a lockfile, builds are non-reproducible and vulnerable to dependency confusion.

---

## 8. Summary of Key Attack Surface Areas

| # | Area | Severity | Taxonomy | Detail |
|---|---|---|---|---|
| **S1** | `gmail.gongrzhe.com` domain takeover | **Critical** | TL | Domain is NXDOMAIN; anyone can register it and capture OAuth auth codes from users following README instructions |
| **S2** | Credential files written world-readable | **High** | TL | `credentials.json` (containing refresh token) written with default 0644 permissions |
| **S3** | Path traversal in `download_attachment` | **High** | II | User-controlled `savePath` and `filename` with no sanitisation allow writing to arbitrary paths |
| **S4** | No per-tool access control | **High** | SE, CD | All tools share one broad-scope token; no server-side confirmation for destructive ops |
| **S5** | `create_filter` can auto-forward email | **High** | CD | The `forward` action in filter creation can silently redirect all future email to an attacker address |
| **S6** | Prompt injection via email content | **High** | PI-TR | `read_email` returns raw email body to LLM; malicious email content could hijack tool calls |
| **S7** | Batch operations amplify blast radius | **Medium** | CD | `batch_delete_emails` can permanently delete 50 emails per call with no confirmation |
| **S8** | OAuth callback URL injection | **Medium** | TL | Any URL passed as argv[3] becomes the OAuth redirect URI; no validation |
| **S9** | `mcp-evals` in production deps | **Low** | RP | Unnecessary attack surface in production; pulls in OpenAI SDK |
| **S10** | Caret version pinning, no lockfile | **Low** | RP | Non-reproducible builds; vulnerable to dependency confusion |

---

## 9. Files for Phase 2 Deep Analysis

The following files warrant detailed static analysis:

1. **`src/index.ts`** — OAuth flow (lines 96-191), credential I/O (lines 96-143, 178), download_attachment handler (lines 1110-1185), all tool handlers
2. **`src/utl.ts`** — Email construction (attachment file path handling, lines 117-128)
3. **`src/filter-manager.ts`** — Filter creation with `forward` action (lines 38-57)
4. **`package.json`** — Dependency versions and pinning
5. **`README.md`** — `gmail.gongrzhe.com` documentation (lines 141-180)
