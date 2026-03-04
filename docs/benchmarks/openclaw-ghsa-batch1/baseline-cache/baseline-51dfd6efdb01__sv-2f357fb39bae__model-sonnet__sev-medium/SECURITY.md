# Security Architecture

## Overview

Clawdbot is a multi-channel AI gateway bot. It connects messaging platforms (WhatsApp, Telegram, Discord, Slack, Signal, iMessage, Microsoft Teams, Matrix, Zalo, and others via extension plugins) to AI model providers (Anthropic Claude, OpenAI, Groq, Deepgram, MiniMax, Qwen, GitHub Copilot proxy, and local models via Ollama/node-llama-cpp). The system runs a local gateway daemon that orchestrates message routing, AI agent invocations, session management, tool execution, and an optional OpenAI-compatible HTTP API surface.

The codebase is a TypeScript/Node.js monorepo with companion native apps for macOS, iOS, and Android. A Swift sub-package (`Swabble`) provides voice-wake/transcription functionality.

---

## Architecture

```
+------------------+        WebSocket (ws:/wss:)        +---------------------+
|  macOS / iOS /   |<--------------------------------->  |                     |
|  Android Clients |                                     |   Gateway Daemon    |
+------------------+        HTTP REST (OpenAI compat)    |   (Node.js/ESM)     |
                             /v1/chat/completions         |   port 18789        |
+------------------+         /v1/responses               |                     |
|  External Hooks  |-------> HTTP POST /hooks/...        |  +---------------+  |
+------------------+                                     |  | Auth module   |  |
                                                         |  +-------+-------+  |
+-------------------------------+                        |          |           |
| Messaging Channels (inbound)  |   internal dispatch   |  +-------v-------+  |
|  WhatsApp (Baileys web proto) |<--------------------> |  | Agent Runner  |  |
|  Telegram (grammy)            |                        |  | (pi-agent-   |  |
|  Discord (carbon/@buape)      |                        |  |  core)        |  |
|  Slack (bolt)                 |                        |  +-------+-------+  |
|  Signal, iMessage (native)    |                        |          |           |
|  MS Teams, Matrix (plugins)   |                        |  +-------v-------+  |
+-------------------------------+                        |  | Tool executor |  |
                                                         |  | (web, browser,|  |
+-------------------------------+                        |  |  bash, FS)    |  |
| AI Providers (outbound)       |<--------------------> |  +---------------+  |
|  Anthropic, OpenAI, Groq, etc.|                        |                     |
|  Local (Ollama, node-llama)   |                        |  +---------+------+ |
+-------------------------------+                        |  |  State  |Config| |
                                                         |  | (~/.clawdbot)  | |
                                                         +---------------------+
                                                                    |
                                                           Tailscale (optional)
                                                           serve / funnel mode
```

**Key architectural boundaries:**

1. The Gateway daemon is the single choke-point for all inbound channel traffic and all outbound AI calls.
2. Messaging channels communicate inward; AI providers receive outbound requests.
3. The HTTP layer is multiplexed on a single port alongside the WebSocket control-plane.
4. Native mobile/macOS nodes connect back to the Gateway via the same WebSocket port, registering device commands.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 22+ (ESM), Bun (dev/test) |
| Language | TypeScript (strict) |
| HTTP server | Node.js `http`/`https`, Express 5, Hono 4 |
| WebSocket | `ws` 8 |
| WhatsApp | `@whiskeysockets/baileys` (WhatsApp Web protocol) |
| Telegram | `grammy` + `@grammyjs/runner` |
| Discord | `@buape/carbon` |
| Slack | `@slack/bolt` + `@slack/web-api` |
| AI agent core | `@mariozechner/pi-agent-core`, `@mariozechner/pi-ai` |
| Schema validation | `@sinclair/typebox`, `ajv`, `zod` |
| Browser automation | Playwright Core 1.57, Chromium BiDi |
| Vector/memory | `sqlite-vec`, `node-llama-cpp` (optional) |
| Config format | JSON5 |
| Scheduling | `croner` |
| macOS app | Swift / SwiftUI (separate Xcode project) |
| iOS app | Swift / SwiftUI |
| Android app | Kotlin / Jetpack Compose |
| Voice (Swabble) | Swift, macOS/iOS SpeechRecognition framework |
| TLS | Node.js `tls`, auto-generated self-signed cert option |
| Service discovery | mDNS via `@homebridge/ciao` (Bonjour) |
| Network mesh | Tailscale (optional: serve or funnel mode) |

---

## Entry Points

### WebSocket API (`ws://` / `wss://`)
- **Default port:** 18789 (configurable via `gateway.port` or `CLAWDBOT_GATEWAY_PORT`)
- Carries the primary control-plane protocol (JSON frames, TypeBox-validated)
- Used by macOS, iOS, Android native clients, and the TUI
- Authenticated via token, password, Tailscale identity headers, or device-token
- Max incoming frame size: 512 KB (`MAX_PAYLOAD_BYTES`)
- Handshake timeout: 10 seconds

### HTTP: OpenAI-compatible Chat Completions
- `POST /v1/chat/completions` — enabled via `gateway.http.endpoints.chatCompletions.enabled`
- Accepts Bearer token (same auth as WS)
- Body size limit: 1 MB default
- Supports streaming (SSE) and non-streaming modes

### HTTP: OpenResponses API
- `POST /v1/responses` — enabled via `gateway.http.endpoints.responses.enabled`
- Accepts Bearer token
- Body size limit: 20 MB default; per-file limit 5 MB; per-image limit 10 MB
- Supports file and image inputs (URL fetch with configurable redirect/timeout limits)

### HTTP: Webhook Hooks Endpoint
- `POST /<hooks.path>/wake` — triggers the agent from an external event
- `POST /<hooks.path>/agent` — dispatches a full agent message with optional delivery
- `POST /<hooks.path>/<custom-sub>` — custom mapping rules (config-driven)
- Protected by a shared secret token (`hooks.token` or query parameter `?token=`)
- Body size limit: configurable (`maxBodyBytes`)

### HTTP: Slack Events / Interactions
- Receives Slack event payloads via HTTP POST (handled by `@slack/bolt`)

### HTTP: Control UI
- Served at `/` or configurable `gateway.controlUi.basePath`
- Web-based dashboard for config, sessions, and agent management
- No separate auth beyond gateway-level auth

### HTTP: Canvas / A2UI Host
- Serves the canvas host UI and A2UI bundle on the same port
- WebSocket upgrade handled for live-reload

### CLI Commands
- `clawdbot gateway` — start the local gateway daemon
- `clawdbot agent` — invoke the AI agent directly (bypasses channel routing)
- `clawdbot message send/read/edit/delete` — direct message management
- `clawdbot security audit` / `clawdbot security fix` — built-in security scanning
- `clawdbot login` — interactive credential flow
- `clawdbot doctor` — health/diagnostic checks

### External Webhooks (Inbound)
- Telegram bot webhook or long-polling
- Discord gateway WS
- Slack Events API over HTTP
- MS Teams / Matrix via extension plugins

---

## Authentication & Authorization

### Gateway Connection Authentication

The Gateway supports three authentication modes (configured via `gateway.auth.mode`):

| Mode | Mechanism | Notes |
|---|---|---|
| `token` | Static Bearer token compared with `timingSafeEqual` | Recommended; token sourced from config or `CLAWDBOT_GATEWAY_TOKEN` env |
| `password` | Shared password compared with `timingSafeEqual` | Sourced from config or `CLAWDBOT_GATEWAY_PASSWORD` env; audit warns if stored in config file |
| `none` | No credential required | Blocked with a critical audit finding if `gateway.bind` is not `loopback` |

Tailscale identity-header bypass is also supported when `gateway.tailscale.mode="serve"` and `auth.allowTailscale=true`. The gateway verifies that the request arrived from a loopback address (i.e., the Tailscale proxy) and that the `tailscale-user-login` header is present and the `x-forwarded-for` / `x-forwarded-proto` / `x-forwarded-host` headers are set.

Loopback-only connections (`127.0.0.1`, `::1`, `::ffff:127.*`) to `localhost` without any proxy-forwarding headers bypass auth entirely when `allowTailscale` is false and mode is `none`.

Device-token authentication (v1/v2) is also present for node registration (`src/gateway/device-auth.ts`). Device auth payloads include `deviceId`, `clientId`, `role`, `scopes`, and a timestamp, joined with pipe delimiters.

### Channel Authorization

Each messaging channel has an allow-from model:

- **allowFrom list** — explicit user IDs or phone numbers that can DM the bot
- **groupPolicy** — `"allowlist"` (require per-group allow-from list) or `"open"` (any group member can interact; flagged as critical risk in audit)
- **Pairing store** — runtime-approved pairs stored in the state directory, appended to the allow-from list

The audit system (`src/security/audit.ts`) actively checks for:
- Open DM policies (critical)
- Wildcard `*` in allow-from lists (critical)
- Missing allowlists on group commands (critical)
- Multi-user DM sessions sharing a single session (warn)
- Discord/Slack slash commands enabled without access groups (critical)
- Telegram group access without sender allowlists (critical)

### Tool & Exec Authorization

Tool access is controlled through layered policies:

1. **Tool profile** (`tools.profile`) — maps to a named allow/deny set
2. **Global allow/deny** (`tools.allow`, `tools.deny`)
3. **Per-agent allow/deny** (`agents.list[].tools`)
4. **Sandbox enforcement** — Docker-based sandboxing for filesystem-touching tools

Elevated tool mode (`tools.elevated`) requires an explicit per-channel `allowFrom` list. Wildcards in the elevated allowlist produce a critical audit finding.

Node commands (from connected native clients) are controlled by a platform-based allowlist (`src/gateway/node-command-policy.ts`). Each platform (iOS, Android, macOS, Linux, Windows) has a default set; extra commands can be added or denied via `gateway.nodes.allowCommands`/`denyCommands`.

Exec approvals require an out-of-band decision via the `ExecApprovalManager`; each pending approval has a UUID and times out.

---

## Data Flow

### 1. Inbound Messaging Channel to Agent

```
Messaging platform
  → Channel adapter (Telegram/WhatsApp/Discord/Slack/…)
  → Allow-from check (allowFrom list + pairing store)
  → Group policy check (allowlist / open)
  → Mention gating (requireMention flag)
  → Session key resolution (per-channel-peer or main)
  → Message queue (auto-reply queue)
  → Agent runner (pi-agent-core)
  → AI provider API (Anthropic / OpenAI / etc.)
  → Response delivery (channel adapter)
```

Sensitive data in this flow: message content (potentially private), user identifiers (phone numbers, user IDs), AI provider API keys (used outbound only).

### 2. External Hook to Agent

```
External system (HTTP POST to /hooks/…)
  → Token verification (shared secret, timing-safe compare)
  → Payload normalization (normalizeAgentPayload / normalizeWakePayload)
  → Optional mapping rules (hook mappings config)
  → Agent dispatch (async, returns runId immediately)
  → Agent runner
  → Optional delivery back to a channel
```

### 3. OpenAI-Compatible HTTP to Agent

```
Client (HTTP POST /v1/chat/completions or /v1/responses)
  → Bearer token auth (authorizeGatewayConnect)
  → JSON body parse (size-limited)
  → Message extraction / sanitization (stripEnvelopeFromMessages)
  → Session key derivation (IP + agent ID + user field)
  → Agent runner
  → SSE stream or JSON response
```

### 4. WebSocket Control-Plane (native clients)

```
Native client (macOS/iOS/Android)
  → WebSocket connect + handshake
  → Device-token or gateway-token auth
  → Node registration (platform, deviceFamily, declared commands)
  → Bidirectional JSON frame exchange (TypeBox-validated schema)
  → Node command execution (camera, screen, location, system.run, etc.)
    subject to node command policy allowlist
```

### 5. Config and Secrets Flow

```
~/.clawdbot/clawdbot.json (JSON5, chmod 600 recommended)
  → Config I/O loader (JSON5 parse → $include resolution → env var substitution)
  → Auth profiles resolved: ~/.clawdbot/agents/<id>/agent/auth-profiles.json
  → Credentials directory: ~/.clawdbot/credentials/oauth.json
  → Gateway runtime holds resolved secrets in memory only
```

---

## Sensitive Data

| Data Type | Storage Location | Notes |
|---|---|---|
| AI provider API keys | `~/.clawdbot/agents/<id>/agent/auth-profiles.json` | JSON, mode 600 recommended; also accepted via env vars |
| OAuth access/refresh tokens | `~/.clawdbot/credentials/` | Per-provider OAuth credentials |
| Gateway auth token/password | Config file or `CLAWDBOT_GATEWAY_TOKEN`/`CLAWDBOT_GATEWAY_PASSWORD` env | Audit warns if password stored in config |
| WhatsApp session keys | `~/.clawdbot/sessions/` | Baileys multi-file auth state |
| Chat transcripts / session logs | `~/.clawdbot/agents/<id>/sessions/*.jsonl` | Can contain message content from all channels |
| Telegram bot token | Config or `TELEGRAM_BOT_TOKEN` env | |
| Discord bot token | Config or `DISCORD_BOT_TOKEN` env | |
| Slack bot/app tokens | Config or `SLACK_BOT_TOKEN`/`SLACK_APP_TOKEN` env | |
| ElevenLabs API key | Config (`talk.apiKey`) or `ELEVENLABS_API_KEY` env | TTS service |
| Web search API keys | Config (`tools.web.search.apiKey`) or `BRAVE_API_KEY`/`PERPLEXITY_API_KEY`/`OPENROUTER_API_KEY` env | |
| Hooks shared secret | Config (`hooks.token`) | Audit warns if reused as gateway token |
| Browser control token | Config (`browser.controlToken`) or `CLAWDBOT_BROWSER_CONTROL_TOKEN` env | Audit warns if reused |
| TLS private key | Config (`gateway.tls.keyPath`) or auto-generated | Stored on local filesystem |
| User phone numbers / identifiers | Channel pairing store and session logs | PII |
| Message content | In-memory during processing, persisted in session transcripts | Potentially confidential |

**Logging redaction:** When `logging.redactSensitive` is not `"off"`, sensitive tool-call data is redacted from logs. Disabling this (`"off"`) is flagged as a warning in the security audit.

---

## External Dependencies

### Messaging Platform Dependencies

| Dependency | Purpose | Notes |
|---|---|---|
| `@whiskeysockets/baileys` | WhatsApp Web protocol | Maintains long-lived WebSocket to WhatsApp; session keys stored locally |
| `grammy` + `@grammyjs/runner` | Telegram Bot API | Polling or webhook |
| `@buape/carbon` | Discord bot framework | |
| `@slack/bolt` + `@slack/web-api` | Slack Events + Web API | |
| Signal, iMessage | Native OS bridges | Platform-specific, not in npm |

### AI Provider Dependencies

| Provider | Auth Method |
|---|---|
| Anthropic | API key |
| OpenAI / GitHub Copilot proxy | API key / OAuth token |
| Groq | API key |
| Deepgram | API key |
| MiniMax | API key |
| Qwen portal | OAuth |
| Ollama | Local HTTP (no auth by default) |
| node-llama-cpp | Local, no network |

### Infrastructure Dependencies

| Dependency | Purpose | Risk Notes |
|---|---|---|
| `playwright-core` + `chromium-bidi` | Browser automation tool | Remote code execution surface; controlled via tool policy |
| `@lydell/node-pty` | PTY/subprocess execution | Shell execution surface; controlled via tool policy + sandbox |
| `sqlite-vec` | Vector memory store | Local SQLite + native extension |
| `@homebridge/ciao` | mDNS/Bonjour service discovery | Advertises gateway on local network |
| `pdfjs-dist` | PDF parsing | Parses uploaded PDFs; size/page limits enforced |
| `sharp` | Image processing | Processes uploaded images |
| `tar` 7.5.4 | Archive handling | Version pinned via pnpm override |
| `hono` 4.11.4 | HTTP framework | Version pinned via pnpm override |
| `ajv` | JSON Schema validation | Used for TypeBox schema validation |
| `undici` | HTTP client | Used for outbound URL fetching in responses API |

---

## Security Controls

### Input Validation

- All WebSocket frames are validated against TypeBox schemas on receipt
- HTTP JSON bodies are size-limited before parsing (1 MB for chat completions; 20 MB for responses; configurable)
- Per-file and per-image byte limits enforced in the responses API (5 MB / 10 MB defaults)
- PDF parsing is limited by max pages (4 default) and max pixels (4M default)
- URL fetches for file/image inputs have redirect limits (3 default) and timeouts (10 s default)
- Message content sanitization strips internal envelope headers to prevent spoofing channel attribution

### Authentication Security

- Token and password comparisons use Node.js `crypto.timingSafeEqual` to prevent timing attacks
- Tokens shorter than 24 characters produce a warning in the security audit
- Token reuse across gateway, hooks, and browser-control endpoints is detected and warned

### Authorization Controls

- Channel allow-from lists and group policies gate all inbound message processing
- Elevated tool mode requires a separate per-channel allowlist
- Node commands (from native clients) are restricted to a platform-specific allowlist; extension via config is possible but must be explicit
- Exec approvals provide a human-in-the-loop gate for sensitive shell operations
- Access group enforcement for Discord and Slack slash commands

### Transport Security

- TLS support for the gateway server (`gateway.tls`) with optional auto-generated self-signed certificate
- TLS fingerprint pinning for remote gateway connections (`gateway.remote.tlsFingerprint`)
- Tailscale integration for zero-config VPN-level transport (serve mode: tailnet only; funnel mode: public internet — flagged as critical)
- Loopback-only binding is the default (`gateway.bind="loopback"`) and the safest mode

### Filesystem Security

- Built-in `security audit` command checks permissions of state dir, config file, credentials dir, auth-profiles, and session store
- Built-in `security fix` command auto-applies `chmod 600` / `chmod 700` to sensitive paths
- Warns if state/config resides in cloud-synced directories (iCloud, Dropbox, OneDrive, Google Drive)
- Symlink detection on critical paths

### Secrets Management

- Config supports `${ENV_VAR_NAME}` substitution at load time; missing variables throw errors
- Audit detects secrets stored directly in the config file and recommends environment variables
- Credentials are kept in a dedicated `credentials/` subdirectory separate from general state

### Sandboxing

- Docker-based sandbox mode (`agents.defaults.sandbox.mode`) can isolate tool execution
- Sandbox tool policies allow/deny specific tools per agent
- Small models (below a parameter threshold) with web or browser tools exposed are flagged as critical risk

### Rate Limiting / DoS Protections

- WS frame cap: 512 KB max payload per frame
- Per-connection send buffer cap: 1.5 MB
- Handshake timeout: 10 seconds
- HTTP body size limits on all inbound endpoints
- Deduplication of events: TTL 5 minutes, max 1000 entries

### Logging

- Sensitive tool output is redacted by default (`logging.redactSensitive="tools"`)
- Log file permissions are audited; world/group-readable log files are flagged

### Plugin Trust

- Extensions loaded from `~/.clawdbot/extensions/` are audited for the presence of `plugins.allow` allowlist
- Absence of an allowlist when native skill commands are exposed is flagged critical

### Model Security

- Audit checks for legacy models (GPT-3.5, Claude 2/Instant, old GPT-4 snapshots) — flagged as warn
- Audit checks for small models (<= 300B parameters) paired with web/browser tools and no sandboxing — flagged critical
- Audit recommends modern, instruction-hardened models for bots with tools or untrusted inboxes

---

## Notes

### High-Priority Attack Surface Observations

1. **Open group policy with elevated tools:** If `groupPolicy="open"` is set on any channel while `tools.elevated` is enabled, a prompt injection from any group member becomes a critical incident. The audit system flags this combination explicitly.

2. **Tailscale funnel mode:** Enabling `gateway.tailscale.mode="funnel"` exposes the gateway to the public internet. This is flagged critical. Only `"serve"` (tailnet-only) is recommended for remote access.

3. **Browser automation and PTY:** Both Playwright-based browser control and PTY/subprocess execution (via `@lydell/node-pty`) are high-impact tool surfaces. They are governed by tool policies and can be further restricted via `tools.deny=["group:web","browser"]`.

4. **WhatsApp session persistence:** Baileys WhatsApp sessions contain long-lived credentials stored on disk. These should be in the state directory with restricted permissions.

5. **Config file includes:** The config supports recursive `$include` directives. Writable include files are flagged critical because they can influence the effective configuration without modifying the main config file.

6. **Hook endpoint SSRF risk:** The `input_file` and `input_image` fields in the OpenResponses API perform outbound URL fetches. Redirect limits, MIME-type allowlists, and timeout controls are configurable but may require tightening in high-trust deployments.

7. **Session isolation for DMs:** Multiple DM senders sharing the same `main` session (`session.dmScope="main"`) can leak conversation context across users. The audit flags this with a warning and recommends `"per-channel-peer"`.

8. **No rate limiting on hooks or HTTP endpoints:** The codebase does not implement rate limiting on the hooks or OpenAI-compat HTTP endpoints. In internet-facing deployments, a reverse proxy with rate limiting is strongly advised.

9. **Canvas eval command:** `canvas.eval` is included in the node command allowlist for macOS, iOS, and Android platforms. This command can execute arbitrary code on the connected device and should be carefully controlled via `gateway.nodes.denyCommands` if not needed.

10. **Token length enforcement:** The audit enforces a minimum length of 24 characters for gateway tokens and hooks tokens. Tokens shorter than this generate a warning but are not rejected at runtime.
