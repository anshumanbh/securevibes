# Security Architecture

## Overview

Clawdbot is a multi-platform AI agent gateway that bridges messaging platforms (WhatsApp, Telegram, Slack, Discord, iMessage, Signal, Microsoft Teams) with AI model providers (Anthropic Claude, OpenAI, Google Gemini, Groq, Mistral, xAI, MiniMax, and others). The system runs as a persistent local daemon exposing a WebSocket gateway, an HTTP server, and an OpenAI-compatible chat completions endpoint. Mobile and desktop companion apps (iOS, Android, macOS menubar) communicate with the local gateway over the WebSocket protocol. An embedded agentic subsystem ("Pi") can execute shell commands, read and write files, control browsers, spawn sub-agents, and send messages across all connected providers.

---

## Architecture

```
                        ┌──────────────────────────────────────────────────────────┐
                        │                  Clawdbot Gateway (Node.js/Bun)           │
                        │                                                            │
  ┌────────────┐        │  ┌──────────┐  ┌───────────┐  ┌─────────────────────┐   │
  │ iOS app    │──WS────│  │ WebSocket│  │ HTTP/SSE  │  │  Hooks HTTP server  │   │
  │ Android app│        │  │ server   │  │ (OpenAI   │  │  POST /hooks/{path} │   │
  │ macOS app  │        │  │          │  │ compat.)  │  │  (token-gated)      │   │
  │ Web UI     │        │  └────┬─────┘  └─────┬─────┘  └──────────┬──────────┘   │
  └────────────┘        │       │               │                   │              │
                        │  ┌────▼───────────────▼───────────────────▼──────────┐   │
                        │  │          Gateway Server (server.ts)                │   │
                        │  │  auth / session mgmt / config reload / cron       │   │
                        │  └──────────────────┬─────────────────────────────────┘   │
                        │                     │                                      │
                        │  ┌──────────────────▼──────────────────────────────────┐  │
                        │  │              Agent Layer (pi-embedded)               │  │
                        │  │  exec/process tools, read/write/edit, browser ctrl  │  │
                        │  └──────────┬────────────────────────────┬─────────────┘  │
                        │             │                            │                 │
                        │  ┌──────────▼────────────┐   ┌──────────▼──────────────┐  │
                        │  │  Messaging Providers  │   │   AI Model Providers    │  │
                        │  │  WhatsApp (Baileys)   │   │   Anthropic, OpenAI,    │  │
                        │  │  Telegram (grammY)    │   │   Google, Groq, etc.    │  │
                        │  │  Slack (@slack/bolt)  │   └─────────────────────────┘  │
                        │  │  Discord (Carbon)     │                                 │
                        │  │  iMessage, Signal,    │                                 │
                        │  │  MS Teams             │                                 │
                        │  └───────────────────────┘                                 │
                        └──────────────────────────────────────────────────────────┘
```

**Trust boundaries:**
- Local loopback (127.0.0.1): trusted by default for gateway WebSocket and HTTP access
- Tailscale network: optionally trusted via Tailscale serve/funnel headers (`tailscale-user-login`, etc.)
- LAN / 0.0.0.0 binding: optionally enabled, expands the attack surface significantly
- External AI providers: trusted third-party API endpoints over HTTPS
- Messaging platform APIs: trusted third-party endpoints; inbound message content is untrusted

---

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 22+ / Bun (TypeScript ESM) |
| CLI framework | Commander |
| Gateway protocol | WebSocket (`ws` 8.x) + HTTP (`express` 5.x) |
| WhatsApp | `@whiskeysockets/baileys` 7.0.0-rc.9 (multi-device) |
| Telegram | `grammy` |
| Slack | `@slack/bolt`, `@slack/web-api` |
| Discord | `@buape/carbon`, `discord-api-types` |
| MS Teams | `@microsoft/agents-hosting*` |
| Agent core | `@mariozechner/pi-agent-core`, `pi-coding-agent`, `pi-ai` |
| Config validation | Zod 4.x + AJV |
| Credential storage | macOS Keychain (`security` CLI), JSON files |
| Scheduling | `croner` |
| Media processing | `sharp`, `file-type` |
| Browser automation | `playwright-core`, `chromium-bidi` |
| Service discovery | `@homebridge/ciao` (mDNS/Bonjour) |
| Locking | `proper-lockfile` |
| Logging | `tslog` |
| Package manager | pnpm 10.x (with Bun interop) |
| Mobile: iOS | Swift / SwiftUI |
| Mobile: Android | Kotlin / Gradle |
| Desktop: macOS | Swift / SwiftUI (menubar) |
| Voice capture | Swift (Swabble subdirectory) |

---

## Entry Points

### WebSocket Gateway (`src/gateway/server.ts`)
- Default port: 18789 (configurable via `CLAWDBOT_GATEWAY_PORT` or `gateway.port`)
- Default bind host: `127.0.0.1` (loopback only). Configurable to `0.0.0.0` (LAN) or Tailscale IP.
- Protocol: custom JSON-framed RPC over WebSocket with a 10-second handshake timeout.
- Frame size cap: 512 KB inbound / 1.5 MB per-connection send buffer.
- Authentication enforced at connection time via `authorizeGatewayConnect()`.

### HTTP Server (same port)
- `POST /v1/chat/completions` — OpenAI-compatible endpoint (when `gateway.openaiChatCompletions.enabled`)
- `POST /hooks/{path}/wake` — Webhook to trigger agent wake (token-gated)
- `POST /hooks/{path}/agent` — Webhook to run agent turns (token-gated)
- `GET /control-ui/*` — Web control panel static assets
- Canvas host (a2ui) endpoints for the browser-based canvas feature

### Inbound Messaging (Provider-Specific)
- WhatsApp: Baileys WebSocket connection to WhatsApp servers, inbound messages processed per-account
- Telegram: grammY polling/webhook
- Slack: Slack Bolt app socket mode or webhook
- Discord: Discord gateway via Carbon
- iMessage: macOS-only, AppleScript/local bridge
- Signal: local Signal CLI bridge
- MS Teams: `@microsoft/agents-hosting-express`
- Gmail: Google Pub/Sub push to a local HTTP listener (configurable port, default 8788)

### CLI (`src/entry.ts`)
- `clawdbot gateway` — start gateway daemon
- `clawdbot agent` — run agent turn (RPC or direct)
- `clawdbot login` — credential setup wizard
- `clawdbot message send` — send outbound message
- `clawdbot status` — status/health queries
- Various sub-commands for config management, provider setup, etc.

---

## Authentication & Authorization

### Gateway Connection Auth (`src/gateway/auth.ts`)

Three modes selectable in `gateway.auth.mode`:

| Mode | Mechanism | Notes |
|---|---|---|
| `none` | No credential required for loopback connections | Default when no token/password is configured |
| `token` | Static bearer token (`CLAWDBOT_GATEWAY_TOKEN` or `gateway.auth.token`) | Compared with string equality (NOT timing-safe for the token mode) |
| `password` | Static password | Compared with `timingSafeEqual` (constant-time) |

Tailscale auth is a supplementary mode: when `gateway.auth.allowTailscale` is enabled, connections arriving via the Tailscale serve proxy (identified by `tailscale-user-login` / `x-forwarded-for` headers from loopback) are authenticated as the Tailscale user without needing a token or password.

**Notable issues:**
- In `token` mode, the comparison at line 174 of `src/gateway/auth.ts` uses `!==` (a non-constant-time string comparison). This is susceptible to timing-based token extraction for sufficiently fast local or network connections. Only the `password` mode uses `timingSafeEqual`.
- The default mode is `none`, meaning any process on the same machine (or any LAN host when bind is `0.0.0.0`) can connect to the gateway without credentials unless explicitly configured.

### AI Provider Auth (`src/agents/auth-profiles.ts`, `src/agents/model-auth.ts`)

- API keys stored in `~/.clawdbot/credentials/auth-profiles.json` (file-locked with `proper-lockfile`).
- OAuth tokens (Anthropic, OpenAI Codex) stored via macOS Keychain on Darwin; fall back to `~/.claude/.credentials.json` or `~/.codex/auth.json`.
- Secret retrieval from macOS Keychain uses `execSync` with the `security` CLI binary.
- Environment variables are also scanned: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY`, `XAI_API_KEY`, `OPENROUTER_API_KEY`, `MINIMAX_API_KEY`, `CEREBRAS_API_KEY`, `COPILOT_GITHUB_TOKEN`, `ZAI_API_KEY`, `OPENCODE_API_KEY`.
- Credentials are loaded from `~/.clawdbot/.env` and the process working directory `.env` via `dotenv`.

### Messaging Provider Auth

- WhatsApp (Baileys): multi-device auth state persisted locally in `~/.clawdbot/` as multi-file auth; QR code pairing in setup
- Telegram: bot token stored in config JSON
- Slack: bot token + app token stored in config JSON
- Discord: bot token stored in config JSON
- iMessage: uses native macOS Messages app (no credentials needed)
- Signal: local Signal CLI; credentials managed externally
- MS Teams: Microsoft identity tokens handled by `@microsoft/agents-hosting`

### Inbound Message Authorization (Messaging Providers)

- WhatsApp: `dmPolicy` (`pairing`, `allowlist`, `open`, `disabled`) and `allowFrom` / `groupAllowFrom` phone number allowlists
- Telegram/Discord/Slack: channel/user allowlists configurable per-provider
- Groups: `groupPolicy` (`open`, `disabled`, `allowlist`)
- Webhook (hooks): static `hooks.token` required; supported via `Authorization: Bearer`, `X-Clawdbot-Token` header, or `?token=` query string

### Elevated Tool Execution

- An `elevated` flag on the `exec` tool bypasses the Docker sandbox and runs directly on the host.
- Requires both `tools.elevated.enabled = true` and `tools.elevated.allowFrom.<provider>` to authorize the provider.
- Defaults to disabled; must be explicitly opted in.

---

## Data Flow

### 1. Inbound Message to Agent Response
```
Messaging Platform → Provider Plugin (e.g., Baileys) → allowFrom check
  → session lookup → agent turn queue → Pi embedded runner
  → AI model API (Anthropic/OpenAI/etc.) → response → provider send
  → Messaging Platform
```

### 2. Webhook Trigger to Agent
```
External caller → POST /hooks/{path}/{action} → token validation
  → payload normalization → dispatch agent hook
  → Pi embedded runner → AI model → optional message deliver
```

### 3. Client App to Gateway
```
iOS/Android/macOS app → WebSocket connect (handshake 10s timeout)
  → auth check (token/password/tailscale/none)
  → JSON-RPC request frame → gateway handler
  → agent command or config mutation
  → response frame → client
```

### 4. OpenAI-compatible Completions
```
External tool → POST /v1/chat/completions → Bearer token auth
  → prompt extraction from messages[] → agent command
  → Pi embedded runner → AI model → streaming SSE or JSON response
```

### 5. Agent Tool Execution
```
AI model → exec tool call → (sandbox check) → shell spawn
  → optional Docker container → process output → agent context
```

---

## Sensitive Data

| Data | Location | Sensitivity |
|---|---|---|
| Anthropic / OpenAI / Gemini / etc. API keys | `~/.clawdbot/credentials/auth-profiles.json`, macOS Keychain, env vars, `~/.clawdbot/.env` | Critical |
| WhatsApp session keys (Baileys auth state) | `~/.clawdbot/` directory | Critical |
| Telegram / Slack / Discord bot tokens | `~/.clawdbot/clawdbot.json` (config) | Critical |
| Gateway auth token / password | `~/.clawdbot/clawdbot.json`, env vars | High |
| OAuth tokens (Anthropic, OpenAI Codex) | macOS Keychain or `~/.claude/.credentials.json` / `~/.codex/auth.json` | Critical |
| Hooks webhook token | `~/.clawdbot/clawdbot.json` | High |
| Gmail push token, hook token | `~/.clawdbot/clawdbot.json` | High |
| Conversation history / session transcripts | `~/.clawdbot/agents/*/sessions/*.jsonl` | High |
| User phone numbers (WhatsApp allowlists) | `~/.clawdbot/clawdbot.json` | Medium |
| Pairing codes | In-memory, sent over messaging channel | High (transient) |

**Logging redaction:** `logging.redactSensitive` (default: `"tools"`) applies regex-based redaction to tool summaries. Patterns are configurable; defaults cover common token/key patterns.

**Config file:** `~/.clawdbot/clawdbot.json` contains API keys, bot tokens, and access credentials in plaintext JSON. File system permissions are the only protection.

---

## External Dependencies

### AI Model Providers (Outbound HTTPS)
- Anthropic API (`api.anthropic.com`)
- OpenAI API (`api.openai.com`)
- Google Gemini / Vertex AI
- Groq, Mistral, xAI, MiniMax, OpenRouter, Cerebras, ZAI, Opencode
- GitHub Copilot

### Messaging Platforms (Persistent Connections / Outbound)
- WhatsApp Web servers (Baileys long-lived WebSocket)
- Telegram Bot API
- Slack API / RTM
- Discord Gateway
- Microsoft Teams / Azure Bot Service
- Google Pub/Sub (Gmail hook push)

### Infrastructure Services
- Tailscale: optional VPN overlay for secure remote access; `tailscale serve` / `tailscale funnel` for HTTPS exposure
- Bonjour/mDNS (`@homebridge/ciao`): local network service advertisement
- Docker: used for agent sandbox mode (optional)

### Key npm Dependencies (Security-relevant)
| Package | Version | Purpose |
|---|---|---|
| `@whiskeysockets/baileys` | 7.0.0-rc.9 | WhatsApp Web protocol |
| `@mariozechner/pi-agent-core` | ^0.42.2 | Agent framework; includes patched version |
| `ws` | ^8.19.0 | WebSocket server |
| `express` | ^5.2.1 | HTTP routing |
| `ajv` | ^8.17.1 | JSON schema validation |
| `zod` | ^4.3.5 | Runtime type validation |
| `playwright-core` | 1.57.0 | Browser automation |
| `proper-lockfile` | ^4.1.2 | File locking for auth store |
| `dotenv` | ^17.2.3 | Env file loading |
| `chromium-bidi` | 12.0.1 | Browser automation protocol |
| `undici` | ^7.18.2 | HTTP client |
| `tar` | ^7.5.2 | Archive handling |
| `sharp` | ^0.34.5 | Image processing (native module) |

Note: `@mariozechner/pi-ai@0.42.2` is patched via `patches/@mariozechner__pi-ai@0.42.2.patch`. A `minimumReleaseAge: 2880` (48 hours) setting delays adoption of newly published packages, reducing the risk of dependency confusion or malicious quick-publish attacks.

---

## Security Controls

### Input Validation
- Config object validated with Zod schema (`src/config/zod-schema.ts`) and AJV for JSON schema use.
- Webhook payloads normalized and validated through typed parser functions (`normalizeWakePayload`, `normalizeAgentPayload`).
- Body size limits: hooks max 256 KB, OpenAI endpoint max 1 MB by default.
- Sandbox path traversal protection: `resolveSandboxPath()` and `assertSandboxPath()` detect `../` escapes and symlinks when the agent operates in sandboxed mode.
- Unicode space normalization applied to paths before resolution.
- Shell metacharacter check (`isSafeExecutableValue`) in `src/infra/exec-safety.ts` guards values passed to exec calls, blocking `;`, `|`, `` ` ``, `$`, `<`, `>`, newlines, quotes.

### Command Injection Mitigations
- Shell commands are spawned via `spawn(shell, ['-c', command])`, not `exec(command)` — this avoids some injection vectors but the raw `command` string from AI model output is still passed to the shell interpreter without sanitization.
- Docker sandbox mode wraps commands with `docker exec`, constraining the execution environment.
- Elevated execution requires explicit per-provider configuration.

### Authentication Controls
- Gateway password comparison uses `timingSafeEqual` (constant-time).
- Tailscale auth validates both the presence of `tailscale-user-login` header and that the connection source IP is loopback (ensuring it is the local Tailscale daemon, not a spoofed header from a remote source).
- `x-forwarded-for` / proxy headers cause local-direct bypass to be denied, preventing localhost spoofing through reverse proxies.

### Session and Deduplication
- Request deduplication map (max 1000 entries, 5-minute TTL) prevents replayed requests.
- Handshake timeout (10 seconds) limits resource holding from unauthenticated connections.

### File System
- Auth store writes protected by `proper-lockfile` (retry on contention, 30-second stale timeout).
- Agent workspace directories are isolated per-agent under `~/.clawdbot/agents/`.

### Logging
- Structured logging via `tslog` with configurable levels.
- Sensitive token redaction in tool summaries (configurable regex patterns).

### Transport Security
- All outbound requests to AI model providers and messaging platforms use HTTPS.
- WebSocket connections from mobile/desktop apps to the local gateway are **not** TLS-encrypted by default (plain WebSocket on loopback). Tailscale serve/funnel provides HTTPS for remote access.
- SSH port-forward support for tunneling the gateway through an SSH connection.

### Supply Chain
- `pnpm.minimumReleaseAge: 2880` (48-hour delay on new dependency versions).
- TypeBox override pinned to exact version.
- `pi-ai` dependency is patched locally.

---

## Notes

### Areas of Concern for Deeper Analysis

**1. Token-mode gateway authentication uses non-constant-time comparison.**
In `src/gateway/auth.ts` line 174, the token-mode check uses `connectAuth.token !== auth.token` (string equality). The password mode correctly uses `timingSafeEqual`. An attacker with network access to the gateway (LAN bind, or through a side-channel) could potentially measure timing differences to extract the token character by character. Priority: Medium.

**2. AI-model-generated shell commands execute directly in the user shell.**
The `exec` tool in `src/agents/bash-tools.ts` passes the AI model's `command` string directly to `spawn(shell, ['-c', command])`. No sanitization or allowlisting of commands is applied. The security boundary relies entirely on the AI model's behavior and the optional Docker sandbox. If the model is prompted maliciously (prompt injection via an inbound WhatsApp/Telegram message) it could execute arbitrary commands on the host. Priority: High.

**3. Default gateway auth mode is `none`.**
With default configuration, any process on the same machine or any host on the LAN (if `bind: lan` is configured) can issue gateway commands without credentials. Documentation encourages token configuration, but the default is permissive. Priority: High (especially for LAN/cloud deployments).

**4. Sensitive credentials stored in plaintext JSON.**
`~/.clawdbot/clawdbot.json` and `~/.clawdbot/credentials/auth-profiles.json` store API keys, bot tokens, and OAuth credentials in cleartext. These files rely solely on filesystem permissions for protection. No at-rest encryption is applied. Priority: Medium.

**5. Webhook token exposure via URL query string.**
`extractHookToken()` in `src/gateway/hooks.ts` accepts the hook token as a `?token=` query parameter. Query parameters appear in server access logs, web browser history, and HTTP Referer headers. Priority: Low–Medium.

**6. SSH host key checking set to `accept-new`.**
The SSH tunnel in `src/infra/ssh-tunnel.ts` sets `StrictHostKeyChecking=accept-new`, which auto-trusts new host keys but prevents TOFU downgrade to known-different keys. This is a reasonable default but first-connection trust is not verified. Priority: Low.

**7. Keychain credential write uses shell interpolation.**
In `writeClaudeCliKeychainCredentials()` (`src/agents/cli-credentials.ts` line 281), the JSON credential value is interpolated into a shell command string with single-quote escaping (`replace(/'/g, "'\"'\"'")`) before passing to `execSync`. If the credential JSON contains a carefully crafted value, the escaping may be incomplete. Priority: Medium.

**8. macOS Keychain `security` CLI invoked with `execSync`.**
Reading and writing credentials uses synchronous child process invocations. A blocked `security` prompt could stall the gateway. A compromised or replaced `security` binary would silently receive all OAuth tokens. Priority: Low (host-integrity concern).

**9. Plugin system and dynamic code loading.**
`src/plugins/loader.ts` and `resolvePluginTools` load external plugins at runtime. The security posture of third-party plugins is not evaluated by the core codebase. Priority: Medium (depends on deployment).

**10. Prompt injection via inbound messaging content.**
Inbound messages from WhatsApp, Telegram, Slack, etc. are passed as user context to the AI model. Malicious content could attempt to override system prompts or issue tool calls (prompt injection). The `transcript-sanitize.ts` extension addresses API-level structural issues but not adversarial prompt content. Priority: High.

**11. Broadcast/LAN exposure of mDNS service.**
The Bonjour/mDNS advertiser announces the gateway service on the local network. This enables any device on the LAN to discover the gateway's port and hostname, even if binding is loopback-only. Priority: Low (discovery only, does not bypass auth).

**12. Tailscale header trust assumes local proxy integrity.**
Tailscale auth trusts `tailscale-user-login` headers only when the connection source is loopback and proxy headers are present. This is correct, but depends on no other local process being able to inject those headers on the loopback interface. Priority: Low (local privilege assumed).
