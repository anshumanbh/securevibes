# Security Architecture

## Overview

Clawdbot is a multi-platform AI messaging gateway that bridges multiple messaging channels (WhatsApp, Telegram, Discord, Slack, Signal, iMessage, Microsoft Teams) to large language model (LLM) backends (Anthropic Claude, OpenAI, Google Gemini, and others). The system operates as a persistent local gateway daemon that routes inbound messages from various chat platforms to LLM agents, executes tool calls on the local machine (shell commands, browser control, file operations), and returns AI-generated replies. It also exposes a WebSocket-based RPC protocol and an optional OpenAI-compatible HTTP API. Mobile apps (iOS, Android), a macOS menubar app, and a web control UI connect to the local gateway over this protocol.

The codebase also includes Swabble, a Swift-based companion CLI/library for wake-word detection and voice transcription, which can forward transcribed speech to the Clawdbot gateway.

---

## Architecture

```
External Messaging Platforms
  WhatsApp (Baileys WA Web)
  Telegram (Grammy)
  Discord (discord-api-types)
  Slack (@slack/bolt)
  Signal
  iMessage (macOS-local)
  MS Teams (@microsoft/agents-hosting)
           |
           v
  +---------------------------+
  |   Clawdbot Gateway        |  <-- Node.js daemon (default port 18789)
  |   (server.impl.ts)        |
  |   HTTP + WebSocket (ws)   |
  |   Tailscale optional       |
  +---------------------------+
       |           |         |
       |           |         |
       v           v         v
  WS Bridge   Hooks API   OpenAI-compat HTTP
  (clients)  (POST /hooks) (POST /v1/chat/completions)
       |
       v
  Agent Runtime
  (pi-agent-core)
  +--------------------------+
  | Tool Execution           |
  |  - exec / bash tools     |
  |  - browser (Playwright)  |
  |  - memory search         |
  |  - message send tools    |
  |  - agent-to-agent        |
  +--------------------------+
       |
       v
  LLM API Providers
  (Anthropic, OpenAI, Gemini, Chutes, Minimax, ...)
       |
       v
  Auth Profile Store (~/.clawdbot/agents/*/auth-profiles.json)
  OAuth / API keys / Tokens (macOS Keychain or file)

Mobile/Desktop Clients
  iOS App (Swift)
  Android App (Kotlin)
  macOS Menubar App (Swift)
  Web Control UI (served from gateway)
  CLI (clawdbot binary)
       |
       v (WebSocket to gateway, same port 18789)
  +---------------------------+
  |  Gateway WS Bridge        |
  +---------------------------+
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 22+, Bun (dev/test) |
| Language | TypeScript (ESM), Swift (iOS/macOS/Swabble), Kotlin (Android) |
| Gateway / WS | `ws` WebSocket library, Node.js `http` |
| CLI framework | Commander.js |
| Configuration | JSON5 (`~/.clawdbot/clawdbot.json`), Zod validation |
| Config schema | Zod + AJV |
| Auth store | Plain JSON files (`auth-profiles.json`), macOS Keychain via `security` CLI |
| LLM SDKs | `@mariozechner/pi-agent-core`, `@mariozechner/pi-ai` |
| WhatsApp | `@whiskeysockets/baileys` (WA Web protocol) |
| Telegram | `grammy`, `@grammyjs/runner` |
| Discord | `discord-api-types`, `@buape/carbon` |
| Slack | `@slack/bolt`, `@slack/web-api` |
| MS Teams | `@microsoft/agents-hosting` (Express-based) |
| Browser automation | Playwright Core, Chromium BiDi |
| File locking | `proper-lockfile` |
| Network tunneling | Tailscale (`serve` and `funnel` modes) |
| Cron scheduling | `croner` |
| TTS | ElevenLabs API |
| Local LLM inference | `node-llama-cpp` (optional) |
| Memory/vector search | SQLite + local or OpenAI embeddings |
| Media processing | `sharp`, `file-type` |
| Multicast discovery | `@homebridge/ciao` (Bonjour/mDNS) |
| Test framework | Vitest, V8 coverage |
| iOS app | Swift / SwiftUI, XcodeGen |
| Android app | Kotlin, Gradle |
| macOS app | Swift / SwiftUI |
| Voice | Swabble (Swift CLI, Apple SFSpeechRecognizer) |

---

## Entry Points

### 1. CLI Commands (`clawdbot` binary)
- `clawdbot gateway` - Starts the local gateway daemon
- `clawdbot agent --message "..."` - Sends a message directly to the agent
- `clawdbot message send` - Sends a message via a configured channel
- `clawdbot login` - Authenticates with a provider
- `clawdbot doctor` - Diagnostics / config repair
- `clawdbot status` - Displays system status
- `clawdbot tui` - Launches the terminal UI
- `clawdbot nodes` - Manages connected mobile/remote nodes

### 2. Gateway WebSocket API (port 18789 default)
- Accepts WebSocket connections from mobile/desktop clients
- Initial `connect` message carries optional `token` or `password` for authentication
- Methods dispatched over the WS protocol include: `send`, `agent`, `config.get`, `config.set`, `config.apply`, `sessions.*`, `chat.*`, `models.*`, `health`, `system-event`, `system-presence`, `logs.*`, `nodes.*`, `skills.*`, `usage.*`, `update.*`, `wizard.*`, `channels.*`, `cron.*`, `agents.*`

### 3. HTTP Hooks Endpoint (`POST /hooks/*`)
- Configurable base path (default `/hooks`)
- Authenticated via Bearer token in `Authorization` header, `x-clawdbot-token` header, or `token` query parameter
- Sub-paths: `/hooks/wake` (triggers agent heartbeat), `/hooks/agent` (dispatches agent job)
- Configurable hook mappings via `hooks.mappings[]` in config; supports transform modules loaded from the filesystem (`transformsDir`)

### 4. OpenAI-Compatible HTTP API (`POST /v1/chat/completions`)
- Opt-in via `gateway.http.endpoints.chatCompletions.enabled = true`
- Accepts Bearer token in `Authorization` header for auth; falls back to gateway token or password mode
- Supports both streaming (SSE) and non-streaming responses
- Routes requests to internal agent runtime

### 5. Web Control UI
- Served over HTTP at gateway port (configurable base path, default `/`)
- Opt-in via `gateway.controlUi.enabled`
- No additional authentication layer beyond gateway-level access

### 6. Canvas / A2UI Host
- Optional WebSocket + HTTP server for serving AI-rendered UI components
- Served on a separate port (default 18793)

### 7. External Webhooks (Inbound Channels)
- WhatsApp: WA Web session maintained locally via Baileys; inbound messages polled/monitored
- Telegram: Bot polling or webhook
- Discord: Bot WebSocket gateway
- Slack: Bolt app (Socket Mode or HTTP Events API)
- MS Teams: Express-based Bot Framework endpoint
- Gmail hooks: Optional push subscription via Google Pub/Sub
- iMessage: macOS-only, reads local Messages database

### 8. Swabble Voice CLI
- Swift CLI runs on macOS, listens for wake word via Apple SFSpeechRecognizer
- On activation, executes a user-configured hook command (e.g., `clawdbot agent --message "..."`) as a child process
- Hook command, prefix, and environment variables are user-controlled configuration

### 9. Mobile Apps (iOS / Android)
- Connect to the gateway over WebSocket (local or remote via Tailscale)
- Use the same gateway WS protocol

---

## Authentication & Authorization

### Gateway WebSocket Authentication
Implemented in `src/gateway/auth.ts`. Three modes:

- **`none`**: No authentication required (only safe for loopback-bound deployments)
- **`token`**: Static shared token compared with `timingSafeEqual` (constant-time comparison, mitigates timing attacks). Token sourced from `gateway.auth.token` config or `CLAWDBOT_GATEWAY_TOKEN` env var
- **`password`**: Static shared password compared with `timingSafeEqual`. Password sourced from `gateway.auth.password` config or `CLAWDBOT_GATEWAY_PASSWORD` env var

**Tailscale passthrough**: When `gateway.tailscale.mode = "serve"` and `auth.allowTailscale = true`, requests arriving with Tailscale proxy headers (`tailscale-user-login`, `x-forwarded-for`, `x-forwarded-proto`, `x-forwarded-host`) from loopback are accepted as authenticated by Tailscale identity. The gateway validates that the request arrived from loopback AND has all three forwarded headers before trusting Tailscale identity.

**Local loopback bypass**: When `auth.mode = "none"` and no Tailscale mode is in play, connections from loopback (`127.x.x.x`, `::1`) with no forwarded proxy headers are accepted without authentication.

**Important weakness**: The token comparison for the OpenAI HTTP endpoint (`openai-http.ts`) passes the Bearer token as both `token` and `password` fields, meaning the same token works for either auth mode. There is no distinction between token and password modes in this HTTP path.

### Hooks Endpoint Authentication
- Requires a static shared secret (`hooks.token`) in config
- Token accepted via `Authorization: Bearer <token>`, `x-clawdbot-token` header, or `?token=` query parameter
- Query parameter transmission exposes the token to web server access logs

### LLM Provider Authentication (Auth Profile Store)
- Stored in `~/.clawdbot/agents/<agent-id>/auth-profiles.json`
- Three credential types: `api_key` (static), `token` (bearer/PAT), `oauth` (access + refresh + expiry)
- On macOS, OAuth credentials for Anthropic (Claude CLI) and OpenAI (Codex CLI) are read from and written to the system Keychain via `security` CLI
- File is protected only by filesystem permissions (no encryption at rest)
- Credential file is locked with `proper-lockfile` during writes to prevent concurrent corruption
- Credentials are synced on every load from external CLI credential stores (Claude CLI `~/.claude/.credentials.json`, Codex CLI `~/.codex/auth.json`)
- Auth profiles support cooldown / backoff tracking for rate-limited or billing-failed providers

### Agent Tool Authorization
- Tools are gated by a configurable allow/deny list (`tools.allow`, `tools.deny`) and tool profiles (`minimal`, `coding`, `messaging`, `full`)
- Elevated exec (running shell commands with elevated permissions) requires explicit opt-in via `tools.elevated.enabled = true` and per-provider allowlists (`tools.elevated.allowFrom.<provider>`)
- Sandbox Docker mode isolates exec tool calls inside a container

---

## Data Flow

### 1. Inbound Message (e.g., WhatsApp) to LLM and Back
```
WhatsApp message received (Baileys session)
  --> inbound monitor extracts text / media
  --> deduplicated (in-memory seen-set)
  --> auto-reply pipeline checks allowed senders / routing rules
  --> dispatched to agent runtime (pi-agent-core) with session key
  --> LLM API call (provider selected from auth-profiles, round-robin)
  --> tool calls executed (exec, browser, message, memory, etc.)
  --> reply assembled
  --> outbound delivery to originating channel
  --> session JSONL log appended (~/.clawdbot/agents/<id>/sessions/*.jsonl)
```

### 2. Inbound Hook POST to Agent
```
POST /hooks/agent
  Bearer token validated
  JSON body parsed (max 256 KB default)
  Payload normalized (message, sessionKey, channel, model, etc.)
  Agent job dispatched (async, returns runId immediately)
  Agent runtime executes, delivers to configured channel
```

### 3. WebSocket Client to Gateway
```
Client connects to ws://localhost:18789
  connect message with optional token/password
  Auth validated (timingSafeEqual)
  Session registered on bridge
  Client sends JSON-RPC-like method calls (e.g., "send", "agent", "config.set")
  Server routes to handler
  Response returned on same WS connection
  Real-time events (chat streaming, heartbeat, presence) pushed to subscribed clients
```

### 4. LLM Provider API Call
```
Agent runtime selects auth profile (round-robin with cooldown/backoff)
  OAuth access token potentially refreshed (calls provider token endpoint)
  HTTP request to provider API (Anthropic / OpenAI / etc.)
  Response streamed or awaited
  Tool calls in response executed locally
  Final reply assembled
```

### 5. Credential Sync (External CLI)
```
On every auth-profiles.json load:
  Read ~/.claude/.credentials.json or macOS Keychain (Claude CLI)
  Read ~/.codex/auth.json or macOS Keychain (Codex CLI)
  Merge into auth-profiles.json if not already present
  Written back to disk
```

---

## Sensitive Data

### User Credentials / API Keys
- LLM provider API keys (Anthropic, OpenAI, Gemini, Chutes, Minimax, etc.) stored in `~/.clawdbot/agents/<id>/auth-profiles.json`
- OAuth access and refresh tokens stored in same file
- macOS Keychain used as primary store on macOS for Claude CLI and Codex CLI credentials
- Gateway shared token/password stored in `~/.clawdbot/clawdbot.json`
- ElevenLabs TTS API key optionally stored in config (`talk.apiKey`) or `ELEVENLABS_API_KEY` env var
- SSH identity file path for remote gateway tunneling stored in config (`gateway.remote.sshIdentity`)

### Messaging Platform Credentials
- WhatsApp: WA Web session keys and authentication state stored in `~/.clawdbot/credentials/` (Baileys auth state)
- Telegram: Bot token stored in config
- Discord: Bot token stored in config
- Slack: Bot token and app token stored in config
- Signal: Credentials managed by external Signal CLI or linked device
- MS Teams: App credentials (client ID / secret) in config or environment

### Message Content (PII)
- All inbound and outbound messages are logged to JSONL session files under `~/.clawdbot/agents/<id>/sessions/`
- Message content may include personally identifiable information (phone numbers, names, message text)
- Phone numbers appear in session keys and logs
- Media files (images, audio) transiently processed in memory and may be written to workspace directories

### Shell Command History / Tool Outputs
- All `exec` tool outputs are captured and included in LLM context
- Long-running background processes tracked in the bash process registry
- Tool call results (including potentially sensitive file contents) passed to LLM providers

### Config File
- `~/.clawdbot/clawdbot.json` may contain gateway tokens, provider credentials, and messaging platform tokens in plaintext

---

## External Dependencies

### Messaging Platforms
- Anthropic API (claude.ai, api.anthropic.com)
- OpenAI API (api.openai.com)
- Google Gemini API
- Chutes API
- Minimax API
- ElevenLabs TTS API
- WhatsApp Web (via Baileys - unofficial WA Web client)
- Telegram Bot API
- Discord API
- Slack API
- Signal (via external Signal CLI)
- Microsoft Bot Framework (Teams)
- Google Gmail Pub/Sub (optional hook integration)

### Key npm Dependencies
| Package | Purpose | Security Notes |
|---|---|---|
| `@whiskeysockets/baileys` | WhatsApp WA Web | Unofficial protocol; reverse-engineered; pinned at `7.0.0-rc.9` |
| `@mariozechner/pi-agent-core` | Agent / LLM runtime | Core agent execution loop |
| `@mariozechner/pi-ai` | LLM provider abstraction | OAuth credential management |
| `ws` | WebSocket server | `^8.19.0` |
| `playwright-core` | Browser automation | Pinned at `1.57.0` (patched dep) |
| `chromium-bidi` | Chrome DevTools Protocol | Pinned at `12.0.1` (patched dep) |
| `express` | HTTP server (MS Teams bot) | `^5.2.1` |
| `proper-lockfile` | File locking for auth store | Prevents concurrent write corruption |
| `zod` | Config schema validation | `^4.3.5` |
| `ajv` | JSON Schema validation (protocol) | `^8.17.1` |
| `node-llama-cpp` | Local LLM inference | `3.14.5` (patched dep) |
| `sharp` | Image processing | `^0.34.5` |
| `dotenv` | Environment variable loading | `^17.2.3` |
| `undici` | HTTP client | `^7.18.2` |
| `@slack/bolt` | Slack app framework | `^4.6.0` |
| `grammy` | Telegram bot framework | `^1.39.2` |
| `tar` | Archive extraction (install) | `^7.5.2` |

Several dependencies are pinned to exact versions with patches applied via `pnpm.patchedDependencies`: `playwright-core`, `chromium-bidi`, `node-llama-cpp`, and `long`.

---

## Security Controls

### Input Validation
- Gateway protocol messages validated with AJV-compiled JSON schemas (`src/gateway/protocol/`)
- Config file validated via Zod schemas on load; validation errors are logged but config may be partially preserved
- Hook payloads normalized and validated (field types, required fields, channel allowlist)
- OpenAI HTTP body size limited (default 1 MB) via `readJsonBody` with early stream abort on overflow
- Hook body size limited (default 256 KB) via same mechanism
- `exec` tool output truncated at configurable max (default 30,000 chars, max 150,000)

### Authentication
- Gateway: static token or password with constant-time comparison (`timingSafeEqual` from Node.js `crypto`)
- Hooks: static shared token
- LLM providers: API keys / OAuth managed in auth-profile store with rotation and cooldown
- Tailscale: identity-based auth via Tailscale proxy headers (requires Tailscale serve mode)

### Network Exposure
- Default gateway bind: `127.0.0.1` (loopback only) - safe default
- Explicit `lan` (0.0.0.0), `auto` (Tailnet IP), or `custom` modes available and require operator configuration
- Tailscale `serve` mode exposes on Tailnet only (private network)
- Tailscale `funnel` mode exposes publicly on the internet - requires explicit opt-in

### Sandboxing
- Docker-based sandbox available for `exec` tool calls (`tools.sandbox`)
- Sandbox isolates shell commands inside a container with configurable workspace volume mounting
- Elevated exec (host-level commands bypassing sandbox) requires explicit double-opt-in (`tools.elevated.enabled` + `tools.elevated.allowFrom`)

### File Locking
- Auth profile store uses `proper-lockfile` with stale lock recovery to prevent concurrent write corruption across processes

### Process Isolation
- Background shell processes tracked in a registry with configurable cleanup
- Process timeouts enforced (default 1800 seconds for exec tool)
- Signal handling: abort controller propagated to child processes

### Credential Rotation / Cooldown
- LLM provider profiles have configurable billing backoff (default 5 hours, max 24 hours)
- Round-robin profile selection with cooldown tracking prevents hammering a single failed account
- Automatic OAuth token refresh before expiry

### Replay / Deduplication
- Inbound WhatsApp messages deduplicated via in-memory seen-set (`src/web/inbound/dedupe.ts`)
- Gateway `send` method uses idempotency keys with a short-lived in-memory cache

### Logging
- Structured logging via `tslog`
- Session conversations logged to JSONL files
- Gateway WebSocket events optionally logged
- No apparent automatic log rotation or size limits documented in the source

---

## Notes

### High-Risk Areas

1. **Arbitrary Shell Command Execution**: The `exec` tool (`src/agents/bash-tools.exec.ts`) executes arbitrary shell commands via `child_process.spawn` with the full process environment. The command string is passed directly to the shell (`/bin/sh -c <command>`). The security boundary relies entirely on the LLM not generating malicious commands and on the operator-configured tool allow/deny lists. There is no command allowlist or sanitization at the shell layer.

2. **Hook Transform Modules (Dynamic Code Loading)**: The hooks mapping system supports `transform` entries with a `module` field that loads user-specified JavaScript modules from the filesystem (`transformsDir`). This is effectively dynamic code execution from arbitrary file paths; a compromised or maliciously crafted transform file would execute with full Node.js process privileges.

3. **Swabble Hook Command Injection**: In `Swabble/Sources/SwabbleCore/Hooks/HookExecutor.swift`, the transcribed voice text is appended directly to the hook command arguments. While the payload is passed as a separate argument (not interpolated into a shell string), the `hook.prefix` field undergoes `replacingOccurrences(of: "${hostname}", with: hostname)` substitution with the local hostname. The hostname is not sanitized and could contain characters that influence subsequent command interpretation if the hook command itself does shell processing.

4. **Auth Store Stored in Plaintext**: `~/.clawdbot/agents/*/auth-profiles.json` contains API keys and OAuth tokens in plaintext JSON. File system permissions are the only protection. No encryption at rest is implemented.

5. **Gateway Token in Config File**: `gateway.auth.token` and `gateway.auth.password` are stored in `~/.clawdbot/clawdbot.json` in plaintext. Environment variable alternatives (`CLAWDBOT_GATEWAY_TOKEN`, `CLAWDBOT_GATEWAY_PASSWORD`) are available but not enforced.

6. **Hook Token in Query Parameter**: `extractHookToken` in `src/gateway/hooks.ts` accepts the token via URL query parameter (`?token=...`). This exposes the token in web server access logs, proxy logs, and browser history.

7. **Unofficial WhatsApp Protocol**: Baileys (`@whiskeysockets/baileys`) implements the WhatsApp Web protocol unofficially. Use of this library may violate WhatsApp's Terms of Service, and the protocol may change without notice, causing sudden failures. The library version is pinned at a release candidate (`7.0.0-rc.9`).

8. **LLM Prompt Injection**: Messages arriving from external channels (WhatsApp, Telegram, etc.) are passed directly as LLM input. A malicious sender could craft messages designed to manipulate the agent into performing unintended actions, including executing shell commands, sending messages to other recipients, or exfiltrating information via the available tools.

9. **macOS `security` CLI Invocation**: `src/agents/cli-credentials.ts` invokes the macOS `security` CLI to read and write Keychain entries using `execSync`. The `writeClaudeCliKeychainCredentials` function constructs a shell command that embeds serialized JSON into a single-quoted shell argument, using a custom escaping strategy (`replace(/'/g, "'\"'\"'")`). If the serialized JSON contains single-quote characters in an unexpected structure, the escaping could be incomplete.

10. **Config File Read Exposure via `config.get`**: The `config.get` gateway method returns a snapshot of the raw config file content, which may include plaintext credentials (tokens, API keys) embedded in the config. Any authenticated WebSocket client can retrieve the full config.

11. **No Rate Limiting on Gateway**: The WebSocket and HTTP endpoints do not implement rate limiting. A client with a valid token could submit unlimited `agent` calls, hook POSTs, or OpenAI-compatible requests, potentially leading to unbounded LLM API spend or resource exhaustion.

12. **Session JSONL Files Contain Full Message History**: All message content, tool call inputs/outputs, and LLM responses are stored in plaintext JSONL files under `~/.clawdbot/agents/`. This includes phone numbers, personal message content, and potentially sensitive tool call outputs (e.g., file reads, shell command outputs).
