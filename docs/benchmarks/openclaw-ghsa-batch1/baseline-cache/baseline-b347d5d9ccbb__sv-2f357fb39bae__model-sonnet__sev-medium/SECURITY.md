# Security Architecture

## Overview

Clawdbot is a multi-channel AI gateway that connects messaging platforms (WhatsApp, Telegram, Slack, Discord, iMessage, Signal, Matrix, MS Teams, and others) to AI model providers (Anthropic Claude, OpenAI, Groq, Deepgram, MiniMax, Ollama, GitHub Copilot Proxy, Qwen, Google Gemini, and others). The system runs as a local daemon ("Gateway") on the user's machine, receives messages from external messaging channels, routes them to AI agents, and delivers responses back through those channels.

The codebase also includes Swabble, an embedded Swift voice-wake companion that transcribes local microphone audio and fires shell hooks when a wake word is detected.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│ External Messaging Channels                                   │
│  WhatsApp (Baileys) │ Telegram │ Slack │ Discord │ iMessage  │
│  Signal │ Matrix │ MS Teams │ BlueBubbles │ Web Chat          │
└────────────────────────┬─────────────────────────────────────┘
                         │ inbound messages / outbound replies
                         ▼
┌──────────────────────────────────────────────────────────────┐
│ Gateway (Node.js daemon — src/gateway/)                       │
│  • HTTP/HTTPS + WebSocket server (default port 18789)        │
│  • Auth layer: none | token | password | Tailscale           │
│  • Hooks HTTP endpoint (/hooks/*)                            │
│  • OpenAI-compatible HTTP endpoint (/v1/chat/completions)    │
│  • Control UI (served as static HTML)                        │
│  • Canvas/A2UI host                                          │
│  • Tailscale Serve / Funnel exposure (optional)              │
└──────────┬───────────────────────────┬───────────────────────┘
           │ WebSocket RPC             │ Bridge RPC (Unix/TCP)
           ▼                           ▼
┌────────────────────┐     ┌───────────────────────────┐
│ macOS / iOS / Web  │     │ Pi Agent / Node Agents     │
│ Client Apps        │     │ (src/agents/, src/acp/)    │
│ (apps/macos, ios,  │     │  - Claude CLI runner       │
│  android, ui/)     │     │  - Pi embedded runner      │
└────────────────────┘     │  - Bash/process exec tools │
                           │  - Web fetch/search tools  │
                           │  - Browser automation      │
                           │  - Docker sandbox          │
                           └───────────────────────────┘
                                        │ AI API calls
                                        ▼
                           ┌────────────────────────────┐
                           │ External AI Providers       │
                           │  Anthropic, OpenAI, Groq,  │
                           │  Deepgram, MiniMax, Ollama  │
                           └────────────────────────────┘
```

Swabble (companion):
```
Microphone → SpeechPipeline (on-device, macOS) → WakeWordGate → HookExecutor → shell command
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 22+ / Bun |
| Language | TypeScript (ESM, strict), Swift (Swabble + macOS/iOS apps) |
| Gateway server | `ws` (WebSocket), `express` v5, `hono`, Node `http`/`https` |
| WhatsApp | `@whiskeysockets/baileys` 7.0.0-rc.9 |
| Telegram | `grammy` + `@grammyjs/runner` |
| Slack | `@slack/bolt`, `@slack/web-api` |
| Discord | `@buape/carbon`, `discord-api-types` |
| Protocol validation | `@sinclair/typebox`, `ajv`, `zod` |
| AI agent core | `@mariozechner/pi-agent-core`, `@mariozechner/pi-ai` |
| Browser automation | `playwright-core`, `chromium-bidi` |
| Vector memory | `sqlite-vec`, `node-llama-cpp` (optional) |
| Serialization | `json5`, `yaml` |
| Networking | `undici`, `ws`, Tailscale CLI |
| Crypto | Node.js built-in `node:crypto` (Ed25519 device identity, timingSafeEqual) |
| macOS speech | Apple `Speech` framework (Swabble) |
| Build | TypeScript compiler, Rolldown, pnpm 10 |
| Test | Vitest, V8 coverage |
| Lint | Oxlint, Oxfmt |
| Mobile | SwiftUI (iOS/macOS), Kotlin/Jetpack Compose (Android) |

---

## Entry Points

### Gateway WebSocket (primary client interface)
- **URL:** `ws://127.0.0.1:18789` (default; configurable bind host and port)
- **Upgrade path:** HTTP → WebSocket via `ws` library
- **Auth:** Token, password, or Tailscale identity header; "none" mode permitted only on loopback
- **Clients:** macOS app, iOS app, Android app, web UI, CLI (`clawdbot gateway`)
- **Payload cap:** 512 KB per frame; 1.5 MB per-connection send buffer
- **Handshake timeout:** 10 seconds

### Gateway HTTP Endpoints
| Path | Purpose | Auth |
|---|---|---|
| `/hooks/wake` | POST — trigger agent wake | Hooks token (Bearer or `X-Clawdbot-Token` or `?token=`) |
| `/hooks/agent` | POST — dispatch agent with message | Hooks token |
| `/hooks/<subpath>` | POST — mapped hooks (custom routing) | Hooks token |
| `/v1/chat/completions` | POST — OpenAI-compatible chat completions | Gateway token or password (Bearer) |
| `/slack/*` | Slack events/interactivity webhook | Slack signing secret (internal) |
| Control UI | GET — static web UI | None (loopback assumed) |
| Canvas/A2UI | GET/WebSocket — canvas host | None by default |

### Messaging Channel Inbound
Each channel plugin registers a message listener that feeds into the routing/agent pipeline:
- WhatsApp: Baileys socket events (QR-paired, no user credentials on server)
- Telegram: `grammy` bot polling / webhook
- Slack: Bolt event listener (requires `SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`)
- Discord: Carbon bot (requires `DISCORD_TOKEN`)
- iMessage: platform-native adapter
- Signal: adapter via signal-cli or native
- Matrix: matrix-js-sdk (access token auth)
- MS Teams: Bot Framework adapter (extension)
- BlueBubbles: REST API (extension)
- Voice call: voice call provider extension

### CLI Commands
- `clawdbot gateway` — start the gateway daemon
- `clawdbot agent --message <msg>` — run a one-shot agent session
- `clawdbot login` — credential setup
- `clawdbot security audit` — run built-in security audit
- `clawdbot status` — probe gateway and channels
- `clawdbot doctor` — detect and fix common misconfigurations
- `clawdbot message send/read/edit/delete` — messaging operations

### External Webhooks (inbound)
- Hooks endpoint (`/hooks/*`) accepts external HTTP POST calls to trigger agent runs or wake events
- Slack interactivity/events can be delivered to the gateway HTTP port

### Swabble (voice companion) CLI
- `swabble serve` — starts microphone capture loop; fires hooks on wake word detection
- Hooks execute a configured shell command with transcribed text as an argument

---

## Authentication & Authorization

### Gateway Connection Auth
Resolved from config (`gateway.auth`) or environment variables at startup. Three modes:

| Mode | Mechanism |
|---|---|
| `none` | No credential required; only safe on loopback |
| `token` | Static bearer token compared with `timingSafeEqual` |
| `password` | Password compared with `timingSafeEqual` |
| Tailscale overlay | If `allowTailscale=true`, Tailscale proxy headers (`tailscale-user-login`, `x-forwarded-for`, `x-forwarded-proto`, `x-forwarded-host`) grant access without credentials; only accepted when request arrives via loopback from the Tailscale local proxy |

Config keys: `gateway.auth.token`, `gateway.auth.password`, or env vars `CLAWDBOT_GATEWAY_TOKEN`, `CLAWDBOT_GATEWAY_PASSWORD`.

Loopback detection inspects `req.socket.remoteAddress` and the `Host` header. Requests with `X-Forwarded-For`, `X-Real-IP`, or `X-Forwarded-Host` headers are not treated as local-direct, preventing simple header spoofing.

### Device Identity (client pairing)
Clients generate an Ed25519 key pair stored at `~/.clawdbot/identity/device.json` (mode 0o600). The device ID is the SHA-256 fingerprint of the public key. On WebSocket connect, clients sign a payload containing `deviceId|clientId|clientMode|role|scopes|signedAtMs|token` and send the signature along with the public key. The gateway can verify the signature with `crypto.verify()`.

### Hooks Authentication
HTTP hooks require a static token (`hooks.token` in config). The token may be passed as:
1. `Authorization: Bearer <token>` header
2. `X-Clawdbot-Token` header
3. `?token=<token>` query parameter

A missing or mismatched token returns HTTP 401.

### OpenAI-compatible Endpoint Auth
The `/v1/chat/completions` endpoint reuses the same gateway auth check. The bearer token from the `Authorization` header is tried against both the token and password modes.

### Channel Allowlists (messaging channels)
Each messaging channel enforces its own sender allowlist (`allowFrom`), group policy (`open` | `allowlist` | `disabled`), and optional per-group/per-channel overrides. These are stored in config and in a persistent pairing store. The security audit engine (`src/security/audit.ts`) checks for misconfigured open policies.

### Exec Approval System
Shell command execution by AI agents goes through an approval pipeline:
- Default security: `deny` (no commands allowed without explicit allowlist)
- Modes: `deny` | `allowlist` | `full`
- `ask` mode: `off` | `on-miss` | `always`
- Approved commands are written to `~/.clawdbot/exec-approvals.json` (mode 0o600)
- Interactive approvals are relayed to connected gateway clients via WebSocket broadcast
- The approval manager tracks pending decisions with a configurable timeout (default 120 s); expired requests default to `deny`

### Browser Control Auth
If `browser.controlUrl` is non-loopback, a `browser.controlToken` (or `CLAWDBOT_BROWSER_CONTROL_TOKEN` env) is required. The audit engine flags missing tokens, HTTP-only remote URLs, short tokens, and token reuse between browser control and the gateway token.

---

## Data Flow

### Inbound Message to AI Agent Response
```
1. User sends message on messaging channel (WhatsApp/Telegram/Slack/etc.)
2. Channel plugin receives event → normalizes to internal message format
3. Mention gating (group channels): check if bot was mentioned or command authorized
4. Sender allowlist check: compare sender ID against config allowFrom + pairing store
5. Session key resolved (per-channel-peer or shared main session)
6. Message routed to agent runner (pi-agent-core or claude-cli-runner)
7. Agent calls AI model API (Anthropic, OpenAI, etc.) with API key from auth-profiles
8. Agent may invoke tools (bash exec, web fetch, browser, memory)
   a. Bash exec: checks exec-approvals allowlist; may request interactive approval
   b. Web fetch: fetches URL, extracts readable content (Mozilla Readability)
   c. Browser: Playwright/ChromiumBidi automation
   d. Memory: sqlite-vec or LanceDB vector store
9. Agent assembles response
10. Outbound delivery: formatted for target channel, sent via channel SDK
11. Gateway broadcasts session events to connected WebSocket clients (UI)
```

### External Webhook to Agent
```
1. POST /hooks/agent with JSON body {message, sessionKey, channel, ...}
2. Hooks middleware validates token
3. Payload normalized and validated (normalizeAgentPayload)
4. dispatchAgentHook() queues agent run
5. Agent runs as in steps 6–10 above
6. Response delivered to configured channel if deliver=true
```

### Config Read/Write via Gateway Bridge
```
1. Connected client sends config.get / config.set / config.patch request over WebSocket
2. Gateway checks method allowlist (bridge handler dispatches by method name)
3. Config read: loads current config file, returns snapshot + hash
4. Config write: requires baseHash match (optimistic concurrency); applies merge-patch;
   validates against config schema; writes atomically to disk
5. Gateway broadcasts config.updated event to all connected clients
```

### Credential Storage
- API keys and OAuth tokens stored in `~/.clawdbot/credentials/auth-profiles.json`
- Loaded at agent runtime; never logged or sent over channels
- OAuth flow uses browser redirect; access and refresh tokens stored on disk

---

## Sensitive Data

| Data | Location | Notes |
|---|---|---|
| AI provider API keys | `~/.clawdbot/credentials/auth-profiles.json` | Mode 0o600; loaded per-request |
| OAuth access/refresh tokens | `~/.clawdbot/credentials/` | Mode 0o600; refreshed automatically |
| Gateway auth token/password | `~/.clawdbot/config.json` or env vars | Config should be 0o600 |
| WhatsApp session credentials | `~/.clawdbot/sessions/` | Baileys multi-file auth store |
| Device identity (Ed25519 private key) | `~/.clawdbot/identity/device.json` | Written with mode 0o600 |
| Exec approvals allowlist + socket token | `~/.clawdbot/exec-approvals.json` | Mode 0o600 |
| Hooks token | Config file | Should be a long random string |
| Browser control token | Config or env `CLAWDBOT_BROWSER_CONTROL_TOKEN` | Should be distinct from gateway token |
| Chat session history | `~/.clawdbot/agents/<agentId>/sessions/*.jsonl` | Plaintext; contains conversation content |
| Transcript logs (Swabble) | Local file (configurable) | Voice transcriptions |
| Tailscale user identity | HTTP request headers (transient) | Used only during auth; not persisted |

Logging redaction (`logging.redactSensitive`) can be set to `"tools"` to prevent secrets appearing in tool summary output. Setting it to `"off"` is flagged as a security warning by the audit engine.

---

## External Dependencies

### AI Provider APIs (outbound HTTPS)
- Anthropic Claude API
- OpenAI API (also used for GitHub Copilot Proxy, Qwen portal)
- Groq API
- Deepgram API
- MiniMax API
- Google Gemini (via `google-gemini-cli-auth` extension)
- Ollama (local HTTP, configurable endpoint)

### Messaging Platform APIs
- WhatsApp Web protocol via `@whiskeysockets/baileys` (WebSocket to WhatsApp servers)
- Telegram Bot API via `grammy`
- Slack API via `@slack/bolt` and `@slack/web-api`
- Discord API via `@buape/carbon`
- Matrix homeserver via matrix-js-sdk (extension)
- Microsoft Teams via Bot Framework (extension)
- BlueBubbles REST API (extension)
- Apple iMessage via platform adapter

### Infrastructure
- Tailscale CLI (optional, for Serve/Funnel exposure and tailnet-based auth)
- Docker (optional, for sandbox execution of agent tool calls)
- Playwright / Chromium (optional, for browser automation tools)
- Bonjour/mDNS (`@homebridge/ciao`) for local service discovery

### Key npm Libraries
| Package | Purpose | Security Relevance |
|---|---|---|
| `@whiskeysockets/baileys` 7.0.0-rc.9 | WhatsApp Web | Pinned exact version; no `^` |
| `ws` ^8.19.0 | WebSocket server/client | Core transport |
| `express` ^5.2.1 | HTTP middleware | Slack webhook handling |
| `hono` 4.11.4 | HTTP framework | Pinned (pnpm override) |
| `tar` 7.5.3 | Archive extraction | Pinned (pnpm override; supply-chain risk for extraction) |
| `ajv` ^8.17.1 | JSON schema validation | Protocol frame validation |
| `zod` ^4.3.5 | Runtime type checking | Config/input validation |
| `playwright-core` 1.57.0 | Browser automation | Access to arbitrary web pages |
| `proper-lockfile` ^4.1.2 | File locking | Gateway singleton enforcement |
| `sqlite-vec` 0.1.7-alpha.2 | Vector extension for SQLite | Loaded as native extension |
| `dotenv` ^17.2.3 | Env file loading | Credential exposure risk if misconfigured |

---

## Security Controls

### Built-in Security Audit Engine (`src/security/`)
The application ships a `clawdbot security audit` command that performs a comprehensive self-assessment:
- **Filesystem permissions:** state directory and config file world/group readability/writability (flags `chmod 700` and `chmod 600` remediations)
- **Gateway exposure:** detects non-loopback bind without auth, Tailscale Funnel exposure, short auth tokens
- **Browser control:** detects remote control URL without token, HTTP-only remote URLs, token reuse
- **Logging:** flags `redactSensitive="off"`
- **Elevated exec:** flags wildcard `*` entries in `tools.elevated.allowFrom`
- **Hooks hardening:** checks for hooks token configuration
- **Channel security:** detects open DM/group policies, missing sender allowlists, wildcard allowlists for each channel plugin
- **Secrets in config:** scans config for plaintext secrets
- **Model hygiene:** checks model configuration

### Input Validation
- All WebSocket protocol frames are validated against TypeBox/AJV schemas before processing
- Hook payloads are validated and normalized (type checks, trimming, size limits)
- JSON body size enforced: hooks default 256 KB; OpenAI endpoint default 1 MB
- Executable safety check (`isSafeExecutableValue`) rejects shell metacharacters, null bytes, control characters, and leading dashes before constructing exec commands

### Cryptographic Controls
- Password and token comparisons use `timingSafeEqual` (Node.js `node:crypto`) to prevent timing attacks
- Device identity: Ed25519 key pair generated with `crypto.generateKeyPairSync`; signatures verified with `crypto.verify`
- Token generation: `crypto.randomBytes(24).toString('base64url')`
- Device identity file written with mode 0o600; `chmodSync` called as best-effort after write

### Exec Approval System
- Default exec security mode is `deny`; agents cannot execute shell commands without explicit allowlist entries or interactive approval
- Interactive approvals time out to `deny` if not resolved within the configured window
- Allowlist patterns support glob matching; paths are resolved and normalized before matching

### Network Binding
- Gateway default bind is loopback (`127.0.0.1`)
- `lan` mode binds to `0.0.0.0` and must be paired with explicit auth
- `auto` mode prefers Tailnet IPv4, falls back to `0.0.0.0`
- Auth mode `none` with non-loopback binding is flagged as `critical` by the audit engine

### TLS Support
- Gateway HTTP server supports optional TLS (`tlsOptions` passed to `createHttpsServer`)
- Tailscale Serve provides TLS termination at the Tailscale layer

### Deduplication
- Request deduplication cache (TTL 5 minutes, max 1000 entries) prevents duplicate processing of replayed messages

### Rate Limiting
- Telegram requests throttled via `@grammyjs/transformer-throttler`
- No built-in rate limiting on gateway WebSocket or hooks endpoints; Tailscale Serve provides some network-layer protection when used

### Session Isolation
- Session key scheme supports per-channel-peer isolation (`session.dmScope="per-channel-peer"`) to prevent context leakage across different DM senders
- Shared `main` session (default) is flagged as a warning when multiple DM users are configured

---

## Notes

### Trust Boundaries
1. **Loopback boundary:** The gateway WebSocket and HTTP endpoints are safe without credentials only when bound to loopback and not reachable by other users on the same host.
2. **Tailscale boundary:** When `allowTailscale=true`, the Tailscale local proxy is trusted to inject authenticated user headers; the gateway validates that the request came through loopback with correct proxy headers. This trust depends on the Tailscale daemon not being compromised.
3. **Channel bot token boundary:** Bot tokens (Telegram, Slack, Discord) grant significant permissions on those platforms; compromise of the config file exposes these tokens.
4. **AI provider API key boundary:** API keys stored in `auth-profiles.json` grant billing access; file permissions are the only protection.
5. **Exec approval boundary:** The exec approval system separates agent-requested commands from user-approved commands; however, `allow-always` decisions persist in `exec-approvals.json` and apply to future sessions.
6. **Plugin extension boundary:** Extensions loaded from `extensions/*/` run in the same Node.js process with no sandbox isolation.

### Notable Security Observations
- The hooks token can be passed as a URL query parameter (`?token=`), which may appear in server access logs.
- The OpenAI-compatible endpoint accepts the same token as both `token` and `password` mode auth, which slightly reduces the benefit of using separate credential types.
- Swabble's `HookExecutor` passes wake-word transcription directly as a command-line argument to a user-configured binary. The hook command is trusted by design, but `SWABBLE_TEXT` and prefix interpolation with `${hostname}` use string substitution without shell escaping; callers that pass the payload to a shell must handle quoting themselves.
- Config write operations require a `baseHash` match, providing optimistic concurrency protection against conflicting writes from multiple clients.
- The `BOOT.md` mechanism executes agent instructions from a local file at gateway startup; this file should be treated as a trust boundary if it is writable by other users.
- Tailscale Funnel mode exposes the gateway to the public internet; the audit engine correctly flags this as `critical` and recommends Tailscale Serve instead.
- WhatsApp session files are stored in plaintext under `~/.clawdbot/sessions/`; these allow re-establishing the WhatsApp session without re-pairing.
- The `tar` and `hono` packages are pinned to exact versions via pnpm overrides, reducing supply-chain drift risk for those packages.
