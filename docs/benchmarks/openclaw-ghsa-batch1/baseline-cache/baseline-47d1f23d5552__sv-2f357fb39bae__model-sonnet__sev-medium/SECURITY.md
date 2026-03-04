# Security Architecture

## Overview

Clawdbot is a multi-channel AI gateway application that bridges messaging platforms (WhatsApp, Telegram, Slack, Discord, iMessage, Signal, and others via extensions) to AI language model providers (Anthropic Claude, OpenAI, Groq, Google Gemini/Antigravity, Deepgram, and others). The system is deployed as a personal "gateway" daemon on a user's own machine, with native clients (macOS menubar app, iOS, Android), a CLI, a web control UI, and a WebSocket-based protocol for client-gateway communication.

A secondary sub-project, **Swabble**, is a Swift-based macOS voice wake-word detection CLI that can invoke arbitrary commands on transcribed speech.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                          User Devices                                │
│  macOS App  │  iOS App  │  Android App  │  Web Browser (control UI) │
└──────┬───────┴─────┬─────┴───────┬───────┴──────────┬───────────────┘
       │   WSS       │   WSS       │   WSS             │   HTTP(S)
       ▼             ▼             ▼                   ▼
┌──────────────────────────────────────────────────────┐
│              Gateway (Node.js daemon)                │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ WebSocket  │  │  HTTP Server │  │  Hook Server │ │
│  │ Server(ws) │  │  (express/   │  │  (POST /hooks│ │
│  │           │  │  hono)       │  │  token auth) │ │
│  └────────────┘  └──────────────┘  └──────────────┘ │
│  ┌────────────────────────────────────────────────┐  │
│  │              Gateway Bridge                   │  │
│  │  config · chat · sessions · system methods    │  │
│  └────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────┐  │
│  │           Channel Monitors (inbound)           │  │
│  │  WhatsApp(Baileys)  Telegram(grammy)  Slack    │  │
│  │  Discord  iMessage  Signal  Bluebubbles        │  │
│  │  MSTeams  Matrix  Zalo  Voice-Call (ext)       │  │
│  └────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────┐  │
│  │         Agent / AI Execution Layer             │  │
│  │  pi-agent  claude-cli  bash-tools  web-tools   │  │
│  │  Sandbox (Docker optional)  Cron agent         │  │
│  └────────────────────────────────────────────────┘  │
│  ┌──────────────────┐  ┌───────────────────────────┐ │
│  │  OpenAI-compat   │  │  Tailscale serve/funnel   │ │
│  │  /v1/chat/compl. │  │  (optional exposure)      │ │
│  └──────────────────┘  └───────────────────────────┘ │
└──────────────────────────────────────────────────────┘
       │  HTTPS API calls to AI providers
       ▼
  Anthropic / OpenAI / Groq / Gemini / Deepgram / MiniMax / ...
```

The daemon is typically single-user and runs on a personal machine. It exposes:
- A WebSocket endpoint for its own first-party clients (native apps, TUI).
- An HTTP endpoint for inbound webhooks, Slack HTTP events, a control UI (served as static files), and an OpenAI-compatible `/v1/chat/completions` path.
- Optionally exposed via Tailscale Serve (tailnet-only) or Tailscale Funnel (public internet).

---

## Technology Stack

| Component | Technology |
|---|---|
| Core runtime | Node.js >= 22.12.0, TypeScript (ESM) |
| Package manager | pnpm 10.23, Bun (dev/test) |
| Web framework (HTTP) | Express 5, Hono 4 |
| WebSocket | ws 8 |
| AI agent framework | @mariozechner/pi-agent-core 0.46, pi-ai, pi-coding-agent |
| Agent Client Protocol | @agentclientprotocol/sdk 0.13 |
| WhatsApp | @whiskeysockets/baileys 7.0.0-rc.9 |
| Telegram | grammy 1.39, @grammyjs/runner |
| Slack | @slack/bolt 4, @slack/web-api 7 |
| Discord | @buape/carbon (beta) |
| Browser automation | playwright-core 1.57.0, chromium-bidi 12.0.1 |
| Sandbox | Docker (child_process spawn) |
| Vector memory | sqlite-vec 0.1.7-alpha (SQLite extension), node-llama-cpp 3.14.5 (optional) |
| Schema validation | @sinclair/typebox 0.34.47, ajv 8, zod 4, AJV |
| Job scheduling | croner 9 |
| Media processing | sharp 0.34.5, file-type 21 |
| Tunneling | Tailscale (serve/funnel, via CLI subprocess calls) |
| Network discovery | @homebridge/ciao (mDNS/Bonjour) |
| PTY | @lydell/node-pty |
| Config file format | JSON5 (json5 2.2.3), YAML 2 |
| Locking | proper-lockfile 4.1.2 |
| macOS app | Swift / SwiftUI (apps/macos) |
| iOS app | Swift / SwiftUI (apps/ios) |
| Android app | Kotlin (apps/android) |
| Voice wake-word (Swabble) | Swift, Apple SpeechAnalyzer/SpeechTranscriber (macOS 26+) |
| Test framework | Vitest 4, V8 coverage |
| Linter/formatter | Oxlint, Oxfmt |

---

## Entry Points

### WebSocket (Primary Client Gateway)
- **Endpoint:** `ws://localhost:<port>` (default port configurable; binds to loopback by default)
- **Protocol:** Custom binary/JSON protocol over WebSocket frames; first message must be `connect` with credentials
- **Auth:** Token or password in the `connect` message; Tailscale user-header auth when behind Tailscale Serve
- **Clients:** macOS app, iOS app, Android app, browser control UI, CLI via gateway-cli

### HTTP Server (same port as WebSocket)
- **`POST /hooks/<token>/wake`** and **`POST /hooks/<token>/agent`** — inbound webhook endpoints (token-gated)
- **`POST /hooks/<basePath>/<mapping-path>`** — custom hook mappings
- **`POST /v1/chat/completions`** — OpenAI-compatible chat endpoint (optional, uses same gateway auth)
- **`GET /control-ui/...`** — Static web control UI assets
- **Slack HTTP events** — handled if Slack channel configured
- **Canvas/a2ui** — canvas host HTTP handler for multi-modal app bridge
- **Plugin HTTP handlers** — extension plugins may register additional HTTP routes

### Inbound Messaging Channels (outbound connections from gateway to platform)
- **WhatsApp Web:** WebSocket to WhatsApp servers via Baileys library (long-poll auth with QR or pairing code)
- **Telegram:** Bot API long-polling or webhook via grammy
- **Slack:** Bot socket-mode or HTTP events
- **Discord:** Bot WebSocket connection via @buape/carbon
- **iMessage:** Local macOS iMessage bridge (AppleScript / sqlite)
- **Signal:** Local signal-cli bridge
- **BlueBubbles:** HTTP to local BlueBubbles server (extension)
- **MS Teams:** Bot Framework (extension)
- **Matrix:** Matrix client SDK (extension)
- **Zalo / ZaloUser:** (extension)
- **Voice-Call:** (extension)

### CLI Entry Points
- `clawdbot gateway` — starts the daemon
- `clawdbot agent --message "..."` — sends a message directly to the agent
- `clawdbot message send ...` — sends a message via a configured channel
- `clawdbot security audit` — runs a local security audit
- Various admin subcommands (channels, models, sessions, nodes, cron, sandbox, etc.)

### Cron / Scheduled Agents
- Cron jobs configured in `clawdbot.json5` trigger isolated agent runs on a schedule, without user interaction.

### Swabble (voice wake-word)
- Listens to the microphone continuously, triggers a configurable shell command with the transcribed text when the wake word is detected.

---

## Authentication & Authorization

### Gateway WebSocket Auth
Three modes, configured in `gateway.auth` or via environment variables:

| Mode | Description | Notes |
|---|---|---|
| `none` | No auth required | Only safe on loopback |
| `token` | Static bearer token in `connect` message | Compared with `timingSafeEqual` |
| `password` | Static password in `connect` message | Compared with `timingSafeEqual` |

The `CLAWDBOT_GATEWAY_TOKEN` and `CLAWDBOT_GATEWAY_PASSWORD` environment variables can override config-file values.

**Tailscale auth:** When `gateway.tailscale.mode = "serve"` and `gateway.auth.allowTailscale = true`, connections carrying both `tailscale-user-login` and the `x-forwarded-for/x-forwarded-proto/x-forwarded-host` headers from loopback are accepted based on the Tailscale identity header — without a token/password.

**Local bypass:** Connections from loopback (`127.x`, `::1`, `::ffff:127.x`) to a `localhost` or `127.0.0.1` host header, with no proxy-forwarding headers, are treated as "local direct" connections and skip Tailscale checks (but still enforce token/password if configured).

**Important note:** In `auth.mode = "none"` the gateway accepts all connections from loopback without any credential. If the gateway binds beyond loopback (modes: `lan`, `auto`, `custom`) AND `auth.mode = "none"`, the built-in security audit will flag this as **critical**.

### OpenAI-Compatible Endpoint Auth
The `/v1/chat/completions` endpoint uses the same `authorizeGatewayConnect` function, extracting the Bearer token from the `Authorization` header and mapping it to the gateway token or password.

### Hook Webhook Auth
HTTP webhooks require a token either as:
- `Authorization: Bearer <token>` header
- `X-Clawdbot-Token: <token>` header
- `?token=<token>` query parameter

The token is compared as a plain string equality (`!==`), not timing-safe. This is a potential timing oracle for the webhook token.

### Channel-level Authorization (per-user allowlists)
- Each messaging channel enforces sender allowlists (`allowFrom`, `groupAllowFrom`, per-guild/per-channel user lists for Discord/Slack).
- A pairing system issues 8-character random codes (from a custom alphabet) via DM; successful pairing appends the user to a persisted `allowFrom` store (`pairing-store.ts`), backed by JSON files with file locking.
- `requireMention` logic for group chats: bots in groups require an explicit @-mention unless commands bypass this gate.
- `dmPolicy` can be `open` (anyone), `allowlist` (only approved users), or `disabled`.
- `groupPolicy` can be `open` or `allowlist`.

### Elevated Tool Execution
The `tools.elevated` feature allows certain channel senders (configured in `tools.elevated.allowFrom`) to execute commands with elevated permissions. Wildcards (`*`) in this allowlist are flagged as **critical** by the security audit.

### Exec Approvals
An exec-approval system (`exec-approvals.ts`, schema in `schema/exec-approvals.ts`) controls which shell commands the agent can run without interactive confirmation. The allowlist uses patterns and tracks last-used timestamps. This integrates with a Unix socket for approval dialogs.

---

## Data Flow

### Inbound Message Flow (Messaging Channel → Agent → Reply)
```
1. Messaging platform → Channel monitor (e.g., Baileys WebSocket, grammy poll)
2. Channel monitor → allowFrom / mention-gating checks
3. Authorized message → auto-reply engine (src/auto-reply/reply/)
4. Directive extraction (exec, wake, etc.)
5. Agent execution (pi-embedded or claude-cli-runner)
   a. If sandbox enabled: Docker container is created/reused; agent commands run inside container
   b. Tool calls (bash-tools, web-tools, browser-tools) execute in sandbox or host
6. Agent reply → channel outbound sender
7. Reply delivered back to messaging platform
```

### Gateway Client → Gateway → Agent
```
1. Client WebSocket connect with credentials → auth check
2. Authenticated client sends method calls (chat, config.get, config.set, etc.)
3. Bridge handlers dispatch to appropriate subsystem
4. For chat: message is queued to embedded pi-agent; streaming events sent back via WebSocket
5. Config changes written to ~/.clawdbot/clawdbot.json5
```

### Inbound Webhook → Agent
```
1. External system POST /hooks/<token>/agent
2. Token validated (plain string equality)
3. Payload normalized (message, sessionKey, channel, model, deliver)
4. dispatchAgentHook called → agent runs as isolated job
5. Optional reply delivery to configured channel
```

### OpenAI-Compatible API → Agent
```
1. POST /v1/chat/completions with Bearer token
2. Token validated via authorizeGatewayConnect
3. Message history converted to agent prompt
4. agentCommand executed (non-streaming or SSE streaming)
5. Agent response returned as OpenAI chat completion response
```

### Sensitive Data in Transit
- All AI provider API calls go over HTTPS to external provider endpoints.
- WhatsApp: end-to-end encrypted messages decrypted locally by Baileys; plaintext passes through gateway.
- Telegram/Slack/Discord: messages arrive in plaintext over TLS from platform APIs.
- Between gateway and native clients: WebSocket (optionally TLS via Tailscale Serve/Funnel).
- Voice (Swabble): transcription is entirely on-device via Apple's SpeechAnalyzer; audio is not sent externally.

---

## Sensitive Data

### Credentials & Secrets
- **AI provider API keys** (Anthropic, OpenAI, Groq, Gemini, Deepgram, MiniMax, etc.): stored in `~/.clawdbot/auth-profiles.json`; modes: `api_key`, `oauth` (access+refresh token), `token`
- **Gateway auth token / password**: stored in `~/.clawdbot/clawdbot.json5` or environment variables `CLAWDBOT_GATEWAY_TOKEN` / `CLAWDBOT_GATEWAY_PASSWORD`
- **WhatsApp session credentials**: stored in `~/.clawdbot/sessions/` (Baileys auth state)
- **Telegram bot token**: in config
- **Slack bot/app tokens**: in config
- **Discord bot token**: in config
- **OAuth tokens** (Google Gemini, GitHub Copilot Proxy, etc.): stored in `~/.clawdbot/credentials/`
- **Webhook token**: in `hooks.token` config field
- **Browser control token**: in `browser.controlToken` or `CLAWDBOT_BROWSER_CONTROL_TOKEN`
- **Matrix credentials**: stored in extension state
- **BlueBubbles server password**: in extension config

### Personal / Conversation Data
- **Chat message content**: passes through gateway in plaintext; optionally logged
- **Agent session history**: stored in JSONL files under `~/.clawdbot/agents/<agentId>/sessions/`
- **Voice transcripts** (Swabble): stored in `~/.config/swabble/` by default
- **Pairing store**: user IDs of approved senders stored in `~/.clawdbot/credentials/pairing-<channel>.json`
- **Sandbox workspaces**: file system data written by agents in `~/.clawdbot/workspaces/` (configurable)

### Logging & Redaction
- `logging.redactSensitive` setting controls whether sensitive content is redacted in tool summaries; default should be `"tools"` — setting to `"off"` is flagged as **warn** by the security audit.

---

## External Dependencies

### AI Model Providers (outbound HTTPS)
- Anthropic Claude API
- OpenAI API
- Groq API
- Google Gemini / Antigravity (OAuth-authenticated)
- GitHub Copilot Proxy (OAuth-authenticated, extension)
- Deepgram (audio transcription)
- MiniMax
- Ollama (local, optional)
- Firecrawl (optional web-content tool)

### Messaging Platforms (outbound connections)
- WhatsApp Web (via Baileys, WebSocket to WhatsApp servers)
- Telegram Bot API
- Slack API / Socket Mode
- Discord API (WebSocket bot)
- Apple iMessage (local macOS)
- Signal (local signal-cli binary)
- BlueBubbles server (local HTTP, extension)
- Microsoft Teams Bot Framework (extension)
- Matrix homeserver (extension)
- Zalo API (extension)

### Infrastructure / Tunneling
- **Tailscale**: `tailscale serve` / `tailscale funnel` invoked as a CLI subprocess to expose the gateway; user identity headers injected by Tailscale daemon
- **Docker**: used for agent sandbox isolation; `execDocker` spawns the `docker` CLI as a subprocess

### Notable Third-Party Libraries (security-relevant)
| Library | Purpose | Notes |
|---|---|---|
| `@whiskeysockets/baileys` 7.0.0-rc.9 | WhatsApp Web | RC release; handles E2E key material |
| `ws` 8 | WebSocket server | Core connectivity |
| `playwright-core` 1.57.0 | Browser automation | Used by agents for web tasks |
| `@mozilla/readability` | HTML content extraction | |
| `node-llama-cpp` 3.14.5 | Local LLM inference | Optional |
| `sqlite-vec` 0.1.7-alpha.2 | Vector similarity search | Alpha release; loads native SQLite extension |
| `proper-lockfile` | File locking for pairing/config | |
| `jszip` | ZIP file handling | |
| `tar` 7.5.3 | TAR archive handling | Version pinned via pnpm override |
| `hono` 4.11.4 | HTTP framework | Version pinned via pnpm override |
| `@sinclair/typebox` 0.34.47 | Runtime schema validation | Version pinned |

---

## Security Controls

### Existing Controls

**Authentication**
- WebSocket gateway: token or password auth with `timingSafeEqual` for constant-time comparison
- Hooks: token-based (note: plain `!==` comparison, not timing-safe)
- Channel allowlists: per-sender, per-group, per-channel user allowlists
- Pairing flow: 8-character cryptographically random code exchange for user onboarding

**Input Validation**
- Gateway protocol params validated with AJV-compiled TypeBox schemas before processing
- Config changes via `config.set` / `config.patch` validated against the full config schema
- Body size limits enforced for HTTP hooks (`DEFAULT_HOOKS_MAX_BODY_BYTES = 256 KB`), OpenAI endpoint (1 MB default), and WebSocket frames (`MAX_PAYLOAD_BYTES = 512 KB`)
- Config mutation requires a `baseHash` check to prevent lost-update races

**Authorization / Access Control**
- Channel-level `dmPolicy` / `groupPolicy` enforcement
- `requireMention` gating for group chats
- Elevated exec `allowFrom` lists with wildcard detection in security audit
- Exec approval allowlist with pattern matching for agent shell commands
- Sandbox tool policy (allow/deny lists per agent or global)

**Sandbox Isolation (optional)**
- Agent commands can be isolated in Docker containers via `tools.sandbox` config
- Container hardening options: `--read-only`, `--no-new-privileges`, `--security-opt seccomp=...`, `--security-opt apparmor=...`, `--cap-drop`, `--pids-limit`, memory/CPU limits, `--user`, network isolation
- Workspace access can be set to `none`, `ro`, or `rw`

**Secret Management**
- API keys and OAuth tokens stored in `~/.clawdbot/` (user's home directory)
- Security audit checks file permissions on state dir and config file (flags world-readable/writable as critical, group-readable as warn)
- Security audit checks for secrets accidentally embedded directly in config fields

**Networking**
- Default gateway bind: `127.0.0.1` (loopback only)
- `lan` / `auto` / `custom` modes bind to wider interfaces; security audit flags no-auth + non-loopback as **critical**
- Tailscale Funnel (public internet exposure) flagged as **critical** by security audit

**Logging**
- `logging.redactSensitive` option to redact sensitive content in tool summaries
- `off` setting flagged as **warn** by security audit

**Security Audit System** (`src/security/audit.ts`)
- Built-in CLI command `clawdbot security audit [--deep]`
- Checks: gateway bind + auth, Tailscale exposure, file permissions on state/config, config readable by others, secrets in config, hooks hardening, model hygiene, exposure matrix, channel DM/group policies, elevated exec wildcards, browser control auth, logging redaction, synced folder detection (iCloud/Dropbox/OneDrive), plugin trust

### Notable Absent or Weak Controls

- **Webhook token comparison is not timing-safe**: `extractHookToken` extracts the token, then the caller uses `token !== hooksConfig.token` (plain `!==`), not `timingSafeEqual`. This creates a timing oracle for hook token guessing.
- **No rate limiting** on WebSocket connections, HTTP hooks, or the OpenAI-compatible endpoint in application code; reliance on network-layer controls.
- **No CSRF protection** on the HTTP endpoints; the control UI and hook endpoints do not use CSRF tokens (the hook endpoint uses a secret token instead).
- **Tailscale user headers are implicitly trusted**: if `allowTailscale = true`, the presence of `tailscale-user-login` and proxy headers from loopback is sufficient for full access. There is a check that the connection is from loopback (`isTailscaleProxyRequest`) but the headers themselves are not cryptographically verified by the application — this relies entirely on Tailscale daemon integrity.
- **Docker sandbox is optional and defaults to off**: agents run without sandbox isolation by default; all tool execution (bash, file read/write, web fetch) happens in the host process under the user's OS account.
- **Session key provided by clients**: the OpenAI-compatible endpoint accepts an explicit `x-clawdbot-session-key` header from callers, allowing them to inject arbitrary session keys. The `user` field from the OpenAI payload is used directly to construct persistent session keys (`openai-user:<user>`), enabling cross-session targeting if a caller knows another user's identifier.
- **Config write access**: any authenticated WebSocket client (single auth token) can write/patch the entire gateway config including channel tokens, API keys (via `config.set`), and exec-approval lists.
- **Swabble hook executor**: user-supplied `hook.command` and `hook.args` from `~/.config/swabble/config.json` are passed directly to `Process()` — no sanitization — but the config is local-only.

---

## Notes

### Deployment Context
- Intended as a personal, single-user daemon (not a multi-tenant service).
- Runs on the user's machine (macOS, Linux, Raspberry Pi common targets).
- State stored in `~/.clawdbot/` (configurable via `CLAWDBOT_STATE_DIR`).

### Plugin / Extension Trust Model
- Extensions in `extensions/*` are workspace packages loaded at runtime from the npm package.
- The security audit includes a `collectPluginsTrustFindings` check for plugin file permissions.
- Extensions can register HTTP handlers, channel monitors, and tool providers with broad system access.

### Mobile Apps
- iOS and Android apps connect to the gateway over WebSocket (typically via Tailscale or LAN).
- They do not store AI API keys; keys are managed by the gateway daemon.

### Swabble Specifics
- The Swift `HookExecutor` appends user-transcribed voice text as a shell argument to `hook.command`. If `hook.prefix` or `hook.args` contain attacker-controlled values, this could be a concern — but the config file is local only.
- No network exposure by design; it is a local CLI/daemon.

### Supply Chain Observations
- Several dependencies are pre-release / RC versions: `@whiskeysockets/baileys` (7.0.0-rc.9), `sqlite-vec` (0.1.7-alpha.2), `@buape/carbon` (beta), `@lydell/node-pty` (1.2.0-beta.3). These should be monitored for security advisories.
- `pnpm.minimumReleaseAge = 2880` (2 days) provides a minor supply-chain delay buffer.
- `tar` and `hono` versions are pinned via `pnpm.overrides` (likely for security or compatibility fixes).
