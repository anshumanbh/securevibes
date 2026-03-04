# Security Architecture

## Overview

Clawdbot is a multi-platform AI assistant gateway that bridges multiple messaging platforms (WhatsApp, Telegram, Signal, iMessage, Slack, Discord, Microsoft Teams) with AI language model providers (Anthropic Claude, OpenAI, Google Gemini, and others). The system operates as a locally-run service on the user's machine, receiving messages from external messaging services, routing them to AI models, and delivering responses back. It includes a CLI, a macOS menubar app, and companion iOS/Android applications. A secondary component called Swabble provides voice wake-word detection on macOS.

The application handles highly sensitive data: AI provider API keys or OAuth tokens, WhatsApp session credentials (equivalent to full account access), Telegram bot tokens, Slack and Discord bot tokens, Gmail OAuth tokens, and all user message content flowing through the system.

---

## Architecture

```
                          ┌──────────────────────────────────────────────────────┐
                          │               Host Machine (macOS / Linux)            │
                          │                                                        │
  ┌──────────┐  WebSocket │  ┌────────────┐   ┌──────────────────────────────┐   │
  │ macOS App│◄──────────►│  │  Gateway   │   │        Pi Embedded Runner     │   │
  │ iOS App  │            │  │  Server    │◄──┤  (pi-agent-core, pi-ai libs) │   │
  │ Android  │  WS + HTTP │  │  (WS/HTTP) │   │  Model API calls              │   │
  └──────────┘            │  └─────┬──────┘   └──────────────────────────────┘   │
                          │        │                                               │
  ┌──────────┐  Webhook   │  ┌─────▼──────┐   ┌──────────────────────────────┐   │
  │  Gmail   │◄──────────►│  │   Hooks    │   │  Auth Profiles Store         │   │
  │  Webhook │            │  │  Handler   │   │  (~/.clawdbot/auth-profiles)  │   │
  └──────────┘            │  └────────────┘   └──────────────────────────────┘   │
                          │                                                        │
  ┌──────────┐  Long-poll │  ┌────────────────────────────────────────────────┐  │
  │Telegram  │◄──────────►│  │          Provider Plugins                       │  │
  │Discord   │            │  │  WhatsApp (Baileys) │ Telegram │ Slack          │  │
  │Slack     │  Bot APIs  │  │  Discord  │ iMessage │ Signal   │ MSTeams        │  │
  │Signal    │            │  └────────────────────────────────────────────────┘  │
  │iMessage  │            │                                                        │
  │MSTeams   │            │  ┌────────────────────────────────────────────────┐  │
  └──────────┘            │  │          AI Model Providers (outbound HTTPS)    │  │
                          │  │  Anthropic │ OpenAI │ Google │ Groq │ Others    │  │
                          │  └────────────────────────────────────────────────┘  │
                          │                                                        │
  ┌──────────┐  Tailscale │  ┌──────────────────────────────────────────────────┐│
  │ Remote   │◄──────────►│  │  OpenAI-Compatible HTTP endpoint (/v1/chat/...)  ││
  │ Clients  │            │  └──────────────────────────────────────────────────┘│
  └──────────┘            └──────────────────────────────────────────────────────┘

  Swabble (macOS): Voice wake-word → local subprocess → Clawdbot CLI
```

### Key Components

- **Gateway Server** (`src/gateway/`): Central WebSocket + HTTP server. Manages client connections, dispatches RPC-style messages, handles authentication, and coordinates all subsystems.
- **Provider Plugins** (`src/providers/`): Per-platform adapters for WhatsApp, Telegram, Slack, Discord, Signal, iMessage, and Microsoft Teams.
- **Pi Embedded Runner** (`src/agents/`): Wraps the `@mariozechner/pi-coding-agent` library for LLM inference. Manages API key resolution, context windows, tool execution, and agent sessions.
- **Hooks Handler** (`src/gateway/hooks.ts`, `src/gateway/server-http.ts`): Token-authenticated HTTP webhook receiver for external triggers (e.g., Gmail push notifications).
- **Canvas Host** (`src/canvas-host/`): Embedded HTTP/WebSocket file server for the control UI and agent canvas (a2ui).
- **Cron Service** (`src/cron/`): Scheduled agent task runner.
- **Swabble** (`Swabble/`): Standalone Swift macOS CLI for voice wake-word detection; executes a configurable hook command on trigger.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 22+ (TypeScript/ESM), Bun (dev/build) |
| Language | TypeScript (strict), Swift (macOS/iOS), Kotlin (Android) |
| Core server | `ws` (WebSocket), `express` v5 / raw Node.js `http` |
| WhatsApp | `@whiskeysockets/baileys` 7.0.0-rc.9 (unofficial WhatsApp Web) |
| Telegram | `grammy` + `@grammyjs/runner` |
| Slack | `@slack/bolt`, `@slack/web-api` |
| Discord | `@buape/carbon` (Carbon framework, beta) |
| MS Teams | `@microsoft/agents-hosting-express` |
| AI inference | `@mariozechner/pi-agent-core`, `@mariozechner/pi-ai`, `@mariozechner/pi-coding-agent` |
| Schema validation | `zod`, `@sinclair/typebox`, `ajv` |
| Config format | JSON5 (`json5` library) |
| Browser automation | `playwright-core`, `chromium-bidi` |
| Media processing | `sharp`, `file-type` |
| Discovery | `@homebridge/ciao` (mDNS/Bonjour) |
| Scheduling | `croner` |
| File locking | `proper-lockfile` |
| Credentials storage | macOS Keychain (`security` CLI), flat JSON files |
| Markdown | `markdown-it` |
| Networking | `undici` |

---

## Entry Points

### WebSocket Gateway (primary)
- **Port**: Configurable (default: loopback, `127.0.0.1`; can be set to `0.0.0.0` for LAN, or Tailscale IP).
- **Protocol**: JSON-based RPC over WebSocket.
- **Auth**: Token, password, Tailscale user header, or none (loopback-only mode).
- **Clients**: macOS app, iOS app, Android app, CLI, TUI.

### HTTP Endpoints (co-hosted on gateway port)
- `POST /hooks/<subpath>` — Token-authenticated webhook receiver (external triggers, Gmail push, etc.).
- `POST /v1/chat/completions` — OpenAI-compatible chat completions API (optional, same auth as gateway).
- `GET/POST /canvas/*` — Canvas host (a2ui UI assets, agent canvas files).
- `GET /control-ui/*` — Control web UI static assets.

### CLI Commands
- `clawdbot gateway` — Start the gateway server.
- `clawdbot agent --message <msg>` — Run an agent turn inline.
- `clawdbot message send` — Send a message to a messaging platform.
- `clawdbot login` — Authenticate with a provider.
- `clawdbot tui` — Terminal UI.
- `clawdbot doctor` — Diagnostic checks.
- Various subcommands for config, sessions, cron, status, etc.

### External Webhooks (inbound)
- **Gmail**: Google Pub/Sub push notifications arrive at the configured `hooks.gmail.serveBind:servePort/servePath`; validated by a `pushToken`.
- **Telegram**: Webhook mode (optional); bot token authentication handled by Telegram's infrastructure.
- **Discord**: `@buape/carbon` framework webhook handling.
- **MS Teams**: `@microsoft/agents-hosting-express` webhook with its own JWT validation.

### Swabble (macOS voice component)
- `swabble serve` — Listens for microphone input, fires hook command on wake word.
- Hook command is a configurable shell command; the transcribed text is passed as an argument and via `SWABBLE_TEXT` environment variable.

---

## Authentication & Authorization

### Gateway WebSocket / HTTP Authentication

Three configurable modes (set in `gateway.auth.mode`):

1. **`none`**: No authentication required. The gateway binds only to loopback by default; connections from non-loopback addresses require Tailscale headers when `allowTailscale` is true.
2. **`token`**: A static bearer token (`CLAWDBOT_GATEWAY_TOKEN` env var or `gateway.auth.token` config). Compared using `timingSafeEqual` (constant-time comparison) to prevent timing attacks. Source: `src/gateway/auth.ts`.
3. **`password`**: A plaintext password compared via `timingSafeEqual`.

**Tailscale mode**: When `allowTailscale: true`, requests must arrive via the Tailscale proxy with `tailscale-user-login`, `x-forwarded-for`, `x-forwarded-proto`, and `x-forwarded-host` headers all present. The gateway trusts these headers implicitly when the source address is loopback (proxy-injected). There is no independent cryptographic verification of Tailscale headers beyond the presence of the loopback source address.

**Loopback bypass**: Requests arriving from `127.0.0.1` or `::1` without any forwarding headers bypass authentication entirely in `none` mode. This is a deliberate design choice for local-only deployments. Source: `src/gateway/auth.ts::isLocalDirectRequest`.

**Hooks endpoint**: Uses a separate static bearer token (`hooks.token`) checked via plain string equality (`token !== hooksConfig.token`), not constant-time comparison. Source: `src/gateway/server-http.ts` line 85. This token can also be passed as a query parameter (`?token=...`), which may be logged in access logs or server-side request logs.

**OpenAI-compatible endpoint**: Uses the same gateway auth (token or password), accepting the bearer token from the `Authorization: Bearer <token>` header.

### AI Provider Authentication

API keys and OAuth tokens are resolved from multiple sources in order:
1. Named auth profiles in `~/.clawdbot/auth-profiles.json` (locked with `proper-lockfile` during writes).
2. Environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `TELEGRAM_BOT_TOKEN`, etc.).
3. Per-provider keys in `models.json` / config file.
4. macOS Keychain (via the `security` CLI binary) for Claude CLI and Codex CLI OAuth credentials.

OAuth credentials (Anthropic Claude, OpenAI Codex) are stored as access/refresh token pairs and refreshed automatically; refreshed credentials are written back to the Keychain or credential file.

### WhatsApp Authentication
- Uses the Baileys library to emulate WhatsApp Web.
- Session state (including long-lived auth keys equivalent to full account access) is stored locally in `~/.clawdbot/credentials/` (configurable per account via `WA_WEB_AUTH_DIR`).
- Initial login requires QR code scanning or phone number pairing code.

### Telegram Bot Authentication
- Bot token stored in config (`telegram.botToken`), environment variable (`TELEGRAM_BOT_TOKEN`), or a token file.
- Token file path is configurable and must already exist; the file is read with `fs.readFileSync`.

### Pairing / Access Control
- **DM policy**: Configurable per provider (`open`, `disabled`, `allowlist`, `pairing`). In `pairing` mode, the bot requires an explicit pairing handshake from the user.
- **Group policy**: `open`, `disabled`, or `allowlist`. Groups can require explicit bot mention.
- **Agent access**: Agent tools can optionally be gated to specific providers via `tools.elevated.allowFrom.<provider>`.

---

## Data Flow

### Inbound Message Flow
```
1. External platform (WhatsApp/Telegram/etc.) sends message to provider plugin
2. Provider plugin normalizes message format (sender ID, content, attachments)
3. Message routed to gateway server via internal event queue
4. Gateway applies DM/group policy checks (allowlist, pairing gate, require-mention)
5. Message dispatched to Pi Embedded Runner (agent session)
6. Pi Runner builds context (history + tools), calls AI provider API over HTTPS
7. AI response streamed back; tool calls executed (bash, file I/O, browser, etc.)
8. Reply formatted for target platform (chunking, markdown conversion)
9. Reply delivered via provider plugin outbound send
10. Session transcript stored to ~/.clawdbot/agents/<id>/sessions/*.jsonl
```

### Webhook / Hook Flow
```
1. External system sends POST to /hooks/<subpath> with Bearer token
2. Token validated against hooks.token config (plain equality)
3. JSON body parsed (max 256 KB default)
4. Payload mapped to wake trigger or agent dispatch
5. Agent job queued and executed asynchronously
6. Response (202 Accepted + runId) returned immediately
```

### Credential / Secret Flow
```
1. API key lookup: auth-profiles.json → env vars → config → macOS Keychain
2. Key passed in memory to pi-ai HTTP client as Authorization: Bearer header
3. Outbound HTTPS call to provider API endpoint
4. Response tokens never written to disk unless explicitly cached
5. OAuth refresh: new tokens written to Keychain or auth-profiles.json (file-locked)
```

### Canvas / Control UI Flow
```
1. HTTP GET served from embedded canvas-host server (co-hosted on gateway port)
2. File system access restricted to configured rootDir (symlink traversal blocked)
3. WebSocket connection for live-reload and agent canvas interaction
4. No authentication gating on canvas assets — relies on gateway port being loopback-only
```

---

## Sensitive Data

### AI Provider Credentials
- **Anthropic**: API key (`ANTHROPIC_API_KEY`) or OAuth access+refresh tokens. Stored in macOS Keychain (via `security` binary) or `~/.clawdbot/auth-profiles.json`.
- **OpenAI**: API key (`OPENAI_API_KEY`) or OAuth tokens (Codex). Same storage.
- **Google, Groq, Cerebras, xAI, OpenRouter, MiniMax, Mistral, ZAI**: API keys via env vars or config.
- **GitHub Copilot**: `COPILOT_GITHUB_TOKEN` / `GH_TOKEN` / `GITHUB_TOKEN`.
- **Google Vertex AI**: Application Default Credentials (`gcloud adc`).

### Messaging Platform Credentials
- **WhatsApp**: Long-lived session keys (equivalent to full WhatsApp account access). Stored in `~/.clawdbot/credentials/` as JSON files.
- **Telegram**: Bot token. Stored in config, file, or `TELEGRAM_BOT_TOKEN` env var.
- **Slack**: Bot token (config or env).
- **Discord**: Bot token (config or env).
- **Signal**: Account credentials managed by `signal-cli` (separate process).
- **iMessage**: No credentials in app; relies on OS-level iMessage access.
- **MS Teams**: App ID and password (config or env).

### User Message Content
- All messages from users pass through the application in plaintext.
- Message history is stored on disk in `~/.clawdbot/agents/<id>/sessions/*.jsonl`.
- Content is sent to external AI provider APIs over HTTPS.
- Voice transcripts from Swabble are ephemeral (passed as process arguments, not persisted by Clawdbot itself).

### Gateway Authentication Secrets
- `CLAWDBOT_GATEWAY_TOKEN` / `CLAWDBOT_GATEWAY_PASSWORD`: Static secrets for gateway access.
- `hooks.token`: Webhook authentication token.
- `hooks.gmail.pushToken`: Gmail Pub/Sub push notification verification token.

### Configuration File
- `~/.clawdbot/config.json` (or JSON5 variant): May contain bot tokens, API keys, allowed sender lists, and other sensitive configuration. World-readable unless permissions are manually restricted.

---

## External Dependencies

### Messaging Platform Libraries
- `@whiskeysockets/baileys` 7.0.0-rc.9 — Unofficial WhatsApp Web reverse-engineering library. Pinned to a release candidate. Manipulates WhatsApp's binary protocol.
- `grammy` 1.39.2 + `@grammyjs/runner` — Telegram Bot API client.
- `@slack/bolt` 4.6.0, `@slack/web-api` 7.13.0 — Official Slack SDKs.
- `@buape/carbon` 0.0.0-beta — Discord bot framework (beta channel).
- `@microsoft/agents-hosting` 1.1.1 — Microsoft Teams agent hosting.

### AI / Agent Libraries
- `@mariozechner/pi-agent-core` 0.42.2 — Core agent orchestration (tool calls, sessions).
- `@mariozechner/pi-ai` 0.42.2 — Multi-provider AI API client. Patched locally (`patches/@mariozechner__pi-ai@0.42.2.patch`).
- `@mariozechner/pi-coding-agent` 0.42.2 — Coding-focused agent with file I/O, bash tools.
- `@mariozechner/pi-tui` 0.42.2 — Terminal UI component.

### Browser Automation
- `playwright-core` 1.57.0 — Browser control (CDP/BiDi).
- `chromium-bidi` 12.0.1 — Chromium BiDi protocol implementation.

### Infrastructure
- `express` 5.2.1 — HTTP framework (used for Teams/Discord webhook routing).
- `ws` 8.19.0 — WebSocket server.
- `undici` 7.18.2 — HTTP client.
- `@homebridge/ciao` 1.3.4 — mDNS/Bonjour service announcement for local discovery.
- `proper-lockfile` 4.1.2 — File locking for concurrent credential writes.
- `chokidar` 5.0.0 — File system watcher (config reload, canvas live-reload).
- `dotenv` 17.2.3 — `.env` file loading.
- `croner` 9.1.0 — Cron scheduling.
- `json5` 2.2.3 — JSON5 config parsing.
- `zod` 4.3.5 — Runtime schema validation.
- `ajv` 8.17.1 — JSON Schema validation.
- `sharp` 0.34.5 — Image processing (requires native binaries).
- `jiti` 2.6.1 — Dynamic TypeScript/ESM import.

---

## Security Controls

### In Place

**Authentication**
- Gateway: constant-time token comparison (`timingSafeEqual` from Node.js `crypto`) for token and password modes.
- Tailscale integration: loopback-source + forwarding header check prevents header spoofing from non-proxy sources.
- Hooks endpoint: token-based authentication (plain equality — not constant-time; see concerns below).

**Input Validation**
- Config objects validated via Zod schema (`ClawdbotSchema`) and legacy issue checks before write.
- Hook payloads validated/normalized before dispatch (`normalizeWakePayload`, `normalizeAgentPayload`).
- JSON body size limits enforced on hooks endpoint (default 256 KB) and OpenAI endpoint (default 1 MB).
- HTTP method enforcement (405 Method Not Allowed for non-POST on hook/OpenAI endpoints).

**Sandbox / Path Traversal Prevention**
- Bash tool sandbox mode constrains working directory to `workspaceDir` root.
- `assertSandboxPath` / `resolveSandboxPath` check for `..` traversal and reject symlinks within sandbox paths.
- Canvas host file serving checks symlinks at each path segment.

**Credential Management**
- File locking (`proper-lockfile`) during auth-profile writes to prevent race conditions.
- macOS Keychain preferred over file-based storage for OAuth credentials.
- Credential caching with configurable TTL to reduce disk reads.
- OAuth token refresh with write-back to original storage.

**Network Binding**
- Default gateway binding is loopback (`127.0.0.1`), not `0.0.0.0`. Broader binding requires explicit configuration.
- Tailscale-only mode available for remote access without exposing to LAN.

**Output Safety**
- Final replies only (not streaming partial responses) delivered to external messaging surfaces (WhatsApp, Telegram, etc.).
- Agent turn results screened for binary output sanitization (`sanitizeBinaryOutput`).

**Schema-level Controls**
- Config write path validates against Zod schema to prevent injection of malformed config values via gateway `config.set` / `config.apply` RPC.

### Absent / Limited

- No CSRF protection (WebSocket-only gateway; hooks use bearer token auth).
- No rate limiting on gateway WebSocket connections or hook endpoints.
- No IP allowlist enforcement beyond the loopback/Tailscale distinction.
- No mutual TLS on gateway connections; transport security relies on Tailscale overlay or network isolation.
- No audit logging of authenticated gateway actions.
- Canvas host serves files without authentication (relies on port-level isolation).

---

## Notes

### Critical Security Concerns

**Hook token comparison is not constant-time**
In `src/gateway/server-http.ts` line 85, the hook token is compared with `!token || token !== hooksConfig.token` (plain JavaScript string equality). This is susceptible to timing attacks, unlike the gateway auth which uses `timingSafeEqual`. If the hooks endpoint is exposed to untrusted networks, this allows token enumeration via timing side-channel.

**Hook token in URL query parameters**
`extractHookToken` in `src/gateway/hooks.ts` accepts the token as a URL query parameter (`?token=...`). Query parameters appear in server access logs, proxy logs, and browser history, leaking the secret. The header or Authorization bearer form should be preferred.

**WhatsApp session keys are highly sensitive**
Baileys session credentials stored in `~/.clawdbot/credentials/` grant full WhatsApp account access (send/receive messages as the account holder, access contact list, groups, etc.). Compromise of these files is equivalent to full account takeover. There is no encryption at rest.

**Bash tool enables arbitrary command execution**
The `bash` tool in `src/agents/bash-tools.ts` executes arbitrary shell commands as the user running the Clawdbot process. The AI model (or an attacker who can influence the model's inputs via prompt injection from inbound messages) can use this tool to run any command. The `elevated` mode extends this to host-level execution even when sandboxed. The sandbox (`BashSandboxConfig`) mitigates this via Docker container isolation when enabled, but the default mode runs commands directly on the host.

**Prompt injection via inbound messages**
All inbound messages from WhatsApp, Telegram, etc. are passed as user input to the AI model, which then executes tools (bash, file read/write, browser control). A malicious message sender could craft messages to manipulate the AI into performing unintended actions ("jailbreak via chat message").

**Config write via authenticated gateway RPC**
Any client holding a valid gateway token can call `config.set` or `config.apply` to overwrite the entire configuration file. While the new config is validated by Zod, this still allows a compromised gateway token to modify provider credentials, allowlists, hook tokens, and behavior settings.

**macOS `security` CLI usage for Keychain access**
`src/agents/cli-credentials.ts` calls `execSync` with `security find-generic-password ...` and embeds JSON data in a shell command using single-quote escaping. The escaping logic (`replace(/'/g, "'\"'\"'")`) is applied to the serialized JSON value, but care should be taken if any field values contain special shell characters beyond single quotes.

**Swabble hook command execution**
The `HookExecutor` in Swabble spawns an arbitrary configured command (`config.hook.command`) with the transcribed voice text as a command-line argument. Transcribed text is passed directly via `process.arguments`. If speech recognition produces adversarial text, it could affect argument parsing for the downstream CLI command (though it is passed as a single positional argument, limiting injection risk). The hostname is also interpolated (`${hostname}`) without sanitization.

**`@mariozechner/pi-ai` is patched locally**
The dependency `@mariozechner/pi-ai@0.42.2` has a local patch applied (`patches/@mariozechner__pi-ai@0.42.2.patch`). Local patches bypass upstream security reviews and should be audited with each dependency update.

**`@whiskeysockets/baileys` is a release candidate**
The pinned version `7.0.0-rc.9` is a pre-release version of an unofficial reverse-engineering library. It may contain unpatched bugs, is not under normal semantic versioning stability guarantees, and reverse-engineering unofficial protocols may break without notice.

**`@buape/carbon` is in beta**
The Discord framework dependency is at `0.0.0-beta-*`, indicating an unstable API surface with potentially incomplete security hardening.

**Session transcript files on disk**
All agent conversation history is stored in `~/.clawdbot/agents/<id>/sessions/*.jsonl`. These files may contain sensitive information (PII, confidential messages, tool outputs including file contents) and are stored without encryption. File permissions depend on the OS default umask.

**mDNS/Bonjour service announcement**
When the gateway is running, `@homebridge/ciao` advertises its presence over mDNS on the local network. This reveals the gateway's port number and service name to anyone on the same LAN, potentially aiding targeted attacks.
