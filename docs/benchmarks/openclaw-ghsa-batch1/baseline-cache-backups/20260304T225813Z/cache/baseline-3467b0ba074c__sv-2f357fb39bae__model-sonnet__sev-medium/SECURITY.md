# Security Architecture

## Overview

Clawdbot is a multi-platform AI gateway that connects messaging platforms (WhatsApp, Telegram, Discord, Slack, Signal, iMessage, Microsoft Teams) to AI model providers (Anthropic, OpenAI, Google, and others). It runs as a persistent local daemon (gateway) on the operator's machine and exposes a local WebSocket/HTTP server for control, chat, and automation. The application also supports agentic AI workflows with shell execution, browser automation, memory, and sub-agent spawning capabilities.

---

## Architecture

```
External Messaging Platforms          AI Model Providers
  WhatsApp (Baileys/WS)              Anthropic (Claude)
  Telegram (grammY)                  OpenAI / Codex
  Discord (@buape/carbon)            Google (Gemini/Vertex)
  Slack (@slack/bolt)                GitHub Copilot
  Signal                             Groq, Mistral, xAI, etc.
  iMessage (macOS)                   Ollama (local)
  MS Teams (@microsoft/agents-hosting)
          |                                  |
          v                                  |
  +-----------------------+                  |
  |   Clawdbot Gateway    |<-----------------+
  |  (Node.js daemon)     |
  |                       |
  | HTTP :18789           |
  | WS   :18789           |
  | Bridge :18790         |
  | Browser ctrl :18791   |
  | Canvas host :18793    |
  +-----------------------+
          |
          v
  Local macOS/iOS/Android Apps
  (WebSocket client over loopback or Tailscale)
```

Major components:
- **Gateway server** (`src/gateway/`): Central WebSocket + HTTP server. Manages all provider connections, agent sessions, config, and hooks.
- **Agent runner** (`src/agents/`): Executes AI inference via pi-agent-core/pi-ai; manages auth profiles, model selection, session memory, sandbox, bash tools.
- **Provider plugins** (`src/providers/`): Per-platform adapters for WhatsApp, Telegram, Discord, Slack, Signal, iMessage, MS Teams.
- **Hooks HTTP endpoint** (`src/gateway/hooks.ts`, `server-http.ts`): Token-gated inbound webhook receiver.
- **OpenAI-compatible HTTP endpoint** (`src/gateway/openai-http.ts`): Presents a `/v1/chat/completions` facade.
- **Bridge server** (`src/infra/bridge/`): Secondary WebSocket server for multi-node communication.
- **Canvas host / A2UI** (`src/canvas-host/`): Embedded browser UI host.
- **Plugin system** (`src/plugins/`): Dynamically loaded third-party extensions via `jiti`.
- **Swabble** (`Swabble/`): A separate Swift CLI for on-device speech recognition/transcription (macOS).

---

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js >= 22 (also Bun for dev/tests) |
| Language | TypeScript (ESM) |
| CLI framework | commander |
| HTTP server | node:http (raw), express (MS Teams) |
| WebSocket | ws |
| WhatsApp | @whiskeysockets/baileys (unofficial web API) |
| Telegram | grammy |
| Discord | @buape/carbon |
| Slack | @slack/bolt |
| MS Teams | @microsoft/agents-hosting |
| AI inference | @mariozechner/pi-ai, @mariozechner/pi-agent-core, @mariozechner/pi-coding-agent |
| Schema validation | zod, @sinclair/typebox, ajv |
| Local LLM | node-llama-cpp |
| Browser automation | playwright-core, chromium-bidi |
| Config serialization | json5 |
| File locking | proper-lockfile |
| macOS speech | Swift (Swabble) |
| Mobile | Swift (iOS), Kotlin (Android) |
| Build | tsc, rolldown |
| Test | vitest |
| Lint | biome, oxlint |

---

## Entry Points

### Gateway WebSocket (primary control channel)
- Bind: loopback (`127.0.0.1`) by default; configurable to LAN (`0.0.0.0`), Tailnet IP, or `auto`.
- Default port: 18789 (configurable via `gateway.port`).
- Authentication: `none`, `token` (bearer), or `password` (with timing-safe comparison). Tailscale serve mode adds header-based identity verification.
- Clients: macOS app, iOS app, Android app, CLI (`clawdbot tui`), web UI.

### Hooks HTTP endpoint (`/hooks`)
- Receives inbound webhooks from external systems (e.g., GitHub, Zapier, Gmail).
- Token required via `Authorization: Bearer <token>`, `X-Clawdbot-Token` header, or `?token=` query parameter.
- Mapped sub-paths: `/hooks/wake`, `/hooks/agent`, plus custom mappings.
- Body size capped at 256 KB by default.

### OpenAI-compatible HTTP endpoint (`/v1/chat/completions`)
- Optional; enabled via config (`gateway.openAiChatCompletions.enabled`).
- Accepts `Authorization: Bearer <token>` or password for authentication.
- Supports streaming (SSE) and non-streaming responses.

### WhatsApp inbound messages
- Via Baileys WebSocket connection to WhatsApp web servers.
- Messages arrive from the configured WhatsApp account, filtered by `allowFrom` / `groupPolicy` / `dmPolicy`.

### Telegram inbound messages
- Via grammY long-polling or webhook mode.
- Filtered by `allowFrom`, `groupPolicy`, `dmPolicy`.

### Discord inbound messages
- Via @buape/carbon (Discord bot token required).

### Slack inbound messages
- Via @slack/bolt (Slack app credentials required).

### Voice wake (Swabble / macOS)
- On-device speech detection; forwards transcribed text to the gateway via the agent command.

### CLI commands
- `clawdbot gateway`, `clawdbot agent`, `clawdbot message send`, `clawdbot login`, `clawdbot status`, `clawdbot doctor`, etc.

### Cron jobs
- Internal scheduler (`croner`) fires agent runs on configurable schedules.

### Gmail watcher
- OAuth-based Gmail push notification integration triggers agent runs on new email.

---

## Authentication & Authorization

### Gateway clients (WebSocket and HTTP)
Authentication is resolved at connection time in `src/gateway/auth.ts`:
- **`none`**: No credential required. For loopback direct connections, access is granted. When Tailscale is enabled, a `tailscale-user-login` header must be present and the request must arrive via the Tailscale proxy (loopback + proxy headers). Non-local, non-Tailscale connections are rejected.
- **`token`**: Bearer token compared with `timingSafeEqual` to prevent timing attacks.
- **`password`**: Password compared with `timingSafeEqual`.

Tailscale integration reads `tailscale-user-login` / `tailscale-user-name` from HTTP headers injected by the Tailscale local proxy. The code verifies both the header presence and that the TCP connection originates from loopback (i.e., the Tailscale daemon is the actual sender).

### Hooks endpoint
A separate static token (`hooks.token`) gates all webhook calls. The token can be passed in three ways (header, query string, or `Authorization: Bearer`). There is no per-mapping token differentiation.

### AI model providers
API keys are resolved in `src/agents/model-auth.ts` with a priority order:
1. Named auth profile from `~/.clawdbot/agents/<id>/agent/auth-profiles.json`.
2. Environment variables (e.g., `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, etc.).
3. Inline key from `models.providers.<id>.apiKey` in config.

On macOS, Claude CLI and Codex CLI OAuth tokens are read directly from the macOS Keychain via `security find-generic-password`.

### Messaging platform credentials
- WhatsApp: Baileys multi-file auth state stored in `~/.clawdbot/credentials/` (QR or pairing-code flow).
- Telegram: Bot token in config (`telegram.botToken`) or a file path (`telegram.tokenFile`).
- Discord: Bot token in config.
- Slack: App credentials (bot token + signing secret) in config.
- MS Teams: Azure app credentials in config.

### Agent elevated execution
Bash tool elevation (`elevated: true`) is gated by both `tools.elevated.enabled` and an `allowFrom` provider allowlist. Disabled by default.

### Inbound message allowlists
Each provider supports `allowFrom` (phone numbers / user IDs), `groupAllowFrom`, `groupPolicy`, and `dmPolicy` fields to restrict which external users can trigger agent runs.

---

## Data Flow

### Inbound message to AI response
1. External platform (WhatsApp/Telegram/etc.) delivers a message to the provider plugin.
2. Provider plugin validates the sender against `allowFrom`, `groupPolicy`, `dmPolicy`.
3. Message is enqueued (`src/process/command-queue.ts`) and dispatched to `agentCommand`.
4. `agentCommand` resolves session state, agent config, and model; calls pi-agent-core `streamSimple`.
5. AI model API is called over HTTPS with resolved API key.
6. Response is streamed back; tool calls (bash, browser, memory, etc.) are executed inline.
7. Final response is delivered back to the originating platform via the outbound plugin.

### Webhook (hooks endpoint) to agent
1. External system POSTs to `/hooks/<path>` with bearer token.
2. Token is verified against `hooks.token`.
3. Payload is normalized and dispatched as a wake or agent run.
4. Agent run follows the same flow as an inbound message.

### OpenAI-compatible endpoint
1. Client POSTs to `/v1/chat/completions` with bearer token.
2. Token checked against gateway auth.
3. Message extracted from `messages` array (last `user` role entry).
4. `agentCommand` invoked; response returned as OpenAI-format JSON or SSE.

### Credentials storage flow
- AI API keys: environment variables or `~/.clawdbot/agents/<id>/agent/auth-profiles.json` (JSON, file-locked writes via `proper-lockfile`).
- OAuth tokens: macOS Keychain (preferred) or `~/.claude/.credentials.json` / `~/.codex/auth.json`.
- WhatsApp session: Baileys auth files in `~/.clawdbot/credentials/`.
- Config: `~/.clawdbot/clawdbot.json` (JSON5).

---

## Sensitive Data

| Data | Location | Notes |
|---|---|---|
| AI provider API keys | Env vars or `~/.clawdbot/agents/*/agent/auth-profiles.json` | Plaintext JSON; no encryption at rest |
| Anthropic OAuth access/refresh tokens | macOS Keychain or `~/.claude/.credentials.json` | Keychain preferred on macOS |
| Codex (OpenAI) OAuth tokens | macOS Keychain or `~/.codex/auth.json` | Keychain preferred on macOS |
| WhatsApp session keys | `~/.clawdbot/credentials/` (Baileys files) | Long-lived WhatsApp web session |
| Telegram bot tokens | Config file `~/.clawdbot/clawdbot.json` | Plaintext |
| Discord bot tokens | Config file | Plaintext |
| Slack tokens/secrets | Config file | Plaintext |
| MS Teams app credentials | Config file | Plaintext |
| Gateway auth token/password | Config file or env vars `CLAWDBOT_GATEWAY_TOKEN` / `CLAWDBOT_GATEWAY_PASSWORD` | Plaintext in config |
| Hooks token | Config file | Plaintext |
| Google OAuth / ADC credentials | gcloud ADC or env vars | Standard Google auth chain |
| User message content | Session store (`~/.clawdbot/agents/*/sessions/*.jsonl`), agent memory | On-disk, unencrypted |
| Tool execution output (bash, browser) | In-memory session; logged to JSONL | May contain secrets from shell env |
| GitHub Copilot / GH tokens | Env vars `COPILOT_GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_TOKEN` | |

---

## External Dependencies

### Messaging platform SDKs
- `@whiskeysockets/baileys` (7.0.0-rc.9): Unofficial WhatsApp Web protocol library. Uses a pinned RC version.
- `grammy` + `@grammyjs/runner` + `@grammyjs/transformer-throttler`: Telegram Bot API.
- `@buape/carbon`: Discord bot framework.
- `@slack/bolt` + `@slack/web-api`: Slack integration.
- `@microsoft/agents-hosting` + extensions: MS Teams / Azure Bot Framework.

### AI inference
- `@mariozechner/pi-ai`, `@mariozechner/pi-agent-core`, `@mariozechner/pi-coding-agent` (0.43.x): Core AI abstraction and agent loop. One patch applied (`patches/@mariozechner__pi-ai@0.43.0.patch`).
- `node-llama-cpp` (3.14.5): Local LLM inference (llama.cpp bindings).
- `ollama` (dev): Ollama model support.

### Browser automation
- `playwright-core` (1.57.0): Browser control.
- `chromium-bidi` (12.0.1): Chrome DevTools Protocol.

### Networking / discovery
- `@homebridge/ciao`: mDNS/Bonjour advertiser (gateway discovery on LAN).
- `ws`: WebSocket server/client.
- `undici`: HTTP client.

### Utilities
- `dotenv`: `.env` file loading.
- `zod` + `@sinclair/typebox` + `ajv`: Schema validation.
- `proper-lockfile`: File locking for concurrent credential writes.
- `jiti`: Dynamic TypeScript module loading (used for plugin system).
- `croner`: Cron scheduler.
- `tar`, `sharp`, `file-type`: Archive/media processing.
- `json5`: Config file parsing.
- `chokidar`: File system watching.

---

## Security Controls

### Gateway authentication
- Timing-safe token/password comparison (`timingSafeEqual` from `node:crypto`).
- Tailscale header verification with loopback origin check to prevent spoofing.
- Loopback-only binding by default (no remote access unless explicitly configured).
- X-Forwarded-For / X-Real-IP header detection prevents loopback bypass via reverse proxy.

### Sandbox path enforcement
- `src/agents/sandbox-paths.ts` implements path traversal prevention: paths outside the sandbox root raise an error.
- Symlink traversal in sandbox paths is detected and blocked (`assertNoSymlink`).
- Docker container mode routes bash tool execution through `docker exec`, isolating the AI from the host.

### Elevated execution gating
- Bash tool `elevated` flag requires explicit opt-in via two config gates: `tools.elevated.enabled` and `tools.elevated.allowFrom.<provider>`.

### Executable safety validation
- `src/infra/exec-safety.ts` validates executable names in config against a strict pattern (no shell metacharacters, control characters, or quote characters).

### Schema validation
- Full Zod schema (`src/config/zod-schema.ts`) validates the user-supplied config file at load time.
- Config values that could be used as executables (e.g., transcription command) are checked with `isSafeExecutableValue`.

### Inbound message access control
- Per-provider `allowFrom` allowlists (E.164 phone numbers, user IDs, numeric Telegram IDs).
- `groupPolicy` (`open`, `disabled`, `allowlist`) controls group chat access.
- `dmPolicy` (`pairing`, `allowlist`, `open`, `disabled`) controls direct message access.
- Pairing mode requires explicit pairing handshake before a new user can interact.

### Webhook authentication
- Hooks endpoint requires a static bearer token; returns HTTP 401 on mismatch.
- Body size limit (default 256 KB) prevents large payload attacks.

### Logging redaction
- Config supports `logging.redactSensitive` with custom regex patterns to redact tokens from tool summaries in logs.

### Credential storage on macOS
- OAuth tokens written to macOS Keychain when available, falling back to JSON files.
- File-locking (`proper-lockfile`) prevents race conditions on credential file writes.

### HTTPS for external APIs
- All outbound AI API calls use HTTPS (enforced by the SDK libraries).

---

## Notes

### High-risk areas

1. **Bash tool execution with LLM-controlled input**: The `exec` tool in `src/agents/bash-tools.ts` spawns arbitrary shell commands as directed by the AI model. While sandbox mode (Docker) provides isolation, the default non-sandboxed mode executes commands directly on the host with the daemon's OS user privileges. A prompt injection or model compromise could result in arbitrary code execution on the host.

2. **Plugin system with dynamic code loading**: Plugins are loaded via `jiti` at runtime from paths specified in config. A malicious or misconfigured plugin path could load and execute arbitrary code. There is no signature verification or sandboxing of plugin code.

3. **Hook token in query string**: The hooks endpoint accepts the authentication token as a URL query parameter (`?token=`). Query parameters may appear in server access logs, proxy logs, and browser history, potentially exposing the token.

4. **Sensitive data in config file (plaintext)**: Bot tokens, API keys, gateway passwords, and hook tokens are stored in plaintext in `~/.clawdbot/clawdbot.json`. File system compromise or accidental exposure (e.g., config sync, backup) exposes all credentials at once.

5. **WhatsApp Baileys unofficial API**: The WhatsApp integration uses `@whiskeysockets/baileys`, an unofficial reverse-engineered WhatsApp Web protocol library. This creates a risk of session bans and means the integration could break or behave unexpectedly with WhatsApp protocol changes.

6. **Credentials read from sibling CLI tools' files**: `src/agents/cli-credentials.ts` reads credentials directly from Claude CLI (`~/.claude/.credentials.json`) and OpenAI Codex (`~/.codex/auth.json`). These files belong to separate tools; reading them without explicit consent from those tools' credential managers creates a cross-application credential coupling.

7. **Gateway with `lan` or `auto` bind mode**: When configured with `bind: "lan"` or `bind: "auto"`, the gateway listens on `0.0.0.0`, exposing all its HTTP/WebSocket endpoints to the local network. If `auth.mode` is `none` (the default), any host on the LAN can connect without credentials.

8. **LLM-generated commands flow through shell**: Commands produced by the AI agent are passed as a single string to `sh -lc <command>`, enabling full shell interpretation including pipes, redirections, subshells, and environment variable expansion. This is by design for agent capability but is a significant attack surface if the AI processes attacker-controlled input.

9. **Tailscale header trust**: The Tailscale authentication mode relies on HTTP headers (`tailscale-user-login`, etc.) being injected by the local Tailscale daemon. While the code validates that the connection originates from loopback (ensuring it is the local Tailscale proxy), this model depends on the integrity of the Tailscale daemon and correct loopback detection.

10. **No rate limiting on gateway endpoints**: No explicit rate limiting is visible for the gateway WebSocket, hooks endpoint, or OpenAI-compatible endpoint. A connected or allowlisted client could send high volumes of requests, potentially causing API cost overruns or resource exhaustion.
