# Security Architecture

## Overview

Clawdbot is a multi-channel AI gateway application that bridges messaging platforms (WhatsApp, Telegram, Slack, Discord, iMessage, Signal, Matrix, Microsoft Teams) to AI model providers (Anthropic, OpenAI, Google, Groq, Deepgram, MiniMax, GitHub Copilot, Qwen, Ollama). It runs as a local or self-hosted gateway daemon exposing a WebSocket and HTTP API, and includes native macOS, iOS, and Android companion applications. The system can execute shell commands on behalf of AI agents, interact with browsers via Playwright/Chromium, and optionally expose itself via Tailscale to the broader network.

---

## Architecture

```
                        ┌────────────────────────────────────────────────────┐
                        │                   Trust Boundary: Owner Device      │
                        │                                                      │
  Messaging Channels ──►│  Channel Monitors (WhatsApp/Telegram/Discord/Slack  │
  (External Users)      │  /iMessage/Signal/Matrix/MS Teams)                  │
                        │           │                                          │
                        │           ▼                                          │
                        │  Auto-Reply Engine (mention-gating, allowlists,      │
                        │  session routing, dm-scope isolation)                │
                        │           │                                          │
                        │           ▼                                          │
                        │  Agent Core (pi-agent-core: LLM calls, tool use,    │
                        │  session management, context pruning)                │
                        │      │          │                                    │
                        │      ▼          ▼                                    │
                        │  AI Providers  Tool Execution                        │
                        │  (External)    (bash, browser, web-fetch,           │
                        │               process management)                    │
                        │           │                                          │
                        │           ▼                                          │
 Companion Apps ───────►│  Gateway Server (WebSocket + HTTP)                  │
 (iOS/macOS/Android)   │  - Auth: token, password, Tailscale headers          │
                        │  - Control UI (static SPA)                          │
                        │  - OpenAI-compat HTTP endpoint                      │
                        │  - Hooks HTTP endpoint                              │
                        │  - A2UI canvas host                                  │
                        │           │                                          │
                        │           ▼                                          │
                        │  Tailscale (optional, serve or funnel mode)         │
                        │                                                      │
                        └────────────────────────────────────────────────────┘
                                           │
                                           ▼
                               External AI Provider APIs
                               (Anthropic, OpenAI, Google,
                                Groq, Deepgram, MiniMax, etc.)
```

Major subsystems:

- **Gateway Server** (`src/gateway/`): HTTP + WebSocket server. Native clients connect via WebSocket; a REST-style OpenAI-compatible endpoint is also available.
- **Channel Monitors** (`src/imessage/`, `src/slack/`, `src/discord/`, `src/telegram/`, `extensions/matrix/`, `extensions/msteams/`, etc.): Long-lived connections to external messaging platforms.
- **Auto-Reply Engine** (`src/auto-reply/`): Parses messages, applies allowlists and session routing, dispatches to agents.
- **Agent Core** (`src/agents/`): Wraps `@mariozechner/pi-agent-core`; manages LLM API calls, tool registration, PTY-based shell execution, sandbox (Docker), and session lifecycle.
- **Security Subsystem** (`src/security/`): Built-in audit (`audit.ts`, `audit-extra.ts`) and auto-fix (`fix.ts`) tooling that checks filesystem permissions, config secrets, gateway exposure, channel policies, and model hygiene.
- **Hooks Endpoint** (`src/gateway/hooks.ts`, `src/gateway/server-http.ts`): Token-authenticated HTTP endpoint for external event injection.
- **Extension/Plugin System** (`extensions/`): Workspace packages that add channel providers or authentication flows.
- **Memory Subsystem** (`src/memory/`): Optional vector store (sqlite-vec) and local LLM inference (node-llama-cpp) for agent memory.

---

## Technology Stack

| Category | Technology |
|---|---|
| Primary Language | TypeScript (ESM), Node.js 22+ / Bun |
| Native Apps | Swift / SwiftUI (macOS, iOS), Kotlin (Android) |
| Voice Transcription Component | Swift (Swabble subproject) |
| Web UI | Lit web components (control UI, A2UI canvas) |
| Gateway Protocol | Custom JSON-framed WebSocket protocol (TypeBox-validated) |
| HTTP Framework | Node.js `http` (raw) for gateway; Express 5 / Hono for supplementary routes |
| Config Format | JSON5 with `$include` and `${ENV_VAR}` substitution |
| Config Validation | Zod schema + AJV |
| AI Agent SDK | `@mariozechner/pi-agent-core`, `@mariozechner/pi-ai` |
| WhatsApp Integration | `@whiskeysockets/baileys` (unofficial web API) |
| Telegram Integration | `grammy` |
| Slack Integration | `@slack/bolt`, `@slack/web-api` |
| Discord Integration | `@buape/carbon`, `discord-api-types` |
| Matrix Integration | Custom extension (matrix-js-sdk equivalent) |
| MS Teams Integration | Custom extension |
| Browser Automation | Playwright (`playwright-core`), Chromium Bidi (`chromium-bidi`) |
| Network Exposure | Tailscale (`tailscale serve` / `tailscale funnel`) |
| LAN Discovery | mDNS via `@homebridge/ciao` |
| Memory / Vector Store | `sqlite-vec`, `node-llama-cpp` (optional) |
| Process Execution | Node.js `child_process.spawn`, `@lydell/node-pty` (PTY) |
| Docker Sandboxing | Docker (CLI-driven) |
| Secrets Storage | Filesystem (`~/.clawdbot/credentials/`, `auth-profiles.json`) |
| Secrets in Config | Environment variable substitution (`${VAR}`) |
| Logging | `tslog` |
| Testing | Vitest (unit + e2e), Docker-based integration suites |

---

## Entry Points

### WebSocket Gateway (Primary)

- **Protocol**: Custom JSON-framed WebSocket over HTTP upgrade
- **Default bind**: `127.0.0.1` (loopback) unless `gateway.bind` is set to `lan`, `auto`, or `custom`
- **Authentication**: Token (`Authorization: Bearer <token>` or connect-frame token), password (timing-safe comparison), or Tailscale user headers when `gateway.allowTailscale=true`
- **Clients**: macOS, iOS, and Android companion apps; CLI commands (`clawdbot gateway call`)

### HTTP Endpoints

All HTTP endpoints are served on the same port as the WebSocket gateway.

| Path | Auth Required | Purpose |
|---|---|---|
| `<hooks.path>/wake` | Bearer/`x-clawdbot-token`/`?token=` | Trigger agent wake via external event |
| `<hooks.path>/agent` | Bearer/`x-clawdbot-token`/`?token=` | Trigger agent job via external event |
| `<hooks.path>/<custom>` | Bearer/`x-clawdbot-token`/`?token=` | Mapped hook routes |
| `/v1/chat/completions` | Same as gateway auth (Bearer token) | OpenAI-compatible chat completions endpoint |
| `<controlUiBasePath>/` | None (static SPA, authentication via WS) | Control UI web interface |
| A2UI canvas routes | None (served statically) | A2UI agent UI canvas |
| Plugin HTTP routes | Plugin-defined | Extension-contributed HTTP handlers |

### CLI Commands (Local)

- `clawdbot gateway` — start/control gateway
- `clawdbot agent` — run agent sessions
- `clawdbot message send` — send messages via channels
- `clawdbot security audit` — run security audit
- `clawdbot security fix` — apply security hardening remediations
- `clawdbot login` / `clawdbot status` / `clawdbot doctor` — onboarding and diagnostics
- Cron scheduled agents (`src/cron/isolated-agent.ts`)

### External Webhooks / Inbound Events

- Messaging platform long-poll connections (WhatsApp Web, Telegram bot polling, Slack Socket Mode, Discord gateway, etc.)
- BlueBubbles server connection (iMessage relay)
- Matrix homeserver sync
- MS Teams Bot Framework webhook

### Voice Wake

- `VoiceWakeForwarder` (macOS app, Swabble voice pipeline) — invokes `clawdbot agent --message "${text}"` via shell

---

## Authentication and Authorization

### Gateway Authentication

Three modes, resolved at startup and checked on each WebSocket connect handshake:

| Mode | Mechanism | Notes |
|---|---|---|
| `none` | No credential check (loopback-only safe) | Audit flags this as critical if bind is non-loopback |
| `token` | Static bearer token; timing-safe comparison (`timingSafeEqual`) | Preferred; set via `gateway.auth.token` or `CLAWDBOT_GATEWAY_TOKEN` env var |
| `password` | Static password; timing-safe `safeEqual` | Less preferred; avoid storing in config file |
| `tailscale` | Validated via `Tailscale-User-Login` + `X-Forwarded-*` proxy headers from loopback | Only accepted when `gateway.allowTailscale=true` and request arrives via Tailscale proxy |

The auth check inspects both the WebSocket `connect` frame payload and HTTP headers. Loopback-only requests (verified by `req.socket.remoteAddress` AND absence of forwarding headers) are treated as local direct connections.

### OpenAI HTTP Endpoint Authentication

Uses the same `ResolvedGatewayAuth` resolution as the WebSocket gateway. Bearer token extracted from `Authorization: Bearer <token>`.

### Hooks Endpoint Authentication

Dedicated `hooks.token` (separate from gateway token). Extracted from:
1. `Authorization: Bearer <token>`
2. `X-Clawdbot-Token` header
3. `?token=` query parameter

The built-in audit checks whether `hooks.token` reuses `gateway.auth.token` (cross-contamination risk).

### Browser Control Authentication

Optional `browser.controlToken` or `CLAWDBOT_BROWSER_CONTROL_TOKEN` env var. Only enforced for non-loopback browser control URLs. The audit checks if this token is reused from the gateway token.

### Channel-Level Authorization (Inbound Messages)

Messaging channel authorization is layered:

- **DM policy**: `open` (anyone can DM), `allowlist` (explicit sender allowlist), `disabled`
- **Group policy**: `open` (all group members can invoke commands), `allowlist` (explicit group allowlist)
- **Elevated tool allowlist** (`tools.elevated.allowFrom`): per-provider allowlists restricting who can trigger elevated (shell-exec) mode
- **Pairing store** (`~/.clawdbot/credentials/`): runtime-approved senders stored per channel
- **`commands.useAccessGroups`**: global flag controlling whether Discord/Slack slash commands check access groups

Session isolation: `session.dmScope` controls whether DM sessions from multiple senders share one agent session (`main`) or are isolated per sender (`per-channel-peer`).

---

## Data Flow

### Inbound Message to AI Response

```
External Messaging Platform
  -> Channel Monitor (long-poll / webhook)
  -> mention-gating check (allowlists, DM policy)
  -> session routing (session key derivation)
  -> Auto-Reply Engine (queue, directive parsing)
  -> Agent Core (pi-agent-core)
      -> LLM API call (external AI provider)
      -> Tool execution (bash/PTY, browser, web-fetch)
          [Optional: Docker sandbox]
      -> Response formatting
  -> Channel Send (outbound to platform)
```

### Gateway WebSocket Client Interaction

```
Companion App (iOS/macOS/Android)
  -> TLS/WebSocket connection
  -> Auth handshake (token or Tailscale headers)
  -> Typed method calls (chat, config, sessions, agents, system)
  -> Server broadcasts events (messages, agent status, logs)
```

### Configuration Load

```
~/.clawdbot/clawdbot.json5
  -> JSON5 parse
  -> $include resolution (recursive, depth-limited)
  -> ${ENV_VAR} substitution
  -> Zod schema validation
  -> Runtime override merging
```

### Secrets Flow

```
API keys / tokens
  -> Stored in: ~/.clawdbot/agents/<id>/agent/auth-profiles.json
                ~/.clawdbot/credentials/*.json  (OAuth credentials)
                Config file (gateway token, hooks token, channel bot tokens)
                Environment variables (CLAWDBOT_GATEWAY_TOKEN, etc.)
  -> Used at runtime: passed to LLM API calls, channel SDKs, gateway auth checks
  -> Never written to logs when logging.redactSensitive is active (default)
```

### Media and Attachments

```
Inbound media (images, audio, video)
  -> Downloaded from messaging platform
  -> Type detection (file-type library)
  -> AI provider transcription / vision analysis (Anthropic, Deepgram, Groq, MiniMax)
  -> Result injected into agent context
  -> Temporary files cleaned up post-processing
```

---

## Sensitive Data

| Data Type | Storage Location | Notes |
|---|---|---|
| LLM Provider API Keys | `~/.clawdbot/agents/<id>/agent/auth-profiles.json` | JSON, per-agent; should be chmod 600 |
| OAuth Access/Refresh Tokens | `~/.clawdbot/credentials/*.json` | Per-provider OAuth; should be chmod 700 directory |
| Gateway Auth Token | Config file or `CLAWDBOT_GATEWAY_TOKEN` env var | Audit warns if stored in config file |
| Gateway Auth Password | Config file or `CLAWDBOT_GATEWAY_PASSWORD` env var | Audit warns if stored in config file |
| Hooks Token | Config file or env var | Audit notes if stored in config |
| Browser Control Token | Config file or `CLAWDBOT_BROWSER_CONTROL_TOKEN` env var | Audit warns if stored in config |
| Channel Bot Tokens (Telegram, Slack, Discord, etc.) | Config file | Platform bot credentials |
| WhatsApp Web Session | `~/.clawdbot/sessions/` | Multi-device pairing data (Baileys) |
| Conversation Transcripts | `~/.clawdbot/agents/<id>/sessions/` | Session history in JSONL files |
| Session Routing Metadata | `~/.clawdbot/agents/<id>/sessions/sessions.json` | Maps channel peers to session keys |
| Pairing Allowlists | `~/.clawdbot/credentials/<channel>-allow-from.json` | Per-channel approved sender lists |
| User Phone Numbers | Channel monitors, session routing, pairing store | Treated as routing identifiers |

---

## External Dependencies

### AI / LLM Providers (Network)

- Anthropic API (messages, vision)
- OpenAI API (chat completions, vision)
- Google Gemini / Vertex AI
- Groq API (audio transcription, LLM)
- Deepgram API (audio transcription)
- MiniMax API (video/audio understanding)
- GitHub Copilot (OAuth + model access)
- Qwen Portal (OAuth + model access)
- Ollama (local, optional)
- Firecrawl (optional web scraping service)

### Messaging Platforms (Network / Long-Poll)

- WhatsApp Web (Baileys; unofficial reverse-engineered API)
- Telegram Bot API
- Slack Bolt (Socket Mode or Events API)
- Discord Bot API (`@buape/carbon`)
- Signal (via signal-cli or similar, `src/signal/`)
- Matrix homeserver (extension)
- Microsoft Teams Bot Framework (extension)
- BlueBubbles server (iMessage proxy, extension)

### Network Infrastructure

- Tailscale (optional; `tailscale` CLI must be installed for serve/funnel modes)
- mDNS/Bonjour (`@homebridge/ciao`) for local gateway discovery

### Key npm Dependencies (Security-Relevant)

| Package | Purpose | Notes |
|---|---|---|
| `@whiskeysockets/baileys` | WhatsApp Web protocol | Unofficial API; session credentials stored locally |
| `playwright-core` | Browser automation | Chromium subprocess; significant attack surface |
| `chromium-bidi` | Chrome DevTools Protocol | Used by browser control tools |
| `ws` | WebSocket server/client | Core transport for gateway protocol |
| `express` | HTTP routing (supplementary) | Version 5 |
| `hono` | HTTP routing (supplementary) | Version pinned |
| `@sinclair/typebox` | Runtime schema validation for gateway protocol | Version pinned |
| `zod` | Config schema validation | |
| `ajv` | JSON Schema validation | |
| `sqlite-vec` | Vector storage for agent memory | Alpha version |
| `node-llama-cpp` | Local LLM inference | Optional; native binary |
| `@lydell/node-pty` | PTY for shell tool | |
| `tar` | Archive handling | Version overridden in pnpm.overrides |
| `dotenv` | Env var loading | |
| `proper-lockfile` | Config file locking | |
| `sharp` | Image processing | Native binary |

---

## Security Controls

### Gateway Authentication

- Timing-safe token and password comparison (`node:crypto.timingSafeEqual`) prevents timing oracle attacks
- Tailscale auth validated by checking both proxy headers and loopback source IP; prevents header injection from non-Tailscale sources
- `X-Forwarded-For` / `X-Real-IP` / `X-Forwarded-Host` presence causes loopback direct-mode check to fail, preventing bypasses through forwarded requests
- WebSocket max payload enforced: 512 KB incoming frame cap, 1.5 MB per-connection send buffer (`src/gateway/server-constants.ts`)
- Hooks body size capped (default 256 KB) with 413 status on oversize

### Built-in Security Audit (`clawdbot security audit`)

The `runSecurityAudit()` function in `src/security/audit.ts` checks:

- **Filesystem permissions**: state dir, config file, config include files, credentials dir, `auth-profiles.json`, `sessions.json`, log file — all checked for world/group readability/writability
- **Gateway exposure**: bind beyond loopback without auth (critical), Tailscale funnel enabled (critical), token too short (warn)
- **Browser control**: remote URL without token (critical), HTTP over non-loopback (warn), token reuse with gateway token (warn)
- **Logging redaction**: `logging.redactSensitive=off` (warn)
- **Elevated tool allowlists**: wildcard (`*`) in `tools.elevated.allowFrom` (critical), large allowlist (warn)
- **Hooks hardening**: token too short, hooks token reusing gateway or browser token, root path (`/`)
- **Secrets in config**: gateway password/browser token/hooks token stored as plaintext vs env ref
- **Model hygiene**: warns if legacy (GPT-3.5, Claude 2/Instant, legacy GPT-4 snapshots) or weak-tier models (Haiku) are configured
- **Exposure matrix**: open group policy combined with elevated tools enabled (critical)
- **Channel security**: per-channel DM policy checks, Discord/Slack/Telegram command allowlist checks, multi-user DM session scope warnings, plugin trust (extensions without `plugins.allow`)
- **Synced folder detection**: warns if state/config path is in iCloud/Dropbox/OneDrive/Google Drive

Auto-fix (`clawdbot security fix`) applies remediations: `chmod 700/600` on state dir, config, credentials dir, agent dirs, and sessions; flips `groupPolicy=open` to `allowlist`; enables logging redaction.

### Channel-Level Access Controls

- Per-channel allowlists enforced at the auto-reply engine before agent invocation
- DM scope isolation prevents cross-user context leakage when `session.dmScope=per-channel-peer`
- Mention gating: group messages only processed if the bot is mentioned (configurable)
- Pairing system: senders must be explicitly approved (or `allowFrom` includes their identifier)

### Input Validation

- Gateway protocol messages validated with TypeBox schemas; unknown methods return `FORBIDDEN`
- Config mutations via `config.set` / `config.patch` require a `baseHash` matching the current config snapshot hash (optimistic-lock style TOCTOU protection)
- Hook payloads validated via `normalizeWakePayload` / `normalizeAgentPayload` before dispatch
- Body size limits on HTTP endpoints prevent oversized payload attacks

### Shell / Process Execution Security

- `tools.elevated.enabled` and `tools.elevated.allowFrom` gate which senders can trigger elevated shell execution
- Sandbox config (`tools.sandbox`) supports Docker-isolated execution
- Exec approval subsystem (`src/infra/exec-approvals.ts`) handles allowlisting and interactive approval flows
- Output truncated (default 30,000 chars) to prevent memory exhaustion from runaway processes

### Secrets Management

- Config supports `${ENV_VAR}` substitution so secrets stay out of config files
- Only uppercase env var names accepted (`[A-Z_][A-Z0-9_]*`); others pass through untouched
- `logging.redactSensitive` (default `"tools"`) redacts tool outputs from logs and status displays
- Built-in audit warns when passwords/tokens are stored as literal strings in config rather than env refs

### Deduplification

- Gateway server maintains a deduplication map for incoming messages (TTL 5 minutes, max 1000 entries) to prevent duplicate processing

---

## Notes

### High-Risk Areas

1. **WhatsApp Baileys integration** uses an unofficial reverse-engineered WhatsApp Web protocol. WhatsApp may change the protocol or ban accounts. Session credentials (multi-device pairing) are stored locally; compromise of the state directory yields full WhatsApp access.

2. **Shell tool execution (`exec` / `process`)** is the highest-impact attack vector. Prompt injection through an attacker-controlled message that reaches an agent with elevated tools enabled can result in arbitrary command execution on the host. The `tools.elevated` allowlist and Docker sandbox mitigate but do not eliminate this risk.

3. **Browser automation (Playwright/Chromium)** runs a full Chromium subprocess. The `browser.controlToken` and loopback enforcement are the primary controls. If the browser control endpoint is exposed non-locally without a strong token, it provides full browser control to remote attackers.

4. **Tailscale Funnel** mode exposes the gateway to the public internet. The audit correctly classifies this as critical and recommends `tailscale serve` (tailnet-only) instead.

5. **`session.dmScope=main` with multiple DM senders** leaks conversation context across users. The audit warns about this; `per-channel-peer` isolation should be used whenever multiple users share DM access.

6. **Plugin trust boundary**: Extensions loaded from `~/.clawdbot/extensions/` without a `plugins.allow` allowlist may expose unexpected attack surface, particularly if native skill commands are enabled on messaging surfaces.

7. **Config file permissions**: The config file can contain plaintext tokens. World-readable configs (chmod 644 default on many systems) expose credentials. The `clawdbot security fix` command remediates this to 600.

8. **OpenAI-compat HTTP endpoint**: When `gateway.openai.enabled=true`, the endpoint accepts arbitrary chat completion requests authenticated only by the gateway token. Any tool-capable agent can be invoked from this endpoint.

9. **Credentials directory in synced folders**: If `~/.clawdbot` lands inside iCloud Drive, Dropbox, OneDrive, or Google Drive, all tokens and session credentials sync to cloud storage. The audit detects this condition.

### Trust Boundaries Summary

| Boundary | Trust Level | Controls |
|---|---|---|
| Loopback (127.0.0.1) | High trust | No forwarding headers check, local direct mode |
| Tailscale tailnet | Medium trust | Tailscale user headers validated from loopback proxy |
| LAN / `0.0.0.0` | Low trust | Must have gateway auth configured |
| Tailscale Funnel (public internet) | Untrusted | Gateway auth required; audit warns |
| Messaging channel senders | Untrusted | Channel allowlists, DM policy, elevated allowlists |
| AI provider responses | Untrusted | Prompt injection risk; model hygiene recommendations apply |
| Extension plugins | Semi-trusted | `plugins.allow` enforces explicit plugin allowlisting |
| Docker sandbox | Isolated | Exec runs inside container when sandbox is configured |

### Key Security-Relevant Source Files

- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/gateway/auth.ts` — Gateway auth resolution and `authorizeGatewayConnect`
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/gateway/server-http.ts` — HTTP server, hooks handler, OpenAI endpoint dispatch
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/gateway/server-constants.ts` — Max payload, buffer, handshake timeout constants
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/gateway/hooks.ts` — Hooks token extraction and body size limiting
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/security/audit.ts` — Full security audit logic
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/security/audit-extra.ts` — Extended audit checks (filesystem, exposure matrix, plugin trust, model hygiene)
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/security/fix.ts` — Auto-remediation (chmod, policy flip, config rewrite)
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/agents/bash-tools.exec.ts` — Shell command execution with PTY, approval flow, sandbox
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/config/env-substitution.ts` — `${ENV_VAR}` substitution in config (only uppercase names accepted)
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/gateway/net.ts` — Bind host resolution (loopback, LAN, auto, custom modes)
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/gateway/server-tailscale.ts` — Tailscale serve/funnel control
- `/private/var/folders/gw/14xtk_2n21q2jfw80ymcy4_r0000gn/T/securevibes-GHSA-943q-mwmv-hhvh-fl6bs84m/openclaw/src/config/types.auth.ts` — Auth profile types (api_key, oauth, token modes)
