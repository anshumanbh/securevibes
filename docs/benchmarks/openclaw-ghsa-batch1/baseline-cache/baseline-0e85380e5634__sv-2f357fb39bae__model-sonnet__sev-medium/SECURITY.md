# Security Architecture

## Overview

OpenClaw is a multi-channel AI gateway (version 2026.2.18) that bridges multiple messaging platforms (Telegram, Discord, Slack, WhatsApp, Matrix, iMessage, IRC, LINE, Mattermost, Google Chat, Feishu, Twitch, Zalo, and others) to AI model providers (OpenAI, Anthropic, Google Gemini, MiniMax, OpenRouter, and others). It runs as a persistent local daemon exposing a WebSocket-based gateway that client UIs and channel extensions connect to. The gateway also supports optional Docker-based code execution sandboxes and voice/TTS capabilities.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     External World                          │
│  Telegram │ Discord │ Slack │ WhatsApp │ Matrix │ IRC │ ... │
└──────────────────────────┬──────────────────────────────────┘
                           │ inbound messages (webhooks/polling)
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                  Channel Extension Layer                     │
│  (TypeScript extensions: /extensions/<name>/src/runtime.ts)  │
│  Each extension handles inbound/outbound for one platform    │
└──────────────────────────┬───────────────────────────────────┘
                           │ events / RPC calls
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Gateway Server  (src/gateway/)                  │
│                                                                     │
│  WebSocket Server (ws://<bind>:<port>)                              │
│    - Auth: token / password / Tailscale / trusted-proxy / none      │
│    - Rate Limiter: in-memory sliding-window per IP                  │
│    - Handshake timeout: 10 s                                        │
│    - Max payload: 25 MB                                             │
│                                                                     │
│  HTTP Endpoints                                                     │
│    POST /tools/invoke   – automation API (restricted tool set)      │
│    GET  /health         – health check                              │
│    GET  /canvas/<port>  – canvas model server proxy                 │
│    GET  /control-ui/*   – web control panel                         │
│                                                                     │
│  Protocol: JSON-RPC–style over WebSocket                            │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
          ┌────────────────┼─────────────────────┐
          ▼                ▼                     ▼
┌──────────────┐  ┌───────────────┐   ┌──────────────────────┐
│ Agent Runner │  │  Exec Tools   │   │  LLM Provider APIs   │
│ (pi-embedded)│  │  (bash/exec)  │   │  OpenAI / Anthropic  │
│              │  │  host=gateway │   │  Gemini / OpenRouter │
│  Manages     │  │  host=sandbox │   │  MiniMax / HuggingFace│
│  LLM turns   │  │  host=node    │   └──────────────────────┘
│  context/    │  │               │
│  compaction  │  │  Docker       │
└──────────────┘  │  Sandbox      │
                  └───────────────┘
                           │
                  ┌────────┴──────────────────┐
                  │  Filesystem State          │
                  │  ~/.openclaw/              │
                  │    openclaw.json  (config) │
                  │    sessions/              │
                  │    exec-approvals.json    │
                  │    plugins/               │
                  └───────────────────────────┘
```

**Key architectural boundaries:**
- External messaging channels connect via channel extension plugins (one per platform).
- All LLM orchestration is mediated through the gateway and agent runner.
- Shell command execution is isolated to three host modes: `gateway` (host process), `sandbox` (Docker container), `node` (remote node host).
- The Control UI (web panel) is served from the same HTTP listener as the WebSocket gateway.
- State (config, sessions, approvals) lives in `~/.openclaw/` by default.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js (ESM), TypeScript |
| Gateway transport | WebSocket (`ws` library), HTTP (Node.js built-in `http`/`https`) |
| Build tooling | tsdown, pnpm, Bun |
| Schema validation | Zod, AJV |
| Config format | JSON5 |
| Sandboxing | Docker (optional) |
| macOS / iOS client | Swift (Swabble speech pipeline, SwiftUI apps in `/apps/`) |
| Android client | Kotlin / Gradle (`/apps/android/`) |
| Canvas UI | Angular (vendor), Lit web components (vendor) |
| TLS | Node.js `tls` module (optional; configured via `gateway.tls`) |
| Secret comparison | Node.js `crypto.timingSafeEqual` (SHA-256 hash before comparison) |
| External tunneling | Tailscale Serve / Tailscale Funnel (optional) |
| Observability | OpenTelemetry diagnostics extension (`/extensions/diagnostics-otel/`) |
| Secrets scanning | detect-secrets (`.detect-secrets.cfg`, `.secrets.baseline`) |
| Linting | OxLint (`.oxlintrc.json`), ShellCheck (`.shellcheckrc`) |
| Language (skills) | Python 3, Node.js (skill scripts in `/skills/`) |

**Key AI provider integrations:**
- Anthropic (Claude), OpenAI (GPT / o-series / Responses API), Google Gemini, OpenRouter, MiniMax, HuggingFace, Cloudflare AI Gateway, GitHub Copilot proxy

---

## Entry Points

### WebSocket Gateway (Primary)
- **Bind address:** configurable (`gateway.bind`); defaults loopback (`127.0.0.1`).
- **Default port:** 18789.
- **Protocol:** JSON-RPC–style messages over WebSocket.
- **Auth:** Token, password, Tailscale identity verification, or trusted-proxy header delegation.
- **Clients:** Control UI (web), macOS/iOS/Android native apps, remote nodes.

### HTTP Endpoints
| Path | Purpose | Auth Required |
|---|---|---|
| `POST /tools/invoke` | Automation API — invoke agent tools over HTTP | Gateway auth (token/password), device token, or no-auth if `gateway.http.noAuth` is configured |
| `GET /health` | Health probe | None (public) |
| `GET /canvas/<port>` | Proxy to a running canvas model server; the canvas model server binds network-visible by design | Gateway auth |
| `GET /control-ui/*` | Serves the embedded web control panel SPA | Gateway auth + device identity (unless `dangerouslyDisableDeviceAuth` is set) |

### CLI Commands
- `openclaw gateway` — start the daemon.
- `openclaw security audit` — run the built-in security audit.
- `openclaw status`, `openclaw doctor` — diagnostics.
- `openclaw setup` — interactive setup wizard.

### Channel Webhooks / Polling
Each channel extension establishes its own inbound channel (webhook HTTP endpoint, long-polling, or platform SDK socket). Examples:
- **Telegram**: bot polling or webhook.
- **Discord**: Discord gateway WebSocket.
- **Slack**: Slack Events API webhooks or Socket Mode.
- **WhatsApp**: WhatsApp Web bridge socket.
- **Matrix**: Matrix Client-Server API sync.
- **LINE, Feishu, Google Chat, Mattermost**: respective webhook or API polling.
- **iMessage / BlueBubbles**: local macOS bridge or BlueBubbles server HTTP.
- **IRC**: TCP socket.
- **Nostr, Zalo, Twitch, Nextcloud Talk**: respective protocols.

### External Hook Triggers
- Gmail hooks (`hook:gmail:<id>`), generic webhooks (`hook:webhook:<id>`) can trigger agent runs. External hook content is wrapped with prompt-injection protection markers before being passed to LLMs.

---

## Authentication & Authorization

### Gateway Authentication Modes

The gateway supports four mutually-exclusive authentication modes (`gateway.auth.mode`):

| Mode | Mechanism | Security Notes |
|---|---|---|
| `token` | Bearer token in connect params, compared with timing-safe equality (SHA-256 hash before `timingSafeEqual`) | Default when `OPENCLAW_GATEWAY_TOKEN` is set |
| `password` | Password in connect params, timing-safe comparison | Falls back from token if only a password is set |
| `trusted-proxy` | Delegated to reverse proxy; user identity from configurable header | Requires `gateway.trustedProxies` IP allowlist; `allowUsers` recommended |
| `none` | No authentication | **High risk** — only safe on fully isolated loopback |

**Token/password** comparison is done via `src/security/secret-equal.ts`: both strings are SHA-256 hashed before being passed to `timingSafeEqual`, preventing timing-oracle attacks.

**Tailscale authentication** (`allowTailscale`): When enabled and operating in `serve` mode, Tailscale identity headers (`tailscale-user-login`, `tailscale-user-name`) are verified by cross-checking the client's IP against `tailscale whois` output, ensuring headers cannot be spoofed by non-tailnet clients.

### Rate Limiting
An in-memory sliding-window rate limiter (`src/gateway/auth-rate-limit.ts`) is applied to shared-secret (token/password) and device-token authentication attempts:
- **Default:** 10 failed attempts per 1-minute window, 5-minute lockout.
- Loopback addresses are exempt by default.
- Separate scopes for shared-secret vs. device-token auth.
- The limiter is per-process (no distributed state); a restart resets all counters.

### Control UI Device Identity
The Control UI (web panel) enforces device identity checks on top of the gateway token to prevent CSRF-like attacks. This can be disabled via `dangerouslyDisableDeviceAuth` (flagged as `critical` by the built-in security audit).

### Per-Channel DM Authorization
Each messaging channel has a `allowFrom` list controlling which sender identities (user IDs, email addresses) can initiate direct-message agent sessions. A wildcard `"*"` allows anyone on the platform — this is flagged by the security audit.

### Elevated Execution Authorization
The `tools.elevated` configuration permits AI agents to run commands with elevated OS privileges. Each provider can be granted or denied elevated access via `allowFrom.<provider>`. A wildcard in this list is flagged as `critical` by the security audit.

### ACP (Automation Control Plane) Approval
High-risk tools used over the ACP automation surface (`exec`, `spawn`, `shell`, `sessions_spawn`, `sessions_send`, `gateway`, `fs_write`, `fs_delete`, `fs_move`, `apply_patch`) always require explicit user approval. These are defined in `src/security/dangerous-tools.ts`.

---

## Data Flow

### 1. User Message from Messaging Channel → LLM → Response
```
Channel Platform
  └─▶ Channel Extension (webhook/poll)
        └─▶ Gateway Event Bus
              └─▶ Agent Runner (pi-embedded)
                    ├─▶ LLM Provider API (HTTPS, API key in header)
                    │       └─▶ LLM response streamed back
                    └─▶ Tool Execution (if AI requests a tool call)
                              ├─▶ exec → sandbox (Docker) or gateway host or remote node
                              └─▶ result back to agent context
  ◀── Response ── Channel Extension ◀── Gateway ◀── Agent output
```

### 2. External Hook (Email / Webhook) → Agent
```
External Source (Gmail, generic HTTP webhook)
  └─▶ Hook ingestion endpoint
        └─▶ wrapExternalContent() — prompt-injection safety wrapping
              └─▶ Agent Runner (same flow as above)
```

### 3. Control UI → Gateway Config Change
```
Browser (Control UI)
  └─▶ WebSocket (authenticated)
        └─▶ config.set / config.apply / config.patch
              ├─▶ redactConfigSnapshot() strips secrets before sending to browser
              ├─▶ restoreRedactedValues() re-injects original secrets on write
              └─▶ Config written to ~/.openclaw/openclaw.json
```

### 4. AI Tool: Shell Command Execution
```
AI Agent (tool call: exec)
  └─▶ bash-tools.exec.ts
        ├─▶ Validate host (gateway / sandbox / node)
        ├─▶ Validate security level (deny / allowlist / full)
        ├─▶ If ask=on-miss: request approval via callGatewayTool("exec.approval.request")
        │       └─▶ User approves/denies in Control UI
        ├─▶ validateScriptFileForShellBleed() — detect shell var leakage into Python/JS
        └─▶ runExecProcess() — spawns child process or Docker exec
```

### 5. Sensitive Data Paths for API Keys
```
Environment / .env file
  └─▶ resolveGatewayAuth() / agent config loading
        ├─▶ Stored only in process.env (never written to config)
        ├─▶ Passed to LLM HTTP requests as Authorization header
        └─▶ Blocked from entering Docker sandbox env via sanitizeEnvVars()
```

---

## Sensitive Data

### API Keys and Secrets
- **LLM provider API keys** (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, etc.): Loaded from environment or `.env`. Never persisted to config files. Explicitly blocked from being passed into Docker sandbox containers (`src/agents/sandbox/sanitize-env-vars.ts`).
- **Gateway token / password** (`OPENCLAW_GATEWAY_TOKEN`, `OPENCLAW_GATEWAY_PASSWORD`): The primary shared secret protecting the WebSocket gateway.
- **Channel bot tokens** (`TELEGRAM_BOT_TOKEN`, `DISCORD_BOT_TOKEN`, `SLACK_BOT_TOKEN`, etc.): Platform-specific secrets for messaging channels.
- **Third-party tool API keys** (`BRAVE_API_KEY`, `PERPLEXITY_API_KEY`, `FIRECRAWL_API_KEY`, `ELEVENLABS_API_KEY`, `DEEPGRAM_API_KEY`).

### Configuration File (`~/.openclaw/openclaw.json`)
- Contains channel tokens, gateway auth, and agent settings.
- The security audit checks that this file has permissions no looser than `0600` (world-readable is `critical`; group-readable is `warn`).
- Sensitive fields are redacted before being returned to the Control UI (`REDACTED_SENTINEL = "__OPENCLAW_REDACTED__"`), and original values are restored on write so credentials survive UI round-trips.
- A `detect-secrets` baseline (`.secrets.baseline`) is maintained to prevent accidental secret commits.

### State Directory (`~/.openclaw/`)
- Stores session histories, exec-approvals allowlist, plugin state, embeddings (if memory extension is active), and transcript logs.
- The security audit checks that this directory has permissions no looser than `0700`.

### Conversation History / LLM Context
- User messages and AI responses are stored in session files within the state directory.
- Images passed to multi-modal models are handled via `src/agents/image-sanitization.ts`.

### Personal / User Identity Data
- Tailscale user login/name (from `tailscale whois`), channel-specific user IDs, and optionally email addresses (in DM allowlists) are handled.

---

## External Dependencies

### Core npm Dependencies (selected)
- `ws` — WebSocket server/client
- `zod` — Schema validation for config and protocol messages
- `ajv` — JSON Schema validation (protocol messages)
- `@mariozechner/pi-agent-core` — LLM agent orchestration core
- `ciao` / `bonjour-service` — mDNS/Bonjour gateway discovery on local network
- `@opentelemetry/*` — Telemetry (diagnostics extension)
- `matrix-js-sdk` — Matrix protocol support
- `discord.js` — Discord bot support
- Various platform SDKs per channel extension

### External AI Provider APIs
- Anthropic (`api.anthropic.com`)
- OpenAI (`api.openai.com`)
- Google Gemini (`generativelanguage.googleapis.com`)
- OpenRouter (`openrouter.ai`)
- MiniMax (`api.minimax.chat`)
- HuggingFace inference endpoints
- Cloudflare AI Gateway (optional proxy)
- GitHub Copilot proxy (optional extension)

### External Services
- **Tailscale** — optional VPN/mesh networking for exposing the gateway beyond loopback; `tailscale whois` is used for user identity verification.
- **Docker** — optional sandbox execution environment for AI-generated code.
- **ElevenLabs / Deepgram** — TTS and STT for voice features.
- **Brave Search / Perplexity / Firecrawl** — web search and content fetch tools.

---

## Security Controls

### Input Validation
- All gateway WebSocket messages are validated with AJV JSON Schema validators (`src/gateway/protocol/`).
- Config writes are validated with Zod schemas before being applied.
- `wrapExternalContent()` (`src/security/external-content.ts`) wraps content from external sources (email, webhooks, web fetches) with prompt-injection warning headers and boundary markers before passing to LLMs. Unicode angle-bracket homoglyphs in marker text are normalized to prevent escape.
- Script preflight (`validateScriptFileForShellBleed`) detects shell variable syntax (`$VAR`) accidentally embedded in Python/Node.js scripts before execution.

### CSRF / Clickjacking Protection
- The Control UI is served with a `Content-Security-Policy` header (`src/gateway/control-ui-csp.ts`):
  - `frame-ancestors 'none'` — prevents embedding/clickjacking.
  - `default-src 'self'` — restricts resource origins.
  - `script-src 'self'` — no inline scripts.
  - `base-uri 'none'`, `object-src 'none'`.
- Device identity checks on the Control UI mitigate CSRF-style lateral attacks.

### Secret Comparison
- All token/password comparisons use `safeEqualSecret()` (`src/security/secret-equal.ts`), which SHA-256 hashes both values before calling `timingSafeEqual`, preventing timing-side-channel attacks.

### Rate Limiting
- Gateway authentication has a configurable in-memory sliding-window rate limiter with lockout (`src/gateway/auth-rate-limit.ts`).
- Default: 10 failed attempts/minute, 5-minute lockout per IP per scope.
- Loopback addresses are exempt.

### Sandbox Execution Controls
- Docker sandbox containers enforce:
  - **Blocked host paths**: `/etc`, `/proc`, `/sys`, `/dev`, `/root`, `/boot`, `/run`, `/var/run`, `/var/run/docker.sock` and macOS equivalents cannot be bind-mounted.
  - **Blocked network modes**: `host` network mode is rejected.
  - **Blocked security profiles**: `seccomp=unconfined` and `apparmor=unconfined` are rejected.
  - Symlink resolution is performed before bind-mount validation to prevent symlink escape.
- Sandbox environment variable sanitization (`src/agents/sandbox/sanitize-env-vars.ts`) blocks all API keys, tokens, passwords, and credentials (broad pattern list) from being injected into containers.
- `strictMode` allows only an explicit allowlist of safe env vars.

### Shell Command Allowlist
- The `allowlist` security mode (`tools.exec.security`) only permits commands matching pre-approved patterns.
- `safeBins` restricts which executables can be run in stdin-only segments without shell expansion, verified against a list of trusted binary directories.
- Shell glob/variable expansion can be hardened for `safeBins` segments.

### Tool Deny List (HTTP Surface)
- The HTTP `POST /tools/invoke` endpoint denies `sessions_spawn`, `sessions_send`, `gateway`, and `whatsapp_login` by default to prevent remote code execution and session hijacking over the non-interactive HTTP surface (`src/security/dangerous-tools.ts`).

### Credential Redaction in Logs/UI
- `redactConfigSnapshot()` replaces sensitive config fields with `__OPENCLAW_REDACTED__` before sending config to the Control UI.
- `restoreRedactedValues()` restores originals on write to prevent credential corruption during UI round-trips.
- `logging.redactSensitive` configuration controls tool-summary redaction in logs.

### Filesystem Permission Checks
- The built-in security audit (`runSecurityAudit`) checks permissions on `~/.openclaw/` and `openclaw.json`, flagging world-readable config or world-writable state directories as `critical`.
- Windows ACL checks are also supported.

### TLS Support
- Optional TLS can be configured on the gateway listener (`gateway.tls`), loaded via `src/infra/tls/gateway.ts`.

### Secrets Detection in Repository
- `detect-secrets` with a maintained baseline (`.secrets.baseline`) is present to prevent accidental credential commits.
- Linting via OxLint and ShellCheck for code quality.

---

## Notes

### Known Design Decisions With Security Implications

1. **No-auth loopback mode**: When `gateway.bind=loopback` (default) and no auth is configured, any local process on the machine can connect to the gateway and invoke all tools, including shell execution. The security audit flags this as `critical` when the Control UI is enabled (the assumption being it could be proxied). Users running strictly local-only with no proxy accept this risk.

2. **Canvas model server is network-visible by design**: The canvas model server (when `canvasPort` is configured) binds to a network-visible address to allow cross-origin access from browser tabs. This is documented as an intentional architectural tradeoff. The canvas endpoint is proxied through the gateway (`/canvas/<port>`), which requires gateway auth.

3. **Rate limiter is in-memory only**: The rate limiter does not survive process restarts and is not shared across multiple gateway instances. A denial-of-service or brute-force attack could be mitigated simply by restarting the process to reset lockouts.

4. **Tailscale Funnel (`funnel` mode) is internet-exposed**: If `gateway.tailscale.mode=funnel`, the gateway becomes publicly accessible on the internet via Tailscale Funnel. The built-in security audit flags this as `critical` and recommends using `serve` (tailnet-only) instead.

5. **Plugin trust boundary**: Extensions/plugins loaded from the state directory (`~/.openclaw/plugins/`) run in the same Node.js process as the gateway with full access to gateway internals. The security audit includes a plugin code-safety scan. Only allow plugins from trusted sources.

6. **Exec approvals persist to disk**: The exec-approvals allowlist (`exec-approvals.json`) persists approved command patterns between sessions. A compromised or overly permissive allowlist effectively grants persistent shell execution without further approval prompts.

7. **External content prompt-injection mitigation is heuristic**: The `detectSuspiciousPatterns()` function logs detected injection patterns but does not block them — all external content is still processed. Blocking relies on the LLM correctly interpreting the `SECURITY NOTICE` wrapper. This is a best-effort mitigation; determined prompt injection attacks may still succeed.

8. **ACP automation surface**: The `POST /tools/invoke` HTTP endpoint is intended for narrow programmatic automation. Re-enabling `sessions_spawn` or `gateway` on this surface via `gateway.tools.allow` effectively grants unauthenticated (or weakly authenticated) remote code execution and is flagged as `critical` if the gateway is non-loopback.

9. **`trusted-proxy` auth mode requires careful firewall configuration**: In `trusted-proxy` mode, the gateway relies entirely on the upstream proxy for authentication. Direct network access to the gateway port bypassing the proxy would allow anyone to forge user-identity headers. Firewall rules restricting direct access to the port are essential.

10. **Secrets baseline**: While a `detect-secrets` baseline exists, the `.env.example` file documents which environment variables hold sensitive credentials, providing a useful reference for an attacker enumerating the attack surface.
