# DAST MVP Implementation Plan (Repo‑Aligned)

Status: Draft for review  
Scope: HTTP‑only MVP with IDOR validation, integrated with existing Scanner orchestration

---

## Summary

This plan delivers a minimal but robust DAST phase that validates IDOR findings against a running
target via HTTP requests, captures concise evidence, and merges validation into the final report.
It aligns with the current SecureVibes architecture and avoids duplicating orchestration logic.

Key choices:
- Integrate DAST as a first‑class sub‑agent within the existing scanner workflow.
- Ship an HTTP‑only MVP (no browser/MCP) to reduce risk and dependencies in Phase 1.
- Add a compact evidence schema, redaction, timeouts, and safety gates.
- Update reporters and models to surface validation status clearly.

---

## Scope and Constraints (MVP)

- In scope:
  - HTTP‑mode DAST for IDOR (CWE‑639) using `requests`.
  - Optional activation via CLI flags; default scans unchanged.
  - Evidence capture with redaction and truncation.
  - Merge DAST results into `scan_results.json` via report‑generator agent.
  - Tests: unit + integration for HTTP flow; manual checklist.

- Out of scope (defer to Phase 2+):
  - Browser/MCP mode, screenshots, DOM capture.
  - Parallel/pooling optimization; advanced skill catalog.
  - Marketplace/community skill distribution.

Constraints:
- Preserve existing scanner orchestration; avoid separate CLI‑side “mini orchestrator”.
- Keep install lean; add only `requests` for MVP.

---

## Architecture Integration Decisions

- Orchestration: Keep a single Claude‑driven orchestration in `securevibes/scanner/scanner.py`.
  - DAST runs as a sub‑agent phase after code‑review, controlled by CLI flags.
  - Progress is tracked via existing hooks (`PreToolUse`, `PostToolUse`, `SubagentStop`).

- Merge responsibility: Report‑generator agent reads `.securevibes/DAST_VALIDATION.json` and
  emits a merged `.securevibes/scan_results.json` with validation fields. No CLI‑side merging.

- Skills: For MVP, embed IDOR testing logic as Python helpers callable by the DAST agent/tooling.
  - Introduce a skills directory placeholder for future growth but do not require it for MVP.

- Modes: MVP ships `--dast-mode http` only; `auto` and `browser` are placeholders that explain
  unavailability with clear user guidance.

---

## Files To Add/Modify

- Add: `packages/core/securevibes/prompts/agents/dast.txt` (DAST agent prompt; HTTP‑only scope)
- Modify: `packages/core/securevibes/prompts/loader.py` (include `dast` in `load_all_agent_prompts()`)
- Modify: `packages/core/securevibes/agents/definitions.py` (add `dast` agent definition)
- Modify: `packages/core/securevibes/cli/main.py` (add flags; pass through to Scanner)
- Modify: `packages/core/securevibes/scanner/scanner.py`
  - Accept DAST settings in the orchestration context (via prompt vars/env) and surface a new
    phase banner while still letting Claude orchestrate the sub‑agent.
  - Add lightweight Python helpers for HTTP IDOR tests callable by agent tools (if needed).
- Modify: `packages/core/securevibes/models/issue.py`
  - Add `ValidationStatus` enum and optional validation fields on `SecurityIssue`.
- Modify: `packages/core/securevibes/models/result.py`
  - Add optional DAST metrics on `ScanResult` and helper properties.
- Modify: `packages/core/securevibes/reporters/json_reporter.py` and
  `packages/core/securevibes/reporters/markdown_reporter.py`
  - Render `validation_status`, evidence summary, and DAST metrics when present.
- Add: `packages/core/tests/test_dast_http.py` (unit tests for HTTP IDOR validation helpers)
- Add: `packages/core/tests/integration/test_dast_mvp.py` (end‑to‑end integration; HTTP‑only)
- Modify: `packages/core/pyproject.toml` (add `requests` as a runtime dependency)
- Add (optional): `docs/DAST_GUIDE.md` (user quickstart, HTTP mode)

---

## Data Model Changes

- `packages/core/securevibes/models/issue.py`
  - Add enum:
    - `class ValidationStatus(str, Enum): VALIDATED, FALSE_POSITIVE, UNVALIDATED, PARTIAL`
  - Extend `SecurityIssue` with optional fields:
    - `validation_status: Optional[ValidationStatus] = None`
    - `dast_evidence: Optional[dict] = None` (compact, redacted)
    - `exploitability_score: Optional[float] = None`
    - `validated_at: Optional[str] = None` (ISO timestamp)
  - Update `to_dict()` to include these fields only when set.

- `packages/core/securevibes/models/result.py`
  - Add optional DAST metrics:
    - `dast_enabled: bool = False`
    - `dast_validation_rate: Optional[float] = None`
    - `dast_false_positive_rate: Optional[float] = None`
    - `dast_scan_time_seconds: Optional[float] = None`
  - Update `to_dict()` to include `dast_metrics` when `dast_enabled`.

---

## CLI Flags (MVP)

Add to `securevibes scan`:
- `--dast` (bool): enable DAST phase.
- `--target-url <url>` (required when `--dast`): running app base URL.
- `--dast-mode [http]` (default: `http` for MVP; `browser`/`auto` print guidance).
- `--dast-timeout <int>` (per‑vuln seconds; default 120).
- `--dast-accounts <path>` (optional JSON for test accounts; MVP IDOR can run without auth too).
- `--allow-production` (bypass production URL block with confirmation prompt).

Behavior:
- If `--dast` and no `--target-url`, exit with error and help text.
- Pass flags into scanner context (e.g., environment vars or prompt variables) used by the
  orchestration and DAST agent.

---

## Evidence Schema (MVP)

Stored in `.securevibes/DAST_VALIDATION.json` and referenced in merged `scan_results.json`:

```
{
  "vulnerability_id": "VULN-001",
  "validation_status": "VALIDATED",
  "tested_at": "2025-10-23T12:34:56Z",
  "test_steps": ["Describe succinct steps"],
  "evidence": {
    "http_requests": [
      {
        "request": "GET /api/users/456",
        "status": 200,
        "response_snippet": "<truncated, redacted>",
        "response_hash": "sha256:..."
      }
    ]
  },
  "exploitability_score": 9.0,
  "notes": "IDOR confirmed"
}
```

Controls:
- Redaction: redact sensitive keys; truncate bodies (e.g., 2–4 KB) and include content hash.
- Size caps: configurable; default conservative.

---

## Safety Gates (MVP)

- Authorization: explicit confirmation prompt when `--dast` is set.
- Production detection: heuristic block unless `--allow-production` + confirmation.
- Timeouts: per‑vuln with clear classification to `UNVALIDATED` on expiry.
- Rate limiting: simple sleep‑based limiter in helpers (conservative default).
- Audit logging: optional, off by default in MVP; document enabling.

---

## Dependencies

- Add runtime dependency: `requests>=2.31.0` (MVP).  
  Browser/MCP remains out of scope in Phase 1 to avoid Node tooling at install time.

---

## Implementation Plan

Phase 1 (Weeks 1–2): HTTP‑only MVP
- Agent & prompts
  - Add `dast` agent to `agents/definitions.py` using `prompts/agents/dast.txt`.
  - Keep prompt focused on HTTP IDOR validation; no browser references.
- CLI
  - Add flags; validate inputs; pass settings into Scanner context.
- Scanner integration
  - Keep a single `ClaudeSDKClient`; surface a new “DAST Validation” phase banner via hooks.
  - Provide small Python helper(s) for IDOR HTTP testing callable by the agent (tool binding).
- Models & reporters
  - Implement `ValidationStatus` and optional fields; update JSON/Markdown reporters.
- Output & merge
  - Define `.securevibes/DAST_VALIDATION.json` schema; extend report‑generator prompt to merge.
- Safety & redaction
  - Add redaction/truncation in helpers; confirm/production gating in CLI.
- Tests
  - Unit: redaction, helper logic (success/403/timeout), model serialization.
  - Integration: run a toy HTTP server/fixture to validate IDOR workflow end‑to‑end.
- Docs
  - Add `docs/DAST_GUIDE.md` (HTTP quickstart, flags, troubleshooting).

Phase 2 (Weeks 3–4): Core Enhancements
- Add XSS and SQLi skills (HTTP mode); extend mappings in DAST prompt.
- Parallelism (limited to 2–3); auth token cache for test accounts.
- Expand tests; add cost/time metrics to `ScanResult`.
- Document limitations and roadmap; evaluate MCP readiness for Phase 3.

---

## Validation Checklist (MVP)

Automated
- Code quality
  - Ruff/Black pass on modified files.
  - Type hints added for new functions.
- Unit tests
  - IDOR HTTP helper: VALIDATED on 200 cross‑ID; FALSE_POSITIVE on 401/403; UNVALIDATED on timeout.
  - Redaction: sensitive keys are masked; body truncation enforced; hash present.
  - Model `to_dict()` includes validation fields only when set.
- Integration tests
  - `securevibes scan . --dast --target-url http://localhost:3333 --dast-mode http --no-save` runs.
  - Creates `.securevibes/DAST_VALIDATION.json` and merged `.securevibes/scan_results.json`.
  - Reporters include validation status in JSON and Markdown.
- CLI behavior
  - Missing `--target-url` errors when `--dast` set.
  - `--allow-production` gating prompts; deny without flag.

Manual
- Run a local demo app with two user objects (123/456) and confirm IDOR flow.
- Verify evidence redaction and truncation (no raw PII or secrets stored).
- Confirm phase banners and progress output show a distinct DAST phase.
- Validate UX copy for guidance when mode is not supported (browser placeholder).

Release Gate
- No regressions in existing tests.
- Default scan (without `--dast`) unchanged.
- Documentation updated (flags, quickstart, evidence policy).

---

## Acceptance Criteria

- With a running test target, an IDOR finding is validated end‑to‑end in HTTP mode, with:
  - Validation status set to `VALIDATED` and compact evidence captured.
  - Merged `scan_results.json` includes new fields and DAST metrics.
  - Reporters surface validation status clearly.
- Safety gates prevent accidental production testing without explicit override and confirmation.

---

## Risks & Mitigations

- SDK tool/skills mismatch: Keep MVP logic in Python helpers callable by the agent; avoid SDK‑
  specific “skills” until verified.
- Over‑redaction or under‑redaction: Provide conservative defaults and tests; document overrides.
- Orchestration drift: Do not add a separate CLI orchestrator; keep a single Scanner flow.

---

## Timeline

- Week 1: Models, CLI flags, prompt, IDOR HTTP helper, reporters.
- Week 2: Merge flow, tests (unit/integration), docs, polish and safety gates.

---

## Next Steps

1) Approve repo‑aligned MVP scope and file changes.  
2) Implement Phase 1 tasks behind `--dast` (HTTP‑only).  
3) Validate with demo target and finalize docs.  
4) Plan Phase 2 (XSS/SQLi, parallelism) and reassess MCP readiness.

