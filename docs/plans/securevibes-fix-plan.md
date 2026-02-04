# Plan: Fix PR Review Report Generation & Improve RCE Detection

## Problem Summary

Two issues identified:

### Issue 1: Report shows "No vulnerabilities found" despite PR_VULNERABILITIES.json having 3 findings

**Root Cause:** The `dedupe_pr_vulns` function at `scanner.py:1416-1432` removes PR findings that match entries in `VULNERABILITIES.json`. The baseline `VULNERABILITIES.json` already contains PR-001 through PR-004 (from a previous run), so all 3 new findings are deduped away, leaving `result.issues` empty.

**Flow:**
1. Agent writes PR_VULNERABILITIES.json with 3 findings ✓
2. Scanner reads the file ✓
3. `dedupe_pr_vulns()` removes all 3 because they match `(file_path, threat_id)` in VULNERABILITIES.json
4. `result.issues = []` (empty)
5. Report shows "No vulnerabilities found"

### Issue 2: PR Review missed the RCE (CVE-2026-25253)

**The RCE attack chain (per blog):**
1. **Stage 1 - Token Exfiltration:** `gatewayUrl` accepts attacker's URL, and `authToken` is sent in the WebSocket handshake
2. **Stage 2 - Localhost Bypass:** Attacker uses stolen token to connect to victim's localhost:18789
3. **Stage 3 - Sandbox Escape:** With `operator.admin` scope, attacker disables safety via API (`ask: "off"`, `tools.exec.host: "gateway"`)

**What PR review found:**
- Open redirect (CWE-601) - partial
- Credential leakage (CWE-598)
- XSS risk (CWE-79)

**What PR review missed:**
- Token being bundled into WebSocket handshake (immediate credential exposure to attacker gateway)
- Ability to disable sandbox/safety controls via authenticated API
- The full RCE chain

---

## Implementation Plan

### Fix 1: Dedupe Logic Bug

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py`

**Problem:** PR findings should NOT be deduped against VULNERABILITIES.json entries that have `threat_id` starting with `PR-`. Those are previous PR review findings, not baseline vulnerabilities.

**Change:** Modify `dedupe_pr_vulns` to exclude PR-prefixed entries from the known_keys:

```python
def dedupe_pr_vulns(pr_vulns: list[dict], known_vulns: list[dict]) -> list[dict]:
    """Drop PR findings that match known issues by file + threat_id/title.

    Only dedupe against baseline vulnerabilities (THREAT-*), not previous
    PR findings (PR-*) which may have been merged into VULNERABILITIES.json.
    """
    known_keys = set()
    for vuln in known_vulns:
        if not isinstance(vuln, dict):
            continue
        threat_id = vuln.get("threat_id", "")
        # Skip PR-prefixed entries - those are previous PR findings, not baseline
        if isinstance(threat_id, str) and threat_id.startswith("PR-"):
            continue
        key = (vuln.get("file_path"), threat_id or vuln.get("title"))
        known_keys.add(key)
    # ... rest unchanged
```

**Test:** Add test in `test_scanner.py` or new `test_dedupe.py`:
```python
def test_dedupe_excludes_pr_prefixed_known_vulns():
    pr_vulns = [{"file_path": "app.py", "threat_id": "PR-001", "title": "Test"}]
    known_vulns = [{"file_path": "app.py", "threat_id": "PR-001", "title": "Test"}]
    result = dedupe_pr_vulns(pr_vulns, known_vulns)
    assert len(result) == 1  # Should NOT be deduped
```

### Fix 2: Improve PR Review RCE Detection

**File:** `/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/prompts/agents/pr_code_review.txt`

**Problem:** The PR code review prompt doesn't emphasize detecting credential-in-handshake patterns or sandbox-escape chains.

**Change:** Add specific detection patterns to the PR code review agent prompt:

```
## Critical Attack Patterns to Detect

### 1. Credential Exposure via Configuration Injection
When reviewing URL parameter handling or configuration changes, check for:
- Credentials (tokens, passwords, API keys) sent to externally-configurable endpoints
- Auth tokens included in WebSocket/HTTP handshakes to user-controlled URLs
- OAuth tokens or session cookies exposed to attacker-controlled servers

Example: If code accepts `gatewayUrl` from URL params AND sends `authToken` in the
connection handshake, this enables token theft → RCE chain.

### 2. Sandbox/Safety Bypass Chains
Check if authenticated users can:
- Disable safety controls (ask mode, approval requirements)
- Modify execution policies (sandbox, elevated mode)
- Change tool restrictions at runtime

Example: Token with `operator.admin` scope can disable `ask` mode → enables
unauthorized command execution.

### 3. Localhost Bypass / SSRF-to-RCE
When external input controls connection targets:
- Can attacker redirect connections to localhost services?
- Does the localhost service trust connections with stolen credentials?
- Can the chain lead to code execution?
```

---

## Files to Modify

1. **`/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/scanner/scanner.py`**
   - Line ~1416-1432: Modify `dedupe_pr_vulns` to skip PR-prefixed known entries

2. **`/Users/anshumanbhartiya/repos/securevibes/packages/core/securevibes/prompts/agents/pr_code_review.txt`**
   - Add RCE chain detection patterns

3. **`/Users/anshumanbhartiya/repos/securevibes/packages/core/tests/test_scanner.py`** (or new test file)
   - Add test for dedupe fix

---

## Verification

After implementation:

```bash
cd /Users/anshumanbhartiya/repos/securevibes/packages/core

# Run tests
python -m pytest tests/ -v -k "dedupe"

# Re-run PR review on the same commit
securevibes pr-review /Users/anshumanbhartiya/repos/openclaw-baseline \
  --range c74551c2a^..c74551c2a \
  --debug --model sonnet

# Verify:
# 1. PR_VULNERABILITIES.json findings appear in pr_review_report.md
# 2. Report shows the 3 vulnerabilities (not "No vulnerabilities found")
# 3. Check if RCE chain is detected (may require additional prompt tuning)
```

---

## Summary

| Issue | Root Cause | Fix |
|-------|------------|-----|
| Report empty | Dedupe removes PR-* from PR_VULNERABILITIES against PR-* in VULNERABILITIES.json | Skip PR-prefixed entries in dedupe |
| RCE missed | Prompt lacks credential-handshake and sandbox-escape detection patterns | Add attack chain patterns to pr_code_review prompt |
