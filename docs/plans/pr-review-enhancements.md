# SecureVibes PR Review Enhancements Plan

**Created**: 2026-02-02
**Status**: Proposed

---

## Overview

Three enhancements to improve the pr-review feature based on testing with OpenClaw
security advisories. This plan is implementation-ready and includes edge cases,
CLI behavior, and test expectations.

---

## Part 1: Schema Validation Fix

### Problem

The pr-code-review agent sometimes outputs findings with different field names than the expected schema, causing validation warnings:

| Expected | Agent Used |
|----------|------------|
| `threat_id` | `id` |
| `line_number` (int) | `line_numbers` (array) |
| `finding_type` | missing |
| `cwe_id` | `vulnerability_types` (array) |

### Solution

Add schema normalization in `packages/core/securevibes/models/schemas.py`:

```python
def normalize_pr_vulnerability(vuln: dict) -> dict:
    """Transform common schema variations to expected format."""
    normalized = {}

    # threat_id: accept 'id', 'threat_id', 'finding_id'
    normalized['threat_id'] = vuln.get('threat_id') or vuln.get('id') or vuln.get('finding_id')
    if not normalized['threat_id']:
        normalized['threat_id'] = derive_pr_finding_id(vuln)  # stable hash of file+title+line

    # finding_type: infer from category if missing
    if 'finding_type' not in vuln:
        normalized['finding_type'] = infer_finding_type(vuln) or 'unknown'

    # line_number: flatten array to first element
    if 'line_numbers' in vuln and isinstance(vuln['line_numbers'], list):
        normalized['line_number'] = vuln['line_numbers'][0] if vuln['line_numbers'] else 0
    else:
        normalized['line_number'] = vuln.get('line_number', 0)

    # cwe_id: extract from vulnerability_types array
    normalized['cwe_id'] = extract_cwe_id(vuln) or vuln.get('cwe_id', '')

    # Copy other required fields
    for field in ['title', 'description', 'severity', 'file_path',
                  'code_snippet', 'attack_scenario', 'evidence']:
        normalized[field] = vuln.get(field, '')

    # recommendation: also accept 'mitigation'
    normalized['recommendation'] = vuln.get('recommendation') or vuln.get('mitigation', '')

    return normalized
```

Update `fix_pr_vulnerabilities_json()` to call normalization after unwrapping.

Implementation details:

- Add helper functions in `schemas.py`:
  - `derive_pr_finding_id(vuln: Mapping[str, object]) -> str`:
    Stable hash of `file_path`, `title`, and `line_number` (or first `line_numbers` entry).
  - `infer_finding_type(vuln: Mapping[str, object]) -> str | None`:
    Map known agent fields (e.g., `category`) to expected enums; return `None` if unsure.
  - `extract_cwe_id(vuln: Mapping[str, object]) -> str | None`:
    Accept `vulnerability_types` entries as strings or dicts, use regex `CWE-\d+`.
- Preserve `line_numbers` by adding it to `evidence` (if present) to avoid losing context.
- Log a warning when normalization fills missing fields or alters types.
- Do not default to `new_threat`; unknowns must not be treated as new threats.

### Files to Modify

- `packages/core/securevibes/models/schemas.py` - Add normalization function
- `packages/core/securevibes/scanner/hooks.py` - Apply normalization in validation hook

---

## Part 2: Update Base Artifacts After PR Review

### New CLI Flag

```bash
securevibes pr-review . --range abc..def --update-artifacts
```

### Implementation

After PR review completes, optionally update base artifacts. The command should
auto-detect what to update (no separate flags for threats vs vulnerabilities):

1. **Append new threats to THREAT_MODEL.json**:
   ```python
   for vuln in pr_vulns:
       if vuln['finding_type'] == 'new_threat':
           threat = convert_vuln_to_threat(vuln)
           threat_model.append(threat)
   ```

2. **Append new vulns to VULNERABILITIES.json**:
   ```python
   for vuln in pr_vulns:
       if vuln_key(vuln) not in existing_keys:  # dedupe by stable key
           vulnerabilities.append(vuln)
   ```

3. **Flag SECURITY.md for regeneration** (if architecture changes detected):
   ```python
   if any_new_components_detected(pr_vulns):
       console.print("⚠️  New components detected. Consider running full scan.")
   ```

Implementation details:

- `vuln_key(vuln)` uses normalized fields: `file_path`, `title`, `line_number`, `severity`.
- `new_threat` findings only update THREAT_MODEL; `known_vuln` or `regression`
  update VULNERABILITIES. `unknown` findings are ignored for artifact updates
  (but still reported).
- `any_new_components_detected` heuristic:
  - Use top-level directory + file extension as a component proxy.
  - Compare against existing THREAT_MODEL components list when available.
  - If no component list exists, print the warning but do not auto-update SECURITY.md.

### Files to Modify

- `packages/core/securevibes/cli/main.py` - Add `--update-artifacts` flag
- `packages/core/securevibes/scanner/scanner.py` - Implement artifact update logic

---

## Part 3: Cron-Based Scanning with Commit Tracking

### Overview

Track scan state and review multiple commits since last scan.

### New Artifacts

**`.securevibes/scan_state.json`**:
```json
{
  "last_full_scan": {
    "commit": "abc123",
    "timestamp": "2026-02-02T10:00:00Z",
    "branch": "main"
  },
  "last_pr_review": {
    "commit": "def456",
    "timestamp": "2026-02-02T15:00:00Z",
    "commits_reviewed": ["def456", "ghi789"]
  }
}
```

### New CLI Commands

```bash
# Review all commits since last scan
securevibes pr-review . --since-last-scan

# Review commits in a date range
securevibes pr-review . --since 2026-02-01

# Review last N commits
securevibes pr-review . --last 10

# Catchup mode: pull latest + scan since last
securevibes catchup . --branch main
```

### CLI Behavior

- `--range`, `--since-last-scan`, `--since`, and `--last` are mutually exclusive.
- `--since` is **inclusive** and interpreted in Pacific time
  (`America/Los_Angeles`) at midnight of the provided date.
- If `scan_state.json` is missing **or** the last scan is on a different branch:
  - Print a clear message.
  - Prompt the user: “No baseline scan found for this branch. Run a baseline
    full scan now? [y/N]”.
  - If the user declines, exit with a non-zero status and instructions.
  - If non-interactive (no TTY), exit with a message instructing the user to run
    a baseline scan first.
- Baseline scan = `securevibes scan .` to generate SECURITY.md, THREAT_MODEL.json,
  VULNERABILITIES.json, and initialize `.securevibes/scan_state.json`.

### Workflow

```
┌─────────────────────────────────────────────────────────────┐
│                    CATCHUP WORKFLOW                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Load scan_state.json                                    │
│     └─ Get last_full_scan.commit (e.g., abc123)             │
│                                                             │
│  2. Get commits since last scan                             │
│     └─ git log abc123..HEAD --oneline                       │
│     └─ Returns: [def456, ghi789, jkl012]                    │
│                                                             │
│  3. Generate combined diff                                  │
│     └─ git diff abc123..HEAD                                │
│                                                             │
│  4. Run pr-review on combined diff                          │
│     └─ Uses existing SECURITY.md, THREAT_MODEL.json         │
│     └─ Outputs PR_VULNERABILITIES.json                      │
│                                                             │
│  5. Update scan_state.json                                  │
│     └─ Set last_pr_review.commit = HEAD                     │
│     └─ Set last_pr_review.commits_reviewed = [...]          │
│                                                             │
│  6. (Optional) Update base artifacts                        │
│     └─ Append new threats to THREAT_MODEL.json              │
│     └─ Append new vulns to VULNERABILITIES.json             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Cron Setup (macOS/Linux)

Note: requires a baseline scan to create `.securevibes/scan_state.json`.

```bash
# Daily at 6 AM
0 6 * * * cd /path/to/openclaw && git pull origin main && securevibes pr-review . --since-last-scan --output daily-review-$(date +%Y%m%d).md
```

### Files to Create

- `packages/core/securevibes/scanner/state.py` - State tracking functions

### Files to Modify

- `packages/core/securevibes/cli/main.py` - Add new CLI options
- `packages/core/securevibes/diff/extractor.py` - Add commit range helpers
- `packages/core/securevibes/scanner/scanner.py` - Integrate state tracking
- `.gitignore` - Add `.securevibes/` if scan state should remain local

---

## Testing Evidence

All three OpenClaw security advisories were successfully detected by pr-review:

| Vulnerability | Advisory | CVE | Detected? | Severity |
|--------------|----------|-----|-----------|----------|
| gatewayUrl token exfiltration | GHSA-g8p2-7wf7-98mq | - | ✅ Yes | Critical |
| OS Command Injection (Swift) | GHSA-q284-4pvr-m585 | CVE-2026-25157 | ✅ Yes | High |
| PATH Injection (Docker) | GHSA-mc68-q9jw-2h3v | CVE-2026-24763 | ✅ Yes | High |

### Test Commands Used

```bash
# Vulnerability 1: gatewayUrl
securevibes pr-review /Users/anshumanbhartiya/repos/openclaw/ --range c49fb82ac~1..c49fb82ac --debug --model sonnet

# Vulnerability 2: Command Injection (Swift)
securevibes pr-review /Users/anshumanbhartiya/repos/openclaw/ --range 04b5002d8~1..04b5002d8 --debug --model sonnet

# Vulnerability 3: PATH Injection (Docker)
securevibes pr-review /Users/anshumanbhartiya/repos/openclaw/ --range eaace3423~1..eaace3423 --debug --model sonnet
```

---

## Implementation Priority

1. **Schema fix** - Quick win, improves reliability
2. **Cron + commit tracking** - Enables automated daily scanning
3. **Update artifacts** - Keeps context fresh over time

## Additional Tests to Add

- `normalize_pr_vulnerability`:
  - `finding_id`/`id`/`threat_id` mapping + derived ID.
  - `line_numbers` list normalization + preservation in `evidence`.
  - `vulnerability_types` parsing for string/dict entries with regex.
  - `finding_type` inference fallback to `unknown`.
- CLI parsing:
  - Mutual exclusion between range/last/since/since-last-scan.
  - `--since` timezone parsing in `America/Los_Angeles`.
- State tracking:
  - Missing `scan_state.json` prompt flow.
  - Branch mismatch prompt flow.
  - Non-interactive mode exits with instructions.
