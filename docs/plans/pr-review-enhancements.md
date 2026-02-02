# SecureVibes PR Review Enhancements Plan

**Created**: 2026-02-02
**Status**: Proposed

---

## Overview

Three enhancements to improve the pr-review feature based on testing with OpenClaw security advisories.

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
    normalized['threat_id'] = vuln.get('threat_id') or vuln.get('id') or 'UNKNOWN'

    # finding_type: infer from category if missing
    if 'finding_type' not in vuln:
        normalized['finding_type'] = 'new_threat'  # default

    # line_number: flatten array to first element
    if 'line_numbers' in vuln and isinstance(vuln['line_numbers'], list):
        normalized['line_number'] = vuln['line_numbers'][0] if vuln['line_numbers'] else 0
    else:
        normalized['line_number'] = vuln.get('line_number', 0)

    # cwe_id: extract from vulnerability_types array
    if 'vulnerability_types' in vuln:
        for vtype in vuln['vulnerability_types']:
            if 'CWE-' in vtype:
                normalized['cwe_id'] = vtype.split(':')[0].strip()
                break
    else:
        normalized['cwe_id'] = vuln.get('cwe_id', '')

    # Copy other required fields
    for field in ['title', 'description', 'severity', 'file_path',
                  'code_snippet', 'attack_scenario', 'evidence']:
        normalized[field] = vuln.get(field, '')

    # recommendation: also accept 'mitigation'
    normalized['recommendation'] = vuln.get('recommendation') or vuln.get('mitigation', '')

    return normalized
```

Update `fix_pr_vulnerabilities_json()` to call normalization after unwrapping.

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

After PR review completes, optionally update base artifacts:

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
       if vuln not in existing_vulns:  # dedupe by file+title
           vulnerabilities.append(vuln)
   ```

3. **Flag SECURITY.md for regeneration** (if architecture changes detected):
   ```python
   if any_new_components_detected(pr_vulns):
       console.print("⚠️  New components detected. Consider running full scan.")
   ```

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
