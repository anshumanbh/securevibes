# E2E Test Setup: GHSA-gv46-4xfq-jv58 Incremental Scan Validation

## Context

We want to validate that the incremental scan wrapper (`ops/incremental_scan.py`) can detect a real vulnerability chain when new commits land. We're using advisory [GHSA-gv46-4xfq-jv58](https://github.com/openclaw/openclaw/security/advisories/GHSA-gv46-4xfq-jv58) (RCE via unsanitized `node.invoke` params for `system.run`) in the openclaw repo as our test case.

The idea: park a git worktree at a clean state before the vulnerability existed, run a baseline scan, then advance to include the vuln-introducing commit, and verify the incremental scan catches it.

---

## Vulnerability Analysis

**What**: The gateway's `node.invoke` handler forwarded user-supplied `params` directly to node hosts without sanitizing internal control fields (`approved`, `approvalDecision`). Attackers could inject these to bypass exec approval requirements and execute arbitrary commands.

**Vuln-introducing commit**: `2f8206862` (Jan 19 2026) — "refactor: remove bridge protocol"
- Changed `bridge.invoke({ paramsJSON: JSON.stringify(p.params) })` → `context.nodeRegistry.invoke({ params: p.params })`
- The direct object forwarding (no serialization boundary) enabled the bypass
- File: `src/gateway/server-methods/nodes.ts` line ~392: `params: p.params`

**Fix commits** (all Feb 14 2026):
- `318379cdb` — bind system.run approvals to exec approvals (main fix, +437 lines)
- `a7af646fd` — bind approval IDs to device identity
- `c15946274` — allowlist system.run params
- `0af76f5f0` — centralize node.invoke param sanitization

---

## Existing Worktree Note

There is already a worktree `openclaw-ghsa-gv46-pre` at commit `67be9aed2` — this is **after** the vuln was introduced but **before** the fix. It's in the vulnerable zone, not suitable as a clean baseline.

---

## Worktree Command

Create a new worktree parked at `b347d5d9c` ("feat: add gateway tls support", Jan 19 02:46 UTC) — the commit **immediately before** the vulnerability introduction:

```bash
cd /Users/anshumanbhartiya/repos/openclaw

git worktree add --detach \
  /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline \
  b347d5d9c
```

This gives you a clean codebase where `node.invoke` still uses the bridge protocol with `JSON.stringify()` serialization — no vuln present.

---

## Test Workflow

### Step 1: Baseline scan (clean state)

```bash
cd /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline

# Bootstrap the incremental scanner — records current HEAD as anchor
python /path/to/securevibes/ops/incremental_scan.py \
  --repo . --branch HEAD --debug
```

This creates `.securevibes/incremental_state.json` with `last_seen_sha = b347d5d9c`, `status = "bootstrap"`.

### Step 2: Advance to include the vulnerability

```bash
cd /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline

# Advance to the vuln-introducing commit (5 commits forward)
git checkout 2f8206862
```

The worktree now contains the vulnerable code. The incremental scanner's state still points at `b347d5d9c`.

### Step 3: Run incremental scan

```bash
python /path/to/securevibes/ops/incremental_scan.py \
  --repo /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline \
  --debug
```

The scanner should:
1. Detect 5 new commits (`b347d5d9c..2f8206862`)
2. Classify as a small window (<=8) → single scan range
3. Invoke `securevibes pr-review` with `--range b347d5d9c..2f8206862`
4. The scan should flag the unsanitized param forwarding in `src/gateway/server-methods/nodes.ts`

### Step 4: Validate results

Check `.securevibes/incremental_runs/<run_id>.json` for:
- Scan completed successfully (not infra failure)
- Findings include the param injection / approval bypass issue
- Anchor advanced to `2f8206862`

---

## Key Commits Reference

| Role | SHA | Date | Message |
|---|---|---|---|
| **Baseline anchor** | `b347d5d9c` | Jan 19, 02:46 UTC | feat: add gateway tls support |
| **Vuln introduced** | `2f8206862` | Jan 19, 04:50 UTC | refactor: remove bridge protocol |
| **First fix** | `318379cdb` | Feb 14, 13:02 CET | fix(gateway): bind system.run approvals |
| **Last fix** | `0af76f5f0` | Feb 14, 13:26 CET | refactor: centralize node.invoke param sanitization |

## Commits in the scan window (b347d5d9c..2f8206862)

```
b347d5d9c → 73e9e787b → 47d1f23d5 → c21469b28 → 10a0c96ee → 2f8206862
```

5 commits — well within the "small window" threshold (<=8), so the scanner will process them as a single range.
