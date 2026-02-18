# E2E Test Setup: GHSA-gv46-4xfq-jv58 Incremental Scan Validation

## Context

We want to validate that the incremental scan wrapper (`ops/incremental_scan.py`) can detect a real vulnerability chain when new commits land. We're using advisory [GHSA-gv46-4xfq-jv58](https://github.com/openclaw/openclaw/security/advisories/GHSA-gv46-4xfq-jv58) (RCE via unsanitized `node.invoke` params for `system.run`) in the openclaw repo as our test case.

The idea: park a git worktree at a clean state before the vulnerability existed, run a baseline scan, then simulate new commits arriving via a fake remote, and verify the incremental scan catches the vuln.

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

## Why a Fake Remote is Needed

The incremental scanner detects new commits via `git fetch <remote> <branch>` + `git rev-parse <remote>/<branch>`. Simply doing `git checkout <commit>` in a worktree only changes the working tree — it does **not** change what `origin/main` resolves to. The scanner would never see "new commits."

To simulate commits arriving on a remote, we create a local bare repo as a fake remote and control what's pushed to it.

---

## Test Workflow

### Step 1: Create a fake remote

```bash
git init --bare /tmp/openclaw-test-remote
```

### Step 2: Push the baseline commit to the fake remote

```bash
cd /Users/anshumanbhartiya/repos/openclaw
git remote add test-gv46 /tmp/openclaw-test-remote
git push test-gv46 b347d5d9c:refs/heads/main
```

### Step 3: Create the worktree at the pre-vuln baseline

```bash
cd /Users/anshumanbhartiya/repos/openclaw

git worktree add --detach \
  /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline \
  b347d5d9c
```

This gives you a clean codebase where `node.invoke` still uses the bridge protocol with `JSON.stringify()` serialization — no vuln present.

### Step 4: Run baseline scan to generate real security artifacts

```bash
securevibes scan /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline \
  --debug --model sonnet
```

This generates proper `.securevibes/SECURITY.md` and `.securevibes/THREAT_MODEL.json` with real threat model context for the openclaw codebase, which `pr-review` needs to reason about security implications.

### Step 5: Bootstrap the incremental scanner

```bash
python3 /Users/anshumanbhartiya/repos/securevibes/ops/incremental_scan.py \
  --repo /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline \
  --remote test-gv46 --branch main --debug
```

This creates `.securevibes/incremental_state.json` with `last_seen_sha = b347d5d9c`, `status = "bootstrap"`.

### Step 6: Simulate new commits arriving — push vuln commit to fake remote

```bash
cd /Users/anshumanbhartiya/repos/openclaw
git push test-gv46 2f8206862:refs/heads/main --force
```

Now `test-gv46/main` points to the vuln-introducing commit. The scanner's state still anchors at `b347d5d9c`.

### Step 7: Run incremental scan

```bash
python3 /Users/anshumanbhartiya/repos/securevibes/ops/incremental_scan.py \
  --repo /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline \
  --remote test-gv46 --branch main --debug
```

The scanner should:
1. `git fetch test-gv46 main` — updates `test-gv46/main` to `2f8206862`
2. Detect 5 new commits (`b347d5d9c..2f8206862`)
3. Classify as a small window (<=8) — single scan range
4. Invoke `securevibes pr-review` with `--range b347d5d9c..2f8206862`
5. Flag the unsanitized param forwarding in `src/gateway/server-methods/nodes.ts`

### Step 8: Validate results

```bash
# Check state advanced
cat /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline/.securevibes/incremental_state.json

# Check run record
ls /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline/.securevibes/incremental_runs/

# Read the scan output (run_id from state file)
cat /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline/.securevibes/incremental_runs/<run_id>.json
```

Verify:
- Scan completed successfully (not infra failure)
- Findings include the param injection / approval bypass issue
- Anchor advanced to `2f8206862`

---

## Cleanup

```bash
cd /Users/anshumanbhartiya/repos/openclaw
git remote remove test-gv46
git worktree remove /Users/anshumanbhartiya/repos/openclaw-ghsa-gv46-baseline
rm -rf /tmp/openclaw-test-remote
```

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
b347d5d9c -> 73e9e787b -> 47d1f23d5 -> c21469b28 -> 10a0c96ee -> 2f8206862
```

5 commits — well within the "small window" threshold (<=8), so the scanner will process them as a single range.
