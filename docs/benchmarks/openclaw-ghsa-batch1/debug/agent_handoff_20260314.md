# Agent Handoff - 2026-03-14

## Benchmark State

- Batch: `docs/benchmarks/openclaw-ghsa-batch1`
- Baseline cache: `10/10` complete
- Intro PR-review runs: `10/10` complete
- Current score:
  - Tier-1: `9/10`
  - Tier-2: `7/10`
- Remaining misses:
  - `GHSA-gv46-4xfq-jv58`
  - `GHSA-3c6h-g97w-fg78`
  - `GHSA-g55j-c2v4-pjcg`

## Current Best Understanding Of The Misses

### `GHSA-gv46-4xfq-jv58`

- Miss type: adjacent-vulnerability drift in the correct subsystem
- Advisory root cause: node invoke approval bypass / `system.execApprovals` and `system.run`
- SecureVibes behavior: repeatedly finds nearby real gateway bugs such as `node.invoke.result` spoofing and related command/identity issues
- Current conclusion: not mainly a rate-limit problem; the exact advisory shard was reviewed but the model drifted to adjacent `node.invoke` bugs
- Most relevant files:
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-gv46-4xfq-jv58/analysis.md`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-gv46-4xfq-jv58/detectability.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-gv46-4xfq-jv58/runs/20260310T065513Z/intro_pr_review.commit_2f8206862a68.part_07.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-gv46-4xfq-jv58/runs/20260310T065513Z/intro_pr_review.commit_2f8206862a68.part_07.log.json`

### `GHSA-3c6h-g97w-fg78`

- Miss type: clean semantic miss
- Advisory root cause: `tools.exec.safeBins` long-option abbreviation / canonicalization bypass in safe-bin approval logic
- SecureVibes behavior: reads the right files, but concludes refactor / protections still present
- Current conclusion: timeout noise was reduced, but both introducing commits remain reasoning misses even after prompt/context tuning
- Most relevant files:
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-3c6h-g97w-fg78/analysis.md`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-3c6h-g97w-fg78/detectability.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-3c6h-g97w-fg78/runs/20260312T061854Z/intro_pr_review.commit_2d485cd47a53.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-3c6h-g97w-fg78/runs/20260312T061854Z/intro_pr_review.commit_89aad7b92283.json`

### `GHSA-g55j-c2v4-pjcg`

- Miss type: composed-impact / final-ranking miss
- Advisory root cause: unauthenticated local RCE via WebSocket `config.apply`
- SecureVibes behavior now:
  - clearly detects the new auth/control-plane weaknesses
  - composes them into admin-method / approval / pairing reachability
  - explicitly searched `config.(set|patch|apply)` in the latest rerun
  - still did **not** select the exact `config.apply -> local RCE` chain in the final merged report
- Current conclusion: sink visibility is no longer the main problem; the remaining gap is final reasoning/ranking/selection
- Most relevant files:
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/analysis.md`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/detectability.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/runs/20260314T095048Z/intro_pr_review.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/runs/20260314T095048Z/intro_pr_review.commit_73e9e787b4df.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/runs/20260314T095048Z/intro_pr_review.commit_73e9e787b4df.part_03.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/runs/20260314T095048Z/intro_pr_review.commit_73e9e787b4df.part_03.log.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/runs/20260314T095048Z/intro_pr_review.commit_73e9e787b4df.part_04.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/runs/20260314T095048Z/intro_pr_review.commit_73e9e787b4df.part_05.json`
  - `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/runs/20260314T095048Z/intro_pr_review.commit_73e9e787b4df.part_06.json`

## Latest Case `#6` Rerun Summary

Run:
- `docs/benchmarks/openclaw-ghsa-batch1/cases/GHSA-g55j-c2v4-pjcg/runs/20260314T095048Z`

What survived into the merged report:
- `critical`: client-controlled role/scopes -> administrative operations
- `high`: `exec.approval.resolve` command-context validation gap
- `high`: attacker-controlled `resolvedPath` / `sessionKey` in exec approval requests
- `critical/high`: self-signed device-pairing / scope persistence privilege escalation
- `high`: silent pairing + Tailscale / loopback trust issues
- `high`: macOS device identity private key stored in plaintext

Key observation:
- `part_03.log.json` shows explicit searches for `config.(set|patch|apply)`
- The final merged output still chose adjacent auth/control-plane findings instead of the unchanged sink path
- This strongly suggests the next gain must come from post-review ranking/selection, not more sink-context visibility

## Scanner/Tuning Work Already Added

The current tree already includes multiple generic improvements that were added during this batch, including:
- new-surface threat delta context for PR review
- changed-code dataflow facts and branch semantics summaries
- timeout propagation and phase timing instrumentation
- canonical PR artifact persistence across focused passes
- checkpoint PR-review output writing during focused passes
- benchmark harness fix to review each introducing commit on the correct checkout
- auth-diff composition with baseline high-impact sink summaries
- unchanged baseline sink code anchors in PR-review context
- generic post-review sink-composition pass for newly reachable baseline operations

Practical implication:
- the next useful change for `GHSA-g55j-c2v4-pjcg` should **not** be another broad context expansion
- it should be a final chooser / prioritizer that prefers a fully supported end-to-end sink finding over intermediate auth findings when both exist

## Recommended Next Step

Priority order:
1. Work `GHSA-g55j-c2v4-pjcg`
2. Then `GHSA-gv46-4xfq-jv58`
3. Leave `GHSA-3c6h-g97w-fg78` for last

Concrete next change for `GHSA-g55j-c2v4-pjcg`:
- Add a final composed-finding chooser after findings are merged
- Inputs:
  - merged PR findings
  - baseline high-impact sink anchors
  - changed auth/control-plane chain summaries
- Rule:
  - if a finding proves new reachability to an unchanged critical sink, prefer that end-to-end sink finding over intermediate auth/control-plane findings
- Keep it strict:
  - require the promoted finding to name the changed entry path, the unchanged sink, and the concrete sink impact
  - if that evidence is not present, keep the intermediate finding

Validation path after that change:
1. rerun only `GHSA-g55j-c2v4-pjcg` intro-only
2. check whether final report upgrades to `config.apply -> local RCE`
3. if yes, re-adjudicate case `#6`
4. only then move on to `#3`

## Repository State Notes

- Current git index was clean when this handoff note was written
- There are unrelated local modifications under debug docs and sweep artifacts; do not assume the worktree is clean
- Specifically, `docs/benchmarks/openclaw-ghsa-batch1/debug/README.md` already had unrelated local edits, so this handoff was written as a new standalone file
