# Proposal: Claude Code Tasks Integration

**Author**: Sage (AI Assistant) + Anshuman Bhartiya  
**Date**: 2026-01-24  
**Status**: Proposed

---

## Executive Summary

Integrate Claude Code's new **Tasks** feature into SecureVibes to replace the current file-based artifact dependency system. This enables multi-session collaboration during long scans, automatic resume capabilities, and lays groundwork for parallel agent execution.

SecureVibes is **pre-architected** for this integration — the existing `SUBAGENT_ARTIFACTS` dependency graph maps directly to Tasks' native dependency resolution.

---

## Background

### What are Claude Code Tasks?

Anthropic shipped Tasks in Claude Code (Jan 2026), replacing the previous Todos system:

- **Dependency-aware**: Tasks can depend on each other (stored in metadata)
- **File-based**: Stored in `~/.claude/tasks/` (inspectable, hackable)
- **Multi-session sync**: When one session updates a task, all sessions see it
- **Subagent coordination**: Perfect for spawning workers on complex projects

Reference: https://x.com/trq212/status/2014480496013803643

### Current SecureVibes Architecture

SecureVibes already implements a dependency-aware multi-agent pipeline:

```
┌────────────────┐     ┌─────────────────┐     ┌─────────────────┐     ┌──────────────────┐     ┌──────┐
│   Assessment   │────▶│ Threat Modeling │────▶│   Code Review   │────▶│ Report Generator │────▶│ DAST │
│ (SECURITY.md)  │     │(THREAT_MODEL.json)│   │(VULNERABILITIES │     │(scan_results.json)│     │      │
└────────────────┘     └─────────────────┘     │     .json)      │     └──────────────────┘     └──────┘
                                               └─────────────────┘
```

The `SUBAGENT_ARTIFACTS` dict in `subagent_manager.py` already defines this:

```python
SUBAGENT_ARTIFACTS = {
    "assessment": {
        "creates": "SECURITY.md",
        "requires": None,
    },
    "threat-modeling": {
        "creates": "THREAT_MODEL.json",
        "requires": "SECURITY.md",
    },
    # ...
}
```

This is **functionally equivalent** to Tasks' dependency metadata.

---

## Proposed Changes

### Phase 1: Foundation (1-2 days)

#### 1.1 Environment Variable Support

Add `SECUREVIBES_TASK_LIST_ID` environment variable passthrough:

```python
# cli/main.py
@click.option("--task-list", "-t", help="Task list ID for session continuity")
def scan(..., task_list: Optional[str]):
    if task_list:
        os.environ["SECUREVIBES_TASK_LIST_ID"] = task_list
```

#### 1.2 Task Manager Module

Create `scanner/tasks_manager.py`:

```python
import os
from typing import Optional

TASK_LIST_ID = os.environ.get("SECUREVIBES_TASK_LIST_ID")

def create_scan_tasks(phases: list[str]) -> Optional[str]:
    """Create interdependent security scan tasks"""
    if not TASK_LIST_ID:
        return None
    
    # Create tasks with dependencies matching SUBAGENT_ARTIFACTS
    # Store in ~/.claude/tasks/{TASK_LIST_ID}.json
    ...

def update_task_status(phase: str, status: str, output: Optional[str] = None):
    """Update task status and broadcast to other sessions"""
    ...

def get_first_incomplete_task() -> Optional[str]:
    """For resume functionality"""
    ...
```

#### 1.3 Basic Status Updates in Scanner

Modify `scanner/scanner.py`:

```python
async def _execute_scan(self, repo: Path, ...):
    task_list_id = os.environ.get("SECUREVIBES_TASK_LIST_ID", f"scan-{int(time.time())}")
    os.environ["SECUREVIBES_TASK_LIST_ID"] = task_list_id
    
    for phase in self.phases:
        tasks_manager.update_task_status(phase, "in_progress")
        try:
            await self._run_agent(phase)
            tasks_manager.update_task_status(phase, "completed", output=f".securevibes/{artifact}")
        except Exception as e:
            tasks_manager.update_task_status(phase, "failed", output=str(e))
            raise
```

### Phase 2: Progress Integration (2-3 days)

#### 2.1 Enhanced ProgressTracker

```python
class TaskAwareProgressTracker(ProgressTracker):
    def announce_phase(self, phase_name: str):
        super().announce_phase(phase_name)
        tasks_manager.update_task_status(phase_name, "in_progress")
        tasks_manager.broadcast_update()
```

#### 2.2 Automatic Resume

```python
# cli/main.py
if task_list:
    tl = tasks_manager.load_task_list(task_list)
    resume_from = tasks_manager.get_first_incomplete_task()
    if resume_from:
        console.print(f"Resuming from {resume_from}...")
```

### Phase 3: Collaboration Features (3-5 days)

- Cross-session artifact access
- `securevibes tasks list` / `securevibes tasks status` CLI commands
- Optional web dashboard integration

### Phase 4: Advanced DAG (Future)

Parallel agent execution for independent phases:

```
                    ┌─────────────────────┐
                    │  Secret Detection   │ (parallel)
                    └─────────────────────┘
                              │
┌────────────────┐     ┌─────┴─────────────┐
│   Assessment   │────▶│ Threat Modeling   │
└────────────────┘     └─────┬─────────────┘
                              │
                    ┌─────────┴───────────┐
                    │                     │
             ┌──────▼──────┐      ┌───────▼──────┐
             │ Code Review │      │ Dependency   │  (parallel)
             │ (Security)  │      │ Audit (SBOM) │
             └──────┬──────┘      └───────┬──────┘
                    │                     │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Report Generator   │
                    └─────────────────────┘
```

---

## Benefits

| Current | With Tasks |
|---------|------------|
| Single-terminal progress | Multi-session collaboration |
| Manual `--resume-from` flag | Automatic resume from last task |
| File polling for dependencies | Native dependency resolution |
| Opaque scan state | Inspectable `~/.claude/tasks/` |
| Sequential-only execution | Future parallel DAG support |

---

## Migration Path

The integration is **non-breaking**:

1. Tasks are opt-in via `--task-list` flag
2. Existing artifact system continues to work
3. Can gradually migrate from `SUBAGENT_ARTIFACTS` to Tasks
4. `validate_prerequisites()` becomes a thin wrapper around Tasks API

---

## Files to Modify

| File | Changes |
|------|---------|
| `cli/main.py` | Add `--task-list` option |
| `scanner/scanner.py` | Task status updates in `_execute_scan()` |
| `scanner/tasks_manager.py` | **New file** — Task list management |
| `scanner/subagent_manager.py` | Optional: delegate to tasks_manager |
| `scanner/hooks.py` | Optional: task updates on validation events |

---

## Open Questions

1. **Graceful degradation**: What happens if Claude Code Tasks API is unavailable?
2. **Task list naming**: Should we auto-generate IDs or require explicit naming?
3. **Cleanup policy**: When should old task lists be garbage collected?
4. **CI/CD mode**: Should tasks be disabled in non-interactive environments?

---

## Next Steps

1. [ ] Review and approve this proposal
2. [ ] Implement Phase 1 (foundation)
3. [ ] Test with real security scans
4. [ ] Iterate on Phase 2-3 based on feedback

---

*Generated by Sage 🦉 based on codebase analysis*
