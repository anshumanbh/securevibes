#!/usr/bin/env python3
"""Run empirical SecureVibes evaluation for one GHSA case.

Workflow:
1. Checkout OpenClaw baseline commit and run full scan.
2. Checkout OpenClaw fix commit and run PR review for vulnerable range.
3. Run PR review for fix range.
4. Persist logs/reports under cases/<GHSA>/runs/<timestamp>/.

By default, this runs SecureVibes from the local repository using:
PYTHONPATH=<securevibes_repo>/packages/core python -m securevibes.cli.main

This allows commit-specific SecureVibes testing without reinstalling the CLI.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"
REPO_ROOT = Path(__file__).resolve().parents[4]
VALID_PERMISSION_MODES = ("default", "acceptEdits", "bypassPermissions")
BASELINE_ARTIFACTS = ("SECURITY.md", "THREAT_MODEL.json", "VULNERABILITIES.json")
SPLIT_DIFF_GROUP_SIZE = 4
PREEMPTIVE_SPLIT_FILE_THRESHOLD = 8
LOW_SIGNAL_SPLIT_PATH_PREFIXES = ("docs/",)
LOW_SIGNAL_SPLIT_SUFFIXES = (
    ".md",
    ".rst",
    ".txt",
    ".adoc",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
)
LOW_SIGNAL_SPLIT_BASENAMES = (
    "changelog.md",
    "pnpm-lock.yaml",
    "package-lock.json",
    "yarn.lock",
)


@dataclass(frozen=True)
class SecureVibesContext:
    """Resolved SecureVibes source context used for benchmark runs."""

    repo_path: Path
    commit_sha: str


def run(
    cmd: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_checked(
    cmd: list[str],
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> str:
    code, out, err = run(cmd, cwd=cwd, env=env)
    if code != 0:
        raise RuntimeError(f"Command failed ({code}): {' '.join(cmd)}\n{err}")
    return out.strip()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def summarize_issues(report_path: Path) -> dict[str, Any]:
    """Return compact issue summary for a SecureVibes JSON report."""
    if not report_path.exists():
        return {"exists": False, "issue_count": None, "severities": {}}

    payload = load_json(report_path)
    issues = payload.get("issues") if isinstance(payload, dict) else None
    if not isinstance(issues, list):
        return {"exists": True, "issue_count": None, "severities": {}}

    severities: dict[str, int] = {}
    for issue in issues:
        sev = str(issue.get("severity", "unknown")).lower()
        severities[sev] = severities.get(sev, 0) + 1
    return {"exists": True, "issue_count": len(issues), "severities": severities}


def resolve_securevibes_context(
    securevibes_repo: Path,
    securevibes_commit: str | None,
    temp_root: Path,
) -> tuple[SecureVibesContext, Path | None]:
    """Resolve SecureVibes code path for this run.

    Returns (context, worktree_path_to_cleanup).
    """
    repo = securevibes_repo.resolve()
    if not repo.exists():
        raise RuntimeError(f"SecureVibes repo does not exist: {repo}")

    if securevibes_commit:
        worktree_path = temp_root / "securevibes-worktree"
        run_checked(
            [
                "git",
                "-C",
                str(repo),
                "worktree",
                "add",
                "--detach",
                str(worktree_path),
                securevibes_commit,
            ]
        )
        commit_sha = run_checked(["git", "-C", str(worktree_path), "rev-parse", "HEAD"])
        return (
            SecureVibesContext(repo_path=worktree_path, commit_sha=commit_sha),
            worktree_path,
        )

    commit_sha = run_checked(["git", "-C", str(repo), "rev-parse", "HEAD"])
    return SecureVibesContext(repo_path=repo, commit_sha=commit_sha), None


def securevibes_command(
    sv_ctx: SecureVibesContext,
    python_executable: str,
    permission_mode: str,
    subcommand: str,
    *args: str,
    runtime_home: Path | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Build a commit-pinned SecureVibes command and env."""
    env = os.environ.copy()
    py_path = str((sv_ctx.repo_path / "packages" / "core").resolve())
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = py_path if not existing else f"{py_path}{os.pathsep}{existing}"
    env["SECUREVIBES_PERMISSION_MODE"] = permission_mode
    if runtime_home is not None:
        # Keep Claude/SecureVibes runtime state in a writable directory during benchmark runs.
        runtime_home = runtime_home.resolve()
        runtime_home.mkdir(parents=True, exist_ok=True)
        env["HOME"] = str(runtime_home)
        env["XDG_CONFIG_HOME"] = str(runtime_home / ".config")
        env["XDG_CACHE_HOME"] = str(runtime_home / ".cache")
        env["CLAUDE_CONFIG_DIR"] = str(runtime_home / ".claude")

    cmd = [python_executable, "-m", "securevibes.cli.main", subcommand, *args]
    return cmd, env


def validate_baseline_artifacts(openclaw_repo: Path) -> dict[str, Any]:
    """Validate required baseline artifacts generated by full scan."""
    root = openclaw_repo / ".securevibes"
    security_md = root / "SECURITY.md"
    threat_model = root / "THREAT_MODEL.json"
    vulnerabilities = root / "VULNERABILITIES.json"

    details = {
        "security_md_exists": security_md.exists(),
        "threat_model_exists": threat_model.exists(),
        "vulnerabilities_exists": vulnerabilities.exists(),
        "threat_model_json_valid": False,
        "vulnerabilities_json_valid": False,
    }

    if threat_model.exists():
        try:
            load_json(threat_model)
            details["threat_model_json_valid"] = True
        except (OSError, json.JSONDecodeError):
            details["threat_model_json_valid"] = False

    if vulnerabilities.exists():
        try:
            payload = load_json(vulnerabilities)
            details["vulnerabilities_json_valid"] = isinstance(payload, list)
        except (OSError, json.JSONDecodeError):
            details["vulnerabilities_json_valid"] = False

    details["valid"] = all(
        [
            details["security_md_exists"],
            details["threat_model_exists"],
            details["vulnerabilities_exists"],
            details["threat_model_json_valid"],
            details["vulnerabilities_json_valid"],
        ]
    )
    return details


def persist_command_log(
    path: Path,
    cmd: list[str],
    code: int,
    stdout: str,
    stderr: str,
) -> None:
    payload = {
        "command": cmd,
        "exit_code": code,
        "stdout": stdout,
        "stderr": stderr,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def copy_report_if_present(src: Path, dst: Path) -> None:
    """Copy a generated report to run artifacts if it exists."""
    if src.exists():
        shutil.copy2(src, dst)


def report_indicates_success(report_path: Path) -> bool:
    """Treat report existence as success for flaky non-zero CLI exits."""
    return report_path.exists()


def command_hit_rate_limit(stdout: str, stderr: str) -> bool:
    """Detect Claude quota/rate-limit messaging in command output."""
    haystack = f"{stdout}\n{stderr}"
    return "You've hit your limit" in haystack


def _sanitize_cache_token(value: str) -> str:
    """Convert arbitrary strings to filesystem-safe cache tokens."""
    safe_chars = []
    for ch in value:
        if ch.isalnum():
            safe_chars.append(ch.lower())
        elif ch in ("-", "_"):
            safe_chars.append(ch)
        else:
            safe_chars.append("-")
    token = "".join(safe_chars).strip("-")
    return token or "unknown"


def baseline_cache_key(
    *,
    baseline_commit: str,
    securevibes_commit: str,
    model: str,
    severity: str,
) -> str:
    """Build stable key for cached baseline artifacts."""
    return (
        f"baseline-{baseline_commit[:12]}"
        f"__sv-{securevibes_commit[:12]}"
        f"__model-{_sanitize_cache_token(model)}"
        f"__sev-{_sanitize_cache_token(severity)}"
    )


def find_compatible_baseline_cache_entry(
    *,
    cache_dir: Path,
    baseline_commit: str,
    model: str,
    severity: str,
) -> Path | None:
    """Find latest usable baseline cache entry for same baseline/model/severity."""
    if not cache_dir.exists():
        return None
    pattern = (
        f"baseline-{baseline_commit[:12]}"
        "__sv-*"
        f"__model-{_sanitize_cache_token(model)}"
        f"__sev-{_sanitize_cache_token(severity)}"
    )
    candidates = sorted(
        (entry for entry in cache_dir.glob(pattern) if entry.is_dir()),
        key=lambda entry: entry.stat().st_mtime,
        reverse=True,
    )
    for entry in candidates:
        if baseline_cache_is_usable(entry):
            return entry
    return None


def _cache_meta_path(cache_entry: Path) -> Path:
    return cache_entry / "metadata.json"


def commit_window_from_entries(entries: Any) -> str | None:
    """Build a commit-window range from timeline commit entries."""
    if not isinstance(entries, list):
        return None

    shas: list[str] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        sha = item.get("sha")
        if isinstance(sha, str) and sha:
            shas.append(sha)
    if not shas:
        return None
    return f"{shas[0]}^..{shas[-1]}"


def commit_shas_from_entries(entries: Any) -> list[str]:
    """Extract ordered commit SHAs from timeline entries."""
    if not isinstance(entries, list):
        return []
    shas: list[str] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        sha = item.get("sha")
        if isinstance(sha, str) and sha:
            shas.append(sha)
    return shas


def replace_range_arg(cmd: list[str], new_range: str) -> list[str]:
    """Return command with --range argument value replaced."""
    updated = cmd[:]
    if "--range" not in updated:
        raise ValueError("Expected --range argument in command.")
    idx = updated.index("--range")
    if idx + 1 >= len(updated):
        raise ValueError("Expected value after --range.")
    updated[idx + 1] = new_range
    return updated


def pr_review_hit_context_limits(stdout: str, stderr: str) -> bool:
    """Detect fail-fast abort due oversized PR diff context."""
    haystack = f"{stdout}\n{stderr}".lower()
    return "diff context exceeds safe analysis limits" in haystack


def replace_range_with_diff_arg(cmd: list[str], diff_path: Path) -> list[str]:
    """Return command with --range replaced by --diff <patch>."""
    updated: list[str] = []
    found_range = False
    i = 0
    while i < len(cmd):
        arg = cmd[i]
        if arg == "--range":
            if i + 1 >= len(cmd):
                raise ValueError("Expected value after --range.")
            found_range = True
            i += 2
            continue
        updated.append(arg)
        i += 1
    if not found_range:
        raise ValueError("Expected --range argument in command.")
    updated.extend(["--diff", str(diff_path)])
    return updated


def list_changed_files_for_commit(repo: Path, sha: str) -> list[str]:
    """List changed files for one commit (sha^..sha)."""
    diff_range = f"{sha}^..{sha}"
    out = run_checked(["git", "diff", "--name-only", diff_range], cwd=repo)
    return [line.strip() for line in out.splitlines() if line.strip()]


def is_low_signal_split_path(path: str) -> bool:
    """Heuristic for files unlikely to add security signal in split PR-review."""
    lowered = path.lower()
    if lowered.startswith(LOW_SIGNAL_SPLIT_PATH_PREFIXES):
        return True
    if lowered.endswith(LOW_SIGNAL_SPLIT_SUFFIXES):
        return True
    if Path(lowered).name in LOW_SIGNAL_SPLIT_BASENAMES:
        return True
    return False


def filter_split_review_files(paths: list[str]) -> list[str]:
    """Prefer code/config paths for split-diff fallback; keep all as final fallback."""
    filtered = [path for path in paths if not is_low_signal_split_path(path)]
    return filtered if filtered else paths


def chunk_paths(paths: list[str], chunk_size: int) -> list[list[str]]:
    """Chunk path list into fixed-size groups."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be > 0")
    return [paths[i : i + chunk_size] for i in range(0, len(paths), chunk_size)]


def should_preemptively_split_commit(
    changed_paths: list[str],
    *,
    group_size: int = SPLIT_DIFF_GROUP_SIZE,
    threshold: int = PREEMPTIVE_SPLIT_FILE_THRESHOLD,
) -> bool:
    """Return True when commit should be split into focused diff groups."""
    review_paths = filter_split_review_files(changed_paths)
    return len(review_paths) >= max(group_size + 1, threshold)


def run_commit_split_diff_reviews(
    *,
    work_repo: Path,
    base_cmd: list[str],
    env: dict[str, str],
    repo_report_path: Path,
    run_dir: Path,
    sha: str,
    review_paths: list[str] | None = None,
    group_size: int = SPLIT_DIFF_GROUP_SIZE,
) -> tuple[list[Path], bool]:
    """Run PR-review using per-file-group diffs for one oversized commit."""
    commit_range = f"{sha}^..{sha}"
    effective_paths = (
        filter_split_review_files(review_paths)
        if review_paths is not None
        else filter_split_review_files(list_changed_files_for_commit(work_repo, sha))
    )
    short = sha[:12]
    reports: list[Path] = []
    rate_limited = False

    for index, group in enumerate(chunk_paths(effective_paths, group_size), start=1):
        patch_path = run_dir / f"intro_pr_review.commit_{short}.part_{index:02d}.patch"
        patch = run_checked(["git", "diff", commit_range, "--", *group], cwd=work_repo)
        if not patch.strip():
            continue
        patch_path.write_text(patch, encoding="utf-8")

        diff_cmd = replace_range_with_diff_arg(base_cmd, patch_path)
        if repo_report_path.exists():
            repo_report_path.unlink()
        code, out, err = run(diff_cmd, env=env)
        rate_limited = rate_limited or command_hit_rate_limit(out, err)

        log_path = run_dir / f"intro_pr_review.commit_{short}.part_{index:02d}.log.json"
        report_path = run_dir / f"intro_pr_review.commit_{short}.part_{index:02d}.json"
        persist_command_log(log_path, diff_cmd, code, out, err)
        copy_report_if_present(repo_report_path, report_path)
        if report_indicates_success(report_path):
            reports.append(report_path)

    return reports, rate_limited


def merge_pr_review_reports(report_paths: list[Path], output_path: Path) -> None:
    """Merge multiple PR-review reports into one report with deduped issues."""
    combined_issues: list[dict[str, Any]] = []
    seen: set[str] = set()
    for report_path in report_paths:
        payload = load_json(report_path)
        issues = payload.get("issues") if isinstance(payload, dict) else None
        if not isinstance(issues, list):
            continue
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            key = json.dumps(issue, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            combined_issues.append(issue)

    merged_payload = {
        "issues": combined_issues,
        "meta": {
            "merge_strategy": "per-introducing-commit",
            "source_reports": [str(path.resolve()) for path in report_paths],
        },
    }
    output_path.write_text(
        json.dumps(merged_payload, indent=2) + "\n", encoding="utf-8"
    )


def baseline_cache_is_usable(cache_entry: Path) -> bool:
    """Return True when a baseline cache entry contains required files."""
    if not cache_entry.exists():
        return False
    if not (cache_entry / "baseline_scan.json").exists():
        return False
    for artifact in BASELINE_ARTIFACTS:
        if not (cache_entry / artifact).exists():
            return False
    return True


def restore_baseline_cache(cache_entry: Path, work_repo: Path, run_dir: Path) -> None:
    """Restore cached baseline artifacts into work repo and run artifact folder."""
    securevibes_dir = work_repo / ".securevibes"
    securevibes_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy2(cache_entry / "baseline_scan.json", run_dir / "baseline_scan.json")
    for artifact in BASELINE_ARTIFACTS:
        shutil.copy2(cache_entry / artifact, securevibes_dir / artifact)


def save_baseline_cache(
    cache_entry: Path,
    *,
    baseline_report: Path,
    work_repo: Path,
    meta: dict[str, Any],
) -> None:
    """Persist baseline artifacts/report into cache entry."""
    cache_entry.mkdir(parents=True, exist_ok=True)
    shutil.copy2(baseline_report, cache_entry / "baseline_scan.json")

    securevibes_dir = work_repo / ".securevibes"
    for artifact in BASELINE_ARTIFACTS:
        shutil.copy2(securevibes_dir / artifact, cache_entry / artifact)

    (_cache_meta_path(cache_entry)).write_text(
        json.dumps(meta, indent=2) + "\n",
        encoding="utf-8",
    )


def determine_run_status(
    *,
    baseline_only: bool,
    intro_only: bool,
    baseline_effective_success: bool,
    intro_effective_success: bool,
    fix_effective_success: bool,
) -> str:
    """Resolve detectability status for the selected run mode."""
    if baseline_only:
        return (
            "baseline_only_completed"
            if baseline_effective_success
            else "baseline_only_failed"
        )
    if intro_only:
        return (
            "intro_only_completed"
            if baseline_effective_success and intro_effective_success
            else "intro_only_failed"
        )
    return (
        "completed"
        if baseline_effective_success
        and intro_effective_success
        and fix_effective_success
        else "partial_or_failed"
    )


def build_dry_run_payload(
    *,
    ghsa: str,
    securevibes_repo: Path,
    securevibes_commit: str,
    openclaw_repo: Path,
    baseline: str,
    intro_range: str,
    fix_range: str,
    baseline_only: bool,
    intro_only: bool,
    baseline_cache_enabled: bool,
    refresh_baseline_cache: bool,
    baseline_cache_entry: Path | None,
    baseline_cmd: list[str],
    intro_threat_model_cmd: list[str],
    intro_cmd: list[str],
    fix_cmd: list[str],
) -> dict[str, Any]:
    """Build stable dry-run payload emitted by this script."""
    return {
        "ghsa": ghsa,
        "securevibes_repo": str(securevibes_repo),
        "securevibes_commit": securevibes_commit,
        "openclaw_repo": str(openclaw_repo),
        "baseline": baseline,
        "intro_range": intro_range,
        "fix_range": fix_range,
        "baseline_only": baseline_only,
        "intro_only": intro_only,
        "baseline_cache": {
            "enabled": baseline_cache_enabled,
            "refresh": refresh_baseline_cache,
            "entry": str(baseline_cache_entry) if baseline_cache_entry else None,
        },
        "commands": {
            "baseline_scan": baseline_cmd,
            "intro_threat_modeling": intro_threat_model_cmd,
            "intro_pr_review": intro_cmd,
            "fix_pr_review": fix_cmd,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser for benchmark case execution."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghsa", required=True)
    parser.add_argument("--openclaw-repo", type=Path, default=Path("../openclaw"))
    parser.add_argument("--model", default="sonnet")
    parser.add_argument(
        "--severity",
        default="medium",
        choices=["critical", "high", "medium", "low"],
    )
    parser.add_argument(
        "--securevibes-repo",
        type=Path,
        default=REPO_ROOT,
        help="SecureVibes source repository to execute",
    )
    parser.add_argument(
        "--securevibes-commit",
        default=None,
        help="Optional SecureVibes commit SHA to run (creates temporary worktree)",
    )
    parser.add_argument(
        "--python-executable",
        default="python3",
        help="Python executable used for `python -m securevibes.cli.main`",
    )
    parser.add_argument(
        "--permission-mode",
        default="bypassPermissions",
        choices=VALID_PERMISSION_MODES,
        help="Claude permission mode for benchmark automation",
    )
    parser.add_argument(
        "--baseline-cache-dir",
        type=Path,
        default=ROOT / "baseline-cache",
        help="Directory for cached baseline scans/artifacts",
    )
    parser.add_argument(
        "--no-baseline-cache",
        action="store_true",
        help="Disable baseline cache reads/writes for this run",
    )
    parser.add_argument(
        "--refresh-baseline-cache",
        action="store_true",
        help="Force rerun baseline scan and overwrite cache entry",
    )
    run_mode_group = parser.add_mutually_exclusive_group()
    run_mode_group.add_argument(
        "--baseline-only",
        action="store_true",
        help="Only run/prime baseline scan cache, skip PR-review scans",
    )
    run_mode_group.add_argument(
        "--intro-only",
        action="store_true",
        help="Run baseline + intro PR review only, skip fix PR review",
    )
    parser.add_argument(
        "--intro-threat-model-refresh",
        action="store_true",
        help=(
            "Before intro PR review, refresh THREAT_MODEL.json at intro head via "
            "`scan --subagent threat-modeling`."
        ),
    )
    parser.add_argument(
        "--pr-attempts",
        type=int,
        default=None,
        help="Optional override for `pr-review --pr-attempts`.",
    )
    parser.add_argument(
        "--pr-timeout",
        type=int,
        default=None,
        help="Optional override for `pr-review --pr-timeout` (seconds).",
    )
    parser.add_argument(
        "--isolate-runtime-home",
        action="store_true",
        help=(
            "Run SecureVibes subprocesses with an isolated HOME directory under "
            "the temporary run folder."
        ),
    )
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print resolved commands and exit without executing scans",
    )
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for benchmark case execution."""
    return build_parser().parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    case_dir = CASES_DIR / args.ghsa
    timeline = load_json(case_dir / "timeline.json")
    baseline = timeline["baseline_commit"]
    intro_head = timeline["vulnerable_head"]
    fix_head = timeline["fix_head"]

    runs_dir = case_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    intro_range = f"{baseline}..{intro_head}"
    fix_range = f"{intro_head}..{fix_head}"
    intro_commit_window = commit_window_from_entries(
        timeline.get("introducing_commits")
    )
    intro_commit_shas = commit_shas_from_entries(timeline.get("introducing_commits"))
    fix_commit_window = commit_window_from_entries(timeline.get("fix_commits"))
    if intro_commit_window:
        intro_range = intro_commit_window
    if fix_commit_window:
        fix_range = fix_commit_window

    baseline_cache_enabled = not args.no_baseline_cache
    baseline_cache_dir = args.baseline_cache_dir.resolve()
    baseline_cache_hit = False
    baseline_cache_saved = False
    baseline_cache_entry: Path | None = None
    baseline_cache_id: str | None = None
    baseline_cache_requested_id: str | None = None
    baseline_cache_requested_entry: Path | None = None
    baseline_cache_compat_fallback_used = False

    intro_exit: int | None = None
    fix_exit: int | None = None
    intro_tm_exit: int | None = None
    intro_tm_effective_success = False
    intro_effective_success = False
    fix_effective_success = False
    baseline_rate_limited = False
    intro_rate_limited = False
    fix_rate_limited = False

    with tempfile.TemporaryDirectory(prefix=f"securevibes-{args.ghsa}-") as tmp:
        tmp_path = Path(tmp)
        work_repo = tmp_path / "openclaw"
        runtime_home = tmp_path / "runtime-home" if args.isolate_runtime_home else None

        sv_ctx, sv_worktree = resolve_securevibes_context(
            securevibes_repo=args.securevibes_repo,
            securevibes_commit=args.securevibes_commit,
            temp_root=tmp_path,
        )

        baseline_cache_requested_id = baseline_cache_key(
            baseline_commit=baseline,
            securevibes_commit=sv_ctx.commit_sha,
            model=args.model,
            severity=args.severity,
        )
        baseline_cache_requested_entry = (
            baseline_cache_dir / baseline_cache_requested_id
        )
        baseline_cache_entry = baseline_cache_requested_entry
        if (
            baseline_cache_enabled
            and not args.refresh_baseline_cache
            and not baseline_cache_is_usable(baseline_cache_requested_entry)
        ):
            compatible_entry = find_compatible_baseline_cache_entry(
                cache_dir=baseline_cache_dir,
                baseline_commit=baseline,
                model=args.model,
                severity=args.severity,
            )
            if compatible_entry is not None:
                baseline_cache_entry = compatible_entry
                baseline_cache_compat_fallback_used = (
                    compatible_entry != baseline_cache_requested_entry
                )
        baseline_cache_id = (
            baseline_cache_entry.name if baseline_cache_entry is not None else None
        )

        baseline_cmd, baseline_env = securevibes_command(
            sv_ctx,
            args.python_executable,
            args.permission_mode,
            "scan",
            str(work_repo),
            "--model",
            args.model,
            "--severity",
            args.severity,
            "--format",
            "json",
            "--output",
            str(
                work_repo / ".securevibes" / "benchmark-reports" / "baseline_scan.json"
            ),
            "--force",
            runtime_home=runtime_home,
        )
        pr_budget_args: list[str] = []
        if args.pr_attempts is not None:
            pr_budget_args.extend(["--pr-attempts", str(args.pr_attempts)])
        if args.pr_timeout is not None:
            pr_budget_args.extend(["--pr-timeout", str(args.pr_timeout)])
        intro_cmd, intro_env = securevibes_command(
            sv_ctx,
            args.python_executable,
            args.permission_mode,
            "pr-review",
            str(work_repo),
            "--range",
            intro_range,
            "--model",
            args.model,
            "--severity",
            args.severity,
            "--format",
            "json",
            "--output",
            str(
                work_repo
                / ".securevibes"
                / "benchmark-reports"
                / "intro_pr_review.json"
            ),
            "--clean-pr-artifacts",
            *pr_budget_args,
            runtime_home=runtime_home,
        )
        intro_threat_model_cmd, intro_threat_model_env = securevibes_command(
            sv_ctx,
            args.python_executable,
            args.permission_mode,
            "scan",
            str(work_repo),
            "--subagent",
            "threat-modeling",
            "--model",
            args.model,
            "--severity",
            args.severity,
            "--force",
            runtime_home=runtime_home,
        )
        fix_cmd, fix_env = securevibes_command(
            sv_ctx,
            args.python_executable,
            args.permission_mode,
            "pr-review",
            str(work_repo),
            "--range",
            fix_range,
            "--model",
            args.model,
            "--severity",
            args.severity,
            "--format",
            "json",
            "--output",
            str(
                work_repo / ".securevibes" / "benchmark-reports" / "fix_pr_review.json"
            ),
            "--clean-pr-artifacts",
            *pr_budget_args,
            runtime_home=runtime_home,
        )

        if args.dry_run:
            dry = build_dry_run_payload(
                ghsa=args.ghsa,
                securevibes_repo=sv_ctx.repo_path,
                securevibes_commit=sv_ctx.commit_sha,
                openclaw_repo=args.openclaw_repo.resolve(),
                baseline=baseline,
                intro_range=intro_range,
                fix_range=fix_range,
                baseline_only=args.baseline_only,
                intro_only=args.intro_only,
                baseline_cache_enabled=baseline_cache_enabled,
                refresh_baseline_cache=args.refresh_baseline_cache,
                baseline_cache_entry=baseline_cache_entry,
                baseline_cmd=baseline_cmd,
                intro_threat_model_cmd=intro_threat_model_cmd,
                intro_cmd=intro_cmd,
                fix_cmd=fix_cmd,
            )
            (run_dir / "dry_run.json").write_text(
                json.dumps(dry, indent=2) + "\n", encoding="utf-8"
            )
            print(json.dumps(dry, indent=2))
            if sv_worktree is not None:
                run(
                    [
                        "git",
                        "-C",
                        str(args.securevibes_repo.resolve()),
                        "worktree",
                        "remove",
                        "--force",
                        str(sv_worktree),
                    ]
                )
            return

        clone_cmd = [
            "git",
            "clone",
            "--no-hardlinks",
            str(args.openclaw_repo.resolve()),
            str(work_repo),
        ]
        code, out, err = run(clone_cmd)
        persist_command_log(run_dir / "clone.log.json", clone_cmd, code, out, err)
        if code != 0:
            raise RuntimeError("git clone failed; see clone.log.json")

        repo_reports = work_repo / ".securevibes" / "benchmark-reports"
        repo_reports.mkdir(parents=True, exist_ok=True)
        baseline_repo_report = repo_reports / "baseline_scan.json"
        intro_repo_report = repo_reports / "intro_pr_review.json"
        fix_repo_report = repo_reports / "fix_pr_review.json"
        baseline_report = run_dir / "baseline_scan.json"
        intro_report = run_dir / "intro_pr_review.json"
        fix_report = run_dir / "fix_pr_review.json"

        run(["git", "checkout", baseline], cwd=work_repo)
        if (
            baseline_cache_enabled
            and not args.refresh_baseline_cache
            and baseline_cache_entry is not None
            and baseline_cache_is_usable(baseline_cache_entry)
        ):
            restore_baseline_cache(baseline_cache_entry, work_repo, run_dir)
            baseline_exit = 0
            baseline_cache_hit = True
            persist_command_log(
                run_dir / "baseline_scan.log.json",
                ["baseline-cache-hit", str(baseline_cache_entry)],
                0,
                f"Restored baseline artifacts from cache: {baseline_cache_entry}",
                "",
            )
        else:
            code, out, err = run(baseline_cmd, env=baseline_env)
            baseline_rate_limited = command_hit_rate_limit(out, err)
            persist_command_log(
                run_dir / "baseline_scan.log.json", baseline_cmd, code, out, err
            )
            copy_report_if_present(baseline_repo_report, baseline_report)
            baseline_exit = code

        artifact_validation = validate_baseline_artifacts(work_repo)
        baseline_effective_success = baseline_cache_hit or (
            report_indicates_success(baseline_report) and artifact_validation["valid"]
        )
        if (
            baseline_effective_success
            and baseline_cache_enabled
            and baseline_cache_requested_entry is not None
            and baseline_report.exists()
            and not baseline_cache_hit
        ):
            meta = {
                "baseline_commit": baseline,
                "securevibes_commit": sv_ctx.commit_sha,
                "model": args.model,
                "severity": args.severity,
                "permission_mode": args.permission_mode,
                "created_at": datetime.now(timezone.utc)
                .isoformat()
                .replace("+00:00", "Z"),
                "source_ghsa": args.ghsa,
            }
            save_baseline_cache(
                baseline_cache_requested_entry,
                baseline_report=baseline_report,
                work_repo=work_repo,
                meta=meta,
            )
            baseline_cache_saved = True

        if args.baseline_only:
            persist_command_log(
                run_dir / "intro_pr_review.log.json",
                ["baseline-only-skip"],
                0,
                "Skipped intro PR review because --baseline-only was set.",
                "",
            )
            persist_command_log(
                run_dir / "fix_pr_review.log.json",
                ["baseline-only-skip"],
                0,
                "Skipped fix PR review because --baseline-only was set.",
                "",
            )
        else:
            run(["git", "checkout", intro_head], cwd=work_repo)
            if args.intro_threat_model_refresh:
                code, out, err = run(
                    intro_threat_model_cmd,
                    env=intro_threat_model_env,
                )
                persist_command_log(
                    run_dir / "intro_threat_modeling.log.json",
                    intro_threat_model_cmd,
                    code,
                    out,
                    err,
                )
                intro_tm_exit = code
                intro_tm_effective_success = code == 0
            if intro_repo_report.exists():
                intro_repo_report.unlink()
            code, out, err = run(intro_cmd, env=intro_env)
            intro_rate_limited = command_hit_rate_limit(out, err)
            persist_command_log(
                run_dir / "intro_pr_review.log.json", intro_cmd, code, out, err
            )
            copy_report_if_present(intro_repo_report, intro_report)
            intro_exit = code
            intro_effective_success = report_indicates_success(intro_report)
            if (
                not intro_effective_success
                and pr_review_hit_context_limits(out, err)
                and intro_commit_shas
            ):
                intro_attempt_reports: list[Path] = []
                intro_attempt_ranges: list[str] = []
                for sha in intro_commit_shas:
                    commit_range = f"{sha}^..{sha}"
                    commit_cmd = replace_range_arg(intro_cmd, commit_range)
                    commit_paths = list_changed_files_for_commit(work_repo, sha)
                    if should_preemptively_split_commit(commit_paths):
                        split_reports, split_rate_limited = (
                            run_commit_split_diff_reviews(
                                work_repo=work_repo,
                                base_cmd=intro_cmd,
                                env=intro_env,
                                repo_report_path=intro_repo_report,
                                run_dir=run_dir,
                                sha=sha,
                                review_paths=commit_paths,
                            )
                        )
                        intro_rate_limited = intro_rate_limited or split_rate_limited
                        short = sha[:12]
                        commit_report = run_dir / f"intro_pr_review.commit_{short}.json"
                        if split_reports:
                            merge_pr_review_reports(split_reports, commit_report)
                            intro_attempt_reports.append(commit_report)
                            intro_attempt_ranges.append(commit_range)
                            continue
                    if intro_repo_report.exists():
                        intro_repo_report.unlink()
                    code, out, err = run(commit_cmd, env=intro_env)
                    intro_rate_limited = intro_rate_limited or command_hit_rate_limit(
                        out, err
                    )
                    short = sha[:12]
                    commit_log = run_dir / f"intro_pr_review.commit_{short}.log.json"
                    commit_report = run_dir / f"intro_pr_review.commit_{short}.json"
                    persist_command_log(commit_log, commit_cmd, code, out, err)
                    copy_report_if_present(intro_repo_report, commit_report)
                    if report_indicates_success(commit_report):
                        intro_attempt_reports.append(commit_report)
                    elif pr_review_hit_context_limits(out, err):
                        split_reports, split_rate_limited = (
                            run_commit_split_diff_reviews(
                                work_repo=work_repo,
                                base_cmd=intro_cmd,
                                env=intro_env,
                                repo_report_path=intro_repo_report,
                                run_dir=run_dir,
                                sha=sha,
                            )
                        )
                        intro_rate_limited = intro_rate_limited or split_rate_limited
                        intro_attempt_reports.extend(split_reports)
                    intro_attempt_ranges.append(commit_range)

                if intro_attempt_reports:
                    merge_pr_review_reports(intro_attempt_reports, intro_report)
                    intro_effective_success = True
                    intro_exit = 0
                    intro_range = ",".join(intro_attempt_ranges)
                else:
                    intro_exit = 1

            if args.intro_only:
                persist_command_log(
                    run_dir / "fix_pr_review.log.json",
                    ["intro-only-skip"],
                    0,
                    "Skipped fix PR review because --intro-only was set.",
                    "",
                )
            else:
                run(["git", "checkout", fix_head], cwd=work_repo)
                if fix_repo_report.exists():
                    fix_repo_report.unlink()
                code, out, err = run(fix_cmd, env=fix_env)
                fix_rate_limited = command_hit_rate_limit(out, err)
                persist_command_log(
                    run_dir / "fix_pr_review.log.json", fix_cmd, code, out, err
                )
                copy_report_if_present(fix_repo_report, fix_report)
                fix_exit = code
                fix_effective_success = report_indicates_success(fix_report)

        if args.keep_temp:
            preserved = run_dir / "work_repo"
            if preserved.exists():
                shutil.rmtree(preserved)
            try:
                shutil.copytree(work_repo, preserved)
            except (FileNotFoundError, shutil.Error) as exc:
                warning = (
                    "Could not fully preserve temporary work repository.\n"
                    f"Reason: {exc}\n"
                )
                (run_dir / "keep_temp.warning.txt").write_text(
                    warning,
                    encoding="utf-8",
                )

        if sv_worktree is not None:
            run(
                [
                    "git",
                    "-C",
                    str(args.securevibes_repo.resolve()),
                    "worktree",
                    "remove",
                    "--force",
                    str(sv_worktree),
                ]
            )

    baseline_summary = summarize_issues(run_dir / "baseline_scan.json")
    intro_summary = summarize_issues(run_dir / "intro_pr_review.json")
    fix_summary = summarize_issues(run_dir / "fix_pr_review.json")
    baseline_effective_success = baseline_cache_hit or (
        report_indicates_success(run_dir / "baseline_scan.json")
        and artifact_validation["valid"]
    )
    if intro_exit is not None and not intro_effective_success:
        intro_effective_success = report_indicates_success(
            run_dir / "intro_pr_review.json"
        )
    if fix_exit is not None and not fix_effective_success:
        fix_effective_success = report_indicates_success(run_dir / "fix_pr_review.json")

    status = determine_run_status(
        baseline_only=args.baseline_only,
        intro_only=args.intro_only,
        baseline_effective_success=baseline_effective_success,
        intro_effective_success=intro_effective_success,
        fix_effective_success=fix_effective_success,
    )

    detectability = {
        "id": args.ghsa,
        "status": status,
        "model": args.model,
        "severity_filter": args.severity,
        "run_id": run_id,
        "securevibes_repo": str(args.securevibes_repo.resolve()),
        "securevibes_commit": sv_ctx.commit_sha,
        "baseline_cache": {
            "enabled": baseline_cache_enabled,
            "refresh_requested": bool(args.refresh_baseline_cache),
            "requested_entry_key": baseline_cache_requested_id,
            "requested_entry_path": (
                str(baseline_cache_requested_entry)
                if baseline_cache_requested_entry
                else None
            ),
            "resolved_entry_key": baseline_cache_id,
            "resolved_entry_path": (
                str(baseline_cache_entry) if baseline_cache_entry else None
            ),
            "compatible_fallback_used": baseline_cache_compat_fallback_used,
            "hit": baseline_cache_hit,
            "saved": baseline_cache_saved,
        },
        "baseline_scan": {
            "command_exit": baseline_exit,
            "effective_success": baseline_effective_success,
            "rate_limited": baseline_rate_limited,
            "report": str((run_dir / "baseline_scan.json").resolve()),
            "summary": baseline_summary,
            "artifact_validation": artifact_validation,
            "used_cache": baseline_cache_hit,
        },
        "intro_pr_review": {
            "command_exit": intro_exit,
            "effective_success": (
                intro_effective_success if intro_exit is not None else None
            ),
            "rate_limited": intro_rate_limited if intro_exit is not None else None,
            "range": intro_range,
            "report": str((run_dir / "intro_pr_review.json").resolve()),
            "summary": intro_summary,
        },
        "intro_threat_modeling": {
            "command_exit": intro_tm_exit,
            "effective_success": (
                intro_tm_effective_success if intro_tm_exit is not None else None
            ),
            "log": str((run_dir / "intro_threat_modeling.log.json").resolve()),
        },
        "fix_pr_review": {
            "command_exit": fix_exit,
            "effective_success": (
                fix_effective_success if fix_exit is not None else None
            ),
            "rate_limited": fix_rate_limited if fix_exit is not None else None,
            "range": fix_range,
            "report": str((run_dir / "fix_pr_review.json").resolve()),
            "summary": fix_summary,
        },
        "tier1_detected_from_new_commits": (
            (intro_summary.get("issue_count") or 0) > 0
            if intro_effective_success and intro_summary["exists"]
            else None
        ),
        "tier2_root_cause_match": None,
        "tier2_match_basis": None,
        "tier2_notes": None,
        "could_propose_fix": None,
        "post_fix_regression_status": None,
        "notes": "Tier-2 adjudication is manual: compare intro_pr_review findings against cases/<GHSA>/analysis.md root cause.",
    }

    (case_dir / "detectability.json").write_text(
        json.dumps(detectability, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(detectability, indent=2))


if __name__ == "__main__":
    main()
