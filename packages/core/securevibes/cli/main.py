"""Main CLI entry point for SecureVibes"""

import asyncio
import ipaddress
import json
import subprocess
import sys
from datetime import datetime, time
from pathlib import Path
from typing import Optional
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request
from zoneinfo import ZoneInfo

import click
from rich.console import Console
from rich.table import Table
from rich import box

from securevibes import __version__
from securevibes.models.issue import SEVERITY_RANK, Severity
from securevibes.scanner.scanner import Scanner
from securevibes.diff.extractor import (
    validate_git_ref,
    get_commits_after,
    get_commits_between,
    get_commits_for_range,
    get_commits_since,
    get_diff_from_commit_list,
    get_diff_from_commits,
    get_diff_from_file,
    get_diff_from_git_range,
    get_last_n_commits,
)
from securevibes.diff.parser import DiffContext, parse_unified_diff
from securevibes.scanner.state import (
    build_pr_review_entry,
    get_last_full_scan_commit,
    get_repo_branch,
    get_repo_head_commit,
    load_scan_state,
    scan_state_branch_matches,
    update_scan_state,
    utc_timestamp,
)

console = Console()

SAFE_NON_PRODUCTION_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "::1")
SAFE_NON_PRODUCTION_SUFFIXES = (".local", ".test", ".localhost")
TRANSIENT_PR_ARTIFACTS = (
    "PR_VULNERABILITIES.json",
    "DIFF_CONTEXT.json",
    "pr_review_report.md",
)
REQUIRED_REPORT_FIELDS = ("repository_path", "files_scanned", "scan_time_seconds", "issues")
REQUIRED_REPORT_ISSUE_FIELDS = ("severity", "title", "description", "file_path", "line_number")


def _filter_by_severity(result, min_severity: Optional[str]) -> None:
    """Filter scan issues to only include findings at/above minimum severity."""
    if not min_severity:
        return

    threshold = Severity(min_severity)
    min_rank = SEVERITY_RANK[threshold.value]
    result.issues = [
        issue for issue in result.issues if SEVERITY_RANK.get(issue.severity.value, 0) >= min_rank
    ]


def _resolve_markdown_output_path(
    repo_path: Path, output: Optional[str], default_filename: str
) -> Path:
    """Resolve markdown output to absolute path, defaulting to .securevibes."""
    if output:
        output_path = Path(output)
        if output_path.is_absolute():
            return output_path
        return repo_path / ".securevibes" / output
    return repo_path / ".securevibes" / default_filename


def _write_output(
    result,
    output_format: str,
    output: Optional[str],
    repo_path: Path,
    markdown_default_filename: str,
    markdown_label: str,
    quiet: bool = False,
) -> None:
    """Render or persist CLI output in the selected format."""
    if output_format == "markdown":
        from securevibes.reporters.markdown_reporter import MarkdownReporter

        output_path = _resolve_markdown_output_path(repo_path, output, markdown_default_filename)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            MarkdownReporter.save(result, output_path)
            if output:
                console.print(f"\n✅ {markdown_label} saved to: {output_path}")
            else:
                console.print(f"\n📄 {markdown_label}: [cyan]{output_path}[/cyan]")
        except (IOError, OSError, PermissionError) as exc:
            console.print(f"[bold red]❌ Error writing output file:[/bold red] {exc}")
            sys.exit(1)
        return

    if output_format == "json":
        output_data = result.to_dict()
        if output:
            try:
                output_path = Path(output)
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_text(json.dumps(output_data, indent=2), encoding="utf-8")
                console.print(f"\n✅ Results saved to: {output_path}")
            except (IOError, OSError, PermissionError) as exc:
                console.print(f"[bold red]❌ Error writing output file:[/bold red] {exc}")
                sys.exit(1)
        else:
            console.print_json(data=output_data)
        return

    if output_format == "table":
        _display_table_results(result, quiet=quiet)
        return

    _display_text_results(result)


def _validate_target_url(target_url: str) -> bool:
    """Validate target URL format for DAST execution."""
    parsed = urllib_parse.urlparse(target_url.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.hostname)


@click.group()
@click.version_option(version=__version__, prog_name="securevibes")
def cli():
    """
    🛡️ SecureVibes - AI-Native Platform to Secure Vibecoded Applications

    Detect security vulnerabilities in your code using Claude AI.
    """
    pass


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--model", "-m", default="sonnet", help="Claude model to use (e.g., sonnet, haiku)")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["markdown", "json", "text", "table"]),
    default="markdown",
    help="Output format (default: markdown)",
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    help="Minimum severity to report",
)
@click.option("--quiet", "-q", is_flag=True, help="Minimal output (errors only)")
@click.option("--debug", is_flag=True, help="Show verbose diagnostic output")
@click.option("--dast", is_flag=True, help="Enable DAST validation in full scan")
@click.option(
    "--target-url", type=str, help="Target URL for DAST testing (e.g., http://localhost:3000)"
)
@click.option(
    "--dast-timeout",
    type=int,
    default=120,
    help="DAST validation timeout in seconds (default: 120)",
)
@click.option(
    "--dast-accounts", type=click.Path(exists=True), help="Path to test accounts JSON file"
)
@click.option(
    "--allow-production",
    is_flag=True,
    help="Allow DAST testing on production URLs (use with caution!)",
)
@click.option(
    "--subagent",
    type=click.Choice(["assessment", "threat-modeling", "code-review", "report-generator", "dast"]),
    help="Run specific sub-agent only (mutually exclusive with --dast and --resume-from)",
)
@click.option(
    "--resume-from",
    type=click.Choice(["assessment", "threat-modeling", "code-review", "report-generator", "dast"]),
    help="Resume scan from specific sub-agent onwards",
)
@click.option(
    "--force", is_flag=True, help="Skip confirmation prompts, overwrite existing artifacts"
)
@click.option("--skip-checks", is_flag=True, help="Bypass artifact validation checks")
@click.option(
    "--agentic",
    is_flag=True,
    help="Force agentic classification (require ASI threats in threat model)",
)
@click.option(
    "--no-agentic",
    "no_agentic",
    is_flag=True,
    help="Force non-agentic classification (ASI optional)",
)
def scan(
    path: str,
    model: str,
    output: Optional[str],
    output_format: str,
    severity: Optional[str],
    quiet: bool,
    debug: bool,
    dast: bool,
    target_url: Optional[str],
    dast_timeout: int,
    dast_accounts: Optional[str],
    allow_production: bool,
    subagent: Optional[str],
    resume_from: Optional[str],
    force: bool,
    skip_checks: bool,
    agentic: bool,
    no_agentic: bool,
):
    """
    Scan a repository for security vulnerabilities.

    Examples:

        securevibes scan .  # Creates .securevibes/scan_report.md (default)

        securevibes scan /path/to/project --severity high

        securevibes scan . --format json --output results.json

        securevibes scan . --format markdown --output custom_report.md  # Saves to .securevibes/custom_report.md

        securevibes scan . --format table  # Terminal table (no file saved)

        securevibes scan . --model claude-3-5-haiku-20241022  # Use faster/cheaper model
    """
    try:
        # Validate flag conflicts
        if quiet and debug:
            console.print(
                "[yellow]⚠️  Warning: --quiet and --debug are contradictory. Using --debug.[/yellow]"
            )
            quiet = False  # Debug takes precedence

        # Validate mutually exclusive flags
        if subagent and resume_from:
            console.print(
                "[bold red]❌ Error:[/bold red] --subagent and --resume-from are mutually exclusive"
            )
            sys.exit(1)

        if agentic and no_agentic:
            console.print(
                "[bold red]❌ Error:[/bold red] --agentic and --no-agentic are mutually exclusive"
            )
            sys.exit(1)

        if subagent and dast:
            console.print(
                "[bold red]❌ Error:[/bold red] --subagent and --dast are mutually exclusive"
            )
            console.print("\n[dim]Use either:[/dim]")
            console.print("  --subagent dast --target-url URL      (run DAST sub-agent only)")
            console.print("  --dast --target-url URL               (full scan with DAST)")
            sys.exit(1)

        # Auto-enable DAST for dast sub-agent
        if subagent == "dast":
            dast = True
            if not target_url:
                console.print(
                    "[bold red]❌ Error:[/bold red] --target-url is required for DAST sub-agent"
                )
                console.print(
                    "[dim]Example: securevibes scan . --subagent dast --target-url http://localhost:3000[/dim]"
                )
                sys.exit(1)

        # Validate target-url requirement for resume-from dast
        if resume_from == "dast":
            if not target_url:
                console.print(
                    "[bold red]❌ Error:[/bold red] --target-url is required when resuming from DAST"
                )
                sys.exit(1)
            dast = True

        # Show banner unless quiet
        if not quiet:
            console.print("[bold cyan]🛡️ SecureVibes Security Scanner[/bold cyan]")
            console.print("[dim]AI-Powered Vulnerability Detection[/dim]")
            console.print()

        output_dir = Path(path) / ".securevibes"
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except (IOError, OSError) as e:
            console.print(f"[bold red]❌ Error:[/bold red] Cannot create output directory: {e}")
            sys.exit(1)

        # DAST validation checks
        if dast:
            if not target_url:
                console.print(
                    "[bold red]❌ Error:[/bold red] --target-url is required when --dast is enabled"
                )
                console.print(
                    "[dim]Example: securevibes scan . --dast --target-url http://localhost:3000[/dim]"
                )
                sys.exit(1)

            if not _validate_target_url(target_url):
                console.print(
                    "[bold red]❌ Error:[/bold red] --target-url must be a valid HTTP/HTTPS URL"
                )
                console.print(
                    "[dim]Example: securevibes scan . --dast --target-url http://localhost:3000[/dim]"
                )
                sys.exit(1)

            # Safety gate: production URL detection
            if _is_production_url(target_url) and not allow_production:
                console.print(f"[bold red]⚠️  PRODUCTION URL DETECTED:[/bold red] {target_url}")
                console.print("\n[yellow]DAST testing sends real HTTP requests to the target.")
                console.print(
                    "Testing production systems requires explicit authorization.[/yellow]"
                )
                console.print(
                    "\n[dim]To proceed, add --allow-production flag (ensure you have authorization!)[/dim]"
                )
                sys.exit(1)

            # Safety gate: explicit confirmation
            if not allow_production and not quiet:
                console.print("\n[bold yellow]⚠️  DAST Validation Enabled[/bold yellow]")
                console.print(f"Target: {target_url}")
                console.print("\nDAST will send HTTP requests to validate IDOR vulnerabilities.")
                console.print("Ensure you have authorization to test this target.\n")

                if not click.confirm("Proceed with DAST validation?", default=False):
                    console.print(
                        "[yellow]DAST validation cancelled. Running SAST-only scan...[/yellow]"
                    )
                    dast = False

        # Run scan (full/single sub-agent/resume mode)
        agentic_override = True if agentic else False if no_agentic else None
        result = asyncio.run(
            _run_scan(
                path,
                model,
                True,
                quiet,
                debug,
                dast,
                target_url,
                dast_timeout,
                dast_accounts,
                subagent,
                resume_from,
                force,
                skip_checks,
                agentic_override,
            )
        )

        _filter_by_severity(result, severity)
        _write_output(
            result=result,
            output_format=output_format,
            output=output,
            repo_path=Path(path),
            markdown_default_filename="scan_report.md",
            markdown_label="Markdown report",
            quiet=quiet,
        )

        # Exit code based on findings
        if result.critical_count > 0:
            sys.exit(2)  # Critical issues found
        elif result.high_count > 0:
            sys.exit(1)  # High severity issues found
        else:
            sys.exit(0)  # Success

    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}", style="red")
        if not quiet:
            console.print("\n[dim]Run with --help for usage information[/dim]")
        sys.exit(1)


@cli.command("pr-review")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--base", help="Base branch/commit (e.g., main)")
@click.option("--head", help="Head branch/commit (e.g., feature-branch)")
@click.option("--range", "commit_range", help="Commit range (e.g., abc123~1..abc123)")
@click.option("--diff", "diff_file", type=click.Path(exists=True), help="Path to diff/patch file")
@click.option("--since-last-scan", is_flag=True, help="Review commits since last full scan")
@click.option("--since", "since_date", help="Review commits since date (YYYY-MM-DD, Pacific)")
@click.option("--last", "last_commits", type=click.IntRange(min=1), help="Review last N commits")
@click.option(
    "--update-artifacts",
    is_flag=True,
    help="Update THREAT_MODEL.json and VULNERABILITIES.json from PR findings",
)
@click.option(
    "--clean-pr-artifacts",
    is_flag=True,
    help="Delete transient PR review artifacts before running",
)
@click.option("--model", "-m", default="sonnet", help="Claude model to use (e.g., sonnet, haiku)")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["markdown", "json", "text", "table"]),
    default="markdown",
    help="Output format (default: markdown)",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--debug", is_flag=True, help="Show verbose diagnostic output")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="medium",
    help="Minimum severity to report",
)
def pr_review(
    path: str,
    base: Optional[str],
    head: Optional[str],
    commit_range: Optional[str],
    diff_file: Optional[str],
    since_last_scan: bool,
    since_date: Optional[str],
    last_commits: Optional[int],
    update_artifacts: bool,
    clean_pr_artifacts: bool,
    model: str,
    output_format: str,
    output: Optional[str],
    debug: bool,
    severity: str,
):
    """
    Review a PR diff for security vulnerabilities.

    Examples:

        securevibes pr-review . --base main --head feature-branch

        securevibes pr-review . --range abc123~1..abc123

        securevibes pr-review . --diff changes.patch
    """
    try:
        repo = Path(path).resolve()
        securevibes_dir = repo / ".securevibes"

        if (base or head) and not (base and head):
            console.print("[bold red]❌ Must specify both --base and --head[/bold red]")
            sys.exit(1)

        selection_count = sum(
            [
                bool(diff_file),
                bool(commit_range),
                bool(base and head),
                bool(since_last_scan),
                bool(since_date),
                bool(last_commits is not None),
            ]
        )
        if selection_count != 1:
            console.print(
                "[bold red]❌ Choose exactly one of --base/--head, --range, --diff, "
                "--since-last-scan, --since, or --last[/bold red]"
            )
            sys.exit(1)

        if since_last_scan:
            _ensure_baseline_scan(repo, model, debug)

        required_artifacts = ["SECURITY.md", "THREAT_MODEL.json"]
        missing = [a for a in required_artifacts if not (securevibes_dir / a).exists()]
        if missing:
            console.print(f"[bold red]❌ Missing required artifacts:[/bold red] {missing}")
            console.print("Run 'securevibes scan' first to generate base artifacts.")
            sys.exit(1)

        if clean_pr_artifacts:
            removed_artifacts = _clean_pr_artifacts(securevibes_dir)
            if removed_artifacts:
                removed_list = ", ".join(path.name for path in removed_artifacts)
                console.print(f"[dim]Removed transient PR artifacts: {removed_list}[/dim]")

        commits_reviewed: list[str] = []
        if diff_file:
            diff_content = get_diff_from_file(Path(diff_file))
        elif commit_range:
            diff_content = get_diff_from_commits(repo, commit_range)
            commits_reviewed = get_commits_for_range(repo, commit_range)
        elif base and head:
            diff_content = get_diff_from_git_range(repo, base, head)
            commits_reviewed = get_commits_between(repo, base, head)
        elif since_last_scan:
            state = load_scan_state(securevibes_dir / "scan_state.json") or {}
            base_commit = get_last_full_scan_commit(state)
            if not base_commit:
                console.print(
                    "[bold red]❌ Missing last_full_scan commit in scan_state.json[/bold red]"
                )
                sys.exit(1)
            commits_reviewed = get_commits_after(repo, base_commit)
            if not commits_reviewed:
                console.print("[yellow]No commits since last scan.[/yellow]")
                sys.exit(0)
            diff_content = get_diff_from_commit_list(repo, commits_reviewed)
        elif since_date:
            since_str = _parse_since_date_pacific(since_date)
            commits_reviewed = get_commits_since(repo, since_str)
            if not commits_reviewed:
                console.print(f"[yellow]No commits since {since_date}.[/yellow]")
                sys.exit(0)
            diff_content = get_diff_from_commit_list(repo, commits_reviewed)
        elif last_commits is not None:
            commits_reviewed = get_last_n_commits(repo, last_commits)
            if not commits_reviewed:
                console.print("[yellow]No commits found for the requested range.[/yellow]")
                sys.exit(0)
            diff_content = get_diff_from_commit_list(repo, commits_reviewed)
        else:
            console.print(
                "[bold red]❌ Must specify --base/--head, --range, --diff, "
                "--since-last-scan, --since, or --last[/bold red]"
            )
            sys.exit(1)

        if not diff_content.strip():
            console.print("[yellow]No changes found in diff.[/yellow]")
            sys.exit(0)

        diff_context = parse_unified_diff(diff_content)
        if not diff_context.changed_files:
            console.print("[yellow]No changed files found in diff.[/yellow]")
            sys.exit(0)

        known_vulns_path = securevibes_dir / "VULNERABILITIES.json"
        known_vulns = known_vulns_path if known_vulns_path.exists() else None

        result = asyncio.run(
            _run_pr_review(
                repo,
                model,
                debug,
                diff_context,
                known_vulns,
                severity,
                update_artifacts,
            )
        )

        _filter_by_severity(result, severity)
        _write_output(
            result=result,
            output_format=output_format,
            output=output,
            repo_path=repo,
            markdown_default_filename="pr_review_report.md",
            markdown_label="PR review report",
            quiet=False,
        )

        head_commit = get_repo_head_commit(repo)
        if head_commit:
            update_scan_state(
                securevibes_dir / "scan_state.json",
                pr_review=build_pr_review_entry(
                    commit=head_commit,
                    commits_reviewed=commits_reviewed,
                    timestamp=utc_timestamp(),
                ),
            )

        if result.critical_count > 0:
            sys.exit(2)
        if result.high_count > 0:
            sys.exit(1)
        sys.exit(0)

    except Exception as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}", style="red")
        console.print("\n[dim]Run with --help for usage information[/dim]")
        sys.exit(1)


@cli.command("catchup")
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option("--branch", default="main", help="Branch to pull before reviewing")
@click.option("--model", "-m", default="sonnet", help="Claude model to use (e.g., sonnet, haiku)")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["markdown", "json", "text", "table"]),
    default="markdown",
    help="Output format (default: markdown)",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--debug", is_flag=True, help="Show verbose diagnostic output")
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="medium",
    help="Minimum severity to report",
)
@click.option(
    "--update-artifacts",
    is_flag=True,
    help="Update THREAT_MODEL.json and VULNERABILITIES.json from PR findings",
)
def catchup(
    path: str,
    branch: str,
    model: str,
    output_format: str,
    output: Optional[str],
    debug: bool,
    severity: str,
    update_artifacts: bool,
):
    """
    Pull latest changes and review commits since the last full scan.

    Example:

        securevibes catchup . --branch main
    """
    try:
        repo = Path(path).resolve()
        current_branch = get_repo_branch(repo)
        if current_branch and current_branch != branch:
            console.print(
                f"[bold red]❌ Current branch is {current_branch}. "
                f"Please checkout {branch} before running catchup.[/bold red]"
            )
            sys.exit(1)

        if _repo_has_local_changes(repo):
            console.print(
                "[bold red]❌ Working tree is not clean. "
                "Commit, stash, or discard local changes before running catchup.[/bold red]"
            )
            sys.exit(1)

        try:
            _git_pull(repo, branch)
        except (RuntimeError, ValueError) as e:
            console.print(f"[bold red]❌ git pull failed:[/bold red] {e}")
            sys.exit(1)

        pr_review(
            path=path,
            base=None,
            head=None,
            commit_range=None,
            diff_file=None,
            since_last_scan=True,
            since_date=None,
            last_commits=None,
            update_artifacts=update_artifacts,
            clean_pr_artifacts=False,
            model=model,
            output_format=output_format,
            output=output,
            debug=debug,
            severity=severity,
        )
    except Exception as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}", style="red")
        console.print("\n[dim]Run with --help for usage information[/dim]")
        sys.exit(1)


def _is_production_url(url: str) -> bool:
    """Heuristically detect production URLs for DAST safety checks.

    This is a best-effort heuristic, not strict URL classification.
    """
    parsed = urllib_parse.urlparse(url.lower().strip())
    hostname = parsed.hostname
    if not hostname:
        return True

    if hostname in SAFE_NON_PRODUCTION_HOSTS or hostname.endswith(SAFE_NON_PRODUCTION_SUFFIXES):
        return False

    try:
        ip = ipaddress.ip_address(hostname)
        return not ip.is_loopback
    except ValueError:
        return True


def _clean_pr_artifacts(securevibes_dir: Path) -> list[Path]:
    """Delete transient PR review artifacts that can taint reruns."""
    removed: list[Path] = []
    for file_name in TRANSIENT_PR_ARTIFACTS:
        candidate = securevibes_dir / file_name
        if not candidate.exists() or not candidate.is_file():
            continue
        try:
            candidate.unlink()
        except OSError as exc:
            raise RuntimeError(f"Failed to remove transient artifact {candidate}: {exc}") from exc
        removed.append(candidate)
    return removed


def _parse_since_date_pacific(date_str: str) -> str:
    """Parse a YYYY-MM-DD date as Pacific midnight and return an ISO string."""
    try:
        parsed_date = datetime.strptime(date_str, "%Y-%m-%d").date()
    except ValueError as exc:
        raise click.BadParameter("Date must be in YYYY-MM-DD format") from exc

    pacific = ZoneInfo("America/Los_Angeles")
    since_dt = datetime.combine(parsed_date, time.min, tzinfo=pacific)
    return since_dt.strftime("%Y-%m-%dT%H:%M:%S%z")


def _ensure_baseline_scan(repo: Path, model: str, debug: bool) -> None:
    state_path = repo / ".securevibes" / "scan_state.json"
    state = load_scan_state(state_path)
    branch = get_repo_branch(repo)

    if state and branch and scan_state_branch_matches(state, branch):
        return

    console.print(
        "[yellow]⚠️  No baseline scan found for this branch.[/yellow]",
    )

    if not sys.stdin.isatty():
        console.print("Run 'securevibes scan .' to generate base artifacts.")
        sys.exit(1)

    if not click.confirm(
        "No baseline scan found for this branch. Run a baseline full scan now?",
        default=False,
    ):
        console.print("Run 'securevibes scan .' to generate base artifacts.")
        sys.exit(1)

    console.print("Running baseline scan...")
    asyncio.run(
        _run_scan(
            str(repo),
            model=model,
            save_results=True,
            quiet=False,
            debug=debug,
        )
    )

    state = load_scan_state(state_path)
    branch = get_repo_branch(repo)
    if not state or not branch or not scan_state_branch_matches(state, branch):
        console.print("[bold red]❌ Baseline scan did not initialize scan_state.json[/bold red]")
        sys.exit(1)


def _git_pull(repo: Path, branch: str) -> None:
    validate_git_ref(branch)
    result = subprocess.run(
        ["git", "pull", "origin", "--", branch],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip() or "Unknown git pull error"
        raise RuntimeError(stderr)


def _repo_has_local_changes(repo: Path) -> bool:
    """Return True if the repository has local changes or git status fails."""
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return True
    return bool(result.stdout.strip())


def _check_target_reachability(target_url: str, timeout: int = 5) -> bool:
    """Check if target URL is reachable"""
    try:
        req = urllib_request.Request(target_url, method="HEAD")
        with urllib_request.urlopen(req, timeout=timeout):
            return True
    except urllib_error.HTTPError:
        # 4xx/5xx still proves the host is reachable.
        return True
    except (urllib_error.URLError, ValueError):
        return False


async def _run_scan(
    path: str,
    model: str,
    save_results: bool,
    quiet: bool,
    debug: bool,
    dast: bool = False,
    target_url: Optional[str] = None,
    dast_timeout: int = 120,
    dast_accounts: Optional[str] = None,
    subagent: Optional[str] = None,
    resume_from: Optional[str] = None,
    force: bool = False,
    skip_checks: bool = False,
    agentic_override: Optional[bool] = None,
):
    """Run the actual scan with progress indicator"""

    repo_path = Path(path).absolute()

    # DAST reachability check
    if dast and target_url:
        if not quiet:
            console.print(f"\n🔍 Checking target reachability: {target_url}")

        if not _check_target_reachability(target_url, timeout=5):
            console.print(
                f"[bold yellow]⚠️  Warning:[/bold yellow] Target {target_url} is not reachable"
            )
            console.print("[dim]DAST validation may fail if target is not running[/dim]")

            if not force and not click.confirm("Continue anyway?", default=True):
                console.print("[yellow]Scan cancelled[/yellow]")
                sys.exit(0)
        else:
            if not quiet:
                console.print("[green]✓ Target is reachable[/green]")

    # Create scanner instance with DAST configuration
    scanner = Scanner(model=model, debug=debug)

    # Configure agentic detection override if provided
    scanner.configure_agentic_detection(agentic_override)

    # Configure DAST if enabled
    if dast:
        scanner.configure_dast(
            target_url=target_url, timeout=dast_timeout, accounts_path=dast_accounts
        )

    # Run in appropriate mode
    if subagent:
        result = await scanner.scan_subagent(str(repo_path), subagent, force, skip_checks)
    elif resume_from:
        result = await scanner.scan_resume(str(repo_path), resume_from, force, skip_checks)
    else:
        result = await scanner.scan(str(repo_path))

    return result


async def _run_pr_review(
    repo: Path,
    model: str,
    debug: bool,
    diff_context: DiffContext,
    known_vulns_path: Optional[Path],
    severity_threshold: str,
    update_artifacts: bool,
):
    """Run the PR review with the configured scanner."""
    scanner = Scanner(model=model, debug=debug)
    return await scanner.pr_review(
        str(repo),
        diff_context,
        known_vulns_path,
        severity_threshold,
        update_artifacts=update_artifacts,
    )


def _display_table_results(result, quiet: bool):
    """Display results in a rich table format"""

    if not quiet:
        console.print()
        console.print("=" * 80)
        console.print("[bold]📊 Scan Results[/bold]")
        console.print("=" * 80)

    # Summary stats
    stats_table = Table(show_header=False, box=box.SIMPLE)
    stats_table.add_row("📁 Files scanned:", f"[cyan]{result.files_scanned}[/cyan]")
    stats_table.add_row("⏱️  Scan time:", f"[cyan]{result.scan_time_seconds}s[/cyan]")
    stats_table.add_row("💰 Total cost:", f"[cyan]${result.total_cost_usd:.4f}[/cyan]")
    stats_table.add_row("🐛 Issues found:", f"[bold]{len(result.issues)}[/bold]")

    if result.issues:
        stats_table.add_row("   🔴 Critical:", f"[bold red]{result.critical_count}[/bold red]")
        stats_table.add_row("   🟠 High:", f"[bold yellow]{result.high_count}[/bold yellow]")
        stats_table.add_row("   🟡 Medium:", f"[bold]{result.medium_count}[/bold]")
        stats_table.add_row("   🟢 Low:", f"[dim]{result.low_count}[/dim]")

    console.print(stats_table)

    warnings = getattr(result, "warnings", None)
    if isinstance(warnings, list) and warnings:
        for warning in warnings:
            console.print(f"[bold yellow]WARNING:[/bold yellow] {warning}")

    console.print()

    if result.issues:
        # Issues table
        issues_table = Table(title="🔍 Detected Vulnerabilities", box=box.ROUNDED, show_lines=True)
        issues_table.add_column("#", style="dim", width=3)
        issues_table.add_column("Severity", width=10)
        issues_table.add_column("Issue", style="bold")
        issues_table.add_column("Location", style="cyan")

        for idx, issue in enumerate(result.issues[:20], 1):
            # Color code severity
            severity_colors = {
                "critical": "bold red",
                "high": "bold yellow",
                "medium": "yellow",
                "low": "dim",
            }
            severity_style = severity_colors.get(issue.severity.value, "white")

            issues_table.add_row(
                str(idx),
                f"[{severity_style}]{issue.severity.value.upper()}[/{severity_style}]",
                issue.title[:50],
                f"{issue.file_path}:{issue.line_number}",
            )

        console.print(issues_table)

        if len(result.issues) > 20:
            console.print(f"\n[dim]... and {len(result.issues) - 20} more issues[/dim]")

        console.print("\n💾 Full report: [cyan].securevibes/scan_results.json[/cyan]")
    else:
        console.print("[bold green]✅ No security issues found![/bold green]")

    console.print()


def _display_text_results(result):
    """Display results in plain text format"""
    console.print(f"\nFiles scanned: {result.files_scanned}")
    console.print(f"Scan time: {result.scan_time_seconds}s")
    console.print(f"Issues found: {len(result.issues)}")

    warnings = getattr(result, "warnings", None)
    if isinstance(warnings, list) and warnings:
        for warning in warnings:
            console.print(f"WARNING: {warning}")

    if result.issues:
        console.print(f"  Critical: {result.critical_count}")
        console.print(f"  High: {result.high_count}")
        console.print(f"  Medium: {result.medium_count}")
        console.print(f"  Low: {result.low_count}")
        console.print()

        for idx, issue in enumerate(result.issues, 1):
            console.print(f"\n{idx}. [{issue.severity.value.upper()}] {issue.title}")
            console.print(f"   File: {issue.file_path}:{issue.line_number}")
            console.print(f"   {issue.description[:150]}...")


def _parse_report_issues(raw_issues: list[dict]) -> list:
    """Parse report issues into SecurityIssue models, skipping malformed entries."""
    from securevibes.models.issue import SecurityIssue, Severity

    issues = []
    for idx, item in enumerate(raw_issues):
        if not isinstance(item, dict):
            console.print(
                f"[yellow]⚠️  Warning: Issue #{idx + 1} is not an object - skipping[/yellow]"
            )
            continue

        try:
            issue_id = item.get("threat_id") or item.get("id")
            if not issue_id:
                console.print(
                    f"[yellow]⚠️  Warning: Issue #{idx + 1} missing ID, using index[/yellow]"
                )
                issue_id = f"ISSUE-{idx + 1}"

            missing = [field for field in REQUIRED_REPORT_ISSUE_FIELDS if field not in item]
            if missing:
                console.print(
                    f"[yellow]⚠️  Warning: Issue #{idx + 1} missing fields: "
                    f"{', '.join(missing)} - skipping[/yellow]"
                )
                continue

            issues.append(
                SecurityIssue(
                    id=issue_id,
                    severity=Severity(item["severity"]),
                    title=item["title"],
                    description=item["description"],
                    file_path=item["file_path"],
                    line_number=item["line_number"],
                    code_snippet=item.get("code_snippet", ""),
                    recommendation=item.get("recommendation"),
                    cwe_id=item.get("cwe_id"),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            console.print(
                f"[yellow]⚠️  Warning: Failed to parse issue #{idx + 1}: {exc} - skipping[/yellow]"
            )
            continue
    return issues


@cli.command()
@click.argument(
    "report_path", type=click.Path(exists=True), default=".securevibes/scan_results.json"
)
def report(report_path: str):
    """
    Display a previously saved scan report.

    Examples:

        securevibes report

        securevibes report .securevibes/scan_results.json
    """
    from securevibes.reporters.json_reporter import JSONReporter

    try:
        console.print(f"\n📄 Loading report: [cyan]{report_path}[/cyan]\n")

        data = JSONReporter.load(report_path)

        missing_fields = [field for field in REQUIRED_REPORT_FIELDS if field not in data]
        if missing_fields:
            console.print(
                f"[bold red]❌ Invalid report format:[/bold red] Missing fields: {', '.join(missing_fields)}"
            )
            console.print(
                "\n[dim]The report may be corrupted or from an incompatible version[/dim]"
            )
            sys.exit(1)

        # Create a mock result object for display
        from securevibes.models.result import ScanResult

        raw_issues = data.get("issues", [])
        if not isinstance(raw_issues, list):
            console.print(
                "[yellow]⚠️  Warning: Report 'issues' field is not a list; treating as empty[/yellow]"
            )
            raw_issues = []
        issues = _parse_report_issues(raw_issues)

        try:
            result = ScanResult(
                repository_path=data["repository_path"],
                issues=issues,
                files_scanned=data["files_scanned"],
                scan_time_seconds=data["scan_time_seconds"],
            )
        except (TypeError, ValueError) as e:
            console.print(f"[bold red]❌ Error creating scan result:[/bold red] {e}")
            console.print(
                "\n[dim]The report format may be incompatible with this version of SecureVibes[/dim]"
            )
            sys.exit(1)

        _display_table_results(result, quiet=False)

    except FileNotFoundError:
        console.print(f"[bold red]❌ Report not found:[/bold red] {report_path}")
        console.print("\n[dim]Run 'securevibes scan' first to generate a report[/dim]")
        sys.exit(1)
    except PermissionError:
        console.print(f"[bold red]❌ Permission denied:[/bold red] Cannot read {report_path}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[bold red]❌ Error loading report:[/bold red] {e}")
        if "--debug" in sys.argv:
            import traceback

            console.print("\n[dim]" + traceback.format_exc() + "[/dim]")
        sys.exit(1)


if __name__ == "__main__":
    cli()
