"""Main CLI entry point for SecureVibes"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.panel import Panel
from rich import box

from securevibes import __version__
from securevibes.models.issue import Severity
from securevibes.scanner.scanner import Scanner

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="securevibes")
def cli():
    """
    🛡️ SecureVibes - AI-Native Platform to Secure Vibecoded Applications
    
    Detect security vulnerabilities in your code using Claude AI.
    """
    pass


@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--model', '-m', default='sonnet', 
              help='Claude model to use (e.g., sonnet, haiku)')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['markdown', 'json', 'text', 'table']), default='markdown', help='Output format (default: markdown)')
@click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low']), 
              help='Minimum severity to report')
@click.option('--no-save', is_flag=True, help='Do not save results to .securevibes/')
@click.option('--quiet', '-q', is_flag=True, help='Minimal output (errors only)')
@click.option('--debug', is_flag=True, help='Show verbose diagnostic output')
@click.option('--dast', is_flag=True, help='Enable DAST validation in full scan')
@click.option('--target-url', type=str, help='Target URL for DAST testing (e.g., http://localhost:3000)')
@click.option('--dast-timeout', type=int, default=120, help='DAST validation timeout in seconds (default: 120)')
@click.option('--dast-accounts', type=click.Path(exists=True), help='Path to test accounts JSON file')
@click.option('--allow-production', is_flag=True, help='Allow DAST testing on production URLs (use with caution!)')
@click.option('--subagent', type=click.Choice(['assessment', 'threat-modeling', 'code-review', 'report-generator', 'dast']),
              help='Run specific sub-agent only (mutually exclusive with --dast and --resume-from)')
@click.option('--resume-from', type=click.Choice(['assessment', 'threat-modeling', 'code-review', 'report-generator', 'dast']),
              help='Resume scan from specific sub-agent onwards')
@click.option('--force', is_flag=True, help='Skip confirmation prompts, overwrite existing artifacts')
@click.option('--skip-checks', is_flag=True, help='Bypass artifact validation checks')
def scan(path: str, model: str, output: Optional[str], format: str, 
         severity: Optional[str], no_save: bool, quiet: bool, debug: bool,
         dast: bool, target_url: Optional[str], dast_timeout: int, 
         dast_accounts: Optional[str], allow_production: bool,
         subagent: Optional[str], resume_from: Optional[str], 
         force: bool, skip_checks: bool):
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
            console.print("[yellow]⚠️  Warning: --quiet and --debug are contradictory. Using --debug.[/yellow]")
            quiet = False  # Debug takes precedence
        
        # Validate mutually exclusive flags
        if subagent and resume_from:
            console.print("[bold red]❌ Error:[/bold red] --subagent and --resume-from are mutually exclusive")
            sys.exit(1)
        
        if subagent and dast:
            console.print("[bold red]❌ Error:[/bold red] --subagent and --dast are mutually exclusive")
            console.print("\n[dim]Use either:[/dim]")
            console.print("  --subagent dast --target-url URL      (run DAST sub-agent only)")
            console.print("  --dast --target-url URL               (full scan with DAST)")
            sys.exit(1)
        
        # Auto-enable DAST for dast sub-agent
        if subagent == 'dast':
            dast = True
            if not target_url:
                console.print("[bold red]❌ Error:[/bold red] --target-url is required for DAST sub-agent")
                console.print("[dim]Example: securevibes scan . --subagent dast --target-url http://localhost:3000[/dim]")
                sys.exit(1)
        
        # Validate target-url requirement for resume-from dast
        if resume_from == 'dast' and not target_url:
            console.print("[bold red]❌ Error:[/bold red] --target-url is required when resuming from DAST")
            sys.exit(1)
        
        # Show banner unless quiet
        if not quiet:
            console.print("[bold cyan]🛡️ SecureVibes Security Scanner[/bold cyan]")
            console.print("[dim]AI-Powered Vulnerability Detection[/dim]")
            console.print()
        
        # Ensure output directory exists if saving results
        if not no_save:
            output_dir = Path(path) / '.securevibes'
            try:
                output_dir.mkdir(parents=True, exist_ok=True)
            except (IOError, OSError) as e:
                console.print(f"[bold red]❌ Error:[/bold red] Cannot create output directory: {e}")
                sys.exit(1)
        
        # DAST validation checks
        if dast:
            if not target_url:
                console.print("[bold red]❌ Error:[/bold red] --target-url is required when --dast is enabled")
                console.print("[dim]Example: securevibes scan . --dast --target-url http://localhost:3000[/dim]")
                sys.exit(1)
            
            # Safety gate: production URL detection
            if _is_production_url(target_url) and not allow_production:
                console.print(f"[bold red]⚠️  PRODUCTION URL DETECTED:[/bold red] {target_url}")
                console.print("\n[yellow]DAST testing sends real HTTP requests to the target.")
                console.print("Testing production systems requires explicit authorization.[/yellow]")
                console.print("\n[dim]To proceed, add --allow-production flag (ensure you have authorization!)[/dim]")
                sys.exit(1)
            
            # Safety gate: explicit confirmation
            if not allow_production and not quiet:
                console.print(f"\n[bold yellow]⚠️  DAST Validation Enabled[/bold yellow]")
                console.print(f"Target: {target_url}")
                console.print("\nDAst will send HTTP requests to validate IDOR vulnerabilities.")
                console.print("Ensure you have authorization to test this target.\n")
                
                if not click.confirm("Proceed with DAST validation?", default=False):
                    console.print("[yellow]DAST validation cancelled. Running SAST-only scan...[/yellow]")
                    dast = False
        
        # Run scan (full/single sub-agent/resume mode)
        result = asyncio.run(_run_scan(
            path, model, not no_save, quiet, debug, 
            dast, target_url, dast_timeout, dast_accounts,
            subagent, resume_from, force, skip_checks
        ))
        
        # Filter by severity if specified
        if severity:
            min_severity = Severity(severity)
            severity_order = ['info', 'low', 'medium', 'high', 'critical']
            min_index = severity_order.index(min_severity.value)
            result.issues = [
                issue for issue in result.issues 
                if severity_order.index(issue.severity.value) >= min_index
            ]
        
        # Output results
        if format == 'markdown':
            from securevibes.reporters.markdown_reporter import MarkdownReporter
            
            if output:
                # If absolute path, use as-is; otherwise save to .securevibes/
                output_path = Path(output)
                if not output_path.is_absolute():
                    output_path = Path(path) / '.securevibes' / output
                
                try:
                    # Ensure parent directory exists
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    MarkdownReporter.save(result, output_path)
                    console.print(f"\n✅ Markdown report saved to: {output_path}")
                except (IOError, OSError, PermissionError) as e:
                    console.print(f"[bold red]❌ Error writing output file:[/bold red] {e}")
                    sys.exit(1)
            else:
                # Save to default location
                default_path = Path(path) / '.securevibes' / 'scan_report.md'
                try:
                    MarkdownReporter.save(result, default_path)
                    console.print(f"\n📄 Markdown report: [cyan]{default_path}[/cyan]")
                except (IOError, OSError, PermissionError) as e:
                    console.print(f"[bold red]❌ Error writing report:[/bold red] {e}")
                    sys.exit(1)
        
        elif format == 'json':
            import json
            output_data = result.to_dict()
            if output:
                try:
                    output_path = Path(output)
                    # Ensure parent directory exists
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    output_path.write_text(json.dumps(output_data, indent=2))
                    console.print(f"\n✅ Results saved to: {output}")
                except (IOError, OSError, PermissionError) as e:
                    console.print(f"[bold red]❌ Error writing output file:[/bold red] {e}")
                    sys.exit(1)
            else:
                console.print_json(data=output_data)
        
        elif format == 'table':
            _display_table_results(result, quiet)
        
        else:  # text
            _display_text_results(result)
        
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


def _is_production_url(url: str) -> bool:
    """Detect if a URL appears to be a production system"""
    url_lower = url.lower()
    
    # Safe patterns (local development)
    safe_patterns = [
        'localhost', '127.0.0.1', '0.0.0.0', '[::1]',
        'staging', 'dev', 'test', 'qa',
        '.local', '.test', '.dev'
    ]
    
    # Check if URL contains any safe pattern
    if any(pattern in url_lower for pattern in safe_patterns):
        return False
    
    # Production indicators
    production_patterns = [
        '.com', '.net', '.org', '.io',
        'production', 'prod', 'api.',
        'app.', 'www.'
    ]
    
    return any(pattern in url_lower for pattern in production_patterns)


def _check_target_reachability(target_url: str, timeout: int = 5) -> bool:
    """Check if target URL is reachable"""
    import requests
    
    try:
        response = requests.get(target_url, timeout=timeout, allow_redirects=True)
        return True
    except requests.RequestException:
        return False


async def _run_scan(
    path: str, model: str, save_results: bool, quiet: bool, debug: bool,
    dast: bool = False, target_url: Optional[str] = None, 
    dast_timeout: int = 120, dast_accounts: Optional[str] = None,
    subagent: Optional[str] = None, resume_from: Optional[str] = None,
    force: bool = False, skip_checks: bool = False
):
    """Run the actual scan with progress indicator"""

    repo_path = Path(path).absolute()
    
    # DAST reachability check
    if dast and target_url:
        if not quiet:
            console.print(f"\n🔍 Checking target reachability: {target_url}")
        
        if not _check_target_reachability(target_url, timeout=5):
            console.print(f"[bold yellow]⚠️  Warning:[/bold yellow] Target {target_url} is not reachable")
            console.print("[dim]DAST validation may fail if target is not running[/dim]")
            
            if not force and not click.confirm("Continue anyway?", default=True):
                console.print("[yellow]Scan cancelled[/yellow]")
                sys.exit(0)
        else:
            if not quiet:
                console.print("[green]✓ Target is reachable[/green]")
    
    # Create scanner instance with DAST configuration
    scanner = Scanner(model=model, debug=debug)
    
    # Configure DAST if enabled
    if dast:
        scanner.configure_dast(
            target_url=target_url,
            timeout=dast_timeout,
            accounts_path=dast_accounts
        )
    
    # Run in appropriate mode
    if subagent:
        result = await scanner.scan_subagent(str(repo_path), subagent, force, skip_checks)
    elif resume_from:
        result = await scanner.scan_resume(str(repo_path), resume_from, force, skip_checks)
    else:
        result = await scanner.scan(str(repo_path))

    return result


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
    console.print()
    
    if result.issues:
        # Issues table
        issues_table = Table(
            title="🔍 Detected Vulnerabilities",
            box=box.ROUNDED,
            show_lines=True
        )
        issues_table.add_column("#", style="dim", width=3)
        issues_table.add_column("Severity", width=10)
        issues_table.add_column("Issue", style="bold")
        issues_table.add_column("Location", style="cyan")
        
        for idx, issue in enumerate(result.issues[:20], 1):
            # Color code severity
            severity_colors = {
                'critical': 'bold red',
                'high': 'bold yellow',
                'medium': 'yellow',
                'low': 'dim'
            }
            severity_style = severity_colors.get(issue.severity.value, 'white')
            
            issues_table.add_row(
                str(idx),
                f"[{severity_style}]{issue.severity.value.upper()}[/{severity_style}]",
                issue.title[:50],
                f"{issue.file_path}:{issue.line_number}"
            )
        
        console.print(issues_table)
        
        if len(result.issues) > 20:
            console.print(f"\n[dim]... and {len(result.issues) - 20} more issues[/dim]")
        
        console.print(f"\n💾 Full report: [cyan].securevibes/scan_results.json[/cyan]")
    else:
        console.print("[bold green]✅ No security issues found![/bold green]")
    
    console.print()


def _display_text_results(result):
    """Display results in plain text format"""
    console.print(f"\nFiles scanned: {result.files_scanned}")
    console.print(f"Scan time: {result.scan_time_seconds}s")
    console.print(f"Issues found: {len(result.issues)}")
    
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


@cli.command()
@click.argument('report_path', type=click.Path(exists=True), 
                default='.securevibes/scan_results.json')
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
        
        # Validate required fields
        required_fields = ['repository_path', 'files_scanned', 'scan_time_seconds', 'issues']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            console.print(f"[bold red]❌ Invalid report format:[/bold red] Missing fields: {', '.join(missing_fields)}")
            console.print("\n[dim]The report may be corrupted or from an incompatible version[/dim]")
            sys.exit(1)
        
        # Create a mock result object for display
        from securevibes.models.result import ScanResult
        from securevibes.models.issue import SecurityIssue, Severity
        
        issues = []
        for idx, item in enumerate(data.get('issues', [])):
            try:
                # Accept both threat_id and id, but warn if neither exists
                issue_id = item.get('threat_id') or item.get('id')
                if not issue_id:
                    console.print(f"[yellow]⚠️  Warning: Issue #{idx + 1} missing ID, using index[/yellow]")
                    issue_id = f"ISSUE-{idx + 1}"
                
                # Validate required fields for each issue
                required_issue_fields = ['severity', 'title', 'description', 'file_path', 'line_number']
                missing = [f for f in required_issue_fields if f not in item]
                if missing:
                    console.print(f"[yellow]⚠️  Warning: Issue #{idx + 1} missing fields: {', '.join(missing)} - skipping[/yellow]")
                    continue
                
                issues.append(SecurityIssue(
                    id=issue_id,
                    severity=Severity(item['severity']),
                    title=item['title'],
                    description=item['description'],
                    file_path=item['file_path'],
                    line_number=item['line_number'],
                    code_snippet=item.get('code_snippet', ''),
                    recommendation=item.get('recommendation'),
                    cwe_id=item.get('cwe_id')
                ))
            except (KeyError, ValueError) as e:
                console.print(f"[yellow]⚠️  Warning: Failed to parse issue #{idx + 1}: {e} - skipping[/yellow]")
                continue
        
        try:
            result = ScanResult(
                repository_path=data['repository_path'],
                issues=issues,
                files_scanned=data['files_scanned'],
                scan_time_seconds=data['scan_time_seconds']
            )
        except (TypeError, ValueError) as e:
            console.print(f"[bold red]❌ Error creating scan result:[/bold red] {e}")
            console.print("\n[dim]The report format may be incompatible with this version of SecureVibes[/dim]")
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
        if '--debug' in sys.argv:
            import traceback
            console.print("\n[dim]" + traceback.format_exc() + "[/dim]")
        sys.exit(1)


if __name__ == '__main__':
    cli()
