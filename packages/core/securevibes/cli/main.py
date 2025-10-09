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
from securevibes.scanner.security_scanner import SecurityScanner

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
@click.option('--api-key', envvar='CLAUDE_API_KEY', help='Claude API key')
@click.option('--model', '-m', default='sonnet', 
              help='Claude model to use (e.g., sonnet, haiku)')
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'text', 'table']), default='table', help='Output format')
@click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low']), 
              help='Minimum severity to report')
@click.option('--no-save', is_flag=True, help='Do not save results to .securevibes/')
@click.option('--quiet', '-q', is_flag=True, help='Minimal output (errors only)')
@click.option('--debug', is_flag=True, help='Show verbose diagnostic output')
def scan(path: str, api_key: Optional[str], model: str, output: Optional[str], format: str, 
         severity: Optional[str], no_save: bool, quiet: bool, debug: bool):
    """
    Scan a repository for security vulnerabilities.
    
    Examples:
    
        securevibes scan .
        
        securevibes scan /path/to/project --severity high
        
        securevibes scan . --format json --output results.json
        
        securevibes scan . --model claude-3-5-haiku-20241022  # Use faster/cheaper model
    """
    try:
        # Validate flag conflicts
        if quiet and debug:
            console.print("[yellow]⚠️  Warning: --quiet and --debug are contradictory. Using --debug.[/yellow]")
            quiet = False  # Debug takes precedence
        
        # Validate API key early
        if not api_key:
            console.print("[bold red]❌ Error:[/bold red] CLAUDE_API_KEY environment variable not set")
            console.print("\n[dim]Set it with: export CLAUDE_API_KEY='your-api-key'[/dim]")
            console.print("[dim]Or pass directly: securevibes scan --api-key 'your-api-key'[/dim]")
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
        
        # Run scan
        result = asyncio.run(_run_scan(path, api_key, model, not no_save, quiet, debug))
        
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
        if format == 'json':
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


async def _run_scan(path: str, api_key: Optional[str], model: str, save_results: bool, quiet: bool, debug: bool):
    """Run the actual scan with progress indicator"""

    scanner = SecurityScanner(api_key=api_key, model=model, debug=debug)
    repo_path = Path(path).absolute()

    # The scanner now handles all output
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


@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--api-key', envvar='CLAUDE_API_KEY', help='Claude API key')
@click.option('--model', '-m', default='claude-3-5-haiku-20241022', help='Claude model to use')
@click.option('--debug', is_flag=True, default=True, help='Show verbose diagnostic output (default: enabled)')
def assess(path: str, api_key: Optional[str], model: str, debug: bool):
    """
    Run only the architecture assessment phase.
    
    Creates SECURITY.md in .securevibes/ directory.
    
    Examples:
    
        securevibes assess .
        
        securevibes assess /path/to/project
    """
    try:
        # Validate API key
        if not api_key:
            console.print("[bold red]❌ Error:[/bold red] CLAUDE_API_KEY environment variable not set")
            console.print("\n[dim]Set it with: export CLAUDE_API_KEY='your-api-key'[/dim]")
            sys.exit(1)
        
        console.print(Panel.fit(
            "[bold cyan]📐 SecureVibes Assessment Agent[/bold cyan]\n"
            "[dim]Architecture Documentation[/dim]",
            border_style="cyan"
        ))
        
        # Ensure output directory exists
        output_dir = Path(path) / '.securevibes'
        output_dir.mkdir(parents=True, exist_ok=True)

        scanner = SecurityScanner(api_key=api_key, model=model, debug=debug)
        result = asyncio.run(scanner.assess_only(path))

        console.print(f"\n✅ [green]Assessment complete[/green]")
        console.print(f"📄 Output: [cyan]{result['file']}[/cyan]\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Assessment cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--api-key', envvar='CLAUDE_API_KEY', help='Claude API key')
@click.option('--model', '-m', default='claude-3-5-haiku-20241022', help='Claude model to use')
@click.option('--debug', is_flag=True, default=True, help='Show verbose diagnostic output (default: enabled)')
def threat_model(path: str, api_key: Optional[str], model: str, debug: bool):
    """
    Run only the threat modeling phase.
    
    Requires existing SECURITY.md. Creates THREAT_MODEL.json.
    
    Examples:
    
        securevibes threat-model .
    """
    try:
        # Validate API key
        if not api_key:
            console.print("[bold red]❌ Error:[/bold red] CLAUDE_API_KEY environment variable not set")
            console.print("\n[dim]Set it with: export CLAUDE_API_KEY='your-api-key'[/dim]")
            sys.exit(1)
        
        # Check prerequisites
        security_md = Path(path) / '.securevibes' / 'SECURITY.md'
        if not security_md.exists():
            console.print("[bold red]❌ Error:[/bold red] SECURITY.md not found")
            console.print("\n[dim]Run 'securevibes assess' first to create the security architecture document[/dim]")
            sys.exit(1)
        
        console.print(Panel.fit(
            "[bold cyan]🎯 SecureVibes Threat Modeling Agent[/bold cyan]\n"
            "[dim]STRIDE Analysis[/dim]",
            border_style="cyan"
        ))

        scanner = SecurityScanner(api_key=api_key, model=model, debug=debug)
        result = asyncio.run(scanner.threat_model_only(path))

        console.print(f"\n✅ [green]Threat modeling complete[/green]")
        console.print(f"📄 Output: [cyan]{result['file']}[/cyan]\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Threat modeling cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}")
        sys.exit(1)


@cli.command()
@click.argument('path', type=click.Path(exists=True), default='.')
@click.option('--api-key', envvar='CLAUDE_API_KEY', help='Claude API key')
@click.option('--model', '-m', default='claude-3-5-haiku-20241022', help='Claude model to use')
@click.option('--debug', is_flag=True, default=True, help='Show verbose diagnostic output (default: enabled)')
def review(path: str, api_key: Optional[str], model: str, debug: bool):
    """
    Run only the code review phase.
    
    Requires SECURITY.md and THREAT_MODEL.json. Creates VULNERABILITIES.json.
    
    Examples:
    
        securevibes review .
    """
    try:
        # Validate API key
        if not api_key:
            console.print("[bold red]❌ Error:[/bold red] CLAUDE_API_KEY environment variable not set")
            console.print("\n[dim]Set it with: export CLAUDE_API_KEY='your-api-key'[/dim]")
            sys.exit(1)
        
        # Check prerequisites
        securevibes_dir = Path(path) / '.securevibes'
        security_md = securevibes_dir / 'SECURITY.md'
        threat_model = securevibes_dir / 'THREAT_MODEL.json'
        
        missing = []
        if not security_md.exists():
            missing.append('SECURITY.md (run: securevibes assess)')
        if not threat_model.exists():
            missing.append('THREAT_MODEL.json (run: securevibes threat-model)')
        
        if missing:
            console.print("[bold red]❌ Error:[/bold red] Missing required files:")
            for item in missing:
                console.print(f"  • {item}")
            sys.exit(1)
        
        console.print(Panel.fit(
            "[bold cyan]🔍 SecureVibes Code Review Agent[/bold cyan]\n"
            "[dim]Vulnerability Validation[/dim]",
            border_style="cyan"
        ))

        scanner = SecurityScanner(api_key=api_key, model=model, debug=debug)
        result = asyncio.run(scanner.review_only(path))

        console.print(f"\n✅ [green]Code review complete[/green]")
        console.print(f"📄 Output: [cyan]{result['file']}[/cyan]\n")
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Code review cancelled by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[bold red]❌ Error:[/bold red] {e}")
        sys.exit(1)


if __name__ == '__main__':
    cli()
