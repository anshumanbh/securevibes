"""Markdown output reporter"""

from pathlib import Path
from typing import Union
from datetime import datetime
from securevibes.models.result import ScanResult


class MarkdownReporter:
    """Saves scan results to Markdown files"""

    @staticmethod
    def save(result: "ScanResult", output_path: Union[str, Path]) -> None:
        """
        Save scan result to Markdown file

        Args:
            result: ScanResult to save
            output_path: Path to output Markdown file
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        markdown = MarkdownReporter.generate(result)
        output_file.write_text(markdown, encoding="utf-8")

    @staticmethod
    def generate(result: "ScanResult") -> str:
        """
        Generate markdown content from scan result

        Args:
            result: ScanResult to convert to markdown

        Returns:
            Markdown formatted string
        """
        lines = []

        # Title and metadata
        lines.append("# Security Scan Report")
        lines.append("")
        lines.append(f"**Repository:** `{result.repository_path}`  ")
        lines.append(f"**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        lines.append(f"**Files Scanned:** {result.files_scanned}  ")

        # Format scan time nicely
        scan_time = result.scan_time_seconds
        if scan_time >= 60:
            minutes = int(scan_time // 60)
            seconds = scan_time % 60
            time_str = f"{scan_time:.2f}s (~{minutes}m {seconds:.0f}s)"
        else:
            time_str = f"{scan_time:.2f}s"
        lines.append(f"**Scan Duration:** {time_str}  ")

        if result.total_cost_usd > 0:
            lines.append(f"**Total Cost:** ${result.total_cost_usd:.4f}  ")

        # DAST metrics if enabled
        if result.dast_enabled:
            lines.append("**DAST Enabled:** ✓ Yes  ")
            lines.append(f"**Validation Rate:** {result.dast_validation_rate:.1f}%  ")
            if result.dast_scan_time_seconds > 0:
                lines.append(f"**DAST Time:** {result.dast_scan_time_seconds:.1f}s  ")

        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive summary
        total_issues = len(result.issues)
        if total_issues > 0:
            lines.append("## Executive Summary")
            lines.append("")

            # Severity icon based on highest severity
            if result.critical_count > 0:
                icon = "🔴"
                urgency = "**CRITICAL** - Requires immediate attention"
            elif result.high_count > 0:
                icon = "🟠"
                urgency = "**HIGH** - Should be fixed soon"
            elif result.medium_count > 0:
                icon = "🟡"
                urgency = "**MEDIUM** - Address when possible"
            else:
                icon = "🟢"
                urgency = "Minor issues found"

            lines.append(
                f"{icon} **{total_issues} security {'vulnerability' if total_issues == 1 else 'vulnerabilities'} found** - {urgency}"
            )
            lines.append("")

            # Severity breakdown
            if result.critical_count > 0:
                lines.append(
                    f"- 🔴 **{result.critical_count} Critical** - Require immediate attention"
                )
            if result.high_count > 0:
                lines.append(f"- 🟠 **{result.high_count} High** - Should be fixed soon")
            if result.medium_count > 0:
                lines.append(f"- 🟡 **{result.medium_count} Medium** - Address when possible")
            if result.low_count > 0:
                lines.append(f"- 🟢 **{result.low_count} Low** - Minor issues")

            # DAST validation summary
            if result.dast_enabled:
                lines.append("")
                lines.append("**DAST Validation Status:**")
                lines.append(f"- ✅ {len(result.validated_issues)} Validated")
                lines.append(f"- ❌ {len(result.false_positives)} False Positives")
                lines.append(f"- ❓ {len(result.unvalidated_issues)} Unvalidated")

            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            primary_issue = max(
                result.issues,
                key=lambda issue: (
                    severity_order.get(issue.severity.value, 0),
                    len(issue.attack_scenario or ""),
                    len(issue.evidence or ""),
                ),
            )
            primary_location = (
                f"`{primary_issue.file_path}:{primary_issue.line_number}`"
                if primary_issue.line_number
                else f"`{primary_issue.file_path}`"
            )
            chain_text = (
                primary_issue.attack_scenario
                or primary_issue.evidence
                or primary_issue.description
                or primary_issue.title
            )
            chain_text = " ".join(chain_text.split())
            if len(chain_text) > 420:
                chain_text = f"{chain_text[:417]}..."

            lines.append("")
            lines.append("## Primary Exploit Chain")
            lines.append("")
            lines.append(f"**Finding:** {primary_issue.title}")
            lines.append(f"**Location:** {primary_location}")
            if primary_issue.cwe_id:
                lines.append(f"**CWE:** {primary_issue.cwe_id}")
            lines.append("")
            lines.append(chain_text)
        else:
            lines.append("## Executive Summary")
            lines.append("")
            lines.append("✅ **No security vulnerabilities found!**")
            lines.append("")
            lines.append("The security scan completed successfully with no issues detected.")

        lines.append("")
        lines.append("---")
        lines.append("")

        if total_issues > 0:
            # Severity distribution table
            lines.append("## Severity Distribution")
            lines.append("")
            lines.append("| Severity | Count | Percentage |")
            lines.append("|----------|-------|------------|")

            severity_data = [
                ("🔴 Critical", result.critical_count),
                ("🟠 High", result.high_count),
                ("🟡 Medium", result.medium_count),
                ("🟢 Low", result.low_count),
            ]

            for severity_name, count in severity_data:
                if count > 0:
                    percentage = (count / total_issues) * 100
                    lines.append(f"| {severity_name} | {count} | {percentage:.0f}% |")

            lines.append("")
            lines.append("---")
            lines.append("")

            # Vulnerability overview table
            lines.append("## Vulnerability Overview")
            lines.append("")
            lines.append("| # | Severity | Title | Location |")
            lines.append("|---|----------|-------|----------|")

            severity_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

            for idx, issue in enumerate(result.issues, 1):
                icon = severity_icons.get(issue.severity.value, "⚪")

                # Add validation badge if DAST enabled
                if result.dast_enabled and issue.validation_status:
                    validation_badge = {
                        "VALIDATED": " ✅",
                        "FALSE_POSITIVE": " ❌",
                        "UNVALIDATED": " ❓",
                        "PARTIAL": " ⚠️",
                    }.get(issue.validation_status.value, "")
                    severity_text = f"{icon} {issue.severity.value.upper()}{validation_badge}"
                else:
                    severity_text = f"{icon} {issue.severity.value.upper()}"

                # Truncate title if too long for table
                title = issue.title[:60] + "..." if len(issue.title) > 60 else issue.title
                # Escape pipe characters in title
                title = title.replace("|", "\\|")

                location = (
                    f"`{issue.file_path}:{issue.line_number}`"
                    if issue.line_number
                    else f"`{issue.file_path}`"
                )

                lines.append(f"| {idx} | {severity_text} | {title} | {location} |")

            lines.append("")
            lines.append("---")
            lines.append("")

            # Detailed findings
            lines.append("## Detailed Findings")
            lines.append("")

            for idx, issue in enumerate(result.issues, 1):
                icon = severity_icons.get(issue.severity.value, "⚪")

                # Section header
                lines.append(f"### {idx}. {issue.title} [{icon} {issue.severity.value.upper()}]")
                lines.append("")

                # Metadata
                lines.append(f"**File:** `{issue.file_path}:{issue.line_number}`  ")
                if issue.cwe_id:
                    lines.append(f"**CWE:** {issue.cwe_id}  ")
                lines.append(f"**Severity:** {icon} {issue.severity.value.capitalize()}")
                if issue.finding_type:
                    lines.append(
                        f"**Finding Type:** {issue.finding_type.replace('_', ' ').title()}"
                    )

                # DAST validation status
                if result.dast_enabled and issue.validation_status:
                    status_display = {
                        "VALIDATED": "✅ **Validated** - Exploitability confirmed",
                        "FALSE_POSITIVE": "❌ **False Positive** - Not exploitable",
                        "UNVALIDATED": "❓ **Unvalidated** - Could not verify",
                        "PARTIAL": "⚠️ **Partially Validated** - Needs review",
                    }
                    lines.append(
                        f"**DAST Status:** {status_display.get(issue.validation_status.value, issue.validation_status.value)}"
                    )

                    if issue.exploitability_score is not None:
                        lines.append(f"**Exploitability:** {issue.exploitability_score:.1f}/10")

                lines.append("")

                # Description
                lines.append("**Description:**")
                lines.append("")
                lines.append(issue.description)
                lines.append("")

                if issue.attack_scenario:
                    lines.append("**Attack Scenario:**")
                    lines.append("")
                    lines.append(issue.attack_scenario)
                    lines.append("")

                if issue.evidence and not result.dast_enabled:
                    lines.append("**Evidence:**")
                    lines.append("")
                    lines.append(issue.evidence)
                    lines.append("")

                # Code snippet if available
                if issue.code_snippet:
                    lines.append("**Code Snippet:**")
                    lines.append("")
                    # Try to detect language from file extension
                    file_ext = Path(issue.file_path).suffix.lstrip(".")
                    lang_map = {
                        "py": "python",
                        "js": "javascript",
                        "ts": "typescript",
                        "tsx": "typescript",
                        "jsx": "javascript",
                        "java": "java",
                        "go": "go",
                        "rb": "ruby",
                        "php": "php",
                        "cpp": "cpp",
                        "c": "c",
                        "rs": "rust",
                    }
                    lang = lang_map.get(file_ext, "")

                    lines.append(f"```{lang}")
                    lines.append(issue.code_snippet)
                    lines.append("```")
                    lines.append("")

                # DAST Evidence
                if result.dast_enabled and issue.dast_evidence:
                    lines.append("**DAST Evidence:**")
                    lines.append("")

                    # Show test steps if available
                    test_steps = issue.dast_evidence.get("test_steps")
                    if test_steps:
                        if isinstance(test_steps, list):
                            for step in test_steps:
                                lines.append(f"- {step}")
                        else:
                            lines.append(str(test_steps))
                        lines.append("")

                    # Show HTTP requests if available
                    http_requests = issue.dast_evidence.get("http_requests")
                    if http_requests and isinstance(http_requests, list):
                        for req in http_requests:
                            lines.append(f"Request: `{req.get('request', 'N/A')}`")
                            lines.append(f"- Status: {req.get('status', 'N/A')}")
                            if req.get("authenticated_as"):
                                lines.append(f"- Auth: {req['authenticated_as']}")
                            lines.append("")

                    # Show notes or reason if available
                    notes = issue.dast_evidence.get("notes") or issue.dast_evidence.get("reason")
                    if notes:
                        lines.append(f"*{notes}*")
                        lines.append("")

                # Recommendation
                if issue.recommendation:
                    lines.append("**Recommendation:**")
                    lines.append("")
                    lines.append(MarkdownReporter._format_recommendation(issue.recommendation))
                    lines.append("")

                # Separator between issues
                if idx < len(result.issues):
                    lines.append("---")
                    lines.append("")

        # Footer
        lines.append("---")
        lines.append("")
        lines.append("*Generated by SecureVibes Security Scanner*  ")
        lines.append(f"*Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")

        return "\n".join(lines)

    @staticmethod
    def _format_recommendation(recommendation: str) -> str:
        """
        Format recommendation text into proper markdown list.

        Handles:
        - Numbered items (1. ... 2. ... 3. ...)
        - Inline code formatting
        - Proper line breaks

        Args:
            recommendation: Raw recommendation text

        Returns:
            Formatted markdown string
        """
        import re

        # If already well-formatted (has newlines with numbers), return as-is
        if re.search(r"\n\d+\.", recommendation):
            return recommendation

        # Split on numbered patterns: "1. ", "2. ", etc.
        # Use lookahead to keep the number
        items = re.split(r"(?=\d+\.\s+)", recommendation.strip())
        items = [item.strip() for item in items if item.strip()]

        # Check if any items start with numbered pattern
        has_numbered_items = any(re.match(r"\d+\.\s+", item) for item in items)

        if not has_numbered_items or len(items) == 0:
            # No numbered list detected, return as-is
            return recommendation

        # Format each item
        formatted_items = []
        for item in items:
            # Extract number and text
            match = re.match(r"(\d+)\.\s+(.*)", item, re.DOTALL)
            if match:
                num, text = match.groups()
                text = text.strip()

                # Format inline code:
                # 1. Function/method calls with dots: os.path.realpath() -> `os.path.realpath()`
                text = re.sub(
                    r"\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*\(\))", r"`\1`", text
                )

                # 2. Single quotes around identifiers: 'permission_mode' -> `permission_mode`
                text = re.sub(r"'([a-zA-Z_][a-zA-Z0-9_\.]*)'", r"`\1`", text)

                # 3. File paths: /path/to/file or path/to/file.py
                text = re.sub(r"([a-zA-Z0-9_\-\.]+/[a-zA-Z0-9_/\-\.]+\.[a-z]+)", r"`\1`", text)

                # 4. Environment variables: SOME_VAR_NAME
                text = re.sub(r"\b([A-Z][A-Z0-9_]{3,})\b", r"`\1`", text)

                # Add formatted item
                formatted_items.append(f"{num}. {text}")

        # Join with newlines
        return "\n".join(formatted_items)
