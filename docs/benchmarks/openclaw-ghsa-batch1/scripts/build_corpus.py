#!/usr/bin/env python3
"""Build OpenClaw GHSA batch-1 benchmark corpus artifacts.

This script materializes advisory, timeline, verification, and detectability
artifacts for the selected critical/high advisory set.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = ROOT / "cases"

SELECTION_IDS = [
    "GHSA-qrq5-wjgg-rvqw",
    "GHSA-4rj2-gpmh-qq5x",
    "GHSA-gv46-4xfq-jv58",
    "GHSA-3c6h-g97w-fg78",
    "GHSA-r5fq-947m-xm57",
    "GHSA-943q-mwmv-hhvh",
    "GHSA-g8p2-7wf7-98mq",
    "GHSA-mc68-q9jw-2h3v",
    "GHSA-x22m-j5qq-j49m",
    "GHSA-g55j-c2v4-pjcg",
]

# Decision-complete mapping from plan + manual provenance resolution.
CASE_MAPPING: dict[str, dict[str, Any]] = {
    "GHSA-qrq5-wjgg-rvqw": {
        "introducing_commits": [
            "2f4a248314fdd754b8344d955842fdd47f828fab",
            "3a6ee5ee00176c88aee32bb8bfd543780014c079",
        ],
        "fix_commits": ["d03eca8450dc493b198a88b105fd180895238e57"],
        "confidence": "high",
        "notes": "Plugin install path logic introduced during plugin system bootstrap and hook/plugin install unification.",
    },
    "GHSA-4rj2-gpmh-qq5x": {
        "introducing_commits": ["42c17adb5e4d3ea1f9b1d2fd921b9abc183b79df"],
        "fix_commits": ["f8dfd034f5d9235c5485f492a9e4ccc114e97fdb"],
        "confidence": "high",
        "notes": "Inbound allowlist logic is introduced in the voice-call manager parity commit and hardened in the fix commit.",
    },
    "GHSA-gv46-4xfq-jv58": {
        "introducing_commits": ["2f8206862a684d14f7ca92e9fe0dbce627c5d82b"],
        "fix_commits": [
            "318379cdba1804eb840896f6ebd4dd6dd0fb53cb",
            "0af76f5f0e93540efbdf054895216c398692afcd",
            "01b3226ecbea6f5aa2a433237dae87d181d8790f",
        ],
        "advisory_fix_refs_unresolved": [
            "318379cdb8d045da0009b0051bd0e712e5c65e2d",
            "a7af646fdab124a7536998db6bd6ad567d2b06b0",
            "c1594627421f95b6bc4ad7c606657dc75b5ad0ce",
        ],
        "confidence": "medium",
        "notes": "Advisory lists three SHAs that do not resolve via GitHub API; equivalent public fix sequence was resolved by file history and commit messages.",
    },
    "GHSA-3c6h-g97w-fg78": {
        "introducing_commits": [
            "2d485cd47a539b083c460f88061fe584deaeb064",
            "89aad7b922835e40b4df54a9e6195a5f8ee2e5b6",
        ],
        "fix_commits": ["3b8e33037ae2e12af7beb56fcf0346f1f8cbde6f"],
        "confidence": "high",
        "notes": "Safe-bin policy refactors introduced long-option abbreviation handling gap fixed by targeted deny-path hardening.",
    },
    "GHSA-r5fq-947m-xm57": {
        "introducing_commits": ["8b4bdaa8a473e6e14cab866a916a407e86ab861a"],
        "fix_commits": ["5544646a09c0121fca7d7093812dc2de8437c7f1"],
        "confidence": "high",
        "notes": "Vulnerability is anchored to initial apply_patch tool implementation lacking workspace containment in non-sandbox mode.",
    },
    "GHSA-943q-mwmv-hhvh": {
        "introducing_commits": [
            "9809b47d4545b394a5e49624796297147a8253cb",
            "f1083cd52cf43c7312ae09cf0aa696ba9c95282c",
        ],
        "fix_commits": [
            "749e28dec796f77697398acbfc7a64d4439d7cad",
            "ee31cd47b49f4b2f128a69a2a3745ca9db68b3be",
            "bb1c3dfe10766fd996ef220ff9d3f967eb717faa",
            "539689a2f2897c317be4d6064f8ee10883907efa",
            "153a7644eabc5f0214c9e51dd42cba5276e9bc3e",
        ],
        "confidence": "high",
        "notes": "Issue combines two independently introduced paths: HTTP /tools/invoke surface and ACP auto-approval logic.",
    },
    "GHSA-g8p2-7wf7-98mq": {
        "introducing_commits": ["c74551c2ae0611f3ef0e691dc93a38372f366765"],
        "fix_commits": ["a7534dc22382c42465f3676724536a014ce0cbf7"],
        "confidence": "high",
        "notes": "UI auto-connect trust boundary issue is introduced by query-param based gatewayUrl parsing.",
    },
    "GHSA-mc68-q9jw-2h3v": {
        "introducing_commits": ["eaace34233fdf454c526d23cd2fd49de3be8eb32"],
        "fix_commits": ["771f23d36b95ec2204cc9a0054045f5d8439ea75"],
        "confidence": "high",
        "notes": "PATH handling weakness is introduced by docker sandbox exec PATH restoration and corrected in dedicated fix commit.",
    },
    "GHSA-x22m-j5qq-j49m": {
        "introducing_commits": ["2267d58afcc70fe19408b8f0dce108c340f3426d"],
        "fix_commits": ["5b4121d6011a48c71e747e3c18197f180b872c5d"],
        "confidence": "high",
        "notes": "SSRF surface appears when Feishu media/docx paths start fetching remote URLs without hardened fetch guards.",
    },
    "GHSA-g55j-c2v4-pjcg": {
        "introducing_commits": ["73e9e787b4df7705556f199f5f3e00580fab38c3"],
        "fix_commits": ["9dbc1435a6cac576d5fd71f4e4bff11a5d9d43ba"],
        "confidence": "high",
        "notes": "Gateway ws config.apply + unsafe cliPath flow is introduced in the device-auth/pairing unification and fixed by role and allowlist hardening.",
    },
}

SHA_RE = re.compile(r"[0-9a-f]{40}")
VERSION_RE = re.compile(r"(\d{4}\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)")


@dataclass
class CommitMeta:
    sha: str
    short: str
    authored_at: str
    subject: str


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def advisory_source_from_api() -> list[dict[str, Any]]:
    raw = run(
        [
            "gh",
            "api",
            "--paginate",
            "repos/openclaw/openclaw/security-advisories?per_page=100",
        ]
    )
    return json.loads(raw)


def commit_exists(repo: Path, sha: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "-e", f"{sha}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def commit_meta(repo: Path, sha: str) -> CommitMeta:
    out = run(
        ["git", "-C", str(repo), "show", "-s", "--format=%H%x09%h%x09%cI%x09%s", sha]
    )
    full, short, authored_at, subject = out.split("\t", 3)
    return CommitMeta(sha=full, short=short, authored_at=authored_at, subject=subject)


def parent_commit(repo: Path, sha: str) -> str:
    return run(["git", "-C", str(repo), "rev-parse", f"{sha}^"])


def is_ancestor(repo: Path, a: str, b: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", a, b],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode == 0


def parse_version_bounds(affected: str, patched: str) -> dict[str, str | None]:
    # Heuristic parser for advisory ranges like "< 2026.2.14", "<= 2026.2.22-2", etc.
    bounds: dict[str, str | None] = {
        "affected_lower": None,
        "affected_upper": None,
        "patched_lower": None,
    }
    affected_versions = VERSION_RE.findall(affected or "")
    patched_versions = VERSION_RE.findall(patched or "")

    if ">=" in (affected or "") and affected_versions:
        bounds["affected_lower"] = affected_versions[0]
    if ("<=" in (affected or "") or "<" in (affected or "")) and affected_versions:
        bounds["affected_upper"] = affected_versions[-1]
    if patched_versions:
        bounds["patched_lower"] = patched_versions[0]
    return bounds


def resolve_tag_commit(repo: Path, version: str | None) -> str | None:
    if not version:
        return None
    candidates = [f"v{version}", version]
    for tag in candidates:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "rev-parse",
                "-q",
                "--verify",
                f"{tag}^{{commit}}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode == 0:
            return proc.stdout.strip()
    return None


def make_case(
    adv: dict[str, Any], mapping: dict[str, Any], repo: Path
) -> dict[str, Any]:
    ghsa_id = adv["ghsa_id"]
    intro_commits: list[str] = mapping["introducing_commits"]
    fix_commits: list[str] = mapping["fix_commits"]

    for sha in intro_commits + fix_commits:
        if not commit_exists(repo, sha):
            raise RuntimeError(f"Missing commit in {repo}: {ghsa_id} -> {sha}")

    intro_meta = [commit_meta(repo, sha) for sha in intro_commits]
    fix_meta = [commit_meta(repo, sha) for sha in fix_commits]

    intro_meta_sorted = sorted(intro_meta, key=lambda x: x.authored_at)
    fix_meta_sorted = sorted(fix_meta, key=lambda x: x.authored_at)

    earliest_intro = intro_meta_sorted[0]
    latest_intro = intro_meta_sorted[-1]
    latest_fix = fix_meta_sorted[-1]
    baseline = parent_commit(repo, earliest_intro.sha)
    vulnerable_head = latest_intro.sha
    fix_head = latest_fix.sha

    vulnerable = (adv.get("vulnerabilities") or [{}])[0]
    affected_range = vulnerable.get("vulnerable_version_range", "")
    patched_range = vulnerable.get("patched_versions", "")

    bounds = parse_version_bounds(affected_range, patched_range)
    affected_upper_commit = resolve_tag_commit(repo, bounds["affected_upper"])
    patched_lower_commit = resolve_tag_commit(repo, bounds["patched_lower"])

    checks: list[dict[str, Any]] = []

    checks.append(
        {
            "name": "baseline_is_parent_of_earliest_intro",
            "pass": baseline == parent_commit(repo, earliest_intro.sha),
            "details": f"baseline={baseline} earliest_intro={earliest_intro.sha}",
        }
    )
    checks.append(
        {
            "name": "baseline_ancestor_of_all_intro",
            "pass": all(is_ancestor(repo, baseline, c.sha) for c in intro_meta_sorted),
            "details": "baseline should precede introducing commits",
        }
    )
    checks.append(
        {
            "name": "baseline_ancestor_of_all_fix",
            "pass": all(is_ancestor(repo, baseline, c.sha) for c in fix_meta_sorted),
            "details": "baseline should precede fix commits",
        }
    )
    if patched_lower_commit:
        checks.append(
            {
                "name": "intro_precedes_patched_release",
                "pass": is_ancestor(repo, latest_intro.sha, patched_lower_commit),
                "details": f"intro={latest_intro.sha} patched_tag_commit={patched_lower_commit}",
            }
        )
        checks.append(
            {
                "name": "fix_at_or_before_patched_release",
                "pass": is_ancestor(repo, fix_head, patched_lower_commit)
                or fix_head == patched_lower_commit,
                "details": f"fix_head={fix_head} patched_tag_commit={patched_lower_commit}",
            }
        )
    if affected_upper_commit:
        checks.append(
            {
                "name": "intro_at_or_before_affected_upper",
                "pass": is_ancestor(repo, latest_intro.sha, affected_upper_commit)
                or latest_intro.sha == affected_upper_commit,
                "details": f"intro={latest_intro.sha} affected_upper_commit={affected_upper_commit}",
            }
        )

    verification_pass = all(item["pass"] for item in checks)

    advisory_shas = sorted(set(SHA_RE.findall(adv.get("description", ""))))

    return {
        "id": ghsa_id,
        "severity": adv["severity"],
        "summary": adv["summary"],
        "url": adv["html_url"],
        "cwe_ids": adv.get("cwe_ids", []),
        "cvss_v3": ((adv.get("cvss_severities") or {}).get("cvss_v3") or {}).get(
            "score"
        ),
        "affected_range": affected_range,
        "patched_range": patched_range,
        "advisory_shas": advisory_shas,
        "confidence": mapping["confidence"],
        "notes": mapping["notes"],
        "baseline": baseline,
        "vulnerable_head": vulnerable_head,
        "fix_head": fix_head,
        "introducing_commits": [c.__dict__ for c in intro_meta_sorted],
        "fix_commits": [c.__dict__ for c in fix_meta_sorted],
        "advisory_fix_refs_unresolved": mapping.get("advisory_fix_refs_unresolved", []),
        "checks": checks,
        "verification_pass": verification_pass,
        "affected_upper_commit": affected_upper_commit,
        "patched_lower_commit": patched_lower_commit,
    }


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_analysis(case_dir: Path, case: dict[str, Any]) -> None:
    intro_lines = "\n".join(
        f"- `{c['sha']}` ({c['authored_at']}) {c['subject']}"
        for c in case["introducing_commits"]
    )
    fix_lines = "\n".join(
        f"- `{c['sha']}` ({c['authored_at']}) {c['subject']}"
        for c in case["fix_commits"]
    )
    check_lines = "\n".join(
        f"- [{'PASS' if c['pass'] else 'FAIL'}] `{c['name']}`: {c['details']}"
        for c in case["checks"]
    )

    md = f"""# {case['id']}\n\n## Vulnerability\n- Severity: `{case['severity']}`\n- Summary: {case['summary']}\n- CWE: {', '.join(case['cwe_ids']) if case['cwe_ids'] else 'N/A'}\n- Advisory: {case['url']}\n- Affected range: `{case['affected_range']}`\n- Patched range: `{case['patched_range']}`\n\n## Baseline Commit\n- Baseline (pre-introduction): `{case['baseline']}`\n\n## Vulnerable Introducing Commit(s)\n{intro_lines}\n\n## Fix Commit(s)\n{fix_lines}\n\n## Verification\n- Overall: `{'pass' if case['verification_pass'] else 'needs-review'}`\n- Confidence: `{case['confidence']}`\n- Notes: {case['notes']}\n\n{check_lines}\n\n## SecureVibes Efficacy\n- See `detectability.json` for empirical-run status and findings mapping.\n"""
    (case_dir / "analysis.md").write_text(md, encoding="utf-8")


def build(args: argparse.Namespace) -> None:
    repo = args.openclaw_repo.resolve()
    if not repo.exists():
        raise RuntimeError(f"OpenClaw repo does not exist: {repo}")

    if args.advisories_file:
        advisories = json.loads(args.advisories_file.read_text(encoding="utf-8"))
        source = str(args.advisories_file.resolve())
    else:
        advisories = advisory_source_from_api()
        source = (
            "gh api --paginate repos/openclaw/openclaw/security-advisories?per_page=100"
        )

    advisory_by_id = {item["ghsa_id"]: item for item in advisories}
    missing = [ghsa for ghsa in SELECTION_IDS if ghsa not in advisory_by_id]
    if missing:
        raise RuntimeError(f"Missing advisories in source: {missing}")

    generated_cases: list[dict[str, Any]] = []

    for ghsa_id in SELECTION_IDS:
        adv = advisory_by_id[ghsa_id]
        mapping = CASE_MAPPING[ghsa_id]
        case = make_case(adv, mapping, repo)
        generated_cases.append(case)

        case_dir = CASES_DIR / ghsa_id
        case_dir.mkdir(parents=True, exist_ok=True)

        advisory_payload = {
            "id": ghsa_id,
            "severity": adv["severity"],
            "published_at": adv.get("published_at"),
            "updated_at": adv.get("updated_at"),
            "summary": adv.get("summary"),
            "description": adv.get("description"),
            "url": adv.get("html_url"),
            "cwe_ids": adv.get("cwe_ids", []),
            "cvss_v3": ((adv.get("cvss_severities") or {}).get("cvss_v3") or {}),
            "affected_packages": adv.get("vulnerabilities", []),
            "extracted_shas": case["advisory_shas"],
            "unresolved_fix_refs": case["advisory_fix_refs_unresolved"],
        }
        write_json(case_dir / "advisory.json", advisory_payload)

        timeline_payload = {
            "id": ghsa_id,
            "baseline_commit": case["baseline"],
            "introducing_commits": case["introducing_commits"],
            "vulnerable_head": case["vulnerable_head"],
            "fix_commits": case["fix_commits"],
            "fix_head": case["fix_head"],
            "scan_ranges": {
                "introduction_range": f"{case['baseline']}..{case['vulnerable_head']}",
                "fix_range": f"{case['vulnerable_head']}..{case['fix_head']}",
            },
            "notes": case["notes"],
        }
        write_json(case_dir / "timeline.json", timeline_payload)

        verification_payload = {
            "id": ghsa_id,
            "verification_pass": case["verification_pass"],
            "confidence": case["confidence"],
            "checks": case["checks"],
            "range_commits": {
                "affected_upper_commit": case["affected_upper_commit"],
                "patched_lower_commit": case["patched_lower_commit"],
            },
        }
        write_json(case_dir / "verification.json", verification_payload)

        detectability_payload = {
            "id": ghsa_id,
            "status": "not_run",
            "model": "sonnet",
            "baseline_scan": None,
            "intro_pr_review": None,
            "fix_pr_review": None,
            "detected_from_new_commits": None,
            "could_propose_fix": None,
            "post_fix_regression_status": None,
            "notes": "Populate with scripts/run_case.py after empirical run.",
        }
        write_json(case_dir / "detectability.json", detectability_payload)

        write_analysis(case_dir, case)

    # Selection artifact with transparent ordering evidence.
    highs = [a for a in advisories if a.get("severity") == "high"]
    highs_sorted = sorted(
        highs,
        key=lambda x: (
            ((x.get("cvss_severities") or {}).get("cvss_v3") or {}).get("score")
            or (x.get("cvss") or {}).get("score")
            or -1,
            x.get("published_at") or "",
        ),
        reverse=True,
    )

    criticals = [a for a in advisories if a.get("severity") == "critical"]
    criticals_sorted = sorted(
        criticals, key=lambda x: x.get("published_at") or "", reverse=True
    )

    selection = {
        "snapshot": {
            "fetched_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "source": source,
            "repository": "openclaw/openclaw",
            "counts": {
                "critical": len(criticals),
                "high": len(highs),
                "medium": len([a for a in advisories if a.get("severity") == "medium"]),
                "low": len([a for a in advisories if a.get("severity") == "low"]),
            },
        },
        "policy": {
            "ordering": "all critical first, then high",
            "high_selection": "highest CVSSv3 first, tie-break by published_at desc",
            "cap": 10,
        },
        "selected_ids": SELECTION_IDS,
        "critical_candidates": [
            {
                "id": a["ghsa_id"],
                "published_at": a.get("published_at"),
                "cvss_v3": ((a.get("cvss_severities") or {}).get("cvss_v3") or {}).get(
                    "score"
                ),
            }
            for a in criticals_sorted
        ],
        "high_ranked_top_20": [
            {
                "id": a["ghsa_id"],
                "published_at": a.get("published_at"),
                "cvss_v3": ((a.get("cvss_severities") or {}).get("cvss_v3") or {}).get(
                    "score"
                )
                or (a.get("cvss") or {}).get("score"),
            }
            for a in highs_sorted[:20]
        ],
    }
    write_json(ROOT / "selection.json", selection)

    manifest = {
        "name": "openclaw-ghsa-batch1",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "advisory_source": source,
        "openclaw_repo": str(repo),
        "case_count": len(generated_cases),
        "cases": [
            {
                "id": c["id"],
                "severity": c["severity"],
                "summary": c["summary"],
                "confidence": c["confidence"],
                "baseline": c["baseline"],
                "vulnerable_head": c["vulnerable_head"],
                "fix_head": c["fix_head"],
                "verification_pass": c["verification_pass"],
            }
            for c in generated_cases
        ],
    }
    write_json(ROOT / "manifest.json", manifest)

    rows = [
        "| GHSA | Severity | Baseline | Intro Head | Fix Head | Verification |",
        "|---|---|---|---|---|---|",
    ]
    for c in generated_cases:
        rows.append(
            f"| {c['id']} | {c['severity']} | `{c['baseline'][:12]}` | `{c['vulnerable_head'][:12]}` | `{c['fix_head'][:12]}` | {'PASS' if c['verification_pass'] else 'REVIEW'} |"
        )

    summary = "\n".join(
        [
            "# OpenClaw GHSA Batch-1 Summary",
            "",
            "This file summarizes baseline/introducing/fix commit mapping for the selected 10 advisories.",
            "",
            *rows,
            "",
            "Empirical SecureVibes efficacy data is tracked per-case in `cases/<GHSA>/detectability.json`.",
        ]
    )
    (ROOT / "summary.md").write_text(summary + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--openclaw-repo",
        type=Path,
        default=Path("../openclaw"),
        help="Path to local OpenClaw git checkout",
    )
    parser.add_argument(
        "--advisories-file",
        type=Path,
        default=None,
        help="Optional JSON file with advisories payload (from GitHub API)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    build(parse_args())
