semgrep scan

┌──── ○○○ ────┐
│ Semgrep CLI │
└─────────────┘


Scanning 35 files (only git-tracked) with:

✔ Semgrep OSS
  ✔ Basic security coverage for first-party code vulnerabilities.

✔ Semgrep Code (SAST)
  ✔ Find and fix vulnerabilities in the code you write with advanced scanning and expert security rules.

✘ Semgrep Supply Chain (SCA)
  ✘ Find and fix the reachable vulnerabilities in your OSS dependencies.

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00


┌──────────────┐
│ Scan Summary │
└──────────────┘
✅ Scan completed successfully.
 • Findings: 0 (0 blocking)
 • Rules run: 927
 • Targets scanned: 35
 • Parsed lines: ~100.0%
 • Scan skipped:
   ◦ Files matching .semgrepignore patterns: 11
 • Scan was limited to files tracked by git
 • For a detailed list of skipped files and lines, run semgrep with the --verbose flag
Ran 927 rules on 35 files: 0 findings.

✨ If Semgrep missed a finding, please send us feedback to let us know!
   See https://semgrep.dev/docs/reporting-false-negatives/
