• Security Findings

  - High – Remote agent runs in bypass mode: packages/core/securevibes/scanner/scanner.py:294-304 forces permission_mode='bypassPermissions', so Claude can execute
    any allowed tool with zero human gating; prompt-injection in scanned content can now read or alter local files and exfiltrate them via the model stream. Switch to
    an approval/deny list mode (or add an explicit policy layer) before trusting unvetted repositories.
  - High – Agents can write arbitrarily to the workspace: packages/core/securevibes/agents/definitions.py:49-71 registers the Write tool (and LS/Grep/Glob) for every
    agent without path scoping, letting the remote model overwrite project files or drop payloads if it is tricked; constrain tool usage to read-only or wrap writes
    with server-side validation that enforces a safe allowlist like .securevibes/.
  - Medium – Symlink traversal exposes host files: packages/core/securevibes/scanner/scanner.py:249-252 walks the repo with glob('**/*'), which follows symlinks;
    a malicious repo can point into ~/.ssh or /etc so that the upstream agent “reads project files” while actually exfiltrating host secrets. Add symlink detection
    (Path.is_symlink()), resolve+verify within the repo root, or pre-filter the tree.
  - Medium – --no-save still writes sensitive artifacts: packages/core/securevibes/cli/main.py:41-85 passes save_results but packages/core/securevibes/scanner/
    scanner.py:239-305 always creates .securevibes/ outputs, so users who opt out still leave scan results and derived docs on disk. Either plumb the flag through to
    skip artifact generation or document the limitation so people handling sensitive code can avoid residual files.

  Open questions: Does claude_agent_sdk enforce any filesystem jail beyond cwd? If not, the two high findings become urgent must-fix items.
