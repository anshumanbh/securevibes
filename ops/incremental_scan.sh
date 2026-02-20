#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_DIR"
exec python3 "$SCRIPT_DIR/incremental_scan.py" --repo "$REPO_DIR" "$@"
