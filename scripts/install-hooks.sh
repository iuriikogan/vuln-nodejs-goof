#!/usr/bin/env bash
# Installs the shift-left Git pre-commit hook combining:
# 1. Pre-Commit Secrets Scanning (`secretguard scan --staged`)
# 2. Official Google Cloud CodeMender Staged Diff Scan (`cm find . --diff --staged`)
# Reference: https://docs.cloud.google.com/gemini-enterprise-agent-platform/agents/codemender/integrate-with-cicd#pre-commit-hook

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOK_PATH="$REPO_ROOT/.git/hooks/pre-commit"

mkdir -p "$REPO_ROOT/bin"
if [ ! -x "$REPO_ROOT/bin/secretguard" ]; then
  echo "[install-hooks] Compiling ./bin/secretguard..."
  (cd "$REPO_ROOT" && go build -o bin/secretguard ./cmd/secretguard)
fi

cat > "$HOOK_PATH" << 'EOF'
#!/bin/sh
# Official CodeMender + SecretGuard Pre-Commit Hook
# Scans staged changes for hardcoded secrets and CRITICAL/HIGH vulnerabilities before each commit.

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
MODEL="${CODEMENDER_MODEL:-gemini-3.8-flash}"
FAIL_ON="${CODEMENDER_FAIL_ON:-CRITICAL,HIGH}"

# Stage 1: Fast Pre-Commit Secrets & Policy Scan (<200ms)
if [ -x "$REPO_ROOT/bin/secretguard" ]; then
  if ! "$REPO_ROOT/bin/secretguard" scan --staged --repo "$REPO_ROOT"; then
    echo "SecretGuard blocked this commit: Hardcoded secret or prohibited .env file detected." >&2
    echo "Store secrets in Google Secret Manager and retrieve via ADC." >&2
    exit 1
  fi
fi

# Stage 2: Official Google Cloud CodeMender Staged Diff Scan
# Reference: https://docs.cloud.google.com/gemini-enterprise-agent-platform/agents/codemender/integrate-with-cicd#pre-commit-hook
if ! cm find . --diff --staged --fail-on="$FAIL_ON" \
    --model "$MODEL" --yes --bypass-warning; then
  echo "CodeMender blocked this commit. To see the findings, run:" >&2
  echo "  cm report --status=OPEN" >&2
  echo "To verify exploitability and auto-patch in the local sandbox, run:" >&2
  echo "  cm verify <FINDING_ID>" >&2
  echo "  cm fix <FINDING_ID>" >&2
  echo "  cm vcs diff && cm vcs stage" >&2
  echo "To commit anyway, run git commit --no-verify." >&2
  exit 1
fi
EOF

chmod 0755 "$HOOK_PATH"
echo "[install-hooks] Installed executable pre-commit hook at $HOOK_PATH"
