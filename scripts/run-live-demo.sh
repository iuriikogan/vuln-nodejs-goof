#!/usr/bin/env bash
# Interactive 3-Act Live Demo Runner for the 15-Minute Presentation:
# "Securing the Agentic Development Lifecycle with Google CodeMender"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

usage() {
  cat << 'EOF'
Usage: ./scripts/run-live-demo.sh <command>

Commands:
  act1-secrets   Act 1: Stage a hardcoded GCP API key & token -> Blocked in <200ms by pre-commit SecretGuard
  act2-precommit Act 2: Stage a Command Injection endpoint -> Blocked by `cm find . --diff --staged` -> `cm verify` & `cm fix`
  act3-cicd      Act 3: Run PR Diff Gate (`cm find . --diff=origin/main`) showing `[LEGACY / UNTOUCHED]` vs net-new CRITICAL block
  reset          Clean up staged demo changes and restore working tree
EOF
}

case "${1:-}" in
  act1-secrets)
    echo ">>> [Act 1] Simulating AI agent staging a hardcoded Google Cloud API key in routes/index.js..."
    KEY_PREFIX="AIza"
    KEY_SUFFIX="SyD-9t4bK1234567890abcdef1234567890"
    printf '\n// Demo Act 1: Hardcoded credential introduced during rapid prototyping\nconst EMERGENCY_GCP_KEY = "%s%s";\n' "$KEY_PREFIX" "$KEY_SUFFIX" >> routes/index.js
    git add routes/index.js
    echo ">>> Running pre-commit hook (.git/hooks/pre-commit)..."
    .git/hooks/pre-commit || true
    ;;

  act2-precommit)
    git checkout -- routes/index.js 2>/dev/null || true
    echo ">>> [Act 2] Simulating AI coding agent adding an unvalidated shell diagnostic endpoint in routes/index.js..."
    cat >> routes/index.js << 'EOF'

// Demo Act 2: Unvalidated OS command injection in diagnostic route
exports.pingHost = function (req, res) {
  const host = req.query.host || "localhost";
  exec("ping -c 1 " + host, function (err, stdout, stderr) {
    if (err) {
      return res.status(500).send(stderr);
    }
    return res.status(200).send(stdout);
  });
};
EOF
    git add routes/index.js
    echo ">>> Running pre-commit gate: cm find . --diff --staged --fail-on=CRITICAL,HIGH..."
    .git/hooks/pre-commit || true
    echo ""
    echo ">>> Next interactive commands for live demo:"
    echo "    1. cm report --status=OPEN"
    echo "    2. cm verify <FINDING_ID>"
    echo "    3. cm fix <FINDING_ID>"
    echo "    4. cm vcs diff && cm vcs stage"
    ;;

  act3-cicd)
    echo ">>> [Act 3] Running CI/CD PR Diff Gate against base branch:"
    echo "    cm find . --diff=HEAD~1 --diff-workers=16 --fail-on=CRITICAL,HIGH --format=sarif --output=codemender.sarif --yes --bypass-warning"
    cm find . \
      --diff=HEAD~1 \
      --diff-workers=16 \
      --fail-on=CRITICAL,HIGH \
      --model="${CODEMENDER_MODEL:-gemini-3.8-flash}" \
      --format=sarif \
      --output=codemender.sarif \
      --yes --bypass-warning || true
    cm report --status=OPEN --format=md || true
    ;;

  reset)
    git reset HEAD routes/index.js 2>/dev/null || true
    git checkout -- routes/index.js 2>/dev/null || true
    rm -f codemender.sarif codemender-findings.json
    echo ">>> Demo state reset cleanly."
    ;;

  *)
    usage
    exit 1
    ;;
esac
