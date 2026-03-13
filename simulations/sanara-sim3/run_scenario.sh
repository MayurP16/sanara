#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-all10}"
PROFILE="${2:-mixed}"
EXPECT_DECISION="${3:-}"
EXPECT_CLEAN="${4:-}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
DEFAULT_MAPPING="$REPO_ROOT/rules/mappings/checkov_to_sanara.v0.1.json"
SIM_MAPPING="$ROOT/rules/mappings/checkov_to_sanara.v0.1.json"

usage() {
  cat <<'EOF'
Usage: simulations/sanara-sim3/run_scenario.sh <mode> <profile> [expected-decision] [expected-clean]

Modes:
  all10               Stub scanners, deterministic 10 mapped findings
  fallback            Stub scanners, unresolved findings to exercise AGENTIC_APPLY
  real                Real local checkov from PATH
  real-fallback       Real scanners + mapping overlay to force fallback path
  real-fallback-llm   Same as real-fallback with mini-fix disabled

Profiles:
  mixed               Multi-file vulnerable baseline (default)
  single              Single-file vulnerable baseline
  public-s3           Public S3/DynamoDB lock-table baseline

Optional assertions:
  expected-decision   Assert run_summary.json decision matches (e.g., PR_CREATED, COMMENT_ONLY)
  expected-clean      Assert targeted_results clean is true|false
EOF
}

if [ "$MODE" = "--help" ] || [ "$MODE" = "-h" ]; then
  usage
  exit 0
fi

case "$PROFILE" in
  mixed|single|public-s3) ;;
  *)
    echo "Unknown profile: $PROFILE" >&2
    usage >&2
    exit 1
    ;;
esac

if [ -n "$EXPECT_CLEAN" ] && [ "$EXPECT_CLEAN" != "true" ] && [ "$EXPECT_CLEAN" != "false" ]; then
  echo "expected-clean must be true or false (got: $EXPECT_CLEAN)" >&2
  usage >&2
  exit 1
fi

if [ -x "$REPO_ROOT/.venv/bin/python" ]; then
  PYTHON_BIN="$REPO_ROOT/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
else
  echo "No python interpreter found (.venv/bin/python, python3, or python)." >&2
  exit 1
fi

"$ROOT/reset_vulnerable.sh" "$PROFILE"
cp "$DEFAULT_MAPPING" "$SIM_MAPPING"

cleanup() {
  cp "$DEFAULT_MAPPING" "$SIM_MAPPING"
}
trap cleanup EXIT

cat > "$ROOT/event.json" <<'JSON'
{
  "pull_request": {
    "number": 111,
    "base": {"sha": "", "ref": "main"},
    "head": {"sha": "", "ref": "feature/sim", "repo": {"fork": false}}
  },
  "sender": {"login": "local-sim"},
  "repository": {"full_name": "local/sim"}
}
JSON

cat > "$ROOT/.sanara/policy.yml" <<'YAML'
rule_pack_version: v0.1.0-alpha.1
allow_agentic: true
llm_provider: anthropic
anthropic_model: claude-sonnet-4-6
openai_model: gpt-4o-mini
plan_required: false
allow_paths:
  - "**"
deny_paths:
  - "**/.terraform/**"
max_diff_lines: 600
apply_opt_in_rules:
  - aws.ebs.default_encryption_enabled
YAML

TOOLS_PATH="$ROOT/tools"
PYTHON_BIN_DIR="$(dirname "$PYTHON_BIN")"
PATH_PREFIX="$PYTHON_BIN_DIR:/opt/homebrew/bin"
case "$MODE" in
  real)
    echo "Running REAL scanners (checkov from PATH)"
    RUN_PATH="$PATH_PREFIX:$PATH"
    ;;
  real-fallback)
    echo "Running REAL scanners with simulation fallback overlay (forces AGENTIC_APPLY path)"
    cp "$ROOT/rules/mappings/checkov_to_sanara.real_fallback.json" "$ROOT/rules/mappings/checkov_to_sanara.v0.1.json"
    RUN_PATH="$PATH_PREFIX:$PATH"
    ;;
  real-fallback-llm)
    echo "Running REAL scanners with fallback overlay (forces LLM attempts)"
    cp "$ROOT/rules/mappings/checkov_to_sanara.real_fallback.json" "$ROOT/rules/mappings/checkov_to_sanara.v0.1.json"
    RUN_PATH="$PATH_PREFIX:$PATH"
    ;;
  all10)
    echo "Running ALL10 stub scanner (guaranteed 10 mapped findings)"
    ln -sf "$ROOT/tools/checkov_all10_stub.py" "$ROOT/tools/checkov"
    RUN_PATH="$TOOLS_PATH:$PATH_PREFIX:$PATH"
    ;;
  fallback)
    echo "Running FALLBACK-init scenario (forces unresolved finding + AGENTIC_APPLY)"
    cat > "$ROOT/.sanara/policy.yml" <<'YAML'
rule_pack_version: v0.1.0-alpha.1
allow_agentic: true
llm_provider: anthropic
anthropic_model: claude-sonnet-4-6
openai_model: gpt-4o-mini
plan_required: false
allow_paths:
  - "**"
deny_paths:
  - "**/.terraform/**"
max_diff_lines: 600
apply_opt_in_rules:
  - aws.ebs.default_encryption_enabled
YAML
    ln -sf "$ROOT/tools/checkov_fallback_stub.py" "$ROOT/tools/checkov"
    RUN_PATH="$TOOLS_PATH:$PATH_PREFIX:$PATH"
    ;;
  *)
    echo "Unknown mode: $MODE" >&2
    usage >&2
    exit 1
    ;;
esac

PYTHONPATH="$REPO_ROOT" \
SANARA_SCHEMAS_DIR="$REPO_ROOT/schemas" \
PATH="$RUN_PATH" \
"$PYTHON_BIN" -m sanara.cli run --event "$ROOT/event.json" --workspace "$ROOT" --artifacts "$ROOT/artifacts"

echo "Scenario complete: $MODE"
echo "Artifacts: $ROOT/artifacts"
echo "Profile: $PROFILE"
"$PYTHON_BIN" - "$ROOT/artifacts" "$EXPECT_DECISION" "$EXPECT_CLEAN" <<'PY'
import json
import sys
from pathlib import Path

artifacts = Path(sys.argv[1])
summary_path = artifacts / "run_summary.json"
rescan_path = artifacts / "rescan/targeted_results.json"
ledger_path = artifacts / "agentic/llm_ledger.json"

if summary_path.exists():
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    print("Run summary:")
    print(f"- decision: {summary.get('decision', 'unknown')}")
    print(f"- findings_count: {summary.get('findings_count', 0)}")
    print(f"- drc_attempts: {len(summary.get('attempts', []))}")
else:
    print("Run summary: missing run_summary.json")

if rescan_path.exists():
    rescan = json.loads(rescan_path.read_text(encoding="utf-8"))
    remaining = rescan.get("remaining", [])
    print(f"- targeted_rescan_clean: {bool(rescan.get('clean', False))}")
    print(f"- remaining_findings: {len(remaining)}")
else:
    print("- targeted_rescan_clean: unknown (missing targeted_results.json)")

if ledger_path.exists():
    ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    print(f"- agentic_attempts: {len(ledger.get('attempts', []))}")

expect_decision = sys.argv[2]
expect_clean = sys.argv[3]
failed = False
if expect_decision:
    actual_decision = ""
    if summary_path.exists():
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
        actual_decision = str(summary.get("decision", ""))
    if actual_decision != expect_decision:
        print(f"Assertion failed: decision expected={expect_decision} actual={actual_decision or 'missing'}")
        failed = True

if expect_clean:
    actual_clean = None
    if rescan_path.exists():
        rescan = json.loads(rescan_path.read_text(encoding="utf-8"))
        actual_clean = bool(rescan.get("clean", False))
    expected_clean = expect_clean == "true"
    if actual_clean is None or actual_clean != expected_clean:
        clean_text = "missing" if actual_clean is None else str(actual_clean).lower()
        print(f"Assertion failed: clean expected={expect_clean} actual={clean_text}")
        failed = True

if failed:
    sys.exit(1)
PY
