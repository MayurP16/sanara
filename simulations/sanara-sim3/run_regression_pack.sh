#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SCENARIO_FILE="${1:-$ROOT/scenarios.yml}"

if [ ! -f "$SCENARIO_FILE" ]; then
  echo "Scenario file not found: $SCENARIO_FILE" >&2
  exit 1
fi

if [ -x "$ROOT/../../.venv/bin/python" ]; then
  PYTHON_BIN="$ROOT/../../.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python)"
else
  echo "No python interpreter found." >&2
  exit 1
fi

echo "Running regression pack from: $SCENARIO_FILE"
failures=0
total=0

while IFS='|' read -r name mode profile decision clean; do
  total=$((total + 1))
  echo ""
  echo "[$total] $name :: mode=$mode profile=$profile expect_decision=${decision:-<none>} expect_clean=${clean:-<none>}"
  if ! "$ROOT/run_scenario.sh" "$mode" "$profile" "$decision" "$clean"; then
    echo "FAILED: $name"
    failures=$((failures + 1))
  else
    echo "PASSED: $name"
  fi
done < <(
  "$PYTHON_BIN" - "$SCENARIO_FILE" <<'PY'
import sys
import yaml

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    payload = yaml.safe_load(f) or {}
for entry in payload.get("scenarios", []):
    expected_clean = entry.get("expected_clean", "")
    if isinstance(expected_clean, bool):
        expected_clean = "true" if expected_clean else "false"
    print(
        "|".join(
            [
                str(entry.get("name", "")),
                str(entry.get("mode", "all10")),
                str(entry.get("profile", "mixed")),
                str(entry.get("expected_decision", "")),
                str(expected_clean),
            ]
        )
    )
PY
)

echo ""
echo "Regression pack complete: total=$total failures=$failures"
if [ "$total" -eq 0 ]; then
  echo "No scenarios were executed. Check dependency availability and scenario file format." >&2
  exit 1
fi
if [ "$failures" -gt 0 ]; then
  exit 1
fi
