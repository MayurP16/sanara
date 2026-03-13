#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "[1/3] Deterministic accuracy run (all10, mixed profile)"
"$ROOT/run_scenario.sh" all10 mixed >/dev/null
cat "$ROOT/artifacts/rescan/targeted_results.json"
echo

echo "[2/3] Agentic-path run (fallback, mixed profile)"
"$ROOT/run_scenario.sh" fallback mixed >/dev/null
cat "$ROOT/artifacts/run_summary.json"
echo
cat "$ROOT/artifacts/rescan/targeted_results.json"
echo

if [ -z "${ANTHROPIC_API_KEY:-}" ] && [ -z "${OPENAI_API_KEY:-}" ]; then
  echo "[3/3] Agentic ledger/trace (skipped: no ANTHROPIC_API_KEY/OPENAI_API_KEY in this shell)"
elif [ -f "$ROOT/artifacts/agentic/llm_ledger.json" ]; then
  echo "[3/3] Agentic ledger/trace"
  cat "$ROOT/artifacts/agentic/llm_ledger.json"
  echo
  cat "$ROOT/artifacts/agentic/trace.jsonl"
  echo
fi

echo "Done. Inspect full artifacts under: $ROOT/artifacts"
