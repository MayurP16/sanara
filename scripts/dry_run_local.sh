#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVENT_PATH="${1:-$ROOT/.sanara/event.local.json}"
ARTIFACTS_DIR="${2:-$ROOT/artifacts}"

cat > "$EVENT_PATH" <<'JSON'
{
  "pull_request": {
    "number": 1,
    "base": {"sha": "", "ref": "main"},
    "head": {"sha": "", "ref": "feature", "repo": {"fork": false}}
  },
  "sender": {"login": "local-dev"},
  "repository": {"full_name": "local/sanara"}
}
JSON

if [ -x "$ROOT/.venv/bin/python" ]; then
  "$ROOT/.venv/bin/python" -m sanara.cli run --event "$EVENT_PATH" --workspace "$ROOT" --artifacts "$ARTIFACTS_DIR"
else
  python -m sanara.cli run --event "$EVENT_PATH" --workspace "$ROOT" --artifacts "$ARTIFACTS_DIR"
fi

echo "Dry run complete. Artifacts at: $ARTIFACTS_DIR"
