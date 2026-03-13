#!/usr/bin/env bash
set -euo pipefail

# GitHub-hosted runners mount the workspace into the action container with ownership
# that can trigger Git's "dubious ownership" protection.
git config --global --add safe.directory /github/workspace || true

cd /github/workspace
exec python -m sanara.cli "$@"
