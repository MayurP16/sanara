#!/usr/bin/env bash
set -euo pipefail

EXPECTED_VERSION="${1:-}"

normalize_expected_version() {
  local raw="$1"
  raw="${raw#v}"
  raw="${raw//-alpha./a}"
  raw="${raw//-beta./b}"
  raw="${raw//-rc./rc}"
  printf '%s\n' "$raw"
}

PYPROJECT_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -n1)"
PKG_VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' sanara/__init__.py | head -n1)"
LOCK_VERSION="$(sed -n 's/^sanara=\(.*\)$/\1/p' VERSION_LOCK | head -n1)"

if [[ -z "$PYPROJECT_VERSION" || -z "$PKG_VERSION" || -z "$LOCK_VERSION" ]]; then
  echo "Unable to read one or more version sources." >&2
  exit 1
fi

if [[ "$PYPROJECT_VERSION" != "$PKG_VERSION" || "$PYPROJECT_VERSION" != "$LOCK_VERSION" ]]; then
  echo "Version mismatch detected:" >&2
  echo "  pyproject.toml: $PYPROJECT_VERSION" >&2
  echo "  sanara/__init__.py: $PKG_VERSION" >&2
  echo "  VERSION_LOCK: $LOCK_VERSION" >&2
  exit 1
fi

if [[ -n "$EXPECTED_VERSION" ]]; then
  NORMALIZED_EXPECTED_VERSION="$(normalize_expected_version "$EXPECTED_VERSION")"
fi

if [[ -n "${NORMALIZED_EXPECTED_VERSION:-}" && "$PYPROJECT_VERSION" != "$NORMALIZED_EXPECTED_VERSION" ]]; then
  echo "Version does not match expected tag version:" >&2
  echo "  expected tag:     $EXPECTED_VERSION" >&2
  echo "  expected package: $NORMALIZED_EXPECTED_VERSION" >&2
  echo "  actual:   $PYPROJECT_VERSION" >&2
  exit 1
fi

echo "Version consistency check passed: $PYPROJECT_VERSION"
