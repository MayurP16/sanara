#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
PROFILE="${1:-single}"

find "$ROOT" -maxdepth 1 -type f -name '*.tf' -delete
if [ "$PROFILE" = "mixed" ]; then
  for t in "$ROOT"/templates/mixed/*.tf.tmpl; do
    out="$ROOT/$(basename "${t%.tmpl}")"
    cp "$t" "$out"
  done
elif [ "$PROFILE" = "public-s3" ]; then
  cp "$ROOT/templates/main.public-s3.tmpl" "$ROOT/main.tf"
else
  cp "$ROOT/templates/main.vulnerable.tmpl" "$ROOT/main.tf"
fi
rm -rf "$ROOT/artifacts"
rm -f "$ROOT/sanara_security.tf"

if [ ! -d "$ROOT/.git" ]; then
  git -C "$ROOT" init -q
  git -C "$ROOT" config user.email sim@example.com
  git -C "$ROOT" config user.name sim
fi

git -C "$ROOT" add .
if ! git -C "$ROOT" diff --cached --quiet; then
  git -C "$ROOT" commit -qm "reset vulnerable baseline ($PROFILE)"
fi

echo "Reset complete ($PROFILE): $ROOT"
