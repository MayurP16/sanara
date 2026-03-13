#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def parse_target(args: list[str]) -> Path:
    target = "."
    for i, arg in enumerate(args):
        if arg == "-d" and i + 1 < len(args):
            target = args[i + 1]
            break
    return Path(target)


def main() -> int:
    target = parse_target(sys.argv[1:])
    files = sorted(target.rglob("*.tf"))
    file_text = {p: p.read_text(encoding="utf-8") for p in files}
    text = "\n".join(file_text.values())

    def find_file(resource_type: str, resource_name: str) -> str:
        needle = f'resource "{resource_type}" "{resource_name}"'
        for p, content in file_text.items():
            if needle in content:
                return str(p.relative_to(target))
        return "main.tf"

    failed: list[dict[str, object]] = []

    # Intentionally keep this failing even after DRC to force AGENTIC_APPLY path.
    if 'resource "aws_sns_topic" "alerts"' in text:
        rel = find_file("aws_sns_topic", "alerts")
        failed.append(
            {
                "check_id": "CKV_AWS_26",
                "severity": "HIGH",
                "file_path": rel,
                "file_abs_path": str((target / rel).resolve()),
                "resource": "aws_sns_topic.alerts",
                "file_line_range": [1, 2],
            }
        )

    print(json.dumps({"results": {"failed_checks": failed}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
