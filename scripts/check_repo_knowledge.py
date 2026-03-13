#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path


def fail(msg: str) -> None:
    print(f"[knowledge-check] {msg}")
    raise SystemExit(1)


def main() -> int:
    root = Path(__file__).resolve().parents[1]

    required = [
        root / "ARCHITECTURE.md",
        root / "docs/transforms/v0.1/README.md",
        root / "rules/mappings/checkov_to_sanara.v0.1.json",
        root / "schemas/sanara.finding.v0.1.json",
        root / "schemas/sanara.run_summary.v0.1.json",
        root / "schemas/sanara.patch_contract.v0.1.json",
    ]

    for path in required:
        if not path.exists():
            fail(f"missing file: {path.relative_to(root)}")

    mapping = json.loads(
        (root / "rules/mappings/checkov_to_sanara.v0.1.json").read_text(encoding="utf-8")
    )
    if "rule_pack_version" not in mapping:
        fail("mapping missing rule_pack_version")

    driver = (root / "sanara/orchestrator/driver.py").read_text(encoding="utf-8")
    if "rule_pack_version" not in driver:
        fail("run outputs do not include rule_pack_version")

    print("[knowledge-check] ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
