from __future__ import annotations

from pathlib import Path

from sanara.drc.engine import apply_drc
from sanara.orchestrator.policy import Policy


def test_apply_drc_dedupes_same_rule_same_target(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n', encoding="utf-8")
    findings = [
        {
            "sanara_rule_id": "aws.s3.public_access_block",
            "resource_type": "aws_s3_bucket",
            "resource_name": "b",
            "target": {"file_path": "main.tf", "module_dir": "."},
        },
        {
            "sanara_rule_id": "aws.s3.public_access_block",
            "resource_type": "aws_s3_bucket",
            "resource_name": "b",
            "target": {"file_path": "main.tf", "module_dir": "."},
        },
    ]

    attempts = apply_drc(tmp_path, findings, Policy())

    assert len(attempts) == 1
    assert attempts[0].sanara_rule_id == "aws.s3.public_access_block"
