from __future__ import annotations

from pathlib import Path

from sanara.orchestrator.policy import Policy
from sanara.rails.validator import validate_patch


def test_rails_blocks_network_widening() -> None:
    policy = Policy(allow_paths=["**/*.tf"], deny_paths=[])
    diff = "\n".join(
        [
            "diff --git a/main.tf b/main.tf",
            '+resource "aws_security_group" "x" {',
            '+  cidr_blocks = ["0.0.0.0/0"]',
            "+}",
        ]
    )
    out = validate_patch(diff, Path("."), policy)
    assert not out.ok
    assert out.code == "BLOCKED_BY_RAIL"
