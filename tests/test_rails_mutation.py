from __future__ import annotations

from pathlib import Path

from sanara.orchestrator.policy import Policy
from sanara.rails.validator import validate_patch


def test_rails_blocks_deny_path() -> None:
    policy = Policy(allow_paths=["**/*.tf"], deny_paths=["**/.terraform/**"], max_diff_lines=100)
    diff = 'diff --git a/.terraform/foo.tf b/.terraform/foo.tf\n+resource "aws_s3_bucket" "x" {}\n'
    result = validate_patch(diff, Path("."), policy)
    assert not result.ok
    assert result.code == "BLOCKED_BY_RAIL"


def test_rails_blocks_resource_deletion() -> None:
    policy = Policy(allow_paths=["**/*.tf"], deny_paths=["**/.terraform/**"], max_diff_lines=100)
    diff = 'diff --git a/main.tf b/main.tf\n-resource "aws_s3_bucket" "x" {}\n'
    result = validate_patch(diff, Path("."), policy)
    assert not result.ok
    assert result.code == "BLOCKED_BY_RAIL"


def test_rails_blocks_diff_size_cap() -> None:
    policy = Policy(allow_paths=["**/*.tf"], deny_paths=[], max_diff_lines=2)
    diff = "diff --git a/main.tf b/main.tf\n+a = 1\n+b = 2\n+c = 3\n"
    result = validate_patch(diff, Path("."), policy)
    assert not result.ok
    assert result.code == "BLOCKED_BY_RAIL"
