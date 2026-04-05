from __future__ import annotations

from pathlib import Path

import pytest

from sanara.drc.models import DrcError
from sanara.drc.transforms.core import t1_public_access_block, t16_s3_access_logging
from sanara.orchestrator.policy import Policy


def test_s3_access_logging_rejects_missing_bucket_resource_name(tmp_path: Path) -> None:
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "data" {}\n', encoding="utf-8")
    with pytest.raises(DrcError) as exc:
        t16_s3_access_logging(tmp_path, tmp_path / "main.tf", "aws_s3_bucket", "", Policy())
    assert exc.value.code == "INVALID_TARGET_RESOURCE"


def test_s3_access_logging_valid_target_never_emits_empty_bucket_ref(tmp_path: Path) -> None:
    target = tmp_path / "main.tf"
    target.write_text('resource "aws_s3_bucket" "data" {}\n', encoding="utf-8")
    result = t16_s3_access_logging(tmp_path, target, "aws_s3_bucket", "data", Policy())
    assert result.changed is True
    content = target.read_text(encoding="utf-8")
    assert "aws_s3_bucket..id" not in content
    assert "aws_s3_bucket.data.id" in content


def test_s3_access_logging_uses_counted_bucket_instance_expr(tmp_path: Path) -> None:
    target = tmp_path / "main.tf"
    target.write_text(
        ('resource "aws_s3_bucket" "this" {\n' "  count = 1\n" '  bucket = "example"\n' "}\n"),
        encoding="utf-8",
    )
    result = t16_s3_access_logging(tmp_path, target, "aws_s3_bucket", "this", Policy())
    assert result.changed is True
    content = target.read_text(encoding="utf-8")
    assert "bucket        = aws_s3_bucket.this[0].id" in content
    assert "aws_s3_bucket.this.id" not in content


def test_s3_companion_resources_use_existing_count_var_for_conditional_expr(
    tmp_path: Path,
) -> None:
    # Modules like cloudposse use a different variable name (e.g. create_s3_directory_bucket)
    # to control the directory bucket count. Sanara should use that variable in the generated
    # conditional expression instead of hardcoding var.is_directory_bucket.
    target = tmp_path / "main.tf"
    target.write_text(
        (
            'variable "create_s3_directory_bucket" {\n  type = bool\n  default = false\n}\n'
            'resource "aws_s3_bucket" "default" {\n'
            "  count = local.enabled ? 1 : 0\n"
            '  bucket = "example"\n'
            "}\n"
            'resource "aws_s3_directory_bucket" "default" {\n'
            "  count = var.create_s3_directory_bucket ? 1 : 0\n"
            '  bucket = "example--usw2-az1--x-s3"\n'
            "}\n"
        ),
        encoding="utf-8",
    )
    result = t16_s3_access_logging(tmp_path, target, "aws_s3_bucket", "default", Policy())
    assert result.changed is True
    content = target.read_text(encoding="utf-8")
    assert (
        "bucket        = var.create_s3_directory_bucket"
        " ? aws_s3_directory_bucket.default[0].bucket"
        " : aws_s3_bucket.default[0].id"
    ) in content
    assert "var.is_directory_bucket" not in content


def test_s3_companion_resources_use_directory_bucket_conditional_expr(tmp_path: Path) -> None:
    target = tmp_path / "main.tf"
    target.write_text(
        (
            'variable "is_directory_bucket" {\n  type = bool\n}\n'
            'resource "aws_s3_bucket" "this" {\n'
            "  count = var.is_directory_bucket ? 0 : 1\n"
            '  bucket = "example"\n'
            "}\n"
            'resource "aws_s3_directory_bucket" "this" {\n'
            "  count = var.is_directory_bucket ? 1 : 0\n"
            '  bucket = "example-dir"\n'
            "}\n"
        ),
        encoding="utf-8",
    )
    result = t1_public_access_block(tmp_path, target, "aws_s3_bucket", "this", Policy())
    assert result.changed is True
    content = target.read_text(encoding="utf-8")
    assert (
        "bucket = var.is_directory_bucket ? aws_s3_directory_bucket.this[0].bucket : aws_s3_bucket.this[0].id"
        in content
    )
