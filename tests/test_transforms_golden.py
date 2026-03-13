from __future__ import annotations

from pathlib import Path

import pytest

from sanara.drc.transforms.core import (
    t1_public_access_block,
    t2_s3_sse,
    t3_s3_versioning,
    t4_rds_not_public,
    t5_ebs_encrypted,
    t6_ebs_default,
    t7_sns_encrypted,
    t8_sqs_encrypted,
    t9_dynamodb_pitr,
    t10_log_group_encrypted,
)
from sanara.orchestrator.policy import Policy


def _write(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


@pytest.mark.parametrize(
    "name,seed,fn,rtype,rname,snippet,policy",
    [
        (
            "t1",
            'resource "aws_s3_bucket" "b" {}',
            t1_public_access_block,
            "aws_s3_bucket",
            "b",
            'resource "aws_s3_bucket_public_access_block" "b_pab"',
            Policy(),
        ),
        (
            "t2",
            'resource "aws_s3_bucket" "b" {}',
            t2_s3_sse,
            "aws_s3_bucket",
            "b",
            'resource "aws_s3_bucket_server_side_encryption_configuration" "b_sse"',
            Policy(),
        ),
        (
            "t3",
            'resource "aws_s3_bucket" "b" {}',
            t3_s3_versioning,
            "aws_s3_bucket",
            "b",
            'resource "aws_s3_bucket_versioning" "b_versioning"',
            Policy(),
        ),
        (
            "t4",
            'resource "aws_db_instance" "db" { publicly_accessible = true }',
            t4_rds_not_public,
            "aws_db_instance",
            "db",
            "publicly_accessible = false",
            Policy(),
        ),
        (
            "t5",
            'resource "aws_ebs_volume" "v" { encrypted = false }',
            t5_ebs_encrypted,
            "aws_ebs_volume",
            "v",
            "encrypted = true",
            Policy(),
        ),
        (
            "t7",
            'resource "aws_sns_topic" "topic" {}',
            t7_sns_encrypted,
            "aws_sns_topic",
            "topic",
            'kms_master_key_id = "alias/aws/sns"',
            Policy(),
        ),
        (
            "t8",
            'resource "aws_sqs_queue" "queue" {}',
            t8_sqs_encrypted,
            "aws_sqs_queue",
            "queue",
            'kms_master_key_id = "alias/aws/sqs"',
            Policy(),
        ),
        (
            "t9",
            'resource "aws_dynamodb_table" "tbl" {}',
            t9_dynamodb_pitr,
            "aws_dynamodb_table",
            "tbl",
            "point_in_time_recovery",
            Policy(),
        ),
        (
            "t10",
            'resource "aws_cloudwatch_log_group" "lg" {}',
            t10_log_group_encrypted,
            "aws_cloudwatch_log_group",
            "lg",
            'kms_key_id = "alias/aws/logs"',
            Policy(),
        ),
    ],
)
def test_transform_golden_diff_and_idempotence(
    tmp_path: Path,
    name: str,
    seed: str,
    fn,
    rtype: str,
    rname: str,
    snippet: str,
    policy: Policy,
) -> None:
    _ = name
    main_tf = tmp_path / "main.tf"
    _write(main_tf, seed)
    before = main_tf.read_text(encoding="utf-8")
    out1 = fn(tmp_path, main_tf, rtype, rname, policy)
    after = out1.file_path.read_text(encoding="utf-8")
    assert out1.changed is True
    assert snippet in after
    assert before != after

    # "Expected rescan outcome": secure state remains after subsequent deterministic pass.
    _ = fn(tmp_path, main_tf, rtype, rname, policy)
    after_second = out1.file_path.read_text(encoding="utf-8")
    assert snippet in after_second


def test_t6_golden_opt_in_and_idempotence(tmp_path: Path) -> None:
    policy = Policy(apply_opt_in_rules=["aws.ebs.default_encryption_enabled"])
    main_tf = tmp_path / "main.tf"
    _write(main_tf, 'resource "aws_s3_bucket" "noop" {}')

    out1 = t6_ebs_default(tmp_path, main_tf, "", "", policy)
    assert out1.changed is True
    content = (tmp_path / "sanara_security.tf").read_text(encoding="utf-8")
    assert 'resource "aws_ebs_encryption_by_default" "this"' in content

    before_second = (tmp_path / "sanara_security.tf").read_text(encoding="utf-8")
    _ = t6_ebs_default(tmp_path, main_tf, "", "", policy)
    after_second = (tmp_path / "sanara_security.tf").read_text(encoding="utf-8")
    assert after_second == before_second
